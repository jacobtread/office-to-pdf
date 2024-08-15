//! Office to PDF conversion
//!
//! ```no_run
//! use office_to_pdf::office_to_pdf;
//!
//! #[tokio::main]
//! async fn main() {
//!     let bytes: &[u8] = &[/* ...office file bytes from docx or similar */];
//!     let pdf: Vec<u8> = ConvertServer::default().convert_to_pdf(bytes).await.expect("failed to convert to pdf");
//! }
//!
//! ```
//!
//! Requires libreoffice and unoserver, only supported for linux. See README for installation
//! details

use std::{
    net::SocketAddr,
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{lookup_host, TcpStream},
    process::Command,
    sync::Notify,
    task::AbortHandle,
    time::timeout,
};

/// Errors that can occur while converting an office file
#[derive(Debug, Error)]
pub enum OfficeError {
    /// Error starting the converter server
    #[error("failed to start unoserver: {0}")]
    StartConverterServer(std::io::Error),

    /// Error starting the converter program
    #[error("failed to start unoconvert: {0}")]
    StartConverter(std::io::Error),

    /// Converter stdin was not available to write to
    #[error("unable to access converter input")]
    MissingConverterInput,

    /// Error while writing the document as input to the converter
    #[error("failed to write input into converter")]
    ConverterInput(std::io::Error),

    /// Error while the program output was being waited for / read
    #[error("error while waiting for converter output: {0}")]
    ConverterOutput(std::io::Error),

    /// Document was malformed
    #[error("office document is malformed")]
    MalformedDocument,

    /// Document was encrypted
    #[error("office document is password protected")]
    EncryptedDocument,

    /// Converter program returned an error
    #[error("converter returned error: {0}")]
    ConverterError(String),
}

/// Default port for unoserver
pub const DEFAULT_SERVER_PORT: u16 = 2003;
/// Default port for the Libreoffice uno
pub const DEFAULT_UNO_PORT: u16 = 2002;

#[derive(Debug)]
pub enum ConvertServerHost {
    /// Local converter server
    Local { port: u16 },

    /// Remove converter server
    Remote { host: String, port: u16 },
}

impl Default for ConvertServerHost {
    fn default() -> Self {
        Self::Local {
            port: DEFAULT_SERVER_PORT,
        }
    }
}

/// Convert server
#[derive(Default)]
pub struct ConvertServer {
    /// Host for the server
    host: ConvertServerHost,
}

pub enum ConvertServerState {
    /// Server cannot be reached
    Unreachable,
    /// Server is currently too busy to response
    Busy,
    /// Some IO failure is occurring
    Failure,
    /// Server is connectable and can process requests
    Available,
}

impl ConvertServer {
    pub const DEFAULT_RUNNING_TIMEOUT: Duration = Duration::from_secs(5);

    pub fn new(host: ConvertServerHost) -> Self {
        Self { host }
    }

    /// Obtains a socket address to the server
    pub async fn socket_addr(&self) -> std::io::Result<SocketAddr> {
        // Determine the server host and port
        let addr = match &self.host {
            ConvertServerHost::Local { port } => ("127.0.0.1", *port),
            ConvertServerHost::Remote { host, port } => (host.as_str(), *port),
        };

        // Resolve the address
        let mut addrs = lookup_host(addr).await?;
        addrs.next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to resolve socket address",
            )
        })
    }

    /// Checks if the server is running
    ///
    /// The following states are considered running:
    ///
    /// [ConvertServerState::Busy] [ConvertServerState::Failure] [ConvertServerState::Available]
    pub async fn is_running(&self, timeout_after: Duration) -> bool {
        match self
            .server_state(timeout_after, Duration::from_millis(100))
            .await
        {
            ConvertServerState::Busy
            | ConvertServerState::Available
            | ConvertServerState::Failure => true,
            ConvertServerState::Unreachable => false,
        }
    }

    /// Checks the current server state by making a simple request to it.
    ///
    /// If the server cannot be connected to its considered [ConvertServerState::Unreachable]
    ///
    /// If the server failed an IO portion its considered [ConvertServerState::Failure]
    ///
    /// If the server didn't reply to the ping message within the busy timeout it is
    /// considered [ConvertServerState::Busy]
    ///
    /// If the server is connectable and not busy it is considered [ConvertServerState::Available]
    pub async fn server_state(
        &self,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> ConvertServerState {
        let addr = match self.socket_addr().await {
            Ok(value) => value,
            // Failed to obtain server socket address
            Err(_) => return ConvertServerState::Unreachable,
        };

        // Open a stream connection
        let mut stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => stream,
            // Got some other connection error
            Ok(Err(_)) => return ConvertServerState::Unreachable,
            // Hit a timeout
            Err(_) => return ConvertServerState::Unreachable,
        };

        // Write the most basic of a request
        if stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.is_err() {
            return ConvertServerState::Failure;
        }

        // Just enough buffer to get the first part of the response HTTP/VERSION + STATUS
        let mut buffer = [0; 15];

        match timeout(busy_timeout, stream.read_exact(&mut buffer)).await {
            Ok(Ok(_)) => ConvertServerState::Available,
            // Got some other IO error
            Ok(Err(_)) => ConvertServerState::Failure,
            // Hit a timeout
            Err(_) => ConvertServerState::Busy,
        }
    }

    /// Converts the provided office file bytes to PDF file bytes
    pub async fn convert_to_pdf(&self, input_bytes: &[u8]) -> Result<Vec<u8>, OfficeError> {
        let mut args = Vec::<String>::new();

        match &self.host {
            ConvertServerHost::Local { port } => {
                args.push("--host-location".to_string());
                args.push("local".to_string());

                args.push("--port".to_string());
                args.push(port.to_string());
            }
            ConvertServerHost::Remote { host, port } => {
                args.push("--host-location".to_string());
                args.push("remote".to_string());

                args.push("--host".to_string());
                args.push(host.to_string());

                args.push("--port".to_string());
                args.push(port.to_string());
            }
        }

        // Spawn the unoconvert process
        let mut child = Command::new("unoconvert")
            .args(["--convert-to", "pdf", "-", "-"])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(OfficeError::StartConverter)?;

        // Write the input data to the child process's stdin
        {
            let stdin = child
                .stdin
                .as_mut()
                .ok_or(OfficeError::MissingConverterInput)?;

            stdin
                .write_all(input_bytes)
                .await
                .map_err(OfficeError::ConverterInput)?;
        }

        // Wait for the program to run
        let output = child
            .wait_with_output()
            .await
            .map_err(OfficeError::ConverterOutput)?;

        if !output.status.success() {
            // Determine error message
            let error = if !output.stderr.is_empty() {
                String::from_utf8_lossy(&output.stderr).to_string()
            } else {
                "Unknown error".to_string()
            };

            // Handle malformed document
            if error.contains("Could not load document") {
                return Err(OfficeError::MalformedDocument);
            }

            // Handle encrypted document
            if error.contains("Unsupported URL <private:stream>") {
                return Err(OfficeError::EncryptedDocument);
            }

            return Err(OfficeError::ConverterError(error));
        }

        Ok(output.stdout)
    }
}

/// Simple load balancer for distributing load amongst the provided servers.
///
/// Checks if servers are too under load to process a request and attempts
/// the next available server.
#[derive(Clone)]
pub struct ConvertLoadBalancer {
    inner: Arc<ConvertLoadBalancerInner>,
}

/// Inner shared contents of [ConvertLoadBalancer]
struct ConvertLoadBalancerInner {
    servers: Vec<LoadBalanced>,
    /// Notifier for when connections are no longer busy
    free_notify: Notify,
    connect_timeout: Duration,
    busy_timeout: Duration,
}

/// Load balanced [ConvertServer] contains the busy state for
/// the server
struct LoadBalanced {
    /// Server to do conversion
    server: ConvertServer,
    /// Busy state of the server
    busy: AtomicBool,
}

impl ConvertLoadBalancer {
    /// Creates a new load balancer from the provided servers
    ///
    /// ## Arguments
    /// * `servers` - The servers to load balance
    /// * `connect_timeout` - Timeout to wait while attempting to connect to a server to check if the server is available
    /// * `busy_timeout` - Timeout to wait until data is received when checking if a server is available
    pub fn new(
        servers: Vec<ConvertServer>,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Self {
        let free_notify = Notify::new();
        let servers = servers
            .into_iter()
            .map(|server| LoadBalanced {
                server,
                busy: AtomicBool::new(false),
            })
            .collect();

        Self {
            inner: Arc::new(ConvertLoadBalancerInner {
                servers,
                free_notify,
                connect_timeout,
                busy_timeout,
            }),
        }
    }

    /// Handles a conversion using one of the load balancers
    pub async fn handle(&self, input_bytes: &[u8]) -> Result<Vec<u8>, OfficeError> {
        let inner = &*self.inner;

        loop {
            for server in &inner.servers {
                // Skip busy servers
                if server.busy.load(Ordering::Acquire) {
                    continue;
                }

                // Determine the current server state
                match server
                    .server
                    .server_state(self.inner.connect_timeout, self.inner.busy_timeout)
                    .await
                {
                    // Server is unreachable or failing currently; move to the next one
                    ConvertServerState::Unreachable | ConvertServerState::Failure => continue,
                    // Server is currently busy
                    ConvertServerState::Busy => {
                        // Mark server busy
                        server.busy.store(true, Ordering::SeqCst);
                        continue;
                    }
                    // Server is available, we can use it
                    ConvertServerState::Available => {}
                }

                // Give the load to the server
                let result = server.server.convert_to_pdf(input_bytes).await;

                server.busy.store(false, Ordering::SeqCst);

                // Notify that a server is free
                inner.free_notify.notify_waiters();

                return result;
            }

            // Wait until a server is free before continuing
            inner.free_notify.notified().await;
        }
    }
}

/// Start the conversion server
///
/// Must be running in the background otherwise the unoconvert program
/// will hang waiting from a server to start
pub async fn start_unoserver(server_port: u16, uno_port: u16) -> Result<AbortHandle, OfficeError> {
    // Timeout if the server didn't start within 5 minutes
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(60 * 5);

    // Spawn the unoserver process
    let mut child = Command::new("unoserver")
        .args([
            "--port",
            &server_port.to_string(),
            "--uno-port",
            &uno_port.to_string(),
        ])
        // Pipe output for reading
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(OfficeError::StartConverterServer)?;

    timeout(STARTUP_TIMEOUT, async move {
        let stderr = child.stderr.as_mut().expect("child missing stdout");
        let mut stderr_reader = BufReader::new(stderr).lines();

        loop {
            // Read from the input
            let value = match stderr_reader.next_line().await {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return Err(OfficeError::StartConverterServer(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "didn't receive start message from unoserver",
                    )))
                }
                Err(err) => return Err(OfficeError::StartConverterServer(err)),
            };

            // Wait until startup message is received
            if value.contains("Server PID:") {
                break;
            }
        }

        // Move server to background task
        let abort_handle = tokio::spawn(async move {
            _ = child.wait().await;
        })
        .abort_handle();

        Ok(abort_handle)
    })
    .await
    .map_err(|_| {
        OfficeError::StartConverterServer(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unoserver startup timeout exceeded",
        ))
    })
    .and_then(std::convert::identity)
}

/// Checks if the provided mime is included in the known convertable mime types
pub fn is_known_convertable(mime: &str) -> bool {
    CONVERTABLE_FORMATS.contains(&mime)
}

/// List of supported convertable formats
const CONVERTABLE_FORMATS: &[&str] = &[
    "text/html",
    "application/msword",
    "application/vnd.oasis.opendocument.text-flat-xml",
    "application/rtf",
    "application/vnd.sun.xml.writer",
    "application/vnd.wordperfect",
    "application/vnd.ms-works",
    "application/x-mswrite",
    "application/clarisworks",
    "application/macwriteii",
    "application/x-abiword",
    "application/x-t602",
    "application/vnd.lotus-wordpro",
    "text/plain",
    "application/x-hwp",
    "application/vnd.sun.xml.writer.template",
    "application/pdf",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.text-template",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.slideshow",
    "application/x-fictionbook+xml",
    "application/x-aportisdoc",
    "application/prs.plucker",
    "application/x-iwork-pages-sffpages",
    "application/vnd.palm",
    "application/epub+zip",
    "application/x-pocket-word",
    "application/vnd.oasis.opendocument.spreadsheet-flat-xml",
    "application/vnd.lotus-1-2-3",
    "application/vnd.ms-excel",
    "text/spreadsheet",
    "application/vnd.sun.xml.calc",
    "application/vnd.sun.xml.calc.template",
    "application/x-gnumeric",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    "application/clarisworks",
    "application/x-iwork-numbers-sffnumbers",
    "application/mathml+xml",
    "application/vnd.sun.xml.math",
    "application/vnd.oasis.opendocument.formula",
    "application/vnd.sun.xml.base",
    "image/jpeg",
    "image/png",
    "image/svg+xml",
    "image/webp",
    "application/docbook+xml",
    "application/xhtml+xml",
];

#[cfg(test)]
mod test {

    use std::{sync::Arc, time::Duration};

    use tokio::task::JoinSet;

    use crate::{
        start_unoserver, ConvertLoadBalancer, ConvertServer, ConvertServerHost, ConvertServerState,
        OfficeError, DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT,
    };

    /// Tests the unoserver can be started
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_unoserver() {
        start_unoserver(DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT)
            .await
            .unwrap();
    }

    /// Tests the unoserver can be started
    #[tokio::test]
    #[ignore = "requires unoserver started in advance to compare"]
    async fn test_unoserver_is_running() {
        let server = ConvertServer::new(ConvertServerHost::Local { port: 9250 });

        let is_running = server.is_running(Duration::from_secs(5)).await;

        assert!(is_running);
    }

    /// Tests the unoserver can be started
    #[tokio::test]
    #[ignore = "requires setting up an unoserver and making it busy while testing"]
    async fn test_unoserver_is_busy() {
        let server = ConvertServer::new(ConvertServerHost::Local { port: 9250 });

        let result = server
            .server_state(Duration::from_millis(100), Duration::from_millis(500))
            .await;
        assert!(matches!(result, ConvertServerState::Busy));
    }

    /// Tests a sample docx
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_docx() {
        start_unoserver(DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT)
            .await
            .unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-docx.docx").await.unwrap();
        let _output = ConvertServer::default()
            .convert_to_pdf(&input_bytes)
            .await
            .unwrap();
    }

    /// Tests a sample docx with an image
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_docx_with_image() {
        start_unoserver(DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT)
            .await
            .unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-docx-with-image.docx")
            .await
            .unwrap();
        let _output = ConvertServer::default()
            .convert_to_pdf(&input_bytes)
            .await
            .unwrap();
    }

    /// Tests an encrypted docx
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_docx_encrypted() {
        start_unoserver(DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT)
            .await
            .unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-docx-encrypted.docx")
            .await
            .unwrap();
        let err = ConvertServer::default()
            .convert_to_pdf(&input_bytes)
            .await
            .unwrap_err();

        assert!(matches!(err, OfficeError::EncryptedDocument))
    }

    /// Tests a sample xlsx
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_xlsx() {
        start_unoserver(DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT)
            .await
            .unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-xlsx.xlsx").await.unwrap();
        let _output = ConvertServer::default()
            .convert_to_pdf(&input_bytes)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_xlsx_encrypted() {
        start_unoserver(DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT)
            .await
            .unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-xlsx-encrypted.xlsx")
            .await
            .unwrap();
        let err = ConvertServer::default()
            .convert_to_pdf(&input_bytes)
            .await
            .unwrap_err();

        assert!(matches!(err, OfficeError::EncryptedDocument))
    }

    /// Tests a sample docx
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once, requires running remote instance"]
    async fn test_sample_docx_remote() {
        let input_bytes = tokio::fs::read("./samples/sample-docx.docx").await.unwrap();
        let _output = ConvertServer::new(ConvertServerHost::Remote {
            host: "localhost".to_string(),
            port: 9250,
        })
        .convert_to_pdf(&input_bytes)
        .await
        .unwrap();
    }

    /// Tests a sample docx
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "slow and resource intensive if these tests are run all at once, requires running remote instance"]
    async fn test_sample_docx_remote_load_balanced() {
        let pool = ConvertLoadBalancer::new(
            vec![
                ConvertServer::new(ConvertServerHost::Remote {
                    host: "localhost".to_string(),
                    port: 9250,
                }),
                ConvertServer::new(ConvertServerHost::Remote {
                    host: "localhost".to_string(),
                    port: 9251,
                }),
                ConvertServer::new(ConvertServerHost::Remote {
                    host: "localhost".to_string(),
                    port: 9252,
                }),
                ConvertServer::new(ConvertServerHost::Remote {
                    host: "localhost".to_string(),
                    port: 9253,
                }),
                ConvertServer::new(ConvertServerHost::Remote {
                    host: "localhost".to_string(),
                    port: 9254,
                }),
            ],
            Duration::from_millis(200),
            Duration::from_millis(500),
        );

        let mut join_set = JoinSet::new();
        let input_bytes = Arc::new(tokio::fs::read("./samples/sample-docx.docx").await.unwrap());

        for _ in 0..10 {
            let pool = pool.clone();
            let input_bytes = input_bytes.clone();

            join_set.spawn(async move {
                pool.handle(&input_bytes).await.unwrap();
            });
        }

        while (join_set.join_next().await).is_some() {}
    }
}
