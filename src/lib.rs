#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

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
pub enum ConvertError {
    /// Error starting the converter program
    #[error("failed to start unoconvert: {0}")]
    StartConverter(std::io::Error),

    /// Error when working with the child program stdin/stdout
    #[error("error working with child process io: {0}")]
    ProcessIo(std::io::Error),

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

/// Error when starting an unoserver
#[derive(Debug, Error)]
pub enum ServerError {
    /// Timeout for starting the server was exceeded
    #[error("office server startup timeout reached")]
    StartTimeoutReached,

    /// Didn't get a startup message but the program exited
    #[error("office server process ended without a startup message")]
    NoStartupMessage,

    /// Error when working with the server program stdin/stdout
    #[error("error working with server process io: {0}")]
    ProcessIo(std::io::Error),
}

/// Default port for unoserver
pub const DEFAULT_SERVER_PORT: u16 = 2003;
/// Default port for the Libreoffice uno
pub const DEFAULT_UNO_PORT: u16 = 2002;

/// Server connection details
#[derive(Debug)]
pub enum ConvertServerHost {
    /// Local converter server
    ///
    /// For server running locally on the same machine
    Local {
        /// The local server port
        port: u16,
    },

    /// Remove converter server
    ///
    /// For server running on remote machine
    Remote {
        /// The remote server host
        host: String,
        /// The remote server port
        port: u16,
    },
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

/// State for a converter server
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
    /// Default timeout for the running check
    pub const DEFAULT_RUNNING_TIMEOUT: Duration = Duration::from_secs(5);

    /// Creates a new server
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
    pub async fn convert_to_pdf(&self, input_bytes: &[u8]) -> Result<Vec<u8>, ConvertError> {
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
            .map_err(ConvertError::StartConverter)?;

        // Write the input data to the child process's stdin
        {
            let stdin = child
                .stdin
                .as_mut()
                .expect("stdin was piped but missing from child process");

            stdin
                .write_all(input_bytes)
                .await
                .map_err(ConvertError::ProcessIo)?;
        }

        // Wait for the program to run
        let output = child
            .wait_with_output()
            .await
            .map_err(ConvertError::ProcessIo)?;

        if !output.status.success() {
            // Determine error message
            let error = if !output.stderr.is_empty() {
                String::from_utf8_lossy(&output.stderr).to_string()
            } else {
                "Unknown error".to_string()
            };

            // Handle malformed document
            if error.contains("Could not load document") {
                return Err(ConvertError::MalformedDocument);
            }

            // Handle encrypted document
            if error.contains("Unsupported URL <private:stream>") {
                return Err(ConvertError::EncryptedDocument);
            }

            return Err(ConvertError::ConverterError(error));
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
    pub async fn handle(&self, input_bytes: &[u8]) -> Result<Vec<u8>, ConvertError> {
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
pub async fn start_unoserver(server_port: u16, uno_port: u16) -> Result<AbortHandle, ServerError> {
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
        .map_err(ServerError::ProcessIo)?;

    timeout(STARTUP_TIMEOUT, async move {
        let stderr = child.stderr.as_mut().expect("child missing stdout");
        let mut stderr_reader = BufReader::new(stderr).lines();

        loop {
            // Read from the input
            let value = stderr_reader
                .next_line()
                .await
                .map_err(ServerError::ProcessIo)?
                .ok_or(ServerError::NoStartupMessage)?;

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
    .map_err(|_| ServerError::StartTimeoutReached)
    .and_then(std::convert::identity)
}

/// Checks if the provided mime is included in the known convertable mime types
pub fn is_known_convertable(mime: &str) -> bool {
    CONVERTABLE_FORMATS.contains(&mime)
}

/// List of supported convertable formats
pub const CONVERTABLE_FORMATS: &[&str] = &[
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

    use crate::{
        start_unoserver, ConvertError, ConvertLoadBalancer, ConvertServer, ConvertServerHost,
        ConvertServerState, DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT,
    };
    use std::{sync::Arc, time::Duration};
    use tokio::task::JoinSet;

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

        assert!(matches!(err, ConvertError::EncryptedDocument))
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

        assert!(matches!(err, ConvertError::EncryptedDocument))
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
