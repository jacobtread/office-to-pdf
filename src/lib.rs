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

use reqwest::Client;
use std::{
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
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

    #[error("failed to create load balancer client: {0}")]
    CreateLoadBalancer(reqwest::Error),
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

impl ConvertServer {
    pub fn new(host: ConvertServerHost) -> Self {
        Self { host }
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

/// Check the conversion server is running
pub fn is_unoserver_running() -> bool {
    let system =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    let mut processes = system.processes_by_name("unoserver");

    processes.next().is_some()
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
    /// Client for checking busy connections
    client: reqwest::Client,
    /// Notifier for when connections are no longer busy
    free_notify: Notify,
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
    /// * `busy_timeout` - Timeout to wait before considering an instance to be busy
    ///                    ensure you account for over the internet transfer when using
    ///                    remote instances, this is only for a cheap ping HTTP request
    pub fn new(servers: Vec<ConvertServer>, busy_timeout: Duration) -> Result<Self, OfficeError> {
        let client = Client::builder()
            .timeout(busy_timeout)
            .build()
            .map_err(OfficeError::CreateLoadBalancer)?;
        let free_notify = Notify::new();
        let servers = servers
            .into_iter()
            .map(|server| LoadBalanced {
                server,
                busy: AtomicBool::new(false),
            })
            .collect();
        Ok(Self {
            inner: Arc::new(ConvertLoadBalancerInner {
                servers,
                client,
                free_notify,
            }),
        })
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

                // Determine the server host and port
                let (host, port) = match &server.server.host {
                    ConvertServerHost::Local { port } => ("localhost", port),
                    ConvertServerHost::Remote { host, port } => (host.as_str(), port),
                };

                // Attempt to connect to the server to see if its busy or available
                if inner
                    .client
                    .get(format!("http://{}:{}", host, port))
                    .send()
                    .await
                    .is_err()
                {
                    // Mark server busy
                    server.busy.store(true, Ordering::SeqCst);
                    continue;
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
        start_unoserver, ConvertLoadBalancer, ConvertServer, ConvertServerHost, OfficeError,
        DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT,
    };

    /// Tests the unoserver can be started
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_unoserver() {
        start_unoserver(DEFAULT_SERVER_PORT, DEFAULT_UNO_PORT)
            .await
            .unwrap();
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
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once, requires running remote instance"]
    async fn test_sample_docx_remote_load_balanced() {
        let pool = Arc::new(
            ConvertLoadBalancer::new(
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
                Duration::from_millis(500),
            )
            .unwrap(),
        );

        let mut join_set = JoinSet::new();

        for _ in 0..100 {
            let pool = pool.clone();

            join_set.spawn(async move {
                let input_bytes = tokio::fs::read("./samples/sample-docx.docx").await.unwrap();
                pool.handle(&input_bytes).await.unwrap();
            });
        }

        while (join_set.join_next().await).is_some() {}
    }
}
