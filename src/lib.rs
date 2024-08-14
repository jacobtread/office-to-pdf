//! Office to PDF conversion
//!
//! ```no_run
//! use office_to_pdf::office_to_pdf;
//!
//! #[tokio::main]
//! async fn main() {
//!     let bytes: &[u8] = &[/* ...office file bytes from docx or similar */];
//!     let pdf: Vec<u8> = office_to_pdf(bytes).await.expect("failed to convert to pdf");
//! }
//!
//! ```
//!
//! Requires libreoffice and unoserver, only supported for linux. See README for installation
//! details

use std::{process::Stdio, time::Duration};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
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

/// Options for the converter
#[derive(Debug, Default)]
pub struct ConvertOptions {
    /// Host server to perform the conversion
    host: ConvertServerHost,
}

#[derive(Debug, Default)]
pub enum ConvertServerHost {
    /// Local converter server
    #[default]
    Local,

    /// Remove converter server
    Remote { host: String, port: u16 },
}

/// Converts the provided input bytes from an office file format
/// into a pdf file
pub async fn office_to_pdf(
    input_bytes: &[u8],
    options: &ConvertOptions,
) -> Result<Vec<u8>, OfficeError> {
    // Ensure server is running
    if !is_unoserver_running() {
        start_unoserver().await?;
    }

    let mut args = Vec::<String>::new();

    match &options.host {
        ConvertServerHost::Local => {
            args.push("--host-location".to_string());
            args.push("local".to_string());
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

/// Check the conversion server is running
pub fn is_unoserver_running() -> bool {
    let system =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    let mut processes = system.processes_by_name("unoserver");

    processes.next().is_some()
}

/// Start the conversion server
///
/// Must be running in the background otherwise the unoconvert program
/// will hang waiting from a server to start
pub async fn start_unoserver() -> Result<AbortHandle, OfficeError> {
    // Timeout if the server didn't start within 5 minutes
    const STARTUP_TIMEOUT: Duration = Duration::from_secs(60 * 5);

    // Spawn the unoserver process
    let mut child = Command::new("unoserver")
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

    use crate::{office_to_pdf, start_unoserver, ConvertOptions, OfficeError};

    /// Tests the unoserver can be started
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_unoserver() {
        start_unoserver().await.unwrap();
    }

    /// Tests a sample docx
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_docx() {
        start_unoserver().await.unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-docx.docx").await.unwrap();
        let _output = office_to_pdf(&input_bytes, &ConvertOptions::default())
            .await
            .unwrap();
    }

    /// Tests a sample docx with an image
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_docx_with_image() {
        start_unoserver().await.unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-docx-with-image.docx")
            .await
            .unwrap();
        let _output = office_to_pdf(&input_bytes, &ConvertOptions::default())
            .await
            .unwrap();
    }

    /// Tests an encrypted docx
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_docx_encrypted() {
        start_unoserver().await.unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-docx-encrypted.docx")
            .await
            .unwrap();
        let err = office_to_pdf(&input_bytes, &ConvertOptions::default())
            .await
            .unwrap_err();

        assert!(matches!(err, OfficeError::EncryptedDocument))
    }

    /// Tests a sample xlsx
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_xlsx() {
        start_unoserver().await.unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-xlsx.xlsx").await.unwrap();
        let _output = office_to_pdf(&input_bytes, &ConvertOptions::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once"]
    async fn test_sample_xlsx_encrypted() {
        start_unoserver().await.unwrap();

        let input_bytes = tokio::fs::read("./samples/sample-xlsx-encrypted.xlsx")
            .await
            .unwrap();
        let err = office_to_pdf(&input_bytes, &ConvertOptions::default())
            .await
            .unwrap_err();

        assert!(matches!(err, OfficeError::EncryptedDocument))
    }

    /// Tests a sample docx
    #[tokio::test]
    #[ignore = "slow and resource intensive if these tests are run all at once, requires running remote instance"]
    async fn test_sample_docx_remote() {
        let input_bytes = tokio::fs::read("./samples/sample-docx.docx").await.unwrap();
        let _output = office_to_pdf(
            &input_bytes,
            &ConvertOptions {
                host: crate::ConvertServerHost::Remote {
                    host: "localhost".to_string(),
                    port: 9250,
                },
            },
        )
        .await
        .unwrap();
    }
}
