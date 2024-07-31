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
use tokio::{io::AsyncWriteExt, process::Command, time::sleep};

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

    /// Converter program returned an error
    #[error("converter returned error: {0}")]
    ConverterError(String),
}

/// Converts the provided input bytes from an office file format
/// into a pdf file
pub async fn office_to_pdf(input_bytes: &[u8]) -> Result<Vec<u8>, OfficeError> {
    // Ensure server is running
    if !is_unoserver_running() {
        start_unoserver().await?;
    }

    // Spawn the unoconvert process
    let mut child = Command::new("unoconvert")
        .args(["--convert-to", "pdf", "-", "-"])
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
pub async fn start_unoserver() -> Result<(), OfficeError> {
    Command::new("unoserver")
        .spawn()
        .map_err(OfficeError::StartConverterServer)?;

    // Wait for unoserver to initialize
    sleep(Duration::from_secs(5)).await;
    Ok(())
}
