use hushid::Glossary;
use hushid_proxy::mcp_message;
use std::env;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(vault_dir) = env::var_os("HUSHID_VAULT_DIR").map(PathBuf::from) else {
        eprintln!("missing HUSHID_VAULT_DIR");
        return ExitCode::from(2);
    };
    let glossary = match env::var_os("HUSHID_GLOSSARY").map(PathBuf::from) {
        Some(path) => match Glossary::load(&path) {
            Ok(glossary) => glossary,
            Err(err) => {
                eprintln!("glossary {}: {err}", path.display());
                return ExitCode::from(2);
            }
        },
        None => Glossary::empty(),
    };
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::stdout().lock();
    loop {
        let message = match read_frame(&mut input) {
            Ok(Some(message)) => message,
            Ok(None) => return ExitCode::SUCCESS,
            Err(word) => {
                eprintln!("{word}");
                return ExitCode::from(1);
            }
        };
        if let Some(response) = mcp_message(&vault_dir, &glossary, &message) {
            if write_frame(&mut stdout, &response).is_err() {
                return ExitCode::from(1);
            }
        }
    }
}

fn read_frame(input: &mut impl Read) -> Result<Option<String>, &'static str> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) if header.is_empty() => return Ok(None),
            Ok(0) | Err(_) => return Err("frame"),
            Ok(_) => header.push(byte[0]),
        }
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() > 1024 {
            return Err("frame");
        }
    }
    let text = std::str::from_utf8(&header).map_err(|_| "frame")?;
    let mut length = None;
    for line in text.split("\r\n") {
        if let Some(value) = line.strip_prefix("Content-Length:") {
            length = Some(value.trim().parse::<usize>().map_err(|_| "frame")?);
        }
    }
    let Some(length) = length else {
        return Err("frame");
    };
    let mut body = vec![0u8; length];
    input.read_exact(&mut body).map_err(|_| "frame")?;
    String::from_utf8(body).map(Some).map_err(|_| "frame")
}

fn write_frame(output: &mut impl Write, message: &str) -> io::Result<()> {
    write!(output, "Content-Length: {}\r\n\r\n{message}", message.len())?;
    output.flush()
}
