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
            Err(_) => return ExitCode::from(2),
        },
        None => Glossary::empty(),
    };
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut stdout = io::stdout().lock();
    loop {
        let Some(message) = read_frame(&mut input) else {
            return ExitCode::SUCCESS;
        };
        if let Some(response) = mcp_message(&vault_dir, &glossary, &message) {
            if write_frame(&mut stdout, &response).is_err() {
                return ExitCode::from(1);
            }
        }
    }
}

fn read_frame(input: &mut impl Read) -> Option<String> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if input.read(&mut byte).ok()? == 0 {
            return None;
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
        if header.len() > 1024 {
            return None;
        }
    }
    let text = std::str::from_utf8(&header).ok()?;
    let mut length = 0usize;
    for line in text.split("\r\n") {
        if let Some(value) = line.strip_prefix("Content-Length:") {
            length = value.trim().parse().ok()?;
        }
    }
    let mut body = vec![0u8; length];
    input.read_exact(&mut body).ok()?;
    String::from_utf8(body).ok()
}

fn write_frame(output: &mut impl Write, message: &str) -> io::Result<()> {
    write!(output, "Content-Length: {}\r\n\r\n{message}", message.len())?;
    output.flush()
}
