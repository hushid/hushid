use hushid::Glossary;
use hushid_proxy::Proxy;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut listen = "127.0.0.1:8078".to_string();
    let mut upstream = String::new();
    let mut vault_dir = env::var_os("HUSHID_VAULT_DIR").map(PathBuf::from);
    let mut glossary_path = env::var_os("HUSHID_GLOSSARY").map(PathBuf::from);
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        let Some(value) = args.next() else {
            eprintln!("missing value for {arg}");
            return ExitCode::from(2);
        };
        match arg.as_str() {
            "--listen" => listen = value,
            "--upstream" => upstream = value,
            "--vault-dir" => vault_dir = Some(PathBuf::from(value)),
            "--glossary" => glossary_path = Some(PathBuf::from(value)),
            _ => {
                eprintln!("unknown argument");
                return ExitCode::from(2);
            }
        }
    }
    if upstream.is_empty() {
        eprintln!("missing --upstream");
        return ExitCode::from(2);
    }
    let Some(vault_dir) = vault_dir else {
        eprintln!("missing --vault-dir");
        return ExitCode::from(2);
    };
    let glossary = match glossary_path {
        Some(path) => match Glossary::load(&path) {
            Ok(glossary) => glossary,
            Err(_) => {
                eprintln!("glossary");
                return ExitCode::from(2);
            }
        },
        None => Glossary::empty(),
    };
    let proxy = match Proxy::bind(&listen, &upstream, &vault_dir, glossary) {
        Ok(proxy) => proxy,
        Err(_) => {
            eprintln!("listen");
            return ExitCode::from(2);
        }
    };
    loop {
        if proxy.serve_one().is_err() {
            return ExitCode::from(1);
        }
    }
}
