use hushid::Glossary;
use hushid_proxy::Proxy;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
hushid-proxy --upstream URL --vault-dir DIR [--listen ADDR] [--glossary FILE]
  --listen ADDR     listen address, default 127.0.0.1:8078
  --upstream URL    required
  --vault-dir DIR   required, or HUSHID_VAULT_DIR
  --glossary FILE   optional, or HUSHID_GLOSSARY
";

fn fail(line: &str) -> ExitCode {
    eprintln!("{line}");
    eprint!("{USAGE}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut listen = "127.0.0.1:8078".to_string();
    let mut upstream = String::new();
    let mut vault_dir = env::var_os("HUSHID_VAULT_DIR").map(PathBuf::from);
    let mut glossary_path = env::var_os("HUSHID_GLOSSARY").map(PathBuf::from);
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            "--listen" => {
                let Some(value) = args.next() else {
                    return fail(&format!("missing value for {arg}"));
                };
                listen = value;
            }
            "--upstream" => {
                let Some(value) = args.next() else {
                    return fail(&format!("missing value for {arg}"));
                };
                upstream = value;
            }
            "--vault-dir" => {
                let Some(value) = args.next() else {
                    return fail(&format!("missing value for {arg}"));
                };
                vault_dir = Some(PathBuf::from(value));
            }
            "--glossary" => {
                let Some(value) = args.next() else {
                    return fail(&format!("missing value for {arg}"));
                };
                glossary_path = Some(PathBuf::from(value));
            }
            _ => return fail(&format!("unknown argument {arg}")),
        }
    }
    if upstream.is_empty() {
        return fail("missing --upstream");
    }
    let Some(vault_dir) = vault_dir else {
        return fail("missing --vault-dir");
    };
    let glossary = match glossary_path {
        Some(path) => match Glossary::load(&path) {
            Ok(glossary) => glossary,
            Err(err) => {
                eprintln!("glossary {}: {err}", path.display());
                return ExitCode::from(2);
            }
        },
        None => Glossary::empty(),
    };
    let proxy = match Proxy::bind(&listen, &upstream, &vault_dir, glossary) {
        Ok(proxy) => proxy,
        Err(err) => {
            eprintln!("listen {listen}: {err}");
            return ExitCode::from(2);
        }
    };
    loop {
        if let Err(err) = proxy.serve_one() {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    }
}
