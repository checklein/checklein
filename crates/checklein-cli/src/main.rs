//! `checklein`: verify agent requests, run conformance vectors, manage receipts.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use checklein_core::encoding::{b64url_decode, hex, hex_decode, sha256_label};
use checklein_core::keys::{Jwk, Jwks, TrustList};
use checklein_core::receipt::{ReceiptChain, verify_chain};
use checklein_core::{Checklein, FixedClock, RequestView, StaticResolver};
use checklein_fetch::{FetchConfig, FetchingResolver};
use checklein_webbotauth::WebBotAuth;
use checklein_webbotauth::vectors::{Vector, run};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "checklein",
    version,
    about = "Open-source verifier for AI agent traffic"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify a raw HTTP/1.1 request (file path, or - for stdin) and print the verdict as JSON.
    Verify {
        request: String,
        /// Trust list JSON file. Repeatable; earlier lists take precedence.
        #[arg(long = "trust-list")]
        trust_lists: Vec<PathBuf>,
        /// Pre-fetched operator key directory: OPERATOR=jwks.json. Keys found only here stay at L1.
        #[arg(long = "directory")]
        directories: Vec<String>,
        /// Pinned key: OPERATOR=jwk.json.
        #[arg(long = "pin")]
        pins: Vec<String>,
        /// Verification time (Unix seconds). Defaults to now.
        #[arg(long)]
        now: Option<i64>,
        /// Scheme the request arrived over.
        #[arg(long, default_value = "https")]
        scheme: String,
        /// Append a signed receipt to this log (one JWS per line). Needs --receipt-key.
        #[arg(long, requires = "receipt_key")]
        receipts: Option<PathBuf>,
        /// File holding the 32-byte receipt-signing seed as hex (see `keygen`).
        #[arg(long)]
        receipt_key: Option<PathBuf>,
        /// Relying-party identifier recorded in receipts.
        #[arg(long, default_value = "urn:checklein:local")]
        rp: String,
        /// Fetch unknown operators' key directories live (HTTPS, public addresses only).
        /// Keys found this way stay at L1.
        #[arg(long)]
        fetch: bool,
    },
    /// Run every *.json conformance vector in a directory.
    Conformance { dir: PathBuf },
    /// Verify signatures and hash links of a receipt log.
    VerifyChain {
        log: PathBuf,
        /// Receipt-signing public key, base64url (printed by `keygen`).
        #[arg(long)]
        public_key: String,
    },
    /// Generate a receipt-signing key. Writes the secret seed (hex) to --out and prints the public JWK.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    match real_main(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

type Res<T> = Result<T, String>;

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Res<T> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn split_pair(s: &str) -> Res<(&str, PathBuf)> {
    let (op, path) = s
        .split_once('=')
        .ok_or_else(|| format!("expected OPERATOR=path, got {s:?}"))?;
    Ok((op, PathBuf::from(path)))
}

fn read_seed(path: &Path) -> Res<[u8; 32]> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    hex_decode(&text)
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| format!("{}: expected 64 hex characters", path.display()))
}

fn real_main(cli: Cli) -> Res<ExitCode> {
    match cli.cmd {
        Cmd::Verify {
            request,
            trust_lists,
            directories,
            pins,
            now,
            scheme,
            receipts,
            receipt_key,
            rp,
            fetch,
        } => {
            let raw = if request == "-" {
                let mut s = String::new();
                std::io::stdin()
                    .read_to_string(&mut s)
                    .map_err(|e| e.to_string())?;
                s
            } else {
                fs::read_to_string(&request).map_err(|e| format!("{request}: {e}"))?
            };
            let req = RequestView::parse_http1(&raw, &scheme).map_err(|e| e.to_string())?;

            let mut resolver = StaticResolver::new();
            for p in &pins {
                let (op, path) = split_pair(p)?;
                let jwk: Jwk = read_json(&path)?;
                resolver.pin(&jwk, Some(op)).map_err(|e| e.to_string())?;
            }
            for path in &trust_lists {
                let list: TrustList = read_json(path)?;
                resolver.load_trust_list(&list).map_err(|e| e.to_string())?;
            }
            for d in &directories {
                let (op, path) = split_pair(d)?;
                let jwks: Jwks = read_json(&path)?;
                resolver
                    .add_directory(op, &jwks)
                    .map_err(|e| e.to_string())?;
            }

            let ck = if fetch {
                Checklein::new(FetchingResolver::new(resolver, FetchConfig::default()))
            } else {
                Checklein::new(resolver)
            };
            let mut ck = ck.adapter(WebBotAuth::default());
            if let Some(t) = now {
                ck = ck.clock(FixedClock(t));
            }
            if let (Some(log), Some(key)) = (&receipts, &receipt_key) {
                let mut chain = ReceiptChain::new(read_seed(key)?);
                if let Some(last) = fs::read_to_string(log)
                    .ok()
                    .and_then(|s| s.lines().last().map(str::to_string))
                {
                    chain = chain.resume(sha256_label(last.as_bytes()));
                }
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(log)
                    .map_err(|e| format!("{}: {e}", log.display()))?;
                ck = ck.receipts(&rp, chain.with_sink(Box::new(file)));
            }

            let verdict = ck.verify(&req).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verdict).map_err(|e| e.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }

        Cmd::Conformance { dir } => {
            let mut paths: Vec<_> = fs::read_dir(&dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "json"))
                .collect();
            paths.sort();
            let mut failed = 0;
            for path in &paths {
                let v: Vector = read_json(path)?;
                match run(&v) {
                    Ok(_) => println!("ok    {}", v.name),
                    Err(e) => {
                        failed += 1;
                        println!("FAIL  {}: {e}", v.name);
                    }
                }
            }
            println!("\n{} passed, {failed} failed", paths.len() - failed);
            Ok(if failed == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }

        Cmd::VerifyChain { log, public_key } => {
            let pk: [u8; 32] = b64url_decode(&public_key)
                .and_then(|v| v.try_into().ok())
                .ok_or("public key must be 32 bytes, base64url")?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|e| e.to_string())?;
            let text = fs::read_to_string(&log).map_err(|e| format!("{}: {e}", log.display()))?;
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            match verify_chain(&lines, &vk) {
                Ok(receipts) => {
                    println!("ok: {} receipts, chain intact", receipts.len());
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    println!("FAIL: {e}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }

        Cmd::Keygen { out } => {
            if out.exists() {
                return Err(format!(
                    "{} already exists; refusing to overwrite a key",
                    out.display()
                ));
            }
            let mut seed = [0u8; 32];
            fs::File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut seed))
                .map_err(|e| format!("reading /dev/urandom: {e}"))?;
            fs::write(&out, hex(&seed) + "\n").map_err(|e| format!("{}: {e}", out.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&out, fs::Permissions::from_mode(0o600));
            }
            let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            println!(
                "{}",
                serde_json::to_string_pretty(&Jwk::from_ed25519(&vk.to_bytes()))
                    .map_err(|e| e.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}
