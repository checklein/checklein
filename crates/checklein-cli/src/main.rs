//! `checklein`: verify agent requests, serve forward-auth, run conformance vectors,
//! manage receipts.

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use checklein_core::ThresholdPolicy;
use checklein_core::encoding::{b64url_decode, hex, hex_decode, sha256_label};
use checklein_core::keys::{Jwk, Jwks, TrustList};
use checklein_core::receipt::{ReceiptChain, verify_chain};
use checklein_core::{Checklein, Decision, FixedClock, RequestView, StaticResolver};
use checklein_fetch::{DirectoryFetcher, FetchConfig, FetchingResolver};
use checklein_mcp::{JsonFetcher, McpConfig, McpOAuth};
use checklein_serve::ServeConfig;
use checklein_webbotauth::WebBotAuth;
use checklein_webbotauth::vectors::{Vector, run};
use clap::{Args, Parser, Subcommand};

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

/// Options shared by `verify` and `serve`: where keys come from and where receipts go.
#[derive(Args)]
struct VerifierArgs {
    /// Trust list JSON file. Repeatable; earlier lists take precedence.
    #[arg(long = "trust-list")]
    trust_lists: Vec<PathBuf>,
    /// Pre-fetched operator key directory: OPERATOR=jwks.json. Keys found only here stay at L1.
    #[arg(long = "directory")]
    directories: Vec<String>,
    /// Pinned key: OPERATOR=jwk.json.
    #[arg(long = "pin")]
    pins: Vec<String>,
    /// Fetch unknown operators' key directories live (HTTPS, public addresses only).
    /// Keys found this way stay at L1.
    #[arg(long)]
    fetch: bool,
    /// Append a signed receipt to this log (one JWS per line). Needs --receipt-key.
    #[arg(long, requires = "receipt_key")]
    receipts: Option<PathBuf>,
    /// File holding the 32-byte receipt-signing seed as hex (see `keygen`).
    #[arg(long)]
    receipt_key: Option<PathBuf>,
    /// Relying-party identifier recorded in receipts.
    #[arg(long, default_value = "urn:checklein:local")]
    rp: String,
    /// MCP OAuth config (JSON): resource identifiers, trusted issuers, subject key.
    /// Enables verification of `Authorization: Bearer` access tokens.
    #[arg(long = "mcp-config")]
    mcp_config: Option<PathBuf>,
    /// Require a user-delegated token (assurance 3); weaker requests get step_up (401 in serve).
    #[arg(long)]
    require_delegation: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify a raw HTTP/1.1 request (file path, or - for stdin) and print the verdict as JSON.
    Verify {
        request: String,
        /// Verification time (Unix seconds). Defaults to now.
        #[arg(long)]
        now: Option<i64>,
        /// Scheme the request arrived over.
        #[arg(long, default_value = "https")]
        scheme: String,
        #[command(flatten)]
        verifier: VerifierArgs,
    },
    /// Run a forward-auth server for nginx auth_request, Traefik ForwardAuth or Caddy forward_auth.
    ///
    /// Answers 200 (with Checklein-* headers) or 403. Forwarding headers are trusted:
    /// listen only where your proxy, and nothing else, can reach.
    Serve {
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:8787")]
        listen: String,
        /// Worker threads.
        #[arg(long, default_value_t = 4)]
        workers: usize,
        /// Also answer 403 for these decisions (repeatable): challenge, rate-limit, pass, step-up.
        #[arg(long = "deny-on")]
        deny_on: Vec<String>,
        /// Disable the per-request access log on stderr.
        #[arg(long)]
        quiet: bool,
        /// OAuth Protected Resource Metadata URL (RFC 9728) advertised in 401 responses.
        #[arg(long)]
        resource_metadata: Option<String>,
        #[command(flatten)]
        verifier: VerifierArgs,
    },
    /// Check a deployment: the `serve` endpoint directly, and/or the full path through
    /// your proxy to an endpoint that echoes request headers (for example traefik/whoami).
    ///
    /// Sends a spoofed agent, a request signed with the public RFC 9421 test key, a replay
    /// and forged Checklein-* headers. Exits non-zero if any check fails.
    Selftest {
        /// The `checklein serve` base URL. Default: http://127.0.0.1:8787 (when --via is absent).
        #[arg(long)]
        serve: Option<String>,
        /// A URL behind your proxy whose response echoes the request headers.
        #[arg(long)]
        via: Option<String>,
        /// Host the serve checks pretend the request was for.
        #[arg(long, default_value = "selftest.example")]
        host: String,
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

/// Issuer key fetching for the MCP adapter, through the SSRF-guarded fetcher.
struct GuardedJson(DirectoryFetcher);

impl JsonFetcher for GuardedJson {
    fn get(&self, url: &str) -> Result<(Vec<u8>, std::time::Duration), String> {
        self.0.get_json(url).map_err(|e| e.to_string())
    }
}

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

fn build(args: &VerifierArgs, now: Option<i64>) -> Res<Checklein> {
    let mut resolver = StaticResolver::new();
    for p in &args.pins {
        let (op, path) = split_pair(p)?;
        let jwk: Jwk = read_json(&path)?;
        resolver.pin(&jwk, Some(op)).map_err(|e| e.to_string())?;
    }
    for path in &args.trust_lists {
        let list: TrustList = read_json(path)?;
        resolver.load_trust_list(&list).map_err(|e| e.to_string())?;
    }
    for d in &args.directories {
        let (op, path) = split_pair(d)?;
        let jwks: Jwks = read_json(&path)?;
        resolver
            .add_directory(op, &jwks)
            .map_err(|e| e.to_string())?;
    }

    let ck = if args.fetch {
        Checklein::new(FetchingResolver::new(resolver, FetchConfig::default()))
    } else {
        Checklein::new(resolver)
    };
    let mut ck = ck.adapter(WebBotAuth::default());
    if let Some(path) = &args.mcp_config {
        let cfg: McpConfig = read_json(path)?;
        let needs_fetch = cfg.issuers.iter().any(|i| i.jwks_uri.is_some());
        let mut mcp = McpOAuth::new(cfg).map_err(|e| format!("{}: {e}", path.display()))?;
        if needs_fetch {
            mcp = mcp.with_fetcher(Arc::new(GuardedJson(DirectoryFetcher::new(
                FetchConfig::default(),
            ))));
        }
        ck = ck.adapter(mcp);
    }
    if args.require_delegation {
        ck = ck.policy(ThresholdPolicy {
            require_delegation: true,
            ..ThresholdPolicy::default()
        });
    }
    if let Some(t) = now {
        ck = ck.clock(FixedClock(t));
    }
    if let (Some(log), Some(key)) = (&args.receipts, &args.receipt_key) {
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
        ck = ck.receipts(&args.rp, chain.with_sink(Box::new(file)));
    }
    Ok(ck)
}

fn real_main(cli: Cli) -> Res<ExitCode> {
    match cli.cmd {
        Cmd::Verify {
            request,
            now,
            scheme,
            verifier,
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
            let verdict = build(&verifier, now)?
                .verify(&req)
                .map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&verdict).map_err(|e| e.to_string())?
            );
            Ok(ExitCode::SUCCESS)
        }

        Cmd::Serve {
            listen,
            workers,
            deny_on,
            quiet,
            resource_metadata,
            verifier,
        } => {
            if let Some(url) = &resource_metadata
                && (!url.starts_with("https://") || url.contains(['"', ' ', ',', '\\']))
            {
                return Err(format!(
                    "--resource-metadata must be an https URL without quotes, spaces or commas: {url:?}"
                ));
            }
            let deny_on = deny_on
                .iter()
                .map(|d| Decision::parse(d).ok_or_else(|| format!("unknown decision {d:?}")))
                .collect::<Res<Vec<_>>>()?;
            let ck = Arc::new(build(&verifier, None)?);
            let cfg = ServeConfig {
                listen,
                workers,
                deny_on,
                access_log: !quiet,
                resource_metadata,
            };
            let running = checklein_serve::start(ck, cfg).map_err(|e| e.to_string())?;
            eprintln!(
                "checklein forward-auth listening on http://{}",
                running.addr
            );
            running.join();
            Ok(ExitCode::SUCCESS)
        }

        Cmd::Selftest { serve, via, host } => {
            use checklein_serve::selftest::{Outcome, check_serve, check_via};
            let serve = match (&serve, &via) {
                (None, None) => Some("http://127.0.0.1:8787".to_string()),
                _ => serve,
            };
            let mut checks = Vec::new();
            if let Some(url) = &serve {
                checks.extend(check_serve(url, &host));
            }
            if let Some(url) = &via {
                checks.extend(check_via(url));
            }
            let (mut pass, mut fail, mut skip) = (0, 0, 0);
            for c in &checks {
                let tag = match c.outcome {
                    Outcome::Pass => {
                        pass += 1;
                        "PASS"
                    }
                    Outcome::Fail => {
                        fail += 1;
                        "FAIL"
                    }
                    Outcome::Skip => {
                        skip += 1;
                        "SKIP"
                    }
                };
                println!("{tag}  {}  ({})", c.name, c.detail);
            }
            println!("\n{pass} passed, {fail} failed, {skip} skipped");
            Ok(if fail == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
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
                // Two vector families: MCP OAuth (has `mcp_config`) and Web Bot Auth.
                let raw: serde_json::Value = read_json(path)?;
                let (name, result) = if raw.get("mcp_config").is_some() {
                    let v: checklein_mcp::vectors::Vector = serde_json::from_value(raw)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    (v.name.clone(), checklein_mcp::vectors::run(&v).map(|_| ()))
                } else {
                    let v: Vector = serde_json::from_value(raw)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    (v.name.clone(), run(&v).map(|_| ()))
                };
                match result {
                    Ok(()) => println!("ok    {name}"),
                    Err(e) => {
                        failed += 1;
                        println!("FAIL  {name}: {e}");
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
