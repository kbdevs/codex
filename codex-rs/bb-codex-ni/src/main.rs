use std::fs;
use std::fs::File;
use std::io::Write;
use std::net::TcpListener;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use codex_arg0::Arg0DispatchPaths;
use codex_arg0::arg0_dispatch_or_else;
use codex_protocol::protocol::MAX_THREAD_GOAL_OBJECTIVE_CHARS;
use codex_utils_cli::CliConfigOverrides;
use serde::Deserialize;

const RUN_METADATA_FILE: &str = ".bb-run.env";
const DEFAULT_PEAK_WEBSITES_API: &str = "https://peaksecurity.us/api/websites";
const DEFAULT_PEAK_DEDUP_KEYS: &str = "dennis,nickita";
const DEFAULT_PEAK_ADD_KEY: &str = "karsten";
const DEFAULT_WRAP_UP_PROMPT: &str = "The hard runtime limit for this non-interactive security test has been reached. Stop all further exploration now. Inspect the current directory, notes, logs, and artifacts that already exist, then write or update report.md in this directory with the best report possible from the work completed so far. Include confirmed findings with evidence, tested areas, dead ends, limitations, and recommended follow-up checks. If no vulnerability was confirmed, state that clearly. Do not continue testing after report.md is written.";
const DEFAULT_AUTHORIZATION: &str = r#"# Authorization

This document authorizes aggressive security testing for the bug bounty program associated with the mapped target. The bearer is authorized to perform black-box penetration testing against all in-scope surfaces exposed through this local Blackbox manual mapping, including application endpoints, APIs, authentication flows, client-side surfaces, and related attack surface that belongs to the target program.

Testing must remain limited to assets that are in scope for the target's bug bounty program and must avoid intentionally harming third parties, exfiltrating unrelated data, or persisting unauthorized access beyond what is necessary to demonstrate impact.
"#;

#[derive(Debug)]
enum BbCodexNiCommand {
    AuthStatus,
    Run(BbCodexNiRunArgs),
    WrapUp(BbCodexNiWrapUpArgs),
}

#[derive(Debug)]
struct BbCodexNiRunArgs {
    target_input: String,
    free: bool,
    goal: Option<String>,
    human: bool,
    exec_args: Vec<String>,
}

#[derive(Debug)]
struct BbCodexNiWrapUpArgs {
    prompt: String,
    goal: Option<String>,
    human: bool,
    exec_args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecMode {
    New,
    ResumeLast,
}

#[derive(Parser, Debug)]
struct ExecTopCli {
    #[clap(flatten)]
    config_overrides: CliConfigOverrides,

    #[clap(flatten)]
    inner: codex_exec::Cli,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpencodeAccountRegistry {
    accounts: Vec<OpencodeAccount>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OpencodeAccount {
    id: String,
    #[serde(rename = "type")]
    account_type: String,
    account_id: String,
    email: Option<String>,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    auth_invalid: bool,
    rate_limited_until: Option<u64>,
}

struct ProxyGuard {
    child: Child,
}

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn main() -> Result<()> {
    arg0_dispatch_or_else(|arg0_paths| async move { run(arg0_paths).await })
}

async fn run(arg0_paths: Arg0DispatchPaths) -> Result<()> {
    let command = parse_args()?;
    let home_dir = home_dir()?;
    let args = match command {
        BbCodexNiCommand::AuthStatus => {
            print_dev_auth_status(&home_dir)?;
            return Ok(());
        }
        BbCodexNiCommand::WrapUp(args) => {
            run_codex_wrap_up(arg0_paths, args).await?;
            return Ok(());
        }
        BbCodexNiCommand::Run(args) => args,
    };

    let workspace_root =
        env_path("BB_WORKSPACE_ROOT").unwrap_or_else(|| home_dir.join("pentesting"));
    let support_dir =
        env_path("BB_SUPPORT_DIR").unwrap_or_else(|| home_dir.join(".config").join("blackbox-cli"));
    let authorization_file = env_path("BB_AUTHORIZATION_FILE")
        .unwrap_or_else(|| workspace_root.join("authorization.md"));

    fs::create_dir_all(&workspace_root)?;
    fs::create_dir_all(&support_dir)?;
    ensure_authorization_file(&authorization_file)?;

    let target_domain = normalize_domain(&args.target_input)?;
    check_peak_security_lists(&args.target_input, &target_domain)?;
    maybe_enter_target_subdir(&target_domain)?;

    let default_prompt_file = if args.free {
        workspace_root.join("free.md")
    } else {
        workspace_root.join("prompt.md")
    };
    let prompt_file = env_path("BB_PROMPT_FILE").unwrap_or(default_prompt_file);
    ensure_prompt_file(&prompt_file)?;

    let local_port = pick_random_port()?;
    let localhost_url = format!("https://localhost:{local_port}/");
    let prompt_url = format!("https://localhost:{local_port}");
    let metadata_path = std::env::current_dir()?.join(RUN_METADATA_FILE);
    write_run_metadata(
        &metadata_path,
        &args.target_input,
        &target_domain,
        &localhost_url,
        &prompt_url,
    )?;

    let proxy = start_proxy(
        &support_dir,
        &target_domain,
        local_port,
        &authorization_file,
    )
    .context("failed to start Blackbox proxy")?;

    eprintln!("bb-codex-ni: proxy created for {target_domain}");
    eprintln!("bb-codex-ni: localhost URL: {localhost_url}");
    eprintln!("bb-codex-ni: run metadata: {}", metadata_path.display());

    let local_prompt_file = std::env::current_dir()?.join("prompt.md");
    write_local_prompt(&prompt_file, &local_prompt_file, &prompt_url)?;
    eprintln!(
        "bb-codex-ni: local prompt written to {}",
        local_prompt_file.display()
    );

    let startup_prompt = startup_prompt(&prompt_url, args.free);
    let goal = args
        .goal
        .as_deref()
        .map(str::trim)
        .filter(|goal| !goal.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| thread_goal_objective_for_prompt(&startup_prompt));

    if args.free {
        eprintln!("bb-codex-ni: free mode enabled; using free prompt file");
    }
    eprintln!("bb-codex-ni: prompt loaded from {}", prompt_file.display());
    if !args.human {
        eprintln!(
            "bb-codex-ni: streaming codex exec events as JSONL; pass --human for final-answer output only"
        );
    }

    run_codex_exec(arg0_paths, args.exec_args, startup_prompt, goal, args.human).await?;
    drop(proxy);
    Ok(())
}

async fn run_codex_wrap_up(arg0_paths: Arg0DispatchPaths, args: BbCodexNiWrapUpArgs) -> Result<()> {
    let goal = args
        .goal
        .as_deref()
        .map(str::trim)
        .filter(|goal| !goal.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "Finalize report.md from the current run artifacts".to_string());
    eprintln!("bb-codex-ni: resuming latest session to write report.md");
    run_codex_exec_with_mode(
        arg0_paths,
        args.exec_args,
        args.prompt,
        goal,
        args.human,
        ExecMode::ResumeLast,
    )
    .await
}

async fn run_codex_exec(
    arg0_paths: Arg0DispatchPaths,
    exec_args: Vec<String>,
    prompt: String,
    goal: String,
    human: bool,
) -> Result<()> {
    run_codex_exec_with_mode(arg0_paths, exec_args, prompt, goal, human, ExecMode::New).await
}

async fn run_codex_exec_with_mode(
    arg0_paths: Arg0DispatchPaths,
    exec_args: Vec<String>,
    prompt: String,
    goal: String,
    human: bool,
    mode: ExecMode,
) -> Result<()> {
    let argv = build_exec_argv_for_mode(exec_args, prompt, human, mode);
    let top_cli = ExecTopCli::try_parse_from(argv)?;
    let mut exec_cli = top_cli.inner;
    exec_cli
        .config_overrides
        .prepend_root_overrides(top_cli.config_overrides);
    exec_cli
        .config_overrides
        .raw_overrides
        .push("model_reasoning_summary=detailed".to_string());
    exec_cli
        .config_overrides
        .raw_overrides
        .push("model_supports_reasoning_summaries=true".to_string());
    exec_cli
        .config_overrides
        .raw_overrides
        .push("features.goals=true".to_string());
    exec_cli.goal = Some(goal);

    codex_exec::run_main(exec_cli, arg0_paths).await
}

#[cfg(test)]
fn build_exec_argv(exec_args: Vec<String>, prompt: String, human: bool) -> Vec<String> {
    build_exec_argv_for_mode(exec_args, prompt, human, ExecMode::New)
}

#[cfg(test)]
fn build_resume_exec_argv(exec_args: Vec<String>, prompt: String, human: bool) -> Vec<String> {
    build_exec_argv_for_mode(exec_args, prompt, human, ExecMode::ResumeLast)
}

fn build_exec_argv_for_mode(
    exec_args: Vec<String>,
    prompt: String,
    human: bool,
    mode: ExecMode,
) -> Vec<String> {
    let mut argv = vec![
        "bb-codex-ni".to_string(),
        "--dangerously-bypass-approvals-and-sandbox".to_string(),
    ];
    if !human && !exec_args.iter().any(|arg| arg == "--json") {
        argv.push("--json".to_string());
    }
    argv.extend(exec_args);
    if mode == ExecMode::ResumeLast {
        argv.push("resume".to_string());
        argv.push("--last".to_string());
    }
    argv.push(prompt);
    argv
}

fn parse_args() -> Result<BbCodexNiCommand> {
    let mut raw = std::env::args().skip(1).collect::<Vec<_>>();
    if raw.iter().any(|value| value == "-h" || value == "--help") || raw.is_empty() {
        print_usage();
        if raw.is_empty() {
            anyhow::bail!("missing target");
        }
        std::process::exit(0);
    }

    if raw.first().is_some_and(|value| value == "auth-status") {
        if raw.len() > 1 {
            print_usage();
            anyhow::bail!("auth-status does not accept extra arguments");
        }
        return Ok(BbCodexNiCommand::AuthStatus);
    }

    if raw.first().is_some_and(|value| value == "wrap-up") {
        raw.remove(0);
        return parse_wrap_up_args(raw).map(BbCodexNiCommand::WrapUp);
    }

    parse_run_args(raw).map(BbCodexNiCommand::Run)
}

fn split_exec_args(raw: &mut Vec<String>) -> Vec<String> {
    if let Some(separator) = raw.iter().position(|value| value == "--") {
        let exec_args = raw.split_off(separator + 1);
        raw.pop();
        exec_args
    } else {
        Vec::new()
    }
}

fn parse_wrap_up_args(mut raw: Vec<String>) -> Result<BbCodexNiWrapUpArgs> {
    let exec_args = split_exec_args(&mut raw);
    let mut goal = None;
    let mut human = false;
    let mut prompt_parts = Vec::new();
    let mut index = 0;
    while index < raw.len() {
        let value = &raw[index];
        if value == "--goal" {
            index += 1;
            let Some(next) = raw.get(index) else {
                print_usage();
                anyhow::bail!("--goal requires a value");
            };
            goal = Some(next.clone());
        } else if let Some(next) = value.strip_prefix("--goal=") {
            goal = Some(next.to_string());
        } else if value == "--human" {
            human = true;
        } else if value.starts_with('-') {
            print_usage();
            anyhow::bail!(
                "unknown bb-codex-ni wrap-up argument: {value}; put codex exec args after --"
            );
        } else {
            prompt_parts.push(value.trim().to_string());
        }
        index += 1;
    }
    let prompt = if prompt_parts.is_empty() {
        DEFAULT_WRAP_UP_PROMPT.to_string()
    } else {
        prompt_parts.join(" ")
    };

    Ok(BbCodexNiWrapUpArgs {
        prompt,
        goal,
        human,
        exec_args,
    })
}

fn parse_run_args(mut raw: Vec<String>) -> Result<BbCodexNiRunArgs> {
    let exec_args = split_exec_args(&mut raw);
    let mut target_input = None;
    let mut free = false;
    let mut goal = None;
    let mut human = false;
    let mut index = 0;
    while index < raw.len() {
        let value = &raw[index];
        if value == "--goal" {
            index += 1;
            let Some(next) = raw.get(index) else {
                print_usage();
                anyhow::bail!("--goal requires a value");
            };
            goal = Some(next.clone());
        } else if let Some(next) = value.strip_prefix("--goal=") {
            goal = Some(next.to_string());
        } else if value == "--human" {
            human = true;
        } else if value == "free" {
            free = true;
        } else if value.starts_with('-') {
            print_usage();
            anyhow::bail!("unknown bb-codex-ni argument: {value}; put codex exec args after --");
        } else if target_input.is_none() {
            target_input = Some(value.trim().to_string());
        } else {
            print_usage();
            anyhow::bail!("unexpected argument: {value}");
        }
        index += 1;
    }

    Ok(BbCodexNiRunArgs {
        target_input: target_input.context("missing target")?,
        free,
        goal,
        human,
        exec_args,
    })
}

fn print_usage() {
    eprintln!(
        "Usage: bb-codex-ni <target-domain-or-url|auth-status> [free] [--goal GOAL] [--human] [-- <codex exec options>]"
    );
    eprintln!(
        "       bb-codex-ni wrap-up [--goal GOAL] [--human] [PROMPT] [-- <codex exec options>]"
    );
    eprintln!("Example: bb-codex-ni example.com --goal 'Find an auth bypass'");
    eprintln!("Example: bb-codex-ni example.com free -- -o result.jsonl");
    eprintln!("Example: bb-codex-ni example.com --human");
    eprintln!("Example: bb-codex-ni wrap-up");
    eprintln!("Example: bb-codex-ni auth-status");
}

fn print_dev_auth_status(home_dir: &Path) -> Result<()> {
    let accounts = load_opencode_accounts(home_dir)?;
    println!(
        "bb-codex-ni: native multi-account registry accounts={}",
        accounts.len()
    );
    for account in accounts {
        let limited = account
            .rate_limited_until
            .is_some_and(|until| until > unix_timestamp_millis());
        println!(
            "{} type={} email={} account_id={} enabled={} auth_invalid={} rate_limited={}",
            account.id,
            account.account_type,
            account.email.as_deref().unwrap_or("unknown"),
            account.account_id,
            account.enabled,
            account.auth_invalid,
            limited
        );
    }
    Ok(())
}

fn load_opencode_accounts(home_dir: &Path) -> Result<Vec<OpencodeAccount>> {
    let path = std::env::var_os("BB_CODEX_ACCOUNTS_FILE")
        .or_else(|| std::env::var_os("BB_CODEX_DEV_ACCOUNTS_FILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            home_dir
                .join(".config")
                .join("opencode")
                .join("codex-accounts.json")
        });
    let raw = fs::read_to_string(&path).with_context(|| {
        format!(
            "failed to read OpenCode account registry {}",
            path.display()
        )
    })?;
    let registry: OpencodeAccountRegistry = serde_json::from_str(&raw).with_context(|| {
        format!(
            "failed to parse OpenCode account registry {}",
            path.display()
        )
    })?;
    Ok(registry.accounts)
}

fn check_peak_security_lists(target_input: &str, target_domain: &str) -> Result<()> {
    if std::env::var("BB_SKIP_PEAK_SECURITY").is_ok_and(|value| value == "1" || value == "true") {
        eprintln!("bb-codex-ni: skipping Peak Security check by environment request");
        return Ok(());
    }

    let websites_api = std::env::var("BB_PEAK_WEBSITES_API")
        .unwrap_or_else(|_| DEFAULT_PEAK_WEBSITES_API.to_string());
    let dedup_keys =
        std::env::var("BB_PEAK_DEDUP_KEYS").unwrap_or_else(|_| DEFAULT_PEAK_DEDUP_KEYS.to_string());
    let add_key =
        std::env::var("BB_PEAK_ADD_KEY").unwrap_or_else(|_| DEFAULT_PEAK_ADD_KEY.to_string());

    let Some(python3) = resolve_bin("BB_PYTHON_BIN", "python3", &["/usr/bin/python3"]) else {
        eprintln!("bb-codex-ni: warning: python3 not found; skipping Peak Security dedup check");
        return Ok(());
    };

    let mut child = Command::new(python3)
        .arg("-")
        .arg(target_input)
        .arg(target_domain)
        .arg(websites_api)
        .arg(dedup_keys)
        .arg(add_key)
        .stdin(Stdio::piped())
        .spawn()?;
    if let Some(mut child_stdin) = child.stdin.take() {
        child_stdin.write_all(peak_security_script().as_bytes())?;
    }
    let status = child.wait()?;

    match status.code() {
        Some(0) => {
            eprint!("bb-codex-ni: press Enter to run anyway, or Ctrl-C to stop. ");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
        }
        Some(1) => {}
        Some(code) => {
            eprintln!("bb-codex-ni: warning: Peak Security check exited with status {code}")
        }
        None => eprintln!("bb-codex-ni: warning: Peak Security check was interrupted"),
    }
    Ok(())
}

fn peak_security_script() -> &'static str {
    r#"import json
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

target_input, target_domain, websites_api, dedup_keys, add_key = sys.argv[1:6]


def normalize_host(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    host = (urlparse(value).hostname or "").strip().lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def bulk_check(key: str, domains: list[str]):
    url = f"{websites_api.rstrip('/')}/bulk?{urlencode({'key': key})}"
    payload = json.dumps({"action": "check", "domains": domains}).encode("utf-8")
    request = Request(
        url,
        data=payload,
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "curl/8.0.0"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def bulk_add(key: str, domains: list[str]):
    url = f"{websites_api.rstrip('/')}/bulk?{urlencode({'key': key})}"
    payload = json.dumps({"action": "add", "domains": domains, "pwned": False}).encode("utf-8")
    request = Request(
        url,
        data=payload,
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "curl/8.0.0"},
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def existing_hosts(data, owner_key: str):
    def item_exists(item):
        if not isinstance(item, dict):
            return False
        if item.get("exists") is True:
            return True
        if owner_key and item.get(owner_key) is True:
            return True
        return False

    if isinstance(data, dict) and isinstance(data.get("results"), list):
        for item in data["results"]:
            if not item_exists(item):
                continue
            for field in ("domain", "website", "host", "url"):
                value = item.get(field)
                if isinstance(value, str):
                    yield value
        return

    if isinstance(data, dict):
        for map_key, value in data.items():
            if isinstance(map_key, str) and value is True:
                yield map_key
            elif isinstance(map_key, str) and item_exists(value):
                yield map_key
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str):
                yield item
            elif item_exists(item):
                for field in ("domain", "website", "host", "url"):
                    value = item.get(field)
                    if isinstance(value, str):
                        yield value


target_hosts = {normalize_host(target_input), normalize_host(target_domain)}
target_hosts.discard("")

try:
    keys = [key.strip() for key in dedup_keys.split(",") if key.strip()]
    self_key = add_key.strip()
    check_keys = list(dict.fromkeys(keys + ([self_key] if self_key else [])))
    if not check_keys:
        print("bb-codex-ni: warning: no Peak Security dedup keys configured", file=sys.stderr)
        raise SystemExit(1)

    domains = sorted(target_hosts)
    last_error = None
    checked_keys = []
    for key in check_keys:
        try:
            data = bulk_check(key, domains)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            last_error = exc
            continue
        checked_keys.append(key)

        for value in existing_hosts(data, key):
            host = normalize_host(value)
            if not host and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/.*)?$", value.strip(), re.I):
                host = normalize_host(value)
            if host in target_hosts:
                owner = "you" if self_key and key == self_key else key
                print(f"bb-codex-ni: skipping {target_domain}; target is already listed for {owner} in Peak Security")
                raise SystemExit(0)

    if checked_keys and add_key.strip():
        try:
            bulk_add(add_key.strip(), [target_domain])
            print(f"bb-codex-ni: added {target_domain} to Peak Security for {add_key.strip()}")
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
            print(f"bb-codex-ni: warning: could not add {target_domain} to Peak Security for {add_key.strip()}: {exc}", file=sys.stderr)

    if last_error is not None:
        print(f"bb-codex-ni: warning: could not check Peak Security dedup lists: {last_error}", file=sys.stderr)
except SystemExit:
    raise

raise SystemExit(1)
"#
}

fn thread_goal_objective_for_prompt(prompt: &str) -> String {
    let prompt = prompt.trim();
    if prompt.chars().count() <= MAX_THREAD_GOAL_OBJECTIVE_CHARS {
        return prompt.to_string();
    }
    prompt
        .chars()
        .take(MAX_THREAD_GOAL_OBJECTIVE_CHARS)
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn render_prompt_template(prompt_file: &Path, prompt_url: &str) -> Result<String> {
    let template = match std::env::var("BB_CODEX_PROMPT") {
        Ok(prompt) => prompt,
        Err(_) => fs::read_to_string(prompt_file)
            .with_context(|| format!("failed to read prompt file {}", prompt_file.display()))?,
    };
    Ok(template
        .replace("{{LOCALHOST_URL}}", prompt_url)
        .replace("{localhostURL}", prompt_url)
        .replace("$LOCALHOST_URL", prompt_url))
}

fn write_local_prompt(
    source_prompt_file: &Path,
    local_prompt_file: &Path,
    prompt_url: &str,
) -> Result<()> {
    let prompt = render_prompt_template(source_prompt_file, prompt_url)?;
    fs::write(local_prompt_file, prompt).with_context(|| {
        format!(
            "failed to write local prompt file {}",
            local_prompt_file.display()
        )
    })?;
    Ok(())
}

fn startup_prompt(prompt_url: &str, free_mode: bool) -> String {
    let mut prompt = format!(
        "Follow the instructions in the local prompt.md file in this directory. Your authorization is at {prompt_url}/authorization.md."
    );
    if free_mode {
        prompt.push_str(" Focus on free product vulns.");
    }
    prompt
}

fn start_proxy(
    support_dir: &Path,
    target_domain: &str,
    local_port: u16,
    authorization_file: &Path,
) -> Result<ProxyGuard> {
    let mitmdump = resolve_bin(
        "BB_MITMDUMP_BIN",
        "mitmdump",
        &["/opt/homebrew/bin/mitmdump", "/usr/local/bin/mitmdump"],
    )
    .context("mitmdump not found. Install mitmproxy first or set BB_MITMDUMP_BIN")?;
    let safe_target = safe_name(target_domain);
    let proxy_script = support_dir.join(format!("bb-codex-ni-{safe_target}-{local_port}.py"));
    let proxy_log = support_dir.join(format!("bb-codex-ni-{safe_target}-{local_port}.log"));
    fs::write(&proxy_script, proxy_script_source())?;

    let stdout = File::create(&proxy_log)?;
    let stderr = stdout.try_clone()?;
    let mut child = Command::new(mitmdump)
        .arg("-q")
        .arg("-s")
        .arg(&proxy_script)
        .arg("--listen-host")
        .arg("127.0.0.1")
        .arg("--listen-port")
        .arg(local_port.to_string())
        .env("BLACKBOX_MANUAL_TARGET_DOMAIN", target_domain)
        .env("BLACKBOX_MANUAL_LOCAL_PORT", local_port.to_string())
        .env("BLACKBOX_MANUAL_AUTHORIZATION_PATH", authorization_file)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()?;

    std::thread::sleep(Duration::from_secs(1));
    if let Some(status) = child.try_wait()? {
        anyhow::bail!(
            "proxy exited early with status {status}; see {}",
            proxy_log.display()
        );
    }

    Ok(ProxyGuard { child })
}

fn proxy_script_source() -> &'static str {
    r#"import os
import re
from mitmproxy import http

TARGET_DOMAIN = os.environ.get("BLACKBOX_MANUAL_TARGET_DOMAIN", "").strip().lower()
LOCAL_PORT = os.environ.get("BLACKBOX_MANUAL_LOCAL_PORT", "")
AUTHORIZATION_PATH = os.environ.get("BLACKBOX_MANUAL_AUTHORIZATION_PATH", "")


def target_origin() -> str:
    if not TARGET_DOMAIN:
        return ""
    return f"https://{TARGET_DOMAIN}"


def replacement_origin() -> str:
    if not LOCAL_PORT:
        return ""
    return f"https://localhost:{LOCAL_PORT}"


def request(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_host == "localhost" and flow.request.port == int(LOCAL_PORT or 0):
        if flow.request.path.startswith("/authorization.md") and AUTHORIZATION_PATH:
            return
        flow.request.scheme = "https"
        flow.request.host = TARGET_DOMAIN
        flow.request.port = 443


def response(flow: http.HTTPFlow) -> None:
    if flow.request.pretty_host == "localhost" and flow.request.path.startswith("/authorization.md") and AUTHORIZATION_PATH:
        try:
            with open(AUTHORIZATION_PATH, "rb") as handle:
                content = handle.read()
        except OSError as exc:
            flow.response = http.Response.make(500, f"authorization unavailable: {exc}".encode(), {"content-type": "text/plain"})
            return
        flow.response = http.Response.make(200, content, {"content-type": "text/markdown; charset=utf-8"})
        return

    origin = target_origin()
    replacement = replacement_origin()
    if not origin or not replacement or flow.response is None:
        return
    content_type = flow.response.headers.get("content-type", "")
    if not re.search(r"text|json|javascript|xml", content_type, re.I):
        return
    try:
        text = flow.response.get_text(strict=False)
    except Exception:
        return
    rewritten = text.replace(origin, replacement).replace(origin.replace("https://", "http://"), replacement)
    if rewritten != text:
        flow.response.set_text(rewritten)
"#
}

fn pick_random_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    Ok(listener.local_addr()?.port())
}

fn normalize_domain(input: &str) -> Result<String> {
    let mut value = input.trim().to_ascii_lowercase();
    if value.is_empty() {
        anyhow::bail!("empty target URL");
    }
    if let Some(idx) = value.find("://") {
        value = value[idx + 3..].to_string();
    }
    if let Some(idx) = value.rfind('@') {
        value = value[idx + 1..].to_string();
    }
    if let Some(idx) = value.find(['/', '?', '#']) {
        value.truncate(idx);
    }
    if let Some(idx) = value.find(':') {
        value.truncate(idx);
    }
    value = value.trim_matches('.').to_string();
    if let Some(stripped) = value.strip_prefix("www.") {
        value = stripped.to_string();
    }
    if value.is_empty() {
        anyhow::bail!("invalid target URL: {input}");
    }
    Ok(value)
}

fn maybe_enter_target_subdir(target_domain: &str) -> Result<()> {
    let start_dir = std::env::current_dir()?;
    let slug = safe_name(target_domain);
    let mut candidate = start_dir.join(&slug);
    let mut suffix = 1u32;
    let mut timestamp = None;
    while candidate.exists() {
        let timestamp = timestamp.get_or_insert_with(|| unix_timestamp().to_string());
        candidate = start_dir.join(format!("{slug}-{timestamp}-{suffix}"));
        suffix = suffix.saturating_add(1);
    }
    fs::create_dir_all(&candidate)?;
    std::env::set_current_dir(&candidate)?;
    let base = start_dir
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(".");
    eprintln!(
        "bb-codex-ni: entered workdir {base}/{}",
        candidate.file_name().unwrap_or_default().to_string_lossy()
    );
    Ok(())
}

fn write_run_metadata(
    path: &Path,
    target_input: &str,
    target_domain: &str,
    localhost_url: &str,
    prompt_url: &str,
) -> Result<()> {
    let content = format!(
        "BB_ORIGINAL_URL={}\nBB_TARGET_DOMAIN={}\nBB_LAST_LOCALHOST_URL={}\nBB_LAST_PROMPT_URL={}\nBB_NON_INTERACTIVE=1\nBB_UPDATED_AT={}\n",
        shell_quote(target_input),
        shell_quote(target_domain),
        shell_quote(localhost_url),
        shell_quote(prompt_url),
        shell_quote(&unix_timestamp().to_string())
    );
    fs::write(path, content)?;
    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_timestamp_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn ensure_authorization_file(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, DEFAULT_AUTHORIZATION)?;
    Ok(())
}

fn ensure_prompt_file(path: &Path) -> Result<()> {
    if path.is_file() {
        return Ok(());
    }
    anyhow::bail!(
        "missing bb-codex prompt file {}; create it or set BB_PROMPT_FILE",
        path.display()
    )
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context("HOME is not set")
}

fn resolve_bin(env_name: &str, name: &str, candidates: &[&str]) -> Option<PathBuf> {
    if let Some(path) = env_path(env_name) {
        return Some(path);
    }
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
    })
}

fn safe_name(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches(|ch| matches!(ch, '.' | '_' | '-'));
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn exec_argv_defaults_to_json_events() {
        let argv = build_exec_argv(Vec::new(), "prompt".to_string(), false);
        assert_eq!(
            argv,
            vec![
                "bb-codex-ni",
                "--dangerously-bypass-approvals-and-sandbox",
                "--json",
                "prompt",
            ]
        );
    }

    #[test]
    fn exec_argv_human_mode_preserves_human_output() {
        let argv = build_exec_argv(Vec::new(), "prompt".to_string(), true);
        assert_eq!(
            argv,
            vec![
                "bb-codex-ni",
                "--dangerously-bypass-approvals-and-sandbox",
                "prompt",
            ]
        );
    }

    #[test]
    fn exec_argv_does_not_duplicate_json_flag() {
        let argv = build_exec_argv(vec!["--json".to_string()], "prompt".to_string(), false);
        assert_eq!(
            argv,
            vec![
                "bb-codex-ni",
                "--dangerously-bypass-approvals-and-sandbox",
                "--json",
                "prompt",
            ]
        );
    }

    #[test]
    fn resume_exec_argv_uses_last_thread() {
        let argv = build_resume_exec_argv(Vec::new(), "wrap it up".to_string(), false);
        assert_eq!(
            argv,
            vec![
                "bb-codex-ni",
                "--dangerously-bypass-approvals-and-sandbox",
                "--json",
                "resume",
                "--last",
                "wrap it up",
            ]
        );
    }
}
