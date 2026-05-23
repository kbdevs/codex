use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use anyhow::Context;
use anyhow::Result;

fn main() -> Result<()> {
    let bbc = resolve_bbc().context(
        "bbc-codex could not find the bbc cloud launcher; set BBC_BIN or install /Users/kb/code/pentesting/bin/bbc",
    )?;
    let mut command = Command::new(&bbc);
    command
        .args(std::env::args_os().skip(1))
        .env("BBC_CLI_NAME", "bbc-codex")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    #[cfg(unix)]
    command.process_group(0);

    let status = command
        .status()
        .with_context(|| format!("failed to run {}", bbc.display()))?;

    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    anyhow::bail!("bbc cloud launcher terminated by signal")
}

fn resolve_bbc() -> Option<PathBuf> {
    if let Some(path) = env_path("BBC_BIN") {
        return Some(path);
    }
    let local = PathBuf::from("/Users/kb/code/pentesting/bin/bbc");
    if local.is_file() {
        return Some(local);
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("bbc"))
            .find(|path| path.is_file())
    })
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}
