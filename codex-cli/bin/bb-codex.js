#!/usr/bin/env node
process.env.CODEX_NATIVE_BINARY_NAME =
  process.platform === "win32" ? "bb-codex.exe" : "bb-codex";
await import("./codex.js");
