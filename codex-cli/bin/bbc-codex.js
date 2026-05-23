#!/usr/bin/env node
process.env.CODEX_NATIVE_BINARY_NAME =
  process.platform === "win32" ? "bbc-codex.exe" : "bbc-codex";
await import("./codex.js");
