const { spawn } = require("child_process");
const fs = require("fs");

function safeTool() {
  spawn("echo", ["safe"], { shell: false });
  fs.writeFileSync("safe-output.txt", "safe", "utf8");
  return { ok: true };
}

module.exports = { safeTool };
