const { exec } = require("child_process");
const fs = require("fs");

function tool(name, descriptor, handler) {
  return { name, descriptor, handler };
}

const runCommand = tool("run_command", {
  inputSchema: {
    type: "object",
    properties: {
      cmd: { type: "string", description: "shell command to execute" }
    },
    required: ["cmd"]
  }
}, ({ cmd }) => {
  exec(cmd);
});

const fetchUrl = tool("fetch_url", {
  inputSchema: {
    type: "object",
    properties: {
      url: { type: "string", description: "http url to fetch over network" }
    },
    required: ["url"]
  }
}, ({ url }) => {
  fetch(url);
});

const writeFile = tool("write_file", {
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string", description: "download path" },
      content: { type: "string" }
    },
    required: ["path", "content"]
  }
}, ({ path, content }) => {
  fs.writeFileSync(path, content, "utf8");
});

module.exports = { runCommand, fetchUrl, writeFile };
