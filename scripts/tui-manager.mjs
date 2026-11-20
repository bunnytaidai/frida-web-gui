#!/usr/bin/env node
// scripts/tui-manager.mjs — Bảng Điều Khiển Menu TUI/CLI Kiểu Archify (5 Phân Hệ: Package, Cài Đặt, Môi Trường, Localhost & API/Proxy)
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import readline from "node:readline/promises";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const WORKSPACE_ROOT = path.resolve(PROJECT_ROOT, "..");
const PKG_FILE = path.join(PROJECT_ROOT, "package.json");
const ENV_FILE = path.join(PROJECT_ROOT, ".env");
const ENV_EXAMPLE_FILE = path.join(PROJECT_ROOT, ".env.example");
const RUN_DIR = path.join(PROJECT_ROOT, ".run");
const LOGS_DIR = path.join(PROJECT_ROOT, "logs");
const DATA_DIR = path.join(PROJECT_ROOT, "data");

if (process.platform === "win32" && process.stdout.isTTY) {
  try {
    process.stdout.setDefaultEncoding("utf8");
  } catch {}
}

function maskSecret(val = "") {
  const s = String(val || "").trim();
  if (!s) return "(Chưa thiết lập)";
  if (s.length <= 8) return "****";
  return `${s.slice(0, 4)}****${s.slice(-4)}`;
}

function probePort(host, port, timeoutMs = 600) {
  return new Promise((resolve) => {
    let done = false;
    const sock = net.createConnection({ host, port: Number(port) });
    const finish = (open) => {
      if (done) return;
      done = true;
      try {
        sock.destroy();
      } catch {}
      resolve(open);
    };
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => finish(true));
    sock.once("timeout", () => finish(false));
    sock.once("error", () => finish(false));
  });
}

function parseEnvFile(filePath) {
  const map = new Map();
  if (!fs.existsSync(filePath)) return map;
  const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const val = trimmed
      .slice(eq + 1)
      .trim()
      .replace(/^["']|["']$/g, "");
    if (key) map.set(key, val);
  }
  return map;
}

async function writeEnvKeyAtomic(key, value) {
  const cleanKey = String(key || "").trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(cleanKey)) {
    throw new Error(`Tên biến môi trường '${cleanKey}' không hợp lệ.`);
  }
  const existingText = fs.existsSync(ENV_FILE) ? await fsp.readFile(ENV_FILE, "utf8") : "";
  if (existingText) {
    await fsp.writeFile(`${ENV_FILE}.bak`, existingText, "utf8");
  }

  const lines = existingText ? existingText.split(/\r?\n/) : [];
  let updated = false;
  const nextLines = lines.map((line) => {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (m && m[1] === cleanKey) {
      updated = true;
      return `${cleanKey}=${value}`;
    }
    return line;
  });

  if (!updated) {
    if (nextLines.length > 0 && nextLines[nextLines.length - 1] !== "") {
      nextLines.push("");
    }
    nextLines.push(`${cleanKey}=${value}`);
  }

  const tmp = `${ENV_FILE}.tmp`;
  await fsp.writeFile(tmp, `${nextLines.join("\n").trimEnd()}\n`, "utf8");
  await fsp.rename(tmp, ENV_FILE);
}

export async function scanProjectStatus() {
  const pkg = JSON.parse(await fsp.readFile(PKG_FILE, "utf8"));
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const packages = [];

  for (const [name, wantedRange] of Object.entries(deps)) {
    const modPkgPath = path.join(PROJECT_ROOT, "node_modules", ...name.split("/"), "package.json");
    if (fs.existsSync(modPkgPath)) {
      const modPkg = JSON.parse(fs.readFileSync(modPkgPath, "utf8"));
      packages.push({
        name,
        wanted: wantedRange,
        installedVersion: modPkg.version,
        installed: true,
      });
    } else {
      packages.push({
        name,
        wanted: wantedRange,
        installedVersion: null,
        installed: false,
      });
    }
  }

  const envMap = parseEnvFile(ENV_FILE);
  const host = envMap.get("HOST") || process.env.HOST || "127.0.0.1";
  const port = Number(envMap.get("PORT") || process.env.PORT || 3456);
  const mitmHost = envMap.get("MITM_PROXY_HOST") || "127.0.0.1";
  const mitmPort = Number(envMap.get("MITM_PROXY_PORT") || 8080);

  const [webListening, ssh2222, rabbit8765, mitmOpen] = await Promise.all([
    probePort("127.0.0.1", port, 600),
    probePort("127.0.0.1", 2222, 500),
    probePort("127.0.0.1", 8765, 500),
    probePort(mitmHost, mitmPort, 500),
  ]);

  const pidFile = path.join(RUN_DIR, `localhost_${port}.pid`);
  let trackedPid = null;
  if (fs.existsSync(pidFile)) {
    const rawPid = Number(fs.readFileSync(pidFile, "utf8").trim());
    if (Number.isInteger(rawPid) && rawPid > 0) trackedPid = rawPid;
  }

  const hasParentTweak = fs.existsSync(path.join(WORKSPACE_ROOT, "Tweak.x"));

  return {
    projectName: pkg.name,
    version: pkg.version,
    nodeVersion: process.version,
    projectRoot: PROJECT_ROOT,
    hasParentTweak,
    packages,
    missingPackages: packages.filter((p) => !p.installed),
    dirs: {
      envExists: fs.existsSync(ENV_FILE),
      dataDirExists: fs.existsSync(DATA_DIR),
      logsDirExists: fs.existsSync(LOGS_DIR),
      runDirExists: fs.existsSync(RUN_DIR),
    },
    localhost: {
      host,
      port,
      url: `http://${host}:${port}`,
      listening: webListening,
      trackedPid,
      pidFile,
    },
    channels: {
      ssh2222,
      rabbit8765,
      mitmProxy: { host: mitmHost, port: mitmPort, open: mitmOpen },
    },
    tokens: {
      APPSTORE_ISSUER_ID: maskSecret(envMap.get("APPSTORE_ISSUER_ID")),
      APPSTORE_KEY_ID: maskSecret(envMap.get("APPSTORE_KEY_ID")),
      MITM_PROXY_URL: `${mitmHost}:${mitmPort}`,
    },
  };
}

function padBoxLine(content, innerWidth = 61) {
  const clean = String(content);
  const padCount = Math.max(0, innerWidth - [...clean].length);
  return `║ ${clean}${" ".repeat(padCount)} ║`;
}

function printArchifyBanner(snapshot) {
  const top = `╔${"═".repeat(63)}╗`;
  const sep = `╠${"═".repeat(63)}╣`;
  const bot = `╚${"═".repeat(63)}╝`;

  const pkgOk = snapshot.packages.length - snapshot.missingPackages.length;
  const webTag = snapshot.localhost.listening
    ? `ONLINE (${snapshot.localhost.url})`
    : `OFFLINE (Cổng ${snapshot.localhost.port} đóng)`;
  const sshTag = snapshot.channels.ssh2222 ? "MỞ" : "ĐÓNG";
  const mitmTag = snapshot.channels.mitmProxy.open ? "MỞ" : "ĐÓNG";

  console.log(top);
  console.log(padBoxLine(`TRẠM QUẢN TRỊ DỰ ÁN TUI — FRIDA STUDIO v${snapshot.version}`));
  console.log(
    padBoxLine(`Node ${snapshot.nodeVersion} │ Packages: ${pkgOk}/${snapshot.packages.length} OK │ SSH 2222: ${sshTag}`)
  );
  console.log(padBoxLine(`Web GUI: ${webTag} │ Proxy ${snapshot.channels.mitmProxy.port}: ${mitmTag}`));
  console.log(sep);
  console.log(padBoxLine("[1] Kiểm tra trạng thái Package, Runtime & 6 Kênh kết nối"));
  console.log(padBoxLine("[2] Cài đặt tự động các Package còn thiếu (npm install)"));
  console.log(padBoxLine("[3] Thiết lập môi trường bắt buộc (.env, data/, logs/, .run/)"));
  console.log(padBoxLine("[4] Bật / Tắt máy chủ Localhost 3456 & Cầu nối thiết bị"));
  console.log(padBoxLine("[5] Cấu hình kết nối Proxy MITM & API Token bên thứ 3"));
  console.log(padBoxLine("[0] Thoát trình quản lý TUI"));
  console.log(bot);
}

async function runSetupEnvironment() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await fsp.mkdir(LOGS_DIR, { recursive: true });
  await fsp.mkdir(RUN_DIR, { recursive: true });

  const exampleContent = [
    "# Cấu hình Môi trường Trạm Điều Khiển Frida v6.0.0",
    "HOST=127.0.0.1",
    "PORT=3456",
    "MITM_PROXY_HOST=127.0.0.1",
    "MITM_PROXY_PORT=8080",
    "RABBIT_AGENT_PORT=8765",
    "APPSTORE_ISSUER_ID=",
    "APPSTORE_KEY_ID=",
    "",
  ].join("\n");

  if (!fs.existsSync(ENV_EXAMPLE_FILE)) {
    await fsp.writeFile(ENV_EXAMPLE_FILE, exampleContent, "utf8");
  }
  if (!fs.existsSync(ENV_FILE)) {
    await fsp.writeFile(ENV_FILE, exampleContent, "utf8");
  }

  const gitignorePath = path.join(PROJECT_ROOT, ".gitignore");
  const requiredIgnores = ["node_modules/", ".env", ".env.bak", ".run/", "logs/"];
  let gi = fs.existsSync(gitignorePath) ? await fsp.readFile(gitignorePath, "utf8") : "";
  let changed = false;
  for (const entry of requiredIgnores) {
    if (!gi.includes(entry)) {
      gi = `${gi.trimEnd()}\n${entry}\n`;
      changed = true;
    }
  }
  if (changed) {
    await fsp.writeFile(gitignorePath, gi, "utf8");
  }

  console.log("✔ Đã khởi tạo đầy đủ .env, .env.example, data/, logs/, .run/ và bảo vệ .gitignore.");
}

async function runInstallMissing(snapshot) {
  if (snapshot.missingPackages.length === 0) {
    console.log("✔ Toàn bộ 5/5 gói phụ thuộc trong package.json đều đã cài đặt đầy đủ — không cần tải lại.");
    return;
  }
  const names = snapshot.missingPackages.map((p) => p.name);
  console.log(`⚙ Đang cài đặt các gói còn thiếu: ${names.join(", ")} ...`);
  const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
  const res = spawnSync(npmCmd, ["install", ...names], {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
  if (res.status !== 0) {
    throw new Error(`Lệnh npm install kết thúc với mã lỗi ${res.status}`);
  }
  console.log("✔ Đã cài đặt xong các gói còn thiếu!");
}

async function startLocalhostDaemon(snapshot) {
  if (snapshot.localhost.listening) {
    console.log(`✔ Máy chủ đã đang chạy sẵn tại ${snapshot.localhost.url}`);
    return;
  }
  await fsp.mkdir(RUN_DIR, { recursive: true });
  await fsp.mkdir(LOGS_DIR, { recursive: true });
  const outLog = fs.openSync(path.join(LOGS_DIR, "tui-localhost.log"), "a");
  const child = spawn(process.execPath, ["src/server.mjs"], {
    cwd: PROJECT_ROOT,
    detached: true,
    windowsHide: true,
    stdio: ["ignore", outLog, outLog],
  });
  child.unref();
  await fsp.writeFile(snapshot.localhost.pidFile, String(child.pid), "utf8");

  for (let i = 0; i < 12; i++) {
    await new Promise((r) => setTimeout(r, 300));
    if (await probePort("127.0.0.1", snapshot.localhost.port, 400)) {
      console.log(`✔ Đã bật thành công Trạm Điều Khiển Frida (PID ${child.pid}) tại ${snapshot.localhost.url}`);
      return;
    }
  }
  console.log(`⚠ Đã khởi chạy tiến trình PID ${child.pid}, vui lòng kiểm tra logs/tui-localhost.log.`);
}

async function stopLocalhostDaemon(snapshot) {
  if (!snapshot.localhost.trackedPid) {
    console.log("ℹ Không tìm thấy tệp khóa PID do TUI khởi tạo (.run/localhost_3456.pid).");
    return;
  }
  try {
    process.kill(snapshot.localhost.trackedPid);
    console.log(`✔ Đã dừng tiến trình máy chủ Web PID ${snapshot.localhost.trackedPid} an toàn.`);
  } catch (err) {
    console.log(`ℹ Tiến trình PID ${snapshot.localhost.trackedPid} đã dừng trước đó (${err?.code || "ESRCH"}).`);
  }
  await fsp.rm(snapshot.localhost.pidFile, { force: true });
}

function printDetailedStatus(snapshot) {
  console.log("\n=== [1] BÁO CÁO CHI TIẾT PACKAGE, MÔI TRƯỜNG & KẾT NỐI THẬT ===");
  console.log(`• Thư mục dự án  : ${snapshot.projectRoot}`);
  console.log(`• Phiên bản Node : ${snapshot.nodeVersion}`);
  console.log(`• Tweak gốc kèm  : ${snapshot.hasParentTweak ? "CÓ (RabbitUltra / Daemon 8765)" : "Không"}`);
  console.log("\n--- Danh sách Package trong package.json ---");
  for (const p of snapshot.packages) {
    const badge = p.installed ? `[OK v${p.installedVersion}]` : "[THIẾU]";
    console.log(`  - ${p.name.padEnd(20)} yêu cầu ${p.wanted.padEnd(10)} -> ${badge}`);
  }
  console.log("\n--- Trạng thái Máy chủ & Các Kênh Kết Nối Thực Tế ---");
  console.log(
    `  - Web GUI Localhost   : ${snapshot.localhost.listening ? `ĐANG CHẠY (${snapshot.localhost.url})` : "ĐANG TẮT"}`
  );
  console.log(`  - Cầu nối SSH 2222    : ${snapshot.channels.ssh2222 ? "MỞ THẬT" : "ĐÓNG"}`);
  console.log(`  - Rabbit Agent 8765   : ${snapshot.channels.rabbit8765 ? "MỞ THẬT" : "ĐÓNG"}`);
  console.log(
    `  - Proxy MITM (${snapshot.channels.mitmProxy.host}:${snapshot.channels.mitmProxy.port}) : ${
      snapshot.channels.mitmProxy.open ? "MỞ THẬT" : "ĐÓNG"
    }`
  );
  console.log("\n--- Cấu hình Token / API (Đã che bảo mật) ---");
  for (const [k, v] of Object.entries(snapshot.tokens)) {
    console.log(`  - ${k.padEnd(22)} = ${v}`);
  }
  console.log("");
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes("--json")) {
    const snap = await scanProjectStatus();
    console.log(JSON.stringify(snap, null, 2));
    return;
  }

  if (args.includes("--status") || args.includes("--scan")) {
    const snap = await scanProjectStatus();
    printArchifyBanner(snap);
    printDetailedStatus(snap);
    return;
  }

  if (args.includes("--setup-env")) {
    await runSetupEnvironment();
    return;
  }

  if (args.includes("--install-missing")) {
    const snap = await scanProjectStatus();
    await runInstallMissing(snap);
    return;
  }

  if (args.includes("--start")) {
    const snap = await scanProjectStatus();
    await startLocalhostDaemon(snap);
    return;
  }

  if (args.includes("--stop")) {
    const snap = await scanProjectStatus();
    await stopLocalhostDaemon(snap);
    return;
  }

  const tokenIdx = args.indexOf("--set-token");
  if (tokenIdx !== -1 && args[tokenIdx + 1]) {
    const pair = args[tokenIdx + 1];
    const eq = pair.indexOf("=");
    if (eq === -1) {
      console.error("✖ Cú pháp đúng: --set-token TEN_BIEN=GIA_TRI");
      process.exitCode = 1;
      return;
    }
    const k = pair.slice(0, eq).trim();
    const v = pair.slice(eq + 1).trim();
    await writeEnvKeyAtomic(k, v);
    console.log(`✔ Đã lưu an toàn ${k}=${maskSecret(v)} vào .env (có bản sao lưu .env.bak).`);
    return;
  }

  if (!process.stdin.isTTY) {
    const snap = await scanProjectStatus();
    printArchifyBanner(snap);
    printDetailedStatus(snap);
    return;
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    while (true) {
      const snap = await scanProjectStatus();
      printArchifyBanner(snap);
      const ans = (await rl.question("👉 Chọn mục [0-5]: ")).trim();
      if (ans === "0" || ans.toLowerCase() === "q") break;
      if (ans === "1") {
        printDetailedStatus(snap);
      } else if (ans === "2") {
        await runInstallMissing(snap);
      } else if (ans === "3") {
        await runSetupEnvironment();
      } else if (ans === "4") {
        const sub = (await rl.question("   Chọn [1] Bật localhost:3456 | [2] Tắt localhost:3456: ")).trim();
        if (sub === "1") await startLocalhostDaemon(snap);
        else if (sub === "2") await stopLocalhostDaemon(snap);
      } else if (ans === "5") {
        const key = (
          await rl.question("   Nhập tên biến (VD: MITM_PROXY_PORT, APPSTORE_ISSUER_ID, APPSTORE_KEY_ID): ")
        ).trim();
        if (key) {
          const val = (await rl.question(`   Nhập giá trị cho ${key}: `)).trim();
          await writeEnvKeyAtomic(key, val);
          console.log(`✔ Đã cập nhật ${key}=${maskSecret(val)} an toàn.`);
        }
      }
      console.log("");
    }
  } finally {
    rl.close();
  }
}

main().catch((err) => {
  console.error("✖ Lỗi TUI Manager:", err?.message || err);
  process.exitCode = 1;
});
