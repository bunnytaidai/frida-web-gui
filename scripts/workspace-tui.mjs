#!/usr/bin/env node
// scripts/workspace-tui.mjs — Bảng Điều Khiển Menu TUI/CLI Kiểu Archify 5 Phân Hệ (/tui-package-env-manager)
// Quét toàn bộ dự án, kiểm tra & bật/tắt trạng thái từng Package/Module, Môi trường, Localhost 3456 & API Token
import { execFile, spawn } from "node:child_process";
import fs from "node:fs";
import fsp from "node:fs/promises";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import readline from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "..");
const PKG_FILE = path.join(PROJECT_ROOT, "package.json");
const ENV_FILE = path.join(PROJECT_ROOT, ".env");
const ENV_EXAMPLE_FILE = path.join(PROJECT_ROOT, ".env.example");
const DATA_DIR = path.join(PROJECT_ROOT, "data");
const LOGS_DIR = path.join(PROJECT_ROOT, "logs");
const RUNTIME_DIR = path.join(PROJECT_ROOT, ".tui-runtime");
const PID_FILE = path.join(RUNTIME_DIR, "server.pid.json");
const TOGGLES_FILE = path.join(DATA_DIR, "package-toggles.json");

const SKIP_SCAN_DIRS = new Set(["node_modules", ".git", ".venv", ".run", ".tui-runtime", "logs", "dist", "build"]);
const TOKEN_KEY_RE = /\b([A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|WEBHOOK|CLIENT_ID|ISSUER_ID|KEY_ID|MITM_PROXY)[A-Z0-9_]*)\b/g;

if (process.platform === "win32" && process.stdout.isTTY) {
  try {
    process.stdout.setDefaultEncoding("utf8");
  } catch {}
}

function maskSecretValue(val) {
  const s = String(val ?? "").trim();
  if (!s) return "[✗ CHƯA NHẬP]";
  if (s.length <= 8) return "****";
  return `${s.slice(0, 4)}****${s.slice(-3)}`;
}

function parseDotEnv(rawText) {
  const map = new Map();
  for (const line of String(rawText || "").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx > 0) {
      const k = trimmed.slice(0, eqIdx).trim();
      const v = trimmed.slice(eqIdx + 1).trim().replace(/^['"]|['"]$/g, "");
      map.set(k, v);
    }
  }
  return map;
}

function probeBinarySync(binName) {
  const cmd = process.platform === "win32" ? "where" : "which";
  return execFileAsync(cmd, [binName], { windowsHide: true })
    .then((r) => Boolean(String(r.stdout || "").trim()))
    .catch(() => false);
}

function probePortQuick(port, host = "127.0.0.1", timeoutMs = 450) {
  const t0 = Date.now();
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => {
      if (!done) {
        done = true;
        resolve(v);
      }
    };
    const sock = net.createConnection({ host, port });
    const timer = setTimeout(() => {
      sock.destroy();
      finish({ open: false, latencyMs: null });
    }, timeoutMs);
    sock.once("connect", () => {
      clearTimeout(timer);
      sock.destroy();
      finish({ open: true, latencyMs: Math.max(1, Date.now() - t0) });
    });
    sock.once("error", () => {
      clearTimeout(timer);
      sock.destroy();
      finish({ open: false, latencyMs: null });
    });
  });
}

function httpRequestJson(method, urlStr, bodyObj = null, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const bodyRaw = bodyObj ? JSON.stringify(bodyObj) : null;
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname + u.search,
        method,
        timeout: timeoutMs,
        headers: {
          Accept: "application/json",
          ...(bodyRaw
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(bodyRaw),
              }
            : {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch (err) {
            reject(err);
          }
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error("Timeout")));
    req.on("error", reject);
    if (bodyRaw) req.write(bodyRaw);
    req.end();
  });
}

async function readPackageToggles() {
  if (!fs.existsSync(TOGGLES_FILE)) return {};
  try {
    const raw = JSON.parse(await fsp.readFile(TOGGLES_FILE, "utf8"));
    return raw && typeof raw === "object" ? raw : {};
  } catch {
    return {};
  }
}

async function writePackageToggles(toggles) {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  const tmp = `${TOGGLES_FILE}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(toggles, null, 2) + "\n", "utf8");
  await fsp.rename(tmp, TOGGLES_FILE);
}

async function scanFullProjectTree() {
  const guiPages = [];
  const entrypoints = [];
  const detectedApiKeys = new Set();
  let totalFiles = 0;

  async function walk(dirPath) {
    const entries = await fsp.readdir(dirPath, { withFileTypes: true }).catch(() => []);
    for (const ent of entries) {
      if (SKIP_SCAN_DIRS.has(ent.name)) continue;
      const fullPath = path.join(dirPath, ent.name);
      if (ent.isDirectory()) {
        await walk(fullPath);
        continue;
      }
      totalFiles += 1;
      const rel = path.relative(PROJECT_ROOT, fullPath).replaceAll("\\", "/");
      if (rel.startsWith("public/") && rel.endsWith(".html")) {
        guiPages.push(rel);
      }
      if (["src/server.mjs", "scripts/workspace-tui.mjs", "scripts/tui-manager.mjs"].includes(rel)) {
        entrypoints.push(rel);
      }
      const ext = path.extname(ent.name).toLowerCase();
      if ([".mjs", ".js", ".ts", ".env", ".example"].includes(ext) || ent.name.startsWith(".env")) {
        const text = await fsp.readFile(fullPath, "utf8").catch(() => "");
        for (const m of text.matchAll(TOKEN_KEY_RE)) {
          if (m[1] && m[1].length <= 42) detectedApiKeys.add(m[1]);
        }
      }
    }
  }

  await walk(PROJECT_ROOT);
  return {
    totalFiles,
    guiPages: guiPages.sort(),
    entrypoints: entrypoints.sort(),
    detectedApiKeys: Array.from(detectedApiKeys).sort(),
  };
}

export async function scanWorkspaceStatus() {
  const pkg = JSON.parse(await fsp.readFile(PKG_FILE, "utf8"));
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const toggles = await readPackageToggles();
  const packages = [];

  for (const [depName, wantedVer] of Object.entries(deps)) {
    const depPkgPath = path.join(PROJECT_ROOT, "node_modules", ...depName.split("/"), "package.json");
    const enabled = toggles[depName] !== false;
    if (fs.existsSync(depPkgPath)) {
      try {
        const depMeta = JSON.parse(await fsp.readFile(depPkgPath, "utf8"));
        packages.push({
          name: depName,
          wanted: wantedVer,
          installed: depMeta.version || "installed",
          ok: true,
          enabled,
        });
      } catch {
        packages.push({ name: depName, wanted: wantedVer, installed: null, ok: false, enabled });
      }
    } else {
      packages.push({ name: depName, wanted: wantedVer, installed: null, ok: false, enabled });
    }
  }

  const envMap = fs.existsSync(ENV_FILE) ? parseDotEnv(await fsp.readFile(ENV_FILE, "utf8")) : new Map();
  const portNum = Number(envMap.get("PORT") || 3456);

  const [treeScan, hasNpm, hasGit, webProbe, sshProbe, fridaUsbProbe, rabbitProbe, vpnProxyProbe] = await Promise.all([
    scanFullProjectTree(),
    probeBinarySync("npm"),
    probeBinarySync("git"),
    probePortQuick(portNum),
    probePortQuick(2222),
    probePortQuick(27142),
    probePortQuick(8765),
    probePortQuick(8080),
  ]);

  let apiHealth = null;
  if (webProbe.open) {
    try {
      const h = await httpRequestJson("GET", `http://127.0.0.1:${portNum}/api/v1/health`, null, 1200);
      apiHealth = h?.data || null;
    } catch {
      apiHealth = null;
    }
  }

  let rabbitVerifiedOpen = false;
  if (rabbitProbe.open) {
    try {
      const r = await httpRequestJson("GET", "http://127.0.0.1:8765/api/apps", null, 750);
      rabbitVerifiedOpen = Boolean(
        r && (Array.isArray(r.apps) || Array.isArray(r.apis) || typeof r.version === "string")
      );
    } catch {
      rabbitVerifiedOpen = false;
    }
  }

  return {
    projectName: pkg.name,
    projectVersion: pkg.version,
    nodeVersion: process.version,
    runtimes: { node: true, npm: hasNpm, git: hasGit },
    projectScan: treeScan,
    hasEnvFile: fs.existsSync(ENV_FILE),
    hasDataDir: fs.existsSync(DATA_DIR),
    hasLogsDir: fs.existsSync(LOGS_DIR),
    packages,
    missingCount: packages.filter((p) => !p.ok).length,
    enabledCount: packages.filter((p) => p.enabled).length,
    ports: {
      webGui: { port: portNum, ...webProbe, version: apiHealth?.version || null },
      usbFridaTunnel: { port: 27142, ...fridaUsbProbe },
      usbSsh: { port: 2222, ...sshProbe },
      rabbitDaemon: {
        port: 8765,
        open: rabbitVerifiedOpen,
        tcpPortOccupied: rabbitProbe.open,
        latencyMs: rabbitProbe.latencyMs,
      },
      vpnMitmProxy: { port: 8080, ...vpnProxyProbe },
    },
    maskedEnv: Array.from(envMap.entries()).map(([k, v]) => ({
      key: k,
      value: /KEY|TOKEN|SECRET|PASS/i.test(k) ? maskSecretValue(v) : v,
    })),
    scannedAt: new Date().toISOString(),
  };
}

function padBoxLine(content, innerWidth = 61) {
  const clean = String(content || "");
  const chars = [...clean];
  if (chars.length >= innerWidth - 1) {
    return `║ ${chars.slice(0, innerWidth - 2).join("")} ║`;
  }
  return `║ ${clean}${" ".repeat(innerWidth - 1 - chars.length)}║`;
}

function renderArchifyStatusBox(report) {
  const lines = [];
  const bar = "═".repeat(61);
  const sep = "─".repeat(61);
  const w = report.ports.webGui;
  const rtStr = `Node ${report.nodeVersion} | npm:${report.runtimes.npm ? "OK" : "NO"} | git:${report.runtimes.git ? "OK" : "NO"}`;

  lines.push(`╔${bar}╗`);
  lines.push(padBoxLine(`ARCHIFY TUI — QUẢN TRỊ DỰ ÁN ${report.projectName.toUpperCase()} v${report.projectVersion}`));
  lines.push(padBoxLine(`${rtStr} | ${report.projectScan.totalFiles} tệp`));
  lines.push(`╠${bar}╣`);
  lines.push(
    padBoxLine(
      `[1] Packages: ${report.packages.length - report.missingCount}/${report.packages.length} đã cài | Đang bật: ${report.enabledCount}/${report.packages.length}`
    )
  );
  for (const [idx, p] of report.packages.entries()) {
    const instTag = p.ok ? `v${p.installed}` : "THIẾU";
    const toggleTag = p.enabled ? "[ON ]" : "[OFF]";
    lines.push(padBoxLine(`    (${idx + 1}) ${toggleTag} ${p.ok ? "✓" : "✗"} ${p.name} (${instTag})`));
  }
  lines.push(`╟${sep}╢`);
  lines.push(
    padBoxLine(
      `[3] Môi trường: .env=${report.hasEnvFile ? "OK" : "Chưa có"} | data=${report.hasDataDir ? "OK" : "NO"} | logs=${report.hasLogsDir ? "OK" : "NO"}`
    )
  );
  lines.push(padBoxLine(`    GUI: ${report.projectScan.guiPages.join(", ") || "Không thấy"}`));
  lines.push(`╟${sep}╢`);
  lines.push(
    padBoxLine(
      `[4] Localhost:${w.port} ${w.open ? `[ON • ${w.version || "live"} • ${w.latencyMs}ms]` : "[OFF]"}`
    )
  );
  lines.push(padBoxLine(`    • GUI Chính:   http://127.0.0.1:${w.port}/`));
  lines.push(padBoxLine(`    • GUI Gửi JS:  http://127.0.0.1:${w.port}/js-console.html`));
  lines.push(
    padBoxLine(
      `    • USB:27142=${report.ports.usbFridaTunnel.open ? "ON" : "OFF"} | SSH:2222=${report.ports.usbSsh.open ? "ON" : "OFF"} | Proxy:8080=${report.ports.vpnMitmProxy.open ? "ON" : "OFF"}`
    )
  );
  lines.push(`╚${bar}╝`);
  return lines.join("\n");
}

async function toggleProjectPackage(pkgName) {
  const pkg = JSON.parse(await fsp.readFile(PKG_FILE, "utf8"));
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  if (!Object.prototype.hasOwnProperty.call(deps, pkgName)) {
    throw new Error(`Không tìm thấy package '${pkgName}' trong package.json. Các gói hợp lệ: ${Object.keys(deps).join(", ")}`);
  }
  const toggles = await readPackageToggles();
  const nextState = toggles[pkgName] === false;
  toggles[pkgName] = nextState;
  await writePackageToggles(toggles);
  console.log(`✔ Package '${pkgName}' đã chuyển sang trạng thái: ${nextState ? "[ON - ĐANG BẬT]" : "[OFF - TẠM TẮT]"}`);
  return { name: pkgName, enabled: nextState };
}

async function installMissingPackages(report) {
  if (report.missingCount === 0) {
    console.log("✔ Toàn bộ thư viện Node.js trong package.json đã được cài đặt đầy đủ.");
    return;
  }
  console.log(`⏳ Đang cài đặt ${report.missingCount} package còn thiếu bằng npm install...`);
  const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
  await execFileAsync(npmCmd, ["install"], { cwd: PROJECT_ROOT, windowsHide: true });
  console.log("✔ Cài đặt package hoàn tất!");
}

async function setupEnvironmentFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await fsp.mkdir(LOGS_DIR, { recursive: true });
  await fsp.mkdir(RUNTIME_DIR, { recursive: true });
  if (!fs.existsSync(ENV_FILE)) {
    const template = fs.existsSync(ENV_EXAMPLE_FILE)
      ? await fsp.readFile(ENV_EXAMPLE_FILE, "utf8")
      : [
          "HOST=127.0.0.1",
          "PORT=3456",
          "VPN_MITM_PROXY=127.0.0.1:8080",
          "APPSTORE_ISSUER_ID=",
          "APPSTORE_KEY_ID=",
        ].join("\n") + "\n";
    await fsp.writeFile(ENV_FILE, template, "utf8");
    console.log(`✔ Đã khởi tạo tệp cấu hình ${ENV_FILE} và các thư mục data/, logs/.`);
  } else {
    console.log("✔ Tệp .env và các thư mục bắt buộc đã sẵn sàng (giữ nguyên dữ liệu hiện có).");
  }
}

async function startLocalhostServer(port = 3456) {
  const probe = await probePortQuick(port);
  if (probe.open) {
    console.log(`✔ Máy chủ đang chạy sẵn tại http://127.0.0.1:${port}/ (GUI Gửi JS: /js-console.html)`);
    return;
  }
  await fsp.mkdir(RUNTIME_DIR, { recursive: true });
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, "src/server.mjs")], {
    cwd: PROJECT_ROOT,
    detached: true,
    stdio: "ignore",
    windowsHide: true,
  });
  child.unref();
  await fsp.writeFile(
    PID_FILE,
    JSON.stringify({ pid: child.pid, startedAt: new Date().toISOString(), port }, null, 2),
    "utf8"
  );
  for (let i = 0; i < 15; i++) {
    await new Promise((r) => setTimeout(r, 250));
    const p = await probePortQuick(port);
    if (p.open) {
      console.log(`✔ Đã bật máy chủ thành công (PID ${child.pid}) tại http://127.0.0.1:${port}/`);
      console.log(`  ↳ Bảng Gửi JS Frida: http://127.0.0.1:${port}/js-console.html`);
      return;
    }
  }
  console.log(`! Đã gọi khởi chạy tiến trình PID ${child.pid}, vui lòng kiểm tra lại bằng --status.`);
}

async function stopLocalhostServer() {
  if (!fs.existsSync(PID_FILE)) {
    console.log("i Không tìm thấy tệp PID do TUI khởi tạo (.tui-runtime/server.pid.json). Không tự ý đóng tiến trình ngoài.");
    return;
  }
  const meta = JSON.parse(await fsp.readFile(PID_FILE, "utf8"));
  if (meta?.pid) {
    try {
      process.kill(Number(meta.pid));
      console.log(`✔ Đã dừng an toàn máy chủ PID ${meta.pid}.`);
    } catch {
      console.log(`i Tiến trình PID ${meta.pid} đã dừng trước đó.`);
    }
  }
  await fsp.unlink(PID_FILE).catch(() => {});
}

async function setEnvKeySafe(pairStr) {
  const eq = String(pairStr || "").indexOf("=");
  if (eq <= 0) {
    throw new Error("Cú pháp đúng: --set-token TEN_BIEN=gia_tri");
  }
  const key = pairStr.slice(0, eq).trim();
  const val = pairStr.slice(eq + 1).trim();
  if (!/^[A-Z0-9_]+$/i.test(key)) {
    throw new Error("Tên biến môi trường chỉ được chứa chữ cái, số và dấu gạch dưới.");
  }

  let existingLines = [];
  if (fs.existsSync(ENV_FILE)) {
    const raw = await fsp.readFile(ENV_FILE, "utf8");
    await fsp.writeFile(`${ENV_FILE}.bak`, raw, "utf8");
    existingLines = raw.split(/\r?\n/);
  }

  let updated = false;
  const nextLines = existingLines.map((ln) => {
    if (ln.trim().startsWith(`${key}=`)) {
      updated = true;
      return `${key}=${val}`;
    }
    return ln;
  });
  if (!updated) nextLines.push(`${key}=${val}`);
  await fsp.writeFile(ENV_FILE, nextLines.filter((l, i, arr) => i < arr.length - 1 || l !== "").join("\n") + "\n", "utf8");
  console.log(`✔ Đã lưu an toàn ${key}=${maskSecretValue(val)} vào .env (đã sao lưu .env.bak).`);
}

async function enableUsbFridaViaApi(port = 3456) {
  const out = await httpRequestJson("POST", `http://127.0.0.1:${port}/api/v1/connections/switch`, {
    channel: "usb_frida",
  });
  const ch = out?.data?.channelReport;
  console.log(`✔ Kênh USB + Frida Server: ${ch?.status?.toUpperCase() || "OK"} — ${ch?.detail || ""}`);
}

async function runInteractiveMenu() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    while (true) {
      const report = await scanWorkspaceStatus();
      const port = report.ports.webGui.port;
      console.log("\n" + renderArchifyStatusBox(report));
      console.log("\nChọn phân hệ Archify (5 Phân hệ):");
      console.log("  [1] Quét lại toàn bộ dự án, Package, Runtime & các kênh kết nối");
      console.log("  [2] Cài đặt tự động các Package còn thiếu (npm install)");
      console.log("  [3] Thiết lập môi trường bắt buộc (.env, data/, logs/)");
      console.log("  [4] Bật / Tắt từng Package của dự án hoặc Bật / Tắt Localhost:" + port);
      console.log("  [5] Cấu hình API Token / Proxy vào .env (Che dấu an toàn)");
      console.log("  [0] Thoát trình quản lý TUI");

      const ans = (await rl.question("\n👉 Nhập lựa chọn (0-5): ")).trim();
      if (ans === "0" || ans.toLowerCase() === "q") break;
      if (ans === "1") continue;
      if (ans === "2") {
        await installMissingPackages(report);
      } else if (ans === "3") {
        await setupEnvironmentFiles();
      } else if (ans === "4") {
        console.log("\n--- BẬT / TẮT PACKAGE & LOCALHOST ---");
        console.log("  [s] Bật / Tắt máy chủ Localhost:" + port + ` (hiện tại: ${report.ports.webGui.open ? "ĐANG CHẠY" : "ĐANG TẮT"})`);
        console.log("  [u] Kích hoạt kênh USB + Frida Server qua API");
        for (const [i, p] of report.packages.entries()) {
          console.log(`  [${i + 1}] Đảo trạng thái package '${p.name}' (hiện tại: ${p.enabled ? "ON" : "OFF"})`);
        }
        const sub = (await rl.question("👉 Chọn mục (s / u / số thứ tự package / Enter để quay lại): ")).trim().toLowerCase();
        if (sub === "s") {
          if (report.ports.webGui.open) await stopLocalhostServer();
          else await startLocalhostServer(port);
        } else if (sub === "u") {
          await enableUsbFridaViaApi(port).catch((e) => console.log(`! Lưu ý kênh USB: ${e.message}`));
        } else if (/^\d+$/.test(sub)) {
          const picked = report.packages[Number(sub) - 1];
          if (picked) await toggleProjectPackage(picked.name);
        }
      } else if (ans === "5") {
        console.log("Khóa phát hiện trong mã nguồn:", report.projectScan.detectedApiKeys.join(", ") || "(Không có)");
        const kv = await rl.question("Nhập TEN_BIEN=gia_tri (VD: VPN_MITM_PROXY=127.0.0.1:8080): ");
        if (kv.trim()) await setEnvKeySafe(kv.trim());
      }
    }
  } finally {
    rl.close();
  }
}

async function main() {
  const args = process.argv.slice(2);
  const wantJson = args.includes("--json");

  if (args.includes("--status") || args.includes("--scan") || args.includes("--list-packages")) {
    const report = await scanWorkspaceStatus();
    if (wantJson) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      console.log(renderArchifyStatusBox(report));
    }
    return;
  }

  const toggleIdx = args.indexOf("--toggle-pkg");
  if (toggleIdx !== -1 && args[toggleIdx + 1]) {
    const out = await toggleProjectPackage(args[toggleIdx + 1]);
    if (wantJson) console.log(JSON.stringify(out, null, 2));
    return;
  }

  if (args.includes("--install-missing")) {
    const report = await scanWorkspaceStatus();
    await installMissingPackages(report);
    return;
  }

  if (args.includes("--setup-env")) {
    await setupEnvironmentFiles();
    return;
  }

  if (args.includes("--start")) {
    await startLocalhostServer();
    return;
  }

  if (args.includes("--stop")) {
    await stopLocalhostServer();
    return;
  }

  if (args.includes("--enable-usb-frida")) {
    await enableUsbFridaViaApi();
    return;
  }

  const tokenIdx = args.indexOf("--set-token");
  if (tokenIdx !== -1 && args[tokenIdx + 1]) {
    await setEnvKeySafe(args[tokenIdx + 1]);
    return;
  }

  if (process.stdin.isTTY) {
    await runInteractiveMenu();
  } else {
    const report = await scanWorkspaceStatus();
    console.log(renderArchifyStatusBox(report));
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().catch((err) => {
    console.error(`✖ Lỗi TUI Quản trị: ${err?.message || String(err)}`);
    process.exit(1);
  });
}
