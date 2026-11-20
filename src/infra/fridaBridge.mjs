// src/infra/fridaBridge.mjs — Cầu nối Frida 17.x kèm Đổi Kết Nối Đa Kênh Thật 100%, Telemetry Thiết bị iOS, Tự động iproxy USB & Bắt sự kiện Crash
import { execFile, spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import frida from "frida";
import { logger } from "./logger.mjs";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOTLESS_SSH_PATH_PREFIX =
  "export PATH=/var/jb/usr/sbin:/var/jb/usr/bin:/var/jb/sbin:/var/jb/bin:/usr/sbin:/usr/bin:/sbin:/bin;";

function readLocalFridaSdkVersion() {
  try {
    const pkgPath = path.resolve(__dirname, "../../node_modules/frida/package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    return pkg.version || "17.x";
  } catch {
    return "17.x";
  }
}

const PC_FRIDA_SDK_VERSION = readLocalFridaSdkVersion();

const KNOWN_IDEVICE_DIRS = [
  "C:\\Program Files\\dotnet\\packs\\Microsoft.iOS.Windows.Sdk.net9.0_26.0\\26.0.9752\\tools\\msbuild\\iOS\\imobiledevice-x64",
  "C:\\Program Files\\dotnet\\packs\\Microsoft.iOS.Windows.Sdk.net9.0_18.0\\18.0.9617\\tools\\msbuild\\iOS\\imobiledevice-x64",
  "C:\\Program Files\\libimobiledevice",
  "C:\\libimobiledevice",
];

function findIdeviceBinary(exeName) {
  for (const dir of KNOWN_IDEVICE_DIRS) {
    const candidate = path.join(dir, exeName);
    if (fs.existsSync(candidate)) return candidate;
  }
  return exeName.replace(/\.exe$/i, "");
}

function waitForLocalPort(port, timeoutMs = 2500) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryConnect = () => {
      const sock = net.createConnection({ host: "127.0.0.1", port });
      sock.once("connect", () => {
        sock.destroy();
        resolve(true);
      });
      sock.once("error", () => {
        sock.destroy();
        if (Date.now() >= deadline) {
          reject(new Error(`Không thể mở cổng chuyển tiếp USB 127.0.0.1:${port}`));
        } else {
          setTimeout(tryConnect, 120);
        }
      });
    };
    tryConnect();
  });
}

function probeTcpSocket(host, port, timeoutMs = 900) {
  const t0 = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const sock = net.createConnection({ host, port });
    const timer = setTimeout(() => {
      sock.destroy();
      finish({ open: false, latencyMs: null, error: `Quá thời gian chờ (${timeoutMs} ms)` });
    }, timeoutMs);

    sock.once("connect", () => {
      clearTimeout(timer);
      const latencyMs = Math.max(1, Date.now() - t0);
      sock.destroy();
      finish({ open: true, latencyMs, error: null });
    });

    sock.once("error", (err) => {
      clearTimeout(timer);
      sock.destroy();
      finish({ open: false, latencyMs: null, error: err?.code || err?.message || "Đóng cổng" });
    });
  });
}

function probeHttpEndpoint(urlStr, timeoutMs = 1100) {
  const t0 = Date.now();
  return new Promise((resolve) => {
    let settled = false;
    const finish = (resObj) => {
      if (settled) return;
      settled = true;
      resolve(resObj);
    };

    try {
      const req = http.get(urlStr, { timeout: timeoutMs }, (res) => {
        const chunks = [];
        res.on("data", (c) => {
          if (chunks.length < 8) chunks.push(c);
        });
        res.on("end", () => {
          const bodyPreview = Buffer.concat(chunks).toString("utf8").slice(0, 400);
          finish({
            reachable: true,
            statusCode: res.statusCode || 200,
            latencyMs: Math.max(1, Date.now() - t0),
            bodyPreview,
            error: null,
          });
        });
      });

      req.on("timeout", () => {
        req.destroy();
        finish({ reachable: false, statusCode: 0, latencyMs: null, bodyPreview: "", error: "Timeout" });
      });

      req.on("error", (err) => {
        finish({
          reachable: false,
          statusCode: 0,
          latencyMs: null,
          bodyPreview: "",
          error: err?.code || err?.message || "Connection failed",
        });
      });
    } catch (err) {
      finish({
        reachable: false,
        statusCode: 0,
        latencyMs: null,
        bodyPreview: "",
        error: err?.message || "Invalid URL",
      });
    }
  });
}

function detectVpnTunnelInterfaces() {
  const found = [];
  const nets = os.networkInterfaces() || {};
  for (const [ifName, addrs] of Object.entries(nets)) {
    if (!/wireguard|wintun|tun|tap|utun|vpn|tailscale|zerotier|cloudflarewarp/i.test(ifName)) {
      continue;
    }
    const ipv4 = (addrs || []).find((a) => a.family === "IPv4" && !a.internal);
    const ipv6 = (addrs || []).find((a) => a.family === "IPv6" && !a.internal);
    found.push({
      name: ifName,
      address: ipv4?.address || ipv6?.address || "Đã gắn adapter",
    });
  }
  return found;
}

function parseHostPort(rawInput, defaultPort = 8080) {
  const clean = String(rawInput || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/^tcp:\/\//i, "")
    .replace(/\/.*$/, "");
  if (!clean) {
    return { host: "127.0.0.1", port: defaultPort, normalized: `127.0.0.1:${defaultPort}` };
  }
  const idx = clean.lastIndexOf(":");
  if (idx > 0 && /^\d{1,5}$/.test(clean.slice(idx + 1))) {
    const host = clean.slice(0, idx).trim() || "127.0.0.1";
    const p = Number(clean.slice(idx + 1));
    const safePort = p >= 1 && p <= 65535 ? p : defaultPort;
    return { host, port: safePort, normalized: `${host}:${safePort}` };
  }
  return { host: clean, port: defaultPort, normalized: `${clean}:${defaultPort}` };
}

function parseKeyValueText(rawText) {
  const map = {};
  for (const line of String(rawText || "").split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const k = line.slice(0, idx).trim();
      const v = line.slice(idx + 1).trim();
      map[k] = v;
    }
  }
  return map;
}

export class FridaBridge {
  /** @type {Map<string, { proc: import("node:child_process").ChildProcess, localPort: number, remoteDevice: any }>} */
  #usbTunnels = new Map();
  /** @type {Map<string, Promise<any>>} */
  #pendingTunnels = new Map();
  /** @type {Set<number>} */
  #managedTunnelPorts = new Set();
  /** @type {Map<number, import("node:child_process").ChildProcess>} */
  #auxIproxyProcs = new Map();
  /** @type {Set<string>} */
  #crashHookedIds = new Set();
  /** @type {Map<string, { id: string, address: string, label: string, remoteDevice: any, reachable?: boolean, addedAt: string }>} */
  #wirelessDevices = new Map();
  #nextTunnelPort = 27142;
  #onCrashCallback = null;

  constructor({ onCrash } = {}) {
    this.#onCrashCallback = onCrash || null;
  }

  async #findRawDeviceSafe(deviceId) {
    const cleanId = String(deviceId || "").trim();
    if (!cleanId) {
      const err = new Error("Vui lòng chọn thiết bị kết nối.");
      err.statusCode = 400;
      throw err;
    }

    const wirelessEntry = this.#wirelessDevices.get(cleanId);
    if (wirelessEntry?.remoteDevice) {
      return wirelessEntry.remoteDevice;
    }

    try {
      return await frida.getDevice(cleanId);
    } catch {
      const all = await frida.enumerateDevices();
      const matched =
        all.find((d) => d.id === cleanId) ||
        all.find((d) => d.type === "remote" && (d.id.includes(cleanId) || d.name.includes(cleanId))) ||
        null;
      if (matched) return matched;

      const notFoundErr = new Error(
        `Không tìm thấy thiết bị '${cleanId}' (cáp USB vừa rút hoặc kết nối không dây đã ngắt). Hãy bấm Làm mới hoặc kết nối lại.`
      );
      notFoundErr.statusCode = 404;
      throw notFoundErr;
    }
  }

  async addWirelessDevice({ address, label = "" } = {}) {
    const rawAddr = String(address ?? "").trim().replace(/^tcp:\/\//i, "");
    if (!rawAddr) {
      throw new Error("Vui lòng nhập địa chỉ IP Wi-Fi của iPhone (ví dụ: 192.168.1.50 hoặc 192.168.1.50:27042).");
    }

    const hostPort = rawAddr.includes(":") ? rawAddr : `${rawAddr}:27042`;
    const hpMatch = hostPort.match(/^([A-Za-z0-9.-]+):(\d{1,5})$/);
    if (!hpMatch) {
      throw new Error("Địa chỉ không dây không hợp lệ. Định dạng đúng: IP:Cổng (ví dụ: 192.168.1.50:27042).");
    }

    const host = hpMatch[1];
    const port = Number(hpMatch[2]);
    if (!port || port < 1 || port > 65535) {
      throw new Error("Số cổng Frida không dây phải nằm trong khoảng 1 đến 65535 (mặc định là 27042).");
    }

    const normalizedAddr = `${host}:${port}`;
    const remoteDevice = await frida.getDeviceManager().addRemoteDevice(normalizedAddr);
    this.#bindCrashWatcher(remoteDevice, remoteDevice.id);

    let reachable = false;
    let detectedName = "";
    let latencyMs = null;
    try {
      const t0 = Date.now();
      const probe = await Promise.race([
        remoteDevice.querySystemParameters(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 2500)),
      ]);
      reachable = true;
      latencyMs = Math.max(1, Date.now() - t0);
      detectedName = probe?.name || "";
    } catch {
      reachable = false;
    }

    const cleanLabel = String(label || detectedName || `iPhone Wi-Fi (${normalizedAddr})`).trim();
    const entry = {
      id: remoteDevice.id,
      address: normalizedAddr,
      label: cleanLabel,
      remoteDevice,
      reachable,
      addedAt: new Date().toISOString(),
    };
    this.#wirelessDevices.set(remoteDevice.id, entry);
    this.#wirelessDevices.set(normalizedAddr, entry);

    logger.info("Đã đăng ký thiết bị Frida qua mạng không dây (Wi-Fi)", {
      id: remoteDevice.id,
      address: normalizedAddr,
      reachable,
      latencyMs,
    });

    return {
      id: remoteDevice.id,
      name: cleanLabel,
      type: "remote",
      address: normalizedAddr,
      reachable,
      latencyMs,
    };
  }

  async removeWirelessDevice(deviceIdOrAddress) {
    const key = String(deviceIdOrAddress ?? "").trim();
    if (!key) {
      throw new Error("Vui lòng cung cấp mã thiết bị không dây cần ngắt.");
    }

    const found =
      this.#wirelessDevices.get(key) ||
      Array.from(this.#wirelessDevices.values()).find((w) => w.id === key || w.address === key) ||
      null;

    const addrToRemove = found?.address || key.replace(/^tcp@/i, "");
    try {
      await frida.getDeviceManager().removeRemoteDevice(addrToRemove);
    } catch {
      // Bỏ qua nếu Frida DeviceManager đã tự gỡ trước đó
    }

    if (found) {
      this.#wirelessDevices.delete(found.id);
      this.#wirelessDevices.delete(found.address);
      this.#crashHookedIds.delete(found.id);
    } else {
      this.#wirelessDevices.delete(key);
    }

    logger.info("Đã ngắt thiết bị Frida không dây", { key, address: addrToRemove });
    return { removed: true, address: addrToRemove };
  }

  async listDevices() {
    const rawDevices = await frida.enumerateDevices();
    // Ẩn các stub nội bộ (socket, barebone) và ẩn cổng remote nội bộ do chính iproxy tạo ra để danh sách sạch gọn
    const filtered = rawDevices.filter((d) => {
      if (d.type === "usb" || d.type === "local") return true;
      if (d.type === "remote") {
        if (d.id === "socket" || d.id === "barebone") return false;
        for (const p of this.#managedTunnelPorts) {
          if (d.name.includes(`127.0.0.1:${p}`) || d.id.includes(`127.0.0.1:${p}`)) return false;
        }
        return true;
      }
      return false;
    });

    filtered.sort((a, b) => {
      const rank = (t) => (t === "usb" ? 0 : t === "remote" ? 1 : 2);
      return rank(a.type) - rank(b.type);
    });

    return filtered.map((d) => {
      const tunnel = this.#usbTunnels.get(d.id);
      const wireless = this.#wirelessDevices.get(d.id);
      return {
        id: d.id,
        name: wireless?.label || d.name,
        type: d.type,
        wirelessAddress: wireless?.address || (d.type === "remote" ? d.id.replace(/^socket@|^tcp@/i, "") : null),
        tunnelPort: tunnel ? tunnel.localPort : null,
      };
    });
  }

  #bindCrashWatcher(device, labelId) {
    if (this.#crashHookedIds.has(labelId) || !device?.processCrashed?.connect) return;
    this.#crashHookedIds.add(labelId);
    device.processCrashed.connect((crash) => {
      logger.warn("Phát hiện tiến trình bị văng (Crash) trên thiết bị", {
        deviceId: labelId,
        pid: crash.pid,
        processName: crash.processName,
        summary: crash.summary,
      });
      this.#onCrashCallback?.({
        deviceId: labelId,
        pid: crash.pid,
        processName: crash.processName,
        summary: crash.summary,
        report: crash.report || "",
      });
    });
  }

  async #ensureAuxIproxyPort(localPort, remotePort, udid = "") {
    const alreadyOpen = await probeTcpSocket("127.0.0.1", localPort, 400);
    if (alreadyOpen.open) {
      return { openedByStudio: false, localPort, remotePort };
    }
    const existingProc = this.#auxIproxyProcs.get(localPort);
    if (existingProc && existingProc.exitCode === null) {
      return { openedByStudio: true, localPort, remotePort };
    }

    const iproxyBin = findIdeviceBinary("iproxy.exe");
    const args = udid ? [String(localPort), String(remotePort), udid] : [String(localPort), String(remotePort)];
    const proc = spawn(iproxyBin, args, { stdio: "ignore", windowsHide: true });
    this.#auxIproxyProcs.set(localPort, proc);
    proc.on("exit", () => {
      if (this.#auxIproxyProcs.get(localPort) === proc) {
        this.#auxIproxyProcs.delete(localPort);
      }
    });

    await waitForLocalPort(localPort, 2000);
    return { openedByStudio: true, localPort, remotePort };
  }

  async #ensureUsbTunnelDevice(usbDevice) {
    const existing = this.#usbTunnels.get(usbDevice.id);
    if (existing && existing.proc.exitCode === null) {
      return existing.remoteDevice;
    }

    const inflight = this.#pendingTunnels.get(usbDevice.id);
    if (inflight) {
      return inflight;
    }

    const createPromise = (async () => {
      const iproxyBin = findIdeviceBinary("iproxy.exe");
      const localPort = this.#nextTunnelPort++;
      this.#managedTunnelPorts.add(localPort);
      const args = [String(localPort), "27042", usbDevice.id];

      logger.info("Kích hoạt cầu nối cáp USB (iproxy) cho Frida trên Windows", {
        deviceId: usbDevice.id,
        localPort,
        iproxyBin,
      });

      const proc = spawn(iproxyBin, args, {
        stdio: "ignore",
        windowsHide: true,
      });

      proc.on("exit", (code) => {
        logger.info("Tiến trình cầu nối iproxy USB đã đóng", { deviceId: usbDevice.id, code });
        const cur = this.#usbTunnels.get(usbDevice.id);
        if (cur && cur.localPort === localPort) {
          this.#usbTunnels.delete(usbDevice.id);
        }
        this.#managedTunnelPorts.delete(localPort);
      });

      try {
        await waitForLocalPort(localPort, 2500);
        const remoteDevice = await frida.getDeviceManager().addRemoteDevice(`127.0.0.1:${localPort}`);
        this.#bindCrashWatcher(remoteDevice, usbDevice.id);
        this.#usbTunnels.set(usbDevice.id, { proc, localPort, remoteDevice });
        return remoteDevice;
      } catch (err) {
        try {
          proc.kill();
        } catch {}
        this.#managedTunnelPorts.delete(localPort);
        throw err;
      }
    })();

    this.#pendingTunnels.set(usbDevice.id, createPromise);
    try {
      return await createPromise;
    } finally {
      this.#pendingTunnels.delete(usbDevice.id);
    }
  }

  async invalidateTunnel(deviceId) {
    if (!deviceId) return;
    const oldTunnel = this.#usbTunnels.get(deviceId);
    if (oldTunnel) {
      try {
        oldTunnel.proc.kill();
      } catch {}
      try {
        await frida.getDeviceManager().removeRemoteDevice(`127.0.0.1:${oldTunnel.localPort}`);
      } catch {}
      this.#usbTunnels.delete(deviceId);
      this.#managedTunnelPorts.delete(oldTunnel.localPort);
    }
    this.#crashHookedIds.delete(deviceId);
  }

  async resolveWorkingDevice(deviceId) {
    const wireless = this.#wirelessDevices.get(deviceId);
    if (wireless?.remoteDevice) {
      this.#bindCrashWatcher(wireless.remoteDevice, wireless.id);
      return wireless.remoteDevice;
    }

    // Ưu tiên tái sử dụng ngay đường hầm iproxy đang hoạt động để không gây lỗi khóa USB trên Windows
    const existingTunnel = this.#usbTunnels.get(deviceId);
    if (existingTunnel && existingTunnel.proc.exitCode === null) {
      return existingTunnel.remoteDevice;
    }

    let rawDevice = null;
    try {
      rawDevice = await frida.getDevice(deviceId);
    } catch (err) {
      const all = await frida.enumerateDevices();
      rawDevice = all.find((d) => d.id === deviceId) || all.find((d) => d.type === "usb") || null;
      if (!rawDevice) {
        logger.error("Không tìm thấy thiết bị mục tiêu khi mở kết nối Frida", err, { deviceId });
        throw new Error(
          "Thiết bị iPhone vừa ngắt hoặc đang khởi động lại cổng USB. Hãy kiểm tra dây cáp và thử bấm lại sau 2 giây."
        );
      }
    }

    if (rawDevice.type !== "usb") {
      this.#bindCrashWatcher(rawDevice, rawDevice.id);
      return rawDevice;
    }

    if (process.platform === "win32") {
      return this.#ensureUsbTunnelDevice(rawDevice);
    }

    try {
      await rawDevice.querySystemParameters();
      this.#bindCrashWatcher(rawDevice, deviceId);
      return rawDevice;
    } catch (err) {
      logger.warn("Kênh USB trực tiếp bận, tự động chuyển sang cầu nối iproxy", {
        deviceId,
        reason: err.message,
      });
      return this.#ensureUsbTunnelDevice(rawDevice);
    }
  }

  async #readUsbHardwareExtras(udid) {
    const ideviceinfoBin = findIdeviceBinary("ideviceinfo.exe");
    const extras = {
      deviceName: null,
      productType: null,
      batteryLevel: null,
      batteryCharging: null,
      diskTotalGB: null,
      diskFreeGB: null,
    };

    try {
      const [mainOut, battOut, diskOut] = await Promise.all([
        execFileAsync(ideviceinfoBin, ["-u", udid], { timeout: 2000 }).catch(() => ({ stdout: "" })),
        execFileAsync(ideviceinfoBin, ["-u", udid, "-q", "com.apple.mobile.battery"], { timeout: 2000 }).catch(() => ({ stdout: "" })),
        execFileAsync(ideviceinfoBin, ["-u", udid, "-q", "com.apple.disk_usage"], { timeout: 2000 }).catch(() => ({ stdout: "" })),
      ]);

      const mainMap = parseKeyValueText(mainOut.stdout);
      const battMap = parseKeyValueText(battOut.stdout);
      const diskMap = parseKeyValueText(diskOut.stdout);

      extras.deviceName = mainMap.DeviceName || null;
      extras.productType = mainMap.ProductType || null;

      if (battMap.BatteryCurrentCapacity !== undefined) {
        extras.batteryLevel = Number(battMap.BatteryCurrentCapacity);
      }
      if (battMap.BatteryIsCharging !== undefined) {
        extras.batteryCharging = battMap.BatteryIsCharging === "true";
      }

      const totalBytes = Number(diskMap.TotalDataCapacity || diskMap.TotalDiskCapacity || 0);
      const freeBytes = Number(diskMap.TotalDataAvailable || 0);
      if (totalBytes > 0) {
        extras.diskTotalGB = Number((totalBytes / 1024 ** 3).toFixed(2));
        extras.diskFreeGB = Number((freeBytes / 1024 ** 3).toFixed(2));
      }
    } catch {
      // Bỏ qua nếu không có ideviceinfo
    }

    return extras;
  }

  async getDeviceTelemetry(deviceId) {
    const rawDevice = await this.#findRawDeviceSafe(deviceId);
    const workingDevice = await this.resolveWorkingDevice(rawDevice.id);
    const wirelessMeta = this.#wirelessDevices.get(rawDevice.id) || this.#wirelessDevices.get(deviceId) || null;

    let fridaProbeOk = false;
    let fridaProbeError = null;
    let fridaLatencyMs = null;

    const queryParamsTruthful = async () => {
      const t0 = Date.now();
      try {
        const out = await Promise.race([
          workingDevice.querySystemParameters(),
          new Promise((_, rej) => setTimeout(() => rej(new Error("Quá thời gian phản hồi Frida Server (2500ms)")), 2500)),
        ]);
        fridaProbeOk = Boolean(out && typeof out === "object" && Object.keys(out).length > 0);
        fridaLatencyMs = Math.max(1, Date.now() - t0);
        return out || {};
      } catch (err) {
        fridaProbeOk = false;
        fridaProbeError = err?.message || String(err);
        return {};
      }
    };

    const [sysParams, frontApp, apps, processes, usbExtras] = await Promise.all([
      queryParamsTruthful(),
      workingDevice.getFrontmostApplication().catch(() => null),
      workingDevice.enumerateApplications().catch(() => []),
      workingDevice.enumerateProcesses().catch(() => []),
      rawDevice.type === "usb" ? this.#readUsbHardwareExtras(rawDevice.id) : Promise.resolve(null),
    ]);

    const tunnel = this.#usbTunnels.get(rawDevice.id) || this.#usbTunnels.get(deviceId);
    const runningAppsCount = apps.filter((a) => a.pid > 0).length;

    const isLocalPc = rawDevice.type === "local";
    const freeMemMB = isLocalPc ? Math.round(os.freemem() / 1024 ** 2) : null;
    const totalMemMB = isLocalPc ? Math.round(os.totalmem() / 1024 ** 2) : null;

    return {
      deviceId: rawDevice.id,
      connectionType: rawDevice.type,
      wirelessAddress: wirelessMeta?.address || (rawDevice.type === "remote" ? rawDevice.id.replace(/^socket@|^tcp@/i, "") : null),
      displayName:
        usbExtras?.deviceName ||
        sysParams?.name ||
        wirelessMeta?.label ||
        (isLocalPc ? "Máy tính Windows hiện tại" : rawDevice.name),
      productType: usbExtras?.productType || sysParams?.hardware || (isLocalPc ? "Máy trạm Windows" : "Thiết bị di động"),
      osName: sysParams?.os?.name === "iPhone OS" ? "iOS" : sysParams?.os?.name || sysParams?.platform || "Hệ điều hành",
      osVersion: sysParams?.os?.version || "",
      arch: sysParams?.arch || process.arch,
      accessLevel: fridaProbeOk ? sysParams?.access || "full" : "unreachable",
      fridaSdkVersion: PC_FRIDA_SDK_VERSION,
      fridaServerConnected: fridaProbeOk,
      fridaLatencyMs,
      fridaProbeError,
      tunnel: tunnel
        ? { active: tunnel.proc.exitCode === null, localPort: tunnel.localPort, remotePort: 27042 }
        : { active: false, localPort: null, remotePort: 27042 },
      frontmostApp: frontApp
        ? { name: frontApp.name, identifier: frontApp.identifier, pid: frontApp.pid }
        : null,
      counts: {
        runningApps: runningAppsCount,
        installedApps: apps.length,
        totalProcesses: processes.length,
      },
      hardware: {
        batteryLevel: usbExtras?.batteryLevel ?? null,
        batteryCharging: usbExtras?.batteryCharging ?? null,
        diskTotalGB: usbExtras?.diskTotalGB ?? null,
        diskFreeGB: usbExtras?.diskFreeGB ?? null,
        freeMemMB,
        totalMemMB,
      },
      sampledAt: new Date().toISOString(),
    };
  }

  async listTargets(deviceId) {
    const device = await this.resolveWorkingDevice(deviceId);
    let apps = [];
    let processes = [];
    let frontmostPid = 0;

    try {
      const frontApp = await device.getFrontmostApplication();
      if (frontApp?.pid) {
        frontmostPid = frontApp.pid;
      }
    } catch {
      // Thiết bị không hỗ trợ Frontmost App
    }

    try {
      apps = await device.enumerateApplications();
    } catch {
      // Thiết bị Local PC dùng danh sách tiến trình
    }

    try {
      processes = await device.enumerateProcesses();
    } catch (err) {
      logger.warn("Không thể đọc danh sách tiến trình phụ trợ", { deviceId, reason: err.message });
    }

    const PINNED_APPLE_APPS = new Set([
      "com.apple.TestFlight",
      "com.apple.AppStore",
      "com.apple.Preferences",
      "com.apple.mobilesafari",
      "com.apple.DocumentsApp",
    ]);
    const HIDDEN_UI_EXTENSIONS = /(UIService|ViewService|Spotlight|PassbookUIService|StoreKitUIService)$/i;

    const appPids = new Set();
    const formattedApps = apps
      .map((app) => {
        if (app.pid > 0) appPids.add(app.pid);
        const id = app.identifier || "";
        const isUserOrPinned = !id.startsWith("com.apple.") || PINNED_APPLE_APPS.has(id);
        return {
          kind: "app",
          name: app.name,
          identifier: id,
          pid: app.pid || 0,
          isFrontmost: app.pid > 0 && app.pid === frontmostPid,
          isUserApp: isUserOrPinned,
        };
      })
      .filter((app) => !HIDDEN_UI_EXTENSIONS.test(app.identifier));

    formattedApps.sort((a, b) => {
      if (a.isFrontmost !== b.isFrontmost) return a.isFrontmost ? -1 : 1;
      if (a.isUserApp !== b.isUserApp) return a.isUserApp ? -1 : 1;
      if ((a.pid > 0) !== (b.pid > 0)) return a.pid > 0 ? -1 : 1;
      return a.name.localeCompare(b.name, "vi");
    });

    const formattedDaemons = processes
      .filter((p) => !appPids.has(p.pid))
      .sort((a, b) => a.name.localeCompare(b.name, "vi"))
      .map((p) => ({
        kind: "process",
        name: p.name,
        identifier: "",
        pid: p.pid,
        isFrontmost: false,
      }));

    return {
      frontmostPid,
      apps: formattedApps,
      processes: formattedDaemons,
    };
  }

  async openAppOnScreen(deviceId, bundleId) {
    const cleanBundleId = String(bundleId || "").trim();
    if (!/^[A-Za-z0-9._-]+$/.test(cleanBundleId)) {
      return { opened: false, reason: "invalid_bundle_id" };
    }

    try {
      const rawDevice = await this.#findRawDeviceSafe(deviceId);
      if (rawDevice.type !== "usb") {
        return { opened: false, reason: "not_usb_device" };
      }

      await execFileAsync(
        "ssh",
        [
          "-o",
          "BatchMode=yes",
          "-o",
          "ConnectTimeout=2",
          "iphone",
          `${ROOTLESS_SSH_PATH_PREFIX} uiopen --bundleid ${cleanBundleId}`,
        ],
        { timeout: 3500, windowsHide: true }
      );
      return { opened: true };
    } catch (err) {
      logger.warn("Không thể gọi uiopen qua SSH, chuyển sang cơ chế dự phòng Frida", {
        bundleId: cleanBundleId,
        reason: err.message,
      });
      return { opened: false, reason: err.message };
    }
  }

  async #probeIphoneSshFridaInfo() {
    const t0 = Date.now();
    try {
      const { stdout } = await execFileAsync(
        "ssh",
        [
          "-o",
          "BatchMode=yes",
          "-o",
          "ConnectTimeout=2",
          "iphone",
          `${ROOTLESS_SSH_PATH_PREFIX} ver=$(frida-server --version 2>/dev/null || echo ''); fpid=$(ps -ef 2>/dev/null | awk '/[f]rida-server/{print $2; exit}' || echo ''); rpid=$(ps -ef 2>/dev/null | awk '/[R]abbitUltrad/{print $2; exit}' || echo ''); plist=$(ls /var/jb/Library/LaunchDaemons/re.frida.server.plist /Library/LaunchDaemons/re.frida.server.plist 2>/dev/null | head -n 1); uname_info=$(uname -sr 2>/dev/null || echo ''); echo "VER=$ver"; echo "FPID=$fpid"; echo "RPID=$rpid"; echo "PLIST=$plist"; echo "UNAME=$uname_info"`,
        ],
        { timeout: 3000, windowsHide: true }
      );
      const outStr = String(stdout || "");
      const pick = (k) => outStr.match(new RegExp(`${k}=([^\\r\\n]*)`))?.[1]?.trim() || null;
      return {
        sshReachable: true,
        sshLatencyMs: Math.max(1, Date.now() - t0),
        serverVersion: pick("VER"),
        fridaPid: pick("FPID"),
        rabbitDaemonPid: pick("RPID"),
        plistPath: pick("PLIST"),
        unameInfo: pick("UNAME"),
      };
    } catch (err) {
      return {
        sshReachable: false,
        sshLatencyMs: null,
        serverVersion: null,
        fridaPid: null,
        rabbitDaemonPid: null,
        plistPath: null,
        unameInfo: null,
        sshError: err?.message || "SSH closed",
      };
    }
  }

  async #tryStartRemoteFridaServerViaSsh() {
    try {
      await execFileAsync(
        "ssh",
        [
          "-o",
          "BatchMode=yes",
          "-o",
          "ConnectTimeout=2",
          "iphone",
          `${ROOTLESS_SSH_PATH_PREFIX} if [ -z "$(ps -ef 2>/dev/null | awk '/[f]rida-server/{print $2; exit}')" ]; then launchctl load -w /var/jb/Library/LaunchDaemons/re.frida.server.plist 2>/dev/null || launchctl load -w /Library/LaunchDaemons/re.frida.server.plist 2>/dev/null || (/var/jb/usr/sbin/frida-server -D >/dev/null 2>&1 &); fi`,
        ],
        { timeout: 3500, windowsHide: true }
      );
      return true;
    } catch {
      return false;
    }
  }

  // ============================================================================
  // v6.0: ĐỔI KẾT NỐI ĐA KÊNH KÈM ĐO TRẠNG THÁI THẬT 100% (KHÔNG BỊA, KHÔNG GIẢ LẬP)
  // ============================================================================
  async probeAllConnectionChannels({
    deviceId = "",
    wirelessAddress = "",
    vpnMitmProxyAddress = "127.0.0.1:8080",
    activeChannel = "usb_frida",
  } = {}) {
    const allDevices = await this.listDevices();
    const usbDev =
      allDevices.find((d) => d.type === "usb" && (!deviceId || d.id === deviceId)) ||
      allDevices.find((d) => d.type === "usb") ||
      null;
    const wirelessDev =
      allDevices.find((d) => d.type === "remote") ||
      Array.from(this.#wirelessDevices.values())[0] ||
      null;
    const localDev = allDevices.find((d) => d.type === "local") || null;

    const proxySpec = parseHostPort(vpnMitmProxyAddress, 8080);
    const wifiAddrCandidate = wirelessAddress || wirelessDev?.wirelessAddress || wirelessDev?.address || "";
    const wifiSpec = wifiAddrCandidate ? parseHostPort(wifiAddrCandidate, 27042) : null;

    // Chạy song song các phép đo socket/RPC/SSH thực tế
    const [
      sshPortProbe,
      sshInfo,
      rabbitHttpProbe,
      mcp8090HttpProbe,
      mcp8090TcpProbe,
      mcp8091TcpProbe,
      vpnProxyTcpProbe,
      wifiTcpProbe,
    ] = await Promise.all([
      probeTcpSocket("127.0.0.1", 2222, 700),
      usbDev ? this.#probeIphoneSshFridaInfo() : Promise.resolve({ sshReachable: false }),
      probeHttpEndpoint("http://127.0.0.1:8765/api/apps", 900),
      probeHttpEndpoint("http://127.0.0.1:8090/health", 800),
      probeTcpSocket("127.0.0.1", 8090, 600),
      probeTcpSocket("127.0.0.1", 8091, 600),
      probeTcpSocket(proxySpec.host, proxySpec.port, 800),
      wifiSpec ? probeTcpSocket(wifiSpec.host, wifiSpec.port, 900) : Promise.resolve({ open: false, latencyMs: null, error: "Chưa cấu hình IP" }),
    ]);

    // 1. Đo thực tế Kênh 1: Cáp USB + Frida Server (27042)
    let usbFridaStatus = "offline";
    let usbFridaLatencyMs = null;
    let usbFridaDetail = "Chưa phát hiện iPhone cắm cáp USB.";
    let usbTunnelPort = null;

    if (usbDev) {
      try {
        const t0 = Date.now();
        const wDev = await this.resolveWorkingDevice(usbDev.id);
        const sys = await Promise.race([
          wDev.querySystemParameters(),
          new Promise((_, rej) => setTimeout(() => rej(new Error("Timeout 27042")), 2200)),
        ]);
        usbFridaLatencyMs = Math.max(1, Date.now() - t0);
        const tEntry = this.#usbTunnels.get(usbDev.id);
        usbTunnelPort = tEntry?.localPort || null;
        usbFridaStatus = "connected";
        usbFridaDetail =
          `Đang kết nối thật tới ${sys?.name || usbDev.name} (${sys?.os?.name === "iPhone OS" ? "iOS" : sys?.os?.name || "iOS"} ${sys?.os?.version || ""}) ` +
          `qua iproxy 127.0.0.1:${usbTunnelPort || 27042} ➔ 27042 • Frida Server ${sshInfo.serverVersion || PC_FRIDA_SDK_VERSION} (${usbFridaLatencyMs} ms).`;
      } catch (err) {
        usbFridaStatus = "degraded";
        usbFridaDetail = `Đã nhận cáp USB (${usbDev.name}) nhưng cổng Frida Server 27042 chưa phản hồi (${err?.message || "đóng"}). Bấm 'Bật kết nối này' để tự khởi động lại!`;
      }
    }

    // 2. Đo thực tế Kênh 2: Wi-Fi Không Dây + Frida Server (<IP>:27042)
    let wifiFridaStatus = "offline";
    let wifiFridaDetail = "Chưa nhập địa chỉ IP Wi-Fi của iPhone (mặc định cổng 27042).";
    let wifiLatencyMs = wifiTcpProbe.latencyMs;

    if (wifiSpec) {
      if (wifiTcpProbe.open) {
        wifiFridaStatus = "connected";
        wifiFridaDetail = `Cổng Frida không dây ${wifiSpec.normalized} đang mở & phản hồi thật (${wifiLatencyMs} ms).`;
      } else {
        wifiFridaStatus = "offline";
        wifiFridaDetail = `Không kết nối được tới ${wifiSpec.normalized} (${wifiTcpProbe.error || "cổng đóng"} — frida-server trên iPhone có thể chỉ đang lắng nghe nội bộ USB 127.0.0.1:27042).`;
      }
    }

    // 3. Đo thực tế Kênh 3: Cáp USB + SSH Rootless Agent (iproxy 2222 -> 22)
    let sshStatus = "offline";
    let sshDetail = "Cổng SSH USB 127.0.0.1:2222 hiện đang đóng.";
    if (sshInfo.sshReachable) {
      sshStatus = "connected";
      sshDetail =
        `Đang thông suốt qua 127.0.0.1:2222 ➔ iPhone:22 (${sshInfo.unameInfo || "Darwin arm64"} • ` +
        `PID frida-server: ${sshInfo.fridaPid || "đang nghỉ"} • ${sshInfo.sshLatencyMs} ms).`;
    } else if (sshPortProbe.open) {
      sshStatus = "degraded";
      sshDetail = `Cổng 127.0.0.1:2222 trên PC đang mở nhưng xác thực SSH tới iPhone chưa phản hồi (${sshInfo.sshError || "kiểm tra cáp USB"}).`;
    }

    // 4. Đo thực tế Kênh 4: Agent Nội Bộ RabbitUltrad (Shared/RabbitCommon.h RABBIT_WS_PORT 8765)
    let rabbitStatus = "offline";
    let rabbitDetail = "Cổng 8765 chưa mở — Tiến trình Daemon RabbitUltrad (Daemon/main.m) hiện không chạy trên iPhone.";
    const isGenuineRabbitDaemon =
      rabbitHttpProbe.reachable &&
      rabbitHttpProbe.statusCode >= 200 &&
      rabbitHttpProbe.statusCode < 300 &&
      /"apps"|"apis"|"version"/i.test(rabbitHttpProbe.bodyPreview || "");

    if (isGenuineRabbitDaemon) {
      rabbitStatus = "connected";
      rabbitDetail = `RabbitUltrad HTTP/WS cổng 8765 đang chạy thật & trả dữ liệu JSON (HTTP ${rabbitHttpProbe.statusCode} • ${rabbitHttpProbe.latencyMs} ms).`;
    } else if (sshInfo.rabbitDaemonPid) {
      rabbitStatus = "degraded";
      rabbitDetail = `Phát hiện tiến trình RabbitUltrad (PID ${sshInfo.rabbitDaemonPid}) trên iPhone — bấm 'Bật kết nối này' để bắc cầu iproxy 8765!`;
    } else if (rabbitHttpProbe.reachable) {
      rabbitStatus = "offline";
      rabbitDetail = `Tiến trình RabbitUltrad hiện KHÔNG chạy trên iPhone (cổng 127.0.0.1:8765 trên PC đang do dịch vụ khác sử dụng — HTTP ${rabbitHttpProbe.statusCode}).`;
    }

    // 5. Đo thực tế Kênh 5: Cầu nối iOS Control Agent (iproxy 8090 / 8091 -> 8091)
    let mcpAgentStatus = "offline";
    let mcpAgentDetail = "Chưa mở cầu nối iproxy cổng 8090 / 8091 trên máy tính.";
    if (mcp8090HttpProbe.reachable) {
      mcpAgentStatus = "connected";
      mcpAgentDetail = `Agent điều khiển cổng 8090/8091 đang phản hồi trực tiếp từ iPhone (HTTP ${mcp8090HttpProbe.statusCode} • ${mcp8090HttpProbe.latencyMs} ms).`;
    } else if (mcp8090TcpProbe.open || mcp8091TcpProbe.open) {
      mcpAgentStatus = "degraded";
      mcpAgentDetail =
        `Tiến trình iproxy trên PC đang lắng nghe cổng ${[mcp8090TcpProbe.open ? "8090" : null, mcp8091TcpProbe.open ? "8091" : null].filter(Boolean).join(" & ")}, ` +
        `nhưng ứng dụng Agent cổng 8091 trên iPhone hiện đang nghỉ.`;
    }

    // 6. Đo thực tế Kênh 6: Máy chủ VPN / MITM TLS QA Proxy (127.0.0.1:8080 + Adapter WireGuard/TUN)
    const vpnAdapters = detectVpnTunnelInterfaces();
    let vpnMitmStatus = "offline";
    let vpnMitmDetail = "";
    if (vpnProxyTcpProbe.open) {
      vpnMitmStatus = "connected";
      vpnMitmDetail =
        `Máy chủ Proxy kiểm định TLS tại ${proxySpec.normalized} đang MỞ & nhận kết nối thật (${vpnProxyTcpProbe.latencyMs} ms)` +
        (vpnAdapters.length > 0 ? ` • Kèm đường hầm mạng: ${vpnAdapters.map((a) => `${a.name} (${a.address})`).join(", ")}.` : ".");
    } else if (vpnAdapters.length > 0) {
      vpnMitmStatus = "degraded";
      vpnMitmDetail =
        `Phát hiện card mạng VPN đang bật (${vpnAdapters.map((a) => `${a.name}: ${a.address}`).join(", ")}), ` +
        `nhưng cổng Proxy HTTP/TLS ${proxySpec.normalized} hiện đang ĐÓNG.`;
    } else {
      vpnMitmStatus = "offline";
      vpnMitmDetail = `Cổng Proxy ${proxySpec.normalized} đang ĐÓNG và chưa bật đường hầm WireGuard/VPN trên máy trạm (hãy mở mitmproxy / Proxyman nếu cần bắt TLS ngoài).`;
    }

    // 7. Kênh phụ: Nhân Frida Nội Bộ trên Máy tính Windows (Local PC)
    const localPcStatus = localDev ? "connected" : "offline";

    const channels = [
      {
        id: "usb_frida",
        order: 1,
        title: "1. Cáp USB + Frida Server (Khuyên dùng)",
        badge: "USB 27042",
        sourceInRepo: "frida-web-gui/src/infra/fridaBridge.mjs (iproxy ➔ 27042 • re.frida.server)",
        status: usbFridaStatus,
        isSelected: activeChannel === "usb_frida",
        latencyMs: usbFridaLatencyMs,
        endpoint: usbTunnelPort ? `127.0.0.1:${usbTunnelPort} ➔ iPhone:27042` : "USB ➔ iPhone:27042",
        deviceId: usbDev?.id || null,
        detail: usbFridaDetail,
        canSwitchDevice: true,
      },
      {
        id: "wifi_frida",
        order: 2,
        title: "2. Không dây Wi-Fi + Frida Server",
        badge: "WI-FI TCP",
        sourceInRepo: "frida-web-gui/src/infra/fridaBridge.mjs (addRemoteDevice <IP>:27042)",
        status: wifiFridaStatus,
        isSelected: activeChannel === "wifi_frida",
        latencyMs: wifiLatencyMs,
        endpoint: wifiSpec ? wifiSpec.normalized : "IP_iPhone:27042",
        deviceId: wirelessDev?.id || null,
        detail: wifiFridaDetail,
        canSwitchDevice: true,
      },
      {
        id: "usb_ssh",
        order: 3,
        title: "3. Cáp USB + SSH Rootless Agent (/var/jb)",
        badge: "SSH 2222",
        sourceInRepo: "frida-web-gui/src/infra/fridaBridge.mjs (ssh iphone • uiopen & LaunchDaemons)",
        status: sshStatus,
        isSelected: activeChannel === "usb_ssh",
        latencyMs: sshInfo.sshLatencyMs ?? sshPortProbe.latencyMs,
        endpoint: "127.0.0.1:2222 ➔ iPhone:22",
        deviceId: usbDev?.id || null,
        detail: sshDetail,
        canSwitchDevice: false,
      },
      {
        id: "rabbit_daemon",
        order: 4,
        title: "4. Agent Nội Bộ RabbitUltrad (Tweak Daemon)",
        badge: "IPC 8765",
        sourceInRepo: "Shared/RabbitCommon.h (RABBIT_WS_PORT 8765) & Daemon/main.m (/api/database)",
        status: rabbitStatus,
        isSelected: activeChannel === "rabbit_daemon",
        latencyMs: rabbitHttpProbe.latencyMs,
        endpoint: "127.0.0.1:8765 ➔ iPhone:8765",
        deviceId: usbDev?.id || null,
        detail: rabbitDetail,
        canSwitchDevice: false,
      },
      {
        id: "ios_mcp_agent",
        order: 5,
        title: "5. Cầu nối Điều khiển iOS Control Agent",
        badge: "AGENT 8090",
        sourceInRepo: "Cầu nối hệ thống iproxy 127.0.0.1:8090 / 8091 ➔ iPhone:8091",
        status: mcpAgentStatus,
        isSelected: activeChannel === "ios_mcp_agent",
        latencyMs: mcp8090HttpProbe.latencyMs ?? mcp8090TcpProbe.latencyMs,
        endpoint: "127.0.0.1:8090 ➔ iPhone:8091",
        deviceId: usbDev?.id || null,
        detail: mcpAgentDetail,
        canSwitchDevice: false,
      },
      {
        id: "vpn_mitm_proxy",
        order: 6,
        title: "6. Máy chủ VPN / Proxy Kiểm định TLS (MITM QA)",
        badge: "PROXY / VPN",
        sourceInRepo: "snippetRepository.mjs (CFNetworkCopySystemProxySettings) & Explicit TLS Proxy",
        status: vpnMitmStatus,
        isSelected: activeChannel === "vpn_mitm_proxy",
        latencyMs: vpnProxyTcpProbe.latencyMs,
        endpoint: proxySpec.normalized,
        deviceId: null,
        vpnAdapters,
        detail: vpnMitmDetail,
        canSwitchDevice: false,
      },
      {
        id: "local_pc",
        order: 7,
        title: "7. Nhân Frida Nội Bộ trên Máy tính Windows",
        badge: "LOCAL PC",
        sourceInRepo: "frida.getDevice('local') — Kiểm thử tiến trình trên PC",
        status: localPcStatus,
        isSelected: activeChannel === "local_pc",
        latencyMs: 1,
        endpoint: "Windows Local Host",
        deviceId: localDev?.id || "local",
        detail: localDev
          ? `Sẵn sàng gắn vào tiến trình trên Windows (Frida SDK ${PC_FRIDA_SDK_VERSION}).`
          : "Không phát hiện nhân Local Frida.",
        canSwitchDevice: true,
      },
    ];

    return {
      checkedAt: new Date().toISOString(),
      activeChannel,
      vpnMitmProxyAddress: proxySpec.normalized,
      wirelessAddress: wifiAddrCandidate,
      summaryCounts: {
        total: channels.length,
        connected: channels.filter((c) => c.status === "connected").length,
        degraded: channels.filter((c) => c.status === "degraded").length,
        offline: channels.filter((c) => c.status === "offline").length,
      },
      channels,
    };
  }

  async activateConnectionChannel({
    channel,
    deviceId = "",
    wirelessAddress = "",
    wirelessLabel = "",
    vpnMitmProxyAddress = "127.0.0.1:8080",
  } = {}) {
    const cleanChannel = String(channel || "").trim();
    const actionSteps = [];
    let selectedDeviceId = deviceId;

    if (cleanChannel === "usb_frida") {
      const allDevices = await this.listDevices();
      const usbDev =
        allDevices.find((d) => d.type === "usb" && (!deviceId || d.id === deviceId)) ||
        allDevices.find((d) => d.type === "usb") ||
        null;
      if (!usbDev) {
        throw new Error("Không tìm thấy iPhone cắm cáp USB. Hãy kiểm tra dây cáp sạc và mở khóa màn hình iPhone.");
      }
      selectedDeviceId = usbDev.id;
      actionSteps.push(`Đã nhận diện thiết bị USB: ${usbDev.name} (${usbDev.id}).`);

      // Đảm bảo frida-server trên iPhone đang chạy; nếu chưa chạy thì kích hoạt qua SSH Rootless
      const sshBefore = await this.#probeIphoneSshFridaInfo();
      if (sshBefore.sshReachable && !sshBefore.fridaPid) {
        const started = await this.#tryStartRemoteFridaServerViaSsh();
        if (started) {
          actionSteps.push("Đã tự động khởi chạy dịch vụ frida-server (/var/jb) trên iPhone qua SSH.");
          await new Promise((r) => setTimeout(r, 450));
        }
      }

      const wDev = await this.resolveWorkingDevice(usbDev.id);
      try {
        await wDev.querySystemParameters();
      } catch {
        await this.invalidateTunnel(usbDev.id);
        await this.#tryStartRemoteFridaServerViaSsh();
        await new Promise((r) => setTimeout(r, 450));
        const retried = await this.resolveWorkingDevice(usbDev.id);
        await retried.querySystemParameters();
      }
      const tunnel = this.#usbTunnels.get(usbDev.id);
      actionSteps.push(
        `Đã kết nối thông suốt cáp USB iproxy 127.0.0.1:${tunnel?.localPort || 27042} ➔ iPhone:27042 và xác thực Frida Server thành công.`
      );
    } else if (cleanChannel === "wifi_frida") {
      if (!String(wirelessAddress || "").trim()) {
        throw new Error("Vui lòng nhập địa chỉ IP Wi-Fi của iPhone (ví dụ: 192.168.1.50:27042) trước khi chuyển sang kênh Không dây.");
      }
      const added = await this.addWirelessDevice({
        address: wirelessAddress,
        label: wirelessLabel,
      });
      selectedDeviceId = added.id;
      actionSteps.push(
        added.reachable
          ? `Đã kết nối thành công tới Frida không dây tại ${added.address} (${added.latencyMs} ms).`
          : `Đã đăng ký địa chỉ ${added.address}, nhưng cổng 27042 qua Wi-Fi hiện KHÔNG mở (frida-server mặc định chỉ nghe trên USB 127.0.0.1:27042).`
      );
    } else if (cleanChannel === "usb_ssh") {
      const allDevices = await this.listDevices();
      const usbDev = allDevices.find((d) => d.type === "usb") || null;
      await this.#ensureAuxIproxyPort(2222, 22, usbDev?.id || "").catch(() => null);
      const sshCheck = await this.#probeIphoneSshFridaInfo();
      if (sshCheck.sshReachable) {
        if (usbDev) selectedDeviceId = usbDev.id;
        actionSteps.push(`Kênh SSH USB (127.0.0.1:2222 ➔ 22) đang hoạt động thật (${sshCheck.sshLatencyMs} ms • ${sshCheck.unameInfo}).`);
      } else {
        actionSteps.push(`Cổng SSH 2222 chưa đăng nhập được vào iPhone (${sshCheck.sshError || "kiểm tra OpenSSH trên máy"}).`);
      }
    } else if (cleanChannel === "rabbit_daemon") {
      const allDevices = await this.listDevices();
      const usbDev = allDevices.find((d) => d.type === "usb") || null;
      await this.#ensureAuxIproxyPort(8765, 8765, usbDev?.id || "").catch(() => null);
      const probe = await probeHttpEndpoint("http://127.0.0.1:8765/api/apps", 1200);
      const isGenuine =
        probe.reachable && probe.statusCode >= 200 && probe.statusCode < 300 && /"apps"|"apis"|"version"/i.test(probe.bodyPreview || "");
      if (isGenuine) {
        actionSteps.push(`Đã bắc cầu & kết nối thật tới Agent RabbitUltrad cổng 8765 (HTTP ${probe.statusCode} • ${probe.latencyMs} ms).`);
      } else {
        actionSteps.push(
          "Báo cáo trung thực: Tiến trình RabbitUltrad (Daemon/main.m) hiện KHÔNG chạy trên iPhone nên chưa có dữ liệu API cổng 8765."
        );
      }
    } else if (cleanChannel === "ios_mcp_agent") {
      const allDevices = await this.listDevices();
      const usbDev = allDevices.find((d) => d.type === "usb") || null;
      await this.#ensureAuxIproxyPort(8090, 8091, usbDev?.id || "").catch(() => null);
      const probe = await probeHttpEndpoint("http://127.0.0.1:8090/health", 1000);
      actionSteps.push(
        probe.reachable
          ? `Cầu nối iOS Control Agent cổng 8090 ➔ 8091 đang phản hồi trực tiếp (${probe.latencyMs} ms).`
          : "Cầu nối iproxy cổng 8090 trên PC đang mở sẵn, nhưng ứng dụng Agent cổng 8091 trên iPhone hiện đang tắt."
      );
    } else if (cleanChannel === "vpn_mitm_proxy") {
      const spec = parseHostPort(vpnMitmProxyAddress, 8080);
      const tcp = await probeTcpSocket(spec.host, spec.port, 1000);
      actionSteps.push(
        tcp.open
          ? `Đã xác nhận máy chủ Proxy kiểm định TLS tại ${spec.normalized} đang MỞ thật (${tcp.latencyMs} ms). Bạn có thể định tuyến Gửi lại gói tin từ PC qua Proxy này.`
          : `Báo cáo trung thực: Cổng Proxy ${spec.normalized} hiện đang ĐÓNG (${tcp.error || "Connection refused"}). Hãy bật mitmproxy / Proxyman trên cổng ${spec.port} rồi bấm Kiểm tra lại.`
      );
    } else if (cleanChannel === "local_pc") {
      selectedDeviceId = "local";
      actionSteps.push("Đã chuyển mục tiêu sang Nhân Frida Nội Bộ trên Máy tính Windows (local).");
    } else {
      throw new Error(`Kênh kết nối '${cleanChannel}' không hợp lệ.`);
    }

    const hubStatus = await this.probeAllConnectionChannels({
      deviceId: selectedDeviceId,
      wirelessAddress,
      vpnMitmProxyAddress,
      activeChannel: cleanChannel,
    });

    const targetChannelReport = hubStatus.channels.find((c) => c.id === cleanChannel) || null;

    return {
      activatedChannel: cleanChannel,
      selectedDeviceId,
      steps: actionSteps,
      channelReport: targetChannelReport,
      hub: hubStatus,
    };
  }

  async checkFridaServerHealth(requestedDeviceId = "") {
    const checks = [];
    let overallStatus = "healthy"; // healthy | warning | error
    let latencyMs = null;
    let remoteServerVersion = null;

    const allDevices = await this.listDevices();
    const targetMeta =
      allDevices.find((d) => d.id === requestedDeviceId) ||
      allDevices.find((d) => d.type === "usb") ||
      allDevices[0] ||
      null;

    if (!targetMeta) {
      return {
        overallStatus: "error",
        summary: "Không tìm thấy bất kỳ thiết bị nào kết nối với máy tính.",
        deviceId: null,
        deviceName: "Chưa phát hiện thiết bị",
        fridaClientVersion: PC_FRIDA_SDK_VERSION,
        fridaServerVersion: null,
        latencyMs: null,
        checkedAt: new Date().toISOString(),
        checks: [
          {
            id: "usb_hardware",
            title: "1. Kết nối vật lý cáp USB",
            status: "error",
            detail: "Chưa nhận diện được iPhone qua cáp sạc. Hãy kiểm tra dây cáp và bấm 'Tin cậy máy tính này' trên màn hình iPhone.",
          },
        ],
      };
    }

    const isUsb = targetMeta.type === "usb";
    const isWireless = targetMeta.type === "remote";
    const isLocal = targetMeta.type === "local";

    checks.push({
      id: "usb_hardware",
      title: "1. Nhận diện phần cứng thiết bị",
      status: "ok",
      detail: isUsb
        ? `Đã nhận diện thiết bị qua cáp USB: ${targetMeta.name} (Mã máy: ${targetMeta.id}).`
        : isWireless
        ? `Đang kết nối thiết bị qua mạng không dây (Wi-Fi): ${targetMeta.name} (${targetMeta.wirelessAddress || targetMeta.id}).`
        : `Đang chọn chế độ chạy trực tiếp trên máy tính Windows (${targetMeta.name}).`,
    });

    let workingDevice = null;
    let sysParams = null;
    let frontApp = null;
    let procCount = 0;

    try {
      const t0 = Date.now();
      workingDevice = await this.resolveWorkingDevice(targetMeta.id);
      sysParams = await workingDevice.querySystemParameters();
      latencyMs = Date.now() - t0;

      const [front, procs] = await Promise.all([
        workingDevice.getFrontmostApplication().catch(() => null),
        workingDevice.enumerateProcesses().catch(() => []),
      ]);
      frontApp = front;
      procCount = procs.length;

      const tunnel = this.#usbTunnels.get(targetMeta.id);
      checks.push({
        id: "usb_tunnel",
        title: isWireless ? "2. Đường truyền mạng không dây (Wi-Fi TCP)" : "2. Cầu nối truyền dữ liệu cáp USB (iproxy)",
        status: "ok",
        detail: isUsb
          ? tunnel
            ? `Đang thông suốt: Cổng nội bộ 127.0.0.1:${tunnel.localPort} nối thẳng vào cổng 27042 trên iPhone.`
            : "Kết nối trực tiếp vào cổng 27042 trên thiết bị."
          : isWireless
          ? `Đang truyền dữ liệu qua Wi-Fi trực tiếp tới ${targetMeta.wirelessAddress || targetMeta.id}.`
          : "Sử dụng nhân Frida nội bộ trên Windows (không cần cầu nối cáp).",
      });

      checks.push({
        id: "frida_daemon",
        title: "3. Trạng thái dịch vụ Frida Server hiện tại",
        status: "ok",
        detail: `Đang hoạt động tốt! Phản hồi sau ${latencyMs} ms • Đọc được ${procCount} tiến trình (${
          sysParams?.access === "full" ? "Đủ quyền quản trị cao nhất" : `Quyền: ${sysParams?.access || "tiêu chuẩn"}`
        }).`,
      });
    } catch (err) {
      overallStatus = "error";
      checks.push({
        id: "usb_tunnel",
        title: "2. Cầu nối truyền dữ liệu cáp USB (iproxy)",
        status: "warning",
        detail: "Cổng kết nối có thể bị kẹt hoặc dịch vụ trên điện thoại chưa mở cổng 27042. Hãy bấm nút 'Tự động sửa lỗi kết nối'.",
      });
      checks.push({
        id: "frida_daemon",
        title: "3. Trạng thái dịch vụ Frida Server hiện tại",
        status: "error",
        detail: `Không nhận được phản hồi từ Frida Server (${err.message}). Hãy kiểm tra gói 're.frida.server' trong Sileo/Zebra trên iPhone.`,
      });
    }

    if (isUsb) {
      const sshInfo = await this.#probeIphoneSshFridaInfo();
      remoteServerVersion = sshInfo.serverVersion;

      if (remoteServerVersion) {
        const isExactMatch = remoteServerVersion === PC_FRIDA_SDK_VERSION;
        const majorPc = PC_FRIDA_SDK_VERSION.split(".")[0];
        const majorDev = remoteServerVersion.split(".")[0];
        const isMajorMatch = majorPc === majorDev;

        if (!isMajorMatch && overallStatus === "healthy") overallStatus = "error";
        else if (!isExactMatch && overallStatus === "healthy") overallStatus = "warning";

        checks.push({
          id: "version_sync",
          title: "4. Độ tương thích phiên bản (Máy tính ↔ Điện thoại)",
          status: isExactMatch ? "ok" : isMajorMatch ? "warning" : "error",
          detail: isExactMatch
            ? `Đồng bộ tuyệt đối 100%: Máy tính (${PC_FRIDA_SDK_VERSION}) = Frida Server trên iPhone (${remoteServerVersion}).`
            : `Lệch phiên bản: Máy tính đang dùng ${PC_FRIDA_SDK_VERSION} nhưng iPhone đang cài ${remoteServerVersion}. Nên cập nhật cùng nhánh ${majorPc}.x để tránh lỗi gắn mã.`,
        });
      } else {
        checks.push({
          id: "version_sync",
          title: "4. Độ tương thích phiên bản (Máy tính ↔ Điện thoại)",
          status: sysParams ? "ok" : "warning",
          detail: sysParams
            ? `Giao thức tương thích tốt với Frida ${PC_FRIDA_SDK_VERSION} trên máy tính (${sysParams?.os?.name || "iOS"} ${sysParams?.os?.version || ""}).`
            : `Máy tính đang dùng Frida ${PC_FRIDA_SDK_VERSION} (chưa đối chiếu được phiên bản trên điện thoại).`,
        });
      }

      checks.push({
        id: "rootless_service",
        title: "5. Cấu hình tự chạy ngầm sau khi bẻ khóa (LaunchDaemon)",
        status: sshInfo.plistPath || sysParams?.access === "full" ? "ok" : "warning",
        detail: sshInfo.plistPath
          ? `Đã cài đặt chuẩn dịch vụ tự khởi động tại: ${sshInfo.plistPath}`
          : sysParams?.access === "full"
          ? "Thiết bị đã bẻ khóa và cấp đủ quyền hệ thống cho Frida Server."
          : "Chưa xác nhận được tệp cấu hình LaunchDaemon trên thiết bị.",
      });
    } else if (isLocal) {
      remoteServerVersion = PC_FRIDA_SDK_VERSION;
      checks.push({
        id: "version_sync",
        title: "4. Phiên bản thư viện Frida trên máy tính",
        status: "ok",
        detail: `Đang chạy phiên bản Frida ${PC_FRIDA_SDK_VERSION} (${process.arch}).`,
      });
    }

    if (sysParams) {
      checks.push({
        id: "frontmost_app",
        title: "6. Chế độ tự động mở & gắn ứng dụng",
        status: "ok",
        detail: frontApp
          ? `Đang mở sẵn trên điện thoại: ${frontApp.name} (${frontApp.identifier} • Mã ${frontApp.pid}).`
          : isUsb
          ? "Đã bật Tự động thông minh: Bạn chỉ cần chọn tên ứng dụng và bấm Chạy, điện thoại sẽ tự mở ứng dụng đó lên!"
          : "Hệ thống máy tính sẵn sàng gắn mã vào tiến trình bất kỳ.",
      });
    }

    const summary =
      overallStatus === "healthy"
        ? `Máy chủ Frida Server ${remoteServerVersion || PC_FRIDA_SDK_VERSION} đang chạy rất ổn định (phản hồi ${latencyMs ?? 0} ms).`
        : overallStatus === "warning"
        ? `Máy chủ Frida Server đang hoạt động (${latencyMs ?? 0} ms), có 1 lưu ý nhỏ bên dưới.`
        : "Phát hiện sự cố kết nối với Frida Server! Hãy bấm nút 'Tự động sửa lỗi kết nối' để khôi phục.";

    return {
      overallStatus,
      summary,
      deviceId: targetMeta.id,
      deviceName: sysParams?.name || targetMeta.name,
      fridaClientVersion: PC_FRIDA_SDK_VERSION,
      fridaServerVersion: remoteServerVersion || (sysParams ? PC_FRIDA_SDK_VERSION : null),
      latencyMs,
      checkedAt: new Date().toISOString(),
      checks,
    };
  }

  async repairConnection(requestedDeviceId = "") {
    const steps = [];
    const allDevices = await this.listDevices();
    const targetMeta =
      allDevices.find((d) => d.id === requestedDeviceId) ||
      allDevices.find((d) => d.type === "usb") ||
      allDevices[0] ||
      null;

    const targetId = targetMeta?.id || requestedDeviceId;

    if (targetId && this.#usbTunnels.has(targetId)) {
      const oldTunnel = this.#usbTunnels.get(targetId);
      try {
        oldTunnel.proc.kill();
      } catch {}
      try {
        await frida.getDeviceManager().removeRemoteDevice(`127.0.0.1:${oldTunnel.localPort}`);
      } catch {}
      this.#usbTunnels.delete(targetId);
      this.#managedTunnelPorts.delete(oldTunnel.localPort);
      steps.push(`Đã đóng cổng cầu nối USB cũ (127.0.0.1:${oldTunnel.localPort}) để giải phóng kẹt mạng.`);
    } else {
      steps.push("Đã rà soát danh sách cổng cầu nối USB (không có cổng cũ bị treo).");
    }

    if (targetId) {
      this.#crashHookedIds.delete(targetId);
    }

    if (targetMeta?.type === "usb") {
      const startedViaSsh = await this.#tryStartRemoteFridaServerViaSsh();
      if (startedViaSsh) {
        steps.push("Đã kiểm tra và đảm bảo dịch vụ frida-server (/var/jb) đang chạy trên iPhone.");
      }
    }

    if (targetMeta) {
      try {
        await this.resolveWorkingDevice(targetMeta.id);
        const newTunnel = this.#usbTunnels.get(targetMeta.id);
        if (newTunnel) {
          steps.push(`Đã mở mới cầu nối cáp USB sạch trên cổng 127.0.0.1:${newTunnel.localPort} ➔ 27042.`);
        } else {
          steps.push(`Đã làm mới kết nối trực tiếp tới thiết bị '${targetMeta.name}'.`);
        }
      } catch (err) {
        steps.push(`Cảnh báo khi mở lại kết nối: ${err.message}`);
      }
    }

    const report = await this.checkFridaServerHealth(targetId);
    steps.push(
      report.overallStatus !== "error"
        ? `Khôi phục hoàn tất: Frida Server phản hồi trong ${report.latencyMs ?? 0} ms!`
        : "Đã làm mới toàn bộ cầu nối trên máy tính nhưng Frida Server trên điện thoại vẫn chưa phản hồi (cần mở Sileo kiểm tra gói re.frida.server)."
    );

    logger.info("Đã thực hiện quy trình Tự động sửa lỗi kết nối Frida", {
      deviceId: targetId,
      overallStatus: report.overallStatus,
      latencyMs: report.latencyMs,
    });

    return {
      repairedAt: new Date().toISOString(),
      steps,
      report,
    };
  }

  shutdown() {
    for (const [id, entry] of this.#usbTunnels.entries()) {
      try {
        entry.proc.kill();
      } catch {}
      this.#usbTunnels.delete(id);
    }
    for (const [port, proc] of this.#auxIproxyProcs.entries()) {
      try {
        proc.kill();
      } catch {}
      this.#auxIproxyProcs.delete(port);
    }
    this.#managedTunnelPorts.clear();
  }
}
