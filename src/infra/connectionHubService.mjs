// src/infra/connectionHubService.mjs — Trung tâm Quản lý & Chuyển Đổi 6 Kênh Kết Nối Thực Tế Trong Source (100% Trạng Thái Thật, Không Báo Cáo Giả)
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { logger } from "./logger.mjs";

const KNOWN_IDEVICE_DIRS = [
  "C:\\Program Files\\dotnet\\packs\\Microsoft.iOS.Windows.Sdk.net9.0_26.0\\26.0.9752\\tools\\msbuild\\iOS\\imobiledevice-x64",
  "C:\\Program Files\\dotnet\\packs\\Microsoft.iOS.Windows.Sdk.net9.0_18.0\\18.0.9617\\tools\\msbuild\\iOS\\imobiledevice-x64",
  "C:\\Program Files\\libimobiledevice",
  "C:\\libimobiledevice",
];

function findIproxyExe() {
  for (const dir of KNOWN_IDEVICE_DIRS) {
    const candidate = path.join(dir, "iproxy.exe");
    if (fs.existsSync(candidate)) return candidate;
  }
  return "iproxy";
}

function probeTcpSocket(host, port, { timeoutMs = 900, readBanner = false } = {}) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let settled = false;
    let banner = "";

    const finish = (payload) => {
      if (settled) return;
      settled = true;
      try {
        sock.destroy();
      } catch {}
      resolve(payload);
    };

    const sock = net.createConnection({ host, port: Number(port) });
    sock.setTimeout(timeoutMs);

    sock.once("connect", () => {
      const latencyMs = Math.max(1, Date.now() - t0);
      if (!readBanner) {
        finish({ open: true, latencyMs, banner: "" });
        return;
      }
      setTimeout(() => {
        finish({ open: true, latencyMs, banner: banner.trim() });
      }, 120);
    });

    if (readBanner) {
      sock.on("data", (chunk) => {
        banner += chunk.toString("utf8");
        if (banner.includes("\n") || banner.length >= 64) {
          finish({
            open: true,
            latencyMs: Math.max(1, Date.now() - t0),
            banner: banner.trim().slice(0, 80),
          });
        }
      });
    }

    sock.once("timeout", () => {
      finish({ open: false, latencyMs: null, reason: `Quá thời gian chờ (${timeoutMs} ms)` });
    });

    sock.once("error", (err) => {
      finish({ open: false, latencyMs: null, reason: err?.code || err?.message || "Cổng đóng" });
    });
  });
}

function detectLocalVpnAdapters() {
  const interfaces = os.networkInterfaces() || {};
  const matches = [];
  const vpnNameRegex = /(wireguard|wintun|wg\d*|tun\d*|tap\d*|utun\d*|openvpn|tailscale|zerotier|warp)/i;

  for (const [ifName, addrs] of Object.entries(interfaces)) {
    if (!vpnNameRegex.test(ifName)) continue;
    const ipv4 = (addrs || []).find((a) => a.family === "IPv4" && !a.internal);
    const ipv6 = (addrs || []).find((a) => a.family === "IPv6" && !a.internal);
    matches.push({
      name: ifName,
      address: ipv4?.address || ipv6?.address || "(Không có IP)",
    });
  }
  return matches;
}

export class ConnectionHubService {
  #bridge;
  #settingsRepo;
  /** @type {{ proc: import("node:child_process").ChildProcess, port: number, startedAt: string } | null} */
  #rabbitTunnel = null;

  constructor({ bridge, settingsRepo }) {
    this.#bridge = bridge;
    this.#settingsRepo = settingsRepo;
  }

  async #ensureRabbitTunnel(localPort = 8765, devicePort = 8765) {
    if (this.#rabbitTunnel && this.#rabbitTunnel.proc.exitCode === null && this.#rabbitTunnel.port === localPort) {
      return { startedByGui: true, port: localPort };
    }

    // Kiểm tra xem cổng 8765 đã có tiến trình bên ngoài mở sẵn chưa (tránh đụng độ cổng!)
    const preCheck = await probeTcpSocket("127.0.0.1", localPort, { timeoutMs: 400 });
    if (preCheck.open) {
      return { startedByGui: false, port: localPort, alreadyListening: true };
    }

    const iproxyBin = findIproxyExe();
    const proc = spawn(iproxyBin, [String(localPort), String(devicePort)], {
      stdio: "ignore",
      windowsHide: true,
    });

    this.#rabbitTunnel = {
      proc,
      port: localPort,
      startedAt: new Date().toISOString(),
    };

    proc.on("exit", () => {
      if (this.#rabbitTunnel?.proc === proc) {
        this.#rabbitTunnel = null;
      }
    });

    await new Promise((r) => setTimeout(r, 350));
    return { startedByGui: true, port: localPort };
  }

  stopRabbitTunnel() {
    if (this.#rabbitTunnel?.proc) {
      try {
        this.#rabbitTunnel.proc.kill();
      } catch {}
      this.#rabbitTunnel = null;
      return true;
    }
    return false;
  }

  async probeRabbitDaemonHttp(port = 8765) {
    const tcp = await probeTcpSocket("127.0.0.1", port, { timeoutMs: 800 });
    if (!tcp.open) {
      return {
        tcpOpen: false,
        daemonAlive: false,
        latencyMs: null,
        detail: `Cổng nội bộ 127.0.0.1:${port} hiện đang đóng (chưa bật cầu nối iproxy ${port} hoặc chưa chạy RabbitUltrad).`,
        appleId: null,
        version: null,
      };
    }

    const t0 = Date.now();
    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/database`, {
        signal: AbortSignal.timeout(1500),
      });
      const latencyMs = Math.max(1, Date.now() - t0);
      if (!res.ok) {
        return {
          tcpOpen: true,
          daemonAlive: false,
          latencyMs,
          detail: `Cổng 127.0.0.1:${port} mở nhưng phản hồi HTTP ${res.status} (Daemon 8765 trên iPhone có thể chưa chạy).`,
          appleId: null,
          version: null,
        };
      }
      const db = await res.json();
      return {
        tcpOpen: true,
        daemonAlive: true,
        latencyMs,
        version: db?.version || "2.1.x",
        appleId: db?.currentSandboxId || db?.currentAppleId || null,
        capturedApiCount: Array.isArray(db?.apis) ? db.apis.length : 0,
        detail: `RabbitUltrad v${db?.version || "2.x"} trên iPhone đang phản hồi thật (${latencyMs} ms)!`,
      };
    } catch (err) {
      return {
        tcpOpen: true,
        daemonAlive: false,
        latencyMs: tcp.latencyMs,
        detail: `Cầu nối USB cổng ${port} đang mở nhưng tiến trình RabbitUltrad trên iPhone chưa trả lời (${err?.message || "EOF"}).`,
        appleId: null,
        version: null,
      };
    }
  }

  async inspectAllChannels() {
    const settings = await this.#settingsRepo.getSettings();
    const devices = await this.#bridge.listDevices().catch(() => []);

    const usbDev = devices.find((d) => d.type === "usb") || null;
    const wifiDevs = devices.filter((d) => d.type === "remote");
    const localDev = devices.find((d) => d.type === "local") || null;

    const proxyHost = settings.mitmProxyHost || "127.0.0.1";
    const proxyPort = Number(settings.mitmProxyPort) || 8080;
    const rabbitPort = Number(settings.rabbitAgentPort) || 8765;

    // Quét song song tất cả các cổng thật bằng TCP Socket / HTTP thật (< 1 giây, 0% giả lập)
    const [sshProbe, iosAgent8090, iosAgent8091, rabbitProbe, mitmMainProbe, mitmAlt8888, mitmAlt8081] =
      await Promise.all([
        probeTcpSocket("127.0.0.1", 2222, { timeoutMs: 700, readBanner: true }),
        probeTcpSocket("127.0.0.1", 8090, { timeoutMs: 600 }),
        probeTcpSocket("127.0.0.1", 8091, { timeoutMs: 600 }),
        this.probeRabbitDaemonHttp(rabbitPort),
        probeTcpSocket(proxyHost, proxyPort, { timeoutMs: 750 }),
        proxyPort !== 8888 ? probeTcpSocket("127.0.0.1", 8888, { timeoutMs: 450 }) : Promise.resolve({ open: false }),
        proxyPort !== 8081 ? probeTcpSocket("127.0.0.1", 8081, { timeoutMs: 450 }) : Promise.resolve({ open: false }),
      ]);

    // Kiểm tra thực tế kết nối Wi-Fi Frida đầu tiên (nếu có đăng ký)
    let wifiProbe = { open: false, latencyMs: null, address: settings.wirelessAddress || "" };
    const primaryWifiAddr = wifiDevs[0]?.wirelessAddress || settings.wirelessAddress || "";
    if (primaryWifiAddr) {
      const cleanAddr = primaryWifiAddr.includes(":") ? primaryWifiAddr : `${primaryWifiAddr}:27042`;
      const [wHost, wPort] = cleanAddr.split(":");
      const res = await probeTcpSocket(wHost, Number(wPort) || 27042, { timeoutMs: 800 });
      wifiProbe = { ...res, address: cleanAddr };
    }

    // Kiểm tra thực tế cầu nối USB Frida 27042
    let usbFridaAlive = false;
    let usbFridaLatency = null;
    let usbTunnelPort = usbDev?.tunnelPort || null;
    if (usbDev) {
      const t0 = Date.now();
      try {
        const working = await this.#bridge.resolveWorkingDevice(usbDev.id);
        await Promise.race([
          working.querySystemParameters(),
          new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 1600)),
        ]);
        usbFridaAlive = true;
        usbFridaLatency = Math.max(1, Date.now() - t0);
        const refreshed = await this.#bridge.listDevices().catch(() => []);
        usbTunnelPort = refreshed.find((d) => d.id === usbDev.id)?.tunnelPort || usbTunnelPort;
      } catch {
        usbFridaAlive = false;
      }
    }

    const vpnAdapters = detectLocalVpnAdapters();

    const altProxyNote =
      !mitmMainProbe.open && (mitmAlt8888.open || mitmAlt8081.open)
        ? ` (Gợi ý thật: phát hiện cổng ${mitmAlt8888.open ? "8888" : "8081"} đang mở trên máy)`
        : "";

    const channels = [
      {
        id: "usb_frida",
        order: 1,
        shortLabel: "🔌 Cáp USB Frida",
        title: "1. Cáp USB ➔ Frida Server (iproxy 27042)",
        sourceOrigin: "fridaBridge.mjs (#ensureUsbTunnelDevice ➔ re.frida.server:27042)",
        connected: Boolean(usbDev && usbFridaAlive),
        statusBadge:
          usbDev && usbFridaAlive
            ? `ĐANG KẾT NỐI THẬT (${usbFridaLatency} ms)`
            : usbDev
            ? "ĐÃ CẮM CÁP • CHỜ FRIDA 27042"
            : "CHƯA CẮM CÁP USB",
        statusLevel: usbDev && usbFridaAlive ? "ok" : usbDev ? "warn" : "off",
        endpoint: usbTunnelPort ? `127.0.0.1:${usbTunnelPort} ➔ iPhone:27042` : "Chưa mở cổng iproxy",
        deviceId: usbDev?.id || null,
        deviceName: usbDev?.name || null,
        detail:
          usbDev && usbFridaAlive
            ? `Nhận diện thật '${usbDev.name}' qua cáp sạc, cầu nối 127.0.0.1:${usbTunnelPort || 27142} phản hồi sau ${usbFridaLatency} ms.`
            : usbDev
            ? `Đã thấy iPhone '${usbDev.name}' qua cáp nhưng cổng 27042 chưa trả lời.`
            : "Hiện không có iPhone nào cắm cáp USB vào máy tính.",
      },
      {
        id: "wifi_frida",
        order: 2,
        shortLabel: "📶 Wi-Fi Frida",
        title: "2. Mạng Không Dây Wi-Fi ➔ Frida Server (TCP 27042)",
        sourceOrigin: "fridaBridge.mjs (addWirelessDevice ➔ IP_LAN:27042)",
        connected: Boolean(wifiDevs.length > 0 && wifiProbe.open),
        statusBadge:
          wifiDevs.length > 0 && wifiProbe.open
            ? `ĐANG KẾT NỐI THẬT (${wifiProbe.latencyMs} ms)`
            : primaryWifiAddr
            ? "KHÔNG PHẢN HỒI CỔNG WI-FI"
            : "CHƯA NHẬP IP WI-FI",
        statusLevel: wifiDevs.length > 0 && wifiProbe.open ? "ok" : primaryWifiAddr ? "warn" : "off",
        endpoint: primaryWifiAddr || "Chưa cấu hình IP:27042",
        deviceId: wifiDevs[0]?.id || null,
        deviceName: wifiDevs[0]?.name || null,
        detail:
          wifiDevs.length > 0 && wifiProbe.open
            ? `Kết nối TCP không dây tới ${wifiProbe.address} đang thông suốt (${wifiProbe.latencyMs} ms).`
            : primaryWifiAddr
            ? `Đã kiểm tra thật tới ${wifiProbe.address}: cổng đóng hoặc khác mạng Wi-Fi (${wifiProbe.reason || "timeout"}).`
            : "Nhập địa chỉ IP Wi-Fi của iPhone (VD: 192.168.1.50:27042) để dùng không cần dây cáp.",
      },
      {
        id: "rabbit_agent",
        order: 3,
        shortLabel: "🐰 Rabbit Agent (8765)",
        title: "3. RabbitUltrad IPC Agent trên iPhone (Cổng 8765)",
        sourceOrigin: "Shared/RabbitCommon.h (RABBIT_WS_PORT 8765) & Daemon/main.m (startLocalServer)",
        connected: Boolean(rabbitProbe.daemonAlive),
        statusBadge: rabbitProbe.daemonAlive
          ? `DAEMON SỐNG THẬT (${rabbitProbe.latencyMs} ms)`
          : rabbitProbe.tcpOpen
          ? "CỔNG 8765 MỞ • DAEMON TẮT"
          : "CHƯA BẬT CẦU NỐI 8765",
        statusLevel: rabbitProbe.daemonAlive ? "ok" : rabbitProbe.tcpOpen ? "warn" : "off",
        endpoint: `127.0.0.1:${rabbitPort} ➔ iPhone:${rabbitPort}`,
        bridgeManagedByGui: Boolean(this.#rabbitTunnel),
        appleId: rabbitProbe.appleId,
        daemonVersion: rabbitProbe.version,
        detail: rabbitProbe.detail,
      },
      {
        id: "ssh_ios_agent",
        order: 4,
        shortLabel: "🛠️ SSH & iOS Agent",
        title: "4. Đường hầm SSH Rootless (2222) & iOS Control Agent (8090/8091)",
        sourceOrigin: "fridaBridge.mjs (openAppOnScreen ssh iphone:2222) & ios-mcp bridge (8090/8091)",
        connected: Boolean(sshProbe.open || iosAgent8090.open || iosAgent8091.open),
        statusBadge:
          sshProbe.open && (iosAgent8090.open || iosAgent8091.open)
            ? `SSH + AGENT SỐNG (${sshProbe.latencyMs} ms)`
            : sshProbe.open
            ? `SSH 2222 SỐNG (${sshProbe.latencyMs} ms)`
            : iosAgent8090.open || iosAgent8091.open
            ? "IOS AGENT 8090 SỐNG"
            : "CỔNG 2222 & 8090 ĐÓNG",
        statusLevel: sshProbe.open || iosAgent8090.open || iosAgent8091.open ? "ok" : "off",
        endpoint: `SSH 127.0.0.1:2222 • Agent 127.0.0.1:${iosAgent8090.open ? 8090 : 8091}`,
        sshOpen: sshProbe.open,
        sshBanner: sshProbe.banner || null,
        iosAgentOpen: Boolean(iosAgent8090.open || iosAgent8091.open),
        detail:
          `SSH 2222: ${sshProbe.open ? `Mở thật (${sshProbe.banner || `${sshProbe.latencyMs} ms`})` : "Đóng"} | ` +
          `iOS Agent 8090/8091: ${iosAgent8090.open || iosAgent8091.open ? "Đang lắng nghe thật" : "Đóng"}.`,
      },
      {
        id: "vpn_mitm",
        order: 5,
        shortLabel: "🛡️ VPN / MITM Proxy",
        title: "5. Máy chủ VPN WireGuard & Proxy Kiểm định TLS (MITM)",
        sourceOrigin: "multi-os-vpn-tls-admin (Explicit TLS Proxy 8080/8888 & WireGuard/Wintun Adapter)",
        connected: Boolean(mitmMainProbe.open || vpnAdapters.length > 0),
        statusBadge: mitmMainProbe.open
          ? `PROXY MỞ THẬT (${mitmMainProbe.latencyMs} ms)`
          : vpnAdapters.length > 0
          ? `CÓ VPN (${vpnAdapters[0].name}) • PROXY ĐÓNG`
          : `CHƯA BẬT (${proxyHost}:${proxyPort} ĐÓNG)`,
        statusLevel: mitmMainProbe.open ? "ok" : vpnAdapters.length > 0 ? "warn" : "off",
        endpoint: `Proxy ${proxyHost}:${proxyPort}${vpnAdapters.length ? ` • VPN ${vpnAdapters.map((v) => v.name).join(", ")}` : ""}`,
        proxyOpen: mitmMainProbe.open,
        proxyHost,
        proxyPort,
        routeRepeaterViaProxy: Boolean(settings.routeRepeaterViaProxy),
        vpnAdapters,
        detail:
          (mitmMainProbe.open
            ? `Cổng Proxy kiểm định ${proxyHost}:${proxyPort} đang lắng nghe thật (${mitmMainProbe.latencyMs} ms).`
            : `Đã kiểm tra thật ${proxyHost}:${proxyPort}: hiện chưa có tiến trình mitmproxy/Charles/Proxyman nào mở cổng này${altProxyNote}.`) +
          (vpnAdapters.length > 0
            ? ` Phát hiện card mạng VPN đang bật: ${vpnAdapters.map((v) => `${v.name} (${v.address})`).join(", ")}.`
            : " Chưa bật card mạng ảo WireGuard/VPN trên Windows."),
      },
      {
        id: "local_pc",
        order: 6,
        shortLabel: "💻 Máy tính Windows",
        title: "6. Nhân Frida Nội Bộ Trên Máy Tính Windows (Local Agent)",
        sourceOrigin: "fridaBridge.mjs (rawDevice.type === 'local')",
        connected: Boolean(localDev),
        statusBadge: localDev ? "SẴN SÀNG TRÊN PC" : "KHÔNG KHẢ DỤNG",
        statusLevel: localDev ? "ok" : "off",
        endpoint: "Windows Local Process Runtime",
        deviceId: localDev?.id || "local",
        deviceName: localDev?.name || "Hệ thống Windows hiện tại",
        detail: localDev
          ? "Sẵn sàng gắn kiểm thử vào các tiến trình chạy trực tiếp trên máy trạm Windows."
          : "Không tìm thấy thiết bị local trong Frida.",
      },
    ];

    return {
      checkedAt: new Date().toISOString(),
      activeChannel: settings.activeChannel || "usb_frida",
      routeRepeaterViaProxy: Boolean(settings.routeRepeaterViaProxy),
      mitmProxy: {
        host: proxyHost,
        port: proxyPort,
        open: mitmMainProbe.open,
      },
      channels,
    };
  }

  async switchChannel(options = {}) {
    const channelId = String(options.channelId || "").trim();
    const currentSettings = await this.#settingsRepo.getSettings();
    const patch = {};
    let actionMessage = "";

    if (channelId) {
      patch.activeChannel = channelId;
    }

    if (options.mitmProxyHost !== undefined) patch.mitmProxyHost = String(options.mitmProxyHost);
    if (options.mitmProxyPort !== undefined) patch.mitmProxyPort = Number(options.mitmProxyPort);
    if (typeof options.routeRepeaterViaProxy === "boolean") {
      patch.routeRepeaterViaProxy = options.routeRepeaterViaProxy;
    }
    if (options.wirelessAddress !== undefined) patch.wirelessAddress = String(options.wirelessAddress);
    if (options.wirelessLabel !== undefined) patch.wirelessLabel = String(options.wirelessLabel);
    if (options.rabbitAgentPort !== undefined) patch.rabbitAgentPort = Number(options.rabbitAgentPort);

    if (channelId === "usb_frida") {
      const devices = await this.#bridge.listDevices().catch(() => []);
      const usb = devices.find((d) => d.type === "usb");
      if (usb) {
        patch.selectedDeviceId = usb.id;
        actionMessage = `Đã chuyển sang kênh Cáp USB Frida (${usb.name}).`;
      } else {
        actionMessage = "Đã chọn kênh Cáp USB Frida — nhưng hiện chưa phát hiện iPhone nào cắm cáp sạc!";
      }
    } else if (channelId === "wifi_frida") {
      const addr = String(options.wirelessAddress ?? currentSettings.wirelessAddress ?? "").trim();
      const label = String(options.wirelessLabel ?? currentSettings.wirelessLabel ?? "").trim();
      if (addr) {
        const added = await this.#bridge.addWirelessDevice({ address: addr, label });
        patch.selectedDeviceId = added.id;
        patch.wirelessAddress = added.address;
        actionMessage = added.reachable
          ? `Đã kết nối thật tới Frida Không dây tại ${added.address}!`
          : `Đã chuyển sang kênh Wi-Fi (${added.address}), nhưng cổng 27042 trên điện thoại hiện chưa phản hồi.`;
      } else {
        const devices = await this.#bridge.listDevices().catch(() => []);
        const remote = devices.find((d) => d.type === "remote");
        if (remote) {
          patch.selectedDeviceId = remote.id;
          actionMessage = `Đã chuyển sang thiết bị Wi-Fi ${remote.name}.`;
        } else {
          actionMessage = "Vui lòng nhập địa chỉ IP Wi-Fi của iPhone (VD: 192.168.1.50:27042) để mở kết nối không dây.";
        }
      }
    } else if (channelId === "rabbit_agent") {
      const rPort = Number(options.rabbitAgentPort ?? currentSettings.rabbitAgentPort) || 8765;
      const wantBridge = options.enableBridge !== false;
      if (wantBridge) {
        await this.#ensureRabbitTunnel(rPort, 8765);
        patch.rabbitBridgeEnabled = true;
      } else {
        this.stopRabbitTunnel();
        patch.rabbitBridgeEnabled = false;
      }
      const probe = await this.probeRabbitDaemonHttp(rPort);
      actionMessage = probe.daemonAlive
        ? `Đã nối thông suốt tới RabbitUltrad Agent cổng ${rPort} (${probe.latencyMs} ms)!`
        : probe.detail;
    } else if (channelId === "vpn_mitm") {
      const pHost = String(patch.mitmProxyHost || currentSettings.mitmProxyHost || "127.0.0.1").trim();
      const pPort = Number(patch.mitmProxyPort || currentSettings.mitmProxyPort || 8080);
      const tcp = await probeTcpSocket(pHost, pPort, { timeoutMs: 800 });
      if (options.routeRepeaterViaProxy !== undefined) {
        patch.routeRepeaterViaProxy = Boolean(options.routeRepeaterViaProxy && tcp.open);
      }
      actionMessage = tcp.open
        ? `Đã xác nhận cổng Proxy kiểm định ${pHost}:${pPort} đang mở thật (${tcp.latencyMs} ms)!`
        : `Trạng thái thật: Cổng Proxy ${pHost}:${pPort} hiện ĐANG ĐÓNG. Hãy bật mitmproxy / WireGuard trước khi định tuyến gói tin qua cổng này.`;
    } else if (channelId === "local_pc") {
      const devices = await this.#bridge.listDevices().catch(() => []);
      const loc = devices.find((d) => d.type === "local");
      if (loc) patch.selectedDeviceId = loc.id;
      actionMessage = "Đã chuyển mục tiêu sang Nhân Frida Nội bộ trên Máy tính Windows.";
    } else if (channelId === "ssh_ios_agent") {
      actionMessage = "Đã kiểm tra trực tiếp trạng thái đường hầm SSH (2222) và iOS Control Agent (8090/8091).";
    }

    const updatedSettings = await this.#settingsRepo.updateSettings(patch);
    const snapshot = await this.inspectAllChannels();

    logger.info("Đã thực hiện chuyển đổi / kiểm tra kênh kết nối thực tế", {
      channelId: channelId || updatedSettings.activeChannel,
      actionMessage,
    });

    return {
      actionMessage,
      settings: updatedSettings,
      hub: snapshot,
    };
  }

  async pullRabbitAgentPackets() {
    const settings = await this.#settingsRepo.getSettings();
    const rPort = Number(settings.rabbitAgentPort) || 8765;
    const probe = await this.probeRabbitDaemonHttp(rPort);
    if (!probe.daemonAlive) {
      const err = new Error(
        `Không thể đồng bộ gói tin từ RabbitUltrad vì cổng 127.0.0.1:${rPort} chưa phản hồi thật (${probe.detail})`
      );
      err.statusCode = 503;
      throw err;
    }

    const res = await fetch(`http://127.0.0.1:${rPort}/api/database`, {
      signal: AbortSignal.timeout(2500),
    });
    const db = await res.json();
    const apis = Array.isArray(db?.apis) ? db.apis : [];
    return {
      daemonVersion: db?.version || "2.1.x",
      currentAppleId: db?.currentAppleId || null,
      currentSandboxId: db?.currentSandboxId || null,
      packets: apis,
    };
  }

  shutdown() {
    this.stopRabbitTunnel();
  }
}

