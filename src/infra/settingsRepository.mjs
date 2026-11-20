// src/infra/settingsRepository.mjs — Lưu trữ bền vững Cấu hình Giao diện & Kênh Kết nối (Không mất khi Reload trang / Khởi động lại Server)
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DATA_DIR = path.resolve(__dirname, "../../data");
const DEFAULT_SETTINGS_FILE = path.join(DEFAULT_DATA_DIR, "ui-settings.json");

const ALLOWED_CHANNELS = new Set([
  "usb_frida",
  "wifi_frida",
  "rabbit_agent",
  "ssh_ios_agent",
  "vpn_mitm",
  "local_pc",
]);

const ALLOWED_MODES = new Set(["auto", "spawn", "attach"]);
const ALLOWED_MAIN_STEPS = new Set(["connect", "apps", "inject", "packets", "snippets"]);

export function createDefaultUiSettings() {
  return {
    activeChannel: "usb_frida",
    selectedDeviceId: "",
    selectedTarget: "",
    launchMode: "auto",
    activeMainStep: "packets",
    activeSubTool: "switches", // switches | magnifier | modules | objc | rpc
    activeAppSubView: "list", // list | manifest | sandbox
    activePacketSubView: "capture", // capture | decoder | vault
    wirelessAddress: "",
    wirelessLabel: "",
    mitmProxyHost: "127.0.0.1",
    mitmProxyPort: 8080,
    routeRepeaterViaProxy: false,
    rabbitAgentPort: 8765,
    rabbitBridgeEnabled: false,
    snippetCategoryFilter: "ALL",
    appMgrFilter: "user",
    logLevelFilter: "ALL",
    autoScroll: true,
    guideCollapsed: false,
    draftCode: "",
    updatedAt: null,
  };
}

function sanitizePatch(raw = {}) {
  const out = {};
  if (typeof raw !== "object" || raw === null) return out;

  if (typeof raw.activeChannel === "string" && ALLOWED_CHANNELS.has(raw.activeChannel.trim())) {
    out.activeChannel = raw.activeChannel.trim();
  }
  if (typeof raw.selectedDeviceId === "string") {
    out.selectedDeviceId = raw.selectedDeviceId.trim().slice(0, 160);
  }
  if (typeof raw.selectedTarget === "string") {
    out.selectedTarget = raw.selectedTarget.trim().slice(0, 200);
  }
  if (typeof raw.launchMode === "string" && ALLOWED_MODES.has(raw.launchMode.trim())) {
    out.launchMode = raw.launchMode.trim();
  }
  if (typeof raw.activeMainStep === "string" && ALLOWED_MAIN_STEPS.has(raw.activeMainStep.trim())) {
    out.activeMainStep = raw.activeMainStep.trim();
  }
  if (typeof raw.activeSubTool === "string") {
    out.activeSubTool = raw.activeSubTool.trim().slice(0, 40);
  }
  if (typeof raw.activeAppSubView === "string") {
    out.activeAppSubView = raw.activeAppSubView.trim().slice(0, 40);
  }
  if (typeof raw.activePacketSubView === "string") {
    out.activePacketSubView = raw.activePacketSubView.trim().slice(0, 40);
  }
  if (typeof raw.wirelessAddress === "string") {
    out.wirelessAddress = raw.wirelessAddress.trim().slice(0, 120);
  }
  if (typeof raw.wirelessLabel === "string") {
    out.wirelessLabel = raw.wirelessLabel.trim().slice(0, 80);
  }
  if (typeof raw.mitmProxyHost === "string") {
    const cleanHost = raw.mitmProxyHost.trim().replace(/^https?:\/\//i, "").split("/")[0].split(":")[0];
    if (cleanHost) out.mitmProxyHost = cleanHost.slice(0, 120);
  }
  if (raw.mitmProxyPort !== undefined) {
    const p = Number(raw.mitmProxyPort);
    if (Number.isInteger(p) && p >= 1 && p <= 65535) {
      out.mitmProxyPort = p;
    }
  }
  if (typeof raw.routeRepeaterViaProxy === "boolean") {
    out.routeRepeaterViaProxy = raw.routeRepeaterViaProxy;
  }
  if (raw.rabbitAgentPort !== undefined) {
    const rp = Number(raw.rabbitAgentPort);
    if (Number.isInteger(rp) && rp >= 1 && rp <= 65535) {
      out.rabbitAgentPort = rp;
    }
  }
  if (typeof raw.rabbitBridgeEnabled === "boolean") {
    out.rabbitBridgeEnabled = raw.rabbitBridgeEnabled;
  }
  if (typeof raw.snippetCategoryFilter === "string") {
    out.snippetCategoryFilter = raw.snippetCategoryFilter.trim().slice(0, 120);
  }
  if (typeof raw.appMgrFilter === "string") {
    out.appMgrFilter = raw.appMgrFilter.trim().slice(0, 40);
  }
  if (typeof raw.logLevelFilter === "string") {
    out.logLevelFilter = raw.logLevelFilter.trim().slice(0, 40);
  }
  if (typeof raw.autoScroll === "boolean") {
    out.autoScroll = raw.autoScroll;
  }
  if (typeof raw.guideCollapsed === "boolean") {
    out.guideCollapsed = raw.guideCollapsed;
  }
  if (typeof raw.draftCode === "string") {
    out.draftCode = raw.draftCode.slice(0, 250_000);
  }

  return out;
}

export class SettingsRepository {
  #filePath;
  #writeLock = Promise.resolve();

  constructor({ filePath = DEFAULT_SETTINGS_FILE } = {}) {
    this.#filePath = filePath;
  }

  async getSettings() {
    try {
      const raw = await fs.readFile(this.#filePath, "utf8");
      const parsed = JSON.parse(raw);
      return {
        ...createDefaultUiSettings(),
        ...sanitizePatch(parsed),
        updatedAt: parsed?.updatedAt || null,
      };
    } catch {
      return createDefaultUiSettings();
    }
  }

  async updateSettings(patch = {}) {
    const cleanPatch = sanitizePatch(patch);
    const runWrite = async () => {
      const current = await this.getSettings();
      const next = {
        ...current,
        ...cleanPatch,
        updatedAt: new Date().toISOString(),
      };
      const dir = path.dirname(this.#filePath);
      await fs.mkdir(dir, { recursive: true });
      const tmpPath = `${this.#filePath}.tmp`;
      await fs.writeFile(tmpPath, JSON.stringify(next, null, 2), "utf8");
      await fs.rename(tmpPath, this.#filePath);
      return next;
    };

    const resultPromise = this.#writeLock.then(runWrite, runWrite);
    this.#writeLock = resultPromise.catch(() => {});
    return resultPromise;
  }
}

