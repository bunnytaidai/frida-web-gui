// src/infra/workspaceSettingsRepository.mjs — Lưu trữ bền vững Cấu hình Giao diện & Kênh Kết nối (Không mất khi Reload trang / Khởi động lại Server)
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.resolve(__dirname, "../../data");
const DEFAULT_SETTINGS_FILE = path.join(DATA_DIR, "ui-settings.json");

const ALLOWED_CHANNELS = new Set([
  "usb_frida",
  "wifi_frida",
  "usb_ssh",
  "rabbit_daemon",
  "ios_mcp_agent",
  "vpn_mitm_proxy",
  "local_pc",
]);

const ALLOWED_MODES = new Set(["auto", "spawn", "attach"]);

export function createDefaultWorkspaceSettings() {
  return {
    activeConnectionChannel: "usb_frida",
    selectedDeviceId: "",
    selectedTarget: "",
    launchMode: "auto",
    wirelessAddress: "",
    wirelessLabel: "",
    vpnMitmProxyAddress: "127.0.0.1:8080",
    useProxyForPcRepeater: false,
    rabbitDaemonPort: 8765,
    activeMainTab: "packets",
    appMgrFilter: "user",
    snippetCategoryFilter: "ALL",
    logAutoScroll: true,
    guideCollapsed: false,
    repeaterDraft: {
      method: "GET",
      url: "https://itunes.apple.com/lookup?bundleId=com.apple.TestFlight",
      headers: "{\n  \"Accept\": \"application/json\"\n}",
      body: "",
      sendFrom: "auto",
    },
    updatedAt: null,
  };
}

function sanitizeSettingsPatch(current, patch = {}) {
  const next = {
    ...current,
    repeaterDraft: { ...(current.repeaterDraft || createDefaultWorkspaceSettings().repeaterDraft) },
  };

  if (typeof patch.activeConnectionChannel === "string" && ALLOWED_CHANNELS.has(patch.activeConnectionChannel)) {
    next.activeConnectionChannel = patch.activeConnectionChannel;
  }
  if (typeof patch.selectedDeviceId === "string") {
    next.selectedDeviceId = patch.selectedDeviceId.trim().slice(0, 160);
  }
  if (typeof patch.selectedTarget === "string") {
    next.selectedTarget = patch.selectedTarget.trim().slice(0, 200);
  }
  if (typeof patch.launchMode === "string" && ALLOWED_MODES.has(patch.launchMode)) {
    next.launchMode = patch.launchMode;
  }
  if (typeof patch.wirelessAddress === "string") {
    next.wirelessAddress = patch.wirelessAddress.trim().slice(0, 120);
  }
  if (typeof patch.wirelessLabel === "string") {
    next.wirelessLabel = patch.wirelessLabel.trim().slice(0, 80);
  }
  if (typeof patch.vpnMitmProxyAddress === "string") {
    next.vpnMitmProxyAddress = patch.vpnMitmProxyAddress.trim().slice(0, 120) || "127.0.0.1:8080";
  }
  if (typeof patch.useProxyForPcRepeater === "boolean") {
    next.useProxyForPcRepeater = patch.useProxyForPcRepeater;
  }
  if (typeof patch.activeMainTab === "string" && patch.activeMainTab.trim()) {
    next.activeMainTab = patch.activeMainTab.trim().slice(0, 40);
  }
  if (typeof patch.appMgrFilter === "string" && patch.appMgrFilter.trim()) {
    next.appMgrFilter = patch.appMgrFilter.trim().slice(0, 30);
  }
  if (typeof patch.snippetCategoryFilter === "string" && patch.snippetCategoryFilter.trim()) {
    next.snippetCategoryFilter = patch.snippetCategoryFilter.trim().slice(0, 80);
  }
  if (typeof patch.logAutoScroll === "boolean") {
    next.logAutoScroll = patch.logAutoScroll;
  }
  if (typeof patch.guideCollapsed === "boolean") {
    next.guideCollapsed = patch.guideCollapsed;
  }
  if (patch.repeaterDraft && typeof patch.repeaterDraft === "object") {
    const rd = patch.repeaterDraft;
    if (typeof rd.method === "string" && rd.method.trim()) {
      next.repeaterDraft.method = rd.method.trim().toUpperCase().slice(0, 12);
    }
    if (typeof rd.url === "string") {
      next.repeaterDraft.url = rd.url.slice(0, 4096);
    }
    if (typeof rd.headers === "string") {
      next.repeaterDraft.headers = rd.headers.slice(0, 16384);
    }
    if (typeof rd.body === "string") {
      next.repeaterDraft.body = rd.body.slice(0, 65536);
    }
    if (typeof rd.sendFrom === "string" && ["auto", "device", "pc"].includes(rd.sendFrom)) {
      next.repeaterDraft.sendFrom = rd.sendFrom;
    }
  }

  next.updatedAt = new Date().toISOString();
  return next;
}

export class WorkspaceSettingsRepository {
  #filePath;

  constructor({ filePath = DEFAULT_SETTINGS_FILE } = {}) {
    this.#filePath = filePath;
  }

  async getSettings() {
    const defaults = createDefaultWorkspaceSettings();
    try {
      const raw = await fs.readFile(this.#filePath, "utf8");
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") return defaults;
      return {
        ...defaults,
        ...parsed,
        repeaterDraft: {
          ...defaults.repeaterDraft,
          ...(parsed.repeaterDraft && typeof parsed.repeaterDraft === "object" ? parsed.repeaterDraft : {}),
        },
      };
    } catch {
      return defaults;
    }
  }

  async updateSettings(patch = {}) {
    const current = await this.getSettings();
    const updated = sanitizeSettingsPatch(current, patch);
    await fs.mkdir(path.dirname(this.#filePath), { recursive: true });
    const tmpPath = `${this.#filePath}.tmp`;
    await fs.writeFile(tmpPath, JSON.stringify(updated, null, 2), "utf8");
    await fs.rename(tmpPath, this.#filePath);
    return updated;
  }
}
