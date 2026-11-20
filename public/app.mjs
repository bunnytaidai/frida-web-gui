// public/app.mjs — Bộ điều phối Giao diện Trạm Điều Khiển Frida v7.0.0.0
// Thiết kế chuẩn 6 Không Gian Làm Việc Liên Thông, Trung Thực 100%, Không Nút Thừa, Chuẩn Frida 17 & OWASP MASTG

const DRAFT_STORAGE_KEY = "frida_studio_v7_editor_draft";
const INTERESTING_PARAM_REGEX =
  /(?:^|_|-)(id|uid|user_id|userid|product_id|productid|bundle_id|bundleid|maungdung|masanpham|magoi|transaction_id|transactionid|original_transaction_id|order_id|sku|token|session|receipt|storefront|country|env|environment)(?:$|_|-)/i;

const LEGACY_TAB_MAP = {
  connect: "connect",
  doctor: "connect",
  target: "apps",
  apps: "apps",
  manifest: "apps",
  inject: "studio",
  studio: "studio",
  editor: "studio",
  catalog: "studio",
  capture: "packets",
  packets: "packets",
  params: "packets",
  advanced: "magnifier",
  magnifier: "magnifier",
  modules: "magnifier",
  objc: "magnifier",
  rpc: "magnifier",
  sandbox: "sandbox",
};

const state = {
  ws: null,
  wsAttempts: 0,
  activeWorkspace: "studio",
  activeMagSubTab: "smart",
  activeLogTab: "runtime",
  logLevelFilter: "ALL",
  logSearchKeyword: "",
  logPaused: false,
  pausedPendingCount: 0,

  mode: "auto",
  preferredDeviceId: "",
  preferredTarget: "",
  activeConnectionChannel: "usb_frida",
  hubChannels: [],

  devices: [],
  apps: [],
  processes: [],
  appMgrFilter: "user",
  appMgrSearch: "",

  session: {
    status: "idle",
    deviceId: null,
    pid: null,
    targetLabel: null,
    startedAt: null,
    receivedDeviceEventsCount: 0,
    executionTruth: null,
  },

  featureSwitches: {
    httpCapture: false,
    storekitObserver: false,
    authObserver: false,
    storageObserver: false,
    fileAccessObserver: false,
    uiScreenObserver: false,
  },

  snippets: [],
  categories: [],
  snippetSearchKeyword: "",
  snippetCategoryFilter: "ALL",

  httpExchanges: [],
  selectedPacketId: null,
  packetSearchKeyword: "",
  lastFocusedRepField: "url",

  savedParams: [],
  paramSearchKeyword: "",
  paramFilterCurrentApp: false,

  magPreset: "purchase",
  currentInspectModule: "",
  discoveredRpcExports: [],

  sandboxRelPath: "",
  vaultData: null,
  revealVaultValues: false,

  runtimeLogs: [],
  systemLogs: [],
  saveSettingsTimer: null,
};

const $ = (id) => document.getElementById(id);

const els = {
  toggleGuideBtn: $("toggleGuideBtn"),
  closeGuideBtn: $("closeGuideBtn"),
  newbieGuidePanel: $("newbieGuidePanel"),
  wsDot: $("wsDot"),
  wsStatusText: $("wsStatusText"),

  deviceSelect: $("deviceSelect"),
  refreshAllBtn: $("refreshAllBtn"),
  targetFilter: $("targetFilter"),
  targetSelect: $("targetSelect"),
  modeBtns: Array.from(document.querySelectorAll(".seg-btn[data-mode]")),
  runJsBtn: $("runJsBtn"),
  stopSessionBtn: $("stopSessionBtn"),

  actionStatusBanner: $("actionStatusBanner"),
  actionStatusIcon: $("actionStatusIcon"),
  actionStatusTitle: $("actionStatusTitle"),
  actionStatusText: $("actionStatusText"),

  teleJailbreakBadge: $("teleJailbreakBadge"),
  teleDeviceName: $("teleDeviceName"),
  teleDeviceMeta: $("teleDeviceMeta"),
  teleTunnelBadge: $("teleTunnelBadge"),
  teleTunnelPort: $("teleTunnelPort"),
  teleTunnelSub: $("teleTunnelSub"),
  teleBatteryBadge: $("teleBatteryBadge"),
  teleBatteryText: $("teleBatteryText"),
  teleDiskText: $("teleDiskText"),
  teleAppsCountBadge: $("teleAppsCountBadge"),
  teleFrontApp: $("teleFrontApp"),
  teleInstalledCount: $("teleInstalledCount"),
  teleSessionPidBadge: $("teleSessionPidBadge"),
  teleSessionTarget: $("teleSessionTarget"),
  teleSessionUptime: $("teleSessionUptime"),

  wsNavBtns: Array.from(document.querySelectorAll(".ws-nav-btn[data-ws]")),
  navBadgeConnect: $("navBadgeConnect"),
  navBadgeApps: $("navBadgeApps"),
  navBadgeStudio: $("navBadgeStudio"),
  navBadgePackets: $("navBadgePackets"),
  navBadgeMagnifier: $("navBadgeMagnifier"),
  navBadgeSandbox: $("navBadgeSandbox"),
  platformGuardBanner: $("platformGuardBanner"),

  wsPanes: {
    connect: $("wsPaneConnect"),
    apps: $("wsPaneApps"),
    studio: $("wsPaneStudio"),
    packets: $("wsPanePackets"),
    magnifier: $("wsPaneMagnifier"),
    sandbox: $("wsPaneSandbox"),
  },

  // Không gian 1: Kết nối & Frida SV
  probeAllChannelsBtn: $("probeAllChannelsBtn"),
  quickSwitchUsbBtn: $("quickSwitchUsbBtn"),
  fridaChannelsGrid: $("fridaChannelsGrid"),
  auxBridgesGrid: $("auxBridgesGrid"),
  wifiAddressInput: $("wifiAddressInput"),
  wifiLabelInput: $("wifiLabelInput"),
  connectWifiBtn: $("connectWifiBtn"),
  disconnectWifiBtn: $("disconnectWifiBtn"),
  vpnProxyInput: $("vpnProxyInput"),
  probeVpnBtn: $("probeVpnBtn"),
  syncRabbitBtn: $("syncRabbitBtn"),
  runHealthCheckBtn: $("runHealthCheckBtn"),
  runRepairBtn: $("runRepairBtn"),
  healthSummaryBanner: $("healthSummaryBanner"),
  healthBadge: $("healthBadge"),
  healthSummaryText: $("healthSummaryText"),
  healthLatencyMeta: $("healthLatencyMeta"),
  healthChecksGrid: $("healthChecksGrid"),
  repairStepsPre: $("repairStepsPre"),

  // Không gian 2: Ứng dụng & Hồ sơ bảo mật OWASP MASTG
  appSearchInput: $("appSearchInput"),
  refreshAppsBtn: $("refreshAppsBtn"),
  appFilterBtns: Array.from(document.querySelectorAll(".pill-btn[data-appfilter]")),
  appMgrTableBody: $("appMgrTableBody"),
  inspectPostureBtn: $("inspectPostureBtn"),
  flagPieVal: $("flagPieVal"),
  flagArcVal: $("flagArcVal"),
  flagCanaryVal: $("flagCanaryVal"),
  flagCryptVal: $("flagCryptVal"),
  postureStorekitBody: $("postureStorekitBody"),
  postureFrameworksBody: $("postureFrameworksBody"),
  postureUrlSchemesBody: $("postureUrlSchemesBody"),
  postureAtsBody: $("postureAtsBody"),
  manifestTableBody: $("manifestTableBody"),

  // Không gian 3: Công tắc 1 chạm & Trạm Mã JS
  activeSwitchesCountPill: $("activeSwitchesCountPill"),
  switchCards: Array.from(document.querySelectorAll(".sw-card[data-switch-key]")),
  snippetTotalCount: $("snippetTotalCount"),
  customSnippetsMeta: $("customSnippetsMeta"),
  openNewSnippetBtn: $("openNewSnippetBtn"),
  snippetSearchInput: $("snippetSearchInput"),
  snippetCategorySelect: $("snippetCategorySelect"),
  snippetFormBox: $("snippetFormBox"),
  snippetFormHeading: $("snippetFormHeading"),
  pullEditorCodeBtn: $("pullEditorCodeBtn"),
  importJsFileBtn: $("importJsFileBtn"),
  snippetFileInput: $("snippetFileInput"),
  snippetEditIdInput: $("snippetEditIdInput"),
  snippetTitleInput: $("snippetTitleInput"),
  snippetCategoryInput: $("snippetCategoryInput"),
  snippetRunTypeInput: $("snippetRunTypeInput"),
  snippetDescInput: $("snippetDescInput"),
  snippetCodeInput: $("snippetCodeInput"),
  confirmSaveSnippetBtn: $("confirmSaveSnippetBtn"),
  saveAndRunSnippetBtn: $("saveAndRunSnippetBtn"),
  cancelSnippetFormBtn: $("cancelSnippetFormBtn"),
  snippetCardsList: $("snippetCardsList"),
  saveEditorAsCustomBtn: $("saveEditorAsCustomBtn"),
  clearEditorDraftBtn: $("clearEditorDraftBtn"),
  editorSavedVarsBar: $("editorSavedVarsBar"),
  lineGutter: $("lineGutter"),
  codeEditor: $("codeEditor"),
  studioAnswerBadge: $("studioAnswerBadge"),
  decodeStudioAnswerBtn: $("decodeStudioAnswerBtn"),
  openPacketsFromStudioBtn: $("openPacketsFromStudioBtn"),
  studioQuickAnswerPre: $("studioQuickAnswerPre"),

  // Không gian 4: Bắt gói, Sửa gửi lại, Giải mã JWS & Sổ lưu ID
  enableHttpCaptureBtn: $("enableHttpCaptureBtn"),
  newPacketDraftBtn: $("newPacketDraftBtn"),
  genJsHookFromPacketBtn: $("genJsHookFromPacketBtn"),
  packetSearchInput: $("packetSearchInput"),
  clearPacketsBtn: $("clearPacketsBtn"),
  packetListBody: $("packetListBody"),
  repSelectedBadge: $("repSelectedBadge"),
  repeaterSavedVarsBar: $("repeaterSavedVarsBar"),
  repMethodSelect: $("repMethodSelect"),
  repUrlInput: $("repUrlInput"),
  repResolvedUrlHint: $("repResolvedUrlHint"),
  repHeadersInput: $("repHeadersInput"),
  decodeReqBodyBtn: $("decodeReqBodyBtn"),
  repBodyInput: $("repBodyInput"),
  repSendFromSelect: $("repSendFromSelect"),
  sendRepeaterBtn: $("sendRepeaterBtn"),
  repStatusBadge: $("repStatusBadge"),
  repLatencyBadge: $("repLatencyBadge"),
  decodeResponseBtn: $("decodeResponseBtn"),
  copyResponseBtn: $("copyResponseBtn"),
  detectedParamsBar: $("detectedParamsBar"),
  repResponseBodyPre: $("repResponseBodyPre"),
  repResponseHeadersPre: $("repResponseHeadersPre"),
  unifiedDecoderSection: $("unifiedDecoderSection"),
  decoderModeSelect: $("decoderModeSelect"),
  runDecoderBtn: $("runDecoderBtn"),
  clearDecoderBtn: $("clearDecoderBtn"),
  decoderInputTextarea: $("decoderInputTextarea"),
  decoderFormatBadge: $("decoderFormatBadge"),
  decoderCryptoBanner: $("decoderCryptoBanner"),
  decoderExtractedIdsBar: $("decoderExtractedIdsBar"),
  decoderOutputPre: $("decoderOutputPre"),
  paramTotalCount: $("paramTotalCount"),
  paramFilterCurrentAppChk: $("paramFilterCurrentAppChk"),
  exportParamsBtn: $("exportParamsBtn"),
  paramKeyInput: $("paramKeyInput"),
  paramValueInput: $("paramValueInput"),
  paramNoteInput: $("paramNoteInput"),
  saveParamFormBtn: $("saveParamFormBtn"),
  paramSearchInput: $("paramSearchInput"),
  savedParamsTableBody: $("savedParamsTableBody"),

  // Không gian 5: Kính lúp Hàm, Native, ObjC/RAM & RPC
  magSubTabBtns: Array.from(document.querySelectorAll(".subtab-btn[data-magtab]")),
  magSubPanes: {
    smart: $("magSubSmart"),
    native: $("magSubNative"),
    objc: $("magSubObjc"),
    rpc: $("magSubRpc"),
  },
  magFuncCount: $("magFuncCount"),
  magPresetBtns: Array.from(document.querySelectorAll(".pill-btn[data-magpreset]")),
  magFuncKeywordInput: $("magFuncKeywordInput"),
  magSearchFuncBtn: $("magSearchFuncBtn"),
  magFuncTableBody: $("magFuncTableBody"),
  moduleFilterInput: $("moduleFilterInput"),
  loadModulesBtn: $("loadModulesBtn"),
  modulesTableBody: $("modulesTableBody"),
  exportsTitle: $("exportsTitle"),
  exportFilterInput: $("exportFilterInput"),
  exportsTableBody: $("exportsTableBody"),
  objcFilterInput: $("objcFilterInput"),
  searchObjcClassesBtn: $("searchObjcClassesBtn"),
  objcClassList: $("objcClassList"),
  objcMethodsTitle: $("objcMethodsTitle"),
  objcMethodsBody: $("objcMethodsBody"),
  magMemCountBadge: $("magMemCountBadge"),
  memChipBtns: Array.from(document.querySelectorAll(".mem-chip[data-memclass]")),
  magMemClassInput: $("magMemClassInput"),
  magScanMemBtn: $("magScanMemBtn"),
  magMemTableBody: $("magMemTableBody"),
  refreshRpcExportsBtn: $("refreshRpcExportsBtn"),
  loadRpcDemoBtn: $("loadRpcDemoBtn"),
  rpcDiscoveredBar: $("rpcDiscoveredBar"),
  rpcMethodInput: $("rpcMethodInput"),
  rpcArgsInput: $("rpcArgsInput"),
  invokeRpcBtn: $("invokeRpcBtn"),
  rpcResultPre: $("rpcResultPre"),

  // Không gian 6: Tệp Sandbox & Két sắt bảo mật
  sandboxUpDirBtn: $("sandboxUpDirBtn"),
  sandboxRefreshBtn: $("sandboxRefreshBtn"),
  sandboxQuickDirBtns: Array.from(document.querySelectorAll(".sb-dir-btn[data-sbdir]")),
  sandboxCurrentPathLabel: $("sandboxCurrentPathLabel"),
  sandboxFilesTableBody: $("sandboxFilesTableBody"),
  sandboxPreviewTitle: $("sandboxPreviewTitle"),
  decodeSandboxFileBtn: $("decodeSandboxFileBtn"),
  copySandboxFileBtn: $("copySandboxFileBtn"),
  sandboxFileViewerPre: $("sandboxFileViewerPre"),
  toggleVaultMaskBtn: $("toggleVaultMaskBtn"),
  inspectVaultBtn: $("inspectVaultBtn"),
  vaultSummaryNote: $("vaultSummaryNote"),
  securityVaultTableBody: $("securityVaultTableBody"),

  // Nhật ký đôi thời gian thực bên phải
  logTabBtns: Array.from(document.querySelectorAll(".log-tab-btn[data-logtab]")),
  runtimeLogCount: $("runtimeLogCount"),
  systemLogCount: $("systemLogCount"),
  pauseLogStreamBtn: $("pauseLogStreamBtn"),
  autoScrollToggle: $("autoScrollToggle"),
  exportLogsBtn: $("exportLogsBtn"),
  clearLogsBtn: $("clearLogsBtn"),
  levelFilterBtns: Array.from(document.querySelectorAll(".lv-pill[data-level]")),
  logSearchInput: $("logSearchInput"),
  runtimeLogScroll: $("runtimeLogScroll"),
  systemLogScroll: $("systemLogScroll"),
  runtimeLogBody: $("runtimeLogBody"),
  systemLogBody: $("systemLogBody"),

  toastStack: $("toastStack"),
};

// ============================================================================
// HÀM TIỆN ÍCH CHUNG & GỌI API CHUẨN PHONG BÌ BACKEND
// ============================================================================
function escapeHtml(val) {
  return String(val ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatClockMs(ts) {
  const d = ts ? new Date(ts) : new Date();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms.slice(0, 2)}`;
}

function formatDuration(startedAt) {
  if (!startedAt) return "00:00:00";
  const sec = Math.max(0, Math.floor((Date.now() - Number(startedAt)) / 1000));
  const h = String(Math.floor(sec / 3600)).padStart(2, "0");
  const m = String(Math.floor((sec % 3600) / 60)).padStart(2, "0");
  const s = String(sec % 60).padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function formatByteSize(bytes) {
  const n = Number(bytes) || 0;
  if (n <= 0) return "0 B";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function prettyFormatBody(rawText) {
  const s = String(rawText ?? "").trim();
  if (!s) return "";
  if (s.startsWith("{") || s.startsWith("[")) {
    try {
      return JSON.stringify(JSON.parse(s), null, 2);
    } catch {
      return s;
    }
  }
  return s;
}

function showToast(kind, title, sub = "", durationMs = 3400) {
  if (!els.toastStack) return;
  const item = document.createElement("div");
  const cls = kind === "ok" ? "toast-ok" : kind === "warn" ? "toast-warn" : kind === "err" ? "toast-err" : "toast-info";
  item.className = `toast-item ${cls}`;
  item.innerHTML = `<div class="toast-title">${escapeHtml(title)}</div>${
    sub ? `<div class="toast-sub">${escapeHtml(sub)}</div>` : ""
  }`;
  els.toastStack.appendChild(item);
  while (els.toastStack.children.length > 4) {
    els.toastStack.firstElementChild?.remove();
  }
  setTimeout(() => item.remove(), durationMs);
}

function updateActionBanner(kind, titleText, detailText = "") {
  if (!els.actionStatusBanner) return;
  const map = {
    ok: { cls: "status-ok", icon: "🟢" },
    warn: { cls: "status-warn", icon: "🟡" },
    err: { cls: "status-err", icon: "🔴" },
    info: { cls: "status-info", icon: "🔵" },
    idle: { cls: "status-idle", icon: "💡" },
  };
  const cfg = map[kind] || map.info;
  els.actionStatusBanner.className = `action-status-banner ${cfg.cls}`;
  if (els.actionStatusIcon) els.actionStatusIcon.textContent = cfg.icon;
  if (els.actionStatusTitle) els.actionStatusTitle.textContent = detailText ? `${titleText}:` : "Trạng thái thực tế:";
  if (els.actionStatusText) els.actionStatusText.textContent = detailText || titleText;
}

function reportUiError(prefixTitle, err) {
  const msg = err?.message || String(err);
  updateActionBanner("err", prefixTitle, msg);
  showToast("err", `⚠️ ${prefixTitle}`, msg, 4500);
}

async function apiFetch(url, options = {}) {
  const res = await fetch(url, options);
  const body = await res.json().catch(() => null);
  if (!res.ok || !body || body.success === false) {
    const errMsg = body?.error?.message || `Yêu cầu thất bại (HTTP ${res.status})`;
    const e = new Error(errMsg);
    e.traceId = body?.error?.traceId || "";
    e.code = body?.error?.code || "";
    throw e;
  }
  return body.data;
}

function isLocalPcDeviceSelected() {
  const devId = els.deviceSelect?.value || state.preferredDeviceId || "";
  const dev = state.devices.find((d) => d.id === devId);
  return Boolean(dev && dev.type === "local");
}

function applyPlatformCapabilitiesGuard() {
  const isLocalPc = isLocalPcDeviceSelected();
  if (els.platformGuardBanner) {
    els.platformGuardBanner.hidden = !isLocalPc;
  }
  if (els.navBadgeSandbox) {
    els.navBadgeSandbox.textContent = isLocalPc ? "Chỉ iOS" : "iOS";
  }

  const iosOnlyNodes = document.querySelectorAll('[data-ios-only="1"]');
  for (const node of iosOnlyNodes) {
    node.disabled = isLocalPc;
    if (isLocalPc) {
      node.dataset.origTitle = node.dataset.origTitle || node.title || "";
      node.title = "Tính năng này chỉ hoạt động khi bạn chọn thiết bị iPhone (iOS) ở ô số 1.";
    } else if (node.dataset.origTitle !== undefined) {
      node.title = node.dataset.origTitle;
    }
  }

  if (els.repSendFromSelect) {
    const devOpt = els.repSendFromSelect.querySelector('option[value="device"]');
    if (devOpt) devOpt.disabled = isLocalPc;
    if (isLocalPc && els.repSendFromSelect.value === "device") {
      els.repSendFromSelect.value = "pc";
    }
  }
}

function buildAutoAttachQuery() {
  const devId = els.deviceSelect?.value || "";
  const target = els.targetSelect?.value || els.targetFilter?.value?.trim() || "";
  return `autoAttach=1&deviceId=${encodeURIComponent(devId)}&target=${encodeURIComponent(target)}&mode=${encodeURIComponent(
    state.mode || "auto"
  )}`;
}

// ============================================================================
// LƯU & KHÔI PHỤC CẤU HÌNH BỀN VỮNG (KHÔNG MẤT KHI BẤM F5)
// ============================================================================
function scheduleSaveSettings(extraPatch = {}) {
  if (state.saveSettingsTimer) clearTimeout(state.saveSettingsTimer);
  state.saveSettingsTimer = setTimeout(async () => {
    try {
      const payload = {
        activeConnectionChannel: state.activeConnectionChannel,
        selectedDeviceId: els.deviceSelect?.value || state.preferredDeviceId || "",
        selectedTarget: els.targetSelect?.value || state.preferredTarget || "",
        launchMode: state.mode,
        wirelessAddress: els.wifiAddressInput?.value?.trim() || "",
        wirelessLabel: els.wifiLabelInput?.value?.trim() || "",
        vpnMitmProxyAddress: els.vpnProxyInput?.value?.trim() || "127.0.0.1:8080",
        activeMainTab: state.activeWorkspace,
        appMgrFilter: state.appMgrFilter,
        snippetCategoryFilter: state.snippetCategoryFilter,
        logAutoScroll: Boolean(els.autoScrollToggle?.checked),
        guideCollapsed: Boolean(els.newbieGuidePanel?.hidden),
        repeaterDraft: {
          method: els.repMethodSelect?.value || "GET",
          url: els.repUrlInput?.value || "",
          headers: els.repHeadersInput?.value || "{}",
          body: els.repBodyInput?.value || "",
          sendFrom: els.repSendFromSelect?.value || "auto",
        },
        ...extraPatch,
      };
      await apiFetch("/api/v1/settings", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
    } catch {
      // Bỏ qua lỗi lưu ngầm nếu máy chủ tạm bận
    }
  }, 350);
}

async function loadWorkspaceSettings() {
  try {
    const { settings } = await apiFetch("/api/v1/settings");
    if (!settings) return;

    state.activeConnectionChannel = settings.activeConnectionChannel || "usb_frida";
    state.preferredDeviceId = settings.selectedDeviceId || "";
    state.preferredTarget = settings.selectedTarget || "";
    applyLaunchModeUi(settings.launchMode || "auto");

    if (els.wifiAddressInput && settings.wirelessAddress) els.wifiAddressInput.value = settings.wirelessAddress;
    if (els.wifiLabelInput && settings.wirelessLabel) els.wifiLabelInput.value = settings.wirelessLabel;
    if (els.vpnProxyInput && settings.vpnMitmProxyAddress) els.vpnProxyInput.value = settings.vpnMitmProxyAddress;

    if (settings.appMgrFilter) {
      state.appMgrFilter = settings.appMgrFilter;
      for (const b of els.appFilterBtns) b.classList.toggle("active", b.dataset.appfilter === state.appMgrFilter);
    }
    if (settings.snippetCategoryFilter) {
      state.snippetCategoryFilter = settings.snippetCategoryFilter;
    }
    if (els.autoScrollToggle && typeof settings.logAutoScroll === "boolean") {
      els.autoScrollToggle.checked = settings.logAutoScroll;
    }
    setGuideVisible(!settings.guideCollapsed, false);

    if (settings.repeaterDraft) {
      const rd = settings.repeaterDraft;
      if (els.repMethodSelect && rd.method) els.repMethodSelect.value = rd.method;
      if (els.repUrlInput && rd.url) els.repUrlInput.value = rd.url;
      if (els.repHeadersInput && rd.headers) els.repHeadersInput.value = rd.headers;
      if (els.repBodyInput && typeof rd.body === "string") els.repBodyInput.value = rd.body;
      if (els.repSendFromSelect && rd.sendFrom) els.repSendFromSelect.value = rd.sendFrom;
      updateResolvedUrlPreview();
    }

    const mappedWs = LEGACY_TAB_MAP[settings.activeMainTab] || "studio";
    switchWorkspace(mappedWs, false);
  } catch {
    switchWorkspace("studio", false);
  }
}

function setGuideVisible(visible, persist = true) {
  if (!els.newbieGuidePanel || !els.toggleGuideBtn) return;
  els.newbieGuidePanel.hidden = !visible;
  els.toggleGuideBtn.setAttribute("aria-expanded", String(visible));
  els.toggleGuideBtn.textContent = visible ? "📘 Ẩn hướng dẫn" : "📘 Hướng dẫn nhanh";
  if (persist) scheduleSaveSettings({ guideCollapsed: !visible });
}

function applyLaunchModeUi(nextMode) {
  const valid = ["auto", "attach", "spawn"].includes(nextMode) ? nextMode : "auto";
  state.mode = valid;
  for (const btn of els.modeBtns) {
    btn.classList.toggle("active", btn.dataset.mode === valid);
  }
}

// ============================================================================
// ĐIỀU HƯỚNG 6 KHÔNG GIAN LÀM VIỆC & CHẾ ĐỘ CON
// ============================================================================
function switchWorkspace(wsKey, persist = true) {
  const validKey = els.wsPanes[wsKey] ? wsKey : "studio";
  state.activeWorkspace = validKey;

  for (const btn of els.wsNavBtns) {
    btn.classList.toggle("active", btn.dataset.ws === validKey);
  }
  for (const [k, pane] of Object.entries(els.wsPanes)) {
    if (pane) pane.hidden = k !== validKey;
  }

  if (validKey === "connect") {
    void probeConnectionChannels(false);
  } else if (validKey === "apps") {
    renderAppMgrTable();
  } else if (validKey === "magnifier" && state.activeMagSubTab === "rpc") {
    void refreshDiscoveredRpcExports(false);
  }

  if (persist) scheduleSaveSettings({ activeMainTab: validKey });
}

function switchMagSubTab(subKey) {
  const valid = els.magSubPanes[subKey] ? subKey : "smart";
  state.activeMagSubTab = valid;
  for (const b of els.magSubTabBtns) {
    b.classList.toggle("active", b.dataset.magtab === valid);
  }
  for (const [k, pane] of Object.entries(els.magSubPanes)) {
    if (pane) pane.hidden = k !== valid;
  }
  if (valid === "rpc") {
    void refreshDiscoveredRpcExports(false);
  }
}

// ============================================================================
// KHÔNG GIAN ①: QUẢN LÝ KẾT NỐI ĐA KÊNH, WI-FI, CẦU NỐI & BÁC SĨ FRIDA
// ============================================================================
function updateDisconnectWifiVisibility() {
  if (!els.disconnectWifiBtn) return;
  const hasRemoteWifi = state.devices.some((d) => d.type === "remote");
  els.disconnectWifiBtn.hidden = !hasRemoteWifi;
}

async function probeConnectionChannels(notifyUser = false) {
  if (els.probeAllChannelsBtn) els.probeAllChannelsBtn.disabled = true;
  try {
    const devId = els.deviceSelect?.value || state.preferredDeviceId || "";
    const wifiAddr = els.wifiAddressInput?.value?.trim() || "";
    const vpnAddr = els.vpnProxyInput?.value?.trim() || "127.0.0.1:8080";
    const qs =
      `deviceId=${encodeURIComponent(devId)}` +
      `&wirelessAddress=${encodeURIComponent(wifiAddr)}` +
      `&vpnMitmProxyAddress=${encodeURIComponent(vpnAddr)}` +
      `&activeChannel=${encodeURIComponent(state.activeConnectionChannel)}`;

    const { hub } = await apiFetch(`/api/v1/connections/status?${qs}`);
    state.hubChannels = hub?.channels || [];
    renderConnectionHubCards();

    if (notifyUser) {
      updateActionBanner("ok", "Đã đo thực tế các kênh kết nối", hub?.summaryText || "Hoàn tất kiểm tra cổng thật.");
      showToast("ok", "🔌 Đã kiểm tra cổng kết nối thực tế", hub?.summaryText || "");
    }
  } catch (err) {
    if (notifyUser) reportUiError("Không thể đo trạng thái kênh kết nối", err);
  } finally {
    if (els.probeAllChannelsBtn) els.probeAllChannelsBtn.disabled = false;
  }
}

function renderConnectionHubCards() {
  if (!els.fridaChannelsGrid || !els.auxBridgesGrid) return;

  const fridaExecutionIds = new Set(["usb_frida", "wifi_frida", "local_pc"]);
  const fridaChannels = state.hubChannels.filter((c) => c.canSwitchDevice || fridaExecutionIds.has(c.id));
  const auxChannels = state.hubChannels.filter((c) => !c.canSwitchDevice && !fridaExecutionIds.has(c.id));

  // Cập nhật huy hiệu trên thanh điều hướng
  if (els.navBadgeConnect) {
    const labelMap = { usb_frida: "USB", wifi_frida: "Wi-Fi", local_pc: "PC" };
    els.navBadgeConnect.textContent = labelMap[state.activeConnectionChannel] || "USB";
  }

  // Nhóm A: 3 Kênh Thiết Bị Thực Thi Frida (Có nút Chuyển kênh thật)
  els.fridaChannelsGrid.innerHTML = "";
  for (const ch of fridaChannels) {
    const isCurrent = state.activeConnectionChannel === ch.id;
    const stCls =
      ch.status === "connected" ? "lv-send" : ch.status === "degraded" ? "lv-warning" : "lv-error";

    const card = document.createElement("article");
    card.className = `conn-card${isCurrent ? " conn-active" : ""}`;

    const statusVi =
      ch.statusLabelVi ||
      (ch.status === "connected" ? "ĐANG THÔNG SUỐT" : ch.status === "degraded" ? "CHỜ CẤU HÌNH" : "ĐANG TẮT");

    const top = document.createElement("div");
    top.className = "conn-card-top";
    top.innerHTML = `
      <div>
        <div class="conn-title">${escapeHtml(ch.title)}</div>
        <div class="conn-endpoint">${escapeHtml(ch.endpoint || "-")}</div>
      </div>
      <span class="badge-lv ${stCls}">${escapeHtml(statusVi)}</span>
    `;

    const desc = document.createElement("p");
    desc.className = "conn-detail";
    const detailText = ch.detail || ch.detailVi || "";
    const latStr = typeof ch.latencyMs === "number" && !detailText.includes(" ms") ? ` • Độ trễ thật: ${ch.latencyMs} ms` : "";
    desc.textContent = `${detailText}${latStr}`;

    const btn = document.createElement("button");
    btn.type = "button";
    if (isCurrent && ch.status === "connected") {
      btn.className = "btn btn-accent-sm";
      btn.textContent = "✅ Đang dùng kênh Frida này (Đo lại)";
    } else {
      btn.className = "btn btn-primary btn-sm";
      btn.textContent =
        ch.id === "wifi_frida" && ch.status !== "connected"
          ? "📶 Nhập IP bên dưới để bật Wi-Fi"
          : "⚡ Chuyển sang kênh Frida này";
    }
    btn.addEventListener("click", () => {
      if (ch.id === "wifi_frida" && !(els.wifiAddressInput?.value?.trim())) {
        els.wifiAddressInput?.focus();
        showToast("info", "Nhập địa chỉ IP Wi-Fi của iPhone", "Ví dụ: 192.168.1.50:27042 rồi bấm '+ Kết nối & Chuyển sang Wi-Fi'.");
        return;
      }
      void switchFridaChannel(ch.id, btn);
    });

    card.append(top, desc, btn);
    els.fridaChannelsGrid.appendChild(card);
  }

  // Nhóm B: 4 Cầu Nối Phụ Trợ (KHÔNG có nút chuyển giả — chỉ hiện trạng thái thật!)
  els.auxBridgesGrid.innerHTML = "";
  let rabbitAlive = false;
  for (const ch of auxChannels) {
    if (ch.id === "rabbit_daemon" && ch.status === "connected") {
      rabbitAlive = true;
    }
    const stCls =
      ch.status === "connected" ? "lv-send" : ch.status === "degraded" ? "lv-warning" : "lv-info";
    const card = document.createElement("article");
    card.className = "conn-card";
    const statusVi =
      ch.statusLabelVi ||
      (ch.status === "connected" ? "ĐANG HOẠT ĐỘNG" : ch.status === "degraded" ? "MỘT PHẦN" : "CHƯA BẬT");
    const detailText = ch.detail || ch.detailVi || "";
    const latStr = typeof ch.latencyMs === "number" ? ` (${ch.latencyMs} ms)` : "";
    card.innerHTML = `
      <div class="conn-card-top">
        <div>
          <div class="conn-title">${escapeHtml(ch.title)}</div>
          <div class="conn-endpoint">${escapeHtml(ch.endpoint || "-")}${escapeHtml(latStr)}</div>
        </div>
        <span class="badge-lv ${stCls}">${escapeHtml(statusVi)}</span>
      </div>
      <p class="conn-detail">${escapeHtml(detailText)}</p>
    `;
    els.auxBridgesGrid.appendChild(card);
  }

  // Khóa chặt nút Đồng bộ RabbitUltrad nếu cổng 8765 đang tắt!
  if (els.syncRabbitBtn) {
    els.syncRabbitBtn.disabled = !rabbitAlive;
    els.syncRabbitBtn.textContent = rabbitAlive
      ? "🐰 Đồng bộ gói tin thật từ cổng 8765"
      : "🐰 Đồng bộ gói từ cổng 8765 (Cổng đang tắt)";
  }
}

async function switchFridaChannel(channelId, btnEl = null) {
  if (btnEl) btnEl.disabled = true;
  updateActionBanner("info", "Đang chuyển kênh thực thi Frida", `Đang kiểm tra và kích hoạt '${channelId}'...`);
  try {
    const out = await apiFetch("/api/v1/connections/switch", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": `switch-${channelId}-${Date.now()}`,
      },
      body: JSON.stringify({
        channel: channelId,
        wirelessAddress: els.wifiAddressInput?.value?.trim() || "",
        wirelessLabel: els.wifiLabelInput?.value?.trim() || "",
        vpnMitmProxyAddress: els.vpnProxyInput?.value?.trim() || "127.0.0.1:8080",
      }),
    });

    state.activeConnectionChannel = out.activatedChannel || channelId;
    if (out.selectedDeviceId) {
      state.preferredDeviceId = out.selectedDeviceId;
    }
    state.hubChannels = out.hub?.channels || state.hubChannels;
    renderConnectionHubCards();
    await loadDevicesAndTargets(false);

    const rep = out.channelReport;
    const isOk = rep?.status === "connected";
    updateActionBanner(
      isOk ? "ok" : "warn",
      isOk ? "Đã chuyển kênh Frida thành công" : "Kênh vừa chọn chưa phản hồi đầy đủ",
      `${rep?.title || channelId}: ${rep?.detailVi || ""}`
    );
    showToast(isOk ? "ok" : "warn", `🔌 ${rep?.title || channelId}`, rep?.detailVi || "");
  } catch (err) {
    reportUiError("Không thể chuyển kênh kết nối Frida", err);
  } finally {
    if (btnEl) btnEl.disabled = false;
  }
}

async function handleConnectWifi() {
  const address = els.wifiAddressInput?.value?.trim() || "";
  const label = els.wifiLabelInput?.value?.trim() || "";
  if (!address) {
    els.wifiAddressInput?.focus();
    showToast("warn", "Chưa nhập địa chỉ IP Wi-Fi", "Ví dụ: 192.168.1.50:27042");
    return;
  }
  await switchFridaChannel("wifi_frida", els.connectWifiBtn);
  scheduleSaveSettings({ wirelessAddress: address, wirelessLabel: label });
}

async function handleDisconnectWifi() {
  const remoteDev =
    state.devices.find((d) => d.id === els.deviceSelect?.value && d.type === "remote") ||
    state.devices.find((d) => d.type === "remote");
  if (!remoteDev) return;

  if (els.disconnectWifiBtn) els.disconnectWifiBtn.disabled = true;
  try {
    await apiFetch(`/api/v1/devices/wireless/${encodeURIComponent(remoteDev.id)}`, { method: "DELETE" });
    state.activeConnectionChannel = "usb_frida";
    await loadDevicesAndTargets(false);
    await probeConnectionChannels(false);
    updateActionBanner("info", "Đã ngắt kết nối Wi-Fi", `Đã gỡ thiết bị không dây ${remoteDev.name} và quay về Cáp USB.`);
    showToast("info", "⏹️ Đã ngắt thiết bị Wi-Fi", remoteDev.name);
  } catch (err) {
    reportUiError("Không thể ngắt thiết bị Wi-Fi", err);
  } finally {
    if (els.disconnectWifiBtn) els.disconnectWifiBtn.disabled = false;
  }
}

async function handleSyncRabbitDaemon() {
  if (!els.syncRabbitBtn) return;
  els.syncRabbitBtn.disabled = true;
  try {
    const out = await apiFetch("/api/v1/connections/rabbit-sync", { method: "POST" });
    await loadHttpExchanges();
    switchWorkspace("packets");
    updateActionBanner("ok", "Đồng bộ gói tin RabbitUltrad", out.message || `Đã nhập ${out.importedCount || 0} gói tin.`);
    showToast("ok", "🐰 Đã đồng bộ từ cổng 8765", out.message || "");
  } catch (err) {
    reportUiError("Không thể đồng bộ từ cổng 8765", err);
  } finally {
    void probeConnectionChannels(false);
  }
}

async function handleCheckFridaHealth(notifyToast = true) {
  if (els.runHealthCheckBtn) els.runHealthCheckBtn.disabled = true;
  try {
    const devId = els.deviceSelect?.value || "";
    const { report } = await apiFetch(`/api/v1/frida-server/status?deviceId=${encodeURIComponent(devId)}`);
    renderHealthReport(report);
    const st = report?.overallStatus || report?.status;
    if (notifyToast) {
      showToast(st === "healthy" ? "ok" : "warn", "🩺 Kết quả kiểm tra Frida Server", report.summary);
    }
  } catch (err) {
    if (notifyToast) reportUiError("Không thể kiểm tra sức khỏe Frida Server", err);
  } finally {
    if (els.runHealthCheckBtn) els.runHealthCheckBtn.disabled = false;
  }
}

function renderHealthReport(report) {
  if (!report) return;
  const st = report.overallStatus || report.status || "error";
  if (els.healthBadge) {
    els.healthBadge.className = `badge-lv ${
      st === "healthy" ? "lv-send" : st === "warning" ? "lv-warning" : "lv-error"
    }`;
    els.healthBadge.textContent =
      st === "healthy" ? "HOẠT ĐỘNG TỐT" : st === "warning" ? "CẦN CHÚ Ý" : "GIÁN ĐOẠN";
  }
  if (els.healthSummaryText) els.healthSummaryText.textContent = report.summary || "";
  if (els.healthLatencyMeta) {
    els.healthLatencyMeta.textContent = `SDK PC: ${report.fridaClientVersion || report.pcSdkVersion || "--"} • Máy chủ: ${
      report.fridaServerVersion || report.serverVersion || "--"
    } • Độ trễ: ${report.latencyMs ?? "--"} ms`;
  }
  if (els.healthChecksGrid) {
    els.healthChecksGrid.innerHTML = "";
    for (const c of report.checks || []) {
      const isOk = c.status ? c.status === "ok" : Boolean(c.ok);
      const isWarn = c.status === "warning";
      const div = document.createElement("div");
      div.className = `check-step-card ${isOk ? "step-ok" : "step-fail"}`;
      div.innerHTML = `
        <strong>${isOk ? "✅" : isWarn ? "⚠️" : "❌"} ${escapeHtml(c.title || c.label || "")}</strong>
        <span class="muted-note">${escapeHtml(c.detail || "")}</span>
      `;
      els.healthChecksGrid.appendChild(div);
    }
  }
}

async function handleRepairFridaServer() {
  if (els.runRepairBtn) els.runRepairBtn.disabled = true;
  updateActionBanner("info", "Đang tự động sửa kết nối", "Đang làm mới cầu nối USB 27042 và kiểm tra frida-server qua SSH...");
  try {
    const devId = els.deviceSelect?.value || "";
    const out = await apiFetch("/api/v1/frida-server/repair", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": `repair-${Date.now()}`,
      },
      body: JSON.stringify({ deviceId: devId }),
    });
    if (out.report) renderHealthReport(out.report);
    if (els.repairStepsPre) {
      els.repairStepsPre.hidden = false;
      els.repairStepsPre.textContent = (out.steps || []).map((s, idx) => `${idx + 1}. ${s}`).join("\n");
    }
    await loadDevicesAndTargets(false);
    await probeConnectionChannels(false);
    updateActionBanner("ok", "Đã hoàn tất sửa chữa cầu nối Frida", out.report?.summary || "");
    showToast("ok", "🛠️ Đã làm mới kết nối Frida Server", out.report?.summary || "");
  } catch (err) {
    reportUiError("Không thể tự động sửa kết nối Frida", err);
  } finally {
    if (els.runRepairBtn) els.runRepairBtn.disabled = false;
  }
}

// ============================================================================
// TẢI THIẾT BỊ, THÔNG SỐ TELEMETRY & DANH SÁCH ỨNG DỤNG
// ============================================================================
async function loadDevicesAndTargets(notifyUser = false) {
  try {
    const { devices } = await apiFetch("/api/v1/devices");
    state.devices = devices || [];
    updateDisconnectWifiVisibility();

    els.deviceSelect.innerHTML = "";
    if (state.devices.length === 0) {
      els.deviceSelect.innerHTML = `<option value="">Không tìm thấy thiết bị Frida</option>`;
      return;
    }

    for (const d of state.devices) {
      const opt = document.createElement("option");
      opt.value = d.id;
      const prefix = d.type === "usb" ? "🔌 [USB]" : d.type === "remote" ? "📶 [Wi-Fi]" : "🖥️ [PC]";
      opt.textContent = `${prefix} ${d.name}`;
      els.deviceSelect.appendChild(opt);
    }

    const usbDev = state.devices.find((d) => d.type === "usb");
    const preferredExists = state.devices.some((d) => d.id === state.preferredDeviceId);
    els.deviceSelect.value = preferredExists ? state.preferredDeviceId : usbDev ? usbDev.id : state.devices[0].id;
    state.preferredDeviceId = els.deviceSelect.value;

    applyPlatformCapabilitiesGuard();
    await Promise.all([loadTargetsForCurrentDevice(), refreshTelemetry()]);

    if (notifyUser) {
      showToast("ok", "🔄 Đã cập nhật thiết bị & ứng dụng", `Phát hiện ${state.devices.length} thiết bị.`);
    }
  } catch (err) {
    if (notifyUser) reportUiError("Không thể tải danh sách thiết bị", err);
  }
}

async function loadTargetsForCurrentDevice() {
  const devId = els.deviceSelect?.value;
  if (!devId) return;
  try {
    const data = await apiFetch(`/api/v1/devices/${encodeURIComponent(devId)}/targets`);
    state.apps = data.apps || data.applications || [];
    state.processes = data.processes || [];
    renderTargetDropdown();
    renderAppMgrTable();
    const count = state.apps.length > 0 ? state.apps.length : state.processes.length;
    if (els.navBadgeApps) els.navBadgeApps.textContent = String(count);
  } catch (err) {
    els.targetSelect.innerHTML = `<option value="">Không đọc được danh sách App (${escapeHtml(err.message)})</option>`;
  }
}

function renderTargetDropdown() {
  if (!els.targetSelect) return;
  const kw = (els.targetFilter?.value || "").trim().toLowerCase();
  const prevVal = els.targetSelect.value || state.preferredTarget;
  els.targetSelect.innerHTML = "";

  const useApps = state.apps.length > 0;
  const list = useApps
    ? state.apps.map((a) => ({
        val: a.identifier,
        label: `${a.isFrontmost ? "🟢 [ĐANG MỞ] " : a.pid > 0 ? "🟡 " : ""}${a.name} (${a.identifier})`,
        search: `${a.name} ${a.identifier} ${a.pid}`.toLowerCase(),
        isFrontmost: Boolean(a.isFrontmost),
      }))
    : state.processes.map((p) => ({
        val: String(p.pid),
        label: `${p.name} (PID: ${p.pid})`,
        search: `${p.name} ${p.pid}`.toLowerCase(),
        isFrontmost: false,
      }));

  const filtered = kw ? list.filter((x) => x.search.includes(kw)) : list;
  if (filtered.length === 0) {
    els.targetSelect.innerHTML = `<option value="">Không có ứng dụng khớp từ khóa lọc</option>`;
    return;
  }

  for (const item of filtered.slice(0, 350)) {
    const opt = document.createElement("option");
    opt.value = item.val;
    opt.textContent = item.label;
    els.targetSelect.appendChild(opt);
  }

  if (prevVal && Array.from(els.targetSelect.options).some((o) => o.value === prevVal)) {
    els.targetSelect.value = prevVal;
  } else {
    const front = filtered.find((x) => x.isFrontmost);
    if (front) els.targetSelect.value = front.val;
  }
  state.preferredTarget = els.targetSelect.value;
}

async function refreshTelemetry() {
  const devId = els.deviceSelect?.value;
  if (!devId) return;
  try {
    const { telemetry } = await apiFetch(`/api/v1/devices/${encodeURIComponent(devId)}/telemetry`);
    if (!telemetry) return;

    const connType = telemetry.connectionType || telemetry.deviceType || "usb";
    const hw = telemetry.hardware || {};
    const counts = telemetry.counts || {};
    const tunnelPort = telemetry.tunnel?.localPort || telemetry.tunnelPort || null;
    const isJailbroken = telemetry.accessLevel === "full" || Boolean(telemetry.jailbroken);

    if (els.teleDeviceName) {
      els.teleDeviceName.textContent = telemetry.displayName || telemetry.deviceName || devId;
    }
    if (els.teleDeviceMeta) {
      const osFull = [telemetry.osName, telemetry.osVersion].filter(Boolean).join(" ") || "-";
      els.teleDeviceMeta.textContent = `${telemetry.productType || "-"} • ${osFull} (${telemetry.arch || "-"})`;
    }

    if (els.teleJailbreakBadge) {
      if (connType === "local") {
        els.teleJailbreakBadge.className = "pill pill-info";
        els.teleJailbreakBadge.textContent = "WINDOWS PC";
      } else if (isJailbroken) {
        els.teleJailbreakBadge.className = "pill pill-ok";
        els.teleJailbreakBadge.textContent = "ĐÃ BẺ KHÓA (CÓ QUYỀN)";
      } else {
        els.teleJailbreakBadge.className = "pill pill-warn";
        els.teleJailbreakBadge.textContent = "CHẾ ĐỘ GIỚI HẠN";
      }
    }

    if (els.teleTunnelBadge) {
      els.teleTunnelBadge.className = telemetry.fridaServerConnected !== false ? "pill pill-ok" : "pill pill-err";
      els.teleTunnelBadge.textContent =
        connType === "usb" ? "CÁP USB" : connType === "remote" ? "WI-FI" : "LOCAL PC";
    }
    if (els.teleTunnelPort) {
      els.teleTunnelPort.textContent = tunnelPort
        ? `Cổng cáp 127.0.0.1:${tunnelPort} ➔ 27042`
        : connType === "local"
        ? "Trực tiếp trên máy trạm"
        : `Cổng ${telemetry.wirelessAddress || "27042"} trực tiếp`;
    }
    if (els.teleTunnelSub) {
      const latTxt = typeof telemetry.fridaLatencyMs === "number" ? ` (${telemetry.fridaLatencyMs} ms)` : "";
      els.teleTunnelSub.textContent = `Frida ${telemetry.fridaSdkVersion || "17.26.2"}${latTxt} • ID: ${String(
        telemetry.deviceId || devId
      ).slice(0, 18)}`;
    }

    const battPct = hw.batteryLevel ?? telemetry.batteryPercent;
    const battChg = hw.batteryCharging ?? telemetry.batteryCharging;
    if (els.teleBatteryText) {
      els.teleBatteryText.textContent =
        typeof battPct === "number"
          ? `Mức pin: ${battPct}%`
          : hw.freeMemMB
          ? `RAM trống: ${(hw.freeMemMB / 1024).toFixed(1)} GB`
          : "Nguồn trực tiếp PC";
    }
    if (els.teleBatteryBadge) {
      els.teleBatteryBadge.className = battChg ? "pill pill-ok" : "pill pill-neutral";
      els.teleBatteryBadge.textContent = battChg
        ? "Đang sạc pin"
        : typeof battPct === "number"
        ? "Dùng pin"
        : "AC Power";
    }
    const freeGb = hw.diskFreeGB ?? telemetry.diskFreeGb;
    const totalGb = hw.diskTotalGB ?? telemetry.diskTotalGb;
    if (els.teleDiskText) {
      els.teleDiskText.textContent = freeGb
        ? `Bộ nhớ trống ${freeGb} GB / ${totalGb || "--"} GB`
        : hw.totalMemMB
        ? `Tổng RAM máy trạm: ${(hw.totalMemMB / 1024).toFixed(0)} GB`
        : "Đang đồng bộ phần cứng trực tiếp";
    }

    if (els.teleFrontApp) {
      els.teleFrontApp.textContent = telemetry.frontmostApp
        ? `${telemetry.frontmostApp.name} (PID ${telemetry.frontmostApp.pid})`
        : "Màn hình chính (SpringBoard)";
    }
    if (els.teleAppsCountBadge) {
      els.teleAppsCountBadge.textContent = `${counts.runningApps ?? telemetry.runningAppsCount ?? 0} ứng dụng mở`;
    }
    if (els.teleInstalledCount) {
      els.teleInstalledCount.textContent = `Đã cài: ${counts.installedApps ?? state.apps.length} • Tổng tiến trình: ${
        counts.totalProcesses ?? state.processes.length
      }`;
    }
  } catch {
    // Không ghi đè thông báo lỗi khi làm mới định kỳ ngầm
  }
}

// ============================================================================
// KHÔNG GIAN ②: BẢNG ỨNG DỤNG & HỒ SƠ BẢO MẬT NHỊ PHÂN OWASP MASTG
// ============================================================================
function selectTargetApp(targetVal, displayName) {
  if (!targetVal || !els.targetSelect) return;
  if (!Array.from(els.targetSelect.options).some((o) => o.value === targetVal)) {
    const opt = document.createElement("option");
    opt.value = targetVal;
    opt.textContent = `${displayName} (${targetVal})`;
    els.targetSelect.prepend(opt);
  }
  els.targetSelect.value = targetVal;
  state.preferredTarget = targetVal;
  scheduleSaveSettings({ selectedTarget: targetVal });
  renderAppMgrTable();
  if (state.paramFilterCurrentApp) renderSavedParamsUi();
}

function renderAppMgrTable() {
  if (!els.appMgrTableBody) return;
  const kw = (state.appMgrSearch || "").trim().toLowerCase();
  const curTarget = els.targetSelect?.value || "";

  let rows = [];
  if (state.appMgrFilter === "daemons" || state.apps.length === 0) {
    rows = state.processes.map((p) => ({
      name: p.name,
      identifier: "",
      pid: p.pid || 0,
      isFrontmost: false,
    }));
  } else if (state.appMgrFilter === "user") {
    rows = state.apps.filter((a) => a.isUserApp !== false);
  } else if (state.appMgrFilter === "running") {
    rows = state.apps.filter((a) => a.pid > 0);
  } else {
    rows = [...state.apps];
  }

  if (kw) {
    rows = rows.filter(
      (r) =>
        String(r.name || "").toLowerCase().includes(kw) ||
        String(r.identifier || "").toLowerCase().includes(kw) ||
        String(r.pid || "").includes(kw)
    );
  }

  els.appMgrTableBody.innerHTML = "";
  if (rows.length === 0) {
    els.appMgrTableBody.innerHTML = `<tr><td colspan="4" class="empty-cell">Không có ứng dụng hoặc tiến trình nào khớp bộ lọc hiện tại.</td></tr>`;
    return;
  }

  const frag = document.createDocumentFragment();
  const isLocalPc = isLocalPcDeviceSelected();

  for (const item of rows.slice(0, 220)) {
    const val = item.identifier || String(item.pid);
    const selected = curTarget === val;
    const tr = document.createElement("tr");
    if (selected) tr.className = "app-row-selected";

    const tdName = document.createElement("td");
    tdName.innerHTML = `<strong>${escapeHtml(item.name)}</strong>${
      selected ? `<span class="app-own-badge">Đang chọn</span>` : ""
    }`;

    const tdId = document.createElement("td");
    tdId.className = "mono-cell";
    tdId.textContent = item.identifier || `PID ${item.pid}`;

    const tdState = document.createElement("td");
    if (item.isFrontmost) {
      tdState.innerHTML = `<span class="badge-lv lv-send">🟢 TRÊN MÀN HÌNH (${item.pid})</span>`;
    } else if (item.pid > 0) {
      tdState.innerHTML = `<span class="badge-lv lv-warning">🟡 ĐANG CHẠY (${item.pid})</span>`;
    } else {
      tdState.innerHTML = `<span class="muted-note">⚪ Đang nghỉ (Tự bật khi chạy)</span>`;
    }

    const tdAct = document.createElement("td");
    const grp = document.createElement("div");
    grp.className = "mini-btn-row";

    const pickBtn = document.createElement("button");
    pickBtn.type = "button";
    pickBtn.className = "btn-mini";
    pickBtn.textContent = "🎯 Chọn mục tiêu";
    pickBtn.addEventListener("click", () => {
      selectTargetApp(val, item.name);
      showToast("ok", "🎯 Đã khóa mục tiêu", `${item.name} (${val})`);
    });

    const auditBtn = document.createElement("button");
    auditBtn.type = "button";
    auditBtn.className = "btn-mini btn-mini-info";
    auditBtn.textContent = "🛡️ Soi Hồ Sơ";
    auditBtn.addEventListener("click", () => {
      selectTargetApp(val, item.name);
      void handleInspectSecurityPosture();
    });

    grp.append(pickBtn, auditBtn);

    if (!isLocalPc) {
      const capBtn = document.createElement("button");
      capBtn.type = "button";
      capBtn.className = "btn-mini btn-mini-accent";
      capBtn.textContent = "📡 Bắt gói ngay";
      capBtn.addEventListener("click", () => {
        selectTargetApp(val, item.name);
        switchWorkspace("packets");
        void handleEnableHttpCapture();
      });
      grp.appendChild(capBtn);
    }

    tdAct.appendChild(grp);
    tr.append(tdName, tdId, tdState, tdAct);
    frag.appendChild(tr);
  }
  els.appMgrTableBody.appendChild(frag);
}

async function handleInspectSecurityPosture() {
  if (!els.inspectPostureBtn) return;
  els.inspectPostureBtn.disabled = true;
  const origTxt = els.inspectPostureBtn.textContent;
  els.inspectPostureBtn.textContent = "⏳ Đang quét hồ sơ & nhị phân...";
  updateActionBanner("info", "Đang kiểm toán chỉ đọc", "Đang đọc cấu trúc Mach-O 64-bit, Info.plist, ATS và môi trường StoreKit...");

  try {
    const qs = buildAutoAttachQuery();
    const { result } = await apiFetch(`/api/v1/sessions/inspections/security-posture?${qs}`);
    const sessData = await apiFetch("/api/v1/sessions/current").catch(() => null);
    if (sessData?.session) renderSessionCard(sessData.session);

    renderSecurityPostureResult(result);
    updateActionBanner(
      "ok",
      "Đã đọc xong Hồ sơ & Kiểm toán Bảo mật",
      `Ứng dụng: ${result?.manifest?.bundleId || result?.binaryHardening?.moduleName || "-"}`
    );
    showToast("ok", "🛡️ Đã quét Hồ sơ & Cờ bảo vệ nhị phân", result?.manifest?.bundleId || "Hoàn tất kiểm tra.");
  } catch (err) {
    reportUiError("Không thể quét Hồ sơ & Bảo mật ứng dụng", err);
  } finally {
    els.inspectPostureBtn.disabled = false;
    els.inspectPostureBtn.textContent = origTxt;
  }
}

function renderSecurityPostureResult(posture) {
  if (!posture) return;
  const bh = posture.binaryHardening || {};
  const mf = posture.manifest || {};
  const sk = posture.storeKitReceipt || {};
  const ats = posture.atsParsed || {};

  if (els.flagPieVal) {
    els.flagPieVal.textContent = !bh.isMachO64
      ? "Ngoài Mach-O 64"
      : bh.pieEnabled
      ? "✅ BẬT (An toàn)"
      : "⚠️ TẮT (Rủi ro)";
  }
  if (els.flagArcVal) {
    els.flagArcVal.textContent = !bh.isMachO64 ? "N/A" : bh.hasArc ? "✅ Có ARC" : "⚠️ Không thấy ARC";
  }
  if (els.flagCanaryVal) {
    els.flagCanaryVal.textContent = !bh.isMachO64
      ? "N/A"
      : bh.hasStackCanary
      ? "✅ Có Canary"
      : "ℹ️ Không gọi hàm có Canary";
  }
  if (els.flagCryptVal) {
    els.flagCryptVal.textContent = !bh.isMachO64
      ? "N/A"
      : bh.cryptId === 1
      ? "🔒 CryptID = 1 (FairPlay)"
      : bh.cryptId === 0
      ? "🔓 CryptID = 0 (Đã giải mã)"
      : "Hệ thống / Tự build";
  }

  // Hộp StoreKit
  if (els.postureStorekitBody) {
    if (!mf.objcAvailable) {
      els.postureStorekitBody.textContent = "Tiến trình hiện tại không dùng môi trường iOS Objective-C.";
    } else {
      const payText =
        sk.canMakePayments === true
          ? "✅ Cho phép mua hàng"
          : sk.canMakePayments === false
          ? "⛔ Đang khóa thanh toán"
          : "Chưa nạp khung StoreKit";
      const fileText = sk.receiptExists ? "Đã có tệp biên lai trên máy" : "Chưa sinh tệp biên lai cục bộ";
      els.postureStorekitBody.innerHTML = `
        <div><strong>${escapeHtml(sk.environment || "-")}</strong> • ${escapeHtml(payText)}</div>
        <div class="muted-note">${escapeHtml(fileText)}${sk.receiptPath ? ` (${escapeHtml(sk.receiptPath)})` : ""}</div>
      `;
    }
  }

  // Hộp Frameworks & Tweaks
  if (els.postureFrameworksBody) {
    els.postureFrameworksBody.innerHTML = "";
    const fws = posture.frameworksDetected || [];
    const tweaks = posture.injectedTweaks || [];
    if (fws.length === 0 && tweaks.length === 0) {
      els.postureFrameworksBody.textContent = "Tiến trình Native cơ bản.";
    } else {
      for (const fw of fws) {
        const s = document.createElement("span");
        s.className = "tag-chip";
        s.textContent = fw;
        els.postureFrameworksBody.appendChild(s);
      }
      for (const tw of tweaks) {
        const s = document.createElement("span");
        s.className = "tag-chip tag-chip-warn";
        s.textContent = `💉 Tweak: ${tw.name}`;
        s.title = tw.path;
        els.postureFrameworksBody.appendChild(s);
      }
    }
  }

  // Hộp URL Schemes sạch gọn (KHÔNG in chuỗi plist thô!)
  if (els.postureUrlSchemesBody) {
    els.postureUrlSchemesBody.innerHTML = "";
    const schemes = posture.urlSchemesList || [];
    if (schemes.length === 0) {
      els.postureUrlSchemesBody.textContent = "Ứng dụng không đăng ký URL Scheme mở nhanh nào.";
    } else {
      for (const sc of schemes) {
        const chip = document.createElement("span");
        chip.className = "tag-chip";
        chip.textContent = `${sc}://`;
        els.postureUrlSchemesBody.appendChild(chip);
      }
    }
  }

  // Hộp ATS
  if (els.postureAtsBody) {
    const doms = ats.exceptionDomains || [];
    els.postureAtsBody.innerHTML = `
      <div><strong>${ats.allowsArbitraryLoads ? "⚠️" : "✅"} ${escapeHtml(ats.summaryVi || "-")}</strong></div>
      ${
        doms.length > 0
          ? `<div class="muted-note">Miền ngoại lệ: ${escapeHtml(doms.join(", "))}</div>`
          : `<div class="muted-note">Không có tên miền ngoại lệ HTTP riêng.</div>`
      }
    `;
  }

  // Bảng chi tiết định danh
  if (els.manifestTableBody) {
    els.manifestTableBody.innerHTML = "";
    const entries = [
      ["Mã định danh gói (Bundle ID)", mf.bundleId || "-"],
      ["Phiên bản ứng dụng (Version / Build)", mf.shortVersion ? `${mf.shortVersion} (Build ${mf.buildVersion || "-"})` : "-"],
      ["Mã tiến trình & Kiến trúc CPU", `PID ${mf.pid} • ${mf.arch} • ${mf.platform} (${mf.threadsCount} luồng CPU)`],
      ["Tệp thực thi chính trong RAM", mf.executablePath || bh.moduleName || "-"],
      ["Đường dẫn gói .app (Bundle Path)", mf.bundlePath || "-"],
      ["Ngăn dữ liệu riêng (Sandbox Home)", mf.homeDirectory || "-"],
    ];

    for (const [label, val] of entries) {
      const tr = document.createElement("tr");
      const tdK = document.createElement("td");
      tdK.innerHTML = `<strong>${escapeHtml(label)}</strong>`;
      const tdV = document.createElement("td");
      tdV.className = "mono-cell";
      tdV.textContent = val;

      if (label.includes("Bundle ID") && mf.bundleId) {
        const saveBtn = document.createElement("button");
        saveBtn.type = "button";
        saveBtn.className = "id-chip-btn";
        saveBtn.style.marginLeft = "8px";
        saveBtn.textContent = "💾 Lưu maUngDung";
        saveBtn.addEventListener("click", () => {
          void quickSaveParam({ key: "maUngDung", value: mf.bundleId, note: "Lưu từ Hồ sơ Ứng dụng" }, saveBtn);
        });
        tdV.appendChild(saveBtn);
      }

      tr.append(tdK, tdV);
      els.manifestTableBody.appendChild(tr);
    }
  }
}

// ============================================================================
// KHÔNG GIAN ③: 6 CÔNG TẮC 1 CHẠM, KHO MẪU JS & TRÌNH SOẠN MÃ FRIDA 17
// ============================================================================
function syncEditorGutter() {
  if (!els.codeEditor || !els.lineGutter) return;
  const lineCount = Math.max(1, (els.codeEditor.value || "").split("\n").length);
  const nums = [];
  for (let i = 1; i <= lineCount; i++) nums.push(i);
  els.lineGutter.textContent = nums.join("\n");
}

function renderFeatureSwitchesUi(switches) {
  if (!switches) return;
  state.featureSwitches = { ...state.featureSwitches, ...switches };
  let activeCount = 0;

  for (const card of els.switchCards) {
    const key = card.dataset.switchKey;
    const isOn = Boolean(state.featureSwitches[key]);
    if (isOn) activeCount += 1;
    card.classList.toggle("sw-on", isOn);
    const pill = card.querySelector(".sw-pill");
    if (pill) pill.textContent = isOn ? "ĐANG BẬT" : "TẮT";
  }

  if (els.activeSwitchesCountPill) {
    els.activeSwitchesCountPill.className = activeCount > 0 ? "pill pill-ok" : "pill pill-neutral";
    els.activeSwitchesCountPill.textContent = `Đang bật: ${activeCount} / 6`;
  }
  updateStudioNavBadge();
}

function updateStudioNavBadge() {
  if (!els.navBadgeStudio) return;
  const activeSw = Object.values(state.featureSwitches).filter(Boolean).length;
  els.navBadgeStudio.textContent = activeSw > 0 ? `${activeSw} bật • ${state.snippets.length} mẫu` : `${state.snippets.length} mẫu`;
}

async function handleToggleFeatureSwitch(featureKey, btnEl) {
  if (!featureKey || isLocalPcDeviceSelected()) return;
  const nextEnabled = !state.featureSwitches[featureKey];
  const deviceId = els.deviceSelect?.value || "";
  const target = els.targetSelect?.value || els.targetFilter?.value?.trim() || "";

  if (btnEl) btnEl.disabled = true;
  updateActionBanner("info", "Đang cập nhật công tắc 1 chạm", `${nextEnabled ? "BẬT" : "TẮT"} '${featureKey}'...`);

  try {
    const out = await apiFetch("/api/v1/sessions/feature-switches", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        deviceId,
        target,
        mode: state.mode || "auto",
        featureKey,
        enabled: nextEnabled,
      }),
    });
    if (out.switches) renderFeatureSwitchesUi(out.switches);
    if (out.session) renderSessionCard(out.session);

    const msg = out.switchResult?.message || `Đã cập nhật công tắc ${featureKey}`;
    updateActionBanner(nextEnabled ? "ok" : "info", "Công tắc 1 chạm", msg);
    showToast(nextEnabled ? "ok" : "info", nextEnabled ? "✅ Đã BẬT công tắc" : "⏹️ Đã TẮT công tắc", msg);
  } catch (err) {
    reportUiError("Không thể bật/tắt công tắc 1 chạm", err);
  } finally {
    if (btnEl) btnEl.disabled = isLocalPcDeviceSelected();
  }
}

async function loadSnippets() {
  const data = await apiFetch("/api/v1/snippets");
  state.snippets = data.snippets || [];
  state.categories = data.categories || [];

  if (els.snippetTotalCount) els.snippetTotalCount.textContent = String(state.snippets.length);
  const customCount = state.snippets.filter((s) => !s.builtin).length;
  if (els.customSnippetsMeta) els.customSnippetsMeta.textContent = `${customCount} mẫu riêng của tôi`;
  updateStudioNavBadge();

  if (els.snippetCategorySelect) {
    const prev = state.snippetCategoryFilter || "ALL";
    els.snippetCategorySelect.innerHTML = `<option value="ALL">Tất cả chuyên đề (${state.snippets.length} mẫu)</option>`;
    for (const cat of state.categories) {
      const cnt = state.snippets.filter((s) => s.category === cat).length;
      const opt = document.createElement("option");
      opt.value = cat;
      opt.textContent = `${cat} (${cnt})`;
      els.snippetCategorySelect.appendChild(opt);
    }
    if (Array.from(els.snippetCategorySelect.options).some((o) => o.value === prev)) {
      els.snippetCategorySelect.value = prev;
    }
  }

  renderSnippetCards();
}

function renderSnippetCards() {
  if (!els.snippetCardsList) return;
  const kw = state.snippetSearchKeyword;
  const cat = state.snippetCategoryFilter;

  const filtered = state.snippets.filter((s) => {
    if (cat && cat !== "ALL" && s.category !== cat) return false;
    if (!kw) return true;
    return (
      (s.displayTitle || s.title || "").toLowerCase().includes(kw) ||
      (s.description || "").toLowerCase().includes(kw) ||
      (s.category || "").toLowerCase().includes(kw)
    );
  });

  els.snippetCardsList.innerHTML = "";
  if (filtered.length === 0) {
    els.snippetCardsList.innerHTML = `<div class="empty-cell">Không tìm thấy mẫu JS khớp từ khóa lọc.</div>`;
    return;
  }

  // Ưu tiên đẩy mẫu riêng của người dùng lên trên đầu khi xem Tất cả
  const sorted = [...filtered].sort((a, b) => Number(Boolean(a.builtin)) - Number(Boolean(b.builtin)));

  for (const item of sorted) {
    const card = document.createElement("article");
    card.className = `snippet-card${item.builtin ? "" : " snippet-custom"}`;

    const runBadge =
      item.runType === "listener"
        ? `<span class="badge-lv lv-warning">📡 Chờ thao tác máy</span>`
        : `<span class="badge-lv lv-send">⚡ Trả kết quả ngay</span>`;
    const customBadge = item.builtin ? "" : `<span class="badge-lv lv-info">★ Của tôi</span>`;

    card.innerHTML = `
      <div class="snippet-card-title">${escapeHtml(item.displayTitle || item.title)}</div>
      <div class="snippet-card-meta">
        ${customBadge}
        ${runBadge}
        <span class="muted-note">${escapeHtml(item.category)}</span>
      </div>
      <p class="snippet-card-desc">${escapeHtml(item.description || "")}</p>
    `;

    const actRow = document.createElement("div");
    actRow.className = "snippet-card-actions";

    const runNowBtn = document.createElement("button");
    runNowBtn.type = "button";
    runNowBtn.className = "btn-mini btn-mini-accent";
    runNowBtn.textContent = "▶ Chạy ngay";
    runNowBtn.addEventListener("click", () => {
      els.codeEditor.value = item.code;
      localStorage.setItem(DRAFT_STORAGE_KEY, item.code);
      syncEditorGutter();
      void handleRunJs();
    });

    const loadBtn = document.createElement("button");
    loadBtn.type = "button";
    loadBtn.className = "btn-mini";
    loadBtn.textContent = "Đưa vào khung";
    loadBtn.addEventListener("click", () => {
      els.codeEditor.value = item.code;
      localStorage.setItem(DRAFT_STORAGE_KEY, item.code);
      syncEditorGutter();
      showToast("info", "📝 Đã nạp mã vào khung soạn", item.displayTitle || item.title);
    });

    actRow.append(runNowBtn, loadBtn);

    if (!item.builtin) {
      const editBtn = document.createElement("button");
      editBtn.type = "button";
      editBtn.className = "btn-mini btn-mini-info";
      editBtn.textContent = "Sửa";
      editBtn.addEventListener("click", () => openSnippetForm(item, false));

      const delBtn = document.createElement("button");
      delBtn.type = "button";
      delBtn.className = "btn-mini btn-mini-danger";
      delBtn.textContent = "Xóa";
      delBtn.addEventListener("click", async () => {
        try {
          await apiFetch(`/api/v1/snippets/${encodeURIComponent(item.id)}`, { method: "DELETE" });
          await loadSnippets();
          showToast("info", "🗑️ Đã xóa mẫu riêng", item.displayTitle || item.title);
        } catch (err) {
          reportUiError("Không thể xóa mẫu JS", err);
        }
      });
      actRow.append(editBtn, delBtn);
    }

    card.appendChild(actRow);
    els.snippetCardsList.appendChild(card);
  }
}

function openSnippetForm(existingItem = null, pullFromEditor = true) {
  if (!els.snippetFormBox) return;
  els.snippetFormBox.hidden = false;
  if (existingItem) {
    els.snippetFormHeading.textContent = "✏️ Sửa Mẫu JS Của Tôi";
    els.snippetEditIdInput.value = existingItem.id;
    els.snippetTitleInput.value = existingItem.displayTitle || existingItem.title || "";
    els.snippetCategoryInput.value = existingItem.category || "8. Mẫu JS Của Tôi";
    els.snippetRunTypeInput.value = existingItem.runType || "instant";
    els.snippetDescInput.value = existingItem.description || "";
    els.snippetCodeInput.value = existingItem.code || "";
  } else {
    els.snippetFormHeading.textContent = "💾 Lưu Mẫu JS Mới Của Tôi";
    els.snippetEditIdInput.value = "";
    els.snippetTitleInput.value = "";
    els.snippetCategoryInput.value = "8. Mẫu JS Của Tôi";
    els.snippetRunTypeInput.value = "instant";
    els.snippetDescInput.value = "";
    els.snippetCodeInput.value = pullFromEditor ? els.codeEditor?.value || "" : "";
  }
  els.snippetTitleInput?.focus();
}

async function handleSaveCustomSnippet(runAfterSave = false) {
  const editId = els.snippetEditIdInput?.value?.trim() || "";
  const payload = {
    title: els.snippetTitleInput?.value?.trim() || "",
    category: els.snippetCategoryInput?.value || "8. Mẫu JS Của Tôi",
    runType: els.snippetRunTypeInput?.value || "instant",
    description: els.snippetDescInput?.value?.trim() || "",
    code: els.snippetCodeInput?.value || "",
  };

  try {
    const endpoint = editId ? `/api/v1/snippets/${encodeURIComponent(editId)}` : "/api/v1/snippets";
    const method = editId ? "PUT" : "POST";
    const { snippet } = await apiFetch(endpoint, {
      method,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (els.snippetFormBox) els.snippetFormBox.hidden = true;
    await loadSnippets();
    showToast("ok", "💾 Đã lưu mẫu JS của bạn", snippet.displayTitle || snippet.title);

    if (runAfterSave) {
      els.codeEditor.value = snippet.code;
      localStorage.setItem(DRAFT_STORAGE_KEY, snippet.code);
      syncEditorGutter();
      await handleRunJs();
    }
  } catch (err) {
    reportUiError("Không thể lưu mẫu JS riêng", err);
  }
}

function insertCodeIntoStudio(codeBlock, switchTab = true) {
  if (!els.codeEditor) return;
  if (switchTab) switchWorkspace("studio");
  els.codeEditor.value = codeBlock;
  localStorage.setItem(DRAFT_STORAGE_KEY, codeBlock);
  syncEditorGutter();
  els.codeEditor.focus();
}

// ============================================================================
// CHẠY / DỪNG PHIÊN FRIDA & BÁO CÁO SỰ THẬT 100% (executionTruth)
// ============================================================================
function renderSessionCard(session) {
  if (!session) return;
  state.session = { ...state.session, ...session };
  if (session.featureSwitches) {
    renderFeatureSwitchesUi(session.featureSwitches);
  }

  const isRunning = session.status === "running";
  const isBusy = session.status === "running" || session.status === "connecting";

  // Nút Dừng phiên CHỈ cho phép bấm khi thực sự đang có phiên hoạt động!
  if (els.stopSessionBtn) {
    els.stopSessionBtn.disabled = !isBusy;
  }

  if (els.teleSessionPidBadge) {
    els.teleSessionPidBadge.className = isRunning
      ? "pill pill-ok"
      : session.status === "error"
      ? "pill pill-err"
      : "pill pill-neutral";
    els.teleSessionPidBadge.textContent = isRunning ? `PID ${session.pid}` : session.status === "error" ? "Lỗi gắn" : "Chưa gắn";
  }

  if (els.teleSessionTarget) {
    els.teleSessionTarget.textContent = isRunning ? session.targetLabel || `PID ${session.pid}` : "Đang nghỉ";
  }

  const evCount = session.receivedDeviceEventsCount ?? session.executionTruth?.receivedDeviceEventsCount ?? 0;
  if (els.teleSessionUptime) {
    els.teleSessionUptime.textContent = isRunning
      ? `Chạy: ${formatDuration(session.startedAt)} • ${evCount} sự kiện thật`
      : "Thời gian chạy: 00:00:00 • 0 sự kiện thật";
  }

  syncRpcInvokeButtonState();
}

async function handleRunJs() {
  const deviceId = els.deviceSelect?.value || "";
  const target = els.targetSelect?.value || els.targetFilter?.value?.trim() || "";
  const code = els.codeEditor?.value || "";
  const enableObjCBridge = !isLocalPcDeviceSelected();

  if (!target) {
    showToast("warn", "Chưa chọn ứng dụng mục tiêu", "Hãy chọn một ứng dụng ở ô số 2 trên thanh đỉnh trước khi bấm Chạy!");
    els.targetSelect?.focus();
    return;
  }

  els.runJsBtn.disabled = true;
  if (els.studioAnswerBadge) {
    els.studioAnswerBadge.className = "badge-lv lv-warning";
    els.studioAnswerBadge.textContent = "ĐANG NẠP MÃ...";
  }
  updateActionBanner("info", "Đang biên dịch & nạp mã Frida 17", `Đang gắn vào '${target}'...`);

  try {
    const { session } = await apiFetch("/api/v1/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        deviceId,
        mode: state.mode,
        target,
        code,
        enableObjCBridge,
      }),
    });

    renderSessionCard(session);
    const truth = session?.executionTruth;
    if (truth?.awaitingDeviceInteraction && (session?.receivedDeviceEventsCount || 0) === 0) {
      if (els.studioAnswerBadge) {
        els.studioAnswerBadge.className = "badge-lv lv-warning";
        els.studioAnswerBadge.textContent = "ĐÃ GẮN • CHỜ THAO TÁC TRÊN MÁY (0 KẾT QUẢ)";
      }
      if (els.studioQuickAnswerPre) {
        els.studioQuickAnswerPre.textContent =
          `// 🟡 Đã gắn thành công vào '${target}' (PID ${session.pid}), nhưng mã JS hiện tại là dạng lắng nghe nên CHƯA phát dữ liệu ngay.\n` +
          `// 👉 Hãy cầm điện thoại chạm thao tác vào màn hình liên quan để thu kết quả thật!`;
      }
      updateActionBanner("warn", "Đã gắn đầu dò thành công (0 sự kiện)", truth.truthSummaryVi);
    } else {
      updateActionBanner("ok", "Đã thực thi mã JS trên thiết bị", truth?.truthSummaryVi || `PID ${session.pid}`);
    }

    void refreshDiscoveredRpcExports(false);
    void refreshTelemetry();
  } catch (err) {
    if (els.studioAnswerBadge) {
      els.studioAnswerBadge.className = "badge-lv lv-error";
      els.studioAnswerBadge.textContent = "LỖI THỰC THI";
    }
    if (els.studioQuickAnswerPre) {
      els.studioQuickAnswerPre.textContent = `// ❌ Không thể chạy mã JS:\n${err.message}`;
    }
    reportUiError("Lỗi khi chạy mã Frida JS", err);
  } finally {
    els.runJsBtn.disabled = false;
  }
}

async function handleStopSession() {
  if (els.stopSessionBtn) els.stopSessionBtn.disabled = true;
  try {
    const { session } = await apiFetch("/api/v1/sessions/current", { method: "DELETE" });
    renderSessionCard(session);
    state.discoveredRpcExports = [];
    renderDiscoveredRpcBar();
    updateActionBanner("info", "Đã dừng phiên Frida", "Đã gỡ kịch bản khỏi ứng dụng an toàn.");
    showToast("info", "⏹️ Đã dừng phiên Frida", "Ứng dụng trên máy tiếp tục hoạt động bình thường.");
  } catch (err) {
    reportUiError("Không thể dừng phiên Frida", err);
  }
}

// ============================================================================
// KHÔNG GIAN ④: BẮT GÓI, SỬA GỬI LẠI, GIẢI MÃ JWS & SỔ LƯU ID THEO APP
// ============================================================================
function extractInterestingParams(sourceData, rawUrl = "") {
  const foundMap = new Map();
  const addCandidate = (rawKey, rawVal) => {
    if (foundMap.size >= 12) return;
    const cleanKey = String(rawKey || "")
      .trim()
      .replace(/[^A-Za-z0-9_.-]+/g, "_");
    if (!cleanKey || cleanKey.startsWith("__studio")) return;
    if (rawVal === null || rawVal === undefined || typeof rawVal === "boolean" || typeof rawVal === "object") return;
    const strVal = String(rawVal).trim();
    if (!strVal || strVal.length > 180 || strVal === "N/A" || strVal.startsWith("(Chưa")) return;
    if (!foundMap.has(cleanKey)) {
      foundMap.set(cleanKey, { key: cleanKey, value: strVal });
    }
  };

  if (rawUrl) {
    try {
      const u = new URL(rawUrl);
      for (const [k, v] of u.searchParams.entries()) addCandidate(k, v);
    } catch {
      // Bỏ qua nếu URL đang chứa biến {{khóa}}
    }
  }

  let parsed = sourceData;
  if (typeof sourceData === "string") {
    const t = sourceData.trim();
    if (t.startsWith("{") || t.startsWith("[")) {
      try {
        parsed = JSON.parse(t);
      } catch {
        parsed = null;
      }
    } else {
      parsed = null;
    }
  }

  const walk = (node, depth) => {
    if (!node || typeof node !== "object" || depth > 3 || foundMap.size >= 12) return;
    if (Array.isArray(node)) {
      for (const it of node.slice(0, 6)) walk(it, depth + 1);
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (v && typeof v === "object") walk(v, depth + 1);
      else if (INTERESTING_PARAM_REGEX.test(k)) addCandidate(k, v);
    }
  };
  walk(parsed, 0);
  return Array.from(foundMap.values());
}

function populateDetectedParamChips(candidates, sourceNote) {
  if (!els.detectedParamsBar) return;
  if (!candidates || candidates.length === 0) {
    els.detectedParamsBar.hidden = true;
    els.detectedParamsBar.innerHTML = "";
    return;
  }
  els.detectedParamsBar.hidden = false;
  els.detectedParamsBar.innerHTML = `<strong>💡 Phát hiện mã ID trong phản hồi (Bấm 1 chạm để lưu):</strong>`;

  for (const cand of candidates) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "id-chip-btn";
    const shortVal = cand.value.length > 24 ? `${cand.value.slice(0, 24)}…` : cand.value;
    btn.textContent = `💾 Lưu ${cand.key} = ${shortVal}`;
    btn.addEventListener("click", () => {
      void quickSaveParam({ key: cand.key, value: cand.value, note: sourceNote }, btn);
    });
    els.detectedParamsBar.appendChild(btn);
  }
}

async function quickSaveParam({ key, value, note = "" }, btnEl = null) {
  try {
    const appId = state.session.targetLabel || els.targetSelect?.value || "";
    await apiFetch("/api/v1/saved-params", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, label: key, value, appId, note }),
    });
    if (btnEl) btnEl.textContent = `✅ Đã lưu {{${key}}}`;
    await loadSavedParams();
    updateResolvedUrlPreview();
    showToast("ok", `💾 Đã lưu {{${key}}}`, `Giá trị: ${value}`);
  } catch (err) {
    reportUiError(`Không thể lưu tham số '${key}'`, err);
  }
}

function substituteSavedParams(rawString) {
  const text = String(rawString ?? "");
  if (!text.includes("{{")) return text;

  const currentApp = String(state.session.targetLabel || els.targetSelect?.value || "")
    .trim()
    .toLowerCase();
  const mapByKey = new Map();

  if (currentApp) {
    for (const p of state.savedParams) {
      if (String(p.appId || "").trim().toLowerCase() === currentApp && !mapByKey.has(p.key)) {
        mapByKey.set(p.key, p.value);
      }
    }
  }
  for (const p of state.savedParams) {
    if (!mapByKey.has(p.key)) mapByKey.set(p.key, p.value);
  }

  return text.replace(/\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}/g, (_full, varName) => {
    if (!mapByKey.has(varName)) {
      throw new Error(`Biến {{${varName}}} chưa có trong Sổ lưu Tham số & ID. Hãy lưu khóa '${varName}' trước khi gửi!`);
    }
    return mapByKey.get(varName);
  });
}

function updateResolvedUrlPreview() {
  if (!els.repResolvedUrlHint || !els.repUrlInput) return;
  const rawUrl = els.repUrlInput.value || "";
  if (!rawUrl.includes("{{")) {
    els.repResolvedUrlHint.hidden = true;
    return;
  }
  try {
    const resolved = substituteSavedParams(rawUrl.trim());
    els.repResolvedUrlHint.hidden = false;
    els.repResolvedUrlHint.className = "resolved-url-hint";
    els.repResolvedUrlHint.textContent = `🔗 URL thực tế sẽ gửi: ${resolved}`;
  } catch (err) {
    els.repResolvedUrlHint.hidden = false;
    els.repResolvedUrlHint.className = "resolved-url-hint hint-warn";
    els.repResolvedUrlHint.textContent = `⚠️ ${err.message}`;
  }
}

function insertVariableToRepeater(key) {
  const token = `{{${key}}}`;
  switchWorkspace("packets");
  const isBody = state.lastFocusedRepField === "body";
  const targetInput = isBody ? els.repBodyInput : els.repUrlInput;
  if (!targetInput) return;

  const curVal = targetInput.value || "";
  const s = targetInput.selectionStart ?? curVal.length;
  const e = targetInput.selectionEnd ?? curVal.length;

  if (!isBody && s === e && s === curVal.length && /[?&][^=&#]+=[^&#]*$/.test(curVal)) {
    targetInput.value = curVal.replace(/(=)[^&#]*$/, `$1${token}`);
  } else {
    targetInput.setRangeText(token, s, e, "end");
  }
  targetInput.focus();
  updateResolvedUrlPreview();
  showToast("info", `➕ Đã chèn {{${key}}}`, isBody ? "Đã chèn vào ô Nội dung gửi đi." : targetInput.value);
}

function insertSavedParamIntoJsEditor(key, value) {
  const safeVar = String(key || "maId")
    .replace(/[^A-Za-z0-9_]/g, "_")
    .replace(/^[0-9]/, "_$&");
  const line = `const ${safeVar} = ${JSON.stringify(String(value ?? ""))}; // Sổ ID ({{${key}}})`;
  switchWorkspace("studio");
  const cur = els.codeEditor?.value || "";
  els.codeEditor.value = `${line}\n${cur}`;
  localStorage.setItem(DRAFT_STORAGE_KEY, els.codeEditor.value);
  syncEditorGutter();
  els.codeEditor.focus();
  showToast("ok", `💉 Đã chèn hằng số ${safeVar} vào Mã JS`, line);
}

async function loadSavedParams() {
  const data = await apiFetch("/api/v1/saved-params");
  state.savedParams = data.items || [];
  renderSavedParamsUi();
  updatePacketsNavBadge();
}

function updatePacketsNavBadge() {
  if (!els.navBadgePackets) return;
  const pCount = state.httpExchanges.length;
  const idCount = state.savedParams.length;
  els.navBadgePackets.textContent = idCount > 0 ? `${pCount} gói • ${idCount} ID` : `${pCount} gói`;
}

function renderSavedParamsUi() {
  if (els.paramTotalCount) els.paramTotalCount.textContent = String(state.savedParams.length);

  // Thanh chèn nhanh trên Repeater
  if (els.repeaterSavedVarsBar) {
    els.repeaterSavedVarsBar.innerHTML = `<span class="vars-hint">Chèn nhanh {{biến}} đã lưu:</span>`;
    if (state.savedParams.length === 0) {
      els.repeaterSavedVarsBar.innerHTML += `<span class="muted-note">Chưa có ID nào — bấm 💾 Lưu ID từ Hộp trả lời / Giải mã!</span>`;
    } else {
      for (const item of state.savedParams.slice(0, 12)) {
        const pill = document.createElement("button");
        pill.type = "button";
        pill.className = "var-insert-pill";
        pill.textContent = `+ {{${item.key}}}`;
        pill.title = `Giá trị: ${item.value}`;
        pill.addEventListener("click", () => insertVariableToRepeater(item.key));
        els.repeaterSavedVarsBar.appendChild(pill);
      }
    }
  }

  // Thanh chèn nhanh trên Trình soạn JS
  if (els.editorSavedVarsBar) {
    els.editorSavedVarsBar.innerHTML = `<span class="vars-hint">💉 Chèn nhanh ID đã lưu vào code JS:</span>`;
    if (state.savedParams.length === 0) {
      els.editorSavedVarsBar.innerHTML += `<span class="muted-note">Chưa lưu ID nào trong Sổ ID.</span>`;
    } else {
      for (const item of state.savedParams.slice(0, 12)) {
        const pill = document.createElement("button");
        pill.type = "button";
        pill.className = "var-insert-pill";
        pill.textContent = `+ const ${item.key}`;
        pill.title = `${item.key} = ${JSON.stringify(item.value)}`;
        pill.addEventListener("click", () => insertSavedParamIntoJsEditor(item.key, item.value));
        els.editorSavedVarsBar.appendChild(pill);
      }
    }
  }

  if (!els.savedParamsTableBody) return;
  const kw = state.paramSearchKeyword;
  const curApp = (state.session.targetLabel || els.targetSelect?.value || "").trim().toLowerCase();

  const filtered = state.savedParams.filter((p) => {
    if (state.paramFilterCurrentApp && curApp && String(p.appId || "").toLowerCase() !== curApp) {
      return false;
    }
    if (!kw) return true;
    return (
      p.key.toLowerCase().includes(kw) ||
      p.value.toLowerCase().includes(kw) ||
      (p.note || "").toLowerCase().includes(kw) ||
      (p.appId || "").toLowerCase().includes(kw)
    );
  });

  els.savedParamsTableBody.innerHTML = "";
  if (filtered.length === 0) {
    els.savedParamsTableBody.innerHTML = `<tr><td colspan="4" class="empty-cell">Chưa có tham số / mã ID nào khớp điều kiện lọc hiện tại.</td></tr>`;
    return;
  }

  for (const item of filtered) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono-cell"><strong>${escapeHtml(item.key)}</strong><div class="muted-note">{{${escapeHtml(item.key)}}}</div></td>
      <td class="mono-cell">${escapeHtml(item.value)}</td>
      <td>
        ${item.appId ? `<div class="mono-meta">${escapeHtml(item.appId)}</div>` : ""}
        <div class="muted-note">${escapeHtml(item.note || "-")}</div>
      </td>
    `;

    const tdAct = document.createElement("td");
    const grp = document.createElement("div");
    grp.className = "mini-btn-row";

    const toRep = document.createElement("button");
    toRep.type = "button";
    toRep.className = "btn-mini btn-mini-accent";
    toRep.textContent = "↪ Gói tin";
    toRep.addEventListener("click", () => insertVariableToRepeater(item.key));

    const toJs = document.createElement("button");
    toJs.type = "button";
    toJs.className = "btn-mini btn-mini-info";
    toJs.textContent = "💉 Mã JS";
    toJs.addEventListener("click", () => insertSavedParamIntoJsEditor(item.key, item.value));

    const toDec = document.createElement("button");
    toDec.type = "button";
    toDec.className = "btn-mini";
    toDec.textContent = "🔓 Giải mã";
    toDec.addEventListener("click", () => void sendToDecoder(item.value, `Sổ ID (${item.key})`));

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "btn-mini";
    editBtn.textContent = "Sửa";
    editBtn.addEventListener("click", () => {
      els.paramKeyInput.value = item.key;
      els.paramValueInput.value = item.value;
      els.paramNoteInput.value = item.note || "";
      els.paramValueInput.focus();
    });

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "btn-mini btn-mini-danger";
    delBtn.textContent = "Xóa";
    delBtn.addEventListener("click", async () => {
      await apiFetch(`/api/v1/saved-params/${encodeURIComponent(item.id)}`, { method: "DELETE" });
      await loadSavedParams();
      updateResolvedUrlPreview();
    });

    grp.append(toRep, toJs, toDec, editBtn, delBtn);
    tdAct.appendChild(grp);
    tr.appendChild(tdAct);
    els.savedParamsTableBody.appendChild(tr);
  }
}

async function handleSaveParamFromForm() {
  const key = els.paramKeyInput?.value?.trim() || "";
  const value = els.paramValueInput?.value?.trim() || "";
  const note = els.paramNoteInput?.value?.trim() || "";
  const appId = state.session.targetLabel || els.targetSelect?.value || "";
  if (!key || !value) {
    showToast("warn", "Thiếu tên khóa hoặc giá trị", "Hãy điền cả Tên khóa biến và Giá trị thực tế!");
    return;
  }
  try {
    await apiFetch("/api/v1/saved-params", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key, label: key, value, appId, note }),
    });
    els.paramKeyInput.value = "";
    els.paramValueInput.value = "";
    els.paramNoteInput.value = "";
    await loadSavedParams();
    updateResolvedUrlPreview();
    showToast("ok", `💾 Đã lưu {{${key}}}`, value);
  } catch (err) {
    reportUiError("Không thể lưu vào Sổ ID", err);
  }
}

async function loadHttpExchanges() {
  const data = await apiFetch("/api/v1/http-exchanges?limit=200");
  state.httpExchanges = data.items || [];
  renderPacketList();
  updatePacketsNavBadge();
  if (state.httpExchanges.length > 0 && !state.selectedPacketId) {
    selectPacketForRepeater(state.httpExchanges[state.httpExchanges.length - 1]);
  }
}

function renderPacketList() {
  updatePacketsNavBadge();
  if (!els.packetListBody) return;
  const kw = state.packetSearchKeyword;
  const rows = state.httpExchanges.filter((p) => {
    if (!kw) return true;
    return (
      String(p.url || "").toLowerCase().includes(kw) ||
      String(p.method || "").toLowerCase().includes(kw) ||
      String(p.statusCode || "").includes(kw) ||
      String(p.responseBody || "").toLowerCase().includes(kw)
    );
  });

  els.packetListBody.innerHTML = "";
  if (rows.length === 0) {
    els.packetListBody.innerHTML = `<tr><td colspan="6" class="empty-cell">Chưa có gói tin nào khớp bộ lọc. Bấm <strong>📡 Bật Bắt Gói Tin Trên iPhone</strong> hoặc gửi thử gói ở khung bên dưới!</td></tr>`;
    return;
  }

  for (const pkt of [...rows].reverse()) {
    const tr = document.createElement("tr");
    if (pkt.id === state.selectedPacketId) tr.className = "active-packet-row";

    const code = Number(pkt.statusCode) || 0;
    const lvCls =
      code >= 200 && code < 300 ? "lv-send" : code >= 300 && code < 500 ? "lv-warning" : code >= 500 || pkt.errorText ? "lv-error" : "lv-info";
    const srcTxt = pkt.replayedFromDevice
      ? "🔁 Gửi lại từ trong App iPhone"
      : pkt.replayedFromPc
      ? "🔁 Gửi trực tiếp từ PC"
      : `📱 Bắt trực tiếp từ ${pkt.target || "App"}`;

    tr.innerHTML = `
      <td class="mono-cell">#${pkt.id}</td>
      <td class="mono-cell"><strong>${escapeHtml(pkt.method)}</strong></td>
      <td><span class="badge-lv ${lvCls}">${code > 0 ? code : pkt.errorText ? "LỖI" : "OK"}</span></td>
      <td class="mono-cell">
        <div>${escapeHtml(pkt.url)}</div>
        <div class="muted-note">${escapeHtml(srcTxt)} • ${formatClockMs(pkt.ts)}</div>
      </td>
      <td class="mono-cell">${pkt.elapsedMs ?? 0} ms</td>
    `;

    const tdAct = document.createElement("td");
    const grp = document.createElement("div");
    grp.className = "mini-btn-row";

    const editBtn = document.createElement("button");
    editBtn.type = "button";
    editBtn.className = "btn-mini btn-mini-accent";
    editBtn.textContent = "Sửa & Gửi";
    editBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      selectPacketForRepeater(pkt);
    });

    const decBtn = document.createElement("button");
    decBtn.type = "button";
    decBtn.className = "btn-mini btn-mini-info";
    decBtn.textContent = "🔓 Giải mã";
    decBtn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      selectPacketForRepeater(pkt);
      void sendToDecoder(pkt.responseBody || pkt.requestBody || pkt.url, `Gói #${pkt.id}`);
    });

    grp.append(editBtn, decBtn);
    tdAct.appendChild(grp);
    tr.appendChild(tdAct);
    tr.addEventListener("click", () => selectPacketForRepeater(pkt));
    els.packetListBody.appendChild(tr);
  }
}

function selectPacketForRepeater(pkt) {
  if (!pkt) return;
  state.selectedPacketId = pkt.id;
  if (els.repSelectedBadge) els.repSelectedBadge.textContent = `Gói #${pkt.id}`;
  if (els.repMethodSelect) els.repMethodSelect.value = String(pkt.method || "GET").toUpperCase();
  if (els.repUrlInput) els.repUrlInput.value = pkt.url || "";
  if (els.repHeadersInput) els.repHeadersInput.value = JSON.stringify(pkt.requestHeaders || {}, null, 2);
  if (els.repBodyInput) els.repBodyInput.value = pkt.requestBody || "";
  updateResolvedUrlPreview();
  renderHttpResponseBox(pkt);
  renderPacketList();
}

function renderHttpResponseBox(pkt) {
  if (!pkt) return;
  const code = Number(pkt.statusCode) || 0;
  if (els.repStatusBadge) {
    els.repStatusBadge.className = `badge-lv ${
      code >= 200 && code < 300 ? "lv-send" : code >= 300 && code < 500 ? "lv-warning" : "lv-error"
    }`;
    els.repStatusBadge.textContent = code > 0 ? `HTTP ${code}` : pkt.errorText ? "LỖI KẾT NỐI" : "ĐÃ NHẬN";
  }
  if (els.repLatencyBadge) els.repLatencyBadge.textContent = `${pkt.elapsedMs ?? 0} ms`;
  if (els.repResponseHeadersPre) els.repResponseHeadersPre.textContent = JSON.stringify(pkt.responseHeaders || {}, null, 2);
  if (els.repResponseBodyPre) {
    els.repResponseBodyPre.textContent =
      pkt.errorText && !pkt.responseBody
        ? `// Không nhận được phản hồi:\n${pkt.errorText}`
        : prettyFormatBody(pkt.responseBody) || "// (Nội dung trả về rỗng — xem mã HTTP và Headers bên dưới)";
  }
  const cands = extractInterestingParams(pkt.responseBody, pkt.url);
  populateDetectedParamChips(cands, `Trích từ gói #${pkt.id}`);
}

async function handleEnableHttpCapture() {
  if (isLocalPcDeviceSelected()) return;
  els.enableHttpCaptureBtn.disabled = true;
  updateActionBanner("info", "Đang bật bắt gói tin 3 lớp", "Đang gắn trình quan sát NSURLSession vào ứng dụng trên iPhone...");
  try {
    const out = await apiFetch("/api/v1/http-capture/enable", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        deviceId: els.deviceSelect?.value || "",
        target: els.targetSelect?.value || els.targetFilter?.value?.trim() || "",
        mode: state.mode,
      }),
    });
    if (out.session) renderSessionCard(out.session);
    const msg = out.capture?.message || "Đã bật bắt gói tin & Hộp trả lời!";
    updateActionBanner("ok", "Đang bắt sóng trực tiếp", `${msg} — Hãy mở các mục trên iPhone!`);
    showToast("ok", "📡 Đã bật Bắt Gói Tin 3 Lớp", msg);
  } catch (err) {
    reportUiError("Không thể bật bắt gói tin", err);
  } finally {
    els.enableHttpCaptureBtn.disabled = isLocalPcDeviceSelected();
  }
}

async function handleSendRepeater() {
  els.sendRepeaterBtn.disabled = true;
  updateActionBanner("info", "Đang gửi gói tin HTTP", "Đang chờ máy chủ trả về Hộp trả lời...");
  try {
    const method = els.repMethodSelect.value;
    const finalUrl = substituteSavedParams(els.repUrlInput.value.trim());
    const rawHeaders = substituteSavedParams(els.repHeadersInput.value.trim() || "{}");
    let headers = {};
    try {
      headers = JSON.parse(rawHeaders);
    } catch {
      throw new Error('Ô Tiêu đề (Headers) chưa đúng chuẩn JSON (ví dụ: {"Accept": "application/json"}).');
    }
    const body = substituteSavedParams(els.repBodyInput.value);
    const sendFrom = els.repSendFromSelect.value;

    const { exchange } = await apiFetch("/api/v1/http-repeater/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method, url: finalUrl, headers, body, sendFrom }),
    });

    if (exchange) {
      if (!state.httpExchanges.some((p) => p.id === exchange.id)) {
        state.httpExchanges.push(exchange);
      }
      selectPacketForRepeater(exchange);
      updateActionBanner(
        exchange.statusCode >= 200 && exchange.statusCode < 400 ? "ok" : "warn",
        `Đã nhận Hộp trả lời Gói #${exchange.id}`,
        `HTTP ${exchange.statusCode || 0} (${exchange.elapsedMs ?? 0} ms)`
      );
      showToast("ok", `📬 Gói #${exchange.id}: HTTP ${exchange.statusCode || 0}`, `${exchange.elapsedMs ?? 0} ms`);
    }
  } catch (err) {
    reportUiError("Không thể gửi lại gói tin", err);
  } finally {
    els.sendRepeaterBtn.disabled = false;
  }
}

async function sendToDecoder(rawText, sourceLabel = "") {
  const txt = String(rawText ?? "").trim();
  switchWorkspace("packets");
  els.unifiedDecoderSection?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  if (!txt || txt.startsWith("// ")) {
    els.decoderInputTextarea?.focus();
    showToast("warn", "Chưa có chuỗi dữ liệu để giải mã", "Hãy dán chuỗi JWS, Base64, URL hoặc chạy kịch bản trước!");
    return;
  }
  if (els.decoderInputTextarea) els.decoderInputTextarea.value = txt;
  await handleRunDecoder(sourceLabel);
}

async function handleRunDecoder(sourceLabel = "") {
  const input = els.decoderInputTextarea?.value?.trim() || "";
  const mode = els.decoderModeSelect?.value || "auto";
  if (!input) {
    els.decoderInputTextarea?.focus();
    showToast("warn", "Ô giải mã đang trống", "Hãy dán chuỗi JWS StoreKit 2, JWT, Base64, Hex, URL hoặc WireGuard!");
    return;
  }

  els.runDecoderBtn.disabled = true;
  try {
    const { decoded } = await apiFetch("/api/v1/decoder/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input, mode }),
    });

    const cv = decoded.cryptoVerification;
    if (els.decoderFormatBadge) {
      const cls = cv?.signatureVerified === true ? "lv-send" : cv?.signatureVerified === false ? "lv-error" : "lv-info";
      els.decoderFormatBadge.className = `badge-lv ${cls}`;
      els.decoderFormatBadge.textContent = String(decoded.detectedFormat || "AUTO").toUpperCase();
    }
    if (els.decoderCryptoBanner) {
      els.decoderCryptoBanner.textContent = cv?.verificationSummary || decoded.formatLabelVi || "Đã giải mã thành công";
    }
    if (els.decoderOutputPre) {
      els.decoderOutputPre.textContent = decoded.decodedText || "";
    }

    if (els.decoderExtractedIdsBar) {
      const list = decoded.extractedParams || [];
      els.decoderExtractedIdsBar.hidden = list.length === 0;
      els.decoderExtractedIdsBar.innerHTML = list.length > 0 ? `<strong>🔑 Trích xuất ${list.length} mã ID:</strong>` : "";
      for (const cand of list) {
        const saveBtn = document.createElement("button");
        saveBtn.type = "button";
        saveBtn.className = "id-chip-btn";
        const shortV = cand.value.length > 22 ? `${cand.value.slice(0, 22)}…` : cand.value;
        saveBtn.textContent = `💾 Lưu ${cand.key}=${shortV}`;
        saveBtn.addEventListener("click", () => {
          void quickSaveParam({ key: cand.key, value: cand.value, note: sourceLabel || decoded.detectedFormat }, saveBtn);
        });

        const jsBtn = document.createElement("button");
        jsBtn.type = "button";
        jsBtn.className = "var-insert-pill";
        jsBtn.textContent = "💉 JS";
        jsBtn.addEventListener("click", () => insertSavedParamIntoJsEditor(cand.key, cand.value));

        els.decoderExtractedIdsBar.append(saveBtn, jsBtn);
      }
    }

    updateActionBanner("ok", "Đã giải mã & kiểm định thực tế", decoded.formatLabelVi);
  } catch (err) {
    reportUiError("Lỗi giải mã dữ liệu", err);
  } finally {
    els.runDecoderBtn.disabled = false;
  }
}

// ============================================================================
// KHÔNG GIAN ⑤: TRÌNH SINH MÃ HOOK CHUẨN FRIDA 17, NATIVE, OBJC/RAM & DYNAMIC RPC
// ============================================================================
function buildSafeFrida17ObjcHook(className, selector) {
  const argCount = Math.max(0, (selector.match(/:/g) || []).length);
  return `// ============================================================================
// [CHUẨN FRIDA 17 SPECIALIST] Quan sát chỉ đọc an toàn hàm iOS: ${className} ${selector}
// Tự động bọc try/catch chống văng App, kiểm tra !arg.isNull() & đẩy JSON về Hộp trả lời!
// ============================================================================
if (typeof ObjC === "undefined" || !ObjC.available) {
  console.error("[-] Tiến trình hiện tại không có môi trường iOS Objective-C.");
} else {
  const _cls = ObjC.classes[${JSON.stringify(className)}];
  const _method = _cls ? _cls[${JSON.stringify(selector)}] : null;
  if (!_method) {
    console.warn("[-] Không tìm thấy phương thức:", ${JSON.stringify(`${className} ${selector}`)});
  } else {
    const docThamSoAnToan = (conTro) => {
      try {
        if (!conTro || ptr(conTro).isNull()) return null;
        const obj = new ObjC.Object(ptr(conTro));
        return obj.toString().slice(0, 220);
      } catch {
        return ptr(conTro).toString();
      }
    };

    Interceptor.attach(_method.implementation, {
      onEnter(args) {
        try {
          const thamSoDauVao = [];
          for (let i = 0; i < Math.min(${argCount}, 4); i++) {
            thamSoDauVao.push(docThamSoAnToan(args[2 + i]));
          }
          this._duLieuGoi = {
            suKien: "goi_ham_objc",
            lop: ${JSON.stringify(className)},
            tenHam: ${JSON.stringify(selector)},
            thamSo: thamSoDauVao
          };
        } catch (e) {}
      },
      onLeave(retval) {
        try {
          const ketQuaTraVe = docThamSoAnToan(retval);
          send({
            ...(this._duLieuGoi || { lop: ${JSON.stringify(className)}, tenHam: ${JSON.stringify(selector)} }),
            giaTriTraVe: ketQuaTraVe
          });
        } catch (e) {}
      }
    });
    console.log("[+] Đang theo dõi an toàn chuẩn Frida 17:", ${JSON.stringify(`${className} ${selector}`)});
  }
}`;
}

function buildSafeFrida17NativeHook(moduleName, exportName) {
  return `// ============================================================================
// [CHUẨN FRIDA 17 SPECIALIST] Quan sát chỉ đọc hàm Native: ${moduleName}!${exportName}
// Hỗ trợ tìm trực tiếp & tự động chờ dlopen nếu thư viện nạp trễ!
// ============================================================================
(function theoDoiHamNativeAnToan() {
  const TEN_THU_VIEN = ${JSON.stringify(moduleName)};
  const TEN_HAM = ${JSON.stringify(exportName)};
  let daGan = false;

  function thuGanNgay() {
    if (daGan) return true;
    const mod = Process.findModuleByName(TEN_THU_VIEN);
    if (!mod) return false;
    const diaChi = mod.findExportByName(TEN_HAM);
    if (!diaChi || diaChi.isNull()) return false;
    daGan = true;

    Interceptor.attach(diaChi, {
      onEnter(args) {
        this._arg0 = args[0] ? args[0].toString() : "0x0";
      },
      onLeave(retval) {
        send({
          suKien: "goi_ham_native",
          thuVien: TEN_THU_VIEN,
          tenHam: TEN_HAM,
          thamSo0: this._arg0,
          giaTriTraVe: retval ? retval.toString() : "0x0"
        });
      }
    });
    console.log("[+] Đã gắn theo dõi Frida 17 vào:", TEN_THU_VIEN + "!" + TEN_HAM, "@", diaChi);
    return true;
  }

  if (!thuGanNgay()) {
    const dlopenPtr = Module.findGlobalExportByName("dlopen");
    if (dlopenPtr) {
      Interceptor.attach(dlopenPtr, {
        onEnter(args) {
          this._path = args[0] && !args[0].isNull() ? args[0].readUtf8String() : "";
        },
        onLeave() {
          if (this._path && this._path.includes(TEN_THU_VIEN)) thuGanNgay();
        }
      });
      console.log("[*] Đang chờ thư viện", TEN_THU_VIEN, "được nạp (dlopen)...");
    }
  }
})();`;
}

async function handleSmartFindFunctions() {
  if (!els.magSearchFuncBtn) return;
  els.magSearchFuncBtn.disabled = true;
  const kw = els.magFuncKeywordInput?.value?.trim() || "";
  const preset = kw ? "" : state.magPreset || "purchase";
  els.magFuncTableBody.innerHTML = `<tr><td colspan="2" class="empty-cell">⏳ Đang quét các lớp và hàm xử lý trong ứng dụng...</td></tr>`;

  try {
    const qs = `preset=${encodeURIComponent(preset)}&filter=${encodeURIComponent(kw)}&limit=100&${buildAutoAttachQuery()}`;
    const { result } = await apiFetch(`/api/v1/sessions/inspections/smart-functions?${qs}`);
    const sessRes = await apiFetch("/api/v1/sessions/current").catch(() => null);
    if (sessRes?.session) renderSessionCard(sessRes.session);

    const items = result?.items || [];
    if (els.magFuncCount) els.magFuncCount.textContent = String(items.length);
    els.magFuncTableBody.innerHTML = "";

    if (items.length === 0) {
      els.magFuncTableBody.innerHTML = `<tr><td colspan="2" class="empty-cell">Không tìm thấy hàm khớp điều kiện lọc. Hãy thử chủ đề hoặc từ khóa khác!</td></tr>`;
      return;
    }

    for (const fn of items) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>
          <div class="mono-cell">
            <strong>${escapeHtml(fn.fullSymbol)}</strong>
            ${fn.isAppOwnCode ? `<span class="app-own-badge">★ Hàm của App</span>` : ""}
          </div>
          <div class="muted-note">Thư viện: ${escapeHtml(fn.moduleName || "-")} • Địa chỉ: ${escapeHtml(fn.address || "-")}</div>
        </td>
      `;
      const tdAct = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn-mini btn-mini-accent";
      btn.textContent = "+ Chèn Hook Frida 17";
      btn.addEventListener("click", () => {
        const code =
          fn.kind === "objc"
            ? buildSafeFrida17ObjcHook(fn.className, fn.selector)
            : buildSafeFrida17NativeHook(fn.moduleName, fn.selector);
        insertCodeIntoStudio(code, true);
        showToast("ok", "📝 Đã sinh mã Hook chuẩn Frida 17", `${fn.fullSymbol} — Bấm 'Chạy mã JS' để kích hoạt!`);
      });
      tdAct.appendChild(btn);
      tr.appendChild(tdAct);
      els.magFuncTableBody.appendChild(tr);
    }
  } catch (err) {
    els.magFuncTableBody.innerHTML = `<tr><td colspan="2" class="empty-cell">${escapeHtml(err.message)}</td></tr>`;
    reportUiError("Không thể dò tìm hàm", err);
  } finally {
    els.magSearchFuncBtn.disabled = false;
  }
}

async function handleLoadModules() {
  els.loadModulesBtn.disabled = true;
  try {
    const filter = els.moduleFilterInput?.value?.trim() || "";
    const { result } = await apiFetch(
      `/api/v1/sessions/inspections/modules?filter=${encodeURIComponent(filter)}&${buildAutoAttachQuery()}`
    );
    const sessRes = await apiFetch("/api/v1/sessions/current").catch(() => null);
    if (sessRes?.session) renderSessionCard(sessRes.session);

    const list = Array.isArray(result) ? result : [];
    els.modulesTableBody.innerHTML = "";
    if (list.length === 0) {
      els.modulesTableBody.innerHTML = `<tr><td colspan="4" class="empty-cell">Không tìm thấy thư viện khớp từ khóa.</td></tr>`;
      return;
    }

    for (const mod of list) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono-cell" title="${escapeHtml(mod.path)}"><strong>${escapeHtml(mod.name)}</strong></td>
        <td class="mono-cell">${escapeHtml(mod.base)}</td>
        <td class="mono-cell">${formatByteSize(mod.size)}</td>
      `;
      const tdAct = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn-mini btn-mini-info";
      btn.textContent = "Xem hàm xuất";
      btn.addEventListener("click", () => void handleLoadExports(mod.name));
      tdAct.appendChild(btn);
      tr.appendChild(tdAct);
      els.modulesTableBody.appendChild(tr);
    }
  } catch (err) {
    reportUiError("Không thể tải danh sách thư viện", err);
  } finally {
    els.loadModulesBtn.disabled = false;
  }
}

async function handleLoadExports(moduleName) {
  state.currentInspectModule = moduleName;
  if (els.exportsTitle) els.exportsTitle.textContent = `Hàm xuất (Exports): ${moduleName}`;
  const kw = els.exportFilterInput?.value?.trim() || "";
  els.exportsTableBody.innerHTML = `<tr><td colspan="4" class="empty-cell">⏳ Đang đọc bảng hàm xuất...</td></tr>`;

  try {
    const { result } = await apiFetch(
      `/api/v1/sessions/inspections/exports?moduleName=${encodeURIComponent(moduleName)}&filter=${encodeURIComponent(
        kw
      )}&${buildAutoAttachQuery()}`
    );
    const items = Array.isArray(result) ? result : [];
    els.exportsTableBody.innerHTML = "";
    if (items.length === 0) {
      els.exportsTableBody.innerHTML = `<tr><td colspan="4" class="empty-cell">Không có hàm xuất khớp từ khóa.</td></tr>`;
      return;
    }
    for (const ex of items) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono-cell"><strong>${escapeHtml(ex.name)}</strong></td>
        <td class="mono-cell">${escapeHtml(ex.type)}</td>
        <td class="mono-cell">${escapeHtml(ex.address)}</td>
      `;
      const tdAct = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn-mini btn-mini-accent";
      btn.textContent = "+ Hook";
      btn.addEventListener("click", () => {
        insertCodeIntoStudio(buildSafeFrida17NativeHook(moduleName, ex.name), true);
        showToast("ok", "📝 Đã chèn mã Hook Native", `${moduleName}!${ex.name}`);
      });
      tdAct.appendChild(btn);
      tr.appendChild(tdAct);
      els.exportsTableBody.appendChild(tr);
    }
  } catch (err) {
    reportUiError("Không thể đọc danh sách hàm xuất", err);
  }
}

async function handleSearchObjcClasses() {
  if (isLocalPcDeviceSelected()) return;
  els.searchObjcClassesBtn.disabled = true;
  try {
    const kw = els.objcFilterInput?.value?.trim() || "";
    const { result } = await apiFetch(
      `/api/v1/sessions/inspections/objc-classes?filter=${encodeURIComponent(kw)}&${buildAutoAttachQuery()}`
    );
    const sessRes = await apiFetch("/api/v1/sessions/current").catch(() => null);
    if (sessRes?.session) renderSessionCard(sessRes.session);

    els.objcClassList.innerHTML = "";
    const classes = result?.classes || [];
    if (classes.length === 0) {
      els.objcClassList.innerHTML = `<li class="empty-list-item">Không tìm thấy lớp khớp từ khóa.</li>`;
      return;
    }
    for (const clsName of classes) {
      const li = document.createElement("li");
      li.textContent = clsName;
      li.addEventListener("click", () => {
        for (const el of els.objcClassList.querySelectorAll("li")) el.classList.remove("active");
        li.classList.add("active");
        void handleLoadObjcMethods(clsName);
      });
      els.objcClassList.appendChild(li);
    }
  } catch (err) {
    reportUiError("Không thể quét lớp Objective-C", err);
  } finally {
    els.searchObjcClassesBtn.disabled = isLocalPcDeviceSelected();
  }
}

async function handleLoadObjcMethods(className) {
  if (els.objcMethodsTitle) els.objcMethodsTitle.textContent = `Đang đọc phương thức của ${className}...`;
  try {
    const { result } = await apiFetch(
      `/api/v1/sessions/inspections/objc-methods?className=${encodeURIComponent(className)}&${buildAutoAttachQuery()}`
    );
    const methods = result?.methods || [];
    if (els.objcMethodsTitle) {
      els.objcMethodsTitle.textContent = `${className} (Kế thừa: ${result?.superClass || "NSObject"} • ${methods.length} hàm)`;
    }
    els.objcMethodsBody.innerHTML = "";
    for (const m of methods) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono-cell"><strong>${escapeHtml(m.selector)}</strong></td>
        <td class="mono-cell">${escapeHtml(m.address)}</td>
      `;
      const tdAct = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn-mini btn-mini-accent";
      btn.textContent = "+ Hook";
      btn.addEventListener("click", () => {
        insertCodeIntoStudio(buildSafeFrida17ObjcHook(className, m.selector), true);
        showToast("ok", "📝 Đã chèn Hook ObjC chuẩn Frida 17", `${className} ${m.selector}`);
      });
      tdAct.appendChild(btn);
      tr.appendChild(tdAct);
      els.objcMethodsBody.appendChild(tr);
    }
  } catch (err) {
    reportUiError("Không thể đọc phương thức Objective-C", err);
  }
}

async function handleScanMemoryInstances() {
  if (isLocalPcDeviceSelected()) return;
  const className = els.magMemClassInput?.value?.trim() || "";
  if (!className) return;
  els.magScanMemBtn.disabled = true;
  try {
    const { result } = await apiFetch(
      `/api/v1/sessions/inspections/memory-instances?className=${encodeURIComponent(className)}&maxItems=25&${buildAutoAttachQuery()}`
    );
    const list = result?.instances || [];
    if (els.magMemCountBadge) els.magMemCountBadge.textContent = `${result?.totalCount ?? list.length} đối tượng`;
    els.magMemTableBody.innerHTML = "";
    if (list.length === 0) {
      els.magMemTableBody.innerHTML = `<tr><td colspan="2" class="empty-cell">${escapeHtml(
        result?.message || "Chưa có đối tượng nào của lớp này đang sống trong RAM."
      )}</td></tr>`;
      return;
    }
    for (const inst of list) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono-cell">${escapeHtml(inst.handle)}</td>
        <td class="mono-cell">${escapeHtml(inst.preview || inst.actualClass)}</td>
      `;
      els.magMemTableBody.appendChild(tr);
    }
  } catch (err) {
    reportUiError("Không thể quét bộ nhớ RAM", err);
  } finally {
    els.magScanMemBtn.disabled = isLocalPcDeviceSelected();
  }
}

function syncRpcInvokeButtonState() {
  if (!els.invokeRpcBtn) return;
  const hasSession = state.session.status === "running";
  const hasMethod = Boolean(els.rpcMethodInput?.value?.trim());
  els.invokeRpcBtn.disabled = !(hasSession && hasMethod);
}

function renderDiscoveredRpcBar() {
  if (!els.rpcDiscoveredBar) return;
  els.rpcDiscoveredBar.innerHTML = `<span class="vars-hint">Các hàm RPC đang mở trong phiên hiện tại:</span>`;
  if (state.session.status !== "running") {
    els.rpcDiscoveredBar.innerHTML += `<span class="muted-note">Chưa có phiên Frida đang chạy — hãy bấm "⚡ Nạp & Chạy Mẫu 6.1" ở góc phải!</span>`;
  } else if (state.discoveredRpcExports.length === 0) {
    els.rpcDiscoveredBar.innerHTML += `<span class="muted-note">Kịch bản JS hiện tại không mở hàm rpc.exports nào (bấm nút Mẫu 6.1 để mở mẫu hàm điều khiển).</span>`;
  } else {
    for (const fnName of state.discoveredRpcExports) {
      const pill = document.createElement("button");
      pill.type = "button";
      pill.className = "id-chip-btn";
      pill.textContent = `📡 ${fnName}()`;
      pill.addEventListener("click", () => {
        els.rpcMethodInput.value = fnName;
        syncRpcInvokeButtonState();
      });
      els.rpcDiscoveredBar.appendChild(pill);
    }
    if (!els.rpcMethodInput.value.trim()) {
      els.rpcMethodInput.value = state.discoveredRpcExports[0];
    }
  }
  syncRpcInvokeButtonState();
}

async function refreshDiscoveredRpcExports(notifyToast = false) {
  if (state.session.status !== "running") {
    state.discoveredRpcExports = [];
    renderDiscoveredRpcBar();
    return;
  }
  try {
    const { result } = await apiFetch("/api/v1/sessions/inspections/rpc-exports");
    state.discoveredRpcExports = result?.exports || [];
    renderDiscoveredRpcBar();
    if (notifyToast) {
      showToast("info", "📡 Đã quét rpc.exports", `Tìm thấy ${state.discoveredRpcExports.length} hàm điều khiển từ xa.`);
    }
  } catch {
    state.discoveredRpcExports = [];
    renderDiscoveredRpcBar();
  }
}

async function handleInvokeRpc() {
  const method = els.rpcMethodInput?.value?.trim() || "";
  if (!method) return;
  let args = [];
  try {
    args = JSON.parse(els.rpcArgsInput?.value?.trim() || "[]");
    if (!Array.isArray(args)) throw new Error("Phải là mảng JSON");
  } catch {
    reportUiError("Tham số RPC không hợp lệ", new Error('Ô tham số phải là mảng JSON, ví dụ: ["Antidv"] hoặc []'));
    return;
  }

  els.invokeRpcBtn.disabled = true;
  try {
    const out = await apiFetch("/api/v1/sessions/rpc-calls", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ method, args }),
    });
    els.rpcResultPre.textContent =
      `// ✅ Kết quả gọi rpc.exports.${method}(${JSON.stringify(args)}) — Độ trễ: ${out.elapsedMs} ms\n` +
      JSON.stringify(out.result, null, 2);
    showToast("ok", `📡 Đã gọi ${method}()`, `Phản hồi trong ${out.elapsedMs} ms`);
  } catch (err) {
    els.rpcResultPre.textContent = `// ❌ Lỗi gọi hàm RPC '${method}':\n${err.message}`;
    reportUiError(`Không thể gọi hàm RPC '${method}'`, err);
  } finally {
    syncRpcInvokeButtonState();
  }
}

// ============================================================================
// KHÔNG GIAN ⑥: TRÌNH DUYỆT TỆP SANDBOX & KÉT SẮT BẢO MẬT
// ============================================================================
async function handleLoadSandboxDir(relPath = "") {
  if (isLocalPcDeviceSelected()) return;
  const cleanRel = String(relPath || "").replace(/^\/+|\/+$/g, "");
  state.sandboxRelPath = cleanRel;

  for (const b of els.sandboxQuickDirBtns) {
    b.classList.toggle("active", b.dataset.sbdir === cleanRel);
  }

  els.sandboxRefreshBtn.disabled = true;
  els.sandboxFilesTableBody.innerHTML = `<tr><td colspan="3" class="empty-cell">⏳ Đang đọc thư mục ~/${escapeHtml(cleanRel)}...</td></tr>`;

  try {
    const { result } = await apiFetch(
      `/api/v1/sessions/inspections/sandbox-files?relPath=${encodeURIComponent(cleanRel)}&${buildAutoAttachQuery()}`
    );
    const sessRes = await apiFetch("/api/v1/sessions/current").catch(() => null);
    if (sessRes?.session) renderSessionCard(sessRes.session);

    if (els.sandboxCurrentPathLabel) {
      els.sandboxCurrentPathLabel.textContent = `Đường dẫn hiện tại: ~/${result.currentRelPath || ""} (${result.fullPath || ""})`;
    }

    const items = result?.items || [];
    els.sandboxFilesTableBody.innerHTML = "";
    if (items.length === 0) {
      els.sandboxFilesTableBody.innerHTML = `<tr><td colspan="3" class="empty-cell">Thư mục này đang trống.</td></tr>`;
      return;
    }

    for (const entry of items) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${entry.isDir ? "📁" : "📄"} <strong>${escapeHtml(entry.name)}</strong></td>
        <td class="mono-cell">${entry.isDir ? "Thư mục" : formatByteSize(entry.sizeBytes)}</td>
      `;
      const tdAct = document.createElement("td");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = entry.isDir ? "btn-mini btn-mini-info" : "btn-mini btn-mini-accent";
      btn.textContent = entry.isDir ? "Mở thư mục" : "Xem tệp";
      btn.addEventListener("click", () => {
        if (entry.isDir) void handleLoadSandboxDir(entry.relPath);
        else void handleReadSandboxFile(entry.relPath);
      });
      tdAct.appendChild(btn);
      tr.appendChild(tdAct);
      els.sandboxFilesTableBody.appendChild(tr);
    }
  } catch (err) {
    els.sandboxFilesTableBody.innerHTML = `<tr><td colspan="3" class="empty-cell">${escapeHtml(err.message)}</td></tr>`;
    reportUiError("Không thể đọc thư mục Sandbox", err);
  } finally {
    els.sandboxRefreshBtn.disabled = isLocalPcDeviceSelected();
  }
}

async function handleReadSandboxFile(relPath) {
  if (!relPath) return;
  els.sandboxPreviewTitle.textContent = `📄 Đang đọc ~/${relPath}...`;
  try {
    const { result } = await apiFetch(
      `/api/v1/sessions/inspections/sandbox-read?relPath=${encodeURIComponent(relPath)}&${buildAutoAttachQuery()}`
    );
    els.sandboxPreviewTitle.textContent = `📄 ~/${result.relPath} (${result.format} • ${formatByteSize(result.sizeBytes)})`;
    els.sandboxFileViewerPre.textContent = result.content || "(Tệp trống)";
  } catch (err) {
    els.sandboxFileViewerPre.textContent = `// ❌ Không thể đọc tệp:\n${err.message}`;
    reportUiError("Lỗi đọc tệp Sandbox", err);
  }
}

async function handleInspectVault() {
  if (isLocalPcDeviceSelected()) return;
  els.inspectVaultBtn.disabled = true;
  try {
    const { result } = await apiFetch(`/api/v1/sessions/inspections/security-vault?${buildAutoAttachQuery()}`);
    const sessRes = await apiFetch("/api/v1/sessions/current").catch(() => null);
    if (sessRes?.session) renderSessionCard(sessRes.session);

    state.vaultData = result;
    state.revealVaultValues = false;
    renderSecurityVaultTable();
    showToast(
      "ok",
      "🔐 Đã quét Két sắt Bảo mật",
      `${result.counts?.userDefaults ?? 0} khóa phiên • ${result.counts?.cookies ?? 0} Cookie • ${
        result.counts?.keychain ?? 0
      } mục Keychain`
    );
  } catch (err) {
    reportUiError("Không thể quét Két sắt Bảo mật", err);
  } finally {
    els.inspectVaultBtn.disabled = isLocalPcDeviceSelected();
  }
}

function renderSecurityVaultTable() {
  const vault = state.vaultData;
  if (!vault || !els.securityVaultTableBody) return;
  const showRaw = state.revealVaultValues;
  if (els.toggleVaultMaskBtn) {
    els.toggleVaultMaskBtn.textContent = showRaw ? "🙈 Che bớt giá trị" : "👁️ Hiện giá trị đầy đủ";
  }
  if (els.vaultSummaryNote) {
    els.vaultSummaryNote.textContent = `Phát hiện: ${vault.counts?.userDefaults ?? 0} khóa NSUserDefaults • ${
      vault.counts?.cookies ?? 0
    } Cookie • ${vault.counts?.keychain ?? 0} mục cấu hình Keychain.`;
  }

  const rows = [];
  for (const ud of vault.userDefaultsItems || []) {
    rows.push({
      badge: `<span class="badge-lv lv-info">USERDEFAULTS</span>`,
      name: ud.key,
      val: showRaw ? ud.valuePreview : ud.maskedPreview,
      saveKey: ud.key,
      saveVal: ud.valuePreview,
    });
  }
  for (const ck of vault.cookies || []) {
    rows.push({
      badge: `<span class="badge-lv lv-warning">COOKIE</span>`,
      name: `${ck.name} (${ck.domain})`,
      val: `${showRaw ? ck.valuePreview : ck.maskedPreview} [${ck.isSecure ? "Secure" : "Non-Secure"} • ${
        ck.isHTTPOnly ? "HttpOnly" : "JS-Readable"
      }]`,
      saveKey: ck.name,
      saveVal: ck.valuePreview,
    });
  }
  for (const kc of vault.keychainItems || []) {
    rows.push({
      badge: `<span class="badge-lv lv-send">KEYCHAIN</span>`,
      name: `${kc.service} • ${kc.account}`,
      val: `Nhóm: ${kc.accessGroup} | Bảo vệ: ${kc.protection}`,
      saveKey: kc.account !== "(Không đặt tên)" ? kc.account : kc.service,
      saveVal: `${kc.service}:${kc.account}`,
    });
  }

  els.securityVaultTableBody.innerHTML = "";
  if (rows.length === 0) {
    els.securityVaultTableBody.innerHTML = `<tr><td colspan="4" class="empty-cell">Ứng dụng chưa lưu khóa phiên, Cookie hoặc mục Keychain nào.</td></tr>`;
    return;
  }

  for (const r of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${r.badge}</td>
      <td class="mono-cell">${escapeHtml(r.name)}</td>
      <td class="mono-cell">${escapeHtml(r.val || "(Trống)")}</td>
    `;
    const tdAct = document.createElement("td");
    const grp = document.createElement("div");
    grp.className = "mini-btn-row";

    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.className = "id-chip-btn";
    saveBtn.textContent = "💾 Lưu ID";
    saveBtn.addEventListener("click", () => {
      void quickSaveParam({ key: r.saveKey, value: r.saveVal, note: "Lưu từ Két sắt Bảo mật" }, saveBtn);
    });

    const decBtn = document.createElement("button");
    decBtn.type = "button";
    decBtn.className = "var-insert-pill";
    decBtn.textContent = "🔓 Giải mã";
    decBtn.addEventListener("click", () => void sendToDecoder(r.saveVal, `Két sắt (${r.saveKey})`));

    grp.append(saveBtn, decBtn);
    tdAct.appendChild(grp);
    tr.appendChild(tdAct);
    els.securityVaultTableBody.appendChild(tr);
  }
}

// ============================================================================
// CỘT PHẢI: MÀN HÌNH NHẬT KÝ ĐÔI THỜI GIAN THỰC (< 5 MS)
// ============================================================================
function mirrorDeviceRecordToBoxes(rec) {
  if (!rec) return;
  if (rec.details?.__studioType === "http_exchange") return;

  if (rec.level === "send") {
    const formatted =
      rec.details && typeof rec.details === "object"
        ? JSON.stringify(rec.details, null, 2)
        : prettyFormatBody(rec.text || "");

    if (els.studioAnswerBadge) {
      els.studioAnswerBadge.className = "badge-lv lv-send";
      els.studioAnswerBadge.textContent = `ĐÃ NHẬN JSON (${formatClockMs(rec.ts)})`;
    }
    if (els.studioQuickAnswerPre) els.studioQuickAnswerPre.textContent = formatted;

    if (els.repStatusBadge) {
      els.repStatusBadge.className = "badge-lv lv-send";
      els.repStatusBadge.textContent = "KẾT QUẢ JS • ĐÃ TRẢ LỜI";
    }
    if (els.repLatencyBadge) els.repLatencyBadge.textContent = formatClockMs(rec.ts);
    if (els.repResponseBodyPre) els.repResponseBodyPre.textContent = formatted;
    const cands = extractInterestingParams(rec.details ?? rec.text, "");
    populateDetectedParamChips(cands, `Kết quả JS (${rec.target || "App"})`);
  } else if (rec.level === "error") {
    const errTxt = `${rec.text || ""}${rec.details ? `\n${rec.details}` : ""}`;
    if (els.studioAnswerBadge) {
      els.studioAnswerBadge.className = "badge-lv lv-error";
      els.studioAnswerBadge.textContent = "BÁO LỖI DÒNG CODE";
    }
    if (els.studioQuickAnswerPre) els.studioQuickAnswerPre.textContent = errTxt;
  } else if (rec.source === "console" && els.studioQuickAnswerPre) {
    if (els.studioAnswerBadge && els.studioAnswerBadge.textContent.startsWith("ĐANG")) {
      els.studioAnswerBadge.className = "badge-lv lv-info";
      els.studioAnswerBadge.textContent = "LOG CONSOLE";
    }
  }
}

function renderRuntimeLogs() {
  if (els.runtimeLogCount) els.runtimeLogCount.textContent = String(state.runtimeLogs.length);
  if (!els.runtimeLogBody) return;

  const lv = state.logLevelFilter;
  const kw = state.logSearchKeyword;
  const rows = state.runtimeLogs.filter((r) => {
    if (lv !== "ALL" && r.level !== lv) return false;
    if (!kw) return true;
    return String(r.text || "").toLowerCase().includes(kw) || String(r.target || "").toLowerCase().includes(kw);
  });

  els.runtimeLogBody.innerHTML = "";
  if (rows.length === 0) {
    els.runtimeLogBody.innerHTML = `<tr><td colspan="4" class="empty-cell">Không có dòng kết quả nào khớp bộ lọc hiện tại.</td></tr>`;
    return;
  }

  const frag = document.createDocumentFragment();
  for (const rec of rows.slice(-250)) {
    const tr = document.createElement("tr");
    const lvMap = {
      send: ["lv-send", "JSON"],
      info: ["lv-info", "LOG"],
      system: ["lv-system", "HỆ THỐNG"],
      rpc: ["lv-rpc", "RPC"],
      warning: ["lv-warning", "CẢNH BÁO"],
      error: ["lv-error", "BÁO LỖI"],
    };
    const [cls, label] = lvMap[rec.level] || ["lv-info", String(rec.level || "LOG").toUpperCase()];

    const tdId = document.createElement("td");
    tdId.className = "mono-cell";
    tdId.textContent = String(rec.id || "-");

    const tdTime = document.createElement("td");
    tdTime.className = "mono-cell";
    tdTime.textContent = formatClockMs(rec.ts);

    const tdLv = document.createElement("td");
    tdLv.innerHTML = `<span class="badge-lv ${cls}">${label}</span>`;

    const tdMsg = document.createElement("td");
    const pre = document.createElement("pre");
    pre.className = "log-msg-pre";
    pre.textContent = rec.text || "";
    tdMsg.appendChild(pre);

    if (rec.level === "send" || (rec.text && /eyJ[A-Za-z0-9_-]{12,}/.test(rec.text))) {
      const tools = document.createElement("div");
      tools.className = "log-inline-tools";

      const decBtn = document.createElement("button");
      decBtn.type = "button";
      decBtn.className = "btn-mini btn-mini-info";
      decBtn.textContent = "🔓 Giải mã";
      decBtn.addEventListener("click", () => void sendToDecoder(rec.text, `Log #${rec.id}`));
      tools.appendChild(decBtn);

      const cands = extractInterestingParams(rec.details ?? rec.text, "");
      for (const c of cands.slice(0, 3)) {
        const sBtn = document.createElement("button");
        sBtn.type = "button";
        sBtn.className = "id-chip-btn";
        sBtn.textContent = `💾 Lưu ${c.key}`;
        sBtn.addEventListener("click", () => void quickSaveParam({ key: c.key, value: c.value, note: `Log #${rec.id}` }, sBtn));
        tools.appendChild(sBtn);
      }
      tdMsg.appendChild(tools);
    }

    tr.append(tdId, tdTime, tdLv, tdMsg);
    frag.appendChild(tr);
  }
  els.runtimeLogBody.appendChild(frag);
  if (els.autoScrollToggle?.checked && els.runtimeLogScroll) {
    els.runtimeLogScroll.scrollTop = els.runtimeLogScroll.scrollHeight;
  }
}

function renderSystemLogs() {
  if (els.systemLogCount) els.systemLogCount.textContent = String(state.systemLogs.length);
  if (!els.systemLogBody) return;

  const kw = state.logSearchKeyword;
  const rows = state.systemLogs.filter((r) => {
    if (!kw) return true;
    return (
      String(r.message || "").toLowerCase().includes(kw) ||
      String(r.location || "").toLowerCase().includes(kw) ||
      String(r.traceId || "").toLowerCase().includes(kw)
    );
  });

  els.systemLogBody.innerHTML = "";
  if (rows.length === 0) {
    els.systemLogBody.innerHTML = `<tr><td colspan="4" class="empty-cell">Chưa có dòng nhật ký hệ thống khớp từ khóa.</td></tr>`;
    return;
  }

  const frag = document.createDocumentFragment();
  for (const r of rows.slice(-200)) {
    const tr = document.createElement("tr");
    const lvUpper = String(r.level || "INFO").toUpperCase();
    const cls = lvUpper === "ERROR" ? "lv-error" : lvUpper === "WARN" ? "lv-warning" : "lv-info";
    tr.innerHTML = `
      <td class="mono-cell">${formatClockMs(r.timestamp)}</td>
      <td><span class="badge-lv ${cls}">${escapeHtml(lvUpper)}</span></td>
      <td class="mono-cell">${escapeHtml(r.location || "-")}</td>
      <td class="mono-cell">
        <div>${escapeHtml(r.message || "")}</div>
        ${r.traceId ? `<div class="muted-note">Trace ID: ${escapeHtml(r.traceId)}</div>` : ""}
      </td>
    `;
    frag.appendChild(tr);
  }
  els.systemLogBody.appendChild(frag);
  if (els.autoScrollToggle?.checked && els.systemLogScroll) {
    els.systemLogScroll.scrollTop = els.systemLogScroll.scrollHeight;
  }
}

function switchLogTab(tabKey) {
  state.activeLogTab = tabKey === "system" ? "system" : "runtime";
  for (const b of els.logTabBtns) b.classList.toggle("active", b.dataset.logtab === state.activeLogTab);
  if (els.runtimeLogScroll) els.runtimeLogScroll.hidden = state.activeLogTab !== "runtime";
  if (els.systemLogScroll) els.systemLogScroll.hidden = state.activeLogTab !== "system";
  if (state.activeLogTab === "runtime") renderRuntimeLogs();
  else renderSystemLogs();
}

async function loadInitialLogs() {
  const [evData, sysData, sessData] = await Promise.all([
    apiFetch("/api/v1/event-logs?limit=200").catch(() => ({ items: [] })),
    apiFetch("/api/v1/system-logs?limit=150").catch(() => ({ items: [] })),
    apiFetch("/api/v1/sessions/current").catch(() => ({ session: null })),
  ]);
  state.runtimeLogs = evData.items || [];
  state.systemLogs = sysData.items || [];
  if (sessData?.session) renderSessionCard(sessData.session);
  renderRuntimeLogs();
  renderSystemLogs();
}

// ============================================================================
// KẾT NỐI ĐỒNG BỘ THỜI GIAN THỰC WEBSOCKET (/ws)
// ============================================================================
function connectWebSocket() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${window.location.host}/ws`);
  state.ws = ws;

  ws.onopen = () => {
    state.wsAttempts = 0;
    if (els.wsDot) els.wsDot.className = "status-dot dot-online";
    if (els.wsStatusText) els.wsStatusText.textContent = "Đã kết nối trực tiếp thời gian thực (< 5 ms)";
  };

  ws.onmessage = (ev) => {
    try {
      const pkt = JSON.parse(ev.data);
      if (pkt.event === "session:state") {
        renderSessionCard(pkt.payload);
      } else if (pkt.event === "session:switches") {
        renderFeatureSwitchesUi(pkt.payload?.switches);
      } else if (pkt.event === "script:output") {
        const rec = pkt.payload;
        state.runtimeLogs.push(rec);
        if (state.runtimeLogs.length > 1000) state.runtimeLogs.shift();
        mirrorDeviceRecordToBoxes(rec);

        if (state.logPaused) {
          state.pausedPendingCount += 1;
          if (els.pauseLogStreamBtn) {
            els.pauseLogStreamBtn.textContent = `▶️ Tiếp tục (+${state.pausedPendingCount})`;
          }
        } else if (state.activeLogTab === "runtime") {
          renderRuntimeLogs();
        } else if (els.runtimeLogCount) {
          els.runtimeLogCount.textContent = String(state.runtimeLogs.length);
        }
      } else if (pkt.event === "script:cleared") {
        state.runtimeLogs = [];
        renderRuntimeLogs();
      } else if (pkt.event === "system:log") {
        state.systemLogs.push(pkt.payload);
        if (state.systemLogs.length > 500) state.systemLogs.shift();
        if (!state.logPaused && state.activeLogTab === "system") renderSystemLogs();
        else if (els.systemLogCount) els.systemLogCount.textContent = String(state.systemLogs.length);
      } else if (pkt.event === "http:exchange") {
        const ex = pkt.payload;
        if (!state.httpExchanges.some((x) => x.id === ex.id)) {
          state.httpExchanges.push(ex);
          if (state.httpExchanges.length > 300) state.httpExchanges.shift();
        }
        if (!state.selectedPacketId || ex.replayedFromDevice || ex.replayedFromPc) {
          selectPacketForRepeater(ex);
        } else {
          renderPacketList();
        }
      } else if (pkt.event === "http:cleared") {
        state.httpExchanges = [];
        state.selectedPacketId = null;
        renderPacketList();
      }
    } catch {
      // Bỏ qua bản tin hỏng
    }
  };

  ws.onclose = () => {
    if (els.wsDot) els.wsDot.className = "status-dot dot-offline";
    if (els.wsStatusText) els.wsStatusText.textContent = "Đang tự động kết nối lại kênh thời gian thực...";
    const waitMs = Math.min(1000 * 2 ** state.wsAttempts++, 10000);
    setTimeout(connectWebSocket, waitMs);
  };
}

// ============================================================================
// KHỞI ĐỘNG & GẮN SỰ KIỆN TOÀN BỘ GIAO DIỆN v7.0.0.0
// ============================================================================
async function initStudioV7() {
  // Khôi phục bản nháp trình soạn mã
  const savedDraft = localStorage.getItem(DRAFT_STORAGE_KEY);
  if (savedDraft !== null && els.codeEditor) {
    els.codeEditor.value = savedDraft;
  }
  syncEditorGutter();

  // Hướng dẫn nhanh
  els.toggleGuideBtn?.addEventListener("click", () => setGuideVisible(Boolean(els.newbieGuidePanel?.hidden)));
  els.closeGuideBtn?.addEventListener("click", () => setGuideVisible(false));

  // Điều hướng 6 không gian
  for (const btn of els.wsNavBtns) {
    btn.addEventListener("click", () => switchWorkspace(btn.dataset.ws));
  }

  // Thanh điều khiển đỉnh
  els.deviceSelect?.addEventListener("change", () => {
    state.preferredDeviceId = els.deviceSelect.value;
    applyPlatformCapabilitiesGuard();
    scheduleSaveSettings({ selectedDeviceId: els.deviceSelect.value });
    void loadTargetsForCurrentDevice();
    void refreshTelemetry();
  });
  els.refreshAllBtn?.addEventListener("click", () => void loadDevicesAndTargets(true));
  els.targetFilter?.addEventListener("input", () => renderTargetDropdown());
  els.targetSelect?.addEventListener("change", () => {
    state.preferredTarget = els.targetSelect.value;
    scheduleSaveSettings({ selectedTarget: els.targetSelect.value });
    renderAppMgrTable();
    if (state.paramFilterCurrentApp) renderSavedParamsUi();
  });
  for (const mBtn of els.modeBtns) {
    mBtn.addEventListener("click", () => {
      applyLaunchModeUi(mBtn.dataset.mode);
      scheduleSaveSettings({ launchMode: state.mode });
    });
  }
  els.runJsBtn?.addEventListener("click", () => void handleRunJs());
  els.stopSessionBtn?.addEventListener("click", () => void handleStopSession());

  // Không gian 1: Kết nối & Bác sĩ Frida
  els.probeAllChannelsBtn?.addEventListener("click", () => void probeConnectionChannels(true));
  els.quickSwitchUsbBtn?.addEventListener("click", () => void switchFridaChannel("usb_frida", els.quickSwitchUsbBtn));
  els.connectWifiBtn?.addEventListener("click", () => void handleConnectWifi());
  els.disconnectWifiBtn?.addEventListener("click", () => void handleDisconnectWifi());
  els.probeVpnBtn?.addEventListener("click", () => {
    scheduleSaveSettings({ vpnMitmProxyAddress: els.vpnProxyInput?.value?.trim() || "127.0.0.1:8080" });
    void probeConnectionChannels(true);
  });
  els.syncRabbitBtn?.addEventListener("click", () => void handleSyncRabbitDaemon());
  els.runHealthCheckBtn?.addEventListener("click", () => void handleCheckFridaHealth(true));
  els.runRepairBtn?.addEventListener("click", () => void handleRepairFridaServer());

  // Không gian 2: Ứng dụng & Hồ sơ bảo mật OWASP MASTG
  for (const fBtn of els.appFilterBtns) {
    fBtn.addEventListener("click", () => {
      state.appMgrFilter = fBtn.dataset.appfilter;
      for (const b of els.appFilterBtns) b.classList.toggle("active", b === fBtn);
      renderAppMgrTable();
      scheduleSaveSettings({ appMgrFilter: state.appMgrFilter });
    });
  }
  els.appSearchInput?.addEventListener("input", () => {
    state.appMgrSearch = els.appSearchInput.value;
    renderAppMgrTable();
  });
  els.refreshAppsBtn?.addEventListener("click", () => void loadDevicesAndTargets(true));
  els.inspectPostureBtn?.addEventListener("click", () => void handleInspectSecurityPosture());

  // Không gian 3: Công tắc 1 chạm & Trạm Mã JS
  for (const sw of els.switchCards) {
    sw.addEventListener("click", () => void handleToggleFeatureSwitch(sw.dataset.switchKey, sw));
  }
  els.snippetSearchInput?.addEventListener("input", () => {
    state.snippetSearchKeyword = els.snippetSearchInput.value.trim().toLowerCase();
    renderSnippetCards();
  });
  els.snippetCategorySelect?.addEventListener("change", () => {
    state.snippetCategoryFilter = els.snippetCategorySelect.value;
    renderSnippetCards();
    scheduleSaveSettings({ snippetCategoryFilter: state.snippetCategoryFilter });
  });
  els.openNewSnippetBtn?.addEventListener("click", () => openSnippetForm(null, true));
  els.saveEditorAsCustomBtn?.addEventListener("click", () => openSnippetForm(null, true));
  els.cancelSnippetFormBtn?.addEventListener("click", () => {
    if (els.snippetFormBox) els.snippetFormBox.hidden = true;
  });
  els.pullEditorCodeBtn?.addEventListener("click", () => {
    if (els.snippetCodeInput) els.snippetCodeInput.value = els.codeEditor?.value || "";
  });
  els.importJsFileBtn?.addEventListener("click", () => els.snippetFileInput?.click());
  els.snippetFileInput?.addEventListener("change", async () => {
    const f = els.snippetFileInput.files?.[0];
    if (!f) return;
    const text = await f.text();
    if (els.snippetCodeInput) els.snippetCodeInput.value = text;
    if (els.snippetTitleInput && !els.snippetTitleInput.value.trim()) {
      els.snippetTitleInput.value = f.name.replace(/\.(js|mjs|ts|txt)$/i, "");
    }
    els.snippetFileInput.value = "";
  });
  els.confirmSaveSnippetBtn?.addEventListener("click", () => void handleSaveCustomSnippet(false));
  els.saveAndRunSnippetBtn?.addEventListener("click", () => void handleSaveCustomSnippet(true));

  els.clearEditorDraftBtn?.addEventListener("click", () => {
    els.codeEditor.value = "// Nhập mã Frida 17 JavaScript tại đây...\n";
    localStorage.setItem(DRAFT_STORAGE_KEY, els.codeEditor.value);
    syncEditorGutter();
  });
  els.codeEditor?.addEventListener("input", () => {
    syncEditorGutter();
    localStorage.setItem(DRAFT_STORAGE_KEY, els.codeEditor.value);
  });
  els.codeEditor?.addEventListener("scroll", () => {
    if (els.lineGutter) els.lineGutter.scrollTop = els.codeEditor.scrollTop;
  });
  els.codeEditor?.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      void handleRunJs();
    } else if (e.key === "Tab") {
      e.preventDefault();
      const s = els.codeEditor.selectionStart;
      const end = els.codeEditor.selectionEnd;
      els.codeEditor.setRangeText("  ", s, end, "end");
      localStorage.setItem(DRAFT_STORAGE_KEY, els.codeEditor.value);
    }
  });
  els.decodeStudioAnswerBtn?.addEventListener("click", () => {
    void sendToDecoder(els.studioQuickAnswerPre?.textContent || "", "Phản hồi JS");
  });
  els.openPacketsFromStudioBtn?.addEventListener("click", () => switchWorkspace("packets"));

  // Không gian 4: Bắt gói, Sửa gửi lại, Giải mã JWS & Sổ lưu ID
  els.enableHttpCaptureBtn?.addEventListener("click", () => void handleEnableHttpCapture());
  els.newPacketDraftBtn?.addEventListener("click", () => {
    state.selectedPacketId = null;
    const app = els.targetSelect?.value || "com.apple.TestFlight";
    els.repSelectedBadge.textContent = "Soạn gói mới";
    els.repMethodSelect.value = "GET";
    els.repUrlInput.value = `https://itunes.apple.com/lookup?bundleId=${encodeURIComponent(app)}`;
    els.repHeadersInput.value = JSON.stringify({ Accept: "application/json" }, null, 2);
    els.repBodyInput.value = "";
    updateResolvedUrlPreview();
    renderPacketList();
  });
  els.genJsHookFromPacketBtn?.addEventListener("click", () => {
    const rawUrl = (els.repUrlInput?.value || "").replace(/\{\{[^}]+\}\}/g, "");
    let pathKey = "/api";
    try {
      const u = new URL(rawUrl);
      pathKey = u.pathname && u.pathname !== "/" ? u.pathname : u.host;
    } catch {
      pathKey = rawUrl.slice(0, 50) || "/api";
    }
    const hook = `// [ÁNH XẠ GÓI TIN -> MÃ JS FRIDA 17] Theo dõi chỉ đọc mọi gói khớp: ${JSON.stringify(pathKey)}
if (typeof ObjC !== "undefined" && ObjC.available && ObjC.classes.NSURLSession) {
  const _kw = ${JSON.stringify(pathKey)};
  const _m = ObjC.classes.NSURLSession["- dataTaskWithRequest:completionHandler:"];
  if (_m) {
    Interceptor.attach(_m.implementation, {
      onEnter(args) {
        try {
          if (!args[2] || args[2].isNull()) return;
          const req = new ObjC.Object(args[2]);
          const url = req.URL()?.absoluteString()?.toString() || "";
          if (url.includes(_kw)) {
            send({ suKien: "bat_trung_url_muc_tieu", phuongThuc: req.HTTPMethod()?.toString() || "GET", url });
          }
        } catch {}
      }
    });
    console.log("[+] Đang rình bắt riêng URL chứa:", _kw);
  }
}`;
    insertCodeIntoStudio(hook, true);
    showToast("ok", "💉 Đã sinh mã JS rình URL", pathKey);
  });

  els.packetSearchInput?.addEventListener("input", () => {
    state.packetSearchKeyword = els.packetSearchInput.value.trim().toLowerCase();
    renderPacketList();
  });
  els.clearPacketsBtn?.addEventListener("click", async () => {
    await apiFetch("/api/v1/http-exchanges", { method: "DELETE" });
    state.httpExchanges = [];
    state.selectedPacketId = null;
    renderPacketList();
  });

  els.repUrlInput?.addEventListener("focus", () => {
    state.lastFocusedRepField = "url";
  });
  els.repUrlInput?.addEventListener("input", () => {
    updateResolvedUrlPreview();
    scheduleSaveSettings();
  });
  els.repBodyInput?.addEventListener("focus", () => {
    state.lastFocusedRepField = "body";
  });
  els.repBodyInput?.addEventListener("input", () => scheduleSaveSettings());
  els.repHeadersInput?.addEventListener("input", () => scheduleSaveSettings());
  els.repMethodSelect?.addEventListener("change", () => scheduleSaveSettings());
  els.repSendFromSelect?.addEventListener("change", () => scheduleSaveSettings());
  els.sendRepeaterBtn?.addEventListener("click", () => void handleSendRepeater());

  els.decodeReqBodyBtn?.addEventListener("click", () => void sendToDecoder(els.repBodyInput?.value || "", "Request Body"));
  els.decodeResponseBtn?.addEventListener("click", () => void sendToDecoder(els.repResponseBodyPre?.textContent || "", "Hộp trả lời"));
  els.copyResponseBtn?.addEventListener("click", async () => {
    await navigator.clipboard.writeText(els.repResponseBodyPre?.textContent || "");
    showToast("info", "📋 Đã sao chép Hộp trả lời");
  });

  els.runDecoderBtn?.addEventListener("click", () => void handleRunDecoder("Trực tiếp"));
  els.decoderModeSelect?.addEventListener("change", () => {
    if (els.decoderInputTextarea?.value?.trim()) void handleRunDecoder("Đổi chế độ");
  });
  els.clearDecoderBtn?.addEventListener("click", () => {
    if (els.decoderInputTextarea) els.decoderInputTextarea.value = "";
    if (els.decoderExtractedIdsBar) els.decoderExtractedIdsBar.hidden = true;
    if (els.decoderOutputPre) {
      els.decoderOutputPre.textContent = "// Kết quả giải mã thật và trạng thái xác thực chữ ký số Apple StoreKit JWS sẽ hiển thị tại đây.";
    }
  });

  els.saveParamFormBtn?.addEventListener("click", () => void handleSaveParamFromForm());
  els.paramSearchInput?.addEventListener("input", () => {
    state.paramSearchKeyword = els.paramSearchInput.value.trim().toLowerCase();
    renderSavedParamsUi();
  });
  els.paramFilterCurrentAppChk?.addEventListener("change", () => {
    state.paramFilterCurrentApp = Boolean(els.paramFilterCurrentAppChk.checked);
    renderSavedParamsUi();
  });
  els.exportParamsBtn?.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(state.savedParams, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `so-luu-id-frida-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Không gian 5: Kính lúp Hàm, Native, ObjC & RPC
  for (const b of els.magSubTabBtns) {
    b.addEventListener("click", () => switchMagSubTab(b.dataset.magtab));
  }
  for (const pBtn of els.magPresetBtns) {
    pBtn.addEventListener("click", () => {
      state.magPreset = pBtn.dataset.magpreset;
      for (const x of els.magPresetBtns) x.classList.toggle("active", x === pBtn);
      if (els.magFuncKeywordInput) els.magFuncKeywordInput.value = "";
      void handleSmartFindFunctions();
    });
  }
  els.magSearchFuncBtn?.addEventListener("click", () => void handleSmartFindFunctions());
  els.magFuncKeywordInput?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") void handleSmartFindFunctions();
  });

  els.loadModulesBtn?.addEventListener("click", () => void handleLoadModules());
  els.exportFilterInput?.addEventListener("input", () => {
    if (state.currentInspectModule) void handleLoadExports(state.currentInspectModule);
  });
  els.searchObjcClassesBtn?.addEventListener("click", () => void handleSearchObjcClasses());
  els.magScanMemBtn?.addEventListener("click", () => void handleScanMemoryInstances());
  for (const chip of els.memChipBtns) {
    chip.addEventListener("click", () => {
      if (els.magMemClassInput) els.magMemClassInput.value = chip.dataset.memclass;
      void handleScanMemoryInstances();
    });
  }

  els.refreshRpcExportsBtn?.addEventListener("click", () => void refreshDiscoveredRpcExports(true));
  els.rpcMethodInput?.addEventListener("input", () => syncRpcInvokeButtonState());
  els.invokeRpcBtn?.addEventListener("click", () => void handleInvokeRpc());
  els.loadRpcDemoBtn?.addEventListener("click", async () => {
    const demo = state.snippets.find((s) => s.id === "builtin-rpc-demo");
    if (demo) {
      els.codeEditor.value = demo.code;
      localStorage.setItem(DRAFT_STORAGE_KEY, demo.code);
      syncEditorGutter();
      await handleRunJs();
      await refreshDiscoveredRpcExports(true);
    }
  });

  // Không gian 6: Tệp Sandbox & Két sắt
  for (const dBtn of els.sandboxQuickDirBtns) {
    dBtn.addEventListener("click", () => void handleLoadSandboxDir(dBtn.dataset.sbdir));
  }
  els.sandboxRefreshBtn?.addEventListener("click", () => void handleLoadSandboxDir(state.sandboxRelPath));
  els.sandboxUpDirBtn?.addEventListener("click", () => {
    const parts = (state.sandboxRelPath || "").split("/").filter(Boolean);
    parts.pop();
    void handleLoadSandboxDir(parts.join("/"));
  });
  els.decodeSandboxFileBtn?.addEventListener("click", () => {
    void sendToDecoder(els.sandboxFileViewerPre?.textContent || "", "Tệp Sandbox");
  });
  els.copySandboxFileBtn?.addEventListener("click", async () => {
    await navigator.clipboard.writeText(els.sandboxFileViewerPre?.textContent || "");
    showToast("info", "📋 Đã sao chép nội dung tệp Sandbox");
  });
  els.inspectVaultBtn?.addEventListener("click", () => void handleInspectVault());
  els.toggleVaultMaskBtn?.addEventListener("click", () => {
    state.revealVaultValues = !state.revealVaultValues;
    renderSecurityVaultTable();
  });

  // Cột Nhật ký đôi bên phải
  for (const lBtn of els.logTabBtns) {
    lBtn.addEventListener("click", () => switchLogTab(lBtn.dataset.logtab));
  }
  for (const lvBtn of els.levelFilterBtns) {
    lvBtn.addEventListener("click", () => {
      state.logLevelFilter = lvBtn.dataset.level;
      for (const b of els.levelFilterBtns) b.classList.toggle("active", b === lvBtn);
      renderRuntimeLogs();
    });
  }
  els.logSearchInput?.addEventListener("input", () => {
    state.logSearchKeyword = els.logSearchInput.value.trim().toLowerCase();
    if (state.activeLogTab === "runtime") renderRuntimeLogs();
    else renderSystemLogs();
  });
  els.autoScrollToggle?.addEventListener("change", () => {
    scheduleSaveSettings({ logAutoScroll: Boolean(els.autoScrollToggle.checked) });
  });
  els.pauseLogStreamBtn?.addEventListener("click", () => {
    state.logPaused = !state.logPaused;
    if (!state.logPaused) {
      state.pausedPendingCount = 0;
      els.pauseLogStreamBtn.classList.remove("is-paused");
      els.pauseLogStreamBtn.textContent = "⏸ Tạm dừng";
      renderRuntimeLogs();
      renderSystemLogs();
    } else {
      els.pauseLogStreamBtn.classList.add("is-paused");
      els.pauseLogStreamBtn.textContent = "▶️ Tiếp tục";
    }
  });
  els.exportLogsBtn?.addEventListener("click", () => {
    const arr = state.activeLogTab === "runtime" ? state.runtimeLogs : state.systemLogs;
    const blob = new Blob([JSON.stringify(arr, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nhat-ky-frida-${state.activeLogTab}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });
  els.clearLogsBtn?.addEventListener("click", async () => {
    if (state.activeLogTab === "runtime") {
      await apiFetch("/api/v1/event-logs", { method: "DELETE" });
      state.runtimeLogs = [];
      renderRuntimeLogs();
    } else {
      await apiFetch("/api/v1/system-logs", { method: "DELETE" });
      state.systemLogs = [];
      renderSystemLogs();
    }
  });

  // Bộ đếm thời gian phiên & làm mới thông số định kỳ
  setInterval(() => {
    if (state.session.status === "running" && state.session.startedAt && els.teleSessionUptime) {
      const ev = state.session.receivedDeviceEventsCount ?? 0;
      els.teleSessionUptime.textContent = `Chạy: ${formatDuration(state.session.startedAt)} • ${ev} sự kiện thật`;
    }
  }, 1000);

  setInterval(() => {
    if (!document.hidden) void refreshTelemetry();
  }, 15_000);

  await loadWorkspaceSettings();
  connectWebSocket();
  await Promise.all([loadSnippets(), loadSavedParams(), loadHttpExchanges(), loadInitialLogs()]);
  await loadDevicesAndTargets(false);
  await probeConnectionChannels(false);
  renderDiscoveredRpcBar();
}

void initStudioV7();
