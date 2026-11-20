// public/js-console.mjs — Bảng Điều Khiển Chuyên Gửi JS Frida (Kết nối thật, Móc App, Gửi JS, Phản hồi Server, Bắt Gói Tin & Nhật ký Tools Thời Gian Thực)

const STARTER_FRIDA_17_SCRIPT = `'use strict';
// Mẫu chuẩn Frida 17+ (Null-safe, kiểm tra ObjC.available, gửi kết quả về Khung Trả Lời)
try {
  const info = {
    pid: Process.id,
    arch: Process.arch,
    platform: Process.platform,
    objcAvailable: typeof ObjC !== 'undefined' && Boolean(ObjC.available),
    mainModule: Process.enumerateModules()[0]?.name || null,
    timestamp: new Date().toISOString(),
  };
  console.log('[Frida-JS] Đã thực thi thành công trên PID ' + info.pid + ' (' + info.platform + '/' + info.arch + ')');
  send({ type: 'runtime_probe', info });
} catch (err) {
  console.error('[Frida-JS] Lỗi thực thi:', err && err.message ? err.message : String(err));
}
`;

const state = {
  mode: "auto",
  devices: [],
  targets: { apps: [], processes: [] },
  snippets: [],
  session: null,
  hub: null,
  health: null,
  fridaServerReport: null,
  ws: {
    connected: false,
    latencyMs: null,
    lastMessageAt: null,
    reconnectAttempts: 0,
  },
  responses: [],
  packets: [],
  selectedPacketId: null,
  systemLogs: [],
  lastProbeAt: null,
};

const els = {
  serverVersionPill: document.getElementById("serverVersionPill"),
  wsDot: document.getElementById("wsDot"),
  wsStatusLabel: document.getElementById("wsStatusLabel"),
  sessionBadge: document.getElementById("sessionBadge"),
  truthBadge: document.getElementById("truthBadge"),
  probeConnectionsBtn: document.getElementById("probeConnectionsBtn"),
  repairFridaBtn: document.getElementById("repairFridaBtn"),

  connectionUpdatedAt: document.getElementById("connectionUpdatedAt"),
  channelCards: document.getElementById("channelCards"),
  deviceSelect: document.getElementById("deviceSelect"),
  refreshDevicesBtn: document.getElementById("refreshDevicesBtn"),
  targetFilter: document.getElementById("targetFilter"),
  targetSelect: document.getElementById("targetSelect"),
  modeButtons: Array.from(document.querySelectorAll(".seg-btn[data-mode]")),
  objcBridgeChk: document.getElementById("objcBridgeChk"),
  attachAppBtn: document.getElementById("attachAppBtn"),
  enableCaptureBtn: document.getElementById("enableCaptureBtn"),
  detachAppBtn: document.getElementById("detachAppBtn"),

  snippetSelect: document.getElementById("snippetSelect"),
  insertStarterBtn: document.getElementById("insertStarterBtn"),
  jsEditor: document.getElementById("jsEditor"),
  editorStats: document.getElementById("editorStats"),
  autoCaptureAfterSendChk: document.getElementById("autoCaptureAfterSendChk"),
  saveSnippetBtn: document.getElementById("saveSnippetBtn"),
  clearEditorBtn: document.getElementById("clearEditorBtn"),
  sendJsBtn: document.getElementById("sendJsBtn"),
  rpcMethodInput: document.getElementById("rpcMethodInput"),
  rpcArgsInput: document.getElementById("rpcArgsInput"),
  callRpcBtn: document.getElementById("callRpcBtn"),

  responseFilter: document.getElementById("responseFilter"),
  responseSearch: document.getElementById("responseSearch"),
  responseCountBadge: document.getElementById("responseCountBadge"),
  responseList: document.getElementById("responseList"),
  copyLatestResponseBtn: document.getElementById("copyLatestResponseBtn"),
  clearResponseBtn: document.getElementById("clearResponseBtn"),

  captureStatePill: document.getElementById("captureStatePill"),
  packetSearch: document.getElementById("packetSearch"),
  packetCountBadge: document.getElementById("packetCountBadge"),
  packetList: document.getElementById("packetList"),
  packetDetailTitle: document.getElementById("packetDetailTitle"),
  packetDetailBody: document.getElementById("packetDetailBody"),
  replayFromAppBtn: document.getElementById("replayFromAppBtn"),
  replayFromPcBtn: document.getElementById("replayFromPcBtn"),
  clearPacketsBtn: document.getElementById("clearPacketsBtn"),

  lastProbeBadge: document.getElementById("lastProbeBadge"),
  toolLogLevelFilter: document.getElementById("toolLogLevelFilter"),
  toolLogSearch: document.getElementById("toolLogSearch"),
  clearSystemLogsBtn: document.getElementById("clearSystemLogsBtn"),
  toolsStatusBody: document.getElementById("toolsStatusBody"),
  systemLogsBody: document.getElementById("systemLogsBody"),
  toastRoot: document.getElementById("toastRoot"),
};

function fmtTime(ts) {
  if (!ts) return "--:--:--";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString("vi-VN", { hour12: false });
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function prettyJson(val) {
  if (typeof val === "string") {
    const trimmed = val.trim();
    if ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
      try {
        return JSON.stringify(JSON.parse(trimmed), null, 2);
      } catch {
        return val;
      }
    }
    return val;
  }
  try {
    return JSON.stringify(val, null, 2);
  } catch {
    return String(val);
  }
}

function showToast(message, type = "info") {
  const el = document.createElement("div");
  el.className = `toast-item ${type === "ok" ? "is-ok" : type === "err" ? "is-err" : ""}`;
  el.textContent = message;
  els.toastRoot.appendChild(el);
  setTimeout(() => {
    el.remove();
  }, 4200);
}

function pushResponseRecord({ kind, title, meta = "", body }) {
  state.responses.unshift({
    id: `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    ts: Date.now(),
    kind, // api | send | console | error
    title,
    meta,
    body: typeof body === "string" ? body : prettyJson(body),
  });
  if (state.responses.length > 400) {
    state.responses.length = 400;
  }
  renderResponseList();
}

async function apiRequest(method, url, body = null, { logToResponse = false, label = "" } = {}) {
  const t0 = performance.now();
  const headers = { Accept: "application/json" };
  const opts = { method, headers };
  if (body !== null) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }

  let res;
  let json;
  try {
    res = await fetch(url, opts);
    json = await res.json().catch(() => ({ ok: false, error: { message: `HTTP ${res.status}` } }));
  } catch (networkErr) {
    const elapsedMs = Math.max(1, Math.round(performance.now() - t0));
    if (logToResponse) {
      pushResponseRecord({
        kind: "error",
        title: `${label || `${method} ${url}`} — LỖI MẠNG`,
        meta: `${elapsedMs} ms`,
        body: networkErr?.message || String(networkErr),
      });
    }
    throw networkErr;
  }

  const elapsedMs = Math.max(1, Math.round(performance.now() - t0));
  const ok = res.ok && json?.ok !== false && json?.success !== false;

  if (logToResponse) {
    pushResponseRecord({
      kind: ok ? "api" : "error",
      title: `${label || `${method} ${url}`} • HTTP ${res.status}`,
      meta: `${elapsedMs} ms${json?.error?.traceId ? ` • trace ${json.error.traceId}` : ""}`,
      body: json,
    });
  }

  if (!ok) {
    const errMsg = json?.error?.message || `Yêu cầu ${method} ${url} thất bại (HTTP ${res.status})`;
    const err = new Error(errMsg);
    err.status = res.status;
    err.payload = json;
    throw err;
  }

  return { status: res.status, elapsedMs, json, data: json.data };
}

// ============================================================================
// RENDERERS (100% DỮ LIỆU THẬT)
// ============================================================================
function renderSessionHeader() {
  const s = state.session;
  if (!s) {
    els.sessionBadge.className = "inline-badge badge-idle";
    els.sessionBadge.textContent = "Phiên Frida: Chưa gắn";
    els.detachAppBtn.disabled = true;
    return;
  }

  const running = s.status === "running" && Boolean(s.pid);
  if (running) {
    els.sessionBadge.className = "inline-badge badge-ok";
    els.sessionBadge.textContent = `Đang móc: ${s.targetLabel || "App"} (PID ${s.pid})`;
  } else if (s.status === "connecting") {
    els.sessionBadge.className = "inline-badge badge-warn";
    els.sessionBadge.textContent = `Đang kết nối: ${s.targetLabel || "..."}`;
  } else if (s.status === "error") {
    els.sessionBadge.className = "inline-badge badge-err";
    els.sessionBadge.textContent = "Phiên Frida: Lỗi";
  } else {
    els.sessionBadge.className = "inline-badge badge-idle";
    els.sessionBadge.textContent = "Phiên Frida: Chưa gắn";
  }

  els.detachAppBtn.disabled = !running && s.status !== "connecting";

  const truth = s.executionTruth || {};
  const evCount = Number(truth.receivedDeviceEventsCount || 0);
  if (running && evCount === 0) {
    els.truthBadge.className = "inline-badge badge-warn";
    els.truthBadge.textContent = "Thiết bị: Đã gắn • Đang chờ tín hiệu JS (0)";
  } else if (evCount > 0) {
    els.truthBadge.className = "inline-badge badge-ok";
    els.truthBadge.textContent = `Sự kiện thiết bị: ${evCount} (${fmtTime(truth.lastDeviceOutputAt)})`;
  } else {
    els.truthBadge.className = "inline-badge badge-muted";
    els.truthBadge.textContent = "Sự kiện thiết bị: 0";
  }

  const capOn = Boolean(s.featureSwitches?.httpCapture);
  els.captureStatePill.className = `inline-badge ${capOn ? "badge-ok" : "badge-idle"}`;
  els.captureStatePill.textContent = capOn ? "Hook HTTP: ĐANG BẬT" : "Hook HTTP: Tắt";
}

function renderChannelCards() {
  const channels = state.hub?.channels;
  if (!Array.isArray(channels) || channels.length === 0) {
    els.channelCards.innerHTML = `<div class="muted-text">Chưa có dữ liệu kênh kết nối từ máy chủ.</div>`;
    return;
  }

  const activeId = state.hub?.activeChannel || "";
  els.channelCards.innerHTML = channels
    .map((ch) => {
      const levelClass = ch.statusLevel === "ok" ? "ch-connected" : ch.statusLevel === "warn" ? "ch-ready" : "ch-offline";
      const activeClass = ch.id === activeId ? "is-active" : "";
      return `
        <button
          type="button"
          class="channel-chip ${activeClass}"
          data-channel-id="${escapeHtml(ch.id)}"
          title="${escapeHtml(`${ch.title}\n${ch.detail || ""}\nEndpoint: ${ch.endpoint || ""}`)}"
        >
          <span>${escapeHtml(ch.shortLabel || ch.title)}</span>
          <span class="ch-status ${levelClass}">${escapeHtml(ch.statusBadge || (ch.connected ? "ONLINE" : "OFFLINE"))}</span>
        </button>
      `;
    })
    .join("");

  els.channelCards.querySelectorAll(".channel-chip[data-channel-id]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const chId = btn.getAttribute("data-channel-id");
      if (chId) void switchConnectionChannel(chId);
    });
  });
}

function renderDeviceSelect() {
  const prev = els.deviceSelect.value;
  if (!state.devices.length) {
    els.deviceSelect.innerHTML = `<option value="">Không tìm thấy thiết bị Frida nào</option>`;
    return;
  }
  els.deviceSelect.innerHTML = state.devices
    .map((d) => {
      const tag = d.type ? `[${d.type.toUpperCase()}] ` : "";
      return `<option value="${escapeHtml(d.id)}">${escapeHtml(`${tag}${d.name} (${d.id})`)}</option>`;
    })
    .join("");

  if (prev && state.devices.some((d) => d.id === prev)) {
    els.deviceSelect.value = prev;
  } else {
    const usb = state.devices.find((d) => d.type === "usb" || d.type === "remote");
    els.deviceSelect.value = (usb || state.devices[0]).id;
  }
}

function renderTargetSelect() {
  const kw = els.targetFilter.value.trim().toLowerCase();
  const prev = els.targetSelect.value;
  const apps = (state.targets.apps || []).filter((a) => {
    if (!kw) return true;
    return (
      String(a.name || "").toLowerCase().includes(kw) ||
      String(a.identifier || "").toLowerCase().includes(kw) ||
      String(a.pid || "").includes(kw)
    );
  });
  const procs = (state.targets.processes || []).filter((p) => {
    if (!kw) return true;
    return String(p.name || "").toLowerCase().includes(kw) || String(p.pid || "").includes(kw);
  });

  const groups = [];
  if (apps.length) {
    groups.push(
      `<optgroup label="Ứng dụng đã cài (${apps.length})">${apps
        .map((a) => {
          const val = a.identifier || String(a.pid || a.name);
          const pidTxt = a.pid ? ` • PID ${a.pid}` : " • Đang tắt";
          return `<option value="${escapeHtml(val)}">${escapeHtml(`${a.name} (${a.identifier})${pidTxt}`)}</option>`;
        })
        .join("")}</optgroup>`
    );
  }
  if (procs.length) {
    groups.push(
      `<optgroup label="Tiến trình đang chạy (${procs.length})">${procs
        .slice(0, 120)
        .map((p) => `<option value="${escapeHtml(String(p.pid))}">${escapeHtml(`${p.name} (PID ${p.pid})`)}</option>`)
        .join("")}</optgroup>`
    );
  }

  if (!groups.length) {
    els.targetSelect.innerHTML = `<option value="">Không có ứng dụng/tiến trình khớp bộ lọc</option>`;
    return;
  }

  els.targetSelect.innerHTML = groups.join("");
  if (prev && Array.from(els.targetSelect.options).some((o) => o.value === prev)) {
    els.targetSelect.value = prev;
  }
}

function renderResponseList() {
  const filter = els.responseFilter.value;
  const kw = els.responseSearch.value.trim().toLowerCase();

  const filtered = state.responses.filter((item) => {
    if (filter !== "all" && item.kind !== filter) return false;
    if (!kw) return true;
    return (
      item.title.toLowerCase().includes(kw) ||
      item.meta.toLowerCase().includes(kw) ||
      item.body.toLowerCase().includes(kw)
    );
  });

  els.responseCountBadge.textContent = `${filtered.length} bản ghi`;

  if (!filtered.length) {
    els.responseList.innerHTML = `<div class="empty-state">Chưa có bản ghi nào khớp bộ lọc.</div>`;
    return;
  }

  els.responseList.innerHTML = filtered
    .slice(0, 150)
    .map(
      (item) => `
      <article class="stream-card kind-${escapeHtml(item.kind)}">
        <div class="stream-card-head">
          <strong>${escapeHtml(item.title)}</strong>
          <span>${escapeHtml(fmtTime(item.ts))}${item.meta ? ` • ${escapeHtml(item.meta)}` : ""}</span>
        </div>
        <pre class="stream-card-body">${escapeHtml(item.body)}</pre>
      </article>
    `
    )
    .join("");
}

function renderPacketList() {
  const kw = els.packetSearch.value.trim().toLowerCase();
  const filtered = state.packets.filter((p) => {
    if (!kw) return true;
    return (
      String(p.url || "").toLowerCase().includes(kw) ||
      String(p.method || "").toLowerCase().includes(kw) ||
      String(p.statusCode || "").includes(kw) ||
      String(p.responseBody || "").toLowerCase().includes(kw)
    );
  });

  els.packetCountBadge.textContent = `${filtered.length} gói tin`;

  if (!filtered.length) {
    els.packetList.innerHTML = `<div class="empty-state">Chưa bắt được gói tin nào. Bật "📡 Bắt gói tin" rồi gửi JS hoặc thao tác trong App.</div>`;
    renderSelectedPacketDetail();
    return;
  }

  els.packetList.innerHTML = filtered
    .slice()
    .reverse()
    .map((p) => {
      const code = Number(p.statusCode) || 0;
      const statusCls =
        code >= 200 && code < 400
          ? "pkt-status-2xx"
          : code >= 400 && code < 500
          ? "pkt-status-4xx"
          : "pkt-status-5xx";
      const sel = p.id === state.selectedPacketId ? "is-selected" : "";
      return `
        <div class="packet-row ${sel}" data-packet-id="${escapeHtml(String(p.id))}" role="option" aria-selected="${sel ? "true" : "false"}">
          <span class="muted-text">#${escapeHtml(String(p.id))}</span>
          <span class="pkt-method">${escapeHtml(p.method || "GET")}</span>
          <span class="${statusCls}">${code > 0 ? code : "ERR"}</span>
          <span class="pkt-url" title="${escapeHtml(p.url || "")}">${escapeHtml(p.url || "")}</span>
          <span class="muted-text">${escapeHtml(`${p.elapsedMs || 0}ms`)}</span>
        </div>
      `;
    })
    .join("");

  els.packetList.querySelectorAll(".packet-row[data-packet-id]").forEach((row) => {
    row.addEventListener("click", () => {
      state.selectedPacketId = Number(row.getAttribute("data-packet-id"));
      renderPacketList();
      renderSelectedPacketDetail();
    });
  });

  renderSelectedPacketDetail();
}

function renderSelectedPacketDetail() {
  const pkt = state.packets.find((p) => p.id === state.selectedPacketId);
  if (!pkt) {
    els.packetDetailTitle.textContent = "Chi tiết gói tin đã chọn";
    els.packetDetailBody.textContent = "Chọn một gói tin ở danh sách trên để xem đầy đủ Request/Response Headers & Body.";
    els.replayFromAppBtn.disabled = true;
    els.replayFromPcBtn.disabled = true;
    return;
  }

  els.packetDetailTitle.textContent = `#${pkt.id} • ${pkt.method} ${pkt.url} (HTTP ${pkt.statusCode || "ERR"} • ${pkt.elapsedMs || 0}ms)`;
  els.replayFromAppBtn.disabled = false;
  els.replayFromPcBtn.disabled = false;

  const sections = [
    `=== THÔNG TIN CHUNG ===`,
    `Thời gian: ${fmtTime(pkt.ts)} | Nguồn: ${pkt.replayedFromDevice ? "Gửi lại từ App" : pkt.replayedFromPc ? "Gửi lại từ PC" : pkt.target || "App"}`,
    `URL: ${pkt.method} ${pkt.url}`,
    `Mã HTTP: ${pkt.statusCode || 0}${pkt.errorText ? ` | Lỗi: ${pkt.errorText}` : ""} | Độ trễ: ${pkt.elapsedMs || 0} ms`,
    ``,
    `=== REQUEST HEADERS ===`,
    prettyJson(pkt.requestHeaders || {}),
    ``,
    `=== REQUEST BODY ===`,
    pkt.requestBody ? prettyJson(pkt.requestBody) : "(Trống)",
    ``,
    `=== RESPONSE HEADERS ===`,
    prettyJson(pkt.responseHeaders || {}),
    ``,
    `=== RESPONSE BODY ===`,
    pkt.responseBody ? prettyJson(pkt.responseBody) : "(Trống)",
  ];
  els.packetDetailBody.textContent = sections.join("\n");
}

function renderToolsStatusTable() {
  const nowStr = fmtTime(state.lastProbeAt);
  const s = state.session || {};
  const activeChannelObj = (state.hub?.channels || []).find((c) => c.id === state.hub?.activeChannel);
  const connectedChannelsCount = (state.hub?.channels || []).filter((c) => c.connected).length;
  const totalChannels = (state.hub?.channels || []).length;

  const rows = [
    {
      name: "Web GUI & REST API",
      badgeClass: state.health ? "badge-ok" : "badge-err",
      statusText: state.health ? "ONLINE" : "OFFLINE",
      detail: state.health ? `${state.health.service} (${state.health.version})` : "Không nhận được phản hồi /api/v1/health",
      updatedAt: nowStr,
    },
    {
      name: "WebSocket Realtime (/ws)",
      badgeClass: state.ws.connected ? "badge-ok" : "badge-err",
      statusText: state.ws.connected ? "ĐÃ KẾT NỐI" : "MẤT KẾT NỐI",
      detail: state.ws.connected
        ? `Ping: ${state.ws.latencyMs !== null ? `${state.ws.latencyMs} ms` : "đang đo"} • Tin cuối: ${fmtTime(state.ws.lastMessageAt)}`
        : `Đang thử kết nối lại (lần ${state.ws.reconnectAttempts})`,
      updatedAt: fmtTime(state.ws.lastMessageAt || Date.now()),
    },
    {
      name: "Frida Connection Hub",
      badgeClass: connectedChannelsCount > 0 ? "badge-ok" : "badge-warn",
      statusText: totalChannels ? `${connectedChannelsCount}/${totalChannels} KÊNH MỞ` : "CHƯA QUÉT",
      detail: activeChannelObj
        ? `Kênh chọn: ${activeChannelObj.shortLabel} (${activeChannelObj.statusBadge})`
        : "Chưa chọn kênh kết nối",
      updatedAt: nowStr,
    },
    {
      name: "Frida Server (Thiết bị)",
      badgeClass: state.fridaServerReport?.reachable ? "badge-ok" : state.fridaServerReport ? "badge-warn" : "badge-idle",
      statusText: state.fridaServerReport
        ? state.fridaServerReport.reachable
          ? "PHẢN HỒI THẬT"
          : "KHÔNG PHẢN HỒI"
        : "CHƯA ĐO",
      detail: state.fridaServerReport
        ? `${state.fridaServerReport.summary || state.fridaServerReport.message || state.fridaServerReport.deviceName || "Đã kiểm tra"}`
        : "Chọn thiết bị hoặc bấm 'Kiểm tra kết nối'",
      updatedAt: nowStr,
    },
    {
      name: "Frida Session Runtime",
      badgeClass: s.status === "running" ? "badge-ok" : s.status === "error" ? "badge-err" : "badge-idle",
      statusText: (s.status || "idle").toUpperCase(),
      detail:
        s.status === "running"
          ? `App: ${s.targetLabel || "?"} • PID ${s.pid || "?"} • Sự kiện thiết bị: ${s.executionTruth?.receivedDeviceEventsCount || 0}`
          : "Chưa móc vào ứng dụng nào",
      updatedAt: fmtTime(s.updatedAt),
    },
    {
      name: "HTTP Packet Capture Hook",
      badgeClass: s.featureSwitches?.httpCapture ? "badge-ok" : "badge-idle",
      statusText: s.featureSwitches?.httpCapture ? "ĐANG BẮT GÓI" : "ĐANG TẮT",
      detail: `Tổng gói tin thật đang lưu: ${state.packets.length} gói`,
      updatedAt: fmtTime(state.packets[state.packets.length - 1]?.ts || s.updatedAt),
    },
    {
      name: "System Logger (Realtime)",
      badgeClass: "badge-ok",
      statusText: `${state.systemLogs.length} DÒNG`,
      detail: `ERROR: ${state.systemLogs.filter((l) => l.level === "ERROR").length} • WARN: ${state.systemLogs.filter((l) => l.level === "WARN").length}`,
      updatedAt: fmtTime(state.systemLogs[0]?.timestamp),
    },
  ];

  els.toolsStatusBody.innerHTML = rows
    .map(
      (r) => `
      <tr>
        <td><strong>${escapeHtml(r.name)}</strong></td>
        <td><span class="inline-badge ${r.badgeClass}">${escapeHtml(r.statusText)}</span></td>
        <td class="mono-cell">${escapeHtml(r.detail)}</td>
        <td class="mono-cell muted-text">${escapeHtml(r.updatedAt)}</td>
      </tr>
    `
    )
    .join("");
}

function renderSystemLogsTable() {
  const levelFilter = els.toolLogLevelFilter.value;
  const kw = els.toolLogSearch.value.trim().toLowerCase();

  const filtered = state.systemLogs.filter((entry) => {
    if (levelFilter !== "all" && String(entry.level || "").toUpperCase() !== levelFilter) return false;
    if (!kw) return true;
    return (
      String(entry.message || "").toLowerCase().includes(kw) ||
      String(entry.location || "").toLowerCase().includes(kw) ||
      String(entry.traceId || "").toLowerCase().includes(kw)
    );
  });

  if (!filtered.length) {
    els.systemLogsBody.innerHTML = `<tr><td colspan="4" class="muted-text">Chưa có dòng nhật ký hệ thống nào khớp bộ lọc.</td></tr>`;
    return;
  }

  els.systemLogsBody.innerHTML = filtered
    .slice(0, 120)
    .map((entry) => {
      const lv = String(entry.level || "INFO").toUpperCase();
      const cls = lv === "ERROR" ? "badge-err" : lv === "WARN" ? "badge-warn" : "badge-ok";
      return `
        <tr>
          <td class="mono-cell muted-text">${escapeHtml(fmtTime(entry.timestamp))}</td>
          <td><span class="inline-badge ${cls}">${escapeHtml(lv)}</span></td>
          <td class="mono-cell muted-text">${escapeHtml(entry.location || "-")} ${entry.traceId ? `(${escapeHtml(entry.traceId)})` : ""}</td>
          <td class="mono-cell">${escapeHtml(entry.message || "")}</td>
        </tr>
      `;
    })
    .join("");
}

// ============================================================================
// ACTIONS & REALTIME DATA SYNC
// ============================================================================
async function refreshHealthAndConnections({ silent = false } = {}) {
  state.lastProbeAt = Date.now();
  try {
    const h = await apiRequest("GET", "/api/v1/health");
    state.health = h.data;
    state.session = h.data.session || state.session;
    els.serverVersionPill.textContent = h.data.version || "live";
    renderSessionHeader();
  } catch {
    state.health = null;
    els.serverVersionPill.textContent = "OFFLINE";
  }

  try {
    const devId = els.deviceSelect.value || "";
    const qs = devId ? `?deviceId=${encodeURIComponent(devId)}` : "";
    const c = await apiRequest("GET", `/api/v1/connections/status${qs}`);
    state.hub = c.data.hub;
    els.connectionUpdatedAt.textContent = `Đo thật lúc ${fmtTime(Date.now())}`;
    renderChannelCards();
  } catch (err) {
    if (!silent) showToast(`Không đo được kênh kết nối: ${err.message}`, "err");
  }

  try {
    const devId = els.deviceSelect.value || "";
    const qs = devId ? `?deviceId=${encodeURIComponent(devId)}` : "";
    const f = await apiRequest("GET", `/api/v1/frida-server/status${qs}`);
    state.fridaServerReport = f.data.report;
  } catch {
    state.fridaServerReport = null;
  }

  els.lastProbeBadge.textContent = `Cập nhật thật: ${fmtTime(state.lastProbeAt)}`;
  renderToolsStatusTable();
}

async function switchConnectionChannel(channelId) {
  try {
    const out = await apiRequest(
      "POST",
      "/api/v1/connections/switch",
      { channel: channelId, deviceId: els.deviceSelect.value || "" },
      { logToResponse: true, label: `Đổi kênh kết nối (${channelId})` }
    );
    showToast(`Đã chuyển kênh sang ${channelId}`, "ok");
    if (out.data?.session) {
      state.session = out.data.session;
      renderSessionHeader();
    }
    await refreshDevicesAndTargets();
    await refreshHealthAndConnections({ silent: true });
  } catch (err) {
    showToast(`Đổi kênh thất bại: ${err.message}`, "err");
  }
}

async function refreshDevicesAndTargets() {
  try {
    const res = await apiRequest("GET", "/api/v1/devices");
    state.devices = res.data.devices || [];
    renderDeviceSelect();
    if (els.deviceSelect.value) {
      await loadTargetsForDevice(els.deviceSelect.value);
    }
  } catch (err) {
    showToast(`Không tải được danh sách thiết bị: ${err.message}`, "err");
  }
}

async function loadTargetsForDevice(deviceId) {
  if (!deviceId) {
    state.targets = { apps: [], processes: [] };
    renderTargetSelect();
    return;
  }
  els.targetSelect.innerHTML = `<option value="">Đang tải ứng dụng trên thiết bị...</option>`;
  try {
    const res = await apiRequest("GET", `/api/v1/devices/${encodeURIComponent(deviceId)}/targets`);
    state.targets = {
      apps: res.data.apps || [],
      processes: res.data.processes || [],
    };
    renderTargetSelect();
  } catch (err) {
    state.targets = { apps: [], processes: [] };
    renderTargetSelect();
    showToast(`Không đọc được danh sách App: ${err.message}`, "err");
  }
}

async function loadSnippets() {
  try {
    const res = await apiRequest("GET", "/api/v1/snippets");
    state.snippets = res.data.snippets || [];
    els.snippetSelect.innerHTML =
      `<option value="">-- Nạp mẫu JS từ kho (${state.snippets.length}) --</option>` +
      state.snippets
        .map((s) => `<option value="${escapeHtml(s.id)}">${escapeHtml(`[${s.category || "JS"}] ${s.displayTitle || s.title}`)}</option>`)
        .join("");
  } catch {
    // Giữ trạng thái trống trung thực
  }
}

async function loadInitialStreams() {
  try {
    const [evRes, pktRes, sysRes] = await Promise.all([
      apiRequest("GET", "/api/v1/event-logs?limit=80"),
      apiRequest("GET", "/api/v1/http-exchanges?limit=200"),
      apiRequest("GET", "/api/v1/system-logs?limit=120"),
    ]);

    const events = evRes.data.items || [];
    for (const ev of events) {
      state.responses.unshift({
        id: `ev-${ev.id}`,
        ts: ev.ts || Date.now(),
        kind: ev.level === "error" ? "error" : ev.source === "send" ? "send" : "console",
        title: `[Frida ${ev.source || "event"}]${ev.pid ? ` PID ${ev.pid}` : ""}`,
        meta: ev.level || "info",
        body: ev.details ? `${ev.text}\n${prettyJson(ev.details)}` : ev.text || "",
      });
    }
    renderResponseList();

    state.packets = pktRes.data.items || [];
    renderPacketList();

    state.systemLogs = (sysRes.data.items || []).slice().reverse();
    renderSystemLogsTable();
    renderToolsStatusTable();
  } catch {
    // Bỏ qua nếu máy chủ chưa sẵn sàng
  }
}

async function attachToTargetApp() {
  const deviceId = els.deviceSelect.value;
  const target = els.targetSelect.value;
  if (!deviceId || !target) {
    showToast("Vui lòng chọn Thiết bị và Ứng dụng mục tiêu trước khi móc!", "err");
    return;
  }

  const bootstrapCode =
    els.jsEditor.value.trim() ||
    `console.log('[Móc App] Đã gắn phiên Frida vào tiến trình PID ' + Process.id);\nsend({ type: 'attached', pid: Process.id, arch: Process.arch });`;

  try {
    els.attachAppBtn.disabled = true;
    const out = await apiRequest(
      "POST",
      "/api/v1/sessions",
      {
        deviceId,
        mode: state.mode,
        target,
        code: bootstrapCode,
        enableObjCBridge: els.objcBridgeChk.checked,
      },
      { logToResponse: true, label: `Móc vào App (${state.mode}: ${target})` }
    );
    state.session = out.data.session;
    renderSessionHeader();
    renderToolsStatusTable();
    showToast(`Đã móc thành công vào ${state.session?.targetLabel || target} (PID ${state.session?.pid})`, "ok");
  } catch (err) {
    showToast(`Móc vào App thất bại: ${err.message}`, "err");
  } finally {
    els.attachAppBtn.disabled = false;
  }
}

async function sendJsToFrida() {
  const deviceId = els.deviceSelect.value || state.session?.deviceId;
  const target = els.targetSelect.value || state.session?.targetLabel;
  const code = els.jsEditor.value.trim();

  if (!code) {
    showToast("Vui lòng nhập mã JavaScript trước khi gửi!", "err");
    return;
  }
  if (!deviceId || !target) {
    showToast("Vui lòng chọn Thiết bị và Ứng dụng mục tiêu để gửi JS!", "err");
    return;
  }

  try {
    els.sendJsBtn.disabled = true;
    const out = await apiRequest(
      "POST",
      "/api/v1/sessions",
      {
        deviceId,
        mode: state.mode,
        target,
        code,
        enableObjCBridge: els.objcBridgeChk.checked,
      },
      { logToResponse: true, label: `Gửi JS vào Frida (${target})` }
    );
    state.session = out.data.session;
    renderSessionHeader();

    if (els.autoCaptureAfterSendChk.checked && !state.session?.featureSwitches?.httpCapture) {
      try {
        const cap = await apiRequest(
          "POST",
          "/api/v1/http-capture/enable",
          { deviceId, target, mode: state.mode },
          { logToResponse: true, label: "Tự động bật Bắt gói tin HTTP" }
        );
        if (cap.data?.session) {
          state.session = cap.data.session;
          renderSessionHeader();
        }
      } catch {
        // Không làm hỏng luồng gửi JS nếu tiến trình mục tiêu chưa có ObjC NSURLSession
      }
    }

    renderToolsStatusTable();
    showToast("Đã gửi và thực thi mã JS trên Frida!", "ok");
  } catch (err) {
    showToast(`Gửi JS thất bại: ${err.message}`, "err");
  } finally {
    els.sendJsBtn.disabled = false;
  }
}

async function enableHttpPacketCapture() {
  const deviceId = els.deviceSelect.value || state.session?.deviceId || "";
  const target = els.targetSelect.value || state.session?.targetLabel || "";
  try {
    els.enableCaptureBtn.disabled = true;
    const out = await apiRequest(
      "POST",
      "/api/v1/http-capture/enable",
      { deviceId, target, mode: state.mode },
      { logToResponse: true, label: "Bật hook Bắt gói tin HTTP" }
    );
    state.session = out.data.session;
    renderSessionHeader();
    renderToolsStatusTable();
    showToast(out.data?.capture?.message || "Đã bật bắt gói tin HTTP!", "ok");
  } catch (err) {
    showToast(`Không bật được bắt gói tin: ${err.message}`, "err");
  } finally {
    els.enableCaptureBtn.disabled = false;
  }
}

async function detachSession() {
  try {
    const out = await apiRequest("DELETE", "/api/v1/sessions/current", null, {
      logToResponse: true,
      label: "Ngắt phiên Frida",
    });
    state.session = out.data.session;
    renderSessionHeader();
    renderToolsStatusTable();
    showToast("Đã ngắt phiên Frida an toàn.", "ok");
  } catch (err) {
    showToast(`Lỗi khi ngắt phiên: ${err.message}`, "err");
  }
}

async function callRpcExport() {
  const method = els.rpcMethodInput.value.trim();
  if (!method) {
    showToast("Nhập tên hàm trong rpc.exports trước khi gọi!", "err");
    return;
  }
  let args = [];
  const rawArgs = els.rpcArgsInput.value.trim();
  if (rawArgs) {
    try {
      const parsed = JSON.parse(rawArgs);
      args = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      showToast("Tham số RPC phải là JSON hợp lệ (VD: [\"arg1\", 123])", "err");
      return;
    }
  }
  try {
    await apiRequest(
      "POST",
      "/api/v1/sessions/rpc-calls",
      { method, args },
      { logToResponse: true, label: `Gọi RPC ${method}()` }
    );
    showToast(`Đã gọi RPC ${method}() thành công`, "ok");
  } catch (err) {
    showToast(`Gọi RPC lỗi: ${err.message}`, "err");
  }
}

async function replaySelectedPacket(viaDevice) {
  const pkt = state.packets.find((p) => p.id === state.selectedPacketId);
  if (!pkt) return;
  try {
    await apiRequest(
      "POST",
      "/api/v1/http-repeater/send",
      {
        viaDevice,
        method: pkt.method,
        url: pkt.url,
        headers: pkt.requestHeaders || {},
        body: pkt.requestBody || "",
      },
      { logToResponse: true, label: `Gửi lại gói #${pkt.id} (${viaDevice ? "từ App" : "từ PC"})` }
    );
    showToast(`Đã gửi lại gói tin #${pkt.id}`, "ok");
  } catch (err) {
    showToast(`Gửi lại gói tin thất bại: ${err.message}`, "err");
  }
}

// ============================================================================
// WEBSOCKET REALTIME HUB
// ============================================================================
let wsClient = null;
let wsPingTimer = null;
let wsPingSentAt = 0;

function updateWsIndicator() {
  if (state.ws.connected) {
    els.wsDot.className = "dot dot-online";
    els.wsStatusLabel.textContent = `WebSocket: Đã kết nối${state.ws.latencyMs !== null ? ` (${state.ws.latencyMs} ms)` : ""}`;
  } else {
    els.wsDot.className = "dot dot-offline";
    els.wsStatusLabel.textContent = "WebSocket: Mất kết nối (đang tự kết nối lại...)";
  }
  renderToolsStatusTable();
}

function connectWebSocket() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${proto}//${location.host}/ws`;
  wsClient = new WebSocket(wsUrl);

  wsClient.addEventListener("open", () => {
    state.ws.connected = true;
    state.ws.reconnectAttempts = 0;
    state.ws.lastMessageAt = Date.now();
    updateWsIndicator();

    const sendPing = () => {
      if (wsClient && wsClient.readyState === WebSocket.OPEN) {
        wsPingSentAt = performance.now();
        wsClient.send(JSON.stringify({ event: "ping" }));
      }
    };
    sendPing();
    clearInterval(wsPingTimer);
    wsPingTimer = setInterval(sendPing, 12_000);
  });

  wsClient.addEventListener("message", (evt) => {
    state.ws.lastMessageAt = Date.now();
    let msg;
    try {
      msg = JSON.parse(evt.data);
    } catch {
      return;
    }

    const { event, payload } = msg;
    if (event === "pong") {
      if (wsPingSentAt > 0) {
        state.ws.latencyMs = Math.max(1, Math.round(performance.now() - wsPingSentAt));
        updateWsIndicator();
      }
      return;
    }

    if (event === "session:state") {
      state.session = payload;
      renderSessionHeader();
      renderToolsStatusTable();
      return;
    }

    if (event === "session:switches" && state.session) {
      state.session.featureSwitches = payload?.switches || state.session.featureSwitches;
      renderSessionHeader();
      renderToolsStatusTable();
      return;
    }

    if (event === "script:event") {
      const kind = payload.level === "error" ? "error" : payload.source === "send" ? "send" : "console";
      pushResponseRecord({
        kind,
        title: `[Frida ${payload.source || "event"}]${payload.pid ? ` PID ${payload.pid}` : ""}`,
        meta: payload.level || "info",
        body: payload.details ? `${payload.text}\n${prettyJson(payload.details)}` : payload.text || "",
      });
      return;
    }

    if (event === "http:exchange") {
      state.packets.push(payload);
      if (state.packets.length > 300) state.packets.shift();
      if (!state.selectedPacketId) state.selectedPacketId = payload.id;
      renderPacketList();
      renderToolsStatusTable();
      return;
    }

    if (event === "http:cleared") {
      state.packets = [];
      state.selectedPacketId = null;
      renderPacketList();
      renderToolsStatusTable();
      return;
    }

    if (event === "system:log") {
      state.systemLogs.unshift(payload);
      if (state.systemLogs.length > 250) state.systemLogs.length = 250;
      renderSystemLogsTable();
      renderToolsStatusTable();
    }
  });

  wsClient.addEventListener("close", () => {
    state.ws.connected = false;
    state.ws.reconnectAttempts += 1;
    clearInterval(wsPingTimer);
    updateWsIndicator();
    setTimeout(connectWebSocket, Math.min(5000, 1000 * state.ws.reconnectAttempts));
  });
}

// ============================================================================
// WIRE EVENTS & INIT
// ============================================================================
function updateEditorStats() {
  const val = els.jsEditor.value;
  const lines = val ? val.split("\n").length : 0;
  els.editorStats.textContent = `${lines} dòng • ${val.length} ký tự`;
}

function bindEvents() {
  els.probeConnectionsBtn.addEventListener("click", () => {
    void refreshHealthAndConnections();
    showToast("Đã quét lại trạng thái kết nối thực tế.", "ok");
  });

  els.repairFridaBtn.addEventListener("click", async () => {
    try {
      els.repairFridaBtn.disabled = true;
      const out = await apiRequest(
        "POST",
        "/api/v1/frida-server/repair",
        { deviceId: els.deviceSelect.value || "" },
        { logToResponse: true, label: "Làm sạch & kết nối lại Frida" }
      );
      if (out.data?.session) state.session = out.data.session;
      renderSessionHeader();
      await refreshHealthAndConnections({ silent: true });
      showToast("Đã làm sạch kết nối Frida hoàn tất.", "ok");
    } catch (err) {
      showToast(`Làm sạch Frida thất bại: ${err.message}`, "err");
    } finally {
      els.repairFridaBtn.disabled = false;
    }
  });

  els.refreshDevicesBtn.addEventListener("click", () => void refreshDevicesAndTargets());
  els.deviceSelect.addEventListener("change", () => {
    void loadTargetsForDevice(els.deviceSelect.value);
    void refreshHealthAndConnections({ silent: true });
  });
  els.targetFilter.addEventListener("input", renderTargetSelect);

  els.modeButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      state.mode = btn.getAttribute("data-mode") || "auto";
      els.modeButtons.forEach((b) => b.classList.toggle("active", b === btn));
    });
  });

  els.attachAppBtn.addEventListener("click", () => void attachToTargetApp());
  els.enableCaptureBtn.addEventListener("click", () => void enableHttpPacketCapture());
  els.detachAppBtn.addEventListener("click", () => void detachSession());

  els.snippetSelect.addEventListener("change", () => {
    const found = state.snippets.find((s) => s.id === els.snippetSelect.value);
    if (found?.code) {
      els.jsEditor.value = found.code;
      updateEditorStats();
    }
  });

  els.insertStarterBtn.addEventListener("click", () => {
    els.jsEditor.value = STARTER_FRIDA_17_SCRIPT;
    updateEditorStats();
  });

  els.jsEditor.addEventListener("input", updateEditorStats);
  els.jsEditor.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      void sendJsToFrida();
    } else if (e.key === "Tab") {
      e.preventDefault();
      const start = els.jsEditor.selectionStart;
      const end = els.jsEditor.selectionEnd;
      els.jsEditor.value = `${els.jsEditor.value.slice(0, start)}  ${els.jsEditor.value.slice(end)}`;
      els.jsEditor.selectionStart = els.jsEditor.selectionEnd = start + 2;
      updateEditorStats();
    }
  });

  els.clearEditorBtn.addEventListener("click", () => {
    els.jsEditor.value = "";
    updateEditorStats();
  });

  els.saveSnippetBtn.addEventListener("click", async () => {
    const code = els.jsEditor.value.trim();
    if (!code) {
      showToast("Chưa có mã JS để lưu mẫu!", "err");
      return;
    }
    const title = window.prompt("Nhập tên kịch bản JS cần lưu:");
    if (!title || !title.trim()) return;
    try {
      await apiRequest(
        "POST",
        "/api/v1/snippets",
        { title: title.trim(), category: "Tự tạo", code },
        { logToResponse: true, label: `Lưu mẫu JS "${title.trim()}"` }
      );
      await loadSnippets();
      showToast(`Đã lưu mẫu "${title.trim()}" vào kho!`, "ok");
    } catch (err) {
      showToast(`Lưu mẫu thất bại: ${err.message}`, "err");
    }
  });

  els.sendJsBtn.addEventListener("click", () => void sendJsToFrida());
  els.callRpcBtn.addEventListener("click", () => void callRpcExport());

  els.responseFilter.addEventListener("change", renderResponseList);
  els.responseSearch.addEventListener("input", renderResponseList);
  els.copyLatestResponseBtn.addEventListener("click", async () => {
    const first = state.responses[0];
    if (!first) return;
    await navigator.clipboard.writeText(first.body).catch(() => {});
    showToast("Đã sao chép phản hồi gần nhất vào Clipboard.", "ok");
  });
  els.clearResponseBtn.addEventListener("click", async () => {
    state.responses = [];
    renderResponseList();
    await apiRequest("DELETE", "/api/v1/event-logs").catch(() => {});
  });

  els.packetSearch.addEventListener("input", renderPacketList);
  els.clearPacketsBtn.addEventListener("click", async () => {
    await apiRequest("DELETE", "/api/v1/http-exchanges").catch(() => {});
    state.packets = [];
    state.selectedPacketId = null;
    renderPacketList();
    renderToolsStatusTable();
  });
  els.replayFromAppBtn.addEventListener("click", () => void replaySelectedPacket(true));
  els.replayFromPcBtn.addEventListener("click", () => void replaySelectedPacket(false));

  els.toolLogLevelFilter.addEventListener("change", renderSystemLogsTable);
  els.toolLogSearch.addEventListener("input", renderSystemLogsTable);
  els.clearSystemLogsBtn.addEventListener("click", async () => {
    await apiRequest("DELETE", "/api/v1/system-logs").catch(() => {});
    state.systemLogs = [];
    renderSystemLogsTable();
    renderToolsStatusTable();
  });
}

async function init() {
  els.jsEditor.value = STARTER_FRIDA_17_SCRIPT;
  updateEditorStats();
  bindEvents();
  connectWebSocket();

  await Promise.all([
    refreshDevicesAndTargets(),
    loadSnippets(),
    loadInitialStreams(),
  ]);
  await refreshHealthAndConnections({ silent: true });

  setInterval(() => {
    void refreshHealthAndConnections({ silent: true });
  }, 10_000);
}

void init();

