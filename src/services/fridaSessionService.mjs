// src/services/fridaSessionService.mjs — Quản lý Phiên Frida, Bảng Lịch Sử Log, Bắt Gói Tin + Hộp Trả Lời & Gửi Lại Gói Tin (Repeater)
import { logger } from "../infra/logger.mjs";

const MAX_EVENT_HISTORY = 1000;
const MAX_HTTP_EXCHANGES = 300;
const ALLOWED_HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const ALLOWED_FEATURE_SWITCHES = new Set([
  "httpCapture",
  "storekitObserver",
  "authObserver",
  "storageObserver",
  "fileAccessObserver",
  "uiScreenObserver",
]);

function createDefaultFeatureSwitches() {
  return {
    httpCapture: false,
    storekitObserver: false,
    authObserver: false,
    storageObserver: false,
    fileAccessObserver: false,
    uiScreenObserver: false,
  };
}

function assertSafePcReplayUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Đường dẫn URL không hợp lệ. Vui lòng nhập đầy đủ bắt đầu bằng https:// hoặc http://");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Chỉ hỗ trợ giao thức http:// hoặc https://");
  }

  const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const isBlockedLocal =
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "::" ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(host) ||
    /^f[cd][0-9a-f]{2}:/i.test(host) ||
    /^fe80:/i.test(host);

  if (isBlockedLocal) {
    throw new Error(
      "Chế độ Gửi từ Máy tính chặn địa chỉ mạng nội bộ / localhost để bảo vệ an toàn (SSRF). Vui lòng nhập địa chỉ máy chủ API bên ngoài hoặc gửi từ trong ứng dụng iPhone."
    );
  }

  return parsed.toString();
}

export class FridaSessionService {
  #bridge;
  #emit;
  #compiler;
  #activeSession = null;
  #activeScript = null;
  #eventHistory = [];
  #eventSeq = 1;
  #httpExchanges = [];
  #httpSeq = 1;
  #featureSwitches = createDefaultFeatureSwitches();
  #state = {
    status: "idle", // idle | connecting | running | error
    deviceId: null,
    mode: "attach",
    targetLabel: null,
    pid: null,
    enableObjCBridge: true,
    receivedDeviceEventsCount: 0,
    lastDeviceOutputAt: null,
    startedAt: null,
    updatedAt: Date.now(),
  };

  constructor({ bridge, emit, compiler = null }) {
    this.#bridge = bridge;
    this.#emit = emit;
    this.#compiler = compiler;
  }

  getFeatureSwitches() {
    return { ...this.#featureSwitches };
  }

  getStatus() {
    const isRunning = this.#state.status === "running" && Boolean(this.#state.pid);
    return {
      ...this.#state,
      featureSwitches: { ...this.#featureSwitches },
      executionTruth: {
        attachedToProcess: isRunning,
        pid: this.#state.pid,
        receivedDeviceEventsCount: this.#state.receivedDeviceEventsCount || 0,
        awaitingDeviceInteraction: isRunning && (this.#state.receivedDeviceEventsCount || 0) === 0,
        lastDeviceOutputAt: this.#state.lastDeviceOutputAt || null,
      },
    };
  }

  queryEventLogs({ level = "", search = "", page = 1, limit = 200 } = {}) {
    const lv = String(level || "").toLowerCase();
    const kw = String(search || "").trim().toLowerCase();
    const safePage = Math.max(1, Number(page) || 1);
    const safeLimit = Math.min(500, Math.max(1, Number(limit) || 200));

    const filtered = this.#eventHistory.filter((row) => {
      if (lv && lv !== "all" && row.level !== lv) return false;
      if (!kw) return true;
      return (
        row.text.toLowerCase().includes(kw) ||
        row.source.toLowerCase().includes(kw) ||
        String(row.pid || "").includes(kw) ||
        JSON.stringify(row.details || "").toLowerCase().includes(kw)
      );
    });

    const totalItems = filtered.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / safeLimit));
    const start = Math.max(0, totalItems - safePage * safeLimit);
    const end = totalItems - (safePage - 1) * safeLimit;
    const items = filtered.slice(start, Math.max(0, end));

    return {
      items,
      meta: {
        page: safePage,
        limit: safeLimit,
        totalItems,
        totalPages,
      },
    };
  }

  clearEventLogs() {
    this.#eventHistory.length = 0;
    this.#emit("script:cleared", { ts: Date.now() });
  }

  listHttpExchanges({ search = "", limit = 200 } = {}) {
    const kw = String(search || "").trim().toLowerCase();
    const safeLimit = Math.min(300, Math.max(1, Number(limit) || 200));

    const filtered = this.#httpExchanges.filter((item) => {
      if (!kw) return true;
      return (
        String(item.url || "").toLowerCase().includes(kw) ||
        String(item.method || "").toLowerCase().includes(kw) ||
        String(item.statusCode || "").includes(kw) ||
        String(item.responseBody || "").toLowerCase().includes(kw) ||
        String(item.requestBody || "").toLowerCase().includes(kw)
      );
    });

    const items = filtered.slice(-safeLimit);
    return {
      items,
      meta: {
        page: 1,
        limit: safeLimit,
        totalItems: filtered.length,
        totalPages: 1,
      },
    };
  }

  clearHttpExchanges() {
    this.#httpExchanges.length = 0;
    this.#emit("http:cleared", { ts: Date.now() });
  }

  importExternalPackets(rawPackets = [], sourceLabel = "RabbitUltrad (8765)") {
    if (!Array.isArray(rawPackets) || rawPackets.length === 0) {
      return { importedCount: 0, items: [] };
    }
    const existingSigs = new Set(
      this.#httpExchanges.map((x) => `${x.method}|${x.url}|${x.statusCode}|${(x.responseBody || "").slice(0, 64)}`)
    );
    const imported = [];
    for (const pkt of rawPackets.slice(-120)) {
      const url = String(pkt?.url || pkt?.requestUrl || pkt?.endpoint || "").trim();
      if (!url) continue;
      const method = String(pkt?.method || "GET").toUpperCase();
      const statusCode = Number(pkt?.statusCode ?? pkt?.status ?? 200) || 0;
      const respBody =
        typeof pkt?.responseBody === "string"
          ? pkt.responseBody
          : typeof pkt?.response === "string"
          ? pkt.response
          : pkt?.response
          ? JSON.stringify(pkt.response, null, 2)
          : "";
      const sig = `${method}|${url}|${statusCode}|${respBody.slice(0, 64)}`;
      if (existingSigs.has(sig)) continue;
      existingSigs.add(sig);

      const rec = this.#recordHttpExchange({
        target: pkt?.bundleId || pkt?.app || sourceLabel,
        method,
        url,
        requestHeaders: pkt?.requestHeaders || pkt?.headers || {},
        requestBody:
          typeof pkt?.requestBody === "string"
            ? pkt.requestBody
            : pkt?.body
            ? typeof pkt.body === "string"
              ? pkt.body
              : JSON.stringify(pkt.body, null, 2)
            : "",
        statusCode,
        responseHeaders: pkt?.responseHeaders || {},
        responseBody: respBody,
        elapsedMs: Number(pkt?.elapsedMs || pkt?.durationMs || 0),
      });
      imported.push(rec);
    }
    return { importedCount: imported.length, items: imported };
  }

  #recordHttpExchange(raw = {}, overridePid = null) {
    const record = {
      id: this.#httpSeq++,
      ts: Date.now(),
      pid: overridePid ?? this.#state.pid ?? null,
      target: raw.target ?? this.#state.targetLabel ?? "Ứng dụng",
      method: String(raw.method || "GET").toUpperCase(),
      url: String(raw.url || ""),
      requestHeaders: raw.requestHeaders && typeof raw.requestHeaders === "object" ? raw.requestHeaders : {},
      requestBody: String(raw.requestBody ?? ""),
      statusCode: Number(raw.statusCode) || 0,
      responseHeaders: raw.responseHeaders && typeof raw.responseHeaders === "object" ? raw.responseHeaders : {},
      responseBody: String(raw.responseBody ?? ""),
      elapsedMs: Math.max(0, Number(raw.elapsedMs) || 0),
      errorText: String(raw.errorText ?? ""),
      replayedFromDevice: Boolean(raw.replayedFromDevice),
      replayedFromPc: Boolean(raw.replayedFromPc),
    };

    this.#httpExchanges.push(record);
    if (this.#httpExchanges.length > MAX_HTTP_EXCHANGES) {
      this.#httpExchanges.shift();
    }

    this.#emit("http:exchange", record);

    const originTag = record.replayedFromDevice
      ? "GỬI LẠI TỪ APP"
      : record.replayedFromPc
      ? "GỬI LẠI TỪ PC"
      : "GÓI MẠNG BẮT ĐƯỢC";
    const statusTag = record.statusCode > 0 ? `HTTP ${record.statusCode}` : record.errorText ? "LỖI MẠNG" : "ĐÃ NHẬN";
    this.#pushOutput(
      record.errorText && record.statusCode === 0 ? "warning" : "send",
      "send",
      `[${originTag} • ${statusTag} • ${record.elapsedMs} ms] ${record.method} ${record.url}` +
        (record.responseBody ? `\n↳ Hộp trả lời: ${record.responseBody.slice(0, 260)}${record.responseBody.length > 260 ? " ..." : ""}` : ""),
      record,
      record.pid
    );

    return record;
  }

  async enableHttpCapture({ deviceId, target, mode = "auto" } = {}) {
    const cleanTarget = String(target || this.#state.targetLabel || "").trim();
    const cleanDeviceId = String(deviceId || this.#state.deviceId || "").trim();
    const hasSameLiveSession =
      this.#activeSession &&
      !this.#activeSession.isDetached() &&
      this.#activeScript &&
      !this.#activeScript.isDestroyed &&
      (!cleanTarget || this.#state.targetLabel === cleanTarget);

    if (!hasSameLiveSession) {
      if (!cleanDeviceId || !cleanTarget) {
        throw new Error("Vui lòng chọn Ứng dụng ở Bước 2 phía trên trước khi bật bắt gói tin.");
      }
      const autoSnifferCode = [
        "// ============================================================================",
        "// TỰ ĐỘNG BẬT BẮT GÓI TIN & HỘP TRẢ LỜI (HTTP REQUEST + RESPONSE)",
        "// Hãy cầm iPhone thao tác trong ứng dụng — Gói tin và Hộp trả lời sẽ tự hiện lên!",
        "// ============================================================================",
        "if (typeof globalThis.__studioEnableHttpCapture === 'function') {",
        "  const kq = globalThis.__studioEnableHttpCapture();",
        "  console.log('[+] ' + kq.message);",
        "} else {",
        "  console.warn('[!] Chưa khởi tạo được cầu nối bắt gói tin trên tiến trình này.');",
        "}",
      ].join("\n");

      await this.runScript({
        deviceId: cleanDeviceId,
        mode: mode || "auto",
        target: cleanTarget,
        code: autoSnifferCode,
        enableObjCBridge: true,
      });

      let captureMeta = {
        enabled: true,
        message: "Đã gắn vào ứng dụng & bật bắt Gói tin + Hộp trả lời! Hãy bấm thao tác trên iPhone.",
      };
      try {
        const rpcCheck = await this.callRpcExport("__studioEnableHttpCapture", []);
        if (rpcCheck?.result && typeof rpcCheck.result === "object") {
          captureMeta = rpcCheck.result;
        }
      } catch (err) {
        logger.warn("Không đọc lại được trạng thái xác nhận __studioEnableHttpCapture", {
          target: cleanTarget,
          reason: err?.message,
        });
      }

      this.#featureSwitches.httpCapture = Boolean(captureMeta?.enabled ?? true);
      this.#emit("session:switches", { switches: this.getFeatureSwitches() });
      this.#emit("session:state", this.getStatus());

      return {
        capture: captureMeta,
        session: this.getStatus(),
      };
    }

    const { result } = await this.callRpcExport("__studioEnableHttpCapture", []);
    this.#featureSwitches.httpCapture = Boolean(result?.enabled ?? true);
    this.#emit("session:switches", { switches: this.getFeatureSwitches() });
    this.#emit("session:state", this.getStatus());
    if (result?.message) {
      this.#pushOutput("info", "system", `[Bắt gói tin] ${result.message}`);
    }
    return {
      capture: result,
      session: this.getStatus(),
    };
  }

  async toggleFeatureSwitch({ deviceId, target, mode = "auto", featureKey, enabled } = {}) {
    const cleanKey = String(featureKey || "").trim();
    if (!ALLOWED_FEATURE_SWITCHES.has(cleanKey)) {
      throw new Error(`Tên công tắc tính năng '${cleanKey}' không hợp lệ.`);
    }
    const wantEnabled = Boolean(enabled);
    const cleanTarget = String(target || this.#state.targetLabel || "").trim();
    const cleanDeviceId = String(deviceId || this.#state.deviceId || "").trim();

    const hasSameLiveSession =
      Boolean(this.#activeSession) &&
      !this.#activeSession.isDetached() &&
      Boolean(this.#activeScript) &&
      !this.#activeScript.isDestroyed &&
      (!cleanTarget || this.#state.targetLabel === cleanTarget);

    if (!hasSameLiveSession) {
      if (!wantEnabled) {
        this.#featureSwitches[cleanKey] = false;
        this.#emit("session:switches", { switches: this.getFeatureSwitches() });
        this.#emit("session:state", this.getStatus());
        return {
          switchResult: {
            featureKey: cleanKey,
            enabled: false,
            switches: this.getFeatureSwitches(),
            message: "Công tắc hiện đang ở trạng thái tắt.",
          },
          switches: this.getFeatureSwitches(),
          session: this.getStatus(),
        };
      }

      if (!cleanDeviceId || !cleanTarget) {
        throw new Error("Vui lòng chọn Ứng dụng ở Bước 2 phía trên trước khi bật Công tắc 1 chạm.");
      }

      const bootstrapSwitchCode = [
        "// ============================================================================",
        "// TRẠM CÔNG TẮC 1 CHẠM (CHẾ ĐỘ QUAN SÁT CHỈ ĐỌC AN TOÀN)",
        "// Bạn có thể bật/tắt nhiều công tắc cùng lúc ngay trên giao diện mà không cần gõ mã!",
        "// ============================================================================",
        `console.log('[Công tắc 1 chạm] Đã gắn kết nối quan sát vào ứng dụng — đang kích hoạt công tắc: ${cleanKey}');`,
      ].join("\n");

      await this.runScript({
        deviceId: cleanDeviceId,
        mode: mode || "auto",
        target: cleanTarget,
        code: bootstrapSwitchCode,
        enableObjCBridge: true,
      });
    }

    const { result } = await this.callRpcExport("__studioSetFeatureSwitch", [cleanKey, wantEnabled]);
    if (result?.switches && typeof result.switches === "object") {
      this.#featureSwitches = {
        ...createDefaultFeatureSwitches(),
        ...result.switches,
      };
    } else {
      this.#featureSwitches[cleanKey] = Boolean(result?.enabled ?? wantEnabled);
    }

    if (result?.message) {
      this.#pushOutput("info", "system", `[Công tắc 1 chạm] ${result.message}`);
    }

    this.#emit("session:switches", { switches: this.getFeatureSwitches() });
    this.#emit("session:state", this.getStatus());

    return {
      switchResult: result,
      switches: this.getFeatureSwitches(),
      session: this.getStatus(),
    };
  }

  async replayHttpRequest({ method = "GET", url, headers = {}, body = "", sendFrom = "auto" } = {}) {
    const cleanMethod = String(method || "GET").trim().toUpperCase();
    if (!ALLOWED_HTTP_METHODS.has(cleanMethod)) {
      throw new Error(`Phương thức HTTP '${cleanMethod}' không hợp lệ.`);
    }

    const cleanUrl = String(url ?? "").trim();
    if (!cleanUrl) {
      throw new Error("Vui lòng nhập đường dẫn URL gói tin cần gửi.");
    }
    if (!/^https?:\/\//i.test(cleanUrl)) {
      throw new Error("Đường dẫn URL phải bắt đầu bằng https:// hoặc http://");
    }

    const cleanHeaders = {};
    if (headers && typeof headers === "object" && !Array.isArray(headers)) {
      for (const [k, v] of Object.entries(headers)) {
        const keyTrim = String(k || "").trim();
        if (keyTrim && v !== undefined && v !== null) {
          cleanHeaders[keyTrim] = String(v);
        }
      }
    } else {
      throw new Error("Tiêu đề gói tin (Headers) phải là đối tượng JSON hợp lệ.");
    }

    const cleanBody = body === undefined || body === null ? "" : typeof body === "string" ? body : JSON.stringify(body);
    const hasLiveSession =
      Boolean(this.#activeSession) &&
      !this.#activeSession.isDetached() &&
      Boolean(this.#activeScript) &&
      !this.#activeScript.isDestroyed;

    if (sendFrom === "device" && !hasLiveSession) {
      throw new Error(
        "Hiện chưa gắn vào ứng dụng nào trên iPhone. Hãy bấm '📡 Bật Bắt Gói Tin' (hoặc đổi ô chế độ sang 'Gửi từ Máy tính')."
      );
    }

    if ((sendFrom === "auto" || sendFrom === "device") && hasLiveSession && this.#state.enableObjCBridge) {
      const { result } = await this.callRpcExport("__studioReplayHttpRequest", [
        {
          method: cleanMethod,
          url: cleanUrl,
          headers: cleanHeaders,
          body: cleanBody,
        },
      ]);
      const exchange = this.#recordHttpExchange(
        {
          ...result,
          replayedFromDevice: true,
        },
        this.#state.pid
      );
      return { exchange };
    }

    // Dự phòng hoặc gửi chủ động từ Máy tính (có lớp bảo vệ chống SSRF nội bộ)
    const safeUrl = assertSafePcReplayUrl(cleanUrl);
    const startedAt = Date.now();
    try {
      const res = await fetch(safeUrl, {
        method: cleanMethod,
        headers: cleanHeaders,
        body: cleanMethod !== "GET" && cleanMethod !== "HEAD" && cleanBody ? cleanBody : undefined,
        redirect: "manual",
        signal: AbortSignal.timeout(15_000),
      });

      const respHeaders = {};
      res.headers.forEach((val, key) => {
        respHeaders[key] = val;
      });

      const fullText = await res.text();
      const responseBody =
        fullText.length > 65536
          ? `${fullText.slice(0, 65536)}\n...[Đã cắt bớt từ ${fullText.length} ký tự]`
          : fullText;

      const exchange = this.#recordHttpExchange({
        target: "Máy tính (Gửi trực tiếp)",
        method: cleanMethod,
        url: safeUrl,
        requestHeaders: cleanHeaders,
        requestBody: cleanBody,
        statusCode: res.status,
        responseHeaders: respHeaders,
        responseBody,
        elapsedMs: Math.max(1, Date.now() - startedAt),
        errorText: "",
        replayedFromPc: true,
      });
      return { exchange };
    } catch (err) {
      const errText = err?.message || String(err);
      const exchange = this.#recordHttpExchange({
        target: "Máy tính (Gửi trực tiếp)",
        method: cleanMethod,
        url: safeUrl,
        requestHeaders: cleanHeaders,
        requestBody: cleanBody,
        statusCode: 0,
        responseHeaders: {},
        responseBody: "",
        elapsedMs: Math.max(1, Date.now() - startedAt),
        errorText: errText,
        replayedFromPc: true,
      });
      return { exchange };
    }
  }

  recordExternalEvent({ level = "warning", source = "device", text, details = null, pid = null }) {
    this.#pushOutput(level, source, text, details, pid);
  }

  #setState(patch) {
    this.#state = {
      ...this.#state,
      ...patch,
      updatedAt: Date.now(),
    };
    this.#emit("session:state", this.getStatus());
  }

  #pushOutput(level, source, text, details = null, overridePid = null) {
    const record = {
      id: this.#eventSeq++,
      ts: Date.now(),
      pid: overridePid ?? this.#state.pid ?? null,
      target: this.#state.targetLabel ?? null,
      level,   // info | warning | error | send | rpc | system
      source,  // console | send | runtime | rpc | device | system
      text,
      details,
    };

    this.#eventHistory.push(record);
    if (this.#eventHistory.length > MAX_EVENT_HISTORY) {
      this.#eventHistory.shift();
    }

    this.#emit("script:output", record);
    return record;
  }

  #ensureActiveScript() {
    if (!this.#activeSession || this.#activeSession.isDetached() || !this.#activeScript || this.#activeScript.isDestroyed) {
      throw new Error("Hiện chưa có phiên Frida nào đang chạy. Hãy bấm 'Gửi JS' gắn vào ứng dụng trước.");
    }
    return this.#activeScript;
  }

  async callRpcExport(methodName, args = []) {
    const cleanMethod = String(methodName ?? "").trim();
    if (!cleanMethod) {
      throw new Error("Vui lòng nhập tên hàm trong rpc.exports cần gọi.");
    }
    if (!Array.isArray(args)) {
      throw new Error("Tham số truyền vào RPC phải là một mảng JSON (ví dụ: [\"Antidv\"]).");
    }

    const script = this.#ensureActiveScript();
    const fn = script.exports?.[cleanMethod];
    if (typeof fn !== "function") {
      throw new Error(`Không tìm thấy hàm '${cleanMethod}' trong rpc.exports của phiên hiện tại.`);
    }

    const t0 = Date.now();
    let result;
    let timerId = null;
    try {
      const timeoutPromise = new Promise((_, reject) => {
        timerId = setTimeout(() => {
          reject(
            new Error(
              "Quá thời gian chờ phản hồi từ ứng dụng trên iPhone (18 giây). Ứng dụng có thể đang bị iOS tạm dừng chạy nền — hãy mở sáng ứng dụng lên màn hình iPhone rồi bấm thử lại!"
            )
          );
        }, 18_000);
      });
      result = await Promise.race([fn(...args), timeoutPromise]);
    } catch (err) {
      const raw = err?.message || String(err);
      if (/Script is destroyed|Session is detached|connection is closed|Device is gone/i.test(raw)) {
        logger.warn("Phiên Frida đã ngắt khi đang gọi hàm RPC", { methodName: cleanMethod, reason: raw });
        await this.stopSession(null);
        throw new Error(
          "Hiện chưa có phiên Frida hoạt động (ứng dụng vừa đóng hoặc chuyển trang thái). Hãy bấm 'Chạy mã JS' hoặc '📡 Bật Bắt Gói Tin' để gắn lại!"
        );
      }
      logger.error(`Lỗi khi gọi hàm RPC '${cleanMethod}'`, err, { methodName: cleanMethod });
      throw err;
    } finally {
      if (timerId) clearTimeout(timerId);
    }
    const elapsedMs = Date.now() - t0;

    if (!cleanMethod.startsWith("__studio")) {
      const preview = typeof result === "string" ? result : JSON.stringify(result, null, 2);
      this.#pushOutput("rpc", "rpc", `RPC ${cleanMethod}(${JSON.stringify(args)}) -> (${elapsedMs}ms)\n${preview}`, result);
    }

    return { result, elapsedMs };
  }

  async inspectProcess(kind, params = {}) {
    const hasLive =
      Boolean(this.#activeSession) &&
      !this.#activeSession.isDetached() &&
      Boolean(this.#activeScript) &&
      !this.#activeScript.isDestroyed;

    const reqTarget = String(params.target || "").trim();
    const numericReqPid = /^\d+$/.test(reqTarget) ? Number(reqTarget) : null;
    const curLabel = String(this.#state.targetLabel || "");
    const isSameTarget =
      !reqTarget ||
      curLabel === reqTarget ||
      curLabel.includes(`(${reqTarget})`) ||
      (numericReqPid !== null && this.#state.pid === numericReqPid);

    if ((!hasLive || !isSameTarget) && params.autoAttach && params.deviceId && reqTarget) {
      await this.runScript({
        deviceId: String(params.deviceId),
        mode: String(params.mode || "auto"),
        target: reqTarget,
        code: "// Đã tự động gắn phiên chỉ đọc để tra cứu Kính lúp / Tệp tin Sandbox\nconsole.log('[Hệ thống] Đã mở kết nối tra cứu trực tiếp cho ' + Process.id);",
        enableObjCBridge: true,
      });
    }

    switch (kind) {
      case "manifest":
        return (await this.callRpcExport("__studioGetAppManifest", [])).result;
      case "modules":
        return (await this.callRpcExport("__studioListModules", [params.filter || ""])).result;
      case "exports":
        if (!params.moduleName) {
          throw new Error("Vui lòng chọn tên Module (.dylib / Framework) để xem hàm Export.");
        }
        return (await this.callRpcExport("__studioListExports", [params.moduleName, params.filter || ""])).result;
      case "objc-classes":
        return (await this.callRpcExport("__studioListObjcClasses", [params.filter || ""])).result;
      case "objc-methods":
        if (!params.className) {
          throw new Error("Vui lòng chọn tên lớp Objective-C cần soi selector.");
        }
        return (await this.callRpcExport("__studioGetObjcMethods", [params.className])).result;
      case "smart-functions":
        return (
          await this.callRpcExport("__studioSmartFindFunctions", [
            {
              preset: params.preset || "",
              keyword: params.filter || "",
              limit: Number(params.limit) || 100,
            },
          ])
        ).result;
      case "memory-instances":
        if (!params.className) {
          throw new Error("Vui lòng nhập tên Lớp (Class) cần quét trên bộ nhớ RAM.");
        }
        return (
          await this.callRpcExport("__studioScanMemoryInstances", [
            {
              className: params.className,
              maxItems: Number(params.maxItems) || 25,
            },
          ])
        ).result;
      case "sandbox-files":
        return (await this.callRpcExport("__studioListSandboxFiles", [params.relPath || ""])).result;
      case "sandbox-read":
        if (!params.relPath) {
          throw new Error("Vui lòng chọn đường dẫn tệp tin trong Sandbox để xem nội dung.");
        }
        return (await this.callRpcExport("__studioReadSandboxFile", [params.relPath])).result;
      case "security-vault":
        return (await this.callRpcExport("__studioInspectSecurityVault", [])).result;
      case "security-posture":
        return (await this.callRpcExport("__studioInspectSecurityPosture", [])).result;
      case "rpc-exports":
        return (await this.callRpcExport("__studioListUserRpcExports", [])).result;
      default:
        throw new Error(`Loại truy vấn Inspector không hợp lệ: ${kind}`);
    }
  }

  async stopSession(reasonText = "Đã ngắt kết nối phiên Frida theo yêu cầu.") {
    const prevScript = this.#activeScript;
    const prevSession = this.#activeSession;
    this.#activeScript = null;
    this.#activeSession = null;
    this.#featureSwitches = createDefaultFeatureSwitches();

    if (prevScript) {
      try {
        if (!prevScript.isDestroyed) {
          await prevScript.unload();
        }
      } catch {
        // Bỏ qua nếu tiến trình đích đã tự đóng trước đó
      }
    }

    if (prevSession) {
      try {
        if (!prevSession.isDetached()) {
          await prevSession.detach();
        }
      } catch {
        // Bỏ qua nếu phiên đã ngắt
      }
    }

    if (this.#state.status !== "idle") {
      this.#setState({
        status: "idle",
        pid: null,
        targetLabel: null,
        receivedDeviceEventsCount: 0,
        lastDeviceOutputAt: null,
        startedAt: null,
      });
      if (reasonText) {
        this.#pushOutput("system", "system", reasonText);
      }
    }

    return this.getStatus();
  }

  async runScript({ deviceId, mode = "auto", target, code, enableObjCBridge = true }) {
    if (!deviceId || typeof deviceId !== "string") {
      throw new Error("Vui lòng chọn thiết bị kết nối (Cáp USB iPhone hoặc Máy tính).");
    }
    if (mode !== "auto" && mode !== "attach" && mode !== "spawn") {
      throw new Error("Chế độ chạy không hợp lệ (chỉ chấp nhận 'auto', 'attach' hoặc 'spawn').");
    }
    const cleanTarget = String(target ?? "").trim();
    if (!cleanTarget) {
      throw new Error("Vui lòng chọn một ứng dụng trong danh sách trước khi bấm Chạy.");
    }
    const scriptSource = String(code ?? "");
    if (!scriptSource.trim()) {
      throw new Error("Nội dung mã JavaScript đang để trống.");
    }

    const numericPid = /^\d+$/.test(cleanTarget) ? Number(cleanTarget) : null;
    const canHotReload =
      (mode === "auto" || mode === "attach") &&
      this.#activeSession &&
      !this.#activeSession.isDetached() &&
      this.#state.deviceId === deviceId &&
      ((numericPid !== null && this.#state.pid === numericPid) || this.#state.targetLabel === cleanTarget);

    if (canHotReload && this.#activeScript) {
      try {
        if (!this.#activeScript.isDestroyed) {
          await this.#activeScript.unload();
        }
      } catch {
        // Bỏ qua nếu script cũ đã hủy
      }
      this.#activeScript = null;
      this.#state.receivedDeviceEventsCount = 0;
      this.#state.lastDeviceOutputAt = null;
      this.#pushOutput("system", "system", `Đang nạp nóng lại mã JS vào ứng dụng đang mở (Mã ${this.#state.pid})...`);
    } else {
      await this.stopSession(null);
      this.#setState({
        status: "connecting",
        deviceId,
        mode,
        targetLabel: cleanTarget,
        pid: null,
        enableObjCBridge: Boolean(enableObjCBridge),
        receivedDeviceEventsCount: 0,
        lastDeviceOutputAt: null,
        startedAt: null,
      });
    }

    try {
      let finalSource = scriptSource;
      let lineOffset = 0;

      if (this.#compiler) {
        const compiled = await this.#compiler.compileUserScript(scriptSource, {
          enableObjCBridge: Boolean(enableObjCBridge),
        });
        finalSource = compiled.compiledSource;
        lineOffset = compiled.lineOffset || 0;
      }

      let device = await this.#bridge.resolveWorkingDevice(deviceId);
      let session = this.#activeSession;
      let targetPid = this.#state.pid;
      let spawnedNewProcess = false;

      const attachWithTunnelRetry = async (targetToAttach) => {
        try {
          return await device.attach(targetToAttach);
        } catch (attErr) {
          const msg = attErr?.message || String(attErr);
          if (
            typeof this.#bridge.invalidateTunnel === "function" &&
            /Device is gone|connection is closed|Connection refused|EOF/i.test(msg)
          ) {
            logger.warn("Cầu nối cáp USB vừa đổi cổng, đang tự động mở lại kết nối sạch...", {
              deviceId,
              reason: msg,
            });
            await this.#bridge.invalidateTunnel(deviceId);
            device = await this.#bridge.resolveWorkingDevice(deviceId);
            return await device.attach(targetToAttach);
          }
          throw attErr;
        }
      };

      if (!session || session.isDetached()) {
        const [frontApp, installedApps] = await Promise.all([
          typeof device.getFrontmostApplication === "function"
            ? device.getFrontmostApplication().catch(() => null)
            : Promise.resolve(null),
          typeof device.enumerateApplications === "function"
            ? device.enumerateApplications().catch(() => [])
            : Promise.resolve([]),
        ]);

        const matchedApp = Array.isArray(installedApps)
          ? installedApps.find(
              (a) =>
                a.identifier === cleanTarget ||
                (numericPid !== null && a.pid === numericPid) ||
                a.name === cleanTarget
            )
          : null;

        const appDisplay = matchedApp ? `${matchedApp.name} (${matchedApp.identifier})` : cleanTarget;
        const isAppFrontmostNow = Boolean(
          matchedApp && frontApp && frontApp.identifier === matchedApp.identifier && frontApp.pid > 0
        );

        if (mode === "spawn") {
          const bundleToSpawn = matchedApp?.identifier || cleanTarget;
          this.#pushOutput("system", "system", `Đang mở lại từ đầu ứng dụng '${appDisplay}' trên thiết bị...`);
          targetPid = await device.spawn(bundleToSpawn);
          spawnedNewProcess = true;
          session = await attachWithTunnelRetry(targetPid);
        } else if (mode === "auto" && matchedApp?.identifier) {
          // Chế độ Tự động thông minh: Dùng uiopen đưa App lên màn hình thật (không gây đứt kết nối trên Dopamine Rootless!)
          if (!isAppFrontmostNow && typeof this.#bridge.openAppOnScreen === "function") {
            this.#pushOutput("system", "system", `Đang tự động bật ứng dụng '${appDisplay}' lên màn hình iPhone...`);
            const uiOpenOut = await this.#bridge.openAppOnScreen(deviceId, matchedApp.identifier);

            if (uiOpenOut?.opened) {
              let livePid = 0;
              for (let retry = 0; retry < 8; retry++) {
                await new Promise((r) => setTimeout(r, 300));
                const latestApps =
                  typeof device.enumerateApplications === "function"
                    ? await device.enumerateApplications().catch(() => [])
                    : [];
                const found = latestApps.find((a) => a.identifier === matchedApp.identifier);
                if (found && found.pid > 0) {
                  livePid = found.pid;
                  break;
                }
              }
              if (livePid > 0) {
                await new Promise((r) => setTimeout(r, 350));
                session = await attachWithTunnelRetry(livePid);
                targetPid = session.pid;
              }
            }
          }

          // Dự phòng cho thiết bị không có SSH hoặc môi trường kiểm thử giả lập (Unit Test)
          if (!session) {
            if (isAppFrontmostNow && frontApp?.pid > 0) {
              session = await attachWithTunnelRetry(frontApp.pid);
              targetPid = session.pid;
            } else if (typeof device.spawn === "function" && !isAppFrontmostNow) {
              targetPid = await device.spawn(matchedApp.identifier);
              spawnedNewProcess = true;
              session = await attachWithTunnelRetry(targetPid);
            } else {
              const fallbackTarget = matchedApp.pid > 0 ? matchedApp.pid : matchedApp.identifier;
              session = await attachWithTunnelRetry(fallbackTarget);
              targetPid = session.pid;
            }
          }
        } else {
          const attachArg =
            isAppFrontmostNow && frontApp?.pid
              ? frontApp.pid
              : matchedApp?.pid > 0
              ? matchedApp.pid
              : numericPid !== null
              ? numericPid
              : cleanTarget;

          this.#pushOutput("system", "system", `Đang gắn mã trực tiếp vào '${appDisplay}'...`);
          session = await attachWithTunnelRetry(attachArg);
          targetPid = session.pid;
        }

        this.#activeSession = session;
        session.detached.connect((reason, crash) => {
          if (this.#activeSession === session) {
            this.#activeScript = null;
            this.#activeSession = null;
            this.#featureSwitches = createDefaultFeatureSwitches();
            const crashHint = crash?.summary ? ` | Chi tiết sự cố: ${crash.summary}` : "";
            this.#setState({ status: "idle", pid: null, startedAt: null });
            this.#emit("session:switches", { switches: this.getFeatureSwitches() });
            this.#pushOutput("warning", "system", `Phiên Frida đã ngắt kết nối (Lý do: ${reason}${crashHint}).`);
          }
        });
      }

      const script = await session.createScript(finalSource, { runtime: "qjs" });
      this.#activeScript = script;
      let initialOutputCount = 0;

      const markRealDeviceEvent = () => {
        initialOutputCount += 1;
        this.#state.receivedDeviceEventsCount = (this.#state.receivedDeviceEventsCount || 0) + 1;
        this.#state.lastDeviceOutputAt = Date.now();
        this.#state.updatedAt = Date.now();
        this.#emit("session:state", this.getStatus());
      };

      script.logHandler = (level, text) => {
        markRealDeviceEvent();
        const mappedLevel = level === "error" ? "error" : level === "warning" ? "warning" : "info";
        this.#pushOutput(mappedLevel, "console", text, null, targetPid);
      };

      script.message.connect((message, data) => {
        markRealDeviceEvent();
        if (message.type === "send") {
          if (message.payload && typeof message.payload === "object" && message.payload.__studioType === "http_exchange") {
            this.#recordHttpExchange(message.payload, targetPid);
            return;
          }
          const payloadStr =
            typeof message.payload === "string"
              ? message.payload
              : JSON.stringify(message.payload, null, 2);
          const byteNote = data && data.byteLength > 0 ? ` [+${data.byteLength} byte nhị phân]` : "";
          this.#pushOutput("send", "send", `${payloadStr}${byteNote}`, message.payload, targetPid);
        } else if (message.type === "error") {
          const adjustedLine =
            message.lineNumber && message.lineNumber > lineOffset
              ? message.lineNumber - lineOffset
              : message.lineNumber;
          const loc = adjustedLine ? ` (Dòng ${adjustedLine}:${message.columnNumber || 1})` : "";
          logger.warn("Lỗi cú pháp hoặc thực thi bên trong mã Frida JS của người dùng", {
            target: cleanTarget,
            pid: targetPid,
            description: message.description,
            line: adjustedLine || message.lineNumber || 0,
          });
          this.#pushOutput(
            "error",
            "runtime",
            `${message.description || "Lỗi thực thi Frida JS"}${loc}`,
            message.stack || null,
            targetPid
          );
        }
      });

      await script.load();

      // Tự động khôi phục các Công tắc 1 chạm đang bật nếu người dùng nạp nóng (Hot-Reload) mã JS mới trên cùng phiên
      if (typeof script.exports?.__studioSetFeatureSwitch === "function") {
        for (const [swKey, swVal] of Object.entries(this.#featureSwitches)) {
          if (swVal) {
            try {
              await script.exports.__studioSetFeatureSwitch(swKey, true);
            } catch {
              // Bỏ qua nếu tiến trình mới không hỗ trợ công tắc tương ứng
            }
          }
        }
      }

      if (spawnedNewProcess) {
        await device.resume(targetPid);
        this.#pushOutput(
          "system",
          "system",
          `Đã nạp mã JS${enableObjCBridge ? " (+Cầu nối iOS)" : ""} & kích hoạt chạy tiếp ứng dụng '${cleanTarget}' (Mã ${targetPid}).`,
          null,
          targetPid
        );
      } else {
        this.#pushOutput(
          "system",
          "system",
          `Đã gắn thành công mã JS${enableObjCBridge ? " (+Cầu nối iOS)" : ""} vào '${cleanTarget}' (Mã ${targetPid}).`,
          null,
          targetPid
        );
      }

      // Cho phép microtask từ script.load() kịp đẩy log, nếu vẫn bằng 0 thì phát thông báo chỉ dẫn rõ ràng
      await new Promise((r) => setTimeout(r, 30));
      if (initialOutputCount === 0) {
        this.#pushOutput(
          "info",
          "system",
          `[Phản hồi hệ thống] Mã JS đã gắn vào '${cleanTarget}' (chưa gửi dữ liệu ngay) và đang trực chờ sự kiện — hãy chạm thao tác trên màn hình iPhone để thu kết quả trả về!`,
          null,
          targetPid
        );
      }

      this.#setState({
        status: "running",
        deviceId,
        mode,
        targetLabel: cleanTarget,
        pid: targetPid,
        enableObjCBridge: Boolean(enableObjCBridge),
        startedAt: this.#state.startedAt || Date.now(),
      });

      logger.info("Đã thực thi kịch bản Frida JS thành công", {
        deviceId,
        mode,
        target: cleanTarget,
        pid: targetPid,
        enableObjCBridge: Boolean(enableObjCBridge),
      });

      return this.getStatus();
    } catch (err) {
      logger.error("Lỗi khi nạp hoặc chạy Frida JS", err, { deviceId, mode, target: cleanTarget });
      await this.stopSession(null);
      this.#setState({
        status: "error",
        deviceId,
        mode,
        targetLabel: cleanTarget,
        pid: null,
        startedAt: null,
      });
      const rawMsg = err?.message || String(err);
      let friendlyHint = rawMsg;
      if (rawMsg.includes("Unable to map segment into target memory")) {
        friendlyHint =
          `Ứng dụng '${cleanTarget}' đang bị chặn chèn Tweak trên máy Jailbreak (${rawMsg}) — ` +
          `Nguyên nhân: Bạn đang bật chặn Jailbreak (Choicy / Shadow / Tắt Tweak Injection trong Dopamine) cho riêng ứng dụng này. ` +
          `Hãy chọn ứng dụng khác hoặc bật lại Tweak Injection cho ứng dụng này trong Cài đặt.`;
      } else if (rawMsg.includes("(os/kern) failure") || rawMsg.includes("Timeout was reached")) {
        friendlyHint =
          mode === "auto"
            ? `Ứng dụng '${cleanTarget}' đang bị iOS tạm đóng băng do màn hình iPhone đang khóa tắt (${rawMsg}) — Hãy mở khóa sáng màn hình iPhone rồi bấm thực hiện lại!`
            : `Ứng dụng '${cleanTarget}' đang ngủ ngầm dưới nền (${rawMsg}) — Hãy mở sáng màn hình iPhone và chuyển mục 'Cách mở ứng dụng' sang nút 'Tự động' rồi bấm Chạy lại!`;
      } else if (/Device is gone|connection is closed|Connection refused/i.test(rawMsg)) {
        friendlyHint =
          `Kết nối cáp USB tới Frida Server trên iPhone vừa gián đoạn (${rawMsg}) — ` +
          `Hãy chờ 2 giây hoặc bấm nút 'Máy chủ Frida' ở thanh trên -> 'Tự động sửa lỗi kết nối' rồi bấm Chạy lại!`;
      }
      this.#pushOutput("error", "system", `Không thể thực thi mã JS: ${friendlyHint}`);
      throw new Error(friendlyHint);
    }
  }
}
