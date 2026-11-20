// src/api/routes.mjs — Định tuyến RESTful /api/v1/* chuẩn Unified API Envelope & Phân trang (v6.0.0.0: Đổi Kết Nối Đa Kênh, Lưu Cấu Hình Bền Vững, Sửa Mẫu JS & Giải Mã JWS StoreKit)
import express from "express";
import { createTraceId, extractJsRootFrame, logger } from "../infra/logger.mjs";
import { ParamVaultRepository } from "../infra/paramVaultRepository.mjs";
import { WorkspaceSettingsRepository } from "../infra/workspaceSettingsRepository.mjs";
import { decodeAndInspectPayload } from "../infra/payloadDecoder.mjs";

export const asyncHandler =
  (fn) =>
  (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

function sendSuccess(res, data, { status = 200, meta } = {}) {
  res.status(status).json({
    success: true,
    ok: true,
    data,
    ...(meta ? { meta } : {}),
    timestamp: new Date().toISOString(),
  });
}

export function createApiRouter({
  bridge,
  sessionService,
  snippetRepo,
  paramVault = new ParamVaultRepository(),
  settingsRepo = new WorkspaceSettingsRepository(),
}) {
  const router = express.Router();
  const repairIdempotencyCache = new Map();
  const switchIdempotencyCache = new Map();

  // 1. Kiểm tra sức khỏe máy chủ Web & Trạng thái Frida Server trực tiếp trên thiết bị
  router.get(["/v1/health", "/health"], (_req, res) => {
    sendSuccess(res, {
      service: "tram-dieu-khien-frida",
      version: "version.7.0.0.0",
      session: sessionService.getStatus(),
    });
  });

  // 1A. Lưu trữ bền vững Cấu hình Giao diện & Kênh Kết nối (Không mất khi Reload trang)
  router.get(
    "/v1/settings",
    asyncHandler(async (_req, res) => {
      const settings = await settingsRepo.getSettings();
      sendSuccess(res, { settings });
    })
  );

  router.put(
    "/v1/settings",
    asyncHandler(async (req, res) => {
      const settings = await settingsRepo.updateSettings(req.body ?? {});
      sendSuccess(res, { settings });
    })
  );

  // 1B. Trạm Đổi Kết Nối Đa Kênh Kèm Trạng Thái Thật 100% (7 Kênh thực tế)
  router.get(
    ["/v1/connections/status", "/v1/connections"],
    asyncHandler(async (req, res) => {
      const saved = await settingsRepo.getSettings();
      const deviceId = String(req.query.deviceId ?? saved.selectedDeviceId ?? "").trim();
      const wirelessAddress = String(req.query.wirelessAddress ?? saved.wirelessAddress ?? "").trim();
      const vpnMitmProxyAddress = String(
        req.query.vpnMitmProxyAddress ?? saved.vpnMitmProxyAddress ?? "127.0.0.1:8080"
      ).trim();
      const activeChannel = String(req.query.activeChannel ?? saved.activeConnectionChannel ?? "usb_frida").trim();

      const hub = await bridge.probeAllConnectionChannels({
        deviceId,
        wirelessAddress,
        vpnMitmProxyAddress,
        activeChannel,
      });
      sendSuccess(res, { hub });
    })
  );

  router.post(
    "/v1/connections/rabbit-sync",
    asyncHandler(async (_req, res) => {
      const saved = await settingsRepo.getSettings();
      const port = Number(saved.rabbitDaemonPort) || 8765;
      let db = null;
      try {
        const resp = await fetch(`http://127.0.0.1:${port}/api/database`, {
          signal: AbortSignal.timeout(2000),
        });
        if (!resp.ok) {
          const err = new Error(
            `Cổng 127.0.0.1:${port} trả về HTTP ${resp.status} — tiến trình RabbitUltrad trên iPhone hiện chưa phản hồi dữ liệu.`
          );
          err.statusCode = 503;
          throw err;
        }
        db = await resp.json();
      } catch (fetchErr) {
        if (fetchErr.statusCode) throw fetchErr;
        const err = new Error(
          `Trạng thái thật: Cổng RabbitUltrad 127.0.0.1:${port} hiện chưa có tiến trình Daemon trả lời (${fetchErr?.message || "EOF"}).`
        );
        err.statusCode = 503;
        throw err;
      }

      const rawApis = Array.isArray(db?.apis) ? db.apis : [];
      const imported =
        typeof sessionService.importExternalPackets === "function"
          ? sessionService.importExternalPackets(rawApis, "RabbitUltrad (8765)")
          : { importedCount: 0, items: [] };

      sendSuccess(res, {
        daemonVersion: db?.version || "2.1.x",
        currentSandboxId: db?.currentSandboxId || db?.currentAppleId || null,
        totalInDaemon: rawApis.length,
        importedCount: imported.importedCount,
      });
    })
  );

  router.post(
    "/v1/connections/switch",
    asyncHandler(async (req, res) => {
      const idemKey = String(req.get("Idempotency-Key") || "").trim();
      if (idemKey && switchIdempotencyCache.has(idemKey)) {
        const cached = switchIdempotencyCache.get(idemKey);
        if (Date.now() - cached.ts < 10_000) {
          return sendSuccess(res, cached.payload);
        }
        switchIdempotencyCache.delete(idemKey);
      }

      const saved = await settingsRepo.getSettings();
      const channel = String(req.body?.channel || "").trim();
      if (!channel) {
        throw new Error("Vui lòng chọn kênh kết nối cần chuyển đổi.");
      }

      const deviceId = String(req.body?.deviceId ?? saved.selectedDeviceId ?? "").trim();
      const wirelessAddress = String(req.body?.wirelessAddress ?? saved.wirelessAddress ?? "").trim();
      const wirelessLabel = String(req.body?.wirelessLabel ?? saved.wirelessLabel ?? "").trim();
      const vpnMitmProxyAddress = String(
        req.body?.vpnMitmProxyAddress ?? saved.vpnMitmProxyAddress ?? "127.0.0.1:8080"
      ).trim();

      if (["usb_frida", "wifi_frida", "local_pc"].includes(channel) && typeof sessionService.stopSession === "function") {
        const curStatus = sessionService.getStatus?.() || {};
        if (curStatus.status === "running" && curStatus.deviceId && curStatus.deviceId !== deviceId) {
          await sessionService.stopSession("Đã ngắt phiên cũ để chuyển sang kênh kết nối thiết bị mới.");
        }
      }

      const outcome = await bridge.activateConnectionChannel({
        channel,
        deviceId,
        wirelessAddress,
        wirelessLabel,
        vpnMitmProxyAddress,
      });

      const settings = await settingsRepo.updateSettings({
        activeConnectionChannel: channel,
        ...(outcome.selectedDeviceId ? { selectedDeviceId: outcome.selectedDeviceId } : {}),
        ...(req.body?.wirelessAddress !== undefined ? { wirelessAddress } : {}),
        ...(req.body?.wirelessLabel !== undefined ? { wirelessLabel } : {}),
        ...(req.body?.vpnMitmProxyAddress !== undefined ? { vpnMitmProxyAddress } : {}),
      });

      const payload = {
        ...outcome,
        settings,
        session: sessionService.getStatus(),
      };

      if (idemKey) {
        switchIdempotencyCache.set(idemKey, { ts: Date.now(), payload });
      }
      sendSuccess(res, payload);
    })
  );

  router.get(
    "/v1/frida-server/status",
    asyncHandler(async (req, res) => {
      const deviceId = String(req.query.deviceId || "").trim();
      const report = await bridge.checkFridaServerHealth(deviceId);
      sendSuccess(res, { report });
    })
  );

  router.post(
    "/v1/frida-server/repair",
    asyncHandler(async (req, res) => {
      const idemKey = String(req.get("Idempotency-Key") || "").trim();
      if (idemKey && repairIdempotencyCache.has(idemKey)) {
        const cached = repairIdempotencyCache.get(idemKey);
        if (Date.now() - cached.ts < 15_000) {
          return sendSuccess(res, cached.payload);
        }
        repairIdempotencyCache.delete(idemKey);
      }

      const deviceId = String(req.body?.deviceId || "").trim();
      await sessionService.stopSession("Đã tự động tháo phiên cũ để làm sạch kết nối Frida.");
      const outcome = await bridge.repairConnection(deviceId);
      const payload = {
        repairedAt: outcome.repairedAt,
        steps: ["Đã dọn sạch các phiên gắn mã cũ trên máy tính.", ...outcome.steps],
        report: outcome.report,
        session: sessionService.getStatus(),
      };

      if (idemKey) {
        repairIdempotencyCache.set(idemKey, { ts: Date.now(), payload });
      }
      sendSuccess(res, payload);
    })
  );

  // 2. Danh sách Thiết bị & Telemetry trạng thái thiết bị trực tiếp
  router.get(
    ["/v1/devices", "/devices"],
    asyncHandler(async (_req, res) => {
      const devices = await bridge.listDevices();
      sendSuccess(res, { devices }, {
        meta: { page: 1, limit: devices.length || 1, totalItems: devices.length, totalPages: 1 },
      });
    })
  );

  router.post(
    "/v1/devices/wireless",
    asyncHandler(async (req, res) => {
      const device = await bridge.addWirelessDevice(req.body ?? {});
      sendSuccess(res, { device }, { status: 201 });
    })
  );

  router.delete(
    "/v1/devices/wireless/:deviceId",
    asyncHandler(async (req, res) => {
      const outcome = await bridge.removeWirelessDevice(req.params.deviceId);
      sendSuccess(res, outcome);
    })
  );

  router.get(
    "/v1/devices/:deviceId/telemetry",
    asyncHandler(async (req, res) => {
      const telemetry = await bridge.getDeviceTelemetry(req.params.deviceId);
      sendSuccess(res, { telemetry });
    })
  );

  router.get(
    ["/v1/devices/:deviceId/targets", "/devices/:deviceId/targets"],
    asyncHandler(async (req, res) => {
      const targets = await bridge.listTargets(req.params.deviceId);
      const totalItems = targets.apps.length + targets.processes.length;
      sendSuccess(res, targets, {
        meta: { page: 1, limit: totalItems || 1, totalItems, totalPages: 1 },
      });
    })
  );

  // 3. Quản lý Phiên Frida (Attach / Spawn / Stop / RPC / Process Inspector)
  router.get(["/v1/sessions/current", "/session"], (_req, res) => {
    sendSuccess(res, { session: sessionService.getStatus() });
  });

  router.post(
    ["/v1/sessions", "/session/run"],
    asyncHandler(async (req, res) => {
      const { deviceId, mode, target, code, enableObjCBridge = true } = req.body ?? {};
      const session = await sessionService.runScript({
        deviceId,
        mode,
        target,
        code,
        enableObjCBridge,
      });
      sendSuccess(res, { session });
    })
  );

  router.delete(
    "/v1/sessions/current",
    asyncHandler(async (_req, res) => {
      const session = await sessionService.stopSession();
      sendSuccess(res, { session });
    })
  );

  router.post(
    "/session/stop",
    asyncHandler(async (_req, res) => {
      const session = await sessionService.stopSession();
      sendSuccess(res, { session });
    })
  );

  router.post(
    "/v1/sessions/rpc-calls",
    asyncHandler(async (req, res) => {
      const { method, args = [] } = req.body ?? {};
      const rpcOutcome = await sessionService.callRpcExport(method, args);
      sendSuccess(res, rpcOutcome);
    })
  );

  router.get("/v1/sessions/feature-switches", (_req, res) => {
    const switches =
      typeof sessionService.getFeatureSwitches === "function"
        ? sessionService.getFeatureSwitches()
        : {};
    sendSuccess(res, { switches, session: sessionService.getStatus() });
  });

  router.post(
    "/v1/sessions/feature-switches",
    asyncHandler(async (req, res) => {
      const outcome = await sessionService.toggleFeatureSwitch(req.body ?? {});
      sendSuccess(res, outcome);
    })
  );

  router.get(
    "/v1/sessions/inspections/:kind",
    asyncHandler(async (req, res) => {
      const { kind } = req.params;
      const {
        filter = "",
        moduleName = "",
        className = "",
        preset = "",
        relPath = "",
        maxItems = "25",
        limit = "100",
        autoAttach = "",
        deviceId = "",
        target = "",
        mode = "auto",
      } = req.query;
      const result = await sessionService.inspectProcess(kind, {
        filter: String(filter),
        moduleName: String(moduleName),
        className: String(className),
        preset: String(preset),
        relPath: String(relPath),
        maxItems: Number(maxItems) || 25,
        limit: Number(limit) || 100,
        autoAttach: autoAttach === "1" || autoAttach === "true",
        deviceId: String(deviceId),
        target: String(target),
        mode: String(mode || "auto"),
      });
      sendSuccess(res, { kind, result });
    })
  );

  // 4. Kho Kịch bản Mẫu & Tự Lưu (Thêm mới, Sửa trực tiếp mã JS của người dùng & Xóa)
  router.get(
    "/v1/snippets",
    asyncHandler(async (req, res) => {
      const category = String(req.query.category || "").trim();
      const search = String(req.query.search || "").trim().toLowerCase();
      const allSnippets = await snippetRepo.listAll();
      const snippets = allSnippets.filter((item) => {
        if (category && category !== "ALL" && item.category !== category) return false;
        if (!search) return true;
        return (
          (item.displayTitle || item.title || "").toLowerCase().includes(search) ||
          (item.description || "").toLowerCase().includes(search) ||
          (item.category || "").toLowerCase().includes(search) ||
          (item.code || "").toLowerCase().includes(search)
        );
      });
      const categories = Array.from(new Set(allSnippets.map((s) => s.category)));
      sendSuccess(
        res,
        { snippets, categories },
        {
          meta: {
            page: 1,
            limit: snippets.length || 1,
            totalItems: snippets.length,
            totalPages: 1,
          },
        }
      );
    })
  );

  router.post(
    "/v1/snippets",
    asyncHandler(async (req, res) => {
      const saved = await snippetRepo.saveCustom(req.body ?? {});
      sendSuccess(res, { snippet: saved }, { status: 201 });
    })
  );

  router.put(
    "/v1/snippets/:snippetId",
    asyncHandler(async (req, res) => {
      const updated = await snippetRepo.updateCustom(req.params.snippetId, req.body ?? {});
      sendSuccess(res, { snippet: updated });
    })
  );

  router.delete(
    "/v1/snippets/:snippetId",
    asyncHandler(async (req, res) => {
      await snippetRepo.deleteCustom(req.params.snippetId);
      sendSuccess(res, { deletedId: req.params.snippetId });
    })
  );

  // 5. Truy vấn Bảng Nhật Ký Thực Thi & Nhật Ký Hệ Thống
  router.get("/v1/event-logs", (req, res) => {
    const { level = "", search = "", page = 1, limit = 200 } = req.query;
    const { items, meta } = sessionService.queryEventLogs({ level, search, page, limit });
    sendSuccess(res, { items }, { meta });
  });

  router.delete("/v1/event-logs", (_req, res) => {
    sessionService.clearEventLogs();
    sendSuccess(res, { cleared: true });
  });

  router.get("/v1/system-logs", (req, res) => {
    const { level = "", search = "", page = 1, limit = 150 } = req.query;
    const { items, meta } = logger.queryLogs({ level, search, page, limit });
    sendSuccess(res, { items }, { meta });
  });

  router.delete("/v1/system-logs", (_req, res) => {
    logger.clearBuffer();
    sendSuccess(res, { cleared: true });
  });

  // 6. Bắt Gói Tin + Hộp Trả Lời (HTTP Inspector) & Sửa Gửi Lại Gói Tin (HTTP Repeater)
  router.get("/v1/http-exchanges", (req, res) => {
    const { search = "", limit = 200 } = req.query;
    const { items, meta } = sessionService.listHttpExchanges({ search, limit });
    sendSuccess(res, { items }, { meta });
  });

  router.delete("/v1/http-exchanges", (_req, res) => {
    sessionService.clearHttpExchanges();
    sendSuccess(res, { cleared: true });
  });

  router.post(
    "/v1/http-capture/enable",
    asyncHandler(async (req, res) => {
      const outcome = await sessionService.enableHttpCapture(req.body ?? {});
      sendSuccess(res, outcome);
    })
  );

  router.post(
    "/v1/http-repeater/send",
    asyncHandler(async (req, res) => {
      const outcome = await sessionService.replayHttpRequest(req.body ?? {});
      sendSuccess(res, outcome);
    })
  );

  // 7. Sổ Lưu Tham Số & Mã ID Cần Thiết (Saved Parameters / IDs Vault)
  router.get(
    "/v1/saved-params",
    asyncHandler(async (req, res) => {
      const { search = "", appId = "" } = req.query;
      const items = await paramVault.listAll({ search: String(search), appId: String(appId) });
      sendSuccess(
        res,
        { items },
        {
          meta: {
            page: 1,
            limit: items.length || 1,
            totalItems: items.length,
            totalPages: 1,
          },
        }
      );
    })
  );

  router.post(
    "/v1/saved-params",
    asyncHandler(async (req, res) => {
      const param = await paramVault.saveParam(req.body ?? {});
      sendSuccess(res, { param }, { status: 201 });
    })
  );

  router.delete(
    "/v1/saved-params/:paramId",
    asyncHandler(async (req, res) => {
      await paramVault.deleteParam(req.params.paramId);
      sendSuccess(res, { deletedId: req.params.paramId });
    })
  );

  // 8. Bộ Giải Mã Thực Tế & Xác Thực Mật Mã Apple StoreKit JWS (ES256 x5c) / JWT / Base64 / URL / Hex / JSON
  router.post(
    "/v1/decoder/inspect",
    asyncHandler(async (req, res) => {
      const { input, mode = "auto" } = req.body ?? {};
      const decoded = decodeAndInspectPayload(input, mode);
      sendSuccess(res, { decoded });
    })
  );

  // Middleware bắt lỗi tập trung chuẩn ApiErrorResponse & mã HTTP chuẩn REST
  router.use((err, req, res, _next) => {
    const traceId = createTraceId();
    const rootFrame = extractJsRootFrame(err);
    const msg = err?.message || "Đã xảy ra lỗi không xác định trên máy chủ.";
    logger.error(`Lỗi xử lý API [${req.method} ${req.originalUrl}]`, err, { traceId });

    let httpStatus = Number(err?.statusCode) || 500;
    let errorCode = err?.code || "OPERATION_FAILED";

    if (!err?.statusCode) {
      if (/Từ chối truy cập/i.test(msg)) {
        httpStatus = 403;
        errorCode = "FORBIDDEN_SANDBOX_PATH";
      } else if (
        /Vui lòng|không được để trống|không hợp lệ|phải là|phải gồm|Không giải mã được|quá ngắn|chứa ký tự không thuộc|bắt đầu bằng|Chỉ hỗ trợ giao thức|chặn địa chỉ mạng nội bộ|Số cổng Frida/i.test(
          msg
        )
      ) {
        httpStatus = 400;
        errorCode = "VALIDATION_FAILED";
      } else if (/Không tìm thấy/i.test(msg)) {
        httpStatus = 404;
        errorCode = "RESOURCE_NOT_FOUND";
      } else if (/Hiện chưa có phiên Frida|Hiện chưa gắn vào ứng dụng|Không thể xóa kịch bản mẫu|Không thể sửa trực tiếp kịch bản mẫu/i.test(msg)) {
        httpStatus = 409;
        errorCode = "CONFLICT_STATE";
      }
    }

    res.status(httpStatus).json({
      success: false,
      ok: false,
      error: {
        code: errorCode,
        message: msg,
        location: rootFrame.location,
        traceId,
      },
      timestamp: new Date().toISOString(),
    });
  });

  return router;
}
