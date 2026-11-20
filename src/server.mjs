// src/server.mjs — Máy chủ khởi chạy Trạm Điều Khiển Frida v7.0.0.0 trên PC (Localhost-Only • 6 Không Gian Ánh Xạ 1:1)
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import { FridaBridge } from "./infra/fridaBridge.mjs";
import { logger } from "./infra/logger.mjs";
import { ParamVaultRepository } from "./infra/paramVaultRepository.mjs";
import { FridaScriptCompiler } from "./infra/scriptCompiler.mjs";
import { SnippetRepository } from "./infra/snippetRepository.mjs";
import { WorkspaceSettingsRepository } from "./infra/workspaceSettingsRepository.mjs";
import { FridaSessionService } from "./services/fridaSessionService.mjs";
import { createApiRouter } from "./api/routes.mjs";
import { RealtimeWsHub } from "./api/wsHub.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, "../public");

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 3456);

export function createAppContext() {
  let wsHub = null;
  let sessionService = null;

  const bridge = new FridaBridge({
    onCrash: (crashInfo) => {
      sessionService?.recordExternalEvent({
        level: "error",
        source: "device",
        pid: crashInfo.pid,
        text: `[CRASH THIẾT BỊ] Tiến trình '${crashInfo.processName}' (PID ${crashInfo.pid}) bị văng: ${crashInfo.summary}`,
        details: crashInfo.report || null,
      });
    },
  });

  const compiler = new FridaScriptCompiler();
  const snippetRepo = new SnippetRepository();
  const paramVault = new ParamVaultRepository();
  const settingsRepo = new WorkspaceSettingsRepository();

  sessionService = new FridaSessionService({
    bridge,
    compiler,
    emit: (event, payload) => {
      wsHub?.broadcast(event, payload);
    },
  });

  wsHub = new RealtimeWsHub({
    getStatusSnapshot: () => sessionService.getStatus(),
  });

  const unsubscribeLogger = logger.onEntry((entry) => {
    wsHub?.broadcast("system:log", entry);
  });

  const app = express();
  app.disable("x-powered-by");
  app.use((_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    next();
  });
  app.use(express.json({ limit: "2mb" }));
  app.use(express.static(PUBLIC_DIR));
  app.use("/api", createApiRouter({ bridge, sessionService, snippetRepo, paramVault, settingsRepo }));

  const server = http.createServer(app);
  wsHub.attach(server);

  const shutdown = async (signal) => {
    logger.info(`Đang đóng máy chủ Trạm Điều Khiển Frida an toàn (${signal})...`);
    unsubscribeLogger();
    await sessionService.stopSession(null).catch(() => {});
    wsHub.close();
    bridge.shutdown();
    server.close(() => {
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 1500).unref();
  };

  return { app, server, bridge, compiler, snippetRepo, paramVault, settingsRepo, sessionService, wsHub, shutdown };
}

const isMainModule =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMainModule) {
  const ctx = createAppContext();

  process.on("unhandledRejection", (reason) => {
    logger.error("Bắt được Unhandled Promise Rejection", reason instanceof Error ? reason : new Error(String(reason)));
  });

  process.on("uncaughtException", (err) => {
    logger.error("Bắt được Uncaught Exception toàn cục", err);
  });

  process.on("SIGINT", () => void ctx.shutdown("SIGINT"));
  process.on("SIGTERM", () => void ctx.shutdown("SIGTERM"));

  ctx.server.listen(PORT, HOST, async () => {
    logger.info(`Trạm Điều Khiển Frida v7.0.0.0 (6 Không Gian Ánh Xạ 1:1 • Kiểm Toán Mach-O & StoreKit • Lược Bỏ Nút Chết) đã sẵn sàng tại http://${HOST}:${PORT}`);
    try {
      const saved = await ctx.settingsRepo.getSettings();
      if (!saved.activeConnectionChannel || saved.activeConnectionChannel === "usb_frida") {
        await ctx.bridge.activateConnectionChannel({
          channel: "usb_frida",
          deviceId: saved.selectedDeviceId || "",
        });
      }
    } catch {
      // Nếu chưa cắm cáp USB lúc mới bật máy chủ thì giữ trạng thái chờ trung thực
    }
  });
}
