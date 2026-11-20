// src/api/wsHub.mjs — Kênh truyền dữ liệu thời gian thực (WebSocket + Heartbeat 25s chống Zombie)
import { WebSocketServer, WebSocket } from "ws";
import { logger } from "../infra/logger.mjs";

const HEARTBEAT_INTERVAL_MS = 25_000;

export class RealtimeWsHub {
  /** @type {WebSocketServer | null} */
  #wss = null;
  /** @type {NodeJS.Timeout | null} */
  #heartbeatTimer = null;
  /** @type {() => object} */
  #getStatusSnapshot;

  constructor({ getStatusSnapshot }) {
    this.#getStatusSnapshot = getStatusSnapshot;
  }

  attach(httpServer) {
    this.#wss = new WebSocketServer({ server: httpServer, path: "/ws" });

    this.#wss.on("connection", (ws, req) => {
      // Chỉ chấp nhận kết nối từ localhost trên PC để bảo vệ an toàn tuyệt đối
      const remoteAddr = req.socket.remoteAddress || "";
      const isLocal =
        remoteAddr === "127.0.0.1" ||
        remoteAddr === "::1" ||
        remoteAddr === "::ffff:127.0.0.1";

      if (!isLocal) {
        logger.warn("Từ chối kết nối WebSocket không phải localhost", { remoteAddr });
        ws.close(1008, "Chỉ cho phép truy cập nội bộ trên PC");
        return;
      }

      ws.isAlive = true;
      ws.on("pong", () => {
        ws.isAlive = true;
      });

      ws.on("message", (raw) => {
        try {
          const msg = JSON.parse(String(raw));
          if (msg?.event === "ping") {
            this.sendTo(ws, "pong", { serverTime: Date.now() });
          }
        } catch {
          // Bỏ qua gói tin không phải JSON hợp lệ
        }
      });

      // Gửi ngay trạng thái phiên hiện tại khi trình duyệt vừa mở trang
      this.sendTo(ws, "session:state", this.#getStatusSnapshot());
    });

    this.#heartbeatTimer = setInterval(() => {
      if (!this.#wss) return;
      for (const ws of this.#wss.clients) {
        if (ws.isAlive === false) {
          ws.terminate();
          continue;
        }
        ws.isAlive = false;
        ws.ping();
      }
    }, HEARTBEAT_INTERVAL_MS);

    this.#heartbeatTimer.unref?.();
  }

  sendTo(ws, event, payload) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ event, payload, ts: Date.now() }));
    }
  }

  broadcast(event, payload) {
    if (!this.#wss) return;
    const packet = JSON.stringify({ event, payload, ts: Date.now() });
    for (const client of this.#wss.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(packet);
      }
    }
  }

  close() {
    if (this.#heartbeatTimer) {
      clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = null;
    }
    if (this.#wss) {
      for (const client of this.#wss.clients) {
        client.terminate();
      }
      this.#wss.close();
      this.#wss = null;
    }
  }
}

