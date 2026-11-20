// src/infra/logger.mjs — Bộ ghi nhật ký cấu trúc Tiếng Việt có Ring-Buffer, Trace ID, vị trí dòng lỗi & xoay vòng file
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LOG_DIR = path.resolve(__dirname, "../../logs");
const LOG_FILE = path.join(LOG_DIR, "frida-gui.log");
const MAX_LOG_BYTES = 5 * 1024 * 1024; // 5MB mỗi file
const MAX_RING_BUFFER = 500;

const SENSITIVE_KEYS = /password|token|authorization|api_key|secret/i;

/** @type {Array<object>} */
const logRingBuffer = [];
/** @type {Set<(entry: object) => void>} */
const subscribers = new Set();
let logSeq = 1;

function maskSensitive(data) {
  if (!data || typeof data !== "object") return data;
  if (Array.isArray(data)) return data.map(maskSensitive);
  const clean = {};
  for (const [k, v] of Object.entries(data)) {
    clean[k] = SENSITIVE_KEYS.test(k) ? "***REDACTED***" : maskSensitive(v);
  }
  return clean;
}

export function extractJsRootFrame(err) {
  const stackLines = String(err?.stack ?? "").split(/\r?\n/);
  const frameLine =
    stackLines.find(
      (l) => /\bat\s+.*:\d+:\d+/.test(l) && !l.includes("node:internal") && !l.includes("logger.mjs")
    ) ?? "";
  const match = frameLine.match(/(?:at\s+(?:(.+?)\s+\()?)?(.+?):(\d+):(\d+)\)?$/);
  const filePath = match?.[2] ? path.basename(match[2]) : "unknown";
  const lineNumber = match ? Number(match[3]) : 0;
  return {
    errorType: err?.name ?? "Error",
    functionName: match?.[1] ?? "<anonymous>",
    filePath,
    lineNumber,
    location: `${filePath}:${lineNumber}`,
    message: err?.message ?? String(err),
  };
}

function resolveCallerLocation() {
  const stack = new Error().stack?.split("\n") ?? [];
  for (let i = 3; i < stack.length; i++) {
    const line = stack[i].trim();
    if (!line.includes("logger.mjs") && !line.includes("node:internal")) {
      const match = line.match(/\((.+):(\d+):(\d+)\)$/) || line.match(/at\s+(.+):(\d+):(\d+)$/);
      if (match) {
        return `${path.basename(match[1])}:${match[2]}`;
      }
    }
  }
  return "unknown:0";
}

async function appendRotatingLog(recordJson) {
  try {
    await fs.mkdir(LOG_DIR, { recursive: true });
    try {
      const stat = await fs.stat(LOG_FILE);
      if (stat.size >= MAX_LOG_BYTES) {
        const backup = path.join(LOG_DIR, "frida-gui.1.log");
        await fs.rename(LOG_FILE, backup).catch(() => {});
      }
    } catch {
      // File chưa tồn tại — tạo mới tự động
    }
    await fs.appendFile(LOG_FILE, `${recordJson}\n`, "utf8");
  } catch (err) {
    process.stderr.write(`[LOGGER-FALLBACK] Không thể ghi file log: ${err.message}\n`);
  }
}

export function createTraceId() {
  return crypto.randomUUID().slice(0, 8);
}

export const logger = {
  onEntry(listener) {
    subscribers.add(listener);
    return () => subscribers.delete(listener);
  },

  queryLogs({ level = "", search = "", page = 1, limit = 100 } = {}) {
    const lv = String(level || "").toUpperCase();
    const kw = String(search || "").trim().toLowerCase();
    const safePage = Math.max(1, Number(page) || 1);
    const safeLimit = Math.min(500, Math.max(1, Number(limit) || 100));

    const filtered = logRingBuffer.filter((item) => {
      if (lv && lv !== "ALL" && item.level !== lv) return false;
      if (!kw) return true;
      return (
        item.message.toLowerCase().includes(kw) ||
        item.location.toLowerCase().includes(kw) ||
        item.traceId.toLowerCase().includes(kw) ||
        JSON.stringify(item.meta || {}).toLowerCase().includes(kw)
      );
    });

    // Sắp xếp mới nhất lên trên khi truy vấn bảng hệ thống
    const ordered = [...filtered].reverse();
    const totalItems = ordered.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / safeLimit));
    const start = (safePage - 1) * safeLimit;
    const items = ordered.slice(start, start + safeLimit);

    return {
      items,
      meta: {
        page: safePage,
        limit: safeLimit,
        totalItems,
        totalPages,
      },
    };
  },

  clearBuffer() {
    logRingBuffer.length = 0;
  },

  write(level, message, meta = {}) {
    const cleanMeta = Object.keys(meta).length > 0 ? maskSensitive(meta) : undefined;
    const entry = {
      id: logSeq++,
      timestamp: new Date().toISOString(),
      level,
      traceId: meta.traceId || createTraceId(),
      location: meta.location || resolveCallerLocation(),
      message,
      ...(cleanMeta ? { meta: cleanMeta } : {}),
    };

    logRingBuffer.push(entry);
    if (logRingBuffer.length > MAX_RING_BUFFER) {
      logRingBuffer.shift();
    }

    const serialized = JSON.stringify(entry);
    if (level === "ERROR") {
      process.stderr.write(`${serialized}\n`);
    } else {
      process.stdout.write(`${serialized}\n`);
    }
    void appendRotatingLog(serialized);

    for (const fn of subscribers) {
      try {
        fn(entry);
      } catch {
        // Đảm bảo lỗi subscriber không ảnh hưởng luồng chính
      }
    }

    return entry;
  },

  info(message, meta) {
    return this.write("INFO", message, meta);
  },

  warn(message, meta) {
    return this.write("WARN", message, meta);
  },

  error(message, err, meta = {}) {
    const rootFrame = extractJsRootFrame(err);
    return this.write("ERROR", message, {
      ...meta,
      location: meta.location || (rootFrame.lineNumber > 0 ? rootFrame.location : resolveCallerLocation()),
      errorType: rootFrame.errorType,
      functionName: rootFrame.functionName,
      errorMessage: err?.message || String(err),
      stack: err?.stack ? String(err.stack).split("\n").slice(0, 6).join(" | ") : undefined,
    });
  },
};
