// src/infra/paramVaultRepository.mjs — Kho lưu trữ bền vững các Tham số & Mã ID cần thiết (Saved Parameters / IDs Vault)
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.resolve(__dirname, "../../data");
const SAVED_PARAMS_FILE = path.join(DATA_DIR, "saved-params.json");

function normalizeParamKey(rawKey) {
  return String(rawKey ?? "")
    .trim()
    .replace(/[^A-Za-z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

export class ParamVaultRepository {
  #filePath;

  constructor({ filePath = SAVED_PARAMS_FILE } = {}) {
    this.#filePath = filePath;
  }

  async #readFile() {
    try {
      const raw = await fs.readFile(this.#filePath, "utf8");
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  async #writeFile(items) {
    const dir = path.dirname(this.#filePath);
    await fs.mkdir(dir, { recursive: true });
    const tmpFile = `${this.#filePath}.tmp`;
    await fs.writeFile(tmpFile, JSON.stringify(items, null, 2), "utf8");
    await fs.rename(tmpFile, this.#filePath);
  }

  async listAll({ search = "", appId = "" } = {}) {
    const all = await this.#readFile();
    const kw = String(search || "").trim().toLowerCase();
    const appFilter = String(appId || "").trim().toLowerCase();

    return all.filter((item) => {
      if (appFilter && String(item.appId || "").toLowerCase() !== appFilter) return false;
      if (!kw) return true;
      return (
        String(item.key || "").toLowerCase().includes(kw) ||
        String(item.label || "").toLowerCase().includes(kw) ||
        String(item.value || "").toLowerCase().includes(kw) ||
        String(item.appId || "").toLowerCase().includes(kw) ||
        String(item.note || "").toLowerCase().includes(kw)
      );
    });
  }

  async saveParam({ id, key, label = "", value, appId = "", note = "" }) {
    const cleanKey = normalizeParamKey(key || label);
    const cleanValue = String(value ?? "").trim();
    if (!cleanKey) {
      throw new Error("Tên khóa tham số (ví dụ: product_id, user_id) không được để trống.");
    }
    if (!cleanValue) {
      throw new Error("Giá trị tham số / ID cần lưu không được để trống.");
    }

    const items = await this.#readFile();
    const now = new Date().toISOString();
    const cleanLabel = String(label || cleanKey).trim();
    const cleanApp = String(appId || "").trim();
    const cleanNote = String(note || "").trim();

    const existingIdx = items.findIndex(
      (p) => (id && p.id === id) || (p.key === cleanKey && (p.appId || "") === cleanApp)
    );

    if (existingIdx !== -1) {
      const updated = {
        ...items[existingIdx],
        key: cleanKey,
        label: cleanLabel,
        value: cleanValue,
        appId: cleanApp,
        note: cleanNote,
        updatedAt: now,
      };
      items.splice(existingIdx, 1);
      items.unshift(updated);
      await this.#writeFile(items);
      return updated;
    }

    const created = {
      id: `param-${crypto.randomUUID().slice(0, 8)}`,
      key: cleanKey,
      label: cleanLabel,
      value: cleanValue,
      appId: cleanApp,
      note: cleanNote,
      createdAt: now,
      updatedAt: now,
    };

    items.unshift(created);
    await this.#writeFile(items);
    return created;
  }

  async deleteParam(paramId) {
    const cleanId = String(paramId || "").trim();
    if (!cleanId) {
      throw new Error("Vui lòng cung cấp mã tham số cần xóa.");
    }
    const items = await this.#readFile();
    const next = items.filter((p) => p.id !== cleanId);
    if (next.length === items.length) {
      throw new Error("Không tìm thấy tham số cần xóa.");
    }
    await this.#writeFile(next);
    return true;
  }
}
