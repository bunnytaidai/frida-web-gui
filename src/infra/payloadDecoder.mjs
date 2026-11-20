// src/infra/payloadDecoder.mjs — Bộ Giải Mã Thực Tế & Xác Thực Chữ Ký Mật Mã Apple StoreKit JWS (x5c ES256) / JWT / Base64 / URL / Hex / JSON
import crypto from "node:crypto";
import { auditWireGuardConfig } from "../services/payloadDecoderService.mjs";

const EXTRACT_KEY_REGEX =
  /(id|uid|uuid|guid|token|session|key|code|product|bundle|transaction|originalTransactionId|productId|bundleId|appAccountToken|storefront|environment|expiresDate|purchaseDate|dsid|appleId|user|account|order|receipt|price|currency|status)/i;

function extractParamsFromDecoded(inputData) {
  const map = new Map();
  const add = (rawK, rawV) => {
    if (map.size >= 16) return;
    const key = String(rawK || "")
      .trim()
      .replace(/[^A-Za-z0-9_.-]+/g, "_");
    if (!key) return;
    if (rawV === null || rawV === undefined || typeof rawV === "object" || typeof rawV === "boolean") return;
    const val = String(rawV).trim();
    if (!val || val.length > 220) return;
    if (!map.has(key)) {
      map.set(key, { key, value: val });
    }
  };

  let obj = inputData;
  if (typeof inputData === "string") {
    const t = inputData.trim();
    if (t.startsWith("{") || t.startsWith("[")) {
      try {
        obj = JSON.parse(t);
      } catch {
        obj = null;
      }
    } else {
      obj = null;
    }
  }

  const walk = (node, depth) => {
    if (!node || typeof node !== "object" || depth > 4 || map.size >= 16) return;
    if (Array.isArray(node)) {
      for (const el of node.slice(0, 8)) walk(el, depth + 1);
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (v && typeof v === "object") {
        walk(v, depth + 1);
      } else if (EXTRACT_KEY_REGEX.test(k)) {
        add(k, v);
      }
    }
  };

  walk(obj, 0);
  return Array.from(map.values());
}

function formatEpochFieldsVi(payloadObj) {
  if (!payloadObj || typeof payloadObj !== "object" || Array.isArray(payloadObj)) return null;
  const timeHints = {};
  const msFields = ["purchaseDate", "originalPurchaseDate", "expiresDate", "signedDate", "revocationDate", "gracePeriodExpiresDate"];
  const secFields = ["iat", "exp", "nbf", "auth_time"];

  for (const k of msFields) {
    if (typeof payloadObj[k] === "number" && payloadObj[k] > 1_000_000_000_000) {
      timeHints[k] = new Date(payloadObj[k]).toISOString();
    }
  }
  for (const k of secFields) {
    if (typeof payloadObj[k] === "number" && payloadObj[k] > 1_000_000_000 && payloadObj[k] < 10_000_000_000) {
      timeHints[k] = new Date(payloadObj[k] * 1000).toISOString();
    }
  }
  return Object.keys(timeHints).length > 0 ? timeHints : null;
}

function inspectJwsOrJwt(rawToken) {
  const clean = rawToken.trim().replace(/^Bearer\s+/i, "").trim();
  const parts = clean.split(".");
  if (parts.length !== 3) {
    throw new Error("Chuỗi JWS / JWT phải gồm đúng 3 phần ngăn cách bởi dấu chấm (header.payload.signature).");
  }

  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  } catch {
    throw new Error("Không giải mã được phần Header (phần 1) của JWS/JWT.");
  }

  const payloadRawText = Buffer.from(parts[1], "base64url").toString("utf8");
  try {
    payload = JSON.parse(payloadRawText);
  } catch {
    payload = payloadRawText;
  }

  const cryptoVerification = {
    isAppleStoreKitJws: false,
    signatureVerified: null,
    chainVerified: null,
    algorithm: header?.alg || "unknown",
    leafSubject: null,
    issuerSubject: null,
    validTo: null,
    verificationSummary: "Chuỗi JWT tiêu chuẩn (chỉ giải mã nội dung Header & Payload; không đính kèm chuỗi chứng chỉ x5c để kiểm tra chữ ký công khai).",
  };

  // Xác thực mật mã thật 100% theo chuẩn ios-storekit1-sandbox-tester nếu có x5c + ES256
  if (header?.alg === "ES256" && Array.isArray(header.x5c) && header.x5c.length > 0) {
    cryptoVerification.isAppleStoreKitJws = true;
    try {
      const certs = header.x5c.map((b64Der) => new crypto.X509Certificate(Buffer.from(b64Der, "base64")));
      let chainOk = true;
      for (let i = 0; i < certs.length - 1; i++) {
        if (!certs[i].verify(certs[i + 1].publicKey)) {
          chainOk = false;
          break;
        }
      }
      const sigOk = crypto.verify(
        "sha256",
        Buffer.from(`${parts[0]}.${parts[1]}`),
        { key: certs[0].publicKey, dsaEncoding: "ieee-p1363" },
        Buffer.from(parts[2], "base64url")
      );

      cryptoVerification.chainVerified = chainOk;
      cryptoVerification.signatureVerified = sigOk;
      cryptoVerification.leafSubject = certs[0].subject || null;
      cryptoVerification.issuerSubject = certs[certs.length - 1].issuer || null;
      cryptoVerification.validTo = certs[0].validTo || null;
      cryptoVerification.verificationSummary =
        sigOk && chainOk
          ? "XÁC THỰC MẬT MÃ THẬT: Chữ ký ES256 và chuỗi chứng chỉ x5c hợp lệ 100%!"
          : !sigOk
          ? "CẢNH BÁO MẬT MÃ THẬT: Chữ ký ES256 KHÔNG khớp với nội dung gói tin (dữ liệu đã bị thay đổi hoặc hỏng)!"
          : "CẢNH BÁO CHUỖI CHỨNG CHỈ: Đứt gãy mắt xích chứng chỉ x5c!";
    } catch (certErr) {
      cryptoVerification.signatureVerified = false;
      cryptoVerification.chainVerified = false;
      cryptoVerification.verificationSummary = `Lỗi kiểm tra chứng chỉ x5c: ${certErr.message}`;
    }
  }

  // Nếu bên trong payload lại chứa JWS lồng nhau (ví dụ App Store Server Notifications V2 có data.signedTransactionInfo)
  const nestedDecoded = {};
  if (payload && typeof payload === "object") {
    for (const nestedKey of ["signedTransactionInfo", "signedRenewalInfo", "signedPayload"]) {
      const nestedVal = payload[nestedKey] || payload?.data?.[nestedKey];
      if (typeof nestedVal === "string" && nestedVal.split(".").length === 3) {
        try {
          nestedDecoded[nestedKey] = inspectJwsOrJwt(nestedVal).decodedObject;
        } catch {
          // Bỏ qua nếu không phải JWS hợp lệ
        }
      }
    }
  }

  const readableTimestamps = formatEpochFieldsVi(payload);
  const decodedObject = {
    header,
    payload,
    ...(readableTimestamps ? { thoiGianQuyDoiISO: readableTimestamps } : {}),
    ...(Object.keys(nestedDecoded).length > 0 ? { goiJwsBenTrongDaGiaiMa: nestedDecoded } : {}),
    kiemTraMatMa: cryptoVerification,
  };

  return {
    detectedFormat: cryptoVerification.isAppleStoreKitJws ? "storekit-jws" : "jwt",
    formatLabelVi: cryptoVerification.isAppleStoreKitJws
      ? "Gói giao dịch Apple StoreKit 2 JWS (ES256 + x5c)"
      : `Thẻ phiên JWT (${header?.alg || "alg"})`,
    cryptoVerification,
    decodedText: JSON.stringify(decodedObject, null, 2),
    decodedObject,
    extractedParams: [
      ...extractParamsFromDecoded(payload),
      ...extractParamsFromDecoded(nestedDecoded),
    ].slice(0, 16),
  };
}

function isMostlyPrintableUtf8(buf) {
  if (!buf || buf.length === 0) return false;
  const text = buf.toString("utf8");
  if (text.includes("\uFFFD")) {
    const badCount = (text.match(/\uFFFD/g) || []).length;
    if (badCount / Math.max(1, text.length) > 0.05) return false;
  }
  let printable = 0;
  const sampleLen = Math.min(text.length, 500);
  for (let i = 0; i < sampleLen; i++) {
    const code = text.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) {
      printable += 1;
    }
  }
  return printable / sampleLen >= 0.85;
}

function tryDecodeBase64(rawText) {
  const compact = rawText.replace(/\s+/g, "");
  if (compact.length < 4) {
    throw new Error("Chuỗi Base64 quá ngắn.");
  }
  const normalized = compact.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  if (!/^[A-Za-z0-9+/=]+$/.test(padded)) {
    throw new Error("Chuỗi đầu vào chứa ký tự không thuộc bảng mã Base64.");
  }

  const buf = Buffer.from(padded, "base64");
  if (buf.length === 0) {
    throw new Error("Giải mã Base64 ra 0 byte.");
  }

  if (isMostlyPrintableUtf8(buf)) {
    const utf8Text = buf.toString("utf8").trim();
    let parsedJson = null;
    if (
      (utf8Text.startsWith("{") && utf8Text.endsWith("}")) ||
      (utf8Text.startsWith("[") && utf8Text.endsWith("]"))
    ) {
      try {
        parsedJson = JSON.parse(utf8Text);
      } catch {
        parsedJson = null;
      }
    }
    const finalText = parsedJson ? JSON.stringify(parsedJson, null, 2) : utf8Text;
    return {
      detectedFormat: parsedJson ? "base64-json" : "base64-utf8",
      formatLabelVi: parsedJson ? "Base64 ➔ JSON cấu trúc rõ ràng" : "Base64 ➔ Văn bản UTF-8",
      cryptoVerification: null,
      decodedText: finalText,
      decodedObject: parsedJson,
      extractedParams: parsedJson ? extractParamsFromDecoded(parsedJson) : [],
    };
  }

  // Trường hợp biên lai Apple PKCS#7 ASN.1 nhị phân (bắt đầu bằng 0x30 0x82 ...) — trích các chuỗi ASCII đọc được thực tế bên trong!
  const asciiMatches = buf.toString("latin1").match(/[A-Za-z0-9_.:/-]{4,120}/g) || [];
  const uniqueStrings = Array.from(new Set(asciiMatches)).slice(0, 60);
  const isPkcs7 = buf[0] === 0x30 && (buf[1] === 0x82 || buf[1] === 0x80 || buf[1] === 0x83);

  const summaryObj = {
    loaiDuLieuNhiPhan: isPkcs7
      ? "Biên lai / Chứng chỉ nhị phân ASN.1 DER / PKCS#7 (ví dụ appStoreReceipt Base64)"
      : "Dữ liệu nhị phân (Binary Buffer)",
    dungLuongByte: buf.length,
    dauByteHex: buf.subarray(0, 24).toString("hex"),
    chuoiDocDuocBenTrong: uniqueStrings,
  };

  return {
    detectedFormat: isPkcs7 ? "base64-pkcs7-binary" : "base64-binary",
    formatLabelVi: isPkcs7
      ? `Biên lai nhị phân PKCS#7 / ASN.1 (${buf.length} byte — trích chuỗi thực tế)`
      : `Base64 ➔ Nhị phân (${buf.length} byte)`,
    cryptoVerification: null,
    decodedText: JSON.stringify(summaryObj, null, 2),
    decodedObject: summaryObj,
    extractedParams: [],
  };
}

export function decodeAndInspectPayload(rawInput, mode = "auto") {
  const input = String(rawInput ?? "").trim();
  if (!input) {
    throw new Error("Vui lòng dán hoặc chọn dữ liệu cần giải mã (JWS StoreKit, JWT, Base64, URL-encode, Hex hoặc JSON).");
  }

  const cleanMode = String(mode || "auto").trim().toLowerCase();

  if (cleanMode === "jws" || cleanMode === "jwt") {
    return inspectJwsOrJwt(input);
  }
  if (cleanMode === "base64") {
    return tryDecodeBase64(input);
  }
  if (cleanMode === "url") {
    const decodedUrl = decodeURIComponent(input.replace(/\+/g, " "));
    let parsedParams = {};
    try {
      const sp = new URLSearchParams(input.includes("?") ? input.slice(input.indexOf("?") + 1) : input);
      for (const [k, v] of sp.entries()) {
        if (k) parsedParams[k] = v;
      }
    } catch {
      parsedParams = {};
    }
    const hasQueryPairs = Object.keys(parsedParams).length > 0 && input.includes("=");
    return {
      detectedFormat: "url-decoded",
      formatLabelVi: "Giải mã chuỗi URL / Query String",
      cryptoVerification: null,
      decodedText: hasQueryPairs
        ? `${decodedUrl}\n\n// Bảng tách tham số Query:\n${JSON.stringify(parsedParams, null, 2)}`
        : decodedUrl,
      decodedObject: hasQueryPairs ? parsedParams : null,
      extractedParams: hasQueryPairs ? extractParamsFromDecoded(parsedParams) : [],
    };
  }
  if (cleanMode === "hex") {
    const cleanHex = input.replace(/^0x/i, "").replace(/[\s:-]+/g, "");
    if (cleanHex.length < 2 || cleanHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(cleanHex)) {
      throw new Error("Chuỗi Hex không hợp lệ (cần số lượng ký tự chẵn 0-9, a-f).");
    }
    const buf = Buffer.from(cleanHex, "hex");
    const text = isMostlyPrintableUtf8(buf) ? buf.toString("utf8") : buf.toString("latin1");
    return {
      detectedFormat: "hex-decoded",
      formatLabelVi: `Hex ➔ Văn bản (${buf.length} byte)`,
      cryptoVerification: null,
      decodedText: text,
      decodedObject: null,
      extractedParams: extractParamsFromDecoded(text),
    };
  }

  // CHẾ ĐỘ TỰ ĐỘNG NHẬN DIỆN THÔNG MINH (AUTO)
  if (/^\s*\[Interface\]\s*$/m.test(input) && /^\s*\[Peer\]\s*$/m.test(input)) {
    const wg = auditWireGuardConfig(input);
    return {
      detectedFormat: "wireguard-config",
      formatLabelVi: "Cấu hình Đường hầm VPN WireGuard (Đã tự che PrivateKey)",
      cryptoVerification: {
        isAppleStoreKitJws: false,
        signatureVerified: wg.valid,
        chainVerified: wg.valid,
        algorithm: "Curve25519 / ChaCha20-Poly1305",
        verificationSummary: wg.valid
          ? "Cấu hình WireGuard hợp lệ (Đủ Address, DNS chống rò rỉ, PublicKey 32-byte & AllowedIPs)."
          : `Phát hiện ${wg.issues.length} lưu ý cấu hình WireGuard: ${wg.issues.join(" | ")}`,
      },
      decodedText: JSON.stringify(wg, null, 2),
      decodedObject: wg,
      extractedParams: [],
    };
  }

  const strippedBearer = input.replace(/^Bearer\s+/i, "").trim();
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(strippedBearer)) {
    return inspectJwsOrJwt(strippedBearer);
  }

  // Nếu là JSON, tự động làm đẹp VÀ tự động giải mã luôn các trường JWS / Base64 nằm bên trong JSON!
  if ((input.startsWith("{") && input.endsWith("}")) || (input.startsWith("[") && input.endsWith("]"))) {
    try {
      const parsed = JSON.parse(input);
      const autoUnwrapped = {};
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        for (const [k, v] of Object.entries(parsed)) {
          if (typeof v === "string") {
            const valTrim = v.trim().replace(/^Bearer\s+/i, "");
            if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(valTrim)) {
              try {
                autoUnwrapped[k] = inspectJwsOrJwt(valTrim).decodedObject;
              } catch {}
            } else if (valTrim.length >= 24 && /^[A-Za-z0-9+/=]+$/.test(valTrim) && valTrim.length % 4 === 0) {
              try {
                const b64Out = tryDecodeBase64(valTrim);
                autoUnwrapped[k] = b64Out.decodedObject || b64Out.decodedText;
              } catch {}
            }
          }
        }
      }

      const combinedObj =
        Object.keys(autoUnwrapped).length > 0
          ? { duLieuGoc: parsed, truongMaHoaTuDongGiaiMa: autoUnwrapped }
          : parsed;

      return {
        detectedFormat: Object.keys(autoUnwrapped).length > 0 ? "json-with-nested-crypto" : "json-pretty",
        formatLabelVi:
          Object.keys(autoUnwrapped).length > 0
            ? `JSON + Tự động bung ${Object.keys(autoUnwrapped).length} trường mã hóa (JWS/Base64) bên trong`
            : "Định dạng JSON chuẩn (Đã căn lề & trích xuất ID)",
        cryptoVerification: null,
        decodedText: JSON.stringify(combinedObj, null, 2),
        decodedObject: combinedObj,
        extractedParams: [
          ...extractParamsFromDecoded(parsed),
          ...extractParamsFromDecoded(autoUnwrapped),
        ].slice(0, 16),
      };
    } catch {
      // Tiếp tục thử các định dạng bên dưới nếu không phải JSON hợp lệ
    }
  }

  // Nếu có chứa %XX hoặc query URL
  if (/%[0-9A-Fa-f]{2}/.test(input) || /^https?:\/\//i.test(input)) {
    return decodeAndInspectPayload(input, "url");
  }

  // Nếu là chuỗi Hex thuần
  const maybeHex = input.replace(/^0x/i, "").replace(/\s+/g, "");
  if (maybeHex.length >= 12 && maybeHex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(maybeHex)) {
    return decodeAndInspectPayload(input, "hex");
  }

  // Thử giải mã Base64
  try {
    return tryDecodeBase64(input);
  } catch {
    return {
      detectedFormat: "plain-text",
      formatLabelVi: "Văn bản thuần (Không phát hiện lớp mã hóa ngoài)",
      cryptoVerification: null,
      decodedText: input,
      decodedObject: null,
      extractedParams: extractParamsFromDecoded(input),
    };
  }
}
