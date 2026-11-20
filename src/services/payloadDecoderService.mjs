// src/services/payloadDecoderService.mjs — Bộ Giải Mã & Kiểm Định Thật 100% (StoreKit 2 JWS x5c ES256, JWT, Base64/PKCS#7, URL, Hex, WireGuard Config)
import crypto from "node:crypto";

const INTERESTING_KEY_RE =
  /(id|uid|uuid|guid|token|session|key|code|product|bundle|user|account|order|trans|receipt|storefront|price|version|sub|iss|aud|bid|environment|originalTransactionId|transactionId|productId|appAccountToken|dsid)/i;

function formatEpochVi(val) {
  const num = Number(val);
  if (!Number.isFinite(num) || num <= 0) return null;
  // Epoch giây (10 chữ số) vs mili-giây (13 chữ số)
  const ms = num < 1e11 ? num * 1000 : num;
  if (ms < 946684800000 || ms > 4102444800000) return null;
  return new Date(ms).toISOString();
}

function collectInterestingParams(input, sourceTag = "Giải mã", maxCount = 20) {
  const map = new Map();
  const add = (rawK, rawV) => {
    if (map.size >= maxCount) return;
    const key = String(rawK || "")
      .trim()
      .replace(/[^A-Za-z0-9_.-]+/g, "_");
    if (!key) return;
    if (rawV === null || rawV === undefined || typeof rawV === "boolean" || typeof rawV === "object") return;
    const val = String(rawV).trim();
    if (!val || val.length > 220) return;
    if (!map.has(key)) {
      map.set(key, { key, value: val, source: sourceTag });
    }
  };

  const walk = (node, depth) => {
    if (!node || typeof node !== "object" || depth > 4 || map.size >= maxCount) return;
    if (Array.isArray(node)) {
      for (const item of node.slice(0, 8)) walk(item, depth + 1);
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (v && typeof v === "object") {
        walk(v, depth + 1);
      } else if (INTERESTING_KEY_RE.test(k)) {
        add(k, v);
      }
    }
  };

  walk(input, 0);
  return Array.from(map.values());
}

function tryDecodeBase64Buffer(str) {
  const clean = str.replace(/\s+/g, "");
  if (clean.length < 8) return null;
  const isBase64Url = /[-_]/.test(clean) && !/[+/]/.test(clean);
  const normalized = isBase64Url ? clean.replace(/-/g, "+").replace(/_/g, "/") : clean;
  if (!/^[A-Za-z0-9+/]+=*$/.test(normalized)) return null;
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + "=".repeat(padLen);
  try {
    const buf = Buffer.from(padded, "base64");
    if (buf.length === 0) return null;
    return buf;
  } catch {
    return null;
  }
}

function extractPrintableAsciiStrings(buf, minLen = 4, limit = 60) {
  const out = [];
  let cur = "";
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b <= 0x7e) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= minLen) {
        out.push(cur);
        if (out.length >= limit) break;
      }
      cur = "";
    }
  }
  if (cur.length >= minLen && out.length < limit) {
    out.push(cur);
  }
  return out;
}

export function auditWireGuardConfig(confText) {
  const issues = [];
  const text = String(confText || "");
  if (!/^\s*\[Interface\]\s*$/m.test(text) || !/^\s*\[Peer\]\s*$/m.test(text)) {
    return {
      valid: false,
      issues: ["Thiếu khối [Interface] hoặc [Peer] bắt buộc của cấu hình WireGuard."],
      redactedPreview: redactWireGuardSecrets(text),
    };
  }

  const addrMatches = [...text.matchAll(/^\s*Address\s*=\s*([^\r\n#;]+)/gm)].map((m) => m[1].trim());
  if (addrMatches.length === 0) {
    issues.push("Thiếu trường Address bắt buộc bên trong [Interface].");
  }

  const mtuMatch = text.match(/^\s*MTU\s*=\s*(\d+)/m);
  if (mtuMatch) {
    const mtu = Number(mtuMatch[1]);
    if (mtu < 1280 || mtu > 1420) {
      issues.push(`Giá trị MTU=${mtu} nằm ngoài ngưỡng tối ưu chống phân mảnh WireGuard (1280..1420).`);
    }
  }

  const dnsMatches = [...text.matchAll(/^\s*DNS\s*=\s*([^\r\n#;]+)/gm)].map((m) => m[1].trim());
  if (dnsMatches.length === 0) {
    issues.push("Cảnh báo rò rỉ DNS: Chưa khai báo trường DNS bên trong [Interface].");
  }

  const pubKeys = [...text.matchAll(/^\s*PublicKey\s*=\s*([^\r\n#;]+)/gm)].map((m) => m[1].trim());
  if (pubKeys.length === 0) {
    issues.push("Thiếu khóa PublicKey bên trong [Peer].");
  } else {
    for (const pk of pubKeys) {
      const okLen = pk.length === 44 && pk.endsWith("=");
      let byteOk = false;
      if (okLen) {
        try {
          byteOk = Buffer.from(pk, "base64").length === 32;
        } catch {
          byteOk = false;
        }
      }
      if (!okLen || !byteOk) {
        issues.push("Khóa PublicKey không đúng chuẩn Curve25519 Base64 (32 byte / 44 ký tự).");
      }
    }
  }

  const allowedMatches = [...text.matchAll(/^\s*AllowedIPs\s*=\s*([^\r\n#;]+)/gm)].map((m) => m[1].trim());
  if (allowedMatches.length === 0) {
    issues.push("Thiếu trường định tuyến AllowedIPs bên trong [Peer].");
  }

  return {
    valid: issues.length === 0,
    issues,
    mtu: mtuMatch ? Number(mtuMatch[1]) : null,
    addresses: addrMatches,
    dns: dnsMatches,
    allowedIPs: allowedMatches,
    redactedPreview: redactWireGuardSecrets(text),
  };
}

export function redactWireGuardSecrets(confText) {
  return String(confText || "").replace(
    /^(\s*(?:PrivateKey|PresharedKey)\s*=\s*)([^\r\n#;]+)/gm,
    "$1[ĐÃ_CHE_KHÓA_BÍ_MẬT_WG]"
  );
}

function decodeJwsOrJwtToken(rawToken) {
  const clean = rawToken.trim().replace(/^Bearer\s+/i, "").trim();
  const parts = clean.split(".");
  if (parts.length !== 3) return null;

  let header;
  let payload;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }

  // Trường hợp 1: Apple StoreKit 2 / App Store Server API v2 / ASSN V2 JWS (có chuỗi chứng chỉ x5c + ES256)
  if (Array.isArray(header?.x5c) && header.x5c.length > 0) {
    let certChainValid = true;
    let chainError = "";
    let signatureVerified = false;
    const certificates = [];

    try {
      const certs = header.x5c.map((b64Der) => new crypto.X509Certificate(Buffer.from(b64Der, "base64")));
      for (let i = 0; i < certs.length; i++) {
        certificates.push({
          index: i,
          role: i === 0 ? "Chứng chỉ Lá (Leaf)" : i === certs.length - 1 ? "Chứng chỉ Gốc (Root CA)" : "Chứng chỉ Trung gian",
          subject: certs[i].subject,
          issuer: certs[i].issuer,
          validFrom: certs[i].validFrom,
          validTo: certs[i].validTo,
        });
        if (i < certs.length - 1 && !certs[i].verify(certs[i + 1].publicKey)) {
          certChainValid = false;
          chainError = `Đứt gãy mắt xích chứng chỉ x5c tại vị trí ${i} -> ${i + 1}`;
        }
      }

      if (header.alg === "ES256") {
        signatureVerified = crypto.verify(
          "sha256",
          Buffer.from(`${parts[0]}.${parts[1]}`),
          { key: certs[0].publicKey, dsaEncoding: "ieee-p1363" },
          Buffer.from(parts[2], "base64url")
        );
      }
    } catch (err) {
      certChainValid = false;
      chainError = err?.message || String(err);
    }

    const readableTimestamps = {};
    for (const k of ["purchaseDate", "originalPurchaseDate", "expiresDate", "signedDate", "revocationDate"]) {
      if (payload?.[k]) {
        readableTimestamps[k] = formatEpochVi(payload[k]);
      }
    }

    const extractedParams = collectInterestingParams(payload, "JWS StoreKit");
    return {
      detectedFormat: "apple_jws_x5c",
      formatLabel: "Chữ ký Giao dịch Apple StoreKit 2 / Server API v2 (JWS ES256 + x5c)",
      truthStatus:
        signatureVerified && certChainValid
          ? "ĐÃ XÁC THỰC CHỮ KÝ MẬT MÃ ES256 & CHUỖI CHỨNG CHỈ X5C HỢP LỆ"
          : "ĐÃ GIẢI MÃ NỘI DUNG NHƯNG CHỮ KÝ MẬT MÃ KHÔNG KHỚP HOẶC ĐỨT CHUỖI X5C",
      cryptography: {
        algorithm: header.alg || "UNKNOWN",
        signatureVerified,
        certChainValid,
        chainError: chainError || null,
        certificatesCount: certificates.length,
        certificates,
      },
      summary: {
        environment: payload.environment || "Không rõ",
        bundleId: payload.bundleId || payload.bid || null,
        productId: payload.productId || null,
        transactionId: payload.transactionId || null,
        originalTransactionId: payload.originalTransactionId || null,
        inAppOwnershipType: payload.inAppOwnershipType || null,
        readableTimestamps,
      },
      decoded: {
        header,
        payload,
      },
      extractedParams,
    };
  }

  // Trường hợp 2: JWT tiêu chuẩn (OAuth2 / Đăng nhập / App Store Connect API Token)
  const nowSec = Math.floor(Date.now() / 1000);
  const expSec = typeof payload?.exp === "number" ? payload.exp : null;
  const iatSec = typeof payload?.iat === "number" ? payload.iat : null;
  const isExpired = expSec !== null ? nowSec >= expSec : null;

  return {
    detectedFormat: "jwt",
    formatLabel: `Thẻ Phiên JWT (${header?.alg || "Không rõ thuật toán"})`,
    truthStatus:
      isExpired === null
        ? "ĐÃ GIẢI MÃ HEADER & PAYLOAD (Không có trường hạn dùng exp)"
        : isExpired
        ? `THẺ JWT ĐÃ HẾT HẠN (${Math.abs(nowSec - expSec)} giây trước)`
        : `THẺ JWT ĐANG CÒN HẠN (Còn ${expSec - nowSec} giây)`,
    cryptography: {
      algorithm: header?.alg || "UNKNOWN",
      keyId: header?.kid || null,
      signatureVerified: null,
      note: "JWT thông thường cần khóa bí mật/khóa công khai của máy chủ phát hành để kiểm tra chữ ký.",
    },
    summary: {
      issuer: payload?.iss || null,
      subject: payload?.sub || null,
      audience: payload?.aud || null,
      issuedAtIso: iatSec ? formatEpochVi(iatSec) : null,
      expiresAtIso: expSec ? formatEpochVi(expSec) : null,
      isExpired,
    },
    decoded: {
      header,
      payload,
    },
    extractedParams: collectInterestingParams(payload, "Thẻ JWT"),
  };
}

export function decodeAndInspectPayload(rawInput = "") {
  const text = String(rawInput ?? "").trim();
  if (!text) {
    const err = new Error("Vui lòng dán chuỗi cần giải mã (JWS StoreKit, JWT, Base64 biên lai, URL hoặc JSON).");
    err.statusCode = 400;
    throw err;
  }

  // 1. Kiểm tra nếu người dùng dán cấu hình VPN WireGuard ([Interface] + [Peer])
  if (/^\s*\[Interface\]\s*$/m.test(text) && /^\s*\[Peer\]\s*$/m.test(text)) {
    const wgAudit = auditWireGuardConfig(text);
    return {
      detectedFormat: "wireguard_config",
      formatLabel: "Cấu hình Đường hầm VPN WireGuard",
      truthStatus: wgAudit.valid
        ? "CẤU HÌNH WIREGUARD HỢP LỆ (Đủ Address, DNS, PublicKey 32-byte, AllowedIPs)"
        : `PHÁT HIỆN ${wgAudit.issues.length} LƯU Ý TRONG CẤU HÌNH WIREGUARD`,
      decoded: wgAudit,
      extractedParams: [],
    };
  }

  // 2. Kiểm tra JWS / JWT trực tiếp (hoặc trích JWS từ trong chuỗi JSON như signedTransactionInfo / signedPayload)
  const directJwt = decodeJwsOrJwtToken(text);
  if (directJwt) return directJwt;

  // 3. Kiểm tra JSON (kể cả JSON chứa bên trong là JWS StoreKit như {"signedTransactionInfo": "eyJ..."})
  if ((text.startsWith("{") && text.endsWith("}")) || (text.startsWith("[") && text.endsWith("]"))) {
    try {
      const parsedJson = JSON.parse(text);
      const embeddedJwsKey = ["signedTransactionInfo", "signedRenewalInfo", "signedPayload", "jwsRepresentation"].find(
        (k) => typeof parsedJson?.[k] === "string" && parsedJson[k].split(".").length === 3
      );
      if (embeddedJwsKey) {
        const innerJws = decodeJwsOrJwtToken(parsedJson[embeddedJwsKey]);
        if (innerJws) {
          const outerParams = collectInterestingParams(parsedJson, "Gói JSON");
          const mergedMap = new Map();
          for (const p of [...innerJws.extractedParams, ...outerParams]) {
            if (!mergedMap.has(p.key)) mergedMap.set(p.key, p);
          }
          return {
            ...innerJws,
            formatLabel: `${innerJws.formatLabel} (Bóc tự động từ trường '${embeddedJwsKey}')`,
            outerEnvelope: parsedJson,
            extractedParams: Array.from(mergedMap.values()),
          };
        }
      }

      return {
        detectedFormat: "json",
        formatLabel: "Dữ liệu Cấu trúc JSON",
        truthStatus: "ĐÃ ĐỊNH DẠNG CHUẨN & TRÍCH XUẤT THAM SỐ TỰ ĐỘNG",
        decoded: parsedJson,
        extractedParams: collectInterestingParams(parsedJson, "Dữ liệu JSON"),
      };
    } catch {
      // Tiếp tục thử các bộ giải mã khác nếu không phải JSON chuẩn
    }
  }

  // 4. Kiểm tra URL hoặc chuỗi Query String (?a=1&b=2 hoặc https://...)
  if (/^https?:\/\//i.test(text) || (text.includes("=") && (text.includes("&") || text.includes("%")))) {
    try {
      let queryObj = {};
      let baseUrl = null;
      if (/^https?:\/\//i.test(text)) {
        const u = new URL(text);
        baseUrl = `${u.origin}${u.pathname}`;
        for (const [k, v] of u.searchParams.entries()) {
          queryObj[k] = v;
        }
      } else {
        const cleanQ = text.startsWith("?") ? text.slice(1) : text;
        const sp = new URLSearchParams(cleanQ);
        for (const [k, v] of sp.entries()) {
          queryObj[k] = v;
        }
      }
      if (Object.keys(queryObj).length > 0) {
        return {
          detectedFormat: "url_query",
          formatLabel: "Đường dẫn URL & Tham số Truy vấn (URL-Decoded)",
          truthStatus: `ĐÃ TÁCH ${Object.keys(queryObj).length} THAM SỐ TRUY VẤN`,
          decoded: {
            ...(baseUrl ? { baseUrl } : {}),
            params: queryObj,
          },
          extractedParams: collectInterestingParams(queryObj, "Tham số URL"),
        };
      }
    } catch {
      // Tiếp tục thử Base64 / Hex
    }
  }

  // 5. Kiểm tra chuỗi Hex thuần túy
  const cleanHex = text.replace(/\s+/g, "").replace(/^0x/i, "");
  if (cleanHex.length >= 16 && cleanHex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(cleanHex)) {
    const buf = Buffer.from(cleanHex, "hex");
    const utf8 = buf.toString("utf8");
    return {
      detectedFormat: "hex",
      formatLabel: `Chuỗi Mã Thập Lục Phân (Hex — ${buf.length} byte)`,
      truthStatus: "ĐÃ CHUYỂN ĐỔI TỪ HEX SANG VĂN BẢN / CHUỖI KÝ TỰ",
      decoded: {
        byteLength: buf.length,
        utf8Preview: utf8,
        printableStrings: extractPrintableAsciiStrings(buf, 4, 40),
      },
      extractedParams: [],
    };
  }

  // 6. Kiểm tra Base64 / Base64URL (bao gồm JSON bọc Base64 hoặc Biên lai Apple PKCS#7 ASN.1)
  const b64Buf = tryDecodeBase64Buffer(text);
  if (b64Buf) {
    const utf8 = b64Buf.toString("utf8");
    const printableRatio =
      utf8.length > 0
        ? [...utf8].filter((ch) => {
            const c = ch.charCodeAt(0);
            return c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126) || c >= 160;
          }).length / utf8.length
        : 0;

    if (printableRatio > 0.85) {
      const trimmedUtf = utf8.trim();
      if (
        (trimmedUtf.startsWith("{") && trimmedUtf.endsWith("}")) ||
        (trimmedUtf.startsWith("[") && trimmedUtf.endsWith("]"))
      ) {
        try {
          const parsedInner = JSON.parse(trimmedUtf);
          return {
            detectedFormat: "base64_json",
            formatLabel: `Chuỗi Base64 chứa JSON (${b64Buf.length} byte)`,
            truthStatus: "ĐÃ GIẢI MÃ BASE64 & PHÂN TÍCH CẤU TRÚC JSON BÊN TRONG",
            decoded: parsedInner,
            extractedParams: collectInterestingParams(parsedInner, "Base64 JSON"),
          };
        } catch {
          // Rơi xuống nhánh văn bản Base64
        }
      }
      return {
        detectedFormat: "base64_text",
        formatLabel: `Chuỗi Văn Bản Mã Hóa Base64 (${b64Buf.length} byte)`,
        truthStatus: "ĐÃ GIẢI MÃ BASE64 SANG VĂN BẢN UTF-8",
        decoded: {
          byteLength: b64Buf.length,
          text: utf8,
        },
        extractedParams: [],
      };
    }

    // Nhị phân ASN.1 / PKCS#7 (Ví dụ: receipt-data từ appStoreReceiptURL của StoreKit 1)
    const isPkcs7 = b64Buf[0] === 0x30;
    const asciiStrings = extractPrintableAsciiStrings(b64Buf, 4, 80);
    const detectedEnv = asciiStrings.find((s) => /Sandbox|Production/i.test(s)) || null;
    const extractedReceiptIds = [];
    for (const s of asciiStrings) {
      if (/^[A-Za-z0-9]+(\.[A-Za-z0-9_-]+){2,}$/.test(s) && !s.includes("apple.com") && !s.includes("Apple")) {
        extractedReceiptIds.push({ key: "receipt_identifier", value: s, source: "Biên lai PKCS#7" });
      }
    }

    return {
      detectedFormat: isPkcs7 ? "apple_pkcs7_receipt" : "base64_binary",
      formatLabel: isPkcs7
        ? `Biên lai Nhị phân ASN.1 / PKCS#7 (StoreKit 1 receipt-data • ${b64Buf.length} byte)`
        : `Dữ liệu Nhị phân Base64 (${b64Buf.length} byte)`,
      truthStatus: isPkcs7
        ? `ĐÃ TRÍCH XUẤT ${asciiStrings.length} CHUỖI ĐỊNH DANH BÊN TRONG VÙNG CHỨA PKCS#7 (Chế độ chỉ đọc)`
        : `ĐÃ GIẢI MÃ ${b64Buf.length} BYTE NHỊ PHÂN & LỌC CHUỖI ĐỌC ĐƯỢC`,
      decoded: {
        byteLength: b64Buf.length,
        detectedEnvironmentHint: detectedEnv,
        printableStrings: asciiStrings,
      },
      extractedParams: extractedReceiptIds.slice(0, 8),
    };
  }

  // 7. Thử giải mã URL-encoded đơn lẻ (%7B%22...)
  if (/%[0-9A-Fa-f]{2}/.test(text)) {
    try {
      const dec = decodeURIComponent(text);
      return {
        detectedFormat: "uri_component",
        formatLabel: "Chuỗi Mã Hóa Phần Trăm URL (decodeURIComponent)",
        truthStatus: "ĐÃ GIẢI MÃ KÝ TỰ URL-ENCODED",
        decoded: { text: dec },
        extractedParams: [],
      };
    } catch {
      // Bỏ qua
    }
  }

  return {
    detectedFormat: "plain_text",
    formatLabel: "Văn bản Thuần túy (Không phát hiện lớp mã hóa Base64 / JWS / Hex)",
    truthStatus: "GIỮ NGUYÊN NỘI DUNG GỐC (Chuỗi đầu vào không bị mã hóa)",
    decoded: {
      length: text.length,
      text,
    },
    extractedParams: [],
  };
}

