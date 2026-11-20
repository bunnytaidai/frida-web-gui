// tests/studioAdvanced.test.mjs — Kiểm thử bộ tính năng cao cấp Trạm Điều Khiển Frida v4.0 (Compiler ObjC, Bắt Gói Tin + Hộp Trả Lời, HTTP Repeater, Sổ Lưu Mã ID, 21 Mẫu JS)
import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs/promises";
import crypto from "node:crypto";
import vm from "node:vm";
import express from "express";
import { FridaScriptCompiler } from "../src/infra/scriptCompiler.mjs";
import { FridaBridge } from "../src/infra/fridaBridge.mjs";
import { SnippetRepository } from "../src/infra/snippetRepository.mjs";
import { ParamVaultRepository } from "../src/infra/paramVaultRepository.mjs";
import { WorkspaceSettingsRepository } from "../src/infra/workspaceSettingsRepository.mjs";
import { decodeAndInspectPayload } from "../src/infra/payloadDecoder.mjs";
import { extractJsRootFrame, logger } from "../src/infra/logger.mjs";
import { FridaSessionService } from "../src/services/fridaSessionService.mjs";
import { createApiRouter } from "../src/api/routes.mjs";

test("1. FridaScriptCompiler: Nhúng thành công frida-objc-bridge & hỗ trợ cả JS thuần lẫn ES import", async () => {
  const compiler = new FridaScriptCompiler();

  const plainOut = await compiler.compileUserScript("console.log(ObjC.available);", {
    enableObjCBridge: true,
  });
  const plainLines = plainOut.compiledSource.split("\n");
  assert.equal(plainLines[plainOut.lineOffset], "console.log(ObjC.available);", "lineOffset phải trỏ đúng dòng đầu tiên của mã người dùng");
  assert.ok(plainOut.compiledSource.includes("__studioGetAppManifest"));
  assert.ok(plainOut.compiledSource.length > 5000, "Phải chứa mã bundle của frida-objc-bridge");

  const esmOut = await compiler.compileUserScript(
    `const x: number = 42;\nexport const answer = x;\nconsole.log(answer);`,
    { enableObjCBridge: false }
  );
  assert.equal(esmOut.bundledWithEsbuild, true);
  assert.ok(esmOut.compiledSource.includes("42"));
});

test("2. Logger Ring-Buffer & extractJsRootFrame: Bóc tách đúng file:dòng và lọc phân trang", () => {
  const sampleErr = new Error("Lỗi thử nghiệm");
  const frame = extractJsRootFrame(sampleErr);
  assert.equal(frame.filePath, "studioAdvanced.test.mjs");
  assert.ok(frame.lineNumber > 0);

  logger.info("Thông điệp kiểm tra tìm kiếm đặc biệt XYZ987");
  const res = logger.queryLogs({ search: "xyz987", page: 1, limit: 10 });
  assert.ok(res.items.length >= 1);
  assert.equal(res.meta.page, 1);
});

test("3. FridaSessionService: Gọi hàm RPC, truy vấn Inspector và lọc Bảng Log", async () => {
  const fakeScript = {
    isDestroyed: false,
    logHandler: null,
    exports: {
      ping: async (name) => ({ pong: name }),
      __studioGetAppManifest: async () => ({ pid: 999, bundleId: "com.test.demo" }),
    },
    message: { connect() {} },
    async load() {
      this.logHandler?.("info", "Dòng log mẫu số 1");
      this.logHandler?.("error", "Dòng lỗi mẫu số 2");
    },
    async unload() {
      this.isDestroyed = true;
    },
  };

  const svc = new FridaSessionService({
    bridge: {
      async resolveWorkingDevice() {
        return {
          async attach() {
            return {
              pid: 999,
              isDetached: () => false,
              detach: async () => {},
              detached: { connect() {} },
              createScript: async () => fakeScript,
            };
          },
        };
      },
    },
    emit: () => {},
  });

  // Khi chưa gắn phiên -> gọi RPC phải báo lỗi rõ ràng
  await assert.rejects(() => svc.callRpcExport("ping", ["Tho"]), /Hiện chưa có phiên Frida nào đang chạy/);

  await svc.runScript({
    deviceId: "usb",
    mode: "attach",
    target: "999",
    code: "console.log(1);",
  });

  const rpcRes = await svc.callRpcExport("ping", ["Antidv"]);
  assert.deepEqual(rpcRes.result, { pong: "Antidv" });

  const manifest = await svc.inspectProcess("manifest");
  assert.equal(manifest.bundleId, "com.test.demo");

  const errorLogs = svc.queryEventLogs({ level: "error" });
  assert.equal(errorLogs.items.length, 1);
  assert.ok(errorLogs.items[0].text.includes("Dòng lỗi mẫu số 2"));
});

test("4. SnippetRepository: Lưu mới, đọc danh sách và xóa an toàn kịch bản tự tạo", async () => {
  const tmpSnippetsFile = path.join(os.tmpdir(), `frida-test-snippets-${Date.now()}.json`);
  const repo = new SnippetRepository({ customFilePath: tmpSnippetsFile });
  try {
    const saved = await repo.saveCustom({
      title: "Kịch bản Test Tự Động",
      description: "Chỉ dùng trong bài kiểm thử",
      code: "console.log('test snippet');",
    });
    assert.ok(saved.id.startsWith("custom-"));

    const all = await repo.listAll();
    assert.ok(all.some((s) => s.id === saved.id));

    await assert.rejects(() => repo.deleteCustom("builtin-runtime-overview"), /Không thể xóa kịch bản mẫu mặc định/);

    const deleted = await repo.deleteCustom(saved.id);
    assert.equal(deleted, true);
  } finally {
    await fs.rm(tmpSnippetsFile, { force: true }).catch(() => {});
  }
});

test("5. Kho 21 mẫu JS Tiếng Việt (7 bảng): Đủ 5 mẫu StoreKit & Sandbox TestFlight biên dịch sạch 100%", async () => {
  const repo = new SnippetRepository();
  const compiler = new FridaScriptCompiler();
  const all = await repo.listAll();
  const builtins = all.filter((s) => s.builtin);

  assert.equal(builtins.length, 21, "Phải có đủ 21 mẫu JS mặc định");
  const categories = Array.from(new Set(builtins.map((s) => s.category)));
  assert.equal(categories.length, 7, "Phải chia đúng 7 bảng chuyên đề Tiếng Việt");

  const storeKitItems = builtins.filter((s) => s.category === "7. StoreKit & Sandbox TestFlight");
  assert.equal(storeKitItems.length, 5, "Bảng 7 (StoreKit & Sandbox TestFlight) phải có đủ 5 mẫu");

  for (const item of builtins) {
    assert.ok(item.title.length > 5);
    assert.ok(item.description.length > 10);
    assert.ok(item.code.includes("//"), `Mẫu ${item.id} phải có chú thích Tiếng Việt`);
  }

  for (const sk of storeKitItems) {
    const compiled = await compiler.compileUserScript(sk.code, { enableObjCBridge: true });
    assert.ok(compiled.compiledSource.length > 5000, `Mẫu ${sk.id} phải biên dịch thành công`);
  }
});

test("6. REST API v3.0: Kiểm tra sức khỏe frida-server, Tự động sửa lỗi (Idempotency-Key) & Mã HTTP chuẩn", async () => {
  let repairCalls = 0;
  const fakeBridge = {
    async checkFridaServerHealth(deviceId) {
      return {
        status: "healthy",
        summary: "Máy chủ Frida 17.26.2 đang hoạt động tốt",
        deviceId: deviceId || "usb",
        pcSdkVersion: "17.26.2",
        serverVersion: "17.26.2",
        latencyMs: 12,
        checks: [{ id: "daemon", ok: true, label: "Máy chủ frida-server phản hồi" }],
      };
    },
    async repairConnection(deviceId) {
      repairCalls += 1;
      return {
        repairedAt: new Date().toISOString(),
        steps: ["Đã làm mới cầu nối cổng USB 27042."],
        report: {
          status: "healthy",
          deviceId: deviceId || "usb",
          pcSdkVersion: "17.26.2",
          serverVersion: "17.26.2",
        },
      };
    },
  };

  const fakeSessionService = {
    getStatus: () => ({ active: false }),
    stopSession: async () => ({ active: false }),
    queryEventLogs: () => ({ items: [], meta: { page: 1, limit: 50, totalItems: 0, totalPages: 1 } }),
  };

  const app = express();
  app.use(express.json());
  app.use(
    "/api",
    createApiRouter({
      bridge: fakeBridge,
      sessionService: fakeSessionService,
      snippetRepo: new SnippetRepository(),
    })
  );

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // a) GET /api/v1/frida-server/status
    const stRes = await fetch(`${baseUrl}/api/v1/frida-server/status?deviceId=usb`);
    assert.equal(stRes.status, 200);
    const stBody = await stRes.json();
    assert.equal(stBody.success, true);
    assert.equal(stBody.data.report.status, "healthy");

    // b) POST /api/v1/frida-server/repair kèm Idempotency-Key chống bấm đúp
    const rp1 = await fetch(`${baseUrl}/api/v1/frida-server/repair`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "idem-v3-test" },
      body: JSON.stringify({ deviceId: "usb" }),
    });
    const rp2 = await fetch(`${baseUrl}/api/v1/frida-server/repair`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "idem-v3-test" },
      body: JSON.stringify({ deviceId: "usb" }),
    });
    assert.equal(rp1.status, 200);
    assert.equal(rp2.status, 200);
    assert.equal(repairCalls, 1, "Idempotency-Key phải chặn gọi trùng repairConnection");

    // c) GET /api/v1/snippets hỗ trợ lọc theo chuyên đề StoreKit & Sandbox TestFlight
    const snRes = await fetch(
      `${baseUrl}/api/v1/snippets?category=${encodeURIComponent("7. StoreKit & Sandbox TestFlight")}`
    );
    const snBody = await snRes.json();
    assert.equal(snRes.status, 200);
    assert.equal(snBody.data.snippets.length, 5);
    assert.ok(
      snBody.data.categories.length >= 7 &&
        snBody.data.categories.includes("7. StoreKit & Sandbox TestFlight")
    );

    // d) Kiểm tra mã lỗi HTTP chuẩn REST (400 & 409 thay vì 200)
    const badCreate = await fetch(`${baseUrl}/api/v1/snippets`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "", code: "" }),
    });
    assert.equal(badCreate.status, 400);
    const badCreateJson = await badCreate.json();
    assert.equal(badCreateJson.error.code, "VALIDATION_FAILED");

    const conflictDel = await fetch(`${baseUrl}/api/v1/snippets/builtin-runtime-overview`, {
      method: "DELETE",
    });
    assert.equal(conflictDel.status, 409);
    const conflictJson = await conflictDel.json();
    assert.equal(conflictJson.error.code, "CONFLICT_STATE");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("7. FridaSessionService v4.0: Bắt Gói Tin + Hộp Trả Lời, Sửa Gửi Lại từ Thiết bị & Chặn SSRF trên PC", async () => {
  const compiler = new FridaScriptCompiler();
  const compiled = await compiler.compileUserScript("console.log('ready');", { enableObjCBridge: true });
  assert.ok(compiled.compiledSource.includes("__studioEnableHttpCapture"));
  assert.ok(compiled.compiledSource.includes("__studioReplayHttpRequest"));

  let messageListener = null;
  const wsEvents = [];

  const fakeScript = {
    isDestroyed: false,
    logHandler: null,
    exports: {
      __studioEnableHttpCapture: async () => ({
        enabled: true,
        message: "Đã bật bắt Gói tin & Hộp trả lời!",
      }),
      __studioReplayHttpRequest: async (spec) => ({
        method: spec.method,
        url: spec.url,
        requestHeaders: spec.headers,
        requestBody: spec.body,
        statusCode: 200,
        responseHeaders: { "content-type": "application/json" },
        responseBody: JSON.stringify({ ok: true, product_id: "com.demo.vip_1m", order_id: "ORD-8899" }),
        elapsedMs: 42,
        errorText: "",
        replayedFromDevice: true,
      }),
    },
    message: {
      connect(fn) {
        messageListener = fn;
      },
    },
    async load() {},
    async unload() {
      this.isDestroyed = true;
    },
  };

  const svc = new FridaSessionService({
    bridge: {
      async resolveWorkingDevice() {
        return {
          async attach() {
            return {
              pid: 4321,
              isDetached: () => false,
              detach: async () => {},
              detached: { connect() {} },
              createScript: async () => fakeScript,
            };
          },
        };
      },
    },
    emit: (event, payload) => wsEvents.push({ event, payload }),
  });

  // 1-click bật bắt gói tin khi chưa có phiên -> tự gắn vào App & bật sniffer
  const capOut = await svc.enableHttpCapture({
    deviceId: "usb",
    target: "com.demo.shop",
    mode: "attach",
  });
  assert.equal(capOut.capture.enabled, true);
  assert.equal(svc.getStatus().status, "running");

  // Giả lập gói tin thật từ iOS gửi về qua send({ __studioType: "http_exchange" })
  messageListener?.(
    {
      type: "send",
      payload: {
        __studioType: "http_exchange",
        method: "GET",
        url: "https://api.demo.shop/v1/catalog?user_id=USR_77",
        requestHeaders: { Accept: "application/json" },
        requestBody: "",
        statusCode: 200,
        responseHeaders: { "content-type": "application/json" },
        responseBody: '{"items":[{"product_id":"com.demo.vip_1m","price":99000}]}',
        elapsedMs: 65,
      },
    },
    null
  );

  const listed = svc.listHttpExchanges({ search: "catalog" });
  assert.equal(listed.items.length, 1);
  assert.equal(listed.items[0].statusCode, 200);
  assert.ok(listed.items[0].responseBody.includes("com.demo.vip_1m"));
  assert.ok(wsEvents.some((e) => e.event === "http:exchange"));

  // Sửa tham số & Gửi lại gói tin ngay từ trong thiết bị (HTTP Repeater)
  const replayed = await svc.replayHttpRequest({
    method: "POST",
    url: "https://api.demo.shop/v1/check-entitlement",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ product_id: "com.demo.vip_1m" }),
    sendFrom: "device",
  });
  assert.equal(replayed.exchange.statusCode, 200);
  assert.equal(replayed.exchange.replayedFromDevice, true);
  assert.ok(replayed.exchange.responseBody.includes("ORD-8899"));

  // Bảo vệ chống SSRF khi gửi từ PC tới localhost hoặc IP metadata nội bộ
  await assert.rejects(
    () =>
      svc.replayHttpRequest({
        method: "GET",
        url: "http://127.0.0.1:3456/api/v1/health",
        sendFrom: "pc",
      }),
    /chặn địa chỉ mạng nội bộ/
  );
  await assert.rejects(
    () =>
      svc.replayHttpRequest({
        method: "GET",
        url: "http://169.254.169.254/latest/meta-data/",
        sendFrom: "pc",
      }),
    /chặn địa chỉ mạng nội bộ/
  );

  svc.clearHttpExchanges();
  assert.equal(svc.listHttpExchanges().items.length, 0);
});

test("8. ParamVaultRepository & REST API v4.0: Lưu, Cập nhật (Upsert), Tìm kiếm & Xóa Tham số / Mã ID", async () => {
  const tmpParamFile = path.join(os.tmpdir(), `frida-test-params-${Date.now()}.json`);
  const paramVault = new ParamVaultRepository({ filePath: tmpParamFile });
  const svc = new FridaSessionService({
    bridge: { async resolveWorkingDevice() { throw new Error("no device"); } },
    emit: () => {},
  });

  const app = express();
  app.use(express.json());
  app.use(
    "/api",
    createApiRouter({
      bridge: {},
      sessionService: svc,
      snippetRepo: new SnippetRepository(),
      paramVault,
    })
  );

  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;
  let createdParamId = null;

  try {
    // 1. Lưu mới 1 mã ID cần thiết (HTTP 201)
    const createRes = await fetch(`${baseUrl}/api/v1/saved-params`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        key: "__test_product_id",
        value: "com.antidv.pro_yearly",
        appId: "com.antidv.app",
        note: "Mã gói năm phục vụ kiểm thử tự động",
      }),
    });
    assert.equal(createRes.status, 201);
    const createBody = await createRes.json();
    createdParamId = createBody.data.param.id;
    assert.equal(createBody.data.param.key, "test_product_id");

    // 2. Lưu trùng key + appId -> Tự động cập nhật giá trị mới (Upsert không sinh rác)
    const upsertRes = await fetch(`${baseUrl}/api/v1/saved-params`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        key: "__test_product_id",
        value: "com.antidv.pro_lifetime",
        appId: "com.antidv.app",
        note: "Đã đổi sang gói trọn đời",
      }),
    });
    const upsertBody = await upsertRes.json();
    assert.equal(upsertBody.data.param.id, createdParamId);
    assert.equal(upsertBody.data.param.value, "com.antidv.pro_lifetime");

    // 3. Tìm kiếm tham số đã lưu
    const listRes = await fetch(`${baseUrl}/api/v1/saved-params?search=pro_lifetime`);
    const listBody = await listRes.json();
    assert.equal(listRes.status, 200);
    assert.ok(listBody.data.items.some((p) => p.id === createdParamId));

    // 4. Kiểm tra chặn SSRF qua REST /api/v1/http-repeater/send trả đúng HTTP 400
    const ssrfRes = await fetch(`${baseUrl}/api/v1/http-repeater/send`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        method: "GET",
        url: "http://localhost:3456/api/v1/health",
        sendFrom: "pc",
      }),
    });
    assert.equal(ssrfRes.status, 400);
    const ssrfJson = await ssrfRes.json();
    assert.equal(ssrfJson.error.code, "VALIDATION_FAILED");
  } finally {
    if (createdParamId) {
      await fetch(`${baseUrl}/api/v1/saved-params/${encodeURIComponent(createdParamId)}`, {
        method: "DELETE",
      });
    }
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(tmpParamFile, { force: true }).catch(() => {});
  }
});

test("9. FridaScriptCompiler v4.0.1: __studioEnableHttpCapture sẵn sàng TRƯỚC mã người dùng & giữ nguyên rpc.exports", async () => {
  const compiler = new FridaScriptCompiler();
  const userCode = [
    "globalThis.__testTypeAtUserStart = typeof globalThis.__studioEnableHttpCapture;",
    "rpc.exports = { customPing(who) { return 'xin-chao-' + who; } };",
  ].join("\n");

  const compiled = await compiler.compileUserScript(userCode, { enableObjCBridge: false });
  const lines = compiled.compiledSource.split("\n");
  assert.equal(
    lines[compiled.lineOffset],
    "globalThis.__testTypeAtUserStart = typeof globalThis.__studioEnableHttpCapture;",
    "lineOffset phải khớp chính xác dòng 1 của userCode để báo đúng số dòng lỗi"
  );

  // Mô phỏng chính xác cơ chế biến đóng (private closure) rpcExports của nhân Frida GumJS 17
  let gumInternalExports = {};
  const mockGumRpc = {};
  Object.defineProperty(mockGumRpc, "exports", {
    configurable: true,
    enumerable: true,
    get() {
      return gumInternalExports;
    },
    set(val) {
      gumInternalExports = val;
    },
  });

  const sandbox = {
    rpc: mockGumRpc,
    send: () => {},
    Process: {
      id: 1234,
      arch: "arm64",
      platform: "darwin",
      pageSize: 16384,
      pointerSize: 8,
      enumerateModules: () => [],
      enumerateThreads: () => [],
      findModuleByName: () => null,
    },
    Frida: { heapSize: 2048 },
    Interceptor: { attach: () => {} },
    Module: { getGlobalExportByName: () => null },
    NativeFunction: function () {},
    Memory: { allocUtf8String: (s) => s },
    ptr: (v) => v,
    NULL: null,
    console,
    setTimeout,
    clearTimeout,
  };
  sandbox.globalThis = sandbox;

  vm.runInNewContext(compiled.compiledSource, sandbox);

  assert.equal(
    sandbox.__testTypeAtUserStart,
    "function",
    "globalThis.__studioEnableHttpCapture bắt buộc phải tồn tại TRƯỚC khi userCode chạy!"
  );
  assert.equal(typeof sandbox.rpc.exports.customPing, "function", "Phải giữ nguyên hàm rpc.exports của người dùng");
  assert.equal(sandbox.rpc.exports.customPing("Antidv"), "xin-chao-Antidv");
  assert.equal(
    typeof sandbox.rpc.exports.__studioEnableHttpCapture,
    "function",
    "Không được làm mất hàm nội bộ __studioEnableHttpCapture khi người dùng gán rpc.exports = {...}"
  );
  assert.equal(
    typeof sandbox.rpc.exports.__studioGetAppManifest,
    "function",
    "Không được làm mất __studioGetAppManifest khi người dùng gán rpc.exports = {...}"
  );
  assert.equal(
    typeof gumInternalExports.__studioReplayHttpRequest,
    "function",
    "Biến đóng gumInternalExports bên trong GumJS bắt buộc phải thấy được hàm nội bộ __studioReplayHttpRequest"
  );
  assert.equal(
    gumInternalExports.customPing("Antidv"),
    "xin-chao-Antidv",
    "Biến đóng gumInternalExports bên trong GumJS bắt buộc phải gọi được hàm customPing của người dùng"
  );
});

test("10. Chuẩn error-handling-logger & Phản hồi rõ ràng khi mã JS không in kết quả ngay", async () => {
  // 1. Kiểm tra tự động che dấu dữ liệu nhạy cảm (token, password, authorization)
  const maskedEntry = logger.warn("Kiểm tra lọc khóa nhạy cảm", {
    authorization: "Bearer secret-jwt-999",
    password: "my-secret-password",
    safeField: "hien-thi-binh-thuong",
  });
  assert.equal(maskedEntry.meta.authorization, "***REDACTED***");
  assert.equal(maskedEntry.meta.password, "***REDACTED***");
  assert.equal(maskedEntry.meta.safeField, "hien-thi-binh-thuong");
  assert.ok(maskedEntry.traceId && maskedEntry.traceId.length >= 6);

  // 2. Khi chạy một đoạn mã chỉ gắn lắng nghe (không gọi console.log hay send ngay), hệ thống phải tự phát thông báo hướng dẫn Tiếng Việt
  const emittedOutputs = [];
  const silentScript = {
    isDestroyed: false,
    logHandler: null,
    exports: {},
    message: { connect() {} },
    async load() {
      // Không phát ra dòng log nào khi mới nạp
    },
    async unload() {
      this.isDestroyed = true;
    },
  };

  const svc = new FridaSessionService({
    bridge: {
      async resolveWorkingDevice() {
        return {
          async attach() {
            return {
              pid: 7788,
              isDetached: () => false,
              detach: async () => {},
              detached: { connect() {} },
              createScript: async () => silentScript,
            };
          },
        };
      },
    },
    emit: (event, payload) => {
      if (event === "script:output") emittedOutputs.push(payload);
    },
  });

  await svc.runScript({
    deviceId: "usb",
    mode: "attach",
    target: "7788",
    code: "// Chỉ gắn chờ sự kiện",
  });

  assert.ok(
    emittedOutputs.some((row) => row.level === "info" && /đang trực chờ|thao tác trên màn hình iPhone|chưa gửi dữ liệu ngay/i.test(row.text)),
    "Phải có thông báo Tiếng Việt giải thích rõ khi mã JS chưa trả dữ liệu ngay lập tức"
  );
});

test("11. v5.0 Khu vực 1: Quản lý Thiết bị Không dây (Wi-Fi) & Xử lý êm lỗi rút cáp (HTTP 404 thay vì 500)", async () => {
  const realBridge = new FridaBridge();

  // Kiểm tra bắt lỗi nhập địa chỉ IP không dây sai định dạng / cổng sai
  await assert.rejects(() => realBridge.addWirelessDevice({ address: "" }), /Vui lòng nhập địa chỉ IP Wi-Fi/);
  await assert.rejects(
    () => realBridge.addWirelessDevice({ address: "bad address with spaces" }),
    /Địa chỉ không dây không hợp lệ/
  );
  await assert.rejects(
    () => realBridge.addWirelessDevice({ address: "192.168.1.50:99999" }),
    /Số cổng Frida không dây/
  );

  // Kiểm tra getDeviceTelemetry trả statusCode = 404 rõ ràng khi thiết bị đã rút cáp (Sửa lỗi task-963.log)
  await assert.rejects(
    async () => {
      try {
        await realBridge.getDeviceTelemetry("non-existent-iphone-udid-9999");
      } catch (err) {
        assert.equal(err.statusCode, 404, "Phải gắn statusCode = 404 thay vì crash 500");
        throw err;
      }
    },
    /Không tìm thấy thiết bị/
  );
});

test("12. v5.0 Khu vực 3 & 4: Công tắc 1 chạm (Tự gắn + Giữ trạng thái khi Hot-Reload) & Kính lúp Soi Hàm / Bộ nhớ", async () => {
  // Phần A: Kiểm chứng RPC Kính lúp Hàm & Bộ nhớ trực tiếp trên mã biên dịch
  const compiler = new FridaScriptCompiler();
  const compiled = await compiler.compileUserScript("console.log('v5');", { enableObjCBridge: false });

  const mockObjC = {
    available: true,
    selector: (s) => s,
    classes: {
      NSBundle: {
        mainBundle: () => ({
          bundlePath: () => "/var/containers/Bundle/Application/UUID/DemoShop.app",
        }),
      },
      DemoPaymentManager: {
        $moduleName: "/var/containers/Bundle/Application/UUID/DemoShop.app/DemoShop",
        $ownMethods: ["- startPurchaseWithProductId:", "- verifyReceiptToken:"],
        "- startPurchaseWithProductId:": { implementation: "0x100004000" },
        "- verifyReceiptToken:": { implementation: "0x100004120" },
      },
      SKPaymentQueue: {
        $moduleName: "/System/Library/Frameworks/StoreKit.framework/StoreKit",
        $ownMethods: ["- addPayment:"],
        "- addPayment:": { implementation: "0x190001000" },
      },
    },
    chooseSync(cls) {
      if (cls === mockObjC.classes.SKPaymentQueue) {
        return [{ handle: "0x2800aa100", $className: "SKPaymentQueue", toString: () => "<SKPaymentQueue: 0x2800aa100>" }];
      }
      return [];
    },
  };

  let gumExports = {};
  const sandbox = {
    ObjC: mockObjC,
    rpc: {
      get exports() {
        return gumExports;
      },
      set exports(v) {
        gumExports = v;
      },
    },
    send: () => {},
    Process: {
      id: 5566,
      arch: "arm64",
      platform: "darwin",
      pageSize: 16384,
      pointerSize: 8,
      enumerateModules: () => [{ name: "DemoShop", path: "/var/containers/Bundle/Application/UUID/DemoShop.app/DemoShop", enumerateExports: () => [] }],
      enumerateThreads: () => [],
      findModuleByName: () => null,
    },
    Frida: { heapSize: 4096 },
    Interceptor: { attach: () => {} },
    Module: { getGlobalExportByName: () => null },
    NativeFunction: function () {},
    Memory: { allocUtf8String: (s) => s },
    ptr: (v) => v,
    NULL: null,
    console,
    setTimeout,
    clearTimeout,
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(compiled.compiledSource, sandbox);

  const foundPurchase = gumExports.__studioSmartFindFunctions({ preset: "purchase", limit: 20 });
  assert.equal(foundPurchase.available, true);
  assert.ok(foundPurchase.totalMatched >= 3);
  assert.equal(foundPurchase.items[0].className, "DemoPaymentManager", "Hàm riêng của App phải được ưu tiên xếp lên đầu");
  assert.equal(foundPurchase.items[0].isAppOwnCode, true);

  const memScan = gumExports.__studioScanMemoryInstances({ className: "SKPaymentQueue", maxItems: 10 });
  assert.equal(memScan.foundClass, true);
  assert.equal(memScan.totalCount, 1);
  assert.equal(memScan.instances[0].handle, "0x2800aa100");

  // Phần B: Kiểm chứng dịch vụ Công tắc 1 chạm tự gắn và tự khôi phục khi Hot-Reload
  const switchCalls = [];
  const createFakeScript = () => ({
    isDestroyed: false,
    logHandler: null,
    exports: {
      __studioSetFeatureSwitch: async (key, enabled) => {
        switchCalls.push({ key, enabled });
        return {
          featureKey: key,
          enabled,
          switches: {
            httpCapture: false,
            storekitObserver: key === "storekitObserver" ? enabled : false,
            authObserver: false,
            storageObserver: false,
            fileAccessObserver: false,
            uiScreenObserver: false,
          },
          message: `Đã cập nhật ${key}=${enabled}`,
        };
      },
    },
    message: { connect() {} },
    async load() {},
    async unload() {
      this.isDestroyed = true;
    },
  });

  const svc = new FridaSessionService({
    bridge: {
      async resolveWorkingDevice() {
        return {
          async attach() {
            return {
              pid: 6789,
              isDetached: () => false,
              detach: async () => {},
              detached: { connect() {} },
              createScript: async () => createFakeScript(),
            };
          },
        };
      },
    },
    emit: () => {},
  });

  const toggleOut = await svc.toggleFeatureSwitch({
    deviceId: "usb",
    target: "com.demo.shop",
    mode: "attach",
    featureKey: "storekitObserver",
    enabled: true,
  });
  assert.equal(toggleOut.switches.storekitObserver, true);
  assert.equal(svc.getStatus().featureSwitches.storekitObserver, true);

  // Hot-Reload mã JS mới -> Công tắc storekitObserver đang bật phải được tự động khôi phục!
  await svc.runScript({
    deviceId: "usb",
    mode: "attach",
    target: "com.demo.shop",
    code: "console.log('hot-reload');",
  });
  assert.ok(
    switchCalls.filter((c) => c.key === "storekitObserver" && c.enabled === true).length >= 2,
    "Sau khi Hot-Reload mã JS mới, công tắc đang bật phải được tự động kích hoạt lại"
  );
});

test("13. v5.0 Khu vực 5: Chặn đứng Path Traversal ngoài Sandbox (HTTP 403) & Quét Két sắt Bảo mật Che dấu", async () => {
  const compiler = new FridaScriptCompiler();
  const compiled = await compiler.compileUserScript("// sandbox check", { enableObjCBridge: false });

  const HOME_PATH = "/var/mobile/Containers/Data/Application/APP-UUID-123";
  const mockObjC = {
    available: true,
    selector: (s) => s,
    Object: function (ptrVal) {
      return { toString: () => String(ptrVal) };
    },
    classes: {
      NSString: {
        stringWithUTF8String_: (s) => ({
          stringByStandardizingPath: () => ({ toString: () => s }),
        }),
      },
      NSFileManager: {
        defaultManager: () => ({
          fileExistsAtPath_isDirectory_: (fullPath, dirPtr) => {
            if (fullPath === HOME_PATH || fullPath === `${HOME_PATH}/Documents`) {
              dirPtr.writeU8(1);
              return true;
            }
            if (fullPath === `${HOME_PATH}/Documents/config.json`) {
              dirPtr.writeU8(0);
              return true;
            }
            return false;
          },
          contentsOfDirectoryAtPath_error_: () => ({
            count: () => 1,
            objectAtIndex_: () => ({ toString: () => "Documents" }),
          }),
          attributesOfItemAtPath_error_: () => ({
            objectForKey_: () => null,
          }),
        }),
      },
      NSData: {
        dataWithContentsOfFile_: () => ({
          length: () => 22,
          subdataWithRange_: () => ({ length: () => 16 }),
        }),
      },
      NSUserDefaults: {
        standardUserDefaults: () => ({
          dictionaryRepresentation: () => ({
            allKeys: () => ({
              count: () => 2,
              objectAtIndex_: (i) => ({ toString: () => (i === 0 ? "auth_session_token" : "theme_color") }),
            }),
            objectForKey_: (k) => ({
              $className: "__NSCFString",
              toString: () => (k.toString() === "auth_session_token" ? "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" : "dark"),
            }),
          }),
        }),
      },
      NSHTTPCookieStorage: {
        sharedHTTPCookieStorage: () => ({
          cookies: () => ({
            count: () => 1,
            objectAtIndex_: () => ({
              name: () => ({ toString: () => "sid_cookie" }),
              domain: () => ({ toString: () => ".demo.shop" }),
              path: () => ({ toString: () => "/" }),
              isSecure: () => true,
              isHTTPOnly: () => true,
              expiresDate: () => null,
              value: () => ({ toString: () => "SESS_SECRET_987654321" }),
            }),
          }),
        }),
      },
    },
  };

  let gumExports = {};
  const sandbox = {
    ObjC: mockObjC,
    rpc: {
      get exports() {
        return gumExports;
      },
      set exports(v) {
        gumExports = v;
      },
    },
    send: () => {},
    Process: {
      id: 9001,
      arch: "arm64",
      platform: "darwin",
      pageSize: 16384,
      pointerSize: 8,
      enumerateModules: () => [],
      enumerateThreads: () => [],
      findModuleByName: () => null,
    },
    Frida: { heapSize: 2048 },
    Interceptor: { attach: () => {} },
    Module: {
      getGlobalExportByName: (sym) => (sym === "NSHomeDirectory" ? "sym_home" : null),
    },
    NativeFunction: function () {
      return () => HOME_PATH;
    },
    Memory: {
      allocUtf8String: (s) => s,
      alloc: () => {
        let byteVal = 0;
        return {
          writeU8: (v) => {
            byteVal = v;
          },
          readU8: () => byteVal,
          writePointer: () => {},
          readPointer: () => null,
        };
      },
    },
    ptr: (v) => ({ isNull: () => !v, toString: () => String(v) }),
    NULL: null,
    console,
    setTimeout,
    clearTimeout,
  };
  sandbox.globalThis = sandbox;
  vm.runInNewContext(compiled.compiledSource, sandbox);

  // 1. Duyệt thư mục gốc Sandbox hợp lệ
  const rootListing = gumExports.__studioListSandboxFiles("");
  assert.equal(rootListing.homeDir, HOME_PATH);
  assert.equal(rootListing.items.length, 1);
  assert.equal(rootListing.items[0].name, "Documents");

  // 2. Chặn tuyệt đối Path Traversal đi ngược ra ngoài Sandbox (../../etc/passwd)
  assert.throws(
    () => gumExports.__studioListSandboxFiles("../../private/etc"),
    /Từ chối truy cập/
  );
  assert.throws(
    () => gumExports.__studioReadSandboxFile("../outside.plist"),
    /Từ chối truy cập/
  );

  // 3. Quét Két sắt Bảo mật chỉ lấy khóa phiên & che dấu mặc định
  const vault = gumExports.__studioInspectSecurityVault();
  assert.equal(vault.counts.userDefaults, 1, "Chỉ lọc đúng khóa liên quan phiên/xác thực, bỏ qua theme_color");
  assert.equal(vault.userDefaultsItems[0].key, "auth_session_token");
  assert.ok(vault.userDefaultsItems[0].maskedPreview.includes("••••"), "Phải có bản xem trước đã che dấu");
  assert.equal(vault.counts.cookies, 1);
  assert.equal(vault.cookies[0].isSecure, true);
  assert.equal(vault.cookies[0].isHTTPOnly, true);

  // 4. Kiểm tra REST API trả đúng HTTP 403 FORBIDDEN_SANDBOX_PATH khi gặp lỗi Từ chối truy cập
  const app = express();
  app.use(express.json());
  app.use(
    "/api",
    createApiRouter({
      bridge: {},
      sessionService: {
        getStatus: () => ({ status: "running" }),
        inspectProcess: async () => {
          throw new Error("Từ chối truy cập: Không được phép đi ngược ra ngoài thư mục dữ liệu riêng (Sandbox)!");
        },
      },
      snippetRepo: new SnippetRepository(),
    })
  );
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  try {
    const res = await fetch(`http://127.0.0.1:${port}/api/v1/sessions/inspections/sandbox-files?relPath=..%2F..`);
    assert.equal(res.status, 403);
    const body = await res.json();
    assert.equal(body.error.code, "FORBIDDEN_SANDBOX_PATH");
  } finally {
    await new Promise((r) => server.close(r));
  }
});

// --- BỘ BÀI KIỂM THỬ NÂNG CẤP TOÀN DIỆN v6.0.0.0 ---
function derLen(len) {
  if (len < 128) return Buffer.from([len]);
  const hex = len.toString(16).padStart(len > 255 ? 4 : 2, "0");
  const bytes = Buffer.from(hex, "hex");
  return Buffer.concat([Buffer.from([0x80 | bytes.length]), bytes]);
}

function derTlv(tag, contentBuf) {
  return Buffer.concat([Buffer.from([tag]), derLen(contentBuf.length), contentBuf]);
}

function createSelfSignedP256CertDer(commonName = "Apple StoreKit Sandbox Test") {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiDer = publicKey.export({ type: "spki", format: "der" });

  // AlgorithmIdentifier: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
  const algId = derTlv(0x30, derTlv(0x06, Buffer.from("2a8648ce3d040302", "hex")));
  const version = derTlv(0xa0, derTlv(0x02, Buffer.from([0x02]))); // v3
  const serial = derTlv(0x02, Buffer.from([0x01]));
  const cnAttr = derTlv(
    0x30,
    derTlv(
      0x31,
      derTlv(
        0x30,
        Buffer.concat([
          derTlv(0x06, Buffer.from("550403", "hex")), // OID 2.5.4.3 CN
          derTlv(0x0c, Buffer.from(commonName, "utf8")),
        ])
      )
    )
  );
  const validity = derTlv(
    0x30,
    Buffer.concat([
      derTlv(0x17, Buffer.from("250101000000Z", "ascii")),
      derTlv(0x17, Buffer.from("350101000000Z", "ascii")),
    ])
  );

  const tbs = derTlv(0x30, Buffer.concat([version, serial, algId, cnAttr, validity, cnAttr, spkiDer]));
  const sigDer = crypto.sign("sha256", tbs, privateKey);
  const sigBitString = derTlv(0x03, Buffer.concat([Buffer.from([0x00]), sigDer]));
  const certDer = derTlv(0x30, Buffer.concat([tbs, algId, sigBitString]));

  return { certBase64: certDer.toString("base64"), privateKey, publicKey };
}

test("14. v6.0 Lưu bền vững Cấu hình Giao diện (WorkspaceSettingsRepository & PUT/GET /api/v1/settings)", async () => {
  const tmpSettingsPath = path.join(os.tmpdir(), `frida-ui-settings-${Date.now()}.json`);
  const settingsRepo = new WorkspaceSettingsRepository({ filePath: tmpSettingsPath });

  const app = express();
  app.use(express.json());
  app.use(
    "/api",
    createApiRouter({
      bridge: {},
      sessionService: { getStatus: () => ({ status: "idle" }) },
      snippetRepo: new SnippetRepository({ customFilePath: `${tmpSettingsPath}.snip` }),
      paramVault: new ParamVaultRepository({ filePath: `${tmpSettingsPath}.param` }),
      settingsRepo,
    })
  );

  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const putRes = await fetch(`${baseUrl}/api/v1/settings`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        activeConnectionChannel: "vpn_mitm_proxy",
        selectedDeviceId: "iphone-usb-test",
        selectedTarget: "com.apple.TestFlight",
        launchMode: "spawn",
        vpnMitmProxyAddress: "127.0.0.1:8888",
        activeMainTab: "editor",
        repeaterDraft: {
          method: "POST",
          url: "https://sandbox.itunes.apple.com/verifyReceipt",
          body: '{"receipt-data":"e30="}',
        },
      }),
    });
    assert.equal(putRes.status, 200);

    // Khởi tạo lại Repository mới trỏ cùng file trên ổ cứng (giả lập F5 Reload / Restart Server)
    const reloadedRepo = new WorkspaceSettingsRepository({ filePath: tmpSettingsPath });
    const persisted = await reloadedRepo.getSettings();
    assert.equal(persisted.activeConnectionChannel, "vpn_mitm_proxy");
    assert.equal(persisted.selectedTarget, "com.apple.TestFlight");
    assert.equal(persisted.launchMode, "spawn");
    assert.equal(persisted.vpnMitmProxyAddress, "127.0.0.1:8888");
    assert.equal(persisted.activeMainTab, "editor");
    assert.equal(persisted.repeaterDraft.method, "POST");
  } finally {
    await new Promise((r) => server.close(r));
    await fs.rm(tmpSettingsPath, { force: true }).catch(() => {});
  }
});

test("15. v6.0 Trạm Đổi Kết Nối 7 Kênh: Báo cáo TCP/HTTP thật 100% (cổng đóng báo offline, cổng mở báo connected)", async () => {
  const tmpSettingsPath = path.join(os.tmpdir(), `frida-conn-settings-${Date.now()}.json`);
  const settingsRepo = new WorkspaceSettingsRepository({ filePath: tmpSettingsPath });
  const realBridge = new FridaBridge();

  // Mở một cổng TCP thật trên máy tính để giả lập Proxy Kiểm định TLS đang sống
  const mockProxyServer = net.createServer((sock) => sock.end());
  await new Promise((r) => mockProxyServer.listen(0, "127.0.0.1", r));
  const openProxyPort = mockProxyServer.address().port;

  // Lấy một cổng chắc chắn đang đóng
  const closedSocketProbe = net.createServer();
  await new Promise((r) => closedSocketProbe.listen(0, "127.0.0.1", r));
  const closedProxyPort = closedSocketProbe.address().port;
  await new Promise((r) => closedSocketProbe.close(r));

  const app = express();
  app.use(express.json());
  app.use(
    "/api",
    createApiRouter({
      bridge: realBridge,
      sessionService: { getStatus: () => ({ status: "idle" }), stopSession: async () => ({ status: "idle" }) },
      snippetRepo: new SnippetRepository({ customFilePath: `${tmpSettingsPath}.snip` }),
      paramVault: new ParamVaultRepository({ filePath: `${tmpSettingsPath}.param` }),
      settingsRepo,
    })
  );

  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Khi cổng Proxy đóng -> bắt buộc báo "offline" hoặc "degraded" (chỉ có card mạng), tuyệt đối không báo xanh giả
    const resClosed = await fetch(
      `${baseUrl}/api/v1/connections/status?vpnMitmProxyAddress=${encodeURIComponent(`127.0.0.1:${closedProxyPort}`)}`
    );
    assert.equal(resClosed.status, 200);
    const bodyClosed = await resClosed.json();
    assert.equal(bodyClosed.data.hub.channels.length, 7, "Phải kiểm kê đủ 7 kênh kết nối trong source");
    const vpnClosed = bodyClosed.data.hub.channels.find((c) => c.id === "vpn_mitm_proxy");
    assert.notEqual(vpnClosed.status, "connected", "Cổng Proxy đang đóng thì tuyệt đối không được báo connected!");

    // 2. Khi cổng Proxy thực sự mở -> chuyển sang kênh vpn_mitm_proxy phải báo "connected" kèm độ trễ thật
    const swRes = await fetch(`${baseUrl}/api/v1/connections/switch`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": "test-switch-vpn-1",
      },
      body: JSON.stringify({
        channel: "vpn_mitm_proxy",
        vpnMitmProxyAddress: `127.0.0.1:${openProxyPort}`,
      }),
    });
    assert.equal(swRes.status, 200);
    const swBody = await swRes.json();
    assert.equal(swBody.data.activatedChannel, "vpn_mitm_proxy");
    assert.equal(swBody.data.channelReport.status, "connected");
    assert.equal(typeof swBody.data.channelReport.latencyMs, "number");
  } finally {
    realBridge.shutdown();
    await new Promise((r) => mockProxyServer.close(r));
    await new Promise((r) => server.close(r));
    await fs.rm(tmpSettingsPath, { force: true }).catch(() => {});
  }
});

test("16. v6.0 Trạm Mẫu JS Của Tôi: Lưu code riêng, tự cứu dữ liệu khi dán nhầm code vào ô tên & Sửa trực tiếp (PUT)", async () => {
  const tmpSnipPath = path.join(os.tmpdir(), `frida-custom-snip-${Date.now()}.json`);
  const snippetRepo = new SnippetRepository({ customFilePath: tmpSnipPath });

  const app = express();
  app.use(express.json());
  app.use(
    "/api",
    createApiRouter({
      bridge: {},
      sessionService: { getStatus: () => ({ status: "idle" }) },
      snippetRepo,
      paramVault: new ParamVaultRepository({ filePath: `${tmpSnipPath}.param` }),
      settingsRepo: new WorkspaceSettingsRepository({ filePath: `${tmpSnipPath}.set` }),
    })
  );

  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Giả lập người dùng lỡ dán cả đoạn code JS vào ô title và để trống code -> tự cứu dữ liệu!
    const createRes = await fetch(`${baseUrl}/api/v1/snippets`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "// Mẫu bắt biên lai VIP của Thỏ\nInterceptor.attach(ptr('0x1000'), {});",
        code: "",
      }),
    });
    assert.equal(createRes.status, 201);
    const created = (await createRes.json()).data.snippet;
    assert.ok(created.code.includes("Interceptor.attach"));
    assert.ok(created.displayTitle.includes("Mẫu bắt biên lai VIP của Thỏ"));

    // 2. Sửa lại tên, nhóm và nội dung code JS qua PUT /api/v1/snippets/:snippetId
    const updateRes = await fetch(`${baseUrl}/api/v1/snippets/${encodeURIComponent(created.id)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        title: "Soi StoreKit 2 Của Tôi (Bản v2)",
        category: "8. Mẫu JS Của Tôi",
        runType: "listener",
        description: "Đã cập nhật code mới",
        code: "send({ goiVip: 'com.antidv.yearly', trangThai: 'ok' });",
      }),
    });
    assert.equal(updateRes.status, 200);
    const updated = (await updateRes.json()).data.snippet;
    assert.equal(updated.title, "Soi StoreKit 2 Của Tôi (Bản v2)");
    assert.equal(updated.runType, "listener");
    assert.ok(updated.code.includes("com.antidv.yearly"));

    // 3. Cấm sửa trực tiếp mẫu mặc định (HTTP 409)
    const builtinPut = await fetch(`${baseUrl}/api/v1/snippets/builtin-runtime-overview`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: "Hack", code: "console.log(1)" }),
    });
    assert.equal(builtinPut.status, 409);
  } finally {
    await new Promise((r) => server.close(r));
    await fs.rm(tmpSnipPath, { force: true }).catch(() => {});
  }
});

test("17. v6.0 Giải Mã Liên Thông StoreKit 2 JWS (ES256 + x5c thật), WireGuard & Báo cáo executionTruth trung thực", async () => {
  const { certBase64, privateKey } = createSelfSignedP256CertDer("Apple StoreKit Sandbox Signer");
  const headerB64 = Buffer.from(JSON.stringify({ alg: "ES256", x5c: [certBase64] })).toString("base64url");
  const payloadB64 = Buffer.from(
    JSON.stringify({
      transactionId: "200000099887766",
      originalTransactionId: "200000011223344",
      productId: "com.antidv.vip.pro_yearly",
      bundleId: "com.antidv.app",
      environment: "Sandbox",
      purchaseDate: 1763200000000,
    })
  ).toString("base64url");

  const sigRaw = crypto.sign("sha256", Buffer.from(`${headerB64}.${payloadB64}`), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  const validJws = `${headerB64}.${payloadB64}.${sigRaw.toString("base64url")}`;

  const tamperedPayloadB64 = Buffer.from(
    JSON.stringify({
      transactionId: "200000099887766",
      productId: "com.antidv.vip.lifetime_tampered",
      environment: "Production",
    })
  ).toString("base64url");
  const tamperedJws = `${headerB64}.${tamperedPayloadB64}.${sigRaw.toString("base64url")}`;

  const tmpPath = path.join(os.tmpdir(), `frida-dec-${Date.now()}.json`);
  const svc = new FridaSessionService({
    bridge: {
      async resolveWorkingDevice() {
        return {
          async attach() {
            return {
              pid: 4567,
              isDetached: () => false,
              detach: async () => {},
              detached: { connect() {} },
              createScript: async () => ({
                isDestroyed: false,
                logHandler: null,
                exports: {},
                message: { connect() {} },
                async load() {},
                async unload() {
                  this.isDestroyed = true;
                },
              }),
            };
          },
        };
      },
    },
    emit: () => {},
  });

  const app = express();
  app.use(express.json());
  app.use(
    "/api",
    createApiRouter({
      bridge: {},
      sessionService: svc,
      snippetRepo: new SnippetRepository({ customFilePath: `${tmpPath}.snip` }),
      paramVault: new ParamVaultRepository({ filePath: `${tmpPath}.param` }),
      settingsRepo: new WorkspaceSettingsRepository({ filePath: `${tmpPath}.set` }),
    })
  );

  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. Giải mã & xác thực chữ ký JWS StoreKit hợp lệ -> signatureVerified === true + trích đủ transactionId, productId, bundleId
    const okRes = await fetch(`${baseUrl}/api/v1/decoder/inspect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: validJws, mode: "auto" }),
    });
    assert.equal(okRes.status, 200);
    const okDecoded = (await okRes.json()).data.decoded;
    assert.equal(okDecoded.cryptoVerification.isAppleStoreKitJws, true);
    assert.equal(okDecoded.cryptoVerification.signatureVerified, true);
    assert.equal(okDecoded.cryptoVerification.chainVerified, true);
    assert.ok(okDecoded.extractedParams.some((p) => p.key === "productId" && p.value === "com.antidv.vip.pro_yearly"));
    assert.ok(okDecoded.extractedParams.some((p) => p.key === "transactionId" && p.value === "200000099887766"));

    // 2. Giải mã JWS bị sửa Payload -> bắt buộc phát hiện signatureVerified === false!
    const badRes = await fetch(`${baseUrl}/api/v1/decoder/inspect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: tamperedJws, mode: "auto" }),
    });
    assert.equal(badRes.status, 200);
    const badDecoded = (await badRes.json()).data.decoded;
    assert.equal(badDecoded.cryptoVerification.signatureVerified, false);

    // 3. Giải mã cấu hình WireGuard -> tự động che PrivateKey và kiểm tra AllowedIPs / DNS
    const wgConf = [
      "[Interface]",
      "PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
      "Address = 10.8.0.2/24",
      "DNS = 10.8.0.1",
      "",
      "[Peer]",
      "PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=",
      "Endpoint = 127.0.0.1:51820",
      "AllowedIPs = 0.0.0.0/0",
    ].join("\n");
    const wgRes = await fetch(`${baseUrl}/api/v1/decoder/inspect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ input: wgConf, mode: "auto" }),
    });
    const wgDecoded = (await wgRes.json()).data.decoded;
    assert.equal(wgDecoded.detectedFormat, "wireguard-config");
    assert.equal(wgDecoded.cryptoVerification.signatureVerified, true);
    assert.ok(!wgDecoded.decodedText.includes("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="), "Phải che dấu PrivateKey");

    // 4. Báo cáo trạng thái thật executionTruth: khi mã JS chưa phát ra dữ liệu từ thiết bị -> awaitingDeviceInteraction === true & receivedDeviceEventsCount === 0
    const sessionStatus = await svc.runScript({
      deviceId: "usb",
      mode: "attach",
      target: "4567",
      code: "// listener chờ sự kiện",
    });
    assert.equal(sessionStatus.receivedDeviceEventsCount, 0);
    assert.equal(sessionStatus.executionTruth.attachedToProcess, true);
    assert.equal(sessionStatus.executionTruth.receivedDeviceEventsCount, 0);
    assert.equal(sessionStatus.executionTruth.awaitingDeviceInteraction, true);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("18. v7.0 Kiểm toán Bảo mật Nhị phân Mach-O (security-posture), Tự dò hàm RPC (rpc-exports) & Khử trùng importExternalPackets", async () => {
  const compiler = new FridaScriptCompiler();
  const userCode = `
    rpc.exports = {
      customPing(name) {
        return "pong:" + name;
      },
      readBuildNumber() {
        return 700;
      }
    };
  `;
  const compiled = await compiler.compileUserScript(userCode, { enableObjCBridge: false });

  // Tạo bộ đệm giả lập Header Mach-O 64-bit chuẩn: magic=0xfeedfacf, filetype=2 (MH_EXECUTE), ncmds=1, flags=0x200000 (PIE), LC_ENCRYPTION_INFO_64 (0x2c) cryptid=0
  const machBuf = Buffer.alloc(64, 0);
  machBuf.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64
  machBuf.writeUInt32LE(2, 12); // MH_EXECUTE
  machBuf.writeUInt32LE(1, 16); // ncmds = 1
  machBuf.writeUInt32LE(0x200000, 24); // MH_PIE
  machBuf.writeUInt32LE(0x2c, 32); // LC_ENCRYPTION_INFO_64
  machBuf.writeUInt32LE(24, 36); // cmdsize
  machBuf.writeUInt32LE(0, 48); // cryptid = 0 (đã giải mã / bản Debug Sandbox)

  const dylibBuf = Buffer.alloc(64, 0);
  dylibBuf.writeUInt32LE(0xfeedfacf, 0);
  dylibBuf.writeUInt32LE(6, 12); // MH_DYLIB (như systemhook.dylib trên Dopamine Rootless)

  const makePtr = (offset = 0, buf = machBuf) => ({
    toString: () => `0x10000${offset.toString(16).padStart(4, "0")}`,
    readU32: () => buf.readUInt32LE(offset),
    add: (delta) => makePtr(offset + Number(delta), buf),
  });

  const RECEIPT_PATH = "/var/mobile/Containers/Data/Application/APP-777/StoreKit/sandboxReceipt";
  const mockObjC = {
    available: true,
    classes: {
      NSBundle: {
        mainBundle: () => ({
          bundleIdentifier: () => ({ toString: () => "com.antidv.demoapp" }),
          bundlePath: () => ({ toString: () => "/var/containers/Bundle/Application/APP-777/Demo.app" }),
          executablePath: () => ({ toString: () => "/var/containers/Bundle/Application/APP-777/Demo.app/Demo" }),
          appStoreReceiptURL: () => ({ path: () => ({ toString: () => RECEIPT_PATH }) }),
          infoDictionary: () => ({
            objectForKey_: (key) => {
              if (key === "CFBundleDisplayName") return { toString: () => "Demo App v7" };
              if (key === "CFBundleShortVersionString") return { toString: () => "7.0.0" };
              if (key === "CFBundleVersion") return { toString: () => "700" };
              if (key === "MinimumOSVersion") return { toString: () => "15.0" };
              if (key === "CFBundleURLTypes") {
                const entries = [
                  { schemes: ["prefs", "otpauth"] },
                  { schemes: ["prefs", "antidv-pay"] },
                ];
                return {
                  isNull: () => false,
                  count: () => entries.length,
                  objectAtIndex_: (idx) => ({
                    objectForKey_: (subKey) => {
                      if (subKey !== "CFBundleURLSchemes") return null;
                      const list = entries[idx].schemes;
                      return {
                        count: () => list.length,
                        objectAtIndex_: (j) => ({ toString: () => list[j] }),
                      };
                    },
                  }),
                };
              }
              if (key === "NSAppTransportSecurity") {
                return {
                  isNull: () => false,
                  objectForKey_: (atsKey) => {
                    if (atsKey === "NSAllowsArbitraryLoads") return { toString: () => "0" };
                    if (atsKey === "NSExceptionDomains") {
                      return {
                        allKeys: () => ({
                          count: () => 1,
                          objectAtIndex_: () => ({ toString: () => "sandbox.itunes.apple.com" }),
                        }),
                      };
                    }
                    return null;
                  },
                };
              }
              return null;
            },
          }),
        }),
      },
      NSFileManager: {
        defaultManager: () => ({
          fileExistsAtPath_: (p) => p === RECEIPT_PATH,
        }),
      },
      SKPaymentQueue: {
        canMakePayments: () => true,
      },
    },
  };

  let gumExports = {};
  const sandbox = {
    ObjC: mockObjC,
    rpc: {
      get exports() {
        return gumExports;
      },
      set exports(v) {
        gumExports = v;
      },
    },
    send: () => {},
    console: { log: () => {}, warn: () => {}, error: () => {} },
    Process: {
      id: 7007,
      arch: "arm64",
      platform: "darwin",
      pageSize: 16384,
      pointerSize: 8,
      enumerateThreads: () => [{ id: 1 }],
      enumerateModules: () => [
        {
          name: "systemhook.dylib",
          path: "/var/jb/usr/lib/systemhook.dylib",
          base: makePtr(0, dylibBuf),
          size: 16384,
          enumerateImports: () => [],
        },
        {
          name: "Demo",
          path: "/var/containers/Bundle/Application/APP-777/Demo.app/Demo",
          base: makePtr(0),
          size: 65536,
          enumerateImports: () => [
            { name: "_objc_retain" },
            { name: "___stack_chk_guard" },
          ],
        },
        {
          name: "libswiftCore.dylib",
          path: "/usr/lib/swift/libswiftCore.dylib",
          base: makePtr(0),
          size: 4096,
        },
        {
          name: "StoreKit",
          path: "/System/Library/Frameworks/StoreKit.framework/StoreKit",
          base: makePtr(0),
          size: 4096,
        },
        {
          name: "RabbitHook.dylib",
          path: "/var/jb/Library/MobileSubstrate/DynamicLibraries/RabbitHook.dylib",
          base: makePtr(0),
          size: 4096,
        },
      ],
    },
    Frida: { heapSize: 4096 },
    Interceptor: { attach: () => {} },
    Module: { getGlobalExportByName: () => null },
    NativeFunction: function () {
      return () => "";
    },
    Memory: { allocUtf8String: (s) => s },
  };

  vm.runInNewContext(compiled.compiledSource, sandbox);

  // 1. Kiểm tra tự dò danh sách hàm RPC do người dùng viết (lọc sạch các hàm nội bộ __studio*)
  const rpcInfo = gumExports.__studioListUserRpcExports();
  assert.equal(rpcInfo.available, true);
  assert.deepEqual(Array.from(rpcInfo.exports), ["customPing", "readBuildNumber"]);
  assert.equal(gumExports.customPing("Antidv"), "pong:Antidv");

  // 2. Kiểm tra kiểm toán bảo mật nhị phân Mach-O + bóc tách sạch URL Schemes + ATS + StoreKit Sandbox
  const posture = gumExports.__studioInspectSecurityPosture();
  assert.equal(posture.binaryHardening.moduleName, "Demo");
  assert.equal(posture.binaryHardening.isMachO64, true);
  assert.equal(posture.binaryHardening.pieEnabled, true);
  assert.equal(posture.binaryHardening.cryptId, 0);
  assert.equal(posture.binaryHardening.hasArc, true);
  assert.equal(posture.binaryHardening.hasStackCanary, true);
  assert.ok(Array.from(posture.frameworksDetected).includes("Swift"));
  assert.ok(Array.from(posture.frameworksDetected).includes("StoreKit / In-App Purchase"));
  assert.equal(posture.injectedTweaks.length, 2);
  assert.deepEqual(Array.from(posture.urlSchemesList), ["prefs", "otpauth", "antidv-pay"]);
  assert.deepEqual(Array.from(posture.atsParsed.exceptionDomains), ["sandbox.itunes.apple.com"]);
  assert.equal(posture.storeKitReceipt.environment, "SANDBOX / TESTFLIGHT");
  assert.equal(posture.storeKitReceipt.receiptExists, true);
  assert.equal(posture.storeKitReceipt.canMakePayments, true);

  // 3. Kiểm tra khử trùng lặp importExternalPackets trên FridaSessionService
  const svc = new FridaSessionService({ bridge: {}, emit: () => {} });
  const batch = [
    { method: "POST", url: "https://sandbox.itunes.apple.com/verifyReceipt", statusCode: 200, requestBody: '{"receipt-data":"AAA"}' },
    { method: "GET", requestUrl: "https://api.antidv.vn/v1/profile", statusCode: 200 },
  ];
  const firstImport = svc.importExternalPackets(batch, "RabbitUltrad-Test");
  assert.equal(firstImport.importedCount, 2);
  assert.equal(firstImport.items.length, 2);

  const duplicateImport = svc.importExternalPackets(batch, "RabbitUltrad-Test");
  assert.equal(duplicateImport.importedCount, 0, "Gói tin trùng hệt chữ ký không được nhân đôi trong bảng");
  assert.equal(svc.listHttpExchanges().meta.totalItems, 2);
});




