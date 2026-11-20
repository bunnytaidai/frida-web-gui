// tests/fridaSessionService.test.mjs — Kiểm thử đơn vị vòng đời Phiên Frida (Attach, Spawn, Hot-Reload & Báo lỗi đầu vào)
import test from "node:test";
import assert from "node:assert/strict";
import { FridaSessionService } from "../src/services/fridaSessionService.mjs";

function createFakeBridge() {
  const callOrder = [];
  let detachedHandler = null;
  let messageHandler = null;
  let lastScript = null;

  const fakeSession = {
    pid: 57299,
    detachedFlag: false,
    isDetached() {
      return this.detachedFlag;
    },
    async detach() {
      callOrder.push("session.detach");
      this.detachedFlag = true;
    },
    detached: {
      connect(fn) {
        detachedHandler = fn;
      },
    },
    async createScript(source) {
      callOrder.push(`createScript:${source.length}`);
      lastScript = {
        isDestroyed: false,
        logHandler: null,
        message: {
          connect(fn) {
            messageHandler = fn;
          },
        },
        async load() {
          callOrder.push("script.load");
          if (this.logHandler) {
            this.logHandler("info", "[+] Hello from fake Frida");
          }
          if (messageHandler) {
            messageHandler({ type: "send", payload: { ok: true } }, null);
          }
        },
        async unload() {
          callOrder.push("script.unload");
          this.isDestroyed = true;
        },
      };
      return lastScript;
    },
  };

  const fakeDevice = {
    async spawn(bundleId) {
      callOrder.push(`device.spawn:${bundleId}`);
      return 8888;
    },
    async attach(target) {
      callOrder.push(`device.attach:${target}`);
      fakeSession.pid = typeof target === "number" ? target : 57299;
      fakeSession.detachedFlag = false;
      return fakeSession;
    },
    async resume(pid) {
      callOrder.push(`device.resume:${pid}`);
    },
  };

  return {
    callOrder,
    getDetachedHandler: () => detachedHandler,
    bridge: {
      async resolveWorkingDevice() {
        return fakeDevice;
      },
    },
  };
}

test("1. Tình huống chuẩn: Attach thu nhận đủ console.log + send() và hỗ trợ Hot-Reload", async () => {
  const events = [];
  const { bridge, callOrder } = createFakeBridge();
  const svc = new FridaSessionService({
    bridge,
    emit: (event, payload) => events.push({ event, payload }),
  });

  const status1 = await svc.runScript({
    deviceId: "usb-iphone",
    mode: "attach",
    target: "57299",
    code: "console.log('hi');",
  });

  assert.equal(status1.status, "running");
  assert.equal(status1.pid, 57299);

  const outputs = events.filter((e) => e.event === "script:output").map((e) => e.payload);
  assert.ok(outputs.some((o) => o.level === "info" && o.text.includes("Hello from fake Frida")));
  assert.ok(outputs.some((o) => o.level === "send" && o.text.includes('"ok": true')));

  // Gửi lại JS trên cùng PID -> phải Hot-Reload (unload script cũ mà không detach session)
  await svc.runScript({
    deviceId: "usb-iphone",
    mode: "attach",
    target: "57299",
    code: "console.log('reload');",
  });
  assert.ok(callOrder.includes("script.unload"));
  assert.ok(!callOrder.includes("session.detach"));

  const stopped = await svc.stopSession();
  assert.equal(stopped.status, "idle");
});

test("2. Tình huống chuẩn Spawn: Bắt buộc nạp script trước khi gọi device.resume()", async () => {
  const { bridge, callOrder } = createFakeBridge();
  const svc = new FridaSessionService({
    bridge,
    emit: () => {},
  });

  const status = await svc.runScript({
    deviceId: "usb-iphone",
    mode: "spawn",
    target: "com.apple.Preferences",
    code: "send('ready');",
  });

  assert.equal(status.pid, 8888);
  const loadIdx = callOrder.indexOf("script.load");
  const resumeIdx = callOrder.indexOf("device.resume:8888");
  assert.ok(loadIdx > -1 && resumeIdx > loadIdx, "Phải load script trước khi resume tiến trình Spawn");
});

test("3. Tình huống biên & sai dữ liệu: Chặn ngay khi thiếu mã JS hoặc sai chế độ", async () => {
  const { bridge } = createFakeBridge();
  const svc = new FridaSessionService({ bridge, emit: () => {} });

  await assert.rejects(
    () => svc.runScript({ deviceId: "usb-iphone", mode: "attach", target: "57299", code: "   " }),
    /Nội dung mã JavaScript đang để trống/
  );

  await assert.rejects(
    () => svc.runScript({ deviceId: "usb-iphone", mode: "invalid", target: "57299", code: "1+1" }),
    /Chế độ chạy không hợp lệ/
  );
});

test("4. Chế độ Tự động (auto): Tự mở App ngủ ngầm lên iPhone & nạp nóng lần bấm thứ 2 không tắt App", async () => {
  const { bridge, callOrder } = createFakeBridge();
  const dev = await bridge.resolveWorkingDevice();
  dev.getFrontmostApplication = async () => null; // Đang ở màn hình trống, chưa mở App
  dev.enumerateApplications = async () => [
    { name: "TestFlight", identifier: "com.apple.TestFlight", pid: 58600 },
  ];

  const svc = new FridaSessionService({ bridge, emit: () => {} });

  // Lần bấm 1: App chưa mở sáng -> Tự động spawn("com.apple.TestFlight") + resume
  const st1 = await svc.runScript({
    deviceId: "usb-iphone",
    mode: "auto",
    target: "com.apple.TestFlight",
    code: "console.log('first');",
  });
  assert.equal(st1.status, "running");
  assert.equal(st1.pid, 8888);
  assert.ok(callOrder.includes("device.spawn:com.apple.TestFlight"));
  assert.ok(callOrder.includes("device.resume:8888"));

  // Lần bấm 2: Đổi sang mẫu JS khác trên cùng App -> Nạp nóng (unload script cũ, KHÔNG spawn lại)
  const spawnCountBefore = callOrder.filter((x) => x.startsWith("device.spawn:")).length;
  await svc.runScript({
    deviceId: "usb-iphone",
    mode: "auto",
    target: "com.apple.TestFlight",
    code: "console.log('second');",
  });
  const spawnCountAfter = callOrder.filter((x) => x.startsWith("device.spawn:")).length;
  assert.equal(spawnCountAfter, spawnCountBefore, "Lần bấm thứ 2 phải nạp nóng không mở lại App");
  assert.ok(callOrder.includes("script.unload"));
});

