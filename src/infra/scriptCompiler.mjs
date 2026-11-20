// src/infra/scriptCompiler.mjs — Trình biên dịch JS/TS tốc độ cao & Tự động nhúng frida-objc-bridge cho Frida 17
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { logger } from "./logger.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(__dirname, "../..");

// Các hàm RPC nội bộ phục vụ Trình Soi Tiến Trình, Bắt Gói Tin + Hộp Trả Lời & Gửi Lại Gói Tin (Repeater)
const STUDIO_INSPECTOR_BOOTSTRAP = `
;(function installStudioInspector() {
  const safeStr = (v) => (v === null || v === undefined ? "" : String(v));
  const activeObjcBlocks = new Set();
  const replayedReqPtrs = new Set();
  const replayedTaskKeys = new Set();
  const installedSwitchHooks = new Set();
  const featureFlags = {
    httpCapture: false,
    storekitObserver: false,
    authObserver: false,
    storageObserver: false,
    fileAccessObserver: false,
    uiScreenObserver: false
  };
  let hookWarnCount = 0;

  function reportHookDiag(where, err) {
    if (hookWarnCount >= 8) return;
    hookWarnCount += 1;
    const msg = err && err.message ? err.message : String(err);
    console.warn("[Chẩn đoán nội bộ • " + where + "] " + msg);
  }

  function nsDictToJs(dictObj) {
    const out = {};
    if (!dictObj || dictObj.isNull?.()) return out;
    try {
      const keys = dictObj.allKeys();
      const count = Number(keys.count());
      for (let i = 0; i < count; i++) {
        const k = keys.objectAtIndex_(i);
        const v = dictObj.objectForKey_(k);
        if (k) out[k.toString()] = v ? v.toString() : "";
      }
    } catch (err) {
      reportHookDiag("nsDictToJs", err);
    }
    return out;
  }

  function nsDataToText(dataObj, maxBytes = 49152) {
    if (!dataObj || dataObj.isNull?.()) return "";
    try {
      const totalLen = Number(dataObj.length());
      if (totalLen <= 0) return "";
      const sliceLen = Math.min(totalLen, maxBytes);
      const targetData =
        totalLen > maxBytes ? dataObj.subdataWithRange_([0, sliceLen]) : dataObj;

      // Ưu tiên giải mã chuẩn UTF-8 (encoding = 4)
      const utf8Str = ObjC.classes.NSString.alloc().initWithData_encoding_(targetData, 4);
      if (utf8Str && !utf8Str.isNull?.()) {
        const text = utf8Str.toString();
        return totalLen > maxBytes ? text + "\\n...[Đã cắt bớt từ " + totalLen + " byte]" : text;
      }

      // Dự phòng ASCII / ISO-Latin1 (encoding = 5) nếu chuỗi có ký tự lạ
      const latinStr = ObjC.classes.NSString.alloc().initWithData_encoding_(targetData, 5);
      if (latinStr && !latinStr.isNull?.()) {
        const text = latinStr.toString();
        if (/^[\\x09\\x0a\\x0d\\x20-\\x7e]{8,}/.test(text)) {
          return totalLen > maxBytes ? text + "\\n...[Đã cắt bớt]" : text;
        }
      }
      return "[Dữ liệu nhị phân / mã hóa nhị phân: " + totalLen + " byte]";
    } catch (err) {
      reportHookDiag("nsDataToText", err);
      return "";
    }
  }

  function extractRequestSnapshot(reqObj, fallbackUrl = "") {
    if (!reqObj || reqObj.isNull?.()) {
      return { method: "GET", url: fallbackUrl, requestHeaders: {}, requestBody: "" };
    }
    try {
      const url = reqObj.URL()?.absoluteString()?.toString() || fallbackUrl;
      const method = reqObj.HTTPMethod()?.toString() || "GET";
      const requestHeaders = nsDictToJs(reqObj.allHTTPHeaderFields());
      const requestBody = nsDataToText(reqObj.HTTPBody(), 24576);
      return { method, url, requestHeaders, requestBody };
    } catch (err) {
      reportHookDiag("extractRequestSnapshot", err);
      return { method: "GET", url: fallbackUrl, requestHeaders: {}, requestBody: "" };
    }
  }

  function emitHttpExchange(reqSnap, dataPtr, respPtr, errPtr, startedAt, fallbackBodyNote = "") {
    try {
      if (!reqSnap || !reqSnap.url) return;
      if (featureFlags.authObserver && /login|signin|auth|oauth|token|verify|otp|session/i.test(reqSnap.url)) {
        send({
          nhomCongTac: "auth",
          suKien: "Phát hiện gói mạng Xác thực / Đăng nhập",
          phuongThuc: reqSnap.method,
          url: reqSnap.url
        });
      }
      if (!featureFlags.httpCapture) return;
      let statusCode = 0;
      let responseHeaders = {};
      if (respPtr && !ptr(respPtr).isNull()) {
        const respObj = new ObjC.Object(ptr(respPtr));
        if (respObj.respondsToSelector_(ObjC.selector("statusCode"))) {
          statusCode = Number(respObj.statusCode());
        }
        if (respObj.respondsToSelector_(ObjC.selector("allHeaderFields"))) {
          responseHeaders = nsDictToJs(respObj.allHeaderFields());
        }
      }
      let responseBody =
        dataPtr && !ptr(dataPtr).isNull() ? nsDataToText(new ObjC.Object(ptr(dataPtr)), 49152) : "";
      if (!responseBody && fallbackBodyNote) {
        responseBody = fallbackBodyNote;
      }
      const errorText =
        errPtr && !ptr(errPtr).isNull()
          ? new ObjC.Object(ptr(errPtr)).localizedDescription()?.toString() || "Lỗi mạng"
          : "";

      send({
        __studioType: "http_exchange",
        method: reqSnap.method,
        url: reqSnap.url,
        requestHeaders: reqSnap.requestHeaders,
        requestBody: reqSnap.requestBody,
        statusCode,
        responseHeaders,
        responseBody,
        elapsedMs: Math.max(1, Date.now() - startedAt),
        errorText
      });
    } catch (err) {
      reportHookDiag("emitHttpExchange", err);
    }
  }

  function enableHttpSnifferInternal() {
    if (typeof ObjC === "undefined" || !ObjC.available) {
      return { enabled: false, message: "Tiến trình hiện tại không hỗ trợ ObjC (chỉ áp dụng cho ứng dụng iOS)." };
    }
    featureFlags.httpCapture = true;
    if (globalThis.__studioHttpSnifferInstalled) {
      return { enabled: true, alreadyActive: true, message: "Bộ bắt gói tin & Hộp trả lời đang hoạt động sẵn!" };
    }

    const NSURLSession = ObjC.classes.NSURLSession;
    if (!NSURLSession) {
      featureFlags.httpCapture = false;
      return { enabled: false, message: "Ứng dụng chưa nạp khung mạng NSURLSession." };
    }

    globalThis.__studioHttpSnifferInstalled = true;
    const hookedImpls = new Set();
    const hookedDelegateClasses = new Set();
    const taskBuffers = new Map();
    const emittedTaskKeys = new Set();
    const blockHandledTaskKeys = new Set();
    const pendingResumeTasks = new Map();
    let pollTimer = null;

    function rememberBounded(setObj, key, max = 1500) {
      setObj.add(key);
      if (setObj.size > max) {
        const first = setObj.values().next().value;
        setObj.delete(first);
      }
    }

    // 1. Bắt gói tin qua Completion Block trên cả NSURLSession và lớp con thực thi __NSURLSessionLocal (iOS 15+)
    for (const sessionClsName of ["NSURLSession", "__NSURLSessionLocal"]) {
      const sCls = ObjC.classes[sessionClsName];
      if (!sCls) continue;

      const mReqBlock = sCls["- dataTaskWithRequest:completionHandler:"];
      if (mReqBlock) {
        const implKey = mReqBlock.implementation.toString();
        if (!hookedImpls.has(implKey)) {
          hookedImpls.add(implKey);
          Interceptor.attach(mReqBlock.implementation, {
            onEnter(args) {
              if (args[2].isNull() || args[3].isNull()) return;
              if (replayedReqPtrs.has(args[2].toString())) return;
              const reqSnap = extractRequestSnapshot(new ObjC.Object(args[2]));
              const origBlock = new ObjC.Block(args[3]);
              const origImpl = origBlock.implementation;
              const t0 = Date.now();
              const ctx = this;
              ctx.__wrappedForStudio = true;

              const wrapperBlock = new ObjC.Block({
                retType: "void",
                argTypes: ["pointer", "pointer", "pointer"],
                implementation(dataPtr, respPtr, errPtr) {
                  if (ctx.__taskKey) rememberBounded(emittedTaskKeys, ctx.__taskKey);
                  emitHttpExchange(reqSnap, dataPtr, respPtr, errPtr, t0);
                  origImpl(dataPtr, respPtr, errPtr);
                  activeObjcBlocks.delete(wrapperBlock);
                }
              });
              activeObjcBlocks.add(wrapperBlock);
              args[3] = wrapperBlock.handle;
            },
            onLeave(retval) {
              if (this.__wrappedForStudio && retval && !retval.isNull()) {
                this.__taskKey = retval.toString();
                rememberBounded(blockHandledTaskKeys, this.__taskKey);
              }
            }
          });
        }
      }

      const mUploadBlock = sCls["- uploadTaskWithRequest:fromData:completionHandler:"];
      if (mUploadBlock) {
        const implKey = mUploadBlock.implementation.toString();
        if (!hookedImpls.has(implKey)) {
          hookedImpls.add(implKey);
          Interceptor.attach(mUploadBlock.implementation, {
            onEnter(args) {
              if (args[2].isNull() || args[4].isNull()) return;
              const reqSnap = extractRequestSnapshot(new ObjC.Object(args[2]));
              if (!reqSnap.requestBody && !args[3].isNull()) {
                reqSnap.requestBody = nsDataToText(new ObjC.Object(args[3]), 24576);
              }
              const origBlock = new ObjC.Block(args[4]);
              const origImpl = origBlock.implementation;
              const t0 = Date.now();
              const ctx = this;
              ctx.__wrappedForStudio = true;

              const wrapperBlock = new ObjC.Block({
                retType: "void",
                argTypes: ["pointer", "pointer", "pointer"],
                implementation(dataPtr, respPtr, errPtr) {
                  if (ctx.__taskKey) rememberBounded(emittedTaskKeys, ctx.__taskKey);
                  emitHttpExchange(reqSnap, dataPtr, respPtr, errPtr, t0);
                  origImpl(dataPtr, respPtr, errPtr);
                  activeObjcBlocks.delete(wrapperBlock);
                }
              });
              activeObjcBlocks.add(wrapperBlock);
              args[4] = wrapperBlock.handle;
            },
            onLeave(retval) {
              if (this.__wrappedForStudio && retval && !retval.isNull()) {
                this.__taskKey = retval.toString();
                rememberBounded(blockHandledTaskKeys, this.__taskKey);
              }
            }
          });
        }
      }

      const mUrlBlock = sCls["- dataTaskWithURL:completionHandler:"];
      if (mUrlBlock) {
        const implKey = mUrlBlock.implementation.toString();
        if (!hookedImpls.has(implKey)) {
          hookedImpls.add(implKey);
          Interceptor.attach(mUrlBlock.implementation, {
            onEnter(args) {
              if (args[2].isNull() || args[3].isNull()) return;
              const urlStr = new ObjC.Object(args[2]).absoluteString()?.toString() || "";
              const reqSnap = { method: "GET", url: urlStr, requestHeaders: {}, requestBody: "" };
              const origBlock = new ObjC.Block(args[3]);
              const origImpl = origBlock.implementation;
              const t0 = Date.now();
              const ctx = this;
              ctx.__wrappedForStudio = true;

              const wrapperBlock = new ObjC.Block({
                retType: "void",
                argTypes: ["pointer", "pointer", "pointer"],
                implementation(dataPtr, respPtr, errPtr) {
                  if (ctx.__taskKey) rememberBounded(emittedTaskKeys, ctx.__taskKey);
                  emitHttpExchange(reqSnap, dataPtr, respPtr, errPtr, t0);
                  origImpl(dataPtr, respPtr, errPtr);
                  activeObjcBlocks.delete(wrapperBlock);
                }
              });
              activeObjcBlocks.add(wrapperBlock);
              args[3] = wrapperBlock.handle;
            },
            onLeave(retval) {
              if (this.__wrappedForStudio && retval && !retval.isNull()) {
                this.__taskKey = retval.toString();
                rememberBounded(blockHandledTaskKeys, this.__taskKey);
              }
            }
          });
        }
      }
    }

    // 2. Bắt các gói tin dùng Delegate (AMSURLSession của TestFlight/AppStore, Alamofire, AFNetworking...)
    function hookDelegateClass(clsName) {
      if (!clsName || hookedDelegateClasses.has(clsName)) return;
      const cls = ObjC.classes[clsName];
      if (!cls) return;
      const didReceiveData = cls["- URLSession:dataTask:didReceiveData:"];
      const didComplete = cls["- URLSession:task:didCompleteWithError:"];
      if (!didComplete) return;
      hookedDelegateClasses.add(clsName);

      if (didReceiveData) {
        const recvKey = didReceiveData.implementation.toString();
        if (!hookedImpls.has(recvKey)) {
          hookedImpls.add(recvKey);
          Interceptor.attach(didReceiveData.implementation, {
            onEnter(args) {
              try {
                const task = new ObjC.Object(args[3]);
                const chunk = new ObjC.Object(args[4]);
                const key = task.handle.toString();
                let entry = taskBuffers.get(key);
                if (!entry) {
                  entry = {
                    startedAt: Date.now(),
                    mutableData: ObjC.classes.NSMutableData.alloc().init()
                  };
                  taskBuffers.set(key, entry);
                }
                if (Number(entry.mutableData.length()) < 65536) {
                  entry.mutableData.appendData_(chunk);
                }
              } catch (err) {
                reportHookDiag("didReceiveData", err);
              }
            }
          });
        }
      }

      const compKey = didComplete.implementation.toString();
      if (!hookedImpls.has(compKey)) {
        hookedImpls.add(compKey);
        Interceptor.attach(didComplete.implementation, {
          onEnter(args) {
            try {
              const task = new ObjC.Object(args[3]);
              const key = task.handle.toString();
              const entry = taskBuffers.get(key);
              taskBuffers.delete(key);
              if (emittedTaskKeys.has(key)) return;
              rememberBounded(emittedTaskKeys, key);

              const curReq = task.currentRequest() || task.originalRequest();
              const reqSnap = extractRequestSnapshot(curReq);
              if (!reqSnap.url) return;

              const respPtr = task.response() ? task.response().handle : NULL;
              const dataPtr = entry?.mutableData ? entry.mutableData.handle : NULL;
              const errPtr = args[4];
              emitHttpExchange(reqSnap, dataPtr, respPtr, errPtr, entry?.startedAt || Date.now());
            } catch (err) {
              reportHookDiag("didCompleteWithError", err);
            }
          }
        });
      }
    }

    // Gắn sẵn các lớp Delegate phổ biến của Apple (TestFlight, App Store, StoreKit, WebKit) nếu đã nạp trong RAM
    for (const knownCls of ["AMSURLSession", "ISURLOperation", "SSURLConnectionRequest"]) {
      if (ObjC.classes[knownCls]) {
        hookDelegateClass(knownCls);
      }
    }

    const mSessionCfg = NSURLSession["+ sessionWithConfiguration:delegate:delegateQueue:"];
    if (mSessionCfg) {
      const cfgKey = mSessionCfg.implementation.toString();
      if (!hookedImpls.has(cfgKey)) {
        hookedImpls.add(cfgKey);
        Interceptor.attach(mSessionCfg.implementation, {
          onEnter(args) {
            try {
              if (!args[3].isNull()) {
                hookDelegateClass(new ObjC.Object(args[3]).$className);
              }
            } catch (err) {
              reportHookDiag("sessionWithCfg", err);
            }
          }
        });
      }
    }

    for (const sessionClsName of ["NSURLSession", "__NSURLSessionLocal"]) {
      const sCls = ObjC.classes[sessionClsName];
      if (!sCls) continue;
      for (const selName of ["- dataTaskWithRequest:", "- dataTaskWithURL:", "- uploadTaskWithRequest:fromData:"]) {
        const mTask = sCls[selName];
        if (!mTask) continue;
        const implKey = mTask.implementation.toString();
        if (hookedImpls.has(implKey)) continue;
        hookedImpls.add(implKey);
        Interceptor.attach(mTask.implementation, {
          onEnter(args) {
            try {
              const sessObj = new ObjC.Object(args[0]);
              const del = sessObj.respondsToSelector_(ObjC.selector("delegate")) ? sessObj.delegate() : null;
              if (del && !del.isNull?.()) {
                hookDelegateClass(del.$className);
              }
            } catch (err) {
              reportHookDiag("taskFactoryDelegate", err);
            }
          }
        });
      }
    }

    // 3. Lưới quét phổ quát NSURLSessionTask[- resume] (Bắt cả phiên tạo trước khi gắn Frida & Swift async/await)
    function ensurePendingPoll() {
      if (pollTimer !== null) return;
      pollTimer = setInterval(() => {
        if (pendingResumeTasks.size === 0) {
          clearInterval(pollTimer);
          pollTimer = null;
          return;
        }
        const now = Date.now();
        for (const [taskKey, item] of pendingResumeTasks.entries()) {
          try {
            if (emittedTaskKeys.has(taskKey)) {
              pendingResumeTasks.delete(taskKey);
              item.taskObj.release();
              continue;
            }
            const st = Number(item.taskObj.state());
            const timedOut = now - item.startedAt > 12000;
            // state: 0 = Running, 1 = Suspended, 2 = Canceling, 3 = Completed
            if (st === 3 || st === 2 || timedOut) {
              pendingResumeTasks.delete(taskKey);
              setTimeout(() => {
                try {
                  if (!emittedTaskKeys.has(taskKey)) {
                    rememberBounded(emittedTaskKeys, taskKey);
                    const finalReq = item.taskObj.currentRequest() || item.taskObj.originalRequest();
                    const snap = finalReq ? extractRequestSnapshot(finalReq, item.reqSnap.url) : item.reqSnap;
                    const respPtr = item.taskObj.response() ? item.taskObj.response().handle : NULL;
                    const errPtr = item.taskObj.error() ? item.taskObj.error().handle : NULL;
                    const bufEntry = taskBuffers.get(taskKey);
                    taskBuffers.delete(taskKey);
                    const dataPtr = bufEntry?.mutableData ? bufEntry.mutableData.handle : NULL;
                    const note = !dataPtr || ptr(dataPtr).isNull()
                      ? "// [Đã bắt trọn URL, Headers & Mã HTTP từ luồng CFNetwork/Swift — Bấm '🚀 Gửi Lại Gói Tin' ở bên trái nếu muốn tải lại toàn bộ nội dung thô]"
                      : "";
                    emitHttpExchange(snap, dataPtr, respPtr, errPtr, item.startedAt, note);
                  }
                } catch (err) {
                  reportHookDiag("pollFinalize", err);
                } finally {
                  try {
                    item.taskObj.release();
                  } catch {}
                }
              }, 90);
            }
          } catch (err) {
            pendingResumeTasks.delete(taskKey);
            reportHookDiag("pollLoop", err);
          }
        }
      }, 280);
    }

    for (const taskClsName of ["NSURLSessionTask", "__NSCFLocalSessionTask"]) {
      const tCls = ObjC.classes[taskClsName];
      const mResume = tCls && tCls["- resume"];
      if (!mResume) continue;
      const implKey = mResume.implementation.toString();
      if (hookedImpls.has(implKey)) continue;
      hookedImpls.add(implKey);

      Interceptor.attach(mResume.implementation, {
        onEnter(args) {
          try {
            if (!args[0] || args[0].isNull()) return;
            const taskKey = args[0].toString();
            if (replayedTaskKeys.has(taskKey) || blockHandledTaskKeys.has(taskKey) || pendingResumeTasks.has(taskKey)) {
              return;
            }
            const taskObj = new ObjC.Object(args[0]);

            // Tự phát hiện Delegate của phiên NSURLSession cũ tạo từ lúc mở App
            if (taskObj.respondsToSelector_(ObjC.selector("session"))) {
              const sess = taskObj.session();
              if (sess && !sess.isNull?.() && sess.respondsToSelector_(ObjC.selector("delegate"))) {
                const del = sess.delegate();
                if (del && !del.isNull?.()) {
                  hookDelegateClass(del.$className);
                }
              }
            }

            const curReq =
              (taskObj.respondsToSelector_(ObjC.selector("currentRequest")) && taskObj.currentRequest()) ||
              (taskObj.respondsToSelector_(ObjC.selector("originalRequest")) && taskObj.originalRequest());
            const reqSnap = extractRequestSnapshot(curReq);
            if (!/^https?:\\/\\//i.test(reqSnap.url)) return;

            if (pendingResumeTasks.size < 120) {
              taskObj.retain();
              pendingResumeTasks.set(taskKey, {
                taskObj,
                reqSnap,
                startedAt: Date.now()
              });
              ensurePendingPoll();
            }
          } catch (err) {
            reportHookDiag("taskResume", err);
          }
        }
      });
    }

    return {
      enabled: true,
      alreadyActive: false,
      message: "Đã bật bắt Gói tin & Hộp trả lời (Request + Response đa tầng iOS)! Hãy chạm thao tác trên ứng dụng iPhone."
    };
  }

  function maskTextPreview(rawVal) {
    const s = safeStr(rawVal).trim();
    if (!s) return "";
    if (s.length <= 6) return "***";
    return s.slice(0, 3) + "••••" + s.slice(-3) + " (" + s.length + " ký tự)";
  }

  function nsObjToJs(obj, depth = 0) {
    if (!obj || obj.isNull?.()) return null;
    if (depth > 5) return safeStr(obj.toString()).slice(0, 260);
    try {
      const C = ObjC.classes;
      if (C.NSDictionary && obj.isKindOfClass_(C.NSDictionary)) {
        const out = {};
        const keys = obj.allKeys();
        const total = Math.min(250, Number(keys.count()));
        for (let i = 0; i < total; i++) {
          const k = keys.objectAtIndex_(i);
          const v = obj.objectForKey_(k);
          if (k) out[k.toString()] = nsObjToJs(v, depth + 1);
        }
        return out;
      }
      if (C.NSArray && obj.isKindOfClass_(C.NSArray)) {
        const arr = [];
        const total = Math.min(250, Number(obj.count()));
        for (let i = 0; i < total; i++) {
          arr.push(nsObjToJs(obj.objectAtIndex_(i), depth + 1));
        }
        return arr;
      }
      if (C.NSNumber && obj.isKindOfClass_(C.NSNumber)) {
        const objcType = safeStr(obj.objCType?.());
        if (objcType === "c" || objcType === "B") return Boolean(obj.boolValue());
        return Number(obj.doubleValue());
      }
      if (C.NSData && obj.isKindOfClass_(C.NSData)) {
        return "[Dữ liệu nhị phân NSData: " + Number(obj.length()) + " byte]";
      }
      return obj.toString();
    } catch {
      return safeStr(obj);
    }
  }

  function getSandboxHomeDir() {
    if (typeof ObjC === "undefined" || !ObjC.available) {
      throw new Error("Cần gắn vào ứng dụng iOS để đọc thư mục dữ liệu riêng (Sandbox).");
    }
    const homeSym = Module.getGlobalExportByName("NSHomeDirectory");
    if (!homeSym) {
      throw new Error("Không tìm thấy hàm NSHomeDirectory trên tiến trình hiện tại.");
    }
    const NSHomeDirectoryFn = new NativeFunction(homeSym, "pointer", []);
    const homePtr = NSHomeDirectoryFn();
    if (!homePtr || ptr(homePtr).isNull()) {
      throw new Error("Không xác định được đường dẫn gốc Sandbox của ứng dụng.");
    }
    return new ObjC.Object(ptr(homePtr)).toString().replace(/\\/+$/, "");
  }

  function resolveSafeSandboxPath(relPath = "") {
    const homeDir = getSandboxHomeDir();
    const rawRel = safeStr(relPath).trim().replace(/\\\\/g, "/");
    if (rawRel.includes("\\0")) {
      throw new Error("Đường dẫn chứa ký tự không hợp lệ.");
    }
    const parts = rawRel.split("/").filter((seg) => seg && seg !== ".");
    if (parts.some((seg) => seg === "..")) {
      throw new Error("Từ chối truy cập: Không được phép đi ngược ra ngoài thư mục dữ liệu riêng (Sandbox) của ứng dụng!");
    }
    const cleanRel = parts.join("/");
    const joined = cleanRel ? homeDir + "/" + cleanRel : homeDir;
    let standardized = joined;
    try {
      const nsJoined = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(joined));
      if (nsJoined && nsJoined.stringByStandardizingPath) {
        standardized = nsJoined.stringByStandardizingPath().toString().replace(/\\/+$/, "");
      }
    } catch {}
    if (standardized !== homeDir && !standardized.startsWith(homeDir + "/")) {
      throw new Error("Từ chối truy cập: Đường dẫn vượt ra ngoài thư mục dữ liệu riêng (Sandbox) của ứng dụng!");
    }
    return { homeDir, relPath: cleanRel, fullPath: standardized };
  }

  function installFeatureSwitchInternal(featureKey, enabled) {
    const isOn = Boolean(enabled);
    if (!(featureKey in featureFlags)) {
      throw new Error("Công tắc tính năng không hợp lệ: " + safeStr(featureKey));
    }

    if (typeof ObjC === "undefined" || !ObjC.available) {
      featureFlags[featureKey] = false;
      return {
        featureKey,
        enabled: false,
        switches: { ...featureFlags },
        message: "Tiến trình hiện tại không hỗ trợ ObjC (chỉ áp dụng cho ứng dụng iOS)."
      };
    }

    if (featureKey === "httpCapture") {
      if (isOn) {
        const res = enableHttpSnifferInternal();
        featureFlags.httpCapture = Boolean(res.enabled);
        return { featureKey, enabled: featureFlags.httpCapture, switches: { ...featureFlags }, message: res.message };
      }
      featureFlags.httpCapture = false;
      return {
        featureKey,
        enabled: false,
        switches: { ...featureFlags },
        message: "Đã tạm tắt ghi nhận Gói tin HTTP mới (ứng dụng vẫn chạy bình thường)."
      };
    }

    featureFlags[featureKey] = isOn;

    if (isOn && !installedSwitchHooks.has(featureKey)) {
      installedSwitchHooks.add(featureKey);
      try {
        if (featureKey === "storekitObserver") {
          const SKProductsRequest = ObjC.classes.SKProductsRequest;
          if (SKProductsRequest && SKProductsRequest["- start"]) {
            Interceptor.attach(SKProductsRequest["- start"].implementation, {
              onEnter(args) {
                if (!featureFlags.storekitObserver) return;
                try {
                  const reqObj = new ObjC.Object(args[0]);
                  send({
                    nhomCongTac: "storekit",
                    suKien: "Ứng dụng gửi yêu cầu hỏi danh mục Gói mua hàng (SKProductsRequest - start)",
                    doiTuong: reqObj.$className
                  });
                } catch {}
              }
            });
          }
          const SKPaymentQueue = ObjC.classes.SKPaymentQueue;
          if (SKPaymentQueue && SKPaymentQueue["- addPayment:"]) {
            Interceptor.attach(SKPaymentQueue["- addPayment:"].implementation, {
              onEnter(args) {
                if (!featureFlags.storekitObserver || args[2].isNull()) return;
                try {
                  const pay = new ObjC.Object(args[2]);
                  const prodId = pay.respondsToSelector_(ObjC.selector("productIdentifier"))
                    ? safeStr(pay.productIdentifier())
                    : "";
                  const qty = pay.respondsToSelector_(ObjC.selector("quantity")) ? Number(pay.quantity()) : 1;
                  send({
                    nhomCongTac: "storekit",
                    suKien: "Ứng dụng thêm giao dịch vào Hàng đợi Thanh toán (SKPaymentQueue - addPayment:)",
                    maSanPham: prodId,
                    soLuong: qty
                  });
                } catch {}
              }
            });
          }
        } else if (featureKey === "authObserver") {
          const prevHttpFlag = featureFlags.httpCapture;
          enableHttpSnifferInternal();
          featureFlags.httpCapture = prevHttpFlag;
          const LAContext = ObjC.classes.LAContext;
          if (LAContext && LAContext["- evaluatePolicy:localizedReason:reply:"]) {
            Interceptor.attach(LAContext["- evaluatePolicy:localizedReason:reply:"].implementation, {
              onEnter(args) {
                if (!featureFlags.authObserver) return;
                try {
                  const policy = args[2].toInt32();
                  const reason = !args[3].isNull() ? new ObjC.Object(args[3]).toString() : "";
                  send({
                    nhomCongTac: "auth",
                    suKien: "Kiểm tra Sinh trắc học FaceID / TouchID (LAContext)",
                    maChinhSach: policy,
                    lyDoHienThi: reason
                  });
                } catch {}
              }
            });
          }
          const ASAuth = ObjC.classes.ASAuthorizationController;
          if (ASAuth && ASAuth["- performRequests"]) {
            Interceptor.attach(ASAuth["- performRequests"].implementation, {
              onEnter() {
                if (!featureFlags.authObserver) return;
                send({
                  nhomCongTac: "auth",
                  suKien: "Kích hoạt Đăng nhập bằng tài khoản Apple (Sign in with Apple)"
                });
              }
            });
          }
        } else if (featureKey === "storageObserver") {
          const NSUserDefaults = ObjC.classes.NSUserDefaults;
          if (NSUserDefaults && NSUserDefaults["- setObject:forKey:"]) {
            let lastLogTs = 0;
            Interceptor.attach(NSUserDefaults["- setObject:forKey:"].implementation, {
              onEnter(args) {
                if (!featureFlags.storageObserver || args[3].isNull()) return;
                const now = Date.now();
                if (now - lastLogTs < 80) return;
                lastLogTs = now;
                try {
                  const keyStr = new ObjC.Object(args[3]).toString();
                  if (keyStr.startsWith("WebKit") || keyStr.startsWith("NS") || keyStr.startsWith("AK")) return;
                  const valObj = !args[2].isNull() ? new ObjC.Object(args[2]) : null;
                  const rawPreview = valObj ? safeStr(valObj.toString()).slice(0, 120) : "null";
                  const isSensitive = /token|secret|pass|jwt|cookie|auth|session/i.test(keyStr);
                  send({
                    nhomCongTac: "storage",
                    suKien: "Ứng dụng lưu cài đặt NSUserDefaults",
                    khoa: keyStr,
                    kieuDuLieu: valObj ? valObj.$className : "nil",
                    giaTriXemTruoc: isSensitive ? maskTextPreview(rawPreview) : rawPreview
                  });
                } catch {}
              }
            });
          }
        } else if (featureKey === "fileAccessObserver") {
          const recentPaths = new Set();
          const homePrefix = (() => {
            try { return getSandboxHomeDir(); } catch { return "/var/mobile/Containers/Data"; }
          })();
          const NSDictionary = ObjC.classes.NSDictionary;
          if (NSDictionary && NSDictionary["+ dictionaryWithContentsOfFile:"]) {
            Interceptor.attach(NSDictionary["+ dictionaryWithContentsOfFile:"].implementation, {
              onEnter(args) {
                if (!featureFlags.fileAccessObserver || args[2].isNull()) return;
                try {
                  const p = new ObjC.Object(args[2]).toString();
                  if (!p.startsWith(homePrefix) || recentPaths.has(p)) return;
                  recentPaths.add(p);
                  if (recentPaths.size > 100) recentPaths.delete(recentPaths.values().next().value);
                  send({
                    nhomCongTac: "file_access",
                    suKien: "Ứng dụng đọc tệp cấu hình Plist trong Sandbox",
                    duongDan: p.replace(homePrefix, "~")
                  });
                } catch {}
              }
            });
          }
          const NSData = ObjC.classes.NSData;
          if (NSData && NSData["+ dataWithContentsOfFile:"]) {
            Interceptor.attach(NSData["+ dataWithContentsOfFile:"].implementation, {
              onEnter(args) {
                if (!featureFlags.fileAccessObserver || args[2].isNull()) return;
                try {
                  const p = new ObjC.Object(args[2]).toString();
                  if (!p.startsWith(homePrefix) || !/\\.(plist|json|sqlite|db|txt|xml)$/i.test(p) || recentPaths.has(p)) return;
                  recentPaths.add(p);
                  if (recentPaths.size > 100) recentPaths.delete(recentPaths.values().next().value);
                  send({
                    nhomCongTac: "file_access",
                    suKien: "Ứng dụng nạp tệp dữ liệu trong Sandbox",
                    duongDan: p.replace(homePrefix, "~")
                  });
                } catch {}
              }
            });
          }
        } else if (featureKey === "uiScreenObserver") {
          const UIViewController = ObjC.classes.UIViewController;
          if (UIViewController && UIViewController["- viewDidAppear:"]) {
            const ignoredVc = /^(UIInputWindowController|UICompatibilityInputViewController|_UIRemoteInputViewController|UISystemKeyboardDockController|UINavigationController|UITabBarController|UIEditingOverlayViewController)$/;
            Interceptor.attach(UIViewController["- viewDidAppear:"].implementation, {
              onEnter(args) {
                if (!featureFlags.uiScreenObserver) return;
                try {
                  const vc = new ObjC.Object(args[0]);
                  const clsName = vc.$className;
                  if (ignoredVc.test(clsName)) return;
                  const title = vc.respondsToSelector_(ObjC.selector("title")) && vc.title()
                    ? vc.title().toString()
                    : "";
                  send({
                    nhomCongTac: "ui_screen",
                    suKien: "Chuyển màn hình hiển thị trên iPhone",
                    lopManHinh: clsName,
                    tieuDe: title || "(Không đặt tiêu đề)"
                  });
                } catch {}
              }
            });
          }
        }
      } catch (err) {
        reportHookDiag("switch:" + featureKey, err);
      }
    }

    const labels = {
      storekitObserver: "Soi Mua hàng & StoreKit (Chỉ đọc)",
      authObserver: "Soi Đăng nhập & Sinh trắc học (Chỉ đọc)",
      storageObserver: "Soi Bộ nhớ Cài đặt NSUserDefaults (Chỉ đọc)",
      fileAccessObserver: "Soi Truy cập Tệp Sandbox (Chỉ đọc)",
      uiScreenObserver: "Soi Chuyển Màn hình iOS (UIViewController)"
    };
    const label = labels[featureKey] || featureKey;
    return {
      featureKey,
      enabled: featureFlags[featureKey],
      switches: { ...featureFlags },
      message: (isOn ? "Đã BẬT công tắc: " : "Đã TẮT công tắc: ") + label
    };
  }

  globalThis.__studioEnableHttpCapture = enableHttpSnifferInternal;
  globalThis.__studioSetFeatureSwitch = installFeatureSwitchInternal;

  const inspectorApi = {
    __studioEnableHttpCapture() {
      return enableHttpSnifferInternal();
    },
    __studioGetFeatureSwitches() {
      return { ...featureFlags };
    },
    __studioSetFeatureSwitch(featureKey, enabled) {
      return installFeatureSwitchInternal(featureKey, enabled);
    },
    __studioReplayHttpRequest(spec = {}) {
      if (typeof ObjC === "undefined" || !ObjC.available) {
        throw new Error("Cần gắn vào ứng dụng iOS để gửi gói tin từ bên trong điện thoại.");
      }
      const targetUrl = safeStr(spec.url).trim();
      const method = safeStr(spec.method || "GET").trim().toUpperCase();
      const headers = spec.headers && typeof spec.headers === "object" ? spec.headers : {};
      const bodyStr = safeStr(spec.body);

      if (!/^https?:\\/\\//i.test(targetUrl)) {
        throw new Error("Đường dẫn URL phải bắt đầu bằng http:// hoặc https://");
      }

      return new Promise((resolve, reject) => {
        try {
          const nsUrl = ObjC.classes.NSURL.URLWithString_(targetUrl);
          if (!nsUrl || nsUrl.isNull?.()) {
            return reject(new Error("Đường dẫn URL không hợp lệ: " + targetUrl));
          }

          const req = ObjC.classes.NSMutableURLRequest.requestWithURL_cachePolicy_timeoutInterval_(
            nsUrl,
            1,
            15.0
          );
          req.setHTTPMethod_(method);

          for (const [hKey, hVal] of Object.entries(headers)) {
            if (hKey && hVal !== undefined && hVal !== null) {
              req.setValue_forHTTPHeaderField_(String(hVal), String(hKey));
            }
          }

          if (bodyStr && method !== "GET" && method !== "HEAD") {
            const nsBodyStr = ObjC.classes.NSString.stringWithUTF8String_(
              Memory.allocUtf8String(bodyStr)
            );
            const bodyData = nsBodyStr.dataUsingEncoding_(4);
            if (bodyData) req.setHTTPBody_(bodyData);
          }

          const startedAt = Date.now();
          const doneBlock = new ObjC.Block({
            retType: "void",
            argTypes: ["pointer", "pointer", "pointer"],
            implementation(dataPtr, respPtr, errPtr) {
              activeObjcBlocks.delete(doneBlock);
              try {
                let statusCode = 0;
                let responseHeaders = {};
                if (respPtr && !ptr(respPtr).isNull()) {
                  const respObj = new ObjC.Object(ptr(respPtr));
                  if (respObj.respondsToSelector_(ObjC.selector("statusCode"))) {
                    statusCode = Number(respObj.statusCode());
                  }
                  if (respObj.respondsToSelector_(ObjC.selector("allHeaderFields"))) {
                    responseHeaders = nsDictToJs(respObj.allHeaderFields());
                  }
                }
                const responseBody =
                  dataPtr && !ptr(dataPtr).isNull()
                    ? nsDataToText(new ObjC.Object(ptr(dataPtr)), 65536)
                    : "";
                const errorText =
                  errPtr && !ptr(errPtr).isNull()
                    ? new ObjC.Object(ptr(errPtr)).localizedDescription()?.toString() || "Lỗi mạng"
                    : "";

                const outcome = {
                  method,
                  url: targetUrl,
                  requestHeaders: headers,
                  requestBody: bodyStr,
                  statusCode,
                  responseHeaders,
                  responseBody,
                  elapsedMs: Math.max(1, Date.now() - startedAt),
                  errorText,
                  replayedFromDevice: true
                };
                resolve(outcome);
              } catch (cbErr) {
                reject(cbErr);
              }
            }
          });
          activeObjcBlocks.add(doneBlock);
          const reqPtrKey = req.handle.toString();
          replayedReqPtrs.add(reqPtrKey);

          const task = ObjC.classes.NSURLSession.sharedSession().dataTaskWithRequest_completionHandler_(
            req,
            doneBlock
          );
          replayedReqPtrs.delete(reqPtrKey);
          const replayTaskKey = task && task.handle ? task.handle.toString() : "";
          if (replayTaskKey) {
            replayedTaskKeys.add(replayTaskKey);
            setTimeout(() => replayedTaskKeys.delete(replayTaskKey), 20000);
          }
          task.resume();
        } catch (err) {
          reject(err);
        }
      });
    },
    __studioListModules(filterKeyword = "") {
      const kw = safeStr(filterKeyword).trim().toLowerCase();
      return Process.enumerateModules()
        .filter((m) => !kw || m.name.toLowerCase().includes(kw) || m.path.toLowerCase().includes(kw))
        .slice(0, 300)
        .map((m) => ({
          name: m.name,
          base: m.base.toString(),
          size: m.size,
          path: m.path
        }));
    },
    __studioListExports(moduleName = "", filterKeyword = "") {
      const kw = safeStr(filterKeyword).trim().toLowerCase();
      const mod = Process.findModuleByName(moduleName);
      if (!mod) return [];
      return mod.enumerateExports()
        .filter((e) => !kw || e.name.toLowerCase().includes(kw))
        .slice(0, 250)
        .map((e) => ({
          type: e.type,
          name: e.name,
          address: e.address.toString()
        }));
    },
    __studioListObjcClasses(filterKeyword = "") {
      if (typeof ObjC === "undefined" || !ObjC.available) {
        return { available: false, classes: [] };
      }
      const kw = safeStr(filterKeyword).trim().toLowerCase();
      const matched = [];
      for (const name of Object.keys(ObjC.classes)) {
        if (!kw || name.toLowerCase().includes(kw)) {
          matched.push(name);
          if (matched.length >= 250) break;
        }
      }
      matched.sort();
      return { available: true, classes: matched };
    },
    __studioGetObjcMethods(className = "") {
      if (typeof ObjC === "undefined" || !ObjC.available) {
        return { available: false, methods: [] };
      }
      const cls = ObjC.classes[className];
      if (!cls) return { available: true, methods: [] };
      const methods = cls.$ownMethods.slice(0, 400).map((m) => {
        let impl = "";
        try {
          impl = cls[m]?.implementation?.toString?.() || "";
        } catch {}
        return { selector: m, address: impl };
      });
      return { available: true, className, superClass: cls.$superClass?.$className || null, methods };
    },
    __studioGetAppManifest() {
      const baseInfo = {
        pid: Process.id,
        arch: Process.arch,
        platform: Process.platform,
        pageSize: Process.pageSize,
        pointerSize: Process.pointerSize,
        heapSize: Frida.heapSize,
        threadsCount: Process.enumerateThreads().length,
        objcAvailable: typeof ObjC !== "undefined" && Boolean(ObjC.available)
      };
      if (!baseInfo.objcAvailable) return baseInfo;
      try {
        const NSBundle = ObjC.classes.NSBundle.mainBundle();
        const NSProcessInfo = ObjC.classes.NSProcessInfo.processInfo();
        const NSHomeDirectory = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
        const homePtr = NSHomeDirectory();
        const homeDir = homePtr && !homePtr.isNull() ? new ObjC.Object(homePtr).toString() : "";
        const dict = NSBundle.infoDictionary();
        const readKey = (k) => {
          const obj = dict ? dict.objectForKey_(k) : null;
          return obj ? obj.toString() : null;
        };
        return {
          ...baseInfo,
          bundleId: NSBundle.bundleIdentifier()?.toString() || null,
          bundlePath: NSBundle.bundlePath()?.toString() || null,
          executablePath: NSBundle.executablePath()?.toString() || null,
          shortVersion: readKey("CFBundleShortVersionString"),
          buildVersion: readKey("CFBundleVersion"),
          minimumOsVersion: readKey("MinimumOSVersion"),
          homeDirectory: homeDir,
          hostName: NSProcessInfo.hostName()?.toString() || null,
          osVersionString: NSProcessInfo.operatingSystemVersionString()?.toString() || null,
          atsConfig: readKey("NSAppTransportSecurity") || "Mặc định (Bật bảo vệ ATS chuẩn iOS)",
          urlTypes: readKey("CFBundleURLTypes") || "Không đăng ký URL Scheme"
        };
      } catch (err) {
        return { ...baseInfo, manifestError: String(err.message || err) };
      }
    },
    __studioSmartFindFunctions(opts = {}) {
      const preset = safeStr(opts.preset).trim().toLowerCase();
      const keyword = safeStr(opts.keyword).trim().toLowerCase();
      const maxResults = Math.min(150, Math.max(10, Number(opts.limit) || 100));

      const presetPatterns = {
        login: /login|signin|sign_in|auth|oauth|credential|biometric|passcode|otp|session|account/i,
        purchase: /purchase|payment|storekit|product|receipt|transaction|entitlement|subscribe|subscription|vip|iap|restore/i,
        network: /request|urlsession|http|socket|graphql|api|upload|download|fetch|webhook/i,
        crypto: /crypt|cipher|aes|hmac|sha256|rsa|keychain|secitem|jwt|bearer|sign|verify/i
      };
      const activeRegex = presetPatterns[preset] || null;
      const matchesText = (txt) => {
        if (!txt) return false;
        if (activeRegex && keyword) {
          return activeRegex.test(txt) && txt.toLowerCase().includes(keyword);
        }
        if (activeRegex) return activeRegex.test(txt);
        if (keyword) return txt.toLowerCase().includes(keyword);
        return false;
      };

      const items = [];
      let appBundlePrefix = "";
      const mainMod = Process.enumerateModules()[0] || null;
      const mainModName = mainMod ? mainMod.name : "";

      if (typeof ObjC !== "undefined" && ObjC.available) {
        try {
          appBundlePrefix = ObjC.classes.NSBundle.mainBundle().bundlePath()?.toString() || "";
        } catch {}

        const classNames = Object.keys(ObjC.classes);
        const systemSkipPrefix = /^(UIKeyboard|_UI|NSLayout|CALayer|CAAnimation|WebCore|WKContent|_NS|OS_)/;
        for (let i = 0; i < classNames.length; i++) {
          const clsName = classNames[i];
          if (systemSkipPrefix.test(clsName)) continue;
          const cls = ObjC.classes[clsName];
          if (!cls) continue;

          let modPath = "";
          try {
            modPath = safeStr(cls.$moduleName);
          } catch {}
          const isAppOwnCode = Boolean(
            (appBundlePrefix && modPath.startsWith(appBundlePrefix)) ||
            (mainModName && modPath.endsWith("/" + mainModName))
          );

          const classHit = matchesText(clsName);
          if (!classHit && !isAppOwnCode && items.length >= maxResults) continue;

          let ownMethods = [];
          try {
            ownMethods = cls.$ownMethods || [];
          } catch {}

          for (let j = 0; j < ownMethods.length; j++) {
            const sel = ownMethods[j];
            if (classHit || matchesText(sel)) {
              let addr = "";
              try {
                addr = cls[sel]?.implementation?.toString?.() || "";
              } catch {}
              const prefixSign = sel.startsWith("+") || sel.startsWith("-") ? sel.slice(0, 1) : "-";
              const cleanSel = sel.replace(/^[+-]\\s*/, "");
              items.push({
                kind: "objc",
                className: clsName,
                selector: sel,
                fullSymbol: prefixSign + "[" + clsName + " " + cleanSel + "]",
                moduleName: modPath ? modPath.split("/").pop() : (isAppOwnCode ? mainModName : "Framework"),
                address: addr,
                isAppOwnCode
              });
              if (items.length >= maxResults * 2) break;
            }
          }
          if (items.length >= maxResults * 2) break;
        }
      }

      if (mainMod && typeof mainMod.enumerateExports === "function") {
        try {
          const exps = mainMod.enumerateExports();
          for (let i = 0; i < exps.length; i++) {
            const e = exps[i];
            if (matchesText(e.name)) {
              items.push({
                kind: "export",
                className: "",
                selector: e.name,
                fullSymbol: e.name,
                moduleName: mainMod.name,
                address: e.address.toString(),
                isAppOwnCode: true
              });
              if (items.length >= maxResults * 2 + 40) break;
            }
          }
        } catch {}
      }

      items.sort((a, b) => {
        if (a.isAppOwnCode !== b.isAppOwnCode) return a.isAppOwnCode ? -1 : 1;
        return a.fullSymbol.localeCompare(b.fullSymbol);
      });

      return {
        available: typeof ObjC !== "undefined" && Boolean(ObjC.available),
        preset: preset || "custom",
        keyword,
        totalMatched: items.length,
        items: items.slice(0, maxResults)
      };
    },
    __studioScanMemoryInstances(opts = {}) {
      if (typeof ObjC === "undefined" || !ObjC.available) {
        throw new Error("Cần gắn vào ứng dụng iOS có hỗ trợ Objective-C để quét đối tượng trên bộ nhớ RAM.");
      }
      const className = safeStr(opts.className).trim();
      if (!className) {
        throw new Error("Vui lòng nhập tên Lớp (Class) cần tìm trên bộ nhớ RAM (ví dụ: NSURLSession, SKPaymentQueue).");
      }
      const targetCls = ObjC.classes[className];
      if (!targetCls) {
        return {
          foundClass: false,
          className,
          totalCount: 0,
          instances: [],
          message: "Chưa tìm thấy lớp '" + className + "' trong bộ nhớ ứng dụng hiện tại."
        };
      }
      const maxItems = Math.min(40, Math.max(1, Number(opts.maxItems) || 20));
      const rawMatches = ObjC.chooseSync(targetCls);
      const instances = rawMatches.slice(0, maxItems).map((inst) => {
        let preview = "";
        try {
          preview = safeStr(inst.toString()).slice(0, 220);
        } catch {
          preview = "<Đối tượng tại " + inst.handle.toString() + ">";
        }
        return {
          handle: inst.handle.toString(),
          actualClass: safeStr(inst.$className || className),
          preview
        };
      });
      return {
        foundClass: true,
        className,
        totalCount: rawMatches.length,
        instances,
        message: "Tìm thấy " + rawMatches.length + " đối tượng '" + className + "' đang sống trên bộ nhớ RAM."
      };
    },
    __studioListSandboxFiles(relPath = "") {
      const resolved = resolveSafeSandboxPath(relPath);
      const fm = ObjC.classes.NSFileManager.defaultManager();
      const isDirPtr = Memory.alloc(Process.pointerSize);
      isDirPtr.writeU8(0);
      const exists = Boolean(fm.fileExistsAtPath_isDirectory_(resolved.fullPath, isDirPtr));
      if (!exists) {
        return {
          homeDir: resolved.homeDir,
          currentRelPath: resolved.relPath,
          fullPath: resolved.fullPath,
          exists: false,
          items: []
        };
      }

      const namesArr = fm.contentsOfDirectoryAtPath_error_(resolved.fullPath, NULL);
      if (!namesArr || namesArr.isNull?.()) {
        return {
          homeDir: resolved.homeDir,
          currentRelPath: resolved.relPath,
          fullPath: resolved.fullPath,
          exists: true,
          items: []
        };
      }

      const count = Math.min(300, Number(namesArr.count()));
      const items = [];
      for (let i = 0; i < count; i++) {
        const name = namesArr.objectAtIndex_(i).toString();
        const itemRel = resolved.relPath ? resolved.relPath + "/" + name : name;
        const itemFull = resolved.fullPath + "/" + name;
        let isDir = false;
        let sizeBytes = 0;
        let modifiedAt = "";
        try {
          const itemDirPtr = Memory.alloc(Process.pointerSize);
          itemDirPtr.writeU8(0);
          fm.fileExistsAtPath_isDirectory_(itemFull, itemDirPtr);
          isDir = itemDirPtr.readU8() !== 0;

          const attrs = fm.attributesOfItemAtPath_error_(itemFull, NULL);
          if (attrs && !attrs.isNull?.()) {
            const szObj = attrs.objectForKey_("NSFileSize");
            if (szObj) sizeBytes = Number(szObj.longLongValue?.() ?? szObj.doubleValue?.() ?? 0);
            const modObj = attrs.objectForKey_("NSFileModificationDate");
            if (modObj) modifiedAt = modObj.toString();
          }
        } catch {}

        items.push({
          name,
          relPath: itemRel,
          isDir,
          sizeBytes,
          modifiedAt
        });
      }

      items.sort((a, b) => {
        if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

      return {
        homeDir: resolved.homeDir,
        currentRelPath: resolved.relPath,
        fullPath: resolved.fullPath,
        exists: true,
        items
      };
    },
    __studioReadSandboxFile(relPath = "") {
      const resolved = resolveSafeSandboxPath(relPath);
      if (!resolved.relPath) {
        throw new Error("Vui lòng bấm chọn một tệp tin cụ thể để xem nội dung.");
      }
      const fm = ObjC.classes.NSFileManager.defaultManager();
      const isDirPtr = Memory.alloc(Process.pointerSize);
      isDirPtr.writeU8(0);
      const exists = Boolean(fm.fileExistsAtPath_isDirectory_(resolved.fullPath, isDirPtr));
      if (!exists) {
        throw new Error("Không tìm thấy tệp tin: " + resolved.relPath);
      }
      if (isDirPtr.readU8() !== 0) {
        throw new Error("Đây là thư mục. Hãy bấm đúp để mở danh sách tệp bên trong.");
      }

      const lower = resolved.relPath.toLowerCase();
      if (lower.endsWith(".plist") || lower.endsWith(".strings")) {
        const dict = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(resolved.fullPath);
        if (dict && !dict.isNull?.()) {
          const jsObj = nsObjToJs(dict, 0);
          return {
            relPath: resolved.relPath,
            format: "plist-json",
            sizeBytes: JSON.stringify(jsObj).length,
            content: JSON.stringify(jsObj, null, 2)
          };
        }
        const arr = ObjC.classes.NSArray.arrayWithContentsOfFile_(resolved.fullPath);
        if (arr && !arr.isNull?.()) {
          const jsArr = nsObjToJs(arr, 0);
          return {
            relPath: resolved.relPath,
            format: "plist-json",
            sizeBytes: JSON.stringify(jsArr).length,
            content: JSON.stringify(jsArr, null, 2)
          };
        }
      }

      const data = ObjC.classes.NSData.dataWithContentsOfFile_(resolved.fullPath);
      if (!data || data.isNull?.()) {
        return {
          relPath: resolved.relPath,
          format: "empty",
          sizeBytes: 0,
          content: "(Tệp trống hoặc không có quyền đọc)"
        };
      }

      const totalBytes = Number(data.length());
      if (totalBytes >= 16) {
        try {
          const headStr = nsDataToText(data.subdataWithRange_([0, 16]), 16);
          if (headStr.startsWith("SQLite format 3")) {
            return {
              relPath: resolved.relPath,
              format: "sqlite-meta",
              sizeBytes: totalBytes,
              content:
                "[Cơ sở dữ liệu SQLite 3 chuẩn iOS]\\n" +
                "• Đường dẫn: ~/" + resolved.relPath + "\\n" +
                "• Dung lượng: " + totalBytes.toLocaleString("en-US") + " byte\\n" +
                "• Trạng thái: Đã xác nhận định dạng SQLite hợp lệ (chế độ chỉ đọc an toàn)."
            };
          }
        } catch {}
      }

      const textPreview = nsDataToText(data, 49152);
      return {
        relPath: resolved.relPath,
        format: lower.endsWith(".json") ? "json" : "text",
        sizeBytes: totalBytes,
        content: textPreview || "(Tệp trống)"
      };
    },
    __studioInspectSecurityVault() {
      if (typeof ObjC === "undefined" || !ObjC.available) {
        throw new Error("Cần gắn vào ứng dụng iOS để kiểm tra Két sắt Bảo mật & Phiên đăng nhập.");
      }

      const userDefaultsItems = [];
      const cookies = [];
      const keychainItems = [];

      // 1. Kiểm tra các khóa Phiên / Tài khoản trong NSUserDefaults của chính ứng dụng
      try {
        const defs = ObjC.classes.NSUserDefaults.standardUserDefaults().dictionaryRepresentation();
        if (defs && !defs.isNull?.()) {
          const keys = defs.allKeys();
          const count = Math.min(400, Number(keys.count()));
          const authKeyRegex = /token|session|auth|jwt|user|uid|account|member|receipt|vip|sub|cookie|device_id|uuid|login/i;
          for (let i = 0; i < count; i++) {
            const kObj = keys.objectAtIndex_(i);
            if (!kObj) continue;
            const kStr = kObj.toString();
            if (kStr.startsWith("NS") || kStr.startsWith("Apple") || kStr.startsWith("WebKit") || kStr.startsWith("AK")) continue;
            if (!authKeyRegex.test(kStr)) continue;
            const vObj = defs.objectForKey_(kObj);
            const rawVal = vObj ? safeStr(vObj.toString()).slice(0, 180) : "";
            userDefaultsItems.push({
              key: kStr,
              valueType: vObj ? safeStr(vObj.$className) : "nil",
              maskedPreview: maskTextPreview(rawVal),
              valuePreview: rawVal
            });
            if (userDefaultsItems.length >= 60) break;
          }
        }
      } catch (err) {
        reportHookDiag("vaultUserDefaults", err);
      }

      // 2. Kiểm tra danh sách Cookie phiên đăng nhập trong NSHTTPCookieStorage của ứng dụng
      try {
        const cookieArr = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
        if (cookieArr && !cookieArr.isNull?.()) {
          const count = Math.min(80, Number(cookieArr.count()));
          for (let i = 0; i < count; i++) {
            const c = cookieArr.objectAtIndex_(i);
            if (!c) continue;
            const rawVal = safeStr(c.value()?.toString()).slice(0, 180);
            cookies.push({
              name: safeStr(c.name()?.toString()),
              domain: safeStr(c.domain()?.toString()),
              path: safeStr(c.path()?.toString() || "/"),
              isSecure: Boolean(c.isSecure()),
              isHTTPOnly: Boolean(c.isHTTPOnly()),
              expiresDate: c.expiresDate() ? c.expiresDate().toString() : "Theo phiên (Session)",
              maskedPreview: maskTextPreview(rawVal),
              valuePreview: rawVal
            });
          }
        }
      } catch (err) {
        reportHookDiag("vaultCookies", err);
      }

      // 3. Kiểm tra siêu dữ liệu Két sắt Keychain của ứng dụng (CHỈ ĐỌC thuộc tính cấu hình bảo vệ, KHÔNG trích xuất khóa thô, KHÔNG bật popup FaceID)
      try {
        const readConstObj = (sym) => {
          try {
            const p = Module.getGlobalExportByName(sym);
            if (!p || p.isNull()) return null;
            const cf = p.readPointer();
            return cf && !cf.isNull() ? new ObjC.Object(cf) : null;
          } catch {
            return null;
          }
        };

        const secCopySym = (() => {
          try { return Module.getGlobalExportByName("SecItemCopyMatching"); } catch { return null; }
        })();

        if (secCopySym) {
          const SecItemCopyMatching = new NativeFunction(secCopySym, "int", ["pointer", "pointer"]);
          const kSecClass = readConstObj("kSecClass");
          const kSecReturnAttributes = readConstObj("kSecReturnAttributes");
          const kSecMatchLimit = readConstObj("kSecMatchLimit");
          const kSecMatchLimitAll = readConstObj("kSecMatchLimitAll");
          const kCFBooleanTrue = readConstObj("kCFBooleanTrue");
          const kSecUseAuthenticationUI = readConstObj("kSecUseAuthenticationUI");
          const kSecUseAuthenticationUISkip = readConstObj("kSecUseAuthenticationUISkip");

          const secClasses = [
            { label: "Mật khẩu / Token Chung (GenericPassword)", obj: readConstObj("kSecClassGenericPassword") },
            { label: "Tài khoản Web / API (InternetPassword)", obj: readConstObj("kSecClassInternetPassword") }
          ];

          for (const sc of secClasses) {
            if (!kSecClass || !sc.obj || !kSecReturnAttributes || !kSecMatchLimit || !kSecMatchLimitAll || !kCFBooleanTrue) {
              continue;
            }
            const q = ObjC.classes.NSMutableDictionary.alloc().init();
            q.setObject_forKey_(sc.obj, kSecClass);
            q.setObject_forKey_(kCFBooleanTrue, kSecReturnAttributes);
            q.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit);
            if (kSecUseAuthenticationUI && kSecUseAuthenticationUISkip) {
              q.setObject_forKey_(kSecUseAuthenticationUISkip, kSecUseAuthenticationUI);
            }

            const outPtr = Memory.alloc(Process.pointerSize);
            outPtr.writePointer(NULL);
            const status = SecItemCopyMatching(q.handle, outPtr);
            if (status === 0) {
              const resPtr = outPtr.readPointer();
              if (resPtr && !resPtr.isNull()) {
                const arr = new ObjC.Object(resPtr);
                const cnt = Math.min(50, Number(arr.count?.() || 0));
                for (let idx = 0; idx < cnt; idx++) {
                  const row = arr.objectAtIndex_(idx);
                  const rowJs = nsDictToJs(row);
                  keychainItems.push({
                    itemClass: sc.label,
                    service: rowJs.svce || rowJs.srvr || "(Mặc định)",
                    account: rowJs.acct || "(Không đặt tên)",
                    accessGroup: rowJs.agrp || "(Nhóm mặc định App)",
                    protection: rowJs.pdmn || "chuẩn iOS"
                  });
                }
              }
            }
          }
        }
      } catch (err) {
        reportHookDiag("vaultKeychain", err);
      }

      return {
        sampledAt: new Date().toISOString(),
        counts: {
          userDefaults: userDefaultsItems.length,
          cookies: cookies.length,
          keychain: keychainItems.length
        },
        userDefaultsItems,
        cookies,
        keychainItems
      };
    },
    __studioListUserRpcExports() {
      const exportsList = [];
      try {
        for (const k of Reflect.ownKeys(userExportsTarget)) {
          const name = String(k);
          if (!name || name.startsWith("__studio")) continue;
          if (typeof userExportsTarget[k] === "function") {
            exportsList.push(name);
          }
        }
      } catch {}
      return {
        available: true,
        count: exportsList.length,
        exports: exportsList
      };
    },
    __studioInspectSecurityPosture() {
      const baseManifest = inspectorApi.__studioGetAppManifest();
      const modules = Process.enumerateModules();
      // Trên Dopamine Rootless (/var/jb), modules[0] thường là systemhook.dylib (MH_DYLIB=6) thay vì tệp thực thi chính (MH_EXECUTE=2)
      const mainMod =
        (baseManifest.executablePath && modules.find((m) => m.path === baseManifest.executablePath)) ||
        modules.find((m) => {
          try {
            return (
              m &&
              m.base &&
              typeof m.base.readU32 === "function" &&
              m.base.readU32() === 0xfeedfacf &&
              m.base.add(12).readU32() === 2
            );
          } catch {
            return false;
          }
        }) ||
        modules[0] ||
        null;

      // 1. Kiểm toán cờ bảo vệ tệp nhị phân Mach-O 64-bit trực tiếp từ RAM (Chuẩn OWASP MASTG)
      const binaryHardening = {
        moduleName: mainMod ? mainMod.name : null,
        baseAddress: mainMod && mainMod.base ? mainMod.base.toString() : null,
        isMachO64: false,
        pieEnabled: null,
        cryptId: null,
        hasArc: false,
        hasStackCanary: false
      };

      if (mainMod && mainMod.base) {
        try {
          if (typeof mainMod.base.readU32 === "function") {
            const magic = mainMod.base.readU32();
            if (magic === 0xfeedfacf) {
              binaryHardening.isMachO64 = true;
              const ncmds = mainMod.base.add(16).readU32();
              const flags = mainMod.base.add(24).readU32();
              binaryHardening.pieEnabled = (flags & 0x200000) !== 0;
              let cmdPtr = mainMod.base.add(32);
              const maxCmds = Math.min(180, Number(ncmds) || 0);
              for (let i = 0; i < maxCmds; i++) {
                const cmd = cmdPtr.readU32();
                const cmdSize = cmdPtr.add(4).readU32();
                if (!cmdSize || cmdSize < 8) break;
                if (cmd === 0x2c) {
                  binaryHardening.cryptId = cmdPtr.add(16).readU32();
                  break;
                }
                cmdPtr = cmdPtr.add(cmdSize);
              }
            }
          }
        } catch {}

        try {
          if (typeof mainMod.enumerateImports === "function") {
            const imps = mainMod.enumerateImports();
            for (let i = 0; i < imps.length; i++) {
              const nm = imps[i]?.name || "";
              if (nm.includes("objc_retain") || nm.includes("objc_release")) {
                binaryHardening.hasArc = true;
              }
              if (nm.includes("stack_chk_guard") || nm.includes("stack_chk_fail")) {
                binaryHardening.hasStackCanary = true;
              }
              if (binaryHardening.hasArc && binaryHardening.hasStackCanary) break;
            }
          }
        } catch {}
      }

      // 2. Nhận diện công nghệ đóng gói & các Tweak /var/jb đang gắn trong tiến trình
      const frameworksDetected = [];
      const injectedTweaks = [];
      const hasMod = (re) => modules.some((m) => re.test(m.name || "") || re.test(m.path || ""));
      if (baseManifest.objcAvailable) frameworksDetected.push("Objective-C Runtime");
      if (hasMod(/libswiftCore/i)) frameworksDetected.push("Swift");
      if (hasMod(/Flutter\.framework|Flutter$/i)) frameworksDetected.push("Flutter");
      if (hasMod(/hermes|React\.framework/i)) frameworksDetected.push("React Native");
      if (hasMod(/UnityFramework|il2cpp/i)) frameworksDetected.push("Unity / IL2CPP");
      if (hasMod(/WebKit/i)) frameworksDetected.push("WKWebView");
      if (hasMod(/StoreKit/i)) frameworksDetected.push("StoreKit / In-App Purchase");

      for (const m of modules) {
        const p = m.path || "";
        if (p.includes("/var/jb/") || p.includes("MobileSubstrate") || p.includes("TweakInject") || p.includes("ellekit")) {
          injectedTweaks.push({ name: m.name, path: p });
          if (injectedTweaks.length >= 25) break;
        }
      }

      // 3. Bóc tách sạch danh sách URL Schemes, ngoại lệ mạng ATS & biên lai StoreKit (không in chuỗi thô rối mắt)
      const urlSchemesList = [];
      const atsParsed = {
        allowsArbitraryLoads: false,
        allowsWebArbitraryLoads: false,
        exceptionDomains: [],
        summaryVi: "Chuẩn an toàn cao nhất (Chặn HTTP không mã hóa)"
      };
      const storeKitReceipt = {
        available: false,
        environment: "Không sử dụng / Tiến trình ngoài iOS",
        receiptPath: "",
        receiptExists: false,
        canMakePayments: null
      };

      if (baseManifest.objcAvailable) {
        try {
          const bundle = ObjC.classes.NSBundle.mainBundle();
          const infoDict = bundle ? bundle.infoDictionary() : null;

          // Bóc tách CFBundleURLTypes -> mảng tên scheme sạch gọn (VD: prefs://, otpauth://)
          const urlTypesArr = infoDict ? infoDict.objectForKey_("CFBundleURLTypes") : null;
          if (urlTypesArr && !urlTypesArr.isNull?.() && typeof urlTypesArr.count === "function") {
            const cnt = Math.min(50, Number(urlTypesArr.count()) || 0);
            for (let i = 0; i < cnt; i++) {
              const item = urlTypesArr.objectAtIndex_(i);
              if (!item || typeof item.objectForKey_ !== "function") continue;
              const schemesObj = item.objectForKey_("CFBundleURLSchemes");
              if (schemesObj && typeof schemesObj.count === "function") {
                const sCnt = Math.min(20, Number(schemesObj.count()) || 0);
                for (let j = 0; j < sCnt; j++) {
                  const sVal = schemesObj.objectAtIndex_(j)?.toString?.().trim();
                  if (sVal && !urlSchemesList.includes(sVal)) {
                    urlSchemesList.push(sVal);
                  }
                }
              }
            }
          }

          // Bóc tách NSAppTransportSecurity
          const atsObj = infoDict ? infoDict.objectForKey_("NSAppTransportSecurity") : null;
          if (atsObj && !atsObj.isNull?.() && typeof atsObj.objectForKey_ === "function") {
            const arb = atsObj.objectForKey_("NSAllowsArbitraryLoads");
            const webArb = atsObj.objectForKey_("NSAllowsArbitraryLoadsInWebContent");
            atsParsed.allowsArbitraryLoads = Boolean(arb && arb.toString() === "1");
            atsParsed.allowsWebArbitraryLoads = Boolean(webArb && webArb.toString() === "1");
            const excDomains = atsObj.objectForKey_("NSExceptionDomains");
            if (excDomains && typeof excDomains.allKeys === "function") {
              const dKeys = excDomains.allKeys();
              const dCnt = Math.min(30, Number(dKeys.count?.() || 0));
              for (let i = 0; i < dCnt; i++) {
                const dom = dKeys.objectAtIndex_(i)?.toString?.();
                if (dom) atsParsed.exceptionDomains.push(dom);
              }
            }
            if (atsParsed.allowsArbitraryLoads) {
              atsParsed.summaryVi = "Cảnh báo OWASP M5: Đang bật NSAllowsArbitraryLoads = YES (cho phép kết nối HTTP thường)";
            } else if (atsParsed.exceptionDomains.length > 0) {
              atsParsed.summaryVi = "Có " + atsParsed.exceptionDomains.length + " tên miền ngoại lệ ATS riêng";
            } else if (atsParsed.allowsWebArbitraryLoads) {
              atsParsed.summaryVi = "Cho phép tải trang HTTP thường bên trong khung WebView";
            }
          }

          // Kiểm tra biên lai StoreKit Sandbox / TestFlight
          const recUrl = bundle && typeof bundle.appStoreReceiptURL === "function" ? bundle.appStoreReceiptURL() : null;
          const recPath = recUrl && typeof recUrl.path === "function" ? safeStr(recUrl.path()?.toString()) : "";
          const fm = ObjC.classes.NSFileManager?.defaultManager?.();
          const exists = recPath && fm && typeof fm.fileExistsAtPath_ === "function" ? Boolean(fm.fileExistsAtPath_(recPath)) : false;
          const skQueue = ObjC.classes.SKPaymentQueue;
          storeKitReceipt.available = true;
          storeKitReceipt.receiptPath = recPath;
          storeKitReceipt.receiptExists = exists;
          storeKitReceipt.environment = recPath.endsWith("sandboxReceipt")
            ? "SANDBOX / TESTFLIGHT"
            : recPath
            ? "APP STORE CHÍNH THỨC"
            : "Hệ thống / Chưa định cấu hình biên lai";
          storeKitReceipt.canMakePayments =
            skQueue && typeof skQueue.canMakePayments === "function" ? Boolean(skQueue.canMakePayments()) : null;
        } catch (err) {
          reportHookDiag("securityPosture", err);
        }
      }

      return {
        manifest: baseManifest,
        binaryHardening,
        frameworksDetected,
        injectedTweaks,
        urlSchemesList,
        atsParsed,
        storeKitReceipt
      };
    }
  };
  let userExportsTarget =
    typeof rpc !== "undefined" && rpc && rpc.exports && typeof rpc.exports === "object"
      ? rpc.exports
      : {};

  const proxyRef = new Proxy(inspectorApi, {
    get(_target, prop, receiver) {
      if (prop in inspectorApi) return inspectorApi[prop];
      return Reflect.get(userExportsTarget, prop, receiver);
    },
    set(_target, prop, value) {
      userExportsTarget[prop] = value;
      return true;
    },
    has(_target, prop) {
      return prop in inspectorApi || prop in userExportsTarget;
    },
    ownKeys(_target) {
      return Array.from(new Set([...Reflect.ownKeys(inspectorApi), ...Reflect.ownKeys(userExportsTarget)]));
    },
    getOwnPropertyDescriptor(_target, prop) {
      if (prop in inspectorApi) {
        return { configurable: true, enumerable: true, value: inspectorApi[prop] };
      }
      if (prop in userExportsTarget) {
        return { configurable: true, enumerable: true, value: userExportsTarget[prop] };
      }
      return undefined;
    }
  });

  if (typeof rpc !== "undefined" && rpc) {
    // BẮT BUỘC gán qua setter gốc của Frida GumJS trước để biến đóng rpcExports bên trong GumJS trỏ tới proxyRef!
    rpc.exports = proxyRef;
    try {
      Object.defineProperty(rpc, "exports", {
        configurable: true,
        enumerable: true,
        get() {
          return proxyRef;
        },
        set(nextExports) {
          userExportsTarget = nextExports && typeof nextExports === "object" ? nextExports : {};
        }
      });
    } catch {
      // Nếu môi trường không cho defineProperty thì rpc.exports = proxyRef ở trên vẫn hoạt động
    }
  }
})();
`;

export class FridaScriptCompiler {
  #cachedObjcPrelude = null;
  #cachedBootstrapLine = null;

  async #getObjcPrelude() {
    if (this.#cachedObjcPrelude !== null) {
      return this.#cachedObjcPrelude;
    }
    const res = await build({
      stdin: {
        contents: `import ObjC from "frida-objc-bridge"; globalThis.ObjC = ObjC;`,
        resolveDir: PROJECT_ROOT,
        loader: "js",
      },
      bundle: true,
      minify: true,
      write: false,
      format: "iife",
      platform: "neutral",
      mainFields: ["module", "main"],
    });
    // Đảm bảo đúng 1 dòng duy nhất để dễ tính toán độ lệch số dòng khi báo lỗi
    this.#cachedObjcPrelude = res.outputFiles[0].text.replace(/\r?\n/g, " ").trim();
    logger.info("Đã biên dịch sẵn bộ đệm frida-objc-bridge cho Frida 17", {
      bytes: this.#cachedObjcPrelude.length,
    });
    return this.#cachedObjcPrelude;
  }

  async #getBootstrapLine() {
    if (this.#cachedBootstrapLine !== null) {
      return this.#cachedBootstrapLine;
    }
    const res = await build({
      stdin: {
        contents: STUDIO_INSPECTOR_BOOTSTRAP,
        resolveDir: PROJECT_ROOT,
        loader: "js",
      },
      bundle: false,
      minify: true,
      write: false,
      platform: "neutral",
    });
    this.#cachedBootstrapLine = res.outputFiles[0].text.replace(/\r?\n/g, " ").trim();
    return this.#cachedBootstrapLine;
  }

  async compileUserScript(userSource, { enableObjCBridge = true } = {}) {
    const usesModuleSyntax = /^\s*(import|export)\s+/m.test(userSource);

    if (usesModuleSyntax) {
      const header = enableObjCBridge
        ? `import __StudioObjC from "frida-objc-bridge"; globalThis.ObjC = __StudioObjC;\n`
        : "";
      const res = await build({
        stdin: {
          contents: `${header}${STUDIO_INSPECTOR_BOOTSTRAP}\n${userSource}`,
          resolveDir: PROJECT_ROOT,
          sourcefile: "user-script.ts",
          loader: "ts",
        },
        bundle: true,
        write: false,
        format: "iife",
        platform: "neutral",
        mainFields: ["module", "main"],
      });
      return {
        compiledSource: res.outputFiles[0].text,
        lineOffset: 0,
        bundledWithEsbuild: true,
      };
    }

    const bootstrapLine = await this.#getBootstrapLine();

    if (enableObjCBridge) {
      const prelude = await this.#getObjcPrelude();
      return {
        compiledSource: `${prelude}\n${bootstrapLine}\n${userSource}`,
        lineOffset: 2,
        bundledWithEsbuild: false,
      };
    }

    return {
      compiledSource: `${bootstrapLine}\n${userSource}`,
      lineOffset: 1,
      bundledWithEsbuild: false,
    };
  }
}

