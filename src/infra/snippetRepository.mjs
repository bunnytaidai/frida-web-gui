// src/infra/snippetRepository.mjs — Kho kịch bản mẫu chẩn đoán an toàn (OWASP MASTG Read-Only) & Kịch bản tự lưu
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.resolve(__dirname, "../../data");
const CUSTOM_SNIPPETS_FILE = path.join(DATA_DIR, "custom-snippets.json");

export const BUILTIN_SNIPPETS = [
  // ==========================================================================
  // BẢNG 1: CƠ BẢN & KHÁM PHÁ THIẾT BỊ (3 MẪU)
  // ==========================================================================
  {
    id: "builtin-runtime-overview",
    title: "1.1 Xem thông tin Máy, iOS & Ứng dụng đang mở",
    category: "1. Cơ bản & Thiết bị",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Đọc tên iPhone, phiên bản iOS, chip xử lý, mã định danh ứng dụng và đường dẫn thư mục cài đặt.",
    code: `// ============================================================================
// MẪU 1.1: KIỂM TRA KẾT NỐI & ĐỌC THÔNG TIN CƠ BẢN CỦA ỨNG DỤNG
// Cách dùng: Chọn thiết bị ở Bước 1 -> Chọn ứng dụng ở Bước 3 -> Bấm "Gửi mã JS"
// ============================================================================

// In thông báo chữ thường ra bảng Nhật ký kết quả ở bên phải
console.log(
  "[+] Đã gắn thành công! Nhân Frida:",
  Frida.version,
  "| Kiến trúc chip:",
  Process.arch,
  "| Mã tiến trình:",
  Process.id
);

// Kiểm tra xem cầu nối ngôn ngữ iOS (ObjC) đã được bật chưa
if (typeof ObjC !== "undefined" && ObjC.available) {
  // Đọc thông tin chiếc điện thoại hiện tại qua lớp UIDevice của hệ điều hành
  const thietBi = ObjC.classes.UIDevice.currentDevice();
  // Đọc thông tin gói ứng dụng mà Frida vừa gắn vào
  const goiUngDung = ObjC.classes.NSBundle.mainBundle();

  // Hàm send({...}) gửi một bảng dữ liệu JSON rõ ràng sang cột kết quả bên phải
  send({
    nhom: "thong_tin_co_ban",
    tenDienThoai: thietBi.name().toString(),
    kieuMay: thietBi.model().toString(),
    phienBanHeDieuHanh: thietBi.systemVersion().toString(),
    maGoiUngDung: goiUngDung.bundleIdentifier()
      ? goiUngDung.bundleIdentifier().toString()
      : "Tiến trình hệ thống",
    thuMucCaiDat: goiUngDung.bundlePath().toString()
  });
} else {
  // Trường hợp đang chạy thử trên máy tính Windows hoặc tiến trình thuần C
  send({
    ghiChu: "Tiến trình này chạy trực tiếp trên nhân hệ điều hành (không dùng lớp iOS ObjC)",
    nenTang: Process.platform,
    maTienTrinh: Process.id,
    kienTrucChip: Process.arch
  });
}
`,
  },
  {
    id: "builtin-current-screen-vc",
    title: "1.2 Soi tên màn hình giao diện đang mở hiện tại",
    category: "1. Cơ bản & Thiết bị",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Cho biết chính xác màn hình đang hiện trên iPhone thuộc lớp thiết kế (ViewController) nào.",
    code: `// ============================================================================
// MẪU 1.2: TÌM TÊN LỚP MÀN HÌNH ĐANG HIỂN THỊ TRÊN ĐIỆN THOẠI
// Tác dụng: Giúp bạn biết ngay màn hình đang mở trên iPhone có tên mã là gì
// (Lưu ý an toàn: Mọi thao tác đọc giao diện iOS đều phải chạy trên luồng chính mainQueue)
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.warn("[-] Mẫu này dành cho ứng dụng có giao diện trên iPhone (cần bật cầu nối iOS).");
} else {
  // Đưa lệnh vào luồng vẽ giao diện chính (mainQueue) để không bao giờ gây đơ ứng dụng
  ObjC.schedule(ObjC.mainQueue, () => {
    try {
      const ungDung = ObjC.classes.UIApplication.sharedApplication();
      const cuaSoChinh = ungDung.keyWindow() || ungDung.windows().firstObject();

      if (!cuaSoChinh || cuaSoChinh.isNull()) {
        console.warn("[-] Tiến trình hiện tại không mở cửa sổ giao diện nào.");
        return;
      }

      // Lần từ màn hình gốc (rootViewController) đi sâu vào màn hình đang hiện trên cùng
      let manHinh = cuaSoChinh.rootViewController();
      const duongDiManHinh = [];

      while (manHinh && !manHinh.isNull()) {
        duongDiManHinh.push(manHinh.$className);
        if (manHinh.presentedViewController() && !manHinh.presentedViewController().isNull()) {
          manHinh = manHinh.presentedViewController();
        } else if (manHinh.isKindOfClass_(ObjC.classes.UINavigationController) && manHinh.visibleViewController()) {
          manHinh = manHinh.visibleViewController();
        } else if (manHinh.isKindOfClass_(ObjC.classes.UITabBarController) && manHinh.selectedViewController()) {
          manHinh = manHinh.selectedViewController();
        } else {
          break;
        }
      }

      console.log("[+] Đã tìm thấy màn hình đang mở trên cùng:", duongDiManHinh[duongDiManHinh.length - 1]);
      send({
        manHinhHienTai: duongDiManHinh[duongDiManHinh.length - 1] || "Không xác định",
        cayPhanCapGiaoDien: duongDiManHinh
      });
    } catch (err) {
      console.error("[-] Không đọc được cây màn hình:", err.message);
    }
  });
}
`,
  },
  {
    id: "builtin-threads-memory",
    title: "1.3 Đo bộ nhớ RAM & Danh sách luồng xử lý CPU",
    category: "1. Cơ bản & Thiết bị",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Thống kê số luồng xử lý song song đang chạy, dung lượng bộ nhớ đệm và vùng nhớ mã lệnh.",
    code: `// ============================================================================
// MẪU 1.3: ĐO LƯỜNG HIỆU NĂNG LUỒNG CPU & VÙNG NHỚ ĐANG CHẠY
// Tác dụng: Kiểm tra xem ứng dụng có mở quá nhiều luồng ngầm gây nóng máy hay không
// ============================================================================

// Lấy toàn bộ danh sách các luồng CPU (Threads) đang hoạt động trong ứng dụng
const danhSachLuong = Process.enumerateThreads();

// Đếm số vùng bộ nhớ RAM có quyền thực thi lệnh máy (r-x = Đọc & Chạy lệnh)
const vungNhoMaLenh = Process.enumerateRanges("r-x");

console.log(
  "[+] Tổng số luồng CPU:",
  danhSachLuong.length,
  "| Số vùng nhớ mã lệnh:",
  vungNhoMaLenh.length
);

send({
  maTienTrinh: Process.id,
  boNhoFridaDangDung_KB: Math.round(Frida.heapSize / 1024),
  kichThuocTrangNho_Byte: Process.pageSize,
  tongSoLuongCPU: danhSachLuong.length,
  // Hiển thị 10 luồng đầu tiên kèm trạng thái (đang chạy hoặc đang chờ)
  mau10LuongDauTien: danhSachLuong.slice(0, 10).map((luong) => ({
    maLuong: luong.id,
    trangThai: luong.state,
    conTroLenhHienTai: luong.context.pc.toString()
  }))
});
`,
  },

  // ==========================================================================
  // BẢNG 2: MẠNG & GIAO THỨC TRUYỀN TIN (3 MẪU — CHUẨN OWASP M5)
  // ==========================================================================
  {
    id: "builtin-urlsession-logger",
    title: "2.1 Bắt Gói Tin Mạng & Hộp Trả Lời (Request + Response)",
    category: "2. Mạng & Truyền tin",
    runType: "listener",
    builtin: true,
    description: "[📡 Bật bắt sóng — Bấm xong hãy thao tác trên iPhone] Tự động thu trọn cả Gói gửi đi & Hộp trả lời vào thẻ '1. Gói tin, Hộp trả lời & Gửi lại' để bạn sửa và gửi lại!",
    code: `// ============================================================================
// MẪU 2.1: BẮT TRỌN VẸN GÓI TIN GỬI ĐI & HỘP TRẢ LỜI TỪ MÁY CHỦ (REQUEST + RESPONSE)
// Cách dùng 3 bước cực dễ:
//   1. Bấm "▶ Chạy ngay" trên mẫu này (hoặc bấm nút "📡 Bật Bắt Gói Tin" ở Thẻ số 1).
//   2. Cầm iPhone mở các mục / cửa hàng bên trong ứng dụng để sinh lưu lượng mạng.
//   3. Mở thẻ "1. Gói tin, Hộp trả lời & Gửi lại" ở khung giữa để xem Hộp trả lời,
//      lưu các mã ID cần thiết và Sửa tham số rồi bấm "Gửi Lại Gói Tin"!
// ============================================================================

if (typeof globalThis.__studioEnableHttpCapture === "function") {
  const ketQua = globalThis.__studioEnableHttpCapture();
  console.log("[+] " + ketQua.message);
  send({
    suKien: "bat_bo_bat_goi_tin_va_hop_tra_loi",
    trangThai: ketQua.enabled ? "ĐANG BẮT GÓI TIN & HỘP TRẢ LỜI" : "KHÔNG KHẢ DỤNG",
    huongDanTiepTheo:
      "Hãy cầm iPhone bấm thao tác trong ứng dụng, sau đó xem chi tiết Hộp trả lời và Sửa gửi lại tại thẻ '1. Gói tin, Hộp trả lời & Gửi lại'!"
  });
} else {
  console.error("[-] Vui lòng chọn một ứng dụng iOS trên iPhone để bật bộ bắt gói tin.");
}
`,
  },
  {
    id: "builtin-http-headers-inspector",
    title: "2.2 Soi chi tiết tiêu đề gói tin HTTP (Headers)",
    category: "2. Mạng & Truyền tin",
    runType: "listener",
    builtin: true,
    description: "[📡 Bật bắt sóng — Bấm xong hãy thao tác trên iPhone] Kiểm tra các trường thông tin đính kèm theo yêu cầu mạng (User-Agent, Content-Type) khi App gọi API.",
    code: `// ============================================================================
// MẪU 2.2: KIỂM TRA TIÊU ĐỀ GÓI TIN MẠNG (HTTP REQUEST HEADERS)
// Tác dụng: Giúp nhà phát triển kiểm tra xem ứng dụng gửi kèm những tiêu đề gì lên máy chủ
// (Tự động ẩn bớt chuỗi nhạy cảm nếu có trường Authorization để đảm bảo an toàn nhật ký).
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.error("[-] Cần môi trường iOS Objective-C để đọc tiêu đề NSURLRequest.");
} else {
  const NSURLSession = ObjC.classes.NSURLSession;
  const hamMang = NSURLSession["- dataTaskWithRequest:"];
  const hamMangCoCallback = NSURLSession["- dataTaskWithRequest:completionHandler:"];

  const theoDoiHam = (tenMoTa, phuongThucObjC) => {
    if (!phuongThucObjC) return;
    Interceptor.attach(phuongThucObjC.implementation, {
      onEnter(args) {
        try {
          if (!args[2] || args[2].isNull()) return;
          const req = new ObjC.Object(args[2]);
          const url = req.URL() ? req.URL().absoluteString().toString() : "";
          const method = req.HTTPMethod() ? req.HTTPMethod().toString() : "GET";
          const headersObj = req.allHTTPHeaderFields();
          const bangTieuDe = {};

          if (headersObj && !headersObj.isNull()) {
            const danhSachKhoa = headersObj.allKeys();
            const soLuong = danhSachKhoa.count().valueOf();
            for (let i = 0; i < soLuong; i++) {
              const khoa = danhSachKhoa.objectAtIndex_(i).toString();
              const giaTri = headersObj.objectForKey_(khoa).toString();
              // Che bớt nếu là thẻ phiên đăng nhập dài để tránh lộ thông tin trên màn hình
              bangTieuDe[khoa] =
                /authorization|cookie|token/i.test(khoa) && giaTri.length > 14
                  ? giaTri.slice(0, 10) + "...[Đã ẩn bảo vệ]"
                  : giaTri;
            }
          }

          send({ kenh: tenMoTa, phuongThuc: method, url, tieuDeHTTP: bangTieuDe });
        } catch {}
      }
    });
  };

  theoDoiHam("dataTaskWithRequest", hamMang);
  theoDoiHam("dataTaskWithCompletion", hamMangCoCallback);
  console.log("[+] Đã bật bộ soi tiêu đề HTTP! Hãy sử dụng ứng dụng trên điện thoại.");
}
`,
  },
  {
    id: "builtin-owasp-ats-plist",
    title: "2.3 Kiểm toán bảo mật mạng ATS & Cấu hình Proxy",
    category: "2. Mạng & Truyền tin",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Kiểm tra xem ứng dụng có mở ngoại lệ cho phép kết nối http:// không mã hóa hay không và xem cấu hình Proxy.",
    code: `// ============================================================================
// MẪU 2.3: KIỂM TRA CHÍNH SÁCH BẢO MẬT TRUYỀN TẢI MẠNG (ATS) & PROXY HỆ THỐNG
// Giải thích: Apple mặc định bắt buộc mọi ứng dụng dùng chuẩn mã hóa HTTPS.
// Nếu ứng dụng bật 'NSAllowsArbitraryLoads = 1' nghĩa là đang cho phép cả HTTP thường.
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.warn("[-] Tiến trình hiện tại không dùng môi trường Objective-C.");
} else {
  const tuDienPlist = ObjC.classes.NSBundle.mainBundle().infoDictionary();
  const docKhoa = (tenKhoa) => {
    const giaTri = tuDienPlist ? tuDienPlist.objectForKey_(tenKhoa) : null;
    return giaTri ? giaTri.toString() : null;
  };

  // Kiểm tra cài đặt Proxy / VPN hiện hành trên hệ thống mạng của điện thoại
  let thongTinProxy = "Không đọc được";
  try {
    const fnCopyProxy = Module.findGlobalExportByName("CFNetworkCopySystemProxySettings");
    if (fnCopyProxy) {
      const goiHam = new NativeFunction(fnCopyProxy, "pointer", []);
      const conTro = goiHam();
      if (conTro && !conTro.isNull()) {
        thongTinProxy = new ObjC.Object(conTro).toString();
      }
    }
  } catch (err) {
    thongTinProxy = "Lỗi đọc Proxy: " + err.message;
  }

  console.log("[+] Đã hoàn tất kiểm tra cấu hình bảo mật mạng ATS & Proxy!");
  send({
    maUngDung: docKhoa("CFBundleIdentifier"),
    phienBan: docKhoa("CFBundleShortVersionString"),
    cauHinhBaoMatATS:
      docKhoa("NSAppTransportSecurity") || "Chuẩn an toàn cao nhất (Chặn mọi kết nối HTTP không mã hóa)",
    caiDatProxyHeThong: thongTinProxy
  });
}
`,
  },

  // ==========================================================================
  // BẢNG 3: LƯU TRỮ CỤC BỘ & TỆP DỮ LIỆU SANDBOX (3 MẪU — CHUẨN OWASP M6)
  // ==========================================================================
  {
    id: "builtin-userdefaults-audit",
    title: "3.1 Đọc bảng cài đặt lưu cục bộ (NSUserDefaults)",
    category: "3. Lưu trữ & Tệp tin",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Xem các tùy chọn cấu hình, cờ tính năng và mã ID mà ứng dụng đang lưu trong NSUserDefaults.",
    code: `// ============================================================================
// MẪU 3.1: KIỂM TRA DỮ LIỆU CẤU HÌNH LƯU TRONG NSUSERDEFAULTS
// Giải thích: NSUserDefaults là nơi ứng dụng iOS lưu các cài đặt gọn nhẹ (như ngôn ngữ,
// giao diện sáng/tối, cờ bật tính năng). Lọc bỏ các khóa mặc định của Apple để dễ nhìn.
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.warn("[-] Vui lòng bật cầu nối iOS (ObjC) để đọc NSUserDefaults.");
} else {
  const khoCaiDat = ObjC.classes.NSUserDefaults.standardUserDefaults().dictionaryRepresentation();
  const danhSachKhoa = khoCaiDat.allKeys();
  const tongSoKhoa = danhSachKhoa.count().valueOf();
  const ketQuaRiengCuaApp = {};

  for (let i = 0; i < tongSoKhoa; i++) {
    const tenKhoa = danhSachKhoa.objectAtIndex_(i).toString();
    // Bỏ qua các khóa hệ thống chung của Apple bắt đầu bằng NS, Apple, PK, AK, WebKit...
    if (/^(NS|Apple|WebKit|PK|AK|UIKit|com\.apple\.)/.test(tenKhoa)) continue;

    const giaTri = khoCaiDat.objectForKey_(tenKhoa);
    const chuoiGiaTri = giaTri ? giaTri.toString() : "";
    ketQuaRiengCuaApp[tenKhoa] =
      chuoiGiaTri.length > 160 ? chuoiGiaTri.slice(0, 160) + "...(rút gọn)" : chuoiGiaTri;
  }

  console.log(
    "[+] Tổng khóa hệ thống:",
    tongSoKhoa,
    "| Khóa riêng của ứng dụng:",
    Object.keys(ketQuaRiengCuaApp).length
  );
  send({
    soKhoaRieng: Object.keys(ketQuaRiengCuaApp).length,
    duLieuNSUserDefaults: ketQuaRiengCuaApp
  });
}
`,
  },
  {
    id: "builtin-file-protection-check",
    title: "3.2 Kiểm tra mức mã hóa bảo vệ tệp khi khóa máy",
    category: "3. Lưu trữ & Tệp tin",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Quét thư mục Documents và Library của ứng dụng để xem mức mã hóa bảo vệ tệp phần cứng.",
    code: `// ============================================================================
// MẪU 3.2: RÀ SOÁT CẤP ĐỘ BẢO VỆ TỆP TIN TRONG NGĂN DỮ LIỆU RIÊNG (SANDBOX)
// Giải thích: Trên iOS, tệp đạt mức 'NSFileProtectionComplete' sẽ tự động được mã hóa
// hoàn toàn ngay khi người dùng bấm nút nguồn khóa màn hình iPhone.
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.warn("[-] Cần bật cầu nối iOS (ObjC) để kiểm tra thư mục Sandbox.");
} else {
  const quanLyFile = ObjC.classes.NSFileManager.defaultManager();
  const fnHome = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
  const thuMucGoc = new ObjC.Object(fnHome()).toString();
  const thuMucCanQuet = [thuMucGoc + "/Documents", thuMucGoc + "/Library"];
  const danhSachBaoCao = [];

  for (const duongDanThuMuc of thuMucCanQuet) {
    const danhSachCon = quanLyFile.contentsOfDirectoryAtPath_error_(duongDanThuMuc, NULL);
    if (!danhSachCon || danhSachCon.isNull()) continue;

    const soFile = Math.min(danhSachCon.count().valueOf(), 25);
    for (let i = 0; i < soFile; i++) {
      const tenFile = danhSachCon.objectAtIndex_(i).toString();
      const duongDanDayDu = duongDanThuMuc + "/" + tenFile;
      const thuocTinh = quanLyFile.attributesOfItemAtPath_error_(duongDanDayDu, NULL);
      const mucBaoVe = thuocTinh ? thuocTinh.objectForKey_("NSFileProtectionKey") : null;

      danhSachBaoCao.push({
        tenTep: tenFile,
        thuMucCha: duongDanThuMuc.replace(thuMucGoc, "~"),
        mucMaHoaBaoVe: mucBaoVe ? mucBaoVe.toString() : "Chưa đặt mức bảo vệ riêng"
      });
    }
  }

  console.log("[+] Đã kiểm tra", danhSachBaoCao.length, "tệp/thư mục trong vùng dữ liệu ứng dụng.");
  send({ thuMucSandbox: thuMucGoc, danhSachTepKiemTra: danhSachBaoCao });
}
`,
  },
  {
    id: "builtin-sandbox-databases",
    title: "3.3 Tìm danh sách tệp cơ sở dữ liệu (.sqlite / .plist)",
    category: "3. Lưu trữ & Tệp tin",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Liệt kê nhanh các tệp cơ sở dữ liệu nội bộ (.sqlite, .db, .realm, .plist) trong ngăn lưu trữ riêng.",
    code: `// ============================================================================
// MẪU 3.3: LIỆT KÊ CÁC TỆP CƠ SỞ DỮ LIỆU & CẤU HÌNH TRONG THƯ MỤC ỨNG DỤNG
// Tác dụng: Giúp bạn biết ứng dụng đang lưu dữ liệu cục bộ bằng SQLite, Realm hay Plist
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.warn("[-] Cần bật cầu nối iOS (ObjC) để quét tệp dữ liệu.");
} else {
  const quanLyFile = ObjC.classes.NSFileManager.defaultManager();
  const fnHome = new NativeFunction(Module.getGlobalExportByName("NSHomeDirectory"), "pointer", []);
  const thuMucGoc = new ObjC.Object(fnHome()).toString();
  const boDuyet = quanLyFile.enumeratorAtPath_(thuMucGoc);
  const ketQua = [];

  let doiTuong = boDuyet ? boDuyet.nextObject() : null;
  while (doiTuong && !doiTuong.isNull() && ketQua.length < 50) {
    const duongDanTuongDoi = doiTuong.toString();
    if (/\\.(sqlite|sqlite3|db|realm|plist|json)$/i.test(duongDanTuongDoi)) {
      ketQua.push(duongDanTuongDoi);
    }
    doiTuong = boDuyet.nextObject();
  }

  console.log("[+] Tìm thấy", ketQua.length, "tệp dữ liệu/cấu hình trong ngăn lưu trữ của App.");
  send({ thuMucGocSandbox: thuMucGoc, danhSachTepDuLieu: ketQua });
}
`,
  },

  // ==========================================================================
  // BẢNG 4: GIAO DIỆN WEBVIEW, BỘ NHỚ TẠM & LIÊN KẾT MỞ NHANH (3 MẪU)
  // ==========================================================================
  {
    id: "builtin-wkwebview-monitor",
    title: "4.1 Giám sát trình duyệt nhúng bên trong App (WKWebView)",
    category: "4. Giao diện & Liên kết",
    runType: "listener",
    builtin: true,
    description: "[📡 Bật bắt sóng — Bấm xong hãy thao tác trên iPhone] Phát hiện khi ứng dụng mở khung web WKWebView và ghi lại đường dẫn trang web.",
    code: `// ============================================================================
// MẪU 4.1: THEO DÕI TRÌNH DUYỆT NHÚNG WKWEBVIEW BÊN TRONG ỨNG DỤNG
// Giải thích: Nhiều ứng dụng dùng khung web WKWebView để hiển thị trang tin tức,
// hướng dẫn hoặc biểu mẫu. Mẫu này báo ngay mỗi khi một trang web mới được tải.
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.warn("[-] Vui lòng bật cầu nối iOS (ObjC).");
} else if (!ObjC.classes.WKWebView) {
  console.log("[*] Ứng dụng này hiện chưa nạp thư viện trình duyệt WKWebView.");
} else {
  const WKWebView = ObjC.classes.WKWebView;
  const hamTaiTrang = WKWebView["- loadRequest:"];
  const hamTaiHTML = WKWebView["- loadHTMLString:baseURL:"];

  if (hamTaiTrang) {
    Interceptor.attach(hamTaiTrang.implementation, {
      onEnter(args) {
        try {
          const yeuCau = new ObjC.Object(args[2]);
          const url = yeuCau.URL() ? yeuCau.URL().absoluteString().toString() : "không rõ";
          send({ suKien: "WKWebView_loadRequest", trangWebDangMo: url });
        } catch {}
      }
    });
  }

  if (hamTaiHTML) {
    Interceptor.attach(hamTaiHTML.implementation, {
      onEnter(args) {
        try {
          const baseUrl = args[3] && !args[3].isNull() ? new ObjC.Object(args[3]).toString() : "nội bộ";
          send({ suKien: "WKWebView_loadHTML", nguonGoc: baseUrl });
        } catch {}
      }
    });
  }

  console.log("[+] Đang giám sát WKWebView! Hãy mở các mục có nội dung web trong ứng dụng.");
}
`,
  },
  {
    id: "builtin-url-scheme-deeplink",
    title: "4.2 Theo dõi liên kết mở nhanh (URL Scheme / Deep Link)",
    category: "4. Giao diện & Liên kết",
    runType: "listener",
    builtin: true,
    description: "[⚡ Đọc ngay + 📡 Bắt sóng] Đọc ngay danh sách URL Scheme trong Plist và chờ bắt các liên kết sâu truyền vào ứng dụng.",
    code: `// ============================================================================
// MẪU 4.2: GIÁM SÁT KHI ỨNG DỤNG NHẬN LIÊN KẾT MỞ NHANH (DEEP LINK / URL SCHEME)
// Giải thích: Khi bạn bấm một liên kết dạng 'tenapp://trang-chu?id=1' từ Safari,
// hệ điều hành sẽ truyền đường dẫn đó vào AppDelegate hoặc SceneDelegate của ứng dụng.
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.warn("[-] Vui lòng bật cầu nối iOS (ObjC).");
} else {
  const UIApplication = ObjC.classes.UIApplication;
  const hamMoURL = UIApplication["- openURL:options:completionHandler:"];

  if (hamMoURL) {
    Interceptor.attach(hamMoURL.implementation, {
      onEnter(args) {
        try {
          const doiTuongURL = new ObjC.Object(args[2]);
          send({
            suKien: "ung_dung_goi_mo_lien_ket_ngoai",
            duongDan: doiTuongURL.absoluteString().toString()
          });
        } catch {}
      }
    });
  }

  // Đồng thời đọc danh sách URL Schemes mà ứng dụng đã đăng ký sẵn trong Info.plist
  const plist = ObjC.classes.NSBundle.mainBundle().infoDictionary();
  const dangKyURL = plist ? plist.objectForKey_("CFBundleURLTypes") : null;
  console.log("[+] Đã bật theo dõi liên kết mở nhanh!");
  send({
    cacLienKetDaDangKyTrongPlist: dangKyURL ? dangKyURL.toString() : "Ứng dụng không đăng ký URL Scheme"
  });
}
`,
  },
  {
    id: "builtin-pasteboard-monitor",
    title: "4.3 Kiểm tra khi nào App tự đọc Bộ nhớ tạm (Clipboard)",
    category: "4. Giao diện & Liên kết",
    runType: "listener",
    builtin: true,
    description: "[📡 Bật bắt sóng — Bấm xong hãy thao tác trên iPhone] Báo ngay khi ứng dụng âm thầm đọc hoặc sao chép văn bản trong Clipboard.",
    code: `// ============================================================================
// MẪU 4.3: KIỂM TRA QUYỀN RIÊNG TƯ — PHÁT HIỆN ỨNG DỤNG ĐỌC BỘ NHỚ TẠM (CLIPBOARD)
// Tác dụng: Báo ngay trên bảng Nhật ký mỗi khi ứng dụng đọc hoặc ghi vào bộ nhớ Copy/Paste
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.warn("[-] Vui lòng bật cầu nối iOS (ObjC).");
} else if (ObjC.classes.UIPasteboard) {
  const UIPasteboard = ObjC.classes.UIPasteboard;
  const hamDocChu = UIPasteboard["- string"];
  const hamGhiChu = UIPasteboard["- setString:"];

  if (hamDocChu) {
    Interceptor.attach(hamDocChu.implementation, {
      onLeave(ketQua) {
        const doDai = ketQua && !ketQua.isNull() ? new ObjC.Object(ketQua).length().valueOf() : 0;
        send({ canhBaoRiengTu: "Ứng dụng vừa ĐỌC bộ nhớ tạm (Pasteboard)!", soKyTuDaDoc: doDai });
      }
    });
  }

  if (hamGhiChu) {
    Interceptor.attach(hamGhiChu.implementation, {
      onEnter(args) {
        const doDai = args[2] && !args[2].isNull() ? new ObjC.Object(args[2]).length().valueOf() : 0;
        send({ suKien: "Ứng dụng vừa SAO CHÉP văn bản mới vào bộ nhớ tạm", soKyTu: doDai });
      }
    });
  }

  console.log("[+] Đang giám sát bộ nhớ tạm Copy/Paste (UIPasteboard)!");
}
`,
  },

  // ==========================================================================
  // BẢNG 5: KHẢO SÁT NHỊ PHÂN MACH-O & TIỆN ÍCH TWEAK (2 MẪU)
  // ==========================================================================
  {
    id: "builtin-macho-modules",
    title: "5.1 Liệt kê thư viện riêng (.dylib) & Tweak bẻ khóa",
    category: "5. Nhị phân & Tiện ích",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Liệt kê ngay các thư viện thuộc gói ứng dụng và tiện ích Tweak (/var/jb) đang gắn vào tiến trình.",
    code: `// ============================================================================
// MẪU 5.1: LIỆT KÊ THƯ VIỆN RIÊNG CỦA ỨNG DỤNG & CÁC TIỆN ÍCH TWEAK (/var/jb)
// Giải thích: Giúp bạn kiểm tra xem có những Tweak nào đang can thiệp vào App này
// ============================================================================

const tatCaThuVien = Process.enumerateModules();

// Lọc riêng thư viện nằm trong gói .app hoặc thư mục Jailbreak Rootless (/var/jb/)
const thuVienQuanTam = tatCaThuVien.filter(
  (m) => m.path.includes(".app/") || m.path.includes("/var/jb/") || m.path.includes("MobileSubstrate")
);

console.log(
  "[+] Tổng thư viện hệ thống + App:",
  tatCaThuVien.length,
  "| Thư viện riêng & Tweak:",
  thuVienQuanTam.length
);

send(
  thuVienQuanTam.slice(0, 50).map((m) => ({
    loai: m.path.includes("/var/jb/") ? "Tiện ích Jailbreak (Tweak)" : "Thư viện của App",
    tenTep: m.name,
    diaChiRAM: m.base.toString(),
    dungLuong_KB: Math.round(m.size / 1024),
    duongDan: m.path
  }))
);
`,
  },
  {
    id: "builtin-macho-security-flags",
    title: "5.2 Kiểm tra cờ bảo vệ tệp thực thi Mach-O (PIE / CryptID)",
    category: "5. Nhị phân & Tiện ích",
    runType: "instant",
    builtin: true,
    description: "[⚡ Bấm là ra kết quả ngay] Đọc phần đầu tệp nhị phân trong RAM để kiểm tra ngẫu nhiên hóa địa chỉ (PIE) và mã hóa FairPlay.",
    code: `// ============================================================================
// MẪU 5.2: PHÂN TÍCH PHẦN ĐẦU TỆP NHỊ PHÂN MACH-O CHÍNH TRONG BỘ NHỚ RAM
// Giải thích:
//   - Cờ PIE (MH_PIE): Đổi ngẫu nhiên địa chỉ bộ nhớ mỗi lần chạy giúp chống khai thác.
//   - CryptID = 1: Tệp nhị phân trên đĩa được mã hóa FairPlay từ App Store; = 0: Đã giải mã.
// ============================================================================

const tepChinh = Process.enumerateModules()[0];
const conTroDau = tepChinh.base;
const maNhanDien = conTroDau.readU32(); // 0xfeedfacf = Mach-O 64-bit chuẩn arm64

if (maNhanDien !== 0xfeedfacf) {
  console.warn("[-] Tiến trình không phải định dạng Mach-O 64-bit (Mã đọc được: 0x" + maNhanDien.toString(16) + ").");
  send({ tenTienTrinh: tepChinh.name, dinhDang: "Không phải Mach-O 64-bit (Ví dụ: tệp .exe trên Windows)" });
} else {
  const soLenhNap = conTroDau.add(16).readU32();
  const coBaoVe = conTroDau.add(24).readU32();
  const batPIE = (coBaoVe & 0x200000) !== 0;

  // Duyệt các lệnh nạp (Load Commands) để tìm thông tin mã hóa LC_ENCRYPTION_INFO_64 (0x2c)
  let trangThaiCryptId = null;
  let viTriLenh = conTroDau.add(32);
  for (let i = 0; i < soLenhNap; i++) {
    const loaiLenh = viTriLenh.readU32();
    const kichThuocLenh = viTriLenh.add(4).readU32();
    if (loaiLenh === 0x2c) {
      trangThaiCryptId = viTriLenh.add(16).readU32();
      break;
    }
    viTriLenh = viTriLenh.add(kichThuocLenh);
  }

  console.log("[+] Đã đọc cấu trúc nhị phân Mach-O 64-bit của:", tepChinh.name);
  send({
    tenTepThucThi: tepChinh.name,
    diaChiNapRAM: tepChinh.base.toString(),
    batNgauNhienHoaDiaChi_PIE: batPIE ? "Có bật (An toàn)" : "Không bật",
    maHoaFairPlay_CryptID:
      trangThaiCryptId === null
        ? "Không có trường mã hóa (Tự biên dịch / Hệ thống)"
        : trangThaiCryptId === 1
        ? "1 (Có mã hóa FairPlay gốc)"
        : "0 (Không khóa mã hóa / Đã giải mã)"
  });
}
`,
  },

  // ==========================================================================
  // BẢNG 6: ĐIỀU KHIỂN TỪ XA 2 CHIỀU & KHUÔN MẪU TỰ THEO DÕI HÀM (2 MẪU)
  // ==========================================================================
  {
    id: "builtin-rpc-demo",
    title: "6.1 Bộ hàm điều khiển 2 chiều (Dùng với Thẻ Gọi hàm từ xa)",
    category: "6. Điều khiển từ xa",
    runType: "listener",
    builtin: true,
    description: "[📡 Mở hàm chờ gọi] Đăng ký hàm 'ping' và 'timLopObjC' để bạn chuyển sang thẻ 'Gọi hàm từ xa' bấm gọi trực tiếp.",
    code: `// ============================================================================
// MẪU 6.1: MỞ CÁC HÀM ĐIỀU KHIỂN TỪ XA (DÙNG KÈM THẺ SỐ 6 Ở KHUNG GIỮA)
// Hướng dẫn sử dụng cực dễ:
//   Bước 1: Bấm nút xanh "Gửi mã JS" để nạp đoạn mã này vào điện thoại.
//   Bước 2: Chuyển sang thẻ "6. Gọi hàm điều khiển từ xa" trên thanh công cụ giữa.
//   Bước 3: Gõ tên hàm 'ping' (hoặc 'timLopObjC') rồi bấm "Gọi hàm ngay"!
// ============================================================================

Object.assign(rpc.exports, {
  // Hàm 1: Kiểm tra phản hồi tức thì từ điện thoại về máy tính
  ping(tenNguoiDung = "Antidv") {
    return {
      loiChao: "Xin chào " + tenNguoiDung + "! Điện thoại trả lời từ mã tiến trình " + Process.id,
      phienBanFrida: Frida.version,
      gioTrenThietBi: new Date().toLocaleString("vi-VN")
    };
  },

  // Hàm 2: Tìm nhanh tên các lớp giao diện/chức năng theo từ khóa bất kỳ
  timLopObjC(tuKhoa = "UIView") {
    if (typeof ObjC === "undefined" || !ObjC.available) {
      return ["Tiến trình này không có môi trường iOS ObjC"];
    }
    const tuKhoaThuong = String(tuKhoa).toLowerCase();
    return Object.keys(ObjC.classes)
      .filter((tenLop) => tenLop.toLowerCase().includes(tuKhoaThuong))
      .slice(0, 30);
  }
});

console.log("[+] Đã đăng ký xong hàm 'ping' và 'timLopObjC'! Hãy mở thẻ số 6 để bấm gọi thử.");
`,
  },
  {
    id: "builtin-safe-objc-tracer-template",
    title: "6.2 Khuôn mẫu tự theo dõi bất kỳ hàm iOS nào an toàn",
    category: "6. Điều khiển từ xa",
    runType: "listener",
    builtin: true,
    description: "[📡 Bật bắt sóng — Bấm xong hãy thao tác trên iPhone] Khung mẫu chuẩn chỉ cần điền tên Lớp và tên Hàm iOS muốn quan sát.",
    code: `// ============================================================================
// MẪU 6.2: KHUÔN MẪU CHUẨN ĐỂ TỰ QUAN SÁT MỘT HÀM OBJECTIVE-C BẤT KỲ
// Cách dùng: Bạn chỉ cần đổi 2 dòng TEN_LOP và TEN_HAM bên dưới theo ý muốn,
//            sau đó bấm "Gửi mã JS" rồi chạm thao tác trên điện thoại!
// ============================================================================

const TEN_LOP = "UIViewController";          // <-- Đổi tên Lớp tại đây
const TEN_HAM = "- viewDidAppear:";          // <-- Đổi tên Hàm tại đây (giữ dấu - hoặc +)

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.error("[-] Cần bật cầu nối iOS (ObjC) để sử dụng mẫu này.");
} else {
  const lopMucTieu = ObjC.classes[TEN_LOP];
  if (!lopMucTieu) {
    console.warn("[-] Không tìm thấy lớp:", TEN_LOP);
  } else {
    const doiTuongHam = lopMucTieu[TEN_HAM];
    if (!doiTuongHam) {
      console.warn("[-] Lớp", TEN_LOP, "không có hàm:", TEN_HAM);
    } else {
      // Gắn bộ quan sát an toàn có bọc try/catch chống văng ứng dụng
      Interceptor.attach(doiTuongHam.implementation, {
        onEnter(args) {
          try {
            const doiTuongGoi = new ObjC.Object(args[0]);
            send({
              suKien: "bat_dau_goi_ham",
              lopThucTe: doiTuongGoi.$className,
              tenHam: TEN_HAM
            });
          } catch (err) {
            console.warn("Lỗi đọc tham số đầu vào:", err.message);
          }
        },
        onLeave(giaTriTraVe) {
          console.log("[<=] Kết thúc hàm", TEN_LOP, TEN_HAM, "| Giá trị trả về:", giaTriTraVe);
        }
      });

      console.log("[+] Đang theo dõi an toàn:", TEN_LOP, TEN_HAM, "— Hãy thao tác trên iPhone!");
    }
  }
}
`,
  },

  // ==========================================================================
  // BẢNG 7: STOREKIT & SANDBOX TESTFLIGHT (5 MẪU CHẨN ĐOÁN CHỈ ĐỌC AN TOÀN)
  // ==========================================================================
  {
    id: "builtin-storekit-sandbox-env",
    title: "7.1 Kiểm tra Môi trường Sandbox / TestFlight & Quyền Mua Hàng",
    category: "7. StoreKit & Sandbox TestFlight",
    runType: "instant",
    builtin: true,
    description:
      "[⚡ Bấm là ra kết quả ngay] Xác định ứng dụng đang dùng biên lai Sandbox/TestFlight hay App Store, vùng quốc gia và mã Bundle ID (bấm Lưu ID được ngay).",
    code: `// ============================================================================
// MẪU 7.1: KIỂM TRA MÔI TRƯỜNG SANDBOX / TESTFLIGHT & QUYỀN MUA HÀNG (CHỈ ĐỌC)
// An toàn: Chỉ đọc trạng thái cấu hình StoreKit thực tế, tuyệt đối không sửa biên lai.
// Cách dùng: Mở ứng dụng cần kiểm tra trên iPhone -> Bấm "Gửi mã JS"
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.error("[-] Vui lòng chọn ứng dụng trên iPhone và bật Cầu nối iOS.");
} else {
  const goiChinh = ObjC.classes.NSBundle.mainBundle();
  const quanLyTep = ObjC.classes.NSFileManager.defaultManager();
  const SKPaymentQueue = ObjC.classes.SKPaymentQueue;

  // 1. Đọc đường dẫn tệp biên lai (appStoreReceiptURL) để phân biệt TestFlight/Sandbox với App Store
  const urlBienLai = goiChinh.appStoreReceiptURL();
  const duongDanBienLai = urlBienLai ? urlBienLai.path().toString() : "";
  const laBanSandboxTestFlight = duongDanBienLai.endsWith("sandboxReceipt");
  const daCoTepBienLai = duongDanBienLai
    ? Boolean(quanLyTep.fileExistsAtPath_(duongDanBienLai))
    : false;

  let kichThuocBienLaiByte = 0;
  if (daCoTepBienLai) {
    const thuocTinh = quanLyTep.attributesOfItemAtPath_error_(duongDanBienLai, NULL);
    if (thuocTinh && !thuocTinh.isNull()) {
      kichThuocBienLaiByte = Number(thuocTinh.fileSize());
    }
  }

  // 2. Kiểm tra máy có đang bị khóa tính năng Mua trong ứng dụng (Screen Time) không
  const choPhepThanhToan = SKPaymentQueue ? Boolean(SKPaymentQueue.canMakePayments()) : false;

  // 3. Kiểm tra vùng cửa hàng (Storefront) và các giao dịch đang kẹt chưa đóng (finishTransaction)
  let maQuocGiaCuaHang = "Không xác định";
  let soGiaoDichTonDong = 0;
  if (SKPaymentQueue) {
    const hangDoi = SKPaymentQueue.defaultQueue();
    if (hangDoi.respondsToSelector_(ObjC.selector("storefront")) && hangDoi.storefront()) {
      maQuocGiaCuaHang = hangDoi.storefront().countryCode().toString();
    }
    if (hangDoi.transactions()) {
      soGiaoDichTonDong = Number(hangDoi.transactions().count());
    }
  }

  send({
    nhomKiemTra: "moi_truong_storekit_sandbox",
    maUngDung: goiChinh.bundleIdentifier() ? goiChinh.bundleIdentifier().toString() : "N/A",
    moiTruongBienLai: laBanSandboxTestFlight
      ? "SANDBOX / TESTFLIGHT (sandboxReceipt)"
      : "APP STORE CHÍNH THỨC (receipt)",
    duongDanBienLai,
    daCoTepBienLaiTrenMay: daCoTepBienLai,
    kichThuocBienLaiByte,
    choPhepMuaTrongUngDung: choPhepThanhToan,
    quocGiaStorefront: maQuocGiaCuaHang,
    soGiaoDichChuaKetThucTrongHangDoi: soGiaoDichTonDong,
    giaiThichNhanh: !daCoTepBienLai
      ? "Lưu ý bình thường trên TestFlight/Sandbox mới cài: Tệp sandboxReceipt chỉ xuất hiện sau khi đăng nhập tài khoản Sandbox hoặc làm mới biên lai."
      : soGiaoDichTonDong > 0
        ? "Phát hiện giao dịch cũ còn kẹt trong hàng đợi (ứng dụng chưa gọi finishTransaction:)."
        : "Cấu hình môi trường StoreKit sẵn sàng để kiểm thử."
  });
}
`,
  },
  {
    id: "builtin-storekit-products-inspector",
    title: "7.2 Soi Danh mục Gói Mua Hàng & Lỗi Sai Mã Sản Phẩm (SKProductsRequest)",
    category: "7. StoreKit & Sandbox TestFlight",
    runType: "listener",
    builtin: true,
    description:
      "[📡 Bật bắt sóng — Bấm xong hãy mở mục Mua gói trên iPhone] Tự bắt cả mã gói Product ID, bảng giá Apple trả về VÀ mọi gói tin API/Hộp trả lời!",
    code: `// ============================================================================
// MẪU 7.2: SOI DANH MỤC GÓI MUA HÀNG & PHÁT HIỆN MÃ SẢN PHẨM LỖI TRÊN SANDBOX
// Cách dùng 2 bước:
//   Bước 1: Chọn đúng App Game / App TestFlight có tính năng Mua gói ở ô Bước 2 -> Bấm Chạy.
//   Bước 2: Cầm iPhone chạm mở màn hình "Cửa hàng / Nâng cấp VIP" trong App đó!
//           -> Mã gói Product ID sẽ hiện ở bên phải (bấm Lưu ID được ngay), đồng thời
//              mọi gói tin mạng kèm Hộp trả lời cũng tự hiện ở Thẻ số 1!
// ============================================================================

if (typeof globalThis.__studioEnableHttpCapture === "function") {
  globalThis.__studioEnableHttpCapture();
}

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.error("[-] Vui lòng bật Cầu nối iOS và chọn ứng dụng trên iPhone.");
} else {
  const maAppHienTai = ObjC.classes.NSBundle.mainBundle().bundleIdentifier()?.toString() || "";
  if (maAppHienTai.startsWith("com.apple.") && maAppHienTai !== "com.apple.AppStore") {
    console.warn(
      "[!] LƯU Ý QUAN TRỌNG: Bạn đang chọn ứng dụng hệ thống '" +
        maAppHienTai +
        "' (như Cài đặt) nên sẽ KHÔNG có cửa hàng mua gói In-App! Hãy chọn đúng ứng dụng/game cần kiểm thử ở ô Bước 2 phía trên."
    );
  }
  const SKProductsRequest = ObjC.classes.SKProductsRequest;
  if (!SKProductsRequest) {
    console.warn("[-] Tiến trình hiện tại chưa nạp khung StoreKit.");
  } else {
    const cacLopDaGan = new Set();

    // Hàm phụ chuyển NSSet / NSArray sang mảng chuỗi JavaScript dễ đọc
    function chuyenTapHopSangMang(tapHopObjC) {
      if (!tapHopObjC || tapHopObjC.isNull()) return [];
      const mang = tapHopObjC.respondsToSelector_(ObjC.selector("allObjects"))
        ? tapHopObjC.allObjects()
        : tapHopObjC;
      const ketQua = [];
      const soLuong = Number(mang.count());
      for (let i = 0; i < soLuong; i++) {
        ketQua.push(mang.objectAtIndex_(i).toString());
      }
      return ketQua;
    }

    // 1. Quan sát chỉ đọc danh sách mã gói ứng dụng gửi lên Apple
    const hamKhoiTao = SKProductsRequest["- initWithProductIdentifiers:"];
    if (hamKhoiTao) {
      Interceptor.attach(hamKhoiTao.implementation, {
        onEnter(args) {
          const danhSachMaHoi = chuyenTapHopSangMang(new ObjC.Object(args[2]));
          send({
            suKien: "hoi_danh_sach_goi_san_pham",
            soLuongMa: danhSachMaHoi.length,
            danhSachProductId: danhSachMaHoi
          });
        }
      });
    }

    // 2. Quan sát chỉ đọc phản hồi từ Apple Sandbox trả về cho Delegate
    const hamGanDelegate = SKProductsRequest["- setDelegate:"];
    if (hamGanDelegate) {
      Interceptor.attach(hamGanDelegate.implementation, {
        onEnter(args) {
          if (args[2].isNull()) return;
          const doiTuongNhan = new ObjC.Object(args[2]);
          const tenLopNhan = doiTuongNhan.$className;
          if (cacLopDaGan.has(tenLopNhan)) return;
          cacLopDaGan.add(tenLopNhan);

          const lopNhan = ObjC.classes[tenLopNhan];
          const hamNhanPhanHoi = lopNhan && lopNhan["- productsRequest:didReceiveResponse:"];
          if (hamNhanPhanHoi) {
            Interceptor.attach(hamNhanPhanHoi.implementation, {
              onEnter(cbArgs) {
                const phanHoi = new ObjC.Object(cbArgs[3]);
                const mangHopLe = phanHoi.products();
                const goiHopLe = [];
                const demHopLe = mangHopLe ? Number(mangHopLe.count()) : 0;

                for (let i = 0; i < demHopLe; i++) {
                  const sp = mangHopLe.objectAtIndex_(i);
                  const vungGia = sp.priceLocale();
                  const tienTe = vungGia ? vungGia.objectForKey_("kCFLocaleCurrencyCodeKey") : null;
                  goiHopLe.push({
                    maGoi: sp.productIdentifier().toString(),
                    tenHienThi: sp.localizedTitle() ? sp.localizedTitle().toString() : "",
                    giaSo: sp.price() ? sp.price().toString() : "0",
                    donViTien: tienTe ? tienTe.toString() : ""
                  });
                }

                const maBiTuChoi = chuyenTapHopSangMang(phanHoi.invalidProductIdentifiers());
                send({
                  suKien: "ket_qua_danh_muc_apple_sandbox",
                  lopXuLy: tenLopNhan,
                  soGoiHopLe: goiHopLe.length,
                  chiTietGoiHopLe: goiHopLe,
                  maSanPhamKhongHopLe: maBiTuChoi,
                  goiYNeuLoi:
                    maBiTuChoi.length > 0
                      ? "Các mã trong maSanPhamKhongHopLe bị Apple từ chối (kiểm tra lại mã trên App Store Connect hoặc mục Thỏa thuận Paid Apps)."
                      : "Tất cả mã gói đều hợp lệ trên Apple Sandbox!"
                });
              }
            });
          }

          const hamBaoLoi = lopNhan && lopNhan["- request:didFailWithError:"];
          if (hamBaoLoi) {
            Interceptor.attach(hamBaoLoi.implementation, {
              onEnter(errArgs) {
                const loi = new ObjC.Object(errArgs[3]);
                send({
                  suKien: "loi_tai_danh_muc_storekit",
                  maLoi: Number(loi.code()),
                  mienLoi: loi.domain().toString(),
                  moTaTiengViet: loi.localizedDescription().toString()
                });
              }
            });
          }
        }
      });
    }

    console.log("[+] Đã bật soi chỉ đọc SKProductsRequest! Hãy mở màn hình Mua gói trên ứng dụng.");
  }
}
`,
  },
  {
    id: "builtin-storekit-queue-observer",
    title: "7.3 Nhật ký Giao dịch Hàng đợi Mua Hàng Sandbox (Chỉ đọc — SKPaymentQueue)",
    category: "7. StoreKit & Sandbox TestFlight",
    runType: "listener",
    builtin: true,
    description:
      "[📡 Bật bắt sóng — Bấm xong hãy bấm Mua/Khôi phục trên iPhone] Theo dõi giao dịch Sandbox, mã giao dịch Apple VÀ bắt kèm Gói tin + Hộp trả lời API!",
    code: `// ============================================================================
// MẪU 7.3: THEO DÕI VÒNG ĐỜI GIAO DỊCH HÀNG ĐỢI STOREKIT SANDBOX (CHỈ ĐỌC)
// An toàn: Chỉ ghi nhận sự kiện và mã lỗi trả về từ Apple (onEnter),
//          tuyệt đối KHÔNG can thiệp hay làm giả kết quả giao dịch!
// Cách dùng: Chọn đúng App TestFlight ở Bước 2 -> Bấm Chạy -> Bấm nút Mua/Khôi phục trên iPhone.
// ============================================================================

if (typeof globalThis.__studioEnableHttpCapture === "function") {
  globalThis.__studioEnableHttpCapture();
}

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.error("[-] Vui lòng bật Cầu nối iOS và chọn ứng dụng trên iPhone.");
} else {
  const maAppHienTai = ObjC.classes.NSBundle.mainBundle().bundleIdentifier()?.toString() || "";
  if (maAppHienTai.startsWith("com.apple.") && maAppHienTai !== "com.apple.AppStore") {
    console.warn(
      "[!] LƯU Ý: Bạn đang gắn vào ứng dụng hệ thống '" +
        maAppHienTai +
        "'. Hãy chọn ứng dụng TestFlight / App có mua gói ở ô Bước 2 phía trên rồi thử bấm Mua trên iPhone!"
    );
  }
  const SKPaymentQueue = ObjC.classes.SKPaymentQueue;
  if (!SKPaymentQueue) {
    console.warn("[-] Tiến trình hiện tại chưa nạp khung StoreKit.");
  } else {
    const TEN_TRANG_THAI = {
      0: "0 - Đang gửi yêu cầu lên Apple Sandbox (Purchasing)",
      1: "1 - Giao dịch Sandbox hợp lệ (Purchased)",
      2: "2 - Giao dịch thất bại hoặc người dùng hủy (Failed)",
      3: "3 - Đã khôi phục gói mua trước đó (Restored)",
      4: "4 - Đang chờ phê duyệt gia đình (Deferred / Ask-to-Buy)"
    };

    const cacObserverDaGan = new Set();

    // Hàm đọc thông tin một đối tượng SKPaymentTransaction an toàn (chỉ đọc)
    function tomTatGiaoDich(gd) {
      const thanhToan = gd.payment();
      const loi = gd.error();
      const maTrangThai = Number(gd.transactionState());
      return {
        maSanPham: thanhToan && thanhToan.productIdentifier()
          ? thanhToan.productIdentifier().toString()
          : "N/A",
        soLuong: thanhToan ? Number(thanhToan.quantity()) : 1,
        trangThai: TEN_TRANG_THAI[maTrangThai] || String(maTrangThai),
        maGiaoDichApple: gd.transactionIdentifier()
          ? gd.transactionIdentifier().toString()
          : "(Chưa cấp mã)",
        chiTietLoiSandbox:
          loi && !loi.isNull()
            ? "[" + loi.domain().toString() + " #" + Number(loi.code()) + "] " + loi.localizedDescription().toString()
            : null
      };
    }

    // 1. Khi ứng dụng đẩy lệnh mua mới vào hàng đợi (addPayment:)
    if (SKPaymentQueue["- addPayment:"]) {
      Interceptor.attach(SKPaymentQueue["- addPayment:"].implementation, {
        onEnter(args) {
          const p = new ObjC.Object(args[2]);
          send({
            suKien: "ung_dung_gui_yeu_cau_mua_sandbox",
            maSanPham: p.productIdentifier() ? p.productIdentifier().toString() : "N/A",
            soLuong: Number(p.quantity()),
            moPhongHoiMuaGiaDinh: p.respondsToSelector_(ObjC.selector("simulatesAskToBuyInSandbox"))
              ? Boolean(p.simulatesAskToBuyInSandbox())
              : false
          });
        }
      });
    }

    // 2. Khi ứng dụng yêu cầu Khôi phục gói đã mua (Restore Purchases)
    if (SKPaymentQueue["- restoreCompletedTransactions"]) {
      Interceptor.attach(SKPaymentQueue["- restoreCompletedTransactions"].implementation, {
        onEnter() {
          console.log("[StoreKit] Ứng dụng vừa gọi khôi phục giao dịch (restoreCompletedTransactions).");
        }
      });
    }

    // 3. Khi ứng dụng xác nhận hoàn tất và đóng giao dịch khỏi hàng đợi (finishTransaction:)
    if (SKPaymentQueue["- finishTransaction:"]) {
      Interceptor.attach(SKPaymentQueue["- finishTransaction:"].implementation, {
        onEnter(args) {
          const gd = new ObjC.Object(args[2]);
          send({
            suKien: "ung_dung_dong_giao_dich_finishTransaction",
            ...tomTatGiaoDich(gd)
          });
        }
      });
    }

    // 4. Gắn bộ nghe chỉ đọc vào lớp Observer nhận thông báo cập nhật trạng thái từ Apple
    function ganQuanSatChoLopObserver(tenLop) {
      if (!tenLop || cacObserverDaGan.has(tenLop)) return;
      const lop = ObjC.classes[tenLop];
      const hamCapNhat = lop && lop["- paymentQueue:updatedTransactions:"];
      if (!hamCapNhat) return;
      cacObserverDaGan.add(tenLop);

      Interceptor.attach(hamCapNhat.implementation, {
        onEnter(args) {
          const mangGd = new ObjC.Object(args[3]);
          const dem = Number(mangGd.count());
          const danhSach = [];
          for (let i = 0; i < dem; i++) {
            danhSach.push(tomTatGiaoDich(mangGd.objectAtIndex_(i)));
          }
          send({
            suKien: "apple_cap_nhat_trang_thai_giao_dich",
            lopNhanSuKien: tenLop,
            danhSachGiaoDich: danhSach
          });
        }
      });
      console.log("[+] Đã gắn quan sát chỉ đọc vào Observer:", tenLop);
    }

    // Quét cả các Observer đã đăng ký trước khi gắn Frida (nếu có) và các Observer đăng ký mới
    if (SKPaymentQueue["- addTransactionObserver:"]) {
      Interceptor.attach(SKPaymentQueue["- addTransactionObserver:"].implementation, {
        onEnter(args) {
          if (!args[2].isNull()) {
            ganQuanSatChoLopObserver(new ObjC.Object(args[2]).$className);
          }
        }
      });
    }

    const hangDoiHienTai = SKPaymentQueue.defaultQueue();
    if (
      hangDoiHienTai &&
      hangDoiHienTai.respondsToSelector_(ObjC.selector("transactionObservers")) &&
      hangDoiHienTai.transactionObservers()
    ) {
      const obsArr = hangDoiHienTai.transactionObservers();
      for (let i = 0; i < Number(obsArr.count()); i++) {
        ganQuanSatChoLopObserver(obsArr.objectAtIndex_(i).$className);
      }
    }

    console.log("[+] Đang theo dõi chỉ đọc hàng đợi SKPaymentQueue trên Sandbox/TestFlight!");
  }
}
`,
  },
  {
    id: "builtin-storekit2-inspector",
    title: "7.4 Kiểm tra Khung StoreKit 2 (Swift) & Cửa sổ Mua hàng Hệ thống",
    category: "7. StoreKit & Sandbox TestFlight",
    runType: "instant",
    builtin: true,
    description:
      "[⚡ Bấm là ra kết quả ngay] Phát hiện ngay ứng dụng dùng StoreKit 1 hay StoreKit 2 (Swift JWS hiện đại).",
    code: `// ============================================================================
// MẪU 7.4: NHẬN DIỆN KIẾN TRÚC STOREKIT 1 / STOREKIT 2 (SWIFT) & CỬA SỔ HỆ THỐNG
// Tác dụng: Nhiều ứng dụng đời mới trên TestFlight dùng StoreKit 2 (Swift async/await)
//           thay cho SKPaymentQueue cũ. Mẫu này giúp bạn nhận diện chính xác!
// ============================================================================

const thuVienStoreKit = Process.enumerateModules().filter((m) =>
  /storekit/i.test(m.name)
);

let soKyHieuStoreKit2Swift = 0;
const mauKyHieuSwift = [];

for (const mod of thuVienStoreKit) {
  try {
    const danhSachXuat = mod.enumerateExports();
    for (const ex of danhSachXuat) {
      // Các hàm Swift của StoreKit 2 bắt đầu bằng tiền tố mangling "$s8StoreKit"
      if (ex.name.startsWith("$s8StoreKit")) {
        soKyHieuStoreKit2Swift += 1;
        if (mauKyHieuSwift.length < 12) {
          mauKyHieuSwift.push(ex.name);
        }
      }
    }
  } catch {
    // Bỏ qua nếu thư viện hệ thống giới hạn đọc bảng xuất
  }
}

send({
  nhomKiemTra: "kien_truc_storekit_1_va_2",
  cacThuVienStoreKitDaNap: thuVienStoreKit.map((m) => ({
    tenThuVien: m.name,
    duongDan: m.path
  })),
  coSuDungStoreKit2Swift: soKyHieuStoreKit2Swift > 0,
  tongSoHamSwiftStoreKit2: soKyHieuStoreKit2Swift,
  mauKyHieuStoreKit2DauTien: mauKyHieuSwift
});

// Quan sát thêm hộp thoại giới thiệu ứng dụng / gói tích hợp (SKStoreProductViewController)
if (typeof ObjC !== "undefined" && ObjC.available) {
  const SKStoreProductVC = ObjC.classes.SKStoreProductViewController;
  const hamTaiTrang =
    SKStoreProductVC && SKStoreProductVC["- loadProductWithParameters:completionBlock:"];
  if (hamTaiTrang) {
    Interceptor.attach(hamTaiTrang.implementation, {
      onEnter(args) {
        const thamSo = new ObjC.Object(args[2]);
        send({
          suKien: "mo_cua_so_san_pham_he_thong",
          thamSoTruyenVao: thamSo.toString()
        });
      }
    });
    console.log("[+] Đã bật theo dõi hộp thoại SKStoreProductViewController.");
  }
}
`,
  },
  {
    id: "builtin-storekit-owasp-audit",
    title: "7.5 Kiểm toán Bảo mật Lưu trữ Quyền Mua Hàng (Chuẩn OWASP MASTG)",
    category: "7. StoreKit & Sandbox TestFlight",
    runType: "instant",
    builtin: true,
    description:
      "[⚡ Bấm là ra kết quả ngay] Rà soát phòng thủ chỉ đọc: Phát hiện lỗi lưu trạng thái gói trả phí dạng chữ thô trong NSUserDefaults.",
    code: `// ============================================================================
// MẪU 7.5: KIỂM TOÁN BẢO MẬT LƯU TRỮ QUYỀN MUA HÀNG (CHUẨN OWASP MASTG — CHỈ ĐỌC)
// Tác dụng: Giúp lập trình viên kiểm tra xem ứng dụng TestFlight của mình có vô tình
//           lưu cờ mở khóa gói (như isPro, vip, subscribed) dạng chữ thô không mã hóa
//           trong NSUserDefaults hay không (không trích xuất khóa bí mật).
// ============================================================================

if (typeof ObjC === "undefined" || !ObjC.available) {
  console.error("[-] Cần bật Cầu nối iOS để chạy bài kiểm toán OWASP MASTG này.");
} else {
  const boLuuMacDinh = ObjC.classes.NSUserDefaults.standardUserDefaults();
  const bangTuDien = boLuuMacDinh.dictionaryRepresentation();
  const danhSachKhoa = bangTuDien.allKeys();
  const tongSoKhoa = Number(danhSachKhoa.count());

  const mauTuKhoaNhayCam = /vip|pro|premium|subscri|purchas|unlock|entitle|lifetime|paid|receipt/i;
  const cacKhoaCanRasoát = [];

  for (let i = 0; i < tongSoKhoa; i++) {
    const tenKhoa = danhSachKhoa.objectAtIndex_(i).toString();
    // Bỏ qua các khóa hệ thống của Apple (bắt đầu bằng NS / Apple / WebKit)
    if (/^(NS|Apple|WebKit|AK|PK|com\\.apple\\.)/.test(tenKhoa)) continue;

    if (mauTuKhoaNhayCam.test(tenKhoa)) {
      const giaTriObj = bangTuDien.objectForKey_(tenKhoa);
      cacKhoaCanRasoát.push({
        tenKhoa,
        kieuDuLieuObjC: giaTriObj ? giaTriObj.$className : "null"
      });
    }
  }

  send({
    tieuChuanKiemToan: "OWASP MASTG (MASVS-STORAGE & MASVS-RESILIENCE)",
    tongSoKhoaUserDefaults: tongSoKhoa,
    soKhoaLienQuanQuyenMuaHang: cacKhoaCanRasoát.length,
    danhSachKhoaPhatHienChiDoc: cacKhoaCanRasoát,
    danhGiaRuiRo:
      cacKhoaCanRasoát.length > 0
        ? "CẢNH BÁO THIẾT KẾ: Phát hiện khóa nghi lưu trạng thái gói mua trong NSUserDefaults (dễ bị chỉnh sửa trên máy đã bẻ khóa)."
        : "TỐT: Không thấy khóa trạng thái mua hàng lưu lộ thiên trong NSUserDefaults.",
    khuyenNghiKhacPhuc: [
      "1. Không quyết định quyền tính năng trả phí chỉ dựa vào biến cờ lưu trong NSUserDefaults hoặc tệp plist cục bộ.",
      "2. Với StoreKit 2: Luôn kiểm tra chữ ký số JWS (VerificationResult.verified) của Transaction.currentEntitlements.",
      "3. Với tính năng phía máy chủ: Xác thực giao dịch qua App Store Server API v2 trên máy chủ riêng thay vì gọi verifyReceipt trực tiếp từ điện thoại."
    ]
  });
}
`,
  },
];

function extractCleanTitleFromCodeOrLongString(rawTitle = "", rawCode = "") {
  const trimmed = String(rawTitle ?? "").trim();
  const looksLikeCodeInTitle =
    trimmed.length > 120 ||
    trimmed.includes("\n") ||
    /Interceptor\.|ObjC\.|Process\.|console\.|send\s*\(|function\s+\w+\s*\(/.test(trimmed);
  const sourceForMeta = looksLikeCodeInTitle ? `${trimmed}\n${rawCode || ""}` : String(rawCode || "");

  if (trimmed && !looksLikeCodeInTitle) {
    return trimmed;
  }

  // Tự động trích xuất tên file hoặc dòng mô tả đầu tiên trong chú thích JS nếu người dùng lỡ dán cả code vào ô Tên
  const fileMatch = sourceForMeta.match(/(?:File|Tệp|Mẫu)\s*:\s*([^\r\n*]+)/i);
  const taskMatch = sourceForMeta.match(/(?:Nhiệm vụ|Mô tả|Tác dụng)\s*:\s*([^\r\n*]+)/i);
  if (fileMatch && taskMatch) {
    return `${fileMatch[1].trim()} — ${taskMatch[1].trim()}`.slice(0, 110);
  }
  if (fileMatch) {
    return `Mẫu riêng: ${fileMatch[1].trim()}`.slice(0, 110);
  }
  if (taskMatch) {
    return taskMatch[1].trim().slice(0, 110);
  }

  const firstCommentLine = sourceForMeta
    .split(/\r?\n/)
    .map((l) => l.replace(/^[\s/*#-]+/, "").trim())
    .find((l) => l.length >= 4 && !/^('use strict'|"use strict"|const |let |var |function )/.test(l));

  if (firstCommentLine) {
    return firstCommentLine.slice(0, 100);
  }

  if (trimmed) {
    return `${trimmed.replace(/\s+/g, " ").slice(0, 88)}…`;
  }
  return "";
}

function detectSnippetRunType(code = "") {
  const src = String(code || "");
  if (/Interceptor\.attach|ApiResolver|Stalker\.follow|addTransactionObserver/i.test(src) && !/send\(\{/.test(src)) {
    return "listener";
  }
  return "instant";
}

export class SnippetRepository {
  #customFilePath;

  constructor({ customFilePath = CUSTOM_SNIPPETS_FILE } = {}) {
    this.#customFilePath = customFilePath;
  }

  async #readCustomFile() {
    try {
      const raw = await fs.readFile(this.#customFilePath, "utf8");
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch {
      return [];
    }
  }

  async #writeCustomFile(items) {
    const dir = path.dirname(this.#customFilePath);
    await fs.mkdir(dir, { recursive: true });
    const tmpFile = `${this.#customFilePath}.tmp`;
    await fs.writeFile(tmpFile, JSON.stringify(items, null, 2), "utf8");
    await fs.rename(tmpFile, this.#customFilePath);
  }

  async listAll() {
    const custom = await this.#readCustomFile();
    const normalizedCustom = custom.map((item) => ({
      ...item,
      builtin: false,
      category: item.category || "8. Mẫu JS Của Tôi",
      runType: item.runType || detectSnippetRunType(item.code),
      displayTitle: extractCleanTitleFromCodeOrLongString(item.title, item.code) || "Mẫu JS tự lưu",
    }));
    return [...BUILTIN_SNIPPETS, ...normalizedCustom];
  }

  async saveCustom({ id, title, category = "8. Mẫu JS Của Tôi", runType: requestedRunType, description = "", code }) {
    const rawTitle = String(title ?? "").trim();
    let cleanCode = String(code ?? "");

    // Nếu người dùng lỡ dán nguyên đoạn code vào ô Tên khi ô Code trống, tự động cứu dữ liệu sang ô Code
    if (
      !cleanCode.trim() &&
      (rawTitle.includes("\n") ||
        rawTitle.length > 120 ||
        /function\s+|console\.|Interceptor\.|ObjC\.|Process\.|send\s*\(/.test(rawTitle))
    ) {
      cleanCode = rawTitle;
    }

    if (!rawTitle && !cleanCode.trim()) {
      throw new Error("Tên kịch bản không được để trống.");
    }
    if (!rawTitle) {
      throw new Error("Tên kịch bản không được để trống.");
    }
    if (!cleanCode.trim()) {
      throw new Error("Nội dung mã JS của kịch bản không được để trống.");
    }

    const cleanTitle = extractCleanTitleFromCodeOrLongString(rawTitle, cleanCode);
    const cleanCategory = String(category || "8. Mẫu JS Của Tôi").trim() || "8. Mẫu JS Của Tôi";
    const cleanDesc = String(description || "").trim();
    const runType =
      requestedRunType === "listener" || requestedRunType === "instant"
        ? requestedRunType
        : detectSnippetRunType(cleanCode);

    const custom = await this.#readCustomFile();
    const now = new Date().toISOString();

    if (id && !String(id).startsWith("builtin-")) {
      const idx = custom.findIndex((item) => item.id === id);
      if (idx !== -1) {
        custom[idx] = {
          ...custom[idx],
          title: cleanTitle,
          displayTitle: cleanTitle,
          category: cleanCategory,
          runType,
          description: cleanDesc,
          code: cleanCode,
          updatedAt: now,
        };
        await this.#writeCustomFile(custom);
        return custom[idx];
      }
    }

    const created = {
      id: `custom-${crypto.randomUUID().slice(0, 8)}`,
      title: cleanTitle,
      displayTitle: cleanTitle,
      category: cleanCategory,
      runType,
      builtin: false,
      description: cleanDesc,
      code: cleanCode,
      createdAt: now,
      updatedAt: now,
    };
    custom.unshift(created);
    await this.#writeCustomFile(custom);
    return created;
  }

  async updateCustom(id, payload = {}) {
    if (!id || String(id).startsWith("builtin-")) {
      throw new Error("Không thể sửa trực tiếp kịch bản mẫu mặc định của hệ thống (hãy Lưu thành mẫu riêng mới).");
    }
    const custom = await this.#readCustomFile();
    const existing = custom.find((item) => item.id === id);
    if (!existing) {
      throw new Error("Không tìm thấy kịch bản tự lưu cần cập nhật.");
    }
    return this.saveCustom({
      id,
      title: payload.title !== undefined ? payload.title : existing.title,
      category: payload.category !== undefined ? payload.category : existing.category,
      runType: payload.runType !== undefined ? payload.runType : existing.runType,
      description: payload.description !== undefined ? payload.description : existing.description,
      code: payload.code !== undefined ? payload.code : existing.code,
    });
  }

  async deleteCustom(id) {
    if (!id || String(id).startsWith("builtin-")) {
      throw new Error("Không thể xóa kịch bản mẫu mặc định của hệ thống.");
    }
    const custom = await this.#readCustomFile();
    const next = custom.filter((item) => item.id !== id);
    if (next.length === custom.length) {
      throw new Error("Không tìm thấy kịch bản cần xóa.");
    }
    await this.#writeCustomFile(next);
    return true;
  }
}

