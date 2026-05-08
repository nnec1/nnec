const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const JWT_SECRET = "lms-secret-key-2025";
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("."));

// اطمینان از وجود پوشه uploads
const uploadDir = "./uploads";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
app.use("/uploads", express.static("uploads"));

// تنظیم multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });

// اتصال به دیتابیس
let db;

async function connectDB() {
  try {
    console.log("🔄 Connecting to database...");
    db = await mysql.createConnection({
      host: process.env.DB_HOST || "localhost",
      user: process.env.DB_USER || "root",
      password: process.env.DB_PASSWORD || "Root@123",
      database: process.env.DB_NAME || "lms_db",
      port: parseInt(process.env.DB_PORT) || 3306,
      ssl:
        process.env.DB_SSL === "true"
          ? { rejectUnauthorized: false }
          : undefined,
      connectTimeout: 30000,
    });
    console.log("✅ Database connected successfully!");
  } catch (err) {
    console.error("❌ Database connection failed:", err.message);
    console.log(
      "⚠️ Starting server without database - some features may not work",
    );
  }
}

// ==================== توابع کمکی ====================

function generateStudentCardId() {
  const prefix = "STU";
  const year = new Date().getFullYear().toString().slice(-2);
  const random = Math.floor(Math.random() * 10000)
    .toString()
    .padStart(4, "0");
  return `${prefix}-${year}-${random}`;
}

function generateQrToken() {
  return crypto
    .createHash("md5")
    .update(Date.now() + Math.random().toString())
    .digest("hex");
}

function generateReceiptNumber() {
  return "RCP-" + Date.now() + "-" + Math.floor(Math.random() * 1000);
}

function toNull(value) {
  if (value === undefined || value === "undefined" || value === "") return null;
  return value;
}

// Middleware احراز هویت
const authenticate = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "احراز هویت نشده" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "توکن نامعتبر" });
  }
};

const isCEO = (req, res, next) => {
  if (req.user.role !== "ceo")
    return res.status(403).json({ error: "دسترسی محدود به ریس سیستم" });
  next();
};

const isAdminOrCEO = (req, res, next) => {
  if (!["ceo", "admin"].includes(req.user.role))
    return res.status(403).json({ error: "دسترسی محدود به مدیران" });
  next();
};

// ====================== API عمومی ======================

app.post("/api/login", async (req, res) => {
  const { email, password, userType } = req.body;
  if (userType === "student") {
    return res.status(401).json({ error: "شاگردان باید با QR کد وارد شوند" });
  }
  try {
    const [results] = await db.execute(
      `SELECT * FROM employees WHERE email = ? AND position = ? AND status = 'active'`,
      [email, userType],
    );
    if (results.length === 0)
      return res.status(401).json({ error: "ایمیل یا رمز عبور اشتباه است" });
    const user = results[0];
    let isValid = false;
    if (user.password.startsWith("$2a$")) {
      isValid = await bcrypt.compare(password, user.password);
    } else {
      isValid = password === user.password;
    }
    if (!isValid)
      return res.status(401).json({ error: "ایمیل یا رمز عبور اشتباه است" });
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.position },
      JWT_SECRET,
      { expiresIn: "24h" },
    );
    res.cookie("token", token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
    let redirectUrl =
      user.position === "ceo"
        ? "/ceo/dashboard.html"
        : user.position === "admin"
          ? "/admin/dashboard.html"
          : "/teacher/dashboard.html";
    res.json({
      success: true,
      redirectUrl,
      user: { id: user.id, name: user.name, role: user.position },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "خطای سرور" });
  }
});

app.post("/api/student-login-with-qr", async (req, res) => {
  const { qr_token } = req.body;
  try {
    const [results] = await db.execute(
      `SELECT * FROM students WHERE qr_token = ? AND status = 'active'`,
      [qr_token],
    );
    if (results.length === 0)
      return res
        .status(401)
        .json({ error: "QR کد معتبر نیست یا حساب غیرفعال است" });
    const user = results[0];
    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        role: "student",
        student_card_id: user.student_card_id,
      },
      JWT_SECRET,
      { expiresIn: "24h" },
    );
    res.cookie("token", token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
    res.json({
      success: true,
      redirectUrl: "/student/dashboard.html",
      user: { id: user.id, name: user.name },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "خطای سرور" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ success: true });
});

app.get("/api/announcements/public", async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT * FROM announcements WHERE is_active = 1 AND (expires_at IS NULL OR expires_at >= CURDATE()) ORDER BY created_at DESC LIMIT 5`,
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API صنف‌ها ======================

app.get("/api/classes", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      "SELECT * FROM classes WHERE is_active = 1",
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/classes/all", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute("SELECT * FROM classes ORDER BY id");
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/classes/:id", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute("SELECT * FROM classes WHERE id = ?", [
      req.params.id,
    ]);
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/classes", authenticate, isAdminOrCEO, async (req, res) => {
  const { class_name, start_time, is_active } = req.body;
  if (!class_name || class_name.trim() === "") {
    return res.status(400).json({ error: "نام صنف الزامی است" });
  }
  try {
    const [result] = await db.execute(
      `INSERT INTO classes (class_name, start_time, is_active) VALUES (?, ?, ?)`,
      [
        class_name,
        start_time || "08:00:00",
        is_active !== undefined ? is_active : 1,
      ],
    );
    res.json({ id: result.insertId, message: "صنف با موفقیت ایجاد شد" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      res.status(400).json({ error: "این نام صنف قبلاً ثبت شده است" });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

app.put("/api/classes/:id", authenticate, isAdminOrCEO, async (req, res) => {
  const { class_name, start_time, is_active } = req.body;
  try {
    await db.execute(
      `UPDATE classes SET class_name=?, start_time=?, is_active=? WHERE id=?`,
      [
        class_name,
        start_time || "08:00:00",
        is_active !== undefined ? is_active : 1,
        req.params.id,
      ],
    );
    res.json({ message: "صنف با موفقیت به‌روز شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/classes/:id", authenticate, isAdminOrCEO, async (req, res) => {
  try {
    await db.execute("DELETE FROM classes WHERE id = ?", [req.params.id]);
    res.json({ message: "صنف با موفقیت حذف شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API شاگردان ======================

// // POST /api/students - ثبت شاگرد جدید
// // app.post(
// //   "/api/students",
// //   authenticate,
// //   upload.single("photo"),
// //   async (req, res) => {
// //     const {
// //       name,
// //       father_name,
// //       phone,
// //       class_id,
// //       total_fee,
// //       paid_fee,
// //       due_date,
// //       address,
// //       status,
// //       registration_date,
// //       student_card_id,
// //     } = req.body;

// //     if (req.user.role === "teacher") {
// //       return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
// //     }

// //     const autoPass = Math.random().toString(36).substring(2, 8);
// //     const hashedPass = await bcrypt.hash(autoPass, 10);
// //     const qr_token = generateQrToken();
// //     const finalStudentCardId = student_card_id || generateStudentCardId();
// //     const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

// //     const finalTotalFee = parseFloat(total_fee) || 0;
// //     const finalPaidFee = parseFloat(paid_fee) || 0;
// //     const finalRemainingFee = finalTotalFee - finalPaidFee;

// //     // تاریخ ثبت‌نام (تاریخ صدور)
// //     let finalRegDate = registration_date;
// //     if (!finalRegDate) {
// //       finalRegDate = new Date().toISOString().split("T")[0];
// //     }

// //     // تاریخ انقضا: یک ماه بعد از تاریخ ثبت‌نام
// //     let finalDueDate = due_date;
// //     if (!finalDueDate && (finalTotalFee > 0 || finalPaidFee > 0)) {
// //       const nextMonth = new Date(finalRegDate);
// //       nextMonth.setMonth(nextMonth.getMonth() + 1);
// //       finalDueDate = nextMonth.toISOString().split("T")[0];
// //     }

// //     try {
// //       const [result] = await db.execute(
// //         `
// //             INSERT INTO students
// //             (student_card_id, name, father_name, phone, password, class_id, registration_date,
// //              status, qr_token, total_fee, paid_fee, remaining_fee, due_date, address, photo)
// //             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
// //         `,
// //         [
// //           finalStudentCardId,
// //           name,
// //           toNull(father_name),
// //           toNull(phone),
// //           hashedPass,
// //           class_id,
// //           finalRegDate,
// //           status || "active",
// //           qr_token,
// //           finalTotalFee,
// //           finalPaidFee,
// //           finalRemainingFee < 0 ? 0 : finalRemainingFee,
// //           finalDueDate,
// //           toNull(address),
// //           toNull(photoPath),
// //         ],
// //       );

// //       const studentId = result.insertId;

// //       // ثبت پرداخت اولیه در fee_payments با issue_date و payment_date
// //       if (finalPaidFee > 0) {
// //         const receipt_number = generateReceiptNumber();
// //         const paymentDate = finalRegDate; // تاریخ پرداخت = تاریخ ثبت‌نام
// //         const issueDate = finalRegDate; // تاریخ صدور = تاریخ ثبت‌نام (همان امروز)
// //         const expiryDate = finalDueDate; // تاریخ انقضا = یک ماه بعد

// //         await db.execute(
// //           `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
// //                  VALUES (?, ?, ?, ?, ?, ?)`,
// //           [
// //             studentId,
// //             finalPaidFee,
// //             paymentDate,
// //             issueDate,
// //             receipt_number,
// //             "پرداخت اولیه هنگام ثبت‌نام",
// //           ],
// //         );
// //       }

// //       res.json({
// //         id: studentId,
// //         qr_token,
// //         student_card_id: finalStudentCardId,
// //         password: autoPass,
// //         total_fee: finalTotalFee,
// //         paid_fee: finalPaidFee,
// //         remaining_fee: finalRemainingFee < 0 ? 0 : finalRemainingFee,
// //         due_date: finalDueDate,
// //         registration_date: finalRegDate,
// //       });
// //     } catch (err) {
// //       console.error("Error in POST /api/students:", err);
// //       res.status(500).json({ error: err.message });
// //     }
// //   },
// // );

// app.get("/api/students/:id", authenticate, async (req, res) => {
//   try {
//     const [results] = await db.execute(
//       `
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.total_fee, s.paid_fee, s.remaining_fee, s.due_date, s.status, s.address, s.photo, s.qr_token,
//                    c.class_name
//             FROM students s
//             LEFT JOIN classes c ON s.class_id = c.id
//             WHERE s.id = ?
//         `,
//       [req.params.id],
//     );

//     if (results.length === 0) {
//       return res.status(404).json({ error: "شاگرد یافت نشد" });
//     }

//     const student = results[0];
//     if (student.due_date) {
//       const d = new Date(student.due_date);
//       if (!isNaN(d.getTime())) student.due_date = d.toISOString().split("T")[0];
//     }

//     res.json(student);
//   } catch (err) {
//     console.error("Error in /api/students/:id:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// // app.post(
// //   "/api/students",
// //   authenticate,
// //   upload.single("photo"),
// //   async (req, res) => {
// //     const {
// //       name,
// //       father_name,
// //       phone,
// //       class_id,
// //       total_fee,
// //       paid_fee,
// //       due_date,
// //       address,
// //       status,
// //     } = req.body;
// //     if (req.user.role === "teacher")
// //       return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
// //     const autoPass = Math.random().toString(36).substring(2, 8);
// //     const hashedPass = await bcrypt.hash(autoPass, 10);
// //     const qr_token = generateQrToken();
// //     const student_card_id = generateStudentCardId();
// //     const photoPath = req.file ? `/uploads/${req.file.filename}` : null;
// //     const finalTotalFee = parseFloat(total_fee) || 0;
// //     const finalPaidFee = parseFloat(paid_fee) || 0;
// //     const finalRemainingFee = finalTotalFee - finalPaidFee;
// //     let finalDueDate = due_date;
// //     if (!finalDueDate) {
// //       const nextMonth = new Date();
// //       nextMonth.setMonth(nextMonth.getMonth() + 1);
// //       finalDueDate = nextMonth.toISOString().split("T")[0];
// //     }
// //     try {
// //       const [result] = await db.execute(
// //         `
// //             INSERT INTO students
// //             (student_card_id, name, father_name, phone, password, class_id, registration_date,
// //              status, qr_token, total_fee, paid_fee, remaining_fee, due_date, address, photo)
// //             VALUES (?, ?, ?, ?, ?, ?, CURDATE(), ?, ?, ?, ?, ?, ?, ?, ?)
// //         `,
// //         [
// //           student_card_id,
// //           name,
// //           toNull(father_name),
// //           toNull(phone),
// //           hashedPass,
// //           class_id,
// //           status || "active",
// //           qr_token,
// //           finalTotalFee,
// //           finalPaidFee,
// //           finalRemainingFee,
// //           finalDueDate,
// //           toNull(address),
// //           toNull(photoPath),
// //         ],
// //       );

// //       res.json({
// //         id: result.insertId,
// //         qr_token,
// //         student_card_id,
// //         password: autoPass,
// //         total_fee: finalTotalFee,
// //         paid_fee: finalPaidFee,
// //         remaining_fee: finalRemainingFee,
// //         due_date: finalDueDate,
// //       });
// //     } catch (err) {
// //       console.error("Error in POST /api/students:", err);
// //       res.status(500).json({ error: err.message });
// //     }
// //   },
// // );

// // POST /api/students - ثبت شاگرد جدید
// app.post(
//   "/api/students",
//   authenticate,
//   upload.single("photo"),
//   async (req, res) => {
//     const {
//       name,
//       father_name,
//       phone,
//       class_id,
//       total_fee,
//       paid_fee,
//       due_date,
//       address,
//       status,
//       registration_date,
//       student_card_id,
//     } = req.body;

//     if (req.user.role === "teacher") {
//       return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
//     }

//     const autoPass = Math.random().toString(36).substring(2, 8);
//     const hashedPass = await bcrypt.hash(autoPass, 10);
//     const qr_token = generateQrToken();
//     const finalStudentCardId = student_card_id || generateStudentCardId();
//     const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

//     const finalTotalFee = parseFloat(total_fee) || 0;
//     const finalPaidFee = parseFloat(paid_fee) || 0;
//     const finalRemainingFee = finalTotalFee - finalPaidFee;

//     let finalDueDate = due_date;
//     if (!finalDueDate && (finalTotalFee > 0 || finalPaidFee > 0)) {
//       const nextMonth = new Date();
//       nextMonth.setMonth(nextMonth.getMonth() + 1);
//       finalDueDate = nextMonth.toISOString().split("T")[0];
//     }

//     let finalRegDate = registration_date;
//     if (!finalRegDate) {
//       finalRegDate = new Date().toISOString().split("T")[0];
//     }

//     try {
//       const [result] = await db.execute(
//         `
//             INSERT INTO students
//             (student_card_id, name, father_name, phone, password, class_id, registration_date,
//              status, qr_token, total_fee, paid_fee, remaining_fee, due_date, address, photo)
//             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//         `,
//         [
//           finalStudentCardId,
//           name,
//           toNull(father_name),
//           toNull(phone),
//           hashedPass,
//           class_id,
//           finalRegDate,
//           status || "active",
//           qr_token,
//           finalTotalFee,
//           finalPaidFee,
//           finalRemainingFee < 0 ? 0 : finalRemainingFee,
//           finalDueDate,
//           toNull(address),
//           toNull(photoPath),
//         ],
//       );

//       const studentId = result.insertId;

//       // ========== کد جدید: ثبت پرداخت اولیه در fee_payments ==========
//       if (finalPaidFee > 0) {
//         const receipt_number = generateReceiptNumber();
//         const paymentDate = finalRegDate; // تاریخ ثبت به عنوان تاریخ پرداخت
//         await db.execute(
//           `INSERT INTO fee_payments (student_id, amount, payment_date, receipt_number, notes)
//                  VALUES (?, ?, ?, ?, ?)`,
//           [
//             studentId,
//             finalPaidFee,
//             paymentDate,
//             receipt_number,
//             "پرداخت اولیه هنگام ثبت‌نام",
//           ],
//         );
//       }
//       // ========== پایان کد جدید ==========

//       res.json({
//         id: studentId,
//         qr_token,
//         student_card_id: finalStudentCardId,
//         password: autoPass,
//         total_fee: finalTotalFee,
//         paid_fee: finalPaidFee,
//         remaining_fee: finalRemainingFee < 0 ? 0 : finalRemainingFee,
//         due_date: finalDueDate,
//       });
//     } catch (err) {
//       console.error("Error in POST /api/students:", err);
//       res.status(500).json({ error: err.message });
//     }
//   },
// );

// // ====================== PUT /api/students/:id - ویرایش شاگرد (نسخه اصلاح شده) ======================
// app.put(
//   "/api/students/:id",
//   authenticate,
//   upload.single("photo"),
//   async (req, res) => {
//     try {
//       const studentId = req.params.id;
//       const updates = req.body;

//       console.log("Updating student ID:", studentId);
//       console.log("Request body:", updates);

//       // بررسی وجود شاگرد
//       const [existing] = await db.execute(
//         `SELECT * FROM students WHERE id = ?`,
//         [studentId],
//       );
//       if (existing.length === 0) {
//         return res.status(404).json({ error: "شاگرد یافت نشد" });
//       }

//       // ساخت کوئری داینامیک
//       const updateFields = [];
//       const updateValues = [];

//       // فیلدهای پایه
//       if (updates.name !== undefined) {
//         updateFields.push("name = ?");
//         updateValues.push(updates.name || null);
//       }
//       if (updates.father_name !== undefined) {
//         updateFields.push("father_name = ?");
//         updateValues.push(toNull(updates.father_name));
//       }
//       if (updates.phone !== undefined) {
//         updateFields.push("phone = ?");
//         updateValues.push(toNull(updates.phone));
//       }
//       if (updates.class_id !== undefined) {
//         updateFields.push("class_id = ?");
//         updateValues.push(updates.class_id || null);
//       }
//       if (updates.status !== undefined) {
//         updateFields.push("status = ?");
//         updateValues.push(updates.status || "active");
//       }
//       if (updates.address !== undefined) {
//         updateFields.push("address = ?");
//         updateValues.push(toNull(updates.address));
//       }

//       // فیلدهای مالی (برای ویرایش فیس)
//       let totalFeeChanged = false;
//       let paidFeeChanged = false;
//       let newTotalFee = null;
//       let newPaidFee = null;

//       if (updates.total_fee !== undefined) {
//         newTotalFee = parseFloat(updates.total_fee) || 0;
//         updateFields.push("total_fee = ?");
//         updateValues.push(newTotalFee);
//         totalFeeChanged = true;
//       }
//       if (updates.paid_fee !== undefined) {
//         newPaidFee = parseFloat(updates.paid_fee) || 0;
//         updateFields.push("paid_fee = ?");
//         updateValues.push(newPaidFee);
//         paidFeeChanged = true;
//       }

//       // محاسبه remaining_fee
//       if (totalFeeChanged || paidFeeChanged) {
//         const currentTotal =
//           newTotalFee !== null
//             ? newTotalFee
//             : parseFloat(existing[0].total_fee) || 0;
//         const currentPaid =
//           newPaidFee !== null
//             ? newPaidFee
//             : parseFloat(existing[0].paid_fee) || 0;
//         const newRemaining = currentTotal - currentPaid;
//         updateFields.push("remaining_fee = ?");
//         updateValues.push(newRemaining < 0 ? 0 : newRemaining);
//       }

//       // تاریخ انقضا
//       if (updates.due_date !== undefined) {
//         updateFields.push("due_date = ?");
//         updateValues.push(updates.due_date || null);
//       }

//       // عکس
//       if (req.file) {
//         const photoPath = `/uploads/${req.file.filename}`;
//         updateFields.push("photo = ?");
//         updateValues.push(photoPath);
//       }

//       // رمز عبور
//       if (updates.password && updates.password.trim()) {
//         const hashed = await bcrypt.hash(updates.password, 10);
//         updateFields.push("password = ?");
//         updateValues.push(hashed);
//       }

//       // اگر هیچ فیلدی برای به روزرسانی وجود ندارد
//       if (updateFields.length === 0) {
//         return res.json({ success: true, message: "تغییری اعمال نشد" });
//       }

//       // ساخت و اجرای کوئری
//       updateValues.push(studentId);
//       const query = `UPDATE students SET ${updateFields.join(", ")} WHERE id = ?`;

//       console.log("Query:", query);
//       console.log("Values:", updateValues);

//       await db.execute(query, updateValues);

//       // دریافت اطلاعات به روز شده
//       const [updated] = await db.execute(
//         `SELECT * FROM students WHERE id = ?`,
//         [studentId],
//       );

//       res.json({
//         success: true,
//         message: "اطلاعات با موفقیت به‌روز شد",
//         student: updated[0],
//       });
//     } catch (err) {
//       console.error("Error in PUT /api/students/:id:", err);
//       res.status(500).json({
//         error: err.message,
//         code: err.code,
//         sqlMessage: err.sqlMessage,
//       });
//     }
//   },
// );

// app.delete("/api/students/:id", authenticate, async (req, res) => {
//   if (req.user.role === "teacher")
//     return res.status(403).json({ error: "استاد نمی‌تواند شاگرد حذف کند" });
//   try {
//     // بررسی وجود شاگرد
//     const [existing] = await db.execute(
//       `SELECT id FROM students WHERE id = ?`,
//       [req.params.id],
//     );
//     if (existing.length === 0) {
//       return res.status(404).json({ error: "شاگرد یافت نشد" });
//     }

//     // حذف پرداخت‌های مرتبط
//     await db.execute(`DELETE FROM fee_payments WHERE student_id = ?`, [
//       req.params.id,
//     ]);

//     // حذف شاگرد
//     await db.execute(`DELETE FROM students WHERE id = ?`, [req.params.id]);

//     res.json({ success: true, message: "شاگرد با موفقیت حذف شد" });
//   } catch (err) {
//     console.error("Error in DELETE /api/students/:id:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// ====================== API شاگردان ======================

// GET /api/students - دریافت لیست همه شاگردان
// app.get("/api/students", authenticate, async (req, res) => {
//   try {
//     const [results] = await db.execute(`
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.total_fee, s.paid_fee, s.remaining_fee, s.due_date, s.status,
//                    s.address, s.photo, s.qr_token, s.registration_date,
//                    c.class_name
//             FROM students s
//             LEFT JOIN classes c ON s.class_id = c.id
//             ORDER BY s.id DESC
//         `);

app.get("/api/students", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id, 
                   s.status, s.address, s.photo, s.qr_token, s.registration_date,
                   c.class_name 
            FROM students s 
            LEFT JOIN classes c ON s.class_id = c.id 
            ORDER BY s.id DESC
        `);

    //         res.json(results);
    //     } catch (err) {
    //         console.error("Error in GET /api/students:", err);
    //         res.status(500).json({ error: err.message });
    //     }
    // });
    // فرمت تاریخ‌ها
    const formattedResults = results.map((student) => {
      if (student.due_date) {
        const d = new Date(student.due_date);
        if (!isNaN(d.getTime()))
          student.due_date = d.toISOString().split("T")[0];
      }
      if (student.registration_date) {
        const d = new Date(student.registration_date);
        if (!isNaN(d.getTime()))
          student.registration_date = d.toISOString().split("T")[0];
      }
      return student;
    });

    res.json(formattedResults);
  } catch (err) {
    console.error("Error in GET /api/students:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/students/:id - دریافت اطلاعات یک شاگرد
// app.get("/api/students/:id", authenticate, async (req, res) => {
//   try {
//     const [results] = await db.execute(
//       `
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.total_fee, s.paid_fee, s.remaining_fee, s.due_date, s.status,
//                    s.address, s.photo, s.qr_token, s.registration_date,
//                    c.class_name
//             FROM students s
//             LEFT JOIN classes c ON s.class_id = c.id
//             WHERE s.id = ?
//         `,
//       [req.params.id],
//     );

//     if (results.length === 0) {
//       return res.status(404).json({ error: "شاگرد یافت نشد" });
//     }

//     const student = results[0];

// app.get("/api/students/:id", authenticate, async (req, res) => {
//   try {
//     const [results] = await db.execute(
//       `
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.status, s.address, s.photo, s.qr_token, s.registration_date,
//                    c.class_name
//             FROM students s
//             LEFT JOIN classes c ON s.class_id = c.id
//             WHERE s.id = ?
//         `,
//       [req.params.id],
//     );

//     if (results.length === 0) {
//       return res.status(404).json({ error: "شاگرد یافت نشد" });
//     }

//     //         res.json(results[0]);
//     //     } catch (err) {
//     //         console.error("Error in GET /api/students/:id:", err);
//     //         res.status(500).json({ error: err.message });
//     //     }
//     // // });

app.get("/api/students/:id", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id, 
                   s.status, s.address, s.photo, s.qr_token, s.registration_date,
                   c.class_name 
            FROM students s 
            LEFT JOIN classes c ON s.class_id = c.id 
            WHERE s.id = ?
        `,
      [req.params.id],
    );

    if (results.length === 0) {
      return res.status(404).json({ error: "شاگرد یافت نشد" });
    }

    // اضافه کردن مقادیر پیش‌فرض برای فیلدهای حذف شده
    const student = results[0];
    student.total_fee = 0;
    student.paid_fee = 0;
    student.remaining_fee = 0;
    student.due_date = null;

    //         res.json(student);
    //     } catch (err) {
    //         console.error("Error in GET /api/students/:id:", err);
    //         res.status(500).json({ error: err.message });
    //     }
    // });

    // فرمت تاریخ‌ها
    if (student.due_date) {
      const d = new Date(student.due_date);
      if (!isNaN(d.getTime())) student.due_date = d.toISOString().split("T")[0];
    }
    if (student.registration_date) {
      const d = new Date(student.registration_date);
      if (!isNaN(d.getTime()))
        student.registration_date = d.toISOString().split("T")[0];
    }

    res.json(student);
  } catch (err) {
    console.error("Error in GET /api/students/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/students - ثبت شاگرد جدید
// app.post(
//   "/api/students",
//   authenticate,
//   upload.single("photo"),
//   async (req, res) => {
//     const {
//       name,
//       father_name,
//       phone,
//       class_id,
//       total_fee,
//       paid_fee,
//       due_date,
//       address,
//       status,
//       registration_date,
//       student_card_id,
//     } = req.body;

//     if (req.user.role === "teacher") {
//       return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
//     }

//     // تولید اطلاعات خودکار
//     const autoPass = Math.random().toString(36).substring(2, 8);
//     const hashedPass = await bcrypt.hash(autoPass, 10);
//     const qr_token = generateQrToken();
//     const finalStudentCardId = student_card_id || generateStudentCardId();
//     const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

//     // محاسبات مالی
//     const finalTotalFee = parseFloat(total_fee) || 0;
//     const finalPaidFee = parseFloat(paid_fee) || 0;
//     const finalRemainingFee = finalTotalFee - finalPaidFee;

//     // تاریخ ثبت‌نام (تاریخ صدور)
//     let finalRegDate = registration_date;
//     if (!finalRegDate) {
//       finalRegDate = new Date().toISOString().split("T")[0];
//     }

//     // تاریخ انقضا: یک ماه بعد از تاریخ ثبت‌نام
//     let finalDueDate = due_date;
//     if (!finalDueDate && (finalTotalFee > 0 || finalPaidFee > 0)) {
//       const nextMonth = new Date(finalRegDate);
//       nextMonth.setMonth(nextMonth.getMonth() + 1);
//       finalDueDate = nextMonth.toISOString().split("T")[0];
//     }

//     try {
//       const [result] = await db.execute(
//         `
//             INSERT INTO students
//             (student_card_id, name, father_name, phone, password, class_id, registration_date,
//              status, qr_token, total_fee, paid_fee, remaining_fee, due_date, address, photo)
//             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//         `,
//         [
//           finalStudentCardId,
//           name,
//           toNull(father_name),
//           toNull(phone),
//           hashedPass,
//           class_id,
//           finalRegDate,
//           status || "active",
//           qr_token,
//           finalTotalFee,
//           finalPaidFee,
//           finalRemainingFee < 0 ? 0 : finalRemainingFee,
//           finalDueDate,
//           toNull(address),
//           toNull(photoPath),
//         ],
//       );

//       const studentId = result.insertId;

//       // ثبت پرداخت اولیه در fee_payments با issue_date و payment_date
//       if (finalPaidFee > 0) {
//         const receipt_number = generateReceiptNumber();
//         const paymentDate = finalRegDate; // تاریخ پرداخت = تاریخ ثبت‌نام
//         const issueDate = finalRegDate; // تاریخ صدور = تاریخ ثبت‌نام
//         const expiryDate = finalDueDate; // تاریخ انقضا = یک ماه بعد

//         await db.execute(
//           `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//                  VALUES (?, ?, ?, ?, ?, ?)`,
//           [
//             studentId,
//             finalPaidFee,
//             paymentDate,
//             issueDate,
//             receipt_number,
//             "پرداخت اولیه هنگام ثبت‌نام",
//           ],
//         );
//       }

//       res.json({
//         success: true,
//         id: studentId,
//         qr_token,
//         student_card_id: finalStudentCardId,
//         password: autoPass,
//         total_fee: finalTotalFee,
//         paid_fee: finalPaidFee,
//         remaining_fee: finalRemainingFee < 0 ? 0 : finalRemainingFee,
//         due_date: finalDueDate,
//         registration_date: finalRegDate,
//       });
//     } catch (err) {
//       console.error("Error in POST /api/students:", err);
//       res.status(500).json({ error: err.message });
//     }
//   },
// );

// POST /api/students - ثبت شاگرد جدید
// app.post(
//   "/api/students",
//   authenticate,
//   upload.single("photo"),
//   async (req, res) => {
//     const {
//       name,
//       father_name,
//       phone,
//       class_id,
//       total_fee,
//       paid_fee,
//       due_date,
//       address,
//       status,
//       registration_date,
//       student_card_id,
//     } = req.body;

//     if (req.user.role === "teacher") {
//       return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
//     }

// app.post("/api/students", authenticate, upload.single("photo"), async (req, res) => {
//     const { name, father_name, phone, class_id, address, status, registration_date, student_card_id } = req.body;

//     if (req.user.role === "teacher") {
//         return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
//     }

//     const autoPass = Math.random().toString(36).substring(2, 8);
//     const hashedPass = await bcrypt.hash(autoPass, 10);
//     const qr_token = generateQrToken();
//     const finalStudentCardId = student_card_id || generateStudentCardId();
//     const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

//     let finalRegDate = registration_date;
//     if (!finalRegDate) {
//         finalRegDate = new Date().toISOString().split("T")[0];
//     }

//     try {
//         const [result] = await db.execute(`
//             INSERT INTO students
//             (student_card_id, name, father_name, phone, password, class_id, registration_date,
//              status, qr_token, address, photo)
//             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//         `, [
//             finalStudentCardId,
//             name,
//             toNull(father_name),
//             toNull(phone),
//             hashedPass,
//             class_id,
//             finalRegDate,
//             status || "active",
//             qr_token,
//             toNull(address),
//             toNull(photoPath)
//         ]);

//         const studentId = result.insertId;

//         res.json({
//             success: true,
//             id: studentId,
//             qr_token,
//             student_card_id: finalStudentCardId,
//             password: autoPass,
//             registration_date: finalRegDate,
//         });
// //     } catch (err) {
// //         console.error("Error in POST /api/students:", err);
// //         res.status(500).json({ error: err.message });
// //     }
// // });

//     // تولید اطلاعات خودکار
//     const autoPass = Math.random().toString(36).substring(2, 8);
//     const hashedPass = await bcrypt.hash(autoPass, 10);
//     const qr_token = generateQrToken();
//     const finalStudentCardId = student_card_id || generateStudentCardId();
//     const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

//     // محاسبات مالی
//     const finalTotalFee = parseFloat(total_fee) || 0;
//     const finalPaidFee = parseFloat(paid_fee) || 0;
//     const finalRemainingFee = finalTotalFee - finalPaidFee;

//     // تاریخ ثبت (تاریخ مراجعه شاگرد) - توسط کاربر انتخاب می‌شود
//     let finalRegDate = registration_date;
//     if (!finalRegDate) {
//       finalRegDate = new Date().toISOString().split("T")[0];
//     }

//     // تاریخ انقضا: یک ماه بعد از تاریخ ثبت
//     let finalDueDate = due_date;
//     if (!finalDueDate && (finalTotalFee > 0 || finalPaidFee > 0)) {
//       const nextMonth = new Date(finalRegDate);
//       nextMonth.setMonth(nextMonth.getMonth() + 1);
//       finalDueDate = nextMonth.toISOString().split("T")[0];
//     }

//     // تاریخ صدور (امروز - تاریخ جاری سیستم)
//     const today = new Date().toISOString().split("T")[0];

//     try {
//       const [result] = await db.execute(
//         `
//             INSERT INTO students
//             (student_card_id, name, father_name, phone, password, class_id, registration_date,
//              status, qr_token, total_fee, paid_fee, remaining_fee, due_date, address, photo)
//             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//         `,
//         [
//           finalStudentCardId,
//           name,
//           toNull(father_name),
//           toNull(phone),
//           hashedPass,
//           class_id,
//           finalRegDate,
//           status || "active",
//           qr_token,
//           finalTotalFee,
//           finalPaidFee,
//           finalRemainingFee < 0 ? 0 : finalRemainingFee,
//           finalDueDate,
//           toNull(address),
//           toNull(photoPath),
//         ],
//       );

//       const studentId = result.insertId;

//       // ثبت پرداخت اولیه در fee_payments
//       // payment_date = تاریخ ثبت (تاریخ مراجعه شاگرد)
//       // issue_date = امروز (تاریخ صدور رسید)
//       if (finalPaidFee > 0) {
//         const receipt_number = generateReceiptNumber();

//         await db.execute(
//           `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//                  VALUES (?, ?, ?, ?, ?, ?)`,
//           [
//             studentId,
//             finalPaidFee,
//             finalRegDate,
//             today,
//             receipt_number,
//             "پرداخت اولیه هنگام ثبت‌نام",
//           ],
//         );
//       }

//       res.json({
//         success: true,
//         id: studentId,
//         qr_token,
//         student_card_id: finalStudentCardId,
//         password: autoPass,
//         total_fee: finalTotalFee,
//         paid_fee: finalPaidFee,
//         remaining_fee: finalRemainingFee < 0 ? 0 : finalRemainingFee,
//         due_date: finalDueDate,
//         registration_date: finalRegDate,
//         issue_date: today, // تاریخ صدور = امروز
//       });
//     } catch (err) {
//       console.error("Error in POST /api/students:", err);
//       res.status(500).json({ error: err.message });
//     }
//   },
// );

app.post(
  "/api/students",
  authenticate,
  upload.single("photo"),
  async (req, res) => {
    const {
      name,
      father_name,
      phone,
      class_id,
      address,
      status,
      registration_date,
      student_card_id,
    } = req.body;

    if (req.user.role === "teacher") {
      return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
    }

    const autoPass = Math.random().toString(36).substring(2, 8);
    const hashedPass = await bcrypt.hash(autoPass, 10);
    const qr_token = generateQrToken();
    const finalStudentCardId = student_card_id || generateStudentCardId();
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    let finalRegDate = registration_date;
    if (!finalRegDate) {
      finalRegDate = new Date().toISOString().split("T")[0];
    }

    try {
      const [result] = await db.execute(
        `
            INSERT INTO students 
            (student_card_id, name, father_name, phone, password, class_id, registration_date, 
             status, qr_token, address, photo) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          finalStudentCardId,
          name,
          toNull(father_name),
          toNull(phone),
          hashedPass,
          class_id,
          finalRegDate,
          status || "active",
          qr_token,
          toNull(address),
          toNull(photoPath),
        ],
      );

      const studentId = result.insertId;

      res.json({
        success: true,
        id: studentId,
        qr_token,
        student_card_id: finalStudentCardId,
        password: autoPass,
        registration_date: finalRegDate,
      });
    } catch (err) {
      console.error("Error in POST /api/students:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

// PUT /api/students/:id - ویرایش کامل شاگرد
// app.put(
//   "/api/students/:id",
//   authenticate,
//   upload.single("photo"),
//   async (req, res) => {
//     try {
//       const studentId = req.params.id;
//       const updates = req.body;

//       console.log("Updating student ID:", studentId);
//       console.log("Request body:", updates);

//       // بررسی وجود شاگرد
//       const [existing] = await db.execute(
//         `SELECT * FROM students WHERE id = ?`,
//         [studentId],
//       );
//       if (existing.length === 0) {
//         return res.status(404).json({ error: "شاگرد یافت نشد" });
//       }

//       // ساخت کوئری داینامیک
//       const updateFields = [];
//       const updateValues = [];

//       // فیلدهای پایه
//       if (updates.name !== undefined) {
//         updateFields.push("name = ?");
//         updateValues.push(updates.name || null);
//       }
//       if (updates.father_name !== undefined) {
//         updateFields.push("father_name = ?");
//         updateValues.push(toNull(updates.father_name));
//       }
//       if (updates.phone !== undefined) {
//         updateFields.push("phone = ?");
//         updateValues.push(toNull(updates.phone));
//       }
//       if (updates.class_id !== undefined) {
//         updateFields.push("class_id = ?");
//         updateValues.push(updates.class_id || null);
//       }
//       if (updates.status !== undefined) {
//         updateFields.push("status = ?");
//         updateValues.push(updates.status || "active");
//       }
//       if (updates.address !== undefined) {
//         updateFields.push("address = ?");
//         updateValues.push(toNull(updates.address));
//       }
//       if (updates.registration_date !== undefined) {
//         updateFields.push("registration_date = ?");
//         updateValues.push(updates.registration_date || null);
//       }

//       // فیلدهای مالی
//       let totalFeeChanged = false;
//       let paidFeeChanged = false;
//       let newTotalFee = null;
//       let newPaidFee = null;

//       if (updates.total_fee !== undefined) {
//         newTotalFee = parseFloat(updates.total_fee) || 0;
//         updateFields.push("total_fee = ?");
//         updateValues.push(newTotalFee);
//         totalFeeChanged = true;
//       }
//       if (updates.paid_fee !== undefined) {
//         newPaidFee = parseFloat(updates.paid_fee) || 0;
//         updateFields.push("paid_fee = ?");
//         updateValues.push(newPaidFee);
//         paidFeeChanged = true;
//       }

//       // محاسبه remaining_fee
//       if (totalFeeChanged || paidFeeChanged) {
//         const currentTotal =
//           newTotalFee !== null
//             ? newTotalFee
//             : parseFloat(existing[0].total_fee) || 0;
//         const currentPaid =
//           newPaidFee !== null
//             ? newPaidFee
//             : parseFloat(existing[0].paid_fee) || 0;
//         const newRemaining = currentTotal - currentPaid;
//         updateFields.push("remaining_fee = ?");
//         updateValues.push(newRemaining < 0 ? 0 : newRemaining);
//       }

//       // تاریخ انقضا
//       if (updates.due_date !== undefined) {
//         updateFields.push("due_date = ?");
//         updateValues.push(updates.due_date || null);
//       }

//       // عکس
//       if (req.file) {
//         const photoPath = `/uploads/${req.file.filename}`;
//         updateFields.push("photo = ?");
//         updateValues.push(photoPath);
//       }

//       // رمز عبور
//       if (updates.password && updates.password.trim()) {
//         const hashed = await bcrypt.hash(updates.password, 10);
//         updateFields.push("password = ?");
//         updateValues.push(hashed);
//       }

//       // اگر هیچ فیلدی برای به روزرسانی وجود ندارد
//       if (updateFields.length === 0) {
//         return res.json({ success: true, message: "تغییری اعمال نشد" });
//       }

//       // ساخت و اجرای کوئری
//       updateValues.push(studentId);
//       const query = `UPDATE students SET ${updateFields.join(", ")} WHERE id = ?`;

//       console.log("Query:", query);
//       console.log("Values:", updateValues);

//       await db.execute(query, updateValues);

//       // دریافت اطلاعات به روز شده
//       const [updated] = await db.execute(
//         `SELECT * FROM students WHERE id = ?`,
//         [studentId],
//       );

//       // فرمت تاریخ‌ها
//       if (updated[0].due_date) {
//         const d = new Date(updated[0].due_date);
//         if (!isNaN(d.getTime()))
//           updated[0].due_date = d.toISOString().split("T")[0];
//       }
//       if (updated[0].registration_date) {
//         const d = new Date(updated[0].registration_date);
//         if (!isNaN(d.getTime()))
//           updated[0].registration_date = d.toISOString().split("T")[0];
//       }

//       res.json({
//         success: true,
//         message: "اطلاعات با موفقیت به‌روز شد",
//         student: updated[0],
//       });
//     } catch (err) {
//       console.error("Error in PUT /api/students/:id:", err);
//       res.status(500).json({
//         error: err.message,
//         code: err.code,
//         sqlMessage: err.sqlMessage,
//       });
//     }
//   },
// );

//

app.put(
  "/api/students/:id",
  authenticate,
  upload.single("photo"),
  async (req, res) => {
    try {
      const studentId = req.params.id;
      const updates = req.body;

      const [existing] = await db.execute(
        `SELECT id FROM students WHERE id = ?`,
        [studentId],
      );
      if (existing.length === 0) {
        return res.status(404).json({ error: "شاگرد یافت نشد" });
      }

      const updateFields = [];
      const updateValues = [];

      if (updates.name !== undefined) {
        updateFields.push("name = ?");
        updateValues.push(updates.name || null);
      }
      if (updates.father_name !== undefined) {
        updateFields.push("father_name = ?");
        updateValues.push(toNull(updates.father_name));
      }
      if (updates.phone !== undefined) {
        updateFields.push("phone = ?");
        updateValues.push(toNull(updates.phone));
      }
      if (updates.class_id !== undefined) {
        updateFields.push("class_id = ?");
        updateValues.push(updates.class_id || null);
      }
      if (updates.status !== undefined) {
        updateFields.push("status = ?");
        updateValues.push(updates.status || "active");
      }
      if (updates.address !== undefined) {
        updateFields.push("address = ?");
        updateValues.push(toNull(updates.address));
      }
      if (updates.registration_date !== undefined) {
        updateFields.push("registration_date = ?");
        updateValues.push(updates.registration_date || null);
      }

      if (req.file) {
        const photoPath = `/uploads/${req.file.filename}`;
        updateFields.push("photo = ?");
        updateValues.push(photoPath);
      }

      if (updates.password && updates.password.trim()) {
        const hashed = await bcrypt.hash(updates.password, 10);
        updateFields.push("password = ?");
        updateValues.push(hashed);
      }

      if (updateFields.length === 0) {
        return res.json({ success: true, message: "تغییری اعمال نشد" });
      }

      updateValues.push(studentId);
      const query = `UPDATE students SET ${updateFields.join(", ")} WHERE id = ?`;

      await db.execute(query, updateValues);

      res.json({ success: true, message: "اطلاعات با موفقیت به‌روز شد" });
    } catch (err) {
      console.error("Error in PUT /api/students/:id:", err);
      res.status(500).json({ error: err.message });
    }
  },
);
// DELETE /api/students/:id - حذف شاگرد
app.delete("/api/students/:id", authenticate, async (req, res) => {
  if (req.user.role === "teacher") {
    return res.status(403).json({ error: "استاد نمی‌تواند شاگرد حذف کند" });
  }

  try {
    // بررسی وجود شاگرد
    const [existing] = await db.execute(
      `SELECT id FROM students WHERE id = ?`,
      [req.params.id],
    );
    if (existing.length === 0) {
      return res.status(404).json({ error: "شاگرد یافت نشد" });
    }

    // حذف پرداخت‌های مرتبط (به دلیل کلید خارجی)
    await db.execute(`DELETE FROM fee_payments WHERE student_id = ?`, [
      req.params.id,
    ]);

    // حذف شاگرد
    await db.execute(`DELETE FROM students WHERE id = ?`, [req.params.id]);

    res.json({ success: true, message: "شاگرد با موفقیت حذف شد" });
  } catch (err) {
    console.error("Error in DELETE /api/students/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API کمکی برای شاگردان ======================

// GET /api/student-fee-search - جستجوی شاگردان برای پرداخت فیس
app.get("/api/student-fee-search", authenticate, async (req, res) => {
  const { class_id, search } = req.query;
  let query = `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE 1=1`;
  let params = [];

  if (class_id) {
    query += ` AND s.class_id = ?`;
    params.push(class_id);
  }
  if (search) {
    query += ` AND s.name LIKE ?`;
    params.push(`%${search}%`);
  }

  try {
    const [results] = await db.execute(query, params);
    const formatted = results.map((s) => {
      if (s.due_date) {
        const d = new Date(s.due_date);
        if (!isNaN(d.getTime())) s.due_date = d.toISOString().split("T")[0];
      }
      return s;
    });
    res.json(formatted);
  } catch (err) {
    console.error("Error in GET /api/student-fee-search:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/student/payments/:studentId - دریافت تاریخچه پرداخت‌های شاگرد
app.get("/api/student/payments/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT * FROM fee_payments WHERE student_id = ? ORDER BY payment_date DESC`,
      [req.params.studentId],
    );
    const formatted = results.map((p) => {
      if (p.payment_date) {
        const d = new Date(p.payment_date);
        if (!isNaN(d.getTime())) p.payment_date = d.toISOString().split("T")[0];
      }
      if (p.issue_date) {
        const d = new Date(p.issue_date);
        if (!isNaN(d.getTime())) p.issue_date = d.toISOString().split("T")[0];
      }
      return p;
    });
    res.json(formatted);
  } catch (err) {
    console.error("Error in GET /api/student/payments/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/student/fees/:studentId - دریافت وضعیت فیس شاگرد
app.get("/api/student/fees/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT total_fee, paid_fee, remaining_fee, due_date FROM students WHERE id = ?`,
      [req.params.studentId],
    );
    const student = results[0] || {
      total_fee: 0,
      paid_fee: 0,
      remaining_fee: 0,
    };
    if (student.due_date) {
      const d = new Date(student.due_date);
      if (!isNaN(d.getTime())) student.due_date = d.toISOString().split("T")[0];
    }
    res.json(student);
  } catch (err) {
    console.error("Error in GET /api/student/fees/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/student/info/:studentId - دریافت اطلاعات کامل شاگرد برای پنل شاگرد
app.get("/api/student/info/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT s.*, c.class_name 
            FROM students s 
            LEFT JOIN classes c ON s.class_id = c.id 
            WHERE s.id = ?
        `,
      [req.params.studentId],
    );

    if (results.length === 0) {
      return res.status(404).json({ error: "شاگرد یافت نشد" });
    }

    const student = results[0];
    if (student.due_date) {
      const d = new Date(student.due_date);
      if (!isNaN(d.getTime())) student.due_date = d.toISOString().split("T")[0];
    }
    if (student.registration_date) {
      const d = new Date(student.registration_date);
      if (!isNaN(d.getTime()))
        student.registration_date = d.toISOString().split("T")[0];
    }

    res.json(student);
  } catch (err) {
    console.error("Error in GET /api/student/info/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/student/stats/:studentId - آمار شاگرد (حاضری و نمرات)
app.get("/api/student/stats/:studentId", authenticate, async (req, res) => {
  try {
    const [presentCount] = await db.execute(
      `SELECT COUNT(*) as count FROM attendance_details ad 
             JOIN daily_attendance da ON ad.attendance_id = da.id 
             WHERE ad.student_id = ? AND ad.status = 'present' 
             AND YEAR(da.attendance_date) = YEAR(CURDATE())`,
      [req.params.studentId],
    );

    const [absentCount] = await db.execute(
      `SELECT COUNT(*) as count FROM attendance_details ad 
             JOIN daily_attendance da ON ad.attendance_id = da.id 
             WHERE ad.student_id = ? AND ad.status = 'absent' 
             AND YEAR(da.attendance_date) = YEAR(CURDATE())`,
      [req.params.studentId],
    );

    const [lateCount] = await db.execute(
      `SELECT COUNT(*) as count FROM attendance_details ad 
             JOIN daily_attendance da ON ad.attendance_id = da.id 
             WHERE ad.student_id = ? AND ad.status = 'late' 
             AND YEAR(da.attendance_date) = YEAR(CURDATE())`,
      [req.params.studentId],
    );

    const [grades] = await db.execute(
      `SELECT AVG((score/max_score)*100) as avg_grade FROM grades WHERE student_id = ?`,
      [req.params.studentId],
    );

    res.json({
      present_count: presentCount[0]?.count || 0,
      absent_count: absentCount[0]?.count || 0,
      late_count: lateCount[0]?.count || 0,
      avg_grade: Math.round(grades[0]?.avg_grade || 0),
    });
  } catch (err) {
    console.error("Error in GET /api/student/stats/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/student/attendance/:studentId - گزارش حاضری شاگرد
app.get(
  "/api/student/attendance/:studentId",
  authenticate,
  async (req, res) => {
    const { month, year } = req.query;
    try {
      const [details] = await db.execute(
        `
            SELECT ad.status, ad.notes, da.attendance_date as date
            FROM attendance_details ad
            JOIN daily_attendance da ON ad.attendance_id = da.id
            WHERE ad.student_id = ? AND MONTH(da.attendance_date) = ? AND YEAR(da.attendance_date) = ?
        `,
        [req.params.studentId, month, year],
      );

      const present = details.filter((d) => d.status === "present").length;
      const absent = details.filter((d) => d.status === "absent").length;
      const late = details.filter((d) => d.status === "late").length;

      res.json({
        present,
        absent,
        late,
        details: details.map((d) => ({
          date: d.date ? new Date(d.date).toISOString().split("T")[0] : null,
          status: d.status,
          notes: d.notes,
        })),
      });
    } catch (err) {
      console.error("Error in GET /api/student/attendance/:studentId:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

// GET /api/student/grades/:studentId - دریافت نمرات شاگرد
app.get("/api/student/grades/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT g.*, sub.subject_name 
            FROM grades g 
            JOIN subjects sub ON g.subject_id = sub.id 
            WHERE g.student_id = ? 
            ORDER BY g.exam_date DESC
        `,
      [req.params.studentId],
    );

    const formatted = results.map((g) => {
      if (g.exam_date) {
        const d = new Date(g.exam_date);
        if (!isNaN(d.getTime())) g.exam_date = d.toISOString().split("T")[0];
      }
      return g;
    });

    res.json(formatted);
  } catch (err) {
    console.error("Error in GET /api/student/grades/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/student/update-profile/:studentId - ویرایش پروفایل شاگرد
app.put(
  "/api/student/update-profile/:studentId",
  authenticate,
  upload.single("photo"),
  async (req, res) => {
    const { name, father_name, phone, address, password } = req.body;
    let photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    let setClause = `name=?, father_name=?, phone=?, address=?`;
    let values = [name, toNull(father_name), toNull(phone), toNull(address)];

    if (photoPath) {
      setClause += `, photo=?`;
      values.push(photoPath);
    }
    if (password && password.trim()) {
      const hashed = await bcrypt.hash(password, 10);
      setClause += `, password=?`;
      values.push(hashed);
    }
    values.push(req.params.studentId);

    try {
      await db.execute(`UPDATE students SET ${setClause} WHERE id=?`, values);
      res.json({ message: "پروفایل با موفقیت به‌روز شد" });
    } catch (err) {
      console.error(
        "Error in PUT /api/student/update-profile/:studentId:",
        err,
      );
      res.status(500).json({ error: err.message });
    }
  },
);

// ====================== API کارمندان ======================

app.get("/api/employees", authenticate, async (req, res) => {
  let query =
    "SELECT id, name, father_name, phone, email, position, salary, hire_date, status, created_at FROM employees";
  if (req.user.role === "ceo")
    query += " WHERE position IN ('admin', 'teacher', 'accountant')";
  else if (req.user.role === "admin")
    query += " WHERE position IN ('teacher', 'accountant')";
  else if (req.user.role === "teacher")
    return res.status(403).json({ error: "دسترسی محدود" });
  query += " ORDER BY created_at DESC";
  try {
    const [results] = await db.execute(query);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/teachers", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      "SELECT id, name, email, phone FROM employees WHERE position = 'teacher' AND status = 'active'",
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/api/employees",
  authenticate,
  upload.single("photo"),
  async (req, res) => {
    const {
      name,
      father_name,
      phone,
      email,
      password,
      position,
      salary,
      hire_date,
    } = req.body;
    if (position === "admin" && req.user.role !== "ceo")
      return res
        .status(403)
        .json({ error: "❌ فقط ریس سیستم می‌تواند مدیر ایجاد کند" });
    const hashedPass = await bcrypt.hash(password || "123456", 10);
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    try {
      const [result] = await db.execute(
        `INSERT INTO employees (name, father_name, phone, email, password, position, salary, hire_date, photo, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
        [
          name,
          toNull(father_name),
          toNull(phone),
          email,
          hashedPass,
          position,
          toNull(salary),
          toNull(hire_date),
          toNull(photoPath),
        ],
      );
      res.json({
        id: result.insertId,
        message: `${position} با موفقیت ایجاد شد`,
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.put(
  "/api/employees/:id",
  authenticate,
  upload.single("photo"),
  async (req, res) => {
    const {
      name,
      father_name,
      phone,
      email,
      password,
      position,
      salary,
      hire_date,
      status,
    } = req.body;
    let photoPath = req.file ? `/uploads/${req.file.filename}` : null;
    let setClause = `name=?, father_name=?, phone=?, email=?, position=?, salary=?, hire_date=?, status=?`;
    let values = [
      name,
      toNull(father_name),
      toNull(phone),
      email,
      position,
      toNull(salary),
      toNull(hire_date),
      status,
    ];
    if (photoPath) {
      setClause += `, photo=?`;
      values.push(photoPath);
    }
    if (password && password.trim()) {
      const hashed = await bcrypt.hash(password, 10);
      setClause += `, password=?`;
      values.push(hashed);
    }
    values.push(req.params.id);
    try {
      await db.execute(`UPDATE employees SET ${setClause} WHERE id=?`, values);
      res.json({ message: "به‌روز شد" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.delete("/api/employees/:id", authenticate, async (req, res) => {
  if (req.user.role !== "ceo" && req.user.role !== "admin")
    return res.status(403).json({ error: "دسترسی محدود" });
  try {
    await db.execute("DELETE FROM employees WHERE id = ?", [req.params.id]);
    res.json({ message: "حذف شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API پرداخت فیس ======================

app.get("/api/student-fee-search", authenticate, async (req, res) => {
  const { class_id, search } = req.query;
  let query = `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE 1=1`;
  let params = [];
  if (class_id) {
    query += ` AND s.class_id = ?`;
    params.push(class_id);
  }
  if (search) {
    query += ` AND s.name LIKE ?`;
    params.push(`%${search}%`);
  }
  try {
    const [results] = await db.execute(query, params);
    const formatted = results.map((s) => {
      if (s.due_date) {
        const d = new Date(s.due_date);
        if (!isNaN(d.getTime())) s.due_date = d.toISOString().split("T")[0];
      }
      return s;
    });
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/student/payments/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT * FROM fee_payments WHERE student_id = ? ORDER BY payment_date DESC`,
      [req.params.studentId],
    );
    const formatted = results.map((p) => {
      if (p.payment_date) {
        const d = new Date(p.payment_date);
        if (!isNaN(d.getTime())) p.payment_date = d.toISOString().split("T")[0];
      }
      return p;
    });
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// app.post("/api/collect-fee", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, new_due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );
//     if (student.length === 0)
//       return res.status(404).json({ error: "شاگرد یافت نشد" });

//     const currentPaidFee = parseFloat(student[0].paid_fee) || 0;
//     const currentTotalFee = parseFloat(student[0].total_fee) || 0;

//     let newPaidFee = currentPaidFee + paymentAmount;
//     let newRemainingFee = currentTotalFee - newPaidFee;

//     let overPaymentNote = "";
//     if (newRemainingFee < 0) {
//       overPaymentNote = ` (مبلغ اضافه پرداختی: ${Math.abs(newRemainingFee).toLocaleString()} AFN)`;
//       newRemainingFee = 0;
//     }

//     const finalRemainingFee = newRemainingFee < 0 ? 0 : newRemainingFee;

//     let finalDueDate = student[0].due_date;
//     if (new_due_date && new_due_date !== "") {
//       finalDueDate = new_due_date;
//     } else {
//       const nextMonth = new Date();
//       nextMonth.setMonth(nextMonth.getMonth() + 1);
//       finalDueDate = nextMonth.toISOString().split("T")[0];
//     }

//     await db.execute(
//       `UPDATE students SET paid_fee = ?, remaining_fee = ?, due_date = ? WHERE id = ?`,
//       [newPaidFee, finalRemainingFee, finalDueDate, student_id],
//     );

//     const finalNotes =
//       notes && notes !== "undefined" && notes !== ""
//         ? notes + overPaymentNote
//         : overPaymentNote || null;

//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, receipt_number, notes) VALUES (?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         receipt_number,
//         finalNotes === "" ? null : finalNotes,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       total_fee: currentTotalFee,
//       paid_fee: newPaidFee,
//       remaining_fee: finalRemainingFee,
//       payment_amount: paymentAmount,
//       payment_date: paymentDate,
//       expiry_date: finalDueDate,
//       notes: finalNotes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/collect-fee:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// app.post("/api/collect-fee", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, new_due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//   const issueDate = new Date().toISOString().split("T")[0]; // تاریخ صدور = امروز

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );
//     if (student.length === 0)
//       return res.status(404).json({ error: "شاگرد یافت نشد" });

//     const currentPaidFee = parseFloat(student[0].paid_fee) || 0;
//     const currentTotalFee = parseFloat(student[0].total_fee) || 0;

//     let newPaidFee = currentPaidFee + paymentAmount;
//     let newRemainingFee = currentTotalFee - newPaidFee;

//     let overPaymentNote = "";
//     if (newRemainingFee < 0) {
//       overPaymentNote = ` (مبلغ اضافه پرداختی: ${Math.abs(newRemainingFee).toLocaleString()} AFN)`;
//       newRemainingFee = 0;
//     }

//     const finalRemainingFee = newRemainingFee < 0 ? 0 : newRemainingFee;

//     let finalDueDate = student[0].due_date;
//     if (new_due_date && new_due_date !== "") {
//       finalDueDate = new_due_date;
//     } else {
//       const nextMonth = new Date();
//       nextMonth.setMonth(nextMonth.getMonth() + 1);
//       finalDueDate = nextMonth.toISOString().split("T")[0];
//     }

//     await db.execute(
//       `UPDATE students SET paid_fee = ?, remaining_fee = ?, due_date = ? WHERE id = ?`,
//       [newPaidFee, finalRemainingFee, finalDueDate, student_id],
//     );

//     const finalNotes =
//       notes && notes !== "undefined" && notes !== ""
//         ? notes + overPaymentNote
//         : overPaymentNote || null;

//     // اضافه شدن issue_date
//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         issueDate,
//         receipt_number,
//         finalNotes === "" ? null : finalNotes,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       total_fee: currentTotalFee,
//       paid_fee: newPaidFee,
//       remaining_fee: finalRemainingFee,
//       payment_amount: paymentAmount,
//       payment_date: paymentDate,
//       issue_date: issueDate,
//       expiry_date: finalDueDate,
//       notes: finalNotes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/collect-fee:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// app.post("/api/collect-fee", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, new_due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//   const issueDate = new Date().toISOString().split("T")[0];

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );
//     if (student.length === 0)
//       return res.status(404).json({ error: "شاگرد یافت نشد" });

//     const currentPaidFee = parseFloat(student[0].paid_fee) || 0;
//     const currentTotalFee = parseFloat(student[0].total_fee) || 0;

//     let newPaidFee = currentPaidFee + paymentAmount;
//     let newRemainingFee = currentTotalFee - newPaidFee;

//     let overPaymentNote = "";
//     if (newRemainingFee < 0) {
//       overPaymentNote = ` (مبلغ اضافه پرداختی: ${Math.abs(newRemainingFee).toLocaleString()} AFN)`;
//       newRemainingFee = 0;
//     }

//     const finalRemainingFee = newRemainingFee < 0 ? 0 : newRemainingFee;

//     // محاسبه تاریخ انقضای جدید: یک ماه بعد از تاریخ پرداخت
//     // let finalDueDate = new_due_date;
//     // if (!finalDueDate || finalDueDate === "") {
//     //   const nextMonth = new Date(paymentDate);
//     //   nextMonth.setMonth(nextMonth.getMonth() + 1);
//     //   finalDueDate = nextMonth.toISOString().split("T")[0];
//     // }
//     // محاسبه تاریخ انقضای جدید: یک ماه بعد از تاریخ پرداخت
//     let finalDueDate = new_due_date;
//     if (!finalDueDate || finalDueDate === "") {
//       const nextMonth = new Date(paymentDate);
//       nextMonth.setMonth(nextMonth.getMonth() + 1);
//       finalDueDate = nextMonth.toISOString().split("T")[0];
//     }

//     await db.execute(
//       `UPDATE students SET paid_fee = ?, remaining_fee = ?, due_date = ? WHERE id = ?`,
//       [newPaidFee, finalRemainingFee, finalDueDate, student_id],
//     );

//     const finalNotes =
//       notes && notes !== "undefined" && notes !== ""
//         ? notes + overPaymentNote
//         : overPaymentNote || null;

//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         issueDate,
//         receipt_number,
//         finalNotes === "" ? null : finalNotes,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       total_fee: currentTotalFee,
//       paid_fee: newPaidFee,
//       remaining_fee: finalRemainingFee,
//       payment_amount: paymentAmount,
//       payment_date: paymentDate,
//       issue_date: issueDate,
//       expiry_date: finalDueDate,
//       notes: finalNotes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/collect-fee:", err);
//     res.status(500).json({ error: err.message });
//   }
// });
// ====================== جمع‌آوری فیس ======================
// app.post("/api/collect-fee", authenticate, async (req, res) => {
//     const { student_id, amount, payment_date, new_due_date, notes } = req.body;
//     const receipt_number = generateReceiptNumber();
//     const paymentAmount = parseFloat(amount);

//     if (isNaN(paymentAmount) || paymentAmount <= 0) {
//         return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//     }

//     const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//     const issueDate = new Date().toISOString().split("T")[0];

//     try {
//         const [student] = await db.execute(
//             `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//             [student_id]
//         );
//         if (student.length === 0) return res.status(404).json({ error: "شاگرد یافت نشد" });

//         const currentPaidFee = parseFloat(student[0].paid_fee) || 0;
//         const currentTotalFee = parseFloat(student[0].total_fee) || 0;

//         let newPaidFee = currentPaidFee + paymentAmount;
//         let newRemainingFee = currentTotalFee - newPaidFee;

//         let overPaymentNote = '';
//         if (newRemainingFee < 0) {
//             overPaymentNote = ` (مبلغ اضافه پرداختی: ${Math.abs(newRemainingFee).toLocaleString()} AFN)`;
//             newRemainingFee = 0;
//         }

//         const finalRemainingFee = newRemainingFee < 0 ? 0 : newRemainingFee;

//         // محاسبه تاریخ انقضای جدید: یک ماه بعد از تاریخ پرداخت
//         let finalDueDate = new_due_date;
//         if (!finalDueDate || finalDueDate === "") {
//             const nextMonth = new Date(paymentDate);
//             nextMonth.setMonth(nextMonth.getMonth() + 1);
//             finalDueDate = nextMonth.toISOString().split("T")[0];
//         }

//         // به‌روزرسانی اطلاعات شاگرد
//         await db.execute(
//             `UPDATE students SET paid_fee = ?, remaining_fee = ?, due_date = ? WHERE id = ?`,
//             [newPaidFee, finalRemainingFee, finalDueDate, student_id]
//         );

//         const finalNotes = (notes && notes !== "undefined" && notes !== "") ? (notes + overPaymentNote) : (overPaymentNote || null);

//         // ثبت پرداخت در جدول fee_payments
//         await db.execute(
//             `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//             [student_id, paymentAmount, paymentDate, issueDate, receipt_number, finalNotes === "" ? null : finalNotes]
//         );

//         res.json({
//             success: true,
//             receipt_number,
//             student_name: student[0].name || "",
//             student_father: student[0].father_name || "",
//             student_card_id: student[0].student_card_id || "",
//             total_fee: currentTotalFee,
//             paid_fee: newPaidFee,
//             remaining_fee: finalRemainingFee,
//             payment_amount: paymentAmount,
//             payment_date: paymentDate,
//             issue_date: issueDate,
//             expiry_date: finalDueDate,
//             notes: finalNotes || "",
//         });
//     } catch (err) {
//         console.error("Error in /api/collect-fee:", err);
//         res.status(500).json({ error: err.message });
//     }
// });

// app.post("/api/collect-fee", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, new_due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//   const issueDate = new Date().toISOString().split("T")[0];

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );
//     if (student.length === 0)
//       return res.status(404).json({ error: "شاگرد یافت نشد" });

//     const currentPaidFee = parseFloat(student[0].paid_fee) || 0;
//     const currentTotalFee = parseFloat(student[0].total_fee) || 0;

//     let newPaidFee = currentPaidFee + paymentAmount;
//     let newRemainingFee = currentTotalFee - newPaidFee;

//     let overPaymentNote = "";
//     if (newRemainingFee < 0) {
//       overPaymentNote = ` (مبلغ اضافه پرداختی: ${Math.abs(newRemainingFee).toLocaleString()} AFN)`;
//       newRemainingFee = 0;
//     }

//     const finalRemainingFee = newRemainingFee < 0 ? 0 : newRemainingFee;

//     // ========== اصلاح مهم: محاسبه تاریخ انقضای جدید ==========
//     let finalDueDate;
//     if (new_due_date && new_due_date !== "") {
//       // اگر کاربر تاریخ انقضای جدید وارد کرده، از همان استفاده کن
//       finalDueDate = new_due_date;
//     } else {
//       // در غیر این صورت، یک ماه بعد از تاریخ پرداخت
//       const nextMonth = new Date(paymentDate);
//       nextMonth.setMonth(nextMonth.getMonth() + 1);
//       finalDueDate = nextMonth.toISOString().split("T")[0];
//     }

//     console.log(
//       `📅 Updating due_date for student ${student_id}: ${finalDueDate}`,
//     );

//     // به‌روزرسانی اطلاعات شاگرد (با due_date جدید)
//     await db.execute(
//       `UPDATE students SET paid_fee = ?, remaining_fee = ?, due_date = ? WHERE id = ?`,
//       [newPaidFee, finalRemainingFee, finalDueDate, student_id],
//     );

//     const finalNotes =
//       notes && notes !== "undefined" && notes !== ""
//         ? notes + overPaymentNote
//         : overPaymentNote || null;

//     // ثبت پرداخت در جدول fee_payments
//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         issueDate,
//         receipt_number,
//         finalNotes === "" ? null : finalNotes,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       total_fee: currentTotalFee,
//       paid_fee: newPaidFee,
//       remaining_fee: finalRemainingFee,
//       payment_amount: paymentAmount,
//       payment_date: paymentDate,
//       issue_date: issueDate,
//       expiry_date: finalDueDate,
//       notes: finalNotes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/collect-fee:", err);
//     res.status(500).json({ error: err.message });
//   }
// });
// app.post("/api/collect-fee", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, new_due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//   const issueDate = new Date().toISOString().split("T")[0];

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );
//     if (student.length === 0)
//       return res.status(404).json({ error: "شاگرد یافت نشد" });

//     const currentPaidFee = parseFloat(student[0].paid_fee) || 0;
//     const currentTotalFee = parseFloat(student[0].total_fee) || 0;

//     let newPaidFee = currentPaidFee + paymentAmount;
//     let newRemainingFee = currentTotalFee - newPaidFee;

//     let overPaymentNote = "";
//     if (newRemainingFee < 0) {
//       overPaymentNote = ` (مبلغ اضافه پرداختی: ${Math.abs(newRemainingFee).toLocaleString()} AFN)`;
//       newRemainingFee = 0;
//     }

//     const finalRemainingFee = newRemainingFee < 0 ? 0 : newRemainingFee;

//     // ========== اصلاح مهم: محاسبه تاریخ انقضای جدید ==========
//     let finalDueDate;
//     if (new_due_date && new_due_date !== "") {
//       // اگر کاربر تاریخ انقضای جدید وارد کرده، از همان استفاده کن
//       finalDueDate = new_due_date;
//     } else {
//       // در غیر این صورت، یک ماه بعد از تاریخ پرداخت
//       const nextMonth = new Date(paymentDate);
//       nextMonth.setMonth(nextMonth.getMonth() + 1);
//       finalDueDate = nextMonth.toISOString().split("T")[0];
//     }

//     console.log(
//       `📅 Updating due_date for student ${student_id}: ${finalDueDate}`,
//     );

//     // به‌روزرسانی اطلاعات شاگرد (با due_date جدید)
//     await db.execute(
//       `UPDATE students SET paid_fee = ?, remaining_fee = ?, due_date = ? WHERE id = ?`,
//       [newPaidFee, finalRemainingFee, finalDueDate, student_id],
//     );

//     const finalNotes =
//       notes && notes !== "undefined" && notes !== ""
//         ? notes + overPaymentNote
//         : overPaymentNote || null;

//     // ثبت پرداخت در جدول fee_payments
//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         issueDate,
//         receipt_number,
//         finalNotes === "" ? null : finalNotes,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       total_fee: currentTotalFee,
//       paid_fee: newPaidFee,
//       remaining_fee: finalRemainingFee,
//       payment_amount: paymentAmount,
//       payment_date: paymentDate,
//       issue_date: issueDate,
//       expiry_date: finalDueDate,
//       notes: finalNotes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/collect-fee:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

app.post("/api/collect-fee", authenticate, async (req, res) => {
  const { student_id, amount, payment_date, notes } = req.body;
  const receipt_number = generateReceiptNumber();
  const paymentAmount = parseFloat(amount);

  if (isNaN(paymentAmount) || paymentAmount <= 0) {
    return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
  }

  const paymentDate = payment_date || new Date().toISOString().split("T")[0];
  const issueDate = new Date().toISOString().split("T")[0];

  try {
    const [student] = await db.execute(
      `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
      [student_id],
    );
    if (student.length === 0)
      return res.status(404).json({ error: "شاگرد یافت نشد" });

    // فقط ثبت پرداخت در جدول fee_payments (بدون به‌روزرسانی students)
    await db.execute(
      `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes) 
             VALUES (?, ?, ?, ?, ?, ?)`,
      [
        student_id,
        paymentAmount,
        paymentDate,
        issueDate,
        receipt_number,
        notes || null,
      ],
    );

    // محاسبه مجموع پرداختی شاگرد
    const [totalPaid] = await db.execute(
      `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE student_id = ?`,
      [student_id],
    );

    res.json({
      success: true,
      receipt_number,
      student_name: student[0].name || "",
      student_father: student[0].father_name || "",
      student_card_id: student[0].student_card_id || "",
      total_paid: totalPaid[0]?.total || 0,
      payment_amount: paymentAmount,
      payment_date: paymentDate,
      issue_date: issueDate,
      notes: notes || "",
    });
  } catch (err) {
    console.error("Error in /api/collect-fee:", err);
    res.status(500).json({ error: err.message });
  }
});

// app.post("/api/new-payment", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//   const issueDate = new Date().toISOString().split("T")[0]; // تاریخ صدور = امروز
//   const finalDueDate = due_date || calculateExpiryDate(paymentDate);

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );

//     if (student.length === 0) {
//       return res.status(404).json({ error: "شاگرد یافت نشد" });
//     }

//     // اضافه شدن issue_date
//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         issueDate,
//         receipt_number,
//         notes || null,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       student_phone: student[0].phone || "",
//       class_name: student[0].class_name || "",
//       amount: paymentAmount,
//       payment_date: paymentDate,
//       issue_date: issueDate,
//       due_date: finalDueDate,
//       notes: notes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/new-payment:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// function calculateExpiryDate(dateString) {
//   if (!dateString) return "";
//   let date = new Date(dateString);
//   date.setMonth(date.getMonth() + 1);
//   return date.toISOString().split("T")[0];
// }

// app.get("/api/fee-payments-history", authenticate, async (req, res) => {
//   const { start_date, end_date } = req.query;
//   let query = `SELECT fp.*, s.name as student_name, s.student_card_id, c.class_name FROM fee_payments fp JOIN students s ON fp.student_id = s.id JOIN classes c ON s.class_id = c.id WHERE 1=1`;
//   let params = [];
//   if (start_date && end_date) {
//     query += ` AND fp.payment_date BETWEEN ? AND ?`;
//     params.push(start_date, end_date);
//   }
//   query += ` ORDER BY fp.payment_date DESC`;
//   try {
//     const [results] = await db.execute(query, params);
//     const formatted = results.map((p) => {
//       if (p.payment_date) {
//         const d = new Date(p.payment_date);
//         if (!isNaN(d.getTime())) p.payment_date = d.toISOString().split("T")[0];
//       }
//       return p;
//     });
//     res.json(formatted);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// app.post("/api/new-payment", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//   const issueDate = new Date().toISOString().split("T")[0]; // تاریخ صدور = امروز
//   const finalDueDate = due_date || calculateExpiryDate(paymentDate);

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s
//              JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );

//     if (student.length === 0) {
//       return res.status(404).json({ error: "شاگرد یافت نشد" });
//     }

//     // اضافه شدن issue_date
//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         issueDate,
//         receipt_number,
//         notes || null,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       student_phone: student[0].phone || "",
//       class_name: student[0].class_name || "",
//       amount: paymentAmount,
//       payment_date: paymentDate,
//       issue_date: issueDate,
//       due_date: finalDueDate,
//       notes: notes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/new-payment:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// app.post("/api/new-payment", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//   const issueDate = new Date().toISOString().split("T")[0];

//   // محاسبه تاریخ انقضای جدید: یک ماه بعد از تاریخ پرداخت
//   let finalDueDate = due_date;
//   if (!finalDueDate || finalDueDate === "") {
//     const nextMonth = new Date(paymentDate);
//     nextMonth.setMonth(nextMonth.getMonth() + 1);
//     finalDueDate = nextMonth.toISOString().split("T")[0];
//   }

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );

//     if (student.length === 0) {
//       return res.status(404).json({ error: "شاگرد یافت نشد" });
//     }

//     // به‌روزرسانی due_date در جدول students
//     await db.execute(`UPDATE students SET due_date = ? WHERE id = ?`, [
//       finalDueDate,
//       student_id,
//     ]);

//     // ثبت پرداخت در جدول fee_payments
//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         issueDate,
//         receipt_number,
//         notes || null,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       student_phone: student[0].phone || "",
//       class_name: student[0].class_name || "",
//       amount: paymentAmount,
//       payment_date: paymentDate,
//       issue_date: issueDate,
//       due_date: finalDueDate,
//       notes: notes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/new-payment:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// app.post("/api/new-payment", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, due_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();
//   const paymentAmount = parseFloat(amount);

//   if (isNaN(paymentAmount) || paymentAmount <= 0) {
//     return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
//   }

//   const paymentDate = payment_date || new Date().toISOString().split("T")[0];
//   const issueDate = new Date().toISOString().split("T")[0];

//   // محاسبه تاریخ انقضای جدید: یک ماه بعد از تاریخ پرداخت
//   let finalDueDate = due_date;
//   if (!finalDueDate || finalDueDate === "") {
//     const nextMonth = new Date(paymentDate);
//     nextMonth.setMonth(nextMonth.getMonth() + 1);
//     finalDueDate = nextMonth.toISOString().split("T")[0];
//   }

//   try {
//     const [student] = await db.execute(
//       `SELECT s.*, c.class_name FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
//       [student_id],
//     );

//     if (student.length === 0) {
//       return res.status(404).json({ error: "شاگرد یافت نشد" });
//     }

//     // به‌روزرسانی due_date در جدول students
//     await db.execute(`UPDATE students SET due_date = ? WHERE id = ?`, [
//       finalDueDate,
//       student_id,
//     ]);

//     // ثبت پرداخت در جدول fee_payments
//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?, ?)`,
//       [
//         student_id,
//         paymentAmount,
//         paymentDate,
//         issueDate,
//         receipt_number,
//         notes || null,
//       ],
//     );

//     res.json({
//       success: true,
//       receipt_number,
//       student_name: student[0].name || "",
//       student_father: student[0].father_name || "",
//       student_card_id: student[0].student_card_id || "",
//       student_phone: student[0].phone || "",
//       class_name: student[0].class_name || "",
//       amount: paymentAmount,
//       payment_date: paymentDate,
//       issue_date: issueDate,
//       due_date: finalDueDate,
//       notes: notes || "",
//     });
//   } catch (err) {
//     console.error("Error in /api/new-payment:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

app.post("/api/new-payment", authenticate, async (req, res) => {
  const { student_id, amount, payment_date, due_date, notes } = req.body;
  const receipt_number = generateReceiptNumber();
  const paymentAmount = parseFloat(amount);

  if (isNaN(paymentAmount) || paymentAmount <= 0) {
    return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
  }

  const paymentDate = payment_date || new Date().toISOString().split("T")[0];
  const issueDate = new Date().toISOString().split("T")[0];

  let finalDueDate = due_date;
  if (!finalDueDate || finalDueDate === "") {
    const nextMonth = new Date(paymentDate);
    nextMonth.setMonth(nextMonth.getMonth() + 1);
    finalDueDate = nextMonth.toISOString().split("T")[0];
  }

  try {
    const [student] = await db.execute(
      `
            SELECT s.id, s.name, s.father_name, s.student_card_id, s.phone, c.class_name 
            FROM students s 
            JOIN classes c ON s.class_id = c.id 
            WHERE s.id = ?
        `,
      [student_id],
    );

    if (student.length === 0) {
      return res.status(404).json({ error: "شاگرد یافت نشد" });
    }

    // ثبت پرداخت در جدول fee_payments
    await db.execute(
      `INSERT INTO fee_payments (student_id, amount, payment_date, issue_date, receipt_number, notes) 
             VALUES (?, ?, ?, ?, ?, ?)`,
      [
        student_id,
        paymentAmount,
        paymentDate,
        issueDate,
        receipt_number,
        notes || null,
      ],
    );

    res.json({
      success: true,
      receipt_number,
      student_name: student[0].name || "",
      student_father: student[0].father_name || "",
      student_card_id: student[0].student_card_id || "",
      student_phone: student[0].phone || "",
      class_name: student[0].class_name || "",
      amount: paymentAmount,
      payment_date: paymentDate,
      issue_date: issueDate,
      due_date: finalDueDate,
      notes: notes || "",
    });
  } catch (err) {
    console.error("Error in /api/new-payment:", err);
    res.status(500).json({ error: err.message });
  }
});

// app.get("/api/daily-fee-stats", authenticate, async (req, res) => {
//   const { date } = req.query;
//   const targetDate = date || new Date().toISOString().split("T")[0];

//   try {
//     // دریافت تمام پرداخت‌های امروز بر اساس تاریخ صدور
//     const [payments] = await db.execute(
//       `
//             SELECT fp.*, s.name as student_name, s.father_name, s.student_card_id, c.class_name
//             FROM fee_payments fp
//             JOIN students s ON fp.student_id = s.id
//             JOIN classes c ON s.class_id = c.id
//             WHERE fp.issue_date = ?
//             ORDER BY fp.payment_date DESC
//         `,
//       [targetDate],
//     );

//     const totalToday = payments.reduce(
//       (sum, p) => sum + (parseFloat(p.amount) || 0),
//       0,
//     );
//     const uniqueStudents = new Set(payments.map((p) => p.student_id)).size;

//     res.json({
//       success: true,
//       date: targetDate,
//       total_amount: totalToday,
//       student_count: uniqueStudents,
//       payments: payments.map((p) => ({
//         id: p.id,
//         student_id: p.student_id,
//         student_name: p.student_name,
//         father_name: p.father_name,
//         student_card_id: p.student_card_id,
//         class_name: p.class_name,
//         amount: parseFloat(p.amount) || 0,
//         payment_date: p.payment_date,
//         issue_date: p.issue_date,
//         receipt_number: p.receipt_number,
//         notes: p.notes,
//       })),
//     });
//   } catch (err) {
//     console.error("Error in /api/daily-fee-stats:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// ====================== API آمار روزمره فیس با نمایش تاریخ انقضا ======================
// app.get("/api/daily-fee-stats-with-expiry", authenticate, async (req, res) => {
//   const { date } = req.query;
//   const targetDate = date || new Date().toISOString().split("T")[0];

//   console.log("Fetching daily stats for date:", targetDate);

//   try {
//     const [payments] = await db.execute(
//       `
//             SELECT
//                 fp.id,
//                 fp.student_id,
//                 fp.amount,
//                 fp.payment_date,
//                 fp.receipt_number,
//                 fp.notes,
//                 s.name as student_name,
//                 s.father_name,
//                 s.student_card_id,
//                 s.due_date as old_expiry_date,
//                 c.class_name
//             FROM fee_payments fp
//             JOIN students s ON fp.student_id = s.id
//             JOIN classes c ON s.class_id = c.id
//             WHERE DATE(fp.issue_date) = ?
//             ORDER BY fp.payment_date DESC
//         `,
//       [targetDate],
//     );

//     console.log("Payments found:", payments.length);

//     const formattedPayments = payments.map((p) => {
//       let oldExpiryDate = p.old_expiry_date;
//       if (oldExpiryDate) {
//         const d = new Date(oldExpiryDate);
//         if (!isNaN(d.getTime())) {
//           oldExpiryDate = d.toISOString().split("T")[0];
//         }
//       }

//       let paymentDate = p.payment_date;
//       if (paymentDate) {
//         const d = new Date(paymentDate);
//         if (!isNaN(d.getTime())) {
//           paymentDate = d.toISOString().split("T")[0];
//         }
//       }

//       return {
//         id: p.id,
//         student_id: p.student_id,
//         student_name: p.student_name,
//         father_name: p.father_name,
//         student_card_id: p.student_card_id,
//         class_name: p.class_name,
//         amount: parseFloat(p.amount) || 0,
//         payment_date: paymentDate,
//         old_expiry_date: oldExpiryDate,
//         receipt_number: p.receipt_number,
//         notes: p.notes,
//       };
//     });

//     const totalToday = formattedPayments.reduce((sum, p) => sum + p.amount, 0);
//     const uniqueStudents = new Set(formattedPayments.map((p) => p.student_id))
//       .size;

//     res.json({
//       success: true,
//       date: targetDate,
//       total_amount: totalToday,
//       student_count: uniqueStudents,
//       transaction_count: formattedPayments.length,
//       payments: formattedPayments,
//     });
//   } catch (err) {
//     console.error("Error in /api/daily-fee-stats-with-expiry:", err);
//     res.status(500).json({ error: err.message });
//   }
// });
// ====================== API آمار روزمره فیس با نمایش تاریخ انقضا ======================
app.get("/api/daily-fee-stats-with-expiry", authenticate, async (req, res) => {
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split("T")[0];

  console.log("Fetching daily stats for date:", targetDate);

  try {
    // دریافت تمام پرداخت‌های تاریخ انتخاب شده
    // تاریخ انقضا: یک ماه بعد از آخرین پرداخت هر شاگرد
    const [payments] = await db.execute(
      `
            SELECT 
                fp.id, 
                fp.student_id, 
                fp.amount, 
                fp.payment_date, 
                fp.receipt_number, 
                fp.notes,
                s.name as student_name, 
                s.father_name, 
                s.student_card_id,
                c.class_name,
                (
                    SELECT MAX(payment_date) 
                    FROM fee_payments 
                    WHERE student_id = s.id AND payment_date < fp.payment_date
                ) as previous_payment_date
            FROM fee_payments fp 
            JOIN students s ON fp.student_id = s.id 
            JOIN classes c ON s.class_id = c.id 
            WHERE DATE(fp.issue_date) = ?
            ORDER BY fp.payment_date DESC
        `,
      [targetDate],
    );

    console.log("Payments found:", payments.length);

    // محاسبه تاریخ انقضای قبلی برای هر پرداخت (یک ماه بعد از آخرین پرداخت قبلی)
    const formattedPayments = payments.map((p) => {
      let oldExpiryDate = null;
      if (p.previous_payment_date) {
        const expiryFromPrev = new Date(p.previous_payment_date);
        expiryFromPrev.setMonth(expiryFromPrev.getMonth() + 1);
        oldExpiryDate = expiryFromPrev.toISOString().split("T")[0];
      }

      let paymentDate = p.payment_date;
      if (paymentDate) {
        const d = new Date(paymentDate);
        if (!isNaN(d.getTime())) {
          paymentDate = d.toISOString().split("T")[0];
        }
      }

      return {
        id: p.id,
        student_id: p.student_id,
        student_name: p.student_name,
        father_name: p.father_name,
        student_card_id: p.student_card_id,
        class_name: p.class_name,
        amount: parseFloat(p.amount) || 0,
        payment_date: paymentDate,
        old_expiry_date: oldExpiryDate,
        receipt_number: p.receipt_number,
        notes: p.notes,
      };
    });

    const totalToday = formattedPayments.reduce((sum, p) => sum + p.amount, 0);
    const uniqueStudents = new Set(formattedPayments.map((p) => p.student_id))
      .size;

    res.json({
      success: true,
      date: targetDate,
      total_amount: totalToday,
      student_count: uniqueStudents,
      transaction_count: formattedPayments.length,
      payments: formattedPayments,
    });
  } catch (err) {
    console.error("Error in /api/daily-fee-stats-with-expiry:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/fee-payment/:id", authenticate, async (req, res) => {
  const { payment_date, notes } = req.body;
  const paymentId = req.params.id;
  try {
    const [oldPayment] = await db.execute(
      `SELECT amount, student_id FROM fee_payments WHERE id = ?`,
      [paymentId],
    );
    if (oldPayment.length === 0)
      return res.status(404).json({ error: "پرداخت یافت نشد" });

    const finalNotes =
      notes && notes !== "undefined" && notes !== "" ? notes : null;

    await db.execute(
      `UPDATE fee_payments SET payment_date = ?, notes = ? WHERE id = ?`,
      [payment_date, finalNotes, paymentId],
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Error updating payment:", err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/fee-payment/:id", authenticate, async (req, res) => {
  const { student_id, amount } = req.body;
  const paymentId = req.params.id;
  try {
    const [payment] = await db.execute(
      `SELECT amount FROM fee_payments WHERE id = ?`,
      [paymentId],
    );
    if (payment.length === 0)
      return res.status(404).json({ error: "پرداخت یافت نشد" });
    const paymentAmount = parseFloat(payment[0].amount);
    await db.execute("DELETE FROM fee_payments WHERE id = ?", [paymentId]);
    const [student] = await db.execute(
      `SELECT total_fee, paid_fee FROM students WHERE id = ?`,
      [student_id],
    );
    const newPaidFee = (parseFloat(student[0].paid_fee) || 0) - paymentAmount;
    const newRemainingFee =
      (parseFloat(student[0].total_fee) || 0) - newPaidFee;
    await db.execute(
      `UPDATE students SET paid_fee = ?, remaining_fee = ? WHERE id = ?`,
      [
        newPaidFee < 0 ? 0 : newPaidFee,
        newRemainingFee < 0 ? 0 : newRemainingFee,
        student_id,
      ],
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// app.get("/api/fee-defaulters", authenticate, async (req, res) => {
//   try {
//     const [results] = await db.execute(`
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.total_fee, s.paid_fee, s.remaining_fee, s.due_date, s.status,
//                    c.class_name
//             FROM students s
//             JOIN classes c ON s.class_id = c.id
//             WHERE s.remaining_fee > 0 AND s.status = 'active'
//             ORDER BY s.remaining_fee DESC
//         `);
//     const formatted = results.map((s) => {
//       if (s.due_date) {
//         const d = new Date(s.due_date);
//         if (!isNaN(d.getTime())) s.due_date = d.toISOString().split("T")[0];
//       }
//       return s;
//     });
//     res.json(formatted);
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

app.get("/api/fee-defaulters", authenticate, async (req, res) => {
  try {
    // شاگردانی که در fee_payments آخرین پرداخت آنها منقضی شده یا بدهی دارند
    const [results] = await db.execute(`
            SELECT DISTINCT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id, 
                   s.status, c.class_name,
                   COALESCE(SUM(fp.amount), 0) as total_paid,
                   MAX(fp.payment_date) as last_payment_date
            FROM students s 
            JOIN classes c ON s.class_id = c.id 
            LEFT JOIN fee_payments fp ON s.id = fp.student_id
            WHERE s.status = 'active'
            GROUP BY s.id
            HAVING total_paid < 5000  -- این مقدار باید از تنظیمات یا محاسبه شود
            ORDER BY last_payment_date ASC
        `);

    res.json(results);
  } catch (err) {
    console.error("Error in /api/fee-defaulters:", err);
    res.status(500).json({ error: err.message });
  }
});

// app.get("/api/fee-expired", authenticate, async (req, res) => {
//   try {
//     const [results] = await db.execute(`
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.total_fee, s.paid_fee, s.remaining_fee, s.due_date, s.status,
//                    c.class_name
//             FROM students s
//             JOIN classes c ON s.class_id = c.id
//             WHERE s.due_date IS NOT NULL
//               AND s.due_date < CURDATE()
//               AND s.remaining_fee > 0
//               AND s.status = 'active'
//             ORDER BY s.due_date ASC
//         `);

//     const formatted = results.map((s) => {
//       if (s.due_date) {
//         const d = new Date(s.due_date);
//         if (!isNaN(d.getTime())) {
//           s.due_date = d.toISOString().split("T")[0];
//         }
//       }
//       return s;
//     });
//     res.json(formatted);
//   } catch (err) {
//     console.error("Error in /api/fee-expired:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// app.get("/api/fee-expired", authenticate, async (req, res) => {
//     try {
//         // نمایش همه شاگردانی که تاریخ انقضای آنها از امروز گذشته است (صرف نظر از بدهی)
//         const [results] = await db.execute(`
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.total_fee, s.paid_fee, s.remaining_fee, s.due_date, s.status,
//                    c.class_name
//             FROM students s
//             JOIN classes c ON s.class_id = c.id
//             WHERE s.due_date IS NOT NULL
//               AND s.due_date < CURDATE()
//               AND s.status = 'active'
//             ORDER BY s.due_date ASC
//         `);

//         const formatted = results.map((s) => {
//             if (s.due_date) {
//                 const d = new Date(s.due_date);
//                 if (!isNaN(d.getTime())) {
//                     s.due_date = d.toISOString().split("T")[0];
//                 }
//             }
//             return s;
//         });

//         console.log("Expired students (all):", formatted.length);
//         res.json(formatted);
//     } catch (err) {
//         console.error("Error in /api/fee-expired:", err);
//         res.status(500).json({ error: err.message });
//     }
// });
// app.get("/api/fee-expired", authenticate, async (req, res) => {
//   try {
//     // فقط بررسی تاریخ انقضا (بدون توجه به بدهی)
//     const [results] = await db.execute(`
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.total_fee, s.paid_fee, s.remaining_fee, s.due_date, s.status,
//                    c.class_name
//             FROM students s
//             JOIN classes c ON s.class_id = c.id
//             WHERE s.due_date IS NOT NULL
//               AND s.due_date < CURDATE()
//               AND s.status = 'active'
//             ORDER BY s.due_date ASC
//         `);

//     const formatted = results.map((s) => {
//       if (s.due_date) {
//         const d = new Date(s.due_date);
//         if (!isNaN(d.getTime())) {
//           s.due_date = d.toISOString().split("T")[0];
//         }
//       }
//       return s;
//     });

//     console.log("Expired students (by date only):", formatted.length);
//     res.json(formatted);
//   } catch (err) {
//     console.error("Error in /api/fee-expired:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// ====================== API منقضی شده ======================
// app.get("/api/fee-expired", authenticate, async (req, res) => {
//   try {
//     // دریافت همه شاگردانی که تاریخ انقضای آنها از امروز گذشته است
//     // صرف نظر از بدهی (حتی اگر remaining_fee = 0 باشد)
//     const [results] = await db.execute(`
//             SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
//                    s.total_fee, s.paid_fee, s.remaining_fee, s.due_date, s.status,
//                    c.class_name
//             FROM students s
//             JOIN classes c ON s.class_id = c.id
//             WHERE s.due_date IS NOT NULL
//               AND s.due_date < CURDATE()
//               AND s.status = 'active'
//             ORDER BY s.due_date ASC
//         `);

//     // فرمت تاریخ برای خروجی
//     const formatted = results.map((s) => {
//       if (s.due_date) {
//         const d = new Date(s.due_date);
//         if (!isNaN(d.getTime())) {
//           s.due_date = d.toISOString().split("T")[0];
//         }
//       }
//       return s;
//     });

//     console.log(`📅 Expired students found: ${formatted.length}`);
//     res.json(formatted);
//   } catch (err) {
//     console.error("Error in /api/fee-expired:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

app.get("/api/fee-expired", authenticate, async (req, res) => {
  try {
    // شاگردانی که آخرین پرداخت آنها بیش از یک ماه پیش بوده است
    const [results] = await db.execute(`
            SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id, 
                   s.status, c.class_name,
                   MAX(fp.payment_date) as last_payment_date,
                   DATE_ADD(MAX(fp.payment_date), INTERVAL 1 MONTH) as expiry_date
            FROM students s 
            JOIN classes c ON s.class_id = c.id 
            LEFT JOIN fee_payments fp ON s.id = fp.student_id
            WHERE s.status = 'active'
            GROUP BY s.id
            HAVING expiry_date < CURDATE() OR last_payment_date IS NULL
            ORDER BY expiry_date ASC
        `);

    const formatted = results.map((s) => {
      if (s.expiry_date) {
        const d = new Date(s.expiry_date);
        if (!isNaN(d.getTime())) s.expiry_date = d.toISOString().split("T")[0];
      }
      return s;
    });

    res.json(formatted);
  } catch (err) {
    console.error("Error in /api/fee-expired:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API تخصیص استاد ======================

app.get("/api/teacher-classes", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT tc.*, e.name as teacher_name, c.class_name FROM teacher_classes tc JOIN employees e ON tc.teacher_id = e.id JOIN classes c ON tc.class_id = c.id`,
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/api/assign-teacher-to-class",
  authenticate,
  isAdminOrCEO,
  async (req, res) => {
    const { teacher_id, class_id, subject_id, academic_year, is_main_teacher } =
      req.body;
    try {
      const [classResult] = await db.execute(
        `SELECT id FROM classes WHERE id = ? AND is_active = 1`,
        [class_id],
      );
      if (classResult.length === 0)
        return res
          .status(404)
          .json({ error: "صنف مورد نظر وجود ندارد یا غیرفعال است" });
      const [teacherResult] = await db.execute(
        `SELECT id FROM employees WHERE id = ? AND position = 'teacher' AND status = 'active'`,
        [teacher_id],
      );
      if (teacherResult.length === 0)
        return res
          .status(404)
          .json({ error: "استاد مورد نظر وجود ندارد یا غیرفعال است" });
      await db.execute(
        `INSERT INTO teacher_classes (teacher_id, class_id, subject_id, academic_year, is_main_teacher) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE subject_id = VALUES(subject_id), is_main_teacher = VALUES(is_main_teacher)`,
        [
          teacher_id,
          class_id,
          toNull(subject_id),
          academic_year || "1404",
          is_main_teacher || false,
        ],
      );
      res.json({
        success: true,
        message: "استاد با موفقیت به صنف تخصیص داده شد",
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.delete(
  "/api/teacher-classes/:id",
  authenticate,
  isAdminOrCEO,
  async (req, res) => {
    try {
      await db.execute("DELETE FROM teacher_classes WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// ====================== API دروس ======================

app.get("/api/subjects", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      "SELECT * FROM subjects WHERE is_active = 1",
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/class-subjects/:classId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT DISTINCT s.*, tc.subject_id 
            FROM subjects s 
            JOIN teacher_classes tc ON s.id = tc.subject_id 
            WHERE tc.class_id = ? AND s.is_active = 1
        `,
      [req.params.classId],
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API استاد ======================

app.get("/api/teacher/info/:teacherId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      "SELECT id, name, father_name, phone, email, photo FROM employees WHERE id = ?",
      [req.params.teacherId],
    );
    res.json(results[0] || {});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/teacher/classes/:teacherId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT c.*, tc.subject_id, s.subject_name 
            FROM classes c 
            JOIN teacher_classes tc ON c.id = tc.class_id 
            LEFT JOIN subjects s ON tc.subject_id = s.id
            WHERE tc.teacher_id = ? AND c.is_active = 1
        `,
      [req.params.teacherId],
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/teacher/students/:teacherId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT DISTINCT s.*, c.class_name, s.due_date, s.remaining_fee 
            FROM students s 
            JOIN classes c ON s.class_id = c.id 
            JOIN teacher_classes tc ON c.id = tc.class_id 
            WHERE tc.teacher_id = ? AND s.status = 'active'
        `,
      [req.params.teacherId],
    );

    const formatted = results.map((s) => {
      if (s.due_date) {
        const d = new Date(s.due_date);
        if (!isNaN(d.getTime())) s.due_date = d.toISOString().split("T")[0];
      }
      return s;
    });
    res.json(formatted);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/teacher/save-attendance", authenticate, async (req, res) => {
  const { teacher_id, class_id, date, attendance } = req.body;
  try {
    const [existing] = await db.execute(
      `SELECT id FROM daily_attendance WHERE teacher_id = ? AND class_id = ? AND attendance_date = ?`,
      [teacher_id, class_id, date],
    );
    if (existing.length > 0) {
      await db.execute(
        `DELETE FROM attendance_details WHERE attendance_id = ?`,
        [existing[0].id],
      );
      await db.execute(`DELETE FROM daily_attendance WHERE id = ?`, [
        existing[0].id,
      ]);
    }
    const [result] = await db.execute(
      `INSERT INTO daily_attendance (teacher_id, class_id, attendance_date) VALUES (?, ?, ?)`,
      [teacher_id, class_id, date],
    );
    const attId = result.insertId;
    for (const a of attendance) {
      await db.execute(
        `INSERT INTO attendance_details (attendance_id, student_id, status, notes) VALUES (?, ?, ?, ?)`,
        [attId, a.student_id, a.status, toNull(a.notes)],
      );
    }
    res.json({ success: true, message: "حاضری با موفقیت ثبت شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/attendance/class/:classId", authenticate, async (req, res) => {
  const { classId } = req.params;
  const { date } = req.query;
  try {
    const [results] = await db.execute(
      `
            SELECT da.id, da.attendance_date, ad.student_id, ad.status, ad.notes, s.name, s.father_name 
            FROM daily_attendance da 
            JOIN attendance_details ad ON da.id = ad.attendance_id 
            JOIN students s ON ad.student_id = s.id 
            WHERE da.class_id = ? AND da.attendance_date = ?
        `,
      [classId, date],
    );
    res.json({ exists: results.length > 0, details: results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API تنظیمات ======================

app.get("/api/settings", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      "SELECT setting_key, setting_value FROM system_settings",
    );
    const settings = {};
    results.forEach((r) => {
      settings[r.setting_key] = r.setting_value;
    });
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/settings", authenticate, isAdminOrCEO, async (req, res) => {
  const {
    institute_name,
    institute_tagline,
    institute_phone,
    institute_email,
    institute_address,
    academic_year,
  } = req.body;
  try {
    const updates = [
      { key: "institute_name", value: institute_name },
      { key: "institute_tagline", value: institute_tagline },
      { key: "institute_phone", value: institute_phone },
      { key: "institute_email", value: institute_email },
      { key: "institute_address", value: institute_address },
      { key: "academic_year", value: academic_year },
    ];

    for (const item of updates) {
      if (item.value) {
        await db.execute(
          `INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?) 
                     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
          [item.key, item.value],
        );
      }
    }

    res.json({ success: true, message: "تنظیمات با موفقیت ذخیره شد" });
  } catch (err) {
    console.error("Error in POST /api/settings:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/settings/fee", authenticate, isAdminOrCEO, async (req, res) => {
  const { fee_warning_days, late_fee_percent, card_id_prefix } = req.body;
  try {
    const updates = [
      { key: "fee_warning_days", value: fee_warning_days },
      { key: "late_fee_percent", value: late_fee_percent },
      { key: "card_id_prefix", value: card_id_prefix },
    ];

    for (const item of updates) {
      if (item.value !== undefined) {
        await db.execute(
          `INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?) 
                     ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
          [item.key, item.value.toString()],
        );
      }
    }

    res.json({ success: true, message: "تنظیمات فیس با موفقیت ذخیره شد" });
  } catch (err) {
    console.error("Error in POST /api/settings/fee:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/change-password", authenticate, async (req, res) => {
  const { current, new: newPassword } = req.body;
  const table = req.user.role === "student" ? "students" : "employees";
  try {
    const [results] = await db.execute(
      `SELECT password FROM ${table} WHERE id = ?`,
      [req.user.id],
    );
    if (results.length === 0)
      return res.status(500).json({ error: "کاربر یافت نشد" });
    let isValid = false;
    if (results[0].password.startsWith("$2a$"))
      isValid = await bcrypt.compare(current, results[0].password);
    else isValid = current === results[0].password;
    if (!isValid) return res.status(401).json({ error: "رمز فعلی اشتباه است" });
    const hashed = await bcrypt.hash(newPassword, 10);
    await db.execute(`UPDATE ${table} SET password = ? WHERE id = ?`, [
      hashed,
      req.user.id,
    ]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== آمار داشبورد ======================

// app.get("/api/dashboard-stats", authenticate, async (req, res) => {
//   try {
//     if (req.user.role === "admin") {
//       const [students] = await db.execute(
//         `SELECT COUNT(*) as total_students FROM students WHERE status='active'`,
//       );
//       const [teachers] = await db.execute(
//         `SELECT COUNT(*) as total_teachers FROM employees WHERE position='teacher'`,
//       );
//       const [debtors] = await db.execute(
//         `SELECT COUNT(*) as total_debtors FROM students WHERE remaining_fee > 0`,
//       );
//       const [revenue] = await db.execute(
//         `SELECT COALESCE(SUM(amount),0) as monthly_revenue FROM fee_payments WHERE MONTH(payment_date)=MONTH(CURDATE())`,
//       );
//       res.json({
//         total_students: students[0]?.total_students || 0,
//         total_teachers: teachers[0]?.total_teachers || 0,
//         total_debtors: debtors[0]?.total_debtors || 0,
//         monthly_revenue: revenue[0]?.monthly_revenue || 0,
//       });
//     } else {
//       res.json({});
//     }
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// ====================== آمار داشبورد ======================
app.get("/api/dashboard-stats", authenticate, async (req, res) => {
  try {
    // تعداد شاگردان فعال
    const [students] = await db.execute(
      `SELECT COUNT(*) as total FROM students WHERE status = 'active'`,
    );

    // تعداد استادان
    const [teachers] = await db.execute(
      `SELECT COUNT(*) as total FROM employees WHERE position = 'teacher' AND status = 'active'`,
    );

    // تعداد بدهکاران (بر اساس آخرین پرداخت)
    const [debtors] = await db.execute(`
            SELECT COUNT(DISTINCT s.id) as total 
            FROM students s
            WHERE s.status = 'active'
        `);

    // درآمد ماه جاری
    const [revenue] = await db.execute(
      `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments 
             WHERE MONTH(payment_date) = MONTH(CURDATE()) AND YEAR(payment_date) = YEAR(CURDATE())`,
    );

    res.json({
      total_students: students[0]?.total || 0,
      total_teachers: teachers[0]?.total || 0,
      total_debtors: debtors[0]?.total || 0,
      monthly_revenue: revenue[0]?.total || 0,
    });
  } catch (err) {
    console.error("Error in /api/dashboard-stats:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API پرداخت جدید مستقل ======================
app.post("/api/new-payment", authenticate, async (req, res) => {
  const { student_id, amount, payment_date, due_date, notes } = req.body;
  const receipt_number = generateReceiptNumber();
  const paymentAmount = parseFloat(amount);

  if (isNaN(paymentAmount) || paymentAmount <= 0) {
    return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
  }

  const paymentDate = payment_date || new Date().toISOString().split("T")[0];
  const finalDueDate = due_date || calculateExpiryDate(paymentDate);

  try {
    const [student] = await db.execute(
      `SELECT s.*, c.class_name FROM students s 
             JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
      [student_id],
    );

    if (student.length === 0) {
      return res.status(404).json({ error: "شاگرد یافت نشد" });
    }

    // فقط ثبت پرداخت جدید در جدول fee_payments (بدون به‌روزرسانی students)
    await db.execute(
      `INSERT INTO fee_payments (student_id, amount, payment_date, receipt_number, notes) 
             VALUES (?, ?, ?, ?, ?)`,
      [student_id, paymentAmount, paymentDate, receipt_number, notes || null],
    );

    res.json({
      success: true,
      receipt_number,
      student_name: student[0].name || "",
      student_father: student[0].father_name || "",
      student_card_id: student[0].student_card_id || "",
      student_phone: student[0].phone || "",
      class_name: student[0].class_name || "",
      amount: paymentAmount,
      payment_date: paymentDate,
      due_date: finalDueDate,
      notes: notes || "",
      issue_date: new Date().toISOString().split("T")[0],
    });
  } catch (err) {
    console.error("Error in /api/new-payment:", err);
    res.status(500).json({ error: err.message });
  }
});

function calculateExpiryDate(dateString) {
  if (!dateString) return "";
  let date = new Date(dateString);
  date.setMonth(date.getMonth() + 1);
  return date.toISOString().split("T")[0];
}

// ورود شاگرد با آیدی کارت
app.post("/api/student-login-with-card", async (req, res) => {
  const { student_card_id } = req.body;
  try {
    const [results] = await db.execute(
      `SELECT * FROM students WHERE student_card_id = ? AND status = 'active'`,
      [student_card_id],
    );
    if (results.length === 0) {
      return res
        .status(401)
        .json({ error: "آیدی کارت معتبر نیست یا حساب غیرفعال است" });
    }
    const user = results[0];
    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        role: "student",
        student_card_id: user.student_card_id,
      },
      JWT_SECRET,
      { expiresIn: "24h" },
    );
    res.cookie("token", token, { httpOnly: true, maxAge: 24 * 60 * 60 * 1000 });
    res.json({
      success: true,
      redirectUrl: "/student/dashboard.html",
      user: { id: user.id, name: user.name },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "خطای سرور" });
  }
});

// // ====================== API گزارش فیس روزانه ======================

// // دریافت جمع فیس روزانه در یک بازه زمانی
// app.get("/api/daily-fee-summary", authenticate, async (req, res) => {
//   const { start_date, end_date } = req.query;
//   let query = `
//         SELECT
//             DATE(payment_date) as date,
//             COUNT(*) as payment_count,
//             SUM(amount) as total_amount
//         FROM fee_payments
//         WHERE 1=1
//     `;
//   let params = [];

//   if (start_date && end_date) {
//     query += ` AND payment_date BETWEEN ? AND ?`;
//     params.push(start_date, end_date);
//   }

//   query += ` GROUP BY DATE(payment_date) ORDER BY date DESC`;

//   try {
//     const [results] = await db.execute(query, params);
//     res.json(results);
//   } catch (err) {
//     console.error("Error in /api/daily-fee-summary:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// // دریافت جمع فیس امروز
// app.get("/api/today-fee", authenticate, async (req, res) => {
//   const today = new Date().toISOString().split("T")[0];
//   try {
//     const [results] = await db.execute(
//       `SELECT COALESCE(SUM(amount),0) as today_total, COUNT(*) as today_count
//              FROM fee_payments WHERE payment_date = ?`,
//       [today],
//     );
//     res.json({
//       today_total: results[0]?.today_total || 0,
//       today_count: results[0]?.today_count || 0,
//       date: today,
//     });
//   } catch (err) {
//     console.error("Error in /api/today-fee:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// ====================== API آمار روزانه بر اساس تاریخ صدور ======================

// دریافت جمع فیس امروز (بر اساس payment_date)
app.get("/api/today-fee", authenticate, async (req, res) => {
  const today = new Date().toISOString().split("T")[0];
  try {
    const [results] = await db.execute(
      `SELECT COALESCE(SUM(amount),0) as today_total, 
                    COUNT(*) as today_count 
             FROM fee_payments 
             WHERE payment_date = ?`,
      [today],
    );
    res.json({
      today_total: results[0]?.today_total || 0,
      today_count: results[0]?.today_count || 0,
      date: today,
    });
  } catch (err) {
    console.error("Error in /api/today-fee:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت جمع فیس در بازه زمانی (بر اساس payment_date)
app.get("/api/daily-fee-summary", authenticate, async (req, res) => {
  const { start_date, end_date } = req.query;
  let query = `
        SELECT 
            DATE(payment_date) as date,
            COUNT(*) as payment_count,
            SUM(amount) as total_amount
        FROM fee_payments
        WHERE 1=1
    `;
  let params = [];

  if (start_date && end_date) {
    query += ` AND payment_date BETWEEN ? AND ?`;
    params.push(start_date, end_date);
  }

  query += ` GROUP BY DATE(payment_date) ORDER BY date DESC`;

  try {
    const [results] = await db.execute(query, params);

    // فرمت تاریخ برای خروجی
    const formatted = results.map((r) => ({
      ...r,
      date: r.date ? new Date(r.date).toISOString().split("T")[0] : null,
    }));

    res.json(formatted);
  } catch (err) {
    console.error("Error in /api/daily-fee-summary:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت جزئیات تراکنش‌های یک روز خاص
app.get("/api/daily-fee-details", authenticate, async (req, res) => {
  const { date } = req.query;
  if (!date) {
    return res.status(400).json({ error: "تاریخ مشخص نشده است" });
  }

  try {
    const [results] = await db.execute(
      `SELECT fp.*, s.name as student_name, s.father_name, s.student_card_id, c.class_name 
             FROM fee_payments fp 
             JOIN students s ON fp.student_id = s.id 
             JOIN classes c ON s.class_id = c.id 
             WHERE fp.payment_date = ?
             ORDER BY fp.id DESC`,
      [date],
    );

    const formatted = results.map((p) => {
      if (p.payment_date) {
        const d = new Date(p.payment_date);
        if (!isNaN(d.getTime())) p.payment_date = d.toISOString().split("T")[0];
      }
      return p;
    });

    res.json(formatted);
  } catch (err) {
    console.error("Error in /api/daily-fee-details:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API آمار روزمره فیس ======================
app.get("/api/daily-fee-stats", authenticate, async (req, res) => {
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split("T")[0];

  try {
    // دریافت تمام پرداخت‌های امروز
    const [payments] = await db.execute(
      `
            SELECT fp.*, s.name as student_name, s.father_name, s.student_card_id, c.class_name 
            FROM fee_payments fp 
            JOIN students s ON fp.student_id = s.id 
            JOIN classes c ON s.class_id = c.id 
            WHERE fp.payment_date = ?
            ORDER BY fp.payment_date DESC
        `,
      [targetDate],
    );

    // محاسبه مجموع امروز
    const totalToday = payments.reduce(
      (sum, p) => sum + (parseFloat(p.amount) || 0),
      0,
    );

    // تعداد شاگردانی که امروز پرداخت داشته‌اند
    const uniqueStudents = new Set(payments.map((p) => p.student_id)).size;

    res.json({
      success: true,
      date: targetDate,
      total_amount: totalToday,
      student_count: uniqueStudents,
      payments: payments.map((p) => ({
        id: p.id,
        student_id: p.student_id,
        student_name: p.student_name,
        father_name: p.father_name,
        student_card_id: p.student_card_id,
        class_name: p.class_name,
        amount: parseFloat(p.amount) || 0,
        payment_date: p.payment_date,
        receipt_number: p.receipt_number,
        notes: p.notes,
      })),
    });
  } catch (err) {
    console.error("Error in /api/daily-fee-stats:", err);
    res.status(500).json({ error: err.message });
  }
});
// // ====================== API آمار روزمره فیس با نمایش تاریخ انقضا ======================
// app.get("/api/daily-fee-stats-with-expiry", authenticate, async (req, res) => {
//   const { date } = req.query;
//   // تاریخ صدور = تاریخ جاری (امروز) اگر کاربر تاریخی نفرستاده باشد
//   const targetDate = date || new Date().toISOString().split("T")[0];

//   try {
//     // دریافت تمام پرداخت‌های امروز (تاریخ صدور)
//     const [payments] = await db.execute(
//       `
//             SELECT fp.*, s.name as student_name, s.father_name, s.student_card_id,
//                    c.class_name, s.due_date as old_expiry_date
//             FROM fee_payments fp
//             JOIN students s ON fp.student_id = s.id
//             JOIN classes c ON s.class_id = c.id
//             WHERE fp.payment_date = ?
//             ORDER BY fp.payment_date DESC
//         `,
//       [targetDate],
//     );

//     // برای هر پرداخت، تاریخ انقضای قبلی شاگرد را نمایش بده
//     const formattedPayments = payments.map((p) => {
//       // تاریخ انقضای قبلی (قدیمی) - همان تاریخی که فیس منقضی شده بود
//       let oldExpiryDate = p.old_expiry_date;
//       if (oldExpiryDate) {
//         const d = new Date(oldExpiryDate);
//         if (!isNaN(d.getTime())) {
//           oldExpiryDate = d.toISOString().split("T")[0];
//         }
//       }

//       return {
//         id: p.id,
//         student_id: p.student_id,
//         student_name: p.student_name,
//         father_name: p.father_name,
//         student_card_id: p.student_card_id,
//         class_name: p.class_name,
//         amount: parseFloat(p.amount) || 0,
//         payment_date: p.payment_date, // تاریخ صدور (امروز)
//         old_expiry_date: oldExpiryDate, // تاریخ انقضای قبلی (تاریخی که فیس منقضی شده بود)
//         receipt_number: p.receipt_number,
//         notes: p.notes,
//       };
//     });

//     // محاسبه مجموع امروز
//     const totalToday = formattedPayments.reduce((sum, p) => sum + p.amount, 0);

//     // تعداد شاگردانی که امروز پرداخت داشته‌اند
//     const uniqueStudents = new Set(formattedPayments.map((p) => p.student_id))
//       .size;

//     res.json({
//       success: true,
//       date: targetDate, // تاریخ صدور (امروز)
//       total_amount: totalToday,
//       student_count: uniqueStudents,
//       transaction_count: formattedPayments.length,
//       payments: formattedPayments,
//     });
//   } catch (err) {
//     console.error("Error in /api/daily-fee-stats-with-expiry:", err);
//     res.status(500).json({ error: err.message });
//   }
// });

// ====================== API آمار روزمره فیس با نمایش تاریخ انقضا ======================
app.get("/api/daily-fee-stats-with-expiry", authenticate, async (req, res) => {
  const { date } = req.query;
  // تاریخ صدور = تاریخ جاری (امروز) اگر کاربر تاریخی نفرستاده باشد
  const targetDate = date || new Date().toISOString().split("T")[0];

  console.log("Fetching daily stats for date:", targetDate);

  try {
    // دریافت تمام پرداخت‌های امروز (تاریخ صدور)
    // توجه: در دیتابیس payment_date ممکن است با فرمت DATE ذخیره شده باشد
    const [payments] = await db.execute(
      `
            SELECT 
                fp.id, 
                fp.student_id, 
                fp.amount, 
                fp.payment_date, 
                fp.receipt_number, 
                fp.notes,
                s.name as student_name, 
                s.father_name, 
                s.student_card_id, 
                s.due_date as old_expiry_date,
                c.class_name
            FROM fee_payments fp 
            JOIN students s ON fp.student_id = s.id 
            JOIN classes c ON s.class_id = c.id 
            WHERE DATE(fp.payment_date) = ?
            ORDER BY fp.payment_date DESC
        `,
      [targetDate],
    );

    console.log("Payments found:", payments.length);

    // برای هر پرداخت، تاریخ انقضای قبلی شاگرد را نمایش بده
    const formattedPayments = payments.map((p) => {
      // تاریخ انقضای قبلی (قدیمی) - همان تاریخی که فیس منقضی شده بود
      let oldExpiryDate = p.old_expiry_date;
      if (oldExpiryDate) {
        const d = new Date(oldExpiryDate);
        if (!isNaN(d.getTime())) {
          oldExpiryDate = d.toISOString().split("T")[0];
        }
      }

      // تاریخ پرداخت (تاریخ صدور)
      let paymentDate = p.payment_date;
      if (paymentDate) {
        const d = new Date(paymentDate);
        if (!isNaN(d.getTime())) {
          paymentDate = d.toISOString().split("T")[0];
        }
      }

      return {
        id: p.id,
        student_id: p.student_id,
        student_name: p.student_name,
        father_name: p.father_name,
        student_card_id: p.student_card_id,
        class_name: p.class_name,
        amount: parseFloat(p.amount) || 0,
        payment_date: paymentDate, // تاریخ صدور (امروز)
        old_expiry_date: oldExpiryDate, // تاریخ انقضای قبلی
        receipt_number: p.receipt_number,
        notes: p.notes,
      };
    });

    // محاسبه مجموع امروز
    const totalToday = formattedPayments.reduce((sum, p) => sum + p.amount, 0);

    // تعداد شاگردانی که امروز پرداخت داشته‌اند
    const uniqueStudents = new Set(formattedPayments.map((p) => p.student_id))
      .size;

    res.json({
      success: true,
      date: targetDate,
      total_amount: totalToday,
      student_count: uniqueStudents,
      transaction_count: formattedPayments.length,
      payments: formattedPayments,
    });
  } catch (err) {
    console.error("Error in /api/daily-fee-stats-with-expiry:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/issue-dates - دریافت لیست تاریخ‌های صدور موجود
app.get("/api/issue-dates", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT DISTINCT DATE(issue_date) as issue_date 
            FROM fee_payments 
            WHERE issue_date IS NOT NULL 
            ORDER BY issue_date DESC
        `);

    const dates = results.map((r) => r.issue_date).filter((d) => d);

    res.json({
      success: true,
      dates: dates,
    });
  } catch (err) {
    console.error("Error in GET /api/issue-dates:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== خلاصه مالی ======================
app.get("/api/financial-summary", authenticate, async (req, res) => {
  const { start_date, end_date, period } = req.query;

  try {
    let total_income = 0;
    let total_expense = 0;
    let transaction_count = 0;

    if (period === "monthly") {
      // درآمد این ماه
      const [income] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments 
                 WHERE MONTH(payment_date) = MONTH(CURDATE()) AND YEAR(payment_date) = YEAR(CURDATE())`,
      );
      total_income = income[0]?.total || 0;

      // هزینه این ماه
      const [expense] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM expenses 
                 WHERE MONTH(expense_date) = MONTH(CURDATE()) AND YEAR(expense_date) = YEAR(CURDATE())`,
      );
      total_expense = expense[0]?.total || 0;

      // تعداد تراکنش‌ها
      const [count] = await db.execute(
        `SELECT COUNT(*) as cnt FROM fee_payments 
                 WHERE MONTH(payment_date) = MONTH(CURDATE()) AND YEAR(payment_date) = YEAR(CURDATE())`,
      );
      transaction_count = count[0]?.cnt || 0;
    } else if (period === "yearly") {
      // درآمد امسال
      const [income] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments 
                 WHERE YEAR(payment_date) = YEAR(CURDATE())`,
      );
      total_income = income[0]?.total || 0;

      // هزینه امسال
      const [expense] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM expenses 
                 WHERE YEAR(expense_date) = YEAR(CURDATE())`,
      );
      total_expense = expense[0]?.total || 0;

      // تعداد تراکنش‌ها
      const [count] = await db.execute(
        `SELECT COUNT(*) as cnt FROM fee_payments 
                 WHERE YEAR(payment_date) = YEAR(CURDATE())`,
      );
      transaction_count = count[0]?.cnt || 0;
    } else if (start_date && end_date) {
      // بازه دلخواه
      const [income] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments 
                 WHERE payment_date BETWEEN ? AND ?`,
        [start_date, end_date],
      );
      total_income = income[0]?.total || 0;

      const [expense] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM expenses 
                 WHERE expense_date BETWEEN ? AND ?`,
        [start_date, end_date],
      );
      total_expense = expense[0]?.total || 0;

      const [count] = await db.execute(
        `SELECT COUNT(*) as cnt FROM fee_payments 
                 WHERE payment_date BETWEEN ? AND ?`,
        [start_date, end_date],
      );
      transaction_count = count[0]?.cnt || 0;
    }

    res.json({
      total_income,
      total_expense,
      net_profit: total_income - total_expense,
      transaction_count,
    });
  } catch (err) {
    console.error("Error in /api/financial-summary:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== گزارش مالی ======================
app.get("/api/financial-reports", authenticate, async (req, res) => {
  const { period, start_date, end_date } = req.query;
  let periods = [],
    incomes = [],
    expenses = [];

  try {
    if (period === "daily") {
      // 7 روز اخیر
      for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split("T")[0];
        periods.push(dateStr);

        const [income] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE payment_date = ?`,
          [dateStr],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE expense_date = ?`,
          [dateStr],
        );
        incomes.push(income[0]?.total || 0);
        expenses.push(expense[0]?.total || 0);
      }
    } else if (period === "monthly") {
      // 12 ماه اخیر
      for (let i = 11; i >= 0; i--) {
        const date = new Date();
        date.setMonth(date.getMonth() - i);
        const monthStr = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}`;
        periods.push(monthStr);

        const startDate = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-01`;
        const endDate = new Date(date.getFullYear(), date.getMonth() + 1, 0)
          .toISOString()
          .split("T")[0];

        const [income] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE payment_date BETWEEN ? AND ?`,
          [startDate, endDate],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE expense_date BETWEEN ? AND ?`,
          [startDate, endDate],
        );
        incomes.push(income[0]?.total || 0);
        expenses.push(expense[0]?.total || 0);
      }
    } else if (period === "yearly") {
      // 5 سال اخیر
      const currentYear = new Date().getFullYear();
      for (let i = 4; i >= 0; i--) {
        const year = currentYear - i;
        periods.push(year.toString());

        const startDate = `${year}-01-01`;
        const endDate = `${year}-12-31`;

        const [income] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE payment_date BETWEEN ? AND ?`,
          [startDate, endDate],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE expense_date BETWEEN ? AND ?`,
          [startDate, endDate],
        );
        incomes.push(income[0]?.total || 0);
        expenses.push(expense[0]?.total || 0);
      }
    } else if (start_date && end_date) {
      // بازه دلخواه
      let current = new Date(start_date);
      const end = new Date(end_date);

      while (current <= end) {
        const dateStr = current.toISOString().split("T")[0];
        periods.push(dateStr);

        const [income] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE payment_date = ?`,
          [dateStr],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE expense_date = ?`,
          [dateStr],
        );
        incomes.push(income[0]?.total || 0);
        expenses.push(expense[0]?.total || 0);

        current.setDate(current.getDate() + 1);
      }
    }

    const total_income = incomes.reduce((a, b) => a + b, 0);
    const total_expense = expenses.reduce((a, b) => a + b, 0);

    res.json({
      periods,
      incomes,
      expenses,
      total_income,
      total_expense,
      net_profit: total_income - total_expense,
    });
  } catch (err) {
    console.error("Error in /api/financial-reports:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== آخرین تراکنش‌ها ======================
app.get("/api/recent-transactions", authenticate, async (req, res) => {
  const { limit } = req.query;
  const limitNum = parseInt(limit) || 10;

  try {
    const [results] = await db.execute(
      `
            SELECT fp.*, s.name as student_name, s.student_card_id, c.class_name 
            FROM fee_payments fp 
            JOIN students s ON fp.student_id = s.id 
            JOIN classes c ON s.class_id = c.id 
            ORDER BY fp.payment_date DESC 
            LIMIT ?
        `,
      [limitNum],
    );

    const formatted = results.map((p) => {
      if (p.payment_date) {
        const d = new Date(p.payment_date);
        if (!isNaN(d.getTime())) p.payment_date = d.toISOString().split("T")[0];
      }
      return {
        id: p.id,
        student_id: p.student_id,
        student_name: p.student_name,
        student_card_id: p.student_card_id,
        class_name: p.class_name,
        amount: parseFloat(p.amount) || 0,
        payment_date: p.payment_date,
        receipt_number: p.receipt_number,
        notes: p.notes,
      };
    });

    res.json(formatted);
  } catch (err) {
    console.error("Error in /api/recent-transactions:", err);
    res.status(500).json({ error: err.message });
  }
});
// این API مشابه financial-summary است، فقط برای داشبورد
app.get("/api/financial-summary", authenticate, async (req, res) => {
    const { start_date, end_date, period } = req.query;
    
    try {
        let total_income = 0;
        let total_expense = 0;
        
        if (period === 'daily') {
            const today = new Date().toISOString().split('T')[0];
            const [income] = await db.execute(
                `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE payment_date = ?`,
                [today]
            );
            const [expense] = await db.execute(
                `SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE expense_date = ?`,
                [today]
            );
            total_income = income[0]?.total || 0;
            total_expense = expense[0]?.total || 0;
        } else if (start_date && end_date) {
            const [income] = await db.execute(
                `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE payment_date BETWEEN ? AND ?`,
                [start_date, end_date]
            );
            const [expense] = await db.execute(
                `SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE expense_date BETWEEN ? AND ?`,
                [start_date, end_date]
            );
            total_income = income[0]?.total || 0;
            total_expense = expense[0]?.total || 0;
        }
        
        res.json({
            total_income,
            total_expense,
            net_profit: total_income - total_expense,
            transaction_count: 0
        });
    } catch (err) {
        console.error("Error in /api/financial-summary:", err);
        res.status(500).json({ error: err.message });
    }
});
// ====================== صفحه 404 ======================
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "404.html"));
});

// ====================== شروع سرور ======================
async function startServer() {
  await connectDB();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`\n✅ سرور با موفقیت روی پورت ${PORT} اجرا شد!`);
    console.log(`🔗 آدرس لاگین: http://localhost:${PORT}/index.html`);
    console.log(`\n👤 اطلاعات ورود پیش‌فرض:`);
    console.log(`   📍 ریس سیستم: ceo@school.com / 123456`);
  });
}

startServer();
