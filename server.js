import express from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import dotenv from "dotenv";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

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

app.post("/api/student-login-with-card", async (req, res) => {
  const { student_card_id } = req.body;
  try {
    const [results] = await db.execute(
      `SELECT * FROM students WHERE student_card_id = ? AND status = 'active'`,
      [student_card_id],
    );
    if (results.length === 0)
      return res
        .status(401)
        .json({ error: "آیدی کارت معتبر نیست یا حساب غیرفعال است" });
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

// ====================== API کلاس‌ها ======================

app.get("/api/classes", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT c.*, e.name as teacher_name 
      FROM classes c 
      LEFT JOIN employees e ON c.teacher_id = e.id 
      WHERE c.is_active = 1
    `);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/classes/all", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT c.*, e.name as teacher_name 
      FROM classes c 
      LEFT JOIN employees e ON c.teacher_id = e.id 
      ORDER BY c.id
    `);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/classes/:id", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
      SELECT c.*, e.name as teacher_name 
      FROM classes c 
      LEFT JOIN employees e ON c.teacher_id = e.id 
      WHERE c.id = ?
    `,
      [req.params.id],
    );
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/classes", authenticate, isAdminOrCEO, async (req, res) => {
  const { class_name, teacher_id, start_time, is_active } = req.body;
  if (!class_name || class_name.trim() === "") {
    return res.status(400).json({ error: "نام صنف الزامی است" });
  }
  try {
    const [result] = await db.execute(
      `INSERT INTO classes (class_name, teacher_id, start_time, is_active) VALUES (?, ?, ?, ?)`,
      [
        class_name,
        teacher_id || null,
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
  const { class_name, teacher_id, start_time, is_active } = req.body;
  try {
    await db.execute(
      `UPDATE classes SET class_name=?, teacher_id=?, start_time=?, is_active=? WHERE id=?`,
      [
        class_name,
        teacher_id || null,
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
    res.json(results);
  } catch (err) {
    console.error("Error in GET /api/students:", err);
    res.status(500).json({ error: err.message });
  }
});

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
    if (results.length === 0)
      return res.status(404).json({ error: "شاگرد یافت نشد" });
    res.json(results[0]);
  } catch (err) {
    console.error("Error in GET /api/students/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

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
    let finalRegDate =
      registration_date || new Date().toISOString().split("T")[0];
    try {
      const [result] = await db.execute(
        `
      INSERT INTO students (student_card_id, name, father_name, phone, password, class_id, registration_date, status, qr_token, address, photo) 
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

app.put(
  "/api/students/:id",
  authenticate,
  upload.single("photo"),
  async (req, res) => {
    if (req.user.role !== "ceo" && req.user.role !== "admin") {
      return res
        .status(403)
        .json({ error: "فقط مدیر و ریس می‌توانند شاگرد را ویرایش کنند" });
    }
    try {
      const studentId = req.params.id;
      const updates = req.body;
      const [existing] = await db.execute(
        `SELECT id FROM students WHERE id = ?`,
        [studentId],
      );
      if (existing.length === 0)
        return res.status(404).json({ error: "شاگرد یافت نشد" });
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
        updateFields.push("photo = ?");
        updateValues.push(`/uploads/${req.file.filename}`);
      }
      if (updates.password && updates.password.trim()) {
        updateFields.push("password = ?");
        updateValues.push(await bcrypt.hash(updates.password, 10));
      }
      if (updateFields.length === 0)
        return res.json({ success: true, message: "تغییری اعمال نشد" });
      updateValues.push(studentId);
      await db.execute(
        `UPDATE students SET ${updateFields.join(", ")} WHERE id = ?`,
        updateValues,
      );
      res.json({ success: true, message: "اطلاعات با موفقیت به‌روز شد" });
    } catch (err) {
      console.error("Error in PUT /api/students/:id:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.delete("/api/students/:id", authenticate, async (req, res) => {
  if (req.user.role === "teacher")
    return res.status(403).json({ error: "استاد نمی‌تواند شاگرد حذف کند" });
  try {
    await db.execute(`DELETE FROM fee_payments WHERE student_id = ?`, [
      req.params.id,
    ]);
    await db.execute(`DELETE FROM students WHERE id = ?`, [req.params.id]);
    res.json({ success: true, message: "شاگرد با موفقیت حذف شد" });
  } catch (err) {
    console.error("Error in DELETE /api/students/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API فیس ======================

// 1. دریافت بدهکاران (بر اساس fee_payments)
// ====================== بدهکاران (بر اساس آخرین پرداخت هر شاگرد) ======================
// ====================== بدهکاران (فقط کسانی که باقی مانده > 0) ======================
// ====================== بدهکاران (فقط کسانی که باقی مانده > 0) ======================
app.get("/api/fee-debtors", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT 
        s.id,
        s.student_card_id,
        s.name,
        s.father_name,
        s.phone,
        s.class_id,
        c.class_name,
        fp.remaining_after,
        fp.total_fee,
        fp.paid_fee,
        DATE_FORMAT(fp.due_date, '%Y-%m-%d') as due_date
      FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN (
        SELECT * FROM fee_payments 
        WHERE id IN (SELECT MAX(id) FROM fee_payments GROUP BY student_id)
      ) fp ON s.id = fp.student_id
      WHERE s.status = 'active' AND fp.remaining_after > 0
      ORDER BY fp.remaining_after DESC
    `);

    res.json(results);
  } catch (err) {
    console.error("Error in /api/fee-debtors:", err);
    res.status(500).json({ error: err.message });
  }
});
// ====================== منقضی شده ======================
app.get("/api/fee-expired", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT 
        s.id,
        s.student_card_id,
        s.name,
        s.father_name,
        s.phone,
        s.class_id,
        c.class_name,
        fp.remaining_after,
        fp.total_fee,
        fp.paid_fee,
        DATE_FORMAT(fp.due_date, '%Y-%m-%d') as due_date
      FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN (
        SELECT * FROM fee_payments 
        WHERE id IN (SELECT MAX(id) FROM fee_payments GROUP BY student_id)
      ) fp ON s.id = fp.student_id
      WHERE s.status = 'active' 
        AND fp.due_date IS NOT NULL 
        AND fp.due_date < CURDATE()
        AND fp.remaining_after > 0
      ORDER BY fp.due_date ASC
    `);

    res.json(results);
  } catch (err) {
    console.error("Error in /api/fee-expired:", err);
    res.status(500).json({ error: err.message });
  }
});
// 4. جمع‌آوری فیس
// ====================== جمع‌آوری فیس ======================
// ====================== جمع‌آوری فیس ======================
// ====================== جمع‌آوری فیس ======================
app.post("/api/collect-fee", authenticate, async (req, res) => {
  const { student_id, amount, total_fee, payment_date, due_date, notes } =
    req.body;

  const paymentAmount = parseFloat(amount);
  if (isNaN(paymentAmount) || paymentAmount <= 0) {
    return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
  }

  const paymentDate = payment_date || new Date().toISOString().split("T")[0];
  const issueDate = new Date().toISOString().split("T")[0];
  const receipt_number = generateReceiptNumber();

  let finalDueDate = due_date;
  if (!finalDueDate || finalDueDate === "") {
    const nextMonth = new Date(paymentDate);
    nextMonth.setMonth(nextMonth.getMonth() + 1);
    finalDueDate = nextMonth.toISOString().split("T")[0];
  }

  try {
    // دریافت آخرین رکورد پرداخت شاگرد
    const [lastPayment] = await db.execute(
      `
      SELECT * FROM fee_payments 
      WHERE student_id = ? 
      ORDER BY id DESC 
      LIMIT 1
    `,
      [student_id],
    );

    let finalTotalFee = total_fee ? parseFloat(total_fee) : 0;
    let previousPaidFee = 0;
    let previousRemaining = 0;

    if (lastPayment.length > 0) {
      previousPaidFee = parseFloat(lastPayment[0].paid_fee) || 0;
      previousRemaining = parseFloat(lastPayment[0].remaining_after) || 0;
      if (!finalTotalFee || finalTotalFee === 0) {
        finalTotalFee = parseFloat(lastPayment[0].total_fee) || 0;
      }
    }

    // اگر فیس کل مشخص نشده، از مبلغ پرداختی استفاده کن
    if (finalTotalFee === 0) {
      finalTotalFee = paymentAmount;
    }

    const newPaidFee = previousPaidFee + paymentAmount;
    const newRemaining = finalTotalFee - newPaidFee;
    const finalRemaining = newRemaining > 0 ? newRemaining : 0;

    // ثبت پرداخت جدید
    await db.execute(
      `
      INSERT INTO fee_payments 
      (student_id, amount, total_fee, paid_fee, remaining_after, 
       payment_date, due_date, issue_date, receipt_number, notes) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
      [
        student_id,
        paymentAmount,
        finalTotalFee,
        newPaidFee,
        finalRemaining,
        paymentDate,
        finalDueDate,
        issueDate,
        receipt_number,
        notes || null,
      ],
    );

    // دریافت اطلاعات شاگرد
    const [student] = await db.execute(
      `
      SELECT s.name, s.father_name, s.student_card_id, c.class_name 
      FROM students s 
      JOIN classes c ON s.class_id = c.id 
      WHERE s.id = ?
    `,
      [student_id],
    );

    res.json({
      success: true,
      receipt_number: receipt_number,
      student_name: student[0]?.name || "",
      student_father: student[0]?.father_name || "",
      student_card_id: student[0]?.student_card_id || "",
      class_name: student[0]?.class_name || "",
      total_fee: finalTotalFee,
      paid_fee: newPaidFee,
      remaining_fee: finalRemaining,
      payment_amount: paymentAmount,
      payment_date: paymentDate,
      issue_date: issueDate,
      expiry_date: finalDueDate,
      notes: notes || "",
    });
  } catch (err) {
    console.error("Error in /api/collect-fee:", err);
    res.status(500).json({ error: err.message });
  }
});
// 5. ویرایش فیس و بدهکار (فقط ریس)
// ====================== ویرایش فیس (فقط ریس) ======================
// ====================== ویرایش فیس (فقط ریس) ======================
app.put("/api/fee-payments/:id", authenticate, isCEO, async (req, res) => {
  const {
    total_fee,
    paid_fee,
    remaining_after,
    payment_date,
    due_date,
    notes,
  } = req.body;
  const paymentId = req.params.id;

  try {
    // بررسی وجود پرداخت
    const [check] = await db.execute(
      `SELECT id FROM fee_payments WHERE id = ?`,
      [paymentId],
    );
    if (check.length === 0) {
      return res.status(404).json({ error: "پرداخت یافت نشد" });
    }

    await db.execute(
      `
      UPDATE fee_payments 
      SET total_fee = ?, 
          paid_fee = ?, 
          remaining_after = ?, 
          payment_date = ?,
          due_date = ?, 
          notes = ?
      WHERE id = ?
    `,
      [
        total_fee,
        paid_fee,
        remaining_after,
        payment_date,
        due_date,
        notes || null,
        paymentId,
      ],
    );

    res.json({
      success: true,
      message: "اطلاعات فیس با موفقیت به‌روز شد",
    });
  } catch (err) {
    console.error("❌ Error in PUT /api/fee-payments/:id:", err);
    res.status(500).json({ error: err.message });
  }
});
// ====================== API پیام‌ها ======================

app.post("/api/messages", authenticate, async (req, res) => {
  const { receiver_type, receiver_id, subject, message, reply_to_id } =
    req.body;
  const sender_type = req.user.role === "student" ? "student" : "admin";
  const sender_id = req.user.id;
  try {
    const [result] = await db.execute(
      `
      INSERT INTO messages (sender_type, sender_id, receiver_type, receiver_id, subject, message, reply_to_id) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
      [
        sender_type,
        sender_id,
        receiver_type,
        receiver_id,
        subject,
        message,
        reply_to_id || null,
      ],
    );
    res.json({
      success: true,
      id: result.insertId,
      message: "پیام با موفقیت ارسال شد",
    });
  } catch (err) {
    console.error("Error in POST /api/messages:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/messages", authenticate, async (req, res) => {
  const userId = req.user.id;
  const userRole = req.user.role === "student" ? "student" : "admin";
  try {
    const [results] = await db.execute(
      `
      SELECT m.*, 
        CASE 
          WHEN m.sender_type = 'student' THEN (SELECT name FROM students WHERE id = m.sender_id)
          ELSE (SELECT name FROM employees WHERE id = m.sender_id)
        END as sender_name,
        CASE 
          WHEN m.receiver_type = 'student' THEN (SELECT name FROM students WHERE id = m.receiver_id)
          ELSE (SELECT name FROM employees WHERE id = m.receiver_id)
        END as receiver_name
      FROM messages m
      WHERE (m.sender_type = ? AND m.sender_id = ?) OR (m.receiver_type = ? AND m.receiver_id = ?)
      ORDER BY m.created_at DESC
    `,
      [userRole, userId, userRole, userId],
    );
    res.json(results);
  } catch (err) {
    console.error("Error in GET /api/messages:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/messages/:id/reply", authenticate, async (req, res) => {
  const parentId = req.params.id;
  const { message } = req.body;
  try {
    const [parent] = await db.execute(`SELECT * FROM messages WHERE id = ?`, [
      parentId,
    ]);
    if (parent.length === 0)
      return res.status(404).json({ error: "پیام اصلی یافت نشد" });
    await db.execute(
      `
      INSERT INTO messages (sender_type, sender_id, receiver_type, receiver_id, subject, message, reply_to_id) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
      [
        req.user.role === "student" ? "student" : "admin",
        req.user.id,
        parent[0].sender_type,
        parent[0].sender_id,
        `پاسخ: ${parent[0].subject}`,
        message,
        parentId,
      ],
    );
    await db.execute(`UPDATE messages SET status = 'replied' WHERE id = ?`, [
      parentId,
    ]);
    res.json({ success: true, message: "پاسخ با موفقیت ارسال شد" });
  } catch (err) {
    console.error("Error in POST /api/messages/:id/reply:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API استاد ======================

app.get("/api/teacher/info/:teacherId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT id, name, father_name, phone, email, photo FROM employees WHERE id = ?`,
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
      SELECT c.*, e.name as teacher_name 
      FROM classes c 
      JOIN employees e ON c.teacher_id = e.id 
      WHERE c.teacher_id = ? AND c.is_active = 1
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
      SELECT s.*, c.class_name
      FROM students s 
      JOIN classes c ON s.class_id = c.id 
      WHERE c.teacher_id = ? AND s.status = 'active'
    `,
      [req.params.teacherId],
    );
    res.json(results);
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

// ====================== API داشبورد ======================

app.get("/api/dashboard-stats", authenticate, async (req, res) => {
  try {
    const [students] = await db.execute(
      `SELECT COUNT(*) as total FROM students WHERE status = 'active'`,
    );
    const [teachers] = await db.execute(
      `SELECT COUNT(*) as total FROM employees WHERE position = 'teacher' AND status = 'active'`,
    );
    // بدهکاران: شاگردانی که مجموع پرداختشان کمتر از 5000 است
    const [debtors] = await db.execute(`
      SELECT COUNT(*) as total FROM (
        SELECT s.id, COALESCE(SUM(fp.amount), 0) as total_paid
        FROM students s
        LEFT JOIN fee_payments fp ON s.id = fp.student_id
        WHERE s.status = 'active'
        GROUP BY s.id
        HAVING total_paid < 5000
      ) as debtors_list
    `);
    const [revenue] = await db.execute(
      `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE MONTH(payment_date) = MONTH(CURDATE()) AND YEAR(payment_date) = YEAR(CURDATE())`,
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

app.get("/api/recent-transactions", authenticate, async (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  try {
    const [results] = await db.execute(
      `
      SELECT fp.id, fp.amount, fp.payment_date, fp.receipt_number, s.id as student_id, s.name as student_name, s.student_card_id, c.class_name
      FROM fee_payments fp 
      JOIN students s ON fp.student_id = s.id 
      JOIN classes c ON s.class_id = c.id 
      ORDER BY fp.payment_date DESC, fp.id DESC 
      LIMIT ?
    `,
      [limit],
    );
    res.json(results);
  } catch (err) {
    console.error("Error in /api/recent-transactions:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/financial-summary", authenticate, async (req, res) => {
  const { start_date, end_date, period } = req.query;
  let query = `SELECT COALESCE(SUM(amount), 0) as total_income FROM fee_payments WHERE 1=1`;
  let params = [];
  if (start_date && end_date) {
    query += ` AND payment_date BETWEEN ? AND ?`;
    params.push(start_date, end_date);
  } else if (period === "monthly") {
    query += ` AND MONTH(payment_date) = MONTH(CURDATE()) AND YEAR(payment_date) = YEAR(CURDATE())`;
  } else if (period === "yearly") {
    query += ` AND YEAR(payment_date) = YEAR(CURDATE())`;
  } else {
    query += ` AND payment_date = CURDATE()`;
  }
  try {
    const [incomeResult] = await db.execute(query, params);
    res.json({
      total_income: incomeResult[0]?.total_income || 0,
      total_expense: 0,
      transaction_count: 0,
    });
  } catch (err) {
    console.error("Error in /api/financial-summary:", err);
    res.status(500).json({ error: err.message });
  }
});

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
      `SELECT id, name, email, phone FROM employees WHERE position = 'teacher' AND status = 'active'`,
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
        `
      INSERT INTO employees (name, father_name, phone, email, password, position, salary, hire_date, photo, status) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
    `,
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
          `INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
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

// ====================== دریافت لیست تاریخ‌های صدور موجود ======================
// ====================== دریافت لیست تاریخ‌های صدور موجود ======================
// ====================== دریافت لیست تاریخ‌های صدور (issue_date) موجود ======================
app.get("/api/issue-dates", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT DISTINCT DATE(issue_date) as issue_date 
      FROM fee_payments 
      WHERE issue_date IS NOT NULL
      ORDER BY issue_date DESC
    `);

    console.log("✅ Issue dates found:", results.length);

    const dates = [];
    for (const row of results) {
      if (row.issue_date) {
        dates.push(row.issue_date);
      }
    }

    res.json({
      success: true,
      dates: dates,
    });
  } catch (err) {
    console.error("❌ Error in /api/issue-dates:", err);
    res.json({ success: true, dates: [] });
  }
});
// ====================== آمار روزمره فیس با نمایش تاریخ انقضا ======================
// ====================== آمار روزمره فیس ======================
// ====================== آمار روزمره فیس بر اساس تاریخ صدور (issue_date) ======================
app.get("/api/daily-fee-stats-with-expiry", authenticate, async (req, res) => {
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split("T")[0];

  try {
    const [payments] = await db.execute(
      `
      SELECT 
        fp.id,
        fp.student_id,
        fp.amount,
        fp.total_fee,
        fp.paid_fee,
        fp.remaining_after,
        fp.payment_date,
        fp.issue_date,
        fp.due_date,
        fp.receipt_number,
        fp.notes,
        s.name as student_name,
        s.father_name,
        s.student_card_id,
        c.class_name
      FROM fee_payments fp
      JOIN students s ON fp.student_id = s.id
      JOIN classes c ON s.class_id = c.id
      WHERE DATE(fp.issue_date) = ?
      ORDER BY fp.id DESC
    `,
      [targetDate],
    );

    console.log(
      "✅ Daily stats for issue_date",
      targetDate,
      ":",
      payments.length,
    );

    const totalToday = payments.reduce(
      (sum, p) => sum + (parseFloat(p.amount) || 0),
      0,
    );
    const uniqueStudents = new Set(payments.map((p) => p.student_id)).size;

    const formattedPayments = payments.map((p) => ({
      id: p.id,
      student_id: p.student_id,
      student_name: p.student_name,
      father_name: p.father_name,
      student_card_id: p.student_card_id,
      class_name: p.class_name,
      amount: parseFloat(p.amount) || 0,
      total_fee: parseFloat(p.total_fee) || 0,
      paid_fee: parseFloat(p.paid_fee) || 0,
      remaining_after: parseFloat(p.remaining_after) || 0,
      payment_date: p.payment_date
        ? new Date(p.payment_date).toISOString().split("T")[0]
        : null,
      issue_date: p.issue_date
        ? new Date(p.issue_date).toISOString().split("T")[0]
        : null,
      due_date: p.due_date
        ? new Date(p.due_date).toISOString().split("T")[0]
        : null,
      receipt_number: p.receipt_number,
      notes: p.notes,
    }));

    res.json({
      success: true,
      date: targetDate,
      total_amount: totalToday,
      student_count: uniqueStudents,
      transaction_count: formattedPayments.length,
      payments: formattedPayments,
    });
  } catch (err) {
    console.error("❌ Error in /api/daily-fee-stats-with-expiry:", err);
    res.status(500).json({ error: err.message });
  }
});
// ====================== دریافت تاریخچه پرداخت‌های یک شاگرد ======================
// ====================== دریافت تاریخچه پرداخت‌های یک شاگرد ======================
// ====================== دریافت تاریخچه پرداخت‌های شاگرد ======================
app.get("/api/student/payments/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
      SELECT 
        fp.id,
        fp.amount,
        fp.total_fee,
        fp.paid_fee,
        fp.remaining_after,
        fp.payment_date,
        fp.issue_date,
        fp.due_date,
        fp.receipt_number,
        fp.notes
      FROM fee_payments fp
      WHERE fp.student_id = ?
      ORDER BY fp.id DESC
    `,
      [req.params.studentId],
    );

    const formatted = results.map((p) => ({
      ...p,
      payment_date: p.payment_date
        ? new Date(p.payment_date).toISOString().split("T")[0]
        : null,
      issue_date: p.issue_date
        ? new Date(p.issue_date).toISOString().split("T")[0]
        : null,
      due_date: p.due_date
        ? new Date(p.due_date).toISOString().split("T")[0]
        : null,
    }));

    res.json(formatted);
  } catch (err) {
    console.error("❌ Error in /api/student/payments/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== تاریخچه پرداخت‌های فیس ======================
app.get("/api/fee-payments-history", authenticate, async (req, res) => {
  const { start_date, end_date, class_id } = req.query;

  let query = `
    SELECT 
      fp.id,
      fp.student_id,
      fp.amount,
      fp.total_fee,
      fp.paid_fee,
      fp.remaining_after,
      fp.payment_date,
      fp.issue_date,
      fp.due_date,
      fp.receipt_number,
      fp.notes,
      s.name as student_name,
      s.father_name,
      s.student_card_id,
      c.class_name,
      c.id as class_id
    FROM fee_payments fp
    JOIN students s ON fp.student_id = s.id
    JOIN classes c ON s.class_id = c.id
    WHERE 1=1
  `;

  let params = [];

  if (start_date && end_date) {
    query += ` AND DATE(fp.payment_date) BETWEEN ? AND ?`;
    params.push(start_date, end_date);
  }

  if (class_id && class_id !== "") {
    query += ` AND c.id = ?`;
    params.push(class_id);
  }

  query += ` ORDER BY fp.payment_date DESC, fp.id DESC`;

  try {
    const [results] = await db.execute(query, params);

    const formatted = results.map((p) => ({
      ...p,
      payment_date: p.payment_date
        ? new Date(p.payment_date).toISOString().split("T")[0]
        : null,
      issue_date: p.issue_date
        ? new Date(p.issue_date).toISOString().split("T")[0]
        : null,
      due_date: p.due_date
        ? new Date(p.due_date).toISOString().split("T")[0]
        : null,
    }));

    console.log("✅ Payment history fetched:", formatted.length);
    res.json(formatted);
  } catch (err) {
    console.error("❌ Error in /api/fee-payments-history:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== دریافت گزارش حاضری شاگرد ======================
app.get(
  "/api/student/attendance/:studentId",
  authenticate,
  async (req, res) => {
    const { month, year } = req.query;
    const studentId = req.params.studentId;

    try {
      let query = `
      SELECT 
        ad.status, 
        ad.notes, 
        da.attendance_date as date
      FROM attendance_details ad
      JOIN daily_attendance da ON ad.attendance_id = da.id
      WHERE ad.student_id = ?
    `;
      let params = [studentId];

      if (month && month !== "all") {
        query += ` AND MONTH(da.attendance_date) = ?`;
        params.push(month);
      }

      if (year) {
        query += ` AND YEAR(da.attendance_date) = ?`;
        params.push(year);
      }

      query += ` ORDER BY da.attendance_date DESC`;

      const [details] = await db.execute(query, params);

      const present = details.filter((d) => d.status === "present").length;
      const absent = details.filter((d) => d.status === "absent").length;
      const late = details.filter((d) => d.status === "late").length;

      res.json({
        present: present,
        absent: absent,
        late: late,
        details: details.map((d) => ({
          date: d.date ? new Date(d.date).toISOString().split("T")[0] : null,
          status: d.status,
          notes: d.notes,
        })),
      });
    } catch (err) {
      console.error("❌ Error in /api/student/attendance/:studentId:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

// ====================== گزارش حاضری شاگردان برای مدیر ======================
app.get("/api/attendance-report", authenticate, async (req, res) => {
  const { class_id, start_date, end_date } = req.query;

  try {
    let query = `
      SELECT 
        s.id as student_id,
        s.student_card_id,
        s.name,
        s.father_name,
        c.class_name,
        COUNT(CASE WHEN ad.status = 'present' THEN 1 END) as present_count,
        COUNT(CASE WHEN ad.status = 'absent' THEN 1 END) as absent_count,
        COUNT(CASE WHEN ad.status = 'late' THEN 1 END) as late_count,
        COUNT(*) as total_days
      FROM students s
      JOIN classes c ON s.class_id = c.id
      LEFT JOIN attendance_details ad ON s.id = ad.student_id
      LEFT JOIN daily_attendance da ON ad.attendance_id = da.id
      WHERE s.status = 'active'
    `;
    let params = [];

    if (class_id && class_id !== "") {
      query += ` AND s.class_id = ?`;
      params.push(class_id);
    }

    if (start_date && end_date) {
      query += ` AND da.attendance_date BETWEEN ? AND ?`;
      params.push(start_date, end_date);
    }

    query += ` GROUP BY s.id ORDER BY s.name`;

    const [results] = await db.execute(query, params);

    const formatted = results.map((r) => ({
      ...r,
      attendance_percent:
        r.total_days > 0
          ? ((r.present_count / r.total_days) * 100).toFixed(1)
          : 0,
    }));

    res.json(formatted);
  } catch (err) {
    console.error("❌ Error in /api/attendance-report:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== گزارش حاضری استادان ======================
app.get("/api/teacher-attendance-report", authenticate, async (req, res) => {
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split("T")[0];

  try {
    // دریافت همه استادان فعال
    const [allTeachers] = await db.execute(`
      SELECT id, name, father_name, phone, email 
      FROM employees 
      WHERE position = 'teacher' AND status = 'active'
      ORDER BY name
    `);

    // دریافت استادانی که در تاریخ مشخص حاضری گرفته‌اند
    const [attendedTeachers] = await db.execute(
      `
      SELECT DISTINCT teacher_id 
      FROM daily_attendance 
      WHERE attendance_date = ?
    `,
      [targetDate],
    );

    const attendedIds = new Set(attendedTeachers.map((t) => t.teacher_id));

    // دسته‌بندی استادان
    const teachersWithAttendance = [];
    const teachersWithoutAttendance = [];

    for (const teacher of allTeachers) {
      if (attendedIds.has(teacher.id)) {
        // دریافت کلاس‌هایی که استاد حاضری گرفته
        const [classes] = await db.execute(
          `
          SELECT DISTINCT c.id, c.class_name, c.start_time
          FROM daily_attendance da
          JOIN classes c ON da.class_id = c.id
          WHERE da.teacher_id = ? AND da.attendance_date = ?
        `,
          [teacher.id, targetDate],
        );

        teachersWithAttendance.push({
          ...teacher,
          classes: classes,
        });
      } else {
        teachersWithoutAttendance.push(teacher);
      }
    }

    res.json({
      success: true,
      date: targetDate,
      total_teachers: allTeachers.length,
      attended_count: teachersWithAttendance.length,
      not_attended_count: teachersWithoutAttendance.length,
      attended: teachersWithAttendance,
      not_attended: teachersWithoutAttendance,
    });
  } catch (err) {
    console.error("❌ Error in /api/teacher-attendance-report:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== Comprehensive Teacher Attendance Report ======================
// ====================== Comprehensive Teacher Attendance Report ======================
app.get("/api/teacher-full-attendance", authenticate, async (req, res) => {
  const { teacher_id, month, year, date, start_date, end_date } = req.query;

  try {
    const [teacherClasses] = await db.execute(
      `
      SELECT c.id, c.class_name, c.start_time
      FROM classes c
      JOIN teacher_classes tc ON c.id = tc.class_id
      WHERE tc.teacher_id = ?
    `,
      [teacher_id],
    );

    let classesAttendance = [];

    for (const cls of teacherClasses) {
      let attendanceQuery = `
        SELECT COUNT(*) as count, MAX(attendance_date) as last_attendance
        FROM daily_attendance
        WHERE teacher_id = ? AND class_id = ?
      `;
      let params = [teacher_id, cls.id];

      let studentStatsQuery = `
        SELECT 
          COUNT(DISTINCT s.id) as total_students,
          COUNT(CASE WHEN ad.status = 'present' THEN 1 END) as present_count,
          COUNT(CASE WHEN ad.status = 'absent' THEN 1 END) as absent_count,
          COUNT(CASE WHEN ad.status = 'late' THEN 1 END) as late_count
        FROM students s
        LEFT JOIN attendance_details ad ON s.id = ad.student_id
        LEFT JOIN daily_attendance da ON ad.attendance_id = da.id
        WHERE s.class_id = ? AND s.status = 'active'
      `;
      let studentParams = [cls.id];

      if (date) {
        attendanceQuery += ` AND attendance_date = ?`;
        params.push(date);
        studentStatsQuery += ` AND da.attendance_date = ?`;
        studentParams.push(date);
      } else if (start_date && end_date) {
        attendanceQuery += ` AND attendance_date BETWEEN ? AND ?`;
        params.push(start_date, end_date);
        studentStatsQuery += ` AND da.attendance_date BETWEEN ? AND ?`;
        studentParams.push(start_date, end_date);
      } else if (month && year) {
        attendanceQuery += ` AND MONTH(attendance_date) = ? AND YEAR(attendance_date) = ?`;
        params.push(month, year);
        studentStatsQuery += ` AND MONTH(da.attendance_date) = ? AND YEAR(da.attendance_date) = ?`;
        studentParams.push(month, year);
      }

      const [attendance] = await db.execute(attendanceQuery, params);
      const [studentStats] = await db.execute(studentStatsQuery, studentParams);

      classesAttendance.push({
        class_id: cls.id,
        class_name: cls.class_name,
        start_time: cls.start_time,
        has_attendance: attendance[0]?.count > 0,
        last_attendance: attendance[0]?.last_attendance,
        total_students: studentStats[0]?.total_students || 0,
        present_count: studentStats[0]?.present_count || 0,
        absent_count: studentStats[0]?.absent_count || 0,
        late_count: studentStats[0]?.late_count || 0,
        attendance_percent:
          studentStats[0]?.total_students > 0
            ? (
                (studentStats[0]?.present_count /
                  studentStats[0]?.total_students) *
                100
              ).toFixed(1)
            : 0,
      });
    }

    res.json({
      success: true,
      total_classes: teacherClasses.length,
      classes_attended: classesAttendance.filter((c) => c.has_attendance)
        .length,
      classes_not_attended: classesAttendance.filter((c) => !c.has_attendance)
        .length,
      classes: classesAttendance,
    });
  } catch (err) {
    console.error("❌ Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== Monthly Class Attendance Report ======================
app.get("/api/class-monthly-attendance", authenticate, async (req, res) => {
  const { class_id, month, year, date, start_date, end_date } = req.query;

  try {
    const [students] = await db.execute(
      `
      SELECT id, name, father_name, student_card_id
      FROM students
      WHERE class_id = ? AND status = 'active'
      ORDER BY name
    `,
      [class_id],
    );

    let attendanceQuery = `
      SELECT da.attendance_date, ad.student_id, ad.status
      FROM daily_attendance da
      JOIN attendance_details ad ON da.id = ad.attendance_id
      WHERE da.class_id = ?
    `;
    let params = [class_id];

    if (date) {
      attendanceQuery += ` AND da.attendance_date = ?`;
      params.push(date);
    } else if (start_date && end_date) {
      attendanceQuery += ` AND da.attendance_date BETWEEN ? AND ?`;
      params.push(start_date, end_date);
    } else if (month && year) {
      attendanceQuery += ` AND MONTH(da.attendance_date) = ? AND YEAR(da.attendance_date) = ?`;
      params.push(month, year);
    }

    attendanceQuery += ` ORDER BY da.attendance_date ASC`;

    const [attendanceRecords] = await db.execute(attendanceQuery, params);

    const studentStats = students.map((student) => {
      let present = 0,
        absent = 0,
        late = 0;
      for (const record of attendanceRecords) {
        if (record.student_id === student.id) {
          if (record.status === "present") present++;
          else if (record.status === "absent") absent++;
          else if (record.status === "late") late++;
        }
      }
      const total = present + absent + late;
      return {
        ...student,
        present,
        absent,
        late,
        attendance_percent:
          total > 0 ? ((present / total) * 100).toFixed(1) : 0,
      };
    });

    const datesSet = new Set();
    for (const record of attendanceRecords) {
      datesSet.add(record.attendance_date);
    }

    res.json({
      success: true,
      total_students: students.length,
      total_days: datesSet.size,
      students: studentStats,
    });
  } catch (err) {
    console.error("❌ Error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== گزارش استادان با صنف‌ها و آمار حاضری ======================
app.get("/api/teachers-classes-attendance", authenticate, async (req, res) => {
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split("T")[0];

  try {
    // دریافت همه استادان فعال
    const [teachers] = await db.execute(`
      SELECT id, name, father_name, phone, email
      FROM employees
      WHERE position = 'teacher' AND status = 'active'
      ORDER BY name
    `);

    const result = [];

    for (const teacher of teachers) {
      // دریافت صنف‌های تخصیص داده شده به این استاد
      const [classes] = await db.execute(
        `
        SELECT c.id, c.class_name, c.start_time
        FROM classes c
        JOIN teacher_classes tc ON c.id = tc.class_id
        WHERE tc.teacher_id = ? AND c.is_active = 1
        ORDER BY c.start_time
      `,
        [teacher.id],
      );

      const classDetails = [];

      for (const cls of classes) {
        // بررسی اینکه استاد در تاریخ مشخص حاضری گرفته است یا خیر
        const [attendanceCheck] = await db.execute(
          `
          SELECT COUNT(*) as has_attendance
          FROM daily_attendance
          WHERE teacher_id = ? AND class_id = ? AND attendance_date = ?
        `,
          [teacher.id, cls.id, targetDate],
        );

        // آمار حاضری شاگردان این صنف در تاریخ مشخص
        const [studentStats] = await db.execute(
          `
          SELECT 
            COUNT(DISTINCT s.id) as total_students,
            COUNT(CASE WHEN ad.status = 'present' THEN 1 END) as present_count,
            COUNT(CASE WHEN ad.status = 'absent' THEN 1 END) as absent_count,
            COUNT(CASE WHEN ad.status = 'late' THEN 1 END) as late_count
          FROM students s
          LEFT JOIN attendance_details ad ON s.id = ad.student_id
          LEFT JOIN daily_attendance da ON ad.attendance_id = da.id
          WHERE s.class_id = ? AND s.status = 'active'
            AND (da.attendance_date IS NULL OR da.attendance_date = ?)
        `,
          [cls.id, targetDate],
        );

        classDetails.push({
          class_id: cls.id,
          class_name: cls.class_name,
          start_time: cls.start_time,
          has_attendance: attendanceCheck[0]?.has_attendance > 0,
          total_students: studentStats[0]?.total_students || 0,
          present_count: studentStats[0]?.present_count || 0,
          absent_count: studentStats[0]?.absent_count || 0,
          late_count: studentStats[0]?.late_count || 0,
        });
      }

      if (classDetails.length > 0) {
        result.push({
          teacher: {
            id: teacher.id,
            name: teacher.name,
            father_name: teacher.father_name,
            phone: teacher.phone,
            email: teacher.email,
          },
          classes: classDetails,
          total_classes: classDetails.length,
          attended_classes: classDetails.filter((c) => c.has_attendance).length,
          not_attended_classes: classDetails.filter((c) => !c.has_attendance)
            .length,
        });
      }
    }

    res.json({
      success: true,
      date: targetDate,
      total_teachers: result.length,
      teachers: result,
    });
  } catch (err) {
    console.error("❌ Error in /api/teachers-classes-attendance:", err);
    res.status(500).json({ error: err.message });
  }
});
// ====================== دریافت نمرات یک شاگرد ======================
app.get("/api/student/grades/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
      SELECT 
        g.id,
        g.student_id,
        g.class_id,
        g.score,
        g.max_score,
        g.exam_type,
        g.exam_date,
        g.teacher_id,
        c.class_name
      FROM grades g
      LEFT JOIN classes c ON g.class_id = c.id
      WHERE g.student_id = ?
      ORDER BY g.exam_date DESC
    `,
      [req.params.studentId],
    );

    const formatted = results.map((g) => ({
      ...g,
      exam_date: g.exam_date
        ? new Date(g.exam_date).toISOString().split("T")[0]
        : null,
    }));

    res.json(formatted);
  } catch (err) {
    console.error("❌ Error in /api/student/grades/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== ذخیره نمره (دسترسی استاد) ======================
app.post("/api/teacher/save-grade", authenticate, async (req, res) => {
  const { student_id, class_id, score, max_score, exam_type, teacher_id } =
    req.body;

  try {
    // بررسی وجود نمره قبلی
    const [existing] = await db.execute(
      `
      SELECT id FROM grades 
      WHERE student_id = ? AND class_id = ? AND exam_type = ?
    `,
      [student_id, class_id, exam_type],
    );

    if (existing.length > 0) {
      await db.execute(
        `
        UPDATE grades 
        SET score = ?, max_score = ?, exam_date = CURDATE(), teacher_id = ?
        WHERE id = ?
      `,
        [score, max_score, teacher_id, existing[0].id],
      );
    } else {
      await db.execute(
        `
        INSERT INTO grades (student_id, class_id, score, max_score, exam_type, exam_date, teacher_id)
        VALUES (?, ?, ?, ?, ?, CURDATE(), ?)
      `,
        [student_id, class_id, score, max_score, exam_type, teacher_id],
      );
    }

    res.json({ success: true, message: "نمره با موفقیت ذخیره شد" });
  } catch (err) {
    console.error("❌ Error in /api/teacher/save-grade:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== ذخیره نمره گروهی ======================
app.post("/api/teacher/save-group-grade", authenticate, async (req, res) => {
  const { class_id, score, max_score, exam_type, teacher_id } = req.body;

  try {
    // دریافت همه شاگردان فعال صنف
    const [students] = await db.execute(
      `
      SELECT id FROM students WHERE class_id = ? AND status = 'active'
    `,
      [class_id],
    );

    let saved = 0;
    for (const student of students) {
      const [existing] = await db.execute(
        `
        SELECT id FROM grades 
        WHERE student_id = ? AND class_id = ? AND exam_type = ?
      `,
        [student.id, class_id, exam_type],
      );

      if (existing.length > 0) {
        await db.execute(
          `
          UPDATE grades 
          SET score = ?, max_score = ?, exam_date = CURDATE(), teacher_id = ?
          WHERE id = ?
        `,
          [score, max_score, teacher_id, existing[0].id],
        );
      } else {
        await db.execute(
          `
          INSERT INTO grades (student_id, class_id, score, max_score, exam_type, exam_date, teacher_id)
          VALUES (?, ?, ?, ?, ?, CURDATE(), ?)
        `,
          [student.id, class_id, score, max_score, exam_type, teacher_id],
        );
      }
      saved++;
    }

    res.json({ success: true, message: `${saved} نمره با موفقیت ذخیره شد` });
  } catch (err) {
    console.error("❌ Error in /api/teacher/save-group-grade:", err);
    res.status(500).json({ error: err.message });
  }
});
// ====================== صفحات ======================

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "404.html"));
});

// ====================== شروع سرور ======================
async function startServer() {
  await connectDB();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`\n✅ Server running on port ${PORT}`);
    console.log(`🔗 Login URL: http://localhost:${PORT}/index.html`);
  });
}

startServer();
