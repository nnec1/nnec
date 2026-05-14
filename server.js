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

// ====================== API کلاس‌ها (صنف‌ها) ======================

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

// ====================== API تخصیص استاد به صنف ======================

app.get("/api/active-classes", authenticate, async (req, res) => {
  try {
    const [classes] = await db.execute(`
      SELECT c.*, e.name as teacher_name 
      FROM classes c 
      LEFT JOIN employees e ON c.teacher_id = e.id 
      WHERE c.is_active = 1
    `);
    res.json(classes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/classes-without-teacher", authenticate, async (req, res) => {
  try {
    const [classes] = await db.execute(`
      SELECT c.* 
      FROM classes c 
      WHERE c.id NOT IN (SELECT DISTINCT class_id FROM teacher_classes) 
      AND c.is_active = 1
    `);
    res.json(classes);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/teacher-classes", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT tc.*, e.name as teacher_name, c.class_name 
      FROM teacher_classes tc 
      JOIN employees e ON tc.teacher_id = e.id 
      JOIN classes c ON tc.class_id = c.id
    `);
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
    const { teacher_id, class_id, academic_year, is_main_teacher } = req.body;
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
        `DELETE FROM teacher_classes WHERE class_id = ? AND teacher_id = ?`,
        [class_id, teacher_id],
      );
      await db.execute(
        `
      INSERT INTO teacher_classes (teacher_id, class_id, academic_year, is_main_teacher) 
      VALUES (?, ?, ?, ?)
    `,
        [
          teacher_id,
          class_id,
          academic_year || "1404",
          is_main_teacher === "true" || is_main_teacher === true ? 1 : 0,
        ],
      );
      res.json({
        success: true,
        message: "استاد با موفقیت به صنف تخصیص داده شد",
      });
    } catch (err) {
      console.error("Error in /api/assign-teacher-to-class:", err);
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
      res.json({ success: true, message: "تخصیص با موفقیت حذف شد" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

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

// ====================== API فیس و پرداخت ======================

app.get("/api/fee-debtors", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT 
        s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
        c.class_name, fp.remaining_after, fp.total_fee, fp.paid_fee,
        DATE_FORMAT(fp.due_date, '%Y-%m-%d') as due_date, fp.notes
      FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN (SELECT * FROM fee_payments WHERE id IN (SELECT MAX(id) FROM fee_payments GROUP BY student_id)) fp ON s.id = fp.student_id
      WHERE s.status = 'active' AND fp.remaining_after > 0
      ORDER BY fp.remaining_after DESC
    `);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/fee-debtors:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/fee-expired", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT 
        s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id,
        c.class_name, fp.remaining_after, fp.total_fee, fp.paid_fee,
        DATE_FORMAT(fp.due_date, '%Y-%m-%d') as due_date, fp.notes
      FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN (SELECT * FROM fee_payments WHERE id IN (SELECT MAX(id) FROM fee_payments GROUP BY student_id)) fp ON s.id = fp.student_id
      WHERE s.status = 'active' AND fp.due_date IS NOT NULL AND fp.due_date < CURDATE() AND fp.remaining_after > 0
      ORDER BY fp.due_date ASC
    `);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/fee-expired:", err);
    res.status(500).json({ error: err.message });
  }
});

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
    const [lastPayment] = await db.execute(
      `SELECT * FROM fee_payments WHERE student_id = ? ORDER BY id DESC LIMIT 1`,
      [student_id],
    );
    let finalTotalFee = total_fee ? parseFloat(total_fee) : 0;
    let previousPaidFee = 0;
    if (lastPayment.length > 0) {
      previousPaidFee = parseFloat(lastPayment[0].paid_fee) || 0;
      if (!finalTotalFee || finalTotalFee === 0) {
        finalTotalFee = parseFloat(lastPayment[0].total_fee) || 0;
      }
    }
    if (finalTotalFee === 0) finalTotalFee = paymentAmount;
    const newPaidFee = previousPaidFee + paymentAmount;
    const newRemaining = finalTotalFee - newPaidFee;
    const finalRemaining = newRemaining > 0 ? newRemaining : 0;
    await db.execute(
      `
      INSERT INTO fee_payments (student_id, amount, total_fee, paid_fee, remaining_after, payment_date, due_date, issue_date, receipt_number, notes) 
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
    const [student] = await db.execute(
      `
      SELECT s.name, s.father_name, s.student_card_id, c.class_name 
      FROM students s JOIN classes c ON s.class_id = c.id WHERE s.id = ?
    `,
      [student_id],
    );
    res.json({
      success: true,
      receipt_number,
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

app.get("/api/fee-payments-history", authenticate, async (req, res) => {
  const { start_date, end_date, class_id } = req.query;
  let query = `
    SELECT fp.id, fp.student_id, fp.amount, fp.total_fee, fp.paid_fee, fp.remaining_after,
           fp.payment_date, fp.issue_date, fp.due_date, fp.receipt_number, fp.notes,
           s.name as student_name, s.father_name, s.student_card_id, c.class_name, c.id as class_id
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
    res.json(results);
  } catch (err) {
    console.error("Error in /api/fee-payments-history:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/student/payments/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
      SELECT * FROM fee_payments WHERE student_id = ? ORDER BY id DESC
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
    console.error("Error in /api/student/payments/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/issue-dates", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT DISTINCT DATE(issue_date) as issue_date 
      FROM fee_payments WHERE issue_date IS NOT NULL ORDER BY issue_date DESC
    `);
    const dates = results.map((r) => r.issue_date).filter((d) => d);
    res.json({ success: true, dates });
  } catch (err) {
    res.json({ success: true, dates: [] });
  }
});

app.get("/api/daily-fee-stats-with-expiry", authenticate, async (req, res) => {
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split("T")[0];
  try {
    const [payments] = await db.execute(
      `
      SELECT fp.*, s.name as student_name, s.father_name, s.student_card_id, c.class_name
      FROM fee_payments fp
      JOIN students s ON fp.student_id = s.id
      JOIN classes c ON s.class_id = c.id
      WHERE DATE(fp.issue_date) = ?
    `,
      [targetDate],
    );
    const totalToday = payments.reduce(
      (sum, p) => sum + (parseFloat(p.amount) || 0),
      0,
    );
    const uniqueStudents = new Set(payments.map((p) => p.student_id)).size;
    res.json({
      success: true,
      date: targetDate,
      total_amount: totalToday,
      student_count: uniqueStudents,
      transaction_count: payments.length,
      payments,
    });
  } catch (err) {
    console.error("Error in /api/daily-fee-stats-with-expiry:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API چت (پیام‌ها) ======================

app.post("/api/messages", authenticate, async (req, res) => {
  const { receiver_type, receiver_id, subject, message, reply_to_id } =
    req.body;
  const sender_type = req.user.role === "student" ? "student" : "admin";
  const sender_id = req.user.id;
  if (!message || message.trim() === "")
    return res.status(400).json({ error: "متن پیام نمی‌تواند خالی باشد" });
  try {
    const [result] = await db.execute(
      `
      INSERT INTO messages (sender_type, sender_id, receiver_type, receiver_id, subject, message, reply_to_id, status) 
      VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
    `,
      [
        sender_type,
        sender_id,
        receiver_type,
        receiver_id,
        subject || "پیام جدید",
        message.trim(),
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
        CASE WHEN m.sender_type = 'student' THEN (SELECT name FROM students WHERE id = m.sender_id)
             ELSE (SELECT name FROM employees WHERE id = m.sender_id) END as sender_name,
        CASE WHEN m.receiver_type = 'student' THEN (SELECT name FROM students WHERE id = m.receiver_id)
             ELSE (SELECT name FROM employees WHERE id = m.receiver_id) END as receiver_name
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

app.get(
  "/api/messages/conversation/:studentId",
  authenticate,
  async (req, res) => {
    const studentId = req.params.studentId;
    const userId = req.user.id;
    try {
      const [results] = await db.execute(
        `
      SELECT * FROM messages 
      WHERE (sender_type = 'admin' AND sender_id = ? AND receiver_type = 'student' AND receiver_id = ?)
         OR (sender_type = 'student' AND sender_id = ? AND receiver_type = 'admin' AND receiver_id = ?)
      ORDER BY created_at ASC
    `,
        [userId, studentId, studentId, userId],
      );
      for (const msg of results) {
        if (
          msg.receiver_type === "admin" &&
          msg.receiver_id == userId &&
          msg.is_read == 0
        ) {
          await db.execute(`UPDATE messages SET is_read = 1 WHERE id = ?`, [
            msg.id,
          ]);
        }
      }
      res.json(results);
    } catch (err) {
      console.error("Error in /api/messages/conversation/:studentId:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.get(
  "/api/messages/conversation/student/:studentId",
  authenticate,
  async (req, res) => {
    const studentId = req.params.studentId;
    if (req.user.role === "student" && req.user.id != studentId) {
      return res
        .status(403)
        .json({ error: "شما فقط می‌توانید پیام‌های خود را مشاهده کنید" });
    }
    try {
      const [results] = await db.execute(
        `
      SELECT * FROM messages 
      WHERE (sender_type = 'admin' AND receiver_type = 'student' AND receiver_id = ?)
         OR (sender_type = 'student' AND sender_id = ? AND receiver_type = 'admin')
      ORDER BY created_at ASC
    `,
        [studentId, studentId],
      );
      for (const msg of results) {
        if (
          msg.receiver_type === "student" &&
          msg.receiver_id == studentId &&
          msg.is_read == 0
        ) {
          await db.execute(`UPDATE messages SET is_read = 1 WHERE id = ?`, [
            msg.id,
          ]);
        }
      }
      res.json(results);
    } catch (err) {
      console.error(
        "Error in /api/messages/conversation/student/:studentId:",
        err,
      );
      res.status(500).json({ error: err.message });
    }
  },
);

app.put("/api/messages/:id", authenticate, async (req, res) => {
  const messageId = req.params.id;
  const { message } = req.body;
  const userId = req.user.id;
  const userRole = req.user.role === "student" ? "student" : "admin";
  if (!message || message.trim() === "")
    return res.status(400).json({ error: "متن پیام نمی‌تواند خالی باشد" });
  try {
    const [existing] = await db.execute(`SELECT * FROM messages WHERE id = ?`, [
      messageId,
    ]);
    if (existing.length === 0)
      return res.status(404).json({ error: "پیام یافت نشد" });
    if (
      existing[0].sender_id !== userId ||
      existing[0].sender_type !== userRole
    ) {
      return res
        .status(403)
        .json({ error: "شما اجازه ویرایش این پیام را ندارید" });
    }
    await db.execute(
      `UPDATE messages SET message = ?, is_edited = 1, updated_at = NOW() WHERE id = ?`,
      [message.trim(), messageId],
    );
    res.json({ success: true, message: "پیام با موفقیت ویرایش شد" });
  } catch (err) {
    console.error("Error in PUT /api/messages/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/messages/:id", authenticate, async (req, res) => {
  const messageId = req.params.id;
  const userId = req.user.id;
  const userRole = req.user.role === "student" ? "student" : "admin";
  try {
    const [existing] = await db.execute(`SELECT * FROM messages WHERE id = ?`, [
      messageId,
    ]);
    if (existing.length === 0)
      return res.status(404).json({ error: "پیام یافت نشد" });
    if (
      existing[0].sender_id !== userId ||
      existing[0].sender_type !== userRole
    ) {
      return res
        .status(403)
        .json({ error: "شما اجازه حذف این پیام را ندارید" });
    }
    await db.execute(`DELETE FROM messages WHERE id = ?`, [messageId]);
    res.json({ success: true, message: "پیام با موفقیت حذف شد" });
  } catch (err) {
    console.error("Error in DELETE /api/messages/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/api/messages/mark-read/:senderId",
  authenticate,
  async (req, res) => {
    const senderId = req.params.senderId;
    const currentUserId = req.user.id;
    const currentUserRole = req.user.role === "student" ? "student" : "admin";
    let senderRole = currentUserRole === "student" ? "admin" : "student";
    try {
      await db.execute(
        `
      UPDATE messages SET is_read = 1 
      WHERE sender_type = ? AND sender_id = ? AND receiver_type = ? AND receiver_id = ? AND is_read = 0
    `,
        [senderRole, senderId, currentUserRole, currentUserId],
      );
      res.json({ success: true });
    } catch (err) {
      console.error("Error in POST /api/messages/mark-read/:senderId:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.get("/api/messages/unread-count", authenticate, async (req, res) => {
  const currentUserId = req.user.id;
  const currentUserRole = req.user.role === "student" ? "student" : "admin";
  try {
    const [result] = await db.execute(
      `
      SELECT COUNT(*) as count FROM messages WHERE receiver_type = ? AND receiver_id = ? AND is_read = 0
    `,
      [currentUserRole, currentUserId],
    );
    res.json({ unread_count: result[0]?.count || 0 });
  } catch (err) {
    console.error("Error in /api/messages/unread-count:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/messages/conversations", authenticate, async (req, res) => {
  const currentUserId = req.user.id;
  const currentUserRole = req.user.role === "student" ? "student" : "admin";
  if (currentUserRole !== "admin")
    return res.status(403).json({ error: "دسترسی محدود به مدیر" });
  try {
    const [conversations] = await db.execute(
      `
      SELECT DISTINCT 
        CASE WHEN sender_type = 'student' THEN sender_id WHEN receiver_type = 'student' THEN receiver_id END as student_id,
        MAX(created_at) as last_message_time,
        (SELECT COUNT(*) FROM messages WHERE receiver_type = 'admin' AND receiver_id = ? AND sender_type = 'student' AND sender_id = student_id AND is_read = 0) as unread_count
      FROM messages WHERE (sender_type = 'student' AND receiver_type = 'admin') OR (receiver_type = 'student' AND sender_type = 'admin')
      GROUP BY student_id ORDER BY last_message_time DESC
    `,
      [currentUserId],
    );
    const students = [];
    for (const conv of conversations) {
      if (conv.student_id) {
        const [student] = await db.execute(
          `SELECT id, name, student_card_id, class_id FROM students WHERE id = ?`,
          [conv.student_id],
        );
        if (student.length > 0)
          students.push({
            ...student[0],
            last_message_time: conv.last_message_time,
            unread_count: conv.unread_count,
          });
      }
    }
    res.json(students);
  } catch (err) {
    console.error("Error in GET /api/messages/conversations:", err);
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
      SELECT DISTINCT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id, s.status, s.photo, s.registration_date, c.class_name,
        (SELECT fp.due_date FROM fee_payments fp WHERE fp.student_id = s.id ORDER BY fp.id DESC LIMIT 1) as due_date,
        (SELECT fp.remaining_after FROM fee_payments fp WHERE fp.student_id = s.id ORDER BY fp.id DESC LIMIT 1) as remaining_fee
      FROM students s
      JOIN classes c ON s.class_id = c.id
      JOIN teacher_classes tc ON c.id = tc.class_id
      WHERE tc.teacher_id = ? AND s.status = 'active'
      ORDER BY s.name
    `,
      [req.params.teacherId],
    );
    const formatted = results.map((s) => ({
      ...s,
      due_date: s.due_date
        ? new Date(s.due_date).toISOString().split("T")[0]
        : null,
      is_expired: s.due_date && new Date(s.due_date) < new Date(),
    }));
    res.json(formatted);
  } catch (err) {
    console.error("Error in /api/teacher/students/:teacherId:", err);
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
    console.error("Error saving attendance:", err);
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
    console.error("Error in /api/attendance/class/:classId:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API انتقال شاگرد و غیرفعال/فعال کردن ======================

app.put("/api/transfer-student", authenticate, async (req, res) => {
  const { student_id, new_class_id } = req.body;
  if (req.user.role !== "teacher") {
    return res
      .status(403)
      .json({ error: "فقط استاد می‌تواند شاگرد را انتقال دهد" });
  }
  try {
    const [student] = await db.execute(
      `
      SELECT s.*, c.class_name as current_class_name 
      FROM students s 
      JOIN classes c ON s.class_id = c.id 
      JOIN teacher_classes tc ON c.id = tc.class_id 
      WHERE s.id = ? AND tc.teacher_id = ?
    `,
      [student_id, req.user.id],
    );
    if (student.length === 0)
      return res
        .status(404)
        .json({ error: "شاگرد یافت نشد یا در صنف شما نیست" });
    const [targetClass] = await db.execute(
      `
      SELECT c.* FROM classes c 
      JOIN teacher_classes tc ON c.id = tc.class_id 
      WHERE c.id = ? AND tc.teacher_id = ? AND c.is_active = 1
    `,
      [new_class_id, req.user.id],
    );
    if (targetClass.length === 0)
      return res
        .status(404)
        .json({ error: "صنف مقصد وجود ندارد یا به شما تعلق ندارد" });
    await db.execute(`UPDATE students SET class_id = ? WHERE id = ?`, [
      new_class_id,
      student_id,
    ]);
    res.json({
      success: true,
      message: `شاگرد "${student[0].name}" با موفقیت به صنف "${targetClass[0].class_name}" منتقل شد`,
    });
  } catch (err) {
    console.error("Error in /api/transfer-student:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get(
  "/api/teacher/transfer-classes/:teacherId",
  authenticate,
  async (req, res) => {
    const teacherId = req.params.teacherId;
    try {
      const [classes] = await db.execute(
        `
      SELECT DISTINCT c.id, c.class_name, c.start_time, c.is_active
      FROM classes c 
      INNER JOIN teacher_classes tc ON c.id = tc.class_id
      WHERE tc.teacher_id = ? AND c.is_active = 1 
      ORDER BY c.class_name ASC
    `,
        [teacherId],
      );
      res.json(classes);
    } catch (err) {
      console.error("Error in /api/teacher/transfer-classes/:teacherId:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

app.put("/api/teacher/disable-student", authenticate, async (req, res) => {
  const { student_id } = req.body;
  if (req.user.role !== "teacher")
    return res
      .status(403)
      .json({ error: "فقط استاد می‌تواند شاگرد را غیرفعال کند" });
  try {
    const [check] = await db.execute(
      `
      SELECT s.id, s.name FROM students s 
      JOIN classes c ON s.class_id = c.id 
      JOIN teacher_classes tc ON c.id = tc.class_id 
      WHERE s.id = ? AND tc.teacher_id = ?
    `,
      [student_id, req.user.id],
    );
    if (check.length === 0)
      return res
        .status(404)
        .json({ error: "شاگرد یافت نشد یا در صنف شما نیست" });
    await db.execute(`UPDATE students SET status = 'disabled' WHERE id = ?`, [
      student_id,
    ]);
    res.json({
      success: true,
      message: `شاگرد "${check[0].name}" با موفقیت غیرفعال شد`,
    });
  } catch (err) {
    console.error("Error in /api/teacher/disable-student:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/teacher/enable-student", authenticate, async (req, res) => {
  const { student_id } = req.body;
  if (req.user.role !== "teacher")
    return res
      .status(403)
      .json({ error: "فقط استاد می‌تواند شاگرد را فعال کند" });
  try {
    const [check] = await db.execute(
      `
      SELECT s.id, s.name FROM students s 
      JOIN classes c ON s.class_id = c.id 
      JOIN teacher_classes tc ON c.id = tc.class_id 
      WHERE s.id = ? AND tc.teacher_id = ?
    `,
      [student_id, req.user.id],
    );
    if (check.length === 0)
      return res
        .status(404)
        .json({ error: "شاگرد یافت نشد یا در صنف شما نیست" });
    await db.execute(`UPDATE students SET status = 'active' WHERE id = ?`, [
      student_id,
    ]);
    res.json({
      success: true,
      message: `شاگرد "${check[0].name}" با موفقیت فعال شد`,
    });
  } catch (err) {
    console.error("Error in /api/teacher/enable-student:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API حاضری شاگرد (برای پنل شاگرد) ======================

app.get(
  "/api/student/attendance/:studentId",
  authenticate,
  async (req, res) => {
    const { month, year } = req.query;
    const studentId = req.params.studentId;
    try {
      let query = `
      SELECT ad.status, ad.notes, da.attendance_date as date 
      FROM attendance_details ad 
      JOIN daily_attendance da ON ad.attendance_id = da.id 
      WHERE ad.student_id = ?
    `;
      let params = [studentId];
      if (month && month !== "all" && year) {
        query += ` AND MONTH(da.attendance_date) = ? AND YEAR(da.attendance_date) = ?`;
        params.push(month, year);
      }
      query += ` ORDER BY da.attendance_date DESC`;
      const [details] = await db.execute(query, params);
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
      console.error("Error in /api/student/attendance/:studentId:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

// ====================== API اطلاعات شاگرد (برای پنل شاگرد) ======================

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
    if (results.length === 0)
      return res.status(404).json({ error: "شاگرد یافت نشد" });
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
    console.error("Error in /api/student/info/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/student/stats/:studentId", authenticate, async (req, res) => {
  try {
    const [presentCount] = await db.execute(
      `
      SELECT COUNT(*) as count FROM attendance_details ad 
      JOIN daily_attendance da ON ad.attendance_id = da.id 
      WHERE ad.student_id = ? AND ad.status = 'present' 
      AND YEAR(da.attendance_date) = YEAR(CURDATE())
    `,
      [req.params.studentId],
    );
    const [absentCount] = await db.execute(
      `
      SELECT COUNT(*) as count FROM attendance_details ad 
      JOIN daily_attendance da ON ad.attendance_id = da.id 
      WHERE ad.student_id = ? AND ad.status = 'absent' 
      AND YEAR(da.attendance_date) = YEAR(CURDATE())
    `,
      [req.params.studentId],
    );
    const [lateCount] = await db.execute(
      `
      SELECT COUNT(*) as count FROM attendance_details ad 
      JOIN daily_attendance da ON ad.attendance_id = da.id 
      WHERE ad.student_id = ? AND ad.status = 'late' 
      AND YEAR(da.attendance_date) = YEAR(CURDATE())
    `,
      [req.params.studentId],
    );
    const [grades] = await db.execute(
      `
      SELECT AVG((score/max_score)*100) as avg_grade FROM grades WHERE student_id = ?
    `,
      [req.params.studentId],
    );
    res.json({
      present_count: presentCount[0]?.count || 0,
      absent_count: absentCount[0]?.count || 0,
      late_count: lateCount[0]?.count || 0,
      avg_grade: Math.round(grades[0]?.avg_grade || 0),
    });
  } catch (err) {
    console.error("Error in /api/student/stats/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/student/fees/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
      SELECT COALESCE(SUM(fp.amount), 0) as paid_fee, s.due_date 
      FROM students s 
      LEFT JOIN fee_payments fp ON s.id = fp.student_id 
      WHERE s.id = ? 
      GROUP BY s.id, s.due_date
    `,
      [req.params.studentId],
    );
    const student = results[0] || { paid_fee: 0, due_date: null };
    res.json({
      total_fee: 0,
      paid_fee: student.paid_fee || 0,
      remaining_fee: 0,
      due_date: student.due_date,
    });
  } catch (err) {
    console.error("Error in /api/student/fees/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/student/grades/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
      SELECT g.*, 'مضمون' as subject_name 
      FROM grades g 
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
    console.error("Error in /api/student/grades/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get(
  "/api/student/remaining-before/:studentId",
  authenticate,
  async (req, res) => {
    try {
      const [lastFeeRecord] = await db.execute(
        `
      SELECT total_fee, paid_fee, due_date 
      FROM fee_payments 
      WHERE student_id = ? AND total_fee IS NOT NULL AND total_fee > 0 
      ORDER BY payment_date DESC, id DESC LIMIT 1
    `,
        [req.params.studentId],
      );
      if (lastFeeRecord.length === 0)
        return res.json({
          remaining_before: 0,
          last_total_fee: 0,
          total_paid: 0,
        });
      const lastTotalFee = parseFloat(lastFeeRecord[0].total_fee) || 0;
      const lastPaidFee = parseFloat(lastFeeRecord[0].paid_fee) || 0;
      const remainingBefore = lastTotalFee - lastPaidFee;
      res.json({
        remaining_before: remainingBefore < 0 ? 0 : remainingBefore,
        last_total_fee: lastTotalFee,
        total_paid: lastPaidFee,
        last_due_date: lastFeeRecord[0].due_date,
      });
    } catch (err) {
      console.error("Error in /api/student/remaining-before:", err);
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
    if (req.user.role !== "ceo" && req.user.role !== "admin")
      return res.status(403).json({ error: "دسترسی محدود" });
    if (position === "admin" && req.user.role !== "ceo")
      return res
        .status(403)
        .json({ error: "فقط ریس می‌تواند مدیر را ویرایش کند" });
    try {
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
      await db.execute(`UPDATE employees SET ${setClause} WHERE id=?`, values);
      res.json({ success: true, message: "کارمند با موفقیت به‌روز شد" });
    } catch (err) {
      console.error("Error in PUT /api/employees/:id:", err);
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

// ====================== API داشبورد و گزارشات ======================

app.get("/api/dashboard-stats", authenticate, async (req, res) => {
  try {
    const [students] = await db.execute(
      `SELECT COUNT(*) as total FROM students WHERE status = 'active'`,
    );
    const [teachers] = await db.execute(
      `SELECT COUNT(*) as total FROM employees WHERE position = 'teacher' AND status = 'active'`,
    );
    const [debtors] = await db.execute(
      `SELECT COUNT(*) as total FROM fee_debtors WHERE remaining_fee > 0`,
    );
    const [revenue] = await db.execute(
      `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE MONTH(payment_date) = MONTH(CURDATE()) AND YEAR(payment_date) = YEAR(CURDATE())`,
    );
    const [pendingComplaints] = await db.execute(
      `SELECT COUNT(*) as total FROM complaints WHERE status = 'pending'`,
    );
    res.json({
      total_students: students[0]?.total || 0,
      total_teachers: teachers[0]?.total || 0,
      total_debtors: debtors[0]?.total || 0,
      monthly_revenue: revenue[0]?.total || 0,
      pending_complaints: pendingComplaints[0]?.total || 0,
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
      SELECT fp.id, fp.amount, DATE_FORMAT(fp.payment_date, '%Y-%m-%d') as payment_date, fp.receipt_number,
             s.id as student_id, s.name as student_name, s.student_card_id, c.class_name
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

app.get("/api/financial-reports", authenticate, async (req, res) => {
  const { period, start_date, end_date } = req.query;
  let periods = [],
    incomes = [],
    expenses = [];
  try {
    if (period === "daily") {
      for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split("T")[0];
        periods.push(dateStr);
        const [income] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE DATE(payment_date) = ?`,
          [dateStr],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount), 0) as total FROM expenses WHERE DATE(expense_date) = ?`,
          [dateStr],
        );
        incomes.push(income[0]?.total || 0);
        expenses.push(expense[0]?.total || 0);
      }
    } else if (period === "monthly") {
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
      const currentYear = new Date().getFullYear();
      for (let i = 4; i >= 0; i--) {
        const year = currentYear - i;
        periods.push(year.toString());
        const startDate = `${year}-01-01`,
          endDate = `${year}-12-31`;
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

app.get("/api/financial-summary", authenticate, async (req, res) => {
  const { start_date, end_date, period } = req.query;
  try {
    let total_income = 0;
    if (period === "daily" || (!start_date && !end_date && !period)) {
      const today = new Date().toISOString().split("T")[0];
      const [income] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE payment_date = ?`,
        [today],
      );
      total_income = income[0]?.total || 0;
    } else if (period === "monthly") {
      const [income] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE MONTH(payment_date) = MONTH(CURDATE()) AND YEAR(payment_date) = YEAR(CURDATE())`,
      );
      total_income = income[0]?.total || 0;
    } else if (period === "yearly") {
      const [income] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE YEAR(payment_date) = YEAR(CURDATE())`,
      );
      total_income = income[0]?.total || 0;
    } else if (start_date && end_date) {
      const [income] = await db.execute(
        `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE payment_date BETWEEN ? AND ?`,
        [start_date, end_date],
      );
      total_income = income[0]?.total || 0;
    }
    res.json({
      total_income,
      total_expense: 0,
      net_profit: total_income,
      transaction_count: 0,
    });
  } catch (err) {
    console.error("Error in /api/financial-summary:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API شکایات (Complaints) ======================

app.get("/api/complaints", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
      SELECT c.*, s.name as student_name, s.student_card_id
      FROM complaints c
      LEFT JOIN students s ON c.student_id = s.id
      ORDER BY c.created_at DESC
    `);
    res.json(results);
  } catch (err) {
    console.error("Error in GET /api/complaints:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/complaints", authenticate, async (req, res) => {
  const { student_id, subject, message } = req.body;
  if (!student_id || !subject || !message)
    return res.status(400).json({ error: "اطلاعات کامل نیست" });
  try {
    const [result] = await db.execute(
      `INSERT INTO complaints (student_id, subject, message, status) VALUES (?, ?, ?, 'pending')`,
      [student_id, subject, message],
    );
    res.json({ id: result.insertId, message: "شکایت با موفقیت ثبت شد" });
  } catch (err) {
    console.error("Error in POST /api/complaints:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/complaints/:id", authenticate, async (req, res) => {
  const { response } = req.body;
  try {
    await db.execute(
      `UPDATE complaints SET response = ?, status = 'resolved', resolved_at = NOW() WHERE id = ?`,
      [response, req.params.id],
    );
    res.json({ message: "پاسخ با موفقیت ثبت شد" });
  } catch (err) {
    console.error("Error in PUT /api/complaints/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API اعلانات ======================

app.get("/api/announcements", authenticate, isAdminOrCEO, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT * FROM announcements ORDER BY created_at DESC`,
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/api/announcements",
  authenticate,
  isAdminOrCEO,
  upload.single("file"),
  async (req, res) => {
    const { title, content, target, expires_at } = req.body;
    const filePath = req.file ? `/uploads/${req.file.filename}` : null;
    try {
      const [result] = await db.execute(
        `
      INSERT INTO announcements (title, content, target, file_path, expires_at, created_by) 
      VALUES (?, ?, ?, ?, ?, ?)
    `,
        [
          title,
          content,
          target || "all",
          filePath,
          expires_at || null,
          req.user.id,
        ],
      );
      res.json({ id: result.insertId, message: "اعلان با موفقیت اضافه شد" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.delete(
  "/api/announcements/:id",
  authenticate,
  isAdminOrCEO,
  async (req, res) => {
    try {
      await db.execute("DELETE FROM announcements WHERE id = ?", [
        req.params.id,
      ]);
      res.json({ message: "اعلان حذف شد" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// ====================== API نمرات ======================

app.post("/api/teacher/save-grade", authenticate, async (req, res) => {
  const { student_id, class_id, score, max_score, exam_type, teacher_id } =
    req.body;
  try {
    const [existing] = await db.execute(
      `SELECT id FROM grades WHERE student_id = ? AND class_id = ? AND exam_type = ?`,
      [student_id, class_id, exam_type],
    );
    if (existing.length > 0) {
      await db.execute(
        `UPDATE grades SET score = ?, max_score = ?, exam_date = CURDATE(), teacher_id = ? WHERE id = ?`,
        [score, max_score, teacher_id, existing[0].id],
      );
    } else {
      await db.execute(
        `INSERT INTO grades (student_id, class_id, score, max_score, exam_type, exam_date, teacher_id) VALUES (?, ?, ?, ?, ?, CURDATE(), ?)`,
        [student_id, class_id, score, max_score, exam_type, teacher_id],
      );
    }
    res.json({ success: true, message: "نمره با موفقیت ذخیره شد" });
  } catch (err) {
    console.error("Error in /api/teacher/save-grade:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/teacher/save-group-grade", authenticate, async (req, res) => {
  const { class_id, score, max_score, exam_type, teacher_id } = req.body;
  try {
    const [students] = await db.execute(
      `SELECT id FROM students WHERE class_id = ? AND status = 'active'`,
      [class_id],
    );
    let saved = 0;
    for (const student of students) {
      const [existing] = await db.execute(
        `SELECT id FROM grades WHERE student_id = ? AND class_id = ? AND exam_type = ?`,
        [student.id, class_id, exam_type],
      );
      if (existing.length > 0) {
        await db.execute(
          `UPDATE grades SET score = ?, max_score = ?, exam_date = CURDATE(), teacher_id = ? WHERE id = ?`,
          [score, max_score, teacher_id, existing[0].id],
        );
      } else {
        await db.execute(
          `INSERT INTO grades (student_id, class_id, score, max_score, exam_type, exam_date, teacher_id) VALUES (?, ?, ?, ?, ?, CURDATE(), ?)`,
          [student.id, class_id, score, max_score, exam_type, teacher_id],
        );
      }
      saved++;
    }
    res.json({ success: true, message: `${saved} نمره با موفقیت ذخیره شد` });
  } catch (err) {
    console.error("Error in /api/teacher/save-group-grade:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API کارخانگی ======================

app.get("/api/teacher/homework/:teacherId", authenticate, async (req, res) => {
  const { teacherId } = req.params;
  const { class_id } = req.query;
  try {
    let query = `SELECT h.*, c.class_name FROM homework h JOIN classes c ON h.class_id = c.id WHERE h.teacher_id = ?`;
    let params = [teacherId];
    if (class_id && class_id !== "") {
      query += ` AND h.class_id = ?`;
      params.push(class_id);
    }
    query += ` ORDER BY h.homework_date DESC`;
    const [results] = await db.execute(query, params);
    res.json(results);
  } catch (err) {
    console.error("Error in GET /api/teacher/homework/:teacherId:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/homework/:id", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT h.*, c.class_name FROM homework h JOIN classes c ON h.class_id = c.id WHERE h.id = ?`,
      [req.params.id],
    );
    if (results.length === 0)
      return res.status(404).json({ error: "کارخانگی یافت نشد" });
    res.json(results[0]);
  } catch (err) {
    console.error("Error in GET /api/homework/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/homework", authenticate, async (req, res) => {
  const { class_id, teacher_id, homework_date, due_date, assignment } =
    req.body;
  if (!class_id || !teacher_id || !homework_date || !assignment)
    return res.status(400).json({ error: "اطلاعات کامل نیست" });
  try {
    const [result] = await db.execute(
      `INSERT INTO homework (class_id, teacher_id, homework_date, due_date, assignment) VALUES (?, ?, ?, ?, ?)`,
      [class_id, teacher_id, homework_date, due_date || null, assignment],
    );
    res.json({ id: result.insertId, message: "کارخانگی با موفقیت اضافه شد" });
  } catch (err) {
    console.error("Error in POST /api/homework:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/homework/:id", authenticate, async (req, res) => {
  const { class_id, teacher_id, homework_date, due_date, assignment } =
    req.body;
  try {
    await db.execute(
      `UPDATE homework SET class_id = ?, teacher_id = ?, homework_date = ?, due_date = ?, assignment = ? WHERE id = ?`,
      [
        class_id,
        teacher_id,
        homework_date,
        due_date || null,
        assignment,
        req.params.id,
      ],
    );
    res.json({ message: "کارخانگی با موفقیت ویرایش شد" });
  } catch (err) {
    console.error("Error in PUT /api/homework/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/homework/:id", authenticate, async (req, res) => {
  try {
    await db.execute(`DELETE FROM homework WHERE id = ?`, [req.params.id]);
    res.json({ message: "کارخانگی با موفقیت حذف شد" });
  } catch (err) {
    console.error("Error in DELETE /api/homework/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API امتیازات و شکایات استاد ======================

app.post("/api/teacher/rate-student", authenticate, async (req, res) => {
  const { student_id, class_id, rating, complaint } = req.body;
  const teacher_id = req.user.id;
  if (req.user.role !== "teacher")
    return res.status(403).json({ error: "فقط استاد می‌تواند امتیاز ثبت کند" });
  if (!student_id || !class_id)
    return res.status(400).json({ error: "اطلاعات کامل نیست" });
  try {
    const [check] = await db.execute(
      `SELECT s.id FROM students s JOIN teacher_classes tc ON s.class_id = tc.class_id WHERE s.id = ? AND tc.teacher_id = ?`,
      [student_id, teacher_id],
    );
    if (check.length === 0)
      return res.status(403).json({ error: "شما دسترسی به این شاگرد ندارید" });
    const [result] = await db.execute(
      `INSERT INTO ratings (student_id, teacher_id, class_id, rating, complaint, status) VALUES (?, ?, ?, ?, ?, 'pending')`,
      [student_id, teacher_id, class_id, rating || null, complaint || null],
    );
    res.json({
      success: true,
      id: result.insertId,
      message: rating ? "امتیاز با موفقیت ثبت شد" : "شکایت با موفقیت ثبت شد",
    });
  } catch (err) {
    console.error("Error in POST /api/teacher/rate-student:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/student/ratings/:studentId", authenticate, async (req, res) => {
  const studentId = req.params.studentId;
  if (req.user.role === "student" && req.user.id != studentId)
    return res
      .status(403)
      .json({ error: "شما فقط می‌توانید امتیازات خود را ببینید" });
  try {
    const [results] = await db.execute(
      `
      SELECT r.*, e.name as teacher_name, c.class_name, DATE_FORMAT(r.created_at, '%Y-%m-%d') as created_date
      FROM ratings r JOIN employees e ON r.teacher_id = e.id JOIN classes c ON r.class_id = c.id WHERE r.student_id = ? ORDER BY r.created_at DESC
    `,
      [studentId],
    );
    res.json(results);
  } catch (err) {
    console.error("Error in GET /api/student/ratings/:studentId:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/admin/all-ratings", authenticate, async (req, res) => {
  if (req.user.role !== "admin" && req.user.role !== "ceo")
    return res.status(403).json({ error: "دسترسی محدود" });
  try {
    const [results] = await db.execute(`
      SELECT r.*, s.name as student_name, s.student_card_id, e.name as teacher_name, c.class_name, DATE_FORMAT(r.created_at, '%Y-%m-%d %H:%i') as created_date
      FROM ratings r JOIN students s ON r.student_id = s.id JOIN employees e ON r.teacher_id = e.id JOIN classes c ON r.class_id = c.id ORDER BY r.created_at DESC
    `);
    res.json(results);
  } catch (err) {
    console.error("Error in GET /api/admin/all-ratings:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/admin/respond-rating/:id", authenticate, async (req, res) => {
  const { response } = req.body;
  if (req.user.role !== "admin" && req.user.role !== "ceo")
    return res.status(403).json({ error: "فقط مدیر می‌تواند پاسخ دهد" });
  try {
    await db.execute(
      `UPDATE ratings SET response = ?, status = 'responded', updated_at = NOW() WHERE id = ?`,
      [response, req.params.id],
    );
    res.json({ success: true, message: "پاسخ با موفقیت ثبت شد" });
  } catch (err) {
    console.error("Error in PUT /api/admin/respond-rating/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API بکاپ و سیستم ======================

app.post(
  "/api/students/update-qr-token/:id",
  authenticate,
  async (req, res) => {
    const { qr_token } = req.body;
    try {
      await db.execute(`UPDATE students SET qr_token = ? WHERE id = ?`, [
        qr_token,
        req.params.id,
      ]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.get("/api/check-session", authenticate, (req, res) => {
  res.json({
    id: req.user.id,
    name: req.user.name,
    role: req.user.role,
    email: req.user.email,
  });
});

app.get("/api/ceo/dashboard-stats", authenticate, async (req, res) => {
  if (req.user.role !== "ceo")
    return res.status(403).json({ error: "دسترسی محدود به ریس سیستم" });
  try {
    const [admins] = await db.execute(
      `SELECT COUNT(*) as total FROM employees WHERE position = 'admin' AND status = 'active'`,
    );
    const [teachers] = await db.execute(
      `SELECT COUNT(*) as total FROM employees WHERE position = 'teacher' AND status = 'active'`,
    );
    const [students] = await db.execute(
      `SELECT COUNT(*) as total FROM students WHERE status = 'active'`,
    );
    const [yearlyIncome] = await db.execute(
      `SELECT COALESCE(SUM(amount), 0) as total FROM fee_payments WHERE YEAR(payment_date) = YEAR(CURDATE())`,
    );
    res.json({
      total_admins: admins[0]?.total || 0,
      total_teachers: teachers[0]?.total || 0,
      total_students: students[0]?.total || 0,
      yearly_income: yearlyIncome[0]?.total || 0,
    });
  } catch (err) {
    console.error("Error in /api/ceo/dashboard-stats:", err);
    res.status(500).json({ error: err.message });
  }
});
// ====================== API اسلایدر (عکس‌های کورس) ======================

// ایجاد پوشه uploads/slider اگر وجود ندارد
const sliderDir = "./uploads/slider";
if (!fs.existsSync(sliderDir)) {
  fs.mkdirSync(sliderDir, { recursive: true });
  console.log("📁 Created uploads/slider directory");
}

// تنظیمات ذخیره عکس اسلایدر
const sliderStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/slider/");
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + "-" + file.originalname.replace(/\s/g, "_");
    cb(null, uniqueName);
  },
});

const uploadSlider = multer({
  storage: sliderStorage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase(),
    );
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error("فقط فایل‌های تصویری مجاز هستند"));
    }
  },
});
// دریافت اسلایدرهای فعال (برای صفحه ورود - عمومی)
app.get("/api/slider", async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT id, image_path, title, description, link, order_index 
       FROM slider_images 
       WHERE is_active = 1 
       ORDER BY order_index ASC, id DESC`,
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// دریافت همه اسلایدرها (برای مدیریت - فقط مدیر و ریس)
app.get("/api/admin/slider", authenticate, isAdminOrCEO, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT * FROM slider_images ORDER BY order_index ASC, id DESC`,
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// افزودن اسلایدر جدید (فقط مدیر و ریس)
// افزودن اسلایدر جدید (فقط مدیر و ریس)
app.post(
  "/api/admin/slider",
  authenticate,
  isAdminOrCEO,
  uploadSlider.single("image"),
  async (req, res) => {
    const { title, description, link, order_index, is_active } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "لطفاً عکس را انتخاب کنید" });
    }

    const imagePath = `/uploads/slider/${req.file.filename}`;

    try {
      const [result] = await db.execute(
        `INSERT INTO slider_images (image_path, title, description, link, order_index, is_active, created_by) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          imagePath,
          title || null,
          description || null,
          link || null,
          order_index || 0,
          is_active !== undefined ? is_active : 1,
          req.user.id,
        ],
      );
      res.json({
        id: result.insertId,
        message: "اسلایدر با موفقیت اضافه شد",
        image_path: imagePath,
      });
    } catch (err) {
      console.error("Error in POST /api/admin/slider:", err);
      res.status(500).json({ error: err.message });
    }
  },
);
// ویرایش اسلایدر (فقط مدیر و ریس)
app.put(
  "/api/admin/slider/:id",
  authenticate,
  isAdminOrCEO,
  upload.single("image"),
  async (req, res) => {
    const { title, description, link, order_index, is_active } = req.body;
    let imagePath = null;

    if (req.file) {
      imagePath = `/uploads/slider/${req.file.filename}`;
    }

    try {
      let query = `UPDATE slider_images SET title=?, description=?, link=?, order_index=?, is_active=?`;
      let params = [
        title || null,
        description || null,
        link || null,
        order_index || 0,
        is_active !== undefined ? is_active : 1,
      ];

      if (imagePath) {
        query += `, image_path=?`;
        params.push(imagePath);
      }

      query += ` WHERE id=?`;
      params.push(req.params.id);

      await db.execute(query, params);
      res.json({ message: "اسلایدر با موفقیت به‌روز شد" });
    } catch (err) {
      console.error("Error in PUT /api/admin/slider/:id:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

// حذف اسلایدر (فقط مدیر و ریس)
app.delete(
  "/api/admin/slider/:id",
  authenticate,
  isAdminOrCEO,
  async (req, res) => {
    try {
      // ابتدا مسیر عکس را بگیریم
      const [slider] = await db.execute(
        `SELECT image_path FROM slider_images WHERE id = ?`,
        [req.params.id],
      );
      if (slider.length > 0 && slider[0].image_path) {
        const filePath = path.join(__dirname, slider[0].image_path);
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
        }
      }

      await db.execute(`DELETE FROM slider_images WHERE id = ?`, [
        req.params.id,
      ]);
      res.json({ message: "اسلایدر با موفقیت حذف شد" });
    } catch (err) {
      console.error("Error in DELETE /api/admin/slider/:id:", err);
      res.status(500).json({ error: err.message });
    }
  },
);

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
