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
    return res.status(403).json({ error: "فقط ریس سیستم" });
  next();
};

const isAdminOrCEO = (req, res, next) => {
  if (!["ceo", "admin"].includes(req.user.role))
    return res.status(403).json({ error: "دسترسی محدود" });
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
      return res.status(401).json({ error: "QR کد معتبر نیست" });
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
  const { class_name, teacher_id, start_time, end_time, is_active } = req.body;
  if (!class_name || class_name.trim() === "") {
    return res.status(400).json({ error: "نام صنف الزامی است" });
  }
  try {
    const [result] = await db.execute(
      `INSERT INTO classes (class_name, teacher_id, start_time, end_time, is_active) VALUES (?, ?, ?, ?, ?)`,
      [
        class_name,
        teacher_id || null,
        start_time || "08:00:00",
        end_time || "10:00:00",
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
  const { class_name, teacher_id, start_time, end_time, is_active } = req.body;
  try {
    await db.execute(
      `UPDATE classes SET class_name=?, teacher_id=?, start_time=?, end_time=?, is_active=? WHERE id=?`,
      [
        class_name,
        teacher_id || null,
        start_time || "08:00:00",
        end_time || "10:00:00",
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
                   s.registration_date, s.photo, s.status, s.qr_token,
                   c.class_name, c.teacher_id, e.name as teacher_name
            FROM students s 
            LEFT JOIN classes c ON s.class_id = c.id 
            LEFT JOIN employees e ON c.teacher_id = e.id
            ORDER BY s.id DESC
        `);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/students/:id", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT s.id, s.student_card_id, s.name, s.father_name, s.phone, s.class_id, 
                   s.registration_date, s.photo, s.status, s.qr_token,
                   c.class_name, c.teacher_id, e.name as teacher_name
            FROM students s 
            LEFT JOIN classes c ON s.class_id = c.id 
            LEFT JOIN employees e ON c.teacher_id = e.id
            WHERE s.id = ?
        `,
      [req.params.id],
    );

    if (results.length === 0) {
      return res.status(404).json({ error: "شاگرد یافت نشد" });
    }

    res.json(results[0]);
  } catch (err) {
    console.error("Error in /api/students/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/api/students",
  authenticate,
  upload.single("photo"),
  async (req, res) => {
    const { name, father_name, phone, class_id, registration_date } = req.body;

    if (req.user.role === "teacher") {
      return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
    }

    const autoPass = Math.random().toString(36).substring(2, 8);
    const hashedPass = await bcrypt.hash(autoPass, 10);
    const qr_token = generateQrToken();
    const student_card_id = generateStudentCardId();
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    try {
      const [result] = await db.execute(
        `
            INSERT INTO students 
            (student_card_id, name, father_name, phone, password, class_id, registration_date, status, qr_token, photo) 
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
        `,
        [
          student_card_id,
          name,
          father_name || null,
          phone || null,
          hashedPass,
          class_id,
          registration_date,
          qr_token,
          photoPath,
        ],
      );

      res.json({
        id: result.insertId,
        qr_token,
        student_card_id,
        password: autoPass,
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
    const {
      name,
      father_name,
      phone,
      class_id,
      registration_date,
      status,
      password,
    } = req.body;
    let photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    // فقط مدیر یا ریس بتواند ویرایش کند
    if (req.user.role === "student") {
      return res
        .status(403)
        .json({ error: "شاگرد نمی‌تواند پروفایل خود را ویرایش کند" });
    }

    let setClause = `name=?, father_name=?, phone=?, class_id=?, registration_date=?, status=?`;
    let values = [
      name,
      father_name || null,
      phone || null,
      class_id,
      registration_date,
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
      await db.execute(`UPDATE students SET ${setClause} WHERE id=?`, values);
      res.json({ message: "شاگرد به‌روز شد" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.delete("/api/students/:id", authenticate, async (req, res) => {
  if (req.user.role === "teacher")
    return res.status(403).json({ error: "استاد نمی‌تواند شاگرد حذف کند" });
  try {
    await db.execute("DELETE FROM students WHERE id = ?", [req.params.id]);
    res.json({ message: "حذف شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API جستجوی صنف (برای فرم ثبت شاگرد) ======================

app.get("/api/search-classes", authenticate, async (req, res) => {
  const { search } = req.query;
  let query = `
        SELECT c.id, c.class_name, c.start_time, c.end_time, e.name as teacher_name
        FROM classes c
        LEFT JOIN employees e ON c.teacher_id = e.id
        WHERE c.is_active = 1
    `;
  let params = [];

  if (search && search.trim() !== "") {
    query += ` AND (c.class_name LIKE ? OR e.name LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`);
  }

  query += ` ORDER BY c.class_name`;

  try {
    const [results] = await db.execute(query, params);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API کارمندان ======================

app.get("/api/employees", authenticate, async (req, res) => {
  let query =
    "SELECT id, name, father_name, phone, email, position, status FROM employees";
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
    if (position === "admin" && req.user.role !== "ceo") {
      return res
        .status(403)
        .json({ error: "❌ فقط ریس سیستم می‌تواند مدیر ایجاد کند" });
    }
    const hashedPass = await bcrypt.hash(password || "123456", 10);
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;
    try {
      const [result] = await db.execute(
        `INSERT INTO employees (name, father_name, phone, email, password, position, salary, hire_date, photo, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')`,
        [
          name,
          father_name || null,
          phone || null,
          email,
          hashedPass,
          position,
          salary || null,
          hire_date || null,
          photoPath,
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
      father_name || null,
      phone || null,
      email,
      position,
      salary || null,
      hire_date || null,
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
  if (req.user.role !== "ceo" && req.user.role !== "admin") {
    return res.status(403).json({ error: "دسترسی محدود" });
  }
  try {
    await db.execute("DELETE FROM employees WHERE id = ?", [req.params.id]);
    res.json({ message: "حذف شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API فیس و بدهکاران (فقط ریس) ======================

app.get("/api/fee-debtors", authenticate, isCEO, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT fd.*, s.name, s.father_name, s.student_card_id, s.phone, c.class_name
            FROM fee_debtors fd
            JOIN students s ON fd.student_id = s.id
            JOIN classes c ON s.class_id = c.id
            WHERE fd.remaining_debt > 0
            ORDER BY fd.due_date ASC
        `);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/fee-expired", authenticate, isCEO, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT fd.*, s.name, s.father_name, s.student_card_id, s.phone, c.class_name
            FROM fee_debtors fd
            JOIN students s ON fd.student_id = s.id
            JOIN classes c ON s.class_id = c.id
            WHERE fd.due_date < CURDATE() AND fd.remaining_debt > 0
            ORDER BY fd.due_date ASC
        `);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/fee-payments-history", authenticate, isCEO, async (req, res) => {
  const { start_date, end_date } = req.query;
  let query = `
        SELECT fp.*, s.name as student_name, s.father_name, s.student_card_id, c.class_name
        FROM fee_payments fp
        JOIN students s ON fp.student_id = s.id
        JOIN classes c ON s.class_id = c.id
        WHERE 1=1
    `;
  let params = [];
  if (start_date && end_date) {
    query += ` AND fp.payment_date BETWEEN ? AND ?`;
    params.push(start_date, end_date);
  }
  query += ` ORDER BY fp.payment_date DESC`;
  try {
    const [results] = await db.execute(query, params);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/collect-fee", authenticate, isCEO, async (req, res) => {
  const { student_id, amount, payment_date, new_due_date, notes } = req.body;
  const receipt_number = generateReceiptNumber();
  const paymentAmount = parseFloat(amount);

  if (isNaN(paymentAmount) || paymentAmount <= 0) {
    return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
  }

  const paymentDate = payment_date || new Date().toISOString().split("T")[0];

  try {
    // به‌روزرسانی جدول fee_debtors
    const [debtor] = await db.execute(
      `SELECT * FROM fee_debtors WHERE student_id = ?`,
      [student_id],
    );

    if (debtor.length > 0) {
      const newPaidAmount =
        (parseFloat(debtor[0].paid_amount) || 0) + paymentAmount;
      const newRemainingDebt =
        (parseFloat(debtor[0].total_debt) || 0) - newPaidAmount;
      const newStatus = newRemainingDebt <= 0 ? "paid" : "partial";
      const newDueDate = new_due_date || debtor[0].due_date;

      await db.execute(
        `UPDATE fee_debtors SET paid_amount = ?, remaining_debt = ?, status = ?, due_date = ? WHERE student_id = ?`,
        [
          newPaidAmount,
          newRemainingDebt < 0 ? 0 : newRemainingDebt,
          newStatus,
          newDueDate,
          student_id,
        ],
      );
    }

    // ثبت پرداخت
    await db.execute(
      `INSERT INTO fee_payments (student_id, amount, payment_date, receipt_number, notes) VALUES (?, ?, ?, ?, ?)`,
      [student_id, paymentAmount, paymentDate, receipt_number, notes || null],
    );

    const [student] = await db.execute(
      `SELECT name, father_name, student_card_id FROM students WHERE id = ?`,
      [student_id],
    );

    res.json({
      success: true,
      receipt_number,
      student_name: student[0]?.name || "",
      student_father: student[0]?.father_name || "",
      student_card_id: student[0]?.student_card_id || "",
      payment_amount: paymentAmount,
      payment_date: paymentDate,
      expiry_date: new_due_date || debtor[0]?.due_date,
      notes: notes || "",
    });
  } catch (err) {
    console.error("Error in /api/collect-fee:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API پیام‌ها ======================

app.get("/api/messages/:userId", authenticate, async (req, res) => {
  const { userId } = req.params;
  const userRole = req.user.role;
  const userType = userRole === "student" ? "student" : "admin";

  try {
    const [results] = await db.execute(
      `
            SELECT m.*, 
                   s.name as sender_name, s.photo as sender_photo,
                   r.name as receiver_name
            FROM messages m
            LEFT JOIN students s ON (m.sender_type = 'student' AND m.sender_id = s.id)
            LEFT JOIN employees s2 ON (m.sender_type = 'admin' AND m.sender_id = s2.id)
            LEFT JOIN students r ON (m.receiver_type = 'student' AND m.receiver_id = r.id)
            LEFT JOIN employees r2 ON (m.receiver_type = 'admin' AND m.receiver_id = r2.id)
            WHERE (m.sender_type = ? AND m.sender_id = ?) OR (m.receiver_type = ? AND m.receiver_id = ?)
            ORDER BY m.created_at DESC
        `,
      [userType, userId, userType, userId],
    );

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/api/messages",
  authenticate,
  upload.single("attachment"),
  async (req, res) => {
    const { receiver_id, subject, message, parent_id } = req.body;
    const senderId = req.user.id;
    const senderType = req.user.role === "student" ? "student" : "admin";
    const receiverType = req.user.role === "student" ? "admin" : "student";
    const attachmentPath = req.file ? `/uploads/${req.file.filename}` : null;

    try {
      const [result] = await db.execute(
        `
            INSERT INTO messages (sender_type, sender_id, receiver_type, receiver_id, subject, message, attachment, parent_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          senderType,
          senderId,
          receiverType,
          receiver_id,
          subject || null,
          message,
          attachmentPath,
          parent_id || null,
        ],
      );

      res.json({ id: result.insertId, success: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.put("/api/messages/:id/read", authenticate, async (req, res) => {
  try {
    await db.execute(`UPDATE messages SET is_read = TRUE WHERE id = ?`, [
      req.params.id,
    ]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API شکایات ======================

app.get("/api/complaints", authenticate, async (req, res) => {
  try {
    let query = `
            SELECT cr.*, s.name as student_name, s.student_card_id, e.name as teacher_name
            FROM complaints_ratings cr
            LEFT JOIN students s ON cr.student_id = s.id
            LEFT JOIN employees e ON cr.teacher_id = e.id
            WHERE cr.type = 'complaint'
        `;

    if (req.user.role === "student") {
      query += ` AND cr.student_id = ${req.user.id}`;
    }

    query += ` ORDER BY cr.created_at DESC`;

    const [results] = await db.execute(query);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/complaints", authenticate, async (req, res) => {
  const { subject, message } = req.body;
  const studentId = req.user.id;
  const studentRole = req.user.role;

  if (studentRole !== "student") {
    return res
      .status(403)
      .json({ error: "فقط شاگردان می‌توانند شکایت ثبت کنند" });
  }

  try {
    const [result] = await db.execute(
      `
            INSERT INTO complaints_ratings (student_id, type, subject, message, status)
            VALUES (?, 'complaint', ?, ?, 'pending')
        `,
      [studentId, subject, message],
    );

    res.json({ id: result.insertId, success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/complaints/:id", authenticate, isAdminOrCEO, async (req, res) => {
  const { response } = req.body;

  try {
    await db.execute(
      `
            UPDATE complaints_ratings 
            SET status = 'resolved', response = ?, resolved_at = NOW() 
            WHERE id = ?
        `,
      [response, req.params.id],
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API امتیازات ======================

app.post("/api/ratings", authenticate, async (req, res) => {
  const { student_id, rating_value, message } = req.body;
  const teacherId = req.user.id;

  if (req.user.role !== "teacher") {
    return res
      .status(403)
      .json({ error: "فقط استادان می‌توانند امتیاز ثبت کنند" });
  }

  try {
    const [result] = await db.execute(
      `
            INSERT INTO complaints_ratings (student_id, teacher_id, type, rating_value, message, status)
            VALUES (?, ?, 'rating', ?, ?, 'resolved')
        `,
      [student_id, teacherId, rating_value, message || null],
    );

    res.json({ id: result.insertId, success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/student/ratings/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT cr.*, e.name as teacher_name
            FROM complaints_ratings cr
            JOIN employees e ON cr.teacher_id = e.id
            WHERE cr.student_id = ? AND cr.type = 'rating'
            ORDER BY cr.created_at DESC
        `,
      [req.params.studentId],
    );

    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API حاضری ======================

app.get(
  "/api/attendance/expired-students/:teacherId",
  authenticate,
  async (req, res) => {
    const { teacherId } = req.params;

    try {
      const [results] = await db.execute(
        `
            SELECT s.id, s.name, s.father_name, s.student_card_id, s.phone, c.class_name,
                   fd.due_date, fd.remaining_debt
            FROM fee_debtors fd
            JOIN students s ON fd.student_id = s.id
            JOIN classes c ON s.class_id = c.id
            JOIN teacher_classes tc ON c.id = tc.class_id
            WHERE tc.teacher_id = ? AND fd.due_date < CURDATE() AND fd.remaining_debt > 0
        `,
        [teacherId],
      );

      res.json(results);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

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
        [attId, a.student_id, a.status, a.notes || null],
      );
    }

    res.json({ success: true, message: "حاضری با موفقیت ثبت شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/teacher/students/:teacherId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT DISTINCT s.id, s.name, s.father_name, s.student_card_id, s.phone, s.photo,
                   c.class_name, c.id as class_id,
                   fd.due_date, fd.remaining_debt,
                   CASE WHEN fd.due_date < CURDATE() AND fd.remaining_debt > 0 THEN 1 ELSE 0 END as is_expired
            FROM students s
            JOIN classes c ON s.class_id = c.id
            JOIN teacher_classes tc ON c.id = tc.class_id
            LEFT JOIN fee_debtors fd ON s.id = fd.student_id
            WHERE tc.teacher_id = ? AND s.status = 'active'
        `,
      [req.params.teacherId],
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
            SELECT c.id, c.class_name, c.start_time, c.end_time
            FROM classes c
            JOIN teacher_classes tc ON c.id = tc.class_id
            WHERE tc.teacher_id = ? AND c.is_active = 1
        `,
      [req.params.teacherId],
    );
    res.json(results);
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
    if (results[0].password.startsWith("$2a$")) {
      isValid = await bcrypt.compare(current, results[0].password);
    } else {
      isValid = current === results[0].password;
    }
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

app.get("/api/dashboard-stats", authenticate, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      const [students] = await db.execute(
        `SELECT COUNT(*) as total_students FROM students WHERE status='active'`,
      );
      const [teachers] = await db.execute(
        `SELECT COUNT(*) as total_teachers FROM employees WHERE position='teacher'`,
      );
      const [debtors] = await db.execute(
        `SELECT COUNT(*) as total_debtors FROM fee_debtors WHERE remaining_debt > 0`,
      );
      const [messages] = await db.execute(
        `SELECT COUNT(*) as unread_messages FROM messages WHERE receiver_type='admin' AND receiver_id=? AND is_read=0`,
        [req.user.id],
      );

      res.json({
        total_students: students[0]?.total_students || 0,
        total_teachers: teachers[0]?.total_teachers || 0,
        total_debtors: debtors[0]?.total_debtors || 0,
        unread_messages: messages[0]?.unread_messages || 0,
      });
    } else {
      res.json({});
    }
  } catch (err) {
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
