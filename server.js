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

const app = express();
const PORT = 3000;
const JWT_SECRET = "lms-secret-key-2025";

// Middleware
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
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
// let db;

// (async function initDB() {
//     try {
//         console.log("🔄 Connecting to database...");
//         console.log("   Host:", process.env.DB_HOST);
//         console.log("   Port:", process.env.DB_PORT);

//         db = await mysql.createConnection({
//             host: process.env.DB_HOST || "localhost",
//             user: process.env.DB_USER || "root",
//             password: process.env.DB_PASSWORD || "Root@123",
//             database: process.env.DB_NAME || "lms_db",
//             port: parseInt(process.env.DB_PORT) || 3306,
//             ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined,
//             connectTimeout: 30000
//         });
//         console.log("✅ Database connected successfully!");
//     } catch (err) {
//         console.error("❌ Database connection failed:", err.message);
//         console.error("❌ Full error:", err);
//         process.exit(1);
//     }
// })();

// ==================== اتصال به دیتابیس ====================

require("dotenv").config();

let db;

async function connectDB() {
  try {
    console.log("🔄 Connecting to database...");
    console.log("   Host:", process.env.DB_HOST);
    console.log("   Port:", process.env.DB_PORT);
    console.log("   User:", process.env.DB_USER);
    console.log("   Database:", process.env.DB_NAME);

    db = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: parseInt(process.env.DB_PORT),
      ssl:
        process.env.DB_SSL === "true"
          ? { rejectUnauthorized: false }
          : undefined,
      connectTimeout: 30000,
    });

    console.log("✅ Database connected successfully!");
    return db;
  } catch (err) {
    console.error("❌ Database connection failed:", err.message);
    console.error("❌ Full error:", err);
    throw err;
  }
}

// اتصال به دیتابیس قبل از شروع سرور
let dbConnected = false;

// تابع راه‌اندازی سرور
// async function startServer() {
//   try {
//     await connectDB();
//     dbConnected = true;
//     console.log("✅ Database ready");
//   } catch (err) {
//     console.error("❌ Could not connect to database:", err.message);
//     dbConnected = false;
//     console.log("⚠️ Continuing without database connection...");
//   }

//   // شروع سرور
//   app.listen(PORT, () => {
//     console.log(`\n✅ Server running on port ${PORT}`);
//     console.log(`🔗 Login URL: http://localhost:${PORT}/index.html`);
//     console.log(`\n👤 Default login:`);
//     console.log(`   📍 CEO: ceo@school.com / 123456`);

//     if (!dbConnected) {
//       console.log(
//         `\n⚠️ WARNING: Database not connected! Please check your database settings.`,
//       );
//     }
//   });
// }

// // راه‌اندازی سرور
// startServer();


// ====================== راه‌اندازی سرور ======================

// استفاده از پورت محیطی Render یا 3000 برای localhost
const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        await connectDB();
        console.log("✅ Database ready for connections");
    } catch (err) {
        console.error("❌ Could not connect to database:", err.message);
        console.log("⚠️ Starting server without database connection - some features may not work");
    }
    
    // شروع سرور - مهم: از '0.0.0.0' استفاده کنید
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`\n✅ Server running on port ${PORT}`);
        console.log(`🔗 Login URL: http://localhost:${PORT}/`);
        console.log(`\n👤 Default login:`);
        console.log(`   📍 CEO: ceo@school.com / 123456`);
        console.log(`\n🔑 Order of creation:`);
        console.log(`   1️⃣ Login as CEO and create an admin`);
        console.log(`   2️⃣ Login as admin and create classes`);
        console.log(`   3️⃣ Assign teachers to classes`);
        console.log(`   4️⃣ Register students\n`);
        
        if (!dbConnected) {
            console.log(`⚠️ WARNING: Database not connected!`);
        }
    });
    
    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`❌ Port ${PORT} is already in use!`);
            console.log(`💡 Trying alternative port ${PORT + 1}...`);
            
            // تلاش با پورت بعدی
            app.listen(PORT + 1, '0.0.0.0', () => {
                console.log(`✅ Server running on port ${PORT + 1}`);
            });
        } else {
            console.error('Server error:', err);
        }
    });
}

// شروع سرور
startServer();


// ==================== توابع کمکی ====================

function cleanParams(params) {
  return params.map((p) => (p === undefined || p === "" ? null : p));
}

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
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/classes/all", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute("SELECT * FROM classes ORDER BY id");
    res.json(results);
  } catch (err) {
    console.error(err);
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
    console.error(err);
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

// ====================== API برای کامبوباکس‌های وابسته ======================

app.get("/api/classes-with-teachers", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT DISTINCT c.id, c.class_name, c.start_time
            FROM classes c
            WHERE c.is_active = 1 
            AND EXISTS (SELECT 1 FROM teacher_classes tc WHERE tc.class_id = c.id)
            ORDER BY c.class_name
        `);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/classes-with-teachers:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/teachers-by-class/:classId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT e.id, e.name, e.father_name, e.phone
            FROM teacher_classes tc
            JOIN employees e ON tc.teacher_id = e.id
            WHERE tc.class_id = ? AND e.status = 'active'
        `,
      [req.params.classId],
    );
    res.json(results);
  } catch (err) {
    console.error("Error in /api/teachers-by-class/:classId:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API کارمندان ======================

app.get("/api/employees", authenticate, async (req, res) => {
  let query =
    "SELECT id, name, father_name, phone, email, position, salary, hire_date, status, created_at FROM employees";

  if (req.user.role === "ceo") {
    query += " WHERE position IN ('admin', 'teacher', 'accountant')";
  } else if (req.user.role === "admin") {
    query += " WHERE position IN ('teacher', 'accountant')";
  } else if (req.user.role === "teacher") {
    return res.status(403).json({ error: "دسترسی محدود" });
  }

  query += " ORDER BY created_at DESC";

  try {
    const [results] = await db.execute(query);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/employees:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/admins", authenticate, isCEO, async (req, res) => {
  try {
    const [results] = await db.execute(
      "SELECT id, name, father_name, phone, email, status, created_at FROM employees WHERE position = 'admin' ORDER BY created_at DESC",
    );
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
    if (
      (position === "teacher" || position === "accountant") &&
      !["ceo", "admin"].includes(req.user.role)
    ) {
      return res.status(403).json({
        error: "❌ فقط مدیر یا ریس می‌توانند استاد و حسابدار ایجاد کنند",
      });
    }

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
      console.error("Error in POST /api/employees:", err);
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

    if (position === "admin" && req.user.role !== "ceo") {
      return res.status(403).json({ error: "فقط ریس می‌تواند نقش مدیر بدهد" });
    }

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
      console.error("Error in PUT /api/employees:", err);
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

// ====================== API شاگردان ======================

app.get("/api/students", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT s.*, c.class_name
            FROM students s 
            LEFT JOIN classes c ON s.class_id = c.id
            ORDER BY s.id DESC
        `);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/students:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/students/:id", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT s.*, c.class_name
             FROM students s
             LEFT JOIN classes c ON s.class_id = c.id
             WHERE s.id = ?`,
      [req.params.id],
    );
    res.json(results[0]);
  } catch (err) {
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
      total_fee,
      paid_fee,
      due_date,
      address,
      status,
    } = req.body;

    if (req.user.role === "teacher") {
      return res.status(403).json({ error: "استاد نمی‌تواند شاگرد ثبت کند" });
    }

    const autoPass = Math.random().toString(36).substring(2, 8);
    const hashedPass = await bcrypt.hash(autoPass, 10);
    const qr_token = generateQrToken();
    const student_card_id = generateStudentCardId();
    const photoPath = req.file ? `/uploads/${req.file.filename}` : null;

    const finalTotalFee = parseFloat(total_fee) || 0;
    const finalPaidFee = parseFloat(paid_fee) || 0;
    const finalRemainingFee = finalTotalFee - finalPaidFee;

    // تنظیم تاریخ انقضا پیش‌فرض (یک ماه بعد)
    let finalDueDate = due_date;
    if (!finalDueDate) {
      const nextMonth = new Date();
      nextMonth.setMonth(nextMonth.getMonth() + 1);
      finalDueDate = nextMonth.toISOString().split("T")[0];
    }

    try {
      const [result] = await db.execute(
        `
            INSERT INTO students (student_card_id, name, father_name, phone, password, class_id,
                                  registration_date, status, qr_token, total_fee, paid_fee, remaining_fee, due_date, address, photo)
            VALUES (?, ?, ?, ?, ?, ?, CURDATE(), ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          student_card_id,
          name,
          father_name || null,
          phone || null,
          hashedPass,
          class_id,
          status || "active",
          qr_token,
          finalTotalFee,
          finalPaidFee,
          finalRemainingFee,
          finalDueDate,
          address || null,
          photoPath,
        ],
      );

      res.json({
        id: result.insertId,
        qr_token,
        student_card_id,
        password: autoPass,
        total_fee: finalTotalFee,
        paid_fee: finalPaidFee,
        remaining_fee: finalRemainingFee,
        due_date: finalDueDate,
      });
    } catch (err) {
      console.error(err);
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
      total_fee,
      paid_fee,
      due_date,
      status,
      address,
      password,
    } = req.body;

    let photoPath = req.file ? `/uploads/${req.file.filename}` : null;
    const finalTotalFee = parseFloat(total_fee) || 0;
    const finalPaidFee = parseFloat(paid_fee) || 0;
    const finalRemainingFee = finalTotalFee - finalPaidFee;
    const finalDueDate = due_date || null;

    let setClause = `name=?, father_name=?, phone=?, class_id=?, total_fee=?, paid_fee=?, remaining_fee=?, due_date=?, status=?, address=?`;
    let values = [
      name,
      father_name || null,
      phone || null,
      class_id,
      finalTotalFee,
      finalPaidFee,
      finalRemainingFee,
      finalDueDate,
      status,
      address || null,
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
  if (req.user.role === "teacher") {
    return res.status(403).json({ error: "استاد نمی‌تواند شاگرد حذف کند" });
  }
  try {
    await db.execute("DELETE FROM students WHERE id = ?", [req.params.id]);
    res.json({ message: "حذف شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API دروس ======================

app.get("/api/subjects", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute("SELECT * FROM subjects");
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== تخصیص استاد به صنف ======================

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
    const { teacher_id, class_id, subject_id, academic_year } = req.body;

    try {
      const [classResult] = await db.execute(
        `SELECT id FROM classes WHERE id = ? AND is_active = 1`,
        [class_id],
      );
      if (classResult.length === 0) {
        return res
          .status(404)
          .json({ error: "صنف مورد نظر وجود ندارد یا غیرفعال است" });
      }

      const [teacherResult] = await db.execute(
        `SELECT id FROM employees WHERE id = ? AND position = 'teacher' AND status = 'active'`,
        [teacher_id],
      );
      if (teacherResult.length === 0) {
        return res
          .status(404)
          .json({ error: "استاد مورد نظر وجود ندارد یا غیرفعال است" });
      }

      await db.execute(
        `
            INSERT INTO teacher_classes (teacher_id, class_id, subject_id, academic_year) 
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE subject_id = VALUES(subject_id)
        `,
        [teacher_id, class_id, subject_id || null, academic_year || "1404"],
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
            SELECT c.* FROM classes c 
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
        [attId, a.student_id, a.status, a.notes || null],
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

// ====================== API فیس ======================

app.get("/api/student/fees/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT total_fee, paid_fee, remaining_fee, due_date FROM students WHERE id = ?`,
      [req.params.studentId],
    );
    res.json(results[0] || { total_fee: 0, paid_fee: 0, remaining_fee: 0 });
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
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/student-fee-search", authenticate, async (req, res) => {
  const { class_id, search } = req.query;
  let query = `
        SELECT s.*, c.class_name
        FROM students s 
        JOIN classes c ON s.class_id = c.id 
        WHERE 1=1
    `;
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
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// // ====================== API جمع‌آوری فیس ======================

// app.post("/api/collect-fee", authenticate, async (req, res) => {
//   const { student_id, amount, payment_date, notes } = req.body;
//   const receipt_number = generateReceiptNumber();

//   try {
//     // دریافت اطلاعات کامل شاگرد
//     const [student] = await db.execute(
//       `
//             SELECT s.*, c.class_name
//             FROM students s
//             JOIN classes c ON s.class_id = c.id
//             WHERE s.id = ?
//         `,
//       [student_id],
//     );

//     if (student.length === 0)
//       return res.status(404).json({ error: "شاگرد یافت نشد" });

//     const currentPaidFee = student[0].paid_fee || 0;
//     const currentTotalFee = student[0].total_fee || 0;
//     const newPaidFee = currentPaidFee + parseFloat(amount);
//     const newRemainingFee = currentTotalFee - newPaidFee;

//     // به‌روزرسانی اطلاعات شاگرد
//     await db.execute(
//       `
//             UPDATE students
//             SET paid_fee = ?, remaining_fee = ?
//             WHERE id = ?
//         `,
//       [newPaidFee, newRemainingFee < 0 ? 0 : newRemainingFee, student_id],
//     );

//     // ثبت پرداخت جدید
//     await db.execute(
//       `INSERT INTO fee_payments (student_id, amount, payment_date, receipt_number, notes)
//              VALUES (?, ?, ?, ?, ?)`,
//       [student_id, amount, payment_date, receipt_number, notes || null],
//     );

//     // ارسال اطلاعات کامل برای چاپ رسید
//     res.json({
//       success: true,
//       receipt_number: receipt_number,
//       student_name: student[0].name,
//       student_father: student[0].father_name,
//       student_card_id: student[0].student_card_id,
//       total_fee: student[0].total_fee,
//       paid_fee: newPaidFee,
//       remaining_fee: newRemainingFee < 0 ? 0 : newRemainingFee,
//       payment_amount: amount,
//       payment_date: payment_date,
//       expiry_date: student[0].due_date,
//       notes: notes,
//     });
//   } catch (err) {
//     console.error("Error in /api/collect-fee:", err);
//     res.status(500).json({ error: err.message });
//   }
// });
// ====================== API جمع‌آوری فیس ======================

app.post("/api/collect-fee", authenticate, async (req, res) => {
  const { student_id, amount, payment_date, notes } = req.body;
  const receipt_number = generateReceiptNumber();

  // اعتبارسنجی ورودی
  const paymentAmount = parseFloat(amount);
  if (isNaN(paymentAmount) || paymentAmount <= 0) {
    return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
  }

  const paymentDate = payment_date || new Date().toISOString().split("T")[0];

  try {
    // دریافت اطلاعات کامل شاگرد
    const [student] = await db.execute(
      `SELECT s.*, c.class_name 
             FROM students s 
             JOIN classes c ON s.class_id = c.id 
             WHERE s.id = ?`,
      [student_id],
    );

    if (student.length === 0) {
      return res.status(404).json({ error: "شاگرد یافت نشد" });
    }

    const currentPaidFee = parseFloat(student[0].paid_fee) || 0;
    const currentTotalFee = parseFloat(student[0].total_fee) || 0;
    const newPaidFee = currentPaidFee + paymentAmount;
    const newRemainingFee = currentTotalFee - newPaidFee;
    const finalRemainingFee = newRemainingFee < 0 ? 0 : newRemainingFee;

    // به‌روزرسانی اطلاعات شاگرد
    await db.execute(
      `UPDATE students 
             SET paid_fee = ?, remaining_fee = ? 
             WHERE id = ?`,
      [newPaidFee, finalRemainingFee, student_id],
    );

    // ثبت پرداخت جدید
    await db.execute(
      `INSERT INTO fee_payments (student_id, amount, payment_date, receipt_number, notes) 
             VALUES (?, ?, ?, ?, ?)`,
      [student_id, paymentAmount, paymentDate, receipt_number, notes || null],
    );

    // ارسال اطلاعات کامل برای چاپ رسید
    res.json({
      success: true,
      receipt_number: receipt_number,
      student_name: student[0].name || "",
      student_father: student[0].father_name || "",
      student_card_id: student[0].student_card_id || "",
      total_fee: currentTotalFee,
      paid_fee: newPaidFee,
      remaining_fee: finalRemainingFee,
      payment_amount: paymentAmount,
      payment_date: paymentDate,
      expiry_date: student[0].due_date || "",
      notes: notes || "",
    });
  } catch (err) {
    console.error("Error in /api/collect-fee:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API حذف پرداخت ======================

app.delete("/api/fee-payment/:id", authenticate, async (req, res) => {
  const { student_id, amount } = req.body;
  const paymentId = req.params.id;

  try {
    // دریافت اطلاعات پرداخت
    const [payment] = await db.execute(
      `SELECT amount FROM fee_payments WHERE id = ?`,
      [paymentId],
    );

    if (payment.length === 0) {
      return res.status(404).json({ error: "پرداخت یافت نشد" });
    }

    const paymentAmount = parseFloat(payment[0].amount);

    // حذف پرداخت
    await db.execute(`DELETE FROM fee_payments WHERE id = ?`, [paymentId]);

    // به‌روزرسانی اطلاعات شاگرد
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
    console.error("Error in DELETE /api/fee-payment/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API ویرایش پرداخت ======================

app.put("/api/fee-payment/:id", authenticate, async (req, res) => {
  const { student_id, amount, payment_date, notes } = req.body;
  const paymentId = req.params.id;

  const newAmount = parseFloat(amount);
  if (isNaN(newAmount) || newAmount < 0) {
    return res.status(400).json({ error: "مبلغ معتبر وارد کنید" });
  }

  try {
    // دریافت اطلاعات پرداخت قبلی
    const [oldPayment] = await db.execute(
      `SELECT amount FROM fee_payments WHERE id = ?`,
      [paymentId],
    );

    if (oldPayment.length === 0) {
      return res.status(404).json({ error: "پرداخت یافت نشد" });
    }

    const oldAmount = parseFloat(oldPayment[0].amount);
    const amountDiff = newAmount - oldAmount;

    // به‌روزرسانی پرداخت
    await db.execute(
      `UPDATE fee_payments SET amount = ?, payment_date = ?, notes = ? WHERE id = ?`,
      [newAmount, payment_date, notes || null, paymentId],
    );

    // به‌روزرسانی اطلاعات شاگرد
    const [student] = await db.execute(
      `SELECT total_fee, paid_fee FROM students WHERE id = ?`,
      [student_id],
    );

    const newPaidFee = (parseFloat(student[0].paid_fee) || 0) + amountDiff;
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
    console.error("Error in PUT /api/fee-payment/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/fee-payments-history", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT fp.*, s.name as student_name, s.student_card_id, c.class_name 
            FROM fee_payments fp
            JOIN students s ON fp.student_id = s.id
            JOIN classes c ON s.class_id = c.id
            ORDER BY fp.payment_date DESC
        `);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API اعلانات ======================

app.get("/api/announcements", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT * FROM announcements WHERE is_active = 1 AND (expires_at IS NULL OR expires_at >= CURDATE()) ORDER BY created_at DESC
        `);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post(
  "/api/announcements",
  authenticate,
  upload.single("file"),
  async (req, res) => {
    const { title, content, target, expires_at } = req.body;
    const filePath = req.file ? `/uploads/${req.file.filename}` : null;
    try {
      const [result] = await db.execute(
        `INSERT INTO announcements (title, content, target, file_path, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?)`,
        [title, content, target, filePath, expires_at || null, req.user.id],
      );
      res.json({ id: result.insertId });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.delete("/api/announcements/:id", authenticate, async (req, res) => {
  try {
    await db.execute("DELETE FROM announcements WHERE id = ?", [req.params.id]);
    res.json({ message: "حذف شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API شکایات ======================

app.get("/api/complaints", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT c.*, s.name as student_name, e.name as teacher_name 
            FROM complaints c 
            LEFT JOIN students s ON c.student_id = s.id 
            LEFT JOIN employees e ON c.teacher_id = e.id
            ORDER BY c.created_at DESC
        `);
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/complaints", authenticate, async (req, res) => {
  const { student_id, subject, message } = req.body;
  try {
    const [result] = await db.execute(
      `INSERT INTO complaints (student_id, subject, message) VALUES (?, ?, ?)`,
      [student_id || null, subject, message],
    );
    res.json({ id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/complaints/:id", authenticate, async (req, res) => {
  const { response } = req.body;
  try {
    await db.execute(
      `UPDATE complaints SET status='resolved', response=?, resolved_at=NOW() WHERE id=?`,
      [response, req.params.id],
    );
    res.json({ message: "پاسخ ثبت شد" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API شاگرد (پنل شاگرد) ======================

app.get("/api/student/info/:studentId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `SELECT s.*, c.class_name FROM students s LEFT JOIN classes c ON s.class_id = c.id WHERE s.id = ?`,
      [req.params.studentId],
    );
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

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
            WHERE ad.student_id = ? AND MONTH(da.attendance_date)=? AND YEAR(da.attendance_date)=?
        `,
        [req.params.studentId, month, year],
      );
      res.json({ details });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

app.put(
  "/api/student/update-profile/:studentId",
  authenticate,
  upload.single("photo"),
  async (req, res) => {
    const { name, father_name, phone, address, password } = req.body;
    let photoPath = req.file ? `/uploads/${req.file.filename}` : null;
    let setClause = `name=?, father_name=?, phone=?, address=?`;
    let values = [name, father_name || null, phone || null, address || null];

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
      res.json({ message: "پروفایل به‌روز شد" });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

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
        `SELECT COUNT(*) as total_debtors FROM students WHERE remaining_fee > 0`,
      );
      const [revenue] = await db.execute(
        `SELECT COALESCE(SUM(amount),0) as monthly_revenue FROM fee_payments WHERE MONTH(payment_date)=MONTH(CURDATE())`,
      );

      res.json({
        total_students: students[0]?.total_students || 0,
        total_teachers: teachers[0]?.total_teachers || 0,
        total_debtors: debtors[0]?.total_debtors || 0,
        monthly_revenue: revenue[0]?.monthly_revenue || 0,
      });
    } else {
      res.json({});
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/ceo/dashboard-stats", authenticate, isCEO, async (req, res) => {
  try {
    const [admins] = await db.execute(
      `SELECT COUNT(*) as total_admins FROM employees WHERE position='admin'`,
    );
    const [teachers] = await db.execute(
      `SELECT COUNT(*) as total_teachers FROM employees WHERE position='teacher'`,
    );
    const [students] = await db.execute(
      `SELECT COUNT(*) as total_students FROM students WHERE status='active'`,
    );
    const [income] = await db.execute(
      `SELECT COALESCE(SUM(amount),0) as yearly_income FROM fee_payments WHERE YEAR(payment_date)=YEAR(CURDATE())`,
    );

    res.json({
      total_admins: admins[0]?.total_admins || 0,
      total_teachers: teachers[0]?.total_teachers || 0,
      total_students: students[0]?.total_students || 0,
      yearly_income: income[0]?.yearly_income || 0,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== API اضافی برای صفحات مدیریت ======================

// دریافت صنف‌های فعال (برای کامبوباکس)
app.get("/api/active-classes", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT c.id, c.class_name, c.start_time,
                   (SELECT COUNT(*) FROM teacher_classes tc WHERE tc.class_id = c.id) as teacher_count,
                   (SELECT COUNT(*) FROM students s WHERE s.class_id = c.id AND s.status = 'active') as student_count
            FROM classes c
            WHERE c.is_active = 1
            ORDER BY c.class_name
        `);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/active-classes:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت بدهکاران فیس
app.get("/api/fee-defaulters", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT s.*, c.class_name
            FROM students s 
            JOIN classes c ON s.class_id = c.id 
            WHERE s.remaining_fee > 0 AND s.status = 'active'
            ORDER BY s.remaining_fee DESC
        `);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/fee-defaulters:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت شاگردانی که فیس آنها منقضی شده است
app.get("/api/fee-expired", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(`
            SELECT s.*, c.class_name
            FROM students s 
            JOIN classes c ON s.class_id = c.id 
            WHERE s.due_date < CURDATE() AND s.remaining_fee > 0 AND s.status = 'active'
            ORDER BY s.due_date ASC
        `);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/fee-expired:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت نمرات برای مدیریت (admin/grades.html)
app.get("/api/class-subjects/:classId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT s.*, tc.subject_id 
            FROM subjects s 
            JOIN teacher_classes tc ON s.id = tc.subject_id 
            WHERE tc.class_id = ?
        `,
      [req.params.classId],
    );
    res.json(results);
  } catch (err) {
    console.error("Error in /api/class-subjects/:classId:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت برنامه زمانی استاد
app.get("/api/teacher/timetable/:teacherId", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute(
      `
            SELECT t.*, c.class_name, s.subject_name 
            FROM timetable t
            JOIN classes c ON t.class_id = c.id
            JOIN subjects s ON t.subject_id = s.id
            WHERE t.teacher_id = ?
            ORDER BY FIELD(t.day_of_week, 'saturday', 'sunday', 'monday', 'tuesday', 'wednesday', 'thursday'), t.start_time
        `,
      [req.params.teacherId],
    );
    res.json(results);
  } catch (err) {
    console.error("Error in /api/teacher/timetable/:teacherId:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت تکالیف استاد
app.get("/api/teacher/homework/:teacherId", authenticate, async (req, res) => {
  const { class_id } = req.query;
  let query = `
        SELECT h.*, c.class_name, s.subject_name 
        FROM homework h
        JOIN classes c ON h.class_id = c.id
        JOIN subjects s ON h.subject_id = s.id
        WHERE h.teacher_id = ?
    `;
  let params = [req.params.teacherId];
  if (class_id) {
    query += ` AND h.class_id = ?`;
    params.push(class_id);
  }
  query += ` ORDER BY h.homework_date DESC`;

  try {
    const [results] = await db.execute(query, params);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/teacher/homework/:teacherId:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت یک تکلیف خاص
app.get("/api/homework/:id", authenticate, async (req, res) => {
  try {
    const [results] = await db.execute("SELECT * FROM homework WHERE id = ?", [
      req.params.id,
    ]);
    res.json(results[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ایجاد تکلیف جدید
app.post("/api/homework", authenticate, async (req, res) => {
  const {
    class_id,
    subject_id,
    teacher_id,
    homework_date,
    due_date,
    assignment,
  } = req.body;
  try {
    const [result] = await db.execute(
      `INSERT INTO homework (class_id, subject_id, teacher_id, homework_date, due_date, assignment) 
             VALUES (?, ?, ?, ?, ?, ?)`,
      [class_id, subject_id, teacher_id, homework_date, due_date, assignment],
    );
    res.json({ id: result.insertId });
  } catch (err) {
    console.error("Error in POST /api/homework:", err);
    res.status(500).json({ error: err.message });
  }
});

// ویرایش تکلیف
app.put("/api/homework/:id", authenticate, async (req, res) => {
  const { class_id, subject_id, homework_date, due_date, assignment } =
    req.body;
  try {
    await db.execute(
      `UPDATE homework SET class_id=?, subject_id=?, homework_date=?, due_date=?, assignment=? WHERE id=?`,
      [
        class_id,
        subject_id,
        homework_date,
        due_date,
        assignment,
        req.params.id,
      ],
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// حذف تکلیف
app.delete("/api/homework/:id", authenticate, async (req, res) => {
  try {
    await db.execute("DELETE FROM homework WHERE id = ?", [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// دریافت آمار شاگرد (برای داشبورد شاگرد)
app.get("/api/student/stats/:studentId", authenticate, async (req, res) => {
  try {
    const [presentCount] = await db.execute(
      `
            SELECT COUNT(*) as count 
            FROM attendance_details ad
            JOIN daily_attendance da ON ad.attendance_id = da.id
            WHERE ad.student_id = ? AND ad.status = 'present' AND YEAR(da.attendance_date) = YEAR(CURDATE())
        `,
      [req.params.studentId],
    );

    const [absentCount] = await db.execute(
      `
            SELECT COUNT(*) as count 
            FROM attendance_details ad
            JOIN daily_attendance da ON ad.attendance_id = da.id
            WHERE ad.student_id = ? AND ad.status = 'absent' AND YEAR(da.attendance_date) = YEAR(CURDATE())
        `,
      [req.params.studentId],
    );

    const [lateCount] = await db.execute(
      `
            SELECT COUNT(*) as count 
            FROM attendance_details ad
            JOIN daily_attendance da ON ad.attendance_id = da.id
            WHERE ad.student_id = ? AND ad.status = 'late' AND YEAR(da.attendance_date) = YEAR(CURDATE())
        `,
      [req.params.studentId],
    );

    const [grades] = await db.execute(
      `
            SELECT AVG((score/max_score)*100) as avg_grade 
            FROM grades WHERE student_id = ?
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

// ====================== API گزارش حاضری ======================

// گزارش استادانی که حاضری نگرفته‌اند
app.get("/api/report/teacher-attendance", authenticate, async (req, res) => {
  const { date } = req.query;
  const targetDate = date || new Date().toISOString().split("T")[0];

  try {
    // دریافت همه استادان فعال
    const [teachers] = await db.execute(`
            SELECT id, name, phone 
            FROM employees 
            WHERE position = 'teacher' AND status = 'active'
        `);

    // دریافت استادانی که در تاریخ مشخص حاضری گرفته‌اند
    const [taken] = await db.execute(
      `
            SELECT DISTINCT teacher_id 
            FROM daily_attendance 
            WHERE attendance_date = ?
        `,
      [targetDate],
    );

    const takenIds = taken.map((t) => t.teacher_id);
    const notTaken = teachers.filter((t) => !takenIds.includes(t.id));

    res.json({
      date: targetDate,
      not_taken: notTaken,
      total_teachers: teachers.length,
    });
  } catch (err) {
    console.error("Error in /api/report/teacher-attendance:", err);
    res.status(500).json({ error: err.message });
  }
});

// گزارش حاضری شاگردان
app.get("/api/report/student-attendance", authenticate, async (req, res) => {
  const { class_id, student_name, start_date, end_date } = req.query;

  let query = `
        SELECT ad.*, s.id as student_id, s.name, s.father_name, s.student_card_id, 
               da.attendance_date, c.class_name, c.id as class_id
        FROM attendance_details ad
        JOIN daily_attendance da ON ad.attendance_id = da.id
        JOIN students s ON ad.student_id = s.id
        JOIN classes c ON s.class_id = c.id
        WHERE da.attendance_date BETWEEN ? AND ?
    `;
  let params = [start_date, end_date];

  if (class_id && class_id !== "") {
    query += ` AND s.class_id = ?`;
    params.push(class_id);
  }
  if (student_name && student_name !== "") {
    query += ` AND s.name LIKE ?`;
    params.push(`%${student_name}%`);
  }

  query += ` ORDER BY da.attendance_date DESC, s.name ASC`;

  try {
    const [results] = await db.execute(query, params);
    res.json(results);
  } catch (err) {
    console.error("Error in /api/report/student-attendance:", err);
    res.status(500).json({ error: err.message });
  }
});

// ====================== API مدیریت پرداخت‌ها ======================

// ویرایش پرداخت
app.put("/api/fee-payment/:id", authenticate, async (req, res) => {
  const { student_id, amount, payment_date, notes } = req.body;
  const paymentId = req.params.id;

  try {
    // دریافت اطلاعات پرداخت قبلی
    const [oldPayment] = await db.execute(
      `SELECT amount FROM fee_payments WHERE id = ?`,
      [paymentId],
    );

    if (oldPayment.length === 0) {
      return res.status(404).json({ error: "پرداخت یافت نشد" });
    }

    const oldAmount = oldPayment[0].amount;
    const amountDiff = parseFloat(amount) - oldAmount;

    // به‌روزرسانی پرداخت
    await db.execute(
      `UPDATE fee_payments SET amount = ?, payment_date = ?, notes = ? WHERE id = ?`,
      [amount, payment_date, notes || null, paymentId],
    );

    // به‌روزرسانی اطلاعات شاگرد
    const [student] = await db.execute(
      `SELECT total_fee, paid_fee FROM students WHERE id = ?`,
      [student_id],
    );

    const newPaidFee = (student[0].paid_fee || 0) + amountDiff;
    const newRemainingFee = (student[0].total_fee || 0) - newPaidFee;

    await db.execute(
      `UPDATE students SET paid_fee = ?, remaining_fee = ? WHERE id = ?`,
      [newPaidFee, newRemainingFee < 0 ? 0 : newRemainingFee, student_id],
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error in PUT /api/fee-payment/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// حذف پرداخت
app.delete("/api/fee-payment/:id", authenticate, async (req, res) => {
  const { student_id, amount } = req.body;
  const paymentId = req.params.id;

  try {
    // حذف پرداخت
    await db.execute(`DELETE FROM fee_payments WHERE id = ?`, [paymentId]);

    // به‌روزرسانی اطلاعات شاگرد
    const [student] = await db.execute(
      `SELECT total_fee, paid_fee FROM students WHERE id = ?`,
      [student_id],
    );

    const newPaidFee = (student[0].paid_fee || 0) - parseFloat(amount);
    const newRemainingFee = (student[0].total_fee || 0) - newPaidFee;

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
    console.error("Error in DELETE /api/fee-payment/:id:", err);
    res.status(500).json({ error: err.message });
  }
});

// دریافت تاریخچه پرداخت با فیلتر تاریخ
app.get("/api/fee-payments-history", authenticate, async (req, res) => {
  const { start_date, end_date } = req.query;

  let query = `
        SELECT fp.*, s.name as student_name, s.student_card_id, c.class_name 
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

// ====================== API گزارشات مالی ======================

// خلاصه مالی در بازه زمانی مشخص
app.get("/api/financial-summary", authenticate, async (req, res) => {
  const { start_date, end_date, period } = req.query;

  let startDate, endDate;

  if (period === "monthly") {
    const now = new Date();
    startDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-01`;
    endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0)
      .toISOString()
      .split("T")[0];
  } else if (period === "yearly") {
    const now = new Date();
    startDate = `${now.getFullYear()}-01-01`;
    endDate = `${now.getFullYear()}-12-31`;
  } else {
    startDate = start_date;
    endDate = end_date;
  }

  if (!startDate || !endDate) {
    return res.status(400).json({ error: "بازه زمانی مشخص نشده" });
  }

  try {
    // درآمد
    const [income] = await db.execute(
      `SELECT COALESCE(SUM(amount),0) as total_income, COUNT(*) as transaction_count 
             FROM fee_payments WHERE payment_date BETWEEN ? AND ?`,
      [startDate, endDate],
    );

    // هزینه
    const [expense] = await db.execute(
      `SELECT COALESCE(SUM(amount),0) as total_expense, COUNT(*) as expense_count 
             FROM expenses WHERE expense_date BETWEEN ? AND ?`,
      [startDate, endDate],
    );

    res.json({
      total_income: income[0]?.total_income || 0,
      total_expense: expense[0]?.total_expense || 0,
      transaction_count: income[0]?.transaction_count || 0,
      net_profit:
        (income[0]?.total_income || 0) - (expense[0]?.total_expense || 0),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// گزارش مالی با نمودار (دوره‌ای)
app.get("/api/financial-reports", authenticate, async (req, res) => {
  const { period, start_date, end_date } = req.query;

  let periods = [];
  let incomes = [];
  let expenses = [];

  try {
    if (period === "daily") {
      // آخرین 7 روز
      for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split("T")[0];
        periods.push(dateStr);

        const [income] = await db.execute(
          `SELECT COALESCE(SUM(amount),0) as total FROM fee_payments WHERE payment_date = ?`,
          [dateStr],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount),0) as total FROM expenses WHERE expense_date = ?`,
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
          `SELECT COALESCE(SUM(amount),0) as total FROM fee_payments WHERE payment_date BETWEEN ? AND ?`,
          [startDate, endDate],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount),0) as total FROM expenses WHERE expense_date BETWEEN ? AND ?`,
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
          `SELECT COALESCE(SUM(amount),0) as total FROM fee_payments WHERE payment_date BETWEEN ? AND ?`,
          [startDate, endDate],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount),0) as total FROM expenses WHERE expense_date BETWEEN ? AND ?`,
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
          `SELECT COALESCE(SUM(amount),0) as total FROM fee_payments WHERE payment_date = ?`,
          [dateStr],
        );
        const [expense] = await db.execute(
          `SELECT COALESCE(SUM(amount),0) as total FROM expenses WHERE expense_date = ?`,
          [dateStr],
        );
        incomes.push(income[0]?.total || 0);
        expenses.push(expense[0]?.total || 0);

        current.setDate(current.getDate() + 1);
      }
    }

    const totalIncome = incomes.reduce((a, b) => a + b, 0);
    const totalExpense = expenses.reduce((a, b) => a + b, 0);

    res.json({
      periods,
      incomes,
      expenses,
      total_income: totalIncome,
      total_expense: totalExpense,
      net_profit: totalIncome - totalExpense,
    });
  } catch (err) {
    console.error("Error in /api/financial-reports:", err);
    res.status(500).json({ error: err.message });
  }
});

// آخرین تراکنش‌ها
app.get("/api/recent-transactions", authenticate, async (req, res) => {
  const { limit } = req.query;
  const queryLimit = limit ? parseInt(limit) : 10;

  try {
    const [results] = await db.execute(
      `
            SELECT fp.*, s.name as student_name, s.student_card_id, c.class_name 
            FROM fee_payments fp
            JOIN students s ON fp.student_id = s.id
            JOIN classes c ON s.class_id = c.id
            ORDER BY fp.payment_date DESC, fp.id DESC
            LIMIT ?
        `,
      [queryLimit],
    );
    res.json(results);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ====================== صفحه 404 ======================
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "404.html"));
});

// ====================== شروع سرور ======================
app.listen(PORT, async () => {
  console.log(`\n✅ سرور با موفقیت روی پورت ${PORT} اجرا شد!`);
  console.log(`🔗 آدرس لاگین: http://localhost:${PORT}/login.html`);
  console.log(`\n👤 اطلاعات ورود پیش‌فرض:`);
  console.log(`   📍 ریس سیستم: ceo@school.com / 123456`);
  console.log(`\n🔑 ترتیب صحیح ایجاد:`);
  console.log(`   1️⃣  ابتدا با حساب ریس وارد شوید و یک مدیر ایجاد کنید`);
  console.log(`   2️⃣  با حساب مدیر وارد شوید و صنف ایجاد کنید`);
  console.log(`   3️⃣  سپس استاد ایجاد کنید و به صنف تخصیص دهید`);
  console.log(`   4️⃣  سپس شاگرد ثبت نام کنید\n`);
});
