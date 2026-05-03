require("dotenv").config();

module.exports = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || "lms-secret-key-2025",
  db: {
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "Root@123",
    database: process.env.DB_NAME || "lms_db",
  },
  upload: {
    maxSize: parseInt(process.env.MAX_FILE_SIZE) || 5242880,
    dir: process.env.UPLOAD_DIR || "./uploads",
  },
};