// middleware/auth.js
const jwt = require("jsonwebtoken");
const config = require("../config");

const authenticate = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "احراز هویت نشده" });
  }
  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "توکن نامعتبر" });
  }
};

const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "دسترسی غیرمجاز" });
    }
    next();
  };
};
// const isCEO = (req, res, next) => {
//   if (req.user.role !== "ceo") {
//     return res.status(403).json({ error: "دسترسی محدود به ریس سیستم" });
//   }
//   next();
// };
module.exports = { authenticate, authorize };
