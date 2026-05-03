// utils/helpers.js
function getCurrentYearMonth() {
  const today = new Date();
  return `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-01`;
}

function formatMySQLDate(date) {
  if (!date) return null;
  const d = new Date(date);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function generateAutoPassword(name, fatherName) {
  const cleanName = (name || "user").replace(/[^آ-یa-zA-Z]/g, "");
  const cleanFather = (fatherName || "").replace(/[^آ-یa-zA-Z]/g, "");
  const firstCharName = cleanName.charAt(0) || "u";
  const firstCharFather = cleanFather.charAt(0) || "s";
  const randomNum = Math.floor(1000 + Math.random() * 9000);
  return (firstCharName + firstCharFather + randomNum).toLowerCase();
}

function generateQRToken() {
  return require("crypto")
    .createHash("md5")
    .update(Date.now() + Math.random().toString())
    .digest("hex");
}

module.exports = {
  getCurrentYearMonth,
  formatMySQLDate,
  generateAutoPassword,
  generateQRToken,
};
