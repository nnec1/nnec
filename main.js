// main.js - توابع عمومی

function setupSidebar() {
  const toggleBtn = document.getElementById("sidebarToggle");
  const sidebar = document.getElementById("sidebar");
  const overlay = document.getElementById("overlay");

  if (!toggleBtn) return;

  function closeSidebar() {
    if (sidebar) sidebar.classList.remove("show");
    if (overlay) overlay.classList.remove("show");
  }

  function openSidebar() {
    if (sidebar) sidebar.classList.add("show");
    if (overlay) overlay.classList.add("show");
  }

  toggleBtn.addEventListener("click", openSidebar);
  if (overlay) overlay.addEventListener("click", closeSidebar);

  window.addEventListener("resize", () => {
    if (window.innerWidth > 768) closeSidebar();
  });
}

function setCurrentDate() {
  const dateElem = document.getElementById("currentDate");
  if (dateElem) {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const day = String(now.getDate()).padStart(2, "0");
    dateElem.innerText = `${year}-${month}-${day}`;
  }
}

async function logout() {
  await fetch("/api/logout", { method: "POST" });
  localStorage.clear();
  window.location.href = "/index.html";
}

function showMessage(message, type, elementId = "message") {
  const msgDiv = document.getElementById(elementId);
  if (msgDiv) {
    msgDiv.classList.remove("d-none");
    msgDiv.className = `alert alert-${type} rounded-3 fade-in`;
    msgDiv.innerHTML = `<i class="bi bi-${type === "success" ? "check-circle-fill" : "exclamation-triangle-fill"} me-2"></i> ${message}`;
    setTimeout(() => msgDiv.classList.add("d-none"), 5000);
  } else {
    alert(message);
  }
}

function formatNumber(num) {
  if (num === null || num === undefined) return "0";
  return num.toLocaleString();
}

function getTodayDate() {
  const today = new Date();
  return `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, "0")}-${String(today.getDate()).padStart(2, "0")}`;
}

// تابع چاپ رسید کامل با صفحه جداگانه
function printReceipt(
  studentName,
  studentFather,
  studentCardId,
  totalFee,
  paidFee,
  remainingFee,
  paymentAmount,
  paymentDate,
  expiryDate,
  receiptNumber,
  notes,
  className = "",
  studentStatus = "",
  prevPaidFee = null,
  isOverpaid = false,
) {
  const params = new URLSearchParams();
  params.append("student_name", studentName || "");
  params.append("student_father", studentFather || "");
  params.append("student_card_id", studentCardId || "");
  params.append("class_name", className || "");
  params.append("total_fee", totalFee || 0);
  params.append("paid_fee", paidFee || 0); // اضافه شد
  params.append("remaining_fee", remainingFee || 0);
  params.append("payment_amount", paymentAmount || 0);
  params.append("payment_date", paymentDate || "");
  params.append("expiry_date", expiryDate || "");
  params.append("receipt_number", receiptNumber || "");
  if (prevPaidFee !== null) params.append("prev_paid_fee", prevPaidFee);
  if (notes) params.append("notes", notes);
  if (studentStatus) params.append("student_status", studentStatus);
  if (isOverpaid) params.append("overpaid", "true");

  const receiptWindow = window.open(
    `/receipt.html?${params.toString()}`,
    "_blank",
  );
  if (!receiptWindow) {
    alert("لطفاً pop-up را برای این سایت فعال کنید");
  }
}
// تابع نمایش کارت شناسایی
function showStudentCard(studentId) {
  window.open(`/student-card.html?id=${studentId}`, "_blank");
}

// ==================== توابع اضافه شده جدید ====================

// توابع تاریخ
function formatDate(dateString) {
  if (!dateString) return "-";
  try {
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return dateString;
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  } catch (e) {
    return dateString;
  }
}

function formatDatePersian(dateString) {
  if (!dateString) return "-";
  try {
    const d = new Date(dateString);
    if (isNaN(d.getTime())) return dateString;
    return d.toLocaleDateString("fa-IR");
  } catch (e) {
    return dateString;
  }
}

function calculateExpiryDate(dateString, monthsToAdd = 1) {
  if (!dateString) return "";
  const date = new Date(dateString);
  date.setMonth(date.getMonth() + monthsToAdd);
  return date.toISOString().split("T")[0];
}

// توابع وضعیت فیس
function isDateExpired(dateString) {
  if (!dateString) return false;
  try {
    const dueDate = new Date(dateString);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return dueDate < today;
  } catch (e) {
    return false;
  }
}

function getFeeStatusClass(remainingFee, dueDate) {
  if (remainingFee <= 0) return "bg-success";
  if (isDateExpired(dueDate)) return "bg-danger";
  return "bg-warning";
}

function getFeeStatusText(remainingFee, dueDate) {
  if (remainingFee <= 0) return "پرداخت کامل";
  if (isDateExpired(dueDate)) return "منقضی شده";
  return "بدهکار";
}

// توابع اعتبارسنجی
function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

function validatePhone(phone) {
  const re = /^[0-9]{10,15}$/;
  return re.test(phone);
}

function validatePassword(password) {
  return password && password.length >= 4;
}

// توابع تولید شناسه
function generateStudentCardId() {
  const prefix = "STU";
  const year = new Date().getFullYear().toString().slice(-2);
  const random = Math.floor(Math.random() * 10000)
    .toString()
    .padStart(4, "0");
  return `${prefix}-${year}-${random}`;
}

function generateReceiptNumber() {
  return "RCP-" + Date.now() + "-" + Math.floor(Math.random() * 1000);
}

// تابع نمایش توست
function showToast(message, type) {
  const toast = document.createElement("div");
  toast.className = `toast-message toast-${type}`;
  toast.style.cssText = `
    position: fixed; 
    bottom: 20px; 
    right: 20px; 
    z-index: 1100; 
    min-width: 250px; 
    padding: 12px 20px; 
    border-radius: 12px; 
    color: white; 
    font-weight: 500; 
    background: ${type === "success" ? "#10b981" : "#dc2626"}; 
    animation: slideIn 0.3s ease;
  `;
  toast.innerHTML = `<i class="fa-solid fa-${type === "success" ? "check-circle" : "circle-exclamation"} me-2"></i> ${message}`;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

// تابع دریافت کاربر جاری
function getCurrentUser() {
  return {
    id: localStorage.getItem("userId") || localStorage.getItem("studentId"),
    name:
      localStorage.getItem("userName") || localStorage.getItem("studentName"),
    role: localStorage.getItem("userRole"),
  };
}

// تابع بررسی احراز هویت
function checkAuth() {
  const user = getCurrentUser();
  if (!user.id) {
    window.location.href = "/index.html";
    return false;
  }
  return true;
}

// تابع درخواست API با مدیریت خطا
async function fetchAPI(url, options = {}) {
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || "خطا در درخواست");
    }
    return await response.json();
  } catch (err) {
    console.error("API Error:", err);
    showToast(err.message, "danger");
    throw err;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  setupSidebar();
  setCurrentDate();
});
