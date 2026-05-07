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
  params.append("paid_fee", paidFee || 0);
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

document.addEventListener("DOMContentLoaded", () => {
  setupSidebar();
  setCurrentDate();
});

function printReceipt(
  studentName,
  studentFather,
  studentCardId,
  totalFee,
  paidFee,
  remainingFee,
  paymentAmount,
  paymentDate,
  issueDate,
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
  params.append("paid_fee", paidFee || 0);
  params.append("remaining_fee", remainingFee || 0);
  params.append("payment_amount", paymentAmount || 0);
  params.append("payment_date", paymentDate || "");
  params.append("issue_date", issueDate || ""); // اضافه شد
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
