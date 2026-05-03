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

// function setCurrentDate() {
//   const dateElem = document.getElementById("currentDate");
//   if (dateElem) {
//     const now = new Date();
//     dateElem.innerText = now.toLocaleDateString("fa-IR");
//   }
// }
  function setCurrentDate() {
    const dateElem = document.getElementById("currentDate");
    if (dateElem) {
        const now = new Date();
        const year = now.getFullYear();
        const month = String(now.getMonth() + 1).padStart(2, '0');
        const day = String(now.getDate()).padStart(2, '0');
        dateElem.innerText = `${year}-${month}-${day}`;
    }
}


async function logout() {
  await fetch("/api/logout", { method: "POST" });
  localStorage.clear();
  window.location.href = "/login.html";
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

function generateAutoPassword(name, fatherName) {
  const cleanName = (name || "user").replace(/[^آ-یa-zA-Z]/g, "");
  const cleanFather = (fatherName || "").replace(/[^آ-یa-zA-Z]/g, "");
  const firstCharName = cleanName.charAt(0) || "u";
  const firstCharFather = cleanFather.charAt(0) || "s";
  const randomNum = Math.floor(1000 + Math.random() * 9000);
  return (firstCharName + firstCharFather + randomNum).toLowerCase();
}

// function printReceipt(
//   studentName,
//   studentCardId,
//   amount,
//   date,
//   receiptNumber,
//   notes,
// ) {
//   const win = window.open("", "_blank");
//   win.document.write(`
//     <!DOCTYPE html>
//     <html dir="rtl">
//     <head>
//       <meta charset="UTF-8">
//       <title>رسید پرداخت فیس</title>
//       <style>
//         body { font-family: 'Tahoma', sans-serif; padding: 20px; background: #f5f7fb; }
//         .receipt { max-width: 350px; margin: auto; background: white; border-radius: 20px; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
//         .header { text-align: center; border-bottom: 2px dashed #667eea; padding-bottom: 15px; margin-bottom: 15px; }
//         .header h3 { color: #667eea; margin: 0; }
//         .row { display: flex; justify-content: space-between; margin: 12px 0; padding: 5px 0; border-bottom: 1px dotted #e2e8f0; }
//         .row .label { font-weight: bold; color: #475569; }
//         .row .value { color: #1e293b; }
//         .amount { font-size: 1.3rem; color: #10b981; font-weight: bold; }
//         .footer { text-align: center; margin-top: 20px; padding-top: 15px; border-top: 1px solid #e2e8f0; font-size: 0.8rem; color: #94a3b8; }
//         @media print { body { background: white; } .receipt { box-shadow: none; } }
//       </style>
//     </head>
//     <body>
//       <div class="receipt">
//         <div class="header"><h3>🏫 آموزشگاه نوی نور</h3><small>رسید پرداخت شهریه</small></div>
//         <div class="row"><span class="label">نام شاگرد:</span><span>${studentName}</span></div>
//         <div class="row"><span class="label">آیدی کارت:</span><span>${studentCardId}</span></div>
//         <div class="row"><span class="label">مبلغ پرداختی:</span><span class="amount">${Number(amount).toLocaleString()} افغانی</span></div>
//         <div class="row"><span class="label">تاریخ پرداخت:</span><span>${date}</span></div>
//         <div class="row"><span class="label">شماره رسید:</span><span>${receiptNumber}</span></div>
//         ${notes ? `<div class="row"><span class="label">یادداشت:</span><span>${notes}</span></div>` : ""}
//         <div class="footer">با تشکر از اعتماد شما<br>تیم مدیریت آموزشگاه نوی نور</div>
//       </div>
//       <div style="text-align:center; margin-top:15px;">
//         <button onclick="window.print()" style="padding:8px 20px;background:#667eea;color:white;border:none;border-radius:10px;">🖨️ چاپ رسید</button>
//         <button onclick="window.close()" style="padding:8px 20px;background:#94a3b8;color:white;border:none;border-radius:10px;margin-right:10px;">❌ بستن</button>
//       </div>
//       <script>setTimeout(() => window.print(), 500);<\/script>
//     </body>
//     </html>
//   `);
//   win.document.close();
// }

// تابع چاپ رسید کامل با تمام اطلاعات
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
) {
  // اطمینان از اینکه مقادیر عددی به درستی فرمت می‌شوند
  const formatNumber = (num) => {
    if (num === undefined || num === null || isNaN(num)) return "0";
    return Number(num).toLocaleString();
  };

  const formatDate = (date) => {
    if (!date || date === "null" || date === "undefined") return "-";
    try {
      return new Date(date).toLocaleDateString("fa-IR");
    } catch (e) {
      return date;
    }
  };

  const today = new Date().toLocaleDateString("fa-IR");

  const win = window.open("", "_blank");
  win.document.write(`
        <!DOCTYPE html>
        <html dir="rtl">
        <head>
          <meta charset="UTF-8">
          <title>رسید پرداخت فیس</title>
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Tahoma', sans-serif; padding: 20px; background: #f5f7fb; }
            .receipt { max-width: 400px; margin: auto; background: white; border-radius: 24px; padding: 30px; box-shadow: 0 15px 40px rgba(0,0,0,0.1); border: 1px solid #e2e8f0; }
            .header { text-align: center; border-bottom: 2px dashed #667eea; padding-bottom: 20px; margin-bottom: 20px; }
            .header h2 { color: #667eea; margin: 0; font-size: 1.5rem; }
            .header h3 { color: #1e293b; margin: 5px 0 0; font-size: 1.1rem; }
            .header small { color: #64748b; }
            .row { display: flex; justify-content: space-between; margin: 14px 0; padding: 8px 0; border-bottom: 1px dotted #e2e8f0; }
            .row .label { font-weight: bold; color: #475569; width: 40%; }
            .row .value { color: #1e293b; width: 60%; text-align: left; }
            .amount-total { font-size: 1.2rem; }
            .amount-paid { color: #10b981; font-size: 1.3rem; font-weight: bold; }
            .amount-remaining { color: #dc2626; font-weight: bold; }
            .expiry-warning { background: #fef3c7; padding: 12px; border-radius: 12px; text-align: center; margin: 15px 0; color: #b45309; font-size: 0.8rem; }
            .footer { text-align: center; margin-top: 25px; padding-top: 15px; border-top: 1px solid #e2e8f0; font-size: 0.75rem; color: #94a3b8; }
            .stamp { text-align: center; margin-top: 15px; font-family: monospace; color: #667eea; font-size: 0.7rem; }
            .signature { display: flex; justify-content: space-between; margin-top: 25px; padding-top: 15px; }
            @media print { body { background: white; } .receipt { box-shadow: none; margin: 0; } .no-print { display: none; } }
          </style>
        </head>
        <body>
          <div class="receipt">
            <div class="header">
              <h2>🏫 مؤسسه آموزشی پیشرو</h2>
              <h3>رسید پرداخت شهریه</h3>
              <small>تاریخ چاپ: ${today}</small>
            </div>
            
            <div class="row"><span class="label">نام شاگرد:</span><span class="value"><strong>${studentName || "-"}</strong></span></div>
            <div class="row"><span class="label">نام پدر:</span><span class="value">${studentFather || "-"}</span></div>
            <div class="row"><span class="label">آیدی کارت:</span><span class="value">${studentCardId || "-"}</span></div>
            
            <div class="row"><span class="label">📅 تاریخ پرداخت:</span><span class="value">${formatDate(paymentDate)}</span></div>
            <div class="row"><span class="label">⏰ تاریخ انقضا:</span><span class="value">${formatDate(expiryDate)}</span></div>
            
            <div class="row amount-total"><span class="label">💰 فیس اصلی:</span><span class="value">${formatNumber(totalFee)} AFN</span></div>
            <div class="row"><span class="label">💳 مبلغ پرداختی:</span><span class="value amount-paid">${formatNumber(paymentAmount)} AFN</span></div>
            <div class="row"><span class="label">📊 جمع پرداخت شده:</span><span class="value amount-paid">${formatNumber(paidFee)} AFN</span></div>
            <div class="row"><span class="label">⚠️ باقی مانده:</span><span class="value amount-remaining">${formatNumber(remainingFee)} AFN</span></div>
            
            <div class="row"><span class="label">🔢 شماره رسید:</span><span class="value">${receiptNumber || "-"}</span></div>
            ${notes ? `<div class="row"><span class="label">📝 یادداشت:</span><span class="value">${notes}</span></div>` : ""}
            
            ${remainingFee > 0 ? `<div class="expiry-warning">⚠️ توجه: مبلغ ${formatNumber(remainingFee)} AFN باقی مانده است.</div>` : '<div class="expiry-warning" style="background:#dcfce7;color:#15803d;">✅ فیس به طور کامل پرداخت شد.</div>'}
            
            <div class="footer">
              با تشکر از اعتماد شما<br>
              تیم مدیریت مؤسسه آموزشی پیشرو
            </div>
            <div class="stamp">
              ${today}
            </div>
            <div class="signature">
              <span>امضاء پرداخت‌کننده: ___________</span>
              <span>امضاء مسئول: ___________</span>
            </div>
          </div>
          <div class="text-center no-print" style="margin-top:20px;">
            <button onclick="window.print()" style="padding:10px 25px;background:#667eea;color:white;border:none;border-radius:12px;cursor:pointer;">🖨️ چاپ رسید</button>
            <button onclick="window.close()" style="padding:10px 25px;background:#94a3b8;color:white;border:none;border-radius:12px;margin-right:10px;cursor:pointer;">❌ بستن</button>
          </div>
          <script>setTimeout(() => window.print(), 500);<\/script>
        </body>
        </html>
    `);
  win.document.close();
}

document.addEventListener("DOMContentLoaded", () => {
  setupSidebar();
  setCurrentDate();
});
