// AEGIS-ADS v11.0 - Frontend
console.log("AEGIS-ADS v11.0");

let ws = null;
let reconnectAttempts = 0;

function connectWebSocket() {
    ws = new WebSocket(`ws://${window.location.host}/ws/live`);
    ws.onopen = () => { console.log("WebSocket connected"); reconnectAttempts = 0; };
    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            updateDashboard(data);
            updateLogs(data.logs);
        } catch(e) { console.error(e); }
    };
    ws.onclose = () => {
        setTimeout(() => { if(reconnectAttempts < 10) { reconnectAttempts++; connectWebSocket(); } }, 3000);
    };
}

function updateDashboard(data) {
    const packetEl = document.getElementById("packetCount");
    if(packetEl) packetEl.innerText = data.packets || 0;
    const detectionEl = document.getElementById("detectionCount");
    if(detectionEl) detectionEl.innerText = data.detections || 0;
}

function updateLogs(logs) {
    const tbody = document.getElementById("logsTableBody");
    if(!tbody) return;
    if(!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8">No threats yet. Start capture first. <tr></tr>';
        return;
    }
    tbody.innerHTML = logs.slice(0, 50).map(log => `
        <tr>
            <td>${log.id || '-'}</td>
            <td>${log.timestamp ? log.timestamp.slice(0,19).replace('T', ' ') : '--:--:--'}</td>
            <td><strong>${log.src_ip || '?'}</strong></td>
            <td><span style="color:#f44336;">${log.attack_type || 'Unknown'}</span></td>
            <td>${log.severity || 'MEDIUM'}</td>
            <td>${log.confidence || 0}%</span></td>
            <td>${log.action || 'Logged'}</td>
        </tr>
    `).join("");
}

async function loadDevices() {
    try {
        const res = await fetch("/api/devices");
        const data = await res.json();
        const tbody = document.getElementById("devicesTableBody");
        if(!tbody) return;
        if(!data.devices || data.devices.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6">No devices found. Click Scan Network. </tr></tr>';
            return;
        }
        tbody.innerHTML = data.devices.map(d => `
            <tr>
                <td><strong>${d.ip_address || 'Unknown'}</strong></td>
                <td>${d.mac_address || '-'}</td>
                <td>${d.vendor || 'Unknown'}</td>
                <td>${d.hostname || 'Client'}</td>
                <td><span style="color:#4caf50;">Active</span></td>
                <td><button onclick="blockDevice('${d.ip_address}')">Block</button></td>
            </tr>
        `).join("");
    } catch(e) { console.error(e); }
}

async function loadFirewallRules() {
    try {
        const res = await fetch("/api/firewall/rules");
        const data = await res.json();
        const tbody = document.getElementById("firewallRulesBody");
        if(!tbody) return;
        if(!data.rules || data.rules.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7">No active rules</td><td>No rules yet</td></td>';
            return;
        }
        tbody.innerHTML = data.rules.map((rule) => `
            <tr>
                <td>${rule.id || '-'}</td>
                <td>${rule.name || '-'}</td>
                <td>${rule.source || '-'}</td>
                <td>${rule.protocol || 'ALL'}</td>
                <td>${rule.port || '*'}</td>
                <td><span style="color:#f44336;">${rule.action || 'BLOCK'}</span></td>
                <td>${rule.reason || '-'}</td>
                <td><button onclick="unblockIP('${rule.source}')">Delete</button></td>
            </tr>
        `).join("");
        document.getElementById("ruleCount").innerText = data.rules.length;
    } catch(e) { console.error(e); }
}

async function blockDevice(ip) {
    if(!ip) return;
    try {
        const res = await fetch("/api/firewall/rules", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({src_ip: ip, action: "BLOCK", reason: "Manual"})
        });
        const result = await res.json();
        if(result.status === "blocked") {
            alert(`✅ ${ip} blocked! (${result.rules_added}/30 rules added)`);
            loadDevices();
            loadFirewallRules();
        } else {
            alert(`❌ Failed to block ${ip}`);
        }
    } catch(e) { alert("Error: " + e.message); }
}

async function unblockIP(ip) {
    if(!confirm(`Unblock ${ip}?`)) return;
    try {
        await fetch(`/api/firewall/rules/ip/${ip}`, {method: "DELETE"});
        alert(`✅ ${ip} unblocked`);
        loadFirewallRules();
    } catch(e) { alert("Error: " + e.message); }
}

async function startCapture() { await fetch("/api/capture/start", {method: "POST"}); alert("Capture started"); }
async function stopCapture() { await fetch("/api/capture/stop", {method: "POST"}); alert("Capture stopped"); }
async function scanNetwork() { await fetch("/api/devices/scan", {method: "POST"}); await loadDevices(); alert("Scan completed"); }
async function panicMode() { if(confirm("PANIC MODE?")) { await fetch("/api/panic", {method: "POST"}); alert("PANIC MODE ACTIVATED"); } }

// Reports functions
async function generateReport() {
    try {
        const res = await fetch("/api/reports/generate");
        const data = await res.json();
        if(data.status === "generated") {
            alert(`✅ Report generated: ${data.filename}`);
            loadReportsList();
            window.open(data.file, "_blank");
        } else {
            alert("❌ Failed to generate report");
        }
    } catch(e) { alert("Error: " + e.message); }
}

async function loadReportsList() {
    try {
        const res = await fetch("/api/reports/list");
        const data = await res.json();
        const tbody = document.getElementById("reportsList");
        if(!tbody) return;
        if(!data.files || data.files.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5">No reports yet</td></tr>';
            return;
        }
        tbody.innerHTML = data.files.map(file => `
            <tr>
                <td><strong>${file.name}</strong></td>
                <td>PDF Report</td><td>${file.date}</td>
                <td><button onclick="downloadReport('${file.name}')">Download</button></td>
                <td><button onclick="deleteReport('${file.name}')">Delete</button></td>
            </tr>
        `).join("");
    } catch(e) { console.error(e); }
}

async function downloadReport(filename) { window.open(`/api/reports/download/${filename}`, "_blank"); }
async function deleteReport(filename) {
    if(!confirm(`Delete ${filename}?`)) return;
    await fetch(`/api/reports/delete/${filename}`, {method: "DELETE"});
    loadReportsList();
}
async function emailReport() {
    const email = prompt("Enter email address:", "alaxhmood@gmail.com");
    if(!email) return;
    try {
        const res = await fetch("/api/reports/email", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({email: email})
        });
        const data = await res.json();
        if(data.status === "sent") {
            alert(`✅ Report sent to ${email}`);
        } else {
            alert("❌ Failed to send email");
        }
    } catch(e) { alert("Error: " + e.message); }
}

// Email settings
async function saveEmailSettings() {
    const smtpServer = document.getElementById("smtpServer")?.value || "smtp.gmail.com";
    const smtpPort = document.getElementById("smtpPort")?.value || 587;
    const username = document.getElementById("smtpUsername")?.value || "alaxhmood@gmail.com";
    const password = document.getElementById("smtpPassword")?.value;
    const alertEmail = document.getElementById("alertEmail")?.value || "alaxhmood@gmail.com";
    const additionalEmail = document.getElementById("additionalEmail")?.value;
    
    try {
        const res = await fetch("/api/settings/email/save", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({smtp_server: smtpServer, smtp_port: smtpPort, username: username, password: password, alert_email: alertEmail, additional_email: additionalEmail})
        });
        const data = await res.json();
        if(data.status === "saved") {
            alert("✅ Email settings saved!");
        } else {
            alert("❌ Failed to save settings");
        }
    } catch(e) { alert("Error: " + e.message); }
}

async function testEmail() {
    try {
        const res = await fetch("/api/settings/email/test", {method: "POST"});
        const data = await res.json();
        if(data.status === "sent") {
            alert("✅ Test email sent successfully!");
        } else {
            alert("❌ Failed to send test email");
        }
    } catch(e) { alert("Error: " + e.message); }
}

document.addEventListener("DOMContentLoaded", () => {
    connectWebSocket();
    loadDevices();
    loadFirewallRules();
    loadReportsList();
    setInterval(loadDevices, 10000);
});

// دالة لإضافة IP إلى القائمة البيضاء وفك الحظر
async function whitelistAndUnblock(ip) {
    if (!confirm(`إضافة ${ip} إلى القائمة البيضاء وفك الحظر؟`)) return;
    // أولاً إضافة إلى القائمة البيضاء
    const res = await fetch('/api/whitelist/add', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ip: ip})
    });
    const data = await res.json();
    if (data.status === 'success') {
        showNotification(`✅ تم إضافة ${ip} إلى القائمة البيضاء ورفع الحظر`, 'success');
        loadFirewallRules(); // تحديث القائمة
        loadDevices();
    } else {
        showNotification('❌ فشل', 'error');
    }
}

// إضافة عمود إضافي في جدول القواعد لعرض زر Whitelist (إذا كانت قاعدة تحتوي على IP)
// وأيضاً إضافة زر Whitelist بجانب كل جهاز في جدول الأجهزة



// دالة فك الحظر وإضافة إلى القائمة البيضاء
async function unblockAndWhitelist(ip) {
    if (!confirm(`هل تريد فك الحظر عن ${ip} وإضافته إلى القائمة البيضاء (لن يتم حظره مرة أخرى)؟`)) return;
    try {
        // إضافة إلى القائمة البيضاء أولاً
        const resWhitelist = await fetch('/api/whitelist/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: ip})
        });
        const dataWhitelist = await resWhitelist.json();
        if (dataWhitelist.status === 'success') {
            // ثم حذف قواعد الحظر
            const resUnblock = await fetch(`/api/firewall/rules/ip/${ip}`, {method: 'DELETE'});
            const dataUnblock = await resUnblock.json();
            if (dataUnblock.status === 'unblocked') {
                showNotification(`✅ ${ip} تم فك حظره وإضافته إلى القائمة البيضاء`, 'success');
                loadFirewallRules();
                loadDevices();
            } else {
                showNotification(`⚠️ تمت إضافة ${ip} إلى القائمة البيضاء لكن قد تبقى قواعد قديمة`, 'warning');
            }
        } else {
            showNotification('❌ فشل إضافة IP إلى القائمة البيضاء', 'error');
        }
    } catch(e) {
        showNotification('خطأ: ' + e.message, 'error');
    }
}

// تعديل دالة loadFirewallRules لإضافة زر "فك الحظر"
// نبحث عن المكان الذي يعرض القواعد ونضيف الزر
