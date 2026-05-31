const loginBtn = document.getElementById("loginBtn");
const registerBtn = document.getElementById("registerBtn");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const message = document.getElementById("message");

// ── Live password strength indicator ─────────────────────────────────────────
passwordInput.addEventListener("input", () => {
    const password = passwordInput.value;
    const existing = document.getElementById("strength-box");
    if (existing) existing.remove();

    if (password.length === 0) return;

    const checks = [
        { pass: password.length >= 8,                           label: "8+ characters" },
        { pass: /[A-Z]/.test(password),                         label: "Uppercase letter" },
        { pass: /[0-9]/.test(password),                         label: "Number" },
        { pass: /[!@#$%^&*(),.?\":{}|<>]/.test(password),      label: "Special character (!@#$...)" }
    ];

    const allPass = checks.every(c => c.pass);

    const box = document.createElement("div");
    box.id = "strength-box";
    box.style.cssText = `
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 12px;
        padding: 12px 16px;
        margin-bottom: 16px;
        font-size: 0.8rem;
        text-align: left;
    `;

    box.innerHTML = checks.map(c => `
        <div style="margin-bottom:5px; color: ${c.pass ? '#22c55e' : '#ff4d6d'}">
            ${c.pass ? '✅' : '❌'} ${c.label}
        </div>
    `).join("") + `
        <div style="margin-top:8px; font-weight:600; color:${allPass ? '#22c55e' : '#facc15'}">
            ${allPass ? '🔒 Strong Password' : '⚠️ Password not strong enough'}
        </div>
    `;

    // Insert after the password input group
    passwordInput.closest(".input-group").insertAdjacentElement("afterend", box);
});

// ── Register ──────────────────────────────────────────────────────────────────
registerBtn.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
        message.style.color = "#ff4d6d";
        message.innerHTML = "⚠️ Please enter email and password.";
        return;
    }

    const response = await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
    });
    const data = await response.json();

    if (data.success) {
        message.style.color = "#22c55e";
    } else {
        message.style.color = "#ff4d6d";
    }
    message.innerHTML = data.message;
});

// ── Login ─────────────────────────────────────────────────────────────────────
loginBtn.addEventListener("click", async () => {
    const email = emailInput.value.trim();
    const password = passwordInput.value;

    if (!email || !password) {
        message.style.color = "#ff4d6d";
        message.innerHTML = "⚠️ Please enter email and password.";
        return;
    }

    const response = await fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
    });
    const data = await response.json();

    if (data.success) {
        window.location.href = "/index";
    } else {
        message.style.color = "#ff4d6d";
        message.innerHTML = "⚠️ " + data.message;
    }
});