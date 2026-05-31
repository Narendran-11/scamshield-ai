alert("Script Loaded");
const analyzeBtn = document.querySelector(".analyze-btn");
const textarea = document.querySelector("textarea");
const urlInput = document.querySelector("input");
const riskCircle = document.querySelector(".risk-circle");
const riskStatus = document.querySelector("#risk-status");
const riskScore = document.querySelector("#risk-score");
const scamType = document.querySelector("#scam-type");
const threatList = document.querySelector("#threat-list");
const suggestionList = document.querySelector("#suggestion-list");

// Character counter
const MAX_CHARS = 2000;
const counter = document.createElement("div");
counter.style.cssText = "text-align:right;font-size:0.8rem;color:#94a3b8;margin-top:-15px;margin-bottom:15px;";
counter.innerHTML = "0 / " + MAX_CHARS + " characters";
textarea.insertAdjacentElement("afterend", counter);

textarea.addEventListener("input", () => {
    const len = textarea.value.length;
    counter.innerHTML = len + " / " + MAX_CHARS + " characters";
    if (len > MAX_CHARS * 0.9) {
        counter.style.color = "#ff4d6d";
    } else if (len > MAX_CHARS * 0.7) {
        counter.style.color = "#facc15";
    } else {
        counter.style.color = "#94a3b8";
    }
    if (len > MAX_CHARS) {
        textarea.value = textarea.value.substring(0, MAX_CHARS);
        counter.innerHTML = MAX_CHARS + " / " + MAX_CHARS + " characters — limit reached";
    }
});

// ANALYZE BUTTON
analyzeBtn.addEventListener("click", async () => {
    const message = textarea.value;
    const url = urlInput.value;
    const userInput = `${message}\n${url}`;

    if (!userInput.trim()) {
        alert("Please enter a suspicious message or URL.");
        return;
    }

    analyzeBtn.innerHTML = `
        <i class="fa-solid fa-spinner fa-spin"></i>
        AI Scanning Threats...
    `;
    analyzeBtn.disabled = true;

    try {
        const response = await fetch("/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: userInput })
        });

        const data = await response.json();

        if (data.error) {
            riskStatus.innerHTML = "Error: " + data.error;
            threatList.innerHTML = `<li>⚠️ ${data.error}</li>`;
            return;
        }

        // Update risk score circle
        riskScore.innerHTML = data.score + "%";

        if (data.risk_level === "High") {
            riskScore.style.color = "#ff4d6d";
        } else if (data.risk_level === "Medium") {
            riskScore.style.color = "#facc15";
        } else {
            riskScore.style.color = "#22c55e";
        }

        riskStatus.innerHTML = `<strong>${data.risk_level} Risk</strong>`;

        if (scamType) {
            scamType.innerHTML = `
                ${data.scam_type}
                ${data.attack_technique ? `<br><span style="font-size:.8rem;color:#64748b;">Technique: ${data.attack_technique}</span>` : ""}
            `;
        }

        // Threat indicators from AI
        threatList.innerHTML = data.indicators
            .map(ind => `<li>${ind}</li>`)
            .join("");

        // AI explanation + advice
        suggestionList.innerHTML = `
            ${data.explanation ? `<li>🧠 ${data.explanation}</li>` : ""}
            ${data.victim_advice ? `<li>🛡️ ${data.victim_advice}</li>` : ""}
            <li>✅ Never share OTPs or passwords.</li>
            <li>✅ Verify sender through official channels.</li>
            ${data.risk_level === "High" ? "<li>🚨 High risk — do not respond or click any links.</li>" : ""}
            ${data.risk_level === "Medium" ? "<li>⚠️ Proceed with caution and verify the source.</li>" : ""}
        `;

    } catch (error) {
        riskStatus.innerHTML = "Error connecting to server";
        threatList.innerHTML = `<li>Unable to connect to backend.</li>`;
        console.error(error);
    }

    analyzeBtn.innerHTML = `
        <i class="fa-solid fa-shield-virus"></i>
        Analyze Threat
    `;
    analyzeBtn.disabled = false;
});

// FLOATING CARD EFFECT (unchanged)
const cards = document.querySelectorAll(".card");
cards.forEach(card => {
    card.addEventListener("mousemove", (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        card.style.transform = `
            rotateX(${-(y - rect.height / 2) / 20}deg)
            rotateY(${(x - rect.width / 2) / 20}deg)
            translateY(-10px)
        `;
    });
    card.addEventListener("mouseleave", () => {
        card.style.transform = "rotateX(0) rotateY(0) translateY(0)";
    });
});

// MOVING SHIELD ANIMATION (unchanged)
const shield = document.querySelector(".card-shield");
const wrapper = document.querySelector(".input-card-wrapper");
let progress = 0;

function moveShieldAroundBox() {
    if (!shield || !wrapper) return;
    const width = wrapper.offsetWidth;
    const height = wrapper.offsetHeight;
    const perimeter = 2 * (width + height);
    const pos = progress % perimeter;
    let x, y;
    if (pos < width) {
        x = pos; y = 0;
    } else if (pos < width + height) {
        x = width; y = pos - width;
    } else if (pos < 2 * width + height) {
        x = width - (pos - width - height); y = height;
    } else {
        x = 0; y = height - (pos - 2 * width - height);
    }
    shield.style.left = (x - 20) + "px";
    shield.style.top  = (y - 20) + "px";
    progress += 2;
    requestAnimationFrame(moveShieldAroundBox);
}
moveShieldAroundBox();