from flask import Flask, render_template, request, jsonify, session, redirect
from flask_cors import CORS
from groq import Groq
from dotenv import load_dotenv
import bcrypt
import json
import os
from datetime import datetime
import re

# Load .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "scamshield_secret_2026")
CORS(app)

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

# ── Rate limiting (brute force protection) ────────────────────────────────────
login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 5

def is_locked_out(ip):
    if ip not in login_attempts:
        return False
    record = login_attempts[ip]
    if record["attempts"] >= MAX_ATTEMPTS:
        diff = (datetime.now() - record["last_attempt"]).total_seconds()
        if diff < LOCKOUT_MINUTES * 60:
            remaining = int((LOCKOUT_MINUTES * 60 - diff) / 60) + 1
            return remaining
        else:
            del login_attempts[ip]
    return False

def record_failed_attempt(ip):
    if ip not in login_attempts:
        login_attempts[ip] = {"attempts": 0, "last_attempt": datetime.now()}
    login_attempts[ip]["attempts"] += 1
    login_attempts[ip]["last_attempt"] = datetime.now()

def reset_attempts(ip):
    if ip in login_attempts:
        del login_attempts[ip]

# ── Password strength check ───────────────────────────────────────────────────
def is_strong_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (!@#$...)"
    return True, "Strong"

# ── helpers ───────────────────────────────────────────────────────────────────
def load_users():
    if not os.path.exists("users.json"):
        with open("users.json", "w") as f:
            json.dump({}, f)
    with open("users.json", "r") as f:
        return json.load(f)

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

def load_history():
    if not os.path.exists("history.json"):
        with open("history.json", "w") as f:
            json.dump({}, f)
    with open("history.json", "r") as f:
        return json.load(f)

def save_history(history):
    with open("history.json", "w") as f:
        json.dump(history, f, indent=4)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated

# ── AI scam detection via Groq ────────────────────────────────────────────────
def analyze_with_groq(text):
    prompt = f"""You are a cybersecurity expert specializing in scam and phishing detection.

Analyze the following message and respond ONLY with a valid JSON object, no extra text.

Message to analyze:
\"\"\"{text}\"\"\"

Respond with exactly this JSON format:
{{
  "score": <integer 0-100 representing scam risk percentage>,
  "risk_level": "<High | Medium | Low>",
  "scam_type": "<one of: Phishing Attack | Vishing Scam | Smishing Scam | Lottery Scam | Banking Fraud | Identity Theft | Social Engineering | Malware Distribution | Safe Content>",
  "attack_technique": "<brief name of the attack technique used, e.g. Urgency Manipulation, Authority Impersonation, Reward Baiting>",
  "indicators": [
    "<indicator 1 with emoji>",
    "<indicator 2 with emoji>",
    "<indicator 3 with emoji>"
  ],
  "explanation": "<2 sentence explanation of why this is or isn't a scam>",
  "victim_advice": "<1 sentence specific advice for the potential victim>"
}}

Rules:
- score 70-100 = High risk
- score 30-69 = Medium risk
- score 0-29 = Low risk
- indicators should each start with a relevant emoji
- be specific about the exact scam technique used
- if safe, still give 2-3 indicators explaining what looks legitimate"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=600
    )

    raw = response.choices[0].message.content.strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"^```\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)

    result = json.loads(raw)
    result.setdefault("score", 0)
    result.setdefault("risk_level", "Low")
    result.setdefault("scam_type", "Safe Content")
    result.setdefault("attack_technique", "None detected")
    result.setdefault("indicators", ["✅ No major threats detected"])
    result.setdefault("explanation", "No scam patterns detected.")
    result.setdefault("victim_advice", "This message appears safe.")
    return result

# ── routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/index')
@login_required
def index():
    return render_template('index.html', user=session["user"])

@app.route('/history')
@login_required
def history():
    all_history = load_history()
    user_history = all_history.get(session["user"], [])
    user_history = list(reversed(user_history))
    return render_template('history.html', history=user_history, user=session["user"])

@app.route('/tips')
@login_required
def tips():
    return render_template('tips.html', user=session["user"])

# ── auth ──────────────────────────────────────────────────────────────────────
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        if not email or not password:
            return jsonify({"success": False, "message": "Email and password required"})

        # Password strength check
        strong, msg = is_strong_password(password)
        if not strong:
            return jsonify({"success": False, "message": msg})

        users = load_users()
        if email in users:
            return jsonify({"success": False, "message": "Email already registered"})

        # Hash password with bcrypt before storing
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        users[email] = hashed
        save_users(users)
        return jsonify({"success": True, "message": "Registration successful! Please login."})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/login', methods=['POST'])
def login_user():
    try:
        ip = request.remote_addr

        # Brute force protection
        lockout = is_locked_out(ip)
        if lockout:
            return jsonify({
                "success": False,
                "message": f"Too many failed attempts. Try again in {lockout} minute(s)."
            })

        data = request.get_json()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        users = load_users()

        if email in users and bcrypt.checkpw(password.encode("utf-8"), users[email].encode("utf-8")):
            reset_attempts(ip)
            session["user"] = email
            return jsonify({"success": True})

        record_failed_attempt(ip)
        attempts_left = MAX_ATTEMPTS - login_attempts[ip]["attempts"]
        if attempts_left > 0:
            return jsonify({"success": False, "message": f"Invalid email or password. {attempts_left} attempt(s) remaining."})
        else:
            return jsonify({"success": False, "message": f"Too many failed attempts. Locked out for {LOCKOUT_MINUTES} minutes."})

    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ── analyze ───────────────────────────────────────────────────────────────────
@app.route('/analyze', methods=['POST'])
@login_required
def analyze():
    try:
        data = request.get_json()
        user_message = data.get("message", "").strip()

        if not user_message:
            return jsonify({"error": "No message provided"})

        # Input length limit
        if len(user_message) > 2000:
            return jsonify({"error": "Message too long. Please limit to 2000 characters."})

        result = analyze_with_groq(user_message)

        # Save to history
        all_history = load_history()
        user_email = session["user"]
        if user_email not in all_history:
            all_history[user_email] = []

        all_history[user_email].append({
            "message": user_message[:120] + ("..." if len(user_message) > 120 else ""),
            "risk": result["risk_level"],
            "score": result["score"],
            "scam_type": result["scam_type"],
            "time": datetime.now().strftime("%Y-%m-%d %H:%M")
        })
        all_history[user_email] = all_history[user_email][-50:]
        save_history(all_history)

        return jsonify(result)

    except json.JSONDecodeError:
        return jsonify({"error": "AI returned invalid response. Please try again."})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == '__main__':
    app.run(debug=False)