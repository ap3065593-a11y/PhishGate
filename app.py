import os
import sqlite3
import requests
import base64
import re
from flask import Flask, render_template, request, make_response

app = Flask(__name__)

# VirusTotal API Key
API_KEY = '426f810df3e3df7709999e855549a62cbf7de4412b0a73f96372d5edaadf73c1'

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, status TEXT, score TEXT)''')
    conn.commit()
    conn.close()

init_db()

# SECURITY FIX: Clickjacking se bachne ke liye headers add kiye
@app.after_request
def add_header(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

def check_url_type(url):
    regex = re.compile(r'^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(/.*)?$')
    if not re.match(regex, url):
        return "JUST_TEXT"
    return "URL_FORMAT"

# --- ROUTES START ---

@app.route('/')
def home():
    return render_template('odisha_home.html')

@app.route('/scanner')
def scanner_page():
    return render_template('index.html')

@app.route('/admin')
def admin():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC")
    history = c.fetchall()
    conn.close()
    return render_template('admin.html', history=history)

@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

@app.route('/game')
def game():
    return render_template('game.html')

@app.route('/awareness')
def awareness():
    return render_template('awareness.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()
    url_type = check_url_type(url)
    
    if url_type == "JUST_TEXT":
        status, icon, color = "TEXT", "📝", "#f39c12"
        msg_odia, msg_hindi, msg_eng = "ଏହା ଏକ ମାମୁଲି ଟେକ୍ସଟ୍ ଅଟେ |", "यह सामान्य टेक्स्ट है।", "This is just text."
        trust_score = "N/A"
    else:
        try:
            temp_url = url if url.startswith('http') else 'http://' + url
            url_id = base64.urlsafe_b64encode(temp_url.encode()).decode().strip("=")
            headers = {"x-apikey": API_KEY}
            response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=10)

            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                trust_score = int(((total - malicious) / total) * 100) if total > 0 else 100
                status = "UNSAFE" if malicious > 0 else "SAFE"
                icon = "⚠️" if malicious > 0 else "✅"
                color = "#c0392b" if malicious > 0 else "#27ae60"
                msg_odia = "ଏହି ଲିଙ୍କ୍ ଟି ବିପଦପୂର୍ଣ୍ଣ |" if malicious > 0 else "ଏହି ଲିଙ୍କ୍ ଟି ସୁରକ୍ଷିତ |"
                msg_hindi = "खतरनाक लिंक।" if malicious > 0 else "सुरक्षित लिंक।"
                msg_eng = "Dangerous link." if malicious > 0 else "Safe link."
            else:
                status, icon, color = "NOT_FOUND", "🔍", "#7f8c8d"
                msg_odia, msg_hindi, msg_eng = "ଡୋମେନ୍ ମିଳିଲା ନାହିଁ |", "डोमेन नहीं मिला।", "Domain not found."
                trust_score = "0"
        except:
            status, icon, color = "ERROR", "❌", "#7f8c8d"
            msg_odia, msg_hindi, msg_eng = "ସଂଯୋଗ ବିଫଳ |", "कनेक्शन विफल।", "Connection failed."
            trust_score = "N/A"

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, status, score) VALUES (?, ?, ?)", (url, status, str(trust_score)))
    conn.commit()
    conn.close()

    html_content = f"""
    <html>
    <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ margin: 0; padding: 0; overflow: hidden; background: black; font-family: 'Segoe UI', sans-serif; }}
        canvas {{ display: block; }}
        .overlay {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; background: rgba(0,0,0,0.6); }}
        .card {{ background: rgba(0, 0, 0, 0.85); padding: 20px; border-radius: 20px; border: 3px solid {color}; text-align: center; width: 90%; max-width: 450px; box-shadow: 0 0 40px {color}; color: {color}; backdrop-filter: blur(5px); z-index: 100; }}
        .msg-box {{ background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; margin: 20px 0; text-align: left; color: #fff; border-left: 5px solid {color}; font-size: 14px; }}
        .btn {{ display:inline-block; margin-top: 20px; padding: 12px 30px; background: {color}; color: #000; text-decoration: none; font-weight: bold; border-radius: 8px; transition: 0.3s; }}
        .btn:hover {{ transform: scale(1.05); box-shadow: 0 0 20px white; }}
    </style>
    </head>
    <body>
        <canvas id="matrix"></canvas>
        <div class="overlay">
            <div class="card">
                <h1 style="font-size: 50px; margin:0;">{icon}</h1>
                <h2 style="letter-spacing: 2px; font-size: 1.5rem;">TRUST SCORE: {trust_score}%</h2>
                <div class="msg-box">
                    <p><b>ODIA:</b> {msg_odia}</p>
                    <p><b>HINDI:</b> {msg_hindi}</p>
                    <p><b>ENG:</b> {msg_eng}</p>
                </div>
                <a href="/scanner" class="btn">🛡️ SECURE BACK</a>
            </div>
        </div>
        <script>
            const canvas = document.getElementById('matrix');
            const ctx = canvas.getContext('2d');
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            const fontSize = 16;
            const columns = canvas.width / fontSize;
            const drops = Array(Math.floor(columns)).fill(1);
            function draw() {{
                ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
                ctx.fillRect(0, 0, canvas.width, canvas.height);
                ctx.fillStyle = "{color}"; 
                ctx.font = fontSize + "px monospace";
                for (let i = 0; i < drops.length; i++) {{
                    const text = chars.charAt(Math.floor(Math.random() * chars.length));
                    ctx.fillText(text, i * fontSize, drops[i] * fontSize);
                    if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) drops[i] = 0;
                    drops[i]++;
                }}
            }}
            window.onresize = () => {{ canvas.width = window.innerWidth; canvas.height = window.innerHeight; }};
            setInterval(draw, 35);
        </script>
    </body>
    </html>
    """
    return make_response(html_content)

if __name__ == '__main__':
    # CRASH PROTECTION: Server port dynamically pick karega
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)