from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for
import sqlite3
from datetime import timedelta
import time

app = Flask(__name__)
app.secret_key = "ctfsecret"


app.permanent_session_lifetime = timedelta(minutes=15)

def db():
    return sqlite3.connect("Krisha.db")

@app.context_processor
def inject_globals():
    user_data = None
    solved_count = 0
    total_challenges = 0
    if "user" in session:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT username, score, tab_switches FROM users WHERE id=?", (session["user"],))
        user_data = cur.fetchone()
        
        cur.execute("SELECT COUNT(DISTINCT challenge_id) FROM submissions WHERE user_id=? AND correct=1", (session["user"],))
        solved_count = cur.fetchone()[0] or 0
        
        cur.execute("SELECT COUNT(*) FROM challenges")
        total_challenges = cur.fetchone()[0] or 4
        
        con.close()
    
    return {
        'site_name': 'CTF Platform',
        'year': time.localtime().tm_year,
        'username': user_data[0] if user_data else None,
        'user_score': user_data[1] if user_data else 0,
        'tab_switches': user_data[2] if user_data else 0,
        'solved_count': solved_count,
        'total_challenges': total_challenges,
        'comp_start': session.get('comp_start')
    }

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT id, username FROM users WHERE username=? AND password=?",
            (u, p)
        )
        user = cur.fetchone()
        con.close()

        if user:
            session.permanent = True
            session["user"] = user[0]
            session["username"] = user[1]
            return redirect(url_for('landing'))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/instructions", methods=["GET", "POST"])
def landing():
    if "user" not in session:
        return redirect(url_for('login'))
    
    if request.method == "POST":
        session["instructions_viewed"] = True
        session["comp_start"] = int(time.time() * 1000) # Store in milliseconds for JS
        return redirect(url_for('dashboard'))

    return render_template("landing.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        con = db()
        cur = con.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (u,))
        if cur.fetchone():
            con.close()
            flash("Username already registered.", "error")
            return render_template("register.html")

        cur.execute(
            "INSERT INTO users (username, password, score) VALUES (?, ?, 0)",
            (u, p)
        )
        con.commit()
        con.close()
        flash(f"User '{u}' Registered Successfully! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template("register.html")
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for('login'))
    
    # Enforce viewing instructions/landing page first
    if not session.get("instructions_viewed"):
        return redirect(url_for('landing'))

    con = db()
    cur = con.cursor()
    
    # Fetch challenges with user's specific solve status and time (unique per challenge)
    cur.execute("""
        SELECT c.id, c.title, c.description, c.flag, c.points, c.level, 
               MAX(s.correct), MIN(s.solve_time)
        FROM challenges c
        LEFT JOIN submissions s ON c.id = s.challenge_id AND s.user_id = ? AND s.correct = 1
        GROUP BY c.id
    """, (session["user"],))
    challenges = cur.fetchall()
    con.close()

    return render_template("dashboard.html", challenges=challenges)

@app.route("/challenge/<int:cid>", methods=["GET", "POST"])
def challenge(cid):
    if "user" not in session:
        return redirect(url_for('login'))
    
    if not session.get("instructions_viewed"):
        return redirect(url_for('landing'))

    con = db()
    cur = con.cursor()

    cur.execute("SELECT * FROM challenges WHERE id=?", (cid,))
    ch = cur.fetchone()

    if not ch:
        con.close()
        return "Challenge not found", 404

    if f"start_{cid}" not in session:
        session[f"start_{cid}"] = time.time()

    cur.execute("""
        SELECT solve_time FROM submissions
        WHERE user_id=? AND challenge_id=? AND correct=1
    """, (session["user"], cid))
    solved_row = cur.fetchone()
    solved = solved_row is not None

    msg = ""
    error_type = None   # "sqli" | "xss" | "buffer" | "crypto" | "flag"
    suspicious = False
    solve_time = solved_row[0] if solved else None
    ciphertext = None

  
    if cid == 1:
      
        pass

    xss_content = None
    if cid == 2:
        if request.method == "POST" and request.form.get('comment'):
            comment = request.form.get('comment')
            xss_content = comment 

            if "<script>" in comment.lower():
                msg = f"XSS Successful! The flag is: {ch[3]}"
            else:
                msg = "Invalid script injection. No script tag was detected in your comment."
                error_type = "xss"

    if cid == 3:
        if request.method == "POST" and request.form.get('buffer_input'):
            buf_input = request.form.get('buffer_input')


            if len(buf_input) > 32:
                msg = "Segmentation fault. Your input caused a program crash — the buffer was exceeded too far."
                error_type = "buffer"
            elif len(buf_input) > 16:
                msg = f"Buffer Overflow Successful! You overwrote the return pointer. Flag: {ch[3]}"
            else:
                msg = f"Buffer not overflowed. Your input was only {len(buf_input)} bytes — not enough to overflow the buffer."
                error_type = "buffer"
    if cid == 4:
        import random, string
        if f"crypto_flag_{cid}" not in session:
         
            plaintext = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            session[f"crypto_flag_{cid}"] = plaintext
         
            shifted = ""
            for char in plaintext:
                if char.isalpha():
                    shifted += chr((ord(char) - 65 + 3) % 26 + 65)
                else:
                    shifted += char
            session[f"crypto_cipher_{cid}"] = shifted

        ciphertext = session.get(f"crypto_cipher_{cid}")


    if request.method == "POST":

        if request.form.get("email"):
            suspicious = True
            msg = "Bot detected."
            con.close()
            return render_template(
                "challenge.html", ch=ch, msg=msg, solved=solved, suspicious=True, ciphertext=ciphertext
            )

        if cid == 1 and request.form.get('admin_user'):
            u = request.form.get('admin_user')
            p = request.form.get('admin_pass')
           
            check_val = (u + p).upper()
            if "'" in u or "'" in p or '"' in u or '"' in p or " OR " in check_val or "=" in u or "=" in p:
                 flag = ch[3]
                 msg = f"Logged in as Admin! The flag is: {flag}"
               
            else:
                msg = "Invalid SQL injection attempt. The login was not bypassed."
                error_type = "sqli"

            con.close()
            return render_template(
                "challenge.html", ch=ch, msg=msg, solved=solved, suspicious=False, ciphertext=ciphertext, xss_content=locals().get('xss_content')
            )

        if "flag" in request.form:
            flag = request.form.get("flag", "").strip()


            start_time = session.get(f"start_{cid}", time.time())
            solve_time = round(time.time() - start_time, 2)

            if solve_time < 0: 
                suspicious = True
                msg = "Suspicious activity: solved too fast. CAPTCHA required."
                con.close()
                return render_template(
                    "challenge.html", ch=ch, msg=msg, solved=solved, suspicious=True, ciphertext=ciphertext, xss_content=locals().get('xss_content')
                )

            attempts = session.get(f"attempts_{cid}", 0) + 1
            session[f"attempts_{cid}"] = attempts

            if request.form.get("captcha") is not None:
                if request.form.get("captcha") != "7":
                    msg = "CAPTCHA failed."
                    con.close()
                    return render_template(
                        "challenge.html", ch=ch, msg=msg, solved=solved, suspicious=True, ciphertext=ciphertext, xss_content=locals().get('xss_content')
                    )

            correct_flag = ch[3]

            if cid == 4:
             
                correct_flag = f"CTF{{{session.get(f'crypto_flag_{cid}')}}}"

            if flag == correct_flag:
                # Always record a successful submission row
                cur.execute("""
                    INSERT INTO submissions 
                    (user_id, challenge_id, correct, solve_time, attempts)
                    VALUES (?, ?, 1, ?, ?)
                """, (session["user"], cid, solve_time, attempts))
                
                # Reset session attempts for this challenge for next solve cycle
                session[f"attempts_{cid}"] = 0
                
                # Only award points and original solve message if it's the first time
                if not solved:
                    cur.execute("""
                        UPDATE users SET score = score + ?
                        WHERE id = ?
                    """, (ch[4], session["user"]))
                    msg = f"Congratulations! Correct flag. +{ch[4]} points."
                else:
                    msg = "Correct flag! Participation re-recorded."
                
                con.commit()
            else:
                if cid == 4:
                    msg = "Invalid decryption. The flag you entered does not match the decrypted ciphertext."
                    error_type = "crypto"
                else:
                    msg = "Invalid flag. The flag you entered is incorrect."
                    error_type = "flag"

    con.close()
    return render_template(
        "challenge.html",
        ch=ch,
        msg=msg,
        error_type=error_type,
        solved=solved,
        solve_time=solve_time,
        suspicious=suspicious,
        ciphertext=ciphertext,
        xss_content=locals().get('xss_content')
    )


@app.route("/scoreboard")
def scoreboard():
    if "user" not in session:
        return redirect("/")

    con = db()
    cur = con.cursor()

    cur.execute("""
        SELECT u.username, u.score, ROUND(COALESCE(SUM(s.solve_time), 0), 2) as total_time, u.ai_assisted, u.tab_switches
        FROM users u
        LEFT JOIN submissions s ON u.id = s.user_id AND s.correct = 1
        GROUP BY u.id, u.username, u.score, u.ai_assisted, u.tab_switches
        ORDER BY 
            (u.tab_switches > 0) ASC, 
            u.ai_assisted ASC, 
            u.tab_switches ASC, 
            u.score DESC, 
            total_time ASC
    """)
    users = cur.fetchall()
    con.close()

    return render_template("scoreboard.html", users=users)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/api/ai_helper", methods=["POST"])
def api_ai_helper():
    data = request.get_json(force=True) or {}
    question = (data.get('question') or '').strip()
    ctx = data.get('context') or {}
    ch_id = ctx.get('challenge_id')
    ch_name = ctx.get('challenge_name')
    ciphertext = ctx.get('ciphertext')

    if "user" in session:
        con = db()
        cur = con.cursor()
        cur.execute("UPDATE users SET ai_assisted = 1 WHERE id = ?", (session["user"],))
        con.commit()
        con.close()

    # Rate limiting (increased slightly for better UX)
    session_key = 'ai_helper_count'
    count = session.get(session_key, 0)
    if count > 200:
        return jsonify({'answer': '🚀 Whoa there, speedy! My neural circuits need a break. Rate limit reached.'}), 429
    session[session_key] = count + 1

    q_lower = question.lower()
    # Ensure ch_id is handled as an integer for database and session lookups
    try:
        ch_id = int(ch_id) if ch_id is not None else None
    except (ValueError, TypeError):
        ch_id = None

    # Topic mapping with synonyms
    topics = {
        'sqli': ['sql', 'injection', 'sqli', 'login', 'admin', 'bypass', 'database', 'query', "' or 1=1"],
        'xss': ['xss', 'script', 'inject', 'comment', 'alert', 'javascript', 'cross-site', 'tags'],
        'buffer': ['buffer', 'overflow', 'bof', 'memory', 'crash', 'pointer', 'segmentation', 'stack', 'shellcode'],
        'crypto': ['crypto', 'caesar', 'cipher', 'shift', 'decode', 'encode', 'secret', 'classic', 'alphabet'],
    }

    # Identify topic
    current_topic = None
    for topic, keywords in topics.items():
        if any(k in q_lower for k in keywords):
            current_topic = topic
            break
    
    # Fallback to current challenge type if no specific topic mentioned
    if not current_topic and ch_name:
        name_lower = ch_name.lower()
        if "sql" in name_lower: current_topic = 'sqli'
        elif "xss" in name_lower: current_topic = 'xss'
        elif "buffer" in name_lower: current_topic = 'buffer'
        elif "crypto" in name_lower: current_topic = 'crypto'

    ch_info = None
    con = db()
    cur = con.cursor()
    if ch_id:
        cur.execute("SELECT * FROM challenges WHERE id=?", (ch_id,))
        ch_info = cur.fetchone()
    
    # If no challenge ID or not found, try to find by topic keywords
    if not ch_info and current_topic:
        topic_map = {
            'sqli': 'Injection',
            'xss': 'XSS',
            'buffer': 'Buffer',
            'crypto': 'Crypto'
        }
        search_term = topic_map.get(current_topic, current_topic)
        cur.execute("SELECT * FROM challenges WHERE title LIKE ? OR description LIKE ?", (f'%{search_term}%', f'%{search_term}%'))
        ch_info = cur.fetchone()
    con.close()

    # Define knowledge base with dynamic components
    kb = {
    'sqli': {
        "title": "SQL Injection (SQLi)",
        "concept": "SQL Injection occurs when user input is inserted directly into SQL queries without validation.",
        "hint": "Try bypassing the login by making the SQL condition always TRUE. Example payload: ' OR '1'='1' --"
    },

    'xss': {
        "title": "Cross-Site Scripting (XSS)",
        "concept": "XSS allows attackers to inject JavaScript into a webpage that executes in the browser.",
        "hint": "The comment box does not sanitize input. Try injecting a script like: <script>alert('XSS')</script>"
    },

    'buffer': {
        "title": "Buffer Overflow (BoF)",
        "concept": "Buffer overflow happens when input exceeds the allocated memory buffer.",
        "hint": "The buffer size is 16 bytes. Try sending more than 16 characters such as: AAAAAAAAAAAAAAAAAAAA"
    },

    'crypto': {
        "title": "Caesar Cipher (Cryptography)",
        "concept": "A Caesar cipher shifts letters in the alphabet by a fixed amount.",
        "hint": "The cipher uses +3 shift. Decrypt by shifting each letter 3 positions backward in the alphabet."
    }
}
    # Responses
    prefix = random.choice([
        "Analysis complete. ",
        "Greetings. Here are the results: ",
        "Deep Dive initiated. Findings: ",
        "Neural Link active. Technical brief: "
    ])


    
    # Check if they are greeting
    if any(w in q_lower for w in ['hi', 'hello', 'hey', 'start', 'greet']):
         return jsonify({'answer': f"{prefix}\n\nI am your CTF Assistant. I can explain vulnerabilities and provide hints for any challenge on this platform.\n\nHow can I help you today?"})

    # Check if they want the flag/payload
    wants_solution = any(w in q_lower for w in ['flag', 'payload', 'exactly', 'solution', 'how to solve', 'give me the answer', 'cheat', 'ans', 'result'])

    # If we have challenge info, we can ALWAYS be effective
    if ch_info:
        # Get metadata
        title = ch_info[1]
        desc = ch_info[2]
        
        if wants_solution:
            return jsonify({'answer': (
                f"{prefix}\n\n"
                f"### Protocol Restriction: Solution Requested for {title}\n"
                f"To maintain the integrity of the mission, direct flag disclosure is restricted.\n\n"
                f"**Please fill necessary details and then enter the CTF flag.**\n\n"
                f"I can provide technical hints or analysis of the system architecture ({desc}) but I cannot solve it for you."
            )})
        
        # If they don't want the solution specifically, but we have a topic, give the hint
        if current_topic in kb:
            item = kb[current_topic]
            return jsonify({'answer': (
                f"{prefix}\n\n"
                f"### Tactical Advice: {item['title']}\n"
                f"**The Concept:** {item['concept']}\n"
                f"**Operational Hint:** {item['hint']}\n\n"
                f"Remember to fill necessary details and then enter the CTF flag manually once the vulnerability is successfully exploited."
            )})
        
        # Generic hint for unknown topic but known challenge
        return jsonify({'answer': (
                f"{prefix}\n\n"
                f"### Analysis of {title}\n"
                f"**Current Objective:** {desc}\n\n"
                f"Please analyze the challenge carefully. I can provide hints on general concepts, but the final exploitation is up to you."
            )})

    # Fallback if no specific challenge context
    if current_topic in kb:
         item = kb[current_topic]
         return jsonify({'answer': (
                f"{prefix}\n\n"
                f"### General Intel: {item['title']}\n"
                f"**Concept:** {item['concept']}\n"
                f"**Advice:** Review common techniques for this vulnerability type. I can provide more specific hints if you are on a challenge page."
            )})

    return jsonify({'answer': (
        f"I am ready to help, but I need to know which challenge you are working on.\n\n"
        f"I can provide perfect answers for SQL Injection, XSS, Buffer Overflows, and Cryptography.\n\n"
        f"Please select a challenge or ask for a general concept."
    )})
import random



@app.route("/exit_portal")
def exit_portal():
    if "user" not in session:
        return redirect(url_for('login'))
    return render_template("exit_portal.html")

# Webview API for lockdown functions
class Api:
    def close_app(self):
        import os
        os._exit(0)
    
    def minimize_app(self):
        if 'window' in globals():
            globals()['window'].minimize()



#tab stwich 
@app.route("/api/increment_tab_switch", methods=["POST"])
def increment_tab_switch():
    if "user" not in session:
        return jsonify({"success": False}), 403
    
    # Add a 5-second cooldown to prevent triple-counting from multiple tabs/events
    now = time.time()
    last_increment = session.get('last_tab_switch_time', 0)
    if now - last_increment < 5:
        return jsonify({"success": True, "note": "cooldown active"})
    
    session['last_tab_switch_time'] = now
    
    con = db()
    cur = con.cursor()
    cur.execute("UPDATE users SET tab_switches = tab_switches + 1 WHERE id = ?", (session["user"],))
    con.commit()
    con.close()
    return jsonify({"success": True})


@app.route("/report")
def report():
    if "user" not in session:
        return redirect("/")
    
    con = db()
    cur = con.cursor()
    cur.execute("SELECT username, score, tab_switches, ai_assisted FROM users WHERE id=?", (session["user"],))
    user_stats = cur.fetchone()     
    
    cur.execute("""
        SELECT c.title, MIN(s.solve_time), COUNT(s.id)
        FROM submissions s
        JOIN challenges c ON s.challenge_id = c.id
        WHERE s.user_id = ? AND s.correct = 1
        GROUP BY c.id
    """, (session["user"],))
    solved_challenges = cur.fetchall()
    con.close()
    
    return render_template("report.html", user_stats=user_stats, solved_challenges=solved_challenges)

def start_server():
    app.run(port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    import threading
    try:
        import webview
        
        # Start Flask Server in background thread
        t = threading.Thread(target=start_server)
        t.daemon = True
        t.start()
        
        # Create Fullscreen Lockdown Window
        api = Api()
        global window
        window = webview.create_window(
            "CTF Lockdown Browser",
            "http://localhost:5000",
            fullscreen=True,
            js_api=api
        )
        webview.start()
    except ImportError:
        print("pywebview not installed. Running in standard web mode...")
        app.run(debug=True)
