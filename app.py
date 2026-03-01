from flask import Flask, render_template, request, redirect, session
import sqlite3
from datetime import timedelta
import time

app = Flask(__name__)
app.secret_key = "ctfsecret"


app.permanent_session_lifetime = timedelta(minutes=15)

def db():
    return sqlite3.connect("database.db")

@app.context_processor
def inject_globals():
    return {
        'site_name': 'CTF Platform',
        'year': time.localtime().tm_year
    }

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT id FROM users WHERE username=? AND password=?",
            (u, p)
        )
        user = cur.fetchone()
        con.close()

        if user:
            session.permanent = True
            session["user"] = user[0]
            return redirect("/dashboard")

    return render_template("login.html")


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
            return render_template("register.html", error="Username already registered")

        cur.execute(
            "INSERT INTO users (username, password, score) VALUES (?, ?, 0)",
            (u, p)
        )
        con.commit()
        con.close()
        return redirect("/")

    return render_template("register.html")
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    con = db()
    cur = con.cursor()
    cur.execute("SELECT * FROM challenges")
    challenges = cur.fetchall()
    con.close()

    return render_template("dashboard.html", challenges=challenges)

@app.route("/challenge/<int:cid>", methods=["GET", "POST"])
def challenge(cid):
    if "user" not in session:
        return redirect("/")

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
    suspicious = False
    solve_time = None
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
                msg = "Comment posted. (Try injecting a script tag!)"

    if cid == 3:
        if request.method == "POST" and request.form.get('buffer_input'):
            buf_input = request.form.get('buffer_input')


            if len(buf_input) > 32:
                 msg = "Segmentation Fault! (You crashed the program, but too hard)"
            elif len(buf_input) > 16:
                 msg = f"Buffer Overflow Successful! You overwrote the return pointer. Flag: {ch[3]}"
            else:
                 msg = f"Buffer normal. {len(buf_input)}/16 bytes used. No overflow."
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
                 msg = "Invalid credentials. Try harder."

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

            if solved:
                if flag == correct_flag:
                    msg = f"Practice mode: correct flag. Solve time: {solve_time}s"
                else:
                    msg = "Practice mode: wrong flag."
            else:
                if flag == correct_flag:
                    
                    cur.execute("""
                        INSERT INTO submissions
                        (user_id, challenge_id, correct, solve_time, attempts)
                        VALUES (?, ?, 1, ?, ?)
                    """, (session["user"], cid, solve_time, attempts))

                    cur.execute("""
                        UPDATE users SET score = score + ?
                        WHERE id = ?
                    """, (ch[4], session["user"]))

                    con.commit()
                    solved = True
                    msg = f"Correct! You earned {ch[4]} points. Solved in {solve_time}s."
                else:
                    msg = "Wrong flag."

    con.close()
    return render_template(
        "challenge.html",
        ch=ch,
        msg=msg,
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
        SELECT u.username, u.score, ROUND(COALESCE(SUM(s.solve_time), 0), 2) as total_time
        FROM users u
        LEFT JOIN submissions s ON u.id = s.user_id AND s.correct = 1
        GROUP BY u.id, u.username, u.score
        ORDER BY u.score DESC, total_time ASC
    """)
    users = cur.fetchall()
    con.close()

    return render_template("scoreboard.html", users=users)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/api/ai_helper", methods=["POST"])
def api_ai_helper():
    data = request.get_json(force=True) or {}
    question = (data.get('question') or '').strip()
    ctx = data.get('context') or {}
    ch_type = ctx.get('challenge_id')  # 1=SQLi, 2=XSS, 3=BOF, 4=Crypto
    name = ctx.get('challenge_name') or 'Challenge'

    # Basic rate-limit (per session)
    session_key = 'ai_helper_count'
    count = session.get(session_key, 0)
    if count > 50:
        return jsonify({'answer': 'Rate limit reached for practice mode. Try again later.'}), 429
    session[session_key] = count + 1

    # Hint logic
    def hint_sqli(q):
        return (
            "Try bypassing login using SQL injection. Look for ways to close the query and force a true condition. "
            "Example: `' OR 1=1--` might help you understand how the backend interprets input."
        )

    def hint_xss(q):
        return (
            "The comment box reflects your input using the `safe` filter. Try injecting a `<script>` tag. "
            "Use minimal payloads like `<script>alert(1)</script>` and observe if it executes."
        )

    def hint_bof(q):
        return (
            "The buffer is 16 bytes. Try sending input longer than that to overwrite memory. "
            "Start with 17–32 characters and observe how the system reacts."
        )

    def hint_crypto(q, ciphertext):
        return (
            f"Decrypt the Caesar cipher by shifting each letter back by 3. "
            f"Ciphertext: {ciphertext}. Wrap the result as `CTF{{PLAINTEXT}}`."
        )

    # Route to appropriate helper
    if ch_type == 1:
        answer = hint_sqli(question)
    elif ch_type == 2:
        answer = hint_xss(question)
    elif ch_type == 3:
        answer = hint_bof(question)
    elif ch_type == 4:
        answer = hint_crypto(question, ctx.get('ciphertext', ''))
    else:
        answer = (
            f"I’ll help with {name}. Describe what you’ve tried and I’ll guide you step-by-step."
        )

        return jsonify({'answer': answer})
    
    if __name__ == "__main__":
        app.run(debug=True)
