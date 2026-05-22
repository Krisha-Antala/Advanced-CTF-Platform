# 🚩 CTF Platform

A fully-featured **Capture The Flag (CTF) Learning Platform** with interactive cybersecurity challenges, built with Flask and styled with a stunning **Cyberpunk/Hacker aesthetic**.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-2.x-green)
![SQLite](https://img.shields.io/badge/Database-SQLite-yellow)
![License](https://img.shields.io/badge/License-MIT-purple)

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Screenshots](#screenshots)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Challenges](#challenges)
7. [Security Features](#security-features)
8. [Theme & UI](#theme--ui)
9. [Database Schema](#database-schema)
10. [API Routes](#api-routes)
11. [Project Structure](#project-structure)
12. [Configuration](#configuration)
13. [Contributing](#contributing)
14. [License](#license)

---

## 🔍 Overview

This CTF Platform is designed for **learning and practicing cybersecurity concepts** in a safe, controlled environment. It simulates real-world vulnerabilities including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Buffer Overflow
- Cryptography

Each challenge is interactive with step-by-step guidance, making it perfect for beginners while still being engaging for experienced practitioners.

---

## ✨ Features

### Core Functionality
| Feature | Description |
|---------|-------------|
| **User Registration** | Create accounts with username and password |
| **Secure Authentication** | Session-based login with password hashing |
| **Challenge Dashboard** | Browse all available challenges with titles, descriptions, and point values |
| **Flag Submission** | Submit flags to solve challenges and earn points |
| **Live Scoreboard** | Real-time rankings of all users by score |
| **Practice Mode** | Re-solve already completed challenges for practice |

### Interactive Challenges
| Challenge | Type | Points | Description |
|-----------|------|--------|-------------|
| Basic Injection | SQL Injection | 100 | Bypass a fake admin login panel using SQL injection |
| XSS Attack | Cross-Site Scripting | 150 | Inject malicious scripts into a vulnerable comment section |
| Buffer Overflow | Memory Exploit | 200 | Overflow a 16-byte buffer to corrupt program flow |
| Crypto Challenge | Cryptography | 100 | Decrypt a dynamically generated Caesar cipher message |

### Anti-Cheating & Bot Protection
- 🤖 **Honeypot Fields**: Hidden form fields to detect automated bots
- ⏱️ **Solve Time Tracking**: Records how long each challenge takes
- 🔄 **Attempt Limiting**: Configurable max attempts before CAPTCHA
- 🧮 **CAPTCHA System**: Simple math verification when suspicious activity detected
- 🎯 **Dynamic Flags**: Crypto challenge generates unique flags per session

---

## 🖥️ Screenshots

The platform features a stunning **Cyberpunk/Sci-Fi Neon theme** with:
- Dark blue/black background (#0b1021)
- Electric cyan primary color (#00ffcc)
- Electric blue secondary color (#0077ff)
- Neon red/pink for errors (#ff3366)
- Animated particle background
- Glitch text effects on headers

---

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Step-by-Step Setup

1. **Clone or Download the Repository**
   ```bash
   git clone <repository-url>
   cd "CTF platform"
   ```

2. **Create a Virtual Environment (Recommended)**
   ```bash
   python -m venv venv

   # Windows
   venv\Scripts\activate

   # Linux/Mac
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the Database**
   ```bash
   python db_init.py
   ```
   This creates `Krisha.db` with:
   - Users table (for authentication)
   - Challenges table (pre-seeded with 4 challenges)
   - Submissions table (tracks solved challenges)

5. **Run the Application**
   ```bash
   python app.py
   ```

6. **Access the Platform**
   Open your browser and navigate to:
   ```
   http://localhost:5000
   ```

---

## 🎮 Usage

### Getting Started
1. **Register**: Create a new account on the registration page
2. **Login**: Access your dashboard
3. **Choose a Challenge**: Click any challenge from the dashboard
4. **Solve It**: Follow the on-screen instructions for each challenge type
5. **Submit Flag**: Enter the flag in the format `CTF{...}`
6. **Check Scoreboard**: See your ranking among all users

### User Flow
```
Login/Register → Dashboard → Select Challenge → Solve → Submit Flag → Earn Points → Scoreboard
```

---

## 🔓 Challenges

### Challenge 1: Basic Injection (SQL Injection)
**Objective**: Bypass the Admin Login Panel

**How It Works**:
- A fake "Admin Login Portal" is displayed
- The system simulates a vulnerable SQL query
- Users must craft input that bypasses authentication

**Solution**:
Enter one of these in the Username OR Password field:
```
' OR '1'='1
" OR "1"="1
admin'--
```

**What You Learn**:
- How SQL injection manipulates database queries
- Why input validation and parameterized queries are crucial

---

### Challenge 2: XSS Attack (Cross-Site Scripting)
**Objective**: Inject a script into the comment section

**How It Works**:
- A comment form is displayed
- Comments are rendered without sanitization (using Jinja's `| safe` filter)
- Injected scripts will execute in the browser

**Solution**:
Post a comment containing:
```html
<script>alert('XSS')</script>
```

**What You Learn**:
- How XSS attacks steal user data or hijack sessions
- Why output encoding and Content Security Policy (CSP) matter

---

### Challenge 3: Buffer Overflow
**Objective**: Overflow a 16-byte buffer to gain control

**How It Works**:
- A simulated buffer of 16 bytes exists
- Input beyond 16 characters "overflows" into adjacent memory
- Input between 17-32 characters overwrites the "return pointer"
- Input beyond 32 characters causes a "segmentation fault"

**Solution**:
Enter any string longer than 16 characters but less than 33:
```
AAAAAAAAAAAAAAAAAAAAA  (21 A's)
```

**What You Learn**:
- How buffer overflows corrupt memory
- Why bounds checking and safe string functions are essential

---

### Challenge 4: Crypto Challenge (Caesar Cipher)
**Objective**: Decrypt the intercepted message

**How It Works**:
- A random 8-character plaintext is generated per session
- It's encrypted using Caesar Cipher with a +3 shift
- The ciphertext is displayed; you must decrypt it

**Solution**:
Shift each letter back by 3 positions:
- `D` → `A`, `E` → `B`, `F` → `C`, etc.
- Numbers remain unchanged
- Submit as `CTF{PLAINTEXT}`

**Example**:
```
Ciphertext: GHIJKL9X
Plaintext:  DEFGHI9U
Flag:       CTF{DEFGHI9U}
```

**What You Learn**:
- Basic cryptanalysis techniques
- How weak encryption can be broken

---

## 🛡️ Security Features

### Honeypot Detection
```html
<input type="text" name="email" style="display:none">
```
- Hidden field invisible to humans
- Bots automatically fill it in
- Server rejects submissions with this field populated

### Solve Time Tracking
```python
if f"start_{cid}" not in session:
    session[f"start_{cid}"] = time.time()
```
- Timer starts when challenge page loads
- Flags submitted too quickly trigger suspicion

### CAPTCHA System
```
⚠️ Security Check: What is 3 + 4?
```
- Triggered when suspicious activity detected
- Simple math problem to verify human presence

### Session-Based Authentication
- Flask sessions with secret key
- Password hashing (if implemented in registration)
- User ID stored in session, not cookies

---

## 🎨 Theme & UI

### Color Palette
| Variable | Color | Usage |
|----------|-------|-------|
| `--color-bg` | #0b1021 | Page background |
| `--color-bg-alt` | rgba(16,23,41,0.7) | Card backgrounds |
| `--color-primary` | #00ffcc | Cyan accents, success |
| `--color-secondary` | #0077ff | Blue accents |
| `--color-accent` | #ffffff | White text |
| `--color-text-muted` | #a0aab5 | Grey secondary text |
| `--color-error` | #ff3366 | Red errors, warnings |

### Animations

#### Particle Background (`particles.js`)
- Canvas-based particle system
- Particles connect with lines when close
- Mouse interaction pushes particles away
- Responsive to window resize

#### Glitch Text Effect (CSS)
- Three-layer text with offsets
- Animated `clip-rect` for scanning effect
- Skew animation for distortion
- Uses `::before` and `::after` pseudo-elements

### Components
- **Glass Cards**: Frosted glass effect with `backdrop-filter: blur`
- **Gradient Buttons**: Cyan-to-blue gradient with glow
- **Input Fields**: Dark with cyan focus glow
- **Responsive Layout**: Flexbox-based, mobile-friendly

---

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    score INTEGER DEFAULT 0
);
```

### Challenges Table
```sql
CREATE TABLE challenges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    flag TEXT NOT NULL,
    points INTEGER DEFAULT 100
);
```

### Submissions Table
```sql
CREATE TABLE submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    challenge_id INTEGER,
    correct INTEGER,
    solve_time REAL,
    attempts INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Pre-Seeded Challenges
| ID | Title | Points | Flag |
|----|-------|--------|------|
| 1 | Basic Injection | 100 | CTF{sql_injection_master} |
| 2 | XSS Attack | 150 | CTF{xss_hunter} |
| 3 | Buffer Overflow | 200 | CTF{overflow_ninja} |
| 4 | Crypto Challenge | 100 | (Dynamic per session) |

---

## 🔗 API Routes

| Route | Method | Description | Auth Required |
|-------|--------|-------------|---------------|
| `/` | GET, POST | Login page | No |
| `/register` | GET, POST | Registration page | No |
| `/dashboard` | GET | Challenge list | Yes |
| `/challenge/<id>` | GET, POST | Individual challenge | Yes |
| `/scoreboard` | GET | User rankings | Yes |
| `/logout` | GET | End session | Yes |

---

## 📁 Project Structure

```
CTF platform/
│
├── app.py                 # Main Flask application
│   ├── Routes (login, register, dashboard, challenge, scoreboard, logout)
│   ├── Database helpers
│   ├── Challenge logic (SQLi, XSS, Buffer, Crypto)
│   └── Context processor (site_name, year)
│
├── db_init.py             # Database initialization
│   ├── Creates tables (users, challenges, submissions)
│   └── Seeds sample challenges
│
├── Krisha.db              # SQLite database file
│
├── requirements.txt       # Python dependencies
│
├── README.md              # This documentation
│
├── static/
│   ├── style.css          # Complete CSS theme
│   │   ├── Color variables
│   │   ├── Reset & base styles
│   │   ├── Layout utilities
│   │   ├── Glitch header animations
│   │   ├── Glass card component
│   │   ├── Form & button styles
│   │   └── Utility classes
│   │
│   └── particles.js       # Interactive background
│       ├── Particle class
│       ├── Mouse tracking
│       ├── Connection lines
│       └── Animation loop
│
└── templates/
    ├── base.html          # Base layout with particle canvas
    ├── login.html         # Login form
    ├── register.html      # Registration form
    ├── dashboard.html     # Challenge grid
    ├── challenge.html     # Dynamic challenge UI
    │   ├── SQLi form
    │   ├── XSS comment section
    │   ├── Buffer input
    │   ├── Crypto display
    │   └── Flag submission
    └── scoreboard.html    # Rankings table
```

---

## ⚙️ Configuration

### Environment Variables (Optional)
```python
app.secret_key = "your-secret-key"  # Change in production!
```

### Customization Points
| File | What to Customize |
|------|-------------------|
| `style.css:root` | Color palette variables |
| `app.py:inject_globals` | Site name, additional globals |
| `db_init.py:challenges` | Add/modify challenge content |
| `particles.js` | Particle count, colors, behavior |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-challenge`)
3. Commit changes (`git commit -am 'Add new challenge'`)
4. Push to branch (`git push origin feature/new-challenge`)
5. Open a Pull Request

### Ideas for Contribution
- Add more challenge types (CSRF, SSRF, etc.)
- Implement real password hashing (bcrypt)
- Add challenge categories/tags
- Create admin panel for managing challenges
- Add hints system with point deductions

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## BY KRISHA AND NIDHI

Built with ❤️ for learning cybersecurity fundamentals.

---

*Happy Hacking! 🎯*
