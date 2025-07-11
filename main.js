// 📁 File: index.js
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const MySQL = require('mysql2');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const validator = require('validator');
const { Resend } = require('resend');

const app = express();
const resend = new Resend(process.env.RESEND_API_KEY);

// ✅ Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'otp-secret-key',
  resave: false,
  saveUninitialized: true
}));

// 🔐 AES helpers
function encrypt(text, keyHex) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText, keyHex) {
  const [ivHex, encrypted] = encryptedText.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ✅ MySQL
const db = MySQL.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) throw err;
  console.log("✅ Connected to MySQL");
});

function sendOTP(email, otp, res) {
  resend.emails.send({
    from: process.env.RESEND_SENDER,
    to: email,
    subject: 'Your OTP for Voting',
    text: `Your OTP is ${otp}`
  }).then(() => {
    console.log("✅ OTP Sent to", email);
    res.sendFile(path.join(__dirname, 'public', 'otp.html'));
  }).catch((error) => {
    console.error("❌ Resend error:", error);
    res.send('❌ Failed to send OTP. Please try again.');
  });
}

// ✅ OTP: Send OTP
app.post('/send-otp', (req, res) => {
  console.log("🔥 Received body:", req.body);

  const rawEmail = req.body.email;

  if (!rawEmail || typeof rawEmail !== 'string') {
    return res.send('❌ Email is missing. <a href="/verify.html">Try again</a>');
  }

  const email = rawEmail.trim().toLowerCase();
  console.log("📩 Processed email:", email);

  if (!validator.isEmail(email)) {
    return res.send('❌ Invalid email address. <a href="/verify.html">Try again</a>');
  }

  const otp = Math.floor(100000 + Math.random() * 900000);
  req.session.email = email;
  req.session.otp = otp;
  req.session.otpTimestamp = Date.now();

  sendOTP(email, otp, res);
});

// 🔁 Resend OTP
app.post('/resend-otp', (req, res) => {
  const email = req.session.email;
  if (!email) return res.redirect('/verify.html');

  const otp = Math.floor(100000 + Math.random() * 900000);
  req.session.otp = otp;
  req.session.otpTimestamp = Date.now();

  sendOTP(email, otp, res);
});

// ✅ OTP: Verify OTP
app.post('/verify-otp', (req, res) => {
  const userOtp = req.body.otp;
  const now = Date.now();
  const otpTime = req.session.otpTimestamp;

  if (!otpTime || now - otpTime > 5 * 60 * 1000) {
    return res.send('❌ OTP expired. <a href="/verify.html">Request a new one</a>');
  }

  if (parseInt(userOtp) === req.session.otp) {
    req.session.verified = true;

    db.query('INSERT IGNORE INTO verified_emails (email) VALUES (?)', [req.session.email], (err) => {
      if (err) console.error('❌ Failed to save verified email:', err);
    });

    res.redirect('/vote.html');
  } else {
    res.send('❌ Invalid OTP. <a href="/verify.html">Try again</a>');
  }
});

// ✅ Vote form (restricted)
app.get('/vote.html', (req, res) => {
  if (!req.session.verified) return res.redirect('/verify.html');
  res.sendFile(path.join(__dirname, 'public', 'vote.html'));
});

// ✅ Submit vote
app.post('/vote', (req, res) => {
  if (!req.session.verified) return res.redirect('/verify.html');

  const { choice } = req.body;
  const hashedEmail = crypto.createHash('sha256').update(req.session.email).digest('hex');
  const secret = process.env.AES_SECRET;

  db.query('SELECT * FROM votes WHERE email_hash = ?', [hashedEmail], (err, results) => {
    if (err) return res.send("❌ DB Error");
    if (results.length > 0) {
      return res.send(`
        <div style="text-align:center;margin-top:50px;">
          <h3>⚠ You’ve already voted!</h3>
          <a href="/verify.html" class="btn btn-warning mt-3">Back</a>
        </div>
      `);
    }

    const encryptedVote = encrypt(choice, secret);
    db.query('INSERT INTO votes (email_hash, choice) VALUES (?, ?)', [hashedEmail, encryptedVote], err => {
      if (err) return res.send("❌ Error saving vote");
      req.session.destroy();
      res.redirect('/success.html');
    });
  });
});

// ✅ Admin login
app.get('/admin-login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
});

app.post('/admin-login', (req, res) => {
  const { username, password } = req.body;
  if (username === 'admin' && password === 'quantum123') {
    req.session.admin = true;
    res.redirect('/results');
  } else {
    res.send('❌ Invalid credentials. <a href="/admin-login">Try again</a>');
  }
});

function requireAdmin(req, res, next) {
  if (req.session.admin) return next();
  res.redirect('/admin-login');
}

// ✅ Admin-only result access
app.get('/results', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'results.html'));
});

app.get('/results-data', requireAdmin, (req, res) => {
  const secret = process.env.AES_SECRET;
  db.query('SELECT choice FROM votes', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB Error' });

    const counts = {
      AWS: 0,
      Azure: 0,
      "Google Cloud": 0,
      "IBM Quantum": 0
    };

    rows.forEach(row => {
      try {
        const decrypted = decrypt(row.choice, secret);
        if (counts[decrypted] !== undefined) counts[decrypted]++;
      } catch (e) {
        console.error("⚠ Decryption error:", e.message);
      }
    });

    res.json({ labels: Object.keys(counts), counts: Object.values(counts) });
  });
});

// ✅ Logout admin
app.get('/admin-logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/admin-login');
  });
});

// ✅ Redirect root to verify
app.get('/', (req, res) => {
  res.redirect('/verify.html');
});

// ✅ Start server
app.listen(3000, () => console.log("🚀 Server running at http://localhost:3000"));