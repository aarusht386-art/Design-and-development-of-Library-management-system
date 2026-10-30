// =============================================================================
//  LibraryMS - single-file version.  Frontend, API, schema and first-run setup are all in here.
//  Run:  npm install express mysql2 bcryptjs jsonwebtoken   then   node app.js
//  Optional settings (environment variables or a .env file next to this file):
//    DB_HOST (localhost)  DB_PORT (3306)  DB_USER (root)  DB_PASSWORD ('')  DB_NAME (library_management)
//    PORT (3000)  JWT_SECRET (auto-generated if missing)
// =============================================================================
const _fs = require('fs'), _path = require('path');
try {   // tiny .env reader (no extra package needed); real environment variables win
  _fs.readFileSync(_path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch {}
const DB = { host: process.env.DB_HOST || 'localhost', port: Number(process.env.DB_PORT) || 3306, user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '', database: process.env.DB_NAME || 'library_management' };

const fs = require('fs'), path = require('path'), crypto = require('crypto');
const express = require('express'), mysql = require('mysql2/promise'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());
app.get('/', (req, res) => res.type('html').send(HTML));

// Signing key: from JWT_SECRET if you set it, otherwise generated once and saved next to this file.
const KEY_FILE = path.join(__dirname, '.jwt_secret');
const SECRET = process.env.JWT_SECRET || (fs.existsSync(KEY_FILE) ? fs.readFileSync(KEY_FILE, 'utf8') : (() => {
  const k = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(KEY_FILE, k, { mode: 0o600 }); return k; })());
const pool = mysql.createPool({ host: DB.host, port: DB.port, user: DB.user,
  password: DB.password, database: DB.database, dateStrings: true, connectionLimit: 10 });

// ---------- helpers ----------
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const wrap = fn => (req, res, next) => fn(req, res, next).catch(e => {
  if (e instanceof HttpError) return res.status(e.status).json({ error: e.message });
  if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'That value already exists (duplicate ISBN or enrollment no.)' });
  console.error(e); res.status(500).json({ error: 'Server error' });
});
const bad = m => { throw new HttpError(400, m); };
const str = (v, max, name, required = true) => {
  v = (v ?? '').toString().trim();
  if (required && !v) bad(`${name} is required`);
  if (v.length > max) bad(`${name} is too long`);
  return v || null;
};
const getSettings = async (db = pool) => {
  const [rows] = await db.query('SELECT k, v FROM settings'); const s = {};
  rows.forEach(r => s[r.k] = Number(r.v)); return s;
};
// Fine rule: overdue_days = days past due date minus grace days; fine = overdue_days x daily rate (computed here, never in the browser)
const fineFor = (lateDays, s) => { const d = Math.max(0, lateDays - s.grace_days); return { overdue_days: d, fine: d * s.fine_per_day }; };

const auth = (...roles) => wrap(async (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  let p; try { p = jwt.verify(t, SECRET); } catch { throw new HttpError(401, 'Please sign in again'); }
  const [[u]] = await pool.query('SELECT id, username, name, email, role, active FROM users WHERE id=?', [p.id]);
  if (!u || !u.active) throw new HttpError(401, 'Account is inactive');
  if (roles.length && !roles.includes(u.role)) throw new HttpError(403, 'Not allowed');
  req.user = u; next();
});
const admin = auth('admin'), anyone = auth();

const LOAN_SQL = `SELECT l.id, l.user_id, l.book_id, l.issue_date, l.due_date, l.return_date, b.title, b.author,
    u.name AS student_name, u.username AS enrollment, DATEDIFF(COALESCE(l.return_date, CURDATE()), l.due_date) AS late_days,
    f.id AS fine_id, f.amount AS fine_amount, f.paid AS fine_paid
  FROM loans l JOIN books b ON b.id=l.book_id JOIN users u ON u.id=l.user_id LEFT JOIN fines f ON f.loan_id=l.id`;
function shapeLoan(r, s) {
  const returned = !!r.return_date, live = fineFor(r.late_days, s);
  return { ...r, status: returned ? 'returned' : r.late_days > 0 ? 'overdue' : 'active',
    days_left: returned ? null : -r.late_days,
    fine: returned ? Number(r.fine_amount || 0) : live.fine, fine_paid: Number(r.fine_paid || 0),
    overdue_days: returned ? (r.fine_amount ? fineFor(r.late_days, s).overdue_days : 0) : live.overdue_days };
}
const loanList = async (where, params) => {
  const s = await getSettings(); const [rows] = await pool.query(`${LOAN_SQL} ${where} ORDER BY l.id DESC LIMIT 500`, params);
  return rows.map(r => shapeLoan(r, s));
};


// ---------- first-run admin setup (works only while no admin exists) ----------
app.get('/api/setup-status', wrap(async (req, res) => {
  const [[{ n }]] = await pool.query("SELECT COUNT(*) AS n FROM users WHERE role='admin'"); res.json({ needed: n === 0 });
}));
app.post('/api/setup', wrap(async (req, res) => {
  const pw = String(req.body.password || ''); if (pw.length < 8) bad('Password must be at least 8 characters');
  const [r] = await pool.query(`INSERT INTO users (username,name,password_hash,role)
    SELECT ?,?,?,'admin' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM users WHERE role='admin')`,
    [str(req.body.username, 40, 'Username'), str(req.body.name, 100, 'Name'), await bcrypt.hash(pw, 10)]);
  if (!r.affectedRows) throw new HttpError(403, 'Setup is already done. Please sign in.');
  res.status(201).json({ ok: true });
}));

// ---------- auth ----------
app.post('/api/login', wrap(async (req, res) => {
  const { username = '', password = '', role = '' } = req.body;
  const [[u]] = await pool.query('SELECT * FROM users WHERE username=?', [String(username).trim()]);
  if (!u || !(await bcrypt.compare(String(password), u.password_hash))) throw new HttpError(401, 'Invalid username or password');
  if (role && u.role !== role) throw new HttpError(403, role === 'admin' ? 'This is a student account. Switch to the Student tab.' : 'This is a librarian account. Switch to the Admin tab.');
  if (!u.active) throw new HttpError(403, 'This account has been deactivated. Contact the librarian.');
  res.json({ token: jwt.sign({ id: u.id }, SECRET, { expiresIn: '8h' }), user: { id: u.id, name: u.name, role: u.role, username: u.username, email: u.email } });
}));
app.get('/api/me', anyone, wrap(async (req, res) => res.json(req.user)));
app.put('/api/me', anyone, wrap(async (req, res) => {
  const name = str(req.body.name, 100, 'Name'), email = str(req.body.email, 120, 'Email', false);
  if (email && !/^\S+@\S+\.\S+$/.test(email)) bad('Enter a valid email');
  await pool.query('UPDATE users SET name=?, email=? WHERE id=?', [name, email, req.user.id]);
  if (req.body.password) {
    if (req.body.password.length < 8) bad('Password must be at least 8 characters');
    await pool.query('UPDATE users SET password_hash=? WHERE id=?', [await bcrypt.hash(req.body.password, 10), req.user.id]);
  }
  res.json({ ok: true });
}));

// ---------- books ----------
app.get('/api/books', anyone, wrap(async (req, res) => {
  const { q = '', category = '', available = '', sort = 'title', archived = '' } = req.query;
  const where = [archived === '1' && req.user.role === 'admin' ? '1=1' : 'b.archived=0'], p = [];
  if (q) { where.push('(b.title LIKE ? OR b.author LIKE ? OR b.isbn LIKE ? OR b.category LIKE ?)'); p.push(...Array(4).fill(`%${q}%`)); }
  if (category) { where.push('b.category=?'); p.push(category); }
  const order = { title: 'b.title', author: 'b.author', newest: 'b.id DESC' }[sort] || 'b.title';
  const [rows] = await pool.query(`SELECT b.*, b.copies - COUNT(l.id) AS available FROM books b
    LEFT JOIN loans l ON l.book_id=b.id AND l.return_date IS NULL WHERE ${where.join(' AND ')}
    GROUP BY b.id ${available === '1' ? 'HAVING available>0' : ''} ORDER BY ${order}`, p);
  res.json(rows);
}));
app.get('/api/categories', anyone, wrap(async (req, res) => {
  const [r] = await pool.query('SELECT DISTINCT category FROM books WHERE archived=0 ORDER BY category'); res.json(r.map(x => x.category));
}));
const bookBody = b => {
  const copies = parseInt(b.copies, 10); if (!(copies >= 1 && copies <= 1000)) bad('Copies must be between 1 and 1000');
  return [str(b.title, 200, 'Title'), str(b.author, 120, 'Author'), str(b.isbn, 20, 'ISBN', false), str(b.category, 60, 'Category'), str(b.publisher, 120, 'Publisher', false), copies];
};
app.post('/api/books', admin, wrap(async (req, res) => {
  const [r] = await pool.query('INSERT INTO books (title,author,isbn,category,publisher,copies) VALUES (?,?,?,?,?,?)', bookBody(req.body));
  res.status(201).json({ id: r.insertId });
}));
app.put('/api/books/:id', admin, wrap(async (req, res) => {
  const v = bookBody(req.body);
  const [[{ out }]] = await pool.query('SELECT COUNT(*) AS `out` FROM loans WHERE book_id=? AND return_date IS NULL', [req.params.id]);
  if (v[5] < out) bad(`${out} copies are currently issued; copies cannot be less than that`);
  await pool.query('UPDATE books SET title=?,author=?,isbn=?,category=?,publisher=?,copies=? WHERE id=?', [...v, req.params.id]);
  res.json({ ok: true });
}));
app.post('/api/books/:id/archive', admin, wrap(async (req, res) => {   // soft delete: history is kept
  const archived = req.body.archived ? 1 : 0;
  if (archived) {
    const [[{ out }]] = await pool.query('SELECT COUNT(*) AS `out` FROM loans WHERE book_id=? AND return_date IS NULL', [req.params.id]);
    if (out) bad('Cannot archive: copies are still issued');
  }
  await pool.query('UPDATE books SET archived=? WHERE id=?', [archived, req.params.id]); res.json({ ok: true });
}));

// ---------- students (admin) ----------
app.get('/api/students', admin, wrap(async (req, res) => {
  const q = `%${req.query.q || ''}%`, s = await getSettings();
  const [rows] = await pool.query(`SELECT u.id, u.username, u.name, u.email, u.active,
      (SELECT COUNT(*) FROM loans l WHERE l.user_id=u.id AND l.return_date IS NULL) AS borrowed,
      (SELECT COALESCE(SUM(f.amount-f.paid),0) FROM fines f JOIN loans l ON l.id=f.loan_id WHERE l.user_id=u.id) AS fine_due
    FROM users u WHERE u.role='student' AND (u.name LIKE ? OR u.username LIKE ? OR u.email LIKE ?) ORDER BY u.name`, [q, q, q]);
  res.json(rows);
}));
app.post('/api/students', admin, wrap(async (req, res) => {
  const pw = String(req.body.password || ''); if (pw.length < 8) bad('Password must be at least 8 characters');
  const email = str(req.body.email, 120, 'Email', false); if (email && !/^\S+@\S+\.\S+$/.test(email)) bad('Enter a valid email');
  const [r] = await pool.query("INSERT INTO users (username,name,email,password_hash,role) VALUES (?,?,?,?,'student')",
    [str(req.body.username, 40, 'Enrollment no.').toUpperCase(), str(req.body.name, 100, 'Name'), email, await bcrypt.hash(pw, 10)]);
  res.status(201).json({ id: r.insertId });
}));
app.put('/api/students/:id', admin, wrap(async (req, res) => {
  const email = str(req.body.email, 120, 'Email', false);
  await pool.query("UPDATE users SET name=?, email=? WHERE id=? AND role='student'", [str(req.body.name, 100, 'Name'), email, req.params.id]);
  if (req.body.password) {
    if (req.body.password.length < 8) bad('Password must be at least 8 characters');
    await pool.query("UPDATE users SET password_hash=? WHERE id=? AND role='student'", [await bcrypt.hash(req.body.password, 10), req.params.id]);
  }
  res.json({ ok: true });
}));
app.post('/api/students/:id/active', admin, wrap(async (req, res) => {
  await pool.query("UPDATE users SET active=? WHERE id=? AND role='student'", [req.body.active ? 1 : 0, req.params.id]); res.json({ ok: true });
}));

// ---------- loans ----------
app.post('/api/loans', admin, wrap(async (req, res) => {          // ISSUE
  const userId = parseInt(req.body.user_id, 10), bookId = parseInt(req.body.book_id, 10);
  if (!userId || !bookId) bad('Select a student and a book');
  const conn = await pool.getConnection();
  try {
    // READ COMMITTED: after waiting for the row lock we must see the other admin's committed loan, not an old snapshot
    await conn.query('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
    await conn.beginTransaction();
    const s = await getSettings(conn);
    const [[book]] = await conn.query('SELECT id, copies, archived FROM books WHERE id=? FOR UPDATE', [bookId]);   // row lock: no two admins can issue the last copy
    if (!book || book.archived) bad('Book not found');
    const [[stu]] = await conn.query("SELECT id, active FROM users WHERE id=? AND role='student' FOR UPDATE", [userId]);
    if (!stu) bad('Student not found'); if (!stu.active) bad('Student account is inactive');
    const [[{ out }]] = await conn.query('SELECT COUNT(*) AS `out` FROM loans WHERE book_id=? AND return_date IS NULL', [bookId]);
    if (out >= book.copies) bad('No copies available');
    const [[{ mine }]] = await conn.query('SELECT COUNT(*) mine FROM loans WHERE user_id=? AND return_date IS NULL', [userId]);
    if (mine >= s.max_loans) bad(`Student has reached the borrow limit (${s.max_loans})`);
    const [[{ dup }]] = await conn.query('SELECT COUNT(*) dup FROM loans WHERE user_id=? AND book_id=? AND return_date IS NULL', [userId, bookId]);
    if (dup) bad('Student already has this book');
    const [[{ owed }]] = await conn.query('SELECT COALESCE(SUM(f.amount-f.paid),0) owed FROM fines f JOIN loans l ON l.id=f.loan_id WHERE l.user_id=?', [userId]);
    if (Number(owed) > 0) bad(`Student has unpaid fines of ₹${owed}. Clear fines first.`);
    const [[{ lateOpen }]] = await conn.query('SELECT COUNT(*) lateOpen FROM loans WHERE user_id=? AND return_date IS NULL AND due_date<CURDATE()', [userId]);
    if (lateOpen) bad('Student has overdue books. Return them first.');
    const [r] = await conn.query('INSERT INTO loans (user_id,book_id,librarian_id,issue_date,due_date) VALUES (?,?,?,CURDATE(),DATE_ADD(CURDATE(), INTERVAL ? DAY))',
      [userId, bookId, req.user.id, s.loan_days]);
    await conn.commit(); res.status(201).json({ id: r.insertId });
  } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
}));
app.post('/api/loans/:id/return', admin, wrap(async (req, res) => {   // RETURN
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const s = await getSettings(conn);
    const [[l]] = await conn.query('SELECT id, return_date, DATEDIFF(CURDATE(), due_date) late FROM loans WHERE id=? FOR UPDATE', [req.params.id]);
    if (!l) throw new HttpError(404, 'Loan not found');
    if (l.return_date) bad('This book was already returned');
    await conn.query('UPDATE loans SET return_date=CURDATE() WHERE id=?', [l.id]);
    const f = fineFor(l.late, s);
    if (f.fine > 0) await conn.query('INSERT INTO fines (loan_id, overdue_days, amount) VALUES (?,?,?)', [l.id, f.overdue_days, f.fine]);
    await conn.commit(); res.json({ ok: true, fine: f.fine, overdue_days: f.overdue_days });
  } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
}));
app.get('/api/loans', admin, wrap(async (req, res) => {
  const w = { active: 'WHERE l.return_date IS NULL', overdue: 'WHERE l.return_date IS NULL AND l.due_date<CURDATE()', returned: 'WHERE l.return_date IS NOT NULL' }[req.query.status] || '';
  res.json(await loanList(w, []));
}));
app.get('/api/my/loans', auth('student'), wrap(async (req, res) => {   // always filtered by the logged-in id
  const loans = await loanList('WHERE l.user_id=?', [req.user.id]);
  const s = await getSettings(), notes = [];
  let fineDue = 0;
  loans.forEach(l => {
    if (l.status === 'returned') fineDue += l.fine - l.fine_paid;
    else if (l.status === 'overdue') { fineDue += l.fine; notes.push({ type: 'danger', text: `"${l.title}" is overdue by ${l.late_days} day(s). Fine so far: ₹${l.fine}.` }); }
    else if (l.days_left <= 3) notes.push({ type: 'warn', text: `"${l.title}" is due ${l.days_left === 0 ? 'today' : `in ${l.days_left} day(s)`} (${l.due_date}).` });
  });
  res.json({ loans, notifications: notes, fine_due: fineDue, fine_per_day: s.fine_per_day });
}));

// ---------- fines ----------
app.get('/api/fines', admin, wrap(async (req, res) => {
  const [rows] = await pool.query(`SELECT f.id, f.overdue_days, f.amount, f.paid, f.amount-f.paid AS balance, b.title, u.name AS student_name, u.username AS enrollment, l.return_date
    FROM fines f JOIN loans l ON l.id=f.loan_id JOIN books b ON b.id=l.book_id JOIN users u ON u.id=l.user_id ORDER BY (f.amount-f.paid)>0 DESC, f.id DESC`);
  res.json(rows);
}));
app.post('/api/fines/:id/pay', admin, wrap(async (req, res) => {
  const amt = Math.round(Number(req.body.amount) * 100) / 100; if (!(amt > 0)) bad('Enter a valid amount');
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[f]] = await conn.query('SELECT amount, paid FROM fines WHERE id=? FOR UPDATE', [req.params.id]);
    if (!f) throw new HttpError(404, 'Fine not found');
    if (amt > f.amount - f.paid + 0.0001) bad(`Payment exceeds the balance of ₹${(f.amount - f.paid).toFixed(2)}`);
    await conn.query('UPDATE fines SET paid=paid+? WHERE id=?', [amt, req.params.id]);
    await conn.query('INSERT INTO payments (fine_id, amount, recorded_by) VALUES (?,?,?)', [req.params.id, amt, req.user.id]);
    await conn.commit(); res.json({ ok: true });
  } catch (e) { await conn.rollback(); throw e; } finally { conn.release(); }
}));

// ---------- settings & stats ----------
app.get('/api/settings', admin, wrap(async (req, res) => res.json(await getSettings())));
app.put('/api/settings', admin, wrap(async (req, res) => {
  const rules = { loan_days: [1, 365], fine_per_day: [0, 1000], grace_days: [0, 30], max_loans: [1, 50] };
  for (const [k, [lo, hi]] of Object.entries(rules)) {
    const v = Number(req.body[k]); if (!Number.isFinite(v) || v < lo || v > hi) bad(`${k.replace('_', ' ')} must be between ${lo} and ${hi}`);
    await pool.query('UPDATE settings SET v=? WHERE k=?', [String(v), k]);
  }
  res.json({ ok: true });
}));
app.get('/api/stats', admin, wrap(async (req, res) => {
  const one = async (sql) => (await pool.query(sql))[0][0];
  const [titles, issued, overdue, students, fines] = await Promise.all([
    one('SELECT COUNT(*) n, COALESCE(SUM(copies),0) copies FROM books WHERE archived=0'),
    one('SELECT COUNT(*) n FROM loans WHERE return_date IS NULL'),
    one('SELECT COUNT(*) n FROM loans WHERE return_date IS NULL AND due_date<CURDATE()'),
    one("SELECT COUNT(*) n FROM users WHERE role='student' AND active=1"),
    one('SELECT COALESCE(SUM(amount-paid),0) n FROM fines')]);
  const [top] = await pool.query('SELECT b.title, COUNT(*) n FROM loans l JOIN books b ON b.id=l.book_id GROUP BY b.id ORDER BY n DESC LIMIT 5');
  res.json({ titles: titles.n, copies: Number(titles.copies), issued: issued.n, available: Number(titles.copies) - issued.n,
    overdue: overdue.n, students: students.n, fines_outstanding: Number(fines.n), top_books: top, recent: (await loanList('', [])).slice(0, 8) });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

// ---------- start: create database + tables if needed, then listen ----------
const SCHEMA = `-- Safe to run more than once (IF NOT EXISTS, no DROP statements).
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(40) NOT NULL UNIQUE,          -- enrollment no. for students
  name VARCHAR(100) NOT NULL,
  email VARCHAR(120) NULL,
  password_hash VARCHAR(100) NOT NULL,
  role ENUM('admin','student') NOT NULL DEFAULT 'student',
  active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_role (role)
);
CREATE TABLE IF NOT EXISTS books (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(200) NOT NULL,
  author VARCHAR(120) NOT NULL,
  isbn VARCHAR(20) NULL UNIQUE,
  category VARCHAR(60) NOT NULL,
  publisher VARCHAR(120) NULL,
  copies INT NOT NULL DEFAULT 1,                 -- total physical copies
  archived TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_title (title), INDEX idx_author (author), INDEX idx_category (category)
);
CREATE TABLE IF NOT EXISTS loans (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  book_id INT NOT NULL,
  librarian_id INT NOT NULL,
  issue_date DATE NOT NULL,
  due_date DATE NOT NULL,
  return_date DATE NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (book_id) REFERENCES books(id),
  FOREIGN KEY (librarian_id) REFERENCES users(id),
  INDEX idx_user (user_id), INDEX idx_book (book_id), INDEX idx_open (return_date, due_date)
);
CREATE TABLE IF NOT EXISTS fines (
  id INT AUTO_INCREMENT PRIMARY KEY,
  loan_id INT NOT NULL UNIQUE,
  overdue_days INT NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  paid DECIMAL(10,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (loan_id) REFERENCES loans(id)
);
CREATE TABLE IF NOT EXISTS payments (
  id INT AUTO_INCREMENT PRIMARY KEY,
  fine_id INT NOT NULL,
  amount DECIMAL(10,2) NOT NULL,
  recorded_by INT NOT NULL,
  paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (fine_id) REFERENCES fines(id),
  FOREIGN KEY (recorded_by) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS settings (
  k VARCHAR(30) PRIMARY KEY,
  v VARCHAR(30) NOT NULL
);
-- Defaults match your original app: 14 days, Rs 2/day, 5-book limit.
INSERT IGNORE INTO settings (k, v) VALUES ('loan_days','14'),('fine_per_day','2'),('grace_days','0'),('max_loans','5');
`;
(async () => {
  try {
    const c = await mysql.createConnection({ host: DB.host, port: DB.port, user: DB.user, password: DB.password, multipleStatements: true });
    await c.query(`CREATE DATABASE IF NOT EXISTS \`${DB.database}\` CHARACTER SET utf8mb4`);   // never drops anything
    await c.query(`USE \`${DB.database}\``);
    await c.query(SCHEMA); await c.end();
  } catch (e) {
    console.error('\nCould not connect to MySQL: ' + e.message + '\nIs MySQL running, and are DB_USER / DB_PASSWORD correct? (set them in a .env file next to app.js)\n'); process.exit(1);
  }
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Library running at http://localhost:${port}`));
})();

// ---------- the frontend page (served at /) ----------
const HTML = `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LibraryMS</title>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,500;9..144,700&family=Manrope:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#f3f5fa;--surface:#fff;--surface2:#eef1f8;--border:rgba(10,25,60,.09);--text:#0f1c3a;--muted:#6a7595;--navy:#0b1f4d;--accent:#2f5bea;--teal:#14b8a6;--green:#10b981;--red:#ef4444;--amber:#f59e0b;--shadow:0 2px 10px rgba(10,25,60,.06);--r:12px}
html[data-theme=dark]{--bg:#0a1226;--surface:#111c38;--surface2:#18264a;--border:rgba(255,255,255,.09);--text:#e8ecf8;--muted:#8d99bb;--navy:#060d1f;--shadow:0 2px 12px rgba(0,0,0,.35)}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font:14px 'Sora',sans-serif;min-height:100vh;transition:background .2s,color .2s}
button,input,select{font:inherit;color:inherit}
.hide{display:none!important}
/* login */
.login{min-height:100vh;display:grid;grid-template-columns:1.1fr 1fr}
.login-brand{background:linear-gradient(160deg,var(--navy),#1d3a8a);color:#fff;padding:56px;display:flex;flex-direction:column;justify-content:center}
.login-brand h1{font-size:34px;letter-spacing:-1px;margin-bottom:12px}.login-brand p{opacity:.75;max-width:360px;line-height:1.6}
.shelf{display:flex;gap:6px;align-items:flex-end;margin-top:36px;height:90px}.shelf i{width:18px;border-radius:3px 3px 0 0;background:var(--teal);opacity:.85}
.login-form{display:flex;align-items:center;justify-content:center;padding:32px}.login-card{width:360px;max-width:100%}
.login-card h2{font-size:22px;margin-bottom:4px}.login-card .sub{color:var(--muted);margin-bottom:22px}
/* layout */
.sidebar{position:fixed;inset:0 auto 0 0;width:232px;background:var(--navy);color:#cfd8f3;display:flex;flex-direction:column;padding:22px 0;z-index:30;transition:transform .2s}
.brand{padding:0 22px 20px;font-weight:700;font-size:16px;color:#fff;border-bottom:1px solid rgba(255,255,255,.08);margin-bottom:12px}.brand small{display:block;font:400 11px 'JetBrains Mono';opacity:.6;margin-top:3px}
.nav{display:flex;align-items:center;gap:11px;padding:11px 22px;cursor:pointer;border-left:3px solid transparent;color:#aab6dc;transition:.15s}
.nav:hover{background:rgba(255,255,255,.05);color:#fff}.nav.active{background:rgba(47,91,234,.22);color:#fff;border-left-color:var(--teal)}
.side-foot{margin-top:auto;padding:16px 22px;border-top:1px solid rgba(255,255,255,.08);font-size:12px;display:flex;flex-direction:column;gap:10px}
.main{margin-left:232px;padding:0 32px 40px}
.topbar{display:flex;align-items:center;gap:14px;padding:20px 0;position:sticky;top:0;background:var(--bg);z-index:10}
.topbar h1{font-size:20px;letter-spacing:-.4px;flex:1}.burger{display:none}
.avatar{width:34px;height:34px;border-radius:50%;background:var(--accent);color:#fff;display:grid;place-items:center;font-weight:600}
/* components */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 15px;border-radius:10px;border:1px solid var(--border);background:var(--surface);cursor:pointer;transition:.15s;font-size:13px}
.btn:hover{transform:translateY(-1px);box-shadow:var(--shadow)}.btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}.btn-primary:hover{background:#2449c4}
.btn-danger{color:var(--red);border-color:rgba(239,68,68,.35)}.btn-ok{color:var(--green);border-color:rgba(16,185,129,.4)}.btn-sm{padding:5px 10px;font-size:12px}.btn:disabled{opacity:.5;cursor:wait}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);box-shadow:var(--shadow);padding:18px}
.grid{display:grid;gap:14px}.stats{grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin-bottom:20px}
.stat .l{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);margin-bottom:8px}.stat .v{font:600 26px 'JetBrains Mono'}
.stat{border-top:3px solid var(--accent)}.stat.t{border-top-color:var(--teal)}.stat.r{border-top-color:var(--red)}.stat.a{border-top-color:var(--amber)}.stat.g{border-top-color:var(--green)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}.row .grow{flex:1;min-width:180px}
.table-wrap{overflow-x:auto;padding:0}table{width:100%;border-collapse:collapse;min-width:560px}
th{background:var(--surface2);text-align:left;padding:11px 16px;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted);font-weight:500}
td{padding:12px 16px;border-top:1px solid var(--border);vertical-align:middle}tbody tr:hover{background:var(--surface2)}.mono{font-family:'JetBrains Mono';font-size:12px;color:var(--muted)}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:500}
.b-green{background:rgba(16,185,129,.13);color:var(--green)}.b-red{background:rgba(239,68,68,.13);color:var(--red)}.b-amber{background:rgba(245,158,11,.15);color:#c98200}.b-blue{background:rgba(47,91,234,.12);color:var(--accent)}.b-grey{background:var(--surface2);color:var(--muted)}
input,select{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:var(--surface2);outline:none}input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(47,91,234,.15)}
.fg{margin-bottom:13px}.fg label{display:block;font-size:12px;color:var(--muted);margin-bottom:5px}.fg .err{color:var(--red);font-size:12px;margin-top:4px}
.modal-bg{position:fixed;inset:0;background:rgba(5,12,32,.6);display:flex;align-items:center;justify-content:center;z-index:100;padding:16px}
.modal{background:var(--surface);border-radius:16px;padding:26px;width:440px;max-width:100%;max-height:92vh;overflow:auto}.modal h3{margin-bottom:18px}.actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}
#toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:8px;z-index:200}.toast{background:var(--navy);color:#fff;padding:12px 18px;border-radius:10px;border-left:4px solid var(--green);box-shadow:var(--shadow)}.toast.error{border-left-color:var(--red)}
.empty{text-align:center;padding:44px;color:var(--muted)}.skel{height:64px;border-radius:12px;background:linear-gradient(90deg,var(--surface2),var(--surface),var(--surface2));background-size:200%;animation:sh 1.2s infinite;margin-bottom:10px}@keyframes sh{to{background-position:-200%}}
.books{grid-template-columns:repeat(auto-fill,minmax(210px,1fr))}.book{padding:0;overflow:hidden;cursor:pointer;transition:.18s}.book:hover{transform:translateY(-3px)}
.cover{height:120px;display:grid;place-items:center;color:#fff;font:700 42px 'Sora'}.book .info{padding:14px}.book h4{font-size:14px;margin-bottom:3px;line-height:1.3}.book .au{color:var(--muted);font-size:12px;margin-bottom:10px}
.hello{background:linear-gradient(120deg,var(--navy),#2548b8);color:#fff;border:0;margin-bottom:18px}.hello h2{font-size:22px;margin-bottom:6px}.hello input{margin-top:14px;background:rgba(255,255,255,.15);color:#fff;border-color:rgba(255,255,255,.25)}.hello input::placeholder{color:#cdd7f6}
.note{padding:11px 14px;border-radius:10px;margin-bottom:8px;font-size:13px}.note.danger{background:rgba(239,68,68,.12);color:var(--red)}.note.warn{background:rgba(245,158,11,.14);color:#b47600}
.bar{height:8px;border-radius:6px;background:var(--surface2);margin-top:5px}.bar i{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--accent),var(--teal))}
.two{grid-template-columns:1fr 1fr}
@media(max-width:900px){.login{grid-template-columns:1fr}.login-brand{display:none}.sidebar{transform:translateX(-100%)}.sidebar.open{transform:none}.main{margin-left:0;padding:0 16px 30px}.burger{display:inline-flex}.two{grid-template-columns:1fr}}

:root{--bg:#f6f1e6;--surface:#fffdf8;--surface2:#f0e9da;--border:rgba(48,36,16,.11);--text:#1e2a24;--muted:#7a7565;--navy:#12261f;--accent:#1f7a62;--teal:#d98e2b;--shadow:0 1px 2px rgba(48,36,16,.06),0 8px 24px rgba(48,36,16,.06);--r:16px}
html[data-theme=dark]{--bg:#0e1815;--surface:#15231e;--surface2:#1c2d27;--border:rgba(255,255,255,.08);--text:#ece8dc;--muted:#97a39b;--navy:#08110e;--accent:#38b58f}
body{font:14px 'Manrope',sans-serif}
h1,h2,h3,.stat .v,.login-brand h1{font-family:'Fraunces',serif;font-weight:700}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#fff}.btn-primary:hover{background:#17624e}
.b-blue{background:rgba(31,122,98,.12);color:var(--accent)}.b-amber{color:#b0731a}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(31,122,98,.18)}
/* login */
.login{grid-template-columns:1.15fr 1fr}
.login-brand{position:relative;overflow:hidden;background:radial-gradient(900px 500px at 10% 0,#1f4a3b 0,transparent 60%),radial-gradient(600px 400px at 100% 100%,rgba(217,142,43,.28),transparent 60%),#0d1f19;padding:56px 64px}
.logo{display:flex;align-items:center;gap:10px;font:700 17px 'Manrope';margin-bottom:auto}.logo span{width:34px;height:34px;border-radius:10px;background:var(--teal);color:#1b1305;display:grid;place-items:center;font:700 19px 'Fraunces'}
.login-brand h1{font-size:54px;line-height:1.02;letter-spacing:-1.5px;margin:60px 0 18px}.login-brand h1 em{color:var(--teal);font-style:italic}
.login-brand p{opacity:.72;max-width:400px;line-height:1.7;font-size:15px}
.spines{display:flex;align-items:flex-end;gap:7px;height:190px;margin-top:44px;border-bottom:3px solid rgba(255,255,255,.18)}
.spines i{width:26px;height:var(--t);border-radius:4px 4px 0 0;background:linear-gradient(90deg,hsl(var(--h) 40% 34%),hsl(var(--h) 45% 46%));box-shadow:inset 0 10px 0 rgba(255,255,255,.12),inset 0 -10px 0 rgba(0,0,0,.15);transform-origin:bottom;animation:rise .8s cubic-bezier(.2,.8,.2,1) backwards}
.spines i:nth-child(2){animation-delay:.08s}.spines i:nth-child(3){animation-delay:.16s}.spines i:nth-child(4){animation-delay:.24s}.spines i:nth-child(5){animation-delay:.32s}.spines i:nth-child(6){animation-delay:.4s}.spines i:nth-child(7){animation-delay:.48s}.spines i:nth-child(8){animation-delay:.56s}
.spines i.lean{transform:rotate(9deg);margin:0 8px}@keyframes rise{from{transform:scaleY(0);opacity:0}}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:26px}.chips span{padding:6px 13px;border:1px solid rgba(255,255,255,.2);border-radius:20px;font-size:12px;opacity:.85}
.login-form{background:var(--bg)}.login-card{width:400px;background:var(--surface);padding:30px;border-radius:22px;border:1px solid var(--border);box-shadow:var(--shadow);position:relative;overflow:hidden}
.login-card::before{content:"";position:absolute;inset:0 0 auto;height:4px;background:var(--accent);transition:.3s}.login-card.admin::before{background:var(--teal)}
.login-card h2{font-size:26px;letter-spacing:-.5px}.login-card .sub{margin-bottom:20px}
.seg{position:relative;display:grid;grid-template-columns:1fr 1fr;background:var(--surface2);border-radius:14px;padding:4px;margin-bottom:24px}
.seg::before{content:"";position:absolute;top:4px;bottom:4px;left:4px;width:calc(50% - 4px);background:var(--surface);border-radius:11px;box-shadow:var(--shadow);transition:transform .3s cubic-bezier(.4,1.3,.5,1)}.seg[data-r=admin]::before{transform:translateX(100%)}
.seg button{position:relative;border:0;background:none;padding:10px;border-radius:11px;cursor:pointer;font-weight:600;color:var(--muted);transition:.2s}.seg button.on{color:var(--text)}
.pw{position:relative}.pw input{padding-right:46px}.eye{position:absolute;right:5px;top:50%;transform:translateY(-50%);width:36px;height:36px;border:0;background:none;border-radius:9px;cursor:pointer;color:var(--muted);display:grid;place-items:center}.eye:hover{background:var(--border);color:var(--text)}.eye .slash{display:none}.eye.on{color:var(--accent)}.eye.on .slash{display:block}
.login-card input{padding:12px 14px}.go{width:100%;justify-content:center;padding:13px;font-weight:600;font-size:14px;margin-top:4px}.login-card.admin .go{background:var(--teal);border-color:var(--teal);color:#1b1305}
.shake{animation:shake .4s}@keyframes shake{20%,60%{transform:translateX(-7px)}40%,80%{transform:translateX(7px)}}
/* app shell: floating sidebar */
.sidebar{inset:12px auto 12px 12px;width:224px;border-radius:22px;background:linear-gradient(180deg,#143328,var(--navy))}
.main{margin-left:256px}.brand{font:700 18px 'Fraunces';border:0;padding:4px 24px 18px}.brand small{font:500 10px 'JetBrains Mono';letter-spacing:1px;text-transform:uppercase;color:var(--teal);opacity:1}
.nav{margin:2px 12px;padding:10px 14px;border-radius:12px;border-left:0;font-weight:500}.nav.active{background:var(--teal);color:#1b1305;font-weight:700}
.side-foot{border-top:1px solid rgba(255,255,255,.08);margin-top:auto}
.topbar{background:linear-gradient(var(--bg) 75%,transparent)}.topbar h1{font-size:26px;letter-spacing:-.6px}.avatar{background:var(--teal);color:#1b1305;border-radius:12px}
.card{border-radius:var(--r)}.stat{border:1px solid var(--border);position:relative;overflow:hidden}.stat::after{content:"";position:absolute;right:-18px;top:-18px;width:70px;height:70px;border-radius:50%;background:var(--accent);opacity:.1}
.stat.t::after{background:var(--teal)}.stat.r::after{background:var(--red)}.stat.a::after{background:var(--amber)}.stat.g::after{background:var(--green)}.stat .v{font-size:30px}
th{background:transparent;border-bottom:1px solid var(--border)}
/* hero + ring */
.hero{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:26px 30px;margin-bottom:18px;border-radius:22px;color:#fff;background:radial-gradient(500px 220px at 90% 0,rgba(217,142,43,.35),transparent 70%),linear-gradient(120deg,#12261f,#1f5a47)}
.hero small{font:500 11px 'JetBrains Mono';letter-spacing:1px;text-transform:uppercase;opacity:.65}.hero h2{font-size:30px;margin:6px 0 6px;letter-spacing:-.8px}.hero p{opacity:.8}
.ring{flex:none;width:112px;height:112px;border-radius:50%;display:grid;place-content:center;text-align:center;background:radial-gradient(closest-side,#173a2e 72%,transparent 74%),conic-gradient(var(--teal) calc(var(--p)*1%),rgba(255,255,255,.14) 0)}.ring b{font:700 24px 'Fraunces'}.ring span{font-size:10px;opacity:.7;text-transform:uppercase;letter-spacing:.8px}
.hello{background:radial-gradient(500px 220px at 90% 0,rgba(217,142,43,.35),transparent 70%),linear-gradient(120deg,#12261f,#1f5a47);border-radius:22px;padding:28px}.hello h2{font-size:28px;letter-spacing:-.6px}
/* book covers: cloth-bound spine look */
.cover{position:relative;height:150px;display:flex;flex-direction:column;justify-content:flex-end;padding:16px 16px 14px 28px;text-align:left;color:#fff;font:inherit;background:linear-gradient(135deg,hsl(var(--h) 38% 27%),hsl(calc(var(--h) + 30) 42% 38%));overflow:hidden}
.cover::before{content:"";position:absolute;inset:0 auto 0 0;width:14px;background:rgba(0,0,0,.22);box-shadow:inset -2px 0 0 rgba(255,255,255,.12)}
.cover .foil{position:absolute;left:28px;right:16px;top:16px;height:2px;background:#e8c27a;box-shadow:0 5px 0 #e8c27a;opacity:.85}
.cover em{font:700 17px/1.2 'Fraunces';font-style:normal;margin-bottom:5px;text-shadow:0 1px 2px rgba(0,0,0,.3)}.cover small{font-size:11px;opacity:.75}
.book{transition:.2s}.book:hover{transform:translateY(-5px) rotate(-.6deg);box-shadow:0 14px 30px rgba(48,36,16,.18)}
@media(max-width:900px){.sidebar{transform:translateX(-120%)}.sidebar.open{transform:none}.main{margin-left:0}.hero{flex-direction:column;align-items:flex-start}.login-card{padding:22px}}
</style></head>
<body>
<div id="toasts"></div>
<div id="login" class="login hide">
  <div class="login-brand">
    <div class="logo"><span>L</span>LibraryMS</div>
    <h1>Every book,<br><em>accounted for.</em></h1>
    <p>One calm place for librarians to run the desk and for students to find, borrow and track their reading.</p>
    <div class="spines"><i style="--h:18;--t:120px"></i><i style="--h:150;--t:160px"></i><i style="--h:38;--t:104px"></i><i style="--h:210;--t:176px"></i><i style="--h:340;--t:132px"></i><i class="lean" style="--h:28;--t:150px"></i><i style="--h:170;--t:112px"></i><i style="--h:48;--t:168px"></i></div>
    <div class="chips"><span>Live availability</span><span>Auto fines</span><span>Due-date alerts</span></div></div>
  <div class="login-form"><div class="login-card hide" id="setupCard"><h2>Welcome 👋</h2><div class="sub">First run: create the librarian (admin) account</div><div class="fg"><label>Username</label><input id="su"></div><div class="fg"><label>Full name</label><input id="sn"></div><div class="fg"><label>Password (min 8 characters)</label><div class="pw"><input id="sp" type="password"><button type="button" class="eye" aria-label="Show password" onclick="togglePw('sp',this)"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path class="slash" d="M4 4l16 16"/></svg></button></div><div class="err" id="se"></div></div><button class="btn btn-primary" style="width:100%;justify-content:center" onclick="doSetup()">Create admin &amp; continue</button></div>
    <div class="login-card" id="loginCard">
    <div class="seg" id="seg" data-r="student"><button class="on" data-r="student" onclick="setRole('student')">🎓 Student</button><button data-r="admin" onclick="setRole('admin')">🛡️ Admin</button></div>
    <h2 id="lh">Student sign in</h2><div class="sub" id="ls">Use your enrollment number to see your books and dues.</div>
    <div class="fg"><label id="lul">Enrollment No.</label><input id="lu" autocomplete="username" placeholder="e.g. 22BCA001" onkeydown="if(event.key==='Enter')$('#lp').focus()"></div>
    <div class="fg"><label>Password</label><div class="pw"><input id="lp" type="password" autocomplete="current-password" placeholder="Enter your password"><button type="button" class="eye" aria-label="Show password" onclick="togglePw('lp',this)"><svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><path class="slash" d="M4 4l16 16"/></svg></button></div><div class="err" id="le"></div></div>
    <button class="btn btn-primary go" onclick="doLogin()">Sign in</button></div></div>
</div>
<div id="app" class="hide">
  <aside class="sidebar" id="side"><div class="brand">📚 LibraryMS<small id="roleTag"></small></div><div id="nav"></div>
    <div class="side-foot"><div id="who"></div><button class="btn btn-sm" onclick="toggleTheme()">🌓 Theme</button><button class="btn btn-sm btn-danger" onclick="logout()">Logout</button></div></aside>
  <main class="main"><div class="topbar"><button class="btn burger" onclick="side.classList.toggle('open')">☰</button><h1 id="title"></h1><div class="avatar" id="av"></div></div><div id="view"></div></main>
</div>
<script>
// ---------- tiny helpers ----------
const $ = s => document.querySelector(s);
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let me = null, token = sessionStorage.getItem('lms_token');
async function api(path, method = 'GET', body) {
  const r = await fetch('/api' + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({}));
  if (r.status === 401 && token) { logout(); throw new Error(d.error); }
  if (!r.ok) throw new Error(d.error || 'Something went wrong');
  return d;
}
function toast(msg, type = '') { const t = document.createElement('div'); t.className = 'toast ' + type; t.textContent = msg; $('#toasts').append(t); setTimeout(() => t.remove(), 3500); }
const skeleton = () => '<div class="skel"></div>'.repeat(4);
const money = n => '₹' + Number(n || 0).toFixed(2).replace(/\\.00$/, '');
const badge = s => ({ active: '<span class="badge b-blue">Borrowed</span>', overdue: '<span class="badge b-red">Overdue</span>', returned: '<span class="badge b-green">Returned</span>' }[s]);
const empty = (i, t) => \`<div class="empty"><div style="font-size:34px">\${i}</div>\${t}</div>\`;
const hue = s => [...String(s)].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
const cover = b => '<div class="cover" style="--h:' + hue(b.title) + '"><span class="foil"></span><em>' + esc(b.title.slice(0, 34)) + '</em><small>' + esc(b.author) + '</small></div>';
function toggleTheme() { const n = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; document.documentElement.dataset.theme = n; localStorage.setItem('lms_theme', n); }
document.documentElement.dataset.theme = localStorage.getItem('lms_theme') || 'light';

// modal + confirm; fields: [{id,label,type,value,options}]
function modal(title, bodyHtml, onSave, saveLabel = 'Save') {
  const bg = document.createElement('div'); bg.className = 'modal-bg';
  bg.innerHTML = \`<div class="modal"><h3>\${esc(title)}</h3><div>\${bodyHtml}</div><div class="actions"><button class="btn" data-x>Cancel</button>\${onSave ? \`<button class="btn btn-primary" data-ok>\${saveLabel}</button>\` : ''}</div></div>\`;
  document.body.append(bg); const close = () => bg.remove();
  bg.onclick = e => { if (e.target === bg || e.target.dataset.x !== undefined) close(); };
  const ok = bg.querySelector('[data-ok]');
  if (ok) ok.onclick = async () => {
    bg.querySelectorAll('.err').forEach(e => e.remove()); ok.disabled = true;
    try { await onSave(bg); close(); } catch (e) {
      const m = e.message.toLowerCase(), inputs = [...bg.querySelectorAll('input,select')];
      const hit = inputs.find(i => m.includes((i.dataset.k || i.id).replace('_', ' ').split(' ')[0].toLowerCase()));
      const msg = document.createElement('div'); msg.className = 'err'; msg.textContent = e.message;
      (hit ? hit.parentElement : bg.querySelector('.modal > div')).append(msg);
    } finally { ok.disabled = false; }
  };
  return bg;
}
const confirmBox = (text, fn, label = 'Confirm') => modal('Please confirm', \`<p>\${esc(text)}</p>\`, async () => { await fn(); }, label);
const field = (id, label, v = '', type = 'text', extra = '') => \`<div class="fg"><label>\${label}</label><input id="f_\${id}" data-k="\${id}" type="\${type}" value="\${esc(v)}" \${extra}></div>\`;
const val = (bg, id) => bg.querySelector('#f_' + id).value;

// ---------- auth ----------
let loginRole = 'student';
function setRole(r) {
  loginRole = r; const a = r === 'admin';
  $('#seg').dataset.r = r; document.querySelectorAll('#seg button').forEach(b => b.classList.toggle('on', b.dataset.r === r));
  $('#lh').textContent = a ? 'Librarian sign in' : 'Student sign in';
  $('#ls').textContent = a ? 'Admin access to books, students, loans and fines.' : 'Use your enrollment number to see your books and dues.';
  $('#lul').textContent = a ? 'Username' : 'Enrollment No.'; $('#lu').placeholder = a ? 'Admin username' : 'e.g. 22BCA001';
  $('#loginCard').classList.toggle('admin', a); $('#le').textContent = ''; $('#lu').focus();
}
function togglePw(id, btn) { const i = $('#' + id), show = i.type === 'password'; i.type = show ? 'text' : 'password'; btn.classList.toggle('on', show); btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password'); }
async function doLogin() {
  $('#le').textContent = '';
  try { const d = await api('/login', 'POST', { username: $('#lu').value, password: $('#lp').value, role: loginRole }); token = d.token; sessionStorage.setItem('lms_token', token); start(d.user); }
  catch (e) { $('#le').textContent = e.message; const c = $('#loginCard'); c.classList.remove('shake'); void c.offsetWidth; c.classList.add('shake'); }
}
$('#lp').addEventListener('keydown', e => e.key === 'Enter' && doLogin());
function logout() { sessionStorage.removeItem('lms_token'); token = null; me = null; $('#app').classList.add('hide'); $('#login').classList.remove('hide'); $('#lp').value = ''; }

const NAVS = {
  admin: [['dashboard', '🏠', 'Dashboard'], ['books', '📖', 'Books'], ['students', '🎓', 'Students'], ['loans', '🔁', 'Loans'], ['fines', '💰', 'Fines'], ['settings', '⚙️', 'Settings']],
  student: [['home', '🏠', 'My Dashboard'], ['catalog', '📖', 'Catalog'], ['history', '🕘', 'My History'], ['profile', '👤', 'Profile']]
};
function start(user) {
  me = user; $('#login').classList.add('hide'); $('#app').classList.remove('hide');
  $('#roleTag').textContent = user.role === 'admin' ? 'Librarian console' : 'Student portal'; $('#who').textContent = user.name; $('#av').textContent = user.name[0].toUpperCase();
  $('#nav').innerHTML = NAVS[user.role].map(([k, i, l]) => \`<div class="nav" data-p="\${k}" onclick="go('\${k}')"><span>\${i}</span>\${l}</div>\`).join('');
  go(NAVS[user.role][0][0]);
}
async function go(page, arg) {
  side.classList.remove('open');
  document.querySelectorAll('.nav').forEach(n => n.classList.toggle('active', n.dataset.p === page));
  $('#title').textContent = NAVS[me.role].find(n => n[0] === page)[2]; $('#view').innerHTML = skeleton();
  try { $('#view').innerHTML = await PAGES[page](arg); PAGES[page + '_after']?.(arg); } catch (e) { $('#view').innerHTML = empty('⚠️', esc(e.message)); }
}
const refresh = () => go(document.querySelector('.nav.active').dataset.p);

// ---------- shared: book cards / details ----------
const availBadge = b => b.available > 0 ? \`<span class="badge b-green">\${b.available} available</span>\` : '<span class="badge b-red">All issued</span>';
const bookCards = list => list.length ? \`<div class="grid books">\${list.map(b => \`<div class="card book" onclick="bookDetails(\${b.id})">\${cover(b)}<div class="info"><h4>\${esc(b.title)}</h4><div class="au">\${esc(b.author)}</div><span class="badge b-blue">\${esc(b.category)}</span> \${availBadge(b)}</div></div>\`).join('')}</div>\` : empty('📚', 'No books match your search.');
async function bookDetails(id) {
  const b = (await api('/books')).find(x => x.id === id);
  modal(b.title, \`\${cover(b).replace('height:120px', 'height:90px;border-radius:12px;margin-bottom:14px')}<p><b>\${esc(b.author)}</b></p><p class="mono" style="margin:8px 0">ISBN: \${esc(b.isbn || '—')} · Publisher: \${esc(b.publisher || '—')}</p><p><span class="badge b-blue">\${esc(b.category)}</span> \${availBadge(b)} <span class="mono">\${b.copies} total copies</span></p>\`).querySelector('[data-x]').textContent = 'Close';
}

// ---------- ADMIN pages ----------
const PAGES = {
  async dashboard() {
    const s = await api('/stats'), max = Math.max(1, ...s.top_books.map(t => t.n));
    return \`<div class="hero"><div><small>\${new Date().toDateString()}</small><h2>Good \${new Date().getHours() < 12 ? 'morning' : new Date().getHours() < 17 ? 'afternoon' : 'evening'}, \${esc(me.name.split(' ')[0])}</h2><p>\${s.issued} books out &middot; <b>\${s.overdue}</b> overdue &middot; \${money(s.fines_outstanding)} fines pending</p></div><div class="ring" style="--p:\${Math.round(s.available / Math.max(1, s.copies) * 100)}"><b>\${Math.round(s.available / Math.max(1, s.copies) * 100)}%</b><span>on shelf</span></div></div>
    <div class="row"><button class="btn btn-primary" onclick="bookForm()">+ Add book</button><button class="btn" onclick="studentForm()">+ Register student</button><button class="btn" onclick="issueForm()">Issue book</button><button class="btn" onclick="go('loans')">Process return</button></div>
    <div class="grid stats">\${[['Book titles', s.titles, ''], ['Total copies', s.copies, 't'], ['Available', s.available, 'g'], ['Issued', s.issued, 'a'], ['Overdue', s.overdue, 'r'], ['Students', s.students, ''], ['Fines outstanding', money(s.fines_outstanding), 'r']].map(([l, v, c]) => \`<div class="card stat \${c}"><div class="l">\${l}</div><div class="v">\${v}</div></div>\`).join('')}</div>
    <div class="grid two"><div class="card"><b>Most borrowed</b>\${s.top_books.length ? s.top_books.map(t => \`<div style="margin-top:12px;font-size:13px">\${esc(t.title)} <span class="mono">· \${t.n}</span><div class="bar"><i style="width:\${t.n / max * 100}%"></i></div></div>\`).join('') : empty('📊', 'No borrowing yet')}</div>
    <div class="card table-wrap"><div style="padding:18px 18px 8px"><b>Recent activity</b></div>\${loanTable(s.recent, false)}</div></div>\`;
  },
  async books() {
    return \`<div class="row"><input class="grow" id="bq" placeholder="Search title, author, ISBN, category…" oninput="loadBooks()"><label class="mono"><input type="checkbox" id="barch" style="width:auto" onchange="loadBooks()"> show archived</label><button class="btn btn-primary" onclick="bookForm()">+ Add book</button></div><div class="card table-wrap" id="bt">\${skeleton()}</div>\`;
  },
  books_after() { loadBooks(); },
  async students() {
    return \`<div class="row"><input class="grow" id="sq" placeholder="Search students…" oninput="loadStudents()"><button class="btn btn-primary" onclick="studentForm()">+ Register student</button></div><div class="card table-wrap" id="st">\${skeleton()}</div>\`;
  },
  students_after() { loadStudents(); },
  async loans() {
    return \`<div class="row"><select id="lf" style="width:auto" onchange="loadLoans()"><option value="active">Active loans</option><option value="overdue">Overdue</option><option value="returned">Returned (history)</option><option value="">All</option></select><div class="grow"></div><button class="btn btn-primary" onclick="issueForm()">+ Issue book</button></div><div class="card table-wrap" id="lt">\${skeleton()}</div>\`;
  },
  loans_after() { loadLoans(); },
  async fines() {
    const f = await api('/fines');
    return \`<div class="card table-wrap">\${f.length ? \`<table><thead><tr><th>Student</th><th>Book</th><th>Days late</th><th>Fine</th><th>Paid</th><th>Balance</th><th></th></tr></thead><tbody>\${f.map(x => \`<tr><td>\${esc(x.student_name)}<div class="mono">\${esc(x.enrollment)}</div></td><td>\${esc(x.title)}</td><td>\${x.overdue_days}</td><td>\${money(x.amount)}</td><td>\${money(x.paid)}</td><td><b>\${money(x.balance)}</b></td><td>\${x.balance > 0 ? \`<button class="btn btn-sm btn-ok" onclick="payForm(\${x.id},\${x.balance})">Record payment</button>\` : '<span class="badge b-green">Paid</span>'}</td></tr>\`).join('')}</tbody></table>\` : empty('💰', 'No fines recorded yet.')}</div><p class="mono" style="margin-top:12px">Fines are assessed when a late book is returned. Books still overdue show their running fine on the Loans page.</p>\`;
  },
  async settings() {
    const s = await api('/settings');
    return \`<div class="card" style="max-width:460px"><b>Borrowing rules</b><div style="height:14px"></div>\${field('loan_days', 'Loan period (days)', s.loan_days, 'number')}\${field('fine_per_day', 'Fine per overdue day (₹)', s.fine_per_day, 'number')}\${field('grace_days', 'Grace period (days after due date, no fine)', s.grace_days, 'number')}\${field('max_loans', 'Max books per student', s.max_loans, 'number')}<p class="mono" style="margin-bottom:12px">Fine = (days after due date − grace days) × daily rate. Example: 3 days late at ₹5 = ₹15.</p><button class="btn btn-primary" onclick="saveSettings()">Save settings</button></div>\`;
  },

  // ---------- STUDENT pages ----------
  async home() {
    const d = await api('/my/loans'), cur = d.loans.filter(l => l.status !== 'returned'), first = me.name.split(' ')[0];
    return \`<div class="card hello"><h2>Welcome back, \${esc(first)} 👋</h2><div style="opacity:.8">Find your next read.</div><input id="hq" placeholder="Search title, author, ISBN or category…" onkeydown="if(event.key==='Enter')go('catalog',this.value)"></div>
    <div class="grid stats"><div class="card stat"><div class="l">Currently borrowed</div><div class="v">\${cur.length}</div></div><div class="card stat r"><div class="l">Overdue</div><div class="v">\${cur.filter(l => l.status === 'overdue').length}</div></div><div class="card stat a"><div class="l">Fine balance</div><div class="v">\${money(d.fine_due)}</div></div></div>
    \${d.notifications.length ? \`<div style="margin-bottom:18px"><b>🔔 Notifications</b><div style="height:10px"></div>\${d.notifications.map(n => \`<div class="note \${n.type}">\${esc(n.text)}</div>\`).join('')}</div>\` : ''}
    <b>My books</b><div style="height:10px"></div><div class="card table-wrap">\${cur.length ? myTable(cur) : empty('📖', 'You have no books borrowed right now.')}</div>
    \${d.fine_due > 0 ? \`<p class="mono" style="margin-top:12px">Pay fines at the library desk. Rate: \${money(d.fine_per_day)} per overdue day.</p>\` : ''}\`;
  },
  async catalog(q = '') {
    const cats = await api('/categories');
    return \`<div class="row"><input class="grow" id="cq" value="\${esc(q)}" placeholder="Search title, author, ISBN, category…" oninput="loadCatalog()"><select id="cc" style="width:auto" onchange="loadCatalog()"><option value="">All categories</option>\${cats.map(c => \`<option>\${esc(c)}</option>\`).join('')}</select><select id="ca" style="width:auto" onchange="loadCatalog()"><option value="">Any availability</option><option value="1">Available now</option></select><select id="cs" style="width:auto" onchange="loadCatalog()"><option value="title">Sort: Title</option><option value="author">Sort: Author</option><option value="newest">Sort: Newest</option></select></div><div id="cg">\${skeleton()}</div>\`;
  },
  catalog_after() { loadCatalog(); },
  async history() {
    const d = await api('/my/loans'); return \`<div class="card table-wrap">\${d.loans.length ? myTable(d.loans) : empty('🕘', 'No borrowing history yet.')}</div>\`;
  },
  async profile() {
    const u = await api('/me');
    return \`<div class="card" style="max-width:460px"><div class="fg"><label>Enrollment / username</label><input value="\${esc(u.username)}" disabled></div>\${field('name', 'Full name', u.name)}\${field('email', 'Email', u.email || '', 'email')}\${field('password', 'New password (leave blank to keep)', '', 'password')}<button class="btn btn-primary" onclick="saveProfile()">Save profile</button></div>\`;
  }
};

const myTable = l => \`<table><thead><tr><th>Book</th><th>Issued</th><th>Due</th><th>Returned</th><th>Status</th><th>Fine</th></tr></thead><tbody>\${l.map(x => \`<tr><td><b>\${esc(x.title)}</b><div class="mono">\${esc(x.author)}</div></td><td>\${x.issue_date}</td><td>\${x.due_date}</td><td>\${x.return_date || '—'}</td><td>\${badge(x.status)}</td><td>\${x.fine ? \`<span style="color:var(--red)">\${money(x.fine)}\${x.status === 'overdue' ? ' (so far)' : ''}</span>\` : '—'}</td></tr>\`).join('')}</tbody></table>\`;
const loanTable = (l, actions = true) => l.length ? \`<table><thead><tr><th>Student</th><th>Book</th><th>Issued</th><th>Due</th><th>Status</th><th>Fine</th>\${actions ? '<th></th>' : ''}</tr></thead><tbody>\${l.map(x => \`<tr><td>\${esc(x.student_name)}<div class="mono">\${esc(x.enrollment)}</div></td><td>\${esc(x.title)}</td><td>\${x.issue_date}</td><td>\${x.due_date}</td><td>\${badge(x.status)}</td><td>\${x.fine ? money(x.fine) : '—'}</td>\${actions ? \`<td>\${x.status !== 'returned' ? \`<button class="btn btn-sm btn-primary" onclick="returnLoan(\${x.id},'\${esc(x.title).replace(/'/g, '')}')">Return</button>\` : ''}</td>\` : ''}</tr>\`).join('')}</tbody></table>\` : empty('🔁', 'Nothing here yet.');

// ---------- admin actions ----------
let t; const debounce = fn => { clearTimeout(t); t = setTimeout(fn, 250); };
function loadBooks() { debounce(async () => {
  const b = await api(\`/books?q=\${encodeURIComponent($('#bq').value)}&archived=\${$('#barch').checked ? 1 : 0}\`);
  $('#bt').innerHTML = b.length ? \`<table><thead><tr><th>Title</th><th>Author</th><th>ISBN</th><th>Category</th><th>Copies</th><th></th></tr></thead><tbody>\${b.map(x => \`<tr><td><b>\${esc(x.title)}</b>\${x.archived ? ' <span class="badge b-grey">archived</span>' : ''}</td><td>\${esc(x.author)}</td><td class="mono">\${esc(x.isbn || '—')}</td><td><span class="badge b-blue">\${esc(x.category)}</span></td><td>\${x.available}/\${x.copies} <span class="mono">free</span></td><td style="white-space:nowrap"><button class="btn btn-sm" onclick='bookForm(\${JSON.stringify(x).replace(/'/g, '&#39;')})'>Edit</button> <button class="btn btn-sm btn-danger" onclick="archiveBook(\${x.id},\${x.archived ? 0 : 1})">\${x.archived ? 'Restore' : 'Archive'}</button></td></tr>\`).join('')}</tbody></table>\` : empty('📚', 'No books found. Add one!'); }); }
function bookForm(b = {}) {
  modal(b.id ? 'Edit book' : 'Add book', field('title', 'Title', b.title) + field('author', 'Author', b.author) + field('isbn', 'ISBN (optional)', b.isbn) + field('category', 'Category', b.category) + field('publisher', 'Publisher (optional)', b.publisher) + field('copies', 'Number of copies', b.copies || 1, 'number'),
    async bg => { const body = Object.fromEntries(['title', 'author', 'isbn', 'category', 'publisher', 'copies'].map(k => [k, val(bg, k)])); await api(b.id ? '/books/' + b.id : '/books', b.id ? 'PUT' : 'POST', body); toast('Book saved'); refresh(); });
}
const archiveBook = (id, a) => confirmBox(a ? 'Archive this book? It will be hidden from the catalog; borrowing history is kept.' : 'Restore this book?', async () => { await api(\`/books/\${id}/archive\`, 'POST', { archived: !!a }); toast('Done'); refresh(); });
async function loadStudents() { debounce(async () => {
  const s = await api('/students?q=' + encodeURIComponent($('#sq').value));
  $('#st').innerHTML = s.length ? \`<table><thead><tr><th>Enrollment</th><th>Name</th><th>Email</th><th>Books</th><th>Fine due</th><th>Status</th><th></th></tr></thead><tbody>\${s.map(x => \`<tr><td class="mono">\${esc(x.username)}</td><td><b>\${esc(x.name)}</b></td><td>\${esc(x.email || '—')}</td><td>\${x.borrowed}</td><td>\${Number(x.fine_due) ? money(x.fine_due) : '—'}</td><td>\${x.active ? '<span class="badge b-green">Active</span>' : '<span class="badge b-grey">Inactive</span>'}</td><td style="white-space:nowrap"><button class="btn btn-sm" onclick='studentForm(\${JSON.stringify(x).replace(/'/g, '&#39;')})'>Edit</button> <button class="btn btn-sm \${x.active ? 'btn-danger' : 'btn-ok'}" onclick="toggleStudent(\${x.id},\${x.active ? 0 : 1})">\${x.active ? 'Deactivate' : 'Activate'}</button></td></tr>\`).join('')}</tbody></table>\` : empty('🎓', 'No students found.'); }); }
function studentForm(s = {}) {
  modal(s.id ? 'Edit student' : 'Register student', (s.id ? '' : field('username', 'Enrollment No.', '', 'text', 'placeholder="e.g. 22BCA001"')) + field('name', 'Full name', s.name) + field('email', 'Email (optional)', s.email, 'email') + field('password', s.id ? 'Reset password (optional)' : 'Initial password (min 8 chars)', '', 'password'),
    async bg => { const body = { name: val(bg, 'name'), email: val(bg, 'email'), password: val(bg, 'password') }; if (!s.id) body.username = val(bg, 'username'); await api(s.id ? '/students/' + s.id : '/students', s.id ? 'PUT' : 'POST', body); toast('Student saved'); refresh(); });
}
const toggleStudent = (id, a) => confirmBox(a ? 'Activate this account?' : 'Deactivate this account? The student will not be able to log in or borrow.', async () => { await api(\`/students/\${id}/active\`, 'POST', { active: !!a }); toast('Updated'); refresh(); });
async function loadLoans() { const l = await api('/loans?status=' + $('#lf').value); $('#lt').innerHTML = loanTable(l); }
async function issueForm() {
  const [st, bk] = await Promise.all([api('/students'), api('/books?available=1')]);
  modal('Issue book', \`<div class="fg"><label>Student</label><select id="f_user" data-k="student">\${st.filter(s => s.active).map(s => \`<option value="\${s.id}">\${esc(s.name)} (\${esc(s.username)})</option>\`).join('')}</select></div><div class="fg"><label>Book</label><select id="f_book" data-k="book">\${bk.map(b => \`<option value="\${b.id}">\${esc(b.title)} — \${b.available} left</option>\`).join('')}</select></div><p class="mono">Issue date is today; the due date is set automatically from the loan period.</p>\`,
    async bg => { await api('/loans', 'POST', { user_id: val(bg, 'user'), book_id: val(bg, 'book') }); toast('Book issued'); refresh(); }, 'Issue');
}
const returnLoan = (id, title) => confirmBox(\`Accept return of "\${title}"?\`, async () => { const r = await api(\`/loans/\${id}/return\`, 'POST'); toast(r.fine ? \`Returned. Fine: \${money(r.fine)} (\${r.overdue_days} days)\` : 'Returned on time'); refresh(); }, 'Accept return');
const payForm = (id, bal) => modal('Record payment', \`<p style="margin-bottom:12px">Outstanding balance: <b>\${money(bal)}</b></p>\` + field('amount', 'Amount received (₹)', bal, 'number', 'step="0.01"'), async bg => { await api(\`/fines/\${id}/pay\`, 'POST', { amount: val(bg, 'amount') }); toast('Payment recorded'); refresh(); });
async function saveSettings() { try { await api('/settings', 'PUT', Object.fromEntries(['loan_days', 'fine_per_day', 'grace_days', 'max_loans'].map(k => [k, $('#f_' + k).value]))); toast('Settings saved'); } catch (e) { toast(e.message, 'error'); } }

// ---------- student actions ----------
function loadCatalog() { debounce(async () => {
  const p = new URLSearchParams({ q: $('#cq').value, category: $('#cc').value, available: $('#ca').value, sort: $('#cs').value });
  $('#cg').innerHTML = bookCards(await api('/books?' + p)); }); }
async function saveProfile() { try { await api('/me', 'PUT', { name: $('#f_name').value, email: $('#f_email').value, password: $('#f_password').value }); toast('Profile updated'); me.name = $('#f_name').value; $('#who').textContent = me.name; } catch (e) { toast(e.message, 'error'); } }

// ---------- boot ----------
if (token) api('/me').then(u => start(u)).catch(() => $('#login').classList.remove('hide')); else $('#login').classList.remove('hide');

// ---------- first-run setup ----------
async function checkSetup() {
  try { const d = await api('/setup-status'); if (d.needed) { $('#loginCard').classList.add('hide'); $('#setupCard').classList.remove('hide'); } } catch {}
}
async function doSetup() {
  $('#se').textContent = '';
  try {
    await api('/setup', 'POST', { username: $('#su').value, name: $('#sn').value, password: $('#sp').value });
    const d = await api('/login', 'POST', { username: $('#su').value, password: $('#sp').value });
    token = d.token; sessionStorage.setItem('lms_token', token); start(d.user);
  } catch (e) { $('#se').textContent = e.message; }
}
checkSetup();
</script></body></html>
`;
