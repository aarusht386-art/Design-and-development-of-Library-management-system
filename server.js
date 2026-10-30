require('dotenv').config();
const express = require('express'), mysql = require('mysql2/promise'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const app = express();
app.use(express.json());
app.use(express.static('public'));

const SECRET = process.env.JWT_SECRET;
if (!SECRET) { console.error('JWT_SECRET missing in .env'); process.exit(1); }
const pool = mysql.createPool({ host: process.env.DB_HOST, port: process.env.DB_PORT, user: process.env.DB_USER,
  password: process.env.DB_PASSWORD, database: process.env.DB_NAME, dateStrings: true, connectionLimit: 10 });

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

// ---------- auth ----------
app.post('/api/login', wrap(async (req, res) => {
  const { username = '', password = '' } = req.body;
  const [[u]] = await pool.query('SELECT * FROM users WHERE username=?', [String(username).trim()]);
  if (!u || !(await bcrypt.compare(String(password), u.password_hash))) throw new HttpError(401, 'Invalid username or password');
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
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Library running at http://localhost:${port}`));
