-- Safe to run more than once (IF NOT EXISTS, no DROP statements).
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
