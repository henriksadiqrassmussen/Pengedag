-- server.js opretter disse tabeller automatisk ved Railway-start.
-- Filen er kun dokumentation/reference.
CREATE TABLE IF NOT EXISTS employees (id TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS customers (id TEXT PRIMARY KEY, company_name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS invoices (id TEXT PRIMARY KEY, invoice_number TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS invoice_lines (
  id TEXT PRIMARY KEY,
  invoice_id TEXT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE
);
