CREATE TABLE consent_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cart_token TEXT NOT NULL,
  customer_email TEXT,
  ip_address TEXT,
  terms_version TEXT,
  accepted_at TEXT,
  shop_domain TEXT,
  order_id TEXT,
  order_number TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);