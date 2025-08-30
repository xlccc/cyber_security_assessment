
CREATE DATABASE IF NOT EXISTS system_db;
USE system_db;
-- 用户表
CREATE TABLE Users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password_hash CHAR(128) NOT NULL, -- Argon2id: 动态长度（约 98-128 字符）
  role ENUM('admin', 'user') NOT NULL DEFAULT 'user',
  account_status ENUM('pending', 'active', 'deleted') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP NULL,
  schema_name VARCHAR(50) NULL
);

-- 注册验证表

CREATE TABLE Registrations (
  registration_id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(100) UNIQUE NOT NULL,
  verification_code VARCHAR(6) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL
);

-- 令牌黑名单表
CREATE TABLE Token_Blocklist (
  token_hash CHAR(64) PRIMARY KEY, -- SHA256哈希值
  user_id INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  FOREIGN KEY (user_id) REFERENCES Users(user_id) ON DELETE CASCADE
);

