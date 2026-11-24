-- =====================================================================
-- CyberNexus AI Database Schema
-- Module: Authentication & Database Backend (Harman)
-- Evaluation 1 Scope: Users & Scan History Persistence
-- =====================================================================

-- Step 1: Create the Database if it doesn't already exist
CREATE DATABASE IF NOT EXISTS cybernexus_ai;
USE cybernexus_ai;

-- Step 2: Create the Users Table
-- Stores user credentials and authentication details
CREATE TABLE IF NOT EXISTS users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(60) NOT NULL,  -- BCrypt hash length is strictly 60 characters
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_users_email (email)
);

-- Step 3: Create the Scans Table
-- Stores threat scan results linked to registered users
CREATE TABLE IF NOT EXISTS scans (
    scan_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    scan_type VARCHAR(50) NOT NULL,       -- e.g., 'URL' or 'MESSAGE'
    input_data TEXT,                     -- The scanned URL or message text
    risk_score INT NOT NULL,             -- Calculated threat score (0-100)
    risk_level VARCHAR(20) NOT NULL,     -- e.g., 'SAFE', 'SUSPICIOUS', 'HIGH'
    detection_reason TEXT,               -- Explanation / matched threat rules
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_risk_score CHECK (risk_score BETWEEN 0 AND 100),
    CONSTRAINT fk_scans_user FOREIGN KEY (user_id)
        REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_scans_user (user_id),
    INDEX idx_scans_created (created_at DESC)
);

-- =====================================================================
-- Helpful Queries for Testing and Viva Demo:
-- =====================================================================
-- SELECT * FROM users;
-- SELECT * FROM scans WHERE user_id = 1 ORDER BY created_at DESC;
-- =====================================================================
