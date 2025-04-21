/**
 * Database Configuration File
 * This file handles the SQLite database setup and provides utility functions
 */

import sqlite3 from 'sqlite3';
const db = new sqlite3.Database('./database.sqlite');

/**
 * Gets the current local date and time in SQL format
 * @returns {string} Current datetime in 'YYYY-MM-DD HH:MM:SS' format
 */
function getLocalDateTime() {
    return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

// Initialize database tables and settings
db.serialize(() => {
    // Create users table if it doesn't exist
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        secret TEXT,
        isadmin INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
        last_login DATETIME
    )`);

    // Set datetime format to local time
    db.run(`PRAGMA datetime_format = 'localtime'`);

    // Crear tabla de logs
    db.run(`CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action_type TEXT NOT NULL,
        action_description TEXT NOT NULL,
        performed_by INTEGER NOT NULL,
        performed_on INTEGER,
        created_at DATETIME DEFAULT (datetime('now', 'localtime')),
        FOREIGN KEY (performed_by) REFERENCES users(id)
    )`);
});

export { db, getLocalDateTime };