const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');
const TelegramBot = require('node-telegram-bot-api');

// --- CONFIG ---
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_super_secret_key';
const TELEGRAM_BOT_TOKEN = process.env.BOT_TOKEN || 'YOUR_TELEGRAM_BOT_TOKEN';
const URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

// --- DATABASE ---
const db = new sqlite3.Database('database.db');

// Create tables if not exist
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password_hash TEXT,
        telegram_id INTEGER UNIQUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
});

// --- EXPRESS APP ---
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// --- AUTH HELPERS ---
function send(res, status, data, headers = {}) {
    res.status(status).set(Object.assign({'Content-Type': 'application/json'}, headers)).send(JSON.stringify(data));
}
function getUserFromReq(req) {
    const cookies = cookie.parse(req.headers.cookie || '');
    const token = cookies.jwt;
    if (!token) return null;
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch {
        return null;
    }
}

// --- WEB ROUTES ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Registration
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return send(res, 400, { error: 'Missing fields' });
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash], function(err) {
        if (err) return send(res, 400, { error: 'Registration failed' });
        send(res, 201, { success: true });
    });
});

// Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return send(res, 400, { error: 'Missing fields' });
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err || !user) return send(res, 401, { error: 'Invalid credentials' });
        if (!(await bcrypt.compare(password, user.password_hash))) return send(res, 401, { error: 'Invalid credentials' });
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
        res.status(200)
            .cookie('jwt', token, { httpOnly: true, maxAge: 3600 * 1000, sameSite: 'lax', path: '/' })
            .json({ success: true });
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    res.status(200)
        .cookie('jwt', '', { httpOnly: true, maxAge: 0, sameSite: 'lax', path: '/' })
        .json({ success: true });
});

// Check Auth
app.get('/api/check-auth', (req, res) => {
    const user = getUserFromReq(req);
    send(res, 200, { authenticated: !!user });
});

// Get To-Do Items
app.get('/api/items', (req, res) => {
    const user = getUserFromReq(req);
    if (!user) return send(res, 401, { error: 'Unauthorized' });
    db.all('SELECT id, text FROM items WHERE user_id = ?', [user.userId], (err, rows) => {
        if (err) return send(res, 500, { error: 'DB error' });
        send(res, 200, rows);
    });
});

// Add To-Do Item
app.post('/api/items', (req, res) => {
    const user = getUserFromReq(req);
    if (!user) return send(res, 401, { error: 'Unauthorized' });
    const { text } = req.body;
    if (!text) return send(res, 400, { error: 'Missing text' });
    db.run('INSERT INTO items (text, user_id) VALUES (?, ?)', [text, user.userId], function(err) {
        if (err) return send(res, 500, { error: 'DB error' });
        send(res, 201, { success: true });
    });
});

// Delete To-Do Item
app.delete('/api/items/:id', (req, res) => {
    const user = getUserFromReq(req);
    if (!user) return send(res, 401, { error: 'Unauthorized' });
    const id = req.params.id;
    db.run('DELETE FROM items WHERE id = ? AND user_id = ?', [id, user.userId], function(err) {
        if (err) return send(res, 500, { error: 'DB error' });
        send(res, 200, { success: true });
    });
});

// --- TELEGRAM BOT WEBHOOK SETUP ---
const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { webHook: { port: false } }); // We'll attach to Express manually

const webhookPath = `/bot${TELEGRAM_BOT_TOKEN}`;
const webhookURL = `${URL}${webhookPath}`;

// Set webhook on startup
bot.setWebHook(webhookURL);

// Attach webhook endpoint to Express
app.post(webhookPath, (req, res) => {
    bot.processUpdate(req.body);
    res.sendStatus(200);
});

// Telegram bot logic
bot.onText(/\/start/, (msg) => {
    bot.sendMessage(msg.chat.id, 'Welcome to your Telegram To-Do Bot!\nUse /add <task> to add a to-do.\nUse /list to see your to-dos.');
    db.get('SELECT * FROM users WHERE telegram_id = ?', [msg.from.id], (err, user) => {
        if (!user) {
            db.run('INSERT INTO users (telegram_id) VALUES (?)', [msg.from.id]);
        }
    });
});

bot.onText(/\/add (.+)/, (msg, match) => {
    const todoText = match[1];
    db.get('SELECT * FROM users WHERE telegram_id = ?', [msg.from.id], (err, user) => {
        if (!user) {
            db.run('INSERT INTO users (telegram_id) VALUES (?)', [msg.from.id], function(err) {
                if (err) return bot.sendMessage(msg.chat.id, 'Could not register user.');
                addTodo(this.lastID);
            });
        } else {
            addTodo(user.id);
        }
        function addTodo(userId) {
            db.run('INSERT INTO items (text, user_id) VALUES (?, ?)', [todoText, userId], function(err) {
                if (err) bot.sendMessage(msg.chat.id, 'Failed to add to-do.');
                else bot.sendMessage(msg.chat.id, `Added: ${todoText}`);
            });
        }
    });
});

bot.onText(/\/list/, (msg) => {
    db.get('SELECT * FROM users WHERE telegram_id = ?', [msg.from.id], (err, user) => {
        if (!user) {
            bot.sendMessage(msg.chat.id, 'You have no to-dos. Use /add <task> to add one!');
        } else {
            db.all('SELECT text FROM items WHERE user_id = ?', [user.id], (err, rows) => {
                if (err || !rows.length) {
                    bot.sendMessage(msg.chat.id, 'No to-dos found.');
                } else {
                    const list = rows.map((row, i) => `${i + 1}. ${row.text}`).join('\n');
                    bot.sendMessage(msg.chat.id, `Your To-Dos:\n${list}`);
                }
            });
        }
    });
});

// --- START SERVER ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Telegram webhook set to: ${webhookURL}`);
});
