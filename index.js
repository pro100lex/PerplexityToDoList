const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const PORT = 3000;
const JWT_SECRET = 'your_super_secret_key';

// Open (or create) the SQLite database
const db = new sqlite3.Database('database.db');

// Run schema creation on startup
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
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

function send(res, status, data, headers = {}) {
    res.writeHead(status, Object.assign({'Content-Type': 'application/json'}, headers));
    res.end(JSON.stringify(data));
}
function parseBody(req) {
    return new Promise(resolve => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try { resolve(JSON.parse(body)); }
            catch { resolve({}); }
        });
    });
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

async function handleRequest(req, res) {
    if (req.method === 'GET' && (req.url === '/' || req.url.startsWith('/index.html'))) {
        const html = await fs.promises.readFile(path.join(__dirname, 'index.html'), 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
        return;
    }

    // Registration
    if (req.url === '/api/register' && req.method === 'POST') {
        const { email, password } = await parseBody(req);
        if (!email || !password) return send(res, 400, { error: 'Missing fields' });
        const hash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash], function(err) {
            if (err) return send(res, 400, { error: 'Registration failed' });
            send(res, 201, { success: true });
        });
        return;
    }

    // Login
    if (req.url === '/api/login' && req.method === 'POST') {
        const { email, password } = await parseBody(req);
        if (!email || !password) return send(res, 400, { error: 'Missing fields' });
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
            if (err || !user) return send(res, 401, { error: 'Invalid credentials' });
            if (!(await bcrypt.compare(password, user.password_hash))) return send(res, 401, { error: 'Invalid credentials' });
            const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.writeHead(200, {
                'Content-Type': 'application/json',
                'Set-Cookie': cookie.serialize('jwt', token, {
                    httpOnly: true,
                    maxAge: 3600,
                    sameSite: 'lax',
                    path: '/',
                })
            });
            res.end(JSON.stringify({ success: true }));
        });
        return;
    }

    // Logout
    if (req.url === '/api/logout' && req.method === 'POST') {
        res.writeHead(200, {
            'Content-Type': 'application/json',
            'Set-Cookie': cookie.serialize('jwt', '', {
                httpOnly: true,
                maxAge: 0,
                sameSite: 'lax',
                path: '/',
            })
        });
        res.end(JSON.stringify({ success: true }));
        return;
    }

    // Check Auth
    if (req.url === '/api/check-auth' && req.method === 'GET') {
        const user = getUserFromReq(req);
        send(res, 200, { authenticated: !!user });
        return;
    }

    // Get To-Do Items
    if (req.url === '/api/items' && req.method === 'GET') {
        const user = getUserFromReq(req);
        if (!user) return send(res, 401, { error: 'Unauthorized' });
        db.all('SELECT id, text FROM items WHERE user_id = ?', [user.userId], (err, rows) => {
            if (err) return send(res, 500, { error: 'DB error' });
            send(res, 200, rows);
        });
        return;
    }

    // Add To-Do Item
    if (req.url === '/api/items' && req.method === 'POST') {
        const user = getUserFromReq(req);
        if (!user) return send(res, 401, { error: 'Unauthorized' });
        const { text } = await parseBody(req);
        if (!text) return send(res, 400, { error: 'Missing text' });
        db.run('INSERT INTO items (text, user_id) VALUES (?, ?)', [text, user.userId], function(err) {
            if (err) return send(res, 500, { error: 'DB error' });
            send(res, 201, { success: true });
        });
        return;
    }

    // Delete To-Do Item
    if (req.url.startsWith('/api/items/') && req.method === 'DELETE') {
        const user = getUserFromReq(req);
        if (!user) return send(res, 401, { error: 'Unauthorized' });
        const id = req.url.split('/').pop();
        db.run('DELETE FROM items WHERE id = ? AND user_id = ?', [id, user.userId], function(err) {
            if (err) return send(res, 500, { error: 'DB error' });
            send(res, 200, { success: true });
        });
        return;
    }

    send(res, 404, { error: 'Not found' });
}

const server = http.createServer((req, res) => {
    handleRequest(req, res).catch(e => {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
    });
});
server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

const TelegramBot = require('node-telegram-bot-api'); // <-- This is required!

const token = '7966439372:AAGAYa42pOFjazMKopk2dpWEDFnvvjbSRrU';
const bot = new TelegramBot(token, { polling: true });

bot.onText(/\/start/, (msg) => {
    bot.sendMessage(msg.chat.id, 'Welcome to your Telegram To-Do Bot!\nUse /add <task> to add a to-do.\nUse /list to see your to-dos.');
    // Optionally, register Telegram user in users table if not already present
    db.get('SELECT * FROM users WHERE telegram_id = ?', [msg.from.id], (err, user) => {
        if (!user) {
            db.run('INSERT INTO users (telegram_id) VALUES (?)', [msg.from.id]);
        }
    });
});

bot.onText(/\/add (.+)/, (msg, match) => {
    const todoText = match[1];
    // Ensure user exists in users table
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
