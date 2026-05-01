const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const db = new sqlite3.Database('database.sqlite');

// Create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'member'
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        project_id INTEGER,
        assignee_id INTEGER,
        status TEXT DEFAULT 'todo',
        due_date DATE
    )`);
    
    // Create admin user
    db.get("SELECT * FROM users WHERE email = 'admin@admin.com'", (err, row) => {
        if (!row) {
            const hashedPassword = bcrypt.hashSync('admin123', 10);
            db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
                ['Admin', 'admin@admin.com', hashedPassword, 'admin']);
        }
    });
});

// Middleware
const auth = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    
    jwt.verify(token, 'secret', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Routes
app.post('/api/signup', (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
        [name, email, hashedPassword], function(err) {
            if (err) return res.status(400).json({ error: err.message });
            res.json({ message: 'User created' });
        });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, 'secret');
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    });
});

app.get('/api/projects', auth, (req, res) => {
    db.all("SELECT * FROM projects", (err, projects) => {
        res.json(projects);
    });
});

app.post('/api/projects', auth, (req, res) => {
    const { name, description } = req.body;
    db.run("INSERT INTO projects (name, description) VALUES (?, ?)", [name, description], function(err) {
        res.json({ id: this.lastID });
    });
});

app.get('/api/tasks', auth, (req, res) => {
    db.all("SELECT * FROM tasks", (err, tasks) => {
        res.json(tasks);
    });
});

app.post('/api/tasks', auth, (req, res) => {
    const { title, projectId, assigneeId, dueDate } = req.body;
    db.run("INSERT INTO tasks (title, project_id, assignee_id, due_date) VALUES (?, ?, ?, ?)", 
        [title, projectId, assigneeId, dueDate], function(err) {
            res.json({ id: this.lastID });
        });
});

app.put('/api/tasks/:id', auth, (req, res) => {
    const { status } = req.body;
    db.run("UPDATE tasks SET status = ? WHERE id = ?", [status, req.params.id], () => {
        res.json({ message: 'Updated' });
    });
});

app.get('/api/users', auth, (req, res) => {
    db.all("SELECT id, name, email, role FROM users", (err, users) => {
        res.json(users);
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`Admin: admin@admin.com / admin123`);
});