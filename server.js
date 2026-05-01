const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'my-secret-key';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// Database with /tmp path for Railway
const db = new sqlite3.Database('/tmp/database.sqlite');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'member'
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        project_id INTEGER,
        assignee_id INTEGER,
        priority TEXT DEFAULT 'medium',
        status TEXT DEFAULT 'todo',
        due_date DATE
    )`);
    
    // Create admin user
    db.get("SELECT * FROM users WHERE email = 'admin@admin.com'", (err, row) => {
        if (!row) {
            const hashedPassword = bcrypt.hashSync('admin123', 10);
            db.run("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", 
                ['Admin', 'admin@admin.com', hashedPassword, 'admin']);
            console.log('Admin user created successfully');
        }
    });
    
    console.log('Database initialized');
});

// Auth middleware
const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
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
            res.json({ message: 'User created', userId: this.lastID });
        });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Invalid credentials' });
        
        if (bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET);
            res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

app.get('/api/projects', auth, (req, res) => {
    db.all("SELECT * FROM projects", (err, projects) => {
        res.json(projects || []);
    });
});

app.post('/api/projects', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    const { name, description } = req.body;
    db.run("INSERT INTO projects (name, description) VALUES (?, ?)", [name, description], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, name, description });
    });
});

app.delete('/api/projects/:id', auth, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    db.run("DELETE FROM projects WHERE id = ?", [req.params.id], () => {
        res.json({ message: 'Deleted' });
    });
});

app.get('/api/tasks', auth, (req, res) => {
    db.all("SELECT * FROM tasks", (err, tasks) => {
        res.json(tasks || []);
    });
});

app.post('/api/tasks', auth, (req, res) => {
    const { title, description, projectId, assigneeId, priority, status, dueDate } = req.body;
    db.run(`INSERT INTO tasks (title, description, project_id, assignee_id, priority, status, due_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [title, description, projectId, assigneeId, priority || 'medium', status || 'todo', dueDate],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        });
});

app.put('/api/tasks/:id', auth, (req, res) => {
    const { status } = req.body;
    db.run("UPDATE tasks SET status = ? WHERE id = ?", [status, req.params.id], () => {
        res.json({ message: 'Updated' });
    });
});

app.delete('/api/tasks/:id', auth, (req, res) => {
    db.run("DELETE FROM tasks WHERE id = ?", [req.params.id], () => {
        res.json({ message: 'Deleted' });
    });
});

app.get('/api/users', auth, (req, res) => {
    db.all("SELECT id, name, email, role FROM users", (err, users) => {
        res.json(users || []);
    });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📝 Admin: admin@admin.com / admin123`);
});