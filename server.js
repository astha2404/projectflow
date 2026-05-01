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

// Create tables
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
            console.log('✅ Admin user created');
        }
    });
    
    console.log('✅ Database initialized');
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

// ============ AUTH ROUTES ============
app.post('/api/signup', (req, res) => {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    db.run("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", 
        [name, email, hashedPassword], 
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) {
                    return res.status(400).json({ error: 'Email already exists' });
                }
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: 'User created successfully', userId: this.lastID });
        });
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (bcrypt.compareSync(password, user.password)) {
            const token = jwt.sign(
                { id: user.id, email: user.email, role: user.role, name: user.name }, 
                JWT_SECRET
            );
            res.json({ 
                token, 
                user: { id: user.id, name: user.name, email: user.email, role: user.role } 
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// ============ PROJECT ROUTES ============
app.get('/api/projects', auth, (req, res) => {
    db.all("SELECT * FROM projects ORDER BY id DESC", (err, projects) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(projects || []);
    });
});

app.post('/api/projects', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { name, description } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: 'Project name required' });
    }
    
    db.run("INSERT INTO projects (name, description) VALUES (?, ?)", 
        [name, description || ''], 
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ id: this.lastID, name, description });
        });
});

app.delete('/api/projects/:id', auth, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    db.run("DELETE FROM projects WHERE id = ?", [req.params.id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Project deleted successfully' });
    });
});

// ============ TASK ROUTES ============
app.get('/api/tasks', auth, (req, res) => {
    db.all("SELECT * FROM tasks ORDER BY due_date ASC", (err, tasks) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(tasks || []);
    });
});

app.post('/api/tasks', auth, (req, res) => {
    const { title, description, projectId, assigneeId, priority, status, dueDate } = req.body;
    
    console.log('📝 Creating task:', { title, projectId, assigneeId, priority, status, dueDate });
    
    if (!title || !projectId) {
        return res.status(400).json({ error: 'Title and projectId are required' });
    }
    
    const query = `INSERT INTO tasks (title, description, project_id, assignee_id, priority, status, due_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?)`;
    
    const params = [
        title,
        description || '',
        parseInt(projectId),
        assigneeId ? parseInt(assigneeId) : null,
        priority || 'medium',
        status || 'todo',
        dueDate || null
    ];
    
    db.run(query, params, function(err) {
        if (err) {
            console.error('❌ Database error:', err);
            return res.status(500).json({ error: err.message });
        }
        
        console.log('✅ Task created with ID:', this.lastID);
        res.json({ 
            id: this.lastID,
            title,
            description,
            projectId: parseInt(projectId),
            assigneeId: assigneeId ? parseInt(assigneeId) : null,
            priority: priority || 'medium',
            status: status || 'todo',
            dueDate: dueDate || null
        });
    });
});

app.put('/api/tasks/:id', auth, (req, res) => {
    const { status, title, description, assigneeId, priority, dueDate } = req.body;
    const updates = [];
    const values = [];
    
    if (status !== undefined) { updates.push("status = ?"); values.push(status); }
    if (title !== undefined) { updates.push("title = ?"); values.push(title); }
    if (description !== undefined) { updates.push("description = ?"); values.push(description); }
    if (assigneeId !== undefined) { updates.push("assignee_id = ?"); values.push(assigneeId); }
    if (priority !== undefined) { updates.push("priority = ?"); values.push(priority); }
    if (dueDate !== undefined) { updates.push("due_date = ?"); values.push(dueDate); }
    
    if (updates.length === 0) {
        return res.status(400).json({ error: 'No fields to update' });
    }
    
    values.push(req.params.id);
    db.run(`UPDATE tasks SET ${updates.join(', ')} WHERE id = ?`, values, function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Task updated successfully' });
    });
});

app.delete('/api/tasks/:id', auth, (req, res) => {
    db.run("DELETE FROM tasks WHERE id = ?", [req.params.id], function(err) {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json({ message: 'Task deleted successfully' });
    });
});

// ============ USER ROUTES ============
app.get('/api/users', auth, (req, res) => {
    db.all("SELECT id, name, email, role FROM users ORDER BY name", (err, users) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        res.json(users || []);
    });
});

// ============ SERVE FRONTEND ============
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📝 Admin Login: admin@admin.com / admin123`);
    console.log(`✅ Ready to accept requests!`);
});