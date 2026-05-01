const express = require('express');
const { Pool } = require('pg');
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

// PostgreSQL connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Create tables
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'member'
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS projects (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT
            )
        `);
        
        await pool.query(`
            CREATE TABLE IF NOT EXISTS tasks (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                project_id INTEGER,
                assignee_id INTEGER,
                priority TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'todo',
                due_date DATE
            )
        `);
        
        // Create admin user
        const adminCheck = await pool.query("SELECT * FROM users WHERE email = 'admin@admin.com'");
        if (adminCheck.rows.length === 0) {
            const hashedPassword = bcrypt.hashSync('admin123', 10);
            await pool.query(
                "INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4)",
                ['Admin', 'admin@admin.com', hashedPassword, 'admin']
            );
            console.log('✅ Admin user created');
        }
        
        // Add sample projects if none exist
        const projectsCheck = await pool.query("SELECT * FROM projects");
        if (projectsCheck.rows.length === 0) {
            const sampleProjects = [
                'Website Development',
                'Mobile App Development',
                'E-Commerce Platform',
                'Task Management System',
                'Learning Management System'
            ];
            for (const project of sampleProjects) {
                await pool.query("INSERT INTO projects (name) VALUES ($1)", [project]);
            }
            console.log('✅ Sample projects added');
        }
        
        console.log('✅ Database initialized successfully');
    } catch (err) {
        console.error('Database error:', err);
    }
}

initDB();

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
app.post('/api/signup', async (req, res) => {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields required' });
    }
    
    try {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = await pool.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id",
            [name, email, hashedPassword]
        );
        res.json({ message: 'User created successfully', userId: result.rows[0].id });
    } catch (err) {
        if (err.constraint === 'users_email_unique') {
            return res.status(400).json({ error: 'Email already exists' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        const user = result.rows[0];
        
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, name: user.name },
            JWT_SECRET
        );
        res.json({
            token,
            user: { id: user.id, name: user.name, email: user.email, role: user.role }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ PROJECT ROUTES ============
app.get('/api/projects', auth, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM projects ORDER BY id DESC");
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/projects', auth, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { name, description } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Project name required' });
    }
    
    try {
        const result = await pool.query(
            "INSERT INTO projects (name, description) VALUES ($1, $2) RETURNING id",
            [name, description || '']
        );
        res.json({ id: result.rows[0].id, name, description });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/projects/:id', auth, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    
    try {
        await pool.query("DELETE FROM projects WHERE id = $1", [req.params.id]);
        res.json({ message: 'Project deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ TASK ROUTES ============
app.get('/api/tasks', auth, async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM tasks ORDER BY due_date ASC");
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/tasks', auth, async (req, res) => {
    const { title, description, projectId, assigneeId, priority, status, dueDate } = req.body;
    
    console.log('📝 Creating task:', { title, projectId, assigneeId, priority, status, dueDate });
    
    if (!title || !projectId) {
        return res.status(400).json({ error: 'Title and projectId are required' });
    }
    
    try {
        const result = await pool.query(
            `INSERT INTO tasks (title, description, project_id, assignee_id, priority, status, due_date)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
            [title, description || '', parseInt(projectId), assigneeId ? parseInt(assigneeId) : null, 
             priority || 'medium', status || 'todo', dueDate || null]
        );
        
        console.log('✅ Task created with ID:', result.rows[0].id);
        res.json({
            id: result.rows[0].id,
            title,
            description,
            projectId: parseInt(projectId),
            assigneeId: assigneeId ? parseInt(assigneeId) : null,
            priority: priority || 'medium',
            status: status || 'todo',
            dueDate: dueDate || null
        });
    } catch (err) {
        console.error('❌ Database error:', err);
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/tasks/:id', auth, async (req, res) => {
    const { status } = req.body;
    
    try {
        await pool.query("UPDATE tasks SET status = $1 WHERE id = $2", [status, req.params.id]);
        res.json({ message: 'Task updated successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/tasks/:id', auth, async (req, res) => {
    try {
        await pool.query("DELETE FROM tasks WHERE id = $1", [req.params.id]);
        res.json({ message: 'Task deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ USER ROUTES ============
app.get('/api/users', auth, async (req, res) => {
    try {
        const result = await pool.query("SELECT id, name, email, role FROM users ORDER BY name");
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ============ SERVE FRONTEND ============
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ============ START SERVER ============
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📝 Admin Login: admin@admin.com / admin123`);
    console.log(`✅ PostgreSQL database connected!`);
    console.log(`✅ Sample projects added automatically!`);
});