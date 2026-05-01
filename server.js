const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const db = new sqlite3.Database('database.sqlite');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY, name TEXT, description TEXT)`);
  db.run(`CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, title TEXT, project_id INTEGER, assignee_id INTEGER, status TEXT, due_date TEXT)`);
  
  db.get("SELECT * FROM users WHERE email='admin@admin.com'", (err, row) => {
    if (!row) {
      const hash = bcrypt.hashSync('admin123', 10);
      db.run("INSERT INTO users (name, email, password, role) VALUES (?,?,?,?)", ['Admin', 'admin@admin.com', hash, 'admin']);
      console.log('Admin created');
    }
  });
});

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  jwt.verify(token, 'secret', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid' });
    req.user = user;
    next();
  });
};

app.post('/api/signup', (req, res) => {
  const { name, email, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (name, email, password) VALUES (?,?,?)", [name, email, hash], function(err) {
    if (err) return res.status(400).json({ error: err.message });
    res.json({ message: 'User created' });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get("SELECT * FROM users WHERE email=?", [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid' });
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, role: user.role }, 'secret');
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  });
});

app.get('/api/projects', auth, (req, res) => {
  db.all("SELECT * FROM projects", (err, projects) => res.json(projects || []));
});

app.post('/api/projects', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.run("INSERT INTO projects (name, description) VALUES (?,?)", [req.body.name, req.body.description || ''], function(err) {
    res.json({ id: this.lastID });
  });
});

app.delete('/api/projects/:id', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  db.run("DELETE FROM projects WHERE id=?", [req.params.id], () => res.json({ message: 'Deleted' }));
});

app.get('/api/tasks', auth, (req, res) => {
  db.all("SELECT * FROM tasks", (err, tasks) => res.json(tasks || []));
});

app.post('/api/tasks', auth, (req, res) => {
  const { title, projectId, assigneeId, status, dueDate } = req.body;
  db.run("INSERT INTO tasks (title, project_id, assignee_id, status, due_date) VALUES (?,?,?,?,?)", 
    [title, projectId, assigneeId, status || 'todo', dueDate], function(err) {
      res.json({ id: this.lastID });
    });
});

app.put('/api/tasks/:id', auth, (req, res) => {
  db.run("UPDATE tasks SET status=? WHERE id=?", [req.body.status, req.params.id], () => res.json({ message: 'Updated' }));
});

app.delete('/api/tasks/:id', auth, (req, res) => {
  db.run("DELETE FROM tasks WHERE id=?", [req.params.id], () => res.json({ message: 'Deleted' }));
});

app.get('/api/users', auth, (req, res) => {
  db.all("SELECT id, name, email, role FROM users", (err, users) => res.json(users || []));
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Server on port ${PORT}`));