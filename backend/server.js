// backend/server.js
// Minimal SaeChat backend: JWT auth + posts + real-time messages via Socket.io.
// Quick-start: in-memory stores (USERS, POSTS, MESSAGES). Later swap to MongoDB.

const express = require('express');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

// === Config ===
// Use environment variables in production. For local quick start, defaults are provided.
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const CLIENT_URL = process.env.CLIENT_URL || '*'; // restrict in production

// === Middleware ===
app.use(cors({ origin: CLIENT_URL }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// === File upload (multer) - stores to backend/uploads/ by default ===
const upload = multer({ dest: 'uploads/' });

// === In-memory "DB" - easiest to start with ===
// USERS: { id, username, email, passwordHash, avatar }
// POSTS: { id, authorId, text, imageUrl, likes: [] }
// MESSAGES: { id, from, to, text, createdAt }
const USERS = [];
const POSTS = [];
const MESSAGES = [];
let nextId = 1;
const genId = () => String(nextId++);

// === Simple JWT auth middleware ===
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// === Auth routes ===
// Register: saves user (hashed password) and returns token
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (USERS.find(u => u.email === email)) return res.status(400).json({ error: 'Email used' });
  const passwordHash = await bcrypt.hash(password, 8);
  const user = { id: genId(), username, email, passwordHash, avatar: null };
  USERS.push(user);
  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

// Login: verify password and return token
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  const user = USERS.find(u => u.email === email);
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id }, JWT_SECRET);
  res.json({ token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

// === Posts ===
// Create post (auth required). Accepts 'text' and optional attached 'image' file.
app.post('/api/posts', auth, upload.single('image'), (req, res) => {
  const text = req.body.text || '';
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : null; // saved locally
  const post = { id: genId(), authorId: req.userId, text, imageUrl, likes: [] };
  POSTS.unshift(post);
  res.json(post);
});

// Feed: returns posts (newest first) enriched with author info
app.get('/api/posts/feed', auth, (req, res) => {
  const feed = POSTS.map(p => {
    const author = USERS.find(u => u.id === p.authorId) || { username: 'unknown' };
    return { ...p, author: { id: author.id, username: author.username, avatar: author.avatar } };
  });
  res.json(feed);
});

// Like/unlike
app.post('/api/posts/:id/like', auth, (req, res) => {
  const post = POSTS.find(p => p.id === req.params.id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  const i = post.likes.indexOf(req.userId);
  if (i === -1) post.likes.push(req.userId); else post.likes.splice(i, 1);
  res.json(post);
});

// === Messages ===
// Save message (persist in memory) and return it
app.post('/api/messages', auth, (req, res) => {
  const { to, text } = req.body || {};
  if (!to || !text) return res.status(400).json({ error: 'Missing fields' });
  const msg = { id: genId(), from: req.userId, to, text, createdAt: new Date().toISOString() };
  MESSAGES.push(msg);
  res.json(msg);
});

// Get conversation between current user and another user
app.get('/api/messages/convo/:userId', auth, (req, res) => {
  const otherId = req.params.userId;
  const convo = MESSAGES.filter(m =>
    (m.from === req.userId && m.to === otherId) || (m.from === otherId && m.to === req.userId)
  ).sort((a,b)=> new Date(a.createdAt) - new Date(b.createdAt));
  res.json(convo);
});

// Basic root
app.get('/', (req, res) => res.send('SaeChat backend OK'));

// === Socket.io for real-time messages ===
const io = new Server(server, { cors: { origin: CLIENT_URL } });

// Map of userId -> socketId (simple presence map)
const onlineUsers = new Map();

io.on('connection', socket => {
  // when a client tells server "i'm online" -> store mapping
  socket.on('user-online', userId => {
    onlineUsers.set(userId, socket.id);
  });

  // send-message event: forward to recipient if online
  socket.on('send-message', ({ toUserId, message }) => {
    const toSocket = onlineUsers.get(toUserId);
    if (toSocket) {
      io.to(toSocket).emit('receive-message', message);
    }
  });

  // cleanup on disconnect
  socket.on('disconnect', () => {
    // remove any mapping(s) with this socket id
    for (const [userId, sId] of onlineUsers.entries()) {
      if (sId === socket.id) onlineUsers.delete(userId);
    }
  });
});

// Start server
server.listen(PORT, () => console.log('SaeChat backend listening on', PORT));
