const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');

// ── CONFIG ──
const MONGO_URI = 'mongodb+srv://Nert2027:Neet2027##@cluster0.whyfyy0.mongodb.net/yakeen?appName=Cluster0';
const JWT_SECRET = 'yakeen_super_secret_2026';

const app = express();
app.use(cors());
app.use(express.json());

// ── DATABASE ──
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// ── USER MODEL ──
const User = mongoose.model('User', {
  phone:    { type: String, unique: true },
  name:     String,
  password: String,
  isPaid:   { type: Boolean, default: false }
});

// ── AUTH MIDDLEWARE ──
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ── ROUTES ──

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, name, password } = req.body;
    if (!phone || !name || !password)
      return res.status(400).json({ error: 'All fields required' });
    if (await User.findOne({ phone }))
      return res.status(400).json({ error: 'Already registered. Please login.' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ phone, name, password: hashed });
    const token = jwt.sign({ id: user._id, phone }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { name: user.name, phone: user.phone, isPaid: user.isPaid } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: 'All fields required' });
    const user = await User.findOne({ phone });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(400).json({ error: 'Invalid phone or password' });
    const token = jwt.sign({ id: user._id, phone }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { name: user.name, phone: user.phone, isPaid: user.isPaid } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Me
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ name: user.name, phone: user.phone, isPaid: user.isPaid });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Mark as paid (manual - after Razorpay link payment)
app.post('/api/payment/confirm', auth, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { isPaid: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

// Health check
app.get('/', (req, res) => res.json({ status: 'Yakeen Backend Running ✅' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  
