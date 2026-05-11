require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// ── DATABASE ──
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

// ── USER MODEL ──
const User = mongoose.model('User', {
  phone:    { type: String, unique: true },
  name:     String,
  password: String,
  isPaid:   { type: Boolean, default: false }
});

// ── RAZORPAY ──
const rzp = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ── AUTH MIDDLEWARE ──
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
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
    const token = jwt.sign({ id: user._id, phone }, process.env.JWT_SECRET, { expiresIn: '30d' });
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
    const token = jwt.sign({ id: user._id, phone }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { name: user.name, phone: user.phone, isPaid: user.isPaid } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Me (verify token + get user)
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ name: user.name, phone: user.phone, isPaid: user.isPaid });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create Razorpay Order
app.post('/api/payment/order', auth, async (req, res) => {
  try {
    const order = await rzp.orders.create({ amount: 49900, currency: 'INR' });
    res.json({ key: process.env.RAZORPAY_KEY_ID, amount: order.amount, orderId: order.id });
  } catch (err) {
    res.status(500).json({ error: 'Order creation failed' });
  }
});

// Verify Payment & Unlock
app.post('/api/payment/verify', auth, async (req, res) => {
  try {
    const { razorpayOrderId, razorpayPaymentId, razorpaySignature } = req.body;
    const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
    hmac.update(razorpayOrderId + '|' + razorpayPaymentId);
    if (hmac.digest('hex') !== razorpaySignature)
      return res.status(400).json({ error: 'Invalid payment signature' });
    await User.findByIdAndUpdate(req.user.id, { isPaid: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Health check
app.get('/', (req, res) => res.json({ status: 'Yakeen Backend Running ✅' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
