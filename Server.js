const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

const JWT_SECRET = 'yakeen_super_secret_2026';
const RAZORPAY_WEBHOOK_SECRET = 'yakeen_webhook_secret_2026';

initializeApp({
  credential: cert({
    projectId: "instagram-3a749",
    clientEmail: "firebase-adminsdk-su1js@instagram-3a749.iam.gserviceaccount.com",
    privateKey: "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCn3m37bAghjR6k\nyi9KvnKHvwUmRfRrOUYJwpbprm33svnEaSCYqjXNC5yxTP8KLDujifPEj0Lmx/rG\nXTtFUREB1c2tiN96BTRX3At5r4SVtHozSuGQAdmv92+WxzIOCg5FEAcj9R360+sx\nfFInTWop+sGEZR/BZyWJSvgViaiTCb6kpKm6crhTu1umsImQ/HaARndZSqyCbGIR\nZebypwXpuVQNhStHDTgEHj7Me/Yj3bFlVP9w/r0g9SPtIVrPdNbQNaL+HVIBoM+D\n7NUxJlhawPNdUXohhtwwb10LO5iim0QoCqEe0MfNnCinrtmzklfakakOAHl7zwhz\nx9iqJGifAgMBAAECggEAR0o2+udOLLF5qhITM3LdwLhmv3JF8qNIEy0IWgUxvlfL\nqpXaufrPDl04FjPUu8U9Lp6PX5JXnxqebU96tF1RE65wwpm2DmPXbtiMJwlbDRiw\nLMhIMpgWkpxKT4YYw82RcdL0tViLetI0t7dMTFScGWfcdxVa/w+G6V9lLABiDs8M\nJ0Y2tsCtC5t7Evcqsk73z9ndZlpi96ozUEXe92vDNwk/RpHL6LAEdrU86Z6UR8D2\nx8hb/ilBMopbijD73OQQlLEbzWvi8DRq9mX3TQ5o77SQ2mmof3Twq/VZ22u6X2no\nz8D07osozzJTCspgXnHqYndXcuMzTxeG0w0ZVT08AQKBgQDdoroYTUVScR3EdWx8\nXoIbBzdG021e9YNQSGsD8JGm+zHNQHLFf6zdxsnQoXeLJ+jkrA3GLeYobpwNz6ZO\n+y5+fXdqEc8enEhqFThl7RKaz16Dxxb8fQmETdTfOa21tC7+7pBQ0QhIPAc4253S\nq7S0FcrKgOwofwD3vcw3VgjhwQKBgQDB5ZCE8e3cGIxPdkRw4/K4yenCqNGqGcbm\nIHYAGU+gGgzggIjFoup/HfebbtR10QIhx8hBhGQCvnTrP0mwYiVnCHsb3up9mtjY\nazzhlpYTp8+hRAL7PaRqWLl9lzlbulwBlc9ViG3ZLDovxLtYoNOf5udzGPBZpj5f\nylRn/B0iXwKBgC+V+6yyEnsz7Dc9GvDM/dQ9xWGAjZAA2JPJKKjs4ujeMAAooTvE\nQOJRBw2zTU5kYD2Qr1hojG0L6peQiN2WUpI38AanEjg5R9b2/Wfs8bypX1qdyVKm\nqf9tEpJm+OP1bs2vfO7NIqEXulk71fPgh+jOcP7vlUTQl+2ZI5qR71BBAoGBALM+\nLKM5otFcQBkVE5/omXEJ9vbkaS3+Nkh2qZ7dxyYR7uV67PUG7hAk+8jMY8umM3pW\n3WDzqiB/QEZYcx6DHGBrDqNtJwiGJP+r4tQICSSSdPZ3kOoAygUlkBPxwCxz0qoE\ne25ueF3S7NdL3oTH59ph8oQMAeReMjsLJ4wZHDWxAoGBALT1JDwUkxU7t7RFI3lN\nnG9VHeZB9hirf8+phSZDKsmJ6ccaTE7Bmi/uBu0SNcDa1Scoi6SlbctzWf3Uk/of\nQ4BEFKCIrNQjSGFWNSOUHF8KrPYabZ7GHRfzrfGymjFao6djD8ZILQpSdYM8hkTl\nqQ5TjLQ+1aJZ1eST89wTmen6\n-----END PRIVATE KEY-----\n"
  })
});

const db = getFirestore();
const app = express();

// ── WEBHOOK needs raw body ──
app.use('/api/webhook/razorpay', express.raw({ type: 'application/json' }));
app.use(cors());
app.use(express.json());

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

// ── REGISTER ──
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, name, password } = req.body;
    if (!phone || !name || !password)
      return res.status(400).json({ error: 'All fields required' });
    const userRef = db.collection('users').doc(phone);
    const existing = await userRef.get();
    if (existing.exists)
      return res.status(400).json({ error: 'Already registered. Please login.' });
    const hashed = await bcrypt.hash(password, 10);
    await userRef.set({ phone, name, password: hashed, isPaid: false });
    const token = jwt.sign({ phone }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { name, phone, isPaid: false } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── LOGIN ──
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: 'All fields required' });
    const userRef = db.collection('users').doc(phone);
    const doc = await userRef.get();
    if (!doc.exists)
      return res.status(400).json({ error: 'User not found. Please register.' });
    const user = doc.data();
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ error: 'Invalid phone or password' });
    const token = jwt.sign({ phone }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { name: user.name, phone: user.phone, isPaid: user.isPaid } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── ME ──
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const doc = await db.collection('users').doc(req.user.phone).get();
    if (!doc.exists) return res.status(404).json({ error: 'User not found' });
    const user = doc.data();
    res.json({ name: user.name, phone: user.phone, isPaid: user.isPaid });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── RAZORPAY WEBHOOK ──
app.post('/api/webhook/razorpay', async (req, res) => {
  try {
    const signature = req.headers['x-razorpay-signature'];
    const body = req.body;
    const hmac = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET);
    hmac.update(body);
    const digest = hmac.digest('hex');
    if (digest !== signature) {
      console.error('Invalid webhook signature');
      return res.status(400).json({ error: 'Invalid signature' });
    }
    const event = JSON.parse(body);
    if (event.event === 'payment.captured' || event.event === 'payment_link.paid') {
      const contact = event.payload?.payment?.entity?.contact ||
                      event.payload?.payment_link?.entity?.customer_details?.contact;
      if (contact) {
        const phone = contact.replace('+91', '').replace(/\D/g, '');
        await db.collection('users').doc(phone).update({ isPaid: true });
        console.log('User unlocked:', phone);
      }
    }
    res.json({ status: 'ok' });
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(500).json({ error: 'Webhook error' });
  }
});

// ── HEALTH CHECK ──
app.get('/', (req, res) => res.json({ status: 'Yakeen Backend Running ✅' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
