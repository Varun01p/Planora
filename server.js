const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Environment
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/planora';
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// Mongoose models
const userSchema = new mongoose.Schema({
  name: { type: String, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['client', 'freelancer'], required: true },
  phone: { type: String, default: '' },
  specialization: { type: String, default: '' },
  experienceYears: { type: String, default: '' },
}, { timestamps: true });

userSchema.methods.toSafeJSON = function() {
  return {
    id: this._id.toString(),
    name: this.name || '',
    email: this.email,
    role: this.role,
    phone: this.phone || '',
    specialization: this.specialization || '',
    experienceYears: this.experienceYears || ''
  };
};

const User = mongoose.model('User', userSchema);

// App
const app = express();
app.use(cors());
app.use(express.json());

// Auth middleware
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const [, token] = header.split(' ');
  if (!token) return res.status(401).json({ message: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.auth = payload; // { uid, role, iat, exp }
    return next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// Auth routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password, role, phone, specialization, experienceYears } = req.body || {};

    if (!email || !password || !role) {
      return res.status(400).json({ message: 'email, password and role are required' });
    }
    if (!['client', 'freelancer'].includes(role)) {
      return res.status(400).json({ message: 'role must be client or freelancer' });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: 'Email already in use' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      name: name || '',
      email,
      passwordHash,
      role,
      phone: phone || '',
      specialization: specialization || '',
      experienceYears: experienceYears || ''
    });

    const token = jwt.sign({ uid: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    return res.status(201).json({ token, user: user.toSafeJSON() });
  } catch (err) {
    console.error('Signup error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ message: 'email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ uid: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: user.toSafeJSON() });
  } catch (err) {
    console.error('Login error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Return current user profile
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.auth.uid);
    if (!user) return res.status(404).json({ message: 'User not found' });
    return res.json({ user: user.toSafeJSON() });
  } catch (err) {
    console.error('Me error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Update current user profile (limited fields)
app.patch('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const updates = {};
    const allowed = ['name', 'phone', 'specialization', 'experienceYears', 'email'];
    for (const key of allowed) {
      if (Object.prototype.hasOwnProperty.call(req.body || {}, key)) {
        updates[key] = req.body[key];
      }
    }
    const user = await User.findByIdAndUpdate(req.auth.uid, updates, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    // Issue a fresh token (role may not change but keeps expiry fresh)
    const token = jwt.sign({ uid: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ token, user: user.toSafeJSON() });
  } catch (err) {
    console.error('Profile update error', err);
    if (err.code === 11000) return res.status(409).json({ message: 'Email already in use' });
    return res.status(500).json({ message: 'Internal server error' });
  }
});

// Static files (serve the existing frontend)
const publicDir = path.join(__dirname);
app.use(express.static(publicDir));

// Fallback to index.html for root
app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// Start
async function start() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');
    app.listen(PORT, () => {
      console.log(`Server listening on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server', err);
    process.exit(1);
  }
}

start();


