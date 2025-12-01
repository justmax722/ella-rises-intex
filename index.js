require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const knex = require('knex');
const knexConfig = require('./knexfile');

const app = express();
const PORT = process.env.PORT || 3000;
const db = knex(knexConfig);

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Parse URL-encoded bodies (for login form)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'ella-rises-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true if using HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Landing page route
app.get('/', (req, res) => {
  res.render('landing');
});

// Login page route
app.get('/login', (req, res) => {
  // If already logged in, redirect to dashboard
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('login', { error: null, success: null });
});

// Signup route (POST)
app.post('/signup', async (req, res) => {
  try {
    const { email, password, user_role } = req.body;

    // Validate input
    if (!email || !password || !user_role) {
      return res.render('login', {
        error: 'Please fill in all fields',
        success: null
      });
    }

    // Validate role
    if (!['manager', 'user', 'donor'].includes(user_role)) {
      return res.render('login', {
        error: 'Invalid role selected',
        success: null
      });
    }

    // Check if email already exists
    const existingUser = await db('users').where({ email }).first();
    if (existingUser) {
      return res.render('login', {
        error: 'Email already registered. Please login instead.',
        success: null
      });
    }

    // Insert new user (password is stored as plain text for now - should be hashed in production)
    const [newUser] = await db('users')
      .insert({
        email,
        password, // In production, hash this with bcrypt
        user_role
      })
      .returning(['id', 'email', 'user_role']);

    // Set session
    req.session.userId = newUser.id;
    req.session.userEmail = newUser.email;
    req.session.userRole = newUser.user_role;

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Signup error:', error);
    res.render('login', {
      error: 'An error occurred during signup. Please try again.',
      success: null
    });
  }
});

// Login route (POST)
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.render('login', {
        error: 'Please provide both email and password',
        success: null
      });
    }

    // Find user by email
    const user = await db('users').where({ email }).first();

    if (!user) {
      return res.render('login', {
        error: 'Invalid email or password',
        success: null
      });
    }

    // Check password (plain text comparison for now - should use bcrypt in production)
    if (user.password !== password) {
      return res.render('login', {
        error: 'Invalid email or password',
        success: null
      });
    }

    // Set session
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    req.session.userRole = user.user_role;

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', {
      error: 'An error occurred during login. Please try again.',
      success: null
    });
  }
});

// Dashboard route (protected)
app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const user = await db('users').where({ id: req.session.userId }).first();
    res.render('dashboard', {
      user: {
        email: req.session.userEmail,
        role: req.session.userRole
      }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.redirect('/login');
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
    }
    res.redirect('/');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

