require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const knex = require('knex');
const knexConfig = require('./knexfile');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 8080;
const db = knex(knexConfig);

// Test database connection on startup
(async () => {
  try {
    await db.raw('SELECT 1');
    console.log('✓ Database connection successful');
    
    // Always check for and run new migrations (safe - won't re-run old ones)
    console.log('Checking for pending migrations...');
    const [batchNo, log] = await db.migrate.latest();
    if (log.length === 0) {
      console.log('✓ All migrations are up to date');
    } else {
      console.log(`✓ Applied ${log.length} new migration(s) in batch ${batchNo}`);
      log.forEach(logEntry => console.log(`  - ${logEntry}`));
    }
  } catch (error) {
    console.error('✗ Database connection failed:', error.message);
    console.error('Connection details:', {
      host: process.env.RDS_HOSTNAME || process.env.DB_HOST || 'localhost',
      database: process.env.RDS_DB_NAME || process.env.DB_NAME || 'ella_rises',
      user: process.env.RDS_USERNAME || process.env.DB_USER || 'postgres',
      sslEnabled: !!(process.env.RDS_HOSTNAME || process.env.RDS_DB_NAME || process.env.AWS_EXECUTION_ENV)
    });
    console.error('Please check your database configuration and ensure RDS security groups allow connections.');
  }
})();

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serve static files from public directory
app.use(express.static(path.join(__dirname, 'public')));

// Parse URL-encoded bodies (for login form)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session configuration
const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret && process.env.NODE_ENV === 'production') {
  console.warn('⚠️  WARNING: SESSION_SECRET not set in production! Using default (INSECURE).');
}

app.use(session({
  secret: sessionSecret || 'ella-rises-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true, // Prevent XSS attacks
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

// Donation page route
app.get('/donate', (req, res) => {
  res.render('donate', { query: req.query });
});

// Donation form submission route
app.post('/donate', (req, res) => {
  // TODO: Process donation payment
  // For now, redirect back with success message
  res.redirect('/donate?success=true');
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

    // Hash password before storing
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user
    const [newUser] = await db('users')
      .insert({
        email,
        password: hashedPassword,
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

    // Hardcoded demo accounts
    const demoAccounts = {
      'manager@ellarises.org': {
        password: 'password123',
        role: 'manager',
        id: 'demo-manager'
      },
      'user@ellarises.org': {
        password: 'password123',
        role: 'user',
        id: 'demo-user'
      }
    };

    // Check if it's a demo account
    if (demoAccounts[email.toLowerCase()]) {
      const demoAccount = demoAccounts[email.toLowerCase()];
      if (password === demoAccount.password) {
        // Set session for demo account
        req.session.userId = demoAccount.id;
        req.session.userEmail = email.toLowerCase();
        req.session.userRole = demoAccount.role;
        return res.redirect('/dashboard');
      } else {
        return res.render('login', {
          error: 'Invalid email or password',
          success: null
        });
      }
    }

    // Find user by email in database
    const user = await db('users').where({ email }).first();

    if (!user) {
      return res.render('login', {
        error: 'Invalid email or password',
        success: null
      });
    }

    // Check password using bcrypt
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
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
    // Handle demo accounts (they don't exist in database)
    if (req.session.userId === 'demo-manager' || req.session.userId === 'demo-user') {
      return res.render('dashboard', {
        user: {
          email: req.session.userEmail,
          role: req.session.userRole
        }
      });
    }

    // Handle regular database users
    const user = await db('users').where({ id: req.session.userId }).first();
    if (!user) {
      return res.redirect('/login');
    }
    
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

// Health check endpoint for Elastic Beanstalk
app.get('/health', async (req, res) => {
  try {
    await db.raw('SELECT 1');
    res.status(200).json({ status: 'healthy', database: 'connected' });
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', database: 'disconnected', error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).render('login', {
    error: 'An unexpected error occurred. Please try again.',
    success: null
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

