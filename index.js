// testing
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

// Middleware to restrict routes for donor role
const restrictDonor = (req, res, next) => {
  if (req.session.userRole === 'donor') {
    return res.redirect('/dashboard');
  }
  next();
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
  res.render('login', { error: null, success: null, showSignUp: false });
});

// Signup route (POST)
app.post('/signup', async (req, res) => {
  try {
    const { first_name, last_name, email, password, confirm_password } = req.body;

    // Validate input
    if (!first_name || !last_name || !email || !password || !confirm_password) {
      return res.render('login', {
        error: 'Please fill in all fields',
        success: null,
        showSignUp: true
      });
    }

    // Validate password match
    if (password !== confirm_password) {
      return res.render('login', {
        error: 'Passwords do not match',
        success: null,
        showSignUp: true
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.render('login', {
        error: 'Password must be at least 6 characters long',
        success: null,
        showSignUp: true
      });
    }

    // Check if email already exists
    const existingUser = await db('users').where({ email: email.toLowerCase() }).first();
    if (existingUser) {
      return res.render('login', {
        error: 'Email already registered. Please login instead.',
        success: null,
        showSignUp: true
      });
    }

    // Hash password before storing
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user - all signups are "user" role
    const [newUser] = await db('users')
      .insert({
        email: email.toLowerCase(),
        password: hashedPassword,
        user_role: 'user',
        first_name: first_name,
        last_name: last_name
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
      success: null,
      showSignUp: true
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
        success: null,
        showSignUp: false
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
          success: null,
          showSignUp: false
        });
      }
    }

    // Find user by email in users table (lowercase) with AccountActive check
    // All column names are lowercase in PostgreSQL (unquoted identifiers are lowercased)
    const user = await db('users')
      .where('useremail', email.toLowerCase())
      .where('accountactive', true)
      .first();

    if (!user) {
      return res.render('login', {
        error: 'Invalid email or password, or account is inactive',
        success: null,
        showSignUp: false
      });
    }

    // Check password - note: if passwords are stored plain text, use direct comparison
    // If they're hashed, use bcrypt.compare
    // Column names are lowercase: userpassword
    const userPassword = user.userpassword;
    let passwordMatch;
    if (userPassword && userPassword.startsWith('$2')) {
      // Password is hashed with bcrypt
      passwordMatch = await bcrypt.compare(password, userPassword);
    } else {
      // Password is plain text (for your test accounts)
      passwordMatch = password === userPassword;
    }

    if (!passwordMatch) {
      return res.render('login', {
        error: 'Invalid email or password',
        success: null,
        showSignUp: false
      });
    }

    // Map RoleID to role string
    // RoleID 1 = admin/manager, RoleID 2 = user, RoleID 3 = donor
    // Column names are lowercase: roleid
    const roleID = user.roleid;
    let roleString;
    if (roleID === 1 || roleID === '1') {
      roleString = 'manager';
    } else if (roleID === 2 || roleID === '2') {
      roleString = 'user';
    } else if (roleID === 3 || roleID === '3') {
      roleString = 'donor';
    } else {
      roleString = 'user'; // default
    }

    // Set session - column names are lowercase: userid, useremail
    req.session.userId = user.userid;
    req.session.userEmail = user.useremail;
    req.session.userRole = roleString;

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', {
      error: 'An error occurred during login. Please try again.',
      success: null,
      showSignUp: false
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
    // We already have user info in session from login, no need to query again
    // But if we did, we'd use userid (lowercase), not id
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

// Participants route (protected)
app.get('/participants', requireAuth, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole
    };
    res.render('participants', { user });
  } catch (error) {
    console.error('Participants error:', error);
    res.redirect('/login');
  }
});

// Events route (protected, no donor access)
app.get('/events', requireAuth, restrictDonor, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole
    };
    res.render('events', { user });
  } catch (error) {
    console.error('Events error:', error);
    res.redirect('/login');
  }
});

// Surveys route (protected, no donor access)
app.get('/surveys', requireAuth, restrictDonor, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole
    };
    res.render('surveys', { user });
  } catch (error) {
    console.error('Surveys error:', error);
    res.redirect('/login');
  }
});

// Milestones route (protected, no donor access)
app.get('/milestones', requireAuth, restrictDonor, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole
    };
    res.render('milestones', { user });
  } catch (error) {
    console.error('Milestones error:', error);
    res.redirect('/login');
  }
});

// Donations route (protected)
app.get('/donations', requireAuth, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole
    };
    res.render('donations', { user });
  } catch (error) {
    console.error('Donations error:', error);
    res.redirect('/login');
  }
});

// Users route (protected, manager only)
app.get('/users', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect('/dashboard');
    }
    
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole
    };
    res.render('users', { user, query: req.query });
  } catch (error) {
    console.error('Users error:', error);
    res.redirect('/login');
  }
});

// Update user role route (protected, manager only)
app.post('/users/update', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const { email, role } = req.body;

    if (!email || !role || !['manager', 'user'].includes(role)) {
      return res.status(400).send('Invalid request');
    }

    // Don't allow updating demo accounts
    if (email === 'manager@ellarises.org' || email === 'user@ellarises.org') {
      return res.redirect('/users?error=demo_accounts_cannot_be_modified');
    }

    // Update user role in database
    await db('users')
      .where({ email })
      .update({ user_role: role });

    res.redirect('/users?success=role_updated');
  } catch (error) {
    console.error('Update user error:', error);
    res.redirect('/users?error=update_failed');
  }
});

// Delete user route (protected, manager only)
app.post('/users/delete', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const { email } = req.body;

    if (!email) {
      return res.status(400).send('Invalid request');
    }

    // Don't allow deleting demo accounts
    if (email === 'manager@ellarises.org' || email === 'user@ellarises.org') {
      return res.redirect('/users?error=demo_accounts_cannot_be_deleted');
    }

    // Don't allow deleting yourself
    if (email === req.session.userEmail) {
      return res.redirect('/users?error=cannot_delete_yourself');
    }

    // Delete user from database
    await db('users').where({ email }).del();

    res.redirect('/users?success=user_deleted');
  } catch (error) {
    console.error('Delete user error:', error);
    res.redirect('/users?error=delete_failed');
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

