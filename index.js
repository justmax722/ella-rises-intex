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

// Donation success page route
app.get('/donate/success', async (req, res) => {
  try {
    const userId = parseInt(req.query.userId);
    const amount = parseFloat(req.query.amount);
    const isActive = req.query.active === 'true';

    if (isNaN(userId) || isNaN(amount)) {
      return res.redirect('/donate?error=invalid_parameters');
    }

    // Fetch user data
    const user = await db('users')
      .where('userid', userId)
      .first();

    if (!user) {
      return res.redirect('/donate?error=user_not_found');
    }

    res.render('donate-success', {
      userId: userId,
      amount: amount,
      email: user.useremail,
      isActive: isActive,
      query: req.query
    });
  } catch (error) {
    console.error('Donation success page error:', error);
    res.redirect('/donate?error=page_error');
  }
});

// Claim account route (activate shadow account with password)
app.post('/donate/claim', async (req, res) => {
  try {
    const { userId, firstName, lastName, password, confirmPassword } = req.body;

    const userIdNum = parseInt(userId);
    if (isNaN(userIdNum)) {
      return res.redirect('/donate?error=invalid_user_id');
    }

    // Validate name fields
    if (!firstName || !lastName) {
      return res.redirect(`/donate/success?userId=${userIdNum}&error=missing_name`);
    }

    // Validate password
    if (!password || !confirmPassword) {
      return res.redirect(`/donate/success?userId=${userIdNum}&error=missing_password`);
    }

    if (password !== confirmPassword) {
      return res.redirect(`/donate/success?userId=${userIdNum}&error=password_mismatch`);
    }

    if (password.length < 6) {
      return res.redirect(`/donate/success?userId=${userIdNum}&error=password_too_short`);
    }

    // Check if user exists and is a shadow account
    const user = await db('users')
      .where('userid', userIdNum)
      .where('accountactive', false)
      .first();

    if (!user) {
      return res.redirect('/donate?error=account_already_active');
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Activate account and update name
    await db('users')
      .where('userid', userIdNum)
      .where('accountactive', false)
      .update({
        userfirstname: firstName.trim(),
        userlastname: lastName.trim(),
        userpassword: hashedPassword,
        accountactive: true
      });

    // Set session (auto-login)
    req.session.userId = userIdNum;
    req.session.userEmail = user.useremail;
    req.session.userRole = 'donor';

    // Redirect to dashboard
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Claim account error:', error);
    res.redirect('/donate?error=claim_failed');
  }
});

// Donation form submission route
app.post('/donate', async (req, res) => {
  try {
    const { donationAmount, paymentMethod, creditEmail, debitEmail, paypalEmail, bankEmail, message } = req.body;

    // Validate required fields
    if (!donationAmount || !paymentMethod) {
      return res.redirect('/donate?error=missing_fields');
    }

    // Extract email based on payment method
    let email = null;
    if (paymentMethod === 'credit' && creditEmail) {
      email = creditEmail.toLowerCase().trim();
    } else if (paymentMethod === 'debit' && debitEmail) {
      email = debitEmail.toLowerCase().trim();
    } else if (paymentMethod === 'paypal' && paypalEmail) {
      email = paypalEmail.toLowerCase().trim();
    } else if (paymentMethod === 'bank' && bankEmail) {
      email = bankEmail.toLowerCase().trim();
    }

    if (!email) {
      return res.redirect('/donate?error=email_required');
    }

    const donationAmountNum = parseFloat(donationAmount);
    if (isNaN(donationAmountNum) || donationAmountNum <= 0) {
      return res.redirect('/donate?error=invalid_amount');
    }

    // Look up user by email
    const existingUser = await db('users')
      .where('useremail', email)
      .first();

    let userId;
    let isNewShadowUser = false;

    if (existingUser) {
      // User exists
      userId = existingUser.userid;

      if (existingUser.accountactive) {
        // User is active - just record donation
        // Get next donation number for this user
        const maxDonation = await db('donation')
          .where('userid', userId)
          .max('donationno as maxno')
          .first();

        const nextDonationNo = (maxDonation?.maxno || 0) + 1;

        // Insert donation
        await db('donation').insert({
          userid: userId,
          donationno: nextDonationNo,
          donationamount: donationAmountNum,
          donationdate: new Date()
        });

        // Update total donations
        await db('users')
          .where('userid', userId)
          .increment('totaldonations', donationAmountNum);

        // Redirect to success (active user flow)
        return res.redirect(`/donate/success?userId=${userId}&amount=${donationAmountNum}&active=true`);
      } else {
        // Shadow account exists - record donation and redirect to claim
        const maxDonation = await db('donation')
          .where('userid', userId)
          .max('donationno as maxno')
          .first();

        const nextDonationNo = (maxDonation?.maxno || 0) + 1;

        await db('donation').insert({
          userid: userId,
          donationno: nextDonationNo,
          donationamount: donationAmountNum,
          donationdate: new Date()
        });

        await db('users')
          .where('userid', userId)
          .increment('totaldonations', donationAmountNum);

        return res.redirect(`/donate/success?userId=${userId}&amount=${donationAmountNum}`);
      }
    } else {
      // User doesn't exist - create shadow user
      // Get RoleID 3 for donor
      const donorRole = await db('roletype')
        .where('roleid', 3)
        .first();

      if (!donorRole) {
        return res.redirect('/donate?error=role_not_found');
      }

      // Create shadow user (accountactive = false, userpassword = NULL)
      // Use empty strings for first/last name since database has NOT NULL constraints
      const [newUser] = await db('users')
        .insert({
          useremail: email,
          userfirstname: '',
          userlastname: '',
          userpassword: null,
          roleid: 3,
          accountactive: false,
          totaldonations: donationAmountNum
        })
        .returning('userid');

      userId = newUser.userid;
      isNewShadowUser = true;

      // Insert donation (donationno = 1 for first donation)
      await db('donation').insert({
        userid: userId,
        donationno: 1,
        donationamount: donationAmountNum,
        donationdate: new Date()
      });

      // Redirect to success page for account claiming
      return res.redirect(`/donate/success?userId=${userId}&amount=${donationAmountNum}`);
    }
  } catch (error) {
    console.error('Donation submission error:', error);
    res.redirect('/donate?error=submission_failed');
  }
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
    const existingUser = await db('users')
      .where('useremail', email.toLowerCase())
      .first();
    
    if (existingUser) {
      // Check if it's an active account
      if (existingUser.accountactive) {
        return res.render('login', {
          error: 'Email already registered. Please login instead.',
          success: null,
          showSignUp: true
        });
      } else {
        // Shadow account exists - redirect to verification
        return res.redirect(`/verify-claim?email=${encodeURIComponent(email.toLowerCase())}`);
      }
    }

    // Hash password before storing
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Get roleid for "user" role (assuming it's roleid 2 based on login code)
    const userRole = await db('roletype')
      .where('roleid', 2)
      .first();

    if (!userRole) {
      return res.render('login', {
        error: 'System error: User role not found',
        success: null,
        showSignUp: true
      });
    }

    // Insert new user - all signups are "user" role
    const [newUser] = await db('users')
      .insert({
        useremail: email.toLowerCase(),
        userfirstname: first_name,
        userlastname: last_name,
        userpassword: hashedPassword,
        roleid: 2,
        accountactive: true,
        totaldonations: 0
      })
      .returning(['userid', 'useremail', 'roleid']);

    // Get role name for session
    const role = await db('roletype')
      .where('roleid', newUser.roleid)
      .first();

    // Set session
    req.session.userId = newUser.userid;
    req.session.userEmail = newUser.useremail;
    req.session.userRole = role ? role.rolename.toLowerCase() : 'user';

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

    // Check if user exists (regardless of active status)
    const userCheck = await db('users')
      .where('useremail', email.toLowerCase())
      .first();

    if (!userCheck) {
      return res.render('login', {
        error: 'Invalid email or password',
        success: null,
        showSignUp: false
      });
    }

    // Check if account is unclaimed (shadow account)
    if (!userCheck.accountactive) {
      return res.redirect(`/verify-claim?email=${encodeURIComponent(email.toLowerCase())}&error=unclaimed_account`);
    }

    // Find user by email in users table (lowercase) with AccountActive check
    // All column names are lowercase in PostgreSQL (unquoted identifiers are lowercased)
    const user = await db('users')
      .where('useremail', email.toLowerCase())
      .where('accountactive', true)
      .first();

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

// Verify claim page route (for shadow account verification)
app.get('/verify-claim', async (req, res) => {
  try {
    const email = req.query.email;

    if (!email) {
      return res.redirect('/login?error=email_required');
    }

    // Fetch user data
    const user = await db('users')
      .where('useremail', email.toLowerCase())
      .where('accountactive', false)
      .first();

    if (!user) {
      return res.redirect('/login?error=account_not_found');
    }

    res.render('verify-claim', {
      email: user.useremail,
      query: req.query
    });
  } catch (error) {
    console.error('Verify claim page error:', error);
    res.redirect('/login?error=page_error');
  }
});

// Verify claim submission route
app.post('/verify-claim', async (req, res) => {
  try {
    const { email, firstName, lastName, donationDate, lastDonationAmount, password, confirmPassword } = req.body;

    if (!email || !firstName || !lastName || !donationDate || !lastDonationAmount || !password || !confirmPassword) {
      return res.redirect(`/verify-claim?email=${encodeURIComponent(email)}&error=missing_fields`);
    }

    // Validate name fields
    if (!firstName.trim() || !lastName.trim()) {
      return res.redirect(`/verify-claim?email=${encodeURIComponent(email)}&error=missing_name`);
    }

    // Validate password
    if (password !== confirmPassword) {
      return res.redirect(`/verify-claim?email=${encodeURIComponent(email)}&error=password_mismatch`);
    }

    if (password.length < 6) {
      return res.redirect(`/verify-claim?email=${encodeURIComponent(email)}&error=password_too_short`);
    }

    // Fetch user and donation data
    const user = await db('users')
      .where('useremail', email.toLowerCase())
      .where('accountactive', false)
      .first();

    if (!user) {
      return res.redirect('/login?error=account_not_found');
    }

    // Get last donation
    const lastDonation = await db('donation')
      .where('userid', user.userid)
      .orderBy('donationdate', 'desc')
      .orderBy('donationno', 'desc')
      .first();

    if (!lastDonation) {
      return res.redirect(`/verify-claim?email=${encodeURIComponent(email)}&error=no_donations`);
    }

    // Verify donation date (compare dates, ignoring time)
    // Handle both string dates from database and Date objects
    const inputDate = new Date(donationDate);
    const dbDate = lastDonation.donationdate;
    const donationDateObj = dbDate instanceof Date ? dbDate : new Date(dbDate);
    
    // Normalize to UTC dates for comparison (avoid timezone issues)
    const inputYear = inputDate.getUTCFullYear();
    const inputMonth = inputDate.getUTCMonth();
    const inputDay = inputDate.getUTCDate();
    
    const dbYear = donationDateObj.getUTCFullYear();
    const dbMonth = donationDateObj.getUTCMonth();
    const dbDay = donationDateObj.getUTCDate();
    
    // Compare year, month, and day only
    const dateMatch = inputYear === dbYear &&
      inputMonth === dbMonth &&
      inputDay === dbDay;

    // Verify donation amount (allow small rounding differences, e.g., 0.01)
    const donationAmountNum = parseFloat(lastDonationAmount);
    const lastDonationAmountNum = parseFloat(lastDonation.donationamount);
    const amountMatch = !isNaN(donationAmountNum) && 
      !isNaN(lastDonationAmountNum) &&
      Math.abs(donationAmountNum - lastDonationAmountNum) < 0.01;

    if (!dateMatch || !amountMatch) {
      return res.redirect(`/verify-claim?email=${encodeURIComponent(email)}&error=verification_failed`);
    }

    // Verification passed - hash password and activate account
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    await db('users')
      .where('userid', user.userid)
      .where('accountactive', false)
      .update({
        userfirstname: firstName.trim(),
        userlastname: lastName.trim(),
        userpassword: hashedPassword,
        accountactive: true
      });

    // Set session (auto-login)
    req.session.userId = user.userid;
    req.session.userEmail = user.useremail;
    req.session.userRole = 'donor';

    // Redirect to dashboard
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Verify claim error:', error);
    res.redirect('/login?error=verification_failed');
  }
});

// Donations route (protected)
app.get('/donations', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    if (!userId) {
      return res.redirect('/login');
    }

    // Get user info
    const dbUser = await db('users')
      .where('userid', userId)
      .first();

    if (!dbUser) {
      return res.redirect('/login');
    }

    // Get all donations for this user
    const donations = await db('donation')
      .where('userid', userId)
      .orderBy('donationdate', 'desc')
      .orderBy('donationno', 'desc');

    // Calculate stats
    const totalDonations = parseFloat(dbUser.totaldonations) || 0;

    // Get current month start and end
    const now = new Date();
    const currentMonthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const currentMonthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59);

    // Calculate this month's donations
    const thisMonthDonations = donations
      .filter(d => {
        const donationDate = new Date(d.donationdate);
        return donationDate >= currentMonthStart && donationDate <= currentMonthEnd;
      })
      .reduce((sum, d) => sum + parseFloat(d.donationamount || 0), 0);

    // Calculate average donation
    const averageDonation = donations.length > 0
      ? donations.reduce((sum, d) => sum + parseFloat(d.donationamount || 0), 0) / donations.length
      : 0;

    // Format donations with user info
    const formattedDonations = donations.map(donation => ({
      ...donation,
      donationamount: parseFloat(donation.donationamount || 0),
      donationdate: new Date(donation.donationdate),
      // Format date for display
      formattedDate: new Date(donation.donationdate).toLocaleDateString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      })
    }));

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: dbUser.userfirstname || '',
      lastName: dbUser.userlastname || ''
    };

    res.render('donations', {
      user,
      donations: formattedDonations,
      stats: {
        totalDonations: totalDonations.toFixed(2),
        thisMonthDonations: thisMonthDonations.toFixed(2),
        thisMonthCount: donations.filter(d => {
          const donationDate = new Date(d.donationdate);
          return donationDate >= currentMonthStart && donationDate <= currentMonthEnd;
        }).length,
        averageDonation: averageDonation.toFixed(2)
      }
    });
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
    
    // Build query with optional filters
    let query = db('users')
      .leftJoin('roletype', 'users.roleid', 'roletype.roleid')
      .select(
        'users.userid',
        'users.useremail',
        'users.userfirstname',
        'users.userlastname',
        'users.roleid',
        'users.accountactive',
        'users.totaldonations',
        'roletype.rolename'
      );

    // Apply search filter if provided
    if (req.query.search) {
      const searchTerm = `%${req.query.search.toLowerCase()}%`;
      query = query.where(function() {
        this.whereRaw('LOWER(users.userfirstname) LIKE ?', [searchTerm])
          .orWhereRaw('LOWER(users.userlastname) LIKE ?', [searchTerm])
          .orWhereRaw('LOWER(users.useremail) LIKE ?', [searchTerm])
          .orWhereRaw('LOWER(CONCAT(users.userfirstname, \' \', users.userlastname)) LIKE ?', [searchTerm]);
      });
    }

    // Apply role filter if provided (can be array for multiple roles)
    if (req.query.role) {
      const roleIds = Array.isArray(req.query.role) 
        ? req.query.role.map(r => parseInt(r))
        : [parseInt(req.query.role)];
      query = query.whereIn('users.roleid', roleIds);
    }

    // Apply status filter if provided (can be array for multiple statuses)
    if (req.query.status) {
      const statuses = Array.isArray(req.query.status) 
        ? req.query.status 
        : [req.query.status];
      const activeStatuses = statuses.map(s => s === 'active');
      query = query.whereIn('users.accountactive', activeStatuses);
    }

    const users = await query.orderBy('users.userid', 'asc');
    
    // Fetch all roles for filter dropdown
    const roles = await db('roletype')
      .select('roleid', 'rolename')
      .orderBy('roleid', 'asc');
    
    const currentUser = {
      email: req.session.userEmail,
      role: req.session.userRole
    };
    res.render('users', { user: currentUser, users, roles, query: req.query });
  } catch (error) {
    console.error('Users error:', error);
    res.redirect('/login');
  }
});

// Edit user route (protected, manager only)
app.get('/users/edit/:userid', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect('/dashboard');
    }

    const userId = parseInt(req.params.userid);
    if (isNaN(userId)) {
      return res.redirect('/users?error=invalid_user_id');
    }

    // Fetch user by ID
    const user = await db('users')
      .leftJoin('roletype', 'users.roleid', 'roletype.roleid')
      .where('users.userid', userId)
      .select(
        'users.userid',
        'users.useremail',
        'users.userfirstname',
        'users.userlastname',
        'users.roleid',
        'users.accountactive',
        'users.totaldonations',
        'roletype.rolename'
      )
      .first();

    if (!user) {
      return res.redirect('/users?error=user_not_found');
    }

    // Fetch all available roles
    const roles = await db('roletype')
      .select('roleid', 'rolename')
      .orderBy('roleid', 'asc');

    const currentUser = {
      email: req.session.userEmail,
      role: req.session.userRole
    };

    res.render('edit-user', { user, roles, currentUser, query: req.query });
  } catch (error) {
    console.error('Edit user error:', error);
    res.redirect('/users?error=edit_failed');
  }
});

// Update user route (protected, manager only)
app.post('/users/update/:userid', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const userId = parseInt(req.params.userid);
    if (isNaN(userId)) {
      return res.redirect('/users?error=invalid_user_id');
    }

    const { useremail, userfirstname, userlastname, password, roleid, accountactive } = req.body;

    // Validate required fields
    if (!useremail || !userfirstname || !userlastname || !roleid) {
      return res.redirect(`/users/edit/${userId}?error=missing_fields`);
    }

    // Check if user exists
    const existingUser = await db('users').where('userid', userId).first();
    if (!existingUser) {
      return res.redirect('/users?error=user_not_found');
    }

    // Prepare update object
    // Handle checkbox: if checked, value is 'on', if unchecked, it's undefined
    // Note: totaldonations is not included as it's financial data that cannot be changed
    const updateData = {
      useremail: useremail.toLowerCase(),
      userfirstname: userfirstname,
      userlastname: userlastname,
      roleid: parseInt(roleid),
      accountactive: !!(accountactive === 'on' || accountactive === true || accountactive === 'true')
    };

    // Only update password if provided
    if (password && password.trim() !== '') {
      const saltRounds = 10;
      updateData.userpassword = await bcrypt.hash(password, saltRounds);
    }

    // Update user in database
    await db('users')
      .where('userid', userId)
      .update(updateData);

    res.redirect('/users?success=user_updated');
  } catch (error) {
    console.error('Update user error:', error);
    res.redirect(`/users/edit/${req.params.userid}?error=update_failed`);
  }
});

// Delete user route (protected, manager only)
app.post('/users/delete/:userid', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).json({ success: false, message: 'Forbidden' });
    }

    const userId = parseInt(req.params.userid);
    if (isNaN(userId)) {
      return res.status(400).json({ success: false, message: 'Invalid user ID' });
    }

    // Check if user exists
    const user = await db('users').where('userid', userId).first();
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Prevent deleting yourself
    // Compare both as numbers and as strings to handle different session formats
    const sessionUserId = typeof req.session.userId === 'string' ? parseInt(req.session.userId) : req.session.userId;
    if (userId === sessionUserId || user.useremail === req.session.userEmail) {
      return res.status(400).json({ success: false, message: 'You cannot delete your own account' });
    }

    // Prevent deleting demo accounts
    if (user.useremail === 'manager@ellarises.org' || user.useremail === 'user@ellarises.org') {
      return res.status(400).json({ success: false, message: 'Demo accounts cannot be deleted' });
    }

    // Delete user from database
    // Foreign key constraints will handle related records automatically:
    // - Donations: ON DELETE SET NULL (anonymizes donations)
    // - Profile: ON DELETE CASCADE (deletes profile)
    // - Registration, UserMilestone, Survey: Should be handled by their constraints
    await db('users').where('userid', userId).del();

    // Return JSON response for AJAX requests
    if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
      return res.json({ success: true, message: 'User deleted successfully' });
    }

    // Fallback for non-AJAX requests
    res.redirect('/users?success=user_deleted');
  } catch (error) {
    console.error('Delete user error:', error);
    
    // Return JSON response for AJAX requests
    if (req.headers['x-requested-with'] === 'XMLHttpRequest') {
      return res.status(500).json({ success: false, message: 'Failed to delete user. Please try again.' });
    }

    // Fallback for non-AJAX requests
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

