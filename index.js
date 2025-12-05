// testing
require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const knex = require('knex');
const knexConfig = require('./knexfile');
const bcrypt = require('bcrypt');
const PDFDocument = require('pdfkit');

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
    const host = process.env.RDS_HOSTNAME || process.env.DB_HOST || 'localhost';
    const isRDS = !!(
      process.env.RDS_HOSTNAME || 
      process.env.RDS_DB_NAME || 
      process.env.AWS_EXECUTION_ENV ||
      host.includes('.rds.amazonaws.com') ||
      host.includes('.rds.')
    );
    console.error('Connection details:', {
      host: host,
      database: process.env.RDS_DB_NAME || process.env.DB_NAME || 'ella_rises',
      user: process.env.RDS_USERNAME || process.env.DB_USER || 'postgres',
      sslEnabled: isRDS
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
    return res.redirect('/donations');
  }
  next();
};

// Helper function to get the default redirect destination based on user role
const getDefaultRedirect = (userRole) => {
  if (userRole === 'donor') {
    return '/donations';
  }
  return '/home';
};

// Landing page route
app.get('/', (req, res) => {
  res.render('landing', { isLoggedIn: !!req.session.userId });
});

// Donation page route
app.get('/donate', async (req, res) => {
  try {
    // Check if user is logged in
    if (req.session.userId) {
      // Fetch user email from database
      const dbUser = await db('users')
        .where('userid', req.session.userId)
        .first();
      
      if (dbUser) {
        return res.render('donate', {
          query: req.query,
          loggedIn: true,
          userEmail: dbUser.useremail,
          userId: req.session.userId
        });
      }
    }
    
    // Not logged in - keep existing behavior
    res.render('donate', { query: req.query });
  } catch (error) {
    console.error('Donate page error:', error);
    res.render('donate', { query: req.query });
  }
});

// Donation form submission route
app.post('/donate', async (req, res) => {
  try {
    const { donationAmount, paymentMethod, creditEmail, debitEmail, paypalEmail, bankEmail, message, loggedInUserId } = req.body;

    // Validate required fields
    if (!donationAmount || !paymentMethod) {
      const errorParams = new URLSearchParams();
      errorParams.set('error', 'missing_fields');
      if (donationAmount) errorParams.set('amount', donationAmount);
      if (message) errorParams.set('message', encodeURIComponent(message));
      if (paymentMethod) errorParams.set('paymentMethod', paymentMethod);
      return res.redirect(`/donate?${errorParams.toString()}`);
    }

    const donationAmountNum = parseFloat(donationAmount);
    if (isNaN(donationAmountNum) || donationAmountNum <= 0) {
      const errorParams = new URLSearchParams();
      errorParams.set('error', 'invalid_amount');
      errorParams.set('amount', donationAmount);
      if (message) errorParams.set('message', encodeURIComponent(message));
      if (paymentMethod) errorParams.set('paymentMethod', paymentMethod);
      return res.redirect(`/donate?${errorParams.toString()}`);
    }

    // Check if user is logged in (via session or loggedInUserId from form)
    const sessionUserId = req.session.userId;
    const formUserId = loggedInUserId ? parseInt(loggedInUserId) : null;
    const isLoggedIn = !!(sessionUserId || formUserId);

    if (isLoggedIn) {
      // Logged-in user flow - use session userId or form userId
      const userId = sessionUserId || formUserId;
      
      // Get user from database
      const dbUser = await db('users')
        .where('userid', userId)
        .first();

      if (!dbUser) {
        return res.redirect('/donate?error=user_not_found');
      }

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
        donationdate: new Date(),
        donationmessage: message && message.trim() ? message.trim() : null
      });

      // Update total donations
      await db('users')
        .where('userid', userId)
        .increment('totaldonations', donationAmountNum);

      // Redirect back to donations page with success message
      return res.redirect('/donations?donationSuccess=true');
    }

    // Guest flow - existing logic
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
          donationdate: new Date(),
          donationmessage: message && message.trim() ? message.trim() : null
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
          donationdate: new Date(),
          donationmessage: message && message.trim() ? message.trim() : null
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
      let userId;
      try {
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
      } catch (insertError) {
        // Handle sequence sync issues
        if (insertError.code === '23505') { // Duplicate key error
          console.error('Sequence out of sync. Attempting to fix...');
          const maxResult = await db('users').max('userid as maxid').first();
          const maxId = maxResult?.maxid || 0;
          await db.raw(`SELECT setval('users_userid_seq', ?)`, [maxId + 1]);
          
          // Retry the insert
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
        } else {
          throw insertError; // Re-throw if it's a different error
        }
      }

      // Insert donation (donationno = 1 for first donation)
      await db('donation').insert({
        userid: userId,
        donationno: 1,
        donationamount: donationAmountNum,
        donationdate: new Date(),
        donationmessage: message && message.trim() ? message.trim() : null
      });

      // Redirect to success page for account claiming
      return res.redirect(`/donate/success?userId=${userId}&amount=${donationAmountNum}`);
    }
  } catch (error) {
    console.error('Donation submission error:', error);
    
    // Preserve form data on error
    const errorParams = new URLSearchParams();
    errorParams.set('error', 'submission_failed');
    
    if (req.body.donationAmount) {
      errorParams.set('amount', req.body.donationAmount);
    }
    if (req.body.message) {
      errorParams.set('message', encodeURIComponent(req.body.message));
    }
    if (req.body.paymentMethod) {
      errorParams.set('paymentMethod', req.body.paymentMethod);
    }
    if (req.body.creditEmail) {
      errorParams.set('creditEmail', encodeURIComponent(req.body.creditEmail));
    }
    if (req.body.debitEmail) {
      errorParams.set('debitEmail', encodeURIComponent(req.body.debitEmail));
    }
    if (req.body.paypalEmail) {
      errorParams.set('paypalEmail', encodeURIComponent(req.body.paypalEmail));
    }
    if (req.body.bankEmail) {
      errorParams.set('bankEmail', encodeURIComponent(req.body.bankEmail));
    }
    
    res.redirect(`/donate?${errorParams.toString()}`);
  }
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
    res.redirect(getDefaultRedirect(req.session.userRole));
  } catch (error) {
    console.error('Claim account error:', error);
    res.redirect('/donate?error=claim_failed');
  }
});

// Login page route
app.get('/login', (req, res) => {
  // If already logged in, check for redirect or go to dashboard
  if (req.session.userId) {
    const redirect = req.query.redirect || req.session.loginRedirect;
    if (redirect) {
      delete req.session.loginRedirect;
      return res.redirect(redirect);
    }
    return res.redirect(getDefaultRedirect(req.session.userRole));
  }
  
  // Store redirect in session if provided
  if (req.query.redirect) {
    req.session.loginRedirect = req.query.redirect;
  }
  
  // Check if redirecting from login with non-existent email
  const showSignUp = req.query.signup === 'true';
  const signupEmail = req.session.signupEmail || null;
  const signupPassword = req.session.signupPassword || null;
  const signupMessage = req.session.signupMessage || null;
  
  // Get email from query parameter for pre-fill
  const loginEmail = req.query.email || '';
  
  // Clear signup session data after passing to view
  if (req.session.signupEmail) {
    delete req.session.signupEmail;
  }
  if (req.session.signupPassword) {
    delete req.session.signupPassword;
  }
  if (req.session.signupMessage) {
    delete req.session.signupMessage;
  }
  
  res.render('login', { 
    error: null, 
    success: null, 
    showSignUp: showSignUp,
    signupFirstName: '',
    signupLastName: '',
    signupEmail: signupEmail,
    signupPassword: signupPassword,
    signupConfirmPassword: '',
    signupMessage: signupMessage,
    loginEmail: loginEmail
  });
});

// Signup route (POST)
app.post('/signup', async (req, res) => {
  try {
    const { first_name, last_name, email, password, confirm_password } = req.body;

    // Helper to render with preserved form values
    const renderWithError = (errorMsg, clearPassword = false) => {
      return res.render('login', {
        error: errorMsg,
        success: null,
        showSignUp: true,
        signupFirstName: first_name || '',
        signupLastName: last_name || '',
        signupEmail: email || '',
        signupPassword: clearPassword ? '' : (password || ''),
        signupConfirmPassword: ''  // Always clear confirm password on error
      });
    };

    // Validate input
    if (!first_name || !last_name || !email || !password || !confirm_password) {
      return renderWithError('Please fill in all fields');
    }

    // Validate password match
    if (password !== confirm_password) {
      return renderWithError('Passwords do not match', true);
    }

    // Validate password length
    if (password.length < 6) {
      return renderWithError('Password must be at least 6 characters long', true);
    }

    // Check if email already exists in users table
    const existingUser = await db('users')
      .where('useremail', email.toLowerCase())
      .first();

    // Check if user exists and is active
    if (existingUser && existingUser.accountactive === true) {
      return renderWithError('Email already registered. Please login instead.');
    }

    // Check if user exists but is inactive
    if (existingUser && existingUser.accountactive === false) {
      // Check if it's a shadow donor account (roleid 3) - redirect to verify-claim
      if (existingUser.roleid === 3) {
        return res.redirect(`/verify-claim?email=${encodeURIComponent(email.toLowerCase())}`);
      }
      
      // Otherwise check if it has a profile (pending participant account)
      const existingProfile = await db('profile')
        .where('userid', existingUser.userid)
        .first();
      
      if (existingProfile) {
        return renderWithError('Account exists but is inactive. Please contact support.');
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
      return renderWithError('System error: User role not found');
    }

    let userId;
    
    // If user exists but is inactive and has no profile, update the user
    if (existingUser && existingUser.accountactive === false) {
      await db('users')
        .where('userid', existingUser.userid)
        .update({
          userfirstname: first_name,
          userlastname: last_name,
          userpassword: hashedPassword
        });
      userId = existingUser.userid;
    } else if (!existingUser) {
      // Create new user with accountactive = false
      // Let PostgreSQL auto-generate userid using the identity column
      try {
        const [newUser] = await db('users')
          .insert({
            useremail: email.toLowerCase(),
            userfirstname: first_name,
            userlastname: last_name,
            userpassword: hashedPassword,
            roleid: 2, // user role
            accountactive: false,
            totaldonations: null
          })
          .returning(['userid']);
        userId = newUser.userid;
      } catch (insertError) {
        // If there's a sequence issue, try to fix it and retry
        if (insertError.code === '23505') { // Duplicate key error
          console.error('Sequence out of sync. Attempting to fix...');
          // Get the max userid and set the sequence
          const maxResult = await db('users').max('userid as maxid').first();
          const maxId = maxResult?.maxid || 0;
          // Reset the sequence to be higher than the max
          await db.raw(`SELECT setval('users_userid_seq', ?)`, [maxId + 1]);
          
          // Retry the insert
          const [newUser] = await db('users')
            .insert({
              useremail: email.toLowerCase(),
              userfirstname: first_name,
              userlastname: last_name,
              userpassword: hashedPassword,
              roleid: 2,
              accountactive: false,
              totaldonations: null
            })
            .returning(['userid']);
          userId = newUser.userid;
        } else {
          throw insertError; // Re-throw if it's a different error
        }
      }
    } else {
      // This shouldn't happen based on our checks above, but handle it
      return renderWithError('An error occurred. Please try again.');
    }

    // Store user info in session temporarily for profile completion
    req.session.tempUserId = userId;
    req.session.tempUserEmail = email.toLowerCase();
    req.session.tempUserFirstName = first_name;
    req.session.tempUserLastName = last_name;

    // Redirect to profile form
    res.redirect('/profile');
  } catch (error) {
    console.error('Signup error:', error);
    res.render('login', {
      error: 'An error occurred during signup. Please try again.',
      success: null,
      showSignUp: true,
      signupFirstName: req.body?.first_name || '',
      signupLastName: req.body?.last_name || '',
      signupEmail: req.body?.email || '',
      signupPassword: '',
      signupConfirmPassword: ''
    });
  }
});

// Middleware to check if user is in signup process (has temp session)
const requireSignupSession = (req, res, next) => {
  if (req.session.tempUserId) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Profile completion route (for converted donors)
app.get('/profile/complete', requireAuth, (req, res) => {
  // Check if user is logged in and needs profile completion
  if (req.session.userId) {
    res.render('profile', { 
      error: null,
      user: {
        email: req.session.userEmail,
        firstName: req.session.userFirstName || '',
        lastName: req.session.userLastName || ''
      },
      fromConversion: true
    });
  } else {
    res.redirect('/login');
  }
});

// Profile route (GET) - for completing profile during signup
// This route is for signup only - logged-in users will be handled by the user profile route below
app.get('/profile', (req, res, next) => {
  // If user is already logged in, skip this route and go to the user profile route
  if (req.session.userId) {
    return next('route');
  }
  // Otherwise, check if they're in signup process
  if (req.session.tempUserId) {
    res.render('profile', { 
      error: null,
      user: {
        email: req.session.tempUserEmail,
        firstName: req.session.tempUserFirstName,
        lastName: req.session.tempUserLastName
      }
    });
  } else {
    res.redirect('/login');
  }
});

// Profile route (POST) - save profile and activate account (for signup and conversion)
app.post('/profile', async (req, res) => {
  // Check if user is logged in (from conversion) or in signup process
  const userId = req.session.userId || req.session.tempUserId;
  const isFromConversion = !!req.session.userId;
  
  if (!userId) {
    return res.redirect('/login');
  }
  try {
    const { 
      profiledob,
      dob_month,
      dob_day,
      dob_year,
      profilephone, 
      profilecity, 
      profilestate, 
      profilezip, 
      profileschooloremployer, 
      profilefieldofinterest 
    } = req.body;

    // Combine date fields into YYYY-MM-DD format for database
    // Priority: use separate fields if provided, otherwise use hidden profiledob field
    let dateOfBirth = null;
    if (dob_month && dob_day && dob_year) {
      // Combine separate fields into YYYY-MM-DD format
      const year = parseInt(dob_year);
      const month = parseInt(dob_month);
      const day = parseInt(dob_day);
      
      // Validate date is within reasonable ranges
      if (year < 1900 || year > new Date().getFullYear() || month < 1 || month > 12 || day < 1 || day > 31) {
        return res.render('profile', {
          error: 'Invalid date selected. Please check your date of birth.',
          user: {
            email: req.session.tempUserEmail,
            firstName: req.session.tempUserFirstName,
            lastName: req.session.tempUserLastName
          }
        });
      }
      
      // Validate that the date is actually valid (e.g., not Feb 30, or invalid leap year dates)
      // Use UTC to avoid timezone issues
      const dateObj = new Date(Date.UTC(year, month - 1, day));
      
      // Check if the date is valid by comparing UTC values
      if (dateObj.getUTCFullYear() !== year || 
          dateObj.getUTCMonth() + 1 !== month || 
          dateObj.getUTCDate() !== day) {
        return res.render('profile', {
          error: 'Invalid date selected. Please check your date of birth.',
          user: {
            email: req.session.tempUserEmail,
            firstName: req.session.tempUserFirstName,
            lastName: req.session.tempUserLastName
          }
        });
      }
      
      // Format as YYYY-MM-DD
      dateOfBirth = `${year}-${dob_month}-${dob_day}`;
    } else if (profiledob) {
      // Fallback to hidden field if separate fields not provided
      dateOfBirth = profiledob;
      
      // Validate the date format and validity
      const dateObj = new Date(dateOfBirth + 'T00:00:00'); // Add time to avoid timezone issues
      if (isNaN(dateObj.getTime())) {
        return res.render('profile', {
          error: 'Invalid date format. Please check your date of birth.',
          user: {
            email: req.session.tempUserEmail,
            firstName: req.session.tempUserFirstName,
            lastName: req.session.tempUserLastName
          }
        });
      }
    }

    // Validate all fields are provided
    if (!dateOfBirth || !profilephone || !profilecity || !profilestate || !profilezip || 
        !profileschooloremployer || !profilefieldofinterest) {
      return res.render('profile', {
        error: 'Please fill in all fields',
        user: {
          email: req.session.tempUserEmail,
          firstName: req.session.tempUserFirstName,
          lastName: req.session.tempUserLastName
        }
      });
    }

    // Clean phone number - remove formatting characters for storage
    const cleanPhone = profilephone.replace(/\D/g, '');

    // Check if profile already exists (for conversion case)
    const existingProfile = await db('profile')
      .where('userid', userId)
      .first();

    if (existingProfile) {
      // Update existing profile
      await db('profile')
        .where('userid', userId)
        .update({
          profiledob: dateOfBirth,
          profilephone: cleanPhone,
          profilecity: profilecity,
          profilestate: profilestate,
          profilezip: profilezip,
          profileschooloremployer: profileschooloremployer,
          profilefieldofinterest: profilefieldofinterest
        });
    } else {
      // Insert new profile data
      await db('profile')
        .insert({
          userid: userId,
          profiledob: dateOfBirth,
          profilephone: cleanPhone,
          profilecity: profilecity,
          profilestate: profilestate,
          profilezip: profilezip,
          profileschooloremployer: profileschooloremployer,
          profilefieldofinterest: profilefieldofinterest
        });
    }

    // Check if user account is inactive (admin-created user completing profile)
    const dbUser = await db('users')
      .where('userid', userId)
      .first();
    
    const isAccountInactive = dbUser && !dbUser.accountactive;

    if (isFromConversion || (req.session.userId && !isAccountInactive)) {
      // From conversion or already active account - user is already logged in, just redirect to profile page
      // Clear temp session variables if they exist
      delete req.session.tempUserId;
      delete req.session.tempUserEmail;
      delete req.session.tempUserFirstName;
      delete req.session.tempUserLastName;
      return res.redirect('/profile?tab=profile&success=true');
    } else {
      // From signup or admin-created account - activate account and set session
      // Update users table: set accountactive = true
      await db('users')
        .where('userid', userId)
        .update({ accountactive: true });

      // Get user data to set proper session
      const user = await db('users')
        .where('userid', userId)
        .first();

      // Map RoleID to role string
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

      // Set proper session variables
      req.session.userId = user.userid;
      req.session.userEmail = user.useremail;
      req.session.userRole = roleString;
      req.session.userFirstName = user.userfirstname || '';
      req.session.userLastName = user.userlastname || '';

      // Clear temp session variables
      delete req.session.tempUserId;
      delete req.session.tempUserEmail;
      delete req.session.tempUserFirstName;
      delete req.session.tempUserLastName;

      // Redirect to dashboard
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }
  } catch (error) {
    console.error('Profile error:', error);
    res.render('profile', {
      error: 'An error occurred while saving your profile. Please try again.',
      user: {
        email: req.session.tempUserEmail,
        firstName: req.session.tempUserFirstName,
        lastName: req.session.tempUserLastName
      }
    });
  }
});

// Middleware to check if user is in account claim process
const requireClaimSession = (req, res, next) => {
  if (req.session.claimEmail) {
    next();
  } else {
    res.redirect('/login');
  }
};

// Account Claim route (GET) - verify identity for pending accounts
app.get('/account-claim', requireClaimSession, (req, res) => {
  const attempts = req.session.claimAttempts || 0;
  const remainingAttempts = 5 - attempts;
  const maxAttemptsReached = attempts >= 5;
  
  res.render('account-claim', {
    error: null,
    email: req.session.claimEmail,
    remainingAttempts: remainingAttempts,
    maxAttemptsReached: maxAttemptsReached
  });
});

// Account Claim route (POST) - verify DOB and Zip
app.post('/account-claim', requireClaimSession, async (req, res) => {
  try {
    const { dob_month, dob_day, dob_year, profilezip } = req.body;
    
    // Check if max attempts reached
    const attempts = req.session.claimAttempts || 0;
    if (attempts >= 5) {
      return res.render('account-claim', {
        error: 'Too many failed attempts. Please contact an administrator to access your account.',
        email: req.session.claimEmail,
        remainingAttempts: 0,
        maxAttemptsReached: true
      });
    }
    
    // Validate all fields are provided
    if (!dob_month || !dob_day || !dob_year || !profilezip) {
      return res.render('account-claim', {
        error: 'Please fill in all fields',
        email: req.session.claimEmail,
        remainingAttempts: 5 - attempts,
        maxAttemptsReached: false,
        formData: { dob_month, dob_day, dob_year, profilezip }
      });
    }
    
    // Get user by email
    const user = await db('users')
      .where('useremail', req.session.claimEmail)
      .first();
    
    if (!user) {
      return res.redirect('/login');
    }
    
    // Get profile to verify DOB and Zip
    const profile = await db('profile')
      .where('userid', user.userid)
      .first();
    
    if (!profile) {
      return res.redirect('/login');
    }
    
    // Combine date fields into YYYY-MM-DD format
    const year = parseInt(dob_year);
    const month = parseInt(dob_month);
    const day = parseInt(dob_day);
    
    // Validate date
    if (year < 1900 || year > new Date().getFullYear() || month < 1 || month > 12 || day < 1 || day > 31) {
      req.session.claimAttempts = (req.session.claimAttempts || 0) + 1;
      return res.render('account-claim', {
        error: 'Invalid date. Please try again.',
        email: req.session.claimEmail,
        remainingAttempts: 5 - req.session.claimAttempts,
        maxAttemptsReached: req.session.claimAttempts >= 5,
        formData: { dob_month, dob_day, dob_year, profilezip }
      });
    }
    
    const submittedDOB = `${year}-${dob_month}-${dob_day}`;
    
    // Compare DOB (exact match, YYYY-MM-DD format)
    const storedDOB = profile.profiledob ? profile.profiledob.toISOString().split('T')[0] : null;
    const dobMatch = storedDOB === submittedDOB;
    
    // Compare Zip (case-insensitive)
    const zipMatch = profile.profilezip && 
                     profile.profilezip.toLowerCase().trim() === profilezip.toLowerCase().trim();
    
    if (dobMatch && zipMatch) {
      // Verification successful - store userid for password reset
      req.session.claimUserId = user.userid;
      req.session.claimUserEmail = user.useremail;
      // Clear claim attempts
      delete req.session.claimAttempts;
      return res.redirect('/set-password');
    } else {
      // Verification failed - increment attempts
      req.session.claimAttempts = (req.session.claimAttempts || 0) + 1;
      const newAttempts = req.session.claimAttempts;
      const remainingAttempts = 5 - newAttempts;
      
      if (newAttempts >= 5) {
        return res.render('account-claim', {
          error: 'Too many failed attempts. Please contact an administrator to access your account.',
          email: req.session.claimEmail,
          remainingAttempts: 0,
          maxAttemptsReached: true,
          formData: { dob_month, dob_day, dob_year, profilezip }
        });
      } else {
        return res.render('account-claim', {
          error: `Verification failed. Please check your date of birth and zip code. ${remainingAttempts} attempt(s) remaining.`,
          email: req.session.claimEmail,
          remainingAttempts: remainingAttempts,
          maxAttemptsReached: false,
          formData: { dob_month, dob_day, dob_year, profilezip }
        });
      }
    }
  } catch (error) {
    console.error('Account claim error:', error);
    const { dob_month, dob_day, dob_year, profilezip } = req.body;
    return res.render('account-claim', {
      error: 'An error occurred during verification. Please try again.',
      email: req.session.claimEmail,
      remainingAttempts: 5 - (req.session.claimAttempts || 0),
      maxAttemptsReached: (req.session.claimAttempts || 0) >= 5,
      formData: { dob_month, dob_day, dob_year, profilezip }
    });
  }
});

// Set Password route (GET) - for claiming pending accounts
app.get('/set-password', (req, res) => {
  if (!req.session.claimUserId) {
    return res.redirect('/login');
  }
  
  res.render('set-password', {
    error: null,
    email: req.session.claimUserEmail
  });
});

// Change Password route (GET) - for users with admin-set passwords
app.get('/change-password', requireAuth, (req, res) => {
  if (!req.session.passwordChangeRequired || !req.session.userId) {
    return res.redirect(getDefaultRedirect(req.session.userRole));
  }
  
  res.render('change-password', {
    error: null,
    email: req.session.userEmail
  });
});

// Change Password route (POST) - update password and activate account
app.post('/change-password', requireAuth, async (req, res) => {
  try {
    if (!req.session.passwordChangeRequired || !req.session.userId) {
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }
    
    const { password, confirm_password } = req.body;
    
    // Validate fields
    if (!password || !confirm_password) {
      return res.render('change-password', {
        error: 'Please fill in all fields',
        email: req.session.userEmail
      });
    }
    
    // Validate password match
    if (password !== confirm_password) {
      return res.render('change-password', {
        error: 'Passwords do not match',
        email: req.session.userEmail
      });
    }
    
    // Validate password length
    if (password.length < 6) {
      return res.render('change-password', {
        error: 'Password must be at least 6 characters long',
        email: req.session.userEmail
      });
    }
    
    const userId = req.session.userId;
    
    // Hash new password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Update user password and activate account
    await db('users')
      .where('userid', userId)
      .update({
        userpassword: hashedPassword,
        accountactive: true
      });
    
    // Clear password change requirement from session
    delete req.session.passwordChangeRequired;
    
    // Check if user is a participant (roleid = 2) and needs to complete profile
    const dbUser = await db('users')
      .where('userid', userId)
      .first();
    
    if (dbUser && (dbUser.roleid === 2 || dbUser.roleid === '2')) {
      // Check if profile exists
      const profile = await db('profile')
        .where('userid', userId)
        .first();
      
      if (!profile) {
        // Participant without profile - redirect to profile completion
        req.session.tempUserId = userId;
        req.session.tempUserEmail = dbUser.useremail;
        req.session.tempUserFirstName = dbUser.userfirstname || '';
        req.session.tempUserLastName = dbUser.userlastname || '';
        return res.redirect('/profile?requireProfile=true');
      }
    }
    
    // Check for redirect in session
    const redirect = req.session.loginRedirect;
    if (redirect) {
      delete req.session.loginRedirect;
      return res.redirect(redirect);
    }
    
    // Redirect to dashboard
    res.redirect(getDefaultRedirect(req.session.userRole));
  } catch (error) {
    console.error('Change password error:', error);
    return res.render('change-password', {
      error: 'An error occurred while changing your password. Please try again.',
      email: req.session.userEmail
    });
  }
});

// Set Password route (POST) - set password and activate account
app.post('/set-password', async (req, res) => {
  try {
    if (!req.session.claimUserId) {
      return res.redirect('/login');
    }
    
    const { password, confirm_password } = req.body;
    
    // Validate fields
    if (!password || !confirm_password) {
      return res.render('set-password', {
        error: 'Please fill in all fields',
        email: req.session.claimUserEmail
      });
    }
    
    // Validate password match
    if (password !== confirm_password) {
      return res.render('set-password', {
        error: 'Passwords do not match',
        email: req.session.claimUserEmail
      });
    }
    
    // Validate password length
    if (password.length < 6) {
      return res.render('set-password', {
        error: 'Password must be at least 6 characters long',
        email: req.session.claimUserEmail
      });
    }
    
    const userId = req.session.claimUserId;
    
    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Update user password and activate account
    await db('users')
      .where('userid', userId)
      .update({
        userpassword: hashedPassword,
        accountactive: true
      });
    
    // Get user data to set proper session
    const user = await db('users')
      .where('userid', userId)
      .first();
    
    // Map RoleID to role string
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
    
    // Set proper session variables
    req.session.userId = user.userid;
    req.session.userEmail = user.useremail;
    req.session.userRole = roleString;
    
    // Clear claim-related session data
    delete req.session.claimEmail;
    delete req.session.claimUserId;
    delete req.session.claimUserEmail;
    delete req.session.claimAttempts;
    
    // Redirect to dashboard
    res.redirect(getDefaultRedirect(req.session.userRole));
  } catch (error) {
    console.error('Set password error:', error);
    return res.render('set-password', {
      error: 'An error occurred while setting your password. Please try again.',
      email: req.session.claimUserEmail
    });
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
    res.redirect(getDefaultRedirect(req.session.userRole));
  } catch (error) {
    console.error('Verify claim error:', error);
    res.redirect('/login?error=verification_failed');
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
        showSignUp: false,
        loginEmail: email || '',
        loginPassword: password || ''
      });
    }

    // Check if email exists in users table
    const user = await db('users')
      .where('useremail', email.toLowerCase())
      .first();

    // If email doesn't exist, redirect to signup with email/password stored in session (more secure)
    if (!user) {
      // Store email and password in session for signup pre-fill (more secure than localStorage)
      req.session.signupEmail = email.toLowerCase();
      req.session.signupPassword = password;
      req.session.signupMessage = 'No account found with this email. Please create an account to continue.';
      return res.redirect('/login?signup=true');
    }

    // Check if it's a shadow donor account (inactive, no password, roleid 3) - redirect directly to verify-claim
    if (!user.accountactive && !user.userpassword && user.roleid === 3) {
      return res.redirect(`/verify-claim?email=${encodeURIComponent(email.toLowerCase())}&error=unclaimed_account`);
    }

    // Check password first - note: if passwords are stored plain text, use direct comparison
    // If they're hashed, use bcrypt.compare
    // Column names are lowercase: userpassword
    const userPassword = user.userpassword;
    let passwordMatch = false;
    
    if (userPassword) {
      if (userPassword.startsWith('$2')) {
        // Password is hashed with bcrypt
        passwordMatch = await bcrypt.compare(password, userPassword);
      } else {
        // Password is plain text (for your test accounts)
        passwordMatch = password === userPassword;
      }
    }

    // If password doesn't match and account is inactive, check what to do
    if (!passwordMatch) {
      // Check if account is inactive
      if (!user.accountactive) {
        // Check if it's a shadow donor account (roleid 3) - redirect to verify-claim
        if (user.roleid === 3) {
          return res.redirect(`/verify-claim?email=${encodeURIComponent(email.toLowerCase())}&error=unclaimed_account`);
        }
        
        // No password set or wrong password - check if user has a profile (pending account)
        const profile = await db('profile')
          .where('userid', user.userid)
          .first();
        
        if (profile) {
          // Pending account with profile - redirect to account claim
          req.session.claimEmail = email.toLowerCase();
          req.session.claimAttempts = 0;
          return res.redirect('/account-claim');
        } else {
          // No profile - redirect to signup
          req.session.signupEmail = email.toLowerCase();
          req.session.signupPassword = password;
          req.session.signupMessage = 'Please complete your profile to activate your account.';
          return res.redirect('/login?signup=true');
        }
      } else {
        // Account is active but password is wrong
        return res.render('login', {
          error: 'Invalid email or password',
          success: null,
          showSignUp: false,
          loginEmail: email,
          loginPassword: password
        });
      }
    }

    // Password matches - now check if account is active
    if (!user.accountactive) {
      // Password is correct but account is inactive - admin set password, user must change it
      req.session.userId = user.userid;
      req.session.userEmail = user.useremail;
      // Map role for session (needed for requireAuth middleware)
      const roleID = user.roleid;
      let roleString;
      if (roleID === 1 || roleID === '1') {
        roleString = 'manager';
      } else if (roleID === 2 || roleID === '2') {
        roleString = 'user';
      } else if (roleID === 3 || roleID === '3') {
        roleString = 'donor';
      } else {
        roleString = 'user';
      }
      req.session.userRole = roleString;
      req.session.passwordChangeRequired = true;
      return res.redirect('/change-password');
    }

    // Account is active and password matches - set session and redirect to dashboard
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
    req.session.userFirstName = user.userfirstname || '';
    req.session.userLastName = user.userlastname || '';

    // Check if user is a participant (roleid = 2) and needs to complete profile
    if (user.roleid === 2 || user.roleid === '2') {
      const profile = await db('profile')
        .where('userid', user.userid)
        .first();
      
      if (!profile) {
        // Participant without profile - redirect to profile completion
        req.session.tempUserId = user.userid;
        req.session.tempUserEmail = user.useremail;
        req.session.tempUserFirstName = user.userfirstname || '';
        req.session.tempUserLastName = user.userlastname || '';
        return res.redirect('/profile?requireProfile=true');
      }
    }

    // Check for redirect in session (from query parameter)
    const redirect = req.session.loginRedirect;
    if (redirect) {
      delete req.session.loginRedirect;
      return res.redirect(redirect);
    }

    res.redirect(getDefaultRedirect(req.session.userRole));
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', {
      error: 'An error occurred during login. Please try again.',
      success: null,
      showSignUp: false
    });
  }
});

// Home route (protected) - renamed from dashboard
app.get('/home', requireAuth, async (req, res) => {
  try {
    // Redirect donors to donations page
    if (req.session.userRole === 'donor') {
      return res.redirect('/donations');
    }
    
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // For managers, fetch admin dashboard stats
    let activeParticipantsCount = 0;
    let upcomingEventsCount = 0;
    let milestonesAchievedCount = 0;
    let donationsThisMonth = 0;
    let surveyResponseRate = 0;
    let netPromoterScore = 0;

    if (req.session.userRole === 'manager') {
      try {
        // Count active participants: rows in profile table where user has roleid = 2 (participant)
        // Using inner join to only count profiles that exist with participant role
        const activeParticipantsResult = await db('profile as p')
          .innerJoin('users as u', 'p.userid', 'u.userid')
          .where('u.roleid', 2)
          .count('* as count')
          .first();
        // PostgreSQL returns count as string, handle both string and number
        const count = activeParticipantsResult?.count;
        if (count !== undefined && count !== null) {
          activeParticipantsCount = typeof count === 'string' ? parseInt(count, 10) : Number(count);
          if (isNaN(activeParticipantsCount)) activeParticipantsCount = 0;
        }
      } catch (error) {
        console.error('Error counting active participants:', error);
        activeParticipantsCount = 0;
      }

      try {
        // Count upcoming events: sessions where eventdatetimestart > now
        const now = new Date();
        const upcomingEventsResult = await db('session')
          .where('eventdatetimestart', '>', now)
          .count('* as count')
          .first();
        const count = upcomingEventsResult?.count;
        if (count !== undefined && count !== null) {
          upcomingEventsCount = typeof count === 'string' ? parseInt(count, 10) : Number(count);
          if (isNaN(upcomingEventsCount)) upcomingEventsCount = 0;
        }
      } catch (error) {
        console.error('Error counting upcoming events:', error);
        upcomingEventsCount = 0;
      }

      try {
        // Count total milestones achieved: all rows in usermilestone table
        const milestonesResult = await db('usermilestone')
          .count('* as count')
          .first();
        const count = milestonesResult?.count;
        if (count !== undefined && count !== null) {
          milestonesAchievedCount = typeof count === 'string' ? parseInt(count, 10) : Number(count);
          if (isNaN(milestonesAchievedCount)) milestonesAchievedCount = 0;
        }
      } catch (error) {
        console.error('Error counting milestones:', error);
        milestonesAchievedCount = 0;
      }

      try {
        // Calculate donations this month (same logic as donations page)
        const now = new Date();
        const currentMonth = now.getMonth();
        const currentYear = now.getFullYear();
        
        const allDonations = await db('donation')
          .select('donationamount', 'donationdate');
        
        const thisMonthDonationsList = allDonations.filter(d => {
          const donationDate = new Date(d.donationdate);
          return donationDate.getMonth() === currentMonth && donationDate.getFullYear() === currentYear;
        });
        
        donationsThisMonth = thisMonthDonationsList.reduce((sum, d) => sum + parseFloat(d.donationamount || 0), 0);
      } catch (error) {
        console.error('Error calculating donations this month:', error);
        donationsThisMonth = 0;
      }

      try {
        // Calculate survey response rate: % of people who attended and took surveys
        // Count registrations where attended = true AND survey submitted
        const attendedWithSurvey = await db('registration')
          .where('registrationattendedflag', true)
          .whereNotNull('surveynpsbucket')
          .count('* as count')
          .first();
        
        // Count all registrations where attended = true
        const totalAttended = await db('registration')
          .where('registrationattendedflag', true)
          .count('* as count')
          .first();
        
        const attendedWithSurveyCount = attendedWithSurvey?.count ? (typeof attendedWithSurvey.count === 'string' ? parseInt(attendedWithSurvey.count, 10) : Number(attendedWithSurvey.count)) : 0;
        const totalAttendedCount = totalAttended?.count ? (typeof totalAttended.count === 'string' ? parseInt(totalAttended.count, 10) : Number(totalAttended.count)) : 0;
        
        surveyResponseRate = totalAttendedCount > 0 ? ((attendedWithSurveyCount / totalAttendedCount) * 100) : 0;
      } catch (error) {
        console.error('Error calculating survey response rate:', error);
        surveyResponseRate = 0;
      }

      try {
        // Calculate Net Promoter Score (same logic as surveys page)
        // NPS = ((Promoters - Detractors) / Total Responses) * 100
        const allSurveyResponses = await db('registration')
          .whereNotNull('surveynpsbucket')
          .select('surveynpsbucket');
        
        let promoters = 0;
        let detractors = 0;
        const totalResponses = allSurveyResponses.length;
        
        for (const response of allSurveyResponses) {
          if (response.surveynpsbucket === 'Promoter') promoters++;
          else if (response.surveynpsbucket === 'Detractor') detractors++;
        }
        
        netPromoterScore = totalResponses > 0 ? Math.round(((promoters - detractors) / totalResponses) * 100) : 0;
      } catch (error) {
        console.error('Error calculating Net Promoter Score:', error);
        netPromoterScore = 0;
      }
    }

    // For participants, fetch additional data
    let myUpcomingEvents = [];
    let pendingSurveys = [];
    let milestoneCount = 0;
    let mostRecentMilestone = null;

    if (req.session.userRole === 'user') {
      const userId = req.session.userId;
      const now = new Date();

      // Get upcoming registered events (status is null for active registrations, not 'registered')
      const registeredSessions = await db('registration as r')
        .join('session as s', 'r.sessionid', 's.sessionid')
        .join('event as e', 's.eventid', 'e.eventid')
        .join('eventtype as et', 'e.eventtypeid', 'et.eventtypeid')
        .where('r.userid', userId)
        .where(function() {
          this.whereNull('r.registrationstatus')
            .orWhereNot('r.registrationstatus', 'cancelled');
        })
        .where('s.eventdatetimestart', '>', now)
        .select(
          's.sessionid',
          'e.eventname',
          'e.eventdescription',
          's.eventlocation',
          'et.eventtype',
          's.eventdatetimestart',
          's.eventdatetimeend'
        )
        .orderBy('s.eventdatetimestart', 'asc');

      myUpcomingEvents = registeredSessions;

      // Get pending surveys (events attended but no survey submitted)
      pendingSurveys = await db('registration as r')
        .join('session as s', 'r.sessionid', 's.sessionid')
        .join('event as e', 's.eventid', 'e.eventid')
        .where('r.userid', userId)
        .whereNull('r.surveynpsbucket')
        .where('r.registrationattendedflag', true)
        .select(
          's.sessionid',
          'e.eventname',
          's.eventlocation',
          's.eventdatetimestart'
        )
        .orderBy('s.eventdatetimestart', 'desc');

      // Get milestone count and most recent milestone
      const milestones = await db('usermilestone as um')
        .join('milestonetype as mt', 'um.milestoneid', 'mt.milestoneid')
        .where('um.userid', userId)
        .select('mt.milestonetitle', 'um.milestonedate')
        .orderBy('um.milestonedate', 'desc');

      milestoneCount = milestones.length;
      if (milestones.length > 0) {
        mostRecentMilestone = milestones[0];
      }
    }

    // For managers, fetch low registration events and other data
    let lowRegistrationEvents = [];
    let participants = [];
    let milestoneTypes = [];
    let milestonesThisMonth = 0;
    let topMilestonesThisMonth = [];
    if (req.session.userRole === 'manager') {
      try {
        // Get upcoming events with registration counts and capacity
        const now = new Date();
        const upcomingSessions = await db('session as s')
          .join('event as e', 's.eventid', 'e.eventid')
          .where('s.eventdatetimestart', '>', now)
          .select(
            's.sessionid',
            's.eventid',
            's.eventdatetimestart',
            's.eventlocation',
            's.eventcapacity',
            'e.eventname',
            'e.eventdefaultcapacity'
          )
          .orderBy('s.eventdatetimestart', 'asc');

        // Get registration counts for each session (exclude cancelled)
        const sessionIds = upcomingSessions.map(s => s.sessionid);
        let registrationCountsBySessionId = {};
        if (sessionIds.length > 0) {
          const registrationCounts = await db('registration')
            .select('sessionid')
            .count('* as count')
            .whereIn('sessionid', sessionIds)
            .andWhere(function () {
              this.whereNull('registrationstatus')
                .orWhereNot('registrationstatus', 'cancelled');
            })
            .groupBy('sessionid');

          registrationCountsBySessionId = registrationCounts.reduce((acc, row) => {
            const count = row.count;
            acc[row.sessionid] = typeof count === 'string' ? parseInt(count, 10) : (typeof count === 'number' ? count : 0);
            if (isNaN(acc[row.sessionid])) acc[row.sessionid] = 0;
            return acc;
          }, {});
        }

        // Calculate registration percentage and filter for < 30%
        for (const session of upcomingSessions) {
          const registeredCount = registrationCountsBySessionId[session.sessionid] || 0;
          
          // Parse capacity - use session capacity if available, otherwise default capacity
          const capacityValue = session.eventcapacity || session.eventdefaultcapacity || null;
          let capacity = null;
          
          if (capacityValue !== null && capacityValue !== undefined) {
            if (typeof capacityValue === 'number') {
              capacity = capacityValue;
            } else {
              capacity = parseInt(capacityValue, 10);
              if (isNaN(capacity)) {
                capacity = null;
              }
            }
          }
          
          // Only process if we have a valid capacity > 0
          if (capacity !== null && capacity > 0) {
            const registrationPercentage = (registeredCount / capacity) * 100;
            
            // Debug logging
            console.log(`Session ${session.sessionid}: ${session.eventname} - ${registeredCount}/${capacity} = ${registrationPercentage.toFixed(1)}%`);
            
            if (registrationPercentage < 30) {
              lowRegistrationEvents.push({
                sessionid: session.sessionid,
                eventname: session.eventname,
                eventdatetimestart: session.eventdatetimestart,
                eventlocation: session.eventlocation,
                registeredCount: registeredCount,
                capacity: capacity,
                registrationPercentage: registrationPercentage.toFixed(1)
              });
            }
          } else {
            // Debug logging for sessions without capacity
            console.log(`Session ${session.sessionid}: ${session.eventname} - No capacity (eventcapacity: ${session.eventcapacity}, eventdefaultcapacity: ${session.eventdefaultcapacity})`);
          }
        }
      } catch (error) {
        console.error('Error fetching low registration events:', error);
      }

      try {
        // Get all participants (users with roleid = 2)
        const participantsData = await db('users')
          .where('roleid', 2)
          .select('userid', 'userfirstname', 'userlastname', 'useremail')
          .orderBy('userlastname', 'asc')
          .orderBy('userfirstname', 'asc');
        
        participants = participantsData.map(p => ({
          userid: p.userid,
          userfirstname: p.userfirstname || '',
          userlastname: p.userlastname || '',
          useremail: p.useremail
        }));
      } catch (error) {
        console.error('Error fetching participants for home:', error);
      }

      try {
        // Get all milestone types
        milestoneTypes = await db('milestonetype')
          .select('milestoneid', 'milestonetitle')
          .orderBy('milestonetitle');
      } catch (error) {
        console.error('Error fetching milestone types for home:', error);
      }

      try {
        // Get milestones from the past month (last 30 days)
        const now = new Date();
        const oneMonthAgo = new Date(now);
        oneMonthAgo.setDate(oneMonthAgo.getDate() - 30);

        // Count total milestones reached this past month
        const milestonesThisMonthResult = await db('usermilestone')
          .where('milestonedate', '>=', oneMonthAgo.toISOString())
          .where('milestonedate', '<=', now.toISOString())
          .count('* as count')
          .first();
        
        milestonesThisMonth = milestonesThisMonthResult?.count ? parseInt(milestonesThisMonthResult.count, 10) : 0;

        // Get top 3 most reached milestones for this month
        const topMilestones = await db('usermilestone as um')
          .join('milestonetype as mt', 'um.milestoneid', 'mt.milestoneid')
          .where('um.milestonedate', '>=', oneMonthAgo.toISOString())
          .where('um.milestonedate', '<=', now.toISOString())
          .select('mt.milestoneid', 'mt.milestonetitle')
          .count('* as count')
          .groupBy('mt.milestoneid', 'mt.milestonetitle')
          .orderBy('count', 'desc')
          .limit(3);

        topMilestonesThisMonth = topMilestones.map(m => ({
          milestoneid: m.milestoneid,
          milestonetitle: m.milestonetitle,
          count: typeof m.count === 'string' ? parseInt(m.count, 10) : (typeof m.count === 'number' ? m.count : 0)
        }));
      } catch (error) {
        console.error('Error fetching milestones this month:', error);
        milestonesThisMonth = 0;
        topMilestonesThisMonth = [];
      }
    }

    res.render('home', {
      user,
      myUpcomingEvents,
      pendingSurveys,
      milestoneCount,
      mostRecentMilestone,
      activeParticipantsCount,
      upcomingEventsCount,
      milestonesAchievedCount,
      donationsThisMonth,
      surveyResponseRate,
      netPromoterScore,
      participants,
      milestoneTypes,
      lowRegistrationEvents,
      milestonesThisMonth,
      topMilestonesThisMonth
    });
  } catch (error) {
    console.error('Home error:', error);
    res.redirect('/login');
  }
});

// Dashboard route (protected, manager only) - new route for Tableau dashboard
app.get('/dashboard', requireAuth, async (req, res) => {
  try {
    // Only managers can access the dashboard
    if (req.session.userRole !== 'manager') {
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }

    res.render('dashboard', {
      user: {
        email: req.session.userEmail,
        role: req.session.userRole,
        firstName: req.session.userFirstName || '',
        lastName: req.session.userLastName || ''
      }
    });
  } catch (error) {
    console.error('Dashboard error:', error);
    res.redirect('/login');
  }
});

// Participants route (protected, manager only)
app.get('/participants', requireAuth, restrictDonor, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }

    // Query all participants (users with roleid = 2) with LEFT JOIN to profile table
    const participantsData = await db('users as u')
      .leftJoin('profile as p', 'u.userid', 'p.userid')
      .where('u.roleid', 2)
      .select(
        'u.userid',
        'u.useremail',
        'u.userfirstname',
        'u.userlastname',
        'u.accountactive',
        'p.profiledob',
        'p.profilephone',
        'p.profilecity',
        'p.profilestate',
        'p.profilezip',
        'p.profileschooloremployer',
        'p.profilefieldofinterest'
      )
      .orderBy('u.userlastname', 'asc')
      .orderBy('u.userfirstname', 'asc');

    // Map participants data
    const participants = participantsData.map(p => ({
      userid: p.userid,
      email: p.useremail,
      firstName: p.userfirstname || '',
      lastName: p.userlastname || '',
      fullName: `${p.userfirstname || ''} ${p.userlastname || ''}`.trim() || 'No Name',
      accountActive: p.accountactive,
      profileDOB: p.profiledob,
      profilePhone: p.profilephone,
      profileCity: p.profilecity,
      profileState: p.profilestate,
      profileZip: p.profilezip,
      profileSchoolOrEmployer: p.profileschooloremployer,
      profileFieldOfInterest: p.profilefieldofinterest
    }));

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    res.render('participants', { user, participants, query: req.query });
  } catch (error) {
    console.error('Participants error:', error);
    res.redirect('/login');
  }
});

// Admin View Participant route - GET (protected, manager only)
app.get('/participants/view/:userid', requireAuth, restrictDonor, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }

    const userId = parseInt(req.params.userid);
    if (isNaN(userId)) {
      return res.redirect('/participants?error=invalid_user_id');
    }

    // Fetch participant user data
    const userData = await db('users')
      .where('userid', userId)
      .first();

    if (!userData) {
      return res.redirect('/participants?error=participant_not_found');
    }

    // Verify user is a participant (roleid = 2)
    if (userData.roleid !== 2) {
      return res.redirect('/participants?error=not_participant');
    }

    // Fetch profile data
    const profileData = await db('profile')
      .where('userid', userId)
      .first();

    // Get all milestone types for the add milestone modal
    const milestoneTypes = await db('milestonetype')
      .select('milestoneid', 'milestonetitle')
      .orderBy('milestonetitle');

    // Get all participants for the add milestone modal (though we'll pre-select this one)
    const participants = await db('users')
      .where('roleid', 2)
      .select('userid', 'userfirstname', 'userlastname', 'useremail')
      .orderBy('userlastname', 'asc')
      .orderBy('userfirstname', 'asc');

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    res.render('admin-view-participant', { user, participant: userData, profileData, milestoneTypes, participants, query: req.query });
  } catch (error) {
    console.error('View participant page error:', error);
    res.redirect('/participants?error=page_error');
  }
});

// Admin Edit Participant route - GET (protected, manager only)
app.get('/participants/edit/:userid', requireAuth, restrictDonor, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }

    const userId = parseInt(req.params.userid);
    if (isNaN(userId)) {
      return res.redirect('/participants?error=invalid_user_id');
    }

    // Fetch participant user data
    const userData = await db('users')
      .where('userid', userId)
      .first();

    if (!userData) {
      return res.redirect('/participants?error=participant_not_found');
    }

    // Verify user is a participant (roleid = 2)
    if (userData.roleid !== 2) {
      return res.redirect('/participants?error=not_participant');
    }

    // Fetch profile data
    const profileData = await db('profile')
      .where('userid', userId)
      .first();

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    res.render('admin-edit-participant', { user, participant: userData, profileData, query: req.query });
  } catch (error) {
    console.error('Edit participant page error:', error);
    res.redirect('/participants?error=page_error');
  }
});

// Admin Update Participant route - POST (protected, manager only)
app.post('/participants/edit/:userid', requireAuth, restrictDonor, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const userId = parseInt(req.params.userid);
    if (isNaN(userId)) {
      return res.redirect('/participants?error=invalid_user_id');
    }

    // Verify user exists and is a participant
    const userData = await db('users')
      .where('userid', userId)
      .first();

    if (!userData) {
      return res.redirect('/participants?error=participant_not_found');
    }

    if (userData.roleid !== 2) {
      return res.redirect('/participants?error=not_participant');
    }

    const {
      profiledob,
      dob_month,
      dob_day,
      dob_year,
      profilephone,
      profilecity,
      profilestate,
      profilezip,
      profileschooloremployer,
      profilefieldofinterest
    } = req.body;

    // Combine date fields into YYYY-MM-DD format
    let dateOfBirth = null;
    if (dob_month && dob_day && dob_year) {
      const year = parseInt(dob_year);
      const month = parseInt(dob_month);
      const day = parseInt(dob_day);
      
      if (year < 1900 || year > new Date().getFullYear() || month < 1 || month > 12 || day < 1 || day > 31) {
        return res.redirect(`/participants/edit/${userId}?error=invalid_date`);
      }
      
      const dateObj = new Date(Date.UTC(year, month - 1, day));
      if (dateObj.getUTCFullYear() !== year || 
          dateObj.getUTCMonth() + 1 !== month || 
          dateObj.getUTCDate() !== day) {
        return res.redirect(`/participants/edit/${userId}?error=invalid_date`);
      }
      
      dateOfBirth = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
    } else if (profiledob) {
      dateOfBirth = profiledob;
    }

    // Validate required fields
    if (!dateOfBirth || !profilephone || !profilecity || !profilestate || !profilezip || 
        !profileschooloremployer || !profilefieldofinterest) {
      return res.redirect(`/participants/edit/${userId}?error=missing_fields`);
    }

    // Clean phone number
    const cleanPhone = profilephone.replace(/\D/g, '');

    // Check if profile exists
    const existingProfile = await db('profile')
      .where('userid', userId)
      .first();

    if (existingProfile) {
      // Update existing profile
      await db('profile')
        .where('userid', userId)
        .update({
          profiledob: dateOfBirth,
          profilephone: cleanPhone,
          profilecity: profilecity.trim(),
          profilestate: profilestate.trim(),
          profilezip: profilezip.trim(),
          profileschooloremployer: profileschooloremployer.trim(),
          profilefieldofinterest: profilefieldofinterest.trim()
        });
    } else {
      // Insert new profile
      await db('profile')
        .insert({
          userid: userId,
          profiledob: dateOfBirth,
          profilephone: cleanPhone,
          profilecity: profilecity.trim(),
          profilestate: profilestate.trim(),
          profilezip: profilezip.trim(),
          profileschooloremployer: profileschooloremployer.trim(),
          profilefieldofinterest: profilefieldofinterest.trim()
        });
    }

    res.redirect('/participants?success=participant_updated');
  } catch (error) {
    console.error('Update participant error:', error);
    res.redirect('/participants?error=update_failed');
  }
});

// Admin Delete Participant route - POST (protected, manager only)
app.post('/participants/delete', requireAuth, restrictDonor, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const { userid } = req.body;
    const userId = parseInt(userid);

    if (!userid || isNaN(userId)) {
      return res.status(400).send('Invalid request');
    }

    // Fetch user to verify they exist and are a participant
    const userData = await db('users')
      .where('userid', userId)
      .first();

    if (!userData) {
      return res.redirect('/participants?error=participant_not_found');
    }

    // Don't allow deleting yourself
    if (userId === req.session.userId) {
      return res.redirect('/participants?error=cannot_delete_yourself');
    }

    // Verify user is a participant (roleid = 2)
    if (userData.roleid !== 2) {
      return res.redirect('/participants?error=not_participant');
    }

    // Cascade delete: Delete from Users table - database handles cascade deletion of Profile, Registration, etc.
    await db('users')
      .where('userid', userId)
      .del();

    res.redirect('/participants?success=participant_deleted');
  } catch (error) {
    console.error('Delete participant error:', error);
    res.redirect('/participants?error=delete_failed');
  }
});

// User Profile route (protected) - for viewing/editing own profile
app.get('/profile', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    if (!userId) {
      return res.redirect('/login');
    }

    // Check if user is in signup/temp session (for profile completion during signup)
    if (req.session.tempUserId) {
      // Render profile completion form
      return res.render('profile', { 
        error: null,
        user: {
          email: req.session.tempUserEmail,
          firstName: req.session.tempUserFirstName,
          lastName: req.session.tempUserLastName
        }
      });
    }

    // Get user data from users table
    const dbUser = await db('users')
      .where('userid', userId)
      .first();

    if (!dbUser) {
      return res.redirect('/login');
    }

    const userRole = req.session.userRole;
    const isParticipant = dbUser.roleid === 2 || dbUser.roleid === '2';
    const isDonor = dbUser.roleid === 3 || dbUser.roleid === '3';
    
    // Get profile data if user is a participant
    let profileData = null;
    if (isParticipant) {
      profileData = await db('profile')
        .where('userid', userId)
        .first();
    }

    // Check if profile is required and missing
    const requireProfile = req.query.requireProfile === 'true';
    if (requireProfile && isParticipant && !profileData) {
      // Redirect to profile completion form
      req.session.tempUserId = userId;
      req.session.tempUserEmail = dbUser.useremail;
      req.session.tempUserFirstName = dbUser.userfirstname || '';
      req.session.tempUserLastName = dbUser.userlastname || '';
      return res.render('profile', { 
        error: null,
        user: {
          email: dbUser.useremail,
          firstName: dbUser.userfirstname || '',
          lastName: dbUser.userlastname || ''
        },
        requireProfile: true
      });
    }

    // Determine active tab (default to 'profile' for participants, 'account' for donors)
    const activeTab = req.query.tab || (isParticipant ? 'profile' : 'account');

    const user = {
      email: req.session.userEmail,
      role: userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    res.render('user-profile', {
      user,
      dbUser,
      profileData,
      activeTab,
      isParticipant,
      isDonor,
      requireProfile,
      query: req.query
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.redirect('/login');
  }
});

// Profile Edit Route - GET
app.get('/profile/edit', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const editType = req.query.type; // 'profile' or 'account'
    
    if (!userId) {
      return res.redirect('/login');
    }

    if (!editType || (editType !== 'profile' && editType !== 'account')) {
      return res.redirect('/profile?error=invalid_type');
    }

    // Get user data
    const dbUser = await db('users')
      .where('userid', userId)
      .first();

    if (!dbUser) {
      return res.redirect('/login');
    }

    const isParticipant = dbUser.roleid === 2 || dbUser.roleid === '2';
    const isDonor = dbUser.roleid === 3 || dbUser.roleid === '3';

    // If trying to edit profile but not a participant, redirect
    if (editType === 'profile' && !isParticipant) {
      return res.redirect('/profile?error=not_participant');
    }

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    if (editType === 'profile') {
      // Get profile data
      const profileData = await db('profile')
        .where('userid', userId)
        .first();

      res.render('profile-edit-profile', {
        user,
        profileData,
        dbUser,
        query: req.query
      });
    } else {
      // Account edit
      res.render('profile-edit-account', {
        user,
        dbUser,
        query: req.query
      });
    }
  } catch (error) {
    console.error('Profile edit error:', error);
    res.redirect('/profile?error=edit_failed');
  }
});

// Profile Edit Route - POST
app.post('/profile/edit', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const editType = req.query.type || req.body.type; // 'profile' or 'account'
    
    if (!userId) {
      return res.redirect('/login');
    }

    if (!editType || (editType !== 'profile' && editType !== 'account')) {
      return res.redirect('/profile?error=invalid_type');
    }

    // Get user data to verify role
    const dbUser = await db('users')
      .where('userid', userId)
      .first();

    if (!dbUser) {
      return res.redirect('/login');
    }

    const isParticipant = dbUser.roleid === 2 || dbUser.roleid === '2';

    if (editType === 'profile') {
      // Update profile data
      if (!isParticipant) {
        return res.redirect('/profile?error=not_participant');
      }

      const {
        profiledob,
        dob_month,
        dob_day,
        dob_year,
        profilephone,
        profilecity,
        profilestate,
        profilezip,
        profileschooloremployer,
        profilefieldofinterest
      } = req.body;

      // Combine date fields into YYYY-MM-DD format
      let dateOfBirth = null;
      if (dob_month && dob_day && dob_year) {
        const year = parseInt(dob_year);
        const month = parseInt(dob_month);
        const day = parseInt(dob_day);
        
        if (year < 1900 || year > new Date().getFullYear() || month < 1 || month > 12 || day < 1 || day > 31) {
          return res.redirect('/profile/edit?type=profile&error=invalid_date');
        }
        
        const dateObj = new Date(Date.UTC(year, month - 1, day));
        if (dateObj.getUTCFullYear() !== year || 
            dateObj.getUTCMonth() + 1 !== month || 
            dateObj.getUTCDate() !== day) {
          return res.redirect('/profile/edit?type=profile&error=invalid_date');
        }
        
        dateOfBirth = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      } else if (profiledob) {
        dateOfBirth = profiledob;
      }

      // Validate required fields
      if (!dateOfBirth || !profilephone || !profilecity || !profilestate || !profilezip || 
          !profileschooloremployer || !profilefieldofinterest) {
        return res.redirect('/profile/edit?type=profile&error=missing_fields');
      }

      // Clean phone number
      const cleanPhone = profilephone.replace(/\D/g, '');

      // Check if profile exists
      const existingProfile = await db('profile')
        .where('userid', userId)
        .first();

      if (existingProfile) {
        // Update existing profile
        await db('profile')
          .where('userid', userId)
          .update({
            profiledob: dateOfBirth,
            profilephone: cleanPhone,
            profilecity: profilecity.trim(),
            profilestate: profilestate.trim(),
            profilezip: profilezip.trim(),
            profileschooloremployer: profileschooloremployer.trim(),
            profilefieldofinterest: profilefieldofinterest.trim()
          });
      } else {
        // Insert new profile
        await db('profile')
          .insert({
            userid: userId,
            profiledob: dateOfBirth,
            profilephone: cleanPhone,
            profilecity: profilecity.trim(),
            profilestate: profilestate.trim(),
            profilezip: profilezip.trim(),
            profileschooloremployer: profileschooloremployer.trim(),
            profilefieldofinterest: profilefieldofinterest.trim()
          });
      }

      return res.redirect('/profile?tab=profile&success=true');
    } else {
      // Update account data
      const { useremail, userfirstname, userlastname, newPassword, confirmNewPassword } = req.body;

      if (!useremail || !userfirstname || !userlastname) {
        return res.redirect('/profile/edit?type=account&error=missing_fields');
      }

      // Validate password if provided
      if (newPassword || confirmNewPassword) {
        if (!newPassword || !confirmNewPassword) {
          return res.redirect('/profile/edit?type=account&error=password_missing');
        }
        if (newPassword.length < 6) {
          return res.redirect('/profile/edit?type=account&error=password_too_short');
        }
        if (newPassword !== confirmNewPassword) {
          return res.redirect('/profile/edit?type=account&error=password_mismatch');
        }
      }

      // Check if email is already taken by another user
      const emailExists = await db('users')
        .where('useremail', useremail.toLowerCase())
        .where('userid', '!=', userId)
        .first();

      if (emailExists) {
        return res.redirect('/profile/edit?type=account&error=email_taken');
      }

      // Prepare update data
      const updateData = {
        useremail: useremail.toLowerCase().trim(),
        userfirstname: userfirstname.trim(),
        userlastname: userlastname.trim()
      };

      // Hash and update password if provided
      if (newPassword && newPassword.length >= 6) {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        updateData.userpassword = hashedPassword;
      }

      // Update user data
      await db('users')
        .where('userid', userId)
        .update(updateData);

      // Update session
      req.session.userEmail = useremail.toLowerCase().trim();
      req.session.userFirstName = userfirstname.trim();
      req.session.userLastName = userlastname.trim();

      return res.redirect('/profile?tab=account&success=true');
    }
  } catch (error) {
    console.error('Profile edit error:', error);
    res.redirect('/profile?error=edit_failed');
  }
});

// Convert Donor to Participant Route
app.post('/profile/convert-to-participant', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    
    if (!userId) {
      return res.redirect('/login');
    }

    // Get user data
    const dbUser = await db('users')
      .where('userid', userId)
      .first();

    if (!dbUser) {
      return res.redirect('/login');
    }

    // Verify user is a donor
    const isDonor = dbUser.roleid === 3 || dbUser.roleid === '3';
    if (!isDonor) {
      return res.redirect('/profile?error=not_donor');
    }

    // Update role to participant (roleid = 2)
    await db('users')
      .where('userid', userId)
      .update({
        roleid: 2
      });

    // Update session
    req.session.userRole = 'user';

    // Check if profile exists
    const existingProfile = await db('profile')
      .where('userid', userId)
      .first();

    if (!existingProfile) {
      // Redirect to profile completion page (reuse signup profile form)
      // Set temp session variables to reuse the profile completion flow
      req.session.tempUserId = userId;
      req.session.tempUserEmail = dbUser.useremail;
      req.session.tempUserFirstName = dbUser.userfirstname || '';
      req.session.tempUserLastName = dbUser.userlastname || '';
      return res.redirect('/profile/complete');
    } else {
      // Profile exists, just redirect to profile page
      return res.redirect('/profile?tab=profile&success=true');
    }
  } catch (error) {
    console.error('Convert to participant error:', error);
    res.redirect('/profile?error=conversion_failed');
  }
});

// Events route (protected, no donor access)
app.get('/events', requireAuth, restrictDonor, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    const userId = req.session.userId;
    const isManager = req.session.userRole === 'manager';

    // Query all sessions with JOINs to event and eventtype tables
    const allSessions = await db('session as s')
      .join('event as e', 's.eventid', 'e.eventid')
      .join('eventtype as et', 'e.eventtypeid', 'et.eventtypeid')
      .select(
        's.sessionid',
        's.eventid',
        's.eventdatetimestart',
        's.eventlocation',
        's.eventdatetimeend',
        's.eventcapacity',
        's.eventregistrationdeadline',
        'e.eventname',
        'e.eventdescription',
        'e.eventrecurrencepattern',
        'e.eventdefaultcapacity',
        'et.eventtype'
      )
      .orderBy('s.eventdatetimestart', 'asc');

    const now = new Date();

    // Pre-compute active registration counts per session (exclude cancelled)
    const sessionIds = allSessions.map(s => s.sessionid);
    let registrationCountsBySessionId = {};
    if (sessionIds.length > 0) {
      const registrationCounts = await db('registration')
        .select('sessionid')
        .count('* as count')
        .whereIn('sessionid', sessionIds)
        .andWhere(function () {
          this.whereNull('registrationstatus')
            .orWhereNot('registrationstatus', 'cancelled');
        })
        .groupBy('sessionid');

      registrationCountsBySessionId = registrationCounts.reduce((acc, row) => {
        acc[row.sessionid] = parseInt(row.count, 10) || 0;
        return acc;
      }, {});
    }

    // Build distinct event types and recurrence patterns for filters (admin view)
    const eventTypesSet = new Set();
    const recurrenceSet = new Set();
    allSessions.forEach(session => {
      if (session.eventtype) {
        eventTypesSet.add(session.eventtype);
      }
      if (session.eventrecurrencepattern) {
        recurrenceSet.add(session.eventrecurrencepattern);
      }
    });
    const eventTypes = Array.from(eventTypesSet).sort();
    const recurrencePatterns = Array.from(recurrenceSet).sort();

    let currentSessions = [];
    let pastSessions = [];

    // Participant view needs registration data
    let activeRegistrationsBySessionId = {};
    let cancelledRegistrations = [];

    if (!isManager) {
      // Get ALL registrations for this participant
      const registrations = await db('registration as r')
        .join('session as s', 'r.sessionid', 's.sessionid')
        .join('event as e', 's.eventid', 'e.eventid')
        .join('eventtype as et', 'e.eventtypeid', 'et.eventtypeid')
        .where('r.userid', userId)
        .select(
          'r.sessionid',
          'r.registrationstatus',
          'r.registrationcreatedat',
          's.eventdatetimeend',
          's.eventdatetimestart',
          's.eventlocation',
          's.eventcapacity',
          's.eventregistrationdeadline',
          'e.eventid',
          'e.eventname',
          'e.eventdescription',
          'e.eventrecurrencepattern',
          'e.eventdefaultcapacity',
          'et.eventtype'
        )
        .orderBy('r.registrationcreatedat', 'desc');

      // Process registrations
      for (const reg of registrations) {
        const endDate = new Date(reg.eventdatetimeend);
        
        // Default no-show after event end if status is still null
        if (!reg.registrationstatus && endDate < now) {
          try {
            await db('registration')
              .where('userid', userId)
              .andWhere('sessionid', reg.sessionid)
              .andWhere('registrationcreatedat', reg.registrationcreatedat)
              .andWhereNull('registrationstatus')
              .update({ registrationstatus: 'no-show' });
            reg.registrationstatus = 'no-show';
          } catch (updateError) {
            console.error('Failed to default registrationstatus to no-show', updateError);
          }
        }

        // Separate cancelled registrations (show in past events immediately)
        if (reg.registrationstatus === 'cancelled') {
          cancelledRegistrations.push(reg);
        } else {
          // Track active registrations by session (only the most recent active one)
          if (!activeRegistrationsBySessionId[reg.sessionid]) {
            activeRegistrationsBySessionId[reg.sessionid] = {
              registrationstatus: reg.registrationstatus,
              registrationcreatedat: reg.registrationcreatedat
            };
          }
        }
      }
    }

    // Separate sessions into current (upcoming) and past
    // Events move to past 3 hours after event end time
    allSessions.forEach(session => {
      const endDate = new Date(session.eventdatetimeend);
      const threeHoursAfterEnd = new Date(endDate.getTime() + 3 * 60 * 60 * 1000);

      // For participant past events, only show sessions they have ACTIVE registrations for
      if (!isManager && threeHoursAfterEnd < now) {
        if (activeRegistrationsBySessionId[session.sessionid]) {
          pastSessions.push(session);
        }
      } else if (threeHoursAfterEnd < now) {
        pastSessions.push(session);
      } else {
        currentSessions.push(session);
      }
    });

    // Attach registration, deadline, and capacity state to sessions for participant view
    if (!isManager) {
      const deadlinePassed = (deadline) => {
        if (!deadline) return false;
        const d = new Date(deadline);
        return d < now;
      };

      const decorate = (list) =>
        list.map(session => {
          const reg = activeRegistrationsBySessionId[session.sessionid];
          const activeRegistration = reg || null;

          const capacityRaw = session.eventcapacity || session.eventdefaultcapacity;
          const capacity =
            typeof capacityRaw === 'number'
              ? capacityRaw
              : capacityRaw
              ? parseInt(capacityRaw, 10)
              : null;

          const currentRegCount = registrationCountsBySessionId[session.sessionid] || 0;
          const isFull = capacity !== null && !Number.isNaN(capacity) && currentRegCount >= capacity;

          return {
            ...session,
            isRegistered: !!activeRegistration,
            registrationStatus: activeRegistration ? activeRegistration.registrationstatus : null,
            registrationDeadlinePassed: deadlinePassed(session.eventregistrationdeadline),
            currentRegistrationCount: currentRegCount,
            isFull
          };
        });

      currentSessions = decorate(currentSessions);
      pastSessions = decorate(pastSessions);

      // Add cancelled registrations to past events with their session data
      cancelledRegistrations.forEach(reg => {
        const capacityRaw = reg.eventcapacity || reg.eventdefaultcapacity;
        const capacity =
          typeof capacityRaw === 'number'
            ? capacityRaw
            : capacityRaw
            ? parseInt(capacityRaw, 10)
            : null;

        const currentRegCount = registrationCountsBySessionId[reg.sessionid] || 0;
        const isFull = capacity !== null && !Number.isNaN(capacity) && currentRegCount >= capacity;

        pastSessions.push({
          sessionid: reg.sessionid,
          eventid: reg.eventid,
          eventdatetimestart: reg.eventdatetimestart,
          eventdatetimeend: reg.eventdatetimeend,
          eventlocation: reg.eventlocation,
          eventcapacity: reg.eventcapacity,
          eventregistrationdeadline: reg.eventregistrationdeadline,
          eventname: reg.eventname,
          eventdescription: reg.eventdescription,
          eventrecurrencepattern: reg.eventrecurrencepattern,
          eventdefaultcapacity: reg.eventdefaultcapacity,
          eventtype: reg.eventtype,
          isRegistered: true,
          registrationStatus: 'cancelled',
          registrationCreatedAt: reg.registrationcreatedat,
          registrationDeadlinePassed: deadlinePassed(reg.eventregistrationdeadline),
          currentRegistrationCount: currentRegCount,
          isFull,
          isCancelledRecord: true
        });
      });

      // Sort past sessions by event date (oldest first)
      pastSessions.sort((a, b) => {
        const aEnd = a.eventdatetimeend ? new Date(a.eventdatetimeend) : new Date(a.eventdatetimestart);
        const bEnd = b.eventdatetimeend ? new Date(b.eventdatetimeend) : new Date(b.eventdatetimestart);
        return aEnd - bEnd;
      });
    }

    // Get search query parameter
    const searchQuery = req.query.search || '';

    res.render('events', { 
      user,
      currentSessions,
      pastSessions,
      searchQuery,
      eventTypes,
      recurrencePatterns,
      query: req.query
    });
  } catch (error) {
    console.error('Events error:', error);
    res.redirect('/login');
  }
});

// Create Event Route - GET (manager only)
app.get('/events/create', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect('/events');
    }

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Fetch all events for dropdown
    const events = await db('event')
      .select('eventid', 'eventname', 'eventdescription', 'eventdefaultcapacity')
      .orderBy('eventname');

    const selectedEventId = req.query.selectedEventId || null;

    res.render('event-create', { user, events, query: req.query, selectedEventId });
  } catch (error) {
    console.error('Create event error:', error);
    res.redirect('/events');
  }
});

// New Event Definition Routes (manager only)
app.get('/events/new', requireAuth, async (req, res) => {
  try {
    if (req.session.userRole !== 'manager') {
      return res.redirect('/events');
    }

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Fetch existing event types (categories)
    const eventTypes = await db('eventtype')
      .select('eventtypeid', 'eventtype')
      .orderBy('eventtype');

    const returnTo = req.query.returnTo || '/events/create';

    res.render('event-new', { user, eventTypes, query: req.query, returnTo });
  } catch (error) {
    console.error('New event GET error:', error);
    res.redirect('/events/create?error=new_event_failed');
  }
});

app.post('/events/new', requireAuth, async (req, res) => {
  try {
    if (req.session.userRole !== 'manager') {
      return res.redirect('/events');
    }

    let { eventtypeid, neweventtype, eventname, eventdescription, eventrecurrencepattern, eventdefaultcapacity, returnTo } = req.body;

    if (!eventname) {
      return res.redirect('/events/new?error=missing_name');
    }

    // Handle creating a new event type if needed
    let finalEventTypeId = eventtypeid && eventtypeid !== '__new_type' ? parseInt(eventtypeid) : null;

    if (!finalEventTypeId) {
      if (!neweventtype || !neweventtype.trim()) {
        return res.redirect('/events/new?error=missing_event_type');
      }

      // Ensure eventtypeid sequence is in sync
      try {
        await db.raw(`SELECT setval(
          pg_get_serial_sequence('eventtype', 'eventtypeid'),
          GREATEST(COALESCE((SELECT MAX("eventtypeid") + 1 FROM "eventtype"), 1), 1),
          false
        )`);
      } catch (seqError) {
        console.error('Warning: failed to sync eventtypeid sequence', seqError);
      }

      const insertedType = await db('eventtype')
        .insert({ eventtype: neweventtype.trim() })
        .returning('eventtypeid');

      finalEventTypeId = insertedType && insertedType[0].eventtypeid
        ? insertedType[0].eventtypeid
        : insertedType[0];
    }

    // Parse default capacity
    let defaultCapacity = null;
    if (eventdefaultcapacity && eventdefaultcapacity.trim() !== '') {
      defaultCapacity = parseInt(eventdefaultcapacity);
    }

    // Ensure eventid sequence is in sync
    try {
      await db.raw(`SELECT setval(
        pg_get_serial_sequence('event', 'eventid'),
        GREATEST(COALESCE((SELECT MAX("eventid") + 1 FROM "event"), 1), 1),
        false
      )`);
    } catch (seqError) {
      console.error('Warning: failed to sync eventid sequence', seqError);
    }

    // Insert new event definition
    const insertedEvent = await db('event')
      .insert({
        eventtypeid: finalEventTypeId,
        eventname: eventname.trim(),
        eventdescription: eventdescription || null,
        eventrecurrencepattern: eventrecurrencepattern || null,
        eventdefaultcapacity: defaultCapacity
      })
      .returning('eventid');

    const newEventId = insertedEvent && insertedEvent[0].eventid
      ? insertedEvent[0].eventid
      : insertedEvent[0];

    const target = returnTo || '/events/create';
    const separator = target.includes('?') ? '&' : '?';
    res.redirect(`${target}${separator}selectedEventId=${newEventId}`);
  } catch (error) {
    console.error('New event POST error:', error);
    res.redirect('/events/new?error=create_failed');
  }
});

// Create Event Route - POST (manager only)
app.post('/events/create', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect('/events');
    }

    const { eventid, eventdatetimestart, eventlocation, eventdatetimeend, eventcapacity, eventregistrationdeadline } = req.body;

    // Validate required fields
    if (!eventid || !eventdatetimestart || !eventlocation || !eventdatetimeend) {
      return res.redirect('/events/create?error=missing_fields');
    }

    // Parse dates
    let startDateTime, endDateTime, regDeadline = null;
    try {
      startDateTime = new Date(eventdatetimestart);
      endDateTime = new Date(eventdatetimeend);
      if (eventregistrationdeadline) {
        regDeadline = new Date(eventregistrationdeadline);
      }
    } catch (error) {
      return res.redirect('/events/create?error=invalid_date');
    }

    // Validate dates
    if (isNaN(startDateTime.getTime()) || isNaN(endDateTime.getTime())) {
      return res.redirect('/events/create?error=invalid_date');
    }

    if (regDeadline && isNaN(regDeadline.getTime())) {
      return res.redirect('/events/create?error=invalid_date');
    }

    // Validate start date is before end date
    if (startDateTime >= endDateTime) {
      return res.redirect('/events/create?error=start_after_end');
    }

    // Validate registration deadline is not after end date (if provided)
    if (regDeadline && regDeadline > endDateTime) {
      return res.redirect('/events/create?error=deadline_after_end');
    }

    // If EventCapacity is empty, fetch EventDefaultCapacity from Event table
    let finalCapacity = null;
    if (eventcapacity && eventcapacity.trim() !== '') {
      finalCapacity = parseInt(eventcapacity);
    } else {
      const event = await db('event')
        .where('eventid', eventid)
        .first();
      if (event && event.eventdefaultcapacity) {
        finalCapacity = event.eventdefaultcapacity;
      }
    }

    // Ensure sessionid sequence is in sync to avoid duplicate key errors
    try {
      await db.raw(`SELECT setval(
        pg_get_serial_sequence('session', 'sessionid'),
        GREATEST(COALESCE((SELECT MAX("sessionid") + 1 FROM "session"), 1), 1),
        false
      )`);
    } catch (seqError) {
      console.error('Warning: failed to sync sessionid sequence', seqError);
    }

    // Insert new session record
    const inserted = await db('session')
      .insert({
        eventid: parseInt(eventid),
        eventdatetimestart: startDateTime,
        eventlocation: eventlocation.trim(),
        eventdatetimeend: endDateTime,
        eventcapacity: finalCapacity,
        eventregistrationdeadline: regDeadline
      })
      .returning('sessionid');

    // Redirect to event details page
    if (inserted && inserted.length > 0 && inserted[0].sessionid) {
      res.redirect(`/events/${inserted[0].sessionid}?success=true`);
    } else {
      // Fallback: query the last inserted session
      const newSession = await db('session')
        .where('eventid', parseInt(eventid))
        .where('eventdatetimestart', startDateTime)
        .orderBy('sessionid', 'desc')
        .first();
      if (newSession) {
        res.redirect(`/events/${newSession.sessionid}?success=true`);
      } else {
        res.redirect('/events?error=create_failed');
      }
    }
  } catch (error) {
    console.error('Create event POST error:', error);
    res.redirect('/events/create?error=create_failed');
  }
});

// Event Details Route - GET (manager and participant)
app.get('/events/:sessionId', requireAuth, async (req, res) => {
  try {
    const userRole = req.session.userRole;

    // Donors should not access event details
    if (userRole === 'donor') {
      return res.redirect('/donations');
    }

    const sessionId = parseInt(req.params.sessionId);
    if (isNaN(sessionId)) {
      return res.redirect('/events');
    }

    const user = {
      email: req.session.userEmail,
      role: userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Fetch session with JOINs to event and eventtype tables
    const session = await db('session as s')
      .join('event as e', 's.eventid', 'e.eventid')
      .join('eventtype as et', 'e.eventtypeid', 'et.eventtypeid')
      .where('s.sessionid', sessionId)
      .select(
        's.sessionid',
        's.eventid',
        's.eventdatetimestart',
        's.eventlocation',
        's.eventdatetimeend',
        's.eventcapacity',
        's.eventregistrationdeadline',
        'e.eventname',
        'e.eventdescription',
        'e.eventrecurrencepattern',
        'e.eventdefaultcapacity',
        'et.eventtype'
      )
      .first();

    if (!session) {
      return res.redirect('/events');
    }

    // Determine capacity (use session capacity if available, otherwise default)
    const capacityValue = session.eventcapacity || session.eventdefaultcapacity || null;
    const capacity =
      typeof capacityValue === 'number'
        ? capacityValue
        : capacityValue
        ? parseInt(capacityValue, 10)
        : 'N/A';

    // Flag: has this event session ended?
    const eventEnded = session.eventdatetimeend
      ? new Date(session.eventdatetimeend) < new Date()
      : false;

    // Participant registration state
    let isRegistered = false;
    let registrationStatus = null;
    let registrationDeadlinePassed = false;
    let currentRegistrationCount = 0;
    let isFull = false;

    const now = new Date();
    if (session.eventregistrationdeadline) {
      const deadline = new Date(session.eventregistrationdeadline);
      registrationDeadlinePassed = deadline < now;
    }

    // Compute active registration count for this session (exclude cancelled)
    const registrationCountRow = await db('registration')
      .where('sessionid', sessionId)
      .andWhere(function () {
        this.whereNull('registrationstatus')
          .orWhereNot('registrationstatus', 'cancelled');
      })
      .count('* as count')
      .first();

    currentRegistrationCount = registrationCountRow ? parseInt(registrationCountRow.count, 10) || 0 : 0;

    if (typeof capacity === 'number' && !Number.isNaN(capacity)) {
      isFull = currentRegistrationCount >= capacity;
    }

    if (userRole === 'user') {
      const userId = req.session.userId;
      const reg = await db('registration')
        .where('userid', userId)
        .andWhere('sessionid', sessionId)
        .first();

      if (reg) {
        isRegistered = true;
        registrationStatus = reg.registrationstatus;
      }
    }

    // Event statistics (only computed after event ends)
    let metricAverages = [];
    let overallSurveyAverage = null;
    let attendeeCount = 0;
    let attendanceRate = null;

    if (eventEnded) {
      // Average score per survey question
      const metricRows = await db('survey as sv')
        .join('surveymetric as sm', 'sv.metricid', 'sm.metricid')
        .whereNotNull('sv.surveyscore')
        .where('sv.sessionid', sessionId)
        .groupBy('sv.metricid', 'sm.surveymetric', 'sm.metricquestion')
        .select(
          'sv.metricid',
          'sm.surveymetric as metricName',
          'sm.metricquestion as metricQuestion',
          db.raw('AVG(sv.surveyscore) as averageScore')
        );

      metricAverages = metricRows.map(row => ({
        metricId: row.metricid,
        metricName: row.metricName,
        metricQuestion: row.metricQuestion,
        averageScore:
          row.averageScore !== null && row.averageScore !== undefined
            ? Number.parseFloat(row.averageScore).toFixed(1)
            : null
      }));

      // Overall survey score average
      const overallRow = await db('registration')
        .where('sessionid', sessionId)
        .whereNotNull('overallsurveyscore')
        .avg({ avgOverall: 'overallsurveyscore' })
        .first();

      overallSurveyAverage =
        overallRow && overallRow.avgOverall !== null && overallRow.avgOverall !== undefined
          ? Number.parseFloat(overallRow.avgOverall).toFixed(1)
          : null;

      // Attendee count
      const attendeeRow = await db('registration')
        .where('sessionid', sessionId)
        .andWhere('registrationstatus', 'attended')
        .andWhere('registrationattendedflag', true)
        .count('* as count')
        .first();

      attendeeCount = attendeeRow ? parseInt(attendeeRow.count, 10) || 0 : 0;

      // Attendance percentage relative to registered (exclude cancelled)
      attendanceRate =
        currentRegistrationCount > 0
          ? ((attendeeCount / currentRegistrationCount) * 100).toFixed(1)
          : null;
    }

    res.render('event-details', { 
      user, 
      session,
      capacity,
      query: req.query,
      isRegistered,
      registrationStatus,
      registrationDeadlinePassed,
      currentRegistrationCount,
      isFull,
      eventEnded,
      registrationCount: currentRegistrationCount,
      metricAverages,
      overallSurveyAverage,
      attendeeCount,
      attendanceRate
    });
  } catch (error) {
    console.error('Event details error:', error);
    res.redirect('/events');
  }
});

// Delete Event Session Route - POST (manager only)
app.post('/events/:sessionId/delete', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const sessionId = parseInt(req.params.sessionId);
    if (isNaN(sessionId)) {
      return res.redirect('/events');
    }

    // Verify session exists
    const session = await db('session')
      .where('sessionid', sessionId)
      .first();

    if (!session) {
      return res.redirect('/events?error=session_not_found');
    }

    // Cascade delete: First delete all registrations for this session
    await db('registration')
      .where('sessionid', sessionId)
      .del();

    // Then delete the session itself
    await db('session')
      .where('sessionid', sessionId)
      .del();

    res.redirect('/events?success=session_deleted');
  } catch (error) {
    console.error('Delete event session error:', error);
    res.redirect('/events?error=delete_failed');
  }
});

// Edit Event Session Route - GET (manager only)
app.get('/events/:sessionId/edit', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect('/events');
    }

    const sessionId = parseInt(req.params.sessionId);
    if (isNaN(sessionId)) {
      return res.redirect('/events');
    }

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Fetch session with JOINs to event and eventtype tables
    const session = await db('session as s')
      .join('event as e', 's.eventid', 'e.eventid')
      .join('eventtype as et', 'e.eventtypeid', 'et.eventtypeid')
      .where('s.sessionid', sessionId)
      .select(
        's.sessionid',
        's.eventid',
        's.eventdatetimestart',
        's.eventlocation',
        's.eventdatetimeend',
        's.eventcapacity',
        's.eventregistrationdeadline',
        'e.eventname',
        'e.eventdescription',
        'e.eventrecurrencepattern',
        'e.eventdefaultcapacity',
        'et.eventtype'
      )
      .first();

    if (!session) {
      return res.redirect('/events');
    }

    res.render('event-edit', { 
      user, 
      session,
      query: req.query
    });
  } catch (error) {
    console.error('Edit event GET error:', error);
    res.redirect('/events');
  }
});

// Edit Event Session Route - POST (manager only)
app.post('/events/:sessionId/edit', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect('/events');
    }

    const sessionId = parseInt(req.params.sessionId);
    if (isNaN(sessionId)) {
      return res.redirect('/events');
    }

    const { eventdatetimestart, eventlocation, eventdatetimeend, eventcapacity, eventregistrationdeadline } = req.body;

    // Validate required fields
    if (!eventdatetimestart || !eventlocation || !eventdatetimeend) {
      return res.redirect(`/events/${sessionId}/edit?error=missing_fields`);
    }

    // Verify session exists
    const existingSession = await db('session')
      .where('sessionid', sessionId)
      .first();

    if (!existingSession) {
      return res.redirect('/events?error=session_not_found');
    }

    // Parse dates
    let startDateTime, endDateTime, regDeadline = null;
    try {
      startDateTime = new Date(eventdatetimestart);
      endDateTime = new Date(eventdatetimeend);
      if (eventregistrationdeadline && eventregistrationdeadline.trim() !== '') {
        regDeadline = new Date(eventregistrationdeadline);
      }
    } catch (error) {
      return res.redirect(`/events/${sessionId}/edit?error=invalid_date`);
    }

    // Validate dates
    if (isNaN(startDateTime.getTime()) || isNaN(endDateTime.getTime())) {
      return res.redirect(`/events/${sessionId}/edit?error=invalid_date`);
    }

    if (regDeadline && isNaN(regDeadline.getTime())) {
      return res.redirect(`/events/${sessionId}/edit?error=invalid_date`);
    }

    // Validate start date is before end date
    if (startDateTime >= endDateTime) {
      return res.redirect(`/events/${sessionId}/edit?error=start_after_end`);
    }

    // Validate registration deadline is not after end date (if provided)
    if (regDeadline && regDeadline > endDateTime) {
      return res.redirect(`/events/${sessionId}/edit?error=deadline_after_end`);
    }

    // Parse capacity - if empty, set to null (will use event default)
    let finalCapacity = null;
    if (eventcapacity && eventcapacity.trim() !== '') {
      finalCapacity = parseInt(eventcapacity);
      if (isNaN(finalCapacity)) {
        finalCapacity = null;
      }
    }

    // Update session record
    await db('session')
      .where('sessionid', sessionId)
      .update({
        eventdatetimestart: startDateTime,
        eventlocation: eventlocation.trim(),
        eventdatetimeend: endDateTime,
        eventcapacity: finalCapacity,
        eventregistrationdeadline: regDeadline
      });

    res.redirect(`/events/${sessionId}?success=true`);
  } catch (error) {
    console.error('Edit event POST error:', error);
    res.redirect(`/events/${sessionId}/edit?error=update_failed`);
  }
});

// Take Attendance Route - GET (manager only)
app.get('/events/:sessionId/attendance', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect('/events');
    }

    const sessionId = parseInt(req.params.sessionId);
    if (isNaN(sessionId)) {
      return res.redirect('/events');
    }

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Fetch session with JOINs to event and eventtype tables
    const session = await db('session as s')
      .join('event as e', 's.eventid', 'e.eventid')
      .join('eventtype as et', 'e.eventtypeid', 'et.eventtypeid')
      .where('s.sessionid', sessionId)
      .select(
        's.sessionid',
        's.eventid',
        's.eventdatetimestart',
        's.eventlocation',
        's.eventdatetimeend',
        's.eventcapacity',
        's.eventregistrationdeadline',
        'e.eventname',
        'e.eventdescription',
        'e.eventrecurrencepattern',
        'e.eventdefaultcapacity',
        'et.eventtype'
      )
      .first();

    if (!session) {
      return res.redirect('/events');
    }

    // Fetch all registered participants (excluding cancelled)
    const registrations = await db('registration as r')
      .join('users as u', 'r.userid', 'u.userid')
      .where('r.sessionid', sessionId)
      .where(function() {
        this.whereNull('r.registrationstatus')
          .orWhereNot('r.registrationstatus', 'cancelled');
      })
      .select(
        'r.userid',
        'r.registrationstatus',
        'r.registrationattendedflag',
        'r.registrationcheckintime',
        'u.userfirstname',
        'u.userlastname',
        'u.useremail'
      )
      .orderBy('u.userlastname', 'asc')
      .orderBy('u.userfirstname', 'asc');

    // Format participants data
    const participants = registrations.map(reg => ({
      userid: reg.userid,
      firstName: reg.userfirstname || '',
      lastName: reg.userlastname || '',
      fullName: `${reg.userfirstname || ''} ${reg.userlastname || ''}`.trim() || 'No Name',
      email: reg.useremail,
      registrationstatus: reg.registrationstatus,
      registrationattendedflag: reg.registrationattendedflag,
      registrationcheckintime: reg.registrationcheckintime,
      isAttended: reg.registrationstatus === 'attended' && reg.registrationattendedflag === true
    }));

    res.render('event-attendance', { 
      user, 
      session,
      participants,
      query: req.query
    });
  } catch (error) {
    console.error('Take attendance GET error:', error);
    res.redirect('/events');
  }
});

// Take Attendance Route - POST (manager only)
app.post('/events/:sessionId/attendance', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const sessionId = parseInt(req.params.sessionId);
    if (isNaN(sessionId)) {
      return res.redirect('/events?error=invalid_session');
    }

    // Get array of user IDs marked as attended (from checkboxes)
    const attendedUserIds = Array.isArray(req.body.userIds) 
      ? req.body.userIds.map(id => parseInt(id)).filter(id => !isNaN(id))
      : req.body.userIds 
        ? [parseInt(req.body.userIds)].filter(id => !isNaN(id))
        : [];

    // Check if this is a bulk "mark all as no-show" action
    const markAllNoShow = req.body.bulkAction === 'mark_all_no_show';

    // Get all registrations for this session (excluding cancelled)
    const allRegistrations = await db('registration')
      .where('sessionid', sessionId)
      .where(function() {
        this.whereNull('registrationstatus')
          .orWhereNot('registrationstatus', 'cancelled');
      })
      .select('userid', 'sessionid', 'registrationstatus', 'registrationattendedflag');

    const now = new Date();

    // Use transaction for batch updates
    await db.transaction(async (trx) => {
      for (const reg of allRegistrations) {
        if (markAllNoShow) {
          // Bulk action: mark all as no-show (except those explicitly marked as attended)
          if (attendedUserIds.includes(reg.userid)) {
            // Mark as attended
            await trx('registration')
              .where('userid', reg.userid)
              .where('sessionid', sessionId)
              .update({
                registrationstatus: 'attended',
                registrationattendedflag: true,
                registrationcheckintime: now
              });
          } else {
            // Mark as no-show
            await trx('registration')
              .where('userid', reg.userid)
              .where('sessionid', sessionId)
              .update({
                registrationstatus: 'no-show',
                registrationattendedflag: false,
                registrationcheckintime: null
              });
          }
        } else {
          // Normal attendance marking
          const isMarkedAsAttended = attendedUserIds.includes(reg.userid);
          const wasPreviouslyAttended = reg.registrationstatus === 'attended' && reg.registrationattendedflag === true;

          if (isMarkedAsAttended) {
            // Mark as attended
            await trx('registration')
              .where('userid', reg.userid)
              .where('sessionid', sessionId)
              .update({
                registrationstatus: 'attended',
                registrationattendedflag: true,
                registrationcheckintime: now
              });
          } else if (wasPreviouslyAttended) {
            // Allow unchecking - reset to null (will be auto-marked as no-show when event ends)
            await trx('registration')
              .where('userid', reg.userid)
              .where('sessionid', sessionId)
              .update({
                registrationstatus: null,
                registrationattendedflag: null,
                registrationcheckintime: null
              });
          }
          // Otherwise, leave unchanged (will be auto-marked as no-show when event ends)
        }
      }
    });

    res.redirect(`/events/${sessionId}?success=attendance_saved`);
  } catch (error) {
    console.error('Take attendance POST error:', error);
    res.redirect(`/events/${req.params.sessionId}/attendance?error=attendance_save_failed`);
  }
});

// Participant Event Registration Routes
app.post('/events/:sessionId/register', requireAuth, restrictDonor, async (req, res) => {
  try {
    const userId = req.session.userId;
    const sessionId = parseInt(req.params.sessionId);
    const returnTab = req.body.returnTab || 'upcoming';

    if (isNaN(sessionId)) {
      return res.redirect('/events');
    }

    // Validate session and registration deadline, and enforce capacity
    const session = await db('session as s')
      .join('event as e', 's.eventid', 'e.eventid')
      .where('s.sessionid', sessionId)
      .select(
        's.sessionid',
        's.eventcapacity',
        's.eventregistrationdeadline',
        'e.eventdefaultcapacity',
        'e.eventname'
      )
      .first();

    if (!session) {
      return res.redirect('/events?error=session_not_found');
    }

    const now = new Date();
    if (session.eventregistrationdeadline) {
      const deadline = new Date(session.eventregistrationdeadline);
      if (deadline < now) {
        return res.redirect(`/events?tab=${encodeURIComponent(returnTab)}&error=registration_deadline_passed`);
      }
    }

    const capacityRaw = session.eventcapacity || session.eventdefaultcapacity;
    const capacity =
      typeof capacityRaw === 'number'
        ? capacityRaw
        : capacityRaw
        ? parseInt(capacityRaw, 10)
        : null;

    if (capacity !== null && !Number.isNaN(capacity)) {
      const registrationCountRow = await db('registration')
        .where('sessionid', sessionId)
        .andWhere(function () {
          this.whereNull('registrationstatus')
            .orWhereNot('registrationstatus', 'cancelled');
        })
        .count('* as count')
        .first();

      const currentCount = registrationCountRow ? parseInt(registrationCountRow.count, 10) || 0 : 0;

      if (currentCount >= capacity) {
        return res.redirect(`/events?tab=${encodeURIComponent(returnTab)}&error=no_seats_available`);
      }
    }

    // Check if user already has an ACTIVE (non-cancelled) registration
    const activeRegistration = await db('registration')
      .where('userid', userId)
      .andWhere('sessionid', sessionId)
      .andWhere(function() {
        this.whereNull('registrationstatus')
          .orWhereNot('registrationstatus', 'cancelled');
      })
      .first();

    if (activeRegistration) {
      // Already registered with an active registration
      return res.redirect(`/events?tab=${encodeURIComponent(returnTab)}&error=already_registered`);
    }

    // Always create a NEW registration row (even if they have cancelled ones)
    await db('registration').insert({
      userid: userId,
      sessionid: sessionId,
      registrationstatus: null,
      registrationattendedflag: null,
      registrationcheckintime: null,
      registrationcreatedat: now,
      surveynpsbucket: null,
      surveycomments: null,
      overallsurveyscore: null,
      surveysubmissiondate: null
    });

    return res.redirect(`/events?tab=${encodeURIComponent(returnTab)}&success=registered`);
  } catch (error) {
    console.error('Event registration error:', error);
    return res.redirect('/events?error=registration_failed');
  }
});

app.post('/events/:sessionId/cancel-registration', requireAuth, restrictDonor, async (req, res) => {
  try {
    const userId = req.session.userId;
    const sessionId = parseInt(req.params.sessionId);
    const returnTab = req.body.returnTab || 'upcoming';

    if (isNaN(sessionId)) {
      return res.redirect('/events');
    }

    // Find the ACTIVE (non-cancelled) registration
    const existing = await db('registration')
      .where('userid', userId)
      .andWhere('sessionid', sessionId)
      .andWhere(function() {
        this.whereNull('registrationstatus')
          .orWhereNot('registrationstatus', 'cancelled');
      })
      .orderBy('registrationcreatedat', 'desc')
      .first();

    if (!existing) {
      return res.redirect(`/events?tab=${encodeURIComponent(returnTab)}&error=not_registered`);
    }

    // Cancel only this specific registration (by created date)
    await db('registration')
      .where('userid', userId)
      .andWhere('sessionid', sessionId)
      .andWhere('registrationcreatedat', existing.registrationcreatedat)
      .update({ registrationstatus: 'cancelled' });

    return res.redirect(`/events?tab=${encodeURIComponent(returnTab)}&success=cancelled`);
  } catch (error) {
    console.error('Event cancel registration error:', error);
    return res.redirect('/events?error=cancel_failed');
  }
});

// Surveys route (protected, no donor access)
// Take Survey Page (Participants Only)
app.get('/surveys/take/:sessionId', requireAuth, restrictDonor, async (req, res) => {
  try {
    const userId = req.session.userId;
    const sessionId = parseInt(req.params.sessionId);

    // Verify user is registered and attended
    const registration = await db('registration as r')
      .join('session as s', 'r.sessionid', 's.sessionid')
      .join('event as e', 's.eventid', 'e.eventid')
      .where('r.userid', userId)
      .where('r.sessionid', sessionId)
      .where('r.registrationattendedflag', true)
      .whereNull('r.surveynpsbucket')
      .select(
        's.sessionid',
        's.eventdatetimestart',
        'e.eventname',
        'e.eventid'
      )
      .first();

    if (!registration) {
      return res.redirect('/surveys?error=not_eligible');
    }

    // Get active survey metrics with questions
    const surveyMetrics = await db('surveymetric')
      .select('metricid', 'surveymetric', 'metricquestion')
      .where(function() {
        this.where('metricactive', true).orWhereNull('metricactive');
      })
      .orderBy('metricid');

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    res.render('take-survey', {
      user,
      session: registration,
      surveyMetrics
    });
  } catch (error) {
    console.error('Take survey GET error:', error);
    res.redirect('/surveys?error=survey_load_failed');
  }
});

app.get('/surveys', requireAuth, restrictDonor, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Get filter/sort parameters (for managers only)
    const filters = {
      surveyDateFrom: req.query.surveyDateFrom || '',
      surveyDateTo: req.query.surveyDateTo || '',
      sessionDateFrom: req.query.sessionDateFrom || '',
      sessionDateTo: req.query.sessionDateTo || '',
      minScore: req.query.minScore || '',
      maxScore: req.query.maxScore || '',
      eventId: req.query.eventId || '',
      sessionId: req.query.sessionId || '',
      participantSearch: req.query.participantSearch || '',
      sortBy: req.query.sortBy || 'surveysubmissiondate',
      sortOrder: req.query.sortOrder || 'desc',
      success: req.query.success || '',
      error: req.query.error || ''
    };

    // Get all survey metrics (these will be the dynamic columns)
    const surveyMetrics = await db('surveymetric')
      .select('metricid', 'surveymetric', 'metricquestion')
      .where(function() {
        this.where('metricactive', true).orWhereNull('metricactive');
      })
      .orderBy('metricid');

    // Get events list for filter dropdown (managers only)
    let eventsList = [];
    let sessionsList = [];
    if (user.role === 'manager') {
      eventsList = await db('event').select('eventid', 'eventname').orderBy('eventname');
      sessionsList = await db('session as s')
        .join('event as e', 's.eventid', 'e.eventid')
        .select('s.sessionid', 's.eventdatetimestart', 'e.eventname')
        .orderBy('s.eventdatetimestart', 'desc');
    }

    // Get registration data where survey was completed (NPS bucket not null)
    // For managers: show all surveys with optional filters
    // For participants (users): show only their own surveys
    let registrationQuery = db('registration as r')
      .join('users as u', 'r.userid', 'u.userid')
      .join('session as s', 'r.sessionid', 's.sessionid')
      .join('event as e', 's.eventid', 'e.eventid')
      .whereNotNull('r.surveynpsbucket')
      .select(
        'r.userid',
        'r.sessionid',
        'u.userfirstname',
        'u.userlastname',
        'e.eventid',
        'e.eventname',
        's.eventdatetimestart',
        'r.surveycomments',
        'r.surveynpsbucket',
        'r.surveysubmissiondate',
        'r.overallsurveyscore'
      );

    // For participants: also get pending surveys (events attended but no survey submitted)
    let pendingSurveys = [];
    if (user.role !== 'manager') {
      pendingSurveys = await db('registration as r')
        .join('session as s', 'r.sessionid', 's.sessionid')
        .join('event as e', 's.eventid', 'e.eventid')
        .where('r.userid', req.session.userId)
        .whereNull('r.surveynpsbucket')  // No survey submitted yet
        .where('r.registrationattendedflag', true)  // Must have been marked as attended
        .where('s.eventdatetimestart', '<', new Date())  // Event has passed
        .select(
          'r.userid',
          'r.sessionid',
          'e.eventid',
          'e.eventname',
          's.eventdatetimestart',
          's.eventlocation'
        )
        .orderBy('s.eventdatetimestart', 'desc');
    }

    // If not a manager, filter to only show the logged-in user's surveys
    if (user.role !== 'manager') {
      registrationQuery = registrationQuery.where('r.userid', req.session.userId);
    } else {
      // Apply manager filters
      if (filters.surveyDateFrom) {
        registrationQuery = registrationQuery.where('r.surveysubmissiondate', '>=', filters.surveyDateFrom);
      }
      if (filters.surveyDateTo) {
        registrationQuery = registrationQuery.where('r.surveysubmissiondate', '<=', filters.surveyDateTo + ' 23:59:59');
      }
      if (filters.sessionDateFrom) {
        registrationQuery = registrationQuery.where('s.eventdatetimestart', '>=', filters.sessionDateFrom);
      }
      if (filters.sessionDateTo) {
        registrationQuery = registrationQuery.where('s.eventdatetimestart', '<=', filters.sessionDateTo + ' 23:59:59');
      }
      if (filters.minScore) {
        registrationQuery = registrationQuery.where('r.overallsurveyscore', '>=', parseFloat(filters.minScore));
      }
      if (filters.maxScore) {
        registrationQuery = registrationQuery.where('r.overallsurveyscore', '<=', parseFloat(filters.maxScore));
      }
      if (filters.eventId) {
        registrationQuery = registrationQuery.where('e.eventid', filters.eventId);
      }
      if (filters.sessionId) {
        registrationQuery = registrationQuery.where('s.sessionid', filters.sessionId);
      }
      if (filters.participantSearch) {
        const searchTerm = `%${filters.participantSearch}%`;
        registrationQuery = registrationQuery.where(function() {
          this.whereILike('u.userfirstname', searchTerm)
              .orWhereILike('u.userlastname', searchTerm)
              .orWhereRaw("LOWER(u.userfirstname || ' ' || u.userlastname) LIKE LOWER(?)", [searchTerm]);
        });
      }
    }

    // Apply sorting
    const validSortColumns = {
      'surveysubmissiondate': 'r.surveysubmissiondate',
      'sessiondate': 's.eventdatetimestart',
      'overallscore': 'r.overallsurveyscore',
      'eventname': 'e.eventname',
      'participant': 'u.userlastname'
    };
    const sortColumn = validSortColumns[filters.sortBy] || 'r.surveysubmissiondate';
    const sortOrder = filters.sortOrder === 'asc' ? 'asc' : 'desc';
    registrationQuery = registrationQuery.orderBy(sortColumn, sortOrder);

    const registrationData = await registrationQuery;

    // Get metric scores from survey table and create lookup
    // For participants, only get their own scores
    let surveyScoresQuery = db('survey').select('userid', 'sessionid', 'metricid', 'surveyscore');
    
    if (user.role !== 'manager') {
      surveyScoresQuery = surveyScoresQuery.where('userid', req.session.userId);
    }
    
    const allSurveyScores = await surveyScoresQuery;
    
    const metricScoreLookup = {};
    for (const score of allSurveyScores) {
      const key = `${score.userid}-${score.sessionid}`;
      if (!metricScoreLookup[key]) {
        metricScoreLookup[key] = {};
      }
      metricScoreLookup[key][score.metricid] = score.surveyscore;
    }

    // Build survey responses - start from registration data, add metric scores if available
    const surveyResponses = registrationData.map(row => {
      const key = `${row.userid}-${row.sessionid}`;
      return {
        userid: row.userid,
        sessionid: row.sessionid,
        participantName: `${row.userfirstname || ''} ${row.userlastname || ''}`.trim(),
        eventName: row.eventname,
        eventDate: row.eventdatetimestart,
        overallScore: row.overallsurveyscore,
        surveyComments: row.surveycomments,
        npsBucket: row.surveynpsbucket,
        submittedAt: row.surveysubmissiondate,
        metricScores: metricScoreLookup[key] || {}
      };
    });

    // Calculate stats for the cards
    const totalResponses = surveyResponses.length;
    
    // Calculate average of all metric scores
    let totalScore = 0;
    let scoreCount = 0;
    for (const response of surveyResponses) {
      for (const score of Object.values(response.metricScores)) {
        if (score !== null && score !== undefined) {
          totalScore += parseFloat(score);
          scoreCount++;
        }
      }
    }
    const avgSatisfaction = scoreCount > 0 ? (totalScore / scoreCount).toFixed(1) : 0;

    // Calculate NPS (Promoters - Detractors as percentage)
    let promoters = 0, passives = 0, detractors = 0;
    for (const response of surveyResponses) {
      if (response.npsBucket === 'Promoter') promoters++;
      else if (response.npsBucket === 'Passive') passives++;
      else if (response.npsBucket === 'Detractor') detractors++;
    }
    const nps = totalResponses > 0 ? Math.round(((promoters - detractors) / totalResponses) * 100) : 0;

    // Calculate response rate
    const responseRate = totalResponses > 0 ? ((totalResponses / totalResponses) * 100).toFixed(1) : 0;

    // Score distribution for chart based on overallsurveyscore (1-5 scale with 0.5 increments)
    const scoreDistribution = { 
      '1': 0, '1.5': 0, '2': 0, '2.5': 0, 
      '3': 0, '3.5': 0, '4': 0, '4.5': 0, '5': 0 
    };
    for (const response of surveyResponses) {
      const overallScore = response.overallScore;
      if (overallScore !== null && overallScore !== undefined) {
        const score = parseFloat(overallScore);
        // Round to nearest 0.5 for categorization
        const roundedScore = Math.round(score * 2) / 2;
        const category = roundedScore.toString();
        if (scoreDistribution.hasOwnProperty(category)) {
          scoreDistribution[category]++;
        }
      }
    }

    res.render('surveys', { 
      user,
      surveyMetrics,
      surveyResponses,
      pendingSurveys,
      filters,
      eventsList,
      sessionsList,
      stats: {
        totalResponses,
        responseRate,
        avgSatisfaction,
        nps,
        promoters,
        passives,
        detractors,
        scoreDistribution
      }
    });
  } catch (error) {
    console.error('Surveys error:', error);
    res.redirect('/login');
  }
});

// Add/Edit survey question (manager only)
app.post('/surveys/questions', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const { surveyMetric, surveyQuestionText, action, originalMetricId } = req.body;

    if (!surveyMetric) {
      return res.redirect('/surveys?error=question_name_required');
    }

    // Check if name already exists (among active questions)
    const existingQuestion = await db('surveymetric')
      .where('surveymetric', surveyMetric)
      .where(function() {
        this.where('metricactive', true).orWhereNull('metricactive');
      })
      .first();

    // If editing, allow same name if it's the same question being edited
    if (existingQuestion && existingQuestion.metricid != originalMetricId) {
      return res.redirect('/surveys?error=question_name_exists');
    }

    // Get max metricid to avoid sequence conflicts
    const maxIdResult = await db('surveymetric').max('metricid as maxId').first();
    const newId = (maxIdResult.maxId || 0) + 1;

    if (action === 'edit' && originalMetricId) {
      // Create the new question entry FIRST (before updating references)
      await db('surveymetric').insert({
        metricid: newId,
        surveymetric: surveyMetric,
        metricquestion: surveyQuestionText || null,
        metricactive: true,
        createdat: new Date()
      });

      // Update any existing survey responses to use the new metricid
      await db('survey')
        .where('metricid', originalMetricId)
        .update({ metricid: newId });

      // Mark the old question as inactive (don't delete)
      await db('surveymetric')
        .where('metricid', originalMetricId)
        .update({ metricactive: false });
    } else {
      // Add new question at the end
      await db('surveymetric').insert({
        metricid: newId,
        surveymetric: surveyMetric,
        metricquestion: surveyQuestionText || null,
        metricactive: true,
        createdat: new Date()
      });
    }

    res.redirect('/surveys?success=question_saved');
  } catch (error) {
    console.error('Survey question save error:', error);
    res.redirect('/surveys?error=question_save_failed');
  }
});

// Submit survey (participant)
app.post('/surveys/submit', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { sessionId, comments, ...metricScores } = req.body;

    if (!sessionId) {
      return res.redirect('/surveys?error=survey_incomplete');
    }

    // Verify this user is registered for this session
    const registration = await db('registration')
      .where('userid', userId)
      .where('sessionid', sessionId)
      .first();

    if (!registration) {
      return res.redirect('/surveys?error=not_registered');
    }

    // Check if survey already submitted
    if (registration.surveynpsbucket) {
      return res.redirect('/surveys?error=already_submitted');
    }

    // Get active survey metrics
    const activeMetrics = await db('surveymetric')
      .where(function() {
        this.where('metricactive', true).orWhereNull('metricactive');
      })
      .select('metricid');

    // Collect scores for calculating overall score
    const scores = [];

    // Insert metric scores into survey table
    for (const metric of activeMetrics) {
      const scoreKey = `metric_${metric.metricid}`;
      const score = metricScores[scoreKey];
      if (score !== undefined && score !== '') {
        const scoreValue = parseFloat(score); // Use parseFloat to handle decimals
        scores.push(scoreValue);
        await db('survey').insert({
          userid: userId,
          sessionid: parseInt(sessionId),
          metricid: metric.metricid,
          surveyscore: scoreValue
        });
      }
    }

    // Calculate overall score as average of all metric scores
    const overallScore = scores.length > 0 
      ? scores.reduce((sum, s) => sum + s, 0) / scores.length 
      : null;

    // Calculate NPS bucket based on overall score (1-5 scale)
    // 5 = Promoter, 4 = Passive, 1-3 = Detractor
    let npsBucket = 'Passive';
    if (overallScore !== null) {
      if (overallScore >= 4.5) {
        npsBucket = 'Promoter';
      } else if (overallScore <= 3.5) {
        npsBucket = 'Detractor';
      } else {
        npsBucket = 'Passive';
      }
    }

    // Update registration with survey data
    await db('registration')
      .where('userid', userId)
      .where('sessionid', sessionId)
      .update({
        surveynpsbucket: npsBucket,
        surveycomments: comments || null,
        overallsurveyscore: overallScore,
        surveysubmissiondate: new Date()
      });

    res.redirect('/surveys?success=survey_submitted');
  } catch (error) {
    console.error('Survey submit error:', error);
    res.redirect('/surveys?error=survey_submit_failed');
  }
});

// Deactivate survey question (manager only)
app.post('/surveys/questions/delete', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const { metricId } = req.body;

    if (!metricId) {
      return res.redirect('/surveys?error=invalid_request');
    }

    // Mark the question as inactive (don't actually delete)
    await db('surveymetric')
      .where('metricid', metricId)
      .update({ metricactive: false });

    res.redirect('/surveys?success=question_deleted');
  } catch (error) {
    console.error('Survey question deactivate error:', error);
    res.redirect('/surveys?error=question_delete_failed');
  }
});

// Delete survey response (manager only)
app.post('/surveys/delete', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const { userId, sessionId } = req.body;

    if (!userId || !sessionId) {
      return res.redirect('/surveys?error=invalid_request');
    }

    // Delete metric scores from survey table
    await db('survey')
      .where('userid', userId)
      .where('sessionid', sessionId)
      .del();

    // Clear survey data from registration (but keep the registration itself)
    await db('registration')
      .where('userid', userId)
      .where('sessionid', sessionId)
      .update({
        overallsurveyscore: null,
        surveynpsbucket: null,
        surveycomments: null,
        surveysubmissiondate: null
      });

    res.redirect('/surveys?success=survey_deleted');
  } catch (error) {
    console.error('Survey delete error:', error);
    res.redirect('/surveys?error=delete_failed');
  }
});

// Milestones route (protected, no donor access)
app.get('/milestones', requireAuth, restrictDonor, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Get query parameters for filtering
    const filters = {
      participantSearch: req.query.participantSearch || '',
      milestoneSearch: req.query.milestoneSearch || '',
      milestoneType: req.query.milestoneType || '',
      success: req.query.success || '',
      error: req.query.error || '',
      milestoneTitle: req.query.milestoneTitle || ''
    };

    // Get all milestone types
    const milestoneTypes = await db('milestonetype')
      .select('milestoneid', 'milestonetitle')
      .orderBy('milestonetitle');

    // Get all participants (users) for the add milestone dropdown
    const participants = await db('users')
      .select('userid', 'userfirstname', 'userlastname', 'useremail')
      .orderBy('userlastname');

    // Build query for user milestones
    let milestonesQuery = db('usermilestone as um')
      .join('users as u', 'um.userid', 'u.userid')
      .join('milestonetype as mt', 'um.milestoneid', 'mt.milestoneid')
      .select(
        'um.userid',
        'um.milestoneid',
        'um.milestonedate',
        'u.userfirstname',
        'u.userlastname',
        'u.useremail',
        'mt.milestonetitle'
      )
      .orderBy('um.milestonedate', 'desc');

    // For non-managers, only show their own milestones
    if (user.role !== 'manager') {
      milestonesQuery = milestonesQuery.where('um.userid', req.session.userId);
      
      // Apply participant filters (search by milestone type name)
      if (filters.milestoneSearch) {
        const searchTerm = `%${filters.milestoneSearch}%`;
        milestonesQuery = milestonesQuery.whereILike('mt.milestonetitle', searchTerm);
      }
    } else {
      // Apply filters (managers only)
      if (filters.participantSearch) {
        const searchTerm = `%${filters.participantSearch}%`;
        milestonesQuery = milestonesQuery.where(function() {
          this.whereILike('u.userfirstname', searchTerm)
              .orWhereILike('u.userlastname', searchTerm)
              .orWhereRaw("LOWER(u.userfirstname || ' ' || u.userlastname) LIKE LOWER(?)", [searchTerm]);
        });
      }
    }

    // Apply milestone type filter (for both managers and participants)
    if (filters.milestoneType) {
      milestonesQuery = milestonesQuery.where('um.milestoneid', filters.milestoneType);
    }

    const userMilestones = await milestonesQuery;

    // Calculate milestone counts by type (count distinct participants)
    const milestoneCounts = await db('usermilestone')
      .select('milestoneid')
      .countDistinct('userid as count')
      .groupBy('milestoneid');

    const countsMap = {};
    milestoneCounts.forEach(mc => {
      countsMap[mc.milestoneid] = parseInt(mc.count);
    });

    // Add counts to milestone types
    const milestoneTypesWithCounts = milestoneTypes.map(mt => ({
      ...mt,
      count: countsMap[mt.milestoneid] || 0
    }));

    // Get specific milestone types for summary boxes (for managers only)
    let summaryMilestoneTypes = [];
    if (user.role === 'manager') {
      const searchKeywords = ['internship', 'data analyst', 'lab assistant', 'product designer'];
      
      // Get all milestone types with their participant counts using a subquery
      const allMilestonesWithCounts = await db.raw(`
        SELECT 
          mt.milestoneid,
          mt.milestonetitle,
          COALESCE(um_counts.participant_count, 0) as count
        FROM milestonetype mt
        LEFT JOIN (
          SELECT 
            milestoneid,
            COUNT(DISTINCT userid) as participant_count
          FROM usermilestone
          GROUP BY milestoneid
        ) um_counts ON mt.milestoneid = um_counts.milestoneid
      `);
      
      // Extract rows from the raw query result
      const milestones = allMilestonesWithCounts.rows || allMilestonesWithCounts;
      
      // Create a map of milestone titles (lowercase) to milestone objects
      const milestoneMap = new Map();
      milestones.forEach(mt => {
        const key = mt.milestonetitle.toLowerCase().trim();
        milestoneMap.set(key, mt);
      });
      
      // Helper function to capitalize words
      const capitalizeWords = (str) => {
        return str.split(' ').map(word => 
          word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
        ).join(' ');
      };
      
      // Always create 4 boxes in the specified order
      summaryMilestoneTypes = searchKeywords.map(keyword => {
        const keywordLower = keyword.toLowerCase().trim();
        
        // Find matching milestone - try multiple strategies
        let found = null;
        
        // Strategy 1: Exact match (case-insensitive)
        found = Array.from(milestoneMap.entries()).find(([key]) => 
          key === keywordLower
        );
        
        // Strategy 2: Contains match (either direction)
        if (!found) {
          found = Array.from(milestoneMap.entries()).find(([key]) => 
            key.includes(keywordLower) || keywordLower.includes(key)
          );
        }
        
        // Strategy 3: Word-by-word match (handles "Data Analyst" vs "data analyst")
        if (!found) {
          const keywordWords = keywordLower.split(/\s+/);
          found = Array.from(milestoneMap.entries()).find(([key]) => {
            const keyWords = key.split(/\s+/);
            return keywordWords.every(kw => keyWords.some(k => k.includes(kw) || kw.includes(k)));
          });
        }
        
        if (found) {
          const mt = found[1];
          return {
            milestoneid: mt.milestoneid,
            milestonetitle: capitalizeWords(mt.milestonetitle), // Capitalize for display
            count: parseInt(mt.count) || 0
          };
        } else {
          // If milestone doesn't exist, create a placeholder with 0 count
          console.log('Milestone not found for keyword:', keyword);
          console.log('Available milestones:', Array.from(milestoneMap.keys()));
          return {
            milestoneid: null,
            milestonetitle: capitalizeWords(keyword), // Capitalize for display
            count: 0
          };
        }
      });
    }

    // Get completed milestone IDs for the current user (for filtering in add modal)
    let completedMilestoneIds = [];
    if (user.role !== 'manager') {
      // For participants, get their completed milestones
      completedMilestoneIds = userMilestones.map(m => m.milestoneid);
    }
    // For managers, don't filter - they can add any milestone for any participant

    res.render('milestones', { 
      user,
      milestoneTypes: milestoneTypesWithCounts,
      summaryMilestoneTypes: summaryMilestoneTypes,
      participants,
      userMilestones,
      filters,
      completedMilestoneIds
    });
  } catch (error) {
    console.error('Milestones error:', error);
    res.redirect('/login');
  }
});

// Add milestone (manager can add for anyone, participant can add for themselves)
app.post('/milestones/add', requireAuth, async (req, res) => {
  try {
    let { userId, milestoneId, milestoneDate } = req.body;

    // Participants can only add milestones for themselves
    if (req.session.userRole !== 'manager') {
      userId = req.session.userId;
    }

    if (!userId || !milestoneId || !milestoneDate) {
      return res.redirect('/milestones?error=missing_fields');
    }

    // Check if this milestone already exists for this user on this date
    const existing = await db('usermilestone')
      .where('userid', userId)
      .where('milestoneid', milestoneId)
      .where('milestonedate', milestoneDate)
      .first();

    if (existing) {
      return res.redirect('/milestones?error=milestone_exists');
    }

    await db('usermilestone').insert({
      userid: parseInt(userId),
      milestoneid: parseInt(milestoneId),
      milestonedate: milestoneDate
    });

    // Get milestone title for congratulation message (participants only)
    if (req.session.userRole !== 'manager') {
      const milestoneType = await db('milestonetype')
        .where('milestoneid', milestoneId)
        .first();
      if (milestoneType) {
        return res.redirect(`/milestones?success=milestone_added&milestoneTitle=${encodeURIComponent(milestoneType.milestonetitle)}`);
      }
    }

    res.redirect('/milestones?success=milestone_added');
  } catch (error) {
    console.error('Add milestone error:', error);
    res.redirect('/milestones?error=add_failed');
  }
});

// Update milestone (manager can update any, participant can only update their own)
app.post('/milestones/update', requireAuth, async (req, res) => {
  try {
    let { originalUserId, originalMilestoneId, originalDate, newUserId, newMilestoneId, newDate } = req.body;

    // Participants can only update their own milestones
    if (req.session.userRole !== 'manager') {
      if (parseInt(originalUserId) !== req.session.userId) {
        return res.status(403).send('Forbidden');
      }
      // Force the new userId to be themselves (can't transfer to another user)
      newUserId = req.session.userId;
    }

    if (!originalUserId || !originalMilestoneId || !originalDate || !newUserId || !newMilestoneId || !newDate) {
      return res.redirect('/milestones?error=missing_fields');
    }

    // Delete old record
    await db('usermilestone')
      .where('userid', originalUserId)
      .where('milestoneid', originalMilestoneId)
      .where('milestonedate', originalDate)
      .del();

    // Insert new record
    await db('usermilestone').insert({
      userid: parseInt(newUserId),
      milestoneid: parseInt(newMilestoneId),
      milestonedate: newDate
    });

    res.redirect('/milestones?success=milestone_updated');
  } catch (error) {
    console.error('Update milestone error:', error);
    res.redirect('/milestones?error=update_failed');
  }
});

// Delete milestone (manager can delete any, participant can only delete their own)
app.post('/milestones/delete', requireAuth, async (req, res) => {
  try {
    const { userId, milestoneId, milestoneDate } = req.body;

    // Participants can only delete their own milestones
    if (req.session.userRole !== 'manager') {
      if (parseInt(userId) !== req.session.userId) {
        return res.status(403).send('Forbidden');
      }
    }

    if (!userId || !milestoneId || !milestoneDate) {
      return res.redirect('/milestones?error=missing_fields');
    }

    await db('usermilestone')
      .where('userid', userId)
      .where('milestoneid', milestoneId)
      .where('milestonedate', milestoneDate)
      .del();

    res.redirect('/milestones?success=milestone_deleted');
  } catch (error) {
    console.error('Delete milestone error:', error);
    res.redirect('/milestones?error=delete_failed');
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

    const userRole = req.session.userRole;
    const isManager = userRole === 'manager';
    const viewPersonal = req.query.view === 'personal';

    // For managers: show all donations by default, or personal if view=personal
    // For others: always show personal donations
    let donationsQuery = db('donation')
      .leftJoin('users', 'donation.userid', 'users.userid')
      .select(
        'donation.*',
        'users.userfirstname',
        'users.userlastname',
        'users.useremail'
      );

    if (isManager && !viewPersonal) {
      // Manager viewing all donations - no user filter
    } else {
      // Personal view (for managers with view=personal, or for non-managers)
      donationsQuery = donationsQuery.where('donation.userid', userId);
    }

    // Get all donations
    let donations = await donationsQuery
      .orderBy('donation.donationdate', 'desc')
      .orderBy('donation.donationno', 'desc');

    // Get current month start and end
    const now = new Date();
    const currentMonth = now.getMonth();
    const currentYear = now.getFullYear();

    // Calculate stats based on view
    let totalDonations = 0;
    let thisMonthDonations = 0;
    let thisMonthCount = 0;
    let averageDonation = 0;

    if (isManager && !viewPersonal) {
      // Manager viewing all donations - calculate from all donations
      totalDonations = donations.reduce((sum, d) => sum + parseFloat(d.donationamount || 0), 0);
      
      const thisMonthDonationsList = donations.filter(d => {
        const donationDate = new Date(d.donationdate);
        return donationDate.getMonth() === currentMonth && donationDate.getFullYear() === currentYear;
      });
      
      thisMonthDonations = thisMonthDonationsList.reduce((sum, d) => sum + parseFloat(d.donationamount || 0), 0);
      thisMonthCount = thisMonthDonationsList.length;
      
      averageDonation = donations.length > 0 ? totalDonations / donations.length : 0;
    } else {
      // Personal view - calculate from personal donations array
      totalDonations = donations.reduce((sum, d) => sum + parseFloat(d.donationamount || 0), 0);
      
      const thisMonthDonationsList = donations.filter(d => {
        const donationDate = new Date(d.donationdate);
        return donationDate.getMonth() === currentMonth && donationDate.getFullYear() === currentYear;
      });
      
      thisMonthDonations = thisMonthDonationsList.reduce((sum, d) => sum + parseFloat(d.donationamount || 0), 0);
      thisMonthCount = thisMonthDonationsList.length;
      
      averageDonation = donations.length > 0
        ? donations.reduce((sum, d) => sum + parseFloat(d.donationamount || 0), 0) / donations.length
        : 0;
    }

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Format numbers with commas
    const formatCurrency = (num) => {
      return parseFloat(num).toLocaleString('en-US', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
      });
    };

    res.render('donations', {
      user,
      donations,
      query: req.query,
      viewPersonal: viewPersonal,
      stats: {
        totalDonations: formatCurrency(totalDonations),
        totalDonationCount: donations.length,
        thisMonthDonations: formatCurrency(thisMonthDonations),
        thisMonthCount: thisMonthCount.toLocaleString('en-US'),
        averageDonation: formatCurrency(averageDonation)
      }
    });
  } catch (error) {
    console.error('Donations error:', error);
    res.redirect('/login');
  }
});

// Donation Receipt PDF Export route (protected)
app.get('/donations/receipt', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const donationUserId = parseInt(req.query.userId);
    const donationNo = parseInt(req.query.donationNo);
    const userRole = req.session.userRole;

    if (!userId) {
      return res.redirect('/login');
    }

    if (isNaN(donationUserId) || isNaN(donationNo)) {
      return res.status(400).send('Invalid donation parameters');
    }

    // Check permissions: donors and participants can only export their own receipts, managers can export any
    if ((userRole === 'donor' || userRole === 'user') && donationUserId !== userId) {
      return res.status(403).send('You do not have permission to export this receipt');
    }

    // Get donation data
    const donation = await db('donation')
      .leftJoin('users', 'donation.userid', 'users.userid')
      .where('donation.userid', donationUserId)
      .where('donation.donationno', donationNo)
      .select(
        'donation.*',
        'users.userfirstname',
        'users.userlastname',
        'users.useremail'
      )
      .first();

    if (!donation) {
      return res.status(404).send('Donation not found');
    }

    // Create PDF
    const doc = new PDFDocument({ margin: 50, size: 'LETTER' });
    
    // Set response headers
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="donation-receipt-${donationUserId}-${donationNo}.pdf"`);
    
    // Pipe PDF to response
    doc.pipe(res);

    // Header
    const pageWidth = doc.page.width;
    const centerX = pageWidth / 2;
    
    doc.fontSize(24)
       .font('Helvetica-Bold')
       .text('Ella Rises', centerX, 50, { align: 'center' });
    
    doc.fontSize(14)
       .font('Helvetica')
       .text('DONATION RECEIPT', centerX, 85, { align: 'center' });

    // Receipt details
    const receiptY = 130;
    doc.fontSize(10)
       .font('Helvetica')
       .text('Receipt Number:', 50, receiptY)
       .font('Helvetica-Bold')
       .text(`${donationUserId}-${donationNo}`, 180, receiptY);

    doc.font('Helvetica')
       .text('Date:', 50, receiptY + 20)
       .font('Helvetica-Bold')
       .text(new Date(donation.donationdate).toLocaleDateString('en-US', { 
         year: 'numeric', 
         month: 'long', 
         day: 'numeric' 
       }), 180, receiptY + 20);

    // Donor Information
    doc.fontSize(12)
       .font('Helvetica-Bold')
       .text('Donor Information:', 50, receiptY + 60);
    
    doc.fontSize(10)
       .font('Helvetica')
       .text('Name:', 50, receiptY + 85)
       .font('Helvetica-Bold')
       .text(`${donation.userfirstname || ''} ${donation.userlastname || ''}`.trim() || 'N/A', 180, receiptY + 85);
    
    doc.font('Helvetica')
       .text('Email:', 50, receiptY + 105)
       .font('Helvetica-Bold')
       .text(donation.useremail || 'N/A', 180, receiptY + 105);

    // Donation Amount
    const amountY = receiptY + 160;
    doc.fontSize(12)
       .font('Helvetica-Bold')
       .text('Donation Amount:', 50, amountY);
    
    doc.fontSize(20)
       .font('Helvetica-Bold')
       .text(`$${parseFloat(donation.donationamount).toLocaleString('en-US', { 
         minimumFractionDigits: 2, 
         maximumFractionDigits: 2 
       })}`, 50, amountY + 25);

    // Thank you message
    const thankYouY = amountY + 80;
    doc.fontSize(11)
       .font('Helvetica')
       .text('Thank you for your generous donation to Ella Rises. Your contribution helps us continue our mission.', 
             50, thankYouY, { 
               width: 500,
               align: 'left'
             });

    // Footer
    const footerY = 700;
    doc.fontSize(9)
       .font('Helvetica')
       .text('This is an official receipt for tax purposes.', centerX, footerY, { align: 'center' })
       .text('Ella Rises is a registered 501(c)(3) nonprofit organization.', centerX, footerY + 15, { align: 'center' })
       .text('For questions, please contact us at info@ellarises.org', centerX, footerY + 30, { align: 'center' });

    // Finalize PDF
    doc.end();

  } catch (error) {
    console.error('Receipt PDF error:', error);
    res.status(500).send('Error generating receipt');
  }
});

// Users route (protected, manager only)
app.get('/users', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }
    
    // Query all users from database
    const usersData = await db('users')
      .select('userid', 'useremail', 'userfirstname', 'userlastname', 'roleid', 'accountactive', 'totaldonations')
      .orderBy('userid', 'asc');
    
    // Map users data with role names and status
    const users = usersData.map(user => {
      let roleName = 'user';
      if (user.roleid === 1) roleName = 'manager';
      else if (user.roleid === 2) roleName = 'user';
      else if (user.roleid === 3) roleName = 'donor';
      
      return {
        userid: user.userid,
        email: user.useremail,
        firstName: user.userfirstname || '',
        lastName: user.userlastname || '',
        fullName: `${user.userfirstname || ''} ${user.userlastname || ''}`.trim() || 'No Name',
        role: roleName,
        roleid: user.roleid,
        status: user.accountactive ? 'active' : 'inactive',
        accountactive: user.accountactive,
        totaldonations: user.totaldonations
      };
    });
    
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };
    res.render('users', { user, users, query: req.query });
  } catch (error) {
    console.error('Users error:', error);
    res.redirect('/login');
  }
});

// Add User route - GET (protected, manager only)
app.get('/users/add', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    res.render('add-user', { user, query: req.query });
  } catch (error) {
    console.error('Add user page error:', error);
    res.redirect('/users?error=page_error');
  }
});

// Add User route - POST (protected, manager only)
app.post('/users/add', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.status(403).send('Forbidden');
    }

    const { useremail, userfirstname, userlastname, roleid, password, confirmPassword } = req.body;

    // Validate required fields
    if (!useremail || !userfirstname || !userlastname || !roleid || !password || !confirmPassword) {
      return res.redirect('/users/add?error=missing_fields');
    }

    // Validate password match
    if (password !== confirmPassword) {
      return res.redirect('/users/add?error=password_mismatch');
    }

    // Validate password length
    if (password.length < 6) {
      return res.redirect('/users/add?error=password_too_short');
    }

    // Check if email already exists
    const existingUser = await db('users')
      .where('useremail', useremail.toLowerCase())
      .first();

    if (existingUser) {
      return res.redirect('/users/add?error=email_exists');
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user with accountactive = false (Pending status)
    // This will require them to change password on first login
    try {
      const [newUser] = await db('users')
        .insert({
          useremail: useremail.toLowerCase(),
          userfirstname: userfirstname.trim(),
          userlastname: userlastname.trim(),
          userpassword: hashedPassword,
          roleid: parseInt(roleid),
          accountactive: false, // Set to Pending - will be activated after first login/password change
          totaldonations: null
        })
        .returning(['userid']);

      res.redirect('/users?success=user_created');
    } catch (insertError) {
      // Handle sequence sync issues
      if (insertError.code === '23505') { // Duplicate key error
        console.error('Sequence out of sync. Attempting to fix...');
        const maxResult = await db('users').max('userid as maxid').first();
        const maxId = maxResult?.maxid || 0;
        await db.raw(`SELECT setval('users_userid_seq', ?)`, [maxId + 1]);
        
        // Retry the insert
        const [newUser] = await db('users')
          .insert({
            useremail: useremail.toLowerCase(),
            userfirstname: userfirstname.trim(),
            userlastname: userlastname.trim(),
            userpassword: hashedPassword,
            roleid: parseInt(roleid),
            accountactive: false,
            totaldonations: null
          })
          .returning(['userid']);
        
        res.redirect('/users?success=user_created');
      } else {
        throw insertError;
      }
    }
  } catch (error) {
    console.error('Add user error:', error);
    res.redirect('/users/add?error=create_failed');
  }
});

// Edit user page route (protected, manager only)
app.get('/users/edit/:userid', requireAuth, async (req, res) => {
  try {
    // Check if user is manager
    if (req.session.userRole !== 'manager') {
      return res.redirect(getDefaultRedirect(req.session.userRole));
    }

    const userId = parseInt(req.params.userid);
    if (isNaN(userId)) {
      return res.redirect('/users?error=invalid_user_id');
    }

    // Fetch user from database
    const userData = await db('users')
      .where('userid', userId)
      .first();

    if (!userData) {
      return res.redirect('/users?error=user_not_found');
    }

    // Map roleid to role name
    let roleName = 'user';
    if (userData.roleid === 1) roleName = 'manager';
    else if (userData.roleid === 2) roleName = 'user';
    else if (userData.roleid === 3) roleName = 'donor';

    const user = {
      email: req.session.userEmail,
      role: req.session.userRole
    };

    const editUser = {
      userid: userData.userid,
      email: userData.useremail,
      firstName: userData.userfirstname || '',
      lastName: userData.userlastname || '',
      role: roleName,
      roleid: userData.roleid,
      accountactive: userData.accountactive
    };

    res.render('edit-user', { user, editUser, query: req.query });
  } catch (error) {
    console.error('Edit user page error:', error);
    res.redirect('/users?error=page_error');
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

    const { useremail, userfirstname, userlastname, roleid, accountactive, password } = req.body;

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
      if (password.length < 6) {
        return res.redirect(`/users/edit/${userId}?error=password_too_short`);
      }
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

    const { userid } = req.body;
    const userId = parseInt(userid);

    if (!userid || isNaN(userId)) {
      return res.status(400).send('Invalid request');
    }

    // Fetch user to verify they exist
    const userData = await db('users')
      .where('userid', userId)
      .first();

    if (!userData) {
      return res.redirect('/users?error=user_not_found');
    }

    // Don't allow deleting yourself
    if (userId === req.session.userId) {
      return res.redirect('/users?error=cannot_delete_yourself');
    }

    // Cascade delete: Delete from Users table - database handles cascade deletion
    // Donations table has ON DELETE SET NULL, so donations remain but are anonymized
    await db('users')
      .where('userid', userId)
      .del();

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

// Teapot endpoint (418 I'm a teapot)
app.get('/teapot', (req, res) => {
  res.status(418).send("I'm a teapot");
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

