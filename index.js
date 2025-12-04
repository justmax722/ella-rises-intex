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
  
  // Check if redirecting from login with non-existent email
  const showSignUp = req.query.signup === 'true';
  const signupEmail = req.session.signupEmail || null;
  const signupPassword = req.session.signupPassword || null;
  const signupMessage = req.session.signupMessage || null;
  
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
    signupEmail: signupEmail,
    signupPassword: signupPassword,
    signupMessage: signupMessage
  });
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

    // Check if email already exists in users table
    const existingUser = await db('users')
      .where('useremail', email.toLowerCase())
      .first();

    // Check if user exists and is active
    if (existingUser && existingUser.accountactive === true) {
      return res.render('login', {
        error: 'Email already registered. Please login instead.',
        success: null,
        showSignUp: true
      });
    }

    // Check if user exists but is inactive and has a profile
    if (existingUser && existingUser.accountactive === false) {
      const existingProfile = await db('profile')
        .where('userid', existingUser.userid)
        .first();
      
      if (existingProfile) {
        return res.render('login', {
          error: 'Account exists but is inactive. Please contact support.',
          success: null,
          showSignUp: true
        });
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
      return res.render('login', {
        error: 'An error occurred. Please try again.',
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
      showSignUp: true
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

// Profile route (GET) - for completing profile during signup
app.get('/profile', requireSignupSession, (req, res) => {
  res.render('profile', { 
    error: null,
    user: {
      email: req.session.tempUserEmail,
      firstName: req.session.tempUserFirstName,
      lastName: req.session.tempUserLastName
    }
  });
});

// Profile route (POST) - save profile and activate account
app.post('/profile', requireSignupSession, async (req, res) => {
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

    const userId = req.session.tempUserId;

    // Clean phone number - remove formatting characters for storage
    const cleanPhone = profilephone.replace(/\D/g, '');

    // Insert profile data - only the combined date field, not the separate month/day/year
    await db('profile')
      .insert({
        userid: userId,
        profiledob: dateOfBirth, // Combined date in YYYY-MM-DD format
        profilephone: cleanPhone,
        profilecity: profilecity,
        profilestate: profilestate,
        profilezip: profilezip,
        profileschooloremployer: profileschooloremployer,
        profilefieldofinterest: profilefieldofinterest
        // Note: dob_month, dob_day, dob_year are NOT inserted - only the combined profiledob
      });

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

    // Clear temp session variables
    delete req.session.tempUserId;
    delete req.session.tempUserEmail;
    delete req.session.tempUserFirstName;
    delete req.session.tempUserLastName;

    // Redirect to dashboard
    res.redirect('/dashboard');
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
        maxAttemptsReached: false
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
        maxAttemptsReached: req.session.claimAttempts >= 5
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
          maxAttemptsReached: true
        });
      } else {
        return res.render('account-claim', {
          error: `Verification failed. Please check your date of birth and zip code. ${remainingAttempts} attempt(s) remaining.`,
          email: req.session.claimEmail,
          remainingAttempts: remainingAttempts,
          maxAttemptsReached: false
        });
      }
    }
  } catch (error) {
    console.error('Account claim error:', error);
    return res.render('account-claim', {
      error: 'An error occurred during verification. Please try again.',
      email: req.session.claimEmail,
      remainingAttempts: 5 - (req.session.claimAttempts || 0),
      maxAttemptsReached: (req.session.claimAttempts || 0) >= 5
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
    return res.redirect('/dashboard');
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
      return res.redirect('/dashboard');
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
    
    // Redirect to dashboard
    res.redirect('/dashboard');
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
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Set password error:', error);
    return res.render('set-password', {
      error: 'An error occurred while setting your password. Please try again.',
      email: req.session.claimUserEmail
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
          showSignUp: false
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

