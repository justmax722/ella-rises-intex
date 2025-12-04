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
        req.session.userFirstName = demoAccount.role === 'manager' ? 'Demo' : 'Demo';
        req.session.userLastName = demoAccount.role === 'manager' ? 'Manager' : 'User';
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
    req.session.userFirstName = user.userfirstname || '';
    req.session.userLastName = user.userlastname || '';

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
          role: req.session.userRole,
          firstName: req.session.userRole === 'manager' ? 'Demo' : 'Demo',
          lastName: req.session.userRole === 'manager' ? 'Manager' : 'User'
        }
      });
    }

    // Handle regular database users
    // We already have user info in session from login, no need to query again
    // But if we did, we'd use userid (lowercase), not id
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

// Participants route (protected)
app.get('/participants', requireAuth, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
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
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
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
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
    };

    // Get all survey metrics (these will be the dynamic columns)
    const surveyMetrics = await db('surveymetric')
      .select('metricid', 'surveymetric')
      .orderBy('metricid');

    // Get all survey data - start from survey table since that has the metric scores
    const rawSurveyData = await db('survey as sv')
      .join('users as u', 'sv.userid', 'u.userid')
      .join('session as s', 'sv.sessionid', 's.sessionid')
      .join('event as e', 's.eventid', 'e.eventid')
      .leftJoin('registration as r', function() {
        this.on('sv.userid', '=', 'r.userid')
            .andOn('sv.sessionid', '=', 'r.sessionid');
      })
      .select(
        'sv.userid',
        'sv.sessionid',
        'sv.metricid',
        'sv.surveyscore',
        'u.userfirstname',
        'u.userlastname',
        'e.eventname',
        's.eventdatetimestart',
        'r.surveycomments',
        'r.surveynpsbucket',
        'r.surveysubmissiondate',
        'r.overallsurveryscore'
      )
      .orderBy('sv.userid')
      .orderBy('sv.sessionid');

    // Pivot the data: group by userid+sessionid, with metric scores as columns
    const pivotedData = {};
    for (const row of rawSurveyData) {
      const key = `${row.userid}-${row.sessionid}`;
      if (!pivotedData[key]) {
        pivotedData[key] = {
          userid: row.userid,
          sessionid: row.sessionid,
          participantName: `${row.userfirstname || ''} ${row.userlastname || ''}`.trim(),
          eventName: row.eventname,
          eventDate: row.eventdatetimestart,
          overallScore: row.overallsurveryscore,
          surveyComments: row.surveycomments,
          npsBucket: row.surveynpsbucket,
          submittedAt: row.surveysubmissiondate,
          metricScores: {}
        };
      }
      // Add the metric score to this row (pivot)
      if (row.metricid !== null) {
        pivotedData[key].metricScores[row.metricid] = row.surveyscore;
      }
    }

    // Convert to array and sort by submission date (most recent first)
    const surveyResponses = Object.values(pivotedData).sort((a, b) => {
      if (!a.submittedAt) return 1;
      if (!b.submittedAt) return -1;
      return new Date(b.submittedAt) - new Date(a.submittedAt);
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

    // Score distribution for chart based on average metric score per response
    const scoreDistribution = { '0-3': 0, '4-6': 0, '7-8': 0, '9-10': 0 };
    for (const response of surveyResponses) {
      const scores = Object.values(response.metricScores);
      if (scores.length > 0) {
        const avgScore = scores.reduce((a, b) => a + (parseFloat(b) || 0), 0) / scores.length;
        if (avgScore <= 3) scoreDistribution['0-3']++;
        else if (avgScore <= 6) scoreDistribution['4-6']++;
        else if (avgScore <= 8) scoreDistribution['7-8']++;
        else scoreDistribution['9-10']++;
      }
    }

    res.render('surveys', { 
      user,
      surveyMetrics,
      surveyResponses,
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

// Milestones route (protected, no donor access)
app.get('/milestones', requireAuth, restrictDonor, async (req, res) => {
  try {
    const user = {
      email: req.session.userEmail,
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
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
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
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
      role: req.session.userRole,
      firstName: req.session.userFirstName || '',
      lastName: req.session.userLastName || ''
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

    const { email, role, password } = req.body;

    if (!email || !role || !['manager', 'user', 'donor'].includes(role)) {
      return res.status(400).send('Invalid request');
    }

    // Don't allow updating demo accounts
    if (email === 'manager@ellarises.org' || email === 'user@ellarises.org') {
      return res.redirect('/users?error=demo_accounts_cannot_be_modified');
    }

    // Map role string to roleid
    let roleid;
    if (role === 'manager') {
      roleid = 1;
    } else if (role === 'user') {
      roleid = 2;
    } else if (role === 'donor') {
      roleid = 3;
    } else {
      return res.status(400).send('Invalid role');
    }

    // Build update object
    const updateData = {
      roleid: roleid
    };

    // If password is provided, hash it and set password (but keep account inactive)
    // User will be forced to change password on first login
    if (password && password.trim() !== '') {
      if (password.length < 6) {
        return res.redirect('/users?error=password_too_short');
      }
      
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      updateData.userpassword = hashedPassword;
      // Keep account inactive - user must change password to activate
      updateData.accountactive = false;
    }

    // Update user in database (using lowercase column names)
    await db('users')
      .where('useremail', email.toLowerCase())
      .update(updateData);

    if (password && password.trim() !== '') {
      res.redirect('/users?success=user_updated_with_password');
    } else {
      res.redirect('/users?success=role_updated');
    }
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

