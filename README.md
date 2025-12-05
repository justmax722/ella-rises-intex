# Ella Rises - Event Management System

A comprehensive web application for managing events, participants, donations, surveys, and milestones for the Ella Rises organization. The system supports multiple user roles with different access levels and provides a full-featured admin dashboard for managers.

### Login Information
Admin Email: admin@gmail.com
Admin Password: admin123

Participant Email: user@gmail.com
Participant Password: admin123

### To Test the Participant Account Claiming Process:
Email: noah.lee594@ellarises.org
Password: (no password)
Birthday: 1998-12-25
ZipCode: 84536

## Table of Contents

- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [User Roles & Permissions](#user-roles--permissions)
- [Core Features](#core-features)
- [How Things Work Together](#how-things-work-together)
- [Database Schema](#database-schema)
- [Getting Started](#getting-started)
- [Configuration](#configuration)

## Overview

Ella Rises is a Node.js/Express application that serves as a complete management system for a non-profit organization. It handles:

- **Event Management**: Creating, editing, and managing events with multiple sessions
- **Participant Registration**: Allowing users to register for events and track attendance
- **Survey System**: Collecting feedback from participants after events
- **Milestone Tracking**: Recording and tracking participant achievements
- **Donation Processing**: Handling donations with receipt generation
- **User Management**: Admin tools for managing users, participants, and their profiles
- **Analytics Dashboard**: Comprehensive statistics and metrics for administrators

## Tech Stack

### Backend
- **Node.js**: JavaScript runtime environment
- **Express.js**: Web application framework
- **Knex.js**: SQL query builder for PostgreSQL
- **PostgreSQL**: Relational database
- **express-session**: Session management for authentication
- **bcrypt**: Password hashing and security
- **PDFKit**: PDF generation for donation receipts
- **dotenv**: Environment variable management

### Frontend
- **EJS (Embedded JavaScript)**: Server-side templating engine
- **Tailwind CSS**: Utility-first CSS framework
- **PostCSS**: CSS processing
- **Vanilla JavaScript**: Client-side interactivity

### Deployment
- **AWS Elastic Beanstalk**: Application hosting
- **AWS RDS**: Managed PostgreSQL database

## Project Structure

```
ella-rises-intex/
├── index.js                 # Main application file with all routes and logic
├── knexfile.js              # Database configuration (local/AWS)
├── package.json             # Dependencies and scripts
├── tailwind.config.js       # Tailwind CSS configuration
├── postcss.config.js        # PostCSS configuration
├── database/                # Database scripts
│   └── create_users_table.sql
├── views/                   # EJS templates
│   ├── partials/           # Reusable components (sidebar, etc.)
│   ├── landing.ejs         # Public landing page
│   ├── login.ejs           # Login page
│   ├── home.ejs            # Dashboard/home page
│   ├── events.ejs          # Events listing
│   ├── event-details.ejs   # Individual event view
│   ├── participants.ejs    # Participants management
│   ├── surveys.ejs         # Survey management
│   ├── milestones.ejs     # Milestones management
│   ├── donations.ejs       # Donations listing
│   ├── users.ejs           # User management
│   └── ...                 # Other view files
└── public/                  # Static assets
    ├── css/                # Compiled CSS files
    └── images/             # Images and logos
```

## User Roles & Permissions

The system supports three user roles with different access levels:

### 1. Manager (Admin)
- **Full Access**: Can manage all aspects of the system
- **Features**:
  - Create, edit, and delete events
  - View and manage all participants
  - View all surveys and responses
  - Manage users (add, edit, delete)
  - View comprehensive analytics dashboard
  - Mark event attendance
  - Export donation receipts
  - View low registration events
  - Track milestone achievements

### 2. User (Participant)
- **Participant Access**: Can interact with events and their own data
- **Features**:
  - View and register for upcoming events
  - View their own event registrations
  - Complete surveys for attended events
  - View their own milestones
  - Edit their profile information
  - View their own donations (if applicable)

### 3. Donor
- **Limited Access**: Restricted to donation-related features
- **Features**:
  - View their own donations
  - Export donation receipts
  - Access is restricted from most other pages

## Core Features

### 1. Event Management

**Purpose**: Manage organization events with multiple sessions per event.

**How it works**:
- Managers create events with basic information (name, description, type, default capacity)
- Each event can have multiple sessions (specific date/time instances)
- Sessions have their own capacity, location, start/end times, and registration deadlines
- Participants can register for sessions
- Managers can mark attendance after events
- Past events display statistics (registration count, attendance rate, survey scores)

**Key Routes**:
- `GET /events` - List all events (upcoming/past tabs)
- `GET /events/:sessionId` - View event details
- `POST /events/create` - Create new session
- `POST /events/:sessionId/delete` - Delete session (cascades to surveys and registrations)
- `POST /events/:sessionId/register` - Register for event
- `POST /events/:sessionId/attendance` - Mark attendance

### 2. Participant Management

**Purpose**: Manage participant profiles and information.

**How it works**:
- Managers can view all participants in a table
- Participants can be viewed in detail (profile information)
- Managers can add milestones directly from participant view
- Profile information includes: name, email, DOB, phone, address, emergency contacts
- Participants can edit their own profiles

**Key Routes**:
- `GET /participants` - List all participants (manager only)
- `GET /participants/view/:userid` - View participant details
- `GET /participants/edit/:userid` - Edit participant (manager only)

### 3. Survey System

**Purpose**: Collect feedback from participants after events.

**How it works**:
- Managers create survey questions (metrics) that can be active/inactive
- After an event ends and attendance is marked, participants can complete surveys
- Surveys collect scores for each metric question
- Overall survey score is calculated as the average of all metric scores
- NPS (Net Promoter Score) bucket is assigned based on overall score
- Managers can view all survey responses with filtering options
- Survey data is stored in both `survey` table (individual metric scores) and `registration` table (overall score, NPS bucket, comments)

**Key Routes**:
- `GET /surveys` - View surveys (filtered by role)
- `GET /surveys/take/:sessionId` - Take survey for an event
- `POST /surveys/submit` - Submit survey responses
- `GET /surveys/questions` - Manage survey questions (manager only)

### 4. Milestone Tracking

**Purpose**: Track and celebrate participant achievements.

**How it works**:
- Managers define milestone types (e.g., "First Event", "10 Events Attended")
- Milestones can be added to participants manually
- System tracks milestone dates and displays them on participant profiles
- Home page shows milestone statistics (count this month, top 3 milestones)
- Managers can add milestones from the milestones page or participant view page

**Key Routes**:
- `GET /milestones` - View all milestones with filtering
- `POST /milestones/add` - Add milestone to participant
- `POST /milestones/delete` - Delete milestone

### 5. Donation System

**Purpose**: Process donations and generate receipts.

**How it works**:
- Public donation page allows anyone to donate
- Donations can be made via credit card, debit, PayPal, or bank transfer
- If donor email doesn't exist, a "shadow account" is created (inactive)
- Donations are recorded in the `donation` table
- User's `totaldonations` field is updated
- Receipts can be generated as PDFs
- Donors can claim their account after donating

**Key Routes**:
- `GET /donate` - Public donation page
- `POST /donate` - Process donation
- `GET /donations` - View donations (authenticated users)
- `GET /donations/receipt` - Generate PDF receipt

### 6. User Management

**Purpose**: Admin tools for managing system users.

**How it works**:
- Managers can view all users in the system
- Users can be added, edited, or deleted
- When adding a user, account starts as inactive
- User must claim account and set password
- Profile information can be added after account claim
- Account status (active/inactive) controls login access

**Key Routes**:
- `GET /users` - List all users (manager only)
- `GET /users/add` - Add new user form
- `POST /users/add` - Create new user
- `GET /users/edit/:userid` - Edit user form
- `POST /users/update/:userid` - Update user

### 7. Authentication & Account Management

**Purpose**: Secure user authentication and account setup.

**How it works**:
- Users log in with email and password
- Passwords are hashed using bcrypt
- Sessions are managed server-side with express-session
- New users created by admins start as inactive
- Users must claim account via email verification
- Password change required on first login for admin-created accounts
- Account claiming process links donation email to user account

**Key Routes**:
- `GET /login` - Login page
- `POST /login` - Authenticate user
- `GET /signup` - Signup page (for self-registration)
- `GET /account-claim` - Claim account page
- `POST /account-claim` - Verify and claim account
- `GET /change-password` - Change password page
- `POST /change-password` - Update password
- `POST /logout` - End session

## How Things Work Together

### Request Flow

1. **User makes request** → Express receives HTTP request
2. **Middleware processing**:
   - Static files served from `public/` directory
   - Request body parsed (form data or JSON)
   - Session checked (if route requires authentication)
   - Role checked (if route has role restrictions)
3. **Route handler executes**:
   - Database queries using Knex.js
   - Business logic processing
   - Data preparation for view
4. **View rendering**:
   - EJS template receives data
   - Template renders HTML with dynamic content
   - Response sent to client
5. **Client-side**:
   - HTML/CSS/JavaScript loads
   - Tailwind CSS styles applied
   - Interactive features (modals, forms) work via JavaScript

### Database Relationships

The system uses a relational database with the following key relationships:

```
Event (1) ──→ (many) Session
Session (1) ──→ (many) Registration
Session (1) ──→ (many) Survey
User (1) ──→ (many) Registration
User (1) ──→ (many) Survey
User (1) ──→ (many) Donation
User (1) ──→ (many) UserMilestone
MilestoneType (1) ──→ (many) UserMilestone
SurveyMetric (1) ──→ (many) Survey
```

### Key Workflows

#### Event Registration Flow
1. Participant views events page
2. Clicks "Register" on an event session
3. System checks capacity and existing registrations
4. Creates registration record with `registrationstatus = null` (active)
5. Participant sees confirmation
6. After event, manager marks attendance
7. Participant can complete survey
8. Survey scores stored and overall score calculated

#### Donation Flow
1. Donor visits public `/donate` page
2. Enters donation amount and payment method
3. System checks if email exists in database
4. If new: Creates shadow account (inactive)
5. Records donation and updates totals
6. Redirects to success page with claim link
7. Donor can claim account via email verification
8. After claiming, can set password and access system

#### Survey Submission Flow
1. Event ends and manager marks attendance
2. Participant sees pending survey on surveys page
3. Clicks "Take Survey"
4. System verifies: user registered AND attended
5. Shows active survey metrics/questions
6. Participant rates each metric (1-5 scale)
7. System calculates overall score (average)
8. Assigns NPS bucket (Promoter/Passive/Detractor)
9. Stores individual scores in `survey` table
10. Updates `registration` table with overall data

#### Session Deletion Flow (Cascade)
1. Manager clicks delete on event session
2. System deletes in order:
   - All survey responses for session
   - All registrations for session
   - The session itself
3. This prevents foreign key constraint violations

### Authentication & Authorization

**Session Management**:
- User logs in → Session created with `userId`, `userEmail`, `userRole`
- Session stored server-side, identified by cookie
- Cookie is httpOnly (prevents XSS) and secure in production (HTTPS only)
- Session expires after 24 hours of inactivity

**Route Protection**:
- `requireAuth` middleware: Checks if `req.session.userId` exists
- `restrictDonor` middleware: Redirects donors away from restricted pages
- Role checks in route handlers: Verify `req.session.userRole` for manager-only actions

**Password Security**:
- Passwords hashed with bcrypt (10 salt rounds)
- Never stored in plain text
- Password change required for admin-created accounts

## Database Schema

### Core Tables

**users**
- `userid` (PK)
- `useremail` (unique)
- `userpassword` (hashed)
- `userfirstname`, `userlastname`
- `roleid` (1=manager, 2=user, 3=donor)
- `accountactive` (boolean)
- `totaldonations` (decimal)

**event**
- `eventid` (PK)
- `eventtypeid` (FK → eventtype)
- `eventname`
- `eventdescription`
- `eventrecurrencepattern`
- `eventdefaultcapacity`

**session**
- `sessionid` (PK)
- `eventid` (FK → event)
- `eventdatetimestart`, `eventdatetimeend`
- `eventlocation`
- `eventcapacity`
- `eventregistrationdeadline`

**registration**
- `registrationid` (PK)
- `userid` (FK → users)
- `sessionid` (FK → session)
- `registrationstatus` (null = active, 'cancelled' = cancelled)
- `registrationattendedflag` (boolean)
- `registrationcheckintime`
- `registrationcreatedat`
- `overallsurveyscore`
- `surveynpsbucket`
- `surveycomments`
- `surveysubmissiondate`

**survey**
- `surveyid` (PK)
- `userid` (FK → users)
- `sessionid` (FK → session)
- `metricid` (FK → surveymetric)
- `surveyscore` (1-5)

**donation**
- `donationid` (PK)
- `userid` (FK → users)
- `donationno` (sequential per user)
- `donationamount`
- `donationdate`
- `donationmessage`

**usermilestone**
- `usermilestoneid` (PK)
- `userid` (FK → users)
- `milestoneid` (FK → milestonetype)
- `milestonedate`

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- PostgreSQL database
- npm or yarn

### Installation

1. Clone the repository:
```bash
git clone https://github.com/justmax722/ella-rises-intex.git
cd ella-rises-intex
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables (create `.env` file):
```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=ella_rises

# Session Secret (use a strong random string in production)
SESSION_SECRET=your-secret-key-here

# Port (optional, defaults to 8080)
PORT=8080
```

4. Set up the database:
   - Create PostgreSQL database named `ella_rises`
   - Run database migration scripts (if available)
   - Or manually create tables using SQL scripts

5. Build CSS (if using Tailwind):
```bash
npm run build:css
```

6. Start the server:
```bash
npm start
```

7. Access the application:
   - Open browser to `http://localhost:8080`
   - Landing page: `http://localhost:8080/`
   - Login: `http://localhost:8080/login`

### Development

- Watch CSS changes: `npm run watch:css`
- Run database migrations: `npm run migrate`
- Rollback migrations: `npm run migrate:rollback`

## Configuration

### Database Configuration (`knexfile.js`)

The application automatically detects the environment:
- **Local Development**: Uses `DB_*` environment variables, no SSL
- **AWS/Production**: Uses `RDS_*` environment variables, SSL enabled

You can force a mode by setting `FORCE_MODE` in `knexfile.js`:
```javascript
const FORCE_MODE = 'local'; // or 'aws' or null (auto-detect)
```

### Tailwind CSS

Custom configuration in `tailwind.config.js`:
- Custom color scheme (primary, secondary, etc.)
- Custom fonts
- Animation plugins

### Session Configuration

Sessions configured in `index.js`:
- 24-hour expiration
- httpOnly cookies (XSS protection)
- Secure cookies in production (HTTPS only)
- Server-side storage

## Additional Notes

### Error Handling

- Global error handling middleware catches unhandled errors
- Route-specific error handling with try/catch blocks
- User-friendly error messages via query parameters
- Console logging for debugging

### Security Considerations

- Passwords hashed with bcrypt
- SQL injection prevention via Knex.js parameterized queries
- XSS protection via httpOnly cookies and input sanitization
- CSRF protection via session-based authentication
- Role-based access control on all sensitive routes

### Performance

- Database connection pooling (min: 2, max: 10 connections)
- Indexed database columns for faster queries
- Static file serving for CSS/images
- Efficient JOIN queries for related data

### Special Features

- **418 Teapot Route**: `/teapot` returns HTTP 418 status (Easter egg)
- **Low Registration Alerts**: Admin dashboard shows events with <30% registration
- **Monthly Milestone Stats**: Tracks milestones achieved in the past month
- **Event Statistics**: Past events show comprehensive metrics (attendance, survey scores)

---

**Author**: Justin  
**License**: ISC  
**Repository**: https://github.com/justmax722/ella-rises-intex

