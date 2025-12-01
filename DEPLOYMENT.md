# AWS Elastic Beanstalk Deployment Guide

## Prerequisites

1. AWS Account with Elastic Beanstalk and RDS access
2. PostgreSQL RDS instance created
3. Node.js application ready

## Step 1: Set up AWS RDS Database

1. Create a PostgreSQL RDS instance in AWS
2. Note down:
   - Database endpoint (hostname)
   - Database port (usually 5432)
   - Database name
   - Master username
   - Master password

## Step 2: Configure Environment Variables in Elastic Beanstalk

In the Elastic Beanstalk console, go to Configuration > Software > Environment properties and add:

### Required Environment Variables:

```
RDS_HOSTNAME=<your-rds-endpoint>
RDS_PORT=5432
RDS_USERNAME=<your-db-username>
RDS_PASSWORD=<your-db-password>
RDS_DB_NAME=<your-database-name>
SESSION_SECRET=<generate-a-random-secret-string>
NODE_ENV=production
PORT=8080
```

**OR** if your RDS is linked to Elastic Beanstalk, these variables are automatically provided:
- RDS_HOSTNAME
- RDS_PORT
- RDS_USERNAME
- RDS_PASSWORD
- RDS_DB_NAME

You still need to set:
- SESSION_SECRET (generate a random string)
- NODE_ENV=production
- PORT=8080

## Step 3: Link RDS to Elastic Beanstalk (Recommended)

1. In Elastic Beanstalk console, go to your environment
2. Configuration > Database
3. Click "Edit"
4. Create a new RDS DB instance or use an existing one
5. This automatically provides RDS environment variables

## Step 4: Prepare Your Application for Deployment

### Files to include in your ZIP:

```
ella-rises-intex/
├── .ebextensions/        (Elastic Beanstalk configs)
│   ├── 01-database.config
│   └── 02-migrations.config
├── migrations/           (Database migrations)
│   └── create_users_table.js
├── views/               (EJS templates)
├── public/              (Static files)
├── index.js             (Main application)
├── knexfile.js          (Database config)
├── package.json         (Dependencies)
├── Procfile             (Start command)
└── (exclude node_modules - will be installed on EB)
```

### Files to EXCLUDE from ZIP:

- `node_modules/` (installed automatically)
- `.env` (use EB environment variables instead)
- `.git/`
- Any local development files

## Step 5: Create Deployment ZIP

On Windows (PowerShell):
```powershell
# Navigate to project directory
cd C:\Users\justi\Desktop\ella-rises-intex

# Create ZIP excluding node_modules and .git
Compress-Archive -Path * -DestinationPath ../ella-rises-deploy.zip -Force
```

Or use a tool like 7-Zip or WinRAR to create a ZIP file manually.

## Step 6: Deploy to Elastic Beanstalk

1. Go to AWS Elastic Beanstalk Console
2. Create a new application or select existing one
3. Create a new environment:
   - Platform: Node.js
   - Platform version: Latest
   - Application code: Upload your code (choose the ZIP file)
4. Configure more options:
   - Software: Set environment variables (see Step 2)
   - Database: Link to RDS instance (see Step 3)
5. Create environment

## Step 7: Verify Deployment

1. Wait for deployment to complete (5-10 minutes)
2. Check logs for any errors:
   - Go to Logs > Request Logs > Last 100 Lines
3. Visit your application URL
4. Test signup:
   - Go to `/login`
   - Fill out signup form
   - Select a role
   - Create account
   - Should redirect to dashboard showing your role

## Troubleshooting

### Database Connection Issues

1. Check environment variables are set correctly
2. Verify RDS security group allows connections from Elastic Beanstalk
3. Check RDS endpoint is correct (include port if needed)

### Migration Errors

1. Check logs: `/var/log/eb-engine.log`
2. Verify migrations folder is included in ZIP
3. Manually run migrations if needed:
   - SSH into instance
   - Run `npm run migrate`

### Application Won't Start

1. Check `/var/log/nodejs/nodejs.log`
2. Verify PORT environment variable (EB uses 8080)
3. Check Procfile is correct

## Post-Deployment

1. **Test User Creation**: Create a test account to verify database connection
2. **Check Health Endpoint**: Visit `https://your-app-url/health` to verify database connection
3. **Monitor Logs**: Regularly check CloudWatch logs for errors
4. **Set up HTTPS**: Configure SSL certificate in Load Balancer settings

## Security Checklist

- [x] Passwords are hashed with bcrypt
- [ ] SESSION_SECRET is a strong random string
- [ ] HTTPS is enabled (update cookie secure flag)
- [ ] Database credentials are in environment variables, not code
- [ ] RDS is not publicly accessible (use security groups)

## Environment Variables Reference

| Variable | Description | Example |
|----------|-------------|---------|
| RDS_HOSTNAME | RDS endpoint hostname | `mydb.abc123.us-east-1.rds.amazonaws.com` |
| RDS_PORT | RDS port | `5432` |
| RDS_USERNAME | Database username | `postgres` |
| RDS_PASSWORD | Database password | `yourpassword` |
| RDS_DB_NAME | Database name | `ella_rises` |
| SESSION_SECRET | Random string for sessions | Generate with: `openssl rand -base64 32` |
| NODE_ENV | Environment | `production` |
| PORT | Application port | `8080` (EB default) |

