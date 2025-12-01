# Quick Start: AWS Elastic Beanstalk + RDS Setup

## What's Been Configured

✅ **Password Hashing**: All passwords are now hashed with bcrypt  
✅ **Database Migrations**: Automatic migration on deployment  
✅ **AWS RDS Support**: Automatically detects and connects to RDS  
✅ **Environment Variables**: Configured for Elastic Beanstalk  
✅ **Error Handling**: Database connection checks and health endpoint  
✅ **Production Ready**: Secure session cookies, SSL support  

## Critical Steps for Deployment

### 1. Set Environment Variables in Elastic Beanstalk

Go to: **Configuration > Software > Environment Properties**

**Required Variables:**
```
SESSION_SECRET=<generate-random-string>
NODE_ENV=production
```

**If RDS is NOT linked to EB, also add:**
```
RDS_HOSTNAME=your-db-endpoint.region.rds.amazonaws.com
RDS_PORT=5432
RDS_USERNAME=your-db-username
RDS_PASSWORD=your-db-password
RDS_DB_NAME=your-database-name
```

### 2. Link RDS to Elastic Beanstalk (EASIEST)

**Recommended approach:**
1. In EB Console: **Configuration > Database**
2. Click **Edit**
3. Choose **Create new RDS database** or **Attach existing RDS database**
4. This automatically provides all RDS environment variables

### 3. Security Group Configuration

Make sure your RDS security group allows inbound PostgreSQL (port 5432) from your Elastic Beanstalk security group.

### 4. Create Deployment ZIP

**PowerShell command:**
```powershell
# From your project directory
Get-ChildItem -Path . -Exclude node_modules,.git,*.zip | Compress-Archive -DestinationPath ../ella-rises-deploy.zip -Force
```

**Or manually:**
- Select all files/folders EXCEPT: `node_modules`, `.git`, `*.zip`
- Right-click > Send to > Compressed folder

### 5. Deploy

1. Upload ZIP to Elastic Beanstalk
2. Wait for deployment (5-10 minutes)
3. Check logs for errors
4. Visit your app URL
5. Test signup at `/login`

## Testing User Creation

1. Go to `https://your-app-url/login`
2. Fill out the **Sign Up** form:
   - Email: `test@example.com`
   - Password: `test123`
   - Role: Select one (manager/user/donor)
3. Click **Create Account**
4. Should redirect to dashboard showing your role

## Verify It Works

✅ Visit `/health` - Should return: `{"status":"healthy","database":"connected"}`  
✅ Create a test account - Should successfully signup and login  
✅ Check dashboard - Should display your role correctly  

## Troubleshooting

### Database Connection Failed
- Check RDS security group allows EB security group
- Verify environment variables are set correctly
- Check RDS endpoint is correct

### Migration Errors
- Check logs: `/var/log/eb-engine.log`
- Manually SSH into instance and run: `npm run migrate`

### App Won't Start
- Check: `/var/log/nodejs/nodejs.log`
- Verify PORT is set to 8080 (EB default)

## Important Notes

1. **Passwords are hashed** - Old plain-text passwords won't work
2. **Migrations run automatically** - On first deployment
3. **Database is checked on startup** - App verifies connection
4. **Health endpoint available** - `/health` for monitoring

## Files Included in Deployment

All necessary files are ready:
- ✅ `Procfile` - Tells EB how to start the app
- ✅ `.ebextensions/` - EB configuration files
- ✅ `migrations/` - Database migration files
- ✅ `.ebignore` - Excludes unnecessary files

## Next Steps After Deployment

1. Set up HTTPS/SSL certificate
2. Configure custom domain
3. Set up monitoring/alerting
4. Test all user roles (manager, user, donor)
5. Review security best practices

