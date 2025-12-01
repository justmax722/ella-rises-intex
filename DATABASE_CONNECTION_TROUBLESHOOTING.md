# Database Connection Troubleshooting Guide

## Current Error
```
no pg_hba.conf entry for host "172.31.47.91", user "admin", database "database-1", no encryption
```

## Root Cause
AWS RDS PostgreSQL requires SSL/TLS encrypted connections. The connection is being attempted without SSL.

## Solution Applied
✅ Updated `knexfile.js` to automatically enable SSL when:
- RDS environment variables are detected (`RDS_HOSTNAME` or `RDS_DB_NAME`)
- Running in AWS environment (detected via `AWS_EXECUTION_ENV` or `ELASTIC_BEANSTALK_ENVIRONMENT`)

## Additional Issues to Check

### 1. Database Name Mismatch
The error shows it's trying to connect to database `"database-1"`. Verify:

**Check your RDS instance:**
- What is the actual database name in your RDS instance?
- Is it `database-1` or something else?

**In Elastic Beanstalk Environment Properties, verify:**
- `RDS_DB_NAME` matches your actual database name
- If your database is named something other than `database-1`, update the environment variable

**To create a database in RDS (if needed):**
1. Connect to your RDS instance using a database client (pgAdmin, DBeaver, etc.)
2. Create a database named `ella_rises` (or your preferred name)
3. Update `RDS_DB_NAME` environment variable in Elastic Beanstalk

### 2. Security Group Configuration
Your RDS security group must allow inbound connections:

1. Go to AWS Console > RDS > Your Database Instance
2. Click on the **Security** tab
3. Click on the Security Group (VPC security groups)
4. Click **Edit inbound rules**
5. Add rule:
   - **Type**: PostgreSQL
   - **Port**: 5432
   - **Source**: Select the security group of your Elastic Beanstalk environment

**To find your EB security group:**
- Go to Elastic Beanstalk > Your Environment > Configuration > Instances
- Look for "EC2 security groups"
- Use that security group ID in the RDS inbound rule

### 3. Verify Environment Variables
In Elastic Beanstalk Console > Configuration > Software > Environment Properties, ensure you have:

```
RDS_HOSTNAME=<your-rds-endpoint>
RDS_PORT=5432
RDS_USERNAME=admin (or your username)
RDS_PASSWORD=<your-password>
RDS_DB_NAME=database-1 (or your actual database name)
```

**Important**: The database name must match exactly what exists in your RDS instance.

### 4. Test Connection
After redeploying with the SSL fix, check:

1. **Health endpoint**: `https://your-app-url/health`
   - Should return: `{"status":"healthy","database":"connected"}`

2. **Application logs**: Check `/var/log/web.stdout.log` for:
   - `✓ Database connection successful`
   - No SSL errors

3. **Try creating an account**: Go to `/login` and sign up

## Next Steps

1. ✅ **Fix applied**: SSL is now automatically enabled
2. ⚠️ **Action required**: Verify/update database name in environment variables
3. ⚠️ **Action required**: Check RDS security group allows EB security group
4. 🔄 **Redeploy**: Create new ZIP and redeploy
5. ✅ **Test**: Verify connection works

## Creating the Database (if needed)

If your RDS instance doesn't have the correct database:

**Option 1: Using pgAdmin or similar tool**
1. Connect to your RDS instance
2. Create database: `CREATE DATABASE ella_rises;`
3. Update `RDS_DB_NAME=ella_rises` in EB environment variables

**Option 2: Using AWS RDS Console**
- RDS creates a default database with the name you specified during instance creation
- Check what that name is and ensure `RDS_DB_NAME` matches it

