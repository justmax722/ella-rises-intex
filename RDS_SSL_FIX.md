# RDS SSL Connection Fix

## Problem
The error "no pg_hba.conf entry for host..., no encryption" occurs because AWS RDS PostgreSQL requires SSL/TLS connections, but the connection was being attempted without SSL.

## Solution Applied
✅ Updated `knexfile.js` to explicitly enable SSL when RDS environment variables are detected.

## What Changed
- SSL is now forced when `RDS_HOSTNAME` or `RDS_DB_NAME` environment variables are present
- Added logging to confirm when RDS connection with SSL is detected
- Ensured SSL configuration object is properly structured

## Additional Steps You May Need

### 1. Verify RDS Security Group
Your RDS security group must allow inbound connections on port 5432 from your Elastic Beanstalk security group.

### 2. Verify Database Name
The error shows database name "database-1". Make sure:
- Your RDS database is actually named "database-1" OR
- You have set the `RDS_DB_NAME` environment variable to match your actual database name

### 3. Check Environment Variables
In Elastic Beanstalk Console > Configuration > Software > Environment Properties, verify:
- `RDS_HOSTNAME` is set
- `RDS_PORT` is set (usually 5432)
- `RDS_USERNAME` is set (the error shows "admin")
- `RDS_PASSWORD` is set
- `RDS_DB_NAME` matches your actual database name

## After Redeployment

The connection should now use SSL and the authentication error should be resolved. Test by:
1. Visiting `/health` endpoint - should show database connected
2. Trying to create an account at `/login` - should work without SSL errors

