require('dotenv').config();

// ============================================================================
// QUICK SWITCH: Set to 'local' or 'aws' to manually override auto-detection
// ============================================================================
const FORCE_MODE = null; // Options: 'local' | 'aws' | null (auto-detect)

// ============================================================================
// LOCAL DEVELOPMENT CONFIGURATION
// ============================================================================
const localConnection = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432', 10),
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'ella_rises',
  ssl: false, // No SSL for local development
};

// ============================================================================
// ELASTIC BEANSTALK / AWS RDS CONFIGURATION
// ============================================================================
const awsConnection = {
  // AWS RDS provides these environment variables automatically when linked to Elastic Beanstalk
  host: process.env.RDS_HOSTNAME || process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.RDS_PORT || process.env.DB_PORT || '5432', 10),
  user: process.env.RDS_USERNAME || process.env.DB_USER || 'postgres',
  password: process.env.RDS_PASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.RDS_DB_NAME || process.env.DB_NAME || 'ella_rises',
  ssl: { rejectUnauthorized: false }, // SSL required for AWS RDS
};

// ============================================================================
// AUTO-DETECTION LOGIC (only used if FORCE_MODE is null)
// ============================================================================
const detectEnvironment = () => {
  if (FORCE_MODE === 'local') return 'local';
  if (FORCE_MODE === 'aws') return 'aws';
  
  // Auto-detect: Check for AWS indicators
  const host = process.env.RDS_HOSTNAME || process.env.DB_HOST || 'localhost';
  const isAWS = !!(
    process.env.RDS_HOSTNAME || 
    process.env.RDS_DB_NAME || 
    process.env.AWS_EXECUTION_ENV ||
    host.includes('.rds.amazonaws.com') ||
    host.includes('.rds.')
  );
  
  return isAWS ? 'aws' : 'local';
};

// ============================================================================
// SELECT CONNECTION BASED ON MODE
// ============================================================================
const environment = detectEnvironment();
const connection = environment === 'aws' ? awsConnection : localConnection;

// Log which configuration is being used (helpful for debugging)
console.log(`📊 Database config: ${environment === 'aws' ? 'AWS RDS (Elastic Beanstalk)' : 'Local Development'}`);


module.exports = {
  client: 'pg',
  connection: connection,
  pool: {
    min: 2,
    max: 10,
    acquireTimeoutMillis: 30000,
    createTimeoutMillis: 30000,
    idleTimeoutMillis: 30000,
    reapIntervalMillis: 1000,
    createRetryIntervalMillis: 200,
  },
};