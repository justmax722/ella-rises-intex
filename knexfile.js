require('dotenv').config();

// Determine if we're connecting to AWS RDS
const isRDS = !!(process.env.RDS_HOSTNAME || process.env.RDS_DB_NAME);

// Build connection object
const connection = {
  // AWS RDS provides these environment variables automatically when linked to Elastic Beanstalk
  host: process.env.RDS_HOSTNAME || process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.RDS_PORT || process.env.DB_PORT || '5432', 10),
  user: process.env.RDS_USERNAME || process.env.DB_USER || 'postgres',
  password: process.env.RDS_PASSWORD || process.env.DB_PASSWORD || '',
  database: process.env.RDS_DB_NAME || process.env.DB_NAME || 'ella_rises',
};

// AWS RDS requires SSL connections - enable it when RDS variables are present
// Also enable SSL if we detect we're in AWS (checking for EC2 metadata or EB environment)
if (isRDS || process.env.AWS_EXECUTION_ENV || process.env.ELASTIC_BEANSTALK_ENVIRONMENT) {
  connection.ssl = {
    rejectUnauthorized: false
  };
  console.log('RDS connection detected - SSL enabled');
}

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
  migrations: {
    tableName: 'knex_migrations',
    directory: './migrations'
  }
};