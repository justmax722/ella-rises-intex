require('dotenv').config();

// Determine if we're connecting to AWS RDS
const isRDS = process.env.RDS_HOSTNAME || process.env.RDS_DB_NAME;

module.exports = {
  client: 'pg',
  connection: {
    // AWS RDS provides these environment variables automatically when linked to Elastic Beanstalk
    host: process.env.RDS_HOSTNAME || process.env.DB_HOST || 'localhost',
    port: process.env.RDS_PORT || process.env.DB_PORT || 5432,
    user: process.env.RDS_USERNAME || process.env.DB_USER || 'postgres',
    password: process.env.RDS_PASSWORD || process.env.DB_PASSWORD || '',
    database: process.env.RDS_DB_NAME || process.env.DB_NAME || 'ella_rises',
    // Enable SSL for RDS connections (required by AWS)
    ssl: isRDS ? { rejectUnauthorized: false } : false,
  },
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