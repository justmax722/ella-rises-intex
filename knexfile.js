require('dotenv').config();

module.exports = {
  client: 'pg',
  connection: {
    // Check AWS variables first (RDS_...), then fall back to local (.env)
    host: process.env.RDS_HOSTNAME || process.env.DB_HOST || 'localhost',
    port: process.env.RDS_PORT || process.env.DB_PORT || 5432,
    user: process.env.RDS_USERNAME || process.env.DB_USER || 'postgres',
    password: process.env.RDS_PASSWORD || process.env.DB_PASSWORD || '',
    database: process.env.RDS_DB_NAME || process.env.DB_NAME || 'ella_rises',
  },
  pool: {
    min: 2,
    max: 10
  },
  migrations: {
    tableName: 'knex_migrations'
  }
};