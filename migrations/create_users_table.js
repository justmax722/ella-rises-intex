exports.up = function(knex) {
  return knex.schema.createTable('users', function(table) {
    table.increments('id').primary();
    table.string('email', 255).notNullable().unique();
    table.string('password', 255).notNullable();
    table.string('user_role', 50).notNullable();
    table.timestamps(true, true); // created_at and updated_at
  })
  .then(function() {
    // Add CHECK constraint for user_role
    return knex.schema.raw("ALTER TABLE users ADD CONSTRAINT check_user_role CHECK (user_role IN ('manager', 'user', 'donor'))");
  })
  .then(function() {
    // Create indexes for better performance
    return knex.schema.raw('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)');
  })
  .then(function() {
    return knex.schema.raw('CREATE INDEX IF NOT EXISTS idx_users_role ON users(user_role)');
  });
};

exports.down = function(knex) {
  return knex.schema.dropTableIfExists('users');
};