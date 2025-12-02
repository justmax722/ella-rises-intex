exports.up = function(knex) {
  return knex.schema.table('users', function(table) {
    table.string('first_name', 255).nullable();
    table.string('last_name', 255).nullable();
  });
};

exports.down = function(knex) {
  return knex.schema.table('users', function(table) {
    table.dropColumn('first_name');
    table.dropColumn('last_name');
  });
};
