const mysql = require('mysql2');

const pool = mysql.createPool({
    host: process.env.JAWSDB_HOST,
    user: process.env.JAWSDB_USER,
    password: process.env.JAWSDB_PASSWORD,
    database: process.env.JAWSDB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

module.exports = pool.promise();