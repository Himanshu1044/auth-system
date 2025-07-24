import env from 'dotenv'
import pg from 'pg'
env.config()
const db = new pg.Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false, // needed for Render PostgreSQL
    },
});

export default db;


