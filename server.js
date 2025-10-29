const express = require('express');
const cors = require('cors');
const cron = require('node-cron');
require('dotenv').config();
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS Configuration
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());
app.use('/uploads', express.static('uploads'));

// Database Connection
const pool = process.env.DATABASE_URL 
    ? new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
    })
    : new Pool({
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        password: process.env.DB_PASSWORD,
        port: process.env.DB_PORT,
    });

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('❌ Database connection error:', err);
    } else {
        console.log('✅ Database connected successfully at:', res.rows[0].now);
    }
});

app.set('db', pool);

// ==================== AUTOMATIC CLEANUP CRON JOB ====================
// Run daily at 3:00 AM to clean up old activity logs
cron.schedule('0 3 * * *', async () => {
    try {
        console.log('🧹 Running scheduled activity log cleanup...');
        
        // Get retention setting
        const settingResult = await pool.query(
            "SELECT setting_value FROM settings WHERE setting_key = 'activity_log_retention_days'"
        );
        
        const retentionDays = settingResult.rows.length > 0 
            ? parseInt(settingResult.rows[0].setting_value) 
            : 30;

        // Delete old activities
        const result = await pool.query(
            `DELETE FROM activity_log 
             WHERE created_at < NOW() - INTERVAL '${retentionDays} days'`
        );

        console.log(`✅ Cleanup complete: ${result.rowCount} old activity logs deleted (older than ${retentionDays} days)`);
    } catch (error) {
        console.error('❌ Error in scheduled cleanup:', error);
    }
}, {
    scheduled: true,
    timezone: "Asia/Kolkata" // Indian timezone
});

console.log('⏰ Automatic cleanup scheduled: Daily at 3:00 AM IST');

// ==================== ROUTES ====================
const routes = require('./routes');
app.use('/api', routes);

// Test endpoints
app.get('/api/test', (req, res) => {
    res.json({ message: 'Server is working!', timestamp: new Date() });
});

app.get('/api/test-db', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({ message: 'Database connected!', time: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Error handler
app.use((err, req, res, next) => {
    console.error('❌ Error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🌐 API URL: http://localhost:${PORT}/api`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🛑 SIGTERM signal received: closing HTTP server');
    await pool.end();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🛑 SIGINT signal received: closing HTTP server');
    await pool.end();
    process.exit(0);
});
