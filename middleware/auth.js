const jwt = require('jsonwebtoken');

// JWT Secret - from environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'temp-secret-change-in-production-1234567890abcdef';

// Middleware to verify user token
const authenticateUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const token = authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        // Check if token is blacklisted
        const pool = req.app?.get('db');
        if (pool) {
            const blacklisted = await pool.query(
                'SELECT id FROM token_blacklist WHERE token = $1 AND expires_at > NOW()',
                [token]
            );
            
            if (blacklisted.rows.length > 0) {
                return res.status(401).json({ error: 'Token has been revoked' });
            }
        }
        
        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET);
        
        req.userId = decoded.userId;
        req.whatsappNumber = decoded.whatsappNumber;
        
        next();
        
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired, please login again' });
        }
        return res.status(401).json({ error: 'Invalid token' });
    }
};

const authenticateAdmin = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.substring(7);
        
        // ⬇️ NEW: Check if token is blacklisted
        const pool = req.app?.get('db');
        if (pool) {
            const blacklisted = await pool.query(
                'SELECT id FROM token_blacklist WHERE token = $1 AND expires_at > NOW()',
                [token]
            );
            
            if (blacklisted.rows.length > 0) {
                return res.status(401).json({ error: 'Token has been revoked' });
            }
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);

        req.admin = {
            id: decoded.adminId,
            adminId: decoded.adminId,
            username: decoded.username,
            role: decoded.role || 'admin',
            isAdmin: decoded.isAdmin
        };

        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};
module.exports = { 
    authenticateUser, 
    authenticateAdmin, 
    JWT_SECRET 
};
