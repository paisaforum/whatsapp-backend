const jwt = require('jsonwebtoken');

// JWT Secret - from environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'temp-secret-change-in-production-1234567890abcdef';

// Middleware to verify user token
const authenticateUser = (req, res, next) => {
    try {
        // Get token from Authorization header: "Bearer TOKEN"
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        const token = authHeader.split(' ')[1]; // Extract token after "Bearer "
        
        if (!token) {
            return res.status(401).json({ error: 'Authentication required' });
        }
        
        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Attach userId to request object
        req.userId = decoded.userId;
        req.whatsappNumber = decoded.whatsappNumber;
        
        next(); // Continue to the route handler
        
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired, please login again' });
        }
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Middleware to verify admin token
const authenticateAdmin = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader) {
            return res.status(401).json({ error: 'Admin authentication required' });
        }
        
        const token = authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ error: 'Admin authentication required' });
        }
        
        // Verify token
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Check if user is admin
        if (!decoded.isAdmin) {
            return res.status(403).json({ error: 'Admin access required' });
        }
        
        // ⬇️ FIX: Attach admin object to request (not individual properties)
        req.admin = {
            adminId: decoded.adminId,
            username: decoded.username,
            role: decoded.role || 'admin',  // ← ADD: Include role from token
            isAdmin: decoded.isAdmin
        };
        
        next();
        
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired, please login again' });
        }
        return res.status(401).json({ error: 'Invalid admin token' });
    }
};

module.exports = { 
    authenticateUser, 
    authenticateAdmin, 
    JWT_SECRET 
};
