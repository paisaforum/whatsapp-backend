const multer = require('multer');
const path = require('path');
const fs = require('fs');
const express = require('express');
const crypto = require('crypto');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { authenticateUser, authenticateAdmin, JWT_SECRET } = require('./middleware/auth');
// Middleware to check if admin is super_admin
const requireSuperAdmin = (req, res, next) => {
    if (req.admin.role !== 'super_admin') {
        return res.status(403).json({ error: 'Access denied. Super admin only.' });
    }
    next();
};

// Permission checking middleware - FIXED VERSION
const checkPermission = (requiredPermission) => {
    return async (req, res, next) => {
        try {
            // Super admin has all permissions
            if (req.admin.role === 'super_admin') {
                return next();
            }

            // Get database pool
            const pool = req.app.get('db');  // ⬅️ FIX: Get pool from req.app

            // Check if admin has the required permission
            const result = await pool.query(
                'SELECT permission FROM admin_permissions WHERE admin_id = $1',
                [req.admin.id]
            );

            const permissions = result.rows.map(row => row.permission);

            if (!permissions.includes(requiredPermission)) {
                return res.status(403).json({ error: 'Access denied. Insufficient permissions.' });
            }

            next();
        } catch (error) {
            console.error('Permission check error:', error);
            res.status(500).json({ error: 'Permission check failed' });
        }
    };
};

// Activity logging helper
const logAdminActivity = async (pool, adminId, action, details) => {
    try {
        await pool.query(
            'INSERT INTO admin_activity_logs (admin_id, action, details) VALUES ($1, $2, $3)',
            [adminId, action, details]
        );
    } catch (error) {
        console.error('Failed to log activity:', error);
        // Don't throw - logging failure shouldn't break the main action
    }
};


// File upload configuration - Organized by type
const uploadsDir = './uploads';
const bannersDir = './uploads/banners';
const offersDir = './uploads/offers';
const submissionsDir = './uploads/submissions';

// Ensure all directories exist
[uploadsDir, bannersDir, offersDir, submissionsDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Banner storage
const bannerStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/banners/'),
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

// Offer storage
const offerStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/offers/'),
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

// Submission storage
const submissionStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/submissions/'),
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

// Create upload middleware
const uploadBanner = multer({
    storage: bannerStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only images allowed'));
    }
});

const uploadOffer = multer({
    storage: offerStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only images allowed'));
    }
});

const uploadSubmission = multer({
    storage: submissionStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only images allowed'));
    }
});

// Backwards compatibility
const upload = uploadSubmission;



// Helper function to hash phone numbers
function hashPhoneNumber(phoneNumber) {
    return crypto.createHash('sha256').update(phoneNumber).digest('hex');
}

// Register new user
router.post('/register', async (req, res) => {
    const { whatsappNumber, password } = req.body;

    if (!whatsappNumber || !password) {
        return res.status(400).json({ error: 'WhatsApp number and password are required' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    try {
        const pool = req.app.get('db');

        // Check if user already exists
        const existingUser = await pool.query(
            'SELECT id FROM users WHERE whatsapp_number = $1',
            [whatsappNumber]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: 'Account with this number already exists. Please login.' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = await pool.query(
            'INSERT INTO users (whatsapp_number, password_hash) VALUES ($1, $2) RETURNING id',
            [whatsappNumber, passwordHash]
        );

        // Create JWT token
        const token = jwt.sign({ userId: newUser.rows[0].id }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            userId: newUser.rows[0].id,
            token: token,
            message: 'Account created successfully!'
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login user
router.post('/login', async (req, res) => {
    const { whatsappNumber, password } = req.body;

    if (!whatsappNumber || !password) {
        return res.status(400).json({ error: 'WhatsApp number and password are required' });
    }

    try {
        const pool = req.app.get('db');

        // Find user
        const user = await pool.query(
            'SELECT id, password_hash FROM users WHERE whatsapp_number = $1',
            [whatsappNumber]
        );

        if (user.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid WhatsApp number or password' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid WhatsApp number or password' });
        }

        // Create JWT token
        const token = jwt.sign({
            userId: user.rows[0].id,
            whatsappNumber: whatsappNumber  // ← Add this for consistency
        }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            userId: user.rows[0].id,
            token: token,
            message: 'Login successful!'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get user dashboard data (with pagination)
router.get('/dashboard/:userId', authenticateUser, async (req, res) => {
    const { userId } = req.params;
    const { submissionsPage = 1, redemptionsPage = 1, limit = 5 } = req.query;

    try {
        const pool = req.app.get('db');

        // Get user info
        const user = await pool.query(
            'SELECT id, whatsapp_number, created_at FROM users WHERE id = $1',
            [userId]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get current offer
        const offer = await pool.query(
            'SELECT * FROM offers WHERE is_active = true ORDER BY created_at DESC LIMIT 1'
        );

        // Calculate user points
        const pointsResult = await pool.query(
            `SELECT 
        COALESCE(SUM(points_awarded), 0) as total_points
       FROM submissions 
       WHERE user_id = $1 AND status = 'active'`,
            [userId]
        );

        // Get redeemed points
        const redeemedResult = await pool.query(
            `SELECT COALESCE(SUM(points_requested), 0) as redeemed_points
       FROM redemptions 
       WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        const totalPoints = parseInt(pointsResult.rows[0].total_points);
        const redeemedPoints = parseInt(redeemedResult.rows[0].redeemed_points);
        const availablePoints = totalPoints - redeemedPoints;

        // Get total submission count
        const submissionCountResult = await pool.query(
            'SELECT COUNT(*) as total FROM submissions WHERE user_id = $1',
            [userId]
        );
        const totalSubmissions = parseInt(submissionCountResult.rows[0].total);

        // Get paginated submissions
        const submissionsOffset = (submissionsPage - 1) * limit;
        const submissions = await pool.query(
            `SELECT * FROM submissions 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT $2 OFFSET $3`,
            [userId, limit, submissionsOffset]
        );

        // Get total redemption count
        const redemptionCountResult = await pool.query(
            'SELECT COUNT(*) as total FROM redemptions WHERE user_id = $1',
            [userId]
        );
        const totalRedemptions = parseInt(redemptionCountResult.rows[0].total);

        // Get paginated redemptions
        const redemptionsOffset = (redemptionsPage - 1) * limit;
        const redemptions = await pool.query(
            `SELECT * FROM redemptions 
       WHERE user_id = $1 
       ORDER BY requested_at DESC
       LIMIT $2 OFFSET $3`,
            [userId, limit, redemptionsOffset]
        );

        // Get unread notifications
        const notifications = await pool.query(
            `SELECT * FROM notifications 
       WHERE user_id = $1 AND is_read = false 
       ORDER BY created_at DESC`,
            [userId]
        );

        // Get pending redemptions
        const pendingRedemption = await pool.query(
            `SELECT * FROM redemptions 
       WHERE user_id = $1 AND status = 'pending'
       ORDER BY requested_at DESC
       LIMIT 1`,
            [userId]
        );

        res.json({
            user: user.rows[0],
            offer: offer.rows[0] || null,
            points: {
                total: totalPoints,
                redeemed: redeemedPoints,
                available: availablePoints
            },
            submissions: submissions.rows,
            submissionsPagination: {
                total: totalSubmissions,
                page: parseInt(submissionsPage),
                limit: parseInt(limit),
                totalPages: Math.ceil(totalSubmissions / limit)
            },
            redemptions: redemptions.rows,
            redemptionsPagination: {
                total: totalRedemptions,
                page: parseInt(redemptionsPage),
                limit: parseInt(limit),
                totalPages: Math.ceil(totalRedemptions / limit)
            },
            notifications: notifications.rows,
            pendingRedemption: pendingRedemption.rows[0] || null
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

// Submit proof endpoint
router.post('/submit-proof', authenticateUser, uploadSubmission.array('screenshots', 10), async (req, res) => {
    const { userId, recipientNumbers } = req.body;
    const screenshots = req.files;

    if (!userId || !recipientNumbers || !screenshots || screenshots.length === 0) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const pool = req.app.get('db');
        const numbers = JSON.parse(recipientNumbers);

        // Validate counts match
        if (numbers.length !== screenshots.length) {
            return res.status(400).json({ error: 'Number of screenshots must match recipient count' });
        }

        // Hash recipient numbers and check for duplicates
        const hashedNumbers = numbers.map(num => hashPhoneNumber(num));

        const duplicateCheck = await pool.query(
            `SELECT recipient_number_hash FROM user_recipients 
       WHERE user_id = $1 AND recipient_number_hash = ANY($2)`,
            [userId, hashedNumbers]
        );

        if (duplicateCheck.rows.length > 0) {
            return res.status(400).json({
                error: 'You have already submitted shares to some of these recipients'
            });
        }

        // Store screenshot paths
        const screenshotPaths = screenshots.map(file => `/uploads/submissions/${file.filename}`);

        // Create submission
        const submission = await pool.query(
            `INSERT INTO submissions (user_id, screenshots, recipient_count, points_awarded, status) 
       VALUES ($1, $2, $3, $4, 'active') RETURNING id`,
            [userId, screenshotPaths, numbers.length, numbers.length]
        );

        const submissionId = submission.rows[0].id;

        // Store recipient mappings
        // Store recipient mappings with both hash and actual number
        for (let i = 0; i < hashedNumbers.length; i++) {
            await pool.query(
                `INSERT INTO user_recipients (user_id, recipient_number_hash, recipient_number, submission_id) 
     VALUES ($1, $2, $3, $4)`,
                [userId, hashedNumbers[i], numbers[i], submissionId]
            );
        }

        res.json({
            success: true,
            submissionId: submissionId,
            pointsAwarded: numbers.length,
            message: 'Submission successful!'
        });

    } catch (error) {
        console.error('Submission error:', error);
        res.status(500).json({ error: 'Submission failed' });
    }
});


// Request redemption
// Request redemption
router.post('/request-redemption', authenticateUser, async (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID required' });
    }

    try {
        const pool = req.app.get('db');

        // Get system settings
        const settingsResult = await pool.query('SELECT setting_key, setting_value FROM system_settings');
        const settings = {};
        settingsResult.rows.forEach(row => {
            settings[row.setting_key] = parseInt(row.setting_value);
        });

        // Calculate available points
        const pointsResult = await pool.query(
            `SELECT COALESCE(SUM(points_awarded), 0) as total_points
       FROM submissions 
       WHERE user_id = $1 AND status = 'active'`,
            [userId]
        );

        const redeemedResult = await pool.query(
            `SELECT COALESCE(SUM(points_requested), 0) as redeemed_points
       FROM redemptions 
       WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        const totalPoints = parseInt(pointsResult.rows[0].total_points);
        const redeemedPoints = parseInt(redeemedResult.rows[0].redeemed_points);
        const availablePoints = totalPoints - redeemedPoints;

        // Check if user has enough points
        if (availablePoints < settings.min_redemption_points) {
            return res.status(400).json({
                error: `You need ${settings.min_redemption_points} points to redeem. You have ${availablePoints} points.`
            });
        }

        // Check if user already has a pending redemption
        const pendingCheck = await pool.query(
            `SELECT id FROM redemptions 
       WHERE user_id = $1 AND status = 'pending'`,
            [userId]
        );

        if (pendingCheck.rows.length > 0) {
            return res.status(400).json({
                error: 'You already have a pending redemption request. Please wait for review.'
            });
        }

        // Create redemption request with dynamic amount
        const redemption = await pool.query(
            `INSERT INTO redemptions (user_id, points_requested, status) 
       VALUES ($1, $2, 'pending') RETURNING id`,
            [userId, settings.redemption_amount]
        );

        // Create notification for user
        await pool.query(
            `INSERT INTO notifications (user_id, type, message, data) 
       VALUES ($1, 'redemption_requested', 'Your redemption request has been submitted and is under review.', $2)`,
            [userId, JSON.stringify({ redemptionId: redemption.rows[0].id })]
        );

        res.json({
            success: true,
            redemptionId: redemption.rows[0].id,
            message: 'Redemption request submitted successfully!'
        });

    } catch (error) {
        console.error('Redemption request error:', error);
        res.status(500).json({ error: 'Failed to submit redemption request' });
    }
});


// Get system settings (public - no auth required)
router.get('/settings', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const settings = await pool.query(
            'SELECT setting_key, setting_value FROM system_settings ORDER BY setting_key'
        );
        res.json({ settings: settings.rows });
    } catch (error) {
        console.error('Failed to fetch settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});




// Admin Login
router.post('/admin/login', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { username, password, twoFactorCode } = req.body;

        // Find admin
        const result = await pool.query(
            'SELECT * FROM admins WHERE username = $1',
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const admin = result.rows[0];

        // Check if admin is active
        if (!admin.is_active) {
            return res.status(403).json({ error: 'Account is disabled. Contact super admin.' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, admin.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Check if 2FA is enabled
        if (admin.two_fa_enabled) {
            if (!twoFactorCode) {
                // Need 2FA code
                return res.status(200).json({
                    requiresTwoFactor: true,
                    message: 'Please enter your 2FA code'
                });
            }

            // Verify 2FA code
            const valid2FA = await verify2FACode(pool, admin.id, twoFactorCode);
            if (!valid2FA) {
                return res.status(401).json({ error: 'Invalid 2FA code' });
            }
        }

        // Get admin permissions
        const permResult = await pool.query(
            'SELECT permission FROM admin_permissions WHERE admin_id = $1',
            [admin.id]
        );

        const permissions = permResult.rows.map(row => row.permission);

        // Update last login
        await pool.query(
            'UPDATE admins SET last_login = NOW() WHERE id = $1',
            [admin.id]
        );

        // Generate JWT
        const token = jwt.sign(
            {
                adminId: admin.id,
                username: admin.username,
                role: admin.role,
                isAdmin: true
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            adminId: admin.id,
            role: admin.role,
            permissions,
            message: 'Login successful!'
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// ========================================
// LOGOUT ROUTES (TOKEN BLACKLIST)
// ========================================

// Admin logout - blacklist token
router.post('/admin/logout', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const token = req.headers.authorization.substring(7);
        const decoded = jwt.verify(token, JWT_SECRET);

        // Calculate token expiry
        const expiresAt = new Date(decoded.exp * 1000);

        // Add token to blacklist
        await pool.query(
            'INSERT INTO token_blacklist (token, admin_id, expires_at) VALUES ($1, $2, $3)',
            [token, req.admin.adminId, expiresAt]
        );

        // Log activity
        await logAdminActivity(pool, req.admin.adminId, 'logout', 'Logged out');

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});

// User logout - blacklist token
router.post('/logout', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const token = req.headers.authorization.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);

        // Calculate token expiry
        const expiresAt = new Date(decoded.exp * 1000);

        // Add token to blacklist
        await pool.query(
            'INSERT INTO token_blacklist (token, user_id, expires_at) VALUES ($1, $2, $3)',
            [token, req.userId, expiresAt]
        );

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Logout failed' });
    }
});



// Cleanup expired tokens from blacklist (Super Admin only)
router.post('/admin/cleanup-blacklist', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const result = await pool.query(
            'DELETE FROM token_blacklist WHERE expires_at < NOW()'
        );

        await logAdminActivity(pool, req.admin.adminId, 'cleanup_blacklist', `Cleaned up ${result.rowCount} expired tokens`);

        res.json({
            message: 'Cleanup completed',
            deletedCount: result.rowCount
        });
    } catch (error) {
        console.error('Cleanup error:', error);
        res.status(500).json({ error: 'Cleanup failed' });
    }
});


// ========================================
// TWO-FACTOR AUTHENTICATION (2FA) ROUTES
// ========================================

const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Generate 2FA Secret and QR Code
router.post('/admin/2fa/generate', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Get admin info
        const adminResult = await pool.query(
            'SELECT username, two_fa_enabled FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminResult.rows.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        const admin = adminResult.rows[0];

        // Generate secret
        const secret = speakeasy.generateSecret({
            name: `WhatsApp Admin (${admin.username})`,
            issuer: 'vggamee.com'
        });

        // Generate QR code
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // Save secret (but don't enable yet)
        await pool.query(
            'UPDATE admins SET two_fa_secret = $1 WHERE id = $2',
            [secret.base32, req.admin.adminId]
        );

        res.json({
            secret: secret.base32,
            qrCode: qrCodeUrl,
            enabled: admin.two_fa_enabled
        });

    } catch (error) {
        console.error('2FA generation error:', error);
        res.status(500).json({ error: 'Failed to generate 2FA' });
    }
});

// Enable 2FA (verify code first)
router.post('/admin/2fa/enable', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { code } = req.body;

        // Get admin's secret
        const adminResult = await pool.query(
            'SELECT two_fa_secret FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminResult.rows.length === 0 || !adminResult.rows[0].two_fa_secret) {
            return res.status(400).json({ error: '2FA not set up. Generate secret first.' });
        }

        const secret = adminResult.rows[0].two_fa_secret;

        // Verify the code
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: code,
            window: 2
        });

        if (!verified) {
            return res.status(400).json({ error: 'Invalid verification code' });
        }

        // Enable 2FA
        await pool.query(
            'UPDATE admins SET two_fa_enabled = true WHERE id = $1',
            [req.admin.adminId]
        );

        // Log activity
        await logAdminActivity(pool, req.admin.adminId, 'enable_2fa', 'Enabled two-factor authentication');

        res.json({ message: '2FA enabled successfully' });

    } catch (error) {
        console.error('2FA enable error:', error);
        res.status(500).json({ error: 'Failed to enable 2FA' });
    }
});

// Disable 2FA (verify password first)
router.post('/admin/2fa/disable', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { password } = req.body;

        // Verify password
        const adminResult = await pool.query(
            'SELECT password_hash FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminResult.rows.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        const validPassword = await bcrypt.compare(password, adminResult.rows[0].password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Disable 2FA and clear secret
        await pool.query(
            'UPDATE admins SET two_fa_enabled = false, two_fa_secret = NULL WHERE id = $1',
            [req.admin.adminId]
        );

        // Log activity
        await logAdminActivity(pool, req.admin.adminId, 'disable_2fa', 'Disabled two-factor authentication');

        res.json({ message: '2FA disabled successfully' });

    } catch (error) {
        console.error('2FA disable error:', error);
        res.status(500).json({ error: 'Failed to disable 2FA' });
    }
});

// Get 2FA status
router.get('/admin/2fa/status', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');

        const result = await pool.query(
            'SELECT two_fa_enabled FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        res.json({ enabled: result.rows[0].two_fa_enabled || false });

    } catch (error) {
        console.error('2FA status error:', error);
        res.status(500).json({ error: 'Failed to get 2FA status' });
    }
});

// Verify 2FA code during login (called by login route)
const verify2FACode = async (pool, adminId, code) => {
    const result = await pool.query(
        'SELECT two_fa_secret FROM admins WHERE id = $1',
        [adminId]
    );

    if (result.rows.length === 0 || !result.rows[0].two_fa_secret) {
        return false;
    }

    return speakeasy.totp.verify({
        secret: result.rows[0].two_fa_secret,
        encoding: 'base32',
        token: code,
        window: 2
    });
};

// ========================================
// FILE MANAGER ROUTES (SUPER ADMIN ONLY)
// ========================================

// Get list of files in uploads folder
router.get('/admin/file-manager/list', authenticateAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const fs = require('fs');
        const path = require('path');

        const uploadsDir = './uploads';
        const folders = ['banners', 'offers', 'submissions'];

        const filesByFolder = {};
        let totalSize = 0;
        let totalFiles = 0;

        for (const folder of folders) {
            const folderPath = path.join(uploadsDir, folder);

            if (!fs.existsSync(folderPath)) {
                filesByFolder[folder] = [];
                continue;
            }

            const files = fs.readdirSync(folderPath);

            filesByFolder[folder] = files.map(filename => {
                const filePath = path.join(folderPath, filename);
                const stats = fs.statSync(filePath);

                totalSize += stats.size;
                totalFiles++;

                return {
                    filename,
                    folder,
                    size: stats.size,
                    created: stats.birthtime,
                    modified: stats.mtime,
                    url: `/uploads/${folder}/${filename}`
                };
            }).sort((a, b) => b.modified - a.modified); // Newest first
        }

        res.json({
            files: filesByFolder,
            stats: {
                totalFiles,
                totalSize,
                bannerCount: filesByFolder.banners.length,
                offerCount: filesByFolder.offers.length,
                submissionCount: filesByFolder.submissions.length
            }
        });

    } catch (error) {
        console.error('File manager list error:', error);
        res.status(500).json({ error: 'Failed to list files' });
    }
});

// Delete a file
router.delete('/admin/file-manager/delete/:folder/:filename', authenticateAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const fs = require('fs');
        const path = require('path');
        const { folder, filename } = req.params;

        // Validate folder
        const allowedFolders = ['banners', 'offers', 'submissions'];
        if (!allowedFolders.includes(folder)) {
            return res.status(400).json({ error: 'Invalid folder' });
        }

        const filePath = path.join('./uploads', folder, filename);

        // Check if file exists
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Delete file
        fs.unlinkSync(filePath);

        // Log activity
        await logAdminActivity(pool, req.admin.adminId, 'delete_file', `Deleted file: ${folder}/${filename}`);

        res.json({ message: 'File deleted successfully' });

    } catch (error) {
        console.error('File delete error:', error);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

// Bulk delete files
router.post('/admin/file-manager/bulk-delete', authenticateAdmin, requireSuperAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const fs = require('fs');
        const path = require('path');
        const { files } = req.body; // Array of {folder, filename}

        if (!Array.isArray(files) || files.length === 0) {
            return res.status(400).json({ error: 'No files specified' });
        }

        let deletedCount = 0;
        const allowedFolders = ['banners', 'offers', 'submissions'];

        for (const file of files) {
            if (!allowedFolders.includes(file.folder)) continue;

            const filePath = path.join('./uploads', file.folder, file.filename);

            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
                deletedCount++;
            }
        }

        // Log activity
        await logAdminActivity(pool, req.admin.adminId, 'bulk_delete_files', `Bulk deleted ${deletedCount} files`);

        res.json({
            message: `Successfully deleted ${deletedCount} files`,
            deletedCount
        });

    } catch (error) {
        console.error('Bulk delete error:', error);
        res.status(500).json({ error: 'Failed to delete files' });
    }
});


// ==================== ADMIN MANAGEMENT ROUTES ====================

// Change admin password (ANY ADMIN)
router.post('/admin/change-password', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { oldPassword, newPassword } = req.body;
        const adminId = req.admin.adminId;

        if (!oldPassword || !newPassword) {
            return res.status(400).json({ error: 'Old and new passwords required' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        // Get current password hash
        const admin = await pool.query(
            'SELECT password_hash FROM admins WHERE id = $1',
            [adminId]
        );

        if (admin.rows.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        // Verify old password
        const validPassword = await bcrypt.compare(oldPassword, admin.rows[0].password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Hash new password
        const newHash = await bcrypt.hash(newPassword, 10);

        // Update password
        await pool.query(
            'UPDATE admins SET password_hash = $1 WHERE id = $2',
            [newHash, adminId]
        );

        // Log activity
        await pool.query(
            `INSERT INTO admin_activity_logs (admin_id, admin_username, action, details) 
             VALUES ($1, $2, 'PASSWORD_CHANGED', 'Admin changed their password')`,
            [adminId, req.admin.username]
        );


        await logAdminActivity(pool, req.admin.adminId, 'change_password', `Changed own password`);

        res.json({ message: 'Password changed successfully' });
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// Get all admins (SUPER ADMIN ONLY)
router.get('/admin/admins', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied. Super admin only.' });
        }

        const result = await pool.query(`
            SELECT id, username, role, two_fa_enabled, is_active, 
                   last_login, created_at, created_by
            FROM admins 
            ORDER BY created_at DESC
        `);

        res.json({ admins: result.rows });
    } catch (error) {
        console.error('Error fetching admins:', error);
        res.status(500).json({ error: 'Failed to fetch admins' });
    }
});

// Get admin permissions (SUPER ADMIN ONLY)
router.get('/admin/admins/:id/permissions', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const result = await pool.query(
            'SELECT permission FROM admin_permissions WHERE admin_id = $1',
            [id]
        );

        const permissions = result.rows.map(row => row.permission);

        await logAdminActivity(pool, req.admin.adminId, 'update_admin_permissions', `Updated permissions for admin ID ${adminId}`);

        await logAdminActivity(pool, req.admin.adminId, 'update_admin_permissions', `Updated permissions for admin ID ${adminId}`);

        await logAdminActivity(pool, req.admin.adminId, 'delete_admin', `Deleted admin ID ${adminId}`);

        res.json({ permissions });
    } catch (error) {
        console.error('Error fetching permissions:', error);
        res.status(500).json({ error: 'Failed to fetch permissions' });
    }
});

// Create new admin (SUPER ADMIN ONLY)
router.post('/admin/create-admin', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { username, password, permissions } = req.body;

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        // Check if username exists
        const existingAdmin = await pool.query(
            'SELECT id FROM admins WHERE username = $1',
            [username]
        );

        if (existingAdmin.rows.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Create admin
        const result = await pool.query(
            `INSERT INTO admins (username, password_hash, role, created_by, is_active) 
             VALUES ($1, $2, 'admin', $3, true) RETURNING id, username, role`,
            [username, passwordHash, req.admin.adminId]
        );

        const newAdminId = result.rows[0].id;

        // Add permissions
        if (permissions && Array.isArray(permissions)) {
            for (const permission of permissions) {
                await pool.query(
                    'INSERT INTO admin_permissions (admin_id, permission) VALUES ($1, $2)',
                    [newAdminId, permission]
                );
            }
        }

        // Log activity
        await pool.query(
            `INSERT INTO admin_activity_logs (admin_id, admin_username, action, details) 
             VALUES ($1, $2, 'ADMIN_CREATED', $3)`,
            [req.admin.adminId, req.admin.username, `Created admin: ${username}`]
        );

        await logAdminActivity(pool, req.admin.adminId, 'create_admin', `Created new admin: ${username} with ${permissions.length} permissions`);

        res.json({
            message: 'Admin created successfully',
            admin: result.rows[0]
        });
    } catch (error) {
        console.error('Error creating admin:', error);
        res.status(500).json({ error: 'Failed to create admin' });
    }
});

// Update admin permissions (SUPER ADMIN ONLY)
router.put('/admin/admins/:id/permissions', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const { permissions } = req.body;

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Cannot edit super admin permissions
        const targetAdmin = await pool.query(
            'SELECT role, username FROM admins WHERE id = $1',
            [id]
        );

        if (targetAdmin.rows[0].role === 'super_admin') {
            return res.status(400).json({ error: 'Cannot modify super admin permissions' });
        }

        // Delete existing permissions
        await pool.query('DELETE FROM admin_permissions WHERE admin_id = $1', [id]);

        // Add new permissions
        if (permissions && Array.isArray(permissions)) {
            for (const permission of permissions) {
                await pool.query(
                    'INSERT INTO admin_permissions (admin_id, permission) VALUES ($1, $2)',
                    [id, permission]
                );
            }
        }

        // Log activity
        await pool.query(
            `INSERT INTO admin_activity_logs (admin_id, admin_username, action, details) 
             VALUES ($1, $2, 'PERMISSIONS_UPDATED', $3)`,
            [req.admin.adminId, req.admin.username, `Updated permissions for admin ID: ${id}`]
        );

        res.json({ message: 'Permissions updated successfully' });
    } catch (error) {
        console.error('Error updating permissions:', error);
        res.status(500).json({ error: 'Failed to update permissions' });
    }
});

// Delete admin (SUPER ADMIN ONLY)
router.delete('/admin/admins/:id', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Cannot delete super admin or self
        if (parseInt(id) === req.admin.adminId) {
            return res.status(400).json({ error: 'Cannot delete yourself' });
        }

        const targetAdmin = await pool.query(
            'SELECT role, username FROM admins WHERE id = $1',
            [id]
        );

        if (targetAdmin.rows.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        if (targetAdmin.rows[0].role === 'super_admin') {
            return res.status(400).json({ error: 'Cannot delete super admin' });
        }

        // Delete admin (permissions will cascade delete)
        await pool.query('DELETE FROM admins WHERE id = $1', [id]);

        // Log activity
        await pool.query(
            `INSERT INTO admin_activity_logs (admin_id, admin_username, action, details) 
             VALUES ($1, $2, 'ADMIN_DELETED', $3)`,
            [req.admin.adminId, req.admin.username, `Deleted admin: ${targetAdmin.rows[0].username}`]
        );

        res.json({ message: 'Admin deleted successfully' });
    } catch (error) {
        console.error('Error deleting admin:', error);
        res.status(500).json({ error: 'Failed to delete admin' });
    }
});

// Toggle admin active status (SUPER ADMIN ONLY)
router.post('/admin/admins/:id/toggle-status', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        const result = await pool.query(
            `UPDATE admins SET is_active = NOT is_active 
             WHERE id = $1 AND role != 'super_admin' 
             RETURNING username, is_active`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Cannot modify this admin' });
        }

        // Log activity
        await pool.query(
            `INSERT INTO admin_activity_logs (admin_id, admin_username, action, details) 
             VALUES ($1, $2, 'STATUS_CHANGED', $3)`,
            [req.admin.adminId, req.admin.username,
            `Changed status for ${result.rows[0].username} to ${result.rows[0].is_active ? 'active' : 'inactive'}`]
        );

        await logAdminActivity(pool, req.admin.adminId, 'toggle_admin_status', `Toggled status for admin ID ${adminId}`);

        res.json({
            message: 'Status updated',
            isActive: result.rows[0].is_active
        });
    } catch (error) {
        console.error('Error toggling status:', error);
        res.status(500).json({ error: 'Failed to toggle status' });
    }
});

// Get activity logs (SUPER ADMIN ONLY)
router.get('/admin/activity-logs', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { adminId, limit = 50 } = req.query;

        // Check if super admin
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [req.admin.adminId]
        );

        if (adminCheck.rows[0].role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Build query with JOIN to get admin username
        let query = `
            SELECT aal.*, a.username as admin_username
            FROM admin_activity_logs aal
            JOIN admins a ON aal.admin_id = a.id
        `;

        const params = [];

        // If adminId provided, filter by that admin
        if (adminId) {
            query += ' WHERE aal.admin_id = $1';
            params.push(adminId);
        }

        query += ' ORDER BY aal.created_at DESC LIMIT $' + (params.length + 1);
        params.push(limit);

        const result = await pool.query(query, params);

        res.json({ logs: result.rows });
    } catch (error) {
        console.error('Error fetching activity logs:', error);
        res.status(500).json({ error: 'Failed to fetch activity logs' });
    }
});




// Get all redemption requests (admin) - with pagination, filters, search
router.get('/admin/redemptions', authenticateAdmin, checkPermission('view_redemptions'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { page = 1, limit = 20, status = 'all', search = '' } = req.query;
        const offset = (page - 1) * limit;

        // Build WHERE clause
        let whereClause = 'WHERE 1=1';
        const queryParams = [];
        let paramCount = 1;

        if (status !== 'all') {
            whereClause += ` AND r.status = $${paramCount}`;
            queryParams.push(status);
            paramCount++;
        }

        if (search) {
            whereClause += ` AND u.whatsapp_number ILIKE $${paramCount}`;
            queryParams.push(`%${search}%`);
            paramCount++;
        }

        // Get total count
        const countResult = await pool.query(
            `SELECT COUNT(*) as total 
       FROM redemptions r
       JOIN users u ON r.user_id = u.id
       ${whereClause}`,
            queryParams
        );

        const total = parseInt(countResult.rows[0].total);

        // Get paginated results
        queryParams.push(limit, offset);
        const redemptions = await pool.query(
            `SELECT r.*, u.whatsapp_number 
       FROM redemptions r
       JOIN users u ON r.user_id = u.id
       ${whereClause}
       ORDER BY 
         CASE r.status 
           WHEN 'pending' THEN 1 
           WHEN 'approved' THEN 2 
           WHEN 'rejected' THEN 3 
         END,
         r.requested_at DESC
       LIMIT $${paramCount} OFFSET $${paramCount + 1}`,
            queryParams
        );

        res.json({
            redemptions: redemptions.rows,
            pagination: {
                total,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Failed to fetch redemptions:', error);
        res.status(500).json({ error: 'Failed to fetch redemptions' });
    }
});

// Get user submissions (admin)
router.get('/admin/user-submissions/:userId', authenticateAdmin, checkPermission('view_submissions'), async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        const submissions = await pool.query(
            `SELECT s.*, 
              array_agg(ur.recipient_number) as recipient_numbers
       FROM submissions s
       LEFT JOIN user_recipients ur ON s.id = ur.submission_id
       WHERE s.user_id = $1 
       GROUP BY s.id
       ORDER BY s.created_at DESC`,
            [userId]
        );

        res.json({ submissions: submissions.rows });
    } catch (error) {
        console.error('Failed to fetch submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});

// Review redemption (admin)
router.post('/admin/review-redemption', authenticateAdmin, checkPermission('manage_redemptions'), async (req, res) => {
    const { redemptionId, action, giftCode, rejectionReason, adminId } = req.body;

    try {
        const pool = req.app.get('db');

        if (action === 'approve') {
            // Update redemption
            await pool.query(
                `UPDATE redemptions 
         SET status = 'approved', gift_code = $1, reviewed_by = $2, reviewed_at = NOW() 
         WHERE id = $3`,
                [giftCode, adminId, redemptionId]
            );

            // Get redemption details
            const redemption = await pool.query(
                'SELECT user_id, points_requested FROM redemptions WHERE id = $1',
                [redemptionId]
            );

            const userId = redemption.rows[0].user_id;

            // Create notification
            await pool.query(
                `INSERT INTO notifications (user_id, type, message, data) 
         VALUES ($1, 'redemption_approved', 'Your redemption has been approved!', $2)`,
                [userId, JSON.stringify({ giftCode: giftCode, redemptionId: redemptionId })]
            );

            res.json({ success: true, message: 'Redemption approved' });

        } else if (action === 'reject') {
            // Update redemption
            await pool.query(
                `UPDATE redemptions 
         SET status = 'rejected', rejection_reason = $1, reviewed_by = $2, reviewed_at = NOW() 
         WHERE id = $3`,
                [rejectionReason, adminId, redemptionId]
            );

            // Get redemption details
            const redemption = await pool.query(
                'SELECT user_id FROM redemptions WHERE id = $1',
                [redemptionId]
            );

            const userId = redemption.rows[0].user_id;

            // Create notification
            await pool.query(
                `INSERT INTO notifications (user_id, type, message, data) 
         VALUES ($1, 'redemption_rejected', 'Your redemption request was rejected.', $2)`,
                [userId, JSON.stringify({ reason: rejectionReason, redemptionId: redemptionId })]
            );

            res.json({ success: true, message: 'Redemption rejected' });
        }

    } catch (error) {
        console.error('Failed to review redemption:', error);
        res.status(500).json({ error: 'Failed to review redemption' });
    }
});

// Get all users (admin) - with pagination and search
router.get('/admin/users', authenticateAdmin, checkPermission('view_users'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { page = 1, limit = 20, search = '' } = req.query;
        const offset = (page - 1) * limit;

        // Build WHERE clause
        let whereClause = 'WHERE 1=1';
        const queryParams = [];

        if (search) {
            whereClause += ` AND u.whatsapp_number ILIKE $1`;
            queryParams.push(`%${search}%`);
        }

        // Get total count
        const countResult = await pool.query(
            `SELECT COUNT(*) as total FROM users u ${whereClause}`,
            queryParams
        );

        const total = parseInt(countResult.rows[0].total);

        // Get paginated results
        const paramOffset = queryParams.length + 1;
        queryParams.push(limit, offset);

        const users = await pool.query(
            `SELECT u.id, u.whatsapp_number, u.created_at,
              COALESCE(SUM(s.points_awarded), 0) as total_points
       FROM users u
       LEFT JOIN submissions s ON u.id = s.user_id AND s.status = 'active'
       ${whereClause}
       GROUP BY u.id, u.whatsapp_number, u.created_at
       ORDER BY u.created_at DESC
       LIMIT $${paramOffset} OFFSET $${paramOffset + 1}`,
            queryParams
        );

        res.json({
            users: users.rows,
            pagination: {
                total,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(total / limit)
            }
        });
    } catch (error) {
        console.error('Failed to fetch users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});



// Add points to user (admin - for testing)
router.post('/admin/add-points', authenticateAdmin, checkPermission('manage_users'), async (req, res) => {
    const { userId, points } = req.body;

    if (!userId || !points || points <= 0) {
        return res.status(400).json({ error: 'Valid user ID and points required' });
    }

    try {
        const pool = req.app.get('db');

        // Create a test submission with the points
        await pool.query(
            `INSERT INTO submissions (user_id, screenshots, recipient_count, points_awarded, status) 
       VALUES ($1, ARRAY['/uploads/admin-test.jpg'], $2, $2, 'active')`,
            [userId, points]
        );

        await logAdminActivity(pool, req.admin.adminId, 'add_points', `Added ${points} points to user ID ${userId}`);

        res.json({ success: true, message: `Added ${points} points successfully` });
    } catch (error) {
        console.error('Failed to add points:', error);
        res.status(500).json({ error: 'Failed to add points' });
    }
});


// Deduct points from user (admin)
router.post('/admin/deduct-points', authenticateAdmin, checkPermission('manage_users'), async (req, res) => {
    const { userId, points } = req.body;

    if (!userId || !points || points <= 0) {
        return res.status(400).json({ error: 'Valid user ID and points required' });
    }

    try {
        const pool = req.app.get('db');

        // Check current available points
        const pointsResult = await pool.query(
            `SELECT COALESCE(SUM(points_awarded), 0) as total_points
       FROM submissions 
       WHERE user_id = $1 AND status = 'active'`,
            [userId]
        );

        const currentPoints = parseInt(pointsResult.rows[0].total_points);

        if (currentPoints < points) {
            return res.status(400).json({
                error: `Cannot deduct ${points} points. User only has ${currentPoints} available points.`
            });
        }

        // Create a negative submission to deduct points
        await pool.query(
            `INSERT INTO submissions (user_id, screenshots, recipient_count, points_awarded, status) 
       VALUES ($1, ARRAY['/uploads/admin-deduct.jpg'], $2, $3, 'active')`,
            [userId, -points, -points]
        );

        await logAdminActivity(pool, req.admin.adminId, 'deduct_points', `Deducted ${points} points from user ID ${userId}`);

        res.json({ success: true, message: `Deducted ${points} points successfully` });
    } catch (error) {
        console.error('Failed to deduct points:', error);
        res.status(500).json({ error: 'Failed to deduct points' });
    }
});

// Delete user (admin)
router.delete('/admin/delete-user/:userId', authenticateAdmin, checkPermission('manage_users'), async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        // Delete user (CASCADE will handle related records)
        await pool.query('DELETE FROM users WHERE id = $1', [userId]);

        await logAdminActivity(pool, req.admin.adminId, 'delete_user', `Deleted user ID ${userId}`);

        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Failed to delete user:', error);

        res.status(500).json({ error: 'Failed to delete user' });
    }
});


// Cancel submission (user)
router.post('/cancel-submission', authenticateUser, async (req, res) => {
    const { submissionId, userId } = req.body;

    if (!submissionId || !userId) {
        return res.status(400).json({ error: 'Submission ID and User ID required' });
    }

    try {
        const pool = req.app.get('db');

        // Verify submission belongs to user and is active
        const submission = await pool.query(
            `SELECT * FROM submissions WHERE id = $1 AND user_id = $2 AND status = 'active'`,
            [submissionId, userId]
        );

        if (submission.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found or already cancelled' });
        }

        // Update submission status to cancelled
        await pool.query(
            `UPDATE submissions SET status = 'cancelled', cancelled_at = NOW() WHERE id = $1`,
            [submissionId]
        );

        res.json({
            success: true,
            message: 'Submission cancelled successfully',
            pointsDeducted: submission.rows[0].points_awarded
        });

    } catch (error) {
        console.error('Failed to cancel submission:', error);
        res.status(500).json({ error: 'Failed to cancel submission' });
    }
});


// Get user profile (admin)
router.get('/admin/user-profile/:userId', authenticateAdmin, checkPermission('view_users'), async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        // Get user info with total points
        const user = await pool.query(
            `SELECT u.id, u.whatsapp_number, u.created_at,
              COALESCE(SUM(s.points_awarded), 0) as total_points
       FROM users u
       LEFT JOIN submissions s ON u.id = s.user_id AND s.status = 'active'
       WHERE u.id = $1
       GROUP BY u.id, u.whatsapp_number, u.created_at`,
            [userId]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: user.rows[0] });
    } catch (error) {
        console.error('Failed to fetch user profile:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});



// Delete single submission (admin)
router.delete('/admin/delete-submission/:submissionId', authenticateAdmin, checkPermission('approve_submissions'), async (req, res) => {
    const { submissionId } = req.params;

    try {
        const pool = req.app.get('db');

        // Get submission details before deletion
        const submission = await pool.query(
            'SELECT user_id, points_awarded, status FROM submissions WHERE id = $1',
            [submissionId]
        );

        if (submission.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        // Delete submission (CASCADE will handle user_recipients)
        await pool.query('DELETE FROM submissions WHERE id = $1', [submissionId]);

        await logAdminActivity(pool, req.admin.adminId, 'delete_submission', `Deleted submission ID ${submissionId}`);

        res.json({
            success: true,
            message: 'Submission deleted successfully',
            pointsDeducted: submission.rows[0].status === 'active' ? submission.rows[0].points_awarded : 0
        });

    } catch (error) {
        console.error('Failed to delete submission:', error);
        res.status(500).json({ error: 'Failed to delete submission' });
    }
});

// Bulk delete submissions (admin)
router.post('/admin/bulk-delete-submissions', authenticateAdmin, checkPermission('approve_submissions'), async (req, res) => {
    const { submissionIds } = req.body;

    if (!submissionIds || submissionIds.length === 0) {
        return res.status(400).json({ error: 'No submissions selected' });
    }

    try {
        const pool = req.app.get('db');

        // Get total points that will be deducted
        const pointsResult = await pool.query(
            `SELECT SUM(points_awarded) as total_points 
       FROM submissions 
       WHERE id = ANY($1) AND status = 'active'`,
            [submissionIds]
        );

        // Delete submissions
        await pool.query('DELETE FROM submissions WHERE id = ANY($1)', [submissionIds]);

        await logAdminActivity(pool, req.admin.adminId, 'bulk_delete_submissions', `Bulk deleted ${submissionIds.length} submissions`);

        res.json({
            success: true,
            message: `${submissionIds.length} submissions deleted successfully`,
            pointsDeducted: parseInt(pointsResult.rows[0].total_points || 0)
        });

    } catch (error) {
        console.error('Failed to bulk delete submissions:', error);
        res.status(500).json({ error: 'Failed to delete submissions' });
    }
});


// Get all offers (admin)
router.get('/admin/offers', authenticateAdmin, checkPermission('manage_offers'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        const offers = await pool.query(
            'SELECT * FROM offers ORDER BY created_at DESC'
        );

        res.json({ offers: offers.rows });
    } catch (error) {
        console.error('Failed to fetch offers:', error);
        res.status(500).json({ error: 'Failed to fetch offers' });
    }
});

// Create new offer (admin)
router.post('/admin/create-offer', authenticateAdmin, checkPermission('manage_offers'), uploadOffer.single('image'), async (req, res) => {
    const { caption } = req.body;
    const image = req.file;

    if (!caption || !image) {
        return res.status(400).json({ error: 'Caption and image are required' });
    }

    try {
        const pool = req.app.get('db');
        const imagePath = `/uploads/offers/${image.filename}`;

        // Create new offer
        const newOffer = await pool.query(
            'INSERT INTO offers (image_url, caption, is_active) VALUES ($1, $2, false) RETURNING *',
            [imagePath, caption]
        );

        await logAdminActivity(pool, req.admin.adminId, 'create_offer', `Created offer: ${caption.substring(0, 50)}`);

        res.json({ success: true, offer: newOffer.rows[0] });
    } catch (error) {
        console.error('Failed to create offer:', error);
        res.status(500).json({ error: 'Failed to create offer' });
    }
});

// Update offer (admin)
router.put('/admin/update-offer/:offerId', authenticateAdmin, checkPermission('manage_offers'), uploadOffer.single('image'), async (req, res) => {
    const { offerId } = req.params;
    const { caption } = req.body;
    const image = req.file;

    try {
        const pool = req.app.get('db');

        if (image) {
            // Update with new image
            const imagePath = `/uploads/offers/${image.filename}`;
            await pool.query(
                'UPDATE offers SET caption = $1, image_url = $2 WHERE id = $3',
                [caption, imagePath, offerId]
            );
        } else {
            // Update caption only
            await pool.query(
                'UPDATE offers SET caption = $1 WHERE id = $2',
                [caption, offerId]
            );
        }
        await logAdminActivity(pool, req.admin.adminId, 'update_offer', `Updated offer ID ${offerId}`);

        res.json({ success: true, message: 'Offer updated successfully' });
    } catch (error) {
        console.error('Failed to update offer:', error);
        res.status(500).json({ error: 'Failed to update offer' });
    }
});

// Set active offer (admin)
router.post('/admin/set-active-offer', authenticateAdmin, checkPermission('manage_offers'), async (req, res) => {
    const { offerId } = req.body;

    try {
        const pool = req.app.get('db');

        // Set all offers to inactive
        await pool.query('UPDATE offers SET is_active = false');

        // Set selected offer to active
        await pool.query('UPDATE offers SET is_active = true WHERE id = $1', [offerId]);

        await logAdminActivity(pool, req.admin.adminId, 'set_active_offer', `Set offer ID ${offerId} as active`);

        res.json({ success: true, message: 'Active offer updated' });
    } catch (error) {
        console.error('Failed to set active offer:', error);
        res.status(500).json({ error: 'Failed to set active offer' });
    }
});

// Delete offer (admin)
router.delete('/admin/delete-offer/:offerId', authenticateAdmin, checkPermission('manage_offers'), async (req, res) => {
    const { offerId } = req.params;

    try {
        const pool = req.app.get('db');

        await pool.query('DELETE FROM offers WHERE id = $1', [offerId]);

        await logAdminActivity(pool, req.admin.adminId, 'delete_offer', `Deleted offer ID ${offerId}`);

        res.json({ success: true, message: 'Offer deleted successfully' });
    } catch (error) {
        console.error('Failed to delete offer:', error);
        res.status(500).json({ error: 'Failed to delete offer' });
    }
});


// Get all recipient numbers for a user
router.get('/user-recipients/:userId', authenticateUser, async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        const recipients = await pool.query(
            `SELECT DISTINCT ON (recipient_number) 
              recipient_number, 
              MIN(created_at) as first_shared
       FROM user_recipients
       WHERE user_id = $1 AND recipient_number IS NOT NULL
       GROUP BY recipient_number
       ORDER BY recipient_number, first_shared DESC`,
            [userId]
        );

        res.json({ recipients: recipients.rows });
    } catch (error) {
        console.error('Failed to fetch recipients:', error);
        res.status(500).json({ error: 'Failed to fetch recipients' });
    }
});

// Get system settings (admin)
router.get('/admin/settings', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        const settings = await pool.query(
            'SELECT * FROM system_settings ORDER BY setting_key'
        );

        res.json({ settings: settings.rows });
    } catch (error) {
        console.error('Failed to fetch settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Update system setting (admin)
router.put('/admin/settings/:settingKey', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    const { settingKey } = req.params;
    const { value } = req.body;

    if (!value || isNaN(value) || parseInt(value) <= 0) {
        return res.status(400).json({ error: 'Value must be a positive number' });
    }

    try {
        const pool = req.app.get('db');

        await pool.query(
            'UPDATE system_settings SET setting_value = $1, updated_at = NOW() WHERE setting_key = $2',
            [value, settingKey]
        );

        await logAdminActivity(pool, req.admin.adminId, 'update_setting', `Updated ${settingKey} to ${value}`);


        res.json({ success: true, message: 'Setting updated successfully' });
    } catch (error) {
        console.error('Failed to update setting:', error);
        res.status(500).json({ error: 'Failed to update setting' });
    }
});




// ============================================
// PLATFORM STATS ROUTES
// ============================================

// Get calculated platform stats (public - for user dashboard)
router.get('/platform-stats', async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Get config
        const config = await pool.query('SELECT * FROM platform_stats_config WHERE id = 1');

        if (config.rows.length === 0) {
            return res.status(404).json({ error: 'Platform stats config not found' });
        }

        const cfg = config.rows[0];
        const now = new Date();

        // Calculate Total Users
        const usersDaysPassed = (now - new Date(cfg.total_users_start_date)) / (1000 * 60 * 60 * 24);
        const usersDaysTotal = cfg.total_users_days_to_complete;
        const usersProgress = Math.min(usersDaysPassed / usersDaysTotal, 1);
        const usersToAdd = Math.floor((cfg.total_users_target - cfg.total_users_current) * usersProgress);
        const currentUsers = Math.min(cfg.total_users_current + usersToAdd, cfg.total_users_target);

        // Calculate Earned Today (check if needs reset)
        const today = now.toISOString().split('T')[0];
        const lastReset = new Date(cfg.earned_today_last_reset).toISOString().split('T')[0];
        let earnedToday = cfg.earned_today_current;

        if (today !== lastReset) {
            // Reset earned today
            await pool.query(
                'UPDATE platform_stats_config SET earned_today_current = 0, earned_today_last_reset = CURRENT_DATE WHERE id = 1'
            );
            earnedToday = 0;
        }

        // Calculate earned today based on hours passed
        const currentHour = now.getHours();
        const hoursProgress = currentHour / cfg.earned_today_hours_to_complete;
        const targetEarned = Math.floor(cfg.earned_today_target * hoursProgress);
        earnedToday = Math.min(earnedToday + Math.floor(Math.random() * 50) + 10, targetEarned);

        // Update earned today in database
        await pool.query(
            'UPDATE platform_stats_config SET earned_today_current = $1 WHERE id = 1',
            [earnedToday]
        );

        // Calculate Active Now (random between min and max)
        const activeNow = Math.floor(Math.random() * (cfg.active_now_max - cfg.active_now_min + 1)) + cfg.active_now_min;

        // Calculate Total Paid
        const paidDaysPassed = (now - new Date(cfg.total_paid_start_date)) / (1000 * 60 * 60 * 24);
        const paidDaysTotal = cfg.total_paid_days_to_complete;
        const paidProgress = Math.min(paidDaysPassed / paidDaysTotal, 1);
        const amountToAdd = (parseFloat(cfg.total_paid_target) - parseFloat(cfg.total_paid_current)) * paidProgress;
        const currentPaid = Math.min(parseFloat(cfg.total_paid_current) + amountToAdd, parseFloat(cfg.total_paid_target));

        res.json({
            totalUsers: currentUsers,
            earnedToday: earnedToday,
            activeNow: activeNow,
            totalPaid: Math.floor(currentPaid)
        });

    } catch (error) {
        console.error('Failed to get platform stats:', error);
        res.status(500).json({ error: 'Failed to get platform stats' });
    }
});

// Get platform stats config (admin only)
router.get('/admin/platform-stats-config', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const config = await pool.query('SELECT * FROM platform_stats_config WHERE id = 1');

        if (config.rows.length === 0) {
            return res.status(404).json({ error: 'Config not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'update_platform_stats', `Updated platform stats configuration`);

        res.json({ config: config.rows[0] });
    } catch (error) {
        console.error('Failed to get config:', error);
        res.status(500).json({ error: 'Failed to get config' });
    }
});

// Update platform stats config (admin only)
router.put('/admin/platform-stats-config', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    const {
        total_users_current,
        total_users_target,
        total_users_days_to_complete,
        earned_today_target,
        earned_today_hours_to_complete,
        active_now_min,
        active_now_max,
        total_paid_current,
        total_paid_target,
        total_paid_days_to_complete
    } = req.body;

    try {
        const pool = req.app.get('db');

        await pool.query(`
            UPDATE platform_stats_config 
            SET 
                total_users_current = $1,
                total_users_target = $2,
                total_users_start_date = CURRENT_TIMESTAMP,
                total_users_days_to_complete = $3,
                earned_today_target = $4,
                earned_today_hours_to_complete = $5,
                active_now_min = $6,
                active_now_max = $7,
                total_paid_current = $8,
                total_paid_target = $9,
                total_paid_start_date = CURRENT_TIMESTAMP,
                total_paid_days_to_complete = $10,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
        `, [
            total_users_current,
            total_users_target,
            total_users_days_to_complete,
            earned_today_target,
            earned_today_hours_to_complete,
            active_now_min,
            active_now_max,
            total_paid_current,
            total_paid_target,
            total_paid_days_to_complete
        ]);

        await logAdminActivity(pool, req.admin.adminId, 'update_platform_stats', `Updated platform stats configuration`);

        res.json({ success: true, message: 'Platform stats config updated successfully' });

    } catch (error) {
        console.error('Failed to update config:', error);
        res.status(500).json({ error: 'Failed to update config' });
    }
});





// ============================================
// MESSAGING SYSTEM ROUTES
// ============================================

// Get messages for a user (inbox)
router.get('/messages/:userId', authenticateUser, async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        // Get user-specific messages
        const userMessages = await pool.query(`
            SELECT 
                id,
                title,
                message,
                is_read,
                created_at,
                'user' as message_type
            FROM user_messages 
            WHERE user_id = $1 
            ORDER BY created_at DESC
        `, [userId]);

        // Get broadcast messages that this user hasn't read yet
        const broadcasts = await pool.query(`
            SELECT 
                bm.id,
                bm.title,
                bm.message,
                bm.created_at,
                'broadcast' as message_type,
                CASE WHEN br.user_id IS NULL THEN false ELSE true END as is_read
            FROM broadcast_messages bm
            LEFT JOIN broadcast_reads br ON bm.id = br.broadcast_id AND br.user_id = $1
            ORDER BY bm.created_at DESC
        `, [userId]);

        // Combine and sort by date
        const allMessages = [...userMessages.rows, ...broadcasts.rows]
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        res.json({ messages: allMessages });

    } catch (error) {
        console.error('Failed to get messages:', error);
        res.status(500).json({ error: 'Failed to get messages' });
    }
});

// Get unread message count for a user
router.get('/messages/:userId/unread-count', authenticateUser, async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        // Count unread user messages
        const userUnread = await pool.query(
            'SELECT COUNT(*) FROM user_messages WHERE user_id = $1 AND is_read = false',
            [userId]
        );

        // Count unread broadcasts (broadcasts not in broadcast_reads for this user)
        const broadcastUnread = await pool.query(`
            SELECT COUNT(*) FROM broadcast_messages bm
            WHERE NOT EXISTS (
                SELECT 1 FROM broadcast_reads br 
                WHERE br.broadcast_id = bm.id AND br.user_id = $1
            )
        `, [userId]);

        const totalUnread = parseInt(userUnread.rows[0].count) + parseInt(broadcastUnread.rows[0].count);

        res.json({ unreadCount: totalUnread });

    } catch (error) {
        console.error('Failed to get unread count:', error);
        res.status(500).json({ error: 'Failed to get unread count' });
    }
});

// Mark message as read
router.put('/messages/:messageId/read', authenticateUser, async (req, res) => {
    const { messageId } = req.params;
    const { userId, messageType } = req.body;

    try {
        const pool = req.app.get('db');

        if (messageType === 'user') {
            // Mark user message as read
            await pool.query(
                'UPDATE user_messages SET is_read = true WHERE id = $1 AND user_id = $2',
                [messageId, userId]
            );
        } else if (messageType === 'broadcast') {
            // Mark broadcast as read by adding to broadcast_reads
            await pool.query(
                'INSERT INTO broadcast_reads (user_id, broadcast_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
                [userId, messageId]
            );
        }

        res.json({ success: true });

    } catch (error) {
        console.error('Failed to mark as read:', error);
        res.status(500).json({ error: 'Failed to mark as read' });
    }
});

// Send message to specific user (admin only)
router.post('/admin/send-message', authenticateAdmin, checkPermission('send_messages'), async (req, res) => {
    const { userId, title, message, adminId } = req.body;

    if (!userId || !title || !message) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const pool = req.app.get('db');

        await pool.query(
            'INSERT INTO user_messages (user_id, title, message, sent_by_admin) VALUES ($1, $2, $3, $4)',
            [userId, title, message, adminId]
        );

        await logAdminActivity(pool, req.admin.adminId, 'send_message', `Sent message to user ${userId}: "${title}"`);

        res.json({ success: true, message: 'Message sent successfully' });

    } catch (error) {
        console.error('Failed to send message:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Broadcast message to all users (admin only)
router.post('/admin/broadcast-message', authenticateAdmin, checkPermission('send_messages'), async (req, res) => {
    const { title, message, adminId } = req.body;

    if (!title || !message) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const pool = req.app.get('db');

        await pool.query(
            'INSERT INTO broadcast_messages (title, message, sent_by_admin) VALUES ($1, $2, $3)',
            [title, message, adminId]
        );

        await logAdminActivity(pool, req.admin.adminId, 'broadcast_message', `Broadcast: "${title}" to all users`);

        res.json({ success: true, message: 'Broadcast sent successfully' });

    } catch (error) {
        console.error('Failed to broadcast message:', error);
        res.status(500).json({ error: 'Failed to broadcast message' });
    }
});

// Get message history (admin only)
router.get('/admin/messages-history', authenticateAdmin, checkPermission('view_messages'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Get user messages with user info
        const userMessages = await pool.query(`
            SELECT 
                um.id,
                um.title,
                um.message,
                um.created_at,
                u.whatsapp_number,
                'user' as message_type,
                um.is_read
            FROM user_messages um
            JOIN users u ON um.user_id = u.id
            ORDER BY um.created_at DESC
            LIMIT 50
        `);

        // Get broadcast messages with read count
        const broadcasts = await pool.query(`
            SELECT 
                bm.id,
                bm.title,
                bm.message,
                bm.created_at,
                'broadcast' as message_type,
                COUNT(br.user_id) as read_count,
                (SELECT COUNT(*) FROM users) as total_users
            FROM broadcast_messages bm
            LEFT JOIN broadcast_reads br ON bm.id = br.broadcast_id
            GROUP BY bm.id
            ORDER BY bm.created_at DESC
            LIMIT 50
        `);

        res.json({
            userMessages: userMessages.rows,
            broadcasts: broadcasts.rows
        });

    } catch (error) {
        console.error('Failed to get message history:', error);
        res.status(500).json({ error: 'Failed to get message history' });
    }
});



// ============================================
// DATA MANAGEMENT ROUTES (Admin Only)
// ============================================

// Clear all messages
router.delete('/admin/clear-all-messages', authenticateAdmin, checkPermission('send_messages'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        await pool.query('DELETE FROM broadcast_reads');
        await pool.query('DELETE FROM user_messages');
        await pool.query('DELETE FROM broadcast_messages');

        await logAdminActivity(pool, req.admin.adminId, 'clear_all_messages', `Cleared all user messages and broadcasts`);

        res.json({ success: true, message: 'All messages cleared successfully' });

    } catch (error) {
        console.error('Failed to clear messages:', error);
        res.status(500).json({ error: 'Failed to clear messages' });
    }
});

// Clear all submissions (keeps users)
router.delete('/admin/clear-all-submissions', authenticateAdmin, checkPermission('approve_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // This will cascade delete user_recipients due to foreign key
        await pool.query('DELETE FROM submissions');

        await logAdminActivity(pool, req.admin.adminId, 'clear_all_submissions', `Cleared all submissions`);

        res.json({ success: true, message: 'All submissions cleared successfully' });

    } catch (error) {
        console.error('Failed to clear submissions:', error);
        res.status(500).json({ error: 'Failed to clear submissions' });
    }
});

// Clear all redemptions (keeps users)
router.delete('/admin/clear-all-redemptions', authenticateAdmin, checkPermission('manage_redemptions'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        await pool.query('DELETE FROM redemptions');

        await logAdminActivity(pool, req.admin.adminId, 'clear_all_redemptions', `Cleared all redemption history`);

        res.json({ success: true, message: 'All redemptions cleared successfully' });



    } catch (error) {
        console.error('Failed to clear redemptions:', error);
        res.status(500).json({ error: 'Failed to clear redemptions' });
    }
});

// Clear all user recipients history
router.delete('/admin/clear-recipients-history', authenticateAdmin, checkPermission('approve_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        await pool.query('DELETE FROM user_recipients');

        await logAdminActivity(pool, req.admin.adminId, 'clear_recipients_history', `Cleared recipients history`);

        res.json({ success: true, message: 'Recipient history cleared successfully' });

    } catch (error) {
        console.error('Failed to clear recipients:', error);
        res.status(500).json({ error: 'Failed to clear recipients history' });
    }
});

// Get system statistics for data management
router.get('/admin/system-stats', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        const stats = {
            totalUsers: (await pool.query('SELECT COUNT(*) FROM users')).rows[0].count,
            totalSubmissions: (await pool.query('SELECT COUNT(*) FROM submissions')).rows[0].count,
            totalRedemptions: (await pool.query('SELECT COUNT(*) FROM redemptions')).rows[0].count,
            totalMessages: (await pool.query('SELECT COUNT(*) FROM user_messages')).rows[0].count,
            totalBroadcasts: (await pool.query('SELECT COUNT(*) FROM broadcast_messages')).rows[0].count,
            totalRecipients: (await pool.query('SELECT COUNT(*) FROM user_recipients')).rows[0].count,
            totalOffers: (await pool.query('SELECT COUNT(*) FROM offers')).rows[0].count
        };

        res.json({ stats });

    } catch (error) {
        console.error('Failed to get system stats:', error);
        res.status(500).json({ error: 'Failed to get system stats' });
    }
});


// ============================================
// ANALYTICS ROUTES (Admin Only)
// ============================================

// Get user growth analytics
router.get('/admin/analytics/user-growth', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    const { days = 30 } = req.query;

    try {
        const pool = req.app.get('db');

        // Get daily user registrations for the last X days
        const result = await pool.query(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as count
            FROM users
            WHERE created_at >= CURRENT_DATE - INTERVAL '${parseInt(days)} days'
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `);

        res.json({ data: result.rows });

    } catch (error) {
        console.error('Failed to get user growth analytics:', error);
        res.status(500).json({ error: 'Failed to get user growth analytics' });
    }
});

// Get points distribution analytics
router.get('/admin/analytics/points-distribution', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    const { days = 30 } = req.query;

    try {
        const pool = req.app.get('db');

        // Get daily points awarded for the last X days
        const result = await pool.query(`
            SELECT 
                DATE(created_at) as date,
                SUM(points_awarded) as total_points,
                COUNT(*) as submission_count
            FROM submissions
            WHERE created_at >= CURRENT_DATE - INTERVAL '${parseInt(days)} days'
            AND status = 'active'
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        `);

        res.json({ data: result.rows });

    } catch (error) {
        console.error('Failed to get points distribution analytics:', error);
        res.status(500).json({ error: 'Failed to get points distribution analytics' });
    }
});

// Get redemption status breakdown
router.get('/admin/analytics/redemption-status', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Get count by status
        const result = await pool.query(`
            SELECT 
                status,
                COUNT(*) as count,
                SUM(points_requested) as total_points
            FROM redemptions
            GROUP BY status
        `);

        res.json({ data: result.rows });

    } catch (error) {
        console.error('Failed to get redemption status analytics:', error);
        res.status(500).json({ error: 'Failed to get redemption status analytics' });
    }
});

// Get active users trend
router.get('/admin/analytics/active-users', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    const { days = 30 } = req.query;

    try {
        const pool = req.app.get('db');

        // Get daily active users (users who made submissions that day)
        const result = await pool.query(`
            SELECT 
                DATE(s.created_at) as date,
                COUNT(DISTINCT s.user_id) as active_users
            FROM submissions s
            WHERE s.created_at >= CURRENT_DATE - INTERVAL '${parseInt(days)} days'
            GROUP BY DATE(s.created_at)
            ORDER BY date ASC
        `);

        res.json({ data: result.rows });

    } catch (error) {
        console.error('Failed to get active users analytics:', error);
        res.status(500).json({ error: 'Failed to get active users analytics' });
    }
});

// Get overview statistics for analytics dashboard
router.get('/admin/analytics/overview', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Total users
        const totalUsers = await pool.query('SELECT COUNT(*) FROM users');

        // Total points distributed (all time)
        const totalPoints = await pool.query('SELECT SUM(points_awarded) FROM submissions WHERE status = \'active\'');

        // Total redeemed amount
        const totalRedeemed = await pool.query('SELECT SUM(points_requested) FROM redemptions WHERE status = \'approved\'');

        // Active users today
        const activeToday = await pool.query(`
            SELECT COUNT(DISTINCT user_id) 
            FROM submissions 
            WHERE DATE(created_at) = CURRENT_DATE
        `);

        // New users this week
        const newUsersWeek = await pool.query(`
            SELECT COUNT(*) 
            FROM users 
            WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
        `);

        // Pending redemptions
        const pendingRedemptions = await pool.query(`
            SELECT COUNT(*) 
            FROM redemptions 
            WHERE status = 'pending'
        `);

        res.json({
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalPointsDistributed: parseInt(totalPoints.rows[0].sum || 0),
            totalRedeemed: parseInt(totalRedeemed.rows[0].sum || 0),
            activeToday: parseInt(activeToday.rows[0].count),
            newUsersThisWeek: parseInt(newUsersWeek.rows[0].count),
            pendingRedemptions: parseInt(pendingRedemptions.rows[0].count)
        });

    } catch (error) {
        console.error('Failed to get analytics overview:', error);
        res.status(500).json({ error: 'Failed to get analytics overview' });
    }
});


// ============================================
// BANNER MANAGEMENT ROUTES
// ============================================

// Get all active banners (public)
router.get('/banners', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const banners = await pool.query(`
            SELECT id, image_url, title, link_url, display_order
            FROM banners 
            WHERE is_active = true 
            ORDER BY display_order ASC, created_at DESC
        `);
        res.json({ banners: banners.rows });
    } catch (error) {
        console.error('Failed to get banners:', error);
        res.status(500).json({ error: 'Failed to get banners' });
    }
});

// Get all banners (admin)
router.get('/admin/banners', authenticateAdmin, checkPermission('manage_banners'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const banners = await pool.query(`
            SELECT * FROM banners 
            ORDER BY display_order ASC, created_at DESC
        `);
        res.json({ banners: banners.rows });
    } catch (error) {
        console.error('Failed to get banners:', error);
        res.status(500).json({ error: 'Failed to get banners' });
    }
});

// Create banner (admin)
router.post('/admin/create-banner', authenticateAdmin, checkPermission('manage_banners'), uploadBanner.single('image'), async (req, res) => {
    const { title, link_url, display_order } = req.body;

    if (!req.file) {
        return res.status(400).json({ error: 'Image is required' });
    }

    try {
        const pool = req.app.get('db');
        const imagePath = '/uploads/banners/' + req.file.filename;

        await pool.query(
            'INSERT INTO banners (image_url, title, link_url, display_order) VALUES ($1, $2, $3, $4)',
            [imagePath, title || null, link_url || null, display_order || 0]
        );
        // ⬇️ ADD THIS LINE HERE (after banner is created, before res.json)
        await logAdminActivity(pool, req.admin.adminId, 'create_banner', `Created banner: ${title || 'Untitled'}`);

        res.json({ success: true, message: 'Banner created successfully' });
    } catch (error) {
        console.error('Failed to create banner:', error);
        res.status(500).json({ error: 'Failed to create banner' });
    }
});

// Update banner (admin)
router.put('/admin/update-banner/:id', authenticateAdmin, checkPermission('manage_banners'), uploadBanner.single('image'), async (req, res) => {
    const { id } = req.params;
    const { title, link_url, display_order } = req.body;

    try {
        const pool = req.app.get('db');

        if (req.file) {
            const imagePath = '/uploads/banners/' + req.file.filename;
            await pool.query(
                'UPDATE banners SET image_url = $1, title = $2, link_url = $3, display_order = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5',
                [imagePath, title || null, link_url || null, display_order || 0, id]
            );
        } else {
            await pool.query(
                'UPDATE banners SET title = $1, link_url = $2, display_order = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $4',
                [title || null, link_url || null, display_order || 0, id]
            );
        }

        // After successful update, BEFORE res.json():
        await logAdminActivity(
            pool,
            req.admin.adminId,
            'update_banner',
            `Updated banner ID ${id}: ${title || 'Untitled'}`
        );

        res.json({ success: true, message: 'Banner updated successfully' });
    } catch (error) {
        console.error('Failed to update banner:', error);
        res.status(500).json({ error: 'Failed to update banner' });
    }
});

// Toggle banner status (admin)
router.post('/admin/toggle-banner/:id', authenticateAdmin, checkPermission('manage_banners'), async (req, res) => {
    const { id } = req.params;

    try {
        const pool = req.app.get('db');
        await pool.query(
            'UPDATE banners SET is_active = NOT is_active, updated_at = CURRENT_TIMESTAMP WHERE id = $1',
            [id]
        );


        // ⬇️ ADD THIS LINE HERE (after toggle, before res.json)
        await logAdminActivity(pool, req.admin.adminId, 'toggle_banner', `Toggled banner ID ${id} status`);

        res.json({ success: true, message: 'Banner status updated' });
    } catch (error) {
        console.error('Failed to toggle banner:', error);
        res.status(500).json({ error: 'Failed to toggle banner status' });
    }
});

// Delete banner (admin)
router.delete('/admin/delete-banner/:id', authenticateAdmin, checkPermission('manage_banners'), async (req, res) => {
    const { id } = req.params;

    try {
        const pool = req.app.get('db');
        await pool.query('DELETE FROM banners WHERE id = $1', [id]);

        // ⬇️ ADD THIS LINE HERE (after deletion, before res.json)
        await logAdminActivity(pool, req.admin.adminId, 'delete_banner', `Deleted banner ID ${id}`);


        res.json({ success: true, message: 'Banner deleted successfully' });
    } catch (error) {
        console.error('Failed to delete banner:', error);
        res.status(500).json({ error: 'Failed to delete banner' });
    }
});


// ==================== SOCIAL LINKS ROUTES ====================

// Get all active social links (PUBLIC)
router.get('/social-links', async (req, res) => {
    try {
        const pool = req.app.get('db'); // ← CRITICAL: Get database pool

        const result = await pool.query(
            'SELECT * FROM social_links WHERE is_active = true ORDER BY display_order ASC'
        );

        res.json({ links: result.rows });
    } catch (error) {
        console.error('Error fetching social links:', error);
        res.json({ links: [] }); // Return empty array instead of crashing
    }
});

// Get all social links for admin (ADMIN ONLY)
router.get('/admin/social-links', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db'); // ← CRITICAL: Get database pool

        const result = await pool.query(
            'SELECT * FROM social_links ORDER BY display_order ASC'
        );

        res.json({ links: result.rows });
    } catch (error) {
        console.error('Error fetching admin social links:', error);
        res.json({ links: [] }); // Return empty array instead of 500 error
    }
});

// Create social link (ADMIN ONLY)
router.post('/admin/create-social-link', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { platform, title, url, icon, iconUrl, displayOrder } = req.body;

        if (!platform || !title || !url || !icon) {
            return res.status(400).json({ error: 'All fields required' });
        }

        const result = await pool.query(
            `INSERT INTO social_links (platform, title, url, icon, icon_url, display_order, is_active, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, true, NOW())
     RETURNING *`,
            [platform, title, url, icon || '', iconUrl || '', displayOrder || 0]
        );


        await logAdminActivity(pool, req.admin.adminId, 'create_social_link', `Created social link: ${title} (${platform})`);

        res.json({
            message: 'Social link created successfully',
            link: result.rows[0]
        });
    } catch (error) {
        console.error('Error creating social link:', error);
        res.status(500).json({ error: 'Failed to create social link' });
    }
});

// Update social link (ADMIN ONLY)
router.put('/admin/update-social-link/:id', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const { platform, title, url, icon, iconUrl, displayOrder } = req.body;

        const result = await pool.query(
            `UPDATE social_links 
             SET platform = $1, title = $2, url = $3, icon = $4, icon_url = $5, display_order = $6
             WHERE id = $7
             RETURNING *`,
            [platform, title, url, icon || '', iconUrl || '', displayOrder || 0, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Social link not found' });
        }


        await logAdminActivity(pool, req.admin.adminId, 'update_social_link', `Updated social link ID ${id}: ${title}`);



        res.json({
            message: 'Social link updated successfully',
            link: result.rows[0]
        });
    } catch (error) {
        console.error('Error updating social link:', error);
        res.status(500).json({ error: 'Failed to update social link' });
    }
});

// Toggle social link status (ADMIN ONLY)
router.post('/admin/toggle-social-link/:id', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE social_links SET is_active = NOT is_active WHERE id = $1 RETURNING *`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Social link not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'toggle_social_link', `Toggled social link ID ${id} status`);
        res.json({
            message: 'Status toggled successfully',
            link: result.rows[0]
        });
    } catch (error) {
        console.error('Error toggling social link:', error);
        res.status(500).json({ error: 'Failed to toggle social link' });
    }
});

// Delete social link (ADMIN ONLY)
router.delete('/admin/delete-social-link/:id', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const result = await pool.query(
            'DELETE FROM social_links WHERE id = $1 RETURNING *',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Social link not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'delete_social_link', `Deleted social link ID ${id}`);

        res.json({ message: 'Social link deleted successfully' });
    } catch (error) {
        console.error('Error deleting social link:', error);
        res.status(500).json({ error: 'Failed to delete social link' });
    }
});

module.exports = router;
