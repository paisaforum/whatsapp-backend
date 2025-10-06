const multer = require('multer');
const path = require('path');
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Storage for user submissions
const submissionStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/submissions/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'screenshot-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// Storage for admin offers
const offerStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/offers/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'offer-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// Multer upload for submissions
const uploadSubmission = multer({
    storage: submissionStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only image files are allowed'));
    }
});

// Multer upload for offers
const uploadOffer = multer({
    storage: offerStorage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error('Only image files are allowed'));
    }
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

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
        const [existingUser] = await pool.query(
            'SELECT id FROM users WHERE whatsapp_number = ?',
            [whatsappNumber]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({ error: 'Account with this number already exists. Please login.' });
        }

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Create new user
        const [result] = await pool.query(
            'INSERT INTO users (whatsapp_number, password_hash) VALUES (?, ?)',
            [whatsappNumber, passwordHash]
        );

        const userId = result.insertId;

        // Create JWT token
        const token = jwt.sign({ userId: userId }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            userId: userId,
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
        const [user] = await pool.query(
            'SELECT id, password_hash FROM users WHERE whatsapp_number = ?',
            [whatsappNumber]
        );

        if (user.length === 0) {
            return res.status(401).json({ error: 'Invalid WhatsApp number or password' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, user[0].password_hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid WhatsApp number or password' });
        }

        // Create JWT token
        const token = jwt.sign({ userId: user[0].id }, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            userId: user[0].id,
            token: token,
            message: 'Login successful!'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get user dashboard data (with pagination)
router.get('/dashboard/:userId', async (req, res) => {
    const { userId } = req.params;
    const { submissionsPage = 1, redemptionsPage = 1, limit = 5 } = req.query;

    try {
        const pool = req.app.get('db');

        // Get user info
        const [user] = await pool.query(
            'SELECT id, whatsapp_number, created_at FROM users WHERE id = ?',
            [userId]
        );

        if (user.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get current offer
        const [offer] = await pool.query(
            'SELECT * FROM offers WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1'
        );

        // Calculate user points
        const [pointsResult] = await pool.query(
            `SELECT COALESCE(SUM(points_earned), 0) as total_points
             FROM submissions 
             WHERE user_id = ? AND status = 'active'`,
            [userId]
        );

        // Get redeemed points
        const [redeemedResult] = await pool.query(
            `SELECT COALESCE(SUM(points_redeemed), 0) as redeemed_points
             FROM redemptions 
             WHERE user_id = ? AND status = 'approved'`,
            [userId]
        );

        const totalPoints = parseInt(pointsResult[0].total_points);
        const redeemedPoints = parseInt(redeemedResult[0].redeemed_points);
        const availablePoints = totalPoints - redeemedPoints;

        // Get total submission count
        const [submissionCountResult] = await pool.query(
            'SELECT COUNT(*) as total FROM submissions WHERE user_id = ?',
            [userId]
        );
        const totalSubmissions = parseInt(submissionCountResult[0].total);

        // Get paginated submissions
        const submissionsOffset = (submissionsPage - 1) * limit;
        const [submissions] = await pool.query(
            `SELECT * FROM submissions 
             WHERE user_id = ? 
             ORDER BY created_at DESC 
             LIMIT ? OFFSET ?`,
            [userId, parseInt(limit), submissionsOffset]
        );

        // Get total redemption count
        const [redemptionCountResult] = await pool.query(
            'SELECT COUNT(*) as total FROM redemptions WHERE user_id = ?',
            [userId]
        );
        const totalRedemptions = parseInt(redemptionCountResult[0].total);

        // Get paginated redemptions
        const redemptionsOffset = (redemptionsPage - 1) * limit;
        const [redemptions] = await pool.query(
            `SELECT * FROM redemptions 
             WHERE user_id = ? 
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?`,
            [userId, parseInt(limit), redemptionsOffset]
        );

        // Get unread notifications
        const [notifications] = await pool.query(
            `SELECT * FROM notifications 
             WHERE user_id = ? AND is_read = 0 
             ORDER BY created_at DESC`,
            [userId]
        );

        // Get pending redemptions
        const [pendingRedemption] = await pool.query(
            `SELECT * FROM redemptions 
             WHERE user_id = ? AND status = 'pending'
             ORDER BY created_at DESC
             LIMIT 1`,
            [userId]
        );

        res.json({
            user: user[0],
            offer: offer[0] || null,
            points: {
                total: totalPoints,
                redeemed: redeemedPoints,
                available: availablePoints
            },
            submissions: submissions,
            submissionsPagination: {
                total: totalSubmissions,
                page: parseInt(submissionsPage),
                limit: parseInt(limit),
                totalPages: Math.ceil(totalSubmissions / limit)
            },
            redemptions: redemptions,
            redemptionsPagination: {
                total: totalRedemptions,
                page: parseInt(redemptionsPage),
                limit: parseInt(limit),
                totalPages: Math.ceil(totalRedemptions / limit)
            },
            notifications: notifications,
            pendingRedemption: pendingRedemption[0] || null
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});

// Submit proof endpoint
router.post('/submit-proof', uploadSubmission.array('screenshots', 20), async (req, res) => {
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

        const [duplicateCheck] = await pool.query(
            `SELECT recipient_hash FROM user_recipients 
             WHERE user_id = ? AND recipient_hash IN (${hashedNumbers.map(() => '?').join(',')})`,
            [userId, ...hashedNumbers]
        );

        if (duplicateCheck.length > 0) {
            return res.status(400).json({
                error: 'You have already submitted shares to some of these recipients'
            });
        }

        // Store screenshot paths as JSON
        const screenshotPaths = screenshots.map(file => `/uploads/submissions/${file.filename}`);
        const screenshotPathsJSON = JSON.stringify(screenshotPaths);

        // Create submission
        const [result] = await pool.query(
            `INSERT INTO submissions (user_id, screenshot_url, points_earned, status) 
             VALUES (?, ?, ?, 'active')`,
            [userId, screenshotPathsJSON, numbers.length]
        );

        const submissionId = result.insertId;

        // Store recipient mappings
        for (let i = 0; i < hashedNumbers.length; i++) {
            await pool.query(
                `INSERT INTO user_recipients (user_id, recipient_hash, recipient_number, submission_id) 
                 VALUES (?, ?, ?, ?)`,
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
router.post('/request-redemption', async (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'User ID required' });
    }

    try {
        const pool = req.app.get('db');

        // Get system settings
        const [settingsRows] = await pool.query('SELECT * FROM system_settings LIMIT 1');
        const settings = settingsRows[0];

        // Calculate available points
        const [pointsResult] = await pool.query(
            `SELECT COALESCE(SUM(points_earned), 0) as total_points
             FROM submissions 
             WHERE user_id = ? AND status = 'active'`,
            [userId]
        );

        const [redeemedResult] = await pool.query(
            `SELECT COALESCE(SUM(points_redeemed), 0) as redeemed_points
             FROM redemptions 
             WHERE user_id = ? AND status = 'approved'`,
            [userId]
        );

        const totalPoints = parseInt(pointsResult[0].total_points);
        const redeemedPoints = parseInt(redeemedResult[0].redeemed_points);
        const availablePoints = totalPoints - redeemedPoints;

        // Check if user has enough points
        if (availablePoints < settings.min_redemption_points) {
            return res.status(400).json({
                error: `You need ${settings.min_redemption_points} points to redeem. You have ${availablePoints} points.`
            });
        }

        // Check if user already has a pending redemption
        const [pendingCheck] = await pool.query(
            `SELECT id FROM redemptions 
             WHERE user_id = ? AND status = 'pending'`,
            [userId]
        );

        if (pendingCheck.length > 0) {
            return res.status(400).json({
                error: 'You already have a pending redemption request. Please wait for review.'
            });
        }

        // Create redemption request
        const [result] = await pool.query(
            `INSERT INTO redemptions (user_id, points_redeemed, status) 
             VALUES (?, ?, 'pending')`,
            [userId, settings.redemption_amount]
        );

        // Create notification for user
        await pool.query(
            `INSERT INTO notifications (user_id, type, message) 
             VALUES (?, 'info', 'Your redemption request has been submitted and is under review.')`,
            [userId]
        );

        res.json({
            success: true,
            redemptionId: result.insertId,
            message: 'Redemption request submitted successfully!'
        });

    } catch (error) {
        console.error('Redemption request error:', error);
        res.status(500).json({ error: 'Failed to submit redemption request' });
    }
});

// Admin login
router.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        const pool = req.app.get('db');

        // Find admin
        const [admin] = await pool.query(
            'SELECT id, username, password_hash FROM admins WHERE username = ?',
            [username]
        );

        if (admin.length === 0) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Check password
        const validPassword = await bcrypt.compare(password, admin[0].password_hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Create JWT token
        const token = jwt.sign({ adminId: admin[0].id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            adminId: admin[0].id,
            token: token,
            message: 'Login successful!'
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Get all redemption requests (admin)
router.get('/admin/redemptions', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { page = 1, limit = 20, status = 'all', search = '' } = req.query;
        const offset = (page - 1) * limit;

        // Build WHERE clause
        let whereClause = 'WHERE 1=1';
        const queryParams = [];

        if (status !== 'all') {
            whereClause += ` AND r.status = ?`;
            queryParams.push(status);
        }

        if (search) {
            whereClause += ` AND u.whatsapp_number LIKE ?`;
            queryParams.push(`%${search}%`);
        }

        // Get total count
        const [countResult] = await pool.query(
            `SELECT COUNT(*) as total 
             FROM redemptions r
             JOIN users u ON r.user_id = u.id
             ${whereClause}`,
            queryParams
        );

        const total = parseInt(countResult[0].total);

        // Get paginated results
        queryParams.push(parseInt(limit), offset);
        const [redemptions] = await pool.query(
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
               r.created_at DESC
             LIMIT ? OFFSET ?`,
            queryParams
        );

        res.json({
            redemptions: redemptions,
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
router.get('/admin/user-submissions/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        const [submissions] = await pool.query(
            `SELECT s.*, GROUP_CONCAT(ur.recipient_number) as recipient_numbers
             FROM submissions s
             LEFT JOIN user_recipients ur ON s.id = ur.submission_id
             WHERE s.user_id = ? 
             GROUP BY s.id
             ORDER BY s.created_at DESC`,
            [userId]
        );

        // Convert concatenated string to array
        const submissionsWithArrays = submissions.map(sub => ({
            ...sub,
            recipient_numbers: sub.recipient_numbers ? sub.recipient_numbers.split(',') : []
        }));

        res.json({ submissions: submissionsWithArrays });
    } catch (error) {
        console.error('Failed to fetch submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});

// Review redemption (admin)
router.post('/admin/review-redemption', async (req, res) => {
    const { redemptionId, action, giftCode, rejectionReason } = req.body;

    try {
        const pool = req.app.get('db');

        if (action === 'approve') {
            // Update redemption
            await pool.query(
                `UPDATE redemptions 
                 SET status = 'approved', gift_code = ?, updated_at = NOW() 
                 WHERE id = ?`,
                [giftCode, redemptionId]
            );

            // Get redemption details
            const [redemption] = await pool.query(
                'SELECT user_id, points_redeemed FROM redemptions WHERE id = ?',
                [redemptionId]
            );

            const userId = redemption[0].user_id;

            // Create notification
            await pool.query(
                `INSERT INTO notifications (user_id, type, message) 
                 VALUES (?, 'info', CONCAT('Your redemption has been approved! Gift Code: ', ?))`,
                [userId, giftCode]
            );

            res.json({ success: true, message: 'Redemption approved' });

        } else if (action === 'reject') {
            // Update redemption
            await pool.query(
                `UPDATE redemptions 
                 SET status = 'rejected', rejection_reason = ?, updated_at = NOW() 
                 WHERE id = ?`,
                [rejectionReason, redemptionId]
            );

            // Get redemption details
            const [redemption] = await pool.query(
                'SELECT user_id FROM redemptions WHERE id = ?',
                [redemptionId]
            );

            const userId = redemption[0].user_id;

            // Create notification
            await pool.query(
                `INSERT INTO notifications (user_id, type, message) 
                 VALUES (?, 'info', CONCAT('Your redemption request was rejected. Reason: ', ?))`,
                [userId, rejectionReason]
            );

            res.json({ success: true, message: 'Redemption rejected' });
        }

    } catch (error) {
        console.error('Failed to review redemption:', error);
        res.status(500).json({ error: 'Failed to review redemption' });
    }
});

// Get all users (admin)
router.get('/admin/users', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { page = 1, limit = 20, search = '' } = req.query;
        const offset = (page - 1) * limit;

        let whereClause = 'WHERE 1=1';
        const queryParams = [];

        if (search) {
            whereClause += ` AND u.whatsapp_number LIKE ?`;
            queryParams.push(`%${search}%`);
        }

        // Get total count
        const [countResult] = await pool.query(
            `SELECT COUNT(*) as total FROM users u ${whereClause}`,
            queryParams
        );

        const total = parseInt(countResult[0].total);

        queryParams.push(parseInt(limit), offset);

        const [users] = await pool.query(
            `SELECT u.id, u.whatsapp_number, u.created_at,
              COALESCE(SUM(s.points_earned), 0) as total_points
             FROM users u
             LEFT JOIN submissions s ON u.id = s.user_id AND s.status = 'active'
             ${whereClause}
             GROUP BY u.id, u.whatsapp_number, u.created_at
             ORDER BY u.created_at DESC
             LIMIT ? OFFSET ?`,
            queryParams
        );

        res.json({
            users: users,
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

// Add points to user (admin)
router.post('/admin/add-points', async (req, res) => {
    const { userId, points } = req.body;

    if (!userId || !points || points <= 0) {
        return res.status(400).json({ error: 'Valid user ID and points required' });
    }

    try {
        const pool = req.app.get('db');

        await pool.query(
            `INSERT INTO submissions (user_id, screenshot_url, points_earned, status) 
             VALUES (?, '/uploads/admin-test.jpg', ?, 'active')`,
            [userId, points]
        );

        res.json({ success: true, message: `Added ${points} points successfully` });
    } catch (error) {
        console.error('Failed to add points:', error);
        res.status(500).json({ error: 'Failed to add points' });
    }
});

// Deduct points from user (admin)
router.post('/admin/deduct-points', async (req, res) => {
    const { userId, points } = req.body;

    if (!userId || !points || points <= 0) {
        return res.status(400).json({ error: 'Valid user ID and points required' });
    }

    try {
        const pool = req.app.get('db');

        // Check current available points
        const [pointsResult] = await pool.query(
            `SELECT COALESCE(SUM(points_earned), 0) as total_points
             FROM submissions 
             WHERE user_id = ? AND status = 'active'`,
            [userId]
        );

        const currentPoints = parseInt(pointsResult[0].total_points);

        if (currentPoints < points) {
            return res.status(400).json({
                error: `Cannot deduct ${points} points. User only has ${currentPoints} available points.`
            });
        }

        await pool.query(
            `INSERT INTO submissions (user_id, screenshot_url, points_earned, status) 
             VALUES (?, '/uploads/admin-deduct.jpg', ?, 'active')`,
            [userId, -points]
        );

        res.json({ success: true, message: `Deducted ${points} points successfully` });
    } catch (error) {
        console.error('Failed to deduct points:', error);
        res.status(500).json({ error: 'Failed to deduct points' });
    }
});

// Delete user (admin)
router.delete('/admin/delete-user/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        await pool.query('DELETE FROM users WHERE id = ?', [userId]);

        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Failed to delete user:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

// Cancel submission (user)
router.post('/cancel-submission', async (req, res) => {
    const { submissionId, userId } = req.body;

    if (!submissionId || !userId) {
        return res.status(400).json({ error: 'Submission ID and User ID required' });
    }

    try {
        const pool = req.app.get('db');

        const [submission] = await pool.query(
            `SELECT * FROM submissions WHERE id = ? AND user_id = ? AND status = 'active'`,
            [submissionId, userId]
        );

        if (submission.length === 0) {
            return res.status(404).json({ error: 'Submission not found or already cancelled' });
        }

        await pool.query(
            `UPDATE submissions SET status = 'cancelled' WHERE id = ?`,
            [submissionId]
        );

        res.json({
            success: true,
            message: 'Submission cancelled successfully',
            pointsDeducted: submission[0].points_earned
        });

    } catch (error) {
        console.error('Failed to cancel submission:', error);
        res.status(500).json({ error: 'Failed to cancel submission' });
    }
});

// Get user profile (admin)
router.get('/admin/user-profile/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        const [user] = await pool.query(
            `SELECT u.id, u.whatsapp_number, u.created_at,
              COALESCE(SUM(s.points_earned), 0) as total_points
             FROM users u
             LEFT JOIN submissions s ON u.id = s.user_id AND s.status = 'active'
             WHERE u.id = ?
             GROUP BY u.id, u.whatsapp_number, u.created_at`,
            [userId]
        );

        if (user.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: user[0] });
    } catch (error) {
        console.error('Failed to fetch user profile:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

// Delete single submission (admin)
router.delete('/admin/delete-submission/:submissionId', async (req, res) => {
    const { submissionId } = req.params;

    try {
        const pool = req.app.get('db');

        const [submission] = await pool.query(
            'SELECT user_id, points_earned, status FROM submissions WHERE id = ?',
            [submissionId]
        );

        if (submission.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        await pool.query('DELETE FROM submissions WHERE id = ?', [submissionId]);

        res.json({
            success: true,
            message: 'Submission deleted successfully',
            pointsDeducted: submission[0].status === 'active' ? submission[0].points_earned : 0
        });

    } catch (error) {
        console.error('Failed to delete submission:', error);
        res.status(500).json({ error: 'Failed to delete submission' });
    }
});

// Bulk delete submissions (admin)
router.post('/admin/bulk-delete-submissions', async (req, res) => {
    const { submissionIds } = req.body;

    if (!submissionIds || submissionIds.length === 0) {
        return res.status(400).json({ error: 'No submissions selected' });
    }

    try {
        const pool = req.app.get('db');

        const [pointsResult] = await pool.query(
            `SELECT SUM(points_earned) as total_points 
             FROM submissions 
             WHERE id IN (${submissionIds.map(() => '?').join(',')}) AND status = 'active'`,
            submissionIds
        );

        await pool.query(
            `DELETE FROM submissions WHERE id IN (${submissionIds.map(() => '?').join(',')})`,
            submissionIds
        );

        res.json({
            success: true,
            message: `${submissionIds.length} submissions deleted successfully`,
            pointsDeducted: parseInt(pointsResult[0].total_points || 0)
        });

    } catch (error) {
        console.error('Failed to bulk delete submissions:', error);
        res.status(500).json({ error: 'Failed to delete submissions' });
    }
});

// Get all offers (admin)
router.get('/admin/offers', async (req, res) => {
    try {
        const pool = req.app.get('db');

        const [offers] = await pool.query(
            'SELECT * FROM offers ORDER BY created_at DESC'
        );

        res.json({ offers: offers });
    } catch (error) {
        console.error('Failed to fetch offers:', error);
        res.status(500).json({ error: 'Failed to fetch offers' });
    }
});

// Create new offer (admin)
router.post('/admin/create-offer', uploadOffer.single('image'), async (req, res) => {
    const { caption } = req.body;
    const image = req.file;

    if (!caption || !image) {
        return res.status(400).json({ error: 'Caption and image are required' });
    }

    try {
        const pool = req.app.get('db');
        const imagePath = `/uploads/offers/${image.filename}`;

        const [result] = await pool.query(
            'INSERT INTO offers (image_url, caption, is_active) VALUES (?, ?, 0)',
            [imagePath, caption]
        );

        res.json({ success: true, offer: { id: result.insertId, image_url: imagePath, caption, is_active: 0 } });
    } catch (error) {
        console.error('Failed to create offer:', error);
        res.status(500).json({ error: 'Failed to create offer' });
    }
});

// Update offer (admin)
router.put('/admin/update-offer/:offerId', uploadOffer.single('image'), async (req, res) => {
    const { offerId } = req.params;
    const { caption } = req.body;
    const image = req.file;

    try {
        const pool = req.app.get('db');

        if (image) {
            const imagePath = `/uploads/offers/${image.filename}`;
            await pool.query(
                'UPDATE offers SET caption = ?, image_url = ? WHERE id = ?',
                [caption, imagePath, offerId]
            );
        } else {
            await pool.query(
                'UPDATE offers SET caption = ? WHERE id = ?',
                [caption, offerId]
            );
        }

        res.json({ success: true, message: 'Offer updated successfully' });
    } catch (error) {
        console.error('Failed to update offer:', error);
        res.status(500).json({ error: 'Failed to update offer' });
    }
});

// Set active offer (admin)
router.post('/admin/set-active-offer', async (req, res) => {
    const { offerId } = req.body;

    try {
        const pool = req.app.get('db');

        await pool.query('UPDATE offers SET is_active = 0');
        await pool.query('UPDATE offers SET is_active = 1 WHERE id = ?', [offerId]);

        res.json({ success: true, message: 'Active offer updated' });
    } catch (error) {
        console.error('Failed to set active offer:', error);
        res.status(500).json({ error: 'Failed to set active offer' });
    }
});

// Delete offer (admin)
router.delete('/admin/delete-offer/:offerId', async (req, res) => {
    const { offerId } = req.params;

    try {
        const pool = req.app.get('db');

        await pool.query('DELETE FROM offers WHERE id = ?', [offerId]);

        res.json({ success: true, message: 'Offer deleted successfully' });
    } catch (error) {
        console.error('Failed to delete offer:', error);
        res.status(500).json({ error: 'Failed to delete offer' });
    }
});

// Get all recipient numbers for a user
router.get('/user-recipients/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        const [recipients] = await pool.query(
            `SELECT recipient_number, MIN(created_at) as first_shared
             FROM user_recipients
             WHERE user_id = ? AND recipient_number IS NOT NULL
             GROUP BY recipient_number
             ORDER BY recipient_number`,
            [userId]
        );

        res.json({ recipients: recipients });
    } catch (error) {
        console.error('Failed to fetch recipients:', error);
        res.status(500).json({ error: 'Failed to fetch recipients' });
    }
});

// Get system settings
router.get('/settings', async (req, res) => {
    try {
        const pool = req.app.get('db');

        const [settings] = await pool.query(
            'SELECT * FROM system_settings LIMIT 1'
        );

        res.json({ settings: settings[0] || {} });
    } catch (error) {
        console.error('Failed to fetch settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Update system setting (admin)
router.put('/admin/settings', async (req, res) => {
    const { points_per_rupee, min_redemption_points, redemption_amount } = req.body;

    try {
        const pool = req.app.get('db');

        await pool.query(
            `UPDATE system_settings 
             SET points_per_rupee = ?, min_redemption_points = ?, redemption_amount = ?, updated_at = NOW()
             WHERE id = 1`,
            [points_per_rupee, min_redemption_points, redemption_amount]
        );

        res.json({ success: true, message: 'Settings updated successfully' });
    } catch (error) {
        console.error('Failed to update settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

module.exports = router;