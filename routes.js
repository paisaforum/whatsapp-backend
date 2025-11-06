const multer = require('multer');
const path = require('path');
const fs = require('fs');
const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// Public config endpoint (no auth required)
router.get('/config', async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Get domain settings
        const settings = await pool.query(
            `SELECT setting_key, setting_value 
             FROM settings 
             WHERE setting_key IN ('primary_domain', 'api_url')`
        );

        const config = {};
        settings.rows.forEach(row => {
            config[row.setting_key] = row.setting_value;
        });

        // Default values if not set
        config.api_url = config.api_url || `http://${req.get('host')}/api`;
        config.primary_domain = config.primary_domain || req.get('host');

        res.json(config);
    } catch (error) {
        console.error('Error fetching config:', error);
        res.status(500).json({ error: 'Failed to fetch config' });
    }
});

// ==================== POINT TRANSACTION HELPER ====================

const logPointTransaction = async (pool, userId, amount, type, description, referenceId = null) => {
    try {
        // Get current balance
        const userResult = await pool.query('SELECT points FROM users WHERE id = $1', [userId]);
        const balanceAfter = userResult.rows[0]?.points || 0;

        // Log transaction
        await pool.query(`
            INSERT INTO point_transactions (user_id, amount, transaction_type, description, reference_id, balance_after)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [userId, amount, type, description, referenceId, balanceAfter]);

        // Update user's earnings column based on type
        const earningsColumns = {
            'spin': 'spin_earnings',
            'referral': 'referral_earnings',
            'task': 'task_earnings',
            'milestone': 'milestone_earnings',
            'signup_bonus': 'signup_bonus_earnings',
            'streak': 'streak_earnings'
        };

        const column = earningsColumns[type];
        if (column && amount > 0) {
            await pool.query(`UPDATE users SET ${column} = ${column} + $1 WHERE id = $2`, [amount, userId]);
        }

        console.log(`✅ Logged transaction: User ${userId} ${amount > 0 ? '+' : ''}${amount} pts (${type})`);
    } catch (error) {
        console.error('Error logging point transaction:', error);
    }
};



const logActivity = async (pool, userId, activityType, title, description, points, metadata = {}) => {
    try {
        await pool.query(
            `INSERT INTO activity_log (user_id, activity_type, title, description, points, metadata)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [userId, activityType, title, description, points, JSON.stringify(metadata)]
        );
        console.log(`📝 Activity logged: ${activityType} for user ${userId}`);
    } catch (error) {
        console.error('❌ Failed to log activity:', error);
    }
};

const logSpinActivity = async (pool, userId, prize, spinType) => {
    await logActivity(
        pool,
        userId,
        'spin',
        'Spin Wheel',
        `Earned points on ${spinType} Spin`,
        prize,
        { prize, spinType }
    );
};



const logGlobalTaskActivity = async (pool, userId, phone_number, points, leadId, instantAward) => {
    const status = instantAward ? 'earned' : 'pending approval';
    const maskedPhone = phone_number ? `+91${phone_number.slice(-10)}` : 'Hidden';

    await logActivity(
        pool,
        userId,
        'global_task',
        'Global Task',
        `Sent offer to ${maskedPhone} - points ${status}`,
        points,
        { phone_number, leadId, instantAward }
    );
};

const logPersonalShareActivity = async (pool, userId, recipientCount, points, shareType = 'offer') => {
    const contactText = recipientCount === 1 ? 'contact' : 'contacts';
    const pointText = points === 1 ? 'point' : 'points';

    await logActivity(
        pool,
        userId,
        'personal_share',
        'Personal Share',
        `Shared ${shareType} with ${recipientCount} ${contactText}`,
        points,
        { recipientCount, shareType }
    );
};

const logMilestoneActivity = async (pool, userId, shares, bonus, totalShares, nextMilestone = null) => {
    const nextInfo = nextMilestone ? ` | Next: ${nextMilestone} shares` : '';

    await logActivity(
        pool,
        userId,
        'milestone',
        `${shares} Shares Milestone`,
        `Reached ${shares} total shares`,
        bonus,
        { milestone: shares, totalShares, nextMilestone }
    );
};

const logStreakActivity = async (pool, userId, day, bonus, nextDayBonus = null) => {
    const dayText = day === 1 ? 'day' : 'consecutive days';
    const nextInfo = nextDayBonus ? ` | Day ${day + 1}: ${nextDayBonus} points` : '';

    await logActivity(
        pool,
        userId,
        'streak',
        `Day ${day} Streak Bonus`,
        `${day} ${dayText} streak - Earned ${bonus} points${nextInfo}`,
        bonus,
        { day, consecutive: day > 1, nextDayBonus }
    );
};

const logReferralActivity = async (pool, referrerId, referredPhone, bonus, referredUserId) => {
    const maskedPhone = referredPhone ? `+91${referredPhone.slice(-10)}` : 'Friend';

    await logActivity(
        pool,
        referrerId,
        'referral',
        'Referral Bonus',
        `${maskedPhone} joined using your code`,
        bonus,
        { referredPhone, referredUserId }
    );
};

const logWelcomeBonusActivity = async (pool, newUserId, referrerPhone, bonus, referrerId) => {
    const maskedPhone = referrerPhone ? `+91${referrerPhone.slice(-10)}` : 'Referrer';

    await logActivity(
        pool,
        newUserId,
        'referral',
        'Welcome Bonus',
        `${maskedPhone} referred you`,
        bonus,
        { referredBy: referrerId, referrerPhone }
    );
};

const logCommissionActivity = async (pool, referrerId, referredPhone, commission, percentage, fromAmount, referredUserId) => {
    const maskedPhone = referredPhone ? `+91${referredPhone.slice(-10)}` : 'Referral';

    await logActivity(
        pool,
        referrerId,
        'commission',
        'Commission Earned %',
        `${percentage}% commission from ${maskedPhone} (earned ${fromAmount} pts) - Got ${commission} points`,
        commission,
        {
            fromPhone: referredPhone,
            fromUserId: referredUserId,
            percentage,
            fromAmount
        }
    );
};

const logBonusSpinActivity = async (pool, userId, spinsAwarded, totalShares, sharesNeeded) => {
    const spinText = spinsAwarded === 1 ? 'spin' : 'spins';

    await logActivity(
        pool,
        userId,
        'bonus_spin',
        'Bonus Spin Awarded',
        `Earned ${spinsAwarded} bonus ${spinText} for reaching ${totalShares} shares (${sharesNeeded} shares per spin)`,
        0,
        { spinsAwarded, totalShares, sharesNeeded }
    );
};

const logAdminApprovalActivity = async (pool, userId, points, submissionId, adminId) => {
    await logActivity(
        pool,
        userId,
        'admin_approval',
        'Task Approved',
        `Admin approved your submission - Earned ${points} points`,
        points,
        { submissionId, approvedBy: adminId }
    );
};

// ============================================
// BONUS SPIN AWARD HELPER FUNCTION
// ============================================
const awardBonusSpin = async (pool, userId) => {
    try {
        console.log('===== BONUS SPIN AWARD STARTED =====');
        console.log('User ID:', userId);

        const spinSettings = await pool.query(
            'SELECT setting_value FROM settings WHERE setting_key = $1',
            ['spin_per_shares']
        );
        const sharesNeeded = parseInt(spinSettings.rows[0]?.setting_value) || 10;
        console.log('Shares needed per spin:', sharesNeeded);

        // Count OLD system shares (global tasks - OLD)
        const oldSpinShares = await pool.query(
            `SELECT COUNT(DISTINCT recipient_number) as total
             FROM user_recipients ur
             JOIN submissions s ON ur.submission_id = s.id
             WHERE s.user_id = $1 AND s.status = 'active'`,
            [userId]
        );

        // Count NEW global tasks
        const newGlobalTasks = await pool.query(
            `SELECT COUNT(*) as total
             FROM user_lead_assignments
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        // Count NEW system shares (personal shares)
        const newSpinShares = await pool.query(
            `SELECT recipient_numbers FROM personal_share_submissions 
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        let newPersonalCount = 0;
        for (const row of newSpinShares.rows) {
            try {
                const data = JSON.parse(row.recipient_numbers || '{}');
                newPersonalCount += data.recipients?.length || 0;
            } catch (e) {
                console.log('Error parsing recipient_numbers:', e);
            }
        }

        const oldGlobalCount = parseInt(oldSpinShares.rows[0].total) || 0;
        const newGlobalCount = parseInt(newGlobalTasks.rows[0].total) || 0;
        const shareCount = oldGlobalCount + newGlobalCount + newPersonalCount;

        console.log('Old global tasks:', oldGlobalCount);
        console.log('New global tasks:', newGlobalCount);
        console.log('New personal shares:', newPersonalCount);
        console.log('Total shareCount:', shareCount);

        // ✅ NEW LOGIC: Calculate total spins earned vs current spins
        const spinsEarned = Math.floor(shareCount / sharesNeeded);
        console.log(`Total spins earned: ${spinsEarned} (${shareCount} shares / ${sharesNeeded} per spin)`);

        if (spinsEarned > 0) {
            let userSpins = await pool.query(
                'SELECT bonus_spins FROM user_spins WHERE user_id = $1',
                [userId]
            );

            const currentSpins = userSpins.rows.length > 0 ? (userSpins.rows[0].bonus_spins || 0) : 0;
            const spinsToAward = spinsEarned - currentSpins;

            console.log(`Current bonus spins: ${currentSpins}`);
            console.log(`Spins to award: ${spinsToAward}`);

            if (spinsToAward > 0) {
                if (userSpins.rows.length === 0) {
                    console.log(`Creating new user_spins record with ${spinsEarned} spins`);
                    await pool.query(
                        'INSERT INTO user_spins (user_id, bonus_spins) VALUES ($1, $2)',
                        [userId, spinsEarned]
                    );
                } else {
                    console.log(`Adding ${spinsToAward} spins (from ${currentSpins} to ${spinsEarned})`);
                    await pool.query(
                        'UPDATE user_spins SET bonus_spins = $1 WHERE user_id = $2',
                        [spinsEarned, userId]
                    );
                }

                console.log(`🎉 Awarded ${spinsToAward} bonus spin(s) to user ${userId}!`);
                console.log('===== BONUS SPIN AWARD COMPLETED =====');
                return true;
            } else {
                console.log('✅ User already has correct number of spins');
                console.log('===== BONUS SPIN AWARD ENDED =====');
                return false;
            }
        } else {
            console.log('❌ Not enough shares for a bonus spin yet');
            console.log('===== BONUS SPIN AWARD ENDED =====');
            return false;
        }
    } catch (error) {
        console.error('Bonus spin award error:', error);
        console.log('===== BONUS SPIN AWARD FAILED =====');
        return false;
    }
};

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { authenticateUser, authenticateAdmin, JWT_SECRET } = require('./middleware/auth');
const XLSX = require('xlsx');

const uploadLeadsFile = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 100 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowed = ['.csv', '.txt', '.xlsx', '.xls'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowed.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only CSV, TXT, or XLSX files allowed'));
        }
    }
});

// Middleware to check if admin is super_admin
const requireSuperAdmin = (req, res, next) => {
    if (req.admin.role !== 'super_admin') {
        return res.status(403).json({ error: 'Access denied. Super admin only.' });
    }
    next();
};

const checkPermission = (requiredPermission) => {
    return async (req, res, next) => {
        try {
            // Super admin has all permissions
            if (req.admin.role === 'super_admin') {
                return next();
            }

            const pool = req.app.get('db');

            // Get admin's permissions from database
            const result = await pool.query(
                'SELECT permission FROM admin_permissions WHERE admin_id = $1',
                [req.admin.id]
            );

            const permissions = result.rows.map(row => row.permission);

            // Check if admin has the exact permission required
            if (permissions.includes(requiredPermission)) {
                return next();
            }

            // BACKWARD COMPATIBILITY: Map old permissions to new ones
            const backwardCompatMap = {
                'view_users': ['user_view_all', 'user_referral_data', 'user_activity_logs', 'user_ban'],
                'manage_users': ['user_manage', 'user_points'],
                'manage_personal_share': ['task_personal_configuration', 'task_personal_submissions', 'task_personal_settings'],
                'view_analytics': ['view_analytics', 'manage_fake_statistics']
            };

            // Check if admin has an old permission that maps to the required new permission
            for (const [oldPerm, newPerms] of Object.entries(backwardCompatMap)) {
                if (permissions.includes(oldPerm) && newPerms.includes(requiredPermission)) {
                    return next();
                }
            }

            // No permission found
            return res.status(403).json({
                error: 'Access denied. Insufficient permissions.',
                required: requiredPermission
            });

        } catch (error) {
            console.error('Permission check error:', error);
            res.status(500).json({ error: 'Permission check failed' });
        }
    };
};

// ADD THIS HELPER RIGHT AFTER checkPermission:
const checkSettingsPermission = (req, res, next) => {
    try {
        // For super admin, bypass all checks
        if (req.admin.role === 'super_admin') {
            return next();
        }

        const settingType = req.body.type || req.query.type || req.params.key;

        // If no specific type (bulk update), check if admin has ANY settings permission
        if (!settingType) {
            const settingsPermissions = [
                'settings_referral',
                'settings_spin',
                'settings_streak',
                'settings_milestone'
            ];

            const hasAnyPermission = settingsPermissions.some(p =>
                req.admin.permissions?.includes(p)
            );

            if (!hasAnyPermission) {
                return res.status(403).json({ error: 'Access denied to settings' });
            }

            return next();
        }

        // If specific type provided, check that permission
        const settingsMap = {
            'referral': 'settings_referral',
            'spin': 'settings_spin',
            'wheel': 'settings_spin',
            'streak': 'settings_streak',
            'milestone': 'settings_milestone',
            'milestones': 'settings_milestone'
        };

        const permission = settingsMap[settingType.toLowerCase()];

        if (!permission) {
            return res.status(400).json({ error: 'Invalid setting type' });
        }

        return checkPermission(permission)(req, res, next);

    } catch (error) {
        console.error('Settings permission check error:', error);
        return res.status(500).json({ error: 'Permission check failed' });
    }
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



router.post('/register', async (req, res) => {
    const { whatsappNumber, password, referredByCode } = req.body;

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

        // Capture IP address
        const userIp = req.headers['x-forwarded-for']?.split(',')[0] ||
            req.headers['x-real-ip'] ||
            req.connection?.remoteAddress ||
            req.socket?.remoteAddress ||
            'unknown';

        // Hash password
        const passwordHash = await bcrypt.hash(password, 10);

        // Generate unique referral code
        const referralCode = `REF${Math.floor(Math.random() * 1000000).toString().padStart(6, '0')}`;

        // Create new user with referral code and IP
        const newUser = await pool.query(
            'INSERT INTO users (whatsapp_number, password_hash, referral_code, referred_by_code, registration_ip, last_login_ip) VALUES ($1, $2, $3, $4, $5, $5) RETURNING id, whatsapp_number',
            [whatsappNumber, passwordHash, referralCode, referredByCode || null, userIp]
        );

        const userId = newUser.rows[0].id;
        const userWhatsappNumber = newUser.rows[0].whatsapp_number;

        // Log IP history
        await pool.query(
            'INSERT INTO user_ip_history (user_id, ip_address, action) VALUES ($1, $2, $3)',
            [userId, userIp, 'registration']
        );

        // If user was referred, create referral relationship
        if (referredByCode) {
            const referrer = await pool.query(
                'SELECT id FROM users WHERE referral_code = $1',
                [referredByCode]
            );

            if (referrer.rows.length > 0) {
                const referrerId = referrer.rows[0].id;

                // Get signup bonus from settings
                const bonusSettings = await pool.query(
                    'SELECT setting_value FROM settings WHERE setting_key = $1',
                    ['referral_signup_bonus']
                );
                const signupBonus = parseInt(bonusSettings.rows[0]?.setting_value) || 100;

                // Create referral relationship
                await pool.query(
                    'INSERT INTO referrals (referrer_id, referred_id, referral_code, signup_bonus_awarded) VALUES ($1, $2, $3, true)',
                    [referrerId, userId, referredByCode]
                );

                // Award signup bonus to both users
                await pool.query(
                    'UPDATE users SET points = points + $1, signup_bonus_earnings = signup_bonus_earnings + $1 WHERE id IN ($2, $3)',
                    [signupBonus, referrerId, userId]
                );
                // Log transactions
                await logPointTransaction(pool, referrerId, signupBonus, 'signup_bonus', `Signup bonus for referring ${whatsappNumber}`, userId);
                await logPointTransaction(pool, userId, signupBonus, 'signup_bonus', `Welcome bonus for joining`, referrerId);

                // Log for both users
                const referrerUser = await pool.query('SELECT whatsapp_number FROM users WHERE id = $1', [referrerId]);
                const newUserPhone = whatsappNumber;

                await logReferralActivity(pool, referrerId, newUserPhone, signupBonus, userId);
                await logWelcomeBonusActivity(pool, userId, referrerUser.rows[0].whatsapp_number, signupBonus, referrerId);
            }
        }

        // ✅ FIXED:
        const spinSettings = await pool.query(
            'SELECT setting_value FROM settings WHERE setting_key = $1',
            ['spin_free_per_day']
        );
        const freeSpinsPerDay = parseInt(spinSettings.rows[0]?.setting_value) || 1;

        await pool.query(
            'INSERT INTO user_spins (user_id, free_spins_today) VALUES ($1, $2)',
            [userId, freeSpinsPerDay]
        );

        await pool.query(
            'INSERT INTO user_streaks (user_id) VALUES ($1)',
            [userId]
        );

        // AUTO-ASSIGN LEADS TO NEW USER
        let leadsAssigned = 0;
        try {
            const settingsRes = await pool.query(
                "SELECT setting_value FROM campaign_settings WHERE setting_key = 'lead_initial_batch'"
            );
            const initialBatch = parseInt(settingsRes.rows[0]?.setting_value) || 200;

            const availableLeads = await pool.query(
                `SELECT l.id, l.phone_number, l.campaign_id, l.times_assigned
                 FROM leads l
                 WHERE l.campaign_id = 1 
                 AND l.status = 'available'
                 AND (l.times_assigned < 3 OR l.times_assigned IS NULL)
                 ORDER BY 
                    CASE WHEN l.times_assigned IS NULL THEN 0 ELSE l.times_assigned END ASC,
                    l.created_at ASC
                 LIMIT $1`,
                [initialBatch]
            );

            if (availableLeads.rows.length > 0) {
                for (const lead of availableLeads.rows) {
                    await pool.query(
                        `INSERT INTO user_lead_assignments 
                         (user_id, lead_id, campaign_id, status, assigned_at, created_at)
                         VALUES ($1, $2, $3, 'pending', NOW(), NOW())`,
                        [userId, lead.id, lead.campaign_id]
                    );
                }

                const leadIds = availableLeads.rows.map(l => l.id);
                await pool.query(
                    `UPDATE leads 
                     SET times_assigned = COALESCE(times_assigned, 0) + 1 
                     WHERE id = ANY($1::int[])`,
                    [leadIds]
                );

                leadsAssigned = availableLeads.rows.length;
                console.log(`✅ Auto-assigned ${leadsAssigned} leads to new user ${userId}`);
            }
        } catch (assignError) {
            console.error('⚠️ Error auto-assigning leads:', assignError);
        }

        // Generate token
        const token = jwt.sign(
            { userId, whatsapp_number: userWhatsappNumber },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '30d' }
        );

        res.json({
            message: 'Registration successful',
            token,
            userId,
            whatsapp_number: userWhatsappNumber,
            leadsAssigned
        });

    } catch (error) {
        console.error('❌ Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

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

        // Capture IP address
        const userIp = req.headers['x-forwarded-for']?.split(',')[0] ||
            req.headers['x-real-ip'] ||
            req.connection?.remoteAddress ||
            req.socket?.remoteAddress ||
            'unknown';

        // Update last login IP
        await pool.query(
            'UPDATE users SET last_login_ip = $1, last_ip = $1 WHERE id = $2',
            [userIp, user.rows[0].id]
        );

        // Log IP history
        await pool.query(
            'INSERT INTO user_ip_history (user_id, ip_address, action) VALUES ($1, $2, $3)',
            [user.rows[0].id, userIp, 'login']
        );

        // Create JWT token
        const token = jwt.sign({
            userId: user.rows[0].id,
            whatsappNumber: whatsappNumber
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


router.get('/dashboard/:userId', authenticateUser, async (req, res) => {
    const { userId } = req.params;
    const { submissionsPage = 1, redemptionsPage = 1, limit = 5 } = req.query;

    try {
        const pool = req.app.get('db');

        // Get user info
        const user = await pool.query(
            'SELECT id, whatsapp_number, points, referral_code, created_at FROM users WHERE id = $1',
            [userId]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get current offer
        const offer = await pool.query(
            'SELECT * FROM offers WHERE is_active = true ORDER BY created_at DESC LIMIT 1'
        );

        // Get user's current points from users table
        const userPoints = user.rows[0].points;

        // Get redeemed points
        const redeemedResult = await pool.query(
            `SELECT COALESCE(SUM(points_requested), 0) as redeemed_points
             FROM redemptions 
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        const redeemedPoints = parseInt(redeemedResult.rows[0].redeemed_points);
        const availablePoints = userPoints - redeemedPoints;

        const submissionsOffset = (submissionsPage - 1) * limit;

        // Get paginated submissions
        // NEW CODE - Fetch BOTH old and new submissions
        // Get OLD system submissions
        const oldSubmissions = await pool.query(
            `SELECT 
        s.id,
        s.user_id,
        s.status,
        s.points_awarded,
        s.streak_bonus,
        s.created_at,
        COUNT(DISTINCT ur.recipient_number) as recipient_count,
        'old' as submission_type
     FROM submissions s
     LEFT JOIN user_recipients ur ON s.id = ur.submission_id
     WHERE s.user_id = $1
     GROUP BY s.id
     ORDER BY s.created_at DESC`,
            [userId]
        );

        // Get NEW system submissions  
        const newSubmissions = await pool.query(
            `SELECT 
        id,
        user_id,
        status,
        points_awarded,
        0 as streak_bonus,
        created_at,
        'new' as submission_type,
        recipient_numbers
     FROM personal_share_submissions
     WHERE user_id = $1
     ORDER BY created_at DESC`,
            [userId]
        );

        // Parse NEW submissions to add recipient_count
        const parsedNewSubmissions = newSubmissions.rows.map(sub => {
            let recipientCount = 0;
            try {
                const data = JSON.parse(sub.recipient_numbers || '{}');
                recipientCount = data.recipients?.length || 0;
            } catch (e) {
                console.error('Error parsing submission:', e);
            }
            return {
                ...sub,
                recipient_count: recipientCount
            };
        });

        // Combine and sort by date
        const allSubmissions = [
            ...oldSubmissions.rows,
            ...parsedNewSubmissions
        ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        // Apply pagination
        const totalSubmissions = allSubmissions.length;
        const paginatedSubmissions = allSubmissions.slice(
            submissionsOffset,
            submissionsOffset + limit
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

        // Get streak data
        const streakData = await pool.query('SELECT * FROM user_streaks WHERE user_id = $1', [userId]);

        // Get referral data
        const referralData = await pool.query(
            `SELECT 
                COUNT(*) as total_referrals,
                COALESCE(SUM(total_commission_earned), 0) as total_commission
             FROM referrals WHERE referrer_id = $1`,
            [userId]
        );

        // Get spin data
        const spinData = await pool.query('SELECT * FROM user_spins WHERE user_id = $1', [userId]);

        // Get milestone data
        const milestoneData = await pool.query(
            'SELECT * FROM user_milestones WHERE user_id = $1 ORDER BY milestone_value DESC LIMIT 5',
            [userId]
        );

        // ============================================
        // 🆕 NEW: COUNT PERSONAL SHARES (OLD + NEW)
        // ============================================

        // Count OLD personal shares (from user_recipients table)
        const oldPersonalShares = await pool.query(
            `SELECT COUNT(DISTINCT recipient_number) as total
             FROM user_recipients ur
             JOIN submissions s ON ur.submission_id = s.id
             WHERE s.user_id = $1 AND s.status = 'active'`,
            [userId]
        );

        // Count NEW personal shares (from personal_share_submissions JSON)
        const newPersonalShares = await pool.query(
            `SELECT recipient_numbers FROM personal_share_submissions 
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        // Parse JSON and count recipients
        let newPersonalCount = 0;
        for (const row of newPersonalShares.rows) {
            try {
                const data = JSON.parse(row.recipient_numbers || '{}');
                newPersonalCount += data.recipients?.length || 0;
            } catch (e) {
                console.error('Error parsing recipient data:', e);
            }
        }

        // Count global task shares
        const globalTaskShares = await pool.query(
            `SELECT COUNT(*) as total FROM user_lead_assignments 
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        const oldPersonalCount = parseInt(oldPersonalShares.rows[0].total) || 0;
        const globalTaskCount = parseInt(globalTaskShares.rows[0].total) || 0;
        const totalPersonalShares = oldPersonalCount + newPersonalCount;
        const totalShares = totalPersonalShares + globalTaskCount;

        console.log(`📊 Dashboard - User ${userId}: Old Personal=${oldPersonalCount}, New Personal=${newPersonalCount}, Global=${globalTaskCount}, Total=${totalShares}`);

        // ============================================
        // END NEW CODE
        // ============================================

        res.json({
            user: user.rows[0],
            offer: offer.rows[0] || null,
            points: {
                total: userPoints,
                redeemed: redeemedPoints,
                available: availablePoints
            },

            // 🆕 NEW: Share counts
            personalShareCount: totalPersonalShares,  // Changed from personalShares
            globalTaskShares: globalTaskCount,
            totalShares: totalShares,
            shareBreakdown: {
                oldPersonal: oldPersonalCount,
                newPersonal: newPersonalCount,
                globalTasks: globalTaskCount
            },

            // NEW:
            submissions: paginatedSubmissions,
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
            pendingRedemption: pendingRedemption.rows[0] || null,
            streak: streakData.rows[0] || { current_streak: 0, longest_streak: 0 },
            referrals: referralData.rows[0] || { total_referrals: 0, total_commission: 0 },
            spins: spinData.rows[0] || { free_spins_today: 1, bonus_spins: 0, total_won: 0 },
            milestones: milestoneData.rows
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Failed to load dashboard' });
    }
});




// Submit proof endpoint (NEW SYSTEM with settings + duplicate check across old/new)
router.post('/submit-proof', authenticateUser, uploadSubmission.array('screenshots', 50), async (req, res) => {
    const { userId, recipientNumbers } = req.body;
    const screenshots = req.files;

    if (!userId || !recipientNumbers || !screenshots || screenshots.length === 0) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const pool = req.app.get('db');
        const numbers = JSON.parse(recipientNumbers);
        let streakBonus = 0;

        // Get personal share settings
        const settingsResult = await pool.query('SELECT * FROM personal_share_settings ORDER BY id DESC LIMIT 1');
        const settings = settingsResult.rows[0] || {
            points_per_submission: 1,
            instant_points_award: true,
            admin_review_required: false
        };
        // ✅ ADD THIS VALIDATION RIGHT AFTER:
        const maxAllowed = settings.max_screenshots_allowed || 20;
        if (screenshots.length > maxAllowed) {
            return res.status(400).json({
                error: `Maximum ${maxAllowed} screenshots allowed. You uploaded ${screenshots.length}.`
            });
        }

        // Validate counts match
        if (numbers.length !== screenshots.length) {
            return res.status(400).json({ error: 'Number of screenshots must match recipient count' });
        }

        // Hash recipient numbers
        const hashedNumbers = numbers.map(num => hashPhoneNumber(num));

        // ✅ CHECK DUPLICATES IN BOTH OLD AND NEW SYSTEMS
        // Check OLD system (user_recipients table)
        const oldDuplicates = await pool.query(
            `SELECT recipient_number_hash FROM user_recipients 
             WHERE user_id = $1 AND recipient_number_hash = ANY($2)`,
            [userId, hashedNumbers]
        );

        // Check NEW system (personal_share_submissions JSON)
        const newSubmissions = await pool.query(
            `SELECT recipient_numbers FROM personal_share_submissions 
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        // Collect all existing recipient hashes from new system
        const existingRecipients = new Set();
        for (const sub of newSubmissions.rows) {
            try {
                const data = JSON.parse(sub.recipient_numbers || '{}');
                if (data.recipients) {
                    data.recipients.forEach(num => {
                        existingRecipients.add(hashPhoneNumber(num));
                    });
                }
            } catch (e) { }
        }

        // Check if any new numbers are duplicates in EITHER system
        const duplicateNumbers = hashedNumbers.filter(hash =>
            existingRecipients.has(hash) || oldDuplicates.rows.some(row => row.recipient_number_hash === hash)
        );

        if (duplicateNumbers.length > 0) {
            return res.status(400).json({
                error: 'You have already submitted shares to some of these recipients'
            });
        }

        // Store screenshot paths
        const screenshotPaths = screenshots.map(file => `/uploads/submissions/${file.filename}`);

        // Calculate points based on settings
        const basePoints = settings.points_per_submission * numbers.length;
        const instantPoints = settings.instant_points_award !== false;
        const adminReview = settings.admin_review_required === true;

        // Determine status and initial points
        let status = adminReview ? 'pending' : 'approved';
        let pointsToAward = (instantPoints || !adminReview) ? basePoints : 0;

        // Store in NEW personal_share_submissions table
        const submissionData = {
            screenshots: screenshotPaths,
            recipients: numbers
        };

        const submission = await pool.query(
            `INSERT INTO personal_share_submissions (user_id, screenshot_url, recipient_numbers, points_awarded, status, created_at) 
             VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP) RETURNING id`,
            [userId, screenshotPaths[0], JSON.stringify(submissionData), pointsToAward, status]
        );

        const submissionId = submission.rows[0].id;

        // Award initial points if applicable
        if (pointsToAward > 0) {
            await pool.query('UPDATE users SET points = points + $1, task_earnings = task_earnings + $1 WHERE id = $2', [pointsToAward, userId]);

            await pool.query(`
                INSERT INTO point_transactions (user_id, amount, transaction_type, description, created_at)
                VALUES ($1, $2, 'personal_share_submission', $3, CURRENT_TIMESTAMP)
            `, [userId, pointsToAward, `Personal share - ${numbers.length} recipients`]);
        }

        // Only award bonuses if approved (not pending review)
        if (status === 'approved') {
            // Log activity
            await logPersonalShareActivity(pool, userId, numbers.length, pointsToAward, 'offer');

            // 1. UPDATE STREAK
            try {
                const today = new Date().toISOString().split('T')[0];
                let streak = await pool.query('SELECT * FROM user_streaks WHERE user_id = $1', [userId]);

                if (streak.rows.length === 0) {
                    await pool.query(
                        'INSERT INTO user_streaks (user_id, current_streak, longest_streak, last_share_date) VALUES ($1, 1, 1, $2)',
                        [userId, today]
                    );

                    const day1Settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['streak_day1_bonus']);
                    const day1Bonus = parseInt(day1Settings.rows[0]?.setting_value) || 0;

                    if (day1Bonus > 0) {
                        streakBonus = day1Bonus;
                        await pool.query('UPDATE users SET points = points + $1 WHERE id = $2', [day1Bonus, userId]);

                        const day2Settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['streak_day2_bonus']);
                        const day2Bonus = parseInt(day2Settings.rows[0]?.setting_value) || 0;
                        await logStreakActivity(pool, userId, 1, day1Bonus, day2Bonus);

                        await pool.query(
                            'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                            [userId, `🔥 Day 1 streak! You earned ${day1Bonus} bonus points!`, 'streak_bonus']
                        );
                    }
                } else {
                    const lastShareDate = streak.rows[0].last_share_date
                        ? new Date(streak.rows[0].last_share_date).toISOString().split('T')[0]
                        : null;
                    const currentStreak = streak.rows[0].current_streak;

                    if (lastShareDate !== today) {
                        const yesterday = new Date();
                        yesterday.setDate(yesterday.getDate() - 1);
                        const yesterdayStr = yesterday.toISOString().split('T')[0];

                        let newStreak = lastShareDate === yesterdayStr ? currentStreak + 1 : 1;
                        // ✅ Calculate 7-day repeating cycle
                        // ✅ Calculate 7-day repeating cycle

                        const cycleDay = ((newStreak - 1) % 7) + 1;
                        const settingKey = `streak_day${cycleDay}_bonus`;

                        console.log(`🔥 Personal Share: Streak ${newStreak} → Cycle Day ${cycleDay}`);

                        const bonusSettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [settingKey]);
                        streakBonus = parseInt(bonusSettings.rows[0]?.setting_value) || 0;

                        console.log(`💰 Cycle Day ${cycleDay} bonus: ${streakBonus} points`);


                        await pool.query(
                            `UPDATE user_streaks 
                             SET current_streak = $1, longest_streak = GREATEST(longest_streak, $1),
                                 last_share_date = $2, total_streak_bonuses = total_streak_bonuses + $3, updated_at = NOW()
                             WHERE user_id = $4`,
                            [newStreak, today, streakBonus, userId]
                        );

                        if (streakBonus > 0) {
                            await pool.query('UPDATE users SET points = points + $1, streak_earnings = streak_earnings + $1 WHERE id = $2', [streakBonus, userId]);
                            // ✅ ADD THESE 4 LINES:
                            await pool.query(
                                'INSERT INTO point_transactions (user_id, amount, transaction_type, description, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)',
                                [userId, streakBonus, 'streak_bonus', `Day ${newStreak} streak bonus`]
                            );


                            const nextDayKey = `streak_day${newStreak + 1}_bonus`;
                            const nextDaySettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [nextDayKey]);
                            const nextDayBonus = parseInt(nextDaySettings.rows[0]?.setting_value) || 0;
                            await logStreakActivity(pool, userId, newStreak, streakBonus, nextDayBonus);

                            await pool.query(
                                'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                                [userId, `🔥 ${newStreak} day streak! You earned ${streakBonus} bonus points!`, 'streak_bonus']
                            );
                        }
                    }
                }
            } catch (error) {
                console.error('Streak update error:', error);
            }

            // 2. CHECK MILESTONES (count from BOTH old and new systems + global tasks)
            try {
                // Count OLD personal shares
                const oldShares = await pool.query(
                    `SELECT COUNT(DISTINCT recipient_number) as total
                     FROM user_recipients ur
                     JOIN submissions s ON ur.submission_id = s.id
                     WHERE s.user_id = $1 AND s.status = 'active'`,
                    [userId]
                );

                // Count NEW personal shares
                const newShares = await pool.query(
                    `SELECT recipient_numbers FROM personal_share_submissions 
                     WHERE user_id = $1 AND status = 'approved'`,
                    [userId]
                );

                let newShareCount = 0;
                for (const row of newShares.rows) {
                    try {
                        const data = JSON.parse(row.recipient_numbers || '{}');
                        newShareCount += data.recipients?.length || 0;
                    } catch (e) { }
                }

                // Count global tasks
                const globalTasks = await pool.query(
                    `SELECT COUNT(*) as total FROM user_lead_assignments 
                     WHERE user_id = $1 AND status = 'approved'`,
                    [userId]
                );

                const oldShareCount = parseInt(oldShares.rows[0].total) || 0;
                const globalCount = parseInt(globalTasks.rows[0].total) || 0;
                const shareCount = oldShareCount + newShareCount + globalCount;

                console.log(`📊 Milestone Check - User ${userId}: Old=${oldShareCount}, New=${newShareCount}, Global=${globalCount}, Total=${shareCount}`);

                const milestones = await pool.query(`SELECT * FROM settings WHERE setting_key LIKE 'milestone_%' ORDER BY setting_key`);

                const milestonesObj = {};
                milestones.rows.forEach(m => {
                    const shares = m.setting_key.replace('milestone_', '').replace('_shares', '');
                    milestonesObj[shares] = parseInt(m.setting_value);
                });

                for (const [shares, bonus] of Object.entries(milestonesObj)) {
                    const milestoneShares = parseInt(shares);

                    if (shareCount >= milestoneShares) {
                        const exists = await pool.query(
                            'SELECT * FROM user_milestones WHERE user_id = $1 AND milestone_type = $2 AND milestone_value = $3',
                            [userId, 'shares', milestoneShares]
                        );

                        if (exists.rows.length === 0) {
                            await pool.query(
                                'INSERT INTO user_milestones (user_id, milestone_type, milestone_value, bonus_awarded) VALUES ($1, $2, $3, $4)',
                                [userId, 'shares', milestoneShares, bonus]
                            );

                            await pool.query('UPDATE users SET points = points + $1, milestone_earnings = milestone_earnings + $1 WHERE id = $2', [bonus, userId]);

                            const allMilestones = [10, 50, 100, 500, 1000, 5000, 10000];
                            const nextMilestone = allMilestones.find(m => m > milestoneShares) || null;
                            await logMilestoneActivity(pool, userId, milestoneShares, bonus, shareCount, nextMilestone);

                            console.log(`🏆 Milestone ${milestoneShares} achieved! Awarded ${bonus} points to user ${userId}`);
                        }
                    }
                }
            } catch (error) {
                console.error('Milestone check error:', error);
            }

            // 3. AWARD REFERRAL COMMISSION
            try {
                const user = await pool.query('SELECT referred_by_code FROM users WHERE id = $1', [userId]);

                if (user.rows[0].referred_by_code) {
                    const referrer = await pool.query('SELECT id FROM users WHERE referral_code = $1', [user.rows[0].referred_by_code]);

                    if (referrer.rows.length > 0) {
                        const commissionSettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['referral_commission_percent']);
                        const commissionPercent = parseInt(commissionSettings.rows[0].setting_value) || 10;
                        const commission = Math.floor(pointsToAward * commissionPercent / 100);

                        if (commission > 0) {
                            await pool.query('UPDATE users SET points = points + $1, referral_earnings = referral_earnings + $1 WHERE id = $2', [commission, referrer.rows[0].id]);

                            const referredUser = await pool.query('SELECT whatsapp_number FROM users WHERE id = $1', [userId]);
                            await logCommissionActivity(pool, referrer.rows[0].id, referredUser.rows[0].whatsapp_number, commission, commissionPercent, pointsToAward, userId);

                            await pool.query(
                                'UPDATE referrals SET total_commission_earned = total_commission_earned + $1 WHERE referrer_id = $2 AND referred_id = $3',
                                [commission, referrer.rows[0].id, userId]
                            );

                            console.log(`💰 Commission ${commission} awarded to referrer ${referrer.rows[0].id}`);
                        }
                    }
                }
            } catch (error) {
                console.error('Referral commission error:', error);
            }

            // 4. AWARD BONUS SPIN (count from BOTH systems)
            try {
                await awardBonusSpin(pool, userId);
            } catch (error) {
                console.error('Bonus spin award error:', error);
            }
        }

        res.json({
            success: true,
            submissionId: submissionId,
            pointsAwarded: pointsToAward,
            streakBonus: streakBonus || 0,
            totalEarned: pointsToAward + (streakBonus || 0),
            message: status === 'pending' ? 'Submission pending review' : 'Submission successful!',
            status: status
        });

    } catch (error) {
        console.error('Submission error:', error);
        res.status(500).json({ error: 'Submission failed' });
    }
});



// Get user profile data (combines old + new systems)
router.get('/user/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        console.log(`🔍 Profile endpoint called for user ${userId}`);

        // Get user details
        const user = await pool.query(
            'SELECT id, whatsapp_number, points, referral_code, referred_by_code, created_at FROM users WHERE id = $1',
            [userId]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Count OLD personal shares (unique recipients)
        const oldShares = await pool.query(
            `SELECT COUNT(DISTINCT recipient_number) as total
             FROM user_recipients ur
             JOIN submissions s ON ur.submission_id = s.id
             WHERE s.user_id = $1 AND s.status = 'active'`,
            [userId]
        );

        // Count NEW personal shares (recipients from JSON)
        const newShares = await pool.query(
            `SELECT recipient_numbers FROM personal_share_submissions 
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        let newShareCount = 0;
        const submissions = [];
        for (const row of newShares.rows) {
            try {
                const data = JSON.parse(row.recipient_numbers || '{}');
                const recipientCount = data.recipients?.length || 0;
                newShareCount += recipientCount;
                submissions.push({ recipient_count: recipientCount });
            } catch (e) {
                console.error('Error parsing submission:', e);
            }
        }

        const oldShareCount = parseInt(oldShares.rows[0].total) || 0;
        const totalPersonalShares = oldShareCount + newShareCount;

        console.log(`👤 User ${userId} Profile - Personal Shares: ${totalPersonalShares} (Old: ${oldShareCount}, New: ${newShareCount})`);

        // Get referral stats
        const referralStats = await pool.query(
            `SELECT COUNT(*) as total_referrals, 
                    COALESCE(SUM(total_commission_earned), 0) as total_commission
             FROM referrals
             WHERE referrer_id = $1`,
            [userId]
        );

        // Get streak data
        const streak = await pool.query(
            'SELECT current_streak, longest_streak, last_share_date FROM user_streaks WHERE user_id = $1',
            [userId]
        );

        // Get spin count
        const spins = await pool.query(
            'SELECT bonus_spins, free_spins FROM user_spins WHERE user_id = $1',
            [userId]
        );

        res.json({
            user: user.rows[0],
            submissions: submissions,
            personalShareCount: totalPersonalShares,
            shareBreakdown: {
                oldPersonal: oldShareCount,
                newPersonal: newShareCount,
                total: totalPersonalShares
            },
            referralStats: referralStats.rows[0] || { total_referrals: 0, total_commission: 0 },
            streak: streak.rows[0] || { current_streak: 0, longest_streak: 0, last_share_date: null },
            spins: spins.rows[0] || { bonus_spins: 0, free_spins: 0 }
        });

    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
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
        const settingsResult = await pool.query('SELECT setting_key, setting_value FROM settings');
        const settings = {};
        settingsResult.rows.forEach(row => {
            settings[row.setting_key] = parseInt(row.setting_value);
        });

        // ✅ NEW: Get points directly from users table
        const userResult = await pool.query(
            'SELECT points FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const availablePoints = userResult.rows[0].points;

        // Check if user has enough points
        if (availablePoints < settings.min_redemption_points) {
            return res.status(400).json({
                error: `You need ${settings.min_redemption_points} points to redeem. You have ${availablePoints} points.`
            });
        }

        // Check if user already has a pending redemption
        const pendingCheck = await pool.query(
            'SELECT id FROM redemptions WHERE user_id = $1 AND status = $2',
            [userId, 'pending']
        );

        if (pendingCheck.rows.length > 0) {
            return res.status(400).json({ error: 'You already have a pending redemption request' });
        }

        // Create redemption request
        await pool.query(
            'INSERT INTO redemptions (user_id, points_requested, status, requested_at) VALUES ($1, $2, $3, NOW())',
            [userId, settings.min_redemption_points, 'pending']
        );

        // Deduct points from user's balance
        await pool.query(
            'UPDATE users SET points = points - $1 WHERE id = $2',
            [settings.min_redemption_points, userId]
        );

        res.json({
            success: true,
            message: 'Redemption request submitted successfully'
        });

    } catch (error) {
        console.error('Redemption error:', error);
        res.status(500).json({ error: 'Failed to process redemption request' });
    }
});


// Get system settings (public - no auth required)
router.get('/settings', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const settings = await pool.query(
            'SELECT setting_key, setting_value FROM settings ORDER BY setting_key'  // ✅ CORRECT TABLE
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
router.post('/admin/2fa/generate', authenticateAdmin, checkPermission('security_2fa'), async (req, res) => {
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
router.post('/admin/2fa/enable', authenticateAdmin, checkPermission('security_2fa'), async (req, res) => {
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
router.post('/admin/2fa/disable', authenticateAdmin, checkPermission('security_2fa'), async (req, res) => {
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
router.get('/admin/2fa/status', authenticateAdmin, checkPermission('security_2fa'), async (req, res) => {
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

// ============================================
// FILE MANAGER ROUTES (WITH DATABASE CLEANUP)
// ============================================

// Helper: Get file size
const getFileSize = (filePath) => {
    try {
        const stats = fs.statSync(filePath);
        return stats.size;
    } catch {
        return 0;
    }
};

// Helper: Clean up database references when file is deleted
const cleanupDatabaseReferences = async (pool, folder, filename) => {
    const filePath = `/uploads/${folder}/${filename}`;

    try {
        // Clean up banners table
        if (folder === 'banners') {
            await pool.query(`UPDATE banners SET image_url = NULL WHERE image_url = $1`, [filePath]);
            await pool.query(`DELETE FROM banners WHERE image_url = $1 AND title IS NULL`, [filePath]);
        }

        // Clean up offers table
        if (folder === 'offers') {
            await pool.query(`UPDATE offers SET image_url = NULL WHERE image_url = $1`, [filePath]);
            await pool.query(`DELETE FROM offers WHERE image_url = $1 AND title IS NULL`, [filePath]);
        }

        // Clean up activities table
        if (folder === 'activities' || folder === 'banners') {
            await pool.query(`UPDATE activities SET banner_image_url = NULL WHERE banner_image_url = $1`, [filePath]);
            await pool.query(`UPDATE activities SET detail_image_url = NULL WHERE detail_image_url = $1`, [filePath]);
        }

        // Clean up submissions (usually these shouldn't be deleted, but just in case)
        if (folder === 'submissions') {
            await pool.query(`UPDATE submissions SET screenshot_url = NULL WHERE screenshot_url = $1`, [filePath]);
        }

        console.log(`✅ Cleaned up DB references for: ${filePath}`);
    } catch (error) {
        console.error(`Error cleaning up DB for ${filePath}:`, error);
    }
};

// List all files from all folders
router.get('/admin/file-manager/list', authenticateAdmin, checkPermission('security_files'), async (req, res) => {
    try {
        const uploadsDir = path.join(__dirname, 'uploads');
        const folders = ['banners', 'offers', 'submissions', 'activities'];

        const filesByFolder = {};
        let totalFiles = 0;
        let totalSize = 0;

        for (const folder of folders) {
            const folderPath = path.join(uploadsDir, folder);

            if (!fs.existsSync(folderPath)) {
                filesByFolder[folder] = [];
                continue;
            }

            const files = fs.readdirSync(folderPath);
            filesByFolder[folder] = files
                .filter(file => !file.startsWith('.')) // Ignore hidden files
                .map(filename => {
                    const filePath = path.join(folderPath, filename);
                    const size = getFileSize(filePath);
                    totalSize += size;
                    totalFiles++;

                    return {
                        filename,
                        url: `/uploads/${folder}/${filename}`,
                        size,
                        folder
                    };
                })
                .sort((a, b) => b.filename.localeCompare(a.filename)); // Newest first
        }

        const stats = {
            totalFiles,
            totalSize,
            bannerCount: filesByFolder.banners?.length || 0,
            offerCount: filesByFolder.offers?.length || 0,
            submissionCount: filesByFolder.submissions?.length || 0,
            activityCount: filesByFolder.activities?.length || 0
        };

        res.json({ files: filesByFolder, stats });
    } catch (error) {
        console.error('Error listing files:', error);
        res.status(500).json({ error: 'Failed to list files' });
    }
});

// Delete single file
router.delete('/admin/file-manager/delete/:folder/:filename', authenticateAdmin, checkPermission('security_files'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { folder, filename } = req.params;

        const filePath = path.join(__dirname, 'uploads', folder, filename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Delete file
        fs.unlinkSync(filePath);

        // Clean up database
        await cleanupDatabaseReferences(pool, folder, filename);

        console.log(`✅ Deleted file: ${folder}/${filename}`);
        res.json({ message: 'File deleted successfully' });
    } catch (error) {
        console.error('Error deleting file:', error);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

// Bulk delete files
router.post('/admin/file-manager/bulk-delete', authenticateAdmin, checkPermission('security_files'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { files } = req.body; // Array of "folder/filename" strings

        if (!Array.isArray(files) || files.length === 0) {
            return res.status(400).json({ error: 'No files provided' });
        }

        let deleted = 0;
        let failed = 0;

        for (const fileId of files) {
            const [folder, filename] = fileId.split('/');
            const filePath = path.join(__dirname, 'uploads', folder, filename);

            try {
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                    await cleanupDatabaseReferences(pool, folder, filename);
                    deleted++;
                } else {
                    failed++;
                }
            } catch (error) {
                console.error(`Error deleting ${fileId}:`, error);
                failed++;
            }
        }

        console.log(`✅ Bulk delete: ${deleted} deleted, ${failed} failed`);
        res.json({
            message: `Deleted ${deleted} file(s)`,
            deleted,
            failed
        });
    } catch (error) {
        console.error('Error bulk deleting:', error);
        res.status(500).json({ error: 'Failed to bulk delete files' });
    }
});

// Clear entire folder
router.post('/admin/file-manager/clear-folder', authenticateAdmin, checkPermission('security_files'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { folder } = req.body;

        const folderPath = path.join(__dirname, 'uploads', folder);

        if (!fs.existsSync(folderPath)) {
            return res.status(404).json({ error: 'Folder not found' });
        }

        const files = fs.readdirSync(folderPath).filter(f => !f.startsWith('.'));

        let deleted = 0;
        for (const filename of files) {
            const filePath = path.join(folderPath, filename);
            try {
                fs.unlinkSync(filePath);
                await cleanupDatabaseReferences(pool, folder, filename);
                deleted++;
            } catch (error) {
                console.error(`Error deleting ${filename}:`, error);
            }
        }

        console.log(`✅ Cleared folder ${folder}: ${deleted} files deleted`);
        res.json({
            message: `Cleared ${folder}: ${deleted} files deleted`,
            deleted
        });
    } catch (error) {
        console.error('Error clearing folder:', error);
        res.status(500).json({ error: 'Failed to clear folder' });
    }
});

// Find and clean orphaned database records (files deleted but DB still references them)
router.post('/admin/file-manager/cleanup-orphaned', authenticateAdmin, checkPermission('security_files'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const uploadsDir = path.join(__dirname, 'uploads');

        let cleaned = 0;

        // Check banners
        const banners = await pool.query(`SELECT id, image_url FROM banners WHERE image_url IS NOT NULL`);
        for (const banner of banners.rows) {
            const folderPath = path.join(__dirname, 'uploads', folder);
            if (!fs.existsSync(filePath)) {
                await pool.query(`UPDATE banners SET image_url = NULL WHERE id = $1`, [banner.id]);
                cleaned++;
            }
        }

        // Check offers
        const offers = await pool.query(`SELECT id, image_url FROM offers WHERE image_url IS NOT NULL`);
        for (const offer of offers.rows) {
            const filePath = path.join(__dirname, 'public', offer.image_url);
            if (!fs.existsSync(filePath)) {
                await pool.query(`UPDATE offers SET image_url = NULL WHERE id = $1`, [offer.id]);
                cleaned++;
            }
        }

        // Check activities
        const activities = await pool.query(`SELECT id, banner_image_url, detail_image_url FROM activities WHERE banner_image_url IS NOT NULL OR detail_image_url IS NOT NULL`);
        for (const activity of activities.rows) {
            if (activity.banner_image_url) {
                const filePath = path.join(__dirname, 'public', activity.banner_image_url);
                if (!fs.existsSync(filePath)) {
                    await pool.query(`UPDATE activities SET banner_image_url = NULL WHERE id = $1`, [activity.id]);
                    cleaned++;
                }
            }
            if (activity.detail_image_url) {
                const filePath = path.join(__dirname, 'public', activity.detail_image_url);
                if (!fs.existsSync(filePath)) {
                    await pool.query(`UPDATE activities SET detail_image_url = NULL WHERE id = $1`, [activity.id]);
                    cleaned++;
                }
            }
        }

        console.log(`✅ Cleaned ${cleaned} orphaned DB references`);
        res.json({
            message: `Cleaned ${cleaned} orphaned references`,
            cleaned
        });
    } catch (error) {
        console.error('Error cleaning orphaned records:', error);
        res.status(500).json({ error: 'Failed to cleanup orphaned records' });
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
router.get('/admin/admins', authenticateAdmin, checkPermission('manage_admins'), async (req, res) => {
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

        // Admins can only view their own permissions unless they're super_admin
        if (req.admin.adminId !== parseInt(id) && req.admin.role !== 'super_admin') {
            return res.status(403).json({ error: 'Access denied' });
        }

        // Get admin role
        const adminCheck = await pool.query(
            'SELECT role FROM admins WHERE id = $1',
            [id]
        );

        if (adminCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        // Super admins have all permissions
        if (adminCheck.rows[0].role === 'super_admin') {
            return res.json({ permissions: ['*'] });
        }

        const result = await pool.query(
            'SELECT permission FROM admin_permissions WHERE admin_id = $1',
            [id]
        );

        const permissions = result.rows.map(row => row.permission);

        res.json({ permissions });
    } catch (error) {
        console.error('Error fetching permissions:', error);
        res.status(500).json({ error: 'Failed to fetch permissions' });
    }
});

// Create new admin (SUPER ADMIN ONLY)
router.post('/admin/create-admin', authenticateAdmin, checkPermission('manage_admins'), async (req, res) => {
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

        if (req.body.role && req.body.role === 'super_admin') {
            return res.status(403).json({
                error: 'Cannot create super admin accounts. Only one super admin allowed.'
            });
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
router.put('/admin/admins/:id/permissions', authenticateAdmin, checkPermission('manage_admins'), async (req, res) => {
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
router.delete('/admin/admins/:id', authenticateAdmin, checkPermission('manage_admins'), async (req, res) => {
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


// Update admin details (username, password, role)
router.put('/admin/admins/:id', authenticateAdmin, checkPermission('manage_admins'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const { username, password, role } = req.body;

        // Check if admin exists
        const adminCheck = await pool.query('SELECT * FROM admins WHERE id = $1', [id]);
        if (adminCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Admin not found' });
        }

        // Prevent modifying super_admin if not super_admin
        if (adminCheck.rows[0].role === 'super_admin' && req.admin.role !== 'super_admin') {
            return res.status(403).json({ error: 'Cannot modify super admin' });
        }

        // Build update query dynamically
        const updates = [];
        const values = [];
        let paramCount = 1;

        if (username) {
            // Check if username is taken by another admin
            const usernameCheck = await pool.query(
                'SELECT id FROM admins WHERE username = $1 AND id != $2',
                [username, id]
            );
            if (usernameCheck.rows.length > 0) {
                return res.status(400).json({ error: 'Username already taken' });
            }
            updates.push(`username = $${paramCount}`);
            values.push(username);
            paramCount++;
        }

        if (password) {
            const bcrypt = require('bcrypt');
            const hashedPassword = await bcrypt.hash(password, 10);
            updates.push(`password_hash = $${paramCount}`);
            values.push(hashedPassword);
            paramCount++;
        }

        if (role) {
            // Only super_admin can change roles
            if (req.admin.role !== 'super_admin') {
                return res.status(403).json({ error: 'Only super admin can change roles' });
            }

            // ⚠️ ADD THIS BLOCK - Prevent changing TO super_admin
            if (role === 'super_admin') {
                return res.status(403).json({
                    error: 'Cannot change role to super admin. Only one super admin allowed.'
                });
            }

            // ⚠️ ADD THIS - Prevent changing FROM super_admin
            if (adminCheck.rows[0].role === 'super_admin') {
                return res.status(403).json({
                    error: 'Cannot modify super admin role'
                });
            }
            updates.push(`role = $${paramCount}`);
            values.push(role);
            paramCount++;
        }

        if (updates.length === 0) {
            return res.status(400).json({ error: 'No fields to update' });
        }

        // Add id to values
        values.push(id);

        // Execute update
        await pool.query(
            `UPDATE admins SET ${updates.join(', ')} WHERE id = $${paramCount}`,
            values
        );

        // Log activity
        await logAdminActivity(pool, req.admin.adminId, 'update_admin', `Updated admin ${id}`);

        res.json({ message: 'Admin updated successfully' });
    } catch (error) {
        console.error('Error updating admin:', error);
        res.status(500).json({ error: 'Failed to update admin' });
    }
});

// Toggle admin active status (SUPER ADMIN ONLY)
router.post('/admin/admins/:id/toggle-status', authenticateAdmin, checkPermission('manage_admins'), async (req, res) => {
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


router.get('/admin/activity-logs', authenticateAdmin, checkPermission('user_activity_logs'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { limit = 500, adminId } = req.query;

        // If adminId is provided, fetch ADMIN activity logs (for ManageAdmins page)
        if (adminId) {
            const adminLogs = await pool.query(
                `SELECT action, details, ip_address, created_at 
     FROM admin_activity_logs 
     WHERE admin_id = $1 
     ORDER BY created_at DESC 
     LIMIT 100`,
                [adminId]
            );
            return res.json({ logs: adminLogs.rows });
        }

        // Otherwise, fetch USER activity logs (currently unused, but keeping for future)
        const activitiesQuery = `
            SELECT 
                al.id,
                al.user_id,
                al.activity_type,
                al.title,
                al.description,
                al.points as points_awarded,
                al.metadata,
                al.created_at,
                u.whatsapp_number
            FROM activity_log al
            INNER JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT $1
        `;

        const activities = await pool.query(activitiesQuery, [limit]);

        // Get stats
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const statsQuery = `
            SELECT 
                COUNT(*) as total_activities,
                COUNT(*) FILTER (WHERE created_at >= $1) as today_activities,
                COUNT(DISTINCT user_id) FILTER (WHERE created_at >= $1) as active_users_today,
                COALESCE(SUM(points) FILTER (WHERE created_at >= $1), 0) as points_distributed_today
            FROM activity_log
        `;

        const stats = await pool.query(statsQuery, [today]);

        console.log(`✅ Fetched ${activities.rows.length} user activities`);

        res.json({
            activities: activities.rows,
            stats: stats.rows[0]
        });

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
            const pointsRedeemed = redemption.rows[0].points_requested;

            // ============ REFERRAL COMMISSION ON APPROVAL ============
            try {
                // Check if this user was referred by someone
                const user = await pool.query(
                    'SELECT referred_by_code FROM users WHERE id = $1',
                    [userId]
                );

                if (user.rows[0]?.referred_by_code) {
                    // Find the referrer
                    const referrer = await pool.query(
                        'SELECT id, whatsapp_number FROM users WHERE referral_code = $1',
                        [user.rows[0].referred_by_code]
                    );

                    if (referrer.rows.length > 0) {
                        const referrerId = referrer.rows[0].id;

                        // Get commission percentage from settings
                        const commissionSettings = await pool.query(
                            'SELECT setting_value FROM settings WHERE setting_key = $1',
                            ['referral_commission_percent']
                        );

                        const commissionPercent = parseInt(commissionSettings.rows[0]?.setting_value) || 10;

                        // Calculate commission based on redeemed points
                        const commission = Math.floor(pointsRedeemed * commissionPercent / 100);

                        if (commission > 0) {
                            // Award commission points to referrer
                            await pool.query(
                                'UPDATE users SET points = points + $1 WHERE id = $2',
                                [commission, referrerId]
                            );

                            // Update referral commission tracking
                            await pool.query(
                                'UPDATE referrals SET total_commission_earned = total_commission_earned + $1 WHERE referrer_id = $2 AND referred_id = $3',
                                [commission, referrerId, userId]
                            );

                            // Notify referrer about commission
                            await pool.query(
                                'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                                [referrerId, `🎉 You earned ${commission} points commission from your referral's redemption!`, 'referral_commission']
                            );

                            console.log(`✅ Commission awarded: ${commission} points to referrer ${referrerId}`);
                        }
                    }
                }
            } catch (commissionError) {
                console.error('Failed to award referral commission:', commissionError);
                // Don't throw - commission failure shouldn't block redemption approval
            }
            // ============ END REFERRAL COMMISSION ============

            // Create notification for user
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

            // NO COMMISSION ON REJECTION - referrer doesn't earn anything

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
router.get('/admin/users', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
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
        const paramIndex = queryParams.length;
        queryParams.push(limit, offset);

        const users = await pool.query(
            `SELECT u.id, u.whatsapp_number, u.points, u.created_at,
      COUNT(s.id) as total_submissions
   FROM users u
   LEFT JOIN submissions s ON u.id = s.user_id AND s.status = 'active'
   ${whereClause}
   GROUP BY u.id, u.whatsapp_number, u.points, u.created_at
   ORDER BY u.created_at DESC
   LIMIT $${paramIndex + 1} OFFSET $${paramIndex + 2}`,
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

// Add points to user (admin)
router.post('/admin/add-points', authenticateAdmin, checkPermission('user_points'), async (req, res) => {
    const { userId, points, reason } = req.body;

    if (!userId || !points || points <= 0) {
        return res.status(400).json({ error: 'Valid user ID and points required' });
    }

    try {
        const pool = req.app.get('db');

        // Directly update user's points
        await pool.query(
            'UPDATE users SET points = points + $1 WHERE id = $2',
            [points, userId]
        );

        // Create a notification for the user
        await pool.query(
            'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
            [userId, `Admin added ${points} points to your account${reason ? ': ' + reason : ''}`, 'admin_points_added']
        );

        await logAdminActivity(pool, req.admin.adminId, 'add_points', `Added ${points} points to user ID ${userId}${reason ? ' - Reason: ' + reason : ''}`);

        res.json({ success: true, message: `Added ${points} points successfully` });
    } catch (error) {
        console.error('Failed to add points:', error);
        res.status(500).json({ error: 'Failed to add points' });
    }
});

// Deduct points from user (admin)
router.post('/admin/deduct-points', authenticateAdmin, checkPermission('user_points'), async (req, res) => {
    const { userId, points, reason } = req.body;

    if (!userId || !points || points <= 0) {
        return res.status(400).json({ error: 'Valid user ID and points required' });
    }

    try {
        const pool = req.app.get('db');

        // Get current points
        const userResult = await pool.query(
            'SELECT points FROM users WHERE id = $1',
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const currentPoints = parseInt(userResult.rows[0].points);

        if (currentPoints < points) {
            return res.status(400).json({
                error: `Cannot deduct ${points} points. User only has ${currentPoints} points.`
            });
        }

        // Directly update user's points
        await pool.query(
            'UPDATE users SET points = points - $1 WHERE id = $2',
            [points, userId]
        );

        // Create a notification for the user
        await pool.query(
            'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
            [userId, `Admin deducted ${points} points from your account${reason ? ': ' + reason : ''}`, 'admin_points_deducted']
        );

        await logAdminActivity(pool, req.admin.adminId, 'deduct_points', `Deducted ${points} points from user ID ${userId}${reason ? ' - Reason: ' + reason : ''}`);

        res.json({ success: true, message: `Deducted ${points} points successfully` });
    } catch (error) {
        console.error('Failed to deduct points:', error);
        res.status(500).json({ error: 'Failed to deduct points' });
    }
});

// Delete user (admin)
router.delete('/admin/delete-user/:userId', authenticateAdmin, checkPermission('user_manage'), async (req, res) => {
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

router.get('/admin/user-profile/:userId', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    const { userId } = req.params;

    try {
        const pool = req.app.get('db');

        // Get user info directly from users table
        const user = await pool.query(
            `SELECT u.id, u.whatsapp_number, u.points, u.created_at, u.referral_code
             FROM users u
             WHERE u.id = $1`,
            [userId]
        );

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get submission count separately
        const submissionCount = await pool.query(
            `SELECT COUNT(*) as total_submissions
             FROM submissions
             WHERE user_id = $1 AND status = 'active'`,
            [userId]
        );

        res.json({
            user: {
                ...user.rows[0],
                total_submissions: parseInt(submissionCount.rows[0].total_submissions)
            }
        });
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
router.get('/admin/offers', authenticateAdmin, async (req, res) => {
    // Check permission but return empty instead of 403
    if (!req.admin.permissions?.includes('manage_offers') && req.admin.role !== 'super_admin') {
        return res.json({ offers: [] }); // Return empty array instead of 403
    }
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
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        // ✅ Get recipients from OLD system (user_recipients table)
        const oldRecipients = await pool.query(
            `SELECT DISTINCT
                ur.recipient_number,
                s.created_at,
                'old' as source
             FROM user_recipients ur
             JOIN submissions s ON ur.submission_id = s.id
             WHERE s.user_id = $1 AND s.status = 'active'
             ORDER BY s.created_at DESC`,
            [userId]
        );

        // ✅ Get recipients from NEW system (personal_share_submissions JSON)
        const newSubmissions = await pool.query(
            `SELECT 
                recipient_numbers,
                created_at,
                status
             FROM personal_share_submissions
             WHERE user_id = $1 AND status = 'approved'
             ORDER BY created_at DESC`,
            [userId]
        );

        // Parse NEW system recipients from JSON
        const newRecipients = [];
        for (const sub of newSubmissions.rows) {
            try {
                const data = JSON.parse(sub.recipient_numbers || '{}');
                const recipients = data.recipients || [];

                recipients.forEach(number => {
                    newRecipients.push({
                        recipient_number: number,
                        created_at: sub.created_at,
                        source: 'new'
                    });
                });
            } catch (e) {
                console.error('Error parsing recipient numbers:', e);
            }
        }

        // ✅ Combine all recipients
        const allRecipients = [
            ...oldRecipients.rows,
            ...newRecipients
        ];

        // ✅ Remove duplicates (keep latest submission date for each number)
        const uniqueRecipients = {};
        allRecipients.forEach(recipient => {
            const number = recipient.recipient_number;

            // If number doesn't exist OR current date is more recent
            if (!uniqueRecipients[number] ||
                new Date(recipient.created_at) > new Date(uniqueRecipients[number].created_at)) {
                uniqueRecipients[number] = recipient;
            }
        });

        // Convert back to array and sort by date (newest first)
        const recipientsList = Object.values(uniqueRecipients)
            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        console.log(`📞 User ${userId} Recipients: Old=${oldRecipients.rows.length}, New=${newRecipients.length}, Unique=${recipientsList.length}`);

        res.json({
            recipients: recipientsList,
            stats: {
                total_unique: recipientsList.length,
                from_old_system: oldRecipients.rows.length,
                from_new_system: newRecipients.length
            }
        });

    } catch (error) {
        console.error('Error fetching user recipients:', error);
        res.status(500).json({ error: 'Failed to fetch recipients' });
    }
});

// Get system settings (admin)
router.get('/admin/settings', authenticateAdmin, checkPermission('manage_fake_statistics'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // ✅ Only return core redemption settings (not streaks, spins, referrals, etc.)
        const settings = await pool.query(
            `SELECT * FROM settings 
             WHERE setting_key IN ('min_redemption_points', 'points_per_rupee', 'redemption_amount')
             ORDER BY setting_key`
        );

        res.json({ settings: settings.rows });
    } catch (error) {
        console.error('Failed to fetch settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

router.put('/admin/settings/:settingKey', authenticateAdmin, checkPermission('manage_fake_statistics'), async (req, res) => {
    const { settingKey } = req.params;
    const { value } = req.body;

    if (!value || isNaN(value) || parseInt(value) <= 0) {
        return res.status(400).json({ error: 'Value must be a positive number' });
    }

    try {
        const pool = req.app.get('db');

        // ✅ FIXED: Correct table name
        await pool.query(
            'UPDATE settings SET setting_value = $1 WHERE setting_key = $2',
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
router.get('/admin/platform-stats-config', authenticateAdmin, checkPermission('manage_fake_statistics'), async (req, res) => {
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
router.put('/admin/platform-stats-config', authenticateAdmin, checkPermission('manage_fake_statistics'), async (req, res) => {
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

        await pool.query(`UPDATE platform_stats_config 
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

// Admin Dashboard Stats
router.get('/admin/dashboard-stats', authenticateAdmin, checkPermission('view_dashboard'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Total Users
        const totalUsers = await pool.query('SELECT COUNT(*) as count FROM users');

        // Total Points Distributed
        const totalPoints = await pool.query('SELECT COALESCE(SUM(amount), 0) as total FROM point_transactions WHERE amount > 0');

        // Total Redeemed
        const totalRedeemed = await pool.query("SELECT COALESCE(SUM(points_requested), 0) as total FROM redemptions WHERE status = 'approved'");

        // Active Today
        const activeToday = await pool.query("SELECT COUNT(DISTINCT user_id) as count FROM activity_log WHERE created_at >= CURRENT_DATE");

        // New Users Today
        const newUsersToday = await pool.query("SELECT COUNT(*) as count FROM users WHERE created_at >= CURRENT_DATE");

        // Redemption Stats
        const pendingRedemptions = await pool.query("SELECT COUNT(*) as count FROM redemptions WHERE status = 'pending'");
        const approvedRedemptions = await pool.query("SELECT COUNT(*) as count FROM redemptions WHERE status = 'approved'");
        const rejectedRedemptions = await pool.query("SELECT COUNT(*) as count FROM redemptions WHERE status = 'rejected'");

        // Commission Points
        const commissionPoints = await pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM point_transactions WHERE transaction_type = 'referral'");

        // Global Task Participants
        const globalTaskParticipants = await pool.query("SELECT COUNT(DISTINCT user_id) as count FROM user_lead_assignments");

        // Personal Share Participants
        const personalShareParticipants = await pool.query("SELECT COUNT(DISTINCT s.user_id) as count FROM submissions s WHERE s.status = 'active'");

        res.json({
            totalUsers: parseInt(totalUsers.rows[0].count),
            totalPointsDistributed: parseInt(totalPoints.rows[0].total),
            totalRedeemed: parseInt(totalRedeemed.rows[0].total),
            activeToday: parseInt(activeToday.rows[0].count),
            newUsersToday: parseInt(newUsersToday.rows[0].count),
            pendingRedemptions: parseInt(pendingRedemptions.rows[0].count),
            approvedRedemptions: parseInt(approvedRedemptions.rows[0].count),
            rejectedRedemptions: parseInt(rejectedRedemptions.rows[0].count),
            commissionDistributed: parseInt(commissionPoints.rows[0].total),
            globalTaskParticipants: parseInt(globalTaskParticipants.rows[0].count),
            personalShareParticipants: parseInt(personalShareParticipants.rows[0].count)
        });
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

// Admin Dashboard Charts
// Admin Dashboard Charts (SAFE VERSION)
router.get('/admin/dashboard-charts', authenticateAdmin, checkPermission('view_dashboard'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { dateRange } = req.query;

        // Determine days back
        let daysBack = 7;
        if (dateRange === 'today') daysBack = 1;
        else if (dateRange === 'yesterday') daysBack = 2;
        else if (dateRange === 'week') daysBack = 7;
        else if (dateRange === 'month') daysBack = 30;
        else if (dateRange === 'year') daysBack = 365;

        // Comprehensive Overview Data
        const userGrowth = await pool.query(`
            WITH date_series AS (
                SELECT TO_CHAR(generate_series(
                    CURRENT_DATE - INTERVAL '${daysBack} days',
                    CURRENT_DATE,
                    '1 day'
                )::date, 'MM/DD') as date
            )
            SELECT 
                ds.date,
                COALESCE(u.count, 0) as users,
                COALESCE(r.count, 0) as redemptions,
                COALESCE(p.total, 0) as "pointsDistributed",
                COALESCE(t.count, 0) as "tasksCompleted"
            FROM date_series ds
            LEFT JOIN (
                SELECT TO_CHAR(DATE(created_at), 'MM/DD') as date, COUNT(*) as count
                FROM users
                WHERE created_at >= CURRENT_DATE - INTERVAL '${daysBack} days'
                GROUP BY DATE(created_at)
            ) u ON ds.date = u.date
            LEFT JOIN (
                SELECT TO_CHAR(DATE(requested_at), 'MM/DD') as date, COUNT(*) as count
                FROM redemptions
                WHERE requested_at >= CURRENT_DATE - INTERVAL '${daysBack} days' AND status = 'approved'
                GROUP BY DATE(requested_at)
            ) r ON ds.date = r.date
            LEFT JOIN (
                SELECT TO_CHAR(DATE(created_at), 'MM/DD') as date, SUM(amount) as total
                FROM point_transactions
                WHERE created_at >= CURRENT_DATE - INTERVAL '${daysBack} days' AND amount > 0
                GROUP BY DATE(created_at)
            ) p ON ds.date = p.date
            LEFT JOIN (
                SELECT TO_CHAR(DATE(completed_at), 'MM/DD') as date, COUNT(*) as count
                FROM user_lead_assignments
                WHERE completed_at >= CURRENT_DATE - INTERVAL '${daysBack} days' AND status = 'approved'
                GROUP BY DATE(completed_at)
            ) t ON ds.date = t.date
            ORDER BY ds.date
        `);

        // Task Completion
        const taskCompletion = await pool.query(`
            SELECT 
                TO_CHAR(DATE(completed_at), 'MM/DD') as date,
                COUNT(*) as "globalTasks",
                0 as "personalShare"
            FROM user_lead_assignments
            WHERE completed_at >= CURRENT_DATE - INTERVAL '${daysBack} days' AND status = 'approved'
            GROUP BY DATE(completed_at)
            ORDER BY DATE(completed_at)
        `);

        // Redemptions Breakdown
        const redemptions = await pool.query(`
            SELECT 
                status as name,
                COUNT(*)::int as value
            FROM redemptions
            GROUP BY status
        `);

        // Points Distribution
        const pointsDistribution = await pool.query(`
            SELECT 
                transaction_type as category,
                SUM(amount)::int as points
            FROM point_transactions
            WHERE amount > 0
            GROUP BY transaction_type
            ORDER BY points DESC
            LIMIT 10
        `);

        res.json({
            userGrowth: userGrowth.rows,
            taskCompletion: taskCompletion.rows,
            redemptions: redemptions.rows,
            pointsDistribution: pointsDistribution.rows
        });

    } catch (error) {
        console.error('Error fetching dashboard charts:', error);
        res.status(500).json({ error: 'Failed to fetch chart data', details: error.message });
    }
});
// Recent Activities
router.get('/admin/recent-activities', authenticateAdmin, checkPermission('view_dashboard'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { limit = 10 } = req.query;

        const activities = await pool.query(`
            SELECT 
                activity_type,
                title,
                description,
                created_at
            FROM activity_log
            ORDER BY created_at DESC
            LIMIT $1
        `, [limit]);

        res.json(activities.rows);
    } catch (error) {
        console.error('Error fetching recent activities:', error);
        res.status(500).json({ error: 'Failed to fetch activities' });
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


router.post('/track-social-link-click/:id', async (req, res) => {
    const { id } = req.params;
    const pool = req.app.get('db'); // ✅ ADD THIS LINE

    try {
        const result = await pool.query(
            'UPDATE social_links SET clicks = clicks + 1 WHERE id = $1 AND is_active = true RETURNING *',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Link not found or inactive' });
        }

        res.json({
            success: true,
            clicks: result.rows[0].clicks
        });
    } catch (error) {
        console.error('Track social link click error:', error);
        res.status(500).json({ error: 'Failed to track click' });
    }
});

// ==================== SOCIAL LINKS ROUTES ====================

// Get all active social links (PUBLIC)
router.get('/social-links', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const result = await pool.query(
            'SELECT * FROM social_links WHERE is_active = true ORDER BY display_order ASC'
        );
        res.json({ links: result.rows });
    } catch (error) {
        console.error('Error fetching social links:', error);
        res.json({ links: [] });
    }
});

// Get all social links for admin (ADMIN ONLY)
router.get('/admin/social-links', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const result = await pool.query(
            'SELECT * FROM social_links ORDER BY display_order ASC'
        );
        res.json({ links: result.rows });
    } catch (error) {
        console.error('Error fetching admin social links:', error);
        res.json({ links: [] });
    }
});

// Create social link (ADMIN ONLY)
router.post('/admin/social-links', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { platform, title, url, displayOrder } = req.body;

        if (!platform || !title || !url) {
            return res.status(400).json({ error: 'Platform, title, and URL are required' });
        }

        const result = await pool.query(
            `INSERT INTO social_links (platform, title, url, icon, icon_url, display_order, is_active, created_at)
             VALUES ($1, $2, $3, '', '', $4, true, NOW())
             RETURNING *`,
            [platform, title, url, displayOrder || 0]
        );

        await logAdminActivity(pool, req.admin.adminId, 'create_social_link', `Created social link: ${title} (${platform})`);

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Create social link error:', error);
        res.status(500).json({ error: 'Failed to create social link' });
    }
});

// Update social link (ADMIN ONLY)
router.put('/admin/social-links/:id', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const { platform, title, url, displayOrder } = req.body;

        const result = await pool.query(
            `UPDATE social_links 
             SET platform = $1, title = $2, url = $3, display_order = $4
             WHERE id = $5
             RETURNING *`,
            [platform, title, url, displayOrder || 0, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Social link not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'update_social_link', `Updated social link: ${title}`);

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Update social link error:', error);
        res.status(500).json({ error: 'Failed to update social link' });
    }
});

// Toggle social link active status (ADMIN ONLY)
router.patch('/admin/social-links/:id/toggle', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE social_links 
             SET is_active = NOT is_active
             WHERE id = $1
             RETURNING *`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Social link not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'toggle_social_link', `Toggled social link: ${result.rows[0].title}`);

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Toggle social link error:', error);
        res.status(500).json({ error: 'Failed to toggle social link' });
    }
});

// Delete social link (ADMIN ONLY)
router.delete('/admin/social-links/:id', authenticateAdmin, checkPermission('manage_social_links'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const result = await pool.query('DELETE FROM social_links WHERE id = $1 RETURNING *', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Social link not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'delete_social_link', `Deleted social link: ${result.rows[0].title}`);

        res.json({ message: 'Social link deleted successfully' });
    } catch (error) {
        console.error('Delete social link error:', error);
        res.status(500).json({ error: 'Failed to delete social link' });
    }
});





// ==================== STREAK SYSTEM ROUTES ====================

// Get user streak info
router.get('/user-streak/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        let streak = await pool.query('SELECT * FROM user_streaks WHERE user_id = $1', [userId]);

        if (streak.rows.length === 0) {
            // Create initial streak record
            streak = await pool.query(
                'INSERT INTO user_streaks (user_id) VALUES ($1) RETURNING *',
                [userId]
            );
        }

        res.json({ streak: streak.rows[0] });
    } catch (error) {
        console.error('Error fetching streak:', error);
        res.status(500).json({ error: 'Failed to fetch streak' });
    }
});

// Update streak (called after submission)
router.post('/update-streak', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.body;

        const today = new Date().toISOString().split('T')[0];

        // Get current streak
        let streak = await pool.query('SELECT * FROM user_streaks WHERE user_id = $1', [userId]);

        if (streak.rows.length === 0) {
            // Create new streak
            await pool.query(
                'INSERT INTO user_streaks (user_id, current_streak, longest_streak, last_share_date) VALUES ($1, 1, 1, $2)',
                [userId, today]
            );
            return res.json({ message: 'Streak started', currentStreak: 1, bonus: 0 });
        }

        const lastShareDate = streak.rows[0].last_share_date;
        const currentStreak = streak.rows[0].current_streak;

        // Check if already shared today
        if (lastShareDate === today) {
            return res.json({ message: 'Already shared today', currentStreak, bonus: 0 });
        }

        // Check if streak continues
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        const yesterdayStr = yesterday.toISOString().split('T')[0];

        let newStreak = 1;
        if (lastShareDate === yesterdayStr) {
            newStreak = currentStreak + 1;
        }

        // Get settings
        const settings = await pool.query('SELECT * FROM settings WHERE setting_key IN ($1, $2, $3)',
            ['streak_daily_bonus', 'streak_7day_bonus', 'streak_30day_bonus']);

        const settingsObj = {};
        settings.rows.forEach(s => {
            settingsObj[s.setting_key] = parseInt(s.setting_value);
        });

        // Calculate bonus
        let bonus = settingsObj.streak_daily_bonus || 10;
        if (newStreak === 7) bonus = settingsObj.streak_7day_bonus || 50;
        if (newStreak === 30) bonus = settingsObj.streak_30day_bonus || 500;

        // Update streak
        await pool.query(
            `UPDATE user_streaks 
             SET current_streak = $1, 
                 longest_streak = GREATEST(longest_streak, $1),
                 last_share_date = $2,
                 total_streak_bonuses = total_streak_bonuses + $3,
                 updated_at = NOW()
             WHERE user_id = $4`,
            [newStreak, today, bonus, userId]
        );

        // Award bonus points
        if (bonus > 0) {
            await pool.query(
                'UPDATE users SET points = points + $1 WHERE id = $2',
                [bonus, userId]
            );
            // ✅ ADD THIS: Log streak activity
            const nextDayKey = `streak_day${newStreak + 1}_bonus`;
            const nextSettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [nextDayKey]);
            const nextBonus = parseInt(nextSettings.rows[0]?.setting_value) || 0;
            await logStreakActivity(pool, userId, newStreak, bonus, nextBonus);

        }

        res.json({
            message: 'Streak updated',
            currentStreak: newStreak,
            bonus,
            milestone: newStreak === 7 ? '7-day streak!' : newStreak === 30 ? '30-day streak!' : null
        });
    } catch (error) {
        console.error('Error updating streak:', error);
        res.status(500).json({ error: 'Failed to update streak' });
    }
});

// ==================== REFERRAL SYSTEM ROUTES ====================

// Get user referral info
router.get('/referral-info/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        // Get user's referral code
        const user = await pool.query('SELECT referral_code, referred_by_code FROM users WHERE id = $1', [userId]);

        // Get referral stats
        const stats = await pool.query(
            `SELECT 
                COUNT(*) as total_referrals,
                SUM(CASE WHEN signup_bonus_awarded = true THEN 1 ELSE 0 END) as successful_referrals,
                SUM(total_commission_earned) as total_commission
             FROM referrals 
             WHERE referrer_id = $1`,
            [userId]
        );

        // Get referred users list (paginated)
        const referrals = await pool.query(
            `SELECT r.*, u.whatsapp_number, u.points, u.created_at as signup_date
             FROM referrals r
             JOIN users u ON r.referred_id = u.id
             WHERE r.referrer_id = $1
             ORDER BY r.created_at DESC
             LIMIT 10`,
            [userId]
        );

        // Get settings
        const settings = await pool.query(
            'SELECT * FROM settings WHERE setting_key IN ($1, $2)',
            ['referral_signup_bonus', 'referral_commission_percent']
        );

        const settingsObj = {};
        settings.rows.forEach(s => {
            settingsObj[s.setting_key] = s.setting_value;
        });

        res.json({
            referralCode: user.rows[0].referral_code,
            referredBy: user.rows[0].referred_by_code,
            stats: stats.rows[0],
            referrals: referrals.rows,
            settings: settingsObj
        });
    } catch (error) {
        console.error('Error fetching referral info:', error);
        res.status(500).json({ error: 'Failed to fetch referral info' });
    }
});

// Apply referral code (during signup or later)
router.post('/apply-referral', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId, referralCode } = req.body;

        // Check if user already used a referral code
        const user = await pool.query('SELECT referred_by_code FROM users WHERE id = $1', [userId]);
        if (user.rows[0].referred_by_code) {
            return res.status(400).json({ error: 'You have already used a referral code' });
        }

        // Find referrer
        const referrer = await pool.query('SELECT id FROM users WHERE referral_code = $1', [referralCode]);
        if (referrer.rows.length === 0) {
            return res.status(404).json({ error: 'Invalid referral code' });
        }

        const referrerId = referrer.rows[0].id;

        // Can't refer yourself
        if (referrerId === parseInt(userId)) {
            return res.status(400).json({ error: 'Cannot use your own referral code' });
        }

        // Get bonus amount
        const settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['referral_signup_bonus']);
        const bonus = parseInt(settings.rows[0].setting_value) || 100;

        // Create referral record
        await pool.query(
            `INSERT INTO referrals (referrer_id, referred_id, referral_code, signup_bonus_awarded)
             VALUES ($1, $2, $3, true)`,
            [referrerId, userId, referralCode]
        );

        // Update user's referred_by_code
        await pool.query('UPDATE users SET referred_by_code = $1 WHERE id = $2', [referralCode, userId]);

        // Award bonus to referrer
        await pool.query('UPDATE users SET points = points + $1, referral_earnings = referral_earnings + $1 WHERE id = $2', [bonus, referrerId]);
        await logPointTransaction(pool, referrerId, bonus, 'referral', `Referral bonus from user ${userId}`, userId);

        await logAdminActivity(pool, null, 'referral_bonus', `User ${userId} used referral code ${referralCode}. Referrer ${referrerId} got ${bonus} points`);

        res.json({ message: `Referral applied! Your referrer got ${bonus} points`, bonus });
    } catch (error) {
        console.error('Error applying referral:', error);
        res.status(500).json({ error: 'Failed to apply referral code' });
    }
});

// Award referral commission (called when referred user earns points)
router.post('/referral-commission', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId, pointsEarned } = req.body;

        // Check if user was referred
        const user = await pool.query('SELECT referred_by_code FROM users WHERE id = $1', [userId]);
        if (!user.rows[0].referred_by_code) {
            return res.json({ message: 'No referrer' });
        }

        // Find referrer
        const referrer = await pool.query('SELECT id FROM users WHERE referral_code = $1', [user.rows[0].referred_by_code]);
        if (referrer.rows.length === 0) {
            return res.json({ message: 'Referrer not found' });
        }

        // Get commission percentage
        const settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['referral_commission_percent']);
        const commissionPercent = parseInt(settings.rows[0].setting_value) || 10;

        const commission = Math.floor(pointsEarned * commissionPercent / 100);

        if (commission > 0) {
            // Award commission
            await pool.query('UPDATE users SET points = points + $1, referral_earnings = referral_earnings + $1 WHERE id = $2', [commission, referrer.rows[0].id]);

            // ✅ ADD THIS: Log commission activity
            const referredUser = await pool.query('SELECT whatsapp_number FROM users WHERE id = $1', [userId]);
            await logCommissionActivity(pool, referrer.rows[0].id, referredUser.rows[0].whatsapp_number, commission, commissionPercent, pointsEarned, userId);

            // Update referral record
            await pool.query(
                'UPDATE referrals SET total_commission_earned = total_commission_earned + $1 WHERE referrer_id = $2 AND referred_id = $3',
                [commission, referrer.rows[0].id, userId]
            );
        }

        res.json({ message: 'Commission awarded', commission });
    } catch (error) {
        console.error('Error awarding commission:', error);
        res.status(500).json({ error: 'Failed to award commission' });
    }
});

// ==================== SPIN & EARN ROUTES ====================

// Get user spin info
router.get('/user-spins/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const today = new Date().toISOString().split('T')[0];
        // Get free spins setting for first-time spin check
        const firstTimeSpinSettings = await pool.query(
            'SELECT setting_value FROM settings WHERE setting_key = $1',
            ['spin_free_per_day']
        );
        const firstTimeFreeSpins = parseInt(firstTimeSpinSettings.rows[0]?.setting_value) || 1;

        let spins = await pool.query('SELECT * FROM user_spins WHERE user_id = $1', [userId]);

        if (spins.rows.length === 0) {
            // Create initial spin record
            spins = await pool.query(
                'INSERT INTO user_spins (user_id, free_spins_today, last_spin_date) VALUES ($1, $2, $3) RETURNING *',
                [userId, firstTimeFreeSpins, today]
            );
        } else {
            // Reset free spins if new day - FIX: Convert database date to string for comparison
            const lastSpinDate = spins.rows[0].last_spin_date
                ? new Date(spins.rows[0].last_spin_date).toISOString().split('T')[0]
                : null;

            if (lastSpinDate !== today) {
                console.log('📅 New day detected, resetting spins'); // Debug log
                // ✅ FIXED:
                const spinSettings = await pool.query(
                    'SELECT setting_value FROM settings WHERE setting_key = $1',
                    ['spin_free_per_day']
                );
                const freeSpinsPerDay = parseInt(spinSettings.rows[0]?.setting_value) || 1;

                await pool.query(
                    'UPDATE user_spins SET free_spins_today = $1, last_spin_date = $2 WHERE user_id = $3',
                    [freeSpinsPerDay, today, userId]
                );
                spins = await pool.query('SELECT * FROM user_spins WHERE user_id = $1', [userId]);
            }
        }

        // Get settings
        const settings = await pool.query(
            'SELECT * FROM settings WHERE setting_key IN ($1, $2, $3)',
            ['spin_free_per_day', 'spin_cost_points', 'spin_prizes']
        );

        const settingsObj = {};
        settings.rows.forEach(s => {
            settingsObj[s.setting_key] = s.setting_value;
        });

        // Get recent spin history
        const history = await pool.query(
            'SELECT * FROM spin_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10',
            [userId]
        );

        res.json({
            spins: spins.rows[0],
            settings: settingsObj,
            history: history.rows
        });
    } catch (error) {
        console.error('Error fetching spin info:', error);
        res.status(500).json({ error: 'Failed to fetch spin info' });
    }
});

// Spin the wheel
// Spin the wheel
router.post('/spin', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId, spinType } = req.body; // spinType: 'free' or 'bonus' or 'paid'
        console.log('🎰 SPIN REQUEST:', { userId, spinType });
        const today = new Date().toISOString().split('T')[0];

        // Get user spins
        const userSpins = await pool.query('SELECT * FROM user_spins WHERE user_id = $1', [userId]);
        console.log('🎰 Current spins:', userSpins.rows[0]);

        if (userSpins.rows.length === 0) {
            return res.status(400).json({ error: 'Spin data not found' });
        }

        const spinData = userSpins.rows[0];

        // Check if user has spins available
        if (spinType === 'free' && spinData.free_spins_today <= 0) {
            console.log('❌ No free spins available');
            return res.status(400).json({ error: 'No free spins available today' });
        }

        if (spinType === 'bonus' && spinData.bonus_spins <= 0) {
            return res.status(400).json({ error: 'No bonus spins available' });
        }

        if (spinType === 'paid') {
            // Deduct points for paid spin
            const settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['spin_cost_points']);
            const cost = parseInt(settings.rows[0].setting_value) || 50;

            const user = await pool.query('SELECT points FROM users WHERE id = $1', [userId]);
            if (user.rows[0].points < cost) {
                return res.status(400).json({ error: 'Insufficient points' });
            }

            await pool.query('UPDATE users SET points = points - $1 WHERE id = $2', [cost, userId]);
        }

        // Get prize pool
        const settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['spin_prizes']);
        const prizes = JSON.parse(settings.rows[0].setting_value);

        // ============ DYNAMIC WEIGHTED RANDOM SELECTION ============
        const weights = prizes.map((prize, index) => {
            return Math.pow(2, prizes.length - index - 1);
        });

        console.log('🎲 Prizes:', prizes);
        console.log('⚖️ Weights:', weights);

        const totalWeight = weights.reduce((sum, weight) => sum + weight, 0);
        const probabilities = weights.map(w => ((w / totalWeight) * 100).toFixed(2) + '%');
        console.log('📊 Probabilities:', probabilities);

        // Select prize based on weighted random
        let random = Math.random() * totalWeight;
        let prizeIndex = 0;

        for (let i = 0; i < weights.length; i++) {
            random -= weights[i];
            if (random <= 0) {
                prizeIndex = i;
                break;
            }
        }

        const prize = prizes[prizeIndex];
        console.log('🎯 Selected prize:', prize, 'at index', prizeIndex);
        // ============ END WEIGHTED SELECTION ============

        // Award prize
        await pool.query('UPDATE users SET points = points + $1, spin_earnings = spin_earnings + $1 WHERE id = $2', [prize, userId]);

        // Log transaction
        await logSpinActivity(pool, userId, prize, spinType);
        await logPointTransaction(pool, userId, prize, 'spin', `Spin wheel reward: ${prize} points`, null);
        console.log('✅ Points added:', prize);

        // Update spin counts
        if (spinType === 'free') {
            console.log('🔄 Decrementing free spins...');
            await pool.query('UPDATE user_spins SET free_spins_today = free_spins_today - 1 WHERE user_id = $1', [userId]);
        } else if (spinType === 'bonus') {
            await pool.query('UPDATE user_spins SET bonus_spins = bonus_spins - 1 WHERE user_id = $1', [userId]);
        }

        // Update totals
        await pool.query(
            'UPDATE user_spins SET total_spins = total_spins + 1, total_won = total_won + $1 WHERE user_id = $2',
            [prize, userId]
        );
        console.log('✅ Spin complete');

        // Record spin history
        await pool.query(
            'INSERT INTO spin_history (user_id, prize_amount, spin_type) VALUES ($1, $2, $3)',
            [userId, prize, spinType]
        );

        // IMPORTANT: Return both the prize amount AND the exact segment index
        // The frontend wheel segments should match the prizes array order
        res.json({
            success: true,
            message: 'Spin successful!',
            prize: prize,
            prizeIndex: prizeIndex,  // This tells frontend which segment to land on
            totalPrizes: prizes.length // Helps frontend validate
        });
    } catch (error) {
        console.error('Error spinning:', error);
        res.status(500).json({ error: 'Failed to spin' });
    }
});



// Award bonus spin (called after X shares)
router.post('/award-bonus-spin', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.body;

        await pool.query(
            'UPDATE user_spins SET bonus_spins = bonus_spins + 1 WHERE user_id = $1',
            [userId]
        );

        res.json({ message: 'Bonus spin awarded!' });
    } catch (error) {
        console.error('Error awarding bonus spin:', error);
        res.status(500).json({ error: 'Failed to award bonus spin' });
    }
});

// ==================== MILESTONE SYSTEM ====================

// Check and award milestones (called after submission)
router.post('/check-milestones', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.body;

        // ✅ Get OLD personal shares (from user_recipients)
        const oldPersonalShares = await pool.query(
            `SELECT COUNT(DISTINCT recipient_number) as total
             FROM user_recipients sr
             JOIN submissions s ON sr.submission_id = s.id
             WHERE s.user_id = $1 AND s.status = 'active'`,
            [userId]
        );

        // ✅ Get NEW personal shares (from personal_share_submissions JSON)
        const newPersonalShares = await pool.query(
            `SELECT recipient_numbers
             FROM personal_share_submissions
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        // Count recipients from new system
        let newPersonalCount = 0;
        for (const row of newPersonalShares.rows) {
            try {
                const data = JSON.parse(row.recipient_numbers || '{}');
                newPersonalCount += data.recipients?.length || 0;
            } catch (e) {
                console.error('Error parsing recipient data:', e);
            }
        }

        // ✅ Get global task completions
        const globalTasks = await pool.query(
            `SELECT COUNT(*) as total
             FROM user_lead_assignments
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        // ✅ Combine all counts
        const oldPersonalCount = parseInt(oldPersonalShares.rows[0].total) || 0;
        const globalCount = parseInt(globalTasks.rows[0].total) || 0;
        const shareCount = oldPersonalCount + newPersonalCount + globalCount;

        console.log(`📊 User ${userId} Share Breakdown: Old Personal=${oldPersonalCount}, New Personal=${newPersonalCount}, Global=${globalCount}, Total=${shareCount}`);

        // Get milestone settings
        const milestones = await pool.query(
            `SELECT * FROM settings 
             WHERE setting_key LIKE 'milestone_%' 
             ORDER BY setting_key`
        );

        const milestonesObj = {};
        milestones.rows.forEach(m => {
            const shares = m.setting_key.replace('milestone_', '').replace('_shares', '');
            milestonesObj[shares] = parseInt(m.setting_value);
        });

        // Check each milestone
        const awarded = [];
        for (const [shares, bonus] of Object.entries(milestonesObj)) {
            const milestoneShares = parseInt(shares);

            if (shareCount >= milestoneShares) {
                // Check if already awarded
                const exists = await pool.query(
                    'SELECT * FROM user_milestones WHERE user_id = $1 AND milestone_type = $2 AND milestone_value = $3',
                    [userId, 'shares', milestoneShares]
                );

                if (exists.rows.length === 0) {
                    // Award milestone
                    await pool.query(
                        'INSERT INTO user_milestones (user_id, milestone_type, milestone_value, bonus_awarded) VALUES ($1, $2, $3, $4)',
                        [userId, 'shares', milestoneShares, bonus]
                    );

                    await pool.query(
                        'UPDATE users SET points = points + $1 WHERE id = $2',
                        [bonus, userId]
                    );

                    await logPointTransaction(pool, userId, bonus, 'milestone', `Milestone reward: ${milestoneShares} shares completed`, milestoneShares);

                    // Log milestone activity
                    const allMilestones = [10, 50, 100, 500, 1000, 5000, 10000];
                    const nextMilestone = allMilestones.find(m => m > milestoneShares) || null;
                    await logMilestoneActivity(pool, userId, milestoneShares, bonus, shareCount, nextMilestone);

                    awarded.push({ milestone: milestoneShares, bonus });
                }
            }
        }

        res.json({
            message: awarded.length > 0 ? 'Milestones achieved!' : 'No new milestones',
            awarded,
            currentShares: shareCount,
            breakdown: {
                oldPersonal: oldPersonalCount,
                newPersonal: newPersonalCount,
                globalTasks: globalCount
            }
        });
    } catch (error) {
        console.error('Error checking milestones:', error);
        res.status(500).json({ error: 'Failed to check milestones' });
    }
});

// Get user milestones
router.get('/user-milestones/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        // Get OLD personal shares
        const oldShares = await pool.query(
            `SELECT COUNT(DISTINCT recipient_number) as total
             FROM user_recipients sr
             JOIN submissions s ON sr.submission_id = s.id
             WHERE s.user_id = $1 AND s.status = 'active'`,
            [userId]
        );

        // Get NEW personal shares
        const newShares = await pool.query(
            `SELECT recipient_numbers FROM personal_share_submissions
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        let newShareCount = 0;
        for (const row of newShares.rows) {
            try {
                const data = JSON.parse(row.recipient_numbers || '{}');
                newShareCount += data.recipients?.length || 0;
            } catch (e) { }
        }

        // Get global tasks
        const globalTasks = await pool.query(
            `SELECT COUNT(*) as total FROM user_lead_assignments 
             WHERE user_id = $1 AND status = 'approved'`,
            [userId]
        );

        const oldCount = parseInt(oldShares.rows[0].total) || 0;
        const globalCount = parseInt(globalTasks.rows[0].total) || 0;
        const currentShares = oldCount + newShareCount + globalCount;

        // Get achieved milestones
        const milestones = await pool.query(
            `SELECT * FROM user_milestones 
             WHERE user_id = $1 AND milestone_type = 'shares'
             ORDER BY milestone_value ASC`,
            [userId]
        );

        console.log(`🏆 Milestones - User ${userId}: Old=${oldCount}, New=${newShareCount}, Global=${globalCount}, Total=${currentShares}`);

        res.json({
            milestones: milestones.rows,
            currentShares: currentShares,
            breakdown: {
                oldPersonal: oldCount,
                newPersonal: newShareCount,
                globalTasks: globalCount
            }
        });
    } catch (error) {
        console.error('Error fetching user milestones:', error);
        res.status(500).json({ error: 'Failed to fetch milestones' });
    }
});


// ==================== ACTIVITIES ROUTES ====================

// Get all active activities (PUBLIC)
router.get('/activities', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const now = new Date().toISOString();

        const activities = await pool.query(
            `SELECT * FROM activities 
             WHERE is_active = true 
             AND (start_date IS NULL OR start_date <= $1)
             AND (end_date IS NULL OR end_date >= $1)
             ORDER BY display_order ASC, created_at DESC`,
            [now]
        );

        res.json({ activities: activities.rows });
    } catch (error) {
        console.error('Error fetching activities:', error);
        res.json({ activities: [] });
    }
});

// Get activity details
router.get('/activity/:id', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const userId = req.user?.userId;

        const activity = await pool.query('SELECT * FROM activities WHERE id = $1', [id]);

        if (activity.rows.length === 0) {
            return res.status(404).json({ error: 'Activity not found' });
        }

        // Check if user participated
        let participation = null;
        if (userId) {
            const participationData = await pool.query(
                'SELECT * FROM activity_participations WHERE user_id = $1 AND activity_id = $2',
                [userId, id]
            );
            participation = participationData.rows[0] || null;
        }

        res.json({
            activity: activity.rows[0],
            participation
        });
    } catch (error) {
        console.error('Error fetching activity:', error);
        res.status(500).json({ error: 'Failed to fetch activity' });
    }
});


// Get user's activity participations
router.get('/user-activities/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const { page = 1, limit = 10 } = req.query;
        const offset = (page - 1) * limit;

        const participations = await pool.query(
            `SELECT ap.*, a.title, a.description, a.banner_image_url
             FROM activity_participations ap
             JOIN activities a ON ap.activity_id = a.id
             WHERE ap.user_id = $1
             ORDER BY ap.participated_at DESC
             LIMIT $2 OFFSET $3`,
            [userId, limit, offset]
        );

        const total = await pool.query(
            'SELECT COUNT(*) FROM activity_participations WHERE user_id = $1',
            [userId]
        );

        res.json({
            participations: participations.rows,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: parseInt(total.rows[0].count),
                totalPages: Math.ceil(total.rows[0].count / limit)
            }
        });
    } catch (error) {
        console.error('Error fetching user activities:', error);
        res.status(500).json({ error: 'Failed to fetch activities' });
    }
});




// ==================== ADMIN ACTIVITIES ROUTES ====================

// Get all activities for admin
router.get('/admin/activities', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        const activities = await pool.query(
            'SELECT * FROM activities ORDER BY display_order ASC, created_at DESC'
        );

        res.json({ activities: activities.rows });
    } catch (error) {
        console.error('Error fetching activities:', error);
        res.status(500).json({ error: 'Failed to fetch activities' });
    }
});

// Create activity
// Create activity
router.post('/admin/activities', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const {
            title,
            description,
            bannerImageUrl,
            detailImageUrl,
            activityType,
            pointsReward,
            startDate,
            endDate,
            maxParticipations,
            displayOrder
        } = req.body;

        const result = await pool.query(
            `INSERT INTO activities (
        title, description, banner_image_url, detail_image_url, activity_type, 
        points_reward, start_date, end_date, max_participations, display_order
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
            [
                title,
                description || '',
                bannerImageUrl || '',
                detailImageUrl || null,      // ✅ NEW
                activityType || 'promotion',
                pointsReward || 0,
                startDate || null,
                endDate || null,
                maxParticipations || 1,
                displayOrder || 0
            ]
        );
        await logAdminActivity(pool, req.admin.adminId, 'create_activity', `Created activity: ${title}`);

        res.json({ message: 'Activity created successfully', activity: result.rows[0] });
    } catch (error) {
        console.error('Error creating activity:', error);
        res.status(500).json({ error: 'Failed to create activity' });
    }
});

// Update activity
router.put('/admin/activities/:id', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const {
            title,
            description,
            bannerImageUrl,
            detailImageUrl,
            activityType,
            pointsReward,
            startDate,
            endDate,
            maxParticipations,
            displayOrder,
            isActive
        } = req.body;

        const result = await pool.query(
            `UPDATE activities 
     SET title = $1, description = $2, banner_image_url = $3, 
         detail_image_url = $4, activity_type = $5, points_reward = $6, 
         start_date = $7, end_date = $8, max_participations = $9, 
         display_order = $10, is_active = $11, updated_at = NOW()
     WHERE id = $12 RETURNING *`,
            [
                title,
                description || '',
                bannerImageUrl || '',
                detailImageUrl || null,      // ✅ NEW
                activityType || 'promotion',
                pointsReward || 0,
                startDate || null,
                endDate || null,
                maxParticipations || 1,
                displayOrder || 0,
                isActive !== false,
                id
            ]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Activity not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'update_activity', `Updated activity: ${title}`);

        res.json({ message: 'Activity updated successfully', activity: result.rows[0] });
    } catch (error) {
        console.error('Error updating activity:', error);
        res.status(500).json({ error: 'Failed to update activity' });
    }
});


// Toggle activity status
router.patch('/admin/activities/:id/toggle', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const result = await pool.query(
            'UPDATE activities SET is_active = NOT is_active WHERE id = $1 RETURNING *',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Activity not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'toggle_activity', `Toggled activity ID ${id}`);

        res.json({ message: 'Activity status toggled', activity: result.rows[0] });
    } catch (error) {
        console.error('Error toggling activity:', error);
        res.status(500).json({ error: 'Failed to toggle activity' });
    }
});

// Delete activity
router.delete('/admin/activities/:id', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const result = await pool.query('DELETE FROM activities WHERE id = $1 RETURNING *', [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Activity not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'delete_activity', `Deleted activity: ${result.rows[0].title}`);

        res.json({ message: 'Activity deleted successfully' });
    } catch (error) {
        console.error('Error deleting activity:', error);
        res.status(500).json({ error: 'Failed to delete activity' });
    }
});

// Get activity statistics
router.get('/admin/activities/:id/stats', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const stats = await pool.query(
            `SELECT 
                COUNT(*) as total_participations,
                COUNT(DISTINCT user_id) as unique_users,
                SUM(points_earned) as total_points_awarded
             FROM activity_participations 
             WHERE activity_id = $1`,
            [id]
        );

        res.json({ stats: stats.rows[0] });
    } catch (error) {
        console.error('Error fetching activity stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

// Upload activity banner
router.post('/admin/upload-activity-banner', authenticateAdmin, checkPermission('manage_activities'), uploadBanner.single('banner'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        const url = '/uploads/banners/' + req.file.filename;
        console.log('✅ Activity banner uploaded:', url);
        res.json({ url });
    } catch (error) {
        console.error('Error uploading activity banner:', error);
        res.status(500).json({ error: 'Failed to upload banner' });
    }
});

// ==================== ADMIN SETTINGS ROUTES ====================

// Get all feature settings - USE OLD KEYS
router.get('/admin/feature-settings', authenticateAdmin, async (req, res) => {
    // Check permission but return empty instead of 403
    const hasPermission = ['settings_referral', 'settings_spin', 'settings_streak', 'settings_milestone']
        .some(p => req.admin.permissions?.includes(p) || req.admin.role === 'super_admin');

    if (!hasPermission) {
        return res.json({}); // Return empty instead of 403
    }
    try {
        const pool = req.app.get('db');

        const settings = await pool.query(
            `SELECT setting_key, setting_value FROM settings 
     WHERE setting_key LIKE 'streak_day%'    -- ✅ Changed from 'streak_%'
        OR setting_key LIKE 'referral_%' 
        OR setting_key LIKE 'spin_%'
        OR setting_key LIKE 'milestone_%'
     ORDER BY setting_key`
        );

        // Default values using OLD database keys
        const settingsObj = {
            // Streak defaults
            streak_day1_bonus: '5',
            streak_day2_bonus: '15',
            streak_day3_bonus: '20',
            streak_day4_bonus: '25',
            streak_day5_bonus: '30',
            streak_day6_bonus: '35',
            streak_day7_bonus: '50',
            // Referral defaults
            referral_signup_bonus: '50',
            referral_commission_percent: '5',
            // Spin defaults - MAP OLD KEYS TO FRONTEND KEYS
            spin_prizes: '[10,2,3,5,1,20]',
            daily_free_spins: '1',      // Frontend uses this
            shares_per_bonus_spin: '10', // Frontend uses this
            // Milestone defaults
            milestone_100: '10',
            milestone_500: '50',
            milestone_1000: '100',
            milestone_5000: '500',
            milestone_10000: '1000'
        };

        // Override with database values
        settings.rows.forEach(row => {
            // Direct mapping for most keys
            settingsObj[row.setting_key] = row.setting_value;

            // MAP OLD DATABASE KEYS → FRONTEND KEYS
            if (row.setting_key === 'spin_free_per_day') {
                settingsObj['daily_free_spins'] = row.setting_value;
            }
            if (row.setting_key === 'spin_per_shares') {
                settingsObj['shares_per_bonus_spin'] = row.setting_value;
            }
        });

        console.log('📤 Admin settings:', settingsObj);
        res.json(settingsObj);
    } catch (error) {
        console.error('Error fetching feature settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Bulk update feature settings - SAVE TO OLD KEYS
router.put('/admin/feature-settings', authenticateAdmin, checkSettingsPermission, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const updates = req.body;

        console.log('📥 Admin saving:', updates);

        for (const [key, value] of Object.entries(updates)) {
            let dbKey = key;

            // MAP FRONTEND KEYS → OLD DATABASE KEYS
            if (key === 'daily_free_spins') {
                dbKey = 'spin_free_per_day';
            } else if (key === 'shares_per_bonus_spin') {
                dbKey = 'spin_per_shares';
            }

            console.log(`💾 Saving ${key} as ${dbKey} = ${value}`);

            await pool.query(
                `INSERT INTO settings (setting_key, setting_value, updated_at) 
                 VALUES ($1, $2, NOW())
                 ON CONFLICT (setting_key) 
                 DO UPDATE SET setting_value = $2, updated_at = NOW()`,
                [dbKey, value.toString()]
            );
        }

        await logAdminActivity(
            pool,
            req.admin.adminId,
            'update_settings',
            `Updated: ${Object.keys(updates).join(', ')}`
        );

        res.json({
            message: 'Settings updated successfully',
            updatedKeys: Object.keys(updates)
        });
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// Get spin settings for users - USE OLD KEYS
router.get('/spin-settings', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');

        const settings = await pool.query(
            `SELECT setting_key, setting_value FROM settings 
             WHERE setting_key IN ('spin_free_per_day', 'spin_per_shares', 'spin_prizes')`
        );

        const settingsObj = {
            daily_free_spins: 1,
            shares_per_bonus_spin: 10,
            prizes: [10, 2, 3, 5, 1, 20]
        };

        settings.rows.forEach(row => {
            if (row.setting_key === 'spin_free_per_day') {
                settingsObj.daily_free_spins = parseInt(row.setting_value);
            } else if (row.setting_key === 'spin_per_shares') {
                settingsObj.shares_per_bonus_spin = parseInt(row.setting_value);
            } else if (row.setting_key === 'spin_prizes') {
                settingsObj.prizes = JSON.parse(row.setting_value);
            }
        });

        console.log('📤 User spin settings:', settingsObj);
        res.json(settingsObj);
    } catch (error) {
        console.error('Error fetching spin settings:', error);
        res.status(500).json({ error: 'Failed to fetch spin settings' });
    }
});




// KEEP the existing single-setting update route below
// router.put('/admin/feature-settings/:key', ...)

// Update feature setting
router.put('/admin/feature-settings/:key', authenticateAdmin, checkSettingsPermission, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { key } = req.params;
        const { value, description } = req.body;

        const result = await pool.query(
            'UPDATE settings SET setting_value = $1, description = $2, updated_at = NOW() WHERE setting_key = $3 RETURNING *',
            [value, description, key]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Setting not found' });
        }

        await logAdminActivity(pool, req.admin.adminId, 'update_setting', `Updated ${key} to ${value}`);

        res.json({ message: 'Setting updated successfully', setting: result.rows[0] });
    } catch (error) {
        console.error('Error updating setting:', error);
        res.status(500).json({ error: 'Failed to update setting' });
    }
});

router.get('/admin/feature-analytics', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // 1. ACTIVITIES ANALYTICS (Simple - just count activities for info)
        const activitiesData = await pool.query(`
            SELECT 
                COUNT(*) as total_activities
            FROM activities
        `);

        const activityParticipations = await pool.query(`
            SELECT 
                COUNT(*) as total_participations,
                COALESCE(SUM(points_earned), 0)::integer as total_points_awarded
            FROM activity_participations
        `);

        // 2. SPIN ANALYTICS (Fixed: use prize_amount instead of points_won)
        const spinData = await pool.query(`
            SELECT 
                COUNT(*) as total_spins,
                COUNT(CASE WHEN spin_type = 'free' THEN 1 END) as free_spins,
                COUNT(CASE WHEN spin_type = 'bonus' THEN 1 END) as bonus_spins,
                COALESCE(SUM(prize_amount), 0)::integer as total_prize_amount
            FROM spin_history
        `);

        // 3. REFERRAL ANALYTICS (Fixed: use signup_bonus_awarded and correct status)
        const referralData = await pool.query(`
            SELECT 
                COUNT(*) as total_referrals,
                COUNT(CASE WHEN status = 'completed' OR status = 'active' THEN 1 END) as active_referrals,
                COALESCE(SUM(CASE WHEN signup_bonus_awarded = true THEN 100 ELSE 0 END), 0)::integer as signup_bonuses,
                COALESCE(SUM(total_commission_earned), 0)::integer as commission_paid
            FROM referrals
        `);

        // 4. STREAK ANALYTICS
        const streakData = await pool.query(`
            SELECT 
                COUNT(CASE WHEN current_streak > 0 THEN 1 END) as active_streaks,
                COALESCE(SUM(total_streak_bonuses), 0)::integer as total_points_awarded,
                MAX(longest_streak) as longest_streak
            FROM user_streaks
        `);

        // Get total streak claims from activity_log
        const streakClaims = await pool.query(`
            SELECT COUNT(*) as total_claimed
            FROM activity_log
            WHERE activity_type = 'streak'
        `);

        // 5. MILESTONE ANALYTICS
        const milestoneData = await pool.query(`
            SELECT 
                COUNT(*) as total_achieved,
                COALESCE(SUM(bonus_awarded), 0)::integer as points_awarded,
                COUNT(DISTINCT user_id) as users_with_milestones
            FROM user_milestones
        `);

        // Construct response
        const analytics = {
            activities: {
                total: parseInt(activitiesData.rows[0]?.total_activities) || 0,
                active: parseInt(activitiesData.rows[0]?.total_activities) || 0, // All activities are "active" for display purposes
                totalParticipations: parseInt(activityParticipations.rows[0]?.total_participations) || 0,
                pointsAwarded: activityParticipations.rows[0]?.total_points_awarded || 0
            },
            spins: {
                totalSpins: parseInt(spinData.rows[0]?.total_spins) || 0,
                freeSpins: parseInt(spinData.rows[0]?.free_spins) || 0,
                bonusSpins: parseInt(spinData.rows[0]?.bonus_spins) || 0,
                pointsWon: spinData.rows[0]?.total_prize_amount || 0
            },
            referrals: {
                totalReferrals: parseInt(referralData.rows[0]?.total_referrals) || 0,
                activeReferrals: parseInt(referralData.rows[0]?.active_referrals) || 0,
                pointsAwarded: referralData.rows[0]?.signup_bonuses || 0,
                commissionPaid: referralData.rows[0]?.commission_paid || 0
            },
            streaks: {
                activeStreaks: parseInt(streakData.rows[0]?.active_streaks) || 0,
                totalClaimed: parseInt(streakClaims.rows[0]?.total_claimed) || 0,
                pointsAwarded: streakData.rows[0]?.total_points_awarded || 0,
                longestStreak: parseInt(streakData.rows[0]?.longest_streak) || 0
            },
            milestones: {
                totalAchieved: parseInt(milestoneData.rows[0]?.total_achieved) || 0,
                pointsAwarded: milestoneData.rows[0]?.points_awarded || 0,
                usersWithMilestones: parseInt(milestoneData.rows[0]?.users_with_milestones) || 0
            }
        };

        console.log('📊 Feature Analytics fetched successfully');

        res.json(analytics);

    } catch (error) {
        console.error('Error fetching feature analytics:', error);
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});



// ==================== GLOBAL TASK SYSTEM ROUTES ====================

// Get active campaign and assign leads to user (first visit or request more)
router.get('/global-task/assign-leads/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const { requestMore } = req.query; // ?requestMore=true

        // Get campaign settings
        const settingsRes = await pool.query(
            'SELECT setting_key, setting_value FROM campaign_settings'
        );
        const settings = {};
        settingsRes.rows.forEach(row => {
            settings[row.setting_key] = row.setting_value;
        });

        const initialBatch = parseInt(settings.lead_initial_batch) || 200;
        const requestBatch = parseInt(settings.lead_request_batch) || 50;
        const expiryHours = parseInt(settings.assignment_expiry_hours) || 48;
        const maxTimesAssigned = parseInt(settings.max_times_lead_assigned) || 3;

        // Get active campaign
        const campaignRes = await pool.query(
            "SELECT * FROM campaigns WHERE status = 'active' ORDER BY created_at DESC LIMIT 1"
        );

        if (campaignRes.rows.length === 0) {
            return res.status(404).json({ error: 'No active campaign found' });
        }

        const campaign = campaignRes.rows[0];

        // Check if user already has assignments for this campaign
        const existingRes = await pool.query(
            "SELECT COUNT(*) as count FROM user_lead_assignments WHERE user_id = $1 AND campaign_id = $2 AND status IN ('pending', 'sent', 'proof_uploaded')",
            [userId, campaign.id]
        );

        const hasExisting = parseInt(existingRes.rows[0].count) > 0;
        const batchSize = (hasExisting || requestMore) ? requestBatch : initialBatch;

        // Get available leads
        const leadsRes = await pool.query(
            `SELECT * FROM leads 
             WHERE campaign_id = $1 
             AND status = 'available' 
             AND times_assigned < $2
             ORDER BY times_assigned ASC, created_at ASC
             LIMIT $3`,
            [campaign.id, maxTimesAssigned, batchSize]
        );

        if (leadsRes.rows.length === 0) {
            return res.status(404).json({ error: 'No leads available at the moment' });
        }

        const leads = leadsRes.rows;
        const expiresAt = new Date(Date.now() + expiryHours * 60 * 60 * 1000);

        // Assign leads to user
        for (const lead of leads) {
            await pool.query(
                `INSERT INTO user_lead_assignments 
                 (user_id, campaign_id, lead_id, status, expires_at)
                 VALUES ($1, $2, $3, 'pending', $4)
                 ON CONFLICT (user_id, lead_id) DO NOTHING`,
                [userId, campaign.id, lead.id, expiresAt]
            );

            // Update lead status and times_assigned
            await pool.query(
                "UPDATE leads SET status = 'assigned', times_assigned = times_assigned + 1 WHERE id = $1",
                [lead.id]
            );
        }

        res.json({
            campaign,
            leadsAssigned: leads.length,
            message: `${leads.length} leads assigned successfully`
        });
    } catch (error) {
        console.error('Error assigning leads:', error);
        res.status(500).json({ error: 'Failed to assign leads' });
    }
});

// Get user's assigned leads with status
router.get('/global-task/my-leads/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const { campaignId } = req.query;

        let query = `
            SELECT 
                ula.id as assignment_id,
                ula.status as assignment_status,
                ula.assigned_at,
                ula.expires_at,
                ula.sent_at,
                ula.proof_uploaded_at,
                ula.completed_at,
                ula.points_awarded,
                ula.rejection_reason,
                l.id as lead_id,
                l.phone_number,
                l.lead_name,
                l.lead_city,
                c.id as campaign_id,
                c.title as campaign_title,
                c.message_template,
                c.offer_image_url,
                c.points_per_lead
            FROM user_lead_assignments ula
            JOIN leads l ON ula.lead_id = l.id
            JOIN campaigns c ON ula.campaign_id = c.id
            WHERE ula.user_id = $1
        `;

        const params = [userId];

        if (campaignId) {
            query += ' AND ula.campaign_id = $2';
            params.push(campaignId);
        }

        query += ' ORDER BY ula.assigned_at DESC';

        const result = await pool.query(query, params);

        // Group by status
        const leads = {
            pending: [],
            sent: [],
            proof_uploaded: [],
            approved: [],
            rejected: [],
            expired: []
        };

        result.rows.forEach(row => {
            leads[row.assignment_status].push(row);
        });

        // Calculate progress
        const total = result.rows.length;
        const completed = leads.approved.length;
        const pending = leads.pending.length;
        const sent = leads.sent.length;

        res.json({
            leads,
            progress: {
                total,
                pending,
                sent,
                completed,
                percentage: total > 0 ? ((completed / total) * 100).toFixed(1) : 0
            }
        });
    } catch (error) {
        console.error('Error fetching user leads:', error);
        res.status(500).json({ error: 'Failed to fetch leads' });
    }
});

// Mark lead as sent (after clicking Send button)
router.put('/global-task/mark-sent/:assignmentId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { assignmentId } = req.params;
        const { userId } = req.body;

        // Verify assignment belongs to user
        const checkRes = await pool.query(
            'SELECT * FROM user_lead_assignments WHERE id = $1 AND user_id = $2',
            [assignmentId, userId]
        );

        if (checkRes.rows.length === 0) {
            return res.status(404).json({ error: 'Assignment not found' });
        }

        // Update status to 'sent'
        await pool.query(
            "UPDATE user_lead_assignments SET status = 'sent', updated_at = NOW() WHERE id = $1",
            [assignmentId]
        );

        res.json({
            message: 'Marked as sent successfully',
            status: 'sent'
        });
    } catch (error) {
        console.error('Error marking as sent:', error);
        res.status(500).json({ error: 'Failed to update status' });
    }
});

// Upload proof for a lead
router.post('/global-task/upload-proof', authenticateUser, uploadSubmission.single('screenshot'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { assignmentId, userId, additionalNotes } = req.body;

        if (!req.file) {
            return res.status(400).json({ error: 'Screenshot is required' });
        }

        // Get assignment details
        const assignmentRes = await pool.query(
            'SELECT * FROM user_lead_assignments WHERE id = $1 AND user_id = $2',
            [assignmentId, userId]
        );

        if (assignmentRes.rows.length === 0) {
            return res.status(404).json({ error: 'Assignment not found' });
        }

        const assignment = assignmentRes.rows[0];

        // Get settings
        const settingsRes = await pool.query(
            "SELECT setting_key, setting_value FROM campaign_settings WHERE setting_key IN ('instant_points_award', 'points_per_lead', 'admin_review_required', 'max_times_lead_assigned')"
        );

        const settings = {};
        settingsRes.rows.forEach(r => settings[r.setting_key] = r.setting_value);

        const instantAward = settings.instant_points_award === 'true';
        const adminReviewRequired = settings.admin_review_required === 'true';
        const pointsPerLead = parseInt(settings.points_per_lead) || 2;
        const maxTimesAssigned = parseInt(settings.max_times_lead_assigned) || 3;

        const screenshotUrl = `/uploads/submissions/${req.file.filename}`;
        const submissionStatus = adminReviewRequired ? 'pending' : 'approved';
        const assignmentStatus = adminReviewRequired ? 'proof_uploaded' : 'approved';

        // Create submission
        await pool.query(
            `INSERT INTO lead_submissions 
             (assignment_id, user_id, lead_id, campaign_id, screenshot_url, additional_notes, status)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [assignmentId, userId, assignment.lead_id, assignment.campaign_id, screenshotUrl, additionalNotes, submissionStatus]
        );

        // Update assignment status
        await pool.query(
            "UPDATE user_lead_assignments SET status = $1, proof_uploaded_at = NOW(), updated_at = NOW() WHERE id = $2",
            [assignmentStatus, assignmentId]
        );

        // ✅ ONLY award points and recycle lead if instant award (no admin review)
        if (instantAward) {
            // Award points
            await pool.query(
                'UPDATE users SET points = points + $1, task_earnings = task_earnings + $1 WHERE id = $2',
                [pointsPerLead, userId]
            );

            await pool.query(
                'UPDATE user_lead_assignments SET points_awarded = $1, completed_at = NOW() WHERE id = $2',
                [pointsPerLead, assignmentId]
            );

            await logPointTransaction(pool, userId, pointsPerLead, 'task', `Global task completed - instant award`, assignmentId);


            // Check if lead should return to pool
            const leadCheck = await pool.query(
                'SELECT times_assigned FROM leads WHERE id = $1',
                [assignment.lead_id]
            );

            const currentTimesAssigned = leadCheck.rows[0].times_assigned || 0;

            if (currentTimesAssigned < maxTimesAssigned) {
                // Lead can be assigned again - return to available pool
                await pool.query(
                    "UPDATE leads SET status = 'available' WHERE id = $1",
                    [assignment.lead_id]
                );
                console.log(`✅ Lead ${assignment.lead_id} returned to pool (${currentTimesAssigned}/${maxTimesAssigned} completions)`);
            } else {
                // Max reached - mark as completed permanently
                await pool.query(
                    "UPDATE leads SET status = 'completed' WHERE id = $1",
                    [assignment.lead_id]
                );
                console.log(`🎯 Lead ${assignment.lead_id} completed permanently (${currentTimesAssigned}/${maxTimesAssigned} times)`);
            }




            // ✅ UPDATE STREAK FOR USER COMPLETION
            try {
                const today = new Date().toISOString().split('T')[0];
                let streak = await pool.query('SELECT * FROM user_streaks WHERE user_id = $1', [userId]);

                if (streak.rows.length === 0) {
                    await pool.query(
                        'INSERT INTO user_streaks (user_id, current_streak, longest_streak, last_share_date) VALUES ($1, 1, 1, $2)',
                        [userId, today]
                    );

                    const day1Settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['streak_day1_bonus']);
                    const day1Bonus = parseInt(day1Settings.rows[0]?.setting_value) || 0;

                    if (day1Bonus > 0) {
                        await pool.query('UPDATE users SET points = points + $1 WHERE id = $2', [day1Bonus, userId]);
                        await pool.query(
                            'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                            [userId, `🔥 Day 1 streak! You earned ${day1Bonus} bonus points!`, 'streak_bonus']
                        );
                    }

                    console.log(`🔥 User Completion: Created new streak for user ${userId}`);
                } else {
                    const lastShareDate = streak.rows[0].last_share_date
                        ? new Date(streak.rows[0].last_share_date).toISOString().split('T')[0]
                        : null;
                    const currentStreak = streak.rows[0].current_streak;

                    if (lastShareDate !== today) {
                        const yesterday = new Date();
                        yesterday.setDate(yesterday.getDate() - 1);
                        const yesterdayStr = yesterday.toISOString().split('T')[0];

                        let newStreak = lastShareDate === yesterdayStr ? currentStreak + 1 : 1;

                        const cycleDay = ((newStreak - 1) % 7) + 1;
                        const settingKey = `streak_day${cycleDay}_bonus`;

                        console.log(`🔥 User Completion: Streak ${newStreak} → Cycle Day ${cycleDay}`);

                        const bonusSettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [settingKey]);
                        const streakBonus = parseInt(bonusSettings.rows[0]?.setting_value) || 0;

                        console.log(`💰 Cycle Day ${cycleDay} bonus: ${streakBonus} points`);

                        await pool.query(
                            `UPDATE user_streaks 
                         SET current_streak = $1, 
                             longest_streak = GREATEST(longest_streak, $1),
                             last_share_date = $2, 
                             total_streak_bonuses = total_streak_bonuses + $3,
                             updated_at = NOW()
                         WHERE user_id = $4`,
                            [newStreak, today, streakBonus, userId]
                        );

                        if (streakBonus > 0) {
                            await pool.query('UPDATE users SET points = points + $1, streak_earnings = streak_earnings + $1 WHERE id = $2', [streakBonus, userId]);

                            // Log point transaction
                            await pool.query(
                                'INSERT INTO point_transactions (user_id, amount, transaction_type, description, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)',
                                [userId, streakBonus, 'streak_bonus', `Day ${newStreak} streak bonus`]
                            );

                            // Log activity
                            const nextDayKey = `streak_day${((newStreak) % 7) + 1}_bonus`;
                            const nextDaySettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [nextDayKey]);
                            const nextDayBonus = parseInt(nextDaySettings.rows[0]?.setting_value) || 0;
                            await logStreakActivity(pool, userId, newStreak, streakBonus, nextDayBonus);

                            await pool.query(
                                'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                                [userId, `🔥 Day ${newStreak} streak! You earned ${streakBonus} bonus points!`, 'streak_bonus']
                            );
                        }

                        console.log(`🔥 User Completion: User ${userId} streak day ${newStreak}, earned ${streakBonus} bonus`);
                    }
                }
            } catch (streakError) {
                console.error('User completion streak error:', streakError);
            }

            // ✅ AWARD BONUS SPIN (instant mode)
            try {
                await awardBonusSpin(pool, userId);
            } catch (bonusError) {
                console.error('User completion bonus spin error:', bonusError);
            }

            // ✅ MILESTONE CHECK (instant mode)
            try {
                console.log('===== MILESTONE CHECK STARTED (INSTANT MODE) =====');
                console.log('User ID:', userId);

                // Get share count
                const personalShares = await pool.query(`
                    SELECT COUNT(DISTINCT recipient_number) as total
                    FROM user_recipients sr
                    JOIN submissions s ON sr.submission_id = s.id
                    WHERE s.user_id = $1 AND s.status = 'active'`, [userId]);

                const globalTasks = await pool.query(`
                    SELECT COUNT(*) as total
                    FROM user_lead_assignments
                    WHERE user_id = $1 AND status = 'approved'`, [userId]);

                const shareCount = parseInt(personalShares.rows[0].total) + parseInt(globalTasks.rows[0].total);

                console.log('Personal shares:', personalShares.rows[0].total);
                console.log('Global tasks:', globalTasks.rows[0].total);
                console.log('Total shareCount:', shareCount);

                // Check milestones
                const milestones = await pool.query(`
                    SELECT * FROM settings WHERE setting_key LIKE 'milestone_%' ORDER BY setting_key`);

                console.log('Milestones found:', milestones.rows.length);

                for (const m of milestones.rows) {
                    const shares = parseInt(m.setting_key.replace('milestone_', ''));
                    const bonus = parseInt(m.setting_value);

                    console.log(`Checking milestone ${shares}: shareCount=${shareCount}, bonus=${bonus}`);

                    if (shareCount >= shares) {
                        console.log('✅ Share count met!');

                        const exists = await pool.query(
                            'SELECT * FROM user_milestones WHERE user_id = $1 AND milestone_type = $2 AND milestone_value = $3',
                            [userId, 'shares', shares]
                        );

                        console.log('Already awarded?', exists.rows.length > 0);

                        if (exists.rows.length === 0) {
                            console.log('🎯 AWARDING MILESTONE NOW!');

                            await pool.query(
                                'INSERT INTO user_milestones (user_id, milestone_type, milestone_value, bonus_awarded) VALUES ($1, $2, $3, $4)',
                                [userId, 'shares', shares, bonus]
                            );

                            await pool.query(
                                'UPDATE users SET points = points + $1, milestone_earnings = milestone_earnings + $1 WHERE id = $2',
                                [bonus, userId]
                            );

                            await logPointTransaction(pool, userId, bonus, 'milestone', `Milestone reward: ${shares} shares completed`, shares);

                            const allMilestones = [10, 50, 100, 500, 1000, 5000, 10000];
                            const nextMilestone = allMilestones.find(m => m > shares) || null;
                            await logMilestoneActivity(pool, userId, shares, bonus, shareCount, nextMilestone);

                            console.log(`🎉 Milestone awarded: ${shares} shares - ${bonus} points to user ${userId}`);
                        }
                    }
                }

                console.log('===== MILESTONE CHECK COMPLETED =====');
            } catch (error) {
                console.error('Error auto-checking milestones (instant mode):', error);
            }




        } else {
            console.log(`⏳ Lead ${assignment.lead_id} awaiting admin approval before recycling`);
        }

        await logGlobalTaskActivity(pool, userId, assignment.lead_phone, pointsPerLead, assignment.lead_id, instantAward);





        res.json({
            message: 'Proof uploaded successfully',
            pointsAwarded: instantAward ? pointsPerLead : 0,
            instantAward,
            requiresReview: adminReviewRequired
        });
    } catch (error) {
        console.error('Error uploading proof:', error);
        res.status(500).json({ error: 'Failed to upload proof' });
    }
});

// Get campaign settings
router.get('/global-task/settings', async (req, res) => {
    try {
        const pool = req.app.get('db');
        const result = await pool.query('SELECT setting_key, setting_value FROM campaign_settings');

        const settings = {};
        result.rows.forEach(row => {
            settings[row.setting_key] = row.setting_value;
        });

        res.json({ settings });
    } catch (error) {
        console.error('Error fetching campaign settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// ==================== ADMIN ROUTES - GLOBAL TASK ====================

// Get all campaigns
router.get('/admin/campaigns', authenticateAdmin, checkPermission('task_global_configuration'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const result = await pool.query(
            'SELECT * FROM campaigns ORDER BY created_at DESC'
        );
        res.json({ campaigns: result.rows });
    } catch (error) {
        console.error('Error fetching campaigns:', error);
        res.status(500).json({ error: 'Failed to fetch campaigns' });
    }
});



// Update campaign configuration
router.put('/admin/campaigns/:id', authenticateAdmin, checkPermission('task_global_configuration'), uploadOffer.single('offerImage'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const { title, description, messageTemplate, pointsPerLead } = req.body;

        const offerImageUrl = req.file ? `/uploads/offers/${req.file.filename}` : null;

        // Build update query dynamically
        const updates = [];
        const values = [];
        let paramCount = 1;

        if (title) {
            updates.push(`title = $${paramCount}`);
            values.push(title);
            paramCount++;
        }
        if (description !== undefined) {
            updates.push(`description = $${paramCount}`);
            values.push(description);
            paramCount++;
        }
        if (messageTemplate) {
            updates.push(`message_template = $${paramCount}`);
            values.push(messageTemplate);
            paramCount++;
        }
        if (offerImageUrl) {
            updates.push(`offer_image_url = $${paramCount}`);
            values.push(offerImageUrl);
            paramCount++;
        }

        // ⬇️ ADD THIS LINE
        updates.push(`status = 'active'`);
        updates.push(`updated_at = NOW()`);
        values.push(id);

        await pool.query(
            `UPDATE campaigns SET ${updates.join(', ')} WHERE id = $${paramCount}`,
            values
        );

        await logAdminActivity(pool, req.admin.adminId, 'update_campaign', `Updated campaign ${id} configuration`);

        res.json({ message: 'Campaign updated successfully' });
    } catch (error) {
        console.error('Error updating campaign:', error);
        res.status(500).json({ error: 'Failed to update campaign' });
    }
});

// Get leads statistics for a campaign
router.get('/admin/campaigns/:id/leads-stats', authenticateAdmin, checkPermission('task_global_upload_leads'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const result = await pool.query(
            `SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'available') as available,
                COUNT(*) FILTER (WHERE status = 'assigned') as assigned,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'blocked') as blocked
             FROM leads
             WHERE campaign_id = $1`,
            [id]
        );

        res.json({ stats: result.rows[0] });
    } catch (error) {
        console.error('Error fetching leads stats:', error);
        res.status(500).json({ error: 'Failed to fetch leads statistics' });
    }
});

// Clear all leads for a campaign (add after the leads-stats route)
router.delete('/admin/campaigns/:id/leads', authenticateAdmin, checkPermission('task_global_upload_leads'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        // Delete all user assignments for this campaign
        await pool.query(
            'DELETE FROM user_lead_assignments WHERE campaign_id = $1',
            [id]
        );

        // Delete all leads for this campaign
        const result = await pool.query(
            'DELETE FROM leads WHERE campaign_id = $1 RETURNING *',
            [id]
        );

        await logAdminActivity(pool, req.admin.adminId, 'clear_leads', `Cleared ${result.rowCount} leads from campaign ${id}`);

        res.json({
            message: 'All leads cleared successfully',
            deleted: result.rowCount
        });
    } catch (error) {
        console.error('Error clearing leads:', error);
        res.status(500).json({ error: 'Failed to clear leads' });
    }
});

// Bulk upload leads
router.post('/admin/campaigns/:id/upload-leads', authenticateAdmin, checkPermission('task_global_upload_leads'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const { leads } = req.body; // Array of {phone_number, lead_name, lead_city}

        if (!Array.isArray(leads) || leads.length === 0) {
            return res.status(400).json({ error: 'Leads array is required' });
        }

        let inserted = 0;
        let skipped = 0;

        for (const lead of leads) {
            try {
                await pool.query(
                    `INSERT INTO leads (campaign_id, phone_number, lead_name, lead_city)
                     VALUES ($1, $2, $3, $4)`,
                    [id, lead.phone_number, lead.lead_name || null, lead.lead_city || null]
                );
                inserted++;
            } catch (err) {
                skipped++;
            }
        }

        await logAdminActivity(pool, req.admin.adminId, 'upload_leads', `Uploaded ${inserted} leads to campaign ${id}`);

        res.json({
            message: 'Leads uploaded',
            inserted,
            skipped,
            total: leads.length
        });
    } catch (error) {
        console.error('Error uploading leads:', error);
        res.status(500).json({ error: 'Failed to upload leads' });
    }
});


router.post('/admin/campaigns/:id/upload-leads-file', authenticateAdmin, checkPermission('task_global_upload_leads'), uploadLeadsFile.single('file'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const file = req.file;

        if (!file) {
            return res.status(400).json({ error: 'File is required' });
        }

        console.log(`📁 Processing: ${file.originalname} (${(file.size / 1024 / 1024).toFixed(2)}MB)`);

        let phoneNumbers = [];
        const ext = path.extname(file.originalname).toLowerCase();

        if (ext === '.csv' || ext === '.txt') {
            const content = file.buffer.toString('utf-8');
            phoneNumbers = content.split(/[\r\n]+/).map(line => line.trim()).filter(line => line && /^\d+$/.test(line));
        }
        else if (ext === '.xlsx' || ext === '.xls') {
            const workbook = XLSX.read(file.buffer, { type: 'buffer' });
            const sheet = workbook.Sheets[workbook.SheetNames[0]];
            const data = XLSX.utils.sheet_to_json(sheet, { header: 1 });
            phoneNumbers = data.map(row => String(row[0] || '').trim()).filter(num => num && /^\d+$/.test(num));
        }

        phoneNumbers = [...new Set(phoneNumbers)];
        console.log(`📊 ${phoneNumbers.length} unique numbers`);

        if (phoneNumbers.length === 0) {
            return res.status(400).json({ error: 'No valid phone numbers found' });
        }

        const startTime = Date.now();
        let inserted = 0;

        // Batch insert - 1000 at a time
        const batchSize = 1000;
        for (let i = 0; i < phoneNumbers.length; i += batchSize) {
            const batch = phoneNumbers.slice(i, i + batchSize);
            const valuesList = batch.map((phone, idx) => `($1, $${idx + 2}, 'available', 0, NOW())`).join(',');

            const result = await pool.query(
                `INSERT INTO leads (campaign_id, phone_number, status, times_assigned, created_at)
                 VALUES ${valuesList}
                 ON CONFLICT (campaign_id, phone_number) DO NOTHING
                 RETURNING id`,
                [id, ...batch]
            );

            inserted += result.rowCount;
            console.log(`✅ Batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(phoneNumbers.length / batchSize)}`);
        }

        const duration = Date.now() - startTime;
        const skipped = phoneNumbers.length - inserted;

        console.log(`✅ Done: ${inserted} inserted, ${skipped} skipped in ${(duration / 1000).toFixed(2)}s`);

        res.json({
            message: 'Leads uploaded',
            inserted,
            skipped,
            total: phoneNumbers.length,
            duration: `${(duration / 1000).toFixed(2)}s`
        });
    } catch (error) {
        console.error('❌ Upload error:', error);
        res.status(500).json({ error: error.message });
    }
});

router.get('/admin/global-task/submissions/users', authenticateAdmin, checkPermission('task_global_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { status } = req.query;

        // Build the query to group submissions by user
        let query = `
            SELECT 
                u.id as user_id,
                u.whatsapp_number,
                COUNT(ls.id) as total_submissions,
                COUNT(ls.id) FILTER (WHERE ls.status = 'pending') as pending_count,
                COUNT(ls.id) FILTER (WHERE ls.status = 'approved') as approved_count,
                COUNT(ls.id) FILTER (WHERE ls.status = 'rejected') as rejected_count,
                MAX(ls.created_at) as last_submission
            FROM users u
            INNER JOIN lead_submissions ls ON u.id = ls.user_id
        `;

        const params = [];

        // Filter by status if provided
        if (status && status !== 'all') {
            query += ` WHERE ls.status = $1`;
            params.push(status);
        }

        query += ` 
            GROUP BY u.id, u.whatsapp_number
            ORDER BY last_submission DESC
        `;

        const result = await pool.query(query, params);

        res.json({ users: result.rows });
    } catch (error) {
        console.error('Error fetching users with submissions:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// 2. Get all submissions for a specific user
router.get('/admin/global-task/submissions/user/:userId', authenticateAdmin, checkPermission('task_global_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const { status } = req.query;

        let query = `
            SELECT 
                ls.id,
                ls.assignment_id,
                ls.user_id,
                ls.lead_id,
                ls.campaign_id,
                ls.screenshot_url,
                ls.additional_notes,
                ls.status,
                ls.created_at,
                ls.reviewed_at,
                ls.admin_notes,
                l.phone_number as lead_phone,
                c.title as campaign_title,
                ula.points_awarded
            FROM lead_submissions ls
            JOIN leads l ON ls.lead_id = l.id
            JOIN campaigns c ON ls.campaign_id = c.id
            JOIN user_lead_assignments ula ON ls.assignment_id = ula.id
            WHERE ls.user_id = $1
        `;

        const params = [userId];

        // Filter by status if provided and not 'all'
        if (status && status !== 'all') {
            query += ` AND ls.status = $2`;
            params.push(status);
        }

        query += ` ORDER BY ls.created_at DESC`;

        const result = await pool.query(query, params);

        res.json({ submissions: result.rows });
    } catch (error) {
        console.error('Error fetching user submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});


router.get('/admin/lead-submissions', authenticateAdmin, checkPermission('task_global_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { status } = req.query;

        let query = `
            SELECT 
                ls.id,
                ls.assignment_id,
                ls.user_id,
                ls.lead_id,
                ls.campaign_id,
                ls.screenshot_url,
                ls.additional_notes,
                ls.status,
                ls.created_at,
                ls.reviewed_at,
                ls.admin_notes,
                u.whatsapp_number,
                l.phone_number as lead_phone,
                c.title as campaign_title,
                ula.status as assignment_status,
                ula.points_awarded
            FROM lead_submissions ls
            JOIN users u ON ls.user_id = u.id
            JOIN leads l ON ls.lead_id = l.id
            JOIN campaigns c ON ls.campaign_id = c.id
            JOIN user_lead_assignments ula ON ls.assignment_id = ula.id
        `;

        const params = [];

        if (status) {
            // ✅ FIX: Filter by submission status, not assignment status
            query += ` WHERE ls.status = $1`;
            params.push(status);
        }

        query += ` ORDER BY ls.created_at DESC LIMIT 100`;

        const result = await pool.query(query, params);

        res.json({ submissions: result.rows });
    } catch (error) {
        console.error('Error fetching submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});

// 2. NEW: Master Clear - Reset all completed leads
router.post('/admin/campaigns/:campaignId/master-clear', authenticateAdmin, checkPermission('task_global_settings'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { campaignId } = req.params;
        const { confirmCode } = req.body;

        // Security: Require confirmation code
        if (confirmCode !== 'RESET_ALL_LEADS') {
            return res.status(400).json({ error: 'Invalid confirmation code' });
        }

        // Get stats before clearing
        const beforeStats = await pool.query(
            `SELECT 
                COUNT(*) FILTER (WHERE status = 'completed') as completed_count,
                COUNT(*) FILTER (WHERE times_assigned >= 3) as maxed_out_count
             FROM leads 
             WHERE campaign_id = $1`,
            [campaignId]
        );

        // Reset all completed leads back to available
        await pool.query(
            `UPDATE leads 
             SET 
                status = 'available',
                times_assigned = 0,
                times_rejected = 0,
                updated_at = NOW()
             WHERE campaign_id = $1 AND status = 'completed'`,
            [campaignId]
        );

        // Archive old assignments (don't delete, keep for history)
        await pool.query(
            `UPDATE user_lead_assignments 
             SET 
                archived = true,
                archived_at = NOW()
             WHERE campaign_id = $1 AND status = 'approved'`,
            [campaignId]
        );

        // Log admin activity
        await logAdminActivity(
            pool,
            req.admin.adminId,
            'master_clear_leads',
            `Reset ${beforeStats.rows[0].completed_count} completed leads for campaign ${campaignId}`
        );

        res.json({
            message: 'Master clear completed successfully',
            stats: {
                leadsReset: parseInt(beforeStats.rows[0].completed_count),
                maxedOutLeads: parseInt(beforeStats.rows[0].maxed_out_count),
                assignmentsArchived: true
            }
        });
    } catch (error) {
        console.error('Error in master clear:', error);
        res.status(500).json({ error: 'Failed to clear leads' });
    }
});

// 3. NEW: HARD RESET - Nuclear option, deletes EVERYTHING
router.post('/admin/campaigns/:campaignId/hard-reset', authenticateAdmin, checkPermission('task_global_settings'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { campaignId } = req.params;
        const { confirmCode } = req.body;

        // Security: Require confirmation code
        if (confirmCode !== 'DELETE_EVERYTHING') {
            return res.status(400).json({ error: 'Invalid confirmation code' });
        }

        // Get stats before deletion
        const beforeStats = await pool.query(
            `SELECT 
                COUNT(*) as total_leads,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'available') as available
             FROM leads 
             WHERE campaign_id = $1`,
            [campaignId]
        );

        const assignmentCount = await pool.query(
            'SELECT COUNT(*) as count FROM user_lead_assignments WHERE campaign_id = $1',
            [campaignId]
        );

        const submissionCount = await pool.query(
            'SELECT COUNT(*) as count FROM lead_submissions WHERE campaign_id = $1',
            [campaignId]
        );

        // 1. Delete all lead submissions
        await pool.query(
            'DELETE FROM lead_submissions WHERE campaign_id = $1',
            [campaignId]
        );

        // 2. Delete all user assignments
        await pool.query(
            'DELETE FROM user_lead_assignments WHERE campaign_id = $1',
            [campaignId]
        );

        // 3. Delete all leads
        await pool.query(
            'DELETE FROM leads WHERE campaign_id = $1',
            [campaignId]
        );

        // 4. Keep campaign itself (id=1) but reset counters if they exist
        await pool.query(
            `UPDATE campaigns 
             SET updated_at = NOW()
             WHERE id = $1`,
            [campaignId]
        );

        // Log admin activity
        await logAdminActivity(
            pool,
            req.admin.adminId,
            'hard_reset_campaign',
            `HARD RESET: Deleted ${beforeStats.rows[0].total_leads} leads, ${assignmentCount.rows[0].count} assignments, ${submissionCount.rows[0].count} submissions for campaign ${campaignId}`
        );

        res.json({
            message: 'Hard reset completed successfully - All data deleted',
            stats: {
                leadsDeleted: parseInt(beforeStats.rows[0].total_leads),
                assignmentsDeleted: parseInt(assignmentCount.rows[0].count),
                submissionsDeleted: parseInt(submissionCount.rows[0].count),
                breakdown: {
                    completed: parseInt(beforeStats.rows[0].completed),
                    pending: parseInt(beforeStats.rows[0].pending),
                    available: parseInt(beforeStats.rows[0].available)
                }
            }
        });
    } catch (error) {
        console.error('Error in hard reset:', error);
        res.status(500).json({ error: 'Failed to perform hard reset' });
    }
});


// Get detailed lead statistics
router.get('/admin/campaigns/:campaignId/leads-stats-detailed', authenticateAdmin, checkPermission('task_global_upload_leads'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { campaignId } = req.params;

        const result = await pool.query(
            `SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'available') as available,
                COUNT(*) FILTER (WHERE status = 'assigned') as assigned,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'blocked') as blocked,
                COUNT(*) FILTER (WHERE times_assigned = 0) as fresh,
                COUNT(*) FILTER (WHERE times_assigned = 1) as assigned_once,
                COUNT(*) FILTER (WHERE times_assigned = 2) as assigned_twice,
                COUNT(*) FILTER (WHERE times_assigned >= 3) as maxed_out
             FROM leads 
             WHERE campaign_id = $1`,
            [campaignId]
        );

        res.json({ leads: result.rows[0] });
    } catch (error) {
        console.error('Error fetching detailed stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});




// Review lead submission (approve/reject)
router.put('/admin/lead-submissions/:id/review', authenticateAdmin, checkPermission('task_global_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const { action, adminNotes } = req.body; // action: 'approve' or 'reject'

        // Get submission details
        const submissionRes = await pool.query(
            'SELECT * FROM lead_submissions WHERE id = $1',
            [id]
        );

        if (submissionRes.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        const submission = submissionRes.rows[0];

        // Get assignment details
        const assignmentRes = await pool.query(
            'SELECT * FROM user_lead_assignments WHERE id = $1',
            [submission.assignment_id]
        );
        const assignment = assignmentRes.rows[0];

        // Get settings for lead recycling
        const settingsRes = await pool.query(
            "SELECT setting_key, setting_value FROM campaign_settings WHERE setting_key IN ('points_per_lead', 'max_times_lead_assigned')"
        );
        const settings = {};
        settingsRes.rows.forEach(r => settings[r.setting_key] = r.setting_value);
        const maxTimesAssigned = parseInt(settings.max_times_lead_assigned) || 3;

        if (action === 'approve') {
            // Update submission
            await pool.query(
                `UPDATE lead_submissions 
                 SET status = 'approved', admin_notes = $1, reviewed_by = $2, reviewed_at = NOW()
                 WHERE id = $3`,
                [adminNotes, req.admin.adminId, id]
            );

            // Update assignment
            await pool.query(
                "UPDATE user_lead_assignments SET status = 'approved', completed_at = NOW() WHERE id = $1",
                [submission.assignment_id]
            );

            // ✅ UPDATE STREAK FOR GLOBAL TASK (runs on every approval)
            try {
                const today = new Date().toISOString().split('T')[0];
                let streak = await pool.query('SELECT * FROM user_streaks WHERE user_id = $1', [submission.user_id]);

                if (streak.rows.length === 0) {
                    await pool.query(
                        'INSERT INTO user_streaks (user_id, current_streak, longest_streak, last_share_date) VALUES ($1, 1, 1, $2)',
                        [submission.user_id, today]
                    );

                    const day1Settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['streak_day1_bonus']);
                    const day1Bonus = parseInt(day1Settings.rows[0]?.setting_value) || 0;

                    if (day1Bonus > 0) {
                        await pool.query('UPDATE users SET points = points + $1 WHERE id = $2', [day1Bonus, submission.user_id]);
                        await pool.query(
                            'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                            [submission.user_id, `🔥 Day 1 streak! You earned ${day1Bonus} bonus points!`, 'streak_bonus']
                        );
                    }

                    console.log(`🔥 Global Task: Created new streak for user ${submission.user_id}`);
                } else {
                    const lastShareDate = streak.rows[0].last_share_date
                        ? new Date(streak.rows[0].last_share_date).toISOString().split('T')[0]
                        : null;
                    const currentStreak = streak.rows[0].current_streak;

                    if (lastShareDate !== today) {
                        const yesterday = new Date();
                        yesterday.setDate(yesterday.getDate() - 1);
                        const yesterdayStr = yesterday.toISOString().split('T')[0];

                        let newStreak = lastShareDate === yesterdayStr ? currentStreak + 1 : 1;

                        const cycleDay = ((newStreak - 1) % 7) + 1;
                        const settingKey = `streak_day${cycleDay}_bonus`;

                        console.log(`🔥 Global Task: Streak ${newStreak} → Cycle Day ${cycleDay}`);

                        const bonusSettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [settingKey]);
                        const streakBonus = parseInt(bonusSettings.rows[0]?.setting_value) || 0;

                        console.log(`💰 Cycle Day ${cycleDay} bonus: ${streakBonus} points`);

                        await pool.query(
                            `UPDATE user_streaks 
                             SET current_streak = $1, 
                                 longest_streak = GREATEST(longest_streak, $1),
                                 last_share_date = $2, 
                                 total_streak_bonuses = total_streak_bonuses + $3,
                                 updated_at = NOW()
                             WHERE user_id = $4`,
                            [newStreak, today, streakBonus, submission.user_id]
                        );

                        if (streakBonus > 0) {
                            await pool.query('UPDATE users SET points = points + $1, streak_earnings = streak_earnings + $1 WHERE id = $2', [streakBonus, submission.user_id]);

                            // Log point transaction
                            await pool.query(
                                'INSERT INTO point_transactions (user_id, amount, transaction_type, description, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)',
                                [submission.user_id, streakBonus, 'streak_bonus', `Day ${newStreak} streak bonus`]
                            );

                            // Log activity
                            const nextDayKey = `streak_day${((newStreak) % 7) + 1}_bonus`;
                            const nextDaySettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [nextDayKey]);
                            const nextDayBonus = parseInt(nextDaySettings.rows[0]?.setting_value) || 0;
                            await logStreakActivity(pool, submission.user_id, newStreak, streakBonus, nextDayBonus);

                            await pool.query(
                                'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                                [submission.user_id, `🔥 Day ${newStreak} streak! You earned ${streakBonus} bonus points!`, 'streak_bonus']
                            );
                        }

                        console.log(`🔥 Global Task: User ${submission.user_id} streak day ${newStreak}, earned ${streakBonus} bonus`);
                    }
                }
            } catch (streakError) {
                console.error('Global task streak error:', streakError);
            }


            // ✅ AWARD BONUS SPIN (after admin approval)
            try {
                await awardBonusSpin(pool, submission.user_id);
            } catch (bonusError) {
                console.error('Global task bonus spin error:', bonusError);
            }


            // If points not awarded yet, award now
            if (assignment.points_awarded === 0) {
                const pointsRes = await pool.query(
                    "SELECT setting_value FROM campaign_settings WHERE setting_key = 'points_per_lead'"
                );
                const points = parseInt(pointsRes.rows[0]?.setting_value) || 1;

                await pool.query(
                    'UPDATE users SET points = points + $1, task_earnings = task_earnings + $1 WHERE id = $2',
                    [points, submission.user_id]
                );

                await logAdminApprovalActivity(pool, submission.user_id, points, submission.id, req.admin?.adminId || null);

                await pool.query(
                    'UPDATE user_lead_assignments SET points_awarded = $1 WHERE id = $2',
                    [points, submission.assignment_id]
                );

                await logPointTransaction(pool, submission.user_id, points, 'task', `Task approved - Lead submission #${submission.id}`, submission.id);
            }

            // ✅ MILESTONE CHECK - MOVED OUTSIDE (runs every time admin approves)
            try {
                console.log('===== MILESTONE CHECK STARTED (GLOBAL TASK) =====');
                console.log('User ID:', submission.user_id);

                // Get share count
                const personalShares = await pool.query(`
                SELECT COUNT(DISTINCT recipient_number) as total
                FROM user_recipients sr
                JOIN submissions s ON sr.submission_id = s.id
                WHERE s.user_id = $1 AND s.status = 'active'`, [submission.user_id]);

                const globalTasks = await pool.query(`
                SELECT COUNT(*) as total
                FROM user_lead_assignments
                WHERE user_id = $1 AND status = 'approved'`, [submission.user_id]);

                const shareCount = parseInt(personalShares.rows[0].total) + parseInt(globalTasks.rows[0].total);

                console.log('Personal shares:', personalShares.rows[0].total);
                console.log('Global tasks:', globalTasks.rows[0].total);
                console.log('Total shareCount:', shareCount);

                // Check milestones
                const milestones = await pool.query(`
                 SELECT * FROM settings WHERE setting_key LIKE 'milestone_%' ORDER BY setting_key`);

                console.log('Milestones found:', milestones.rows.length);

                for (const m of milestones.rows) {
                    const shares = parseInt(m.setting_key.replace('milestone_', ''));
                    const bonus = parseInt(m.setting_value);

                    console.log(`Checking milestone ${shares}: shareCount=${shareCount}, bonus=${bonus}`);

                    if (shareCount >= shares) {
                        console.log('✅ Share count met!');

                        const exists = await pool.query(
                            'SELECT * FROM user_milestones WHERE user_id = $1 AND milestone_type = $2 AND milestone_value = $3',
                            [submission.user_id, 'shares', shares]
                        );

                        console.log('Already awarded?', exists.rows.length > 0);

                        if (exists.rows.length === 0) {
                            console.log('🎯 AWARDING MILESTONE NOW!');

                            await pool.query(
                                'INSERT INTO user_milestones (user_id, milestone_type, milestone_value, bonus_awarded) VALUES ($1, $2, $3, $4)',
                                [submission.user_id, 'shares', shares, bonus]
                            );

                            await pool.query(
                                'UPDATE users SET points = points + $1, milestone_earnings = milestone_earnings + $1 WHERE id = $2',
                                [bonus, submission.user_id]
                            );

                            await logPointTransaction(pool, submission.user_id, bonus, 'milestone', `Milestone reward: ${shares} shares completed`, shares);

                            const allMilestones = [10, 50, 100, 500, 1000, 5000, 10000];
                            const nextMilestone = allMilestones.find(m => m > shares) || null;
                            await logMilestoneActivity(pool, submission.user_id, shares, bonus, shareCount, nextMilestone);

                            console.log(`🎉 Milestone awarded: ${shares} shares - ${bonus} points to user ${submission.user_id}`);
                        }
                    }
                }

                console.log('===== MILESTONE CHECK COMPLETED =====');
            } catch (error) {
                console.error('Error auto-checking milestones:', error);
            }

            // ✅ NEW: Lead Recycling Logic
            const leadCheck = await pool.query(
                'SELECT times_assigned FROM leads WHERE id = $1',
                [submission.lead_id]
            );

            const currentTimesAssigned = leadCheck.rows[0].times_assigned || 0;

            if (currentTimesAssigned < maxTimesAssigned) {
                // Lead can be assigned again - return to available pool
                await pool.query(
                    "UPDATE leads SET status = 'available' WHERE id = $1",
                    [submission.lead_id]
                );
                console.log(`✅ Lead ${submission.lead_id} returned to pool after admin approval (${currentTimesAssigned}/${maxTimesAssigned} completions)`);
            } else {
                // Max reached - mark as completed permanently
                await pool.query(
                    "UPDATE leads SET status = 'completed' WHERE id = $1",
                    [submission.lead_id]
                );
                console.log(`🎯 Lead ${submission.lead_id} completed permanently (${currentTimesAssigned}/${maxTimesAssigned} times)`);
            }

        } else if (action === 'reject') {
            // Update submission
            await pool.query(
                `UPDATE lead_submissions 
                 SET status = 'rejected', admin_notes = $1, reviewed_by = $2, reviewed_at = NOW()
                 WHERE id = $3`,
                [adminNotes, req.admin.adminId, id]
            );

            // Update assignment
            await pool.query(
                "UPDATE user_lead_assignments SET status = 'rejected', rejection_reason = $1 WHERE id = $2",
                [adminNotes, submission.assignment_id]
            );

            // Deduct points if already awarded
            if (assignment.points_awarded > 0) {
                await pool.query(
                    'UPDATE users SET points = points - $1 WHERE id = $2',
                    [assignment.points_awarded, submission.user_id]
                );
            }

            // Return lead to pool (rejection doesn't count toward max_times_assigned)
            await pool.query(
                "UPDATE leads SET status = 'available', times_rejected = COALESCE(times_rejected, 0) + 1 WHERE id = $1",
                [submission.lead_id]
            );

            console.log(`❌ Lead ${submission.lead_id} returned to pool after rejection`);
        }

        await logAdminActivity(pool, req.admin.adminId, 'review_submission', `${action} submission ${id}`);

        res.json({ message: `Submission ${action}d successfully` });
    } catch (error) {
        console.error('Error reviewing submission:', error);
        res.status(500).json({ error: 'Failed to review submission' });
    }
});

// Update campaign settings
router.put('/admin/campaign-settings/:key', authenticateAdmin, checkPermission('task_global_settings'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { key } = req.params;
        const { value } = req.body;

        // Update campaign_settings table
        await pool.query(
            'UPDATE campaign_settings SET setting_value = $1, updated_at = NOW() WHERE setting_key = $2',
            [value, key]
        );

        // ✅ ADD THIS: If points_per_lead is updated, sync to campaigns table
        if (key === 'points_per_lead') {
            await pool.query(
                'UPDATE campaigns SET points_per_lead = $1, updated_at = NOW() WHERE id = 1',
                [parseInt(value)]
            );
        }

        await logAdminActivity(pool, req.admin.adminId, 'update_campaign_setting', `Updated ${key} to ${value}`);

        res.json({ message: 'Setting updated successfully' });
    } catch (error) {
        console.error('Error updating setting:', error);
        res.status(500).json({ error: 'Failed to update setting' });
    }
});

// Get all campaign settings
router.get('/admin/campaign-settings', authenticateAdmin, checkPermission('task_global_settings'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const result = await pool.query(
            'SELECT setting_key, setting_value FROM campaign_settings ORDER BY setting_key'
        );

        const settings = {};
        result.rows.forEach(row => {
            settings[row.setting_key] = row.setting_value;
        });

        res.json({ settings });
    } catch (error) {
        console.error('Error fetching campaign settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
})


// Get active campaign info for users (public endpoint)
router.get('/api/campaign-info', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Check if campaigns table exists
        const tableCheck = await pool.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'campaigns'
            );
        `);

        if (!tableCheck.rows[0].exists) {
            console.error('Campaigns table does not exist');
            return res.json({
                campaign: null,
                settings: { points_per_lead: 1 }
            });
        }

        // Get active campaign
        const campaignRes = await pool.query(
            `SELECT id, title, description, points_per_lead, status, created_at 
             FROM campaigns 
             WHERE status = 'active' 
             ORDER BY created_at DESC 
             LIMIT 1`
        );

        if (campaignRes.rows.length === 0) {
            console.log('No active campaign found');
            return res.json({
                campaign: null,
                settings: { points_per_lead: 1 }
            });
        }

        const campaign = campaignRes.rows[0];

        console.log('Campaign info fetched:', campaign.id);

        res.json({
            campaign: campaign,
            settings: {
                points_per_lead: campaign.points_per_lead || 1
            }
        });
    } catch (error) {
        console.error('Error fetching campaign info:', error.message);
        console.error('Error stack:', error.stack);
        // Return default instead of 500
        res.json({
            campaign: null,
            settings: { points_per_lead: 1 }
        });
    }
});


// Get campaign statistics
router.get('/admin/campaigns/:id/stats', authenticateAdmin, checkPermission('task_global_configuration'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const stats = await pool.query(
            `SELECT 
                COUNT(DISTINCT ula.user_id) as total_users,
                COUNT(ula.id) as total_assignments,
                COUNT(CASE WHEN ula.status = 'approved' THEN 1 END) as completed,
                COUNT(CASE WHEN ula.status = 'rejected' THEN 1 END) as rejected,
                COUNT(CASE WHEN ula.status IN ('pending', 'sent') THEN 1 END) as pending,
                SUM(ula.points_awarded) as total_points_awarded
             FROM user_lead_assignments ula
             WHERE ula.campaign_id = $1`,
            [id]
        );

        res.json({ stats: stats.rows[0] });
    } catch (error) {
        console.error('Error fetching campaign stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});



// ==================== ACTIVITY LOG ROUTES ====================

// Get user activity history
router.get('/activity-log/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const { limit = 10, offset = 0 } = req.query;

        const activities = await pool.query(
            `SELECT * FROM activity_log 
             WHERE user_id = $1 
             ORDER BY created_at DESC 
             LIMIT $2 OFFSET $3`,
            [userId, parseInt(limit), parseInt(offset)]
        );

        const total = await pool.query(
            'SELECT COUNT(*) as count FROM activity_log WHERE user_id = $1',
            [userId]
        );

        res.json({
            activities: activities.rows,
            total: parseInt(total.rows[0].count),
            hasMore: parseInt(offset) + activities.rows.length < parseInt(total.rows[0].count)
        });
    } catch (error) {
        console.error('Error fetching activity log:', error);
        res.status(500).json({ error: 'Failed to fetch activity log' });
    }
});

// Clean up old activities (older than specified days)
router.post('/cleanup-activities', authenticateAdmin, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { days = 30 } = req.body;

        const result = await pool.query(
            `DELETE FROM activity_log 
             WHERE created_at < NOW() - INTERVAL '${parseInt(days)} days'
             RETURNING id`
        );

        res.json({
            message: 'Old activities cleaned up',
            deleted: result.rowCount
        });
    } catch (error) {
        console.error('Error cleaning up activities:', error);
        res.status(500).json({ error: 'Failed to cleanup activities' });
    }
});


// ==================== ACTIVITY LOG ADMIN ENDPOINTS ====================

// Get activity statistics with recent activities
router.get('/admin/activity-stats', authenticateAdmin, checkPermission('view_analytics'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { limit = 500 } = req.query;

        // Get activities with user info
        const activitiesQuery = `
            SELECT 
                al.id,
                al.user_id,
                al.activity_type,
                al.title,
                al.description,
                al.points as points_awarded,
                al.metadata,
                al.created_at,
                u.whatsapp_number
            FROM activity_log al
            INNER JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT $1
        `;
        const activities = await pool.query(activitiesQuery, [limit]);

        // Get today stats
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Total count
        const totalResult = await pool.query('SELECT COUNT(*) as total FROM activity_log');
        const total = parseInt(totalResult.rows[0].total);

        // Oldest and newest
        const rangeResult = await pool.query(
            'SELECT MIN(created_at) as oldest, MAX(created_at) as newest FROM activity_log'
        );

        // Count by type
        const byTypeResult = await pool.query(
            `SELECT activity_type, COUNT(*) as count 
             FROM activity_log 
             GROUP BY activity_type 
             ORDER BY count DESC`
        );

        // Get retention setting
        const retentionResult = await pool.query(
            "SELECT setting_value FROM settings WHERE setting_key = 'activity_log_retention_days'"
        );
        const retentionDays = retentionResult.rows.length > 0
            ? parseInt(retentionResult.rows[0].setting_value)
            : 30;

        // Count activities older than retention days
        const oldActivitiesResult = await pool.query(
            `SELECT COUNT(*) as count 
             FROM activity_log 
             WHERE created_at < NOW() - INTERVAL '${retentionDays} days'`
        );

        // Today's stats
        const todayStats = await pool.query(
            `SELECT 
                COUNT(*) as today_activities,
                COUNT(DISTINCT user_id) as active_users_today,
                COALESCE(SUM(points), 0) as points_distributed_today
             FROM activity_log
             WHERE created_at >= $1`,
            [today]
        );

        res.json({
            activities: activities.rows,
            stats: {
                total_activities: total,
                today_activities: parseInt(todayStats.rows[0].today_activities),
                active_users_today: parseInt(todayStats.rows[0].active_users_today),
                points_distributed_today: parseInt(todayStats.rows[0].points_distributed_today),
                old_activities: parseInt(oldActivitiesResult.rows[0].count),
                oldest: rangeResult.rows[0].oldest,
                newest: rangeResult.rows[0].newest,
                byType: byTypeResult.rows
            }
        });
    } catch (error) {
        console.error('Error fetching activity stats:', error);
        res.status(500).json({ error: 'Failed to fetch activity statistics' });
    }
});

// Manual cleanup endpoint
router.post('/admin/cleanup-activities', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { daysOld, deleteAll } = req.body;

        let result;
        let deletedCount;

        if (deleteAll) {
            // Delete ALL activities
            result = await pool.query('DELETE FROM activity_log');
            deletedCount = result.rowCount;
        } else {
            // Delete activities older than specified days
            const days = parseInt(daysOld) || 30;
            result = await pool.query(
                `DELETE FROM activity_log 
                 WHERE created_at < NOW() - INTERVAL '${days} days'`
            );
            deletedCount = result.rowCount;
        }

        res.json({
            success: true,
            deletedCount: deletedCount,
            message: `Successfully deleted ${deletedCount} activities`
        });
    } catch (error) {
        console.error('Error cleaning up activities:', error);
        res.status(500).json({ error: 'Failed to cleanup activities' });
    }
});

// Get activity cleanup settings
router.get('/admin/activity-settings', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Get retention days setting
        const setting = await pool.query(
            "SELECT setting_value FROM settings WHERE setting_key = 'activity_log_retention_days'"
        );

        const retentionDays = setting.rows.length > 0
            ? parseInt(setting.rows[0].setting_value)
            : 30;

        res.json({ retentionDays });
    } catch (error) {
        console.error('Error fetching activity settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Update activity cleanup settings
router.post('/admin/activity-settings', authenticateAdmin, checkPermission('manage_activities'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { retentionDays } = req.body;

        if (!retentionDays || retentionDays < 1) {
            return res.status(400).json({ error: 'Invalid retention days' });
        }

        // Upsert the setting
        await pool.query(
            `INSERT INTO settings (setting_key, setting_value, description) 
             VALUES ('activity_log_retention_days', $1, 'Number of days to keep activity logs before auto-deletion')
             ON CONFLICT (setting_key) 
             DO UPDATE SET setting_value = $1, updated_at = NOW()`,
            [retentionDays.toString()]
        );

        res.json({
            success: true,
            message: `Activity log retention set to ${retentionDays} days`
        });
    } catch (error) {
        console.error('Error updating activity settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});


// Get domain settings (Admin only)
router.get('/admin/domain-settings', authenticateAdmin, checkPermission('security_domain'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        const settings = await pool.query(
            `SELECT setting_key, setting_value, description 
             FROM settings 
             WHERE setting_key IN ('primary_domain', 'api_url')`
        );

        const config = {};
        settings.rows.forEach(row => {
            config[row.setting_key] = row.setting_value;
        });

        res.json(config);
    } catch (error) {
        console.error('Error fetching domain settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Update domain settings (Super Admin only)
router.post('/admin/domain-settings', authenticateAdmin, checkPermission('security_domain'), async (req, res) => {
    try {
        // Check if super admin
        if (req.admin.role !== 'super_admin') {
            return res.status(403).json({ error: 'Only super admin can change domain settings' });
        }

        const pool = req.app.get('db');
        const { primary_domain, api_url } = req.body;

        if (primary_domain) {
            await pool.query(
                `INSERT INTO settings (setting_key, setting_value, description) 
                 VALUES ('primary_domain', $1, 'Primary domain name')
                 ON CONFLICT (setting_key) 
                 DO UPDATE SET setting_value = $1, updated_at = NOW()`,
                [primary_domain]
            );
        }

        if (api_url) {
            await pool.query(
                `INSERT INTO settings (setting_key, setting_value, description) 
                 VALUES ('api_url', $1, 'API base URL')
                 ON CONFLICT (setting_key) 
                 DO UPDATE SET setting_value = $1, updated_at = NOW()`,
                [api_url]
            );
        }

        res.json({
            success: true,
            message: 'Domain settings updated successfully'
        });
    } catch (error) {
        console.error('Error updating domain settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// Get user's referrals with detailed info
router.get('/user-referrals/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const { page = 1, limit = 20, status = 'all', sortBy = 'newest' } = req.query;
        const offset = (page - 1) * limit;

        // Build query based on filters
        let whereClause = 'WHERE r.referrer_id = $1';
        let orderClause = 'ORDER BY r.created_at DESC';

        if (status === 'active') {
            whereClause += " AND r.status = 'active'";
        } else if (status === 'inactive') {
            whereClause += " AND r.status != 'active'";
        }

        if (sortBy === 'oldest') {
            orderClause = 'ORDER BY r.created_at ASC';
        } else if (sortBy === 'points') {
            orderClause = 'ORDER BY u.points DESC';
        }

        // Get referrals with their stats
        const referralsQuery = `
            SELECT 
                r.id as referral_id,
                r.referred_id,
                r.status,
                r.total_commission_earned as earnings_from_them,
                r.created_at as joined_at,
                u.whatsapp_number,
                u.points,
                COALESCE(u.is_active, true) as is_active,
                (SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id) as their_referrals
            FROM referrals r
            JOIN users u ON r.referred_id = u.id
            ${whereClause}
            ${orderClause}
            LIMIT $2 OFFSET $3
        `;

        const referrals = await pool.query(referralsQuery, [userId, limit, offset]);

        // Get total count
        const countQuery = `
            SELECT COUNT(*) 
            FROM referrals r
            ${whereClause}
        `;
        const totalCount = await pool.query(countQuery, [userId]);

        // Get user's total referral earnings
        const earningsQuery = `
            SELECT COALESCE(SUM(total_commission_earned), 0) as total_earnings
            FROM referrals
            WHERE referrer_id = $1
        `;
        const earnings = await pool.query(earningsQuery, [userId]);

        res.json({
            referrals: referrals.rows,
            total: parseInt(totalCount.rows[0].count),
            page: parseInt(page),
            limit: parseInt(limit),
            totalEarnings: parseInt(earnings.rows[0].total_earnings)
        });

    } catch (error) {
        console.error('Error fetching referrals:', error);
        res.status(500).json({ error: 'Failed to fetch referrals' });
    }
});

// Get referral stats summary
router.get('/user-referrals-stats/:userId', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        // Get stats from referrals table
        const stats = await pool.query(`
            SELECT 
                COUNT(*) as total_referrals,
                COUNT(*) FILTER (WHERE r.status = 'active') as active_referrals,
                COUNT(*) FILTER (WHERE r.status != 'active') as inactive_referrals,
                COALESCE(SUM(u.points), 0) as total_points_by_referrals,
                COALESCE(SUM(r.total_commission_earned), 0) as total_commission
            FROM referrals r
            LEFT JOIN users u ON r.referred_id = u.id
            WHERE r.referrer_id = $1
        `, [userId]);

        res.json({
            total_referrals: parseInt(stats.rows[0].total_referrals),
            active_referrals: parseInt(stats.rows[0].active_referrals),
            inactive_referrals: parseInt(stats.rows[0].inactive_referrals),
            total_points_by_referrals: parseInt(stats.rows[0].total_points_by_referrals),
            total_commission: parseInt(stats.rows[0].total_commission)
        });

    } catch (error) {
        console.error('Error fetching referral stats:', error);
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});



// ==================== ADMIN REFERRAL ANALYTICS ====================

// Search users by ID or phone
router.get('/admin/search-users', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { query, type } = req.query; // type: 'id' or 'phone'

        let searchQuery;
        if (type === 'id') {
            searchQuery = await pool.query(`
                SELECT 
                    u.id,
                    u.whatsapp_number,
                    u.points,
                    u.referral_code,
                    u.referred_by_code,
                    u.registration_ip,
                    u.last_login_ip,
                    u.is_active,
                    u.created_at,
                    (SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id) as total_referrals
                FROM users u
                WHERE u.id = $1
            `, [query]);
        } else {
            searchQuery = await pool.query(`
                SELECT 
                    u.id,
                    u.whatsapp_number,
                    u.points,
                    u.referral_code,
                    u.referred_by_code,
                    u.registration_ip,
                    u.last_login_ip,
                    u.is_active,
                    u.created_at,
                    (SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id) as total_referrals
                FROM users u
                WHERE u.whatsapp_number LIKE $1
                LIMIT 10
            `, [`%${query}%`]);
        }

        res.json({ users: searchQuery.rows });
    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).json({ error: 'Failed to search users' });
    }
});

// Get recent registered users
router.get('/admin/recent-users', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { limit = 10 } = req.query;

        const users = await pool.query(`
            SELECT 
                u.id,
                u.whatsapp_number,
                u.points,
                u.referral_code,
                u.registration_ip,
                u.is_active,
                u.created_at,
                (SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id) as total_referrals
            FROM users u
            ORDER BY u.created_at DESC
            LIMIT $1
        `, [limit]);

        res.json({ users: users.rows });
    } catch (error) {
        console.error('Error fetching recent users:', error);
        res.status(500).json({ error: 'Failed to fetch recent users' });
    }
});

// Get user's referrals (subordinates)
router.get('/admin/user-referrals/:userId', authenticateAdmin, checkPermission('user_referral_data'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        const referrals = await pool.query(`
            SELECT 
                r.id as referral_id,
                r.referred_id,
                r.status,
                r.total_commission_earned,
                r.created_at as joined_at,
                u.whatsapp_number,
                u.points,
                u.is_active,
                u.registration_ip,
                u.last_login_ip,
                (SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id) as their_referrals
            FROM referrals r
            JOIN users u ON r.referred_id = u.id
            WHERE r.referrer_id = $1
            ORDER BY r.created_at DESC
        `, [userId]);

        res.json({ referrals: referrals.rows });
    } catch (error) {
        console.error('Error fetching user referrals:', error);
        res.status(500).json({ error: 'Failed to fetch referrals' });
    }
});

// IP Lookup - Find all users with specific IP
router.get('/admin/ip-lookup', authenticateAdmin, checkPermission('security_ip_lookup'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { ip } = req.query;

        const users = await pool.query(`
            SELECT DISTINCT
                u.id,
                u.whatsapp_number,
                u.registration_ip,
                u.last_login_ip,
                u.is_active,
                u.created_at,
                u.points
            FROM users u
            WHERE u.registration_ip = $1 OR u.last_login_ip = $1
            ORDER BY u.created_at DESC
        `, [ip]);

        res.json({
            ip,
            total_users: users.rows.length,
            users: users.rows
        });
    } catch (error) {
        console.error('Error in IP lookup:', error);
        res.status(500).json({ error: 'Failed to lookup IP' });
    }
});

// ==================== IP RISK & FLAG MANAGEMENT ====================

// Get IP risk settings
router.get('/admin/ip-risk-settings', authenticateAdmin, checkPermission('security_ip_risk'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const settings = await pool.query(`
            SELECT setting_key, setting_value 
            FROM settings 
            WHERE setting_key LIKE 'ip_%'
        `);

        const settingsObj = {};
        settings.rows.forEach(row => {
            settingsObj[row.setting_key] = row.setting_value;
        });

        res.json(settingsObj);
    } catch (error) {
        console.error('Error fetching IP settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Update IP risk settings
router.put('/admin/ip-risk-settings', authenticateAdmin, checkPermission('security_ip_risk'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { ip_risk_low_threshold, ip_risk_medium_threshold, ip_risk_high_threshold, ip_auto_action, ip_whitelist } = req.body;

        await pool.query(`UPDATE settings SET setting_value = $1 WHERE setting_key = 'ip_risk_low_threshold'`, [ip_risk_low_threshold]);
        await pool.query(`UPDATE settings SET setting_value = $1 WHERE setting_key = 'ip_risk_medium_threshold'`, [ip_risk_medium_threshold]);
        await pool.query(`UPDATE settings SET setting_value = $1 WHERE setting_key = 'ip_risk_high_threshold'`, [ip_risk_high_threshold]);
        await pool.query(`UPDATE settings SET setting_value = $1 WHERE setting_key = 'ip_auto_action'`, [ip_auto_action]);
        await pool.query(`UPDATE settings SET setting_value = $1 WHERE setting_key = 'ip_whitelist'`, [ip_whitelist]);

        res.json({ message: 'Settings updated successfully' });
    } catch (error) {
        console.error('Error updating IP settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// Flag user manually
router.post('/admin/flag-user', authenticateAdmin, checkPermission('manage_flagged_users'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId, flagReason, flagType = 'manual', ipAddress, totalAccountsOnIp } = req.body;
        const adminId = req.admin.adminId;

        // Flag the user
        await pool.query(`
            UPDATE users 
            SET is_flagged = true, flag_reason = $1, flagged_at = NOW(), flagged_by = $2 
            WHERE id = $3
        `, [flagReason, adminId, userId]);

        // Create flag record
        await pool.query(`
            INSERT INTO user_flags (user_id, flagged_by, flag_type, flag_reason, ip_address, total_accounts_on_ip)
            VALUES ($1, $2, $3, $4, $5, $6)
        `, [userId, adminId, flagType, flagReason, ipAddress, totalAccountsOnIp]);

        res.json({ message: 'User flagged successfully' });
    } catch (error) {
        console.error('Error flagging user:', error);
        res.status(500).json({ error: 'Failed to flag user' });
    }
});

// Get all flagged users
router.get('/admin/flagged-users', authenticateAdmin, checkPermission('manage_flagged_users'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { resolved = 'false' } = req.query;

        const flaggedUsers = await pool.query(`
            SELECT 
                u.id,
                u.whatsapp_number,
                u.points,
                u.is_active,
                u.is_flagged,
                u.flag_reason,
                u.flagged_at,
                u.registration_ip,
                u.last_login_ip,
                (SELECT COUNT(*) FROM user_flags WHERE user_id = u.id AND is_resolved = false) as active_flags,
                (SELECT COUNT(*) FROM referrals WHERE referrer_id = u.id) as total_referrals
            FROM users u
            WHERE u.is_flagged = true
            ORDER BY u.flagged_at DESC
        `);

        res.json({ users: flaggedUsers.rows });
    } catch (error) {
        console.error('Error fetching flagged users:', error);
        res.status(500).json({ error: 'Failed to fetch flagged users' });
    }
});

// Get user's flag history
router.get('/admin/user-flags/:userId', authenticateAdmin, checkPermission('manage_flagged_users'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        const flags = await pool.query(`
            SELECT 
                f.*,
                a1.username as flagged_by_username,
                a2.username as resolved_by_username
            FROM user_flags f
            LEFT JOIN admins a1 ON f.flagged_by = a1.id
            LEFT JOIN admins a2 ON f.resolved_by = a2.id
            WHERE f.user_id = $1
            ORDER BY f.created_at DESC
        `, [userId]);

        res.json({ flags: flags.rows });
    } catch (error) {
        console.error('Error fetching user flags:', error);
        res.status(500).json({ error: 'Failed to fetch flags' });
    }
});

// Resolve flag
router.post('/admin/resolve-flag', authenticateAdmin, checkPermission('manage_flagged_users'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId, action, notes } = req.body; // action: 'cleared', 'disabled', 'whitelisted'
        const adminId = req.admin.adminId;

        // Update user based on action
        if (action === 'disabled') {
            await pool.query(`UPDATE users SET is_active = false WHERE id = $1`, [userId]);
        } else if (action === 'cleared') {
            await pool.query(`
                UPDATE users 
                SET is_flagged = false, flag_reason = NULL 
                WHERE id = $1
            `, [userId]);
        }

        // Mark flags as resolved
        await pool.query(`
            UPDATE user_flags 
            SET is_resolved = true, resolved_by = $1, resolved_at = NOW(), resolution_action = $2, resolution_notes = $3
            WHERE user_id = $4 AND is_resolved = false
        `, [adminId, action, notes, userId]);

        res.json({ message: 'Flag resolved successfully' });
    } catch (error) {
        console.error('Error resolving flag:', error);
        res.status(500).json({ error: 'Failed to resolve flag' });
    }
});

// Auto-flag users based on IP risk (can be called periodically or on-demand)
router.post('/admin/auto-flag-ip-risk', authenticateAdmin, checkPermission('manage_flagged_users'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Get settings
        const settings = await pool.query(`SELECT setting_key, setting_value FROM settings WHERE setting_key LIKE 'ip_%'`);
        const settingsObj = {};
        settings.rows.forEach(row => { settingsObj[row.setting_key] = row.setting_value; });

        const highThreshold = parseInt(settingsObj.ip_risk_high_threshold) || 7;
        const autoAction = settingsObj.ip_auto_action || 'flag';
        const whitelist = settingsObj.ip_whitelist ? settingsObj.ip_whitelist.split(',').map(ip => ip.trim()).filter(ip => ip) : [];

        if (autoAction === 'none') {
            return res.json({ message: 'Auto-flagging is disabled', flagged: 0, riskyIPs: 0 });
        }

        // Build query dynamically based on whitelist
        let riskyIPsQuery = `
            SELECT 
                registration_ip as ip,
                COUNT(*) as user_count
            FROM users
            WHERE registration_ip IS NOT NULL
        `;

        const queryParams = [];

        // Add whitelist filter if not empty
        if (whitelist.length > 0) {
            const placeholders = whitelist.map((_, i) => `$${i + 1}`).join(',');
            riskyIPsQuery += ` AND registration_ip NOT IN (${placeholders})`;
            queryParams.push(...whitelist);
        }

        riskyIPsQuery += `
            GROUP BY registration_ip
            HAVING COUNT(*) >= $${queryParams.length + 1}
        `;

        queryParams.push(highThreshold);

        const riskyIPs = await pool.query(riskyIPsQuery, queryParams);

        let flaggedCount = 0;
        const adminId = req.admin.adminId;

        for (const row of riskyIPs.rows) {
            const usersOnIP = await pool.query(`SELECT id FROM users WHERE registration_ip = $1 AND is_flagged = false`, [row.ip]);

            for (const user of usersOnIP.rows) {
                const flagReason = `Auto-flagged: ${row.user_count} accounts from IP ${row.ip}`;

                await pool.query(`
                    UPDATE users 
                    SET is_flagged = true, flag_reason = $1, flagged_at = NOW(), flagged_by = $2 
                    WHERE id = $3
                `, [flagReason, adminId, user.id]);

                await pool.query(`
                    INSERT INTO user_flags (user_id, flagged_by, flag_type, flag_reason, ip_address, total_accounts_on_ip)
                    VALUES ($1, $2, 'ip_risk', $3, $4, $5)
                `, [user.id, adminId, flagReason, row.ip, row.user_count]);

                flaggedCount++;
            }
        }

        console.log(`✅ Auto-flag complete: ${riskyIPs.rows.length} risky IPs, ${flaggedCount} users flagged`);

        res.json({
            message: `Auto-flagging complete`,
            riskyIPs: riskyIPs.rows.length,
            flagged: flaggedCount
        });
    } catch (error) {
        console.error('Error auto-flagging:', error);
        res.status(500).json({ error: 'Failed to auto-flag users', details: error.message });
    }
});


// Disable/Enable user
router.put('/admin/user-status/:userId', authenticateAdmin, checkPermission('user_manage'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const { isActive } = req.body;

        await pool.query(`UPDATE users SET is_active = $1 WHERE id = $2`, [isActive, userId]);

        res.json({ message: `User ${isActive ? 'enabled' : 'disabled'} successfully` });
    } catch (error) {
        console.error('Error updating user status:', error);
        res.status(500).json({ error: 'Failed to update user status' });
    }
});



// Ban user (sets is_flagged to true in users table)
router.post('/admin/ban-user', authenticateAdmin, checkPermission('user_ban'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId, reason } = req.body;

        if (!userId || !reason) {
            return res.status(400).json({ error: 'User ID and reason are required' });
        }

        // Update user record
        await pool.query(
            `UPDATE users 
             SET is_flagged = true, 
                 flag_reason = $1, 
                 flagged_at = NOW(), 
                 flagged_by = $2,
                 is_active = false
             WHERE id = $3`,
            [reason, req.admin.adminId, userId]
        );

        // Create entry in user_flags table
        await pool.query(
            `INSERT INTO user_flags (user_id, flagged_by, flag_type, flag_reason, created_at)
             VALUES ($1, $2, $3, $4, NOW())`,
            [userId, req.admin.adminId, 'admin_ban', reason]
        );

        await logAdminActivity(pool, req.admin.adminId, 'ban_user', `Banned user ID ${userId}: ${reason}`);

        console.log(`✅ User ${userId} banned by admin ${req.admin.adminId}`);

        res.json({
            success: true,
            message: 'User banned successfully'
        });

    } catch (error) {
        console.error('Error banning user:', error);
        res.status(500).json({ error: 'Failed to ban user' });
    }
});

// Unban user (sets is_flagged to false in users table)
router.post('/admin/unban-user', authenticateAdmin, checkPermission('user_ban'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ error: 'User ID is required' });
        }

        // Update user record
        await pool.query(
            `UPDATE users 
             SET is_flagged = false, 
                 flag_reason = NULL, 
                 flagged_at = NULL, 
                 flagged_by = NULL,
                 is_active = true
             WHERE id = $1`,
            [userId]
        );

        // Mark all user_flags as resolved
        await pool.query(
            `UPDATE user_flags 
             SET is_resolved = true, 
                 resolved_by = $1, 
                 resolved_at = NOW(),
                 resolution_action = 'unbanned'
             WHERE user_id = $2 AND is_resolved = false`,
            [req.admin.adminId, userId]
        );

        await logAdminActivity(pool, req.admin.adminId, 'unban_user', `Unbanned user ID ${userId}`);

        console.log(`✅ User ${userId} unbanned by admin ${req.admin.adminId}`);

        res.json({
            success: true,
            message: 'User unbanned successfully'
        });

    } catch (error) {
        console.error('Error unbanning user:', error);
        res.status(500).json({ error: 'Failed to unban user' });
    }
});



// ==================== EARNINGS BREAKDOWN ====================

// Get user earnings breakdown
router.get('/admin/user-earnings/:userId', authenticateAdmin, checkPermission('user_points'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        // Get earnings from users table
        const earnings = await pool.query(`
            SELECT 
                spin_earnings,
                referral_earnings,
                task_earnings,
                milestone_earnings,
                signup_bonus_earnings,
                streak_earnings,
                points
            FROM users
            WHERE id = $1
        `, [userId]);

        if (earnings.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get recent transactions
        const transactions = await pool.query(`
            SELECT *
            FROM point_transactions
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 50
        `, [userId]);

        // Get transaction summary by type
        const summary = await pool.query(`
            SELECT 
                transaction_type,
                COUNT(*) as transaction_count,
                SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END) as total_earned,
                SUM(CASE WHEN amount < 0 THEN amount ELSE 0 END) as total_spent
            FROM point_transactions
            WHERE user_id = $1
            GROUP BY transaction_type
        `, [userId]);

        res.json({
            earnings: earnings.rows[0],
            recentTransactions: transactions.rows,
            summary: summary.rows
        });
    } catch (error) {
        console.error('Error fetching earnings:', error);
        res.status(500).json({ error: 'Failed to fetch earnings' });
    }
});

// Get user earnings for user-facing (non-admin)
router.get('/user-earnings', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const userId = req.user.userId;

        const earnings = await pool.query(`
            SELECT 
                spin_earnings,
                referral_earnings,
                task_earnings,
                milestone_earnings,
                signup_bonus_earnings,
                streak_earnings,
                points
            FROM users
            WHERE id = $1
        `, [userId]);

        res.json(earnings.rows[0]);
    } catch (error) {
        console.error('Error fetching user earnings:', error);
        res.status(500).json({ error: 'Failed to fetch earnings' });
    }
});



// ========================================
// USER PERSONAL SHARE SUBMISSION (NEW SYSTEM)
// ========================================

// User submits personal share proof
router.post('/submit-personal-share', authenticateUser, uploadSubmission.single('screenshot'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const userId = req.user.userId;
        const recipientNumbers = req.body.recipientNumbers; // JSON string or array

        if (!req.file) {
            return res.status(400).json({ error: 'Screenshot is required' });
        }

        if (!recipientNumbers) {
            return res.status(400).json({ error: 'Recipient numbers are required' });
        }

        // Parse recipient numbers
        let recipients;
        try {
            recipients = typeof recipientNumbers === 'string'
                ? JSON.parse(recipientNumbers)
                : recipientNumbers;
        } catch (e) {
            return res.status(400).json({ error: 'Invalid recipient numbers format' });
        }

        if (!Array.isArray(recipients) || recipients.length === 0) {
            return res.status(400).json({ error: 'At least one recipient is required' });
        }

        // Get settings
        const settingsResult = await pool.query('SELECT * FROM personal_share_settings ORDER BY id DESC LIMIT 1');
        const settings = settingsResult.rows[0];

        if (!settings) {
            return res.status(500).json({ error: 'Personal share settings not configured' });
        }

        const screenshotUrl = `/uploads/proofs/${req.file.filename}`;
        const pointsPerSubmission = settings.points_per_submission || 5;
        const instantPoints = settings.instant_points_award || false;
        const adminReview = settings.admin_review_required !== false;

        // Determine status and points
        let status = 'pending';
        let pointsAwarded = 0;

        if (!adminReview && instantPoints) {
            status = 'approved';
            pointsAwarded = pointsPerSubmission;
        } else if (instantPoints) {
            status = 'pending';
            pointsAwarded = pointsPerSubmission;
        } else if (!adminReview) {
            status = 'approved';
            pointsAwarded = pointsPerSubmission;
        }

        // Insert submission
        const submissionResult = await pool.query(`
            INSERT INTO personal_share_submissions (
                user_id, screenshot_url, recipient_numbers, 
                status, points_awarded, created_at
            )
            VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
            RETURNING *
        `, [userId, screenshotUrl, JSON.stringify(recipients), status, pointsAwarded]);

        // Award points if applicable
        if (pointsAwarded > 0) {
            await pool.query('UPDATE users SET points = points + $1 WHERE id = $2', [pointsAwarded, userId]);

            await pool.query(`
                INSERT INTO point_transactions (user_id, amount, transaction_type, description, created_at)
                VALUES ($1, $2, 'personal_share_submission', $3, CURRENT_TIMESTAMP)
            `, [userId, pointsAwarded, `Personal share submission - ${pointsAwarded} points`]);
        }

        res.json({
            message: 'Submission recorded successfully',
            submission: submissionResult.rows[0],
            pointsAwarded,
            status
        });
    } catch (error) {
        console.error('Error submitting personal share:', error);
        res.status(500).json({ error: 'Failed to submit personal share' });
    }
});

// Get user's personal share submissions
router.get('/my-personal-share-submissions', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const userId = req.user.userId;

        const result = await pool.query(`
            SELECT 
                id,
                screenshot_url,
                recipient_numbers,
                status,
                points_awarded,
                admin_notes,
                created_at
            FROM personal_share_submissions
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT 50
        `, [userId]);

        res.json({ submissions: result.rows });
    } catch (error) {
        console.error('Error fetching submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});

// Get personal share settings for user
router.get('/personal-share-settings', authenticateUser, async (req, res) => {
    try {
        const pool = req.app.get('db');
        const result = await pool.query('SELECT * FROM personal_share_settings ORDER BY id DESC LIMIT 1');

        if (result.rows.length === 0) {
            return res.json({
                points_per_submission: 5,
                instant_points_award: false,
                admin_review_required: true,
                max_screenshots_allowed: 20,
                status: 'active'
            });
        }

        // ✅ ADD: Include max_screenshots_allowed
        res.json({
            points_per_submission: result.rows[0].points_per_submission,
            instant_points_award: result.rows[0].instant_points_award,
            admin_review_required: result.rows[0].admin_review_required,
            max_screenshots_allowed: result.rows[0].max_screenshots_allowed || 20
        });
    } catch (error) {
        console.error('Error fetching settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// ========================================
// ADMIN PERSONAL SHARE MANAGEMENT (NEW SYSTEM)
// ========================================

// Get Personal Share Settings
router.get('/admin/personal-share/settings', authenticateAdmin, checkPermission('task_personal_settings'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const result = await pool.query('SELECT * FROM personal_share_settings ORDER BY id DESC LIMIT 1');

        if (result.rows.length === 0) {
            const defaultSettings = await pool.query(`
                INSERT INTO personal_share_settings (points_per_submission, instant_points_award, admin_review_required) 
                VALUES (5, false, true) 
                RETURNING *
            `);
            return res.json(defaultSettings.rows[0]);
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching personal share settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

// Update Personal Share Task Settings
router.put('/admin/personal-share/settings', authenticateAdmin, checkPermission('task_personal_settings'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { pointsPerSubmission, instantPointsAward, adminReviewRequired, maxScreenshotsAllowed } = req.body;

        // ✅ ADD: Default value for maxScreenshotsAllowed
        const maxScreenshots = maxScreenshotsAllowed || 20;

        // Ensure we get the latest settings ID
        const currentSettings = await pool.query('SELECT id FROM personal_share_settings ORDER BY id DESC LIMIT 1');

        if (currentSettings.rows.length === 0) {
            // Create if doesn't exist
            await pool.query(`
                INSERT INTO personal_share_settings (points_per_submission, instant_points_award, admin_review_required, max_screenshots_allowed, created_at, updated_at)
                VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            `, [pointsPerSubmission, instantPointsAward, adminReviewRequired, maxScreenshots]);
        } else {
            // Update existing
            await pool.query(`
                UPDATE personal_share_settings 
                SET points_per_submission = $1, instant_points_award = $2, admin_review_required = $3, max_screenshots_allowed = $4, updated_at = CURRENT_TIMESTAMP
                WHERE id = $5
            `, [pointsPerSubmission, instantPointsAward, adminReviewRequired, maxScreenshots, currentSettings.rows[0].id]);
        }

        // Sync to settings table
        await pool.query(
            'UPDATE settings SET setting_value = $1, updated_at = NOW() WHERE setting_key = $2',
            [pointsPerSubmission.toString(), 'points_per_share']
        );

        await logAdminActivity(pool, req.admin.adminId, 'update_personal_share_settings', 'Updated personal share task settings');

        res.json({ message: 'Settings updated successfully' });
    } catch (error) {
        console.error('Error updating personal share settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});
// Get Personal Share Submissions - User List
router.get('/admin/personal-share/submissions/users', authenticateAdmin, checkPermission('task_personal_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { status } = req.query;

        let query = `
            SELECT 
                u.id as user_id,
                u.whatsapp_number,
                COUNT(pss.id) as total_submissions,
                COUNT(CASE WHEN pss.status = 'pending' THEN 1 END) as pending_count,
                COUNT(CASE WHEN pss.status = 'approved' THEN 1 END) as approved_count,
                COUNT(CASE WHEN pss.status = 'rejected' THEN 1 END) as rejected_count,
                COALESCE(SUM(pss.points_awarded), 0) as total_points_earned,
                MAX(pss.created_at) as last_submission_date
            FROM users u
            INNER JOIN personal_share_submissions pss ON u.id = pss.user_id
        `;

        const params = [];
        if (status && status !== 'all') {
            query += ` WHERE pss.status = $1`;
            params.push(status);
        }

        query += `
            GROUP BY u.id, u.whatsapp_number
            ORDER BY MAX(pss.created_at) DESC
        `;

        const result = await pool.query(query, params);

        res.json({ users: result.rows });
    } catch (error) {
        console.error('Error fetching personal share users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Get Personal Share Submissions by User
router.get('/admin/personal-share/submissions/user/:userId', authenticateAdmin, checkPermission('task_personal_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;
        const { status } = req.query;

        let query = `
            SELECT 
                pss.*,
                u.whatsapp_number,
                a.username as reviewed_by_username
            FROM personal_share_submissions pss
            INNER JOIN users u ON pss.user_id = u.id
            LEFT JOIN admins a ON pss.reviewed_by = a.id
            WHERE pss.user_id = $1
        `;

        const params = [userId];

        if (status && status !== 'all') {
            query += ` AND pss.status = $2`;
            params.push(status);
        }

        query += ` ORDER BY pss.created_at DESC`;

        const result = await pool.query(query, params);

        res.json({ submissions: result.rows });
    } catch (error) {
        console.error('Error fetching user submissions:', error);
        res.status(500).json({ error: 'Failed to fetch submissions' });
    }
});

// Review Personal Share Submission
router.post('/admin/personal-share/review-submission', authenticateAdmin, checkPermission('task_personal_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { submissionId, action, adminNotes } = req.body;

        const submission = await pool.query('SELECT * FROM personal_share_submissions WHERE id = $1', [submissionId]);
        if (submission.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        const sub = submission.rows[0];
        const settings = await pool.query('SELECT * FROM personal_share_settings ORDER BY id DESC LIMIT 1');
        const pointsPerSubmission = settings.rows[0]?.points_per_submission || 5;

        // ✅ FIX: Parse JSON to get recipient count
        let recipientCount = 1;
        try {
            const data = JSON.parse(sub.recipient_numbers || '{}');
            recipientCount = data.recipients?.length || 1;
        } catch (e) {
            console.error('Error parsing recipients:', e);
        }

        const status = action === 'approve' ? 'approved' : 'rejected';
        let pointsChange = 0;

        if (action === 'approve' && sub.points_awarded === 0) {
            // ✅ FIX: Award points based on recipient count!
            pointsChange = pointsPerSubmission * recipientCount;
        } else if (action === 'reject' && sub.points_awarded > 0) {
            pointsChange = -sub.points_awarded;
        }

        const finalPointsAwarded = action === 'approve' ? (pointsPerSubmission * recipientCount) : 0;

        // Update submission
        await pool.query(`
            UPDATE personal_share_submissions 
            SET status = $1, admin_notes = $2, points_awarded = $3, reviewed_by = $4, reviewed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = $5
        `, [status, adminNotes, finalPointsAwarded, req.admin.adminId, submissionId]);

        // Apply points change with task_earnings tracking
        if (pointsChange !== 0) {
            await pool.query('UPDATE users SET points = points + $1, task_earnings = task_earnings + $1 WHERE id = $2', [pointsChange, sub.user_id]);

            const description = pointsChange > 0
                ? `Personal share approved - ${recipientCount} recipients, ${pointsChange} points awarded`
                : `Personal share rejected - ${Math.abs(pointsChange)} points revoked`;

            await pool.query(`
                INSERT INTO point_transactions (user_id, amount, transaction_type, description, created_at)
                VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
            `, [sub.user_id, pointsChange, action === 'approve' ? 'personal_share_approved' : 'personal_share_rejected', description]);
        }

        if (action === 'approve') {
            // Log user activity
            await logPersonalShareActivity(pool, sub.user_id, recipientCount, finalPointsAwarded, 'offer');

            // ✅ UPDATE STREAK
            try {
                const today = new Date().toISOString().split('T')[0];
                let streak = await pool.query('SELECT * FROM user_streaks WHERE user_id = $1', [sub.user_id]);

                if (streak.rows.length === 0) {
                    await pool.query(
                        'INSERT INTO user_streaks (user_id, current_streak, longest_streak, last_share_date) VALUES ($1, 1, 1, $2)',
                        [sub.user_id, today]
                    );

                    const day1Settings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', ['streak_day1_bonus']);
                    const day1Bonus = parseInt(day1Settings.rows[0]?.setting_value) || 0;

                    if (day1Bonus > 0) {
                        await pool.query('UPDATE users SET points = points + $1, streak_earnings = streak_earnings + $1 WHERE id = $2', [day1Bonus, sub.user_id]);
                        await pool.query(
                            'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                            [sub.user_id, `🔥 Day 1 streak! You earned ${day1Bonus} bonus points!`, 'streak_bonus']
                        );
                    }

                    console.log(`🔥 Personal Share Admin: Created new streak for user ${sub.user_id}`);
                } else {
                    const lastShareDate = streak.rows[0].last_share_date
                        ? new Date(streak.rows[0].last_share_date).toISOString().split('T')[0]
                        : null;
                    const currentStreak = streak.rows[0].current_streak;

                    if (lastShareDate !== today) {
                        const yesterday = new Date();
                        yesterday.setDate(yesterday.getDate() - 1);
                        const yesterdayStr = yesterday.toISOString().split('T')[0];

                        let newStreak = lastShareDate === yesterdayStr ? currentStreak + 1 : 1;
                        const cycleDay = ((newStreak - 1) % 7) + 1;
                        const settingKey = `streak_day${cycleDay}_bonus`;

                        console.log(`🔥 Personal Share Admin: Streak ${newStreak} → Cycle Day ${cycleDay}`);

                        const bonusSettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [settingKey]);
                        const streakBonus = parseInt(bonusSettings.rows[0]?.setting_value) || 0;

                        console.log(`💰 Cycle Day ${cycleDay} bonus: ${streakBonus} points`);

                        await pool.query(
                            `UPDATE user_streaks 
                             SET current_streak = $1, 
                                 longest_streak = GREATEST(longest_streak, $1),
                                 last_share_date = $2, 
                                 total_streak_bonuses = total_streak_bonuses + $3,
                                 updated_at = NOW()
                             WHERE user_id = $4`,
                            [newStreak, today, streakBonus, sub.user_id]
                        );

                        if (streakBonus > 0) {
                            await pool.query('UPDATE users SET points = points + $1, streak_earnings = streak_earnings + $1 WHERE id = $2', [streakBonus, sub.user_id]);

                            await pool.query(
                                'INSERT INTO point_transactions (user_id, amount, transaction_type, description, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)',
                                [sub.user_id, streakBonus, 'streak_bonus', `Day ${newStreak} streak bonus`]
                            );

                            const nextDayKey = `streak_day${((newStreak) % 7) + 1}_bonus`;
                            const nextDaySettings = await pool.query('SELECT setting_value FROM settings WHERE setting_key = $1', [nextDayKey]);
                            const nextDayBonus = parseInt(nextDaySettings.rows[0]?.setting_value) || 0;
                            await logStreakActivity(pool, sub.user_id, newStreak, streakBonus, nextDayBonus);

                            await pool.query(
                                'INSERT INTO notifications (user_id, message, type) VALUES ($1, $2, $3)',
                                [sub.user_id, `🔥 Day ${newStreak} streak! You earned ${streakBonus} bonus points!`, 'streak_bonus']
                            );
                        }

                        console.log(`🔥 Personal Share Admin: User ${sub.user_id} streak day ${newStreak}, earned ${streakBonus} bonus`);
                    }
                }
            } catch (streakError) {
                console.error('Personal share admin approval streak error:', streakError);
            }

            // ✅ AWARD BONUS SPIN
            try {
                await awardBonusSpin(pool, sub.user_id);
            } catch (bonusError) {
                console.error('Personal share bonus spin error:', bonusError);
            }

            // ✅ CHECK MILESTONES (NEW - WAS MISSING!)
            try {
                console.log('===== MILESTONE CHECK STARTED (PERSONAL SHARE ADMIN) =====');
                console.log('User ID:', sub.user_id);

                const personalShares = await pool.query(`
                    SELECT COUNT(DISTINCT recipient_number) as total
                    FROM user_recipients sr
                    JOIN submissions s ON sr.submission_id = s.id
                    WHERE s.user_id = $1 AND s.status = 'active'`, [sub.user_id]);

                const newShares = await pool.query(`
                    SELECT recipient_numbers FROM personal_share_submissions 
                    WHERE user_id = $1 AND status = 'approved'`, [sub.user_id]);

                let newShareCount = 0;
                for (const row of newShares.rows) {
                    try {
                        const data = JSON.parse(row.recipient_numbers || '{}');
                        newShareCount += data.recipients?.length || 0;
                    } catch (e) { }
                }

                const globalTasks = await pool.query(`
                    SELECT COUNT(*) as total
                    FROM user_lead_assignments
                    WHERE user_id = $1 AND status = 'approved'`, [sub.user_id]);

                const shareCount = parseInt(personalShares.rows[0].total) + newShareCount + parseInt(globalTasks.rows[0].total);

                console.log('Personal shares:', personalShares.rows[0].total);
                console.log('New personal shares:', newShareCount);
                console.log('Global tasks:', globalTasks.rows[0].total);
                console.log('Total shareCount:', shareCount);

                const milestones = await pool.query(`
                    SELECT * FROM settings WHERE setting_key LIKE 'milestone_%' ORDER BY setting_key`);

                console.log('Milestones found:', milestones.rows.length);

                for (const m of milestones.rows) {
                    const shares = parseInt(m.setting_key.replace('milestone_', ''));
                    const bonus = parseInt(m.setting_value);

                    console.log(`Checking milestone ${shares}: shareCount=${shareCount}, bonus=${bonus}`);

                    if (shareCount >= shares) {
                        console.log('✅ Share count met!');

                        const exists = await pool.query(
                            'SELECT * FROM user_milestones WHERE user_id = $1 AND milestone_type = $2 AND milestone_value = $3',
                            [sub.user_id, 'shares', shares]
                        );

                        console.log('Already awarded?', exists.rows.length > 0);

                        if (exists.rows.length === 0) {
                            console.log('🎯 AWARDING MILESTONE NOW!');

                            await pool.query(
                                'INSERT INTO user_milestones (user_id, milestone_type, milestone_value, bonus_awarded) VALUES ($1, $2, $3, $4)',
                                [sub.user_id, 'shares', shares, bonus]
                            );

                            await pool.query(
                                'UPDATE users SET points = points + $1, milestone_earnings = milestone_earnings + $1 WHERE id = $2',
                                [bonus, sub.user_id]
                            );

                            await logPointTransaction(pool, sub.user_id, bonus, 'milestone', `Milestone reward: ${shares} shares completed`, shares);

                            const allMilestones = [10, 50, 100, 500, 1000, 5000, 10000];
                            const nextMilestone = allMilestones.find(m => m > shares) || null;
                            await logMilestoneActivity(pool, sub.user_id, shares, bonus, shareCount, nextMilestone);

                            console.log(`🎉 Milestone awarded: ${shares} shares - ${bonus} points to user ${sub.user_id}`);
                        }
                    }
                }

                console.log('===== MILESTONE CHECK COMPLETED =====');
            } catch (error) {
                console.error('Error checking milestones (personal share admin):', error);
            }

        } else if (action === 'reject') {
            const shortReason = adminNotes.length > 30 ? adminNotes.substring(0, 30) + '...' : adminNotes;
            await logActivity(
                pool,
                sub.user_id,
                'personal_share',
                'Submission Rejected',
                `Personal share submission rejected: ${shortReason}`,
                0,
                { status: 'rejected', reason: adminNotes }
            );
        }

        await logAdminActivity(pool, req.admin.adminId, 'review_personal_share', `${action} submission #${submissionId}`);

        res.json({ message: `Submission ${action}d successfully` });
    } catch (error) {
        console.error('Error reviewing submission:', error);
        res.status(500).json({ error: 'Failed to review submission' });
    }
});


// Get Personal Share Statistics
router.get('/admin/personal-share/stats', authenticateAdmin, checkPermission('task_personal_submissions'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        const stats = await pool.query(`
            SELECT 
                COUNT(*) as total_submissions,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
                COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved,
                COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected,
                COALESCE(SUM(points_awarded), 0) as total_points_awarded,
                COUNT(DISTINCT user_id) as total_users
            FROM personal_share_submissions
        `);

        res.json(stats.rows[0]);
    } catch (error) {
        console.error('Error fetching personal share stats:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});



// ==================== NEW USER MANAGEMENT ROUTES (No Conflicts) ====================

// Get all users with comprehensive stats (for AllUsers page)
router.get('/admin/all-users', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        // Get all users with their stats
        const usersQuery = `
            SELECT 
                u.id,
                u.whatsapp_number,
                u.points,
                u.referral_code,
                u.is_active,
                u.created_at,
                u.registration_ip,
                u.last_login_ip,
                u.spin_earnings,
                u.referral_earnings,
                u.task_earnings,
                u.milestone_earnings,
                u.signup_bonus_earnings,
                u.streak_earnings,
                COUNT(DISTINCT r.referred_id) as total_referrals,
                COUNT(DISTINCT ula.id) FILTER (WHERE ula.status = 'approved') as global_tasks_count,
                (
                    SELECT COUNT(*)
                    FROM submissions s
                    WHERE s.user_id = u.id AND s.status = 'active'
                ) +
                (
                    SELECT COUNT(*)
                    FROM personal_share_submissions pss
                    WHERE pss.user_id = u.id AND pss.status = 'approved'
                ) as personal_shares_count,
                (
                    SELECT COALESCE(SUM(points_requested), 0)
                    FROM redemptions red
                    WHERE red.user_id = u.id AND red.status = 'completed'
                ) as total_redeemed
            FROM users u
            LEFT JOIN referrals r ON u.id = r.referrer_id
            LEFT JOIN user_lead_assignments ula ON u.id = ula.user_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
        `;

        const users = await pool.query(usersQuery);

        // Get overall stats
        const statsQuery = `
            SELECT 
                COUNT(*) as total_users,
                COUNT(*) FILTER (WHERE is_active = true) as active_users,
                COALESCE(SUM(points), 0) as total_points,
                (
                    SELECT COALESCE(SUM(points_requested), 0)
                    FROM redemptions
                    WHERE status = 'completed'
                ) as total_redeemed
            FROM users
        `;

        const stats = await pool.query(statsQuery);

        console.log(`✅ Fetched ${users.rows.length} users`);

        res.json({
            users: users.rows,
            stats: stats.rows[0]
        });

    } catch (error) {
        console.error('Error fetching all users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Master delete all users
router.delete('/admin/master-delete-users', authenticateAdmin, checkPermission('user_manage'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        console.log('🚨 MASTER DELETE INITIATED');

        // Delete in correct order to respect foreign key constraints
        await pool.query('DELETE FROM point_transactions');
        await pool.query('DELETE FROM activity_log');
        await pool.query('DELETE FROM notifications');
        await pool.query('DELETE FROM user_recipients');
        await pool.query('DELETE FROM submissions');
        await pool.query('DELETE FROM personal_share_submissions');
        await pool.query('DELETE FROM user_lead_assignments');
        await pool.query('DELETE FROM user_milestones');
        await pool.query('DELETE FROM user_streaks');
        await pool.query('DELETE FROM user_spins');
        await pool.query('DELETE FROM redemptions');
        await pool.query('DELETE FROM referrals');
        await pool.query('DELETE FROM user_ip_history');
        await pool.query('DELETE FROM spin_history');
        await pool.query('DELETE FROM broadcast_reads');
        await pool.query('DELETE FROM user_messages');
        await pool.query('DELETE FROM user_flags');
        await pool.query('DELETE FROM token_blacklist');
        await pool.query('DELETE FROM activity_participations');
        await pool.query('DELETE FROM lead_submissions');
        await pool.query('DELETE FROM user_campaign_stats');
        await pool.query('DELETE FROM users');

        console.log('✅ All users and related data deleted');

        res.json({
            success: true,
            message: 'All users deleted successfully'
        });

    } catch (error) {
        console.error('Error in master delete:', error);
        res.status(500).json({ error: 'Failed to delete users' });
    }
});

// Get comprehensive user details (for UserDetails page)
router.get('/admin/user-details/:userId', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        // Get user basic info with earnings
        const user = await pool.query(`
            SELECT 
                u.*,
                (SELECT whatsapp_number FROM users WHERE referral_code = u.referred_by_code) as referrer_phone,
                COUNT(DISTINCT r.referred_id) as total_referrals,
                COALESCE((SELECT SUM(amount) FROM point_transactions WHERE user_id = u.id AND transaction_type = 'spin'), 0)::integer as spin_earnings,
                COALESCE((SELECT SUM(amount) FROM point_transactions WHERE user_id = u.id AND transaction_type LIKE '%referral%'), 0)::integer as referral_earnings,
                COALESCE((SELECT SUM(amount) FROM point_transactions WHERE user_id = u.id AND transaction_type IN ('task', 'personal_share_submission', 'personal_share_approved')), 0)::integer as task_earnings,
                COALESCE((SELECT SUM(amount) FROM point_transactions WHERE user_id = u.id AND transaction_type = 'milestone'), 0)::integer as milestone_earnings,
                COALESCE((SELECT SUM(amount) FROM point_transactions WHERE user_id = u.id AND transaction_type = 'signup_bonus'), 0)::integer as signup_bonus_earnings,
                COALESCE((SELECT SUM(amount) FROM point_transactions WHERE user_id = u.id AND transaction_type = 'streak_bonus'), 0)::integer as streak_earnings
            FROM users u
            LEFT JOIN referrals r ON u.id = r.referrer_id
            WHERE u.id = $1
            GROUP BY u.id
        `, [userId]);

        if (user.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Get IP stats
        const ipStats = await pool.query(`
            SELECT 
                (SELECT COUNT(*) FROM users WHERE registration_ip = $1) as users_same_reg_ip,
                (SELECT COUNT(*) FROM users WHERE last_login_ip = $2) as users_same_login_ip
        `, [user.rows[0].registration_ip, user.rows[0].last_login_ip]);

        // Get IP history (from user_ip_history table)
        const ipHistory = await pool.query(`
            SELECT ip_address, action, created_at, id
            FROM user_ip_history 
            WHERE user_id = $1 
            ORDER BY created_at DESC 
            LIMIT 20
        `, [userId]);

        // Get activity stats - FIXED: Only count tasks where user earned points
        const activityStats = await pool.query(`
    SELECT 
        (
            SELECT COUNT(*)
            FROM user_lead_assignments ula
            WHERE ula.user_id = $1 AND ula.status = 'approved' AND ula.points_awarded > 0
        ) + 
        (
            SELECT COUNT(*)
            FROM personal_share_submissions pss
            WHERE pss.user_id = $1 AND pss.status = 'approved'
        ) as total_submissions,
        (
            SELECT COUNT(*)
            FROM spin_history
            WHERE user_id = $1
        ) as total_spins,
        (
            SELECT COUNT(*)
            FROM redemptions
            WHERE user_id = $1
        ) as total_redemptions,
        (
            SELECT COALESCE(SUM(points_requested), 0)
            FROM redemptions
            WHERE user_id = $1 AND status = 'approved'
        ) as total_redeemed_points
`, [userId]);

        res.json({
            user: user.rows[0],
            ipStats: ipStats.rows[0] || { users_same_reg_ip: 0, users_same_login_ip: 0 },
            ipHistory: ipHistory.rows,
            activityStats: activityStats.rows[0] || {
                total_submissions: 0,
                total_spins: 0,
                total_redemptions: 0,
                total_redeemed_points: 0
            }
        });

    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ error: 'Failed to fetch user details' });
    }
});

// Search users
router.get('/admin/search-users', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { query, type } = req.query;

        let searchQuery;
        if (type === 'id') {
            searchQuery = `
                SELECT u.*, COUNT(DISTINCT r.referred_id) as total_referrals
                FROM users u
                LEFT JOIN referrals r ON u.id = r.referrer_id
                WHERE u.id = $1
                GROUP BY u.id
            `;
        } else {
            searchQuery = `
                SELECT u.*, COUNT(DISTINCT r.referred_id) as total_referrals
                FROM users u
                LEFT JOIN referrals r ON u.id = r.referrer_id
                WHERE u.whatsapp_number LIKE $1
                GROUP BY u.id
                LIMIT 10
            `;
        }

        const searchParam = type === 'id' ? query : `%${query}%`;
        const users = await pool.query(searchQuery, [searchParam]);

        res.json({ users: users.rows });

    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).json({ error: 'Failed to search users' });
    }
});

// Get recent users
router.get('/admin/recent-users', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const limit = req.query.limit || 10;

        const users = await pool.query(`
            SELECT u.*, COUNT(DISTINCT r.referred_id) as total_referrals
            FROM users u
            LEFT JOIN referrals r ON u.id = r.referrer_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
            LIMIT $1
        `, [limit]);

        res.json({ users: users.rows });

    } catch (error) {
        console.error('Error fetching recent users:', error);
        res.status(500).json({ error: 'Failed to fetch recent users' });
    }
});

// Get user referrals
router.get('/admin/user-referrals/:userId', authenticateAdmin, checkPermission('user_referral_data'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        const referrals = await pool.query(`
            SELECT 
                r.id as referral_id,
                r.referred_id,
                r.total_commission_earned,
                r.created_at as joined_at,
                u.whatsapp_number,
                u.points,
                u.is_active,
                CASE WHEN u.is_active THEN 'active' ELSE 'inactive' END as status,
                COUNT(DISTINCT r2.referred_id) as their_referrals
            FROM referrals r
            JOIN users u ON r.referred_id = u.id
            LEFT JOIN referrals r2 ON u.id = r2.referrer_id
            WHERE r.referrer_id = $1
            GROUP BY r.id, r.referred_id, r.total_commission_earned, r.created_at, 
                     u.whatsapp_number, u.points, u.is_active
            ORDER BY r.created_at DESC
        `, [userId]);

        res.json({ referrals: referrals.rows });

    } catch (error) {
        console.error('Error fetching user referrals:', error);
        res.status(500).json({ error: 'Failed to fetch referrals' });
    }
});


// Get activity logs (for UserActivityLogs page)
router.get('/admin/user-activity-logs', authenticateAdmin, checkPermission('user_activity_logs'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { limit = 500 } = req.query;

        // Get activities with user info
        const activitiesQuery = `
            SELECT 
                al.id,
                al.user_id,
                al.activity_type,
                al.title,
                al.description,
                al.points as points_awarded,
                al.metadata,
                al.created_at,
                u.whatsapp_number
            FROM activity_log al
            INNER JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT $1
        `;

        const activities = await pool.query(activitiesQuery, [limit]);

        // Get today's date at midnight
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        // Get retention setting
        const retentionResult = await pool.query(
            "SELECT setting_value FROM settings WHERE setting_key = 'activity_log_retention_days'"
        );
        const retentionDays = retentionResult.rows.length > 0
            ? parseInt(retentionResult.rows[0].setting_value)
            : 30;

        // Get stats including old activities count
        const statsQuery = `
            SELECT 
                COUNT(*) as total_activities,
                COUNT(*) FILTER (WHERE created_at >= $1) as today_activities,
                COUNT(DISTINCT user_id) FILTER (WHERE created_at >= $1) as active_users_today,
                COALESCE(SUM(points) FILTER (WHERE created_at >= $1), 0) as points_distributed_today,
                COUNT(*) FILTER (WHERE created_at < NOW() - INTERVAL '${retentionDays} days') as old_activities
            FROM activity_log
        `;

        const stats = await pool.query(statsQuery, [today]);

        console.log(`✅ Fetched ${activities.rows.length} activities`);

        res.json({
            activities: activities.rows,
            stats: {
                ...stats.rows[0],
                retention_days: retentionDays
            }
        });

    } catch (error) {
        console.error('Error fetching activity logs:', error);
        res.status(500).json({ error: 'Failed to fetch activity logs' });
    }
});



// ==================== USER REFERRAL DATA ROUTES ====================

// Get referral statistics (for stats cards)
router.get('/admin/referral-stats', authenticateAdmin, checkPermission('user_referral_data'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        const stats = await pool.query(`
            SELECT 
                COUNT(DISTINCT u.id) as total_users,
                COUNT(DISTINCT r.referrer_id) FILTER (WHERE r.referrer_id IS NOT NULL) as active_referrers,
                COUNT(r.id) as total_referrals,
                COALESCE(SUM(pt.amount) FILTER (WHERE pt.transaction_type = 'referral'), 0) as total_commission
            FROM users u
            LEFT JOIN referrals r ON u.id = r.referrer_id
            LEFT JOIN point_transactions pt ON u.id = pt.user_id AND pt.transaction_type = 'referral'
        `);

        res.json(stats.rows[0]);
    } catch (error) {
        console.error('Error fetching referral stats:', error);
        res.status(500).json({ error: 'Failed to fetch statistics' });
    }
});

// Get recent users
router.get('/admin/recent-users', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { limit = 10 } = req.query;

        const users = await pool.query(`
            SELECT 
                u.id,
                u.whatsapp_number,
                u.points,
                u.created_at,
                u.is_active,
                COUNT(r.id) as total_referrals
            FROM users u
            LEFT JOIN referrals r ON u.id = r.referrer_id
            GROUP BY u.id
            ORDER BY u.created_at DESC
            LIMIT $1
        `, [limit]);

        res.json({ users: users.rows });
    } catch (error) {
        console.error('Error fetching recent users:', error);
        res.status(500).json({ error: 'Failed to fetch recent users' });
    }
});

// Search users by phone or ID
router.get('/admin/search-users', authenticateAdmin, checkPermission('user_view_all'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { query, type } = req.query;

        let searchQuery;
        let params;

        if (type === 'id') {
            searchQuery = `
                SELECT 
                    u.id,
                    u.whatsapp_number,
                    u.points,
                    u.is_active,
                    COUNT(r.id) as total_referrals
                FROM users u
                LEFT JOIN referrals r ON u.id = r.referrer_id
                WHERE u.id = $1
                GROUP BY u.id
            `;
            params = [parseInt(query)];
        } else {
            // Phone search
            searchQuery = `
                SELECT 
                    u.id,
                    u.whatsapp_number,
                    u.points,
                    u.is_active,
                    COUNT(r.id) as total_referrals
                FROM users u
                LEFT JOIN referrals r ON u.id = r.referrer_id
                WHERE u.whatsapp_number LIKE $1
                GROUP BY u.id
                LIMIT 20
            `;
            params = [`%${query}%`];
        }

        const users = await pool.query(searchQuery, params);

        res.json({ users: users.rows });
    } catch (error) {
        console.error('Error searching users:', error);
        res.status(500).json({ error: 'Failed to search users' });
    }
});

// Get user's referrals
router.get('/admin/user-referrals/:userId', authenticateAdmin, checkPermission('user_referral_data'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { userId } = req.params;

        const referrals = await pool.query(`
            SELECT 
                r.id as referral_id,
                r.referred_id,
                u.whatsapp_number,
                u.points,
                u.is_active,
                r.created_at as joined_at,
                CASE WHEN u.is_active THEN 'active' ELSE 'inactive' END as status,
                COUNT(r2.id) as their_referrals,
                COALESCE(SUM(pt.amount) FILTER (WHERE pt.transaction_type = 'referral'), 0) as total_commission_earned
            FROM referrals r
            INNER JOIN users u ON r.referred_id = u.id
            LEFT JOIN referrals r2 ON u.id = r2.referrer_id
            LEFT JOIN point_transactions pt ON r.referrer_id = pt.user_id 
                AND pt.transaction_type = 'referral' 
                AND pt.reference_id = r.referred_id::text
            WHERE r.referrer_id = $1
            GROUP BY r.id, r.referred_id, u.whatsapp_number, u.points, u.is_active, r.created_at
            ORDER BY r.created_at DESC
        `, [userId]);

        res.json({ referrals: referrals.rows });
    } catch (error) {
        console.error('Error fetching user referrals:', error);
        res.status(500).json({ error: 'Failed to fetch referrals' });
    }
});


// ==================== NOTICES ROUTES - ADD TO routes.js ====================
// Replace the existing notices routes section with this updated version
// Uses new 'manage_notices' permission

// Get all active notices for users (public - no auth required)
router.get('/api/notices/active', async (req, res) => {
    try {
        const pool = req.app.get('db');

        const query = `
            SELECT id, title, content, type, is_important, created_at
            FROM notices 
            WHERE is_active = true 
            ORDER BY is_important DESC, created_at DESC
        `;

        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching active notices:', error);
        res.status(500).json({ error: 'Failed to fetch notices' });
    }
});

// Get all notices for users (includes inactive ones)
router.get('/api/notices', async (req, res) => {
    try {
        const pool = req.app.get('db');

        const query = `
            SELECT id, title, content, type, is_important, is_active, created_at
            FROM notices 
            ORDER BY is_important DESC, created_at DESC
        `;

        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching notices:', error);
        res.status(500).json({ error: 'Failed to fetch notices' });
    }
});

// Admin: Get all notices - NEW PERMISSION: manage_notices
router.get('/admin/notices', authenticateAdmin, checkPermission('manage_notices'), async (req, res) => {
    try {
        const pool = req.app.get('db');

        const query = `
            SELECT id, title, content, type, is_important, is_active, created_at, updated_at
            FROM notices 
            ORDER BY created_at DESC
        `;

        const result = await pool.query(query);
        console.log(`✅ Admin ${req.admin.id} fetched ${result.rows.length} notices`);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching notices:', error);
        res.status(500).json({ error: 'Failed to fetch notices' });
    }
});

// Admin: Create new notice - NEW PERMISSION: manage_notices
router.post('/admin/notices', authenticateAdmin, checkPermission('manage_notices'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { title, content, type, is_important, is_active } = req.body;

        if (!content) {
            return res.status(400).json({ error: 'Content is required' });
        }

        // Auto-generate title from content if not provided
        const noticeTitle = title || content.substring(0, 100);

        const query = `
            INSERT INTO notices (title, content, type, is_important, is_active)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
        `;

        const result = await pool.query(query, [
            noticeTitle,
            content,
            type || 'announcement',
            is_important || false,
            is_active !== false
        ]);

        console.log(`✅ Notice created: "${noticeTitle}" by admin ${req.admin.id}`);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating notice:', error);
        res.status(500).json({ error: 'Failed to create notice' });
    }
});

// Admin: Update notice - NEW PERMISSION: manage_notices
router.put('/admin/notices/:id', authenticateAdmin, checkPermission('manage_notices'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;
        const { title, content, type, is_important, is_active } = req.body;

        // Auto-generate title from content if not provided
        const noticeTitle = title || content.substring(0, 100);

        const query = `
            UPDATE notices 
            SET title = $1, content = $2, type = $3, is_important = $4, is_active = $5, updated_at = NOW()
            WHERE id = $6
            RETURNING *
        `;

        const result = await pool.query(query, [noticeTitle, content, type, is_important, is_active, id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Notice not found' });
        }

        console.log(`✅ Notice updated: ID ${id} by admin ${req.admin.id}`);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error updating notice:', error);
        res.status(500).json({ error: 'Failed to update notice' });
    }
});

// Admin: Delete notice - NEW PERMISSION: manage_notices
router.delete('/admin/notices/:id', authenticateAdmin, checkPermission('manage_notices'), async (req, res) => {
    try {
        const pool = req.app.get('db');
        const { id } = req.params;

        const query = 'DELETE FROM notices WHERE id = $1 RETURNING id, title';

        const result = await pool.query(query, [id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Notice not found' });
        }

        console.log(`✅ Notice deleted: "${result.rows[0].title}" by admin ${req.admin.id}`);
        res.json({ message: 'Notice deleted successfully' });
    } catch (error) {
        console.error('Error deleting notice:', error);
        res.status(500).json({ error: 'Failed to delete notice' });
    }
});


module.exports = router;
