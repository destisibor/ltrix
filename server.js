require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// PRECISION ARITHMETIC & BLOCKCHAIN CONSTANTS
// ==========================================
function round2(n) {
    return Math.round((Number(n) + Number.EPSILON) * 100) / 100;
}

function round3(n) {
    return Math.round((Number(n) + Number.EPSILON) * 1000) / 1000;
}

function isValidBep20Address(addr) {
    return /^0x[a-fA-F0-9]{40}$/.test(String(addr || '').trim());
}

const USDT_CONTRACT_BEP20 = '0x55d398326f99059ff775485246999027b3197955';
const ERC20_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const BSC_RPC_URLS = [
    'https://bsc-dataseed.binance.org/',
    'https://bsc-dataseed1.defibit.io/',
    'https://bsc-dataseed1.ninicoin.io/'
];

function normalizeEvmTxid(txid) {
    const cleaned = String(txid || '').trim();
    const match = cleaned.match(/^(?:0x)?([0-9a-fA-F]{64})$/);
    return match ? '0x' + match[1].toLowerCase() : null;
}

async function rpcCallWithFallback(rpcUrls, method, params) {
    let lastErr = null;
    for (const url of rpcUrls) {
        try {
            const res = await axios.post(
                url,
                { jsonrpc: '2.0', id: 1, method, params },
                { timeout: 12000 }
            );
            if (res.data && res.data.result !== undefined) {
                return res.data.result;
            }
        } catch (err) {
            lastErr = err;
        }
    }
    throw new Error(lastErr ? lastErr.message : 'Blockchain RPC unreachable');
}

async function verifyBep20UsdtDeposit({ txid, platformAddress, requiredConfirmations }) {
    const receipt = await rpcCallWithFallback(BSC_RPC_URLS, 'eth_getTransactionReceipt', [txid]);
    if (!receipt) {
        throw new Error('Transaction not found on BNB Smart Chain (BEP20) yet. Please wait a moment and try again.');
    }
    if (receipt.status !== '0x1') {
        throw new Error('Transaction failed on the blockchain.');
    }

    const latestBlockHex = await rpcCallWithFallback(BSC_RPC_URLS, 'eth_blockNumber', []);
    const latestBlock = parseInt(latestBlockHex, 16);
    const txBlock = parseInt(receipt.blockNumber, 16);
    const confirmations = Math.max(0, latestBlock - txBlock + 1);

    if (confirmations < requiredConfirmations) {
        throw new Error(`Transaction requires ${requiredConfirmations} confirmations on BEP20. Currently has ${confirmations}.`);
    }

    const normalizedPlatform = String(platformAddress).trim().toLowerCase().replace(/^0x/, '').padStart(64, '0');
    const matchingLog = (receipt.logs || []).find(log => {
        const isUsdtContract = String(log.address || '').toLowerCase() === USDT_CONTRACT_BEP20;
        const isTransfer = Array.isArray(log.topics) && String(log.topics[0] || '').toLowerCase() === ERC20_TRANSFER_TOPIC;
        const toTopic = Array.isArray(log.topics) && log.topics[2] ? String(log.topics[2]).toLowerCase().replace(/^0x/, '') : '';
        return isUsdtContract && isTransfer && toTopic === normalizedPlatform;
    });

    if (!matchingLog) {
        throw new Error('No valid USDT (BEP20) transfer to the configured platform wallet address was found in this transaction.');
    }

    const rawWei = BigInt(matchingLog.data);
    const divisorFor3Decimals = 10n ** 15n;
    const millUnits = Number(rawWei / divisorFor3Decimals);
    return round3(millUnits / 1000);
}

const usdtRequestLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 15,
    message: {
        error: 'Too many deposit requests generated. Please pay the exact amount shown on your current pending request, or wait an hour.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false }
});

const passwordResetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { error: 'Too many password reset attempts. Please try again in 15 minutes.' },
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false }
});

async function sendResendEmail({ to, subject, html }) {
    const apiKey = process.env.RESEND_API_KEY;
    const fromEmail = process.env.RESEND_FROM_EMAIL;

    const res = await axios.post(
        'https://api.resend.com/emails',
        {
            from: fromEmail,
            to: Array.isArray(to) ? to : [to],
            subject,
            html
        },
        {
            headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
            },
            timeout: 12000
        }
    );
    return res.data;
}

// ==========================================
// 1. DATABASE CONNECTION & SCHEMAS
// ==========================================
mongoose.connect(process.env.MONGO_URI)
    .then(async () => {
        console.log('LTRIX Server connected to MongoDB Atlas');
        await seedPackages();
        await ensureSystemSettings();
        await migrateUserRoles();
    })
    .catch((err) => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String, default: '' },
    passwordHash: { type: String, required: true },
    referralCode: { type: String, unique: true },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    role: { type: String, enum: ['USER', 'ADMIN', 'SUPERADMIN'], default: 'USER' },
    status: { type: String, enum: ['ACTIVE', 'SUSPENDED', 'LOCKED'], default: 'ACTIVE' },
    availableBalance: { type: Number, default: 0 },
    referralEarnings: { type: Number, default: 0 },
    totalWithdrawals: { type: Number, default: 0 },
    usdtWithdrawalAddress: { type: String, default: '' },
    resetPasswordOtpHash: { type: String, default: null },
    resetPasswordExpires: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
});

const packagePlanSchema = new mongoose.Schema({
    category: { type: String, enum: ['STANDARD', 'HOT'], default: 'STANDARD' },
    price: { type: Number, required: true },
    dailyIncome: { type: Number, required: true },
    durationDays: { type: Number, required: true },
    totalPayout: { type: Number, required: true },
    purchaseLimit: { type: Number, default: 1 },
    isLocked: { type: Boolean, default: false },
    totalSlots: { type: Number, default: 0 },
    slotsClaimed: { type: Number, default: 0 }
});

const nairaBankSchema = new mongoose.Schema({
    bankName: { type: String, required: true },
    accountNumber: { type: String, required: true },
    accountName: { type: String, required: true },
    isActive: { type: Boolean, default: true }
});

const systemSettingSchema = new mongoose.Schema({
    key: { type: String, unique: true, default: 'GLOBAL_CONFIG' },
    forceHotWindowOpen: { type: Boolean, default: false },
    verifiedPromotionalBudget: { type: Number, default: 5000 },
    businessRegistrationNo: { type: String, default: 'LTRIX-GLOBAL-RC-20268841' },

    usdtEnabled: { type: Boolean, default: true },
    usdtBep20Address: { type: String, default: '0x71C0000000000000000000000000000000008841' },
    usdtConfirmations: { type: Number, default: 12 },

    nairaDepositEnabled: { type: Boolean, default: true },
    nairaExchangeRate: { type: Number, default: 1500 },
    nairaBankInstructions: { type: String, default: 'Include your LTRIX Deposit Reference in the bank transfer narration.' },

    nairaBankAccounts: [nairaBankSchema],
    nairaRotationCounter: { type: Number, default: 0 },

    nairaBankName: { type: String },
    nairaBankAccountNumber: { type: String },
    nairaBankAccountName: { type: String }
});

const weeklyClaimSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    weekKey: { type: String, required: true },
    tier: { type: String, enum: ['BUILDER_15', 'LEADER_40'], required: true },
    amount: { type: Number, required: true },
    claimedAt: { type: Date, default: Date.now }
});
weeklyClaimSchema.index({ userId: 1, weekKey: 1, tier: 1 }, { unique: true });

const activePackageSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    planId: { type: mongoose.Schema.Types.ObjectId, ref: 'PackagePlan', required: true },
    category: { type: String, enum: ['STANDARD', 'HOT'], default: 'STANDARD' },
    price: Number,
    dailyIncome: Number,
    durationDays: Number,
    daysCredited: { type: Number, default: 1 },
    nextPayoutAt: { type: Date, required: true },
    expiresAt: { type: Date, required: true },
    status: { type: String, enum: ['ACTIVE', 'COMPLETED'], default: 'ACTIVE' },
    purchasedAt: { type: Date, default: Date.now }
});

const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    relatedUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    type: {
        type: String,
        enum: ['DEPOSIT', 'WITHDRAWAL', 'PACKAGE_PURCHASE', 'DAILY_INCOME', 'REFERRAL_BONUS', 'WEEKLY_REWARD'],
        required: true
    },
    amount: { type: Number, required: true },
    requestedAmount: { type: Number, default: 0 },
    adjustedAmount: { type: Number, default: 0 },
    decimalOffset: { type: Number, default: 0 },
    paymentMethod: { type: String, enum: ['USDT_BEP20', 'NGN_BANK', 'MANUAL_ADMIN', 'WALLET'], default: 'WALLET' },
    paymentCurrency: { type: String, enum: ['USD', 'USDT', 'NGN'], default: 'USD' },
    usdtNetwork: { type: String, default: '' },
    withdrawalAddress: { type: String, default: '' },
    withdrawalNetwork: { type: String, default: 'BEP20' },
    isUsdtDeposit: { type: Boolean, default: false, index: true },
    isNairaDeposit: { type: Boolean, default: false, index: true },
    nairaRequestedAmount: { type: Number, default: 0 },
    exchangeRateUsed: { type: Number, default: 0 },

    assignedBankDetails: {
        bankName: String,
        accountNumber: String,
        accountName: String
    },

    reference: { type: String, index: true },
    txid: { type: String, sparse: true, index: true },
    fee: { type: Number, default: 0 },
    netAmount: { type: Number, required: true },
    description: String,
    status: {
        type: String,
        enum: ['PENDING', 'PROCESSING', 'COMPLETED', 'REJECTED', 'MANUALLY_CREDITED'],
        default: 'COMPLETED'
    },
    creditedByAdmin: { type: String, default: '' },
    adminNote: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
});

const manualCreditAuditSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    transactionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Transaction', required: true },
    usdAmountCredited: { type: Number, required: true },
    rawAmountReceived: { type: Number, required: true },
    paymentCurrency: { type: String, enum: ['USDT', 'NGN', 'USD'], required: true },
    paymentMethod: { type: String, enum: ['USDT_BEP20', 'NGN_BANK'], required: true },
    txidOrReference: { type: String, required: true, unique: true },
    adminIdentifier: { type: String, required: true },
    adminNote: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const notificationSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: String,
    message: String,
    isRead: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const ticketSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    ticketRef: { type: String, required: true },
    category: { type: String, default: 'GENERAL' },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    adminReply: { type: String, default: '' },
    status: { type: String, enum: ['OPEN', 'RESOLVED'], default: 'OPEN' },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const PackagePlan = mongoose.model('PackagePlan', packagePlanSchema);
const SystemSetting = mongoose.model('SystemSetting', systemSettingSchema);
const WeeklyClaim = mongoose.model('WeeklyClaim', weeklyClaimSchema);
const ActivePackage = mongoose.model('ActivePackage', activePackageSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const ManualCreditAudit = mongoose.model('ManualCreditAudit', manualCreditAuditSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const Ticket = mongoose.model('Ticket', ticketSchema);

// ==========================================
// 2. SEED & SYNC PACKAGES & SETTINGS
// ==========================================

async function migrateUserRoles() {
    try {
        await User.updateMany(
            { role: { $exists: false } },
            { $set: { role: 'USER', status: 'ACTIVE' } }
        );
        console.log('User roles and statuses migrated successfully.');
    } catch (err) {
        console.error('Migration error:', err);
    }
}

async function seedPackages() {
    try {
        const indexes = await PackagePlan.collection.indexes().catch(() => []);
        if (indexes.some(idx => idx.name === 'price_1')) {
            await PackagePlan.collection.dropIndex('price_1').catch(() => { });
        }

        await PackagePlan.updateMany({ category: { $exists: false } }, { $set: { category: 'STANDARD' } });

        const standardPlans = [
            { category: 'STANDARD', price: 8, dailyIncome: 2, durationDays: 5, totalPayout: 10, defaultLimit: 1, defaultLocked: false },
            { category: 'STANDARD', price: 10, dailyIncome: 3, durationDays: 5, totalPayout: 15, defaultLimit: 1, defaultLocked: false },
            { category: 'STANDARD', price: 30, dailyIncome: 5, durationDays: 10, totalPayout: 50, defaultLimit: 2, defaultLocked: false },
            { category: 'STANDARD', price: 50, dailyIncome: 8, durationDays: 10, totalPayout: 80, defaultLimit: 2, defaultLocked: false },
            { category: 'STANDARD', price: 80, dailyIncome: 10, durationDays: 10, totalPayout: 100, defaultLimit: 2, defaultLocked: false },
            { category: 'STANDARD', price: 100, dailyIncome: 15, durationDays: 10, totalPayout: 150, defaultLimit: 2, defaultLocked: false },
            { category: 'STANDARD', price: 200, dailyIncome: 5, durationDays: 90, totalPayout: 450, defaultLimit: 1, defaultLocked: true },
            { category: 'STANDARD', price: 300, dailyIncome: 10, durationDays: 90, totalPayout: 900, defaultLimit: 1, defaultLocked: true }
        ];

        for (const plan of standardPlans) {
            await PackagePlan.findOneAndUpdate(
                { category: 'STANDARD', price: plan.price },
                {
                    $set: {
                        dailyIncome: plan.dailyIncome,
                        durationDays: plan.durationDays,
                        totalPayout: plan.totalPayout
                    },
                    $setOnInsert: {
                        purchaseLimit: plan.defaultLimit,
                        isLocked: plan.defaultLocked,
                        totalSlots: 0,
                        slotsClaimed: 0
                    }
                },
                { upsert: true, new: true }
            );
        }

        const hotPlans = [
            { category: 'HOT', price: 30, dailyIncome: 10, durationDays: 4, totalPayout: 40, defaultLimit: 1, defaultSlots: 25 },
            { category: 'HOT', price: 50, dailyIncome: 11, durationDays: 7, totalPayout: 77, defaultLimit: 1, defaultSlots: 20 },
            { category: 'HOT', price: 100, dailyIncome: 15, durationDays: 15, totalPayout: 225, defaultLimit: 1, defaultSlots: 15 },
            { category: 'HOT', price: 200, dailyIncome: 20, durationDays: 20, totalPayout: 400, defaultLimit: 1, defaultSlots: 10 }
        ];

        for (const plan of hotPlans) {
            await PackagePlan.findOneAndUpdate(
                { category: 'HOT', price: plan.price },
                {
                    $set: {
                        dailyIncome: plan.dailyIncome,
                        durationDays: plan.durationDays,
                        totalPayout: plan.totalPayout
                    },
                    $setOnInsert: {
                        purchaseLimit: plan.defaultLimit,
                        isLocked: false,
                        totalSlots: plan.defaultSlots,
                        slotsClaimed: 0
                    }
                },
                { upsert: true, new: true }
            );
        }

        console.log('LTRIX Standard and Sunday HOT packages synced.');
    } catch (err) {
        console.error('Seed error:', err);
    }
}

async function ensureSystemSettings() {
    let settings = await SystemSetting.findOne({ key: 'GLOBAL_CONFIG' });
    if (!settings) {
        settings = await SystemSetting.create({
            key: 'GLOBAL_CONFIG',
            forceHotWindowOpen: false,
            verifiedPromotionalBudget: 5000,
            businessRegistrationNo: 'LTRIX-GLOBAL-RC-20268841',
            usdtEnabled: true,
            usdtBep20Address: '0x71C0000000000000000000000000000000008841',
            usdtConfirmations: 12,
            nairaDepositEnabled: true,
            nairaExchangeRate: 1500,
            nairaBankInstructions: 'Include your LTRIX Deposit Reference in the bank transfer narration.',
            nairaBankName: 'Moniepoint MFB',
            nairaBankAccountNumber: '8012345678',
            nairaBankAccountName: 'LTRIX DIGITAL SERVICES',
            nairaBankAccounts: [{
                bankName: 'Moniepoint MFB',
                accountNumber: '8012345678',
                accountName: 'LTRIX DIGITAL SERVICES',
                isActive: true
            }]
        });
    } else {
        let modified = false;

        if (!settings.nairaBankAccounts || settings.nairaBankAccounts.length === 0) {
            if (settings.nairaBankName) {
                settings.nairaBankAccounts = [{
                    bankName: settings.nairaBankName,
                    accountNumber: settings.nairaBankAccountNumber || '8012345678',
                    accountName: settings.nairaBankAccountName || 'LTRIX DIGITAL SERVICES',
                    isActive: true
                }];
            } else {
                settings.nairaBankAccounts = [{
                    bankName: 'Moniepoint MFB',
                    accountNumber: '8012345678',
                    accountName: 'LTRIX DIGITAL SERVICES',
                    isActive: true
                }];
            }
            modified = true;
        }

        const primaryBank = settings.nairaBankAccounts.find(b => b.isActive) || settings.nairaBankAccounts[0];
        if (primaryBank && (!settings.nairaBankName || !settings.nairaBankAccountNumber || !settings.nairaBankAccountName)) {
            settings.nairaBankName = primaryBank.bankName;
            settings.nairaBankAccountNumber = primaryBank.accountNumber;
            settings.nairaBankAccountName = primaryBank.accountName;
            modified = true;
        }

        if (settings.nairaExchangeRate === undefined) { settings.nairaExchangeRate = 1500; modified = true; }
        if (settings.usdtBep20Address === undefined) { settings.usdtBep20Address = '0x71C0000000000000000000000000000000008841'; modified = true; }
        if (settings.usdtEnabled === undefined) { settings.usdtEnabled = true; modified = true; }
        if (settings.nairaDepositEnabled === undefined) { settings.nairaDepositEnabled = true; modified = true; }

        if (modified) await settings.save();
    }
    return settings;
}

function getCurrentWeekContext() {
    const now = new Date();
    const day = now.getUTCDay();
    const diffToMonday = day === 0 ? -6 : 1 - day;
    const startOfWeek = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + diffToMonday, 0, 0, 0));
    const endOfWeek = new Date(startOfWeek.getTime() + 7 * 24 * 60 * 60 * 1000 - 1);

    // Calculate week number from startOfWeek (Monday) so weekKey never rolls over early on Sunday
    const oneJan = new Date(Date.UTC(startOfWeek.getUTCFullYear(), 0, 1));
    const weekNumber = Math.ceil((((startOfWeek - oneJan) / 86400000) + oneJan.getUTCDay() + 1) / 7);
    const weekKey = `${startOfWeek.getUTCFullYear()}-W${String(weekNumber).padStart(2, '0')}`;

    return { startOfWeek, endOfWeek, weekKey };
}

function getStartOfUtcDay(date = new Date()) {
    return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate(), 0, 0, 0, 0));
}

async function getHotWindowStatus() {
    const settings = await ensureSystemSettings();
    const forceOpen = settings ? settings.forceHotWindowOpen : false;

    const now = new Date();
    const watTime = new Date(now.getTime() + (60 * 60 * 1000));
    const day = watTime.getUTCDay();
    const hour = watTime.getUTCHours();

    const isScheduledSundayWindow = (day === 0 && hour >= 9 && hour < 12);
    return {
        isOpen: forceOpen || isScheduledSundayWindow,
        isScheduledSundayWindow,
        forceHotWindowOpen: forceOpen,
        verifiedPromotionalBudget: settings ? settings.verifiedPromotionalBudget : 5000
    };
}

// ==========================================
// 3. AUTHENTICATION MIDDLEWARE
// ==========================================
async function auth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Authentication required' });
    const token = header.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Explicitly reject SUPERADMIN tokens from member APIs
        if (decoded.role === 'SUPERADMIN' || !decoded.userId) {
            return res.status(403).json({ error: 'Admin account cannot access member dashboard' });
        }

        const user = await User.findById(decoded.userId);
        if (!user) return res.status(401).json({ error: 'User not found' });

        // SUSPENDED users are blocked entirely
        if (user.status === 'SUSPENDED') {
            return res.status(403).json({ error: 'Your account has been suspended.' });
        }

        // LOCKED users can login/use platform, but specific routes (like withdrawals) will block them

        req.userId = decoded.userId;
        req.role = user.role;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
}

async function adminAuth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Admin authentication required' });
    const token = header.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded.role === 'SUPERADMIN') {
            req.adminPhone = decoded.adminPhone || 'classic84';
            req.role = 'SUPERADMIN';
            return next();
        }

        if (!decoded.userId) {
            return res.status(403).json({ error: 'Admin access denied' });
        }

        const user = await User.findById(decoded.userId);
        if (!user || user.status === 'SUSPENDED' || (user.role !== 'ADMIN' && user.role !== 'SUPERADMIN')) {
            return res.status(403).json({ error: 'Admin access denied' });
        }

        req.userId = user._id;
        req.adminPhone = user.username || user.email || 'classic84';
        req.role = user.role;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired admin token' });
    }
}

function superAdminAuth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Super Admin authentication required' });
    const token = header.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.role !== 'SUPERADMIN') {
            return res.status(403).json({ error: 'Super Admin access denied' });
        }
        req.adminPhone = decoded.adminPhone || 'classic84';
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired admin token' });
    }
}

// ==========================================
// 4. UNIFIED AUTH & MEMBER API ROUTES
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, phone, password, referralCode } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        const expectedAdmin = (process.env.ADMIN_PHONE || 'classic84').toLowerCase();
        if (username.toLowerCase() === expectedAdmin || email.toLowerCase() === expectedAdmin) {
            return res.status(400).json({ error: 'This identifier is reserved' });
        }

        const existing = await User.findOne({
            $or: [{ email: email.toLowerCase() }, { username: username.trim() }]
        });
        if (existing) return res.status(400).json({ error: 'Username or email already in use' });

        let referrer = null;
        if (referralCode) {
            referrer = await User.findOne({ referralCode: referralCode.trim().toUpperCase() });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        const cleanUser = username.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 5);
        const myRefCode = `LTRIX-${cleanUser}${Math.floor(100 + Math.random() * 900)}`;

        const user = await User.create({
            username: username.trim(),
            email: email.toLowerCase().trim(),
            phone: phone || '',
            passwordHash,
            referralCode: myRefCode,
            referredBy: referrer ? referrer._id : null,
            role: 'USER',
            status: 'ACTIVE'
        });

        await Notification.create({
            userId: user._id,
            title: 'Welcome to LTRIX',
            message: `Your LTRIX account is active. Your unique referral code is ${myRefCode}.`
        });

        if (referrer) {
            await Notification.create({
                userId: referrer._id,
                title: 'New Member Joined via Your Referral!',
                message: `${user.username} registered using your referral code (${referrer.referralCode}). You will earn 6% when they activate a package.`
            });
        }

        const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, role: user.role, username: user.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, email, password } = req.body;
        const loginInput = (identifier || email || '').trim();
        if (!loginInput || !password) {
            return res.status(400).json({ error: 'Login ID/Email and password are required' });
        }

        const expectedAdminPhone = process.env.ADMIN_PHONE || 'classic84';
        const expectedAdminPassword = process.env.ADMIN_PASSWORD || 'All@star26';

        if (loginInput === expectedAdminPhone && password === expectedAdminPassword) {
            const token = jwt.sign(
                { role: 'SUPERADMIN', adminPhone: expectedAdminPhone },
                process.env.JWT_SECRET,
                { expiresIn: '12h' }
            );
            return res.json({ token, role: 'SUPERADMIN', username: expectedAdminPhone });
        }

        const user = await User.findOne({
            $or: [
                { email: loginInput.toLowerCase() },
                { username: loginInput },
                { phone: loginInput }
            ]
        });

        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        // SUSPENDED users cannot log in
        if (user.status === 'SUSPENDED') {
            return res.status(403).json({ error: 'Your account has been suspended.' });
        }

        const valid = await bcrypt.compare(password, user.passwordHash);
        if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, role: user.role, username: user.username });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/forgot-password', passwordResetLimiter, async (req, res) => {
    try {
        const identifier = String(req.body.identifier || '').trim();
        if (!identifier) {
            return res.status(400).json({ error: 'Please enter your registered Email or Username.' });
        }

        const user = await User.findOne({
            $or: [
                { email: identifier.toLowerCase() },
                { username: identifier }
            ]
        });

        if (!user) {
            return res.status(404).json({ error: 'No account found with that Email or Username.' });
        }

        if (user.status === 'SUSPENDED') {
            return res.status(403).json({ error: 'Your account has been suspended.' });
        }

        // Generate 6-digit OTP valid for 15 minutes
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

        user.resetPasswordOtpHash = otpHash;
        user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);
        await user.save();

        const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; background: #0f172a; color: #f8fafc; padding: 24px; border-radius: 12px; border: 1px solid #1e293b;">
                <h2 style="color: #34d399; margin-top: 0;">💎 LTRIX Password Reset</h2>
                <p style="color: #cbd5e1; font-size: 14px;">Hello <strong>${user.username}</strong>,</p>
                <p style="color: #cbd5e1; font-size: 14px;">Use the 6-digit verification code below to reset your LTRIX account password. This code expires in <strong>15 minutes</strong>:</p>
                <div style="background: #020617; border: 1px solid #10b981; border-radius: 8px; padding: 16px; text-align: center; margin: 20px 0;">
                    <span style="font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #34d399; font-family: monospace;">${otp}</span>
                </div>
                <p style="color: #94a3b8; font-size: 12px;">If you did not request this password reset, you can safely ignore this email.</p>
            </div>
        `;

        await sendResendEmail({
            to: user.email,
            subject: 'LTRIX Password Reset Verification Code',
            html: emailHtml
        });

        const [localPart, domainPart] = user.email.split('@');
        const maskedEmail = `${localPart.slice(0, 2)}***@${domainPart}`;

        res.json({
            message: `A 6-digit reset code has been sent to ${maskedEmail}.`,
            email: user.email
        });
    } catch (err) {
        console.error('Forgot Password Error:', err.response?.data || err.message);
        res.status(500).json({
            error: err.response?.data?.message || 'Failed to send reset email. Please verify your Resend sender configuration.'
        });
    }
});

app.post('/api/auth/reset-password', passwordResetLimiter, async (req, res) => {
    try {
        const identifier = String(req.body.identifier || '').trim();
        const otp = String(req.body.otp || '').trim();
        const newPassword = String(req.body.newPassword || '');

        if (!identifier || !otp || !newPassword) {
            return res.status(400).json({ error: 'All fields (Account, 6-digit OTP, and New Password) are required.' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
        }

        const otpHash = crypto.createHash('sha256').update(otp).digest('hex');

        const user = await User.findOne({
            $or: [
                { email: identifier.toLowerCase() },
                { username: identifier }
            ],
            resetPasswordOtpHash: otpHash,
            resetPasswordExpires: { $gt: new Date() }
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired 6-digit reset code.' });
        }

        user.passwordHash = await bcrypt.hash(newPassword, 10);
        user.resetPasswordOtpHash = null;
        user.resetPasswordExpires = null;
        await user.save();

        await Notification.create({
            userId: user._id,
            title: '🔐 Password Reset Successful',
            message: 'Your LTRIX account password was recently reset via email verification.'
        });

        res.json({ message: 'Password reset successful! You can now log in with your new password.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Public Endpoint for Landing Page Activity Cards
app.get('/api/public/platform-stats', async (req, res) => {
    try {
        const totalMembersCount = await User.countDocuments();

        // Fetch the 3 most recent completed withdrawals
        const recentWithdrawals = await Transaction.find({ type: 'WITHDRAWAL', status: 'COMPLETED' })
            .sort({ createdAt: -1 })
            .limit(3)
            .populate('userId', 'username');

        // Map data safely for public display
        const recentPayouts = recentWithdrawals.map(w => ({
            username: w.userId ? w.userId.username : 'Member',
            amount: w.amount,
            time: w.createdAt
        }));

        res.json({
            totalMembersCount,
            recentPayouts
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Member Dashboard
app.get('/api/dashboard', auth, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-passwordHash');
        if (!user) return res.status(404).json({ error: 'User not found' });

        const settings = await ensureSystemSettings();
        const standardPlans = await PackagePlan.find({ category: 'STANDARD' }).sort({ price: 1 });
        const hotPlans = await PackagePlan.find({ category: 'HOT' }).sort({ price: 1 });
        const hotWindow = await getHotWindowStatus();

        const thirtyMinsAgo = new Date(Date.now() - 30 * 60 * 1000);
        await Transaction.updateMany(
            { userId: req.userId, type: 'DEPOSIT', isUsdtDeposit: true, status: 'PENDING', createdAt: { $lt: thirtyMinsAgo } },
            { $set: { status: 'REJECTED', description: 'USDT BEP20 Deposit Request auto-expired (30m timeout)' } }
        );

        const activePackages = await ActivePackage.find({ userId: req.userId }).sort({ purchasedAt: -1 });
        const transactions = await Transaction.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(100);
        const notifications = await Notification.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(30);
        const tickets = await Ticket.find({ userId: req.userId }).sort({ createdAt: -1 });

        const pendingUsdtDeposit = await Transaction.findOne({
            userId: req.userId,
            type: 'DEPOSIT',
            isUsdtDeposit: true,
            status: 'PENDING'
        });

        const pendingNairaDeposit = await Transaction.findOne({
            userId: req.userId,
            type: 'DEPOSIT',
            isNairaDeposit: true,
            status: { $in: ['PENDING', 'PROCESSING'] }
        });

        const startOfTodayUtc = getStartOfUtcDay();
        const nextWithdrawalResetAt = new Date(startOfTodayUtc.getTime() + 24 * 60 * 60 * 1000);
        const todayWithdrawal = await Transaction.findOne({
            userId: req.userId,
            type: 'WITHDRAWAL',
            status: { $in: ['PENDING', 'PROCESSING', 'COMPLETED'] },
            createdAt: { $gte: startOfTodayUtc }
        }).sort({ createdAt: -1 });
        const withdrawalLimitReached = !!todayWithdrawal;

        const rawReferrals = await User.find({ referredBy: req.userId }).select('username createdAt').sort({ createdAt: -1 });
        const referralIds = rawReferrals.map(r => r._id);
        const referralPackages = await ActivePackage.find({ userId: { $in: referralIds } });

        const { startOfWeek, endOfWeek, weekKey } = getCurrentWeekContext();
        let weeklyEligibleReferralsCount = 0;

        const referrals = rawReferrals.map(ref => {
            const pkgs = referralPackages.filter(p => String(p.userId) === String(ref._id));
            const totalActivatedVolume = pkgs.reduce((s, p) => s + p.price, 0);
            const commissionGenerated = round2(totalActivatedVolume * 0.06);
            const isEligible = pkgs.length > 0;
            const activatedThisWeek = pkgs.some(p => p.purchasedAt >= startOfWeek && p.purchasedAt <= endOfWeek);
            if (activatedThisWeek) weeklyEligibleReferralsCount += 1;

            return {
                _id: ref._id,
                username: ref.username,
                createdAt: ref.createdAt,
                isEligible,
                packagesCount: pkgs.length,
                totalActivatedVolume,
                commissionGenerated,
                activatedThisWeek
            };
        });

        const claimsThisWeek = await WeeklyClaim.find({ userId: req.userId, weekKey });
        const builderClaimed = claimsThisWeek.some(c => c.tier === 'BUILDER_15');
        const leaderClaimed = claimsThisWeek.some(c => c.tier === 'LEADER_40');

        const totalMembersCount = await User.countDocuments();
        const totalActivePackagesCount = await ActivePackage.countDocuments({ status: 'ACTIVE' });
        const completedWithdrawals = await Transaction.find({ type: 'WITHDRAWAL', status: 'COMPLETED' });
        const totalVerifiedWithdrawalsVolume = completedWithdrawals.reduce((s, t) => s + (t.amount - t.fee), 0);

        const pendingIncome = activePackages
            .filter(p => p.status === 'ACTIVE')
            .reduce((sum, p) => sum + ((p.durationDays - p.daysCredited) * p.dailyIncome), 0);

        const primaryBank = (settings.nairaBankAccounts || []).find(b => b.isActive) || (settings.nairaBankAccounts || [])[0] || {};

        res.json({
            user,
            pendingIncome,
            withdrawalLimit: {
                dailyLimit: 1,
                usedToday: withdrawalLimitReached ? 1 : 0,
                limitReached: withdrawalLimitReached,
                resetsAt: nextWithdrawalResetAt,
                timezone: 'UTC',
                lastWithdrawalAt: todayWithdrawal ? todayWithdrawal.createdAt : null,
                lastWithdrawalStatus: todayWithdrawal ? todayWithdrawal.status : null
            },
            paymentSettings: {
                usdtEnabled: settings.usdtEnabled,
                usdtNetwork: 'BNB Smart Chain (BEP20)',
                usdtBep20Address: settings.usdtBep20Address,
                usdtConfirmations: settings.usdtConfirmations,
                nairaDepositEnabled: settings.nairaDepositEnabled,
                nairaExchangeRate: settings.nairaExchangeRate,
                nairaBankInstructions: settings.nairaBankInstructions,
                nairaBankName: primaryBank.bankName || settings.nairaBankName || 'Unavailable',
                nairaBankAccountNumber: primaryBank.accountNumber || settings.nairaBankAccountNumber || 'Unavailable',
                nairaBankAccountName: primaryBank.accountName || settings.nairaBankAccountName || 'Unavailable'
            },
            pendingUsdtDeposit,
            pendingNairaDeposit,
            standardPlans,
            hotPlans,
            hotWindow,
            activePackages,
            transactions,
            notifications,
            referrals,
            weeklyRewards: {
                weekKey,
                startOfWeek,
                endOfWeek,
                weeklyEligibleReferralsCount,
                builderClaimed,
                leaderClaimed,
                verifiedPromotionalBudget: settings.verifiedPromotionalBudget
            },
            transparency: {
                businessRegistrationNo: settings.businessRegistrationNo,
                verifiedPromotionalBudget: settings.verifiedPromotionalBudget,
                totalMembersCount,
                totalActivePackagesCount,
                totalVerifiedWithdrawalsVolume
            },
            tickets
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});
// ==========================================================
// 5. USDT BEP20 UNIQUE 3-DECIMAL DEPOSIT & NGN BANK DEPOSIT
// ==========================================================

app.post('/api/wallet/usdt-deposit-request', auth, usdtRequestLimiter, async (req, res) => {
    try {
        const rawAmount = Number(req.body.amount);
        const baseAmount = round2(rawAmount);

        if (!isFinite(baseAmount) || baseAmount < 5) {
            return res.status(400).json({ error: 'Minimum deposit is $5.00 USDT.' });
        }

        const settings = await ensureSystemSettings();
        if (!settings.usdtEnabled || !settings.usdtBep20Address || !settings.usdtBep20Address.trim()) {
            return res.status(403).json({ error: 'USDT BEP20 deposits are currently unavailable.' });
        }

        const thirtyMinsAgo = new Date(Date.now() - 30 * 60 * 1000);
        await Transaction.updateMany(
            { userId: req.userId, status: 'PENDING', type: 'DEPOSIT', isUsdtDeposit: true, createdAt: { $lt: thirtyMinsAgo } },
            { $set: { status: 'REJECTED', description: 'USDT Deposit Request auto-expired' } }
        );

        const existing = await Transaction.findOne({
            userId: req.userId,
            type: 'DEPOSIT',
            isUsdtDeposit: true,
            status: 'PENDING'
        });
        if (existing) {
            return res.json({
                success: true,
                requestedAmount: existing.requestedAmount,
                exactAmount: existing.adjustedAmount,
                decimalOffset: existing.decimalOffset,
                network: 'BEP20',
                address: settings.usdtBep20Address,
                confirmations: settings.usdtConfirmations,
                reference: existing.reference
            });
        }

        const baseMills = Math.round(baseAmount * 1000);
        let uniqueAdjustedAmount = 0;
        let chosenOffset = 0;

        const shuffledOffsets = Array.from({ length: 100 }, (_, i) => i + 1).sort(() => Math.random() - 0.5);
        for (const millOffset of shuffledOffsets) {
            const candidate = round3((baseMills + millOffset) / 1000);
            const conflict = await Transaction.exists({
                type: 'DEPOSIT',
                isUsdtDeposit: true,
                status: 'PENDING',
                adjustedAmount: candidate
            });
            if (!conflict) {
                uniqueAdjustedAmount = candidate;
                chosenOffset = round3(millOffset / 1000);
                break;
            }
        }

        if (!uniqueAdjustedAmount) {
            return res.status(500).json({
                error: 'High volume for this exact base amount right now. Please try a different amount (e.g., $11 instead of $10).'
            });
        }

        const reference = `UDEP-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

        const newTx = await Transaction.create({
            userId: req.userId,
            type: 'DEPOSIT',
            amount: uniqueAdjustedAmount,
            requestedAmount: baseAmount,
            adjustedAmount: uniqueAdjustedAmount,
            decimalOffset: chosenOffset,
            fee: 0,
            netAmount: uniqueAdjustedAmount,
            paymentMethod: 'USDT_BEP20',
            paymentCurrency: 'USDT',
            usdtNetwork: 'BEP20',
            isUsdtDeposit: true,
            reference,
            status: 'PENDING',
            description: `USDT (BEP20) Deposit Request — Base: $${baseAmount.toFixed(2)} | Exact Transfer: ${uniqueAdjustedAmount.toFixed(3)} USDT`
        });

        res.json({
            success: true,
            requestedAmount: baseAmount,
            exactAmount: newTx.adjustedAmount,
            decimalOffset: chosenOffset,
            network: 'BEP20',
            address: settings.usdtBep20Address,
            confirmations: settings.usdtConfirmations,
            reference
        });
    } catch (err) {
        console.error('USDT request error:', err);
        res.status(500).json({ error: 'Internal server error generating USDT deposit request.' });
    }
});

app.post('/api/wallet/usdt-deposit-request/cancel', auth, async (req, res) => {
    try {
        await Transaction.updateMany(
            { userId: req.userId, type: 'DEPOSIT', isUsdtDeposit: true, status: 'PENDING' },
            { $set: { status: 'REJECTED', description: 'USDT BEP20 Deposit Request cancelled by user' } }
        );
        res.json({ success: true, message: 'Pending USDT deposit request cancelled.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/wallet/deposit-usdt', auth, async (req, res) => {
    try {
        const { txid } = req.body;
        const pendingTx = await Transaction.findOne({
            userId: req.userId,
            type: 'DEPOSIT',
            isUsdtDeposit: true,
            status: 'PENDING'
        });

        if (!pendingTx) {
            return res.status(400).json({ error: 'No pending USDT deposit request found. Please generate a new request first.' });
        }

        const settings = await ensureSystemSettings();
        if (!settings.usdtEnabled) {
            return res.status(403).json({ error: 'USDT BEP20 deposits are currently disabled.' });
        }

        const platformAddress = String(settings.usdtBep20Address || '').trim();
        const requiredConfirmations = Number(settings.usdtConfirmations) || 12;
        const expectedAmount = round3(pendingTx.adjustedAmount);

        const effectiveTxid = normalizeEvmTxid(txid);
        if (!effectiveTxid) {
            return res.status(400).json({
                error: 'Invalid BEP20 transaction hash format. Please paste the full 64-character hex TXID.'
            });
        }

        const existingTx = await Transaction.findOne({ txid: effectiveTxid });
        const existingManual = await ManualCreditAudit.findOne({ txidOrReference: effectiveTxid });
        if (existingTx || existingManual) {
            return res.status(400).json({ error: 'This Transaction Hash (TXID) has already been used.' });
        }

        let actualAmountReceived = 0;
        try {
            actualAmountReceived = await verifyBep20UsdtDeposit({
                txid: effectiveTxid,
                platformAddress,
                requiredConfirmations
            });
        } catch (verifyErr) {
            return res.status(400).json({ error: verifyErr.message });
        }

        const roundedReceived = round3(actualAmountReceived);
        if (roundedReceived !== expectedAmount) {
            return res.status(400).json({
                error: `Exact Decimal Mismatch! Your request required EXACTLY ${expectedAmount.toFixed(3)} USDT, but the blockchain transfer was ${roundedReceived.toFixed(3)} USDT. Please contact support or ask Admin for a Manual Credit with your TXID.`
            });
        }

        const updatedTx = await Transaction.findOneAndUpdate(
            { _id: pendingTx._id, status: 'PENDING' },
            {
                $set: {
                    status: 'COMPLETED',
                    txid: effectiveTxid,
                    description: `Verified USDT (BEP20) Deposit (${expectedAmount.toFixed(3)} USDT)`
                }
            },
            { new: true }
        );

        if (!updatedTx) {
            return res.status(400).json({ error: 'Deposit request already processed or expired.' });
        }

        const userAfterCredit = await User.findByIdAndUpdate(
            req.userId,
            { $inc: { availableBalance: expectedAmount } },
            { new: true }
        );
        if (userAfterCredit) {
            userAfterCredit.availableBalance = round3(userAfterCredit.availableBalance);
            await userAfterCredit.save();
        }

        await Notification.create({
            userId: req.userId,
            title: 'USDT (BEP20) Deposit Verified & Credited!',
            message: `Your transfer of ${expectedAmount.toFixed(3)} USDT (Ref: ${updatedTx.reference}) was verified on BNB Smart Chain and credited to your wallet.`
        });

        res.json({
            success: true,
            message: `Successfully verified and credited ${expectedAmount.toFixed(3)} USDT to your wallet!`,
            transaction: updatedTx
        });
    } catch (err) {
        console.error('Deposit USDT Error:', err.message);
        res.status(500).json({ error: 'Error verifying blockchain transaction. Please ensure the TXID is valid.' });
    }
});

app.post('/api/wallet/naira-deposit-request', auth, async (req, res) => {
    try {
        const usdAmount = round2(Number(req.body.usdAmount));
        if (!isFinite(usdAmount) || usdAmount < 5) {
            return res.status(400).json({ error: 'Minimum deposit is $5.00 USD equivalent.' });
        }

        const settings = await ensureSystemSettings();
        if (!settings.nairaDepositEnabled) {
            return res.status(403).json({ error: 'Nigerian Naira (NGN) deposits are currently disabled.' });
        }

        const existing = await Transaction.findOne({
            userId: req.userId,
            type: 'DEPOSIT',
            isNairaDeposit: true,
            status: { $in: ['PENDING', 'PROCESSING'] }
        });

        if (existing) {
            return res.json({ success: true, deposit: existing });
        }

        const activeBanks = settings.nairaBankAccounts.filter(b => b.isActive);
        if (activeBanks.length === 0) {
            return res.status(400).json({ error: 'No active NGN bank accounts are configured. Please contact support.' });
        }

        const updatedSettings = await SystemSetting.findOneAndUpdate(
            { key: 'GLOBAL_CONFIG' },
            { $inc: { nairaRotationCounter: 1 } },
            { new: true }
        );

        const currentCount = updatedSettings.nairaRotationCounter - 1;
        const assignedBank = activeBanks[currentCount % activeBanks.length];

        const rate = Number(settings.nairaExchangeRate) || 1500;
        const nairaAmount = round2(usdAmount * rate);
        const reference = `NDEP-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

        const deposit = await Transaction.create({
            userId: req.userId,
            type: 'DEPOSIT',
            amount: usdAmount,
            requestedAmount: usdAmount,
            adjustedAmount: usdAmount,
            decimalOffset: 0,
            fee: 0,
            netAmount: usdAmount,
            paymentMethod: 'NGN_BANK',
            paymentCurrency: 'NGN',
            isNairaDeposit: true,
            nairaRequestedAmount: nairaAmount,
            exchangeRateUsed: rate,
            assignedBankDetails: {
                bankName: assignedBank.bankName,
                accountNumber: assignedBank.accountNumber,
                accountName: assignedBank.accountName
            },
            reference,
            status: 'PENDING',
            description: `NGN Bank Deposit: ₦${nairaAmount.toLocaleString()} ($${usdAmount.toFixed(2)} @ ₦${rate}/$1)`
        });

        res.json({ success: true, deposit });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/wallet/naira-deposit-confirm', auth, async (req, res) => {
    try {
        const { senderInfo } = req.body;
        const tx = await Transaction.findOne({
            userId: req.userId,
            type: 'DEPOSIT',
            isNairaDeposit: true,
            status: 'PENDING'
        });

        if (!tx) return res.status(404).json({ error: 'No pending Naira deposit request found.' });

        tx.status = 'PROCESSING';
        if (senderInfo && String(senderInfo).trim()) {
            tx.txid = String(senderInfo).trim();
            tx.description = `${tx.description} | Sender/Ref: ${String(senderInfo).trim()}`;
        }
        await tx.save();

        await Notification.create({
            userId: req.userId,
            title: 'NGN Transfer Marked as Processing',
            message: `Your ₦${tx.nairaRequestedAmount.toLocaleString()} deposit (${tx.reference}) is now being verified by LTRIX Admin.`
        });

        res.json({
            success: true,
            message: 'Transfer submitted for verification! Your wallet will be credited as soon as Admin confirms receipt.',
            deposit: tx
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/wallet/naira-deposit-cancel', auth, async (req, res) => {
    try {
        await Transaction.updateMany(
            { userId: req.userId, type: 'DEPOSIT', isNairaDeposit: true, status: 'PENDING' },
            { $set: { status: 'REJECTED', description: 'NGN Deposit Request cancelled by user' } }
        );
        res.json({ success: true, message: 'Naira deposit request cancelled.' });
    } catch (err) {
        // Corrected: added the missing colon after "error"
        res.status(500).json({ error: err.message });
    }
});

// ==========================================================
// 6. USDT-ONLY WITHDRAWALS, REWARDS, NOTIFICATIONS & PACKAGES
// ==========================================================

app.put('/api/wallet/withdrawal-address', auth, async (req, res) => {
    try {
        const address = String(req.body.usdtWithdrawalAddress || '').trim();
        if (!isValidBep20Address(address)) {
            return res.status(400).json({
                error: 'Invalid USDT (BEP20) wallet address. Must be a 42-character BNB Smart Chain address starting with 0x.'
            });
        }

        const user = await User.findByIdAndUpdate(
            req.userId,
            { $set: { usdtWithdrawalAddress: address } },
            { new: true }
        ).select('-passwordHash');

        res.json({
            message: 'Default USDT (BEP20) withdrawal wallet saved!',
            usdtWithdrawalAddress: user.usdtWithdrawalAddress
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/wallet/withdraw', auth, async (req, res) => {
    try {
        const amount = round2(Number(req.body.amount));
        if (!amount || amount < 5) {
            return res.status(400).json({ error: 'Minimum LTRIX withdrawal is $5.00 USDT' });
        }

        const startOfTodayUtc = getStartOfUtcDay();
        const existingWithdrawalToday = await Transaction.findOne({
            userId: req.userId,
            type: 'WITHDRAWAL',
            status: { $in: ['PENDING', 'PROCESSING', 'COMPLETED'] },
            createdAt: { $gte: startOfTodayUtc }
        });
        if (existingWithdrawalToday) {
            const nextResetAt = new Date(startOfTodayUtc.getTime() + 24 * 60 * 60 * 1000);
            return res.status(429).json({
                error: `Daily withdrawal limit reached. LTRIX allows exactly 1 withdrawal request per day (UTC). Your next withdrawal will be available after ${nextResetAt.toISOString()} (00:00 UTC).`
            });
        }

        const userCheck = await User.findById(req.userId);
        if (!userCheck) return res.status(404).json({ error: 'User not found' });

        // LOCKED users cannot withdraw
        if (userCheck.status === 'LOCKED') {
            return res.status(403).json({ error: 'Your account is currently locked from making withdrawals. Please contact support.' });
        }

        const targetAddress = String(req.body.usdtAddress || userCheck.usdtWithdrawalAddress || '').trim();
        if (!isValidBep20Address(targetAddress)) {
            return res.status(400).json({
                error: 'Withdrawals are processed exclusively in USDT (BEP20). Please provide a valid BEP20 wallet address starting with 0x.'
            });
        }

        const fee = round2(amount * 0.05);
        const netAmount = round2(amount - fee);

        // Atomic balance check and deduction to prevent concurrent race conditions
        const user = await User.findOneAndUpdate(
            {
                _id: req.userId,
                status: { $ne: 'LOCKED' },
                availableBalance: { $gte: amount }
            },
            {
                $inc: { availableBalance: -amount },
                $set: { usdtWithdrawalAddress: targetAddress }
            },
            { new: true }
        ).select('-passwordHash');

        if (!user) {
            return res.status(400).json({ error: 'Insufficient available balance' });
        }

        user.availableBalance = round3(user.availableBalance);
        await user.save();

        const reference = `WDR-${Date.now()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;

        await Transaction.create({
            userId: req.userId,
            type: 'WITHDRAWAL',
            amount,
            fee,
            netAmount: -amount,
            paymentMethod: 'USDT_BEP20',
            paymentCurrency: 'USDT',
            usdtNetwork: 'BEP20',
            withdrawalAddress: targetAddress,
            withdrawalNetwork: 'BEP20',
            reference,
            description: `USDT (BEP20) Withdrawal: $${amount.toFixed(2)} (5% Fee: $${fee.toFixed(2)}, Net Payout: ${netAmount.toFixed(2)} USDT) → ${targetAddress}`,
            status: 'PENDING'
        });

        await Notification.create({
            userId: req.userId,
            title: 'USDT (BEP20) Withdrawal Submitted',
            message: `Your withdrawal of ${netAmount.toFixed(2)} USDT (after 5% fee) to ${targetAddress} is pending admin verification.`
        });

        res.json({
            message: `USDT (BEP20) withdrawal submitted! Net payout of ${netAmount.toFixed(2)} USDT to ${targetAddress} is pending verification.`,
            user
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/rewards/claim-weekly', auth, async (req, res) => {
    try {
        const { tier } = req.body;
        const tierConfig = {
            BUILDER_15: { requiredReferrals: 5, rewardAmount: 15, label: 'Builder Weekly Reward ($15)' },
            LEADER_40: { requiredReferrals: 10, rewardAmount: 40, label: 'Leader Weekly Reward ($40)' }
        }[tier];

        if (!tierConfig) return res.status(400).json({ error: 'Invalid weekly reward tier' });

        const { startOfWeek, endOfWeek, weekKey } = getCurrentWeekContext();
        const existingClaim = await WeeklyClaim.findOne({ userId: req.userId, weekKey, tier });
        if (existingClaim) {
            return res.status(400).json({ error: `You have already claimed the ${tierConfig.label} for week ${weekKey}.` });
        }

        const referredUsers = await User.find({ referredBy: req.userId }).select('_id');
        const refIds = referredUsers.map(u => u._id);
        const activeRefsThisWeek = await ActivePackage.distinct('userId', {
            userId: { $in: refIds },
            purchasedAt: { $gte: startOfWeek, $lte: endOfWeek }
        });

        if (activeRefsThisWeek.length < tierConfig.requiredReferrals) {
            return res.status(400).json({
                error: `Eligibility not met: You have ${activeRefsThisWeek.length}/${tierConfig.requiredReferrals} qualifying active referrals this week.`
            });
        }

        await ensureSystemSettings();
        const updatedSettings = await SystemSetting.findOneAndUpdate(
            {
                key: 'GLOBAL_CONFIG',
                verifiedPromotionalBudget: { $gte: tierConfig.rewardAmount }
            },
            {
                $inc: { verifiedPromotionalBudget: -tierConfig.rewardAmount }
            },
            { new: true }
        );

        if (!updatedSettings) {
            return res.status(400).json({ error: 'Promotional budget exhausted for this cycle. Please contact support.' });
        }

        await WeeklyClaim.create({ userId: req.userId, weekKey, tier, amount: tierConfig.rewardAmount });
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            { $inc: { availableBalance: tierConfig.rewardAmount } },
            { new: true }
        );
        if (updatedUser) {
            updatedUser.availableBalance = round3(updatedUser.availableBalance);
            await updatedUser.save();
        }

        await Transaction.create({
            userId: req.userId,
            type: 'WEEKLY_REWARD',
            amount: tierConfig.rewardAmount,
            fee: 0,
            netAmount: tierConfig.rewardAmount,
            description: `${tierConfig.label} — Settled from Verified Promotional Budget (${weekKey})`,
            status: 'COMPLETED'
        });

        await Notification.create({
            userId: req.userId,
            title: '🏆 Weekly Promotional Reward Claimed!',
            message: `$${tierConfig.rewardAmount.toFixed(2)} USD (${tierConfig.label}) has been credited to your available wallet balance.`
        });

        res.json({ message: `${tierConfig.label} credited to your wallet!` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/notifications/read-all', auth, async (req, res) => {
    try {
        await Notification.updateMany({ userId: req.userId, isRead: false }, { $set: { isRead: true } });
        res.json({ message: 'All notifications marked as read' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch('/api/notifications/:id/read', auth, async (req, res) => {
    try {
        await Notification.findOneAndUpdate({ _id: req.params.id, userId: req.userId }, { $set: { isRead: true } });
        res.json({ message: 'Notification marked as read' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/packages/purchase', auth, async (req, res) => {
    try {
        const { planId } = req.body;
        const plan = await PackagePlan.findById(planId);
        if (!plan) return res.status(404).json({ error: 'LTRIX Package not found' });
        if (plan.isLocked) return res.status(400).json({ error: 'This LTRIX package tier is currently locked' });

        const existingCount = await ActivePackage.countDocuments({ userId: req.userId, planId: plan._id });
        if (existingCount >= plan.purchaseLimit) {
            return res.status(400).json({ error: `Purchase limit reached (${plan.purchaseLimit}x max for this package)` });
        }

        if (plan.category === 'HOT') {
            const hotWindow = await getHotWindowStatus();
            if (!hotWindow.isOpen) {
                return res.status(400).json({
                    error: '🔥 Hot Plans are only open on Sundays between 9:00 AM and 12:00 PM!'
                });
            }
        }

        const netBalanceDelta = round3(-plan.price + plan.dailyIncome);

        // Atomic balance check and deduction (+ immediate Day 1 dailyIncome credit)
        const user = await User.findOneAndUpdate(
            {
                _id: req.userId,
                availableBalance: { $gte: plan.price }
            },
            {
                $inc: { availableBalance: netBalanceDelta }
            },
            { new: true }
        );

        if (!user) {
            return res.status(400).json({ error: 'Insufficient balance to purchase this package' });
        }

        if (plan.category === 'HOT') {
            const claimedPlan = await PackagePlan.findOneAndUpdate(
                {
                    _id: plan._id,
                    isLocked: false,
                    $expr: { $lt: ['$slotsClaimed', '$totalSlots'] }
                },
                { $inc: { slotsClaimed: 1 } },
                { new: true }
            );

            if (!claimedPlan) {
                // Refund the balance change if slots sold out concurrently
                await User.findByIdAndUpdate(req.userId, {
                    $inc: { availableBalance: -netBalanceDelta }
                });
                return res.status(400).json({
                    error: '⚡ Sold Out! All Fastest Finger slots for this Sunday Hot Package have been claimed.'
                });
            }
        }

        user.availableBalance = round3(user.availableBalance);
        await user.save();

        const now = new Date();
        const nextPayoutAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);
        const expiresAt = new Date(now.getTime() + (plan.durationDays - 1) * 24 * 60 * 60 * 1000);
        const labelPrefix = plan.category === 'HOT' ? '🔥 HOT' : 'LTRIX';

        await ActivePackage.create({
            userId: user._id,
            planId: plan._id,
            category: plan.category,
            price: plan.price,
            dailyIncome: plan.dailyIncome,
            durationDays: plan.durationDays,
            daysCredited: 1,
            nextPayoutAt,
            expiresAt,
            status: plan.durationDays === 1 ? 'COMPLETED' : 'ACTIVE'
        });

        await Transaction.create({
            userId: user._id,
            type: 'PACKAGE_PURCHASE',
            amount: plan.price,
            fee: 0,
            netAmount: -plan.price,
            description: `Activated ${labelPrefix} $${plan.price} Package`
        });

        await Transaction.create({
            userId: user._id,
            type: 'DAILY_INCOME',
            amount: plan.dailyIncome,
            fee: 0,
            netAmount: plan.dailyIncome,
            description: `Immediate Day 1/${plan.durationDays} reward for ${labelPrefix} $${plan.price} Package`
        });

        await Notification.create({
            userId: user._id,
            title: `${labelPrefix} Package Activated!`,
            message: `Your $${plan.price} ${plan.category === 'HOT' ? 'Sunday Hot Plan' : 'package'} is active! Day 1 reward of $${plan.dailyIncome} was credited immediately.`
        });

        if (user.referredBy) {
            const commission = round2(plan.price * 0.06);
            const refUser = await User.findByIdAndUpdate(
                user.referredBy,
                { $inc: { availableBalance: commission, referralEarnings: commission } },
                { new: true }
            );
            if (refUser) {
                refUser.availableBalance = round3(refUser.availableBalance);
                refUser.referralEarnings = round2(refUser.referralEarnings);
                await refUser.save();
            }

            await Transaction.create({
                userId: user.referredBy,
                relatedUserId: user._id,
                type: 'REFERRAL_BONUS',
                amount: commission,
                fee: 0,
                netAmount: commission,
                description: `6% LTRIX Referral Bonus from ${user.username}'s ${labelPrefix} $${plan.price} package`
            });

            await Notification.create({
                userId: user.referredBy,
                title: '🎁 6% Referral Commission Credited!',
                message: `You earned $${commission.toFixed(2)} USD (6%) from ${user.username}'s $${plan.price} package activation.`
            });
        }

        res.json({
            message: `${labelPrefix} $${plan.price} Package activated! Day 1 reward ($${plan.dailyIncome}) credited immediately.`
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/support/ticket', auth, async (req, res) => {
    try {
        const { category, subject, message } = req.body;
        if (!subject || !message) return res.status(400).json({ error: 'Subject and message are required' });

        const ticketRef = `TKT-${Math.floor(100000 + Math.random() * 900000)}`;
        const ticket = await Ticket.create({
            userId: req.userId,
            ticketRef,
            category: category || 'GENERAL',
            subject,
            message
        });

        await Notification.create({
            userId: req.userId,
            title: `Support Ticket Opened (${ticketRef})`,
            message: `We received your inquiry "${subject}". Track status in the Customer Support Centre.`
        });

        res.json({ message: `Support ticket ${ticketRef} submitted`, ticket });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================================
// 7. ADMIN API ROUTES
// ==========================================================

app.get('/api/admin/overview', adminAuth, async (req, res) => {
    try {
        const settings = await ensureSystemSettings();
        const users = await User.find().select('-passwordHash').sort({ createdAt: -1 });
        const standardPlans = await PackagePlan.find({ category: 'STANDARD' }).sort({ price: 1 });
        const hotPlans = await PackagePlan.find({ category: 'HOT' }).sort({ price: 1 });
        const hotWindow = await getHotWindowStatus();

        const pendingWithdrawals = await Transaction.find({ type: 'WITHDRAWAL', status: 'PENDING' })
            .populate('userId', 'username email phone availableBalance usdtWithdrawalAddress')
            .sort({ createdAt: -1 });

        const deposits = await Transaction.find({ type: 'DEPOSIT' })
            .populate('userId', 'username email phone availableBalance')
            .sort({ createdAt: -1 })
            .limit(150);

        const manualAuditLogs = await ManualCreditAudit.find()
            .populate('userId', 'username email')
            .sort({ createdAt: -1 })
            .limit(50);

        const tickets = await Ticket.find()
            .populate('userId', 'username email')
            .sort({ createdAt: -1 });

        res.json({
            settings,
            users,
            standardPlans,
            hotPlans,
            hotWindow,
            pendingWithdrawals,
            deposits,
            manualAuditLogs,
            tickets
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch('/api/admin/users/:id/status', adminAuth, async (req, res) => {
    try {
        const { status } = req.body;
        if (!['ACTIVE', 'SUSPENDED', 'LOCKED'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status code.' });
        }

        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.role === 'SUPERADMIN') return res.status(403).json({ error: 'Cannot modify Super Admin status.' });

        user.status = status;
        await user.save();
        res.json({ message: `User status updated to ${status}.`, user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.role === 'SUPERADMIN') return res.status(403).json({ error: 'Cannot delete a Super Admin.' });

        await User.findByIdAndDelete(req.params.id);
        await ActivePackage.deleteMany({ userId: req.params.id });
        await Notification.deleteMany({ userId: req.params.id });
        await Ticket.deleteMany({ userId: req.params.id });
        await Transaction.deleteMany({ userId: req.params.id });
        await WeeklyClaim.deleteMany({ userId: req.params.id });
        await ManualCreditAudit.deleteMany({ userId: req.params.id });

        res.json({ message: 'User and all associated data permanently deleted.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// SUPER ADMIN ONLY ROUTE
app.patch('/api/admin/users/:id/role', superAdminAuth, async (req, res) => {
    try {
        const { role } = req.body;
        if (!['USER', 'ADMIN'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role selected.' });
        }

        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.role === 'SUPERADMIN') return res.status(403).json({ error: 'Cannot modify Super Admin role.' });

        user.role = role;
        await user.save();
        res.json({ message: `User role successfully updated to ${role}.`, user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/admin/payment-settings', adminAuth, async (req, res) => {
    try {
        const {
            usdtEnabled,
            usdtBep20Address,
            usdtConfirmations,
            nairaDepositEnabled,
            nairaExchangeRate,
            nairaBankInstructions,
            nairaBankAccounts,
            nairaBankName,
            nairaBankAccountNumber,
            nairaBankAccountName
        } = req.body;

        const rateNum = Number(nairaExchangeRate);
        if (!isFinite(rateNum) || rateNum <= 0) {
            return res.status(400).json({ error: 'Exchange rate must be a valid positive number.' });
        }

        const currentSettings = await ensureSystemSettings();
        let resolvedBanks = currentSettings.nairaBankAccounts || [];

        if (Array.isArray(nairaBankAccounts) && nairaBankAccounts.length > 0) {
            resolvedBanks = nairaBankAccounts;
        } else if (nairaBankName && nairaBankAccountNumber && nairaBankAccountName) {
            resolvedBanks = [{
                bankName: String(nairaBankName).trim(),
                accountNumber: String(nairaBankAccountNumber).trim(),
                accountName: String(nairaBankAccountName).trim(),
                isActive: true
            }];
        }

        const primaryBank = resolvedBanks.find(b => b.isActive) || resolvedBanks[0] || {};

        const updated = await SystemSetting.findOneAndUpdate(
            { key: 'GLOBAL_CONFIG' },
            {
                $set: {
                    usdtEnabled: Boolean(usdtEnabled),
                    usdtBep20Address: String(usdtBep20Address || '').trim(),
                    usdtConfirmations: Math.max(1, Number(usdtConfirmations) || 12),
                    nairaDepositEnabled: Boolean(nairaDepositEnabled),
                    nairaExchangeRate: rateNum,
                    nairaBankInstructions: String(nairaBankInstructions || 'Include your LTRIX Deposit Reference in the bank transfer narration.').trim(),
                    nairaBankAccounts: resolvedBanks,
                    nairaBankName: primaryBank.bankName || '',
                    nairaBankAccountNumber: primaryBank.accountNumber || '',
                    nairaBankAccountName: primaryBank.accountName || ''
                }
            },
            { new: true, upsert: true }
        );

        res.json({
            message: 'Payment & Bank configurations saved! Changes are now live on the member deposit screen.',
            settings: updated
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/admin/users/search', adminAuth, async (req, res) => {
    try {
        const q = String(req.query.q || '').trim();
        if (!q) return res.json({ users: [] });

        const orFilters = [
            { username: { $regex: q, $options: 'i' } },
            { email: { $regex: q, $options: 'i' } }
        ];
        if (mongoose.Types.ObjectId.isValid(q)) {
            orFilters.push({ _id: q });
        }

        const users = await User.find({ $or: orFilters })
            .select('_id username email phone availableBalance referralCode createdAt')
            .limit(10);

        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/deposits/manual-credit', adminAuth, async (req, res) => {
    try {
        const {
            userId,
            amountReceived,
            paymentCurrency,
            paymentMethod,
            txidOrReference,
            adminNote
        } = req.body;

        if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ error: 'Valid target user is required.' });
        }

        const rawAmount = Number(amountReceived);
        if (!isFinite(rawAmount) || rawAmount <= 0) {
            return res.status(400).json({ error: 'Specify a valid positive amount received.' });
        }

        if (!adminNote || String(adminNote).trim().length < 5) {
            return res.status(400).json({ error: 'An explanation or internal audit note (min 5 characters) is mandatory for manual credits.' });
        }

        const user = await User.findById(userId);
        if (!user) return res.status(404).json({ error: 'Target user account not found.' });

        const settings = await ensureSystemSettings();
        const cleanRef = txidOrReference && String(txidOrReference).trim()
            ? String(txidOrReference).trim()
            : `MCRED-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

        const existingAudit = await ManualCreditAudit.findOne({ txidOrReference: cleanRef });
        const existingTx = await Transaction.findOne({
            $or: [{ txid: cleanRef }, { reference: cleanRef }],
            status: { $in: ['COMPLETED', 'MANUALLY_CREDITED'] }
        });

        if (existingAudit || existingTx) {
            return res.status(400).json({
                error: `Duplicate Prevention: TXID or Reference "${cleanRef}" has already been credited.`
            });
        }

        let usdToCredit = 0;
        const rate = Number(settings.nairaExchangeRate) || 1500;
        if (paymentCurrency === 'NGN') {
            usdToCredit = round2(rawAmount / rate);
        } else {
            usdToCredit = round3(rawAmount);
        }

        if (usdToCredit <= 0) {
            return res.status(400).json({ error: 'Calculated USD credit amount is too small.' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            user._id,
            { $inc: { availableBalance: usdToCredit } },
            { new: true }
        );
        if (updatedUser) {
            updatedUser.availableBalance = round3(updatedUser.availableBalance);
            await updatedUser.save();
        }

        const txRecord = await Transaction.create({
            userId: user._id,
            type: 'DEPOSIT',
            amount: usdToCredit,
            requestedAmount: usdToCredit,
            adjustedAmount: usdToCredit,
            fee: 0,
            netAmount: usdToCredit,
            paymentMethod: paymentMethod === 'NGN_BANK' ? 'NGN_BANK' : 'USDT_BEP20',
            paymentCurrency: paymentCurrency === 'NGN' ? 'NGN' : 'USDT',
            usdtNetwork: paymentMethod === 'USDT_BEP20' ? 'BEP20' : '',
            isUsdtDeposit: paymentMethod === 'USDT_BEP20',
            isNairaDeposit: paymentMethod === 'NGN_BANK',
            nairaRequestedAmount: paymentCurrency === 'NGN' ? rawAmount : 0,
            exchangeRateUsed: paymentCurrency === 'NGN' ? rate : 1,
            reference: cleanRef,
            txid: cleanRef,
            status: 'MANUALLY_CREDITED',
            creditedByAdmin: req.adminPhone,
            adminNote: String(adminNote).trim(),
            description: `Manually Credited Deposit (${paymentCurrency === 'NGN' ? `₦${rawAmount.toLocaleString()} -> $${usdToCredit.toFixed(2)}` : `${usdToCredit.toFixed(3)} USDT`}) — Ref: ${cleanRef}`
        });

        const auditEntry = await ManualCreditAudit.create({
            userId: user._id,
            transactionId: txRecord._id,
            usdAmountCredited: usdToCredit,
            rawAmountReceived: rawAmount,
            paymentCurrency: paymentCurrency === 'NGN' ? 'NGN' : 'USDT',
            paymentMethod: paymentMethod === 'NGN_BANK' ? 'NGN_BANK' : 'USDT_BEP20',
            txidOrReference: cleanRef,
            adminIdentifier: req.adminPhone,
            adminNote: String(adminNote).trim()
        });

        await Notification.create({
            userId: user._id,
            title: 'Deposit Manually Credited by Admin',
            message: `Your wallet has been credited with $${usdToCredit.toFixed(3)} USD (${paymentMethod === 'NGN_BANK' ? 'NGN Bank Deposit' : 'USDT BEP20'}). Ref: ${cleanRef}.`
        });

        res.json({
            message: `Successfully credited $${usdToCredit.toFixed(3)} USD to ${user.username} (Status: MANUALLY_CREDITED).`,
            transaction: txRecord,
            auditEntry,
            newBalance: updatedUser ? updatedUser.availableBalance : user.availableBalance
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/deposits/:id/decision', adminAuth, async (req, res) => {
    try {
        const { decision, adminNote } = req.body;
        if (!['APPROVE', 'REJECT'].includes(decision)) {
            return res.status(400).json({ error: 'Invalid decision.' });
        }

        const newStatus = decision === 'APPROVE' ? 'COMPLETED' : 'REJECTED';
        const updateData = {
            status: newStatus,
            creditedByAdmin: req.adminPhone
        };
        if (adminNote) updateData.adminNote = adminNote;

        const tx = await Transaction.findOneAndUpdate(
            {
                _id: req.params.id,
                type: 'DEPOSIT',
                status: { $in: ['PENDING', 'PROCESSING'] }
            },
            { $set: updateData },
            { new: true }
        );

        if (!tx) {
            const checkTx = await Transaction.findById(req.params.id);
            if (!checkTx || checkTx.type !== 'DEPOSIT') {
                return res.status(404).json({ error: 'Deposit transaction not found.' });
            }
            return res.status(400).json({ error: `Deposit is already ${checkTx.status}.` });
        }

        if (decision === 'APPROVE') {
            const user = await User.findByIdAndUpdate(
                tx.userId,
                { $inc: { availableBalance: tx.amount } },
                { new: true }
            );

            if (user) {
                user.availableBalance = round3(user.availableBalance);
                await user.save();

                await Notification.create({
                    userId: user._id,
                    title: 'Deposit Approved & Credited!',
                    message: `Your deposit of $${tx.amount.toFixed(2)} USD (Ref: ${tx.reference}) has been approved and credited to your wallet.`
                });
            }
            return res.json({ message: `Deposit ${tx.reference} approved and $${tx.amount.toFixed(2)} credited!` });
        } else {
            const user = await User.findById(tx.userId);
            if (user) {
                await Notification.create({
                    userId: user._id,
                    title: 'Deposit Request Rejected',
                    message: `Your deposit request (${tx.reference}) was rejected.${adminNote ? ' Note: ' + adminNote : ''}`
                });
            }
            return res.json({ message: `Deposit ${tx.reference} marked as REJECTED.` });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/hot-window', adminAuth, async (req, res) => {
    try {
        const { forceHotWindowOpen, resetSlots, verifiedPromotionalBudget } = req.body;
        const update = {};
        if (forceHotWindowOpen !== undefined) update.forceHotWindowOpen = Boolean(forceHotWindowOpen);
        if (verifiedPromotionalBudget !== undefined) update.verifiedPromotionalBudget = Number(verifiedPromotionalBudget);

        const settings = await SystemSetting.findOneAndUpdate(
            { key: 'GLOBAL_CONFIG' },
            update,
            { new: true, upsert: true }
        );

        if (resetSlots) {
            await PackagePlan.updateMany({ category: 'HOT' }, { $set: { slotsClaimed: 0 } });
        }

        res.json({
            message: `Settings updated (${settings.forceHotWindowOpen ? 'FORCE OPEN' : 'AUTO SUNDAY'})${resetSlots ? ' & Slots Reset!' : ''}`,
            settings
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/withdrawals/:id/decision', adminAuth, async (req, res) => {
    try {
        const { decision, payoutTxid } = req.body;
        if (!['APPROVE', 'REJECT'].includes(decision)) {
            return res.status(400).json({ error: 'Invalid decision' });
        }

        const updateData = {
            status: decision === 'APPROVE' ? 'COMPLETED' : 'REJECTED',
            creditedByAdmin: req.adminPhone
        };
        if (decision === 'APPROVE' && payoutTxid && String(payoutTxid).trim()) {
            updateData.txid = String(payoutTxid).trim();
        }

        const tx = await Transaction.findOneAndUpdate(
            {
                _id: req.params.id,
                type: 'WITHDRAWAL',
                status: 'PENDING'
            },
            { $set: updateData },
            { new: true }
        );

        if (!tx) {
            return res.status(400).json({ error: 'Pending withdrawal not found' });
        }

        const netPayout = round2(tx.amount - tx.fee);

        if (decision === 'APPROVE') {
            const user = await User.findByIdAndUpdate(
                tx.userId,
                { $inc: { totalWithdrawals: netPayout } },
                { new: true }
            );
            const targetAddr = tx.withdrawalAddress || (user ? user.usdtWithdrawalAddress : '');

            if (user) {
                user.totalWithdrawals = round2(user.totalWithdrawals);
                await user.save();

                await Notification.create({
                    userId: user._id,
                    title: 'USDT (BEP20) Withdrawal Approved & Sent!',
                    message: `Your withdrawal of ${netPayout.toFixed(2)} USDT (after 5% fee) has been sent to your BEP20 wallet (${targetAddr}).`
                });
            }
            return res.json({ message: `USDT (BEP20) Withdrawal of ${netPayout.toFixed(2)} USDT marked as COMPLETED!` });
        } else {
            const user = await User.findByIdAndUpdate(
                tx.userId,
                { $inc: { availableBalance: tx.amount } },
                { new: true }
            );

            if (user) {
                user.availableBalance = round3(user.availableBalance);
                await user.save();

                await Notification.create({
                    userId: user._id,
                    title: 'Withdrawal Rejected & Refunded',
                    message: `Your withdrawal request of $${tx.amount.toFixed(2)} USDT was rejected and refunded to your available balance.`
                });
            }
            return res.json({ message: 'Withdrawal rejected and funds returned to member balance' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch('/api/admin/packages/:id', adminAuth, async (req, res) => {
    try {
        const { isLocked, purchaseLimit, totalSlots, resetClaimed } = req.body;
        const updateFields = {};

        if (isLocked !== undefined) updateFields.isLocked = Boolean(isLocked);
        if (purchaseLimit !== undefined) updateFields.purchaseLimit = Math.max(1, Number(purchaseLimit) || 1);
        if (totalSlots !== undefined) updateFields.totalSlots = Number(totalSlots);
        if (resetClaimed) updateFields.slotsClaimed = 0;

        const plan = await PackagePlan.findByIdAndUpdate(req.params.id, updateFields, { new: true });
        res.json({ message: `${plan.category} $${plan.price} Package updated`, plan });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/users/:id/reward', adminAuth, async (req, res) => {
    try {
        const amount = round2(Number(req.body.amount));
        const note = req.body.note || 'LTRIX Verified Weekly Promotional Reward';
        if (!amount || amount <= 0) return res.status(400).json({ error: 'Enter a valid positive reward amount' });

        const user = await User.findByIdAndUpdate(
            req.params.id,
            { $inc: { availableBalance: amount } },
            { new: true }
        );
        if (!user) return res.status(404).json({ error: 'User not found' });

        user.availableBalance = round3(user.availableBalance);
        await user.save();

        await Transaction.create({
            userId: user._id,
            type: 'WEEKLY_REWARD',
            amount,
            fee: 0,
            netAmount: amount,
            description: note,
            status: 'COMPLETED'
        });

        await Notification.create({
            userId: user._id,
            title: 'Weekly Promotional Reward Credited!',
            message: `You received a $${amount.toFixed(2)} USD reward: ${note}`
        });

        res.json({ message: `Credited $${amount.toFixed(2)} to ${user.username}` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admin/tickets/:id/reply', adminAuth, async (req, res) => {
    try {
        const { adminReply } = req.body;
        const ticket = await Ticket.findByIdAndUpdate(
            req.params.id,
            { adminReply, status: 'RESOLVED' },
            { new: true }
        );

        await Notification.create({
            userId: ticket.userId,
            title: `Support Ticket Resolved (${ticket.ticketRef || ticket.subject})`,
            message: `LTRIX Support Reply: ${adminReply}`
        });

        res.json({ message: 'Ticket resolved and member notified', ticket });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ==========================================
// 8. AUTOMATED 24-HOUR PAYOUT & SUNDAY RESET CRON
// ==========================================
let isPayoutCronRunning = false;

cron.schedule('* * * * *', async () => {
    if (isPayoutCronRunning) return;
    isPayoutCronRunning = true;

    try {
        const now = new Date();
        const duePackages = await ActivePackage.find({
            status: 'ACTIVE',
            nextPayoutAt: { $lte: now }
        });

        for (const pkg of duePackages) {
            const nextDayCount = pkg.daysCredited + 1;
            const isCompleting = nextDayCount >= pkg.durationDays;
            const nextScheduledPayout = new Date(pkg.nextPayoutAt.getTime() + 24 * 60 * 60 * 1000);

            // Atomically advance package state so overlapping ticks cannot double-credit
            const claimedPkg = await ActivePackage.findOneAndUpdate(
                {
                    _id: pkg._id,
                    status: 'ACTIVE',
                    daysCredited: pkg.daysCredited,
                    nextPayoutAt: pkg.nextPayoutAt
                },
                {
                    $set: {
                        daysCredited: nextDayCount,
                        status: isCompleting ? 'COMPLETED' : 'ACTIVE',
                        nextPayoutAt: nextScheduledPayout
                    }
                },
                { new: true }
            );

            if (!claimedPkg) continue;

            const label = claimedPkg.category === 'HOT' ? '🔥 HOT' : 'LTRIX';

            const updatedUser = await User.findByIdAndUpdate(
                claimedPkg.userId,
                { $inc: { availableBalance: claimedPkg.dailyIncome } },
                { new: true }
            );
            if (updatedUser) {
                updatedUser.availableBalance = round3(updatedUser.availableBalance);
                await updatedUser.save();
            }

            await Transaction.create({
                userId: claimedPkg.userId,
                type: 'DAILY_INCOME',
                amount: claimedPkg.dailyIncome,
                fee: 0,
                netAmount: claimedPkg.dailyIncome,
                description: `${label} Daily Income (Day ${claimedPkg.daysCredited}/${claimedPkg.durationDays}) - $${claimedPkg.price} Package`
            });

            if (isCompleting) {
                await Notification.create({
                    userId: claimedPkg.userId,
                    title: `${label} Package Completed`,
                    message: `Your $${claimedPkg.price} package has completed all ${claimedPkg.durationDays} payout cycles.`
                });
            } else {
                await Notification.create({
                    userId: claimedPkg.userId,
                    title: `${label} Daily Income Credited`,
                    message: `$${claimedPkg.dailyIncome.toFixed(2)} credited for Day ${claimedPkg.daysCredited}/${claimedPkg.durationDays} of your $${claimedPkg.price} package.`
                });
            }
        }
    } catch (err) {
        console.error('Error processing LTRIX daily payouts:', err);
    } finally {
        isPayoutCronRunning = false;
    }
});

cron.schedule('59 8 * * 0', async () => {
    try {
        await PackagePlan.updateMany({ category: 'HOT' }, { $set: { slotsClaimed: 0 } });
        console.log('Sunday Hot Plan slots reset for 9:00 AM WAT opening.');
    } catch (err) {
        console.error('Error resetting Sunday Hot Plan slots:', err);
    }
}, {
    timezone: 'Africa/Lagos'
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`LTRIX Server running on http://localhost:${PORT}`));