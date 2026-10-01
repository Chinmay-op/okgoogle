var dbbconnection = require('./server');
//server1 for offline
var express = require('express');
var app = express();
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.locals.getDateTimeInUserTimeZone = getDateTimeInUserTimeZone;
  next();
});
var bodyparser = require('body-parser');
const jwt = require('jsonwebtoken')
var path = require('path');
const secretkey = "secretkeysvpcet";
const studentSecretKey = "studentsecretkeysvpcet"; // Separate secret for student tokens
const bcrypt = require('bcrypt');
var session = require('express-session');
var cookieParser = require('cookie-parser');
var flash = require('connect-flash');
const uploadFile = require("./uploader");
const uploadComplainImage = require("./uploader").uploadComplainImage;
const readXlsxFile = require('read-excel-file/node');
const { time } = require('console');
const nodemailer = require('nodemailer');
const ejs = require('ejs');
const fs = require('fs');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();
const demoDataService = require('./demoDataService');

// Automated Webhook notification for new student pass requests
function triggerPassRequestWebhook(passData) {
  const webhookUrl = process.env.EIGI_WEBHOOK_URL || 'https://dev-api.eigi.ai/v1/eigi-agent/webhooks/k8MfbgmatB2tClv_XuKJSWzKF9o-Q9Yo/new-pass-request';
  const webhookSecret = process.env.EIGI_WEBHOOK_SECRET || 'ZoqVXUC-QywgLwWRv7PPnzCs20aU7OWgfSpz0ohuVLQ';

  if (!webhookUrl) return;

  try {
    const payload = JSON.stringify(passData);
    const ts = Math.floor(Date.now() / 1000).toString();
    const sig = crypto.createHmac('sha256', webhookSecret).update(`${ts}.${payload}`).digest('hex');
    const hubSig = 'sha256=' + crypto.createHmac('sha256', webhookSecret).update(payload).digest('hex');

    axios.post(webhookUrl, payload, {
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Signature-V2': sig,
        'X-Webhook-Timestamp': ts,
        'X-Hub-Signature-256': hubSig
      },
      timeout: 5000
    }).then(res => {
      console.log(`[Eigi Webhook] Sent notification for pass request #${passData.request_id} (Status: ${res.status})`);
    }).catch(err => {
      console.error(`[Eigi Webhook Error]:`, err.message);
    });
  } catch (err) {
    console.error(`[Eigi Webhook Error] Failed to prepare payload:`, err.message);
  }
}

const CANONICAL_DEPARTMENTS = [
  "COMPUTER ENGINEERING",
  "ELECTRICAL ENGINEERING",
  "INFORMATION TECHNOLOGY",
  "ELECTRONICS & TELECOMMUNICATION ENGINEERING",
  "MECHANICAL ENGINEERING",
  "CIVIL ENGINEERING",
  "ARTIFICIAL INTELLIGENCE",
  "COMPUTER SCIENCE & ENGINEERING (DATA SCIENCE)",
  "COMPUTER SCIENCE & ENGINEERING (CYBER SECURITY)",
  "INDUSTRIAL IOT",
  "COMPUTER SCIENCE AND BUSINESS SYSTEMS",
  "ROBOTICS & ARTIFICIAL INTELLIGENCE",
  "MECHANICAL CAD-CAM",
  "B.VOC. IN CYBER SECURITY",
  "B.VOC. IN SOFTWARE DEVELOPMENT",
  "B.VOC. IN VIRTUAL REALITY & AUGMENTED REALITY",
  "B VOCATIONAL",
  "BCA",
  "BBA",
  "MCA",
  "MBA",
  "M.TECH",
  "M.TECH CSE",
  "M.TECH CADCAM"
];


// Rate limiters for Bonafide Certificate routes
const rateLimit = require('express-rate-limit');
const validateConfig = { xForwardedForHeader: false, trustProxy: false };

const studentBonafideLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many requests, please try again after 15 minutes.',
  validate: validateConfig
});
const adminBonafideLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests, please try again after 15 minutes.',
  validate: validateConfig
});

const studentBankLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many requests, please try again after 15 minutes.',
  validate: validateConfig
});
const adminBankLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests, please try again after 15 minutes.',
  validate: validateConfig
});

const mcpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5000,
  message: 'Too many MCP requests, please try again after 15 minutes.',
  validate: validateConfig
});

// CSRF Protection for Bonafide Certificate routes
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });


// Ensure cookies are parsed for all routes
app.use(cookieParser());

// Ensure body parsing for form posts and JSON (moved below MCP router)

const mcpCors = (req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', '*');
  res.header('Access-Control-Expose-Headers', '*');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
};

const mcpRouter = require('./mcp_server');

const mcpAuth = (req, res, next) => {
  let token = null;
  const authHeader = req.headers.authorization || req.headers['x-api-key'];
  if (authHeader) {
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7).trim();
    } else {
      token = authHeader.trim();
    }
  } else if (req.query && req.query.token) {
    token = req.query.token;
  }

  // Always allow GET requests to /sse to initialize the SSE connection
  if (req.method === 'GET' && req.path === '/sse') {
    return next();
  }

  // If a valid session has already been established via SSE handshake, allow POST messages for that session
  if (!token && req.query && req.query.sessionId && mcpRouter.isValidSession && mcpRouter.isValidSession(req.query.sessionId)) {
    return next();
  }

  if (!token) {
    return res.status(401).json({ success: false, reason: 'Missing or invalid Authorization header' });
  }

  // Support master static token
  if (token === process.env.MCP_BEARER_TOKEN || token === "tnps_gatepass_mcp_token_2026") {
    req.decode = { user: 'superadmin', role: 'SuperID' };
    return next();
  }

  try {
    const decode = jwt.verify(token, secretkey);
    if (decode && (decode.role === 'admin' || decode.user === 'mcp-client')) {
      decode.role = 'SuperID';
    }
    req.decode = decode;
    next();
  } catch (err) {
    console.error(`[MCP Auth Error] Token verification failed:`, err.message);
    return res.status(401).json({ success: false, reason: 'Invalid token' });
  }
};

// Debug logging for MCP routes
app.use('/mcp', (req, res, next) => {
  console.log(`[MCP Router] ${req.method} ${req.url} from ${req.ip} (Auth: ${req.headers.authorization ? 'Present' : 'Missing'})`);
  next();
}, mcpCors, mcpAuth, mcpLimiter, mcpRouter);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session and flash (required for req.flash)
app.use(session({
  secret: process.env.SESSION_SECRET || 'svpcet_gatepass_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  }
}));
app.use(flash());

// Health check endpoint for Render / monitoring
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// Helper function to format a Date object to IST string (YYYY-MM-DD HH:MM:SS)
function formatDateToISTString(date) {
  if (!date) return null;
  console.log('formatDateToISTString - Input Date:', date);
  const inputDate = (date instanceof Date) ? new Date(date.getTime()) : new Date(date);
  if (Number.isNaN(inputDate.getTime())) {
    console.log('formatDateToISTString - Invalid date input');
    return null;
  }

  // Convert to IST by applying the fixed +05:30 offset, then read UTC parts.
  // This avoids Intl locale quirks that can emit "24" for midnight.
  const istDate = new Date(inputDate.getTime() + (5.5 * 60 * 60 * 1000));
  const year = istDate.getUTCFullYear();
  const month = String(istDate.getUTCMonth() + 1).padStart(2, '0');
  const day = String(istDate.getUTCDate()).padStart(2, '0');
  const hour = String(istDate.getUTCHours()).padStart(2, '0');
  const minute = String(istDate.getUTCMinutes()).padStart(2, '0');
  const second = String(istDate.getUTCSeconds()).padStart(2, '0');

  const istString = `${year}-${month}-${day} ${hour}:${minute}:${second}`;
  console.log('formatDateToISTString - Output IST String:', istString);
  return istString;
}

const IST_TIME_ZONE = 'Asia/Kolkata';
const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;
const POST_10PM_CUTOFF_HOUR = 22;
const STUDENT_PICS_ROOT = path.join(__dirname, 'public', 'images', 'student_pics');
const DEFAULT_STUDENT_AVATAR = '/images/default-avatar.png';
// ─── Student photo index ───────────────────────────────────────────────────
// Built once at startup. Maps multiple lowercase key variants → file entry.
// Keys for "ARYAN ASHISH SETH.JPG" (year 2023):
//   "aryan ashish seth"  (full base)
//   "aryan seth"         (first + last — resolves missing middle name in DB)
//   "aryan ashish"       (consecutive pair)
//   "ashish seth"        (consecutive pair)
// ───────────────────────────────────────────────────────────────────────────
let _photoIndex = null;

function _normKey(str) {
  return String(str || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function _wordsOf(base) {
  return base.replace(/\.[^.]+$/, '').replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
}

function buildPhotoIndex() {
  const idx = Object.create(null);
  if (!fs.existsSync(STUDENT_PICS_ROOT)) return idx;
  let yearDirs = [];
  try {
    yearDirs = fs.readdirSync(STUDENT_PICS_ROOT, { withFileTypes: true })
      .filter(e => e.isDirectory())
      .map(e => e.name)
      .sort((a, b) => b.localeCompare(a, undefined, { numeric: true, sensitivity: 'base' }));
  } catch (_) { return idx; }

  for (const yearDir of yearDirs) {
    const yearPath = path.join(STUDENT_PICS_ROOT, yearDir);
    let files = [];
    try { files = fs.readdirSync(yearPath); } catch (_) { continue; }
    for (const filename of files) {
      if (!/\.(jpg|jpeg|png|webp|gif)$/i.test(filename)) continue;
      const webPath = '/images/student_pics/' + yearDir + '/' + filename;
      const entry = { yearDir, filename, webPath };
      const words = _wordsOf(filename);
      if (!words.length) continue;
      // 1. Full base name (case-insensitive)
      const fullKey = _normKey(words.join(' '));
      if (!idx[fullKey]) idx[fullKey] = entry;
      // 2. First word + Last word  (handles missing middle name)
      if (words.length >= 3) {
        const flKey = _normKey(words[0] + ' ' + words[words.length - 1]);
        if (!idx[flKey]) idx[flKey] = entry;
      }
      // 3. Every consecutive word pair
      for (let i = 0; i < words.length - 1; i++) {
        const pk = _normKey(words[i] + ' ' + words[i + 1]);
        if (!idx[pk]) idx[pk] = entry;
      }
    }
  }
  return idx;
}

function getPhotoIndex() {
  if (!_photoIndex) _photoIndex = buildPhotoIndex();
  return _photoIndex;
}

function refreshPhotoIndex() {
  _photoIndex = buildPhotoIndex();
}

function getISTDateParts(dateObj = new Date()) {
  const inputDate = (dateObj instanceof Date) ? new Date(dateObj.getTime()) : new Date(dateObj);
  if (Number.isNaN(inputDate.getTime())) {
    return null;
  }

  const istDate = new Date(inputDate.getTime() + IST_OFFSET_MS);
  return {
    year: istDate.getUTCFullYear(),
    month: String(istDate.getUTCMonth() + 1).padStart(2, '0'),
    day: String(istDate.getUTCDate()).padStart(2, '0'),
    hour: String(istDate.getUTCHours()).padStart(2, '0'),
    minute: String(istDate.getUTCMinutes()).padStart(2, '0'),
    second: String(istDate.getUTCSeconds()).padStart(2, '0')
  };
}

function normalizePublicImagePath(value) {
  if (!value) return null;
  const raw = String(value).trim();
  if (!raw) return null;
  if (/^https?:\/\//i.test(raw)) return raw;
  if (raw.startsWith('/')) return raw.replace(/\\/g, '/');
  return '/' + raw.replace(/\\/g, '/').replace(/^\/+/, '');
}

function buildStudentPhotoNames(student) {
  const names = [];
  const rawPath = normalizePublicImagePath(student && (student.path || student.student_photo_path || student.photo_path || student.image_path || student.image));
  if (rawPath) {
    names.push(rawPath);
    const rawBase = path.posix.basename(rawPath);
    if (rawBase && rawBase !== rawPath) {
      names.push(rawBase);
    }
  }

  const fullName = ((student && (student.sname || student.name)) || '').toString().trim().toUpperCase();
  if (fullName) {
    const safeBase = fullName.replace(/[<>:"/\\|?*\u0000-\u001F]/g, '').replace(/\s+/g, ' ').trim();
    if (safeBase) {
      names.push(safeBase);
      names.push(`${safeBase}.JPG`);
      names.push(`${safeBase}.JPEG`);
      names.push(`${safeBase}.PNG`);
      names.push(`${safeBase}.WEBP`);
    }
  }

  if (student && (student.uid || student.student_uid || student.UID)) {
    names.push(String(student.uid || student.student_uid || student.UID).trim());
  }

  return Array.from(new Set(names.filter(Boolean)));
}

function resolveStudentPhotoUrl(student) {
  const rawUrl = normalizePublicImagePath(student && (student.path || student.student_photo_path || student.photo_path || student.image_path || student.image));

  // If the stored path already points into student_pics, trust it only when the
  // file actually exists on disk (avoids serving stale DB paths).
  if (rawUrl && /^\/images\/student_pics\//i.test(rawUrl)) {
    const absPath = path.join(__dirname, 'public', rawUrl.replace(/^\//, ''));
    if (fs.existsSync(absPath)) return rawUrl;
    // File not on disk — fall through to index lookup below
  }
  if (rawUrl && /^\/(images|uploads)\//i.test(rawUrl) && !/student_pics/i.test(rawUrl)) {
    return rawUrl; // non-student-pics URL — return as-is
  }

  // ── Phase 1: index-based lookup (handles case differences & missing middle names) ──
  const idx = getPhotoIndex();
  const sname = ((student && (student.sname || student.name)) || '').toString().trim();
  const uid   = ((student && (student.uid || student.student_uid || student.UID))   || '').toString().trim();

  if (sname) {
    const words = sname.replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
    const fullKey = _normKey(sname);
    const firstLastKey = words.length >= 2 ? _normKey(words[0] + ' ' + words[words.length - 1]) : null;

    // Priority order:
    // 1. Exact full name match (case-insensitive)
    if (idx[fullKey]) return idx[fullKey].webPath;
    // 2. First + Last (resolves missing-middle-name problem)
    if (firstLastKey && idx[firstLastKey]) return idx[firstLastKey].webPath;
    // 3. Try each consecutive word pair from the DB name
    for (let i = 0; i < words.length - 1; i++) {
      const pairKey = _normKey(words[i] + ' ' + words[i + 1]);
      if (idx[pairKey]) return idx[pairKey].webPath;
    }
    // 4. UID-based lookup
    if (uid && idx[_normKey(uid)]) return idx[_normKey(uid)].webPath;
  }

  // ── Phase 2: legacy filesystem walk (exact-case) ──
  const picsRoot = STUDENT_PICS_ROOT;
  if (fs.existsSync(picsRoot)) {
    let yearDirs = [];
    try {
      yearDirs = fs.readdirSync(picsRoot, { withFileTypes: true })
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .filter(Boolean)
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true, sensitivity: 'base' }));
    } catch (_) { yearDirs = []; }

    const candidateNames = buildStudentPhotoNames(student);
    for (const candidate of candidateNames) {
      const cleanCandidate = String(candidate).replace(/^\/+/, '');
      if (/^\/images\/student_pics\//i.test(cleanCandidate)) return cleanCandidate;
      if (/^images\/student_pics\//i.test(cleanCandidate)) return '/' + cleanCandidate;

      for (const yearDir of yearDirs) {
        const absoluteCandidate = path.join(picsRoot, yearDir, cleanCandidate);
        if (fs.existsSync(absoluteCandidate)) {
          return `/images/student_pics/${yearDir}/${cleanCandidate}`;
        }
      }
    }
  }

  return rawUrl || DEFAULT_STUDENT_AVATAR;
}
function attachStudentPhotoUrl(studentRow) {
  if (!studentRow || typeof studentRow !== 'object') return studentRow;
  studentRow.photoUrl = resolveStudentPhotoUrl(studentRow);
  studentRow.path = studentRow.photoUrl;
  return studentRow;
}
if (typeof app !== 'undefined' && app.locals) {
    app.locals.attachStudentPhotoUrl = attachStudentPhotoUrl;
}

function getISTDateOnlyString(dateObj = new Date()) {
  const parts = getISTDateParts(dateObj);
  return parts ? `${parts.year}-${parts.month}-${parts.day}` : null;
}

function isAfterISTCutoff(dateObj = new Date(), cutoffHour = POST_10PM_CUTOFF_HOUR) {
  const parts = getISTDateParts(dateObj);
  if (!parts) return false;
  return Number(parts.hour) >= cutoffHour;
}

function buildLatestActivePassSql() {
  return `
    SELECT *
    FROM log_details1
    WHERE uid = ?
      AND status = 'ACTIVE'
      AND passtype IN ('City Pass', 'Home Pass')
    ORDER BY logid DESC
    LIMIT 1
  `;
}

function insertRestrictionAudit(connection, payload, callback) {
  const auditSql = `
    INSERT INTO pass_restriction_audit
      (uid, logid, passtype, restriction_reason, restriction_source, details, restricted_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  connection.query(
    auditSql,
    [
      payload.uid,
      payload.logid || null,
      payload.passtype || null,
      payload.reason || 'unknown',
      payload.source || 'system',
      payload.details ? JSON.stringify(payload.details) : null,
      formatDateToISTString(new Date())
    ],
    function (err) {
      if (typeof callback === 'function') {
        callback(err || null);
      }
    }
  );
}

function applyPost10pmPassRulesForUid(connection, uid, callback) {
  loadFeatureFlagsMap(connection, function (ffErr, flagsMap) {
    if (ffErr) {
      return callback(ffErr);
    }

    const restrictionEnabled = (flagsMap && flagsMap.post_10pm_restriction) ? !!flagsMap.post_10pm_restriction.enabled : true;
    if (!restrictionEnabled) {
      return callback(null, { skipped: true, reason: 'restriction_disabled_by_admin' });
    }

    const now = new Date();
    if (!isAfterISTCutoff(now)) {
      return callback(null, { skipped: true });
    }

    connection.query(buildLatestActivePassSql(), [uid], function (latestErr, rows) {
      if (latestErr) {
        return callback(latestErr);
      }

      if (!rows || rows.length === 0) {
        return callback(null, { skipped: false, hostelSynced: false, restricted: false, reason: 'no_active_pass' });
      }

      const pass = rows[0];
      const hostelinMissing = pass.hostelintime === null || pass.hostelintime === undefined || pass.hostelintime === '';
      const shouldSync = pass.approvaldt !== null && pass.outdatetime === null && pass.indatetime === null && hostelinMissing;

      if (shouldSync) {
        const syncSql = `
        UPDATE log_details1
        SET hostelintime = approvaldt
        WHERE logid = ?
          AND uid = ?
          AND status = 'ACTIVE'
          AND passtype IN ('City Pass', 'Home Pass')
          AND approvaldt IS NOT NULL
          AND outdatetime IS NULL
          AND indatetime IS NULL
          AND hostelintime IS NULL
      `;

        return connection.query(syncSql, [pass.logid, uid], function (syncErr) {
          if (syncErr) {
            return callback(syncErr);
          }

          return callback(null, { skipped: false, hostelSynced: true, restricted: false, reason: 'synced_only' });
        });
      }

      const hostelinAfter10pm = (() => {
        if (hostelinMissing || !pass.hostelintime) return false;
        const raw = String(pass.hostelintime);
        const timePart = raw.includes(' ') ? raw.split(' ')[1] : raw;
        const hour = Number(String(timePart).split(':')[0]);
        return Number.isFinite(hour) && hour >= POST_10PM_CUTOFF_HOUR;
      })();

      const shouldRestrict =
        pass.status === 'ACTIVE' &&
        pass.outdatetime !== null &&
        pass.outdatetime !== undefined &&
        (
          pass.passtype === 'City Pass' ||
          (
            pass.passtype === 'Home Pass' &&
            pass.indatetime !== null &&
            pass.indatetime !== undefined &&
            (hostelinMissing || hostelinAfter10pm)
          )
        );

      if (!shouldRestrict) {
        return callback(null, { skipped: false, hostelSynced: false, restricted: false, reason: 'not_eligible' });
      }

      const restrictSql = `
      UPDATE studentdetails
      SET status = 'Restrict'
      WHERE uid = ?
        AND category = 'Hostel'
        AND COALESCE(status, '') <> 'Restrict'
        AND EXISTS (
          SELECT 1
          FROM log_details1 l
          WHERE l.logid = ?
            AND l.uid = ?
            AND l.status = 'ACTIVE'
            AND l.passtype IN ('City Pass', 'Home Pass')
        )
    `;

      connection.query(restrictSql, [uid, pass.logid, uid], function (restrictErr, restrictResult) {
        if (restrictErr) {
          return callback(restrictErr);
        }

        if (restrictResult && restrictResult.affectedRows > 0) {
          insertRestrictionAudit(connection, {
            uid,
            logid: pass.logid,
            passtype: pass.passtype,
            reason: 'post_10pm_rule',
            source: 'student_session',
            details: {
              status: pass.status,
              approvaldt: pass.approvaldt,
              outdatetime: pass.outdatetime,
              indatetime: pass.indatetime,
              hostelintime: pass.hostelintime
            }
          }, function () { });
        }

        return callback(null, {
          skipped: false,
          hostelSynced: false,
          restricted: !!(restrictResult && restrictResult.affectedRows > 0),
          reason: 'restricted_latest_active_pass'
        });
      });
    });
  });
}

function checkHostelInRestriction(connection, logid, callback) {
  loadFeatureFlagsMap(connection, function (ffErr, flagsMap) {
    if (ffErr) {
      return callback(ffErr);
    }

    const restrictionEnabled = (flagsMap && flagsMap.post_10pm_restriction) ? !!flagsMap.post_10pm_restriction.enabled : true;
    if (!restrictionEnabled) {
      return callback(null, false);
    }

    if (!isAfterISTCutoff(currentdate(), 22)) {
      return callback(null, false);
    }

    const query = "SELECT uid, passtype, approvaldt, outdatetime, indatetime, hostelintime, status FROM log_details1 WHERE logid = ?";
    connection.query(query, [logid], function (err, rows) {
      if (err) return callback(err);
      if (!rows || rows.length === 0) return callback(null, false);

      const log = rows[0];
      let restrict = false;
      let restrictReason = '';

      if (log.passtype === 'City Pass' || log.passtype === 'Home Pass') {
        restrict = true;
        restrictReason = 'hostel_scan_after_10pm';
      }

      if (restrict) {
        const updateStu = "UPDATE studentdetails SET status = 'Restrict' WHERE uid = ?";
        connection.query(updateStu, [log.uid], function (updateErr) {
          if (updateErr) return callback(updateErr);
          // Insert audit record for this scan-time restriction
          insertRestrictionAudit(connection, {
            uid: log.uid,
            logid: logid,
            passtype: log.passtype,
            reason: restrictReason,
            source: 'hostel_scan',
            details: {
              status: log.status,
              approvaldt: log.approvaldt,
              outdatetime: log.outdatetime,
              indatetime: log.indatetime,
              hostelintime: log.hostelintime || formatDateTimeForDB(currentdate())
            }
          }, function () {});
          return callback(null, true);
        });
      } else {
        return callback(null, false);
      }
    });
  });
}

function sweepPost10pmPassRules(connection, callback) {
  // This function is called exactly at midnight (12 AM IST) via a one-shot cron.
  // No time-of-day guard needed here — the cron schedule itself ensures correct timing.

  // Hostel-out → hostel-in sync:
  // Only copy hostelintime for students who scanned at hostel out BUT have NOT
  // scanned at gate out (outdatetime IS NULL), meaning they are still inside campus.
  // Students who have also scanned at gate out (outdatetime IS NOT NULL) are excluded
  // so their hostel-in entry is not erroneously set.
  const syncSql = `
    UPDATE log_details1 l
    SET hostelintime = approvaldt
    WHERE l.logid = (
      SELECT x.logid
      FROM (
        SELECT logid
        FROM log_details1
        WHERE uid = l.uid
          AND status = 'ACTIVE'
          AND passtype IN ('City Pass', 'Home Pass')
        ORDER BY logid DESC
        LIMIT 1
      ) AS x
    )
      AND l.approvaldt IS NOT NULL
      AND l.outdatetime IS NULL
      AND l.indatetime IS NULL
      AND l.hostelintime IS NULL
  `;

  connection.query(syncSql, function (syncErr) {
    if (syncErr) {
      return callback(syncErr);
    }

    // First SELECT the students that will be restricted, capturing pass details for the audit log.
    const selectToRestrictSql = `
      SELECT sd.uid, l.logid, l.passtype, l.approvaldt, l.outdatetime, l.indatetime, l.hostelintime, l.status AS log_status,
        CASE
          WHEN l.passtype = 'City Pass' THEN 'midnight_sweep_city_pass_no_return'
          WHEN l.passtype = 'Home Pass' AND l.hostelintime IS NULL THEN 'midnight_sweep_home_pass_no_hostel_scan'
          WHEN l.passtype = 'Home Pass' AND TIME(l.hostelintime) > '22:00:00' THEN 'midnight_sweep_home_pass_late_hostel_scan'
          ELSE 'midnight_sweep_post_10pm'
        END AS restrict_reason
      FROM studentdetails sd
      JOIN log_details1 l ON l.uid = sd.uid
      WHERE sd.category = 'Hostel'
        AND COALESCE(sd.status, '') <> 'Restrict'
        AND l.logid = (
          SELECT x.logid
          FROM (
            SELECT logid
            FROM log_details1
            WHERE uid = sd.uid
              AND status = 'ACTIVE'
              AND passtype IN ('City Pass', 'Home Pass')
            ORDER BY logid DESC
            LIMIT 1
          ) AS x
        )
        AND l.status = 'ACTIVE'
        AND l.passtype IN ('City Pass', 'Home Pass')
        AND l.outdatetime IS NOT NULL
        AND (
          l.passtype = 'City Pass'
          OR (
            l.passtype = 'Home Pass'
            AND l.outdatetime IS NOT NULL
            AND l.indatetime IS NOT NULL
            AND (l.hostelintime IS NULL OR TIME(l.hostelintime) > '22:00:00')
          )
        )
    `;

    connection.query(selectToRestrictSql, function (selErr, toRestrictRows) {
      if (selErr) {
        console.error('sweepPost10pmPassRules: Failed to select students to restrict for audit:', selErr);
        toRestrictRows = [];
      }

      const restrictSql = `
        UPDATE studentdetails sd
        SET sd.status = 'Restrict'
        WHERE sd.category = 'Hostel'
          AND COALESCE(sd.status, '') <> 'Restrict'
          AND EXISTS (
            SELECT 1
            FROM log_details1 l
            WHERE l.logid = (
              SELECT x.logid
              FROM (
                SELECT logid
                FROM log_details1
                WHERE uid = sd.uid
                  AND status = 'ACTIVE'
                  AND passtype IN ('City Pass', 'Home Pass')
                ORDER BY logid DESC
                LIMIT 1
              ) AS x
            )
              AND l.uid = sd.uid
              AND l.status = 'ACTIVE'
              AND l.passtype IN ('City Pass', 'Home Pass')
              AND l.outdatetime IS NOT NULL
              AND (
                l.passtype = 'City Pass'
                OR (
                  l.passtype = 'Home Pass'
                  AND l.outdatetime IS NOT NULL
                  AND l.indatetime IS NOT NULL
                  AND (l.hostelintime IS NULL OR TIME(l.hostelintime) > '22:00:00')
                )
              )
          )
      `;

      connection.query(restrictSql, function (restrictErr, restrictResult) {
        if (restrictErr) {
          return callback(restrictErr);
        }

        // Batch-insert audit rows for each student that was just restricted
        if (toRestrictRows && toRestrictRows.length > 0) {
          var nowIST = formatDateToISTString(new Date());
          var auditRows = toRestrictRows.map(function (row) {
            return [
              row.uid,
              row.logid || null,
              row.passtype || null,
              row.restrict_reason || 'midnight_sweep_post_10pm',
              'midnight_sweep',
              JSON.stringify({
                log_status: row.log_status,
                approvaldt: row.approvaldt,
                outdatetime: row.outdatetime,
                indatetime: row.indatetime,
                hostelintime: row.hostelintime
              }),
              nowIST
            ];
          });
          const batchAuditSql = `
            INSERT INTO pass_restriction_audit
              (uid, logid, passtype, restriction_reason, restriction_source, details, restricted_at)
            VALUES ?
          `;
          connection.query(batchAuditSql, [auditRows], function (auditErr) {
            if (auditErr) {
              console.error('sweepPost10pmPassRules: Failed to insert restriction audit rows:', auditErr);
            }
          });
        }

        return callback(null, {
          skipped: false,
          hostelSyncedRows: true,
          restrictedRows: restrictResult ? restrictResult.affectedRows : 0
        });
      });
    });
  });
}

function runRoomBookingPaymentStatusMigration(done) {
  dbbconnection.getConnection(function (err, connection) {
    if (err || !connection) {
      if (typeof done === 'function') done();
      return;
    }

    const expandEnumSql = `
      ALTER TABLE room_bookings
      MODIFY COLUMN payment_status ENUM('pending','confirmed','paid','cancelled') DEFAULT 'pending'
    `;
    const normalizeSql = `
      UPDATE room_bookings
      SET payment_status = CASE
        WHEN booking_status = 'cancelled' THEN 'cancelled'
        WHEN LOWER(COALESCE(payment_status, '')) = 'paid' THEN 'confirmed'
        ELSE payment_status
      END
      WHERE booking_status = 'cancelled'
         OR LOWER(COALESCE(payment_status, '')) = 'paid'
    `;
    const finalEnumSql = `
      ALTER TABLE room_bookings
      MODIFY COLUMN payment_status ENUM('pending','confirmed','cancelled') DEFAULT 'pending'
    `;
    const addBedStatusIndexSql = `
      CREATE INDEX idx_room_bookings_bed_status
      ON room_bookings (room_no, block, floor, bed_no, booking_status)
    `;

    connection.query(expandEnumSql, function (expandErr) {
      if (expandErr) {
        connection.release();
        if (expandErr.code !== 'ER_NO_SUCH_TABLE') {
          console.error('room booking payment enum expand failed:', expandErr.message);
        }
        if (typeof done === 'function') done();
        return;
      }

      connection.query(normalizeSql, function (normalizeErr) {
        if (normalizeErr) {
          console.error('room booking payment normalization failed:', normalizeErr.message);
        }

        connection.query(finalEnumSql, function (finalErr) {
          if (finalErr) {
            console.error('room booking payment enum finalize failed:', finalErr.message);
          }

          connection.query("ALTER TABLE room_bookings DROP INDEX unique_bed_lock", function (dropErr1) {
            if (dropErr1 && dropErr1.code !== 'ER_CANT_DROP_FIELD_OR_KEY') {
              console.error('drop unique_bed_lock failed:', dropErr1.message);
            }

            connection.query("ALTER TABLE room_bookings DROP INDEX uq_room_booking_lock", function (dropErr2) {
              if (dropErr2 && dropErr2.code !== 'ER_CANT_DROP_FIELD_OR_KEY') {
                console.error('drop uq_room_booking_lock failed:', dropErr2.message);
              }

              connection.query("ALTER TABLE room_bookings DROP INDEX unique_room_lock", function (dropErr3) {
                if (dropErr3 && dropErr3.code !== 'ER_CANT_DROP_FIELD_OR_KEY') {
                  console.error('drop unique_room_lock failed:', dropErr3.message);
                }

                connection.query(addBedStatusIndexSql, function (idxErr) {
                  connection.release();
                  if (idxErr && idxErr.code !== 'ER_DUP_KEYNAME') {
                    console.error('add idx_room_bookings_bed_status failed:', idxErr.message);
                  }
                  if (typeof done === 'function') done();
                });
              });
            });
          });
        });
      });
    });
  });
}

const PERMANENT_ROOM_NAMES = new Set(['AF-02', 'AF-31', 'AS-31', 'BG-26']);

function isPermanentRoomName(roomName) {
  return PERMANENT_ROOM_NAMES.has(((roomName || '') + '').trim().toUpperCase());
}

function isPermanentRoomRow(roomRow) {
  if (!roomRow) return false;
  return isPermanentRoomName(roomRow.name || roomRow.room_no || roomRow.room);
}

// Keep studentdetails room columns aligned with booking status.
// Regular students only keep room data when they have a confirmed booking.
// Admission-generated students are preserved so their profiles stay populated.
function runRoomDetailsStartupCleanup() {
  dbbconnection.getConnection(function (err, connection) {
    if (err || !connection) {
      if (err) console.error('room details startup cleanup skipped:', err.message);
      return;
    }

    const cleanupSql = `
      UPDATE studentdetails s
      LEFT JOIN (
        SELECT rb.uid, rb.room_no, rb.bed_no, rb.block
        FROM room_bookings rb
        WHERE rb.booking_status = 'locked'
          AND COALESCE(rb.locked_by, '') = 'SuperID-Admission'
          AND NOT EXISTS (
            SELECT 1
            FROM room_bookings rb2
            WHERE rb2.uid = rb.uid
              AND rb2.booking_status = 'locked'
              AND COALESCE(rb2.locked_by, '') = 'SuperID-Admission'
              AND (
                rb2.created_at > rb.created_at
                OR (rb2.created_at = rb.created_at AND rb2.id > rb.id)
              )
          )
      ) adm ON adm.uid = s.uid
      LEFT JOIN (
        SELECT rb.uid, rb.room_no, rb.bed_no, rb.block
        FROM room_bookings rb
        WHERE rb.booking_status = 'locked'
          AND LOWER(COALESCE(rb.payment_status, '')) = 'confirmed'
          AND COALESCE(rb.locked_by, '') <> 'SuperID-Admission'
          AND NOT EXISTS (
            SELECT 1
            FROM room_bookings rb2
            WHERE rb2.uid = rb.uid
              AND rb2.booking_status = 'locked'
              AND LOWER(COALESCE(rb2.payment_status, '')) = 'confirmed'
              AND COALESCE(rb2.locked_by, '') <> 'SuperID-Admission'
              AND (
                rb2.created_at > rb.created_at
                OR (rb2.created_at = rb.created_at AND rb2.id > rb.id)
              )
          )
      ) conf ON conf.uid = s.uid
      SET
        s.room_no = CASE
          WHEN COALESCE(s.is_temp_uid, 0) = 1 OR UPPER(LEFT(COALESCE(s.uid, ''), 2)) = 'BH'
            THEN COALESCE(adm.room_no, conf.room_no, s.room_no)
          WHEN adm.uid IS NOT NULL THEN adm.room_no
          WHEN conf.uid IS NOT NULL THEN conf.room_no
          ELSE NULL
        END,
        s.bed_no = CASE
          WHEN COALESCE(s.is_temp_uid, 0) = 1 OR UPPER(LEFT(COALESCE(s.uid, ''), 2)) = 'BH'
            THEN COALESCE(adm.bed_no, conf.bed_no, s.bed_no)
          WHEN adm.uid IS NOT NULL THEN adm.bed_no
          WHEN conf.uid IS NOT NULL THEN conf.bed_no
          ELSE NULL
        END,
        s.block = CASE
          WHEN COALESCE(s.is_temp_uid, 0) = 1 OR UPPER(LEFT(COALESCE(s.uid, ''), 2)) = 'BH'
            THEN COALESCE(adm.block, conf.block, s.block)
          WHEN adm.uid IS NOT NULL THEN adm.block
          WHEN conf.uid IS NOT NULL THEN conf.block
          ELSE NULL
        END,
        s.other2 = CASE
          WHEN COALESCE(s.is_temp_uid, 0) = 1 OR UPPER(LEFT(COALESCE(s.uid, ''), 2)) = 'BH'
            THEN COALESCE(adm.block, conf.block, s.other2)
          WHEN adm.uid IS NOT NULL THEN adm.block
          WHEN conf.uid IS NOT NULL THEN conf.block
          ELSE NULL
        END
      WHERE LOWER(TRIM(COALESCE(s.category, ''))) = 'hostel'
    `;

    connection.query(cleanupSql, function (qErr) {
      connection.release();
      if (qErr) {
        console.error('room details startup cleanup failed:', qErr.message);
      }
    });
  });
}

function runPermanentRoomMetadataMigration(done) {
  dbbconnection.getConnection(function (err, connection) {
    if (err || !connection) {
      if (typeof done === 'function') done();
      return;
    }

    const sql = `
      UPDATE rooms
      SET is_permanent = 1,
          description = CASE name
            WHEN 'AF-02' THEN 'Prayer Room'
            WHEN 'AF-31' THEN 'Store Room'
            WHEN 'AS-31' THEN 'Store Room'
            WHEN 'BG-26' THEN 'Store Room'
            ELSE description
          END
      WHERE name IN ('AF-02', 'AF-31', 'AS-31', 'BG-26')
    `;

    connection.query(sql, function (qErr) {
      connection.release();
      if (qErr) {
        console.error('permanent room metadata migration failed:', qErr.message);
      }
      if (typeof done === 'function') done();
    });
  });
}

setImmediate(function () {
  runRoomBookingPaymentStatusMigration(() => runPermanentRoomMetadataMigration(runRoomDetailsStartupCleanup));
});

// =====================================================
// MOBILE API - Technician Complaints
app.get('/api/mobile/v1/technician/complaints', verifyMobileJwt, function (req, res) {
  const role = req.decode.role;
  if (role !== "Technician") {
    return res.status(403).json({ success: false, error: 'Unauthorized Access' });
  }
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    const sql = 'SELECT c.*, s.sname as student, s.mobileno, s.room_no FROM complaints c LEFT JOIN studentdetails s ON c.student_uid = s.uid WHERE c.status = "approved" ORDER BY c.timestamp DESC';
    connection.query(sql, function (qErr, results) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Error fetching complaints' });
      }
      res.json({ success: true, data: results });
    });
  });
});


app.get('/api/mobile/v1/technician/complaints/resolved', verifyMobileJwt, function (req, res) {
  const role = req.decode.role;
  if (role !== "Technician") {
    return res.status(403).json({ success: false, error: 'Unauthorized Access' });
  }
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    const sql = 'SELECT c.*, s.sname as student, s.mobileno, s.room_no FROM complaints c LEFT JOIN studentdetails s ON c.student_uid = s.uid WHERE c.status = "resolved" ORDER BY c.timestamp DESC';
    connection.query(sql, function (qErr, results) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Error fetching complaints' });
      }
      res.json({ success: true, data: results });
    });
  });
});

app.post('/api/mobile/v1/technician/complaints/:id/resolve', verifyMobileJwt, function (req, res) {
  const role = req.decode.role;
  if (role !== "Technician") {
    return res.status(403).json({ success: false, error: 'Unauthorized Access' });
  }
  const id = req.params.id;
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    const sql = 'UPDATE complaints SET status = "resolved" WHERE id = ?';
    connection.query(sql, [id], function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Error marking complaint as resolved' });
      }
      res.json({ success: true, message: 'Complaint marked as resolved' });
    });
  });
});

// =====================================================
// Password Reset via Email OTP (Option A: user sets new password)
// =====================================================
// Ensure helper table exists
dbbconnection.getConnection(function (err, connection) {
  if (!err && connection) {
    const createSql = `
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_type ENUM('student','admin') NOT NULL,
        email VARCHAR(255) NOT NULL,
        otp_hash VARCHAR(255) NOT NULL,
        expires_at DATETIME NOT NULL,
        attempts INT DEFAULT 0,
        used TINYINT(1) DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )`;
    connection.query(createSql, function () { connection.release(); });
  }
});

// Ensure announcements table exists
dbbconnection.getConnection(function (err, connection) {
  if (!err && connection) {
    const createAnnouncementsSql = `
      CREATE TABLE IF NOT EXISTS announcements (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        target_year ENUM('all','1','2','3','4') DEFAULT 'all',
        created_by VARCHAR(100),
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active TINYINT(1) DEFAULT 1
      )`;
    connection.query(createAnnouncementsSql, function () { connection.release(); });
  }
});

// Ensure tally_fee_data table exists
dbbconnection.getConnection(function (err, connection) {
  if (!err && connection) {
    const createTallyFeeDataSql = `
      CREATE TABLE IF NOT EXISTS tally_fee_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        suid VARCHAR(50) NOT NULL,
        student_name VARCHAR(255),
        recv_arrear_fee DECIMAL(12,2) DEFAULT 0,
        recv_current_year DECIMAL(12,2) DEFAULT 0,
        recv_extra_stay DECIMAL(12,2) DEFAULT 0,
        recd_arrear_fee DECIMAL(12,2) DEFAULT 0,
        recd_current_year DECIMAL(12,2) DEFAULT 0,
        recd_extra DECIMAL(12,2) DEFAULT 0,
        balance DECIMAL(12,2) DEFAULT 0,
        as_on_date VARCHAR(20),
        imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uq_suid (suid)
      )`;
    connection.query(createTallyFeeDataSql, function () { connection.release(); });
  }
});

// Ensure pass_requests has the columns required by the request/conversion flow
dbbconnection.getConnection(function (err, connection) {
  if (err || !connection) return;
  connection.query("SHOW TABLES LIKE 'pass_requests'", function (tErr, rows) {
    if (tErr || !rows || rows.length === 0) {
      connection.release();
      return;
    }
    connection.query('SHOW COLUMNS FROM pass_requests', function (cErr, cols) {
      if (cErr) {
        connection.release();
        return;
      }
      const fields = new Set((cols || []).map(c => c.Field));
      const alters = [];
      if (!fields.has('request_kind')) {
        alters.push("ADD COLUMN request_kind VARCHAR(20) NOT NULL DEFAULT 'new'");
      }
      if (!fields.has('conversion_enabled')) {
        alters.push("ADD COLUMN conversion_enabled TINYINT(1) NOT NULL DEFAULT 0");
      }
      if (!fields.has('conversion_enabled_by')) {
        alters.push("ADD COLUMN conversion_enabled_by VARCHAR(100) NULL");
      }

      if (alters.length === 0) {
        connection.release();
        return;
      }

      connection.query(`ALTER TABLE pass_requests ${alters.join(', ')}`, function () {
        connection.release();
      });
    });
  });
});

function randomOtp() {
  return ('' + Math.floor(100000 + Math.random() * 900000));
}

function findUserByEmail(userType, email, cb) {
  dbbconnection.getConnection(function (err, connection) {
    if (err) return cb(err);
    const sql = userType === 'admin'
      ? 'SELECT * FROM admin WHERE email = ? LIMIT 1'
      : 'SELECT * FROM studentdetails WHERE email = ? LIMIT 1';
    connection.query(sql, [email], function (qerr, rows) {
      connection.release();
      if (qerr) return cb(qerr);
      cb(null, rows && rows[0]);
    });
  });
}

// GET Forgot Password page
app.get('/auth/forgot', function (req, res) {
  res.render(__dirname + '/views/auth/forgot', { message: req.flash('message') });
});

// POST Forgot: generate OTP and email it
app.post('/auth/forgot', function (req, res) {
  const email = (req.body.email || '').trim();
  const userType = (req.body.userType || 'student').trim();
  if (!email || !['student', 'admin'].includes(userType)) {
    req.flash('message', 'Invalid request');
    return res.redirect('/auth/forgot');
  }
  findUserByEmail(userType, email, function (err, user) {
    const otp = randomOtp();
    bcrypt.hash(otp, 10, function (hErr, hash) {
      dbbconnection.getConnection(function (cErr, connection) {
        if (connection) {
          const expiresAt = formatDateTimeForDB(new Date(Date.now() + 10 * 60 * 1000));
          const ins = 'INSERT INTO password_reset_tokens (user_type, email, otp_hash, expires_at) VALUES (?,?,?,?)';
          connection.query(ins, [userType, email, hash, expiresAt], function (qErr2) {
            if (qErr2 && qErr2.code === 'ER_NO_SUCH_TABLE') {
              // Table missing: create and retry once
              const createSql = `
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                  id INT AUTO_INCREMENT PRIMARY KEY,
                  user_type ENUM('student','admin') NOT NULL,
                  email VARCHAR(255) NOT NULL,
                  otp_hash VARCHAR(255) NOT NULL,
                  expires_at DATETIME NOT NULL,
                  attempts INT DEFAULT 0,
                  used TINYINT(1) DEFAULT 0,
                  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )`;
              return connection.query(createSql, function (crtErr) {
                if (crtErr) {
                  connection.release();
                  console.error('Create password_reset_tokens failed:', crtErr);
                  req.flash('message', 'Could not create reset code. Please try again later.');
                  return res.redirect('/auth/forgot');
                }
                connection.query(ins, [userType, email, hash, expiresAt], function (retryErr) {
                  if (retryErr) {
                    connection.release();
                    console.error('OTP insert retry failed:', retryErr);
                    req.flash('message', 'Could not create reset code. Please try again.');
                    return res.redirect('/auth/forgot');
                  }
                  // proceed to send mail
                  proceedSend(connection);
                });
              });
            }
            if (qErr2) {
              connection.release();
              console.error('OTP insert failed:', qErr2);
              req.flash('message', 'Could not create reset code. Please try again.');
              return res.redirect('/auth/forgot');
            }
            // proceed to send mail
            proceedSend(connection);
          });

          function proceedSend(conn) {
            // Send OTP email (do not disclose user existence in response)
            const mailOpts = {
              from: process.env.MAIL_FROM || process.env.MAIL_USER || 'no-reply@resend.dev',
              to: email,
              subject: 'Password Reset OTP',
              text: `Your OTP is ${otp}. It expires in 10 minutes.`
            };
            transporter.sendMail(mailOpts, function (errSmtp) {
              conn.release();
              if (errSmtp) {
                console.error('SMTP send failed:', errSmtp);
                req.flash('message', 'Could not send OTP email. Please try again later.');
                return res.redirect('/auth/forgot');
              }
              req.flash('message', 'If the email exists, an OTP has been sent.');
              return res.redirect('/auth/verify-otp?email=' + encodeURIComponent(email) + '&userType=' + encodeURIComponent(userType));
            });
          }
        } else {
          console.error('DB connection error while creating OTP:', cErr);
          req.flash('message', 'Temporary error, please try again.');
          return res.redirect('/auth/forgot');
        }
      });
    });
  });
});

// API: Return available beds (A, B, C) for a given block and room
app.get('/api/available-beds', verifyStudentJwt, function (req, res) {
  const block = ((req.query.block || '') + '').toUpperCase();
  const room = ((req.query.room || '') + '').toUpperCase();
  if (!room) {
    return res.status(400).json({ success: false, message: 'room is required' });
  }

  const allBeds = ['A', 'B', 'C', 'D', 'E', 'F'];

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    connection.query('SHOW COLUMNS FROM studentdetails', function (colErr, cols) {
      if (colErr) {
        connection.release();
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      const fields = new Set((cols || []).map(c => c.Field));
      const hasBlock = fields.has('block');
      const roomCol = fields.has('room_no') ? 'room_no' : (fields.has('room') ? 'room' : (fields.has('rno') ? 'rno' : null));
      const bedCol = fields.has('bed_no') ? 'bed_no' : (fields.has('bed') ? 'bed' : null);
      if (!roomCol || !bedCol) {
        connection.release();
        return res.status(500).json({ success: false, message: 'Room/Bed columns missing' });
      }

      let sql = `SELECT ${bedCol} as bed${hasBlock ? ', block' : ''} FROM studentdetails WHERE ${roomCol} = ? AND ${bedCol} IS NOT NULL AND ${bedCol} <> ''`;
      const params = [room];
      if (hasBlock && block) {
        sql += ' AND block = ?';
        params.push(block);
      }

      connection.query(sql, params, function (qerr, rows) {
        connection.release();
        if (qerr) {
          return res.status(500).json({ success: false, message: 'Database error' });
        }
        const taken = new Set();
        (rows || []).forEach(r => {
          const b = ((r.bed || '') + '').toUpperCase();
          if (allBeds.includes(b)) taken.add(b);
        });
        const available = allBeds.filter(b => !taken.has(b));
        return res.json({ success: true, block: block || undefined, room, beds: available });
      });
    });
  });
});

// GET Verify OTP page
app.get('/auth/verify-otp', function (req, res) {
  res.render(__dirname + '/views/auth/verify-otp', {
    message: req.flash('message'),
    email: req.query.email || '',
    userType: req.query.userType || 'student',
    mode: req.query.mode || '',
    uid: req.query.uid || ''
  });
});

// POST Verify OTP
app.post('/auth/verify-otp', function (req, res) {
  const email = (req.body.email || '').trim();
  const userType = (req.body.userType || 'student').trim();
  const otp = (req.body.otp || '').trim();
  const mode = (req.body.mode || '').trim();
  const uid = (req.body.uid || '').trim();
  if (!email || !otp || !['student', 'admin'].includes(userType)) {
    req.flash('message', 'Invalid request');
    return res.redirect('/auth/verify-otp?email=' + encodeURIComponent(email) + '&userType=' + encodeURIComponent(userType));
  }
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Temporary error');
      return res.redirect('/auth/verify-otp?email=' + encodeURIComponent(email) + '&userType=' + encodeURIComponent(userType));
    }
    const sel = `SELECT * FROM password_reset_tokens WHERE email=? AND user_type=? AND used=0 AND expires_at>=NOW() ORDER BY id DESC LIMIT 1`;
    connection.query(sel, [email, userType], function (qerr, rows) {
      if (qerr || !rows || rows.length === 0) {
        connection.release();
        req.flash('message', 'Invalid/expired OTP');
        return res.redirect('/auth/verify-otp?email=' + encodeURIComponent(email) + '&userType=' + encodeURIComponent(userType));
      }
      const tokenRow = rows[0];
      if (tokenRow.attempts >= 5) {
        connection.release();
        req.flash('message', 'Too many attempts. Please request a new OTP.');
        return res.redirect('/auth/forgot');
      }
      bcrypt.compare(otp, tokenRow.otp_hash, function (cErr, ok) {
        if (!ok) {
          const upd = 'UPDATE password_reset_tokens SET attempts=attempts+1 WHERE id=?';
          connection.query(upd, [tokenRow.id], function () { connection.release(); });
          req.flash('message', 'Incorrect OTP');
          return res.redirect('/auth/verify-otp?email=' + encodeURIComponent(email) + '&userType=' + encodeURIComponent(userType));
        }
        const markUsed = 'UPDATE password_reset_tokens SET used=1 WHERE id=?';
        connection.query(markUsed, [tokenRow.id], function (muErr) {
          if (muErr) {
            connection.release();
            req.flash('message', 'Temporary error');
            return res.redirect('/auth/forgot');
          }

          // Mode: reset student password back to default (mobile number)
          if (mode === 'default' && userType === 'student') {
            if (!uid) {
              connection.release();
              req.flash('message', 'Invalid request');
              return res.redirect('/student/forgot');
            }
            const updDefault = "UPDATE studentdetails SET password = NULL WHERE uid = ? AND email = ?";
            return connection.query(updDefault, [uid, email], function (uErr, result) {
              connection.release();
              if (uErr) {
                console.error('Reset to default failed:', uErr);
                req.flash('message', 'Could not reset password. Please try again.');
                return res.redirect('/student/forgot');
              }
              if (!result || result.affectedRows === 0) {
                req.flash('message', 'Could not reset password for this UID');
                return res.redirect('/student/forgot');
              }
              req.flash('message', 'Password reset to default (mobile number). Please login.');
              return res.redirect('/student/login');
            });
          }

          // Default flow: Issue short-lived resetToken (10 minutes)
          const payload = { scope: 'pwdreset', email, userType };
          jwt.sign(payload, secretkey, { expiresIn: '10m' }, function (sErr, resetToken) {
            connection.release();
            if (sErr) {
              req.flash('message', 'Temporary error');
              return res.redirect('/auth/forgot');
            }
            return res.redirect('/auth/reset?email=' + encodeURIComponent(email) + '&userType=' + encodeURIComponent(userType) + '&token=' + encodeURIComponent(resetToken));
          });
        });
      });
    });
  });
});

// =====================================================
// Student Forgot Password via UID (reset back to default mobile number)
// =====================================================
app.get('/student/forgot', function (req, res) {
  return res.render(__dirname + '/views/student_forgot', { message: req.flash('message') });
});

app.post('/student/forgot', function (req, res) {
  const uid = (req.body.uid || '').trim();
  if (!uid) {
    req.flash('message', 'UID is required');
    return res.redirect('/student/forgot');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err || !connection) {
      req.flash('message', 'Database error');
      return res.redirect('/student/forgot');
    }

    const sql = "SELECT uid, email FROM studentdetails WHERE uid = ? LIMIT 1";
    connection.query(sql, [uid], function (qErr, rows) {
      if (qErr || !rows || rows.length === 0) {
        connection.release();
        req.flash('message', 'Invalid UID');
        return res.redirect('/student/forgot');
      }

      const email = ((rows[0].email || '') + '').trim();
      if (!email) {
        connection.release();
        req.flash('message', 'No email found for this UID. Contact admin.');
        return res.redirect('/student/forgot');
      }

      const otp = randomOtp();
      bcrypt.hash(otp, 10, function (hErr, hash) {
        if (hErr) {
          connection.release();
          req.flash('message', 'Temporary error');
          return res.redirect('/student/forgot');
        }
        const expiresAt = formatDateTimeForDB(new Date(Date.now() + 10 * 60 * 1000));
        const ins = 'INSERT INTO password_reset_tokens (user_type, email, otp_hash, expires_at) VALUES (?,?,?,?)';
        connection.query(ins, ['student', email, hash, expiresAt], function (iErr) {
          if (iErr) {
            connection.release();
            console.error('OTP insert failed (student forgot):', iErr);
            req.flash('message', 'Could not create reset code. Please try again.');
            return res.redirect('/student/forgot');
          }

          const mailOpts = {
            from: process.env.MAIL_FROM || process.env.MAIL_USER || 'no-reply@resend.dev',
            to: email,
            subject: 'Student Password Reset OTP',
            text: `Your OTP is ${otp}. It expires in 10 minutes.`
          };
          transporter.sendMail(mailOpts, function (smtpErr) {
            connection.release();
            if (smtpErr) {
              console.error('SMTP send failed (student forgot):', smtpErr);
              req.flash('message', 'Could not send OTP email. Please try again later.');
              return res.redirect('/student/forgot');
            }

            req.flash('message', 'OTP sent to your registered email');
            return res.redirect(
              '/auth/verify-otp?email=' + encodeURIComponent(email)
              + '&userType=student'
              + '&mode=default'
              + '&uid=' + encodeURIComponent(uid)
            );
          });
        });
      });
    });
  });
});

// GET Reset page (set new password)
app.get('/auth/reset', function (req, res) {
  res.render(__dirname + '/views/auth/reset', {
    message: req.flash('message'),
    email: req.query.email || '',
    userType: req.query.userType || 'student',
    token: req.query.token || ''
  });
});

// POST Reset (set new password)
app.post('/auth/reset', function (req, res) {
  const email = (req.body.email || '').trim();
  const userType = (req.body.userType || 'student').trim();
  const token = (req.body.token || '').trim();
  const newPassword = (req.body.newPassword || '').trim();
  const confirmPassword = (req.body.confirmPassword || '').trim();
  if (!email || !token || !newPassword || newPassword !== confirmPassword) {
    req.flash('message', 'Invalid input or passwords do not match');
    return res.redirect('back');
  }
  // Verify reset token
  jwt.verify(token, secretkey, function (err, decoded) {
    if (err || !decoded || decoded.scope !== 'pwdreset' || decoded.email !== email || decoded.userType !== userType) {
      req.flash('message', 'Invalid or expired reset link');
      return res.redirect('/auth/forgot');
    }
    // Basic password policy
    if (newPassword.length < 8) {
      req.flash('message', 'Password must be at least 8 characters');
      return res.redirect('back');
    }
    bcrypt.hash(newPassword, 10, function (hErr, hash) {
      if (hErr) {
        req.flash('message', 'Temporary error');
        return res.redirect('back');
      }
      dbbconnection.getConnection(function (cErr, connection) {
        if (cErr) {
          req.flash('message', 'Temporary error');
          return res.redirect('back');
        }
        const upd = userType === 'admin'
          ? 'UPDATE admin SET password=? WHERE email=?'
          : 'UPDATE studentdetails SET password=? WHERE email=?';
        connection.query(upd, [hash, email], function (qerr) {
          connection.release();
          if (qerr) {
            req.flash('message', 'Failed to update password');
            return res.redirect('back');
          }
          // Clear sessions if any
          res.clearCookie('jwt');
          res.clearCookie('studentjwt');
          req.flash('message', 'Password updated. Please log in with your new password.');
          return res.redirect(userType === 'admin' ? '/loginpanel' : '/student/login');
        });
      });
    });
  });
});

// Helper function to format a date and time string as an IST wall-clock string (YYYY-MM-DD HH:MM:SS)
// IMPORTANT: Treats the provided dateStr/timeStr as already in IST, without shifting by server timezone
var formatDateTime = function (dateStr, timeStr) {
  if (!dateStr || !timeStr) return null;
  // Ensure seconds component is present
  var hhmmss = timeStr.length === 5 ? (timeStr + ':00') : timeStr;
  // Return the combined string directly for MySQL DATETIME storage
  // This avoids server timezone affecting the intended IST time selected by the user
  return `${dateStr} ${hhmmss}`;
};



// Auto-enforce midnight pass rules in IST (Asia/Kolkata)
// Runs ONCE at exactly 12:00 AM IST every day Ã¢â‚¬â€ NOT on an interval.
// This ensures the hostel-out Ã¢â€ â€™ hostel-in sync and restriction logic
// are applied exactly once at midnight, not repeatedly throughout the night.
var CronJob = require('cron').CronJob;
var post10pmPassRulesJob = new CronJob('0 0 * * *', function () {
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error('Database connection error during midnight pass rules job:', err);
      return;
    }

    sweepPost10pmPassRules(connection, function (jobErr, result) {
      if (jobErr) {
        console.error('Error enforcing midnight pass rules:', jobErr);
      } else if (result && !result.skipped) {
        console.log(`Midnight pass rules applied at 12 AM IST. Hostel sync complete and ${result.restrictedRows || 0} students restricted.`);
      }
      connection.release();
    });
  });
}, function () {
  /* This function is executed when the job stops */
},
  true, /* Start the job right now */
  IST_TIME_ZONE /* Time zone of this job. */
);

//Auto Reset Pass Requests Daily at 6 AM
var resetPassRequestsJob = new CronJob('0 0 * * *', function () {
  console.log('Running daily pass request reset at 12 AM...');

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error('Database connection error during pass request reset:', err);
      return;
    }

    // Only clear old PENDING requests.
    // Keep approved/rejected rows so gate scan can still activate passes even if approval was done on a previous day.
    var resetSql = `
      DELETE FROM pass_requests 
      WHERE status = 'pending' AND DATE(CONVERT_TZ(created_at, '+00:00', '+05:30')) < DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30'))
    `;

    connection.query(resetSql, function (err, result) {
      if (err) {
        console.error('Error resetting pass requests:', err);
      } else {
        console.log(`Pass request reset completed at 12 AM. ${result.affectedRows} requests reset.`);
      }
      connection.release();
    });
  });

  /*
  * Runs every day at 12:00:00 AM.
  */
}, function () {
  /* This function is executed when the job stops */
},
  true, /* Start the job right now */
  'Asia/Kolkata' /* Time zone of this job. */
);

//email configuration
const templatePath = __dirname + '/views/email.ejs';
const emailTemplate = fs.readFileSync(templatePath, 'utf-8');
const admissionWelcomeTemplate = fs.readFileSync(__dirname + '/views/admission-welcome.ejs', 'utf-8');
const bookingConfirmedTemplate = fs.readFileSync(__dirname + '/views/booking-confirmed.ejs', 'utf-8');
const hostelLogoPath = path.join(__dirname, 'public', 'images', 'hostellogo.png');
const hostelManagerSignPath = path.join(__dirname, 'public', 'images', 'fr-roby-sign.png');



const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

// Using Nodemailer (SMTP) for OTP emails


function currentdate() {
  return new Date(); // Returns a Date object representing the current server time
}

function formatDateTimeForDB(dateObj) {
  // Always output IST (Asia/Kolkata) wall-clock time regardless of server timezone
  return formatDateToISTString(dateObj);
}

function getDateTimeInUserTimeZone(dateObj) {
  if (!dateObj) return null;
  return dateObj.toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

function getDateTimeInUserTimeZone(dateObj) {
  if (!dateObj) return null;
  return dateObj.toLocaleString(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
}

function getdate(str) {
  const dateObject = new Date(str);
  // current date
  // adjust 0 before single digit date
  const date = (`${dateObject.getDate()}`).slice(-2);

  return (`${date}`);
}

function getmonth(str) {
  const dateObject = new Date(str);
  // current date
  // current month
  const month = (`${dateObject.getMonth() + 1}`).slice(-2);

  return (`${month}`);
}


function convert(str) {
  var date = new Date(str),
    mnth = ("0" + (date.getMonth() + 1)).slice(-2),
    day = ("0" + date.getDate()).slice(-2);
  return [date.getFullYear(), mnth, day].join("-");
}

app.get('/uploads/complaints/:filename', function (req, res) {
  var name = path.basename(String(req.params.filename || ''));
  if (!name) return res.status(404).end();
  res.sendFile(path.join(__dirname, 'uploads', 'complaints', name), function (err) {
    if (err) res.status(404).end();
  });
});
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyparser.json());
app.use(bodyparser.urlencoded({ extended: true }));
app.use(session({

  secret: 'tpdc',

  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: (1000 * 60 * 100)
  }

}));
app.use(cookieParser());
app.use(flash());

//View tables
app.set('view engine', 'ejs');


app.get('/', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID" || role == "Gateauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      res.render(__dirname + '/views/homepage', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //
});

app.get('/homepage', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID" || role == "Gateauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin" || role == "KitchenAdmin" || role == "Technician") {
      res.render(__dirname + '/views/unifiedscanner', { message: req.flash('message'), role: role, getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //
});

app.get('/Collegepage', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID" || role == "Gateauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      res.render(__dirname + '/views/Collegepage', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //
});

// Unified scanner (Hostel + Day Scholar)
app.get('/unifiedscanner', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    if (role == "SuperID" || role == "Hostelauthority" || role == "Gateauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      return res.render(__dirname + '/views/unifiedscanner', {
        message: req.flash('message'),
        role: role,
        getDateTimeInUserTimeZone: getDateTimeInUserTimeZone
      });
    }
    req.flash('message', 'Unauthorised Access', role);
    return res.redirect('/loginpanel');
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

app.get('/unifiedcodescanner/:uid', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  const backUrl = req.query.back === '/homepage' ? '/homepage' : '/unifiedscanner';
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    if (role == "SuperID" || role == "Hostelauthority" || role == "Gateauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      const uid = req.params.uid;
      dbbconnection.getConnection(function (err, connection) {
        if (err) {
          req.flash('message', 'Database error');
          return res.redirect(backUrl);
        }
        const sql = "SELECT category FROM studentdetails WHERE uid = ?";
        connection.query(sql, [uid], function (qErr, rows) {
          connection.release();
          if (qErr) {
            req.flash('message', 'Database error');
            return res.redirect(backUrl);
          }
          if (!rows || rows.length === 0) {
            req.flash('message', 'Invalid user');
            return res.redirect(backUrl);
          }

          const category = rows[0].category;
          if (category === 'Hostel') {
            return res.redirect('/codescanner/' + uid + '?back=' + encodeURIComponent(backUrl));
          }
          if (category === 'Day Scholar') {
            return res.redirect('/codescanner1/' + uid + '?back=' + encodeURIComponent(backUrl));
          }

          req.flash('message', 'Please mention the category,Contact admin');
          return res.redirect(backUrl);
        });
      });
    } else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

app.get('/gateouttoday', verifyjwt, function (req, res) {


  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID" || role == "Gateauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      dbbconnection.getConnection(function (err, connection) {
        var sql1 = "select log.logid,stu.uid,stu.sname,log.indatetime,log.outdatetime,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and indatetime is null and date(outdatetime) = date('" + formatDateTimeForDB(currentdate()) + "') ORDER BY log.logid desc";
        connection.query(sql1, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/gateouttoday', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
        connection.release();
      });

    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //
});

//hostel out for hostel authority
app.get('/hostelouttoday', verifyjwt, function (req, res) {


  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "SuperID" || role == "Hostelauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      dbbconnection.getConnection(function (err, connection) {
        var sql1 = "select log.logid,stu.uid,stu.sname,stu.mobileno,log.approvaldt,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and log.hostelintime is null and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql1, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/hostelouttoday', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
        connection.release();
      });

    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //
});

app.get('/bound', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    var role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database connection error');
        return res.redirect('/loginpanel');
      }

      if (role == "BoysHostelAdmin") {
        var sql = "select * from timebound where hostel='Boys'";
        connection.query(sql, function (err, result) {
          connection.release();
          if (err) throw err;
          res.render(__dirname + '/views/bound', { result: result, role: role, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
        });
      }
      else if (role == "GirlsHostelAdmin") {
        var sql = "select * from timebound where hostel='Girls'";
        connection.query(sql, function (err, result) {
          connection.release();
          if (err) throw err;
          res.render(__dirname + '/views/bound', { result: result, role: role, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
        });
      }
      else if (role == "SuperID") {
        var sql = "select * from timebound";
        connection.query(sql, function (err, result) {
          connection.release();
          if (err) throw err;
          res.render(__dirname + '/views/bound', { result: result, role: role, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
        });
      }
      else {
        connection.release();
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }
    });


  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }

});

//reports


//Department Columns Chart

app.get('/deptdetails', (req, res) => {
  const query = "SELECT dept,count(*) as Count FROM studentdetails where category='Hostel' group by dept"; // Replace with your table name
  dbbconnection.getConnection(function (err, connection) {
    connection.query(query, (err, data) => {
      if (err) {
        console.error('Error fetching data from MySQL:', err);
        return res.status(500).send('Error fetching data from MySQL');
      }
      else {
        res.json(data)
      }


    });
  });
});

// All distinct branch names (dept) from studentdetails - for HOD dropdown etc.
app.get('/api/branches', verifyjwt, function (req, res) {
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    var sql = "SELECT DISTINCT TRIM(dept) AS dept FROM studentdetails WHERE dept IS NOT NULL AND TRIM(dept) <> '' ORDER BY dept";
    connection.query(sql, function (qErr, rows) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ error: 'Error fetching branches' });
      }
      var raw = (rows || []).map(function (r) { return r.dept; });
      var bvocVariants = ['B.VOC. in Cyber Security', 'B.VOC. in Software Development', 'B.VOC. in Virtual Reality & AR'];
      var branches = raw.filter(function (d) { return bvocVariants.indexOf(d) === -1; });
      var hasBvoc = raw.some(function (d) { return bvocVariants.indexOf(d) !== -1; });
      if (hasBvoc && branches.indexOf('B Vocational') === -1) branches.push('B Vocational');
      branches.sort();
      res.json({ branches: branches });
    });
  });
});

// Student Forgot Password - Request code
app.get('/student/forgot', function (req, res) {
  return res.render(__dirname + '/views/student_forgot', { message: req.flash('message') });
});

app.post('/student/forgot', function (req, res) {
  const uid = (req.body.uid || '').trim();
  if (!uid) {
    req.flash('message', 'Please enter your UID');
    return res.redirect('/student/forgot');
  }
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/forgot');
    }
    const sql = 'SELECT uid, sname, email FROM studentdetails WHERE uid = ? LIMIT 1';
    connection.query(sql, [uid], function (err, rows) {
      if (err || rows.length === 0) {
        connection.release();
        req.flash('message', 'Student not found');
        return res.redirect('/student/forgot');
      }
      const student = rows[0];
      if (!student.email) {
        connection.release();
        req.flash('message', 'No email found on your profile. Contact admin.');
        return res.redirect('/student/forgot');
      }
      // Generate 6-digit code and expiry 15 minutes
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      const expirySql = "UPDATE studentdetails SET password_reset_code = ?, password_reset_expires = DATE_ADD(NOW(), INTERVAL 15 MINUTE) WHERE uid = ?";
      connection.query(expirySql, [code, uid], function (uerr) {
        connection.release();
        if (uerr) {
          req.flash('message', 'Could not create reset code');
          return res.redirect('/student/forgot');
        }
        // Send email
        const mailOptions = {
          from: 'tnps@stvincentngp.edu.in',
          to: student.email,
          subject: 'Password reset code',
          html: `<p>Hi ${student.sname || 'Student'},</p><p>Your password reset code is <b>${code}</b>. It expires in 15 minutes.</p>`
        };
        transporter.sendMail(mailOptions, function (merr) {
          if (merr) {
            console.error('Reset mail error:', merr);
            req.flash('message', 'Failed to send email. Try again later.');
            return res.redirect('/student/forgot');
          }
          req.flash('message', 'Reset code sent to your email');
          return res.redirect('/student/reset?uid=' + encodeURIComponent(uid));
        });
      });
    });
  });
});

// Student Reset Password - Verify code and set new password
app.get('/student/reset', function (req, res) {
  return res.render(__dirname + '/views/student_reset', { message: req.flash('message'), uid: req.query.uid || '' });
});

app.post('/student/reset', async function (req, res) {
  const uid = (req.body.uid || '').trim();
  const code = (req.body.code || '').trim();
  const newPassword = (req.body.newPassword || '').trim();
  const confirmPassword = (req.body.confirmPassword || '').trim();
  if (!uid || !code || !newPassword || !confirmPassword) {
    req.flash('message', 'All fields are required');
    return res.redirect('/student/reset?uid=' + encodeURIComponent(uid));
  }
  if (newPassword !== confirmPassword) {
    req.flash('message', 'Passwords do not match');
    return res.redirect('/student/reset?uid=' + encodeURIComponent(uid));
  }
  if (newPassword.length < 6) {
    req.flash('message', 'Password must be at least 6 characters');
    return res.redirect('/student/reset?uid=' + encodeURIComponent(uid));
  }
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/reset?uid=' + encodeURIComponent(uid));
    }
    const sql = `SELECT uid FROM studentdetails 
                 WHERE uid = ? AND password_reset_code = ? 
                   AND password_reset_expires IS NOT NULL 
                   AND password_reset_expires > NOW() LIMIT 1`;
    connection.query(sql, [uid, code], async function (qerr, rows) {
      if (qerr || rows.length === 0) {
        connection.release();
        req.flash('message', 'Invalid or expired code');
        return res.redirect('/student/reset?uid=' + encodeURIComponent(uid));
      }
      try {
        const hash = await bcrypt.hash(newPassword, 12);
        const up = "UPDATE studentdetails SET password = ?, password_reset_code = NULL, password_reset_expires = NULL WHERE uid = ?";
        connection.query(up, [hash, uid], function (uerr2) {
          connection.release();
          if (uerr2) {
            req.flash('message', 'Error updating password');
            return res.redirect('/student/reset?uid=' + encodeURIComponent(uid));
          }
          req.flash('message', 'Password reset successful. Please log in.');
          return res.redirect('/student/login');
        });
      } catch (e) {
        connection.release();
        req.flash('message', 'Internal error');
        return res.redirect('/student/reset?uid=' + encodeURIComponent(uid));
      }
    });
  });
});


//Status pie chart api
app.get('/datastatus', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID") {
      dbbconnection.getConnection(function (err, connection) {
        var sql = "select CASE WHEN status = 'Restrict' THEN 'Restrict' ELSE 'Unrestrict' END as status, count(*) as Count from studentdetails where category='Hostel' group by CASE WHEN status = 'Restrict' THEN 'Restrict' ELSE 'Unrestrict' END";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.json(result)
          }
        })
      })
    }
    else if (role == "BoysHostelAdmin" || role == "Hostelauthority") {
      dbbconnection.getConnection(function (err, connection) {
        var sql = "select CASE WHEN status = 'Restrict' THEN 'Restrict' ELSE 'Unrestrict' END as status, count(*) as Count from studentdetails where gender='MALE' and category='Hostel' group by CASE WHEN status = 'Restrict' THEN 'Restrict' ELSE 'Unrestrict' END";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.json(result)
          }
        })
      })
    }
    else if (role == "GirlsHostelAdmin") {
      dbbconnection.getConnection(function (err, connection) {
        var sql = "select CASE WHEN status = 'Restrict' THEN 'Restrict' ELSE 'Unrestrict' END as status, count(*) as Count from studentdetails where gender='FEMALE' and category='Hostel' group by CASE WHEN status = 'Restrict' THEN 'Restrict' ELSE 'Unrestrict' END";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.json(result)
          }
        })
      })
    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }

});



//line chart api
app.get('/datatimelines', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID") {
      dbbconnection.getConnection(function (err, connection) {
        var sql = "select hour(approvaldt) as Timeframe ,count(log.uid) as Count from log_details1 as log join studentdetails as stu where stu.uid=log.uid and DATE(approvaldt) = '" + convert(formatDateTimeForDB(currentdate())) + "' and stu.category='Hostel' group by hour(approvaldt)";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.json(result)
          }
        })
      })
    }
    else if (role == "BoysHostelAdmin" || role == "Hostelauthority") {
      dbbconnection.getConnection(function (err, connection) {
        var sql = "select hour(approvaldt) as Timeframe ,count(log.uid) as Count from log_details1 as log join studentdetails as stu where stu.uid=log.uid and DATE(approvaldt) = '" + convert(formatDateTimeForDB(currentdate())) + "' and stu.category='Hostel' and stu.gender='MALE' group by hour(approvaldt)";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.json(result)
          }
        })
      })
    }
    else if (role == "GirlsHostelAdmin") {
      dbbconnection.getConnection(function (err, connection) {
        var sql = "select hour(approvaldt) as Timeframe ,count(log.uid) as Count from log_details1 as log join studentdetails as stu where stu.uid=log.uid and DATE(approvaldt) = '" + convert(formatDateTimeForDB(currentdate())) + "' and stu.category='Hostel' and stu.gender='FEMALE' group by hour(approvaldt)";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.json(result)
          }
        })
      })
    }

    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }

});


app.get('/takein/:uid', function (req, res) {
  var uid = req.params.uid;

  dbbconnection.getConnection(function (err, connection) {
    var sql = "select * From studentdetails where category='Hostel' and uid='" + uid + "' ";
    connection.query(sql, function (err, result) {
      if (err) throw err;
      else {
        if (!result[0] == 0) {
          res.render(__dirname + '/views/takein', { getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
        }
        else {
          req.flash('message', 'Please scan the Id of Hosteliers');
          res.redirect('/tokenhomepage');
        }
      }
    });
    connection.release();
  });
});


app.post('/takein/:logid', verifyjwt, function (req, res) {
  var logid = req.params.logid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database connection error');
      return res.redirect('/tokenhomepage');
    }
    checkHostelInRestriction(connection, logid, function (restrictErr, isRestricted) {
      if (restrictErr) {
        connection.release();
        req.flash('message', 'Error checking restriction');
        return res.redirect('/tokenhomepage');
      }

      if (isRestricted) {
        connection.release();
        req.flash('message', 'Restricted due to 10pm rule');
        return res.redirect('/tokenhomepage');
      }

      var takeinquery = "Update log_details1 set status='DEAD',hostelintime='" + formatDateTimeForDB(currentdate()) + "' where logid='" + logid + "'"
      connection.query(takeinquery, function (err, result) {
        connection.release();
        if (err) throw err
        else {
          req.flash('message', 'Your log is updated successfully');
          res.redirect('/tokenhomepage');
        }
      });
    });
  });
});

//update time bound
app.post('/updatetimebound', verifyjwt, function (req, res) {
  var day = req.body.dropdownlist1;
  var start = req.body.StartTime1;
  var end = req.body.EndTime1;
  var start1 = req.body.StartTime2;
  var end1 = req.body.EndTime2;
  var hostel = req.body.hostel;
  console.log('[updatetimebound] Received:', { day, start, end, start1, end1, hostel });
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    var role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (err) throw err;

      if (role == "SuperID" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
        var targetHostel = hostel;
        if (role == "BoysHostelAdmin") targetHostel = "Boys";
        if (role == "GirlsHostelAdmin") targetHostel = "Girls";
        // Fallback: SuperID must supply hostel; default to 'Boys' if missing
        if (role == "SuperID" && (!targetHostel || targetHostel === 'undefined')) targetHostel = "Boys";

        const dayNoMap = {
          'Sunday': '0',
          'Monday': '1',
          'Tuesday': '2',
          'Wednesday': '3',
          'Thursday': '4',
          'Friday': '5',
          'Saturday': '6'
        };
        const dayno = dayNoMap[day] || '';

        var checkSql = "SELECT * FROM timebound WHERE hostel = ? AND days = ?";
        connection.query(checkSql, [targetHostel, day], function (err, rows) {
          if (err) {
            connection.release();
            throw err;
          }
          if (rows && rows.length > 0) {
            var updateSql = "UPDATE timebound SET start = ?, end = ?, start1 = ?, end1 = ?, dayno = ? WHERE hostel = ? AND days = ?";
            connection.query(updateSql, [start, end, start1, end1, dayno, targetHostel, day], function (err, result) {
              connection.release();
              if (err) throw err;
              req.flash('message', 'Time Bound Updated successfully');
              res.redirect('/bound');
            });
          } else {
            var insertSql = "INSERT INTO timebound (days, start, end, start1, end1, dayno, hostel) VALUES (?, ?, ?, ?, ?, ?, ?)";
            connection.query(insertSql, [day, start, end, start1, end1, dayno, targetHostel], function (err, result) {
              connection.release();
              if (err) throw err;
              req.flash('message', 'Time Bound Updated successfully');
              res.redirect('/bound');
            });
          }
        });
      } else {
        connection.release();
        req.flash('message', 'Unauthorised access');
        res.redirect('/loginpanel');
      }
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});


app.get('/deletetimebound/:tbid', verifyjwt, function (req, res) {
  const tbid = req.params.tbid;
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    var role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (err) throw err;

      var checkSql = "SELECT * FROM timebound WHERE tbid = ?";
      connection.query(checkSql, [tbid], function (err, rows) {
        if (err) {
          connection.release();
          throw err;
        }
        if (rows && rows.length > 0) {
          const record = rows[0];
          let allowed = false;
          if (role === "SuperID") allowed = true;
          else if (role === "BoysHostelAdmin" && record.hostel === "Boys") allowed = true;
          else if (role === "GirlsHostelAdmin" && record.hostel === "Girls") allowed = true;

          if (allowed) {
            var deleteSql = "DELETE FROM timebound WHERE tbid = ?";
            connection.query(deleteSql, [tbid], function (err, result) {
              connection.release();
              if (err) throw err;
              req.flash('message', 'Time Bound removed successfully');
              res.redirect('/bound');
            });
          } else {
            connection.release();
            req.flash('message', 'Unauthorised access');
            res.redirect('/bound');
          }
        } else {
          connection.release();
          req.flash('message', 'Time Bound record not found');
          res.redirect('/bound');
        }
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

app.get('/toggletimebound/:tbid/:status', verifyjwt, function (req, res) {
  const tbid = req.params.tbid;
  const newStatus = req.params.status === 'INACTIVE' ? 'INACTIVE' : 'ACTIVE';
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    var role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (err) throw err;
      
      var checkSql = "SELECT * FROM timebound WHERE tbid = ?";
      connection.query(checkSql, [tbid], function (err, rows) {
        if (err) {
          connection.release();
          throw err;
        }
        if (rows && rows.length > 0) {
          const record = rows[0];
          let allowed = false;
          if (role === "SuperID") allowed = true;
          else if (role === "BoysHostelAdmin" && record.hostel === "Boys") allowed = true;
          else if (role === "GirlsHostelAdmin" && record.hostel === "Girls") allowed = true;
          
          if (allowed) {
            var updateSql = "UPDATE timebound SET status = ? WHERE tbid = ?";
            connection.query(updateSql, [newStatus, tbid], function (err, result) {
              connection.release();
              if (err) throw err;
              req.flash('message', 'Time Bound ' + (newStatus === 'ACTIVE' ? 'enabled' : 'disabled') + ' successfully');
              res.redirect('/bound');
            });
          } else {
            connection.release();
            req.flash('message', 'Unauthorised access');
            res.redirect('/bound');
          }
        } else {
          connection.release();
          req.flash('message', 'Time Bound record not found');
          res.redirect('/bound');
        }
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});


app.get('/token/:uid', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  const specificDate = currentdate(); // Create a new Date object
  const Time = formatDateTimeForDB(currentdate()).split(" ", 3);
  const day = specificDate.getDay(); // Get the day of the week (0-6)

  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID" || role == "Hostelauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      var uid = req.params.uid;
      dbbconnection.getConnection(function (err, connection) {
        var sql = "select * From studentdetails where category='Hostel' and uid='" + uid + "' ";
        var details = "Select stu.uid,log.logid,stu.path,log.approvaldt from log_details1 as log left join studentdetails as stu on log.uid=stu.uid where logid=(select max(logid) from log_details1 where uid='" + uid + "')"

        connection.query(sql, function (err, result) {
          if (err) throw err;
          if (!result || result.length === 0) {
            req.flash('message', 'Student not found or no data available.');
            return res.redirect('/tokenhomepage');
          }
          else if (result[0].status == 'Restrict') {
            req.flash('message', 'Your Id is Blocked, Please contact hostel admin');
            res.redirect('/tokenhomepage');
          }
          else {
            connection.query(details, function (err, details) {
              if (err) throw err;
              else {
                if (!result[0] == 0) {
                  if (result[0].gender == 'MALE') {

                    var logquery = "Select * from log_details1 where logid=(select max(logid) from log_details1 where uid='" + uid + "')";
                    connection.query(logquery, function (err, result1) {
                      if (err) throw err;
                      if (!result1[0] == 0) {
                        if (result1[0].status == 'ACTIVE') {
                          res.render(__dirname + '/views/takein', { result: details });
                        }
                        else if (result1[0].status == 'DEAD') {

                          if (!result1[0].hostelintime == 0) {

                            // var checktime = "SELECT * FROM timebound WHERE ((start <= '" + Time[2] + "' AND end>= '" + Time[2] + "') OR (start1 <= '" + Time[2] + "' AND end1>= '" + Time[2] + "')) AND dayno='" + day + "'AND hostel='Boys';";
                            // connection.query(checktime, function (err, check) {
                            // if (err) throw err;
                            // else if (!check[0] == 0) {
                            res.render(__dirname + '/views/token', { result: result });
                            // }
                            // else {

                            // req.flash('message', 'Time Bounded');
                            // res.redirect('/tokenhomepage');
                            // }
                            // });
                          }
                          else {
                            res.render(__dirname + '/views/takein', { result: details })
                          }

                        }
                        else {
                          req.flash('message', 'There is issue ERROR 131, Please Contact Admin');
                          res.redirect('/tokenhomepage');
                        }
                      }
                      else {
                        res.render(__dirname + '/views/token', { result: result });
                      }
                    })

                  }
                  else if (result[0].gender === 'FEMALE') {

                    var logquery = "Select * from log_details1 where logid=(select max(logid) from log_details1 where uid='" + uid + "')";
                    connection.query(logquery, function (err, result1) {
                      if (err) throw err;
                      if (!result1[0] == 0) {
                        if (result1[0].status == 'ACTIVE') {
                          res.render(__dirname + '/views/takein', { result: details });
                        }
                        else if (result1[0].status == 'DEAD') {

                          if (!result1[0].hostelintime == 0) {
                            // var checktime = "SELECT * FROM timebound WHERE start <= '" + Time[2] + "' AND end>= '" + Time[2] + "' and dayno='" + day + "'and hostel='Girls';";
                            // connection.query(checktime, function (err, check) {
                            // if (err) throw err;
                            // else if (!check[0] == 0) {
                            res.render(__dirname + '/views/token', { result: result });
                            // }
                            // else {
                            // req.flash('message', 'Time Bounded');
                            // res.redirect('/tokenhomepage');
                            // }
                            // });
                          }
                          else {
                            res.render(__dirname + '/views/takein', { result: details })
                          }

                        }
                        else {
                          req.flash('message', 'There is issue ERROR 131, Please Contact Admin');
                          res.redirect('/tokenhomepage');
                        }
                      }
                      else {
                        res.render(__dirname + '/views/token', { result: result });
                      }
                    })

                  }
                }
                else {
                  req.flash('message', 'Please scan the Id of Hosteliers');
                  res.redirect('/tokenhomepage');
                }
              }
            });
          }
        });
        connection.release();

      });
    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }



});


//List all user
app.get('/updateuser', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (err) throw err;
      else if (role == "SuperID") {

        var sql = "select * From admin ";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/updateuser', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "BoysHostelAdmin") {
        var sql = "select * From admin where hostel='Boys' ";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/updateuser', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "GirlsHostelAdmin") {
        var sql = "select * From admin where hostel='Girls' ";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/updateuser', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else {
        req.flash('message', 'Unauthourised access ', role);
        res.redirect('/loginpanel');
      }
      connection.release();
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }


});


//add user
app.get('/adduser', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;

    if (role == "SuperID" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      res.render(__dirname + '/views/adduser', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
    }
    else {
      req.flash('message', 'Unauthourised access ', role);
      res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }

});


app.get('/tokenhomepage', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID" || role == "Hostelauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      res.render(__dirname + '/views/tokenhomepage', {
        message: req.flash('message'),
        role: role,
        getDateTimeInUserTimeZone: getDateTimeInUserTimeZone
      });
    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }


});

//user profile
app.get('/userprofile/:uid', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;

    if (role == "SuperID" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      var uid = req.params.uid;
      dbbconnection.getConnection(function (err, connection) {
        if (err) throw err;

        var sql = "Select * from admin where uid='" + uid + "'";

        connection.query(sql, function (err, result) {
          if (err) {

            throw err
          }

          else {
            res.render(__dirname + '/views/userprofile', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }

        });
        connection.release();
      });
    }
    else {
      req.flash('message', 'Unauthourised access ', role);
      res.redirect('/loginpanel');
    }

  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }



});

//Delete user
app.get('/deleteuser/:uid', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;

    if (role == "SuperID" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      var uid = req.params.uid;
      dbbconnection.getConnection(function (err, connection) {
        if (err) throw err;

        var sql = "Delete from admin where uid = '" + uid + "'";

        connection.query(sql, function (err, result) {
          if (err) {

            throw err
          }

          else {
            req.flash('message', 'Deleted successfully');
            res.redirect('/updateuser');
          }

        });
        connection.release();
      });
    }
    else {
      req.flash('message', 'Unauthourised access ', role);
      res.redirect('/loginpanel');
    }

  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }



});



app.post('/saveuser/:id', async function (req, res) {
  var id = req.params.id;
  var uid = req.body.uid;
  var name = req.body.name;
  var category = req.body.category;
  let password = await bcrypt.hash(req.body.password, 12);
  var hostel = req.body.hostel;
  dbbconnection.getConnection(function (err, connection) {
    if (err) throw err;

    var sql = "Update admin set uid='" + uid + "',name='" + name + "',category='" + category + "',password='" + password + "',hostel='" + hostel + "' where adminid='" + id + "' ";

    connection.query(sql, function (err, result) {
      if (err) {

        throw err
      }

      else {
        req.flash('message', 'Updated successfully');
        res.redirect('/updateuser');
      }

    })
    connection.release();
  });


});


//add user
app.post('/adduser', async function (req, res) {
  var uid = req.body.uid;
  var name = req.body.name;
  var category = req.body.category;
  let password = await bcrypt.hash(req.body.password, 12);
  var hostel = req.body.hostel;
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database connection error');
      return res.redirect('/adduser');
    }

    var sql = "Insert into admin (uid,name,password,category,hostel) VALUES ? ";
    var values = [[uid, name, password, category, hostel]]

    connection.query(sql, [values], function (err, result) {
      connection.release();
      if (err) {
        if (err.code === 'ER_DUP_ENTRY' || err.errno === 1062) {
          req.flash('message', 'User ID already exists');
          return res.redirect('/adduser');
        }
        req.flash('message', 'Error adding user');
        return res.redirect('/adduser');
      }

      req.flash('message', 'Added successfully');
      res.redirect('/daterange');
    });

  });


});



app.get('/instudents/:id', verifyjwt, function (req, res) {

  var id = req.params.id;


  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database connection error');
      return res.redirect('/outstudents');
    }
    checkHostelInRestriction(connection, id, function (restrictErr, isRestricted) {
      if (restrictErr) {
        connection.release();
        req.flash('message', 'Error checking restriction');
        return res.redirect('/outstudents');
      }

      if (isRestricted) {
        connection.release();
        req.flash('message', 'Restricted due to 10pm rule');
        return res.redirect('/outstudents');
      }

      var sql = "Update log_details1 set hostelintime='" + formatDateTimeForDB(currentdate()) + "',status='DEAD' where logid='" + id + "'";
      connection.query(sql, function (err, result) {
        connection.release();
        if (err) throw err;
        else {
          req.flash('message', 'Updated successfully');
          res.redirect('/outstudents');
        }
      });
    });
  });



});

//posting token in database with uid
app.post('/token/:uid', function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    var name = decode.adminname;
    dbbconnection.getConnection(function (err, connection) {
      var uid = req.params.uid;
      var passtype = req.body.radio;
      var sql = "Select * from log_details1 where logid= (Select max(logid) from log_details1 where uid='" + uid + "')";
      connection.query(sql, function (err, result) {
        if (err) throw err;
        else {
          if (!result[0] == 0) {

            if (result[0].status == 'ACTIVE') {
              req.flash('message', 'New Pass can not be Created');
              res.redirect('/tokenhomepage');
            }
            else if (result[0].status == 'DEAD') {
              var insertsql1 = "Insert into log_details1 (uid,status,approvaldt,passtype,hosteloutauth) VALUES ('" + uid + "','ACTIVE','" + formatDateTimeForDB(currentdate()) + "','" + passtype + "','" + name + "')";
              connection.query(insertsql1, function (err, result) {
                if (err) throw err;
                else {

                  // req.flash('message', 'Gate Pass Generated Successfully');
                  // res.redirect('/tokenhomepage');

                  //start
                  var fetchstu = "Select * from studentdetails where uid='" + uid + "'"
                  connection.query(fetchstu, function (err, fetched) {
                    const data = {
                      name: fetched[0].sname,
                      uid: fetched[0].uid,
                      date: formatDateTimeForDB(currentdate()),
                      pass: passtype
                    };

                    // Render the email template with EJS
                    const renderedTemplate = ejs.render(emailTemplate, data);

                    // Email options
                    const mailOptions = {
                      from: 'tnps@stvincentngp.edu.in',
                      to: fetched[0].email,
                      subject: "Hostel Pass Generated successfully ['" + formatDateTimeForDB(currentdate()) + "']",
                      html: renderedTemplate,
                      attachments: [
                        { filename: 'hostellogo.png', path: hostelLogoPath, cid: 'hostel-logo' }
                      ]
                    };

                    // Send the email
                    transporter.sendMail(mailOptions, (error, info) => {
                      if (error) {
                        console.error(error);
                        console.log('message:', error)
                        req.flash('message', 'Gate Pass Generated Successfully');
                        res.redirect('/tokenhomepage');
                      } else {
                        console.log('Email sent:', info.response);
                        req.flash('message', 'Gate Pass Generated Successfully');
                        res.redirect('/tokenhomepage');
                      }
                    });
                  })
                  //end

                }
              })
            }

          }
          else {
            var insertsql1 = "Insert into log_details1 (uid,status,approvaldt,passtype,hosteloutauth) VALUES ('" + uid + "','ACTIVE','" + formatDateTimeForDB(currentdate()) + "','" + passtype + "','" + name + "')";
            connection.query(insertsql1, function (err, result) {
              if (err) throw err;
              else {
                // req.flash('message', 'Gate Pass Generated Successfully');
                // res.redirect('/tokenhomepage');
                //start
                var fetchstu = "Select * from studentdetails where uid='" + uid + "'"
                connection.query(fetchstu, function (err, fetched) {
                  const data = {
                    name: fetched[0].sname,
                    uid: fetched[0].uid,
                    date: formatDateTimeForDB(currentdate()),
                    pass: passtype
                  };

                  // Render the email template with EJS
                  const renderedTemplate = ejs.render(emailTemplate, data);

                  // Email options
                  const mailOptions = {
                    from: 'tnps@stvincentngp.edu.in',
                    to: fetched[0].email,
                    subject: "Pass is Generated for UID: '" + uid + "'",
                    html: renderedTemplate,
                    attachments: [
                      { filename: 'hostellogo.png', path: hostelLogoPath, cid: 'hostel-logo' }
                    ]
                  };

                  // Send the email
                  transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                      console.log('message:', error)
                      req.flash('message', 'Gate Pass Generated Successfully');
                      res.redirect('/tokenhomepage');
                    } else {
                      console.log('Email sent:', info.response);
                      req.flash('message', 'Gate Pass Generated Successfully');
                      res.redirect('/tokenhomepage');
                    }
                  });
                })
                //end
              }
            })
          }
        }
      });
      connection.release();
    })
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }

});

app.get('/studentsupdatehostel/:role', verifyjwt, function (req, res) {
  var role = req.params.role;
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error(err);
      req.flash('message', 'Database Connection Error');
      return res.redirect('/loginpanel');
    }

    if (role == "BoysHostelAdmin") {
      var sql = "select * from studentdetails where gender='MALE' and category='Hostel'";
      connection.query(sql, function (err, result) {
        connection.release();
        if (err) {
          console.error(err);
          req.flash('message', 'Database Query Error');
          return res.redirect('/loginpanel');
        }
        (result || []).forEach(attachStudentPhotoUrl);
        res.render(__dirname + '/views/studentsupdatehostel', {
          result: result,
          message: req.flash('message'),
          getDateTimeInUserTimeZone: getDateTimeInUserTimeZone,
          role: role
        });
      });
    }
    else if (role == "GirlsHostelAdmin") {
      var sql = "select * from studentdetails where gender='FEMALE' and category='Hostel'";
      connection.query(sql, function (err, result) {
        connection.release();
        if (err) {
          console.error(err);
          req.flash('message', 'Database Query Error');
          return res.redirect('/loginpanel');
        }
        (result || []).forEach(attachStudentPhotoUrl);
        res.render(__dirname + '/views/studentsupdatehostel', {
          result: result,
          message: req.flash('message'),
          getDateTimeInUserTimeZone: getDateTimeInUserTimeZone,
          role: role
        });
      });
    }
    else if (role == "SuperID") {
      var sql = "select * from studentdetails where category='Hostel'";
      connection.query(sql, function (err, result) {
        connection.release();
        if (err) {
          console.error(err);
          req.flash('message', 'Database Query Error');
          return res.redirect('/loginpanel');
        }
        (result || []).forEach(attachStudentPhotoUrl);
        res.render(__dirname + '/views/studentsupdatehostel', {
          result: result,
          message: req.flash('message'),
          getDateTimeInUserTimeZone: getDateTimeInUserTimeZone,
          role: role
        });
      });
    }
    else {
      connection.release();
      req.flash('message', 'Unauthorised Access');
      res.redirect('/loginpanel');
    }
  });
});

// Download hostel student details as CSV (Excel-compatible) for the same set shown on studentsupdatehostel
app.get('/studentsupdatehostel/:role/download', verifyjwt, function (req, res) {
  var role = req.params.role;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error('DB connection error for hostel export:', err);
      req.flash('message', 'Error generating export.');
      return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
    }

    var sql;
    if (role == "BoysHostelAdmin") {
      sql = "select * from studentdetails where gender='MALE' and category='Hostel'";
    } else if (role == "GirlsHostelAdmin") {
      sql = "select * from studentdetails where gender='FEMALE' and category='Hostel'";
    } else if (role == "SuperID") {
      sql = "select * from studentdetails where category='Hostel'";
    } else {
      connection.release();
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    connection.query(sql, function (qErr, result) {
      connection.release();

      if (qErr) {
        console.error('Query error for hostel export:', qErr);
        req.flash('message', 'Error generating export.');
        return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
      }

      var rows = result || [];
      if (!rows.length) {
        req.flash('message', 'No hostel students found to export.');
        return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
      }

      function csvEscape(v) {
        if (v === undefined || v === null) return '""';
        var s = String(v).replace(/"/g, '""');
        return '"' + s + '"';
      }

      var header = [
        'UID',
        'Name',
        'Email',
        'Department',
        'Address',
        'Year',
        'Category',
        'Gender',
        'Mobile',
        'DOB',
        'AcademicYear',
        'RoomNo',
        'BedNo',
        'MessType',
        'Block',
        'ParentName',
        'ParentNumber',
        'Status'
      ];

      var lines = [];
      lines.push(header.join(','));

      rows.forEach(function (r) {
        lines.push([
          csvEscape(r.uid),
          csvEscape(r.sname),
          csvEscape(r.email),
          csvEscape(r.dept),
          csvEscape(r.address),
          csvEscape(r.year),
          csvEscape(r.category),
          csvEscape(r.gender),
          csvEscape(r.mobileno),
          csvEscape(r.dob),
          csvEscape(r.academicyear),
          csvEscape(r.room_no),
          csvEscape(r.bed_no),
          csvEscape(r.mess_type || r.other1),
          csvEscape(r.block || r.other2),
          csvEscape(r.parentname),
          csvEscape(r.parentnumber),
          csvEscape(r.status)
        ].join(','));
      });

      var csv = lines.join('\n');
      var fileName = 'hostel_students_' + role + '.csv';

      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="' + fileName + '"');
      res.send(csv);
    });
  });
});

app.get('/studentsupdatehostel/:role/export-master', verifyjwt, function (req, res) {
  var role = req.params.role;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Error generating export.');
      return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
    }

    var sql = "SELECT sd.uid, sd.sname, sd.email, sd.dept, sd.year, sd.academicyear, sd.gender, sd.mobileno, sd.dob, sd.address, sd.mess_type, sd.parentname, sd.parentnumber, sd.status, COALESCE(rb.room_no, sd.room_no) AS final_room_no, COALESCE(rb.block, sd.block) AS final_block, COALESCE(rb.bed_no, sd.bed_no) AS final_bed_no, sd.hostel_id AS haa_hostel_id, haa.full_name AS haa_full_name, haa.father_name AS haa_father_name, haa.father_occupation AS haa_father_occupation, haa.mother_name AS haa_mother_name, haa.mother_occupation AS haa_mother_occupation, haa.permanent_address AS haa_address, haa.parent_phone AS haa_parent_phone, haa.student_mobile AS haa_student_mobile, haa.student_email AS haa_student_email, haa.religion AS haa_religion, haa.caste_category AS haa_caste, haa.mess_preference AS haa_mess, haa.dob AS haa_dob, haa.admission_year AS haa_batch, haa.branch AS haa_branch, haa.submission_date AS haa_submission_date, rm.capacity AS room_capacity FROM studentdetails sd LEFT JOIN room_bookings rb ON rb.uid = sd.uid AND rb.booking_status = 'locked' AND rb.id = ( SELECT MAX(rb2.id) FROM room_bookings rb2 WHERE rb2.uid = sd.uid AND rb2.booking_status = 'locked' ) LEFT JOIN hostel_admission_applications haa ON haa.student_uid COLLATE utf8mb4_unicode_ci = sd.uid COLLATE utf8mb4_unicode_ci AND haa.status = 'Admitted' LEFT JOIN rooms rm ON rm.name = COALESCE(rb.room_no, sd.room_no) AND rm.block = COALESCE(rb.block, sd.block) WHERE sd.category = 'Hostel' AND sd.uid LIKE 'BH%'";

    if (role == "BoysHostelAdmin") {
      sql += " AND sd.gender = 'MALE'";
    } else if (role == "GirlsHostelAdmin") {
      sql += " AND sd.gender = 'FEMALE'";
    } else if (role == "SuperID") {
      // no gender filter
    } else {
      connection.release();
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    connection.query(sql, function (qErr, result) {
      connection.release();

      if (qErr) {
        req.flash('message', 'Error generating export.');
        return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
      }

      var rows = result || [];
      if (!rows.length) {
        req.flash('message', 'No hostel students found to export.');
        return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
      }

      function formatDob(val) {
        if (!val) return '';
        var d = new Date(val);
        if (isNaN(d.getTime())) return String(val);
        var dd = String(d.getUTCDate()).padStart(2, '0');
        var mm = String(d.getUTCMonth() + 1).padStart(2, '0');
        var yyyy = d.getUTCFullYear();
        return dd + '/' + mm + '/' + yyyy;
      }

      function getRoomType(capacity) {
        if (capacity == 1) return 'Single';
        if (capacity == 2) return 'Double';
        if (capacity == 3) return 'Triple';
        if (capacity >= 4) return 'Dormitory';
        return '';
      }

      var LABELS = [
        'Hostel UID', 'College UID', 'Application Date', 'Student Name',
        'Batch', 'Branch', 'Date of Birth', 'Gender',
        'Mother Tongue', 'Religion', 'Cast', 'Community',
        'Native Place', 'Blood Group', 'Communication Address',
        'Student Mobile No', 'Student Mail Id', "Father's Name",
        'Occupation', 'Mobile No.', "Mother's Name", 'Occupation',
        'Mobile No.', 'Contact Person', 'Mobile No.', 'WhatsApp No.',
        'Hostel Block', 'Room Type', 'Room No.', 'Bed No.',
        'Mess Preference', 'Remarks (if any)'
      ];

      var aoa = LABELS.map(function(label) { return [label]; });

      rows.forEach(function(r) {
        var vals = [
          r.haa_hostel_id || '',                                             // Row 0:  Hostel UID
          r.uid || '',                                                        // Row 1:  College UID
          formatDob(r.haa_submission_date),                                   // Row 2:  Application Date
          r.haa_full_name  || r.sname       || '',                           // Row 3:  Student Name
          r.haa_batch      || r.academicyear || '',                          // Row 4:  Batch
          r.haa_branch     || r.dept        || '',                           // Row 5:  Branch
          formatDob(r.haa_dob || r.dob),                                     // Row 6:  Date of Birth
          r.gender || '',                                                     // Row 7:  Gender
          '',                                                                 // Row 8:  Mother Tongue (not in DB)
          r.haa_religion   || '',                                            // Row 9:  Religion
          r.haa_caste      || '',                                            // Row 10: Cast
          '',                                                                 // Row 11: Community (not in DB)
          r.haa_address    || r.address     || '',                           // Row 12: Native Place
          '',                                                                 // Row 13: Blood Group (not in DB)
          r.haa_address    || r.address     || '',                           // Row 14: Communication Address
          r.haa_student_mobile || r.mobileno || '',                          // Row 15: Student Mobile No
          r.haa_student_email  || r.email   || '',                           // Row 16: Student Mail Id
          r.haa_father_name    || r.parentname   || '',                      // Row 17: Father's Name
          r.haa_father_occupation || '',                                     // Row 18: Father Occupation
          r.haa_parent_phone   || r.parentnumber || '',                      // Row 19: Father Mobile No.
          r.haa_mother_name    || '',                                        // Row 20: Mother's Name
          r.haa_mother_occupation || '',                                     // Row 21: Mother Occupation
          '',                                                                 // Row 22: Mother Mobile No. (not in DB)
          r.haa_father_name    || r.parentname   || '',                      // Row 23: Contact Person (Mapped to Father)
          r.haa_parent_phone   || r.parentnumber || '',                      // Row 24: Contact Mobile (Mapped to Father Mobile)
          r.haa_student_mobile || r.mobileno || '',                          // Row 25: WhatsApp No. (Mapped to Student Mobile)
          r.final_block    || '',                                            // Row 26: Hostel Block
          getRoomType(r.room_capacity),                                       // Row 27: Room Type
          r.final_room_no  || '',                                            // Row 28: Room No.
          r.final_bed_no   || '',                                            // Row 29: Bed No.
          r.haa_mess       || r.mess_type   || '',                           // Row 30: Mess Preference
          ''                                                                  // Row 31: Remarks
        ];
        vals.forEach(function(v, i) { aoa[i].push(v); });
      });

      const XLSX = require('xlsx');
      var ws = XLSX.utils.aoa_to_sheet(aoa);
      var wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'Hostel_Students');
      var buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
      var fname = 'hostel_master_' + role + '_' + Date.now() + '.xlsx';
      res.setHeader('Content-Disposition', 'attachment; filename="' + fname + '"');
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
      res.send(buf);
    });
  });
});

app.get('/studentsupdate', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    var role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (role == "BoysHostelAdmin") {
        const hostelSql = "select * from studentdetails where gender='MALE' and category='Hostel'";
        const daySql = "select * from studentdetails where gender='MALE' and category='Day Scholar'";
        connection.query(hostelSql, function (err, hostelStudents) {
          if (err) throw err;
          connection.query(daySql, function (err2, dayScholarStudents) {
            connection.release();
            if (err2) throw err2;
            (hostelStudents || []).forEach(attachStudentPhotoUrl);
            (dayScholarStudents || []).forEach(attachStudentPhotoUrl);
            res.render(__dirname + '/views/studentsupdate', {
              hostelStudents: hostelStudents,
              dayScholarStudents: dayScholarStudents,
              message: req.flash('message'),
              getDateTimeInUserTimeZone: getDateTimeInUserTimeZone
            });
          });
        });
      }
      else if (role == "GirlsHostelAdmin") {
        const hostelSql = "select * from studentdetails where gender='FEMALE' and category='Hostel'";
        const daySql = "select * from studentdetails where gender='FEMALE' and category='Day Scholar'";
        connection.query(hostelSql, function (err, hostelStudents) {
          if (err) throw err;
          connection.query(daySql, function (err2, dayScholarStudents) {
            connection.release();
            if (err2) throw err2;
            (hostelStudents || []).forEach(attachStudentPhotoUrl);
            (dayScholarStudents || []).forEach(attachStudentPhotoUrl);
            res.render(__dirname + '/views/studentsupdate', {
              hostelStudents: hostelStudents,
              dayScholarStudents: dayScholarStudents,
              message: req.flash('message'),
              getDateTimeInUserTimeZone: getDateTimeInUserTimeZone
            });
          });
        });
      }
      else if (role == "SuperID" || role == "CollegeLateAdmin" || role == "CollegeLateComerAdmin") {
        const hostelSql = "select * from studentdetails where category='Hostel'";
        const daySql = "select * from studentdetails where category='Day Scholar'";
        connection.query(hostelSql, function (err, hostelStudents) {
          if (err) throw err;
          connection.query(daySql, function (err2, dayScholarStudents) {
            connection.release();
            if (err2) throw err2;
            (hostelStudents || []).forEach(attachStudentPhotoUrl);
            (dayScholarStudents || []).forEach(attachStudentPhotoUrl);
            res.render(__dirname + '/views/studentsupdate', {
              hostelStudents: hostelStudents,
              dayScholarStudents: dayScholarStudents,
              message: req.flash('message'),
              getDateTimeInUserTimeZone: getDateTimeInUserTimeZone
            });
          });
        });
      }
      else {
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }
    });

  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }

});

app.get('/insertcategory/:uid', verifyjwt, function (req, res) {

  var uid = req.params.uid;
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;

    dbbconnection.getConnection(function (err, connection) {

      var sql = "Update studentdetails set category='Hostel' where uid='" + uid + "'";
      connection.query(sql, function (err, result) {
        if (err) throw err;
        else {
          req.flash('message', 'Added successfully');
          res.redirect('/studentsupdate');
        }
      });
      connection.release();
    });


  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }

});

app.get('/codescanner/:uid', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  var inout;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID" || role == "Gateauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      const backUrl = req.query.back || '/homepage';
      var uid = req.params.uid;

      dbbconnection.getConnection(function (err, connection) {
        var sql = "select * From studentdetails where uid=? ";
        connection.query(sql, [uid], function (err, result) {
          if (err) throw err;
          else if (!result[0] == 0) {
            if (result[0].category == 0) {
              req.flash('message', 'Please mention the category,Contact admin');
              res.redirect(backUrl);
            }
            else {

              // in out button disable

              var logquery = "Select * from log_details1 where logid=(select max(logid) from log_details1 where uid='" + uid + "')";
              connection.query(logquery, function (err, result1) {
                if (err) throw err;
                if (!result1[0] == 0) {
                  /*  var abc= result[0].status;
                    if (result1[0].status == 'ACTIVE') {
                      alert('New value: ' );
                    } */


                  if (result && result[0]) {
                    attachStudentPhotoUrl(result[0]);
                  }
                  res.render(__dirname + '/views/codescanner', { result: result, result1: result1, backUrl: backUrl });
                }
                else {
                  // inout="0";
                  //alert('New dfgdfgdfgdf value: ' );
                  req.flash('message', 'chk else');
                }
              })






              //res.render(__dirname + '/views/codescanner', { result: result }); res.render('index', { data1: results1, data2: results2 });





            }





          }
          else {
            req.flash('message', 'Invalid user');
            res.redirect(backUrl);
          }


        });
        connection.release();
      });
    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //


});

app.get('/codescanner1/:uid', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  const decode = jwt.verify(tokenadmin, secretkey);

  var name = decode.adminname;
  var inout;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    if (role == "SuperID" || role == "Gateauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      const backUrl = req.query.back || '/Collegepage';
      var uid = req.params.uid;

      dbbconnection.getConnection(function (err, connection) {
        var sql = "select * From studentdetails where uid=? ";
        connection.query(sql, [uid], function (err, result) {
          if (err) throw err;
          else if (!result[0] == 0) {
            if (result[0].category == 0) {
              req.flash('message', 'Please mention the category,Contact admin');
              res.redirect(backUrl);
            }
            else {

              // college student entry

              var currTimeDb = formatDateTimeForDB(currentdate());
              var insertsqlin1 = "INSERT INTO log_detail (uid, indatetime, GuardName) SELECT '" + uid + "', '" + currTimeDb + "', '" + name + "' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM log_detail WHERE uid = '" + uid + "' AND indatetime >= DATE_SUB('" + currTimeDb + "', INTERVAL 1 MINUTE))";
              //var insertsqlin1 = "Insert into log_detail(uid,indatetime) VALUES ('" + uid + "','" + datetime(currentdate())+ "')";
              connection.query(insertsqlin1, function (err, result) {

                if (err) throw err;
                else {
                  req.flash('message', 'Submitted Successfully Z');
                  res.redirect(backUrl);
                }
              })




              //res.render(__dirname + '/views/codescanner', { result: result }); res.render('index', { data1: results1, data2: results2 });





            }





          }
          else {
            req.flash('message', 'Invalid user');
            res.redirect(backUrl);
          }


        });
        connection.release();
      });
    }
    else {
      req.flash('message', 'Unauthorised Access', role);
      return res.redirect('/loginpanel');
    }
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //


});


// =====================================================
// ADMIN NOTIFICATION COUNTS API
// =====================================================
app.get('/api/admin/notification-counts', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (!["SuperID", "BoysHostelAdmin", "GirlsHostelAdmin", "Hostelauthority"].includes(role)) {
      return res.json({});
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) return res.json({});

      let genderJoinBase = "";
      let genderWhereBase = "";

      if (role === 'BoysHostelAdmin') {
        genderJoinBase = " LEFT JOIN studentdetails sd ON {alias}.{col} = sd.uid ";
        genderWhereBase = " AND sd.gender = 'MALE' ";
      } else if (role === 'GirlsHostelAdmin') {
        genderJoinBase = " LEFT JOIN studentdetails sd ON {alias}.{col} = sd.uid ";
        genderWhereBase = " AND sd.gender = 'FEMALE' ";
      }

      function getScope(alias, col) {
        if (!genderJoinBase) return "";
        return genderJoinBase.replace('{alias}', alias).replace('{col}', col) + genderWhereBase;
      }

      const sql = `
        SELECT
          (SELECT COUNT(*) FROM pass_requests pr ${getScope('pr', 'uid')} WHERE pr.status = 'pending') AS passRequests,
          (SELECT COUNT(*) FROM sick_leave_requests slr ${getScope('slr', 'uid')} WHERE slr.status = 'pending' AND DATE(slr.created_at) = CURDATE()) AS sickLeaveRequests,
          (SELECT COUNT(*) FROM bonafide_requests br ${getScope('br', 'student_uid')} WHERE br.status = 'Pending') AS bonafideRequests,
          (SELECT COUNT(*) FROM hostel_bank_requests hbr ${getScope('hbr', 'student_uid')} WHERE hbr.status = 'Pending') AS hostelBankRequests,
          (SELECT COUNT(*) FROM hostel_admission_applications WHERE status = 'Pending') AS pendingAdmissions,
          (SELECT COUNT(*) FROM room_bookings rb ${getScope('rb', 'uid')} WHERE rb.booking_status = 'locked' AND rb.payment_status = 'pending') AS roomBookings,
          (SELECT COUNT(*) FROM complaints c ${getScope('c', 'student_uid')} WHERE c.status = 'pending_approval') AS verifyComplaints,
          (SELECT COUNT(*) FROM pass_restriction_audit pra ${getScope('pra', 'uid')} WHERE (DATE(pra.restricted_at) >= CURDATE() - INTERVAL 1 DAY OR DATE(pra.created_at) >= CURDATE() - INTERVAL 1 DAY)) AS restrictionAudit
      `;

      connection.query(sql, function (qErr, results) {
        connection.release();
        if (qErr || !results || results.length === 0) return res.json({});

        const counts = results[0];
        res.json({
          passRequests: counts.passRequests || 0,
          sickLeaveRequests: counts.sickLeaveRequests || 0,
          bonafideRequests: counts.bonafideRequests || 0,
          hostelBankRequests: counts.hostelBankRequests || 0,
          pendingAdmissions: counts.pendingAdmissions || 0,
          roomBookings: counts.roomBookings || 0,
          verifyComplaints: counts.verifyComplaints || 0,
          restrictionAudit: counts.restrictionAudit || 0
        });
      });
    });
  } catch (err) {
    res.json({});
  }
});

app.get('/daterange', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/loginpanel');
      }

      let genderJoinBase = "";
      let genderWhereBase = "";
      if (role === 'BoysHostelAdmin') {
        genderJoinBase = " LEFT JOIN studentdetails sd ON {alias}.{col} = sd.uid ";
        genderWhereBase = " AND sd.gender = 'MALE' ";
      } else if (role === 'GirlsHostelAdmin') {
        genderJoinBase = " LEFT JOIN studentdetails sd ON {alias}.{col} = sd.uid ";
        genderWhereBase = " AND sd.gender = 'FEMALE' ";
      }

      function getScope(alias, col) {
        if (!genderJoinBase) return "";
        return genderJoinBase.replace('{alias}', alias).replace('{col}', col) + genderWhereBase;
      }

      const countSql = `
        SELECT
          (SELECT COUNT(*) FROM pass_requests pr ${getScope('pr', 'uid')} WHERE pr.status = 'pending') AS passRequests,
          (SELECT COUNT(*) FROM sick_leave_requests slr ${getScope('slr', 'uid')} WHERE slr.status = 'pending' AND DATE(slr.created_at) = CURDATE()) AS sickLeaveRequests,
          (SELECT COUNT(*) FROM bonafide_requests br ${getScope('br', 'student_uid')} WHERE br.status = 'Pending') AS bonafideRequests,
          (SELECT COUNT(*) FROM hostel_bank_requests hbr ${getScope('hbr', 'student_uid')} WHERE hbr.status = 'Pending') AS hostelBankRequests,
          (SELECT COUNT(*) FROM hostel_admission_applications WHERE status = 'Pending') AS pendingAdmissions,
          (SELECT COUNT(*) FROM room_bookings rb ${getScope('rb', 'uid')} WHERE rb.booking_status = 'locked' AND rb.payment_status = 'pending') AS roomBookings,
          (SELECT COUNT(*) FROM complaints c ${getScope('c', 'student_uid')} WHERE c.status = 'pending_approval') AS verifyComplaints,
          (SELECT COUNT(*) FROM pass_restriction_audit pra ${getScope('pra', 'uid')} WHERE (DATE(pra.restricted_at) >= CURDATE() - INTERVAL 1 DAY OR DATE(pra.created_at) >= CURDATE() - INTERVAL 1 DAY)) AS restrictionAudit
      `;

      connection.query(countSql, function (cErr, cResults) {
        let initialCounts = { passRequests: 0, sickLeaveRequests: 0, bonafideRequests: 0, hostelBankRequests: 0, pendingAdmissions: 0, roomBookings: 0, verifyComplaints: 0, restrictionAudit: 0 };
        if (!cErr && cResults && cResults.length > 0) {
          initialCounts = cResults[0];
        }

        if (role == "SuperID") {
          connection.release();
          res.render(__dirname + '/views/daterange', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone, counts: initialCounts });
        }
        else if (role == "BoysHostelAdmin") {
          var sql = "select * from studentdetails where EXTRACT(DAY FROM dob)='" + getdate(currentdate()) + "' and extract(month from dob)='" + getmonth(currentdate()) + "'and category='Hostel' and gender='MALE'"
          connection.query(sql, function (err, result) {
            connection.release();
            if (err) throw err;
            else {
              res.render(__dirname + '/views/daterange', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone, counts: initialCounts });
            }
          });
        }
        else if (role == "GirlsHostelAdmin") {
          var sql = "select * from studentdetails where EXTRACT(DAY FROM dob)='" + getdate(currentdate()) + "' and extract(month from dob)='" + getmonth(currentdate()) + "'and category='Hostel' and gender='FEMALE'"
          connection.query(sql, function (err, result) {
            connection.release();
            if (err) throw err;
            else {
              res.render(__dirname + '/views/daterange', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone, counts: initialCounts });
            }
          });
        }
        else {
          connection.release();
          req.flash('message', 'Unauthorised Access', role);
          return res.redirect('/loginpanel');
        }
      });
    })
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //


});




app.post('/daterange', function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (role == "BoysHostelAdmin") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;

        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.passtype,log.hosteloutauth,CONCAT(FLOOR(HOUR(TIMEDIFF(outdatetime, indatetime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(outdatetime, indatetime)), 24), ' hours ',MINUTE(TIMEDIFF(outdatetime, indatetime)), ' minutes')AS `Duration`,CONCAT(FLOOR(HOUR(TIMEDIFF(approvaldt, hostelintime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(approvaldt, hostelintime)), 24), ' hours ',MINUTE(TIMEDIFF(approvaldt, hostelintime)), ' minutes') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='MALE' and (date(log.approvaldt) between date('" + datefrom + "') and date('" + dateto + "') or date(log.indatetime) between date('" + datefrom + "') and date('" + dateto + "')) and category='Hostel' ORDER BY log.logid desc";

        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/hostelpanel2', { result: result, message: req.flash('message'), datefrom: datefrom, dateto: dateto });
          }
        });
      }
      else if (role == "GirlsHostelAdmin") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;

        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.passtype,log.hosteloutauth,CONCAT(FLOOR(HOUR(TIMEDIFF(outdatetime, indatetime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(outdatetime, indatetime)), 24), ' hours ',MINUTE(TIMEDIFF(outdatetime, indatetime)), ' minutes')AS `Duration`,CONCAT(FLOOR(HOUR(TIMEDIFF(approvaldt, hostelintime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(approvaldt, hostelintime)), 24), ' hours ',MINUTE(TIMEDIFF(approvaldt, hostelintime)), ' minutes') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='FEMALE' and (date(log.approvaldt) between date('" + datefrom + "') and date('" + dateto + "') or date(log.indatetime) between date('" + datefrom + "') and date('" + dateto + "')) and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/hostelpanel2', { result: result, message: req.flash('message'), datefrom: datefrom, dateto: dateto });
          }
        });
      }
      else if (role == "SuperID") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;

        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.passtype,log.hosteloutauth,CONCAT(FLOOR(HOUR(TIMEDIFF(outdatetime, indatetime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(outdatetime, indatetime)), 24), ' hours ',MINUTE(TIMEDIFF(outdatetime, indatetime)), ' minutes')AS `Duration`,CONCAT(FLOOR(HOUR(TIMEDIFF(approvaldt, hostelintime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(approvaldt, hostelintime)), 24), ' hours ',MINUTE(TIMEDIFF(approvaldt, hostelintime)), ' minutes') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and ((date(log.outdatetime) between date('" + datefrom + "') and date('" + dateto + "')) or (date(log.approvaldt) between date('" + datefrom + "') and date('" + dateto + "')) or (date(log.indatetime) between date('" + datefrom + "') and date('" + dateto + "'))) ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/hostelpanel2', { result: result, message: req.flash('message'), datefrom: datefrom, dateto: dateto });
          }
        });
      }
      else {
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }

      connection.release();
    });

  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }


});


//College Late Commer
app.get('/daterangeC', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (role == "SuperID" || role == "CollegeLateAdmin" || role == "CollegeLateComerAdmin") {
        res.render(__dirname + '/views/CollegeLate', { result: [], message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
      }
      else if (role == "BoysHostelAdmin") {
        var sql = "select * from studentdetails where EXTRACT(DAY FROM dob)='" + getdate(currentdate()) + "' and extract(month from dob)='" + getmonth(currentdate()) + "'and category='Hostel' and gender='MALE'"
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/CollegeLate', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "GirlsHostelAdmin") {
        var sql = "select * from studentdetails where EXTRACT(DAY FROM dob)='" + getdate(currentdate()) + "' and extract(month from dob)='" + getmonth(currentdate()) + "'and category='Hostel' and gender='FEMALE'"
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/CollegeLate', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else {
        req.flash('message', 'Unauthorised Access', role);
        return res.redirect('/loginpanel');
      }
    })
  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  //


});



//College late commer
app.post('/daterangeC', function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (role == "BoysHostelAdmin") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;

        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.passtype,log.hosteloutauth,CONCAT(FLOOR(HOUR(TIMEDIFF(outdatetime, indatetime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(outdatetime, indatetime)), 24), ' hours ',MINUTE(TIMEDIFF(outdatetime, indatetime)), ' minutes')AS `Duration`,CONCAT(FLOOR(HOUR(TIMEDIFF(approvaldt, hostelintime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(approvaldt, hostelintime)), 24), ' hours ',MINUTE(TIMEDIFF(approvaldt, hostelintime)), ' minutes') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='MALE' and date(log.approvaldt) between date('" + datefrom + "') and date('" + dateto + "') and category='Hostel' ORDER BY log.logid desc";

        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/hostelpanel2', { result: result, message: req.flash('message'), datefrom: datefrom, dateto: dateto });
          }
        });
      }
      else if (role == "GirlsHostelAdmin") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;

        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.passtype,log.hosteloutauth,CONCAT(FLOOR(HOUR(TIMEDIFF(outdatetime, indatetime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(outdatetime, indatetime)), 24), ' hours ',MINUTE(TIMEDIFF(outdatetime, indatetime)), ' minutes')AS `Duration`,CONCAT(FLOOR(HOUR(TIMEDIFF(approvaldt, hostelintime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(approvaldt, hostelintime)), 24), ' hours ',MINUTE(TIMEDIFF(approvaldt, hostelintime)), ' minutes') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='FEMALE' and date(log.approvaldt) between date('" + datefrom + "') and date('" + dateto + "') and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/hostelpanel2', { result: result, message: req.flash('message'), datefrom: datefrom, dateto: dateto });
          }
        });
      }
      else if (role == "SuperID") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;

        var sql = "select stu.uid,stu.sname,stu.dept,stu.year,log.indatetime,log.Guardname from log_detail as log join studentdetails as stu where stu.uid=log.uid and ((date(log.indatetime) between date('" + datefrom + "') and date('" + dateto + "'))) ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/hostelpanel2', { result: result, message: req.flash('message'), datefrom: datefrom, dateto: dateto });
          }
        });
      }
      else if (role == "CollegeLateAdmin" || role == "CollegeLateComerAdmin") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;

        var sql = "select stu.uid,stu.sname,stu.dept,stu.year,log.indatetime,IFNULL(log.GuardName,log.Guardname) as Guardname from log_detail as log join studentdetails as stu on stu.uid=log.uid where date(log.indatetime) between date(?) and date(?) ORDER BY log.logid desc";
        connection.query(sql, [datefrom, dateto], function (err, result) {
          connection.release();
          if (err) {
            req.flash('message', 'Database error');
            return res.redirect('/CollegeLate');
          }
          return res.render(__dirname + '/views/CollegeLate', { result: result || [], message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())), datefrom: datefrom, dateto: dateto });
        });
        return;
      }
      else {
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }

      connection.release();
    });

  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }


});


app.post('/codescanner/:uid', async function (req, res) {
  dbbconnection.getConnection(function (err, connection) {
    var uid = req.params.uid;
    //var inout;
    const backUrl = req.query.back || '/homepage';
    var categoryquery = "Select category from studentdetails where uid='" + uid + "'";
    connection.query(categoryquery, function (err, result) {
      if (err) throw err;
      else {
        if (result[0].category == 'Day Scholar') {
          var mainsql = "Select * from log_details1 where uid='" + uid + "'";
          connection.query(mainsql, function (err, result) {

            if (err) throw err;
            else {
              if (!result[0] == 0)//if something value is coming from the database
              {
                //inout=1;

                if (!req.body.buttonout == 0) {

                  var sql = "Select * from log_details1 where logid=(Select max(logid) from log_details1 where uid='" + uid + "')";
                  connection.query(sql, function (err, result) {
                    if (err) throw err;
                    else {
                      if (!result[0].outdatetime == 0) {
                        var insertsql1 = "Insert into log_details1 (uid,outdatetime) VALUES ('" + uid + "','" + formatDateTimeForDB(currentdate()) + "')";
                        connection.query(insertsql1, function (err, result) {
                          if (err) throw err;
                          else {
                            req.flash('message', 'Submitted Successfully');
                            res.redirect(backUrl);
                          }
                        })
                      }
                      else {

                        var updatesql1 = "Update log_details1 set outdatetime='" + formatDateTimeForDB(currentdate()) + "' where logid='" + result[0].logid + "'";
                        connection.query(updatesql1, function (err, result) {
                          if (err) throw err;
                          else {
                            req.flash('message', 'Submitted Successfully');
                            res.redirect(backUrl);
                          }
                        })
                      }
                    }
                  });
                }
                else {
                  var sql = "Select * from log_details1 where logid=(Select max(logid) from log_details1 where uid='" + uid + "')";
                  connection.query(sql, function (err, result) {
                    if (err) throw err;
                    else {
                      if (!result[0].indatetime == 0) {
                        var insertsql1 = "Insert into log_details1 (uid,indatetime) VALUES ('" + uid + "','" + formatDateTimeForDB(currentdate()) + "')";
                        connection.query(insertsql1, function (err, result) {
                          if (err) throw err;
                          else {
                            req.flash('message', 'Submitted Successfully');
                            res.redirect(backUrl);
                          }
                        })
                      }
                      else {

                        var updatesql1 = "Update log_details1 set indatetime='" + formatDateTimeForDB(currentdate()) + "' where logid='" + result[0].logid + "'";
                        connection.query(updatesql1, function (err, result) {
                          if (err) throw err;
                          else {
                            req.flash('message', 'Submitted Successfully');
                            res.redirect(backUrl);
                          }
                        })
                      }
                    }
                  });
                }
              }
              else {
                if (!req.body.buttonout == 0)//OUT
                {

                  var sql = "Insert into log_details1 (uid,outdatetime) VALUES ? ";
                  var values = [
                    [uid, formatDateTimeForDB(currentdate())]
                  ]
                  connection.query(sql, [values], function (err, result) {
                    if (err) throw err;
                    else {
                      req.flash('message', 'Submitted Successfully');
                      res.redirect(backUrl);
                    }
                  });
                }
                else//IN
                {
                  var sql = "Insert into log_details1 (uid,indatetime) VALUES ? ";
                  var values = [
                    [uid, formatDateTimeForDB(currentdate())]
                  ]
                  connection.query(sql, [values], function (err, result) {
                    if (err) throw err;
                    else {
                      req.flash('message', 'Submitted Successfully');
                      res.redirect(backUrl);
                    }
                  });
                }
              }
            }
          })


        }
        else if (result[0].category == 'Hostel') {
          if (!req.body.buttonout == 0)//out
          {
            // First check for approved pass request - if exists, create pass record now (mandatory scanning)
            var checkApprovedRequestSql = "SELECT * FROM pass_requests WHERE uid = ? AND status = 'approved' ORDER BY approved_at DESC, requestid DESC LIMIT 1";
            connection.query(checkApprovedRequestSql, [uid], function (err, approvedRequest) {
              if (err) throw err;

              // If there's an approved request but no pass record yet, create it now (scanning is mandatory)
              if (approvedRequest && approvedRequest.length > 0) {
                var statusquery = "Select * from log_details1 where logid=(Select max(logid) from log_details1 where uid='" + uid + "' and status='ACTIVE' )";
                connection.query(statusquery, function (err, passResult) {
                  if (err) throw err;

                  // If no ACTIVE pass exists, create it from the approved request (scanning is mandatory)
                  if (!passResult || passResult.length == 0) {
                    var currentDateTime = formatDateTimeForDB(currentdate());
                    var createPassSql = "INSERT INTO log_details1 (uid, status, approvaldt, passtype, hosteloutauth, outdatetime) VALUES (?, 'ACTIVE', ?, ?, ?, ?)";
                    connection.query(createPassSql, [uid, currentDateTime, approvedRequest[0].passtype, approvedRequest[0].approved_by, currentDateTime], function (err, createResult) {
                      if (err) throw err;
                      req.flash('message', 'Submitted Successfully - Pass activated and gate out recorded');
                      res.redirect(backUrl);
                    });
                  }
                  // If ACTIVE pass exists, proceed with normal flow
                  else if (passResult[0].status == 'ACTIVE') {
                    var updatesql1 = "Update log_details1 set outdatetime='" + formatDateTimeForDB(currentdate()) + "',status='ACTIVE' where logid='" + passResult[0].logid + "'";
                    connection.query(updatesql1, function (err, result) {
                      if (err) throw err;
                      else {
                        req.flash('message', 'Submitted Successfully');
                        res.redirect(backUrl);
                      }
                    });
                  }
                  else {
                    req.flash('message', 'Hostel Pass is not generated');
                    res.redirect(backUrl);
                  }
                });
              }
              // No approved request - check for existing ACTIVE pass
              else {
                var statusquery = "Select * from log_details1 where logid=(Select max(logid) from log_details1 where uid='" + uid + "' and status='ACTIVE' )";
                connection.query(statusquery, function (err, result) {
                  if (err) throw err;
                  else if (result.length == 0) {
                    req.flash('message', 'Hostel Pass is not generated or not approved');
                    res.redirect(backUrl);
                  }
                  else if (result[0].status == 'ACTIVE') {
                    var updatesql1 = "Update log_details1 set outdatetime='" + formatDateTimeForDB(currentdate()) + "',status='ACTIVE' where logid='" + result[0].logid + "'";
                    connection.query(updatesql1, function (err, result) {
                      if (err) throw err;
                      else {
                        req.flash('message', 'Submitted Successfully');
                        res.redirect(backUrl);
                      }
                    });
                  }
                  else if (result[0].status == 'DEAD') {
                    req.flash('message', 'Hostel Pass is not generated');
                    res.redirect(backUrl);
                  }
                  else {
                    req.flash('message', 'Failed 401, Contact admin');
                    res.redirect(backUrl);
                  }
                });
              }
            });
          }
          else//in
          {
            var statusquery = "Select * from log_details1 where logid=(Select max(logid) from log_details1 where uid='" + uid + "' )";
            connection.query(statusquery, function (err, result) {

              if (err) throw err;

              else if (!result[0].outdatetime == 0) {
                var updatesql1 = "Update log_details1 set indatetime='" + formatDateTimeForDB(currentdate()) + "' where logid='" + result[0].logid + "'";
                connection.query(updatesql1, function (err, result) {
                  if (err) throw err;
                  else {
                    req.flash('message', 'Submitted Successfully');
                    res.redirect(backUrl);
                  }
                });
              }

              else {
                var insertsqlin = "Insert into log_details1 (uid,indatetime) VALUES ('" + uid + "','" + formatDateTimeForDB(currentdate()) + "') ";

                connection.query(insertsqlin, function (err, result) {
                  if (err) throw err;
                  else {
                    req.flash('message', 'Submitted Successfully');
                    res.redirect(backUrl);
                  }
                });
              }
            });
          }
        }
        else {
          req.flash('message', 'Error not valid category, Contact admin');
          res.redirect(backUrl);
        }
      }
    })
    connection.release();
  })
});


app.post('/codescanner1/:uid', async function (req, res) {
  dbbconnection.getConnection(function (err, connection) {
    var uid = req.params.uid;
    //var inout;
    const backUrl = req.query.back || '/Collegepage';
    var categoryquery = "Select category from studentdetails where uid='" + uid + "'";
    connection.query(categoryquery, function (err, result) {
      if (err) throw err;
      else {
        if (result[0].category == 'Day Scholar') {

          var currTimeDb = formatDateTimeForDB(currentdate());
          var insertsqlin1 = "INSERT INTO log_detail (uid, indatetime, GuardName) SELECT '" + uid + "', '" + currTimeDb + "', '" + name + "' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM log_detail WHERE uid = '" + uid + "' AND indatetime >= DATE_SUB('" + currTimeDb + "', INTERVAL 1 MINUTE))";
          //var insertsqlin1 = "Insert into log_detail(uid,indatetime) VALUES ('" + uid + "','" + datetime(currentdate())+ "')";
          connection.query(insertsqlin1, function (err, result) {

            if (err) throw err;
            else {
              req.flash('message', 'Submitted Successfully');
              res.redirect(backUrl);
            }
          })
        }

      }
    })
    connection.release();
  })
});

app.post('/updatestudent/:uid', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  let role = null;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
  } catch (e) {
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }

  if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
    req.flash('message', 'Unauthorised Access');
    return res.redirect('/loginpanel');
  }

  const oldUid = String(req.params.uid || '').trim();
  const newUid = String(req.body.new_uid || oldUid).trim();

  const dept = req.body.Department;
  const academicyear = req.body.academicyear;
  const year = req.body.year;
  const category = req.body.category;
  const mobile = req.body.mobile;
  const status = req.body.Block;
  const gender = req.body.gender;
  const dob = req.body.dob;
  const address = req.body.address;
  const email = req.body.email;
  const ParentsName = req.body.ParentsName;
  const ParentsNumber = req.body.ParentsNumber;
  const block = req.body.block;
  const room_no = req.body.room_no;
  const bed_no = req.body.bed_no;
  const mess_type = req.body.mess_type;
  const newPassword = String(req.body.new_password || '').trim();

  if (!oldUid) {
    req.flash('message', 'Invalid student UID');
    return res.redirect('/studentsupdate');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err || !connection) {
      req.flash('message', 'Database error');
      return res.redirect('/studentprofile/' + encodeURIComponent(oldUid));
    }
    let responded = false;

    const finish = (msg, redirectUid) => {
      if (responded) return;
      responded = true;
      connection.release();
      req.flash('message', msg);
      return res.redirect('/studentprofile/' + encodeURIComponent(redirectUid));
    };

    const cascadeSqls = [
      { sql: 'UPDATE log_details1 SET uid = ? WHERE uid = ?', params: [newUid, oldUid] },
      { sql: 'UPDATE log_detail SET uid = ? WHERE uid = ?', params: [newUid, oldUid] },
      { sql: 'UPDATE complaints SET student_uid = ? WHERE student_uid = ?', params: [newUid, oldUid] },
      { sql: 'UPDATE pass_requests SET student_uid = ? WHERE student_uid = ?', params: [newUid, oldUid] }
    ];

    const executeUpdate = (hashedPassword) => {
      const fieldsConfig = [
        { field: 'uid', val: newUid },
        { field: 'email', val: email },
        { field: 'dept', val: dept },
        { field: 'address', val: address },
        { field: 'year', val: year },
        { field: 'category', val: category },
        { field: 'gender', val: gender },
        { field: 'mobileno', val: mobile },
        { field: 'dob', val: dob },
        { field: 'academicyear', val: academicyear },
        { field: 'status', val: status },
        { field: 'parentname', val: ParentsName },
        { field: 'parentnumber', val: ParentsNumber },
        { field: 'block', val: block },
        { field: 'room_no', val: room_no },
        { field: 'bed_no', val: bed_no },
        { field: 'mess_type', val: mess_type }
      ];

      const updateFields = [];
      const updateStudentParams = [];

      fieldsConfig.forEach(item => {
        if (item.val !== undefined) {
          updateFields.push(`${item.field} = ?`);
          updateStudentParams.push(item.val);
        }
      });

      if (hashedPassword) {
        updateFields.push('password = ?');
        updateStudentParams.push(hashedPassword);
      }

      updateStudentParams.push(oldUid);
      const updateStudentSql = `UPDATE studentdetails
      SET ${updateFields.join(', ')}
      WHERE uid = ?`;

      const runUpdateQuery = () => {
        // If UID is not changing, avoid transaction overhead
        if (newUid === oldUid) {
          return connection.query(updateStudentSql, updateStudentParams, function (uErr) {
            if (uErr) {
              console.error('updatestudent failed:', uErr);
              return finish('Could not update student profile', oldUid);
            }
            return finish('Updated Successfully', oldUid);
          });
        }

        connection.beginTransaction(function (tErr) {
          if (tErr) {
            console.error('updatestudent beginTransaction failed:', tErr);
            return finish('Could not update student profile', oldUid);
          }

          connection.query(updateStudentSql, updateStudentParams, function (uErr) {
            if (uErr) {
              return connection.rollback(function () {
                console.error('updatestudent update studentdetails failed:', uErr);
                return finish('Could not update student profile', oldUid);
              });
            }

            const runCascade = (idx) => {
              if (idx >= cascadeSqls.length) {
                return connection.commit(function (cErr) {
                  if (cErr) {
                    return connection.rollback(function () {
                      console.error('updatestudent commit failed:', cErr);
                      return finish('Could not update student profile', oldUid);
                    });
                  }
                  return finish('Updated Successfully', newUid);
                });
              }

              const item = cascadeSqls[idx];
              connection.query(item.sql, item.params, function (cErr) {
                if (cErr) {
                  return connection.rollback(function () {
                    console.error('updatestudent cascade failed:', cErr);
                    return finish('Could not update student profile', oldUid);
                  });
                }
                return runCascade(idx + 1);
              });
            };

            return runCascade(0);
          });
        });
      };

      return runUpdateQuery();
    };

    const startFinalUpdate = function () {
      if (newPassword.length > 0) {
        if (newPassword.length < 6) {
          return finish('Password must be at least 6 characters', oldUid);
        }
        return bcrypt.hash(newPassword, 12, function (hashErr, hashedPassword) {
          if (hashErr) {
            console.error('updatestudent password hash failed:', hashErr);
            return finish('Could not update student profile', oldUid);
          }
          return executeUpdate(hashedPassword);
        });
      }
      return executeUpdate(null);
    };

    if (newUid !== oldUid) {
      if (role !== 'SuperID') {
        return finish('Only SuperID can change UID', oldUid);
      }
      if (!newUid) {
        return finish('New UID cannot be empty', oldUid);
      }
      const existsSql = 'SELECT uid FROM studentdetails WHERE uid = ? LIMIT 1';
      return connection.query(existsSql, [newUid], function (eErr, rows) {
        if (eErr) {
          console.error('updatestudent uid exists check failed:', eErr);
          return finish('Could not update student profile', oldUid);
        }
        if (rows && rows.length > 0) {
          return finish('UID already exists', oldUid);
        }
        return startFinalUpdate();
      });
    }

    return startFinalUpdate();
  });
});

app.get('/loginpanel', function (req, res) {

  res.render(__dirname + '/views/loginpanel', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
});

app.get('/privacy-policy', function (req, res) {
  res.render(__dirname + '/views/privacy-policy');
});


// Sign up page (render)
app.get('/signup', function (req, res) {
  res.render(__dirname + '/views/signup', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
});

// Sign up form handler - create admin user with bcrypt-hashed password
app.post('/signup', async function (req, res) {
  const UID = req.body.UID;
  const name = req.body.name || '';
  const password = req.body.password;
  const category = req.body.category;
  const Hostel = req.body.Hostel || null;

  if (!UID || !password || !category) {
    req.flash('message', 'UID, password and category are required');
    return res.redirect('/signup');
  }

  try {
    const hashed = await bcrypt.hash(password, 12);

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        console.error('DB connection error:', err);
        req.flash('message', 'Database connection error');
        return res.redirect('/signup');
      }

      const sql = 'INSERT INTO admin (uid, name, password, category, Hostel) VALUES (?, ?, ?, ?, ?)';
      const params = [UID, name, hashed, category, Hostel];

      connection.query(sql, params, function (err, result) {
        connection.release();
        if (err) {
          console.error('Error inserting admin:', err);
          // handle duplicate UID gracefully
          if (err.code === 'ER_DUP_ENTRY') {
            req.flash('message', 'UID already exists');
            return res.redirect('/signup');
          }
          req.flash('message', 'Error creating account');
          return res.redirect('/signup');
        }

        req.flash('message', 'Signup successful. Please login.');
        return res.redirect('/loginpanel');
      });
    });
  } catch (e) {
    console.error('Signup error:', e);
    req.flash('message', 'Server error');
    return res.redirect('/signup');
  }
});

app.get('/chart', function (req, res) {

  res.render(__dirname + '/views/chart', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
});

app.post('/loginpanel', function (req, res) {


  var UID = req.body.UID;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.log('DB connection error on /loginpanel:', err);
      req.flash('message', 'Database error. Please try again.');
      return res.redirect('/loginpanel');
    }
    var sql = "select * from admin where UID ='" + UID + "' ";
    connection.query(sql, function (err, result) {
      connection.release();

      if (err) {
        console.log(err);
        req.flash('message', 'Database error. Please try again.');
        return res.redirect('/loginpanel');
      }
      else if (result.length > 0) {
        bcrypt.compare(req.body.password, result[0].password, (berr, bresult) => {

          if (bresult) {

            const user = {
              role: result[0].category,
              adminname: result[0].name,
              adminuid: result[0].uid || result[0].UID,
              // For HODs we store the branch in the hostel/Hostel column.
              // Support both cases in case the DB column is defined with different casing.
              hostel: result[0].hostel || result[0].Hostel || null
            }

            jwt.sign(user, secretkey, {
              expiresIn: '7d'
            }, (err, tokenadmin) => {

              res.cookie('jwt', tokenadmin, {
                httpOnly: true,
                sameSite: 'lax',
                secure: process.env.NODE_ENV === 'production',
                maxAge: 7 * 24 * 60 * 60 * 1000
              })
              try {
                const decode = jwt.verify(tokenadmin, secretkey);
                role = decode.role;
                if (role == "SuperID" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
                  res.redirect("/daterange");
                }
                else if (role == "HOD" || role == "HODFirstYear") {
                  res.redirect("/HODCollegeLate");
                }
                else if (role == "CollegeLateAdmin") {
                  res.redirect("/collegeadmindashboard");
                }
                else if (role == "CollegeLateComerAdmin") {
                  res.redirect("/CollegeLate");
                }
                else if (role == "Gateauthority") {
                  res.redirect("/homepage");
                }
                else if (role == "Hostelauthority") {
                  res.redirect("/tokenhomepage");
                }
                else if (role == "KitchenAdmin") {
                  res.redirect("/kitchen");
                }
                else if (role == "Technician") {
                  res.redirect("/complain");
                }

              } catch (err) {
                res.clearCookie("jwt");
                req.flash('message', 'Something went wrong');
                return res.redirect('/loginpanel');
              }




            });
          }
          else {
            req.flash('message', 'Incorrect password');
            res.redirect('/loginpanel');
          }
        });

      }
      else {
        req.flash('message', 'Incorrect password');
        res.redirect('/loginpanel')
      }
    })
  });

});
app.use(cookieParser());

// --------------------------------------------------------------------------------------------------------------
function verifyjwt(req, res, next) {
  const tokenadmin = req.cookies.jwt;
  if (!tokenadmin) {
    return res.redirect('/loginpanel');
  }
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    // CRITICAL FIX: Attach the decoded data to the request object
    req.decode = decode;
    // Sliding session: re-issue token on each verified request (preserve extra fields if present)
    const payload = {
      role: decode.role,
      adminname: decode.adminname,
      adminuid: decode.adminuid,
      hostel: decode.hostel
    };
    jwt.sign(payload, secretkey, { expiresIn: '7d' }, (err, newToken) => {
      if (!err && newToken) {
        res.cookie('jwt', newToken, {
          httpOnly: true,
          sameSite: 'lax',
          secure: process.env.NODE_ENV === 'production',
          maxAge: 7 * 24 * 60 * 60 * 1000
        });
      }
      next();
    });
  } catch (err) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
};
// --------------------------------------------------------------------------------------------------------------------
// MOBILE API AUTH MIDDLEWARE (Bearer token, JSON responses)
function verifyMobileJwt(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ success: false, error: 'Missing or invalid Authorization header' });
  }

  // Support master static token from environment or default secret
  if (token === process.env.MCP_BEARER_TOKEN || token === "tnps_gatepass_mcp_token_2026") {
    req.decode = { user: 'superadmin', role: 'SuperID' };
    return next();
  }

  jwt.verify(token, secretkey, function (err, decode) {
    if (err) {
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }

    // Automatically promote admin or mcp-client role to SuperID for full system access
    if (decode && (decode.role === 'admin' || decode.user === 'mcp-client')) {
      decode.role = 'SuperID';
    }

    const allowedRoles = ['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin', 'Hostelauthority', 'KitchenAdmin', 'Technician', 'admin'];
    if (!allowedRoles.includes(decode.role)) {
      return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
    }

    req.decode = decode;
    next();
  });
}
// --------------------------------------------------------------------------------------------------------------------
// MOBILE STUDENT API AUTH MIDDLEWARE (Bearer token, JSON responses)
function verifyMobileStudentJwt(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ success: false, error: 'Missing or invalid Authorization header' });
  }

  jwt.verify(token, studentSecretKey, function (err, decode) {
    if (err) {
      return res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }

    req.studentUid = decode.uid;
    req.studentName = decode.name;
    next();
  });
}

// Global Demo Mode Interceptor Middleware
app.use('/api/mobile/v1', function (req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (token) {
    try {
      let decoded = null;
      try {
        decoded = jwt.verify(token, secretkey);
      } catch (e) {
        try {
          decoded = jwt.verify(token, studentSecretKey);
        } catch (e2) {}
      }
      if (decoded && decoded.isDemo) {
        req.isDemo = true;
        req.decode = decoded;
        req.studentUid = decoded.uid || (decoded.role === 'Student' ? decoded.uid : null);
        req.studentName = decoded.name;
        return demoDataService.handleRequest(req, res);
      }
    } catch (err) {}
  }
  next();
});

// --------------------------------------------------------------------------------------------------------------------
// BONAFIDE RBAC MIDDLEWARE
// canAccessBonafide: SuperID + Hostelauthority
function canAccessBonafide(req, res, next) {
  const role = req.decode && req.decode.role;
  if (role === 'SuperID' || role === 'Hostelauthority') {
    return next();
  }
  return res.status(403).send('Forbidden: Access Denied');
}
// canManageBonafide: SuperID only
function canManageBonafide(req, res, next) {
  const role = req.decode && req.decode.role;
  if (role === 'SuperID') {
    return next();
  }
  return res.status(403).send('Forbidden: Access Denied');
}
// --------------------------------------------------------------------------------------------------------------------

function getFeatureFlag(connection, featureKey, cb) {
  if (!connection) return cb(null, true);
  const sql = "SELECT enabled FROM feature_flags WHERE feature_key = ? LIMIT 1";
  connection.query(sql, [featureKey], function (err, rows) {
    if (err) {
      if (err.code === 'ER_NO_SUCH_TABLE') return cb(null, true);
      console.error('getFeatureFlag failed:', err);
      return cb(null, true);
    }
    if (!rows || rows.length === 0) return cb(null, true);
    return cb(null, !!rows[0].enabled);
  });
}

function ensureFeatureFlagsColumns(connection, cb) {
  if (!connection) return cb ? cb() : null;
  connection.query("ALTER TABLE feature_flags ADD COLUMN value_int INT DEFAULT NULL", function () {
    connection.query("ALTER TABLE feature_flags ADD COLUMN value_str VARCHAR(255) DEFAULT NULL", function () {
      if (cb) cb();
    });
  });
}

function loadFeatureFlagsMap(connection, cb) {
  if (!connection) return cb(null, {});
  ensureFeatureFlagsColumns(connection, function () {
    const sql = "SELECT feature_key, enabled, updated_by, updated_at, value_int, value_str FROM feature_flags";
    connection.query(sql, function (err, rows) {
      if (err) {
        if (err.code === 'ER_NO_SUCH_TABLE') return cb(null, {});
        console.error('loadFeatureFlagsMap failed:', err);
        return cb(null, {});
      }
      const map = {};
      (rows || []).forEach(r => {
        map[r.feature_key] = {
          enabled: !!r.enabled,
          updated_by: r.updated_by,
          updated_at: r.updated_at,
          value_int: r.value_int !== undefined ? r.value_int : null,
          value_str: r.value_str !== undefined ? r.value_str : null
        };
      });
      return cb(null, map);
    });
  });
}



app.get('/hostelpanel', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/loginpanel');
      }

      if (role == "BoysHostelAdmin") {
        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.hosteloutauth,log.passtype,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='MALE' and (DATE(approvaldt) = '" + convert(formatDateTimeForDB(currentdate())) + "' or DATE(log.indatetime) = '" + convert(formatDateTimeForDB(currentdate())) + "' or DATE(log.outdatetime) = '" + convert(formatDateTimeForDB(currentdate())) + "' or DATE(log.hostelintime) = '" + convert(formatDateTimeForDB(currentdate())) + "') and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/hostelpanel', { result: result, message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())) });
          }
        });
      }
      else if (role == "GirlsHostelAdmin") {
        const today = convert(formatDateTimeForDB(currentdate()));
        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.hosteloutauth,log.passtype,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='FEMALE' and (DATE(log.approvaldt) = '" + today + "' or DATE(log.outdatetime) = '" + today + "' or DATE(log.indatetime) = '" + today + "' or DATE(log.hostelintime) = '" + today + "') and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/hostelpanel', { result: result, message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())) });
          }
        });
      }
      else if (role == "SuperID") {
        const today = convert(formatDateTimeForDB(currentdate()));
        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.hosteloutauth,log.passtype,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and (DATE(log.approvaldt) = '" + today + "' or DATE(log.outdatetime) = '" + today + "' or DATE(log.indatetime) = '" + today + "' or DATE(log.hostelintime) = '" + today + "') ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/hostelpanel', { result: result, message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())) });
          }
        });
      }
      else {
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }

      connection.release();
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }
});

app.get('/CollegeLate', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/loginpanel');
      }

      if (role == "BoysHostelAdmin") {
        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.hosteloutauth,log.passtype,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='MALE' and DATE(approvaldt) = '" + convert(formatDateTimeForDB(currentdate())) + "' and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          connection.release();
          if (err) throw err;
          res.render(__dirname + '/views/CollegeLate', { result: result, message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())) });
        });
      } else if (role == "GirlsHostelAdmin") {
        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,log.hostelintime,log.hosteloutauth,log.passtype,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='FEMALE' and DATE(approvaldt) = '" + convert(formatDateTimeForDB(currentdate())) + "' and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          connection.release();
          if (err) throw err;
          res.render(__dirname + '/views/CollegeLate', { result: result, message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())) });
        });
      } else if (role == "SuperID" || role == "CollegeLateAdmin" || role == "CollegeLateComerAdmin") {
        var sql = "select stu.uid,stu.sname,stu.dept,stu.year,log.indatetime,IFNULL(log.GuardName,log.Guardname) as Guardname from log_detail as log join studentdetails as stu on stu.uid=log.uid ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          connection.release();
          if (err) throw err;
          res.render(__dirname + '/views/CollegeLate', { result: result || [], message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())) });
        });
      } else {
        connection.release();
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }
});

// Simple dashboard for College Late Admin to choose which list to open
app.get('/collegeadmindashboard', verifyjwt, function (req, res) {
  try {
    const role = (req.decode && req.decode.role) || '';
    if (role !== 'CollegeLateAdmin') {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }
    return res.render(__dirname + '/views/collegeadmindashboard', {
      message: req.flash('message')
    });
  } catch (err) {
    res.clearCookie('jwt');
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }
});

// Map HOD branch abbreviation to name as stored in studentdetails.dept (exact names only; no CSBS ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“ use name as in student details)
function resolveHODBranchToFullName(branch) {
  if (!branch || typeof branch !== 'string') return branch;
  var b = branch.trim().toUpperCase();
  var map = {
    'MECHANICAL ENGINEERING': 'Mechanical Engineering',
    'MECH': 'Mechanical Engineering',
    'BASIC SCIENCE AND HUMANITIES': 'Basic science and humanities',
    'BSH': 'Basic science and humanities',
    'COMPUTER ENGINEERING': 'Computer Engineering',
    'CSE': 'Computer Engineering',
    'COMPUTER SCIENCE AND ARTIFICIAL INTELLIGENCE': 'Computer Science and Artificial Intelligence',
    'CSE AI': 'Computer Science and Artificial Intelligence',
    'COMPUTER SCIENCE AND DATA SCIENCE': 'Computer Science and Data Science',
    'CSE DS': 'Computer Science and Data Science',
    'ARTIFICIAL INTELLIGENCE': 'Artificial Intelligence',
    'AI': 'Artificial Intelligence',
    'ELECTRONICS AND TELECOMMUNICATION': 'Electronics and Telecommunication',
    'ETC': 'Electronics and Telecommunication',
    'ELECTRICAL ENGINEERING': 'Electrical Engineering',
    'ELECTIRICAL': 'Electrical Engineering',
    'EEE': 'Electrical Engineering',
    'CIVIL ENGINEERING': 'Civil Engineering',
    'CIVIL': 'Civil Engineering',
    'B VOCATIONAL': 'B Vocational',
    'BVOC': 'B Vocational',
    'B.VOC. IN CYBER SECURITY': 'B Vocational',
    'B.VOC. IN SOFTWARE DEVELOPMENT': 'B Vocational',
    'B.VOC. IN VIRTUAL REALITY & AR': 'B Vocational'
  };
  return map[b] || map[branch.trim()] || branch;
}

// B.VOC HOD: one login authority for all three B.VOC depts. Returns { deptCondition: "SQL fragment", deptParams: [...] }.
var B_VOC_DEPTS = ['B Vocational', 'B.VOC. in Cyber Security', 'B.VOC. in Software Development', 'B.VOC. in Virtual Reality & AR'];
function getHODDeptCondition(branch) {
  if (branch === 'B Vocational') {
    return {
      deptCondition: 'LOWER(TRIM(IFNULL(stu.dept,\'\'))) IN (?, ?, ?, ?)',
      deptParams: B_VOC_DEPTS.map(function (d) { return (d || '').trim().toLowerCase(); })
    };
  }
  return {
    deptCondition: 'LOWER(TRIM(IFNULL(stu.dept,\'\'))) = LOWER(TRIM(?))',
    deptParams: [branch]
  };
}

// HOD - College Late Comers (branch-wise and first-year)
app.get('/HODCollegeLate', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    const branchRaw = decode.hostel; // For HOD, this stores the department/branch
    var branch = (branchRaw && String(branchRaw).trim()) || '';
    branch = resolveHODBranchToFullName(branch) || branch;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/loginpanel');
      }

      if (role === "HOD") {
        if (!branch) {
          connection.release();
          req.flash('message', 'Branch not configured for HOD. Log out and log in again after setting your branch.');
          return res.redirect('/loginpanel');
        }
        var hodCond = getHODDeptCondition(branch);
        // Match dept (single branch or B.VOC = all three). Exclude first year (FE/1/First Year).
        var sql = "select stu.uid,stu.sname,stu.dept,stu.year,log.indatetime,IFNULL(log.GuardName,log.Guardname) as Guardname from log_detail as log join studentdetails as stu on stu.uid=log.uid where " + hodCond.deptCondition + " and (IFNULL(stu.year,'') NOT IN ('FE','fe','1','First Year','first year')) ORDER BY log.logid desc";
        connection.query(sql, hodCond.deptParams, function (qErr, result) {
          if (qErr) {
            connection.release();
            req.flash('message', 'Database error');
            return res.redirect('/loginpanel');
          }
          // If no rows, try without year filter (include first year for this branch only)
          if (!result || result.length === 0) {
            var sqlAny = "select stu.uid,stu.sname,stu.dept,stu.year,log.indatetime,IFNULL(log.GuardName,log.Guardname) as Guardname from log_detail as log join studentdetails as stu on stu.uid=log.uid where " + hodCond.deptCondition + " ORDER BY log.logid desc";
            connection.query(sqlAny, hodCond.deptParams, function (qErr2, result2) {
              connection.release();
              if (qErr2) {
                return res.render(__dirname + '/views/HODCollegeLate', { result: [], message: req.flash('message'), datetime: convert(formatDateTimeForDB(currentdate())) });
              }
              if (result2 && result2.length > 0) {
                return res.render(__dirname + '/views/HODCollegeLate', {
                  result: result2,
                  message: req.flash('message'),
                  datetime: convert(formatDateTimeForDB(currentdate())),
                  branchMismatchNote: 'Branch: ' + branch + ' (all years).'
                });
              }
              // No late comers for this branch: show empty only (do not show other branches' data)
              return res.render(__dirname + '/views/HODCollegeLate', {
                result: [],
                message: req.flash('message'),
                datetime: convert(formatDateTimeForDB(currentdate())),
                branchMismatchNote: 'No late comers for your branch (' + branch + ') today.'
              });
            });
            return;
          }
          connection.release();
          return res.render(__dirname + '/views/HODCollegeLate', {
            result: result,
            message: req.flash('message'),
            datetime: convert(formatDateTimeForDB(currentdate()))
          });
        });
      } else if (role === "HODFirstYear") {
        var sqlFy = "select stu.uid,stu.sname,stu.dept,stu.year,log.indatetime,IFNULL(log.GuardName,log.Guardname) as Guardname from log_detail as log join studentdetails as stu on stu.uid=log.uid where (LOWER(TRIM(IFNULL(stu.year,''))) IN ('fe','1','first year')) ORDER BY log.logid desc";
        connection.query(sqlFy, function (qErr, result) {
          connection.release();
          if (qErr) {
            req.flash('message', 'Database error');
            return res.redirect('/loginpanel');
          }
          return res.render(__dirname + '/views/HODCollegeLate', {
            result: result || [],
            message: req.flash('message'),
            datetime: convert(formatDateTimeForDB(currentdate()))
          });
        });
      } else {
        connection.release();
        req.flash('message', 'Unauthorised Access');
        return res.redirect('/loginpanel');
      }
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }
});

// HOD - College Late Comers (date range filter)
app.post('/HODCollegeLateRange', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    var branch = (decode.hostel && String(decode.hostel).trim()) || '';
    branch = resolveHODBranchToFullName(branch) || branch;

    const datefrom = req.body.datefrom;
    const dateto = req.body.dateto;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/loginpanel');
      }

      if (role === "HOD") {
        var branchClean = (branch && String(branch).trim()) || '';
        if (!branchClean) {
          connection.release();
          req.flash('message', 'Branch not configured for HOD');
          return res.redirect('/loginpanel');
        }
        var hodCond = getHODDeptCondition(branchClean);
        var sql = "select stu.uid,stu.sname,stu.dept,stu.year,log.indatetime,IFNULL(log.GuardName,log.Guardname) as Guardname from log_detail as log join studentdetails as stu on stu.uid=log.uid where " + hodCond.deptCondition + " and (IFNULL(stu.year,'') NOT IN ('FE','fe','1','First Year','first year')) and date(log.indatetime) between date(?) and date(?) ORDER BY log.logid desc";
        connection.query(sql, hodCond.deptParams.concat([datefrom, dateto]), function (qErr, result) {
          connection.release();
          if (qErr) {
            req.flash('message', 'Database error');
            return res.redirect('/loginpanel');
          }
          return res.render(__dirname + '/views/HODCollegeLate', {
            result: result || [],
            message: req.flash('message'),
            datetime: convert(formatDateTimeForDB(currentdate())),
            datefrom: datefrom,
            dateto: dateto
          });
        });
      } else if (role === "HODFirstYear") {
        var sqlFy = "select stu.uid,stu.sname,stu.dept,stu.year,log.indatetime,IFNULL(log.GuardName,log.Guardname) as Guardname from log_detail as log join studentdetails as stu on stu.uid=log.uid where (LOWER(TRIM(IFNULL(stu.year,''))) IN ('fe','1','first year')) and date(log.indatetime) between date(?) and date(?) ORDER BY log.logid desc";
        connection.query(sqlFy, [datefrom, dateto], function (qErr, result) {
          connection.release();
          if (qErr) {
            req.flash('message', 'Database error');
            return res.redirect('/loginpanel');
          }
          return res.render(__dirname + '/views/HODCollegeLate', {
            result: result,
            message: req.flash('message'),
            datetime: convert(formatDateTimeForDB(currentdate())),
            datefrom: datefrom,
            dateto: dateto
          });
        });
      } else {
        connection.release();
        req.flash('message', 'Unauthorised Access');
        return res.redirect('/loginpanel');
      }
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }
});

app.get('/studentprofile/:uid', verifyjwt, function (req, res) {
  var uid = req.params.uid;
  var from = req.query.from;
  var originRole = req.query.role;

  // Determine where the "Back to Dashboard" link should point to
  var backUrl = '/studentsupdate';
  if (from === 'hostel' && originRole) {
    backUrl = '/studentsupdatehostel/' + encodeURIComponent(originRole);
  } else if (from === 'update') {
    backUrl = '/studentsupdate';
  }

  dbbconnection.getConnection(function (err, connection) {
    var sql = `
      SELECT s.*, t.recv_arrear_fee, t.recv_current_year, t.recv_extra_stay,
             t.recd_arrear_fee, t.recd_current_year, t.recd_extra,
             t.balance, t.as_on_date
      FROM studentdetails s
      LEFT JOIN tally_fee_data t ON (s.uid = t.suid OR s.hostel_id = t.suid)
      WHERE s.uid = ?
    `;
    connection.query(sql, [uid], function (err, result) {
      if (err) {
        connection.release();
        throw err;
      } else {
        // Prepare monthly pass data with counts and dates for the current year
        var passDataSql = `
          SELECT MONTH(approvaldt) AS m, passtype, DATE_FORMAT(approvaldt, '%a, %b %e, %Y') AS formatted_date, approvaldt
          FROM log_details1
          WHERE uid = ? AND passtype IS NOT NULL AND approvaldt IS NOT NULL
            AND YEAR(approvaldt) = YEAR(CURDATE())
          ORDER BY MONTH(approvaldt), approvaldt`;

        connection.query(passDataSql, [uid], function (pErr, rows) {
          // Initialize data structure for months 1..12
          var monthlyPassData = {};
          var monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
            'July', 'August', 'September', 'October', 'November', 'December'];

          // Initialize all months
          monthNames.forEach(function (month, index) {
            monthlyPassData[month] = {
              'City Pass': { count: 0, dates: [] },
              'Home Pass': { count: 0, dates: [] },
              'Sick Leave': { count: 0, dates: [] }
            };
          });

          if (!pErr && rows && rows.length > 0) {
            rows.forEach(function (r) {
              var monthIndex = parseInt(r.m, 10) - 1; // Convert to 0-based index
              if (monthIndex >= 0 && monthIndex < 12) {
                var monthName = monthNames[monthIndex];
                var passType = (r.passtype || '').toString().trim();

                if (passType.toLowerCase() === 'city pass') {
                  monthlyPassData[monthName]['City Pass'].count++;
                  monthlyPassData[monthName]['City Pass'].dates.push(r.formatted_date);
                } else if (passType.toLowerCase() === 'home pass') {
                  monthlyPassData[monthName]['Home Pass'].count++;
                  monthlyPassData[monthName]['Home Pass'].dates.push(r.formatted_date);
                }
              }
            });
          }

          // Query sick leave data for the current year
          var sickLeaveDataSql = `
            SELECT MONTH(logdate) AS m, DATE_FORMAT(logdate, '%a, %b %e, %Y') AS formatted_date, logdate
            FROM sick_leave_logs
            WHERE uid = ? AND logdate IS NOT NULL
              AND YEAR(logdate) = YEAR(CURDATE())
            ORDER BY MONTH(logdate), logdate`;

          connection.query(sickLeaveDataSql, [uid], function (slErr, slRows) {
            connection.release();

            if (!slErr && slRows && slRows.length > 0) {
              slRows.forEach(function (r) {
                var monthIndex = parseInt(r.m, 10) - 1; // Convert to 0-based index
                if (monthIndex >= 0 && monthIndex < 12) {
                  var monthName = monthNames[monthIndex];
                  monthlyPassData[monthName]['Sick Leave'].count++;
                  monthlyPassData[monthName]['Sick Leave'].dates.push(r.formatted_date);
                }
              });
            }

            // Resolve photo URL for every row before rendering (admin view)
            (result || []).forEach(attachStudentPhotoUrl);
            
            const student = (result && result.length > 0) ? result[0] : null;
            const tallyFee = (student && student.balance !== undefined && student.balance !== null) ? {
              recv_arrear_fee: student.recv_arrear_fee,
              recv_current_year: student.recv_current_year,
              recv_extra_stay: student.recv_extra_stay,
              recd_arrear_fee: student.recd_arrear_fee,
              recd_current_year: student.recd_current_year,
              recd_extra: student.recd_extra,
              balance: student.balance,
              as_on_date: student.as_on_date
            } : null;

            // Render view with monthlyPassData and backUrl to control "Back" navigation
            res.render(__dirname + '/views/studentprofile', {
              message: req.flash('message'),
              result: result,
              tallyFee: tallyFee,
              monthlyPassData: monthlyPassData,
              backUrl: backUrl
            });
          });
        });
      }

    });
  });
});

app.get('/logout', function (req, res) {
  res.clearCookie("jwt");
  res.render(__dirname + "/views/loginpanel", { message: req.flash('Logout Successfully') });
});

//out Hostel students route

app.get('/outstudents', verifyjwt, async function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (role == "BoysHostelAdmin") {
        var sql = "select log.logid,stu.uid,stu.sname,stu.status,log.hostelintime,log.approvaldt,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='MALE' and hostelintime is null and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/outstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "GirlsHostelAdmin") {
        var sql = "select log.logid,stu.uid,stu.sname,stu.status,log.hostelintime,log.approvaldt,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='FEMALE' and hostelintime is null and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/outstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "SuperID") {
        var sql = "select log.logid,stu.uid,stu.sname,stu.status,log.hostelintime,log.approvaldt,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and hostelintime is null and category='Hostel' ORDER BY log.logid desc";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/outstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else {
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }
      connection.release();
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

//gate out Students
app.get('/Gateoutstudents', verifyjwt, function (req, res,) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      // Align to IST calendar date like other routes
      var todayISTDateOnly = formatDateToISTString(new Date()).slice(0, 10); // 'YYYY-MM-DD'
      if (role == "BoysHostelAdmin") {
        var sql1 = "select log.logid,stu.uid,stu.sname,log.indatetime,log.outdatetime,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='MALE' and indatetime is null and outdatetime IS NOT NULL and category='Hostel' and date(log.outdatetime)=date('" + todayISTDateOnly + "') ORDER BY log.logid desc";
        connection.query(sql1, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/Gateoutstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "GirlsHostelAdmin") {
        var sql1 = "select log.logid,stu.uid,stu.sname,log.indatetime,log.outdatetime,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='FEMALE' and indatetime is null and outdatetime IS NOT NULL and category='Hostel' and date(log.outdatetime)=date('" + todayISTDateOnly + "') ORDER BY log.logid desc";
        connection.query(sql1, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/Gateoutstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "SuperID") {
        var sql1 = "select log.logid,stu.uid,stu.sname,log.indatetime,log.outdatetime,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and indatetime is null and outdatetime IS NOT NULL and date(log.outdatetime)=date('" + todayISTDateOnly + "') ORDER BY log.logid desc";
        connection.query(sql1, function (err, result) {
          if (err) throw err;
          else {

            res.render(__dirname + '/views/Gateoutstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }

      else {
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }
      connection.release();
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});


//Out student (gate)(In provision)
app.get('/gateout/:id', verifyjwt, function (req, res) {

  var id = req.params.id;


  dbbconnection.getConnection(function (err, connection) {

    var sql = "Update log_details1 set indatetime='" + formatDateTimeForDB(currentdate()) + "' where logid='" + id + "'";
    connection.query(sql, function (err, result) {
      if (err) throw err;
      else {
        req.flash('message', 'Updated successfully');
        res.redirect('/Gateoutstudents');
      }
    });
    connection.release();
  });




});


// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------
//importing excel
// Optimized Excel Import for Integrated Schema
// Route to display the list of hostel students
// Full Updated Route for Automatic Room Allocation
app.post('/import-tally-excel', verifyjwt, uploadFile.single('import-excel'), async function (req, res) {
  const tokenadmin = req.cookies.jwt;
  const decode = jwt.verify(tokenadmin, secretkey);
  const role = decode.role;

  if (!req.file) {
    req.flash('message', 'Error: No file selected.');
    return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
  }

  try {
    const allRows = await readXlsxFile(req.file.path);
    if (!allRows || allRows.length <= 3) {
      req.flash('message', 'Error: Excel file is empty or missing data rows.');
      return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
    }

    const dataRows = allRows.slice(2);
    const records = [];

    dataRows.forEach(row => {
      const suid = row[0];
      if (suid && String(suid).trim() !== '') {
        const asOnDateVal = row[9];
        let formattedDate = String(asOnDateVal || '');
        if (asOnDateVal instanceof Date) {
          formattedDate = `${String(asOnDateVal.getUTCDate()).padStart(2, '0')}/${String(asOnDateVal.getUTCMonth() + 1).padStart(2, '0')}/${asOnDateVal.getUTCFullYear()}`;
        }
        
        records.push([
          String(suid).trim(),
          String(row[1] || '').trim(),
          parseFloat(row[2]) || 0,
          parseFloat(row[3]) || 0,
          parseFloat(row[4]) || 0,
          parseFloat(row[5]) || 0,
          parseFloat(row[6]) || 0,
          parseFloat(row[7]) || 0,
          parseFloat(row[8]) || 0,
          formattedDate
        ]);
      }
    });

    if (records.length === 0) {
      req.flash('message', 'Error: No valid records found in the Excel file.');
      return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database connection error.');
        return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
      }

      const sql = `
        INSERT INTO tally_fee_data 
        (suid, student_name, recv_arrear_fee, recv_current_year, recv_extra_stay, 
         recd_arrear_fee, recd_current_year, recd_extra, balance, as_on_date) 
        VALUES ? 
        ON DUPLICATE KEY UPDATE 
        student_name=VALUES(student_name),
        recv_arrear_fee=VALUES(recv_arrear_fee),
        recv_current_year=VALUES(recv_current_year),
        recv_extra_stay=VALUES(recv_extra_stay),
        recd_arrear_fee=VALUES(recd_arrear_fee),
        recd_current_year=VALUES(recd_current_year),
        recd_extra=VALUES(recd_extra),
        balance=VALUES(balance),
        as_on_date=VALUES(as_on_date)
      `;

      connection.query(sql, [records], function (err, result) {
        connection.release();
        if (err) {
          console.error(err);
          req.flash('message', 'Error importing Tally data.');
        } else {
          req.flash('message', `Tally data imported successfully. ${records.length} records processed.`);
        }
        res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
      });
    });
  } catch (error) {
    console.error(error);
    req.flash('message', 'Error parsing Excel file.');
    res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
  }
});

app.get('/tally-preview', verifyjwt, function (req, res) {
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error.');
      return res.redirect('/studentsupdatehostel/SuperID'); // generic fallback
    }

    const sql = `
      SELECT t.*, s.uid, s.sname, s.dept, s.year 
      FROM tally_fee_data t 
      LEFT JOIN studentdetails s ON (s.uid = t.suid OR s.hostel_id = t.suid)
      ORDER BY t.suid ASC
    `;
    connection.query(sql, function (err, rows) {
      connection.release();
      if (err) {
        req.flash('message', 'Error fetching preview data.');
        return res.redirect('/studentsupdatehostel/SuperID');
      }
      res.render(__dirname + '/views/tally_preview', {
        result: rows,
        message: req.flash('message')
      });
    });
  });
});

app.post('/push-tally-data', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  const decode = jwt.verify(tokenadmin, secretkey);
  const role = decode.role;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database connection error.');
      return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
    }

    const countMatchedSql = `SELECT COUNT(DISTINCT t.suid) as matched FROM tally_fee_data t INNER JOIN studentdetails s ON (t.suid = s.uid OR t.suid = s.hostel_id)`;
    const countTotalSql = `SELECT COUNT(*) as total FROM tally_fee_data`;

    connection.query(countMatchedSql, function (err1, matchedResult) {
      if (err1) {
        connection.release();
        req.flash('message', 'Error verifying data linkage.');
        return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
      }
      connection.query(countTotalSql, function (err2, totalResult) {
        connection.release();
        if (err2) {
          req.flash('message', 'Error verifying data linkage.');
          return res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
        }

        const matched = matchedResult[0].matched;
        const total = totalResult[0].total;
        const unmatched = total - matched;
        
        let msg = `Tally data is live on student profiles. ${matched}/${total} students matched.`;
        if (unmatched > 0) {
          msg += ` ${unmatched} UIDs not found in system.`;
        }
        
        req.flash('message', msg);
        res.redirect('/studentsupdatehostel/' + encodeURIComponent(role));
      });
    });
  });
});

app.post('/import-excel', uploadFile.single('import-excel'), async function (req, res) {
  const tokenadmin = req.cookies.jwt;
  const decode = jwt.verify(tokenadmin, secretkey);
  const role = decode.role;

  if (!req.file) {
    // Fetch list to prevent EJS error if no file selected
    dbbconnection.getConnection((err, connection) => {
      let sql = (role === "BoysHostelAdmin") ? "SELECT * FROM studentdetails WHERE gender='MALE' AND category='Hostel'" :
        (role === "GirlsHostelAdmin") ? "SELECT * FROM studentdetails WHERE gender='FEMALE' AND category='Hostel'" :
          "SELECT * FROM studentdetails WHERE category='Hostel'";

      connection.query(sql, (err, students) => {
        connection.release();
        return res.render(__dirname + '/views/studentsupdate', {
          result: students,
          message: "Error: No file selected."
        });
      });
    });
    return;
  }

  try {
    const allRows = await readXlsxFile(req.file.path);
    if (!allRows || allRows.length === 0) {
      req.flash('message', 'Error: Excel file is empty.');
      return res.redirect('/studentsupdate');
    }

    const firstRow = allRows[0] || [];
    const looksLikeHeader = firstRow.some(v => typeof v === 'string' && /uid|name|dept|department|email|mobile|dob|gender|category|parent|photo|path|year|address/i.test(v));
    const headerRow = looksLikeHeader ? firstRow : null;
    const dataRows = looksLikeHeader ? allRows.slice(1) : allRows;

    function normHeader(h) {
      return String(h || '')
        .trim()
        .toLowerCase()
        .replace(/\s+/g, '')
        .replace(/[^a-z0-9]/g, '');
    }

    const headerIndex = {};
    if (headerRow) {
      for (let i = 0; i < headerRow.length; i++) {
        const key = normHeader(headerRow[i]);
        if (key && headerIndex[key] === undefined) headerIndex[key] = i;
      }
    }

    function pick(row, keys) {
      for (const k of keys) {
        const idx = headerIndex[normHeader(k)];
        if (idx !== undefined) return row[idx];
      }
      return undefined;
    }

    function cleaned(v) {
      if (v === undefined || v === null) return null;
      const s = String(v).trim();
      return s === '' ? null : s;
    }

    // Determine default category when sheet doesn't provide it
    const fileName = String((req.file && req.file.originalname) || '').toLowerCase();
    const defaultCategory = (fileName.includes('day') && fileName.includes('scholar')) ? 'Day Scholar' : 'Hostel';

    const preparedRows = [];
    for (const row of dataRows) {
      if (!row || row.length === 0) continue;
      const uidRaw = headerRow ? pick(row, ['uid', 'studentuid', 'enrollment', 'rollno', 'rollnumber']) : row[0];
      const uid = cleaned(uidRaw);
      if (!uid) continue;

      // Build 20 columns in the exact order expected by SQL
      const sname = cleaned(headerRow ? pick(row, ['sname', 'name', 'studentname', 'fullname']) : row[1]);
      const email = cleaned(headerRow ? pick(row, ['email', 'mail', 'emailid']) : row[2]);
      const dept = cleaned(headerRow ? pick(row, ['dept', 'department', 'branch']) : row[3]);
      const address = cleaned(headerRow ? pick(row, ['address', 'addr', 'residentialaddress']) : row[4]);
      const year = cleaned(headerRow ? pick(row, ['year', 'class', 'studyear']) : row[5]);
      const category = cleaned(headerRow ? pick(row, ['category', 'type']) : row[6]) || defaultCategory;
      const gender = cleaned(headerRow ? pick(row, ['gender', 'sex']) : row[7]);
      const mobileno = cleaned(headerRow ? pick(row, ['mobileno', 'mobile', 'phonenumber', 'contact']) : row[8]);
      const dob = cleaned(headerRow ? pick(row, ['dob', 'dateofbirth', 'birthdate']) : row[9]);
      const academicyear = cleaned(headerRow ? pick(row, ['academicyear', 'academicyear', 'admissionyear']) : row[10]);
      const path = cleaned(headerRow ? pick(row, ['path', 'photo', 'photopath', 'image', 'imagepath']) : row[11]);
      const status = cleaned(headerRow ? pick(row, ['status', 'restrictionstatus']) : row[12]) || 'Unrestrict';
      const parentname = cleaned(headerRow ? pick(row, ['parentname', 'parentsname', 'fathername', 'guardianname']) : row[13]);
      const parentnumber = cleaned(headerRow ? pick(row, ['parentnumber', 'parentsnumber', 'parentcontact', 'guardiancontact']) : row[14]);

      // Hostel allocation columns not provided in most sheets
      const room_no = cleaned(headerRow ? pick(row, ['roomno', 'room', 'room_no']) : row[15]);
      const bed_no = cleaned(headerRow ? pick(row, ['bedno', 'bed', 'bed_no']) : row[16]);

      const other1 = cleaned(headerRow ? pick(row, ['other1', 'messtype', 'mess', 'mess_type']) : row[17]);
      const other2 = cleaned(headerRow ? pick(row, ['other2', 'block']) : row[18]);
      const other3 = cleaned(headerRow ? pick(row, ['other3']) : row[19]);

      preparedRows.push([
        uid,
        sname,
        email,
        dept,
        address,
        year,
        category,
        gender,
        mobileno,
        dob,
        academicyear,
        path,
        status,
        parentname,
        parentnumber,
        room_no,
        bed_no,
        other1,
        other2,
        other3
      ]);
    }

    if (preparedRows.length === 0) {
      req.flash('message', 'Error: No valid rows found in Excel.');
      return res.redirect('/studentsupdate');
    }

    dbbconnection.getConnection((error, connection) => {
      if (error) throw error;

      // UPDATED SQL: 20 Columns including room_no and bed_no
      let sql = `INSERT INTO studentdetails 
                (uid, sname, email, dept, address, year, category, gender, mobileno, dob, academicyear, path, status, parentname, parentnumber, room_no, bed_no, other1, other2, other3) 
                VALUES ? 
                ON DUPLICATE KEY UPDATE 
                category=VALUES(category),
                room_no=VALUES(room_no),
                bed_no=VALUES(bed_no)`;

      connection.query(sql, [preparedRows], (error, response) => {
        connection.release();
        if (error) {
          console.error("Excel Import Error:", error);
          req.flash('message', 'Error importing Excel. Please ensure UID is present and columns are mapped correctly.');
          return res.redirect('/studentsupdate');
        }
        req.flash('message', 'Students Imported and Allocated Successfully');
        res.redirect('/studentsupdate');
      });
    });
  } catch (err) {
    console.error("Excel Parsing Error:", err);
    req.flash('message', 'Error reading Excel file.');
    res.redirect('/studentsupdate');
  }
});
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------
//date range for Gate out Students

app.post('/Gateoutdaterange', function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (role == "BoysHostelAdmin") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;
        var sql = "select log.logid,stu.uid,stu.sname,log.indatetime,log.outdatetime,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='MALE' and indatetime is null and outdatetime IS NOT NULL and date(log.approvaldt) between date('" + datefrom + "') and date('" + dateto + "') and category='Hostel' ORDER BY log.logid desc"
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/Gateoutstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "GirlsHostelAdmin") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;
        var sql = "select log.logid,stu.uid,stu.sname,log.indatetime,log.outdatetime,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.gender='FEMALE' and indatetime is null and outdatetime IS NOT NULL and date(log.approvaldt) between date('" + datefrom + "') and date('" + dateto + "') and category='Hostel' ORDER BY log.logid desc"

        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/Gateoutstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else if (role == "SuperID") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;
        var sql = "select log.logid,stu.uid,stu.sname,log.indatetime,log.outdatetime,log.passtype from log_details1 as log join studentdetails as stu where stu.uid=log.uid and indatetime is null and outdatetime IS NOT NULL and date(log.approvaldt) between date('" + datefrom + "') and date('" + dateto + "') and category='Hostel' ORDER BY log.logid desc"
        connection.query(sql, function (err, result) {
          if (err) throw err;
          else {
            res.render(__dirname + '/views/Gateoutstudents', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          }
        });
      }
      else {
        req.flash('message', 'Unauthorised Access');
        res.redirect('/loginpanel');
      }

      connection.release();
    });

  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Login failed');
    return res.redirect('/loginpanel');
  }


});



//Sick Leave - Scan ID page
app.get('/sickleave', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "SuperID" || role == "Hostelauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      res.render(__dirname + '/views/sickleave', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
    } else {
      req.flash('message', 'Unauthorised access');
      res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

//Sick Leave - Form page after scanning
app.get('/sickleaveform/:uid', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "SuperID" || role == "Hostelauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      var uid = req.params.uid;
      dbbconnection.getConnection(function (err, connection) {
        var sql = "select * from studentdetails where category='Hostel' and uid='" + uid + "'";
        connection.query(sql, function (err, result) {
          if (err) throw err;
          if (result.length > 0) {
            attachStudentPhotoUrl(result[0]);
            res.render(__dirname + '/views/sickleaveform', { result: result, message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
          } else {
            req.flash('message', 'Student not found or not a hostel student');
            res.redirect('/sickleave');
          }
          connection.release();
        });
      });
    } else {
      req.flash('message', 'Unauthorised access');
      res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

//Sick Leave - Save sick leave record
app.post('/savesickleave/:uid', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    var adminname = decode.adminname;
    if (role == "SuperID" || role == "Hostelauthority" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      var uid = req.params.uid;
      var illness = req.body.illness || req.body.other_illness;
      if (!illness || illness.trim() === '') {
        req.flash('message', 'Please select or enter an illness type');
        return res.redirect('/sickleaveform/' + uid);
      }
      // Sanitize illness input to prevent SQL injection
      illness = illness.trim().replace(/'/g, "''");

      dbbconnection.getConnection(function (err, connection) {
        var currentDateTime = formatDateTimeForDB(currentdate());
        var logdate = currentDateTime.split(' ')[0];
        var logtime = currentDateTime.split(' ')[1] + ' ' + (currentDateTime.split(' ')[2] || '');

        var sql = "INSERT INTO sick_leave_logs (uid, illness, logdate, logtime, recorded_by, created_at) VALUES ('" + uid + "', '" + illness + "', '" + logdate + "', '" + logtime + "', '" + adminname + "', '" + currentDateTime + "')";
        connection.query(sql, function (err, result) {
          if (err) {
            console.error('Error saving sick leave:', err);
            req.flash('message', 'Error saving sick leave record. Please try again.');
            res.redirect('/sickleaveform/' + uid);
          } else {
            req.flash('message', 'Sick leave recorded successfully');
            res.redirect('/sickleave');
          }
          connection.release();
        });
      });
    } else {
      req.flash('message', 'Unauthorised access');
      res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

//Sick Leave - View logs
app.get('/sickleavelogs', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      // Align filter to IST calendar date and use range on created_at to avoid timezone mismatches and leverage indexes
      var todayISTDateOnly = formatDateToISTString(new Date()).slice(0, 10); // 'YYYY-MM-DD'
      var startIST = todayISTDateOnly + ' 00:00:00';
      if (role == "BoysHostelAdmin") {
        var sql = `
          SELECT sl.logid, sl.uid, sl.illness, sl.logdate, sl.logtime, sl.recorded_by, sl.created_at, stu.sname, stu.dept, 'Approved' as status
          FROM sick_leave_logs as sl 
          JOIN studentdetails as stu ON sl.uid = stu.uid 
          WHERE stu.gender='MALE' AND stu.category='Hostel' 
            AND (date(sl.logdate)=date('${todayISTDateOnly}') OR (sl.created_at >= '${startIST}' AND sl.created_at < DATE_ADD('${startIST}', INTERVAL 1 DAY)))
          UNION ALL
          SELECT NULL as logid, sr.uid, sr.illness, DATE(sr.created_at) as logdate, TIME(sr.created_at) as logtime, sr.approved_by as recorded_by, sr.created_at, stu.sname, stu.dept, 'Rejected' as status
          FROM sick_leave_requests as sr
          JOIN studentdetails as stu ON sr.uid = stu.uid
          WHERE stu.gender='MALE' AND stu.category='Hostel' AND sr.status = 'rejected'
            AND (DATE(sr.created_at) = DATE('${todayISTDateOnly}'))
          ORDER BY created_at DESC LIMIT 100`;
        connection.query(sql, function (err, result) {
          if (err) throw err;
          res.render(__dirname + '/views/sickleavelogs', { result: result, message: req.flash('message'), role: role });
          connection.release();
        });
      } else if (role == "GirlsHostelAdmin") {
        var sql = `
          SELECT sl.logid, sl.uid, sl.illness, sl.logdate, sl.logtime, sl.recorded_by, sl.created_at, stu.sname, stu.dept, 'Approved' as status
          FROM sick_leave_logs as sl 
          JOIN studentdetails as stu ON sl.uid = stu.uid 
          WHERE stu.gender='FEMALE' AND stu.category='Hostel' 
            AND (date(sl.logdate)=date('${todayISTDateOnly}') OR (sl.created_at >= '${startIST}' AND sl.created_at < DATE_ADD('${startIST}', INTERVAL 1 DAY)))
          UNION ALL
          SELECT NULL as logid, sr.uid, sr.illness, DATE(sr.created_at) as logdate, TIME(sr.created_at) as logtime, sr.approved_by as recorded_by, sr.created_at, stu.sname, stu.dept, 'Rejected' as status
          FROM sick_leave_requests as sr
          JOIN studentdetails as stu ON sr.uid = stu.uid
          WHERE stu.gender='FEMALE' AND stu.category='Hostel' AND sr.status = 'rejected'
            AND (DATE(sr.created_at) = DATE('${todayISTDateOnly}'))
          ORDER BY created_at DESC LIMIT 100`;
        connection.query(sql, function (err, result) {
          if (err) throw err;
          res.render(__dirname + '/views/sickleavelogs', { result: result, message: req.flash('message'), role: role });
          connection.release();
        });
      } else if (role == "SuperID") {
        var sql = `
          SELECT sl.logid, sl.uid, sl.illness, sl.logdate, sl.logtime, sl.recorded_by, sl.created_at, stu.sname, stu.dept, 'Approved' as status
          FROM sick_leave_logs as sl 
          JOIN studentdetails as stu ON sl.uid = stu.uid 
          WHERE stu.category='Hostel' 
            AND (date(sl.logdate)=date('${todayISTDateOnly}') OR (sl.created_at >= '${startIST}' AND sl.created_at < DATE_ADD('${startIST}', INTERVAL 1 DAY)))
          UNION ALL
          SELECT NULL as logid, sr.uid, sr.illness, DATE(sr.created_at) as logdate, TIME(sr.created_at) as logtime, sr.approved_by as recorded_by, sr.created_at, stu.sname, stu.dept, 'Rejected' as status
          FROM sick_leave_requests as sr
          JOIN studentdetails as stu ON sr.uid = stu.uid
          WHERE stu.category='Hostel' AND sr.status = 'rejected'
            AND (DATE(sr.created_at) = DATE('${todayISTDateOnly}'))
          ORDER BY created_at DESC LIMIT 100`;
        connection.query(sql, function (err, result) {
          if (err) throw err;
          res.render(__dirname + '/views/sickleavelogs', { result: result, message: req.flash('message'), role: role });
          connection.release();
        });
      } else {
        req.flash('message', 'Unauthorised access');
        res.redirect('/loginpanel');
        connection.release();
      }
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

//Sick Leave - Date range filter
app.post('/sickleavelogsdaterange', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    var datefrom = req.body.datefrom;
    var dateto = req.body.dateto;
    dbbconnection.getConnection(function (err, connection) {
      if (role == "BoysHostelAdmin") {
        var sql = `
          SELECT sl.logid, sl.uid, sl.illness, sl.logdate, sl.logtime, sl.recorded_by, sl.created_at, stu.sname, stu.dept, 'Approved' as status
          FROM sick_leave_logs as sl 
          JOIN studentdetails as stu ON sl.uid = stu.uid 
          WHERE stu.gender='MALE' AND stu.category='Hostel' AND date(sl.logdate) BETWEEN date('${datefrom}') AND date('${dateto}')
          UNION ALL
          SELECT NULL as logid, sr.uid, sr.illness, DATE(sr.created_at) as logdate, TIME(sr.created_at) as logtime, sr.approved_by as recorded_by, sr.created_at, stu.sname, stu.dept, 'Rejected' as status
          FROM sick_leave_requests as sr
          JOIN studentdetails as stu ON sr.uid = stu.uid
          WHERE stu.gender='MALE' AND stu.category='Hostel' AND sr.status = 'rejected' AND DATE(sr.created_at) BETWEEN date('${datefrom}') AND date('${dateto}')
          ORDER BY created_at DESC`;
        connection.query(sql, function (err, result) {
          if (err) throw err;
          res.render(__dirname + '/views/sickleavelogs', { result: result, message: req.flash('message'), role: role });
          connection.release();
        });
      } else if (role == "GirlsHostelAdmin") {
        var sql = `
          SELECT sl.logid, sl.uid, sl.illness, sl.logdate, sl.logtime, sl.recorded_by, sl.created_at, stu.sname, stu.dept, 'Approved' as status
          FROM sick_leave_logs as sl 
          JOIN studentdetails as stu ON sl.uid = stu.uid 
          WHERE stu.gender='FEMALE' AND stu.category='Hostel' AND date(sl.logdate) BETWEEN date('${datefrom}') AND date('${dateto}')
          UNION ALL
          SELECT NULL as logid, sr.uid, sr.illness, DATE(sr.created_at) as logdate, TIME(sr.created_at) as logtime, sr.approved_by as recorded_by, sr.created_at, stu.sname, stu.dept, 'Rejected' as status
          FROM sick_leave_requests as sr
          JOIN studentdetails as stu ON sr.uid = stu.uid
          WHERE stu.gender='FEMALE' AND stu.category='Hostel' AND sr.status = 'rejected' AND DATE(sr.created_at) BETWEEN date('${datefrom}') AND date('${dateto}')
          ORDER BY created_at DESC`;
        connection.query(sql, function (err, result) {
          if (err) throw err;
          res.render(__dirname + '/views/sickleavelogs', { result: result, message: req.flash('message'), role: role });
          connection.release();
        });
      } else if (role == "SuperID") {
        var sql = `
          SELECT sl.logid, sl.uid, sl.illness, sl.logdate, sl.logtime, sl.recorded_by, sl.created_at, stu.sname, stu.dept, 'Approved' as status
          FROM sick_leave_logs as sl 
          JOIN studentdetails as stu ON sl.uid = stu.uid 
          WHERE stu.category='Hostel' AND date(sl.logdate) BETWEEN date('${datefrom}') AND date('${dateto}')
          UNION ALL
          SELECT NULL as logid, sr.uid, sr.illness, DATE(sr.created_at) as logdate, TIME(sr.created_at) as logtime, sr.approved_by as recorded_by, sr.created_at, stu.sname, stu.dept, 'Rejected' as status
          FROM sick_leave_requests as sr
          JOIN studentdetails as stu ON sr.uid = stu.uid
          WHERE stu.category='Hostel' AND sr.status = 'rejected' AND DATE(sr.created_at) BETWEEN date('${datefrom}') AND date('${dateto}')
          ORDER BY created_at DESC`;
        connection.query(sql, function (err, result) {
          if (err) throw err;
          res.render(__dirname + '/views/sickleavelogs', { result: result, message: req.flash('message'), role: role });
          connection.release();
        });
      } else {
        req.flash('message', 'Unauthorised access');
        res.redirect('/loginpanel');
        connection.release();
      }
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

app.post('/api/edit-sick-leave', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    if (role !== 'SuperID') {
      return res.status(403).json({ success: false, message: 'Unauthorised access' });
    }

    const { logid, illness, logdate, logtime } = req.body;
    if (!logid) {
      return res.status(400).json({ success: false, message: 'Missing log ID' });
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) return res.status(500).json({ success: false, message: 'Database error' });

      // Format logdate to YYYY-MM-DD for consistency
      const formattedDate = new Date(logdate).toISOString().split('T')[0];

      const sql = "UPDATE sick_leave_logs SET illness = ?, logdate = ?, logtime = ? WHERE logid = ?";
      connection.query(sql, [illness, formattedDate, logtime, logid], function (upErr, result) {
        connection.release();
        if (upErr) {
          console.error(upErr);
          return res.status(500).json({ success: false, message: 'Update failed' });
        }

        res.json({ success: true, message: 'Log updated successfully' });
      });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/delete-sick-leave', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    if (role !== 'SuperID') {
      return res.status(403).json({ success: false, message: 'Unauthorised access' });
    }

    const { logid } = req.body;
    if (!logid) {
      return res.status(400).json({ success: false, message: 'Missing log ID' });
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) return res.status(500).json({ success: false, message: 'Database error' });

      connection.query("SELECT uid, logdate FROM sick_leave_logs WHERE logid = ?", [logid], function (selErr, selRes) {
        if (selErr || selRes.length === 0) {
          connection.release();
          return res.status(500).json({ success: false, message: 'Log not found' });
        }

        const uid = selRes[0].uid;
        const logdate = selRes[0].logdate;
        let formattedDate;
        try {
          formattedDate = new Date(logdate).toISOString().split('T')[0];
        } catch (e) {
          formattedDate = logdate;
        }

        const sql = "DELETE FROM sick_leave_logs WHERE logid = ?";
        connection.query(sql, [logid], function (delErr, result) {
          if (delErr) {
            connection.release();
            console.error(delErr);
            return res.status(500).json({ success: false, message: 'Deletion failed' });
          }

          const reqSql = "DELETE FROM sick_leave_requests WHERE uid = ? AND DATE(created_at) = ?";
          connection.query(reqSql, [uid, formattedDate], function (reqErr, reqResult) {
            connection.release();
            if (reqErr) {
              console.error(reqErr);
            }
            res.json({ success: true, message: 'Log and associated request deleted successfully' });
          });
        });
      });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

//campus reports
app.get('/campusreports', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (err) throw err;
      else if (role == "SuperID") {
        var sql = "select stu.uid,stu.sname,log.indatetime,stu.dept,log.outdatetime,log.approvaldt,log.hostelintime,log.hosteloutauth,log.passtype,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`,CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and stu.category='Day Scholar' ORDER BY log.logid desc"
        dbbconnection.query(sql, function (err, result) {


          if (err) throw err;
          else {
            res.render(__dirname + '/views/campusreports', { result: result, message: req.flash('message') })
          }
        })

      }
      else {
        req.flash('message', 'Unauthourised access ', role);
        res.redirect('/loginpanel');
      }
      connection.release();
    });

  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }

});

app.post('/daterangecampusreport', verifyjwt, function (req, res) {

  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);

    role = decode.role;
    dbbconnection.getConnection(function (err, connection) {
      if (err) throw err;
      else if (role == "SuperID") {
        var datefrom = req.body.datefrom;
        var dateto = req.body.dateto;
        var sql = "select stu.uid,stu.sname,log.indatetime,log.outdatetime,log.approvaldt,stu.dept,log.hostelintime,log.passtype,log.hosteloutauth,CONCAT(FLOOR(HOUR(TIMEDIFF(outdatetime, indatetime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(outdatetime, indatetime)), 24), ' hours ',MINUTE(TIMEDIFF(outdatetime, indatetime)), ' minutes')AS `Duration`,CONCAT(FLOOR(HOUR(TIMEDIFF(approvaldt, hostelintime)) / 24), ' days ',MOD(HOUR(TIMEDIFF(approvaldt, hostelintime)), 24), ' hours ',MINUTE(TIMEDIFF(approvaldt, hostelintime)), ' minutes') AS `Durationh` from log_details1 as log join studentdetails as stu where stu.uid=log.uid and date(log.outdatetime) between date('" + datefrom + "') and date('" + dateto + "') and stu.category='Day Scholar' ORDER BY log.logid desc"
        dbbconnection.query(sql, function (err, result) {

          if (err) throw err;
          else {
            res.render(__dirname + '/views/campusreports', { result: result, message: req.flash('message') })
          }
        })

      }
      else {
        req.flash('message', 'Unauthourised access ', role);
        res.redirect('/loginpanel');
      }
      connection.release();
    });

  }

  catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }

});


function getSafeRedirectPath(req, fallback = '/outstudents') {
  const direct = req.query.redirect;
  if (direct && direct.startsWith('/')) {
    return direct;
  }
  const referer = req.get('Referer');
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      if (refererUrl.pathname.startsWith('/')) {
        return refererUrl.pathname + refererUrl.search;
      }
    } catch (err) {
      // ignore malformed referer header
    }
  }
  return fallback;
}

app.get('/restrictstu/:uid', verifyjwt, function (req, res) {
  const redirectPath = getSafeRedirectPath(req);
  var uid = req.params.uid;
  dbbconnection.getConnection(function (err, connection) {

    var sql = "Update studentdetails set status='Restrict' where uid='" + uid + "'";
    connection.query(sql, function (err, result) {
      if (err) throw err;
      else {
        req.flash('message', 'Restrict successfully');
        res.redirect(redirectPath);
      }
    });
    connection.release();
  });
})

app.get('/Unrestrictstu/:uid', verifyjwt, function (req, res) {
  const redirectPath = getSafeRedirectPath(req);
  var uid = req.params.uid;
  dbbconnection.getConnection(function (err, connection) {

    var sql = "Update studentdetails set status='Unrestrict' where uid='" + uid + "'";
    connection.query(sql, function (err, result) {
      if (err) throw err;
      else {
        req.flash('message', 'UnRestrict successfully');
        res.redirect(redirectPath);
      }
    });
    connection.release();
  });
})

app.get('/restrictionaudit', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database connection error');
        return res.redirect('/loginpanel');
      }

      const auditSql = `
        SELECT
          a.id,
          a.uid,
          s.sname,
          s.gender,
          s.category,
          a.logid,
          a.passtype,
          a.restriction_reason,
          a.restriction_source,
          a.details,
          a.restricted_at,
          l.approvaldt,
          l.outdatetime,
          l.indatetime,
          l.hostelintime,
          l.status AS log_status
        FROM pass_restriction_audit a
        LEFT JOIN studentdetails s ON s.uid = a.uid
        LEFT JOIN log_details1 l ON l.logid = a.logid
        WHERE s.status = 'Restrict'
        AND a.id = (SELECT MAX(id) FROM pass_restriction_audit WHERE uid = a.uid)
        ORDER BY a.id DESC
        LIMIT 200
      `;

      connection.query(auditSql, function (auditErr, rows) {
        if (auditErr) {
          connection.release();
          console.error('Failed to load restriction audit:', auditErr);
          req.flash('message', 'Unable to load restriction audit');
          return res.render(__dirname + '/views/restrictionaudit', {
            message: req.flash('message'),
            result: [],
            role: role
          });
        }

        connection.release();
        res.render(__dirname + '/views/restrictionaudit', {
          message: req.flash('message'),
          result: rows || [],
          role: role
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

app.post('/api/admin/audit/mark-scan/:logid', express.json(), verifyjwt, function(req, res) {
  const logid = req.params.logid;
  const type = req.body.type;
  const restrictionReason = req.body.restriction_reason || '';

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, message: 'Database connection error' });
    
    if (type === 'unrestrict') {
      // For hostel-scan-after-10pm cases: auto-complete hostel IN using the original scan time
      const isHostelScanCase = [
        'hostel_scan_after_10pm',
        'scanned_after_10pm',
        'midnight_sweep_home_pass_late_hostel_scan'
      ].includes(restrictionReason);

      if (isHostelScanCase) {
        // Look up the original scan time from the audit record's details JSON
        const auditLookupSql = `
          SELECT pra.details, l.hostelintime AS current_hostelintime, l.uid
          FROM pass_restriction_audit pra
          LEFT JOIN log_details1 l ON l.logid = pra.logid
          WHERE pra.logid = ? ORDER BY pra.id DESC LIMIT 1
        `;
        connection.query(auditLookupSql, [logid], function(lookupErr, auditRows) {
          if (lookupErr || !auditRows || auditRows.length === 0) {
            // Fallback: just unrestrict without hostel-in
            const fallbackSql = "UPDATE studentdetails SET status='Unrestrict' WHERE uid=(SELECT uid FROM log_details1 WHERE logid='" + logid + "')";
            connection.query(fallbackSql, function() {
              connection.release();
              return res.json({ success: true, message: 'Student unrestricted (fallback, audit not found)' });
            });
            return;
          }

          const auditRow = auditRows[0];
          let originalHostelInTime = null;

          // Try to extract hostelintime from the details JSON blob
          try {
            const details = typeof auditRow.details === 'string'
              ? JSON.parse(auditRow.details)
              : auditRow.details;
            if (details && details.hostelintime && details.hostelintime !== 'null') {
              originalHostelInTime = details.hostelintime;
            }
          } catch (e) {}

          // If we still don't have a scan time, use the current hostelintime from the log (set at scan time)
          if (!originalHostelInTime && auditRow.current_hostelintime) {
            originalHostelInTime = auditRow.current_hostelintime;
          }

          // If no scan time at all, use current time as last resort
          if (!originalHostelInTime) {
            originalHostelInTime = formatDateTimeForDB(currentdate());
          }

          // Step 1: Mark the log as DEAD with the original hostel-in time
          const markHostelInSql = "UPDATE log_details1 SET status='DEAD', hostelintime=? WHERE logid=?";
          connection.query(markHostelInSql, [originalHostelInTime, logid], function(hostelErr) {
            if (hostelErr) {
              connection.release();
              return res.status(500).json({ success: false, message: 'Failed to record hostel-in time' });
            }
            // Step 2: Unrestrict the student
            const unrestrictSql = "UPDATE studentdetails SET status='Unrestrict' WHERE uid=(SELECT uid FROM log_details1 WHERE logid='" + logid + "')";
            connection.query(unrestrictSql, function(err2) {
              connection.release();
              if (err2) return res.status(500).json({ success: false, message: 'Unrestrict failed' });
              return res.json({ success: true, message: 'Student unrestricted and hostel-in recorded with original scan time' });
            });
          });
        });
        return;
      }

      // Default unrestrict (non-hostel-scan cases)
      const unrestrictSql = "UPDATE studentdetails SET status='Unrestrict' WHERE uid=(SELECT uid FROM log_details1 WHERE logid='" + logid + "')";
      connection.query(unrestrictSql, function(err2) {
        connection.release();
        if (err2) return res.status(500).json({ success: false, message: 'Unrestrict failed' });
        return res.json({ success: true, message: 'Student unrestricted successfully' });
      });
      return;
    }

    let sql = '';
    const currentDateTime = formatDateTimeForDB(currentdate());
    
    if (type === 'gate_in') {
      sql = "UPDATE log_details1 SET indatetime='" + currentDateTime + "' WHERE logid='" + logid + "'";
    } else if (type === 'hostel_in') {
      sql = "UPDATE log_details1 SET status='DEAD', hostelintime='" + currentDateTime + "' WHERE logid='" + logid + "'";
    } else {
      connection.release();
      return res.status(400).json({ success: false, message: 'Invalid scan type' });
    }
    
    connection.query(sql, function(err, result) {
      connection.release();
      if (err) {
        return res.status(500).json({ success: false, message: 'Update failed' });
      }
      
      if (type === 'hostel_in') {
        res.json({ success: true, message: 'Hostel In marked successfully' });
      } else {
        res.json({ success: true, message: 'Gate In marked successfully' });
      }
    });
  });
});


// =====================================================
// STUDENT PORTAL ROUTES
// =====================================================

// Student JWT Verification Middleware
function verifyStudentJwt(req, res, next) {
  const studentToken = req.cookies.studentjwt;
  if (!studentToken) {
    return res.redirect('/student/login');
  }
  try {
    const decode = jwt.verify(studentToken, studentSecretKey);
    req.studentUid = decode.uid;
    req.studentName = decode.name;

    dbbconnection.getConnection(function (err, connection) {
      if (err || !connection) {
        req.flash('message', 'Database connection error');
        res.clearCookie('studentjwt');
        return res.redirect('/student/login');
      }

      applyPost10pmPassRulesForUid(connection, decode.uid, function (rulesErr) {
        if (rulesErr) {
          connection.release();
          console.error('Post-10pm pass rule check failed for student middleware:', rulesErr);
          req.flash('message', 'Temporary error. Please try again.');
          res.clearCookie('studentjwt');
          return res.redirect('/student/login');
        }

        const statusSql = "SELECT status FROM studentdetails WHERE uid = ? LIMIT 1";
        connection.query(statusSql, [decode.uid], function (statusErr, statusResult) {
          connection.release();
          if (statusErr || !statusResult || statusResult.length === 0) {
            req.flash('message', 'Student not found');
            res.clearCookie('studentjwt');
            return res.redirect('/student/login');
          }

          const currentStatus = ((statusResult[0].status || '') + '').trim().toLowerCase();
          if (currentStatus === 'restrict') {
            req.flash('message', 'Login blocked. Your account is restricted. Please contact the hostel office.');
            res.clearCookie('studentjwt');
            return res.redirect('/student/login');
          }

          // Sliding session: re-issue token only after restriction checks pass
          const payload = { uid: decode.uid, name: decode.name, category: decode.category };
          jwt.sign(payload, studentSecretKey, { expiresIn: '7d' }, (signErr, newToken) => {
            if (!signErr && newToken) {
              res.cookie('studentjwt', newToken, {
                httpOnly: true,
                sameSite: 'lax',
                secure: process.env.NODE_ENV === 'production',
                maxAge: 7 * 24 * 60 * 60 * 1000
              });
            }
            next();
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie("studentjwt");
    return res.redirect('/student/login');
  }
}

// Student Login Page
app.get('/student/login', function (req, res) {
  res.render(__dirname + '/views/studentlogin', { message: req.flash('message'), getDateTimeInUserTimeZone: getDateTimeInUserTimeZone });
});

// Student Login Handler
app.post('/student/login', function (req, res) {
  const uid = req.body.uid;
  const password = req.body.password;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database connection error');
      return res.redirect('/student/login');
    }

    // First check if student exists
    var sql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(sql, [uid], function (err, result) {
      if (err) {
        connection.release();
        req.flash('message', 'Error occurred');
        return res.redirect('/student/login');
      }

      if (result.length === 0) {
        connection.release();
        req.flash('message', 'Student not found');
        return res.redirect('/student/login');
      }

      const student = result[0];

      // Check if student has a password set, if not use mobile number as default
      // For first-time login, password should match mobile number
      const studentPassword = student.password || student.mobileno;

      // If password exists and is hashed (starts with $2), use bcrypt compare
      if (student.password && student.password.startsWith('$2')) {
        bcrypt.compare(password, student.password, function (berr, bresult) {
          if (bresult) {
            applyPost10pmPassRulesForUid(connection, student.uid, function (rulesErr) {
              if (rulesErr) {
                connection.release();
                console.error('Post-10pm pass rule check failed during student login:', rulesErr);
                req.flash('message', 'Temporary error. Please try again.');
                return res.redirect('/student/login');
              }

              connection.query("SELECT status FROM studentdetails WHERE uid = ? LIMIT 1", [student.uid], function (statusErr, statusResult) {
                connection.release();
                if (statusErr || !statusResult || statusResult.length === 0) {
                  req.flash('message', 'Student not found');
                  return res.redirect('/student/login');
                }

                const currentStatus = ((statusResult[0].status || '') + '').trim().toLowerCase();
                if (currentStatus === 'restrict') {
                  req.flash('message', 'Login blocked. Your account is restricted. Please contact the hostel office.');
                  return res.redirect('/student/login');
                }

                createStudentSession(req, res, student);
              });
            });
          } else {
            connection.release();
            req.flash('message', 'Incorrect password');
            return res.redirect('/student/login');
          }
        });
      } else {
        // Plain text comparison (mobile number as default password)
        if (password === studentPassword) {
          applyPost10pmPassRulesForUid(connection, student.uid, function (rulesErr) {
            if (rulesErr) {
              connection.release();
              console.error('Post-10pm pass rule check failed during student login:', rulesErr);
              req.flash('message', 'Temporary error. Please try again.');
              return res.redirect('/student/login');
            }

            connection.query("SELECT status FROM studentdetails WHERE uid = ? LIMIT 1", [student.uid], function (statusErr, statusResult) {
              connection.release();
              if (statusErr || !statusResult || statusResult.length === 0) {
                req.flash('message', 'Student not found');
                return res.redirect('/student/login');
              }

              const currentStatus = ((statusResult[0].status || '') + '').trim().toLowerCase();
              if (currentStatus === 'restrict') {
                req.flash('message', 'Login blocked. Your account is restricted. Please contact the hostel office.');
                return res.redirect('/student/login');
              }

              createStudentSession(req, res, student);
            });
          });
        } else {
          connection.release();
          req.flash('message', 'Incorrect password. Use your mobile number as default password.');
          return res.redirect('/student/login');
        }
      }
    });
  });
});

// Helper function to create student session
function createStudentSession(req, res, student) {
  const studentData = {
    uid: student.uid,
    name: student.sname,
    category: student.category
  };

  jwt.sign(studentData, studentSecretKey, { expiresIn: '7d' }, (err, token) => {
    if (err) {
      req.flash('message', 'Error creating session');
      return res.redirect('/student/login');
    }
    res.cookie('studentjwt', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    res.redirect('/student/dashboard');
  });
}

// Student Dashboard
app.get('/student/dashboard', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/login');
    }

    return loadFeatureFlagsMap(connection, function (_ffErr, flagsMap) {

      // Get student details
      var studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
      connection.query(studentSql, [uid], function (err, studentResult) {
        if (err || studentResult.length === 0) {
          connection.release();
          req.flash('message', 'Student not found');
          return res.redirect('/student/login');
        }

        const student = studentResult[0];

        // Get statistics
        var statsSql = "SELECT COUNT(*) as totalPasses FROM log_details1 WHERE uid = ? AND passtype IS NOT NULL";
        var monthStatsSql = "SELECT COUNT(*) as monthPasses FROM log_details1 WHERE uid = ? AND passtype IS NOT NULL AND MONTH(approvaldt) = MONTH(CURDATE()) AND YEAR(approvaldt) = YEAR(CURDATE())";
        var activePassSql = "SELECT * FROM log_details1 WHERE uid = ? AND status = 'ACTIVE' ORDER BY logid DESC LIMIT 1";
        var recentLogsSql = "SELECT * FROM log_details1 WHERE uid = ? ORDER BY logid DESC LIMIT 10";

        connection.query(statsSql, [uid], function (err, statsResult) {
          connection.query(monthStatsSql, [uid], function (err, monthResult) {
            connection.query(activePassSql, [uid], function (err, activeResult) {
              connection.query(recentLogsSql, [uid], function (err, recentResult) {
                connection.release();

                const stats = {
                  totalPasses: statsResult[0] ? statsResult[0].totalPasses : 0,
                  monthPasses: monthResult[0] ? monthResult[0].monthPasses : 0
                };

                const activePass = activeResult.length > 0 ? activeResult[0] : null;
                const recentLogs = recentResult || [];

                attachStudentPhotoUrl(student);
                res.render(__dirname + '/views/studentdashboard', {
                  student: student,
                  stats: stats,
                  activePass: activePass,
                  recentLogs: recentLogs,
                  flagsMap: flagsMap || {},
                  message: req.flash('message')
                });
              });
            });
          });
        });
      });
    });
  });
});

// Admin: Feature Flags (SuperID only)
app.get('/admin/features', verifyjwt, function (req, res) {
  if (!req.decode || !req.decode.role) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
  if (req.decode.role !== 'SuperID') {
    req.flash('message', 'Unauthorised Access');
    return res.redirect('/loginpanel');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err || !connection) {
      req.flash('message', 'Database error');
      return res.redirect('/daterange');
    }

    return loadFeatureFlagsMap(connection, function (_lErr, flagsMap) {
      connection.release();
      return res.render(__dirname + '/views/admin_features', {
        flagsMap: flagsMap || {},
        message: req.flash('message')
      });
    });
  });
});

app.post('/admin/features', verifyjwt, function (req, res) {
  if (!req.decode || !req.decode.role) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
  if (req.decode.role !== 'SuperID') {
    req.flash('message', 'Unauthorised Access');
    return res.redirect('/loginpanel');
  }

  const adminName = ((req.decode.adminname || req.decode.role || '') + '').trim() || 'admin';
  const roomBookingEnabled = !!req.body.room_booking;
  const profileEditEnabled = !!req.body.student_profile_edit;
  const post10pmRestrictionEnabled = !!req.body.post_10pm_restriction;
  // Mess cutoff times
  const messOpenTime = req.body.mess_open_hour || '09:00';
  const messCloseTime = req.body.mess_close_hour || '16:00';
  const openParsed = parseInt(messOpenTime.split(':')[0], 10);
  const messOpenHour = !isNaN(openParsed) ? openParsed : 9;
  const closeParsed = parseInt(messCloseTime.split(':')[0], 10);
  const messCloseHour = !isNaN(closeParsed) ? closeParsed : 16;

  dbbconnection.getConnection(function (err, connection) {
    if (err || !connection) {
      req.flash('message', 'Database error');
      return res.redirect('/admin/features');
    }

    ensureFeatureFlagsColumns(connection, function () {
      const upsertSql = `
        INSERT INTO feature_flags (feature_key, enabled, updated_by)
        VALUES (?, ?, ?)
        ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), updated_by = VALUES(updated_by)
      `;

      connection.beginTransaction(function (tErr) {
        if (tErr) {
          connection.release();
          req.flash('message', 'Database error');
          return res.redirect('/admin/features');
        }

        connection.query(upsertSql, ['room_booking', roomBookingEnabled ? 1 : 0, adminName], function (q1Err) {
          if (q1Err) {
            return connection.rollback(function () {
              connection.release();
              if (q1Err.code === 'ER_NO_SUCH_TABLE') {
                req.flash('message', 'Feature flags table missing. Please run db/feature_flags.sql');
              } else {
                console.error('feature_flags upsert room_booking failed:', q1Err);
                req.flash('message', 'Error updating features');
              }
              return res.redirect('/admin/features');
            });
          }

          connection.query(upsertSql, ['student_profile_edit', profileEditEnabled ? 1 : 0, adminName], function (q2Err) {
            if (q2Err) {
              return connection.rollback(function () {
                connection.release();
                if (q2Err.code === 'ER_NO_SUCH_TABLE') {
                  req.flash('message', 'Feature flags table missing. Please run db/feature_flags.sql');
                } else {
                  console.error('feature_flags upsert student_profile_edit failed:', q2Err);
                  req.flash('message', 'Error updating features');
                }
                return res.redirect('/admin/features');
              });
            }

            connection.query(upsertSql, ['post_10pm_restriction', post10pmRestrictionEnabled ? 1 : 0, adminName], function (q3Err) {
              if (q3Err) {
                return connection.rollback(function () {
                  connection.release();
                  if (q3Err.code === 'ER_NO_SUCH_TABLE') {
                    req.flash('message', 'Feature flags table missing. Please run db/feature_flags.sql');
                  } else {
                    console.error('feature_flags upsert post_10pm_restriction failed:', q3Err);
                    req.flash('message', 'Error updating features');
                  }
                  return res.redirect('/admin/features');
                });
              }

              // Save mess cutoff hours – stored in value_int and value_str columns
              const upsertIntSql = `
                INSERT INTO feature_flags (feature_key, enabled, value_int, value_str, updated_by, updated_at)
                VALUES (?, 1, ?, ?, ?, NOW())
                ON DUPLICATE KEY UPDATE value_int = VALUES(value_int), value_str = VALUES(value_str), updated_by = VALUES(updated_by), updated_at = NOW()
              `;
              connection.query(upsertIntSql, ['mess_open_hour', messOpenHour, messOpenTime, adminName], function (q4Err) {
                if (q4Err) {
                  console.error('feature_flags upsert mess_open_hour failed:', q4Err);
                }
                connection.query(upsertIntSql, ['mess_close_hour', messCloseHour, messCloseTime, adminName], function (q5Err) {
                  if (q5Err) {
                    console.error('feature_flags upsert mess_close_hour failed:', q5Err);
                  }

                  connection.commit(function (cErr) {
                    if (cErr) {
                      return connection.rollback(function () {
                        connection.release();
                        req.flash('message', 'Database error');
                        return res.redirect('/admin/features');
                      });
                    }
                    connection.release();
                    req.flash('message', 'Features updated');
                    return res.redirect('/admin/features');
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

// =====================================================
// Admin Announcements
// =====================================================
app.get('/admin/announcements', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/daterange');
      }

      const sql = "SELECT * FROM announcements WHERE is_active = 1 ORDER BY created_at DESC LIMIT 50";
      connection.query(sql, function (err, results) {
        connection.release();
        res.render(__dirname + '/views/admin_announcements', {
          announcements: results || [],
          message: req.flash('message')
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

app.post('/admin/announcements', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    const adminName = decode.name || 'Admin';

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    const { title, description, target_year } = req.body;

    if (!title || !description) {
      req.flash('message', 'Title and description are required');
      return res.redirect('/admin/announcements');
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/announcements');
      }

      const sql = "INSERT INTO announcements (title, description, target_year, created_by) VALUES (?, ?, ?, ?)";
      connection.query(sql, [title, description, target_year || 'all', adminName], function (err, result) {
        connection.release();
        if (err) {
          console.error('Error creating announcement:', err);
          req.flash('message', 'Error creating announcement');
        } else {
          req.flash('message', 'Announcement sent successfully!');
        }
        return res.redirect('/admin/announcements');
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

app.post('/admin/announcements/delete/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    const announcementId = req.params.id;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/announcements');
      }

      const sql = "UPDATE announcements SET is_active = 0 WHERE id = ?";
      connection.query(sql, [announcementId], function (err, result) {
        connection.release();
        if (err) {
          req.flash('message', 'Error deleting announcement');
        } else {
          req.flash('message', 'Announcement deleted');
        }
        return res.redirect('/admin/announcements');
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

// API to get all available rooms
app.get('/api/rooms', verifyStudentJwt, function (req, res) {
  const bookingDate = req.query.bookingDate;
  const selectedBlock = req.query.block;
  const selectedFloor = req.query.floor;

  if (!bookingDate) {
    return res.status(400).json({ message: 'Booking date is required.' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    let sql = `
      SELECT 
          r.id, 
          r.name, 
          r.capacity, 
          r.price_per_night, 
          r.description, 
          r.is_available, 
          r.block, 
          r.floor, 
          r.room_type,
          CASE
              WHEN MAX(b.id) IS NOT NULL THEN 'on_hold'
              ELSE 'available'
          END AS current_status
      FROM 
          rooms r
      LEFT JOIN 
          bookings b ON r.id = b.room_id
          AND b.booking_date = ?
          AND b.status IN ('on_hold', 'confirmed')
      WHERE 
          r.is_available = TRUE
    `;
    const queryParams = [bookingDate];

    if (selectedBlock) {
      sql += ` AND r.block = ?`;
      queryParams.push(selectedBlock);
    }
    if (selectedFloor) {
      sql += ` AND r.floor = ?`;
      queryParams.push(selectedFloor);
    }

    sql += `
      GROUP BY r.id 
      ORDER BY r.block, r.floor, r.name
    `;

    connection.query(sql, queryParams, function (err, results) {
      connection.release();
      if (err) {
        console.error('Error fetching rooms:', err);
        return res.status(500).json({ message: 'Error fetching rooms' });
      }
      res.json(results);
    });
  });
});

// API to create a new booking
app.post('/api/bookings', verifyStudentJwt, function (req, res) {
  const studentId = req.studentUid; // From JWT token
  const { roomId, bookingDate, selectedRoomPrice } = req.body; // Updated params

  if (!roomId || !bookingDate || !selectedRoomPrice) {
    return res.status(400).json({ message: 'Missing required booking information' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    // Check for overlapping bookings for the selected room and date
    const checkAvailabilitySql = `
      SELECT COUNT(*) AS count FROM bookings
      WHERE room_id = ?
      AND booking_date = ?
      AND status IN ('on_hold', 'confirmed')
    `;

    connection.query(checkAvailabilitySql, [roomId, bookingDate], function (err, availabilityResults) {
      if (err) {
        connection.release();
        console.error('Error checking room availability:', err);
        return res.status(500).json({ message: 'Error checking room availability' });
      }

      if (availabilityResults[0].count > 0) {
        connection.release();
        return res.status(409).json({ message: 'Room is not available for the selected date' });
      }

      // Insert new booking
      const insertBookingSql = "INSERT INTO bookings (room_id, student_id, booking_date, total_price, status, payment_status) VALUES (?, ?, ?, ?, ?, ?)";
      connection.query(insertBookingSql, [roomId, studentId, bookingDate, selectedRoomPrice, 'on_hold', 'pending'], function (err, bookingResults) {
        connection.release();
        if (err) {
          console.error('Error creating booking:', err);
          return res.status(500).json({ message: 'Error creating booking' });
        }
        res.status(201).json({ message: 'Booking created successfully and is on hold for payment.', bookingId: bookingResults.insertId });
      });
    });
  });
});

// API to get a student's booking history
app.get('/api/student/bookings', verifyStudentJwt, function (req, res) {
  const studentId = req.studentUid; // From JWT token

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    const sql = `
      SELECT 
          b.*, 
          r.name as room_name, 
          r.capacity, 
          r.price_per_night,
          r.block,
          r.floor,
          r.room_type
      FROM 
          bookings b
      JOIN 
          rooms r ON b.room_id = r.id
      WHERE 
          b.student_id = ?
      ORDER BY 
          b.booking_date DESC, b.created_at DESC
    `;

    connection.query(sql, [studentId], function (err, results) {
      connection.release();
      if (err) {
        console.error('Error fetching student bookings:', err);
        return res.status(500).json({ message: 'Error fetching student bookings' });
      }
      res.json(results);
    });
  });
});

// Student Profile
app.get('/student/profile', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/dashboard');
    }

    return loadFeatureFlagsMap(connection, function (_ffErr, flagsMap) {

      var sql = `
        SELECT s.*, t.recv_arrear_fee, t.recv_current_year, t.recv_extra_stay,
               t.recd_arrear_fee, t.recd_current_year, t.recd_extra,
               t.balance, t.as_on_date
        FROM studentdetails s
        LEFT JOIN tally_fee_data t ON (s.uid = t.suid OR s.hostel_id = t.suid)
        WHERE s.uid = ?
        LIMIT 1
      `;
      connection.query(sql, [uid], function (err, result) {
        connection.release();
        if (err || result.length === 0) {
          req.flash('message', 'Student not found');
          return res.redirect('/student/dashboard');
        }

        const student = result[0];
        attachStudentPhotoUrl(student);
        
        const tallyFee = (student && student.balance !== undefined && student.balance !== null) ? {
          recv_arrear_fee: student.recv_arrear_fee,
          recv_current_year: student.recv_current_year,
          recv_extra_stay: student.recv_extra_stay,
          recd_arrear_fee: student.recd_arrear_fee,
          recd_current_year: student.recd_current_year,
          recd_extra: student.recd_extra,
          balance: student.balance,
          as_on_date: student.as_on_date
        } : null;

        res.render(__dirname + '/views/student_profile', {
          student: student,
          result: result,
          tallyFee: tallyFee,
          flagsMap: flagsMap || {},
          message: req.flash('message')
        });
      });
    });
  });
});

// Student Change Password
app.post('/student/changepassword', verifyStudentJwt, async function (req, res) {
  const uid = req.studentUid;
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (newPassword !== confirmPassword) {
    req.flash('message', 'New passwords do not match');
    return res.redirect('/student/profile');
  }

  if (newPassword.length < 6) {
    req.flash('message', 'Password must be at least 6 characters');
    return res.redirect('/student/profile');
  }

  dbbconnection.getConnection(async function (err, connection) {
    if (err) {
      const msg = 'Database error';
      if (req.xhr || (req.headers.accept || '').includes('application/json')) {
        return res.status(500).json({ success: false, message: msg });
      }
      req.flash('message', msg);
      return res.redirect('/student/profile');
    }

    // Get current student data
    var sql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(sql, [uid], async function (err, result) {
      if (err || result.length === 0) {
        connection.release();
        req.flash('message', 'Student not found');
        return res.redirect('/student/profile');
      }

      const student = result[0];
      const storedPassword = student.password || student.mobileno;

      // Verify current password
      let passwordMatch = false;
      if (student.password && student.password.startsWith('$2')) {
        passwordMatch = await bcrypt.compare(currentPassword, student.password);
      } else {
        passwordMatch = currentPassword === storedPassword;
      }

      if (!passwordMatch) {
        connection.release();
        req.flash('message', 'Current password is incorrect');
        return res.redirect('/student/profile');
      }

      // Hash new password
      const hashedPassword = await bcrypt.hash(newPassword, 12);

      // Update password
      var updateSql = "UPDATE studentdetails SET password = ? WHERE uid = ?";
      connection.query(updateSql, [hashedPassword, uid], function (err, updateResult) {
        connection.release();
        if (err) {
          req.flash('message', 'Error updating password');
          return res.redirect('/student/profile');
        }

        req.flash('message', 'Password updated successfully');
        res.redirect('/student/profile');
      });
    });
  });
});

// Student Update Profile
app.post('/student/updateprofile', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;

  const sname = (req.body.sname || '').trim();
  const email = (req.body.email || '').trim();
  const gender = (req.body.gender || '').trim();
  const dob = (req.body.dob || '').trim();
  const year = (req.body.year || '').trim();
  const academicyear = (req.body.academicyear || '').trim();
  const address = (req.body.address || '').trim();
  const parentname = (req.body.parentname || '').trim();
  const parentnumber = (req.body.parentnumber || '').trim();

  if (!sname || !email) {
    req.flash('message', 'Please fill required fields.');
    return res.redirect('/student/profile');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err || !connection) {
      req.flash('message', 'Database error');
      return res.redirect('/student/profile');
    }

    return getFeatureFlag(connection, 'student_profile_edit', function (_fErr, enabled) {
      if (!enabled) {
        connection.release();
        req.flash('message', 'Profile editing is currently disabled by admin');
        return res.redirect('/student/profile');
      }

      const sql = `UPDATE studentdetails
        SET sname = ?, email = ?, gender = ?, dob = ?, year = ?, academicyear = ?, address = ?, parentname = ?, parentnumber = ?
        WHERE uid = ?`;

      connection.query(sql, [sname, email, gender, dob, year, academicyear, address, parentname, parentnumber, uid], function (qErr) {
        connection.release();
        if (qErr) {
          console.error('Student updateprofile failed:', qErr);
          req.flash('message', 'Could not update profile.');
          return res.redirect('/student/profile');
        }
        req.flash('message', 'Profile updated successfully');
        return res.redirect('/student/profile');
      });
    });
  });
});

// =====================================================
// ROOM BOOKING SYSTEM
// =====================================================

// Student Room Booking Page
app.get('/student/roombooking', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/dashboard');
    }

    return getFeatureFlag(connection, 'room_booking', function (_fErr, enabled) {
      const roomBookingEnabled = enabled;

      const studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
      connection.query(studentSql, [uid], function (sErr, sRows) {
        if (sErr || !sRows || sRows.length === 0) {
          connection.release();
          req.flash('message', 'Student not found');
          return res.redirect('/student/dashboard');
        }

        const student = sRows[0];
        const category = ((student.category || '') + '').trim().toLowerCase();
        if (category !== 'hostel') {
          connection.release();
          req.flash('message', 'Room booking is only available for Hostel students');
          return res.redirect('/student/dashboard');
        }
        if (((student.status || '') + '').trim() === 'Restrict') {
          connection.release();
          req.flash('message', 'Account restricted. You cannot book rooms.');
          return res.redirect('/student/dashboard');
        }

        const myBookingSql = `
          SELECT rb.*, r.room_type, r.capacity, r.price_per_night
          FROM room_bookings rb
          LEFT JOIN rooms r ON r.name = rb.room_no
          WHERE rb.uid = ? AND rb.booking_status = 'locked'
          ORDER BY rb.created_at DESC
          LIMIT 1
        `;
        connection.query(myBookingSql, [uid], function (bErr, bRows) {
          if (bErr) {
            connection.release();
            console.error('myBookingSql failed:', bErr);
            req.flash('message', 'Error loading room booking');
            return res.redirect('/student/dashboard');
          }

          const roomsSql = `
            SELECT r.name as room_no, r.block, r.floor, r.room_type, r.capacity, r.price_per_night, r.is_permanent, r.description,
                   rb.id as booking_id, rb.uid as booked_uid, rb.bed_no as booked_bed, rb.payment_status as payment_status, rb.created_at as booked_at,
                   sd.sname as booked_name
            FROM rooms r
            LEFT JOIN room_bookings rb
              ON rb.room_no = r.name
             AND rb.block = r.block
             AND rb.floor = r.floor
             AND rb.booking_status = 'locked'
            LEFT JOIN studentdetails sd
              ON sd.uid = rb.uid
            WHERE (r.is_available IS NULL OR r.is_available = TRUE)
            ORDER BY r.block, r.floor, r.name
          `;
          connection.query(roomsSql, function (rErr, roomRows) {
            connection.release();
            if (rErr) {
              console.error('roomsSql failed:', rErr);
              req.flash('message', 'Error loading rooms');
              return res.redirect('/student/dashboard');
            }

            res.render(__dirname + '/views/student_roombooking', {
              student: student,
              rooms: roomRows || [],
              myBooking: (bRows && bRows.length) ? bRows[0] : null,
              message: req.flash('message'),
              roomBookingEnabled: roomBookingEnabled
            });
          });
        });
      });
    });
  });
});

// Student Room Booking Submit
app.post('/student/roombooking', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const room_no = ((req.body.room_no || '') + '').trim();
  const block = ((req.body.block || '') + '').trim();
  const floor = ((req.body.floor || '') + '').trim();
  const bed_no = ((req.body.bed_no || '') + '').trim();
  const agreementAccepted = String(req.body.agreement_accepted || '').toLowerCase() === 'true'
    || String(req.body.agreement_accepted || '').toLowerCase() === 'on'
    || String(req.body.agreement_accepted || '').toLowerCase() === '1';
  const advanceAmountRaw = ((req.body.advance_amount || '') + '').trim();
  const advanceAmount = advanceAmountRaw ? parseFloat(advanceAmountRaw) : null;
  const transactionId = ((req.body.transaction_id || '') + '').trim();

  if (!uid || !room_no || !block || !floor || !bed_no) {
    req.flash('message', 'Invalid room booking request');
    return res.redirect('/student/roombooking');
  }
  if (!agreementAccepted) {
    req.flash('message', 'Agreement must be accepted to lock a room');
    return res.redirect('/student/roombooking');
  }
  if (!advanceAmountRaw || isNaN(advanceAmount)) {
    req.flash('message', 'Please enter a valid advance amount');
    return res.redirect('/student/roombooking');
  }
  if (!transactionId) {
    req.flash('message', 'Transaction ID is required');
    return res.redirect('/student/roombooking');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/roombooking');
    }

    return getFeatureFlag(connection, 'room_booking', function (_fErr, enabled) {
      if (!enabled) {
        connection.release();
        req.flash('message', 'Room booking is currently disabled by admin');
        return res.redirect('/student/dashboard');
      }

      const studentSql = "SELECT uid, category, status FROM studentdetails WHERE uid = ?";
      connection.query(studentSql, [uid], function (sErr, sRows) {
        if (sErr || !sRows || sRows.length === 0) {
          connection.release();
          req.flash('message', 'Student not found');
          return res.redirect('/student/roombooking');
        }
        const student = sRows[0];
        const category = ((student.category || '') + '').trim().toLowerCase();
        if (category !== 'hostel') {
          connection.release();
          req.flash('message', 'Room booking is only available for Hostel students');
          return res.redirect('/student/roombooking');
        }
        if (((student.status || '') + '').trim() === 'Restrict') {
          connection.release();
          req.flash('message', 'Account restricted. You cannot book rooms.');
          return res.redirect('/student/roombooking');
        }

        const roomValidateSql = "SELECT name, block, floor FROM rooms WHERE name = ? AND block = ? AND floor = ? AND (is_available IS NULL OR is_available = TRUE) AND NOT (is_permanent = 1 AND name IN ('AF-02', 'AF-31', 'AS-31', 'BG-26')) LIMIT 1";
        connection.query(roomValidateSql, [room_no, block, floor], function (vErr, vRows) {
          if (vErr || !vRows || vRows.length === 0) {
            connection.release();
            req.flash('message', 'Selected room is not available');
            return res.redirect('/student/roombooking');
          }

          connection.beginTransaction(function (tErr) {
            if (tErr) {
              connection.release();
              req.flash('message', 'Database error');
              return res.redirect('/student/roombooking');
            }

            const myActiveSql = "SELECT id FROM room_bookings WHERE uid = ? AND booking_status = 'locked' LIMIT 1";
            connection.query(myActiveSql, [uid], function (aErr, aRows) {
              if (aErr) {
                return connection.rollback(function () {
                  connection.release();
                  req.flash('message', 'Database error');
                  return res.redirect('/student/roombooking');
                });
              }
              if (aRows && aRows.length > 0) {
                return connection.rollback(function () {
                  connection.release();
                  req.flash('message', 'You already have an active room booking');
                  return res.redirect('/student/roombooking');
                });
              }

              const occupiedSql = `
                SELECT id
                FROM room_bookings
                WHERE room_no = ?
                  AND block = ?
                  AND floor = ?
                  AND bed_no = ?
                  AND booking_status = 'locked'
                LIMIT 1
              `;
              connection.query(occupiedSql, [room_no, block, floor, bed_no], function (oErr, oRows) {
                if (oErr) {
                  return connection.rollback(function () {
                    connection.release();
                    req.flash('message', 'Database error');
                    return res.redirect('/student/roombooking');
                  });
                }
                if (oRows && oRows.length > 0) {
                  return connection.rollback(function () {
                    connection.release();
                    req.flash('message', 'Room already booked');
                    return res.redirect('/student/roombooking');
                  });
                }

                const insertSql = `
                  INSERT INTO room_bookings (
                    room_no, block, floor, bed_no, uid,
                    booking_status, payment_status,
                    advance_amount, transaction_id,
                    agreement_accepted,
                    locked_source, locked_by
                  )
                  VALUES (?, ?, ?, ?, ?, 'locked', 'pending', ?, ?, ?, 'student', NULL)
                `;
                connection.query(insertSql, [room_no, block, floor, bed_no, uid, advanceAmount, transactionId, agreementAccepted ? 1 : 0], function (iErr) {
                  if (iErr) {
                    return connection.rollback(function () {
                      connection.release();
                      if (iErr.code === 'ER_DUP_ENTRY') {
                        req.flash('message', 'Room already booked');
                      } else if (iErr.code === 'ER_NO_SUCH_TABLE') {
                        req.flash('message', 'Room booking feature is not set up in DB. Please run db/room_bookings.sql');
                      } else if (iErr.code === 'ER_BAD_FIELD_ERROR') {
                        req.flash('message', 'Room booking DB schema is outdated. Please run the ALTER TABLE migration to add advance_amount/transaction_id columns.');
                      } else {
                        console.error('Room booking insert failed:', iErr);
                        req.flash('message', 'Error booking room');
                      }
                      return res.redirect('/student/roombooking');
                    });
                  }

                  connection.query(
                    "UPDATE studentdetails SET room_no = NULL, bed_no = NULL, block = NULL, other2 = NULL WHERE uid = ?",
                    [uid],
                    function (clearErr) {
                      if (clearErr) {
                        return connection.rollback(function () {
                          connection.release();
                          req.flash('message', 'Database error');
                          return res.redirect('/student/roombooking');
                        });
                      }

                      connection.commit(function (cErr) {
                        if (cErr) {
                          return connection.rollback(function () {
                            connection.release();
                            req.flash('message', 'Database error');
                            return res.redirect('/student/roombooking');
                          });
                        }
                        connection.release();
                        req.flash('message', 'Room booked successfully (payment pending)');
                        return res.redirect('/student/roombooking');
                      });
                    }
                  );
                });
              });
            });
          });
        });
      });
    });
  });
});

// Admin: View Room Bookings
app.get('/admin/room-status', verifyjwt, function (req, res) {
  if (!req.decode || !req.decode.role) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
  const role = req.decode.role;
  if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
    req.flash('message', 'Unauthorised Access');
    return res.redirect('/loginpanel');
  }

  let adminGender = null;
  if (role === 'BoysHostelAdmin' || role === 'Hostelauthority') {
    adminGender = 'MALE';
  } else if (role === 'GirlsHostelAdmin') {
    adminGender = 'FEMALE';
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/loginpanel');
    }

    const roomsSql = `
      SELECT r.name as room_no, r.block, r.floor, r.room_type, r.capacity, r.is_permanent,
             rb.id as booking_id, sd.gender as occupant_gender
      FROM rooms r
      LEFT JOIN room_bookings rb
        ON rb.room_no = r.name
       AND rb.block = r.block
       AND rb.floor = r.floor
       AND rb.booking_status = 'locked'
      LEFT JOIN studentdetails sd
        ON sd.uid = rb.uid
      WHERE (r.is_available IS NULL OR r.is_available = TRUE)
      ORDER BY r.block, r.floor, r.name
    `;

    connection.query(roomsSql, function (rErr, rows) {
      connection.release();

      if (rErr) {
        console.error('room-status roomsSql failed:', rErr);
        req.flash('message', 'Error loading room status');
        return res.redirect('/admin/roombookings');
      }

      const roomsMap = {};
      const capacityGroups = {
        1: { label: 'Single', total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] },
        2: { label: 'Double', total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] },
        3: { label: 'Triple', total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] },
        4: { label: 'Quad', total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] }
      };

      const rowsData = rows || [];
      let excludedPermanentRooms = 0;
      for (let i = 0; i < rowsData.length; i++) {
        const row = rowsData[i];
        const key = row.block + '|' + row.floor + '|' + row.room_no;

        if (!roomsMap[key]) {
          roomsMap[key] = {
            room_no: row.room_no,
            block: row.block,
            floor: row.floor,
            room_type: row.room_type || 'Unknown',
            capacity: parseInt(row.capacity, 10) || 0,
            is_permanent: !!row.is_permanent,
            occupied: 0,
            hasMale: false,
            hasFemale: false
          };
        }

        if (row.booking_id) {
          roomsMap[key].occupied++;
          if (row.occupant_gender === 'MALE') roomsMap[key].hasMale = true;
          if (row.occupant_gender === 'FEMALE') roomsMap[key].hasFemale = true;
        }
      }

      for (const key in roomsMap) {
        const r = roomsMap[key];

        // Permanent rooms are administrative spaces and should not be counted as vacant.
        if (r.is_permanent || isPermanentRoomRow(r)) {
          excludedPermanentRooms++;
          continue;
        }

        // Exclude rooms occupied by the opposite gender.
        if (adminGender === 'MALE' && r.hasFemale) continue;
        if (adminGender === 'FEMALE' && r.hasMale) continue;

        const cap = r.capacity;
        if (!capacityGroups[cap]) {
          capacityGroups[cap] = { label: r.room_type, total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] };
        }

        const group = capacityGroups[cap];
        group.total_rooms++;
        group.total_beds += cap;
        group.occupied_beds += r.occupied;

        const vacant_beds = cap - r.occupied;
        group.vacant_beds += vacant_beds;

        if (vacant_beds <= 0) {
          group.fully_occupied_rooms++;
        } else {
          group.vacant_rooms.push({
            name: `${r.block}-${r.floor} Room ${r.room_no}`,
            vacant_beds: vacant_beds,
            capacity: cap
          });
        }
      }

      return res.render(__dirname + '/views/admin_room_status', {
        capacityGroups: capacityGroups,
        adminGender: adminGender,
        excludedPermanentRooms: excludedPermanentRooms
      });
    });
  });
});


// API: Admin Room Status for Mobile App
app.get('/api/mobile/v1/admin/room-status', verifyMobileJwt, function (req, res) {
  if (!req.decode || !req.decode.role) {
    return res.status(401).json({ success: false, message: 'Unauthorised Access' });
  }
  const role = req.decode.role;
  if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
    return res.status(403).json({ success: false, message: 'Unauthorised Access' });
  }

  let adminGender = null;
  if (role === 'BoysHostelAdmin' || role === 'Hostelauthority') {
    adminGender = 'MALE';
  } else if (role === 'GirlsHostelAdmin') {
    adminGender = 'FEMALE';
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    const roomsSql = `
      SELECT r.name as room_no, r.block, r.floor, r.room_type, r.capacity, r.is_permanent,
             rb.id as booking_id, sd.gender as occupant_gender
      FROM rooms r
      LEFT JOIN room_bookings rb
        ON rb.room_no = r.name
       AND rb.block = r.block
       AND rb.floor = r.floor
       AND rb.booking_status = 'locked'
      LEFT JOIN studentdetails sd
        ON sd.uid = rb.uid
      WHERE (r.is_available IS NULL OR r.is_available = TRUE)
      ORDER BY r.block, r.floor, r.name
    `;

    connection.query(roomsSql, function (rErr, rows) {
      connection.release();

      if (rErr) {
        console.error('api room-status roomsSql failed:', rErr);
        return res.status(500).json({ success: false, message: 'Error loading room status' });
      }

      const roomsMap = {};
      const capacityGroups = {
        1: { label: 'Single', total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] },
        2: { label: 'Double', total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] },
        3: { label: 'Triple', total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] },
        4: { label: 'Quad', total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] }
      };

      const rowsData = rows || [];
      let excludedPermanentRooms = 0;
      for (let i = 0; i < rowsData.length; i++) {
        const row = rowsData[i];
        const key = row.block + '|' + row.floor + '|' + row.room_no;

        if (!roomsMap[key]) {
          roomsMap[key] = {
            room_no: row.room_no,
            block: row.block,
            floor: row.floor,
            room_type: row.room_type || 'Unknown',
            capacity: parseInt(row.capacity, 10) || 0,
            is_permanent: !!row.is_permanent,
            occupied: 0,
            hasMale: false,
            hasFemale: false
          };
        }

        if (row.booking_id) {
          roomsMap[key].occupied++;
          if (row.occupant_gender === 'MALE') roomsMap[key].hasMale = true;
          if (row.occupant_gender === 'FEMALE') roomsMap[key].hasFemale = true;
        }
      }

      for (const key in roomsMap) {
        const r = roomsMap[key];

        if (r.is_permanent || isPermanentRoomRow(r)) {
          excludedPermanentRooms++;
          continue;
        }

        if (adminGender === 'MALE' && r.hasFemale) continue;
        if (adminGender === 'FEMALE' && r.hasMale) continue;

        const cap = r.capacity;
        if (!capacityGroups[cap]) {
          capacityGroups[cap] = { label: r.room_type, total_rooms: 0, total_beds: 0, occupied_beds: 0, vacant_beds: 0, fully_occupied_rooms: 0, vacant_rooms: [] };
        }

        const group = capacityGroups[cap];
        group.total_rooms++;
        group.total_beds += cap;
        group.occupied_beds += r.occupied;

        const vacant_beds = cap - r.occupied;
        group.vacant_beds += vacant_beds;

        if (vacant_beds <= 0) {
          group.fully_occupied_rooms++;
        } else {
          group.vacant_rooms.push({
            name: `${r.block}-${r.floor} Room ${r.room_no}`,
            vacant_beds: vacant_beds,
            capacity: cap
          });
        }
      }

      return res.json({
        success: true,
        data: {
          capacityGroups: capacityGroups,
          adminGender: adminGender,
          excludedPermanentRooms: excludedPermanentRooms
        }
      });
    });
  });
});

app.get('/admin/roombookings', verifyjwt, function (req, res) {
  if (!req.decode || !req.decode.role) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
  const role = req.decode.role;
  if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
    req.flash('message', 'Unauthorised Access');
    return res.redirect('/loginpanel');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/loginpanel');
    }

    let genderWhere = '';
    const params = [];
    if (role === 'BoysHostelAdmin' || role === 'Hostelauthority') {
      genderWhere = " AND s.gender = ?";
      params.push('MALE');
    } else if (role === 'GirlsHostelAdmin') {
      genderWhere = " AND s.gender = ?";
      params.push('FEMALE');
    }

    let yearFilterWhere = '';
    const yearFilter = req.query.year_filter;
    if (yearFilter === '1') {
      yearFilterWhere = " AND rb.uid LIKE 'BH%'";
    } else if (yearFilter === '2') {
      yearFilterWhere = " AND (s.year = '2' OR s.academicyear = '2') AND rb.uid NOT LIKE 'BH%'";
    } else if (yearFilter === '3') {
      yearFilterWhere = " AND (s.year = '3' OR s.academicyear = '3')";
    } else if (yearFilter === '4') {
      yearFilterWhere = " AND (s.year = '4' OR s.academicyear = '4')";
    }

    const normalizeCancelledSql = `
      UPDATE room_bookings
      SET payment_status = 'cancelled'
      WHERE booking_status = 'cancelled'
        AND LOWER(COALESCE(payment_status, '')) <> 'cancelled'
    `;

    const sql = `
      SELECT rb.id, rb.room_no, rb.block, rb.floor, rb.bed_no, rb.uid, rb.payment_status, rb.booking_status,
             rb.advance_amount, rb.transaction_id, rb.paid_at,
             rb.agreement_accepted, rb.locked_source, rb.locked_by, rb.created_at,
             s.sname
      FROM room_bookings rb
      LEFT JOIN studentdetails s ON s.uid = rb.uid
      WHERE rb.booking_status IN ('locked', 'cancelled')
      ${genderWhere}
      ${yearFilterWhere}
      ORDER BY rb.created_at DESC
    `;

    connection.query(normalizeCancelledSql, function () {
      connection.query(sql, params, function (qErr, rows) {
        if (qErr && qErr.code !== 'ER_BAD_FIELD_ERROR') {
          connection.release();
          req.flash('message', 'Error loading bookings');
          return res.redirect('/loginpanel');
        }

        const bookings = rows || [];

        const roomsSql = `
        SELECT r.name as room_no, r.block, r.floor, r.room_type, r.capacity, r.price_per_night, r.is_permanent, r.description,
               rb.id as booking_id, rb.uid as booked_uid, rb.bed_no as booked_bed, rb.created_at as booked_at,
               rb.payment_status as payment_status, rb.booking_status as booking_status,
               sd.sname as booked_name
        FROM rooms r
        LEFT JOIN room_bookings rb
          ON rb.room_no = r.name
         AND rb.block = r.block
         AND rb.floor = r.floor
         AND rb.booking_status = 'locked'
        LEFT JOIN studentdetails sd
          ON sd.uid = rb.uid
        WHERE (r.is_available IS NULL OR r.is_available = TRUE)
        ORDER BY r.block, r.floor, r.name
      `;

        connection.query(roomsSql, function (rErr, roomRows) {
          if (rErr) {
            connection.release();
            req.flash('message', 'Error loading rooms');
            return res.redirect('/loginpanel');
          }

          const pendingAppsSql = `
          SELECT id, full_name, student_mobile, branch, admission_year,
                 mess_preference, submission_date, created_at
          FROM hostel_admission_applications
          WHERE status = 'Pending'
          ORDER BY created_at ASC
        `;

          connection.query(pendingAppsSql, function (pErr, pendingApps) {
            const shouldLoadStudents = role === 'SuperID';
            if (!shouldLoadStudents) {
              connection.release();
              return res.render(__dirname + '/views/admin_roombookings', {
                role: role,
                bookings: bookings,
                rooms: roomRows || [],
                students: [],
                pendingApplications: pendingApps || [],
                message: req.flash('message'),
                yearFilter: yearFilter || ''
              });
            }

            const studentsSql = "SELECT uid, sname FROM studentdetails WHERE LOWER(TRIM(category)) = 'hostel' AND (status IS NULL OR TRIM(status) <> 'Restrict') ORDER BY sname";
            connection.query(studentsSql, function (stErr, stRows) {
              connection.release();
              return res.render(__dirname + '/views/admin_roombookings', {
                role: role,
                bookings: bookings,
                rooms: roomRows || [],
                students: stRows || [],
                pendingApplications: pendingApps || [],
                message: req.flash('message'),
                yearFilter: yearFilter || ''
              });
            });
          });
        });
      });
    });
  });
});


  // Admin: View Pending Admissions
  app.get('/admin/pending-admissions', verifyjwt, function (req, res) {
    if (!req.decode || !req.decode.role) {
      res.clearCookie("jwt");
      return res.redirect('/loginpanel');
    }
    const role = req.decode.role;
    if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/loginpanel');
      }

      const pendingAppsSql = `
      SELECT id, full_name, student_mobile, branch, admission_year,
             mess_preference, submission_date, created_at
      FROM hostel_admission_applications
      WHERE status = 'Pending'
      ORDER BY created_at ASC
    `;

      connection.query(pendingAppsSql, function (pErr, pendingApps) {
        connection.release();
        if (pErr) {
          req.flash('message', 'Error loading pending applications');
          return res.redirect('/loginpanel');
        }
        return res.render(__dirname + '/views/admin_pending_admissions', {
          role: role,
          pendingApplications: pendingApps || [],
          message: req.flash('message')
        });
      });
    });
  });

  // Admin: Lock Room for Student (SuperID only)
  app.post('/admin/roombooking/lock', verifyjwt, function (req, res) {
    if (!req.decode || !req.decode.role) {
      res.clearCookie("jwt");
      return res.redirect('/loginpanel');
    }
    const role = req.decode.role;
    if (role !== 'SuperID') {
      req.flash('message', 'Only SuperID can lock rooms for students');
      return res.redirect('/admin/roombookings');
    }

    const uid = ((req.body.uid || '') + '').trim();
    const room_no = ((req.body.room_no || '') + '').trim();
    const block = ((req.body.block || '') + '').trim();
    const floor = ((req.body.floor || '') + '').trim();
    const bed_no = ((req.body.bed_no || '') + '').trim();
    const agreementAccepted = String(req.body.agreement_accepted || '').toLowerCase() === 'true'
      || String(req.body.agreement_accepted || '').toLowerCase() === 'on'
      || String(req.body.agreement_accepted || '').toLowerCase() === '1';
    const advanceAmountRaw = ((req.body.advance_amount || '') + '').trim();
    const advanceAmount = advanceAmountRaw ? parseFloat(advanceAmountRaw) : null;
    const transactionId = ((req.body.transaction_id || '') + '').trim();

    if (!uid || !room_no || !block || !floor || !bed_no) {
      req.flash('message', 'Invalid lock request');
      return res.redirect('/admin/roombookings');
    }
    if (!agreementAccepted) {
      req.flash('message', 'Agreement must be accepted to lock a room');
      return res.redirect('/admin/roombookings');
    }

    if (advanceAmountRaw) {
      if (isNaN(advanceAmount)) {
        req.flash('message', 'Advance amount must be a valid number');
        return res.redirect('/admin/roombookings');
      }
      if (!transactionId) {
        req.flash('message', 'Transaction ID is required when advance amount is provided');
        return res.redirect('/admin/roombookings');
      }
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/roombookings');
      }

      const studentSql = "SELECT uid, category, status FROM studentdetails WHERE uid = ?";
      connection.query(studentSql, [uid], function (sErr, sRows) {
        if (sErr || !sRows || sRows.length === 0) {
          connection.release();
          req.flash('message', 'Student not found');
          return res.redirect('/admin/roombookings');
        }

        const student = sRows[0];
        const category = ((student.category || '') + '').trim().toLowerCase();
        if (category !== 'hostel') {
          connection.release();
          req.flash('message', 'Room booking is only available for Hostel students');
          return res.redirect('/admin/roombookings');
        }
        if (((student.status || '') + '').trim() === 'Restrict') {
          connection.release();
          req.flash('message', 'Account restricted. Cannot lock rooms for this student.');
          return res.redirect('/admin/roombookings');
        }

        const roomValidateSql = "SELECT name, block, floor FROM rooms WHERE name = ? AND block = ? AND floor = ? AND (is_available IS NULL OR is_available = TRUE) AND NOT (is_permanent = 1 AND name IN ('AF-02', 'AF-31', 'AS-31', 'BG-26')) LIMIT 1";
      connection.query(roomValidateSql, [room_no, block, floor], function (vErr, vRows) {
        if (vErr || !vRows || vRows.length === 0) {
          connection.release();
          req.flash('message', 'Selected room is not available');
          return res.redirect('/admin/roombookings');
        }

          connection.beginTransaction(function (tErr) {
            if (tErr) {
              connection.release();
              req.flash('message', 'Database error');
              return res.redirect('/admin/roombookings');
            }

            const myActiveSql = "SELECT id FROM room_bookings WHERE uid = ? AND booking_status = 'locked' LIMIT 1";
            connection.query(myActiveSql, [uid], function (aErr, aRows) {
              if (aErr) {
                return connection.rollback(function () {
                  connection.release();
                  req.flash('message', 'Database error');
                  return res.redirect('/admin/roombookings');
                });
              }

              if (aRows && aRows.length > 0) {
                return connection.rollback(function () {
                  connection.release();
                  req.flash('message', 'Student already has an active room booking');
                  return res.redirect('/admin/roombookings');
                });
              }

              const occupiedSql = `
              SELECT id
              FROM room_bookings
              WHERE room_no = ?
                AND block = ?
                AND floor = ?
                AND bed_no = ?
                AND booking_status = 'locked'
              LIMIT 1
            `;
              connection.query(occupiedSql, [room_no, block, floor, bed_no], function (oErr, oRows) {
                if (oErr) {
                  return connection.rollback(function () {
                    connection.release();
                    req.flash('message', 'Database error');
                    return res.redirect('/admin/roombookings');
                  });
                }

                if (oRows && oRows.length > 0) {
                  return connection.rollback(function () {
                    connection.release();
                    req.flash('message', 'Room already booked');
                    return res.redirect('/admin/roombookings');
                  });
                }

                const insertSql = `
                INSERT INTO room_bookings (
                  room_no, block, floor, bed_no, uid,
                  booking_status, payment_status,
                  advance_amount, transaction_id,
                  agreement_accepted,
                  locked_source, locked_by
                )
                VALUES (?, ?, ?, ?, ?, 'locked', 'pending', ?, ?, ?, 'admin', ?)
              `;
                const lockedBy = ((req.decode.adminname || req.decode.role || '') + '').trim() || 'admin';

                connection.query(
                  insertSql,
                  [room_no, block, floor, bed_no, uid, advanceAmount, transactionId || null, 1, lockedBy],
                  function (iErr) {
                    if (iErr) {
                      return connection.rollback(function () {
                        connection.release();
                        if (iErr.code === 'ER_DUP_ENTRY') {
                          req.flash('message', 'Room already booked');
                        } else if (iErr.code === 'ER_NO_SUCH_TABLE') {
                          req.flash('message', 'Room booking feature is not set up in DB. Please run db/room_bookings.sql');
                        } else if (iErr.code === 'ER_BAD_FIELD_ERROR') {
                          req.flash('message', 'Room booking DB schema is outdated. Please run the ALTER TABLE migration to add advance_amount/transaction_id columns.');
                        } else {
                          console.error('Admin room booking insert failed:', iErr);
                          req.flash('message', 'Error locking room');
                        }
                        return res.redirect('/admin/roombookings');
                      });
                    }

                    connection.query(
                      "UPDATE studentdetails SET room_no = NULL, bed_no = NULL, block = NULL, other2 = NULL WHERE uid = ?",
                      [uid],
                      function (clearErr) {
                        if (clearErr) {
                          return connection.rollback(function () {
                            connection.release();
                            req.flash('message', 'Database error');
                            return res.redirect('/admin/roombookings');
                          });
                        }

                        connection.commit(function (cErr) {
                          if (cErr) {
                            return connection.rollback(function () {
                              connection.release();
                              req.flash('message', 'Database error');
                              return res.redirect('/admin/roombookings');
                            });
                          }

                          connection.release();
                          req.flash('message', 'Room locked for student successfully');
                          return res.redirect('/admin/roombookings');
                        });
                      }
                    );
                  }
                );
              });
            });
          });
        });
      });
    });
  });


app.post('/admin/roombooking/payment', verifyjwt, function (req, res) {
  const role = req.decode.role;
  if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
    req.flash('message', 'Unauthorised Access');
    return res.redirect('/loginpanel');
  }

  const { booking_id, advance_amount, transaction_id } = req.body;
  if (!booking_id || !advance_amount || !transaction_id) {
    req.flash('message', 'All fields are required');
    return res.redirect('back');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('back');
    }

    const checkSql = "SELECT id, uid, room_no, block, floor, bed_no, payment_status, booking_status FROM room_bookings WHERE id = ?";
    connection.query(checkSql, [booking_id], function (cErr, rows) {
      if (cErr || !rows || rows.length === 0) {
        connection.release();
        req.flash('message', 'Booking not found or database error');
        return res.redirect('back');
      }

      const booking = rows[0];
      const bookingStatus = String(booking.booking_status || '').toLowerCase();
      const newStatus = 'confirmed';

      const continueWithUpdate = function () {
        const sql = `UPDATE room_bookings
                     SET booking_status = 'locked', payment_status = ?, advance_amount = ?, transaction_id = ?
                     WHERE id = ?`;

        connection.query(sql, [newStatus, advance_amount, transaction_id, booking_id], function (err) {
          if (err) {
            connection.release();
            req.flash('message', 'Error updating payment status');
            return res.redirect('/admin/roombookings#bookingsSection');
          }

          const syncSql = "UPDATE studentdetails sd JOIN room_bookings rb ON rb.uid = sd.uid AND rb.id = ? SET sd.room_no = rb.room_no, sd.bed_no = rb.bed_no, sd.block = rb.block, sd.other2 = rb.block";
          connection.query(syncSql, [booking_id], function (syncErr) {
            if (syncErr) console.error('Failed to sync studentdetails room info on payment:', syncErr.message);
            connection.release();
            req.flash('message', 'Payment details updated successfully');
            res.redirect('/admin/roombookings#bookingsSection');
          });
        });
      };

      const activeBookingSql = "SELECT id FROM room_bookings WHERE uid = ? AND booking_status = 'locked' AND id <> ? LIMIT 1";
      connection.query(activeBookingSql, [booking.uid, booking_id], function (activeErr, activeRows) {
        if (activeErr) {
          connection.release();
          req.flash('message', 'Database error');
          return res.redirect('/admin/roombookings#bookingsSection');
        }
        if (activeRows && activeRows.length > 0) {
          connection.release();
          req.flash('message', 'Student already has another active room booking');
          return res.redirect('/admin/roombookings#bookingsSection');
        }

        if (bookingStatus === 'cancelled') {
          const bedCheckSql = `
            SELECT id, uid
            FROM room_bookings
            WHERE booking_status = 'locked'
              AND room_no = ?
              AND block = ?
              AND floor = ?
              AND COALESCE(bed_no, '') = COALESCE(?, '')
              AND id <> ?
            LIMIT 1
          `;
          connection.query(bedCheckSql, [booking.room_no, booking.block, booking.floor, booking.bed_no, booking_id], function (bedErr, bedRows) {
            if (bedErr) {
              connection.release();
              req.flash('message', 'Database error');
              return res.redirect('/admin/roombookings#bookingsSection');
            }
            if (bedRows && bedRows.length > 0) {
              connection.release();
              req.flash('message', 'Requested bed is no longer empty. Please cancel and book another bed.');
              return res.redirect('/admin/roombookings#bookingsSection');
            }
            return continueWithUpdate();
          });
          return;
        }

        return continueWithUpdate();
      });
    });
  });
});

app.post('/admin/roombooking/approve', verifyjwt, function (req, res) {
  if (!req.decode || !req.decode.role) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
  const role = req.decode.role;
  if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
    req.flash('message', 'Unauthorised Access');
    return res.redirect('/admin/roombookings#bookingsSection');
  }

  const booking_id = parseInt(req.body.booking_id, 10);
  if (!booking_id) {
    req.flash('message', 'Invalid booking');
    return res.redirect('/admin/roombookings#bookingsSection');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/admin/roombookings#bookingsSection');
    }

    const checkSql = "SELECT payment_status, advance_amount, transaction_id FROM room_bookings WHERE id = ? AND booking_status = 'locked'";
    connection.query(checkSql, [booking_id], function (cErr, rows) {
      if (cErr) {
        connection.release();
        req.flash('message', 'Database error');
        return res.redirect('/admin/roombookings#bookingsSection');
      }
      if (!rows || rows.length === 0) {
        connection.release();
        req.flash('message', 'Booking not found');
        return res.redirect('/admin/roombookings#bookingsSection');
      }
      const row = rows[0];
      if ((row.payment_status || '').toLowerCase() !== 'pending') {
        connection.release();
        req.flash('message', 'Booking is not in pending state');
        return res.redirect('/admin/roombookings#bookingsSection');
      }
      if (!row.transaction_id || row.advance_amount == null) {
        connection.release();
        req.flash('message', 'No transaction details found to approve. Use Pay to enter them first.');
        return res.redirect('/admin/roombookings#bookingsSection');
      }

      const updateSql = "UPDATE room_bookings SET payment_status = 'confirmed' WHERE id = ? AND payment_status = 'pending'";
      connection.query(updateSql, [booking_id], function (uErr, result) {
        if (uErr) {
          connection.release();
          req.flash('message', 'Error approving payment');
          return res.redirect('/admin/roombookings#bookingsSection');
        }
        if (!result || result.affectedRows === 0) {
          connection.release();
          req.flash('message', 'Booking already updated by someone else');
          return res.redirect('/admin/roombookings#bookingsSection');
        }

        // Sync studentdetails room info so they appear on attendance
        const syncSql = "UPDATE studentdetails sd JOIN room_bookings rb ON rb.uid = sd.uid AND rb.id = ? SET sd.room_no = rb.room_no, sd.bed_no = rb.bed_no, sd.block = rb.block, sd.other2 = rb.block";
        connection.query(syncSql, [booking_id], function (syncErr) {
          if (syncErr) console.error('Failed to sync studentdetails room info on approve:', syncErr.message);

          // Fetch student details to send confirmation email
          const fetchSql = `
            SELECT rb.room_no, rb.block, rb.bed_no, rb.advance_amount, rb.transaction_id,
                   sd.sname, sd.email, sd.uid
            FROM room_bookings rb
            JOIN studentdetails sd ON sd.uid = rb.uid
            WHERE rb.id = ?
            LIMIT 1
          `;
          connection.query(fetchSql, [booking_id], function (fetchErr, fetchRows) {
            connection.release();
            if (!fetchErr && fetchRows && fetchRows.length > 0 && fetchRows[0].email) {
              const s = fetchRows[0];
              const confirmedOn = formatDateTimeForDB(currentdate());
              const emailData = {
                sname: s.sname,
                uid: s.uid,
                block: s.block || 'N/A',
                room_no: s.room_no,
                bed_no: s.bed_no,
                advance_amount: s.advance_amount != null ? s.advance_amount : 'ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“',
                transaction_id: s.transaction_id || 'ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“',
                confirmed_on: confirmedOn,
                contactEmail: 'tnpshostel@gmail.com'
              };
              const renderedBookingMail = ejs.render(bookingConfirmedTemplate, emailData);
              transporter.sendMail({
                from: process.env.MAIL_USER,
                to: s.email,
                subject: 'TNPS Boys Hostel - Room Booking Payment Confirmed | UID: ' + s.uid,
                html: renderedBookingMail,
                attachments: [
                  { filename: 'hostellogo.png', path: hostelLogoPath, cid: 'hostel-logo' }
                ]
              }, function (mailErr, info) {
                if (mailErr) console.error('Booking email failed:', mailErr.message);
                else console.log('Booking email sent:', info.response);
              });
            } else if (fetchErr) {
              console.error('Could not fetch student for booking email:', fetchErr.message);
            }
            req.flash('message', 'Payment approved as Confirmed');
            return res.redirect('/admin/roombookings#bookingsSection');
          });
        });
      });
    });
  });
});

app.post('/admin/roombooking/transfer', verifyjwt, function (req, res) {
  if (!req.decode || !req.decode.role) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }

  const role = req.decode.role;
  if (role !== 'SuperID') {
    req.flash('message', 'Only SuperID can transfer room bookings');
    return res.redirect('/admin/roombookings#bookingsSection');
  }

  const booking_id = parseInt(req.body.booking_id, 10);
  const new_block = ((req.body.new_block || '') + '').trim();
  const new_room = ((req.body.new_room || '') + '').trim();
  const new_floor = ((req.body.new_floor || '') + '').trim();
  const new_bed = ((req.body.new_bed || '') + '').trim().toUpperCase();

  if (!booking_id || !new_block || !new_room || !new_floor || !new_bed) {
    req.flash('message', 'Invalid transfer request');
    return res.redirect('/admin/roombookings#bookingsSection');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/admin/roombookings#bookingsSection');
    }

    const checkSql = `
      SELECT id, uid, room_no, block, floor, bed_no, payment_status, booking_status
      FROM room_bookings
      WHERE id = ? AND booking_status = 'locked'
      LIMIT 1
    `;
    connection.query(checkSql, [booking_id], function (cErr, rows) {
      if (cErr) {
        connection.release();
        req.flash('message', 'Database error');
        return res.redirect('/admin/roombookings#bookingsSection');
      }
      if (!rows || rows.length === 0) {
        connection.release();
        req.flash('message', 'Booking not found');
        return res.redirect('/admin/roombookings#bookingsSection');
      }

      const booking = rows[0];
      const paymentStatus = (booking.payment_status || '').toLowerCase();
      if (paymentStatus !== 'pending' && paymentStatus !== 'confirmed') {
        connection.release();
        req.flash('message', 'Only pending or confirmed bookings can be transferred');
        return res.redirect('/admin/roombookings#bookingsSection');
      }

      if (
        (booking.room_no || '') === new_room &&
        (booking.block || '') === new_block &&
        (booking.floor || '') === new_floor &&
        ((booking.bed_no || '') + '').trim().toUpperCase() === new_bed
      ) {
        connection.release();
        req.flash('message', 'Selected room/bed is already assigned to this booking');
        return res.redirect('/admin/roombookings#bookingsSection');
      }

      const activeBookingSql = `
        SELECT id
        FROM room_bookings
        WHERE uid = ?
          AND booking_status = 'locked'
          AND id <> ?
        LIMIT 1
      `;
      connection.query(activeBookingSql, [booking.uid, booking_id], function (aErr, aRows) {
        if (aErr) {
          connection.release();
          req.flash('message', 'Database error');
          return res.redirect('/admin/roombookings#bookingsSection');
        }
        if (aRows && aRows.length > 0) {
          connection.release();
          req.flash('message', 'Student already has another active room booking');
          return res.redirect('/admin/roombookings#bookingsSection');
        }

        const roomSql = `
          SELECT name, block, floor, capacity
          FROM rooms
          WHERE name = ? AND block = ? AND floor = ?
            AND (is_available IS NULL OR is_available = TRUE)
            AND NOT (is_permanent = 1 AND name IN ('AF-02', 'AF-31', 'AS-31', 'BG-26'))
            LIMIT 1
        `;
        connection.query(roomSql, [new_room, new_block, new_floor], function (rErr, rRows) {
          if (rErr) {
            connection.release();
            req.flash('message', 'Database error');
            return res.redirect('/admin/roombookings#bookingsSection');
          }
          if (!rRows || rRows.length === 0) {
            connection.release();
            req.flash('message', 'Selected room is not available');
            return res.redirect('/admin/roombookings#bookingsSection');
          }

          const room = rRows[0];
          const capacity = parseInt(room.capacity, 10) || 1;
          const validBeds = ['A', 'B', 'C', 'D', 'E', 'F'].slice(0, capacity);
          if (!validBeds.includes(new_bed)) {
            connection.release();
            req.flash('message', 'Selected bed is not valid for the chosen room');
            return res.redirect('/admin/roombookings#bookingsSection');
          }

          connection.beginTransaction(function (tErr) {
            if (tErr) {
              connection.release();
              req.flash('message', 'Database error');
              return res.redirect('/admin/roombookings#bookingsSection');
            }

            const occupiedSql = `
              SELECT id
              FROM room_bookings
              WHERE booking_status = 'locked'
                AND room_no = ?
                AND block = ?
                AND floor = ?
                AND bed_no = ?
                AND id <> ?
              LIMIT 1
            `;
            connection.query(occupiedSql, [new_room, new_block, new_floor, new_bed, booking_id], function (oErr, oRows) {
              if (oErr) {
                return connection.rollback(function () {
                  connection.release();
                  req.flash('message', 'Database error');
                  return res.redirect('/admin/roombookings#bookingsSection');
                });
              }
              if (oRows && oRows.length > 0) {
                return connection.rollback(function () {
                  connection.release();
                  req.flash('message', 'Selected room/bed is already booked');
                  return res.redirect('/admin/roombookings#bookingsSection');
                });
              }

              const updateBookingSql = `
                UPDATE room_bookings
                SET room_no = ?, block = ?, floor = ?, bed_no = ?
                WHERE id = ? AND booking_status = 'locked'
              `;
              connection.query(updateBookingSql, [new_room, new_block, new_floor, new_bed, booking_id], function (uErr, result) {
                if (uErr) {
                  return connection.rollback(function () {
                    connection.release();
                    req.flash('message', 'Error transferring booking');
                    return res.redirect('/admin/roombookings#bookingsSection');
                  });
                }
                if (!result || result.affectedRows === 0) {
                  return connection.rollback(function () {
                    connection.release();
                    req.flash('message', 'Booking not found or already updated');
                    return res.redirect('/admin/roombookings#bookingsSection');
                  });
                }

                const finishTransfer = function () {
                  connection.commit(function (cErr) {
                    if (cErr) {
                      return connection.rollback(function () {
                        connection.release();
                        req.flash('message', 'Database error');
                        return res.redirect('/admin/roombookings#bookingsSection');
                      });
                    }
                    connection.release();
                    req.flash('message', 'Room transfer successful');
                    return res.redirect('/admin/roombookings#bookingsSection');
                  });
                };

                if (paymentStatus === 'confirmed') {
                  const syncSql = `
                    UPDATE studentdetails sd
                    JOIN room_bookings rb ON rb.uid = sd.uid AND rb.id = ?
                    SET sd.room_no = rb.room_no,
                        sd.bed_no = rb.bed_no,
                        sd.block = rb.block,
                        sd.other2 = rb.block
                  `;
                  connection.query(syncSql, [booking_id], function (syncErr) {
                    if (syncErr) {
                      return connection.rollback(function () {
                        connection.release();
                        req.flash('message', 'Error updating student details for transfer');
                        return res.redirect('/admin/roombookings#bookingsSection');
                      });
                    }
                    finishTransfer();
                  });
                } else {
                  finishTransfer();
                }
              });
            });
          });
        });
      });
    });
  });
});

app.get('/api/admin/roombookings/unapplied-students', verifyjwt, function (req, res) {
  const role = req.decode && req.decode.role ? req.decode.role : '';
  if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
    return res.status(403).json([]);
  }

  const term = ((req.query.term || '') + '').trim();
  const genderWhere = (role === 'BoysHostelAdmin')
    ? " AND UPPER(TRIM(COALESCE(s.gender, ''))) = 'MALE' "
    : (role === 'GirlsHostelAdmin')
      ? " AND UPPER(TRIM(COALESCE(s.gender, ''))) = 'FEMALE' "
      : '';

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json([]);
    }

    let sql = `
      SELECT s.uid, s.sname
      FROM studentdetails s
      WHERE LOWER(TRIM(COALESCE(s.category, ''))) = 'hostel'
        AND (s.status IS NULL OR TRIM(s.status) <> 'Restrict')
        ${genderWhere}
        AND NOT EXISTS (
          SELECT 1
          FROM room_bookings rb
          WHERE rb.uid = s.uid
        )
    `;
    const params = [];

    if (term) {
      sql += " AND (s.uid LIKE ? OR s.sname LIKE ?)";
      params.push('%' + term + '%', '%' + term + '%');
    }

    sql += " ORDER BY s.sname ASC LIMIT 500";

    connection.query(sql, params, function (qErr, rows) {
      connection.release();
      if (qErr) {
        console.error('unapplied-students:', qErr);
        return res.status(500).json([]);
      }
      res.json(rows || []);
    });
  });
});

// Admin: Cancel Room Booking (SuperID only)
app.post('/admin/roombooking/cancel', verifyjwt, function (req, res) {
  if (!req.decode || !req.decode.role) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
  const role = req.decode.role;
  if (role !== 'SuperID') {
    req.flash('message', 'Only SuperID can cancel bookings');
    return res.redirect('/admin/roombookings#bookingsSection');
  }
  const id = parseInt(req.body.id, 10);
  if (!id) {
    req.flash('message', 'Invalid booking');
    return res.redirect('/admin/roombookings#bookingsSection');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/admin/roombookings#bookingsSection');
    }
    const sql = "UPDATE room_bookings SET booking_status = 'cancelled', payment_status = 'cancelled' WHERE id = ?";
    connection.query(sql, [id], function (qErr, result) {
      if (qErr) {
        connection.release();
        console.error('cancel booking failed:', qErr);
        req.flash('message', 'Error cancelling booking');
        return res.redirect('/admin/roombookings#bookingsSection');
      }
      if (!result || result.affectedRows === 0) {
        connection.release();
        req.flash('message', 'Booking not found or already cancelled');
        return res.redirect('/admin/roombookings#bookingsSection');
      }

      const clearSql = `
        UPDATE studentdetails sd
        JOIN room_bookings rb ON rb.id = ? AND rb.uid = sd.uid
        SET sd.room_no = NULL, sd.bed_no = NULL, sd.block = NULL, sd.other2 = NULL
      `;
      connection.query(clearSql, [id], function (clearErr) {
        connection.release();
        if (clearErr) {
          console.error('clear student room details on cancel failed:', clearErr);
          req.flash('message', 'Booking cancelled, but student room fields may need manual refresh');
          return res.redirect('/admin/roombookings#bookingsSection');
        }
        req.flash('message', 'Booking cancelled');
        return res.redirect('/admin/roombookings#bookingsSection');
      });
    });
  });
});

// Student Allocate Room (self-service for block/room/bed only)
app.post('/student/allocate-room', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const block = (req.body.block || '').trim();
  const room_no = (req.body.room_no || '').trim();
  const bed_no = (req.body.bed_no || '').trim();

  // Only room and bed are strictly required; block is optional depending on schema
  if (!room_no || !bed_no) {
    const msg = 'Please provide Room No and Bed No.';
    if (req.xhr || (req.headers.accept || '').includes('application/json')) {
      return res.status(400).json({ success: false, message: msg });
    }
    req.flash('message', msg);
    return res.redirect('/student/profile');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      const msg = 'Database error';
      if (req.xhr || (req.headers.accept || '').includes('application/json')) {
        return res.status(500).json({ success: false, message: msg });
      }
      req.flash('message', msg);
      return res.redirect('/student/profile');
    }
    // Detect actual column names and build queries dynamically
    connection.query('SHOW COLUMNS FROM studentdetails', function (colErr, cols) {
      if (colErr) {
        connection.release();
        const msg = 'Database error';
        if (req.xhr || (req.headers.accept || '').includes('application/json')) {
          return res.status(500).json({ success: false, message: msg });
        }
        req.flash('message', msg);
        return res.redirect('/student/profile');
      }

      const fields = new Set((cols || []).map(c => c.Field));
      const hasBlock = fields.has('block');
      const roomCol = fields.has('room_no') ? 'room_no' : (fields.has('room') ? 'room' : (fields.has('rno') ? 'rno' : null));
      const bedCol = fields.has('bed_no') ? 'bed_no' : (fields.has('bed') ? 'bed' : null);

      if (!roomCol || !bedCol) {
        connection.release();
        const msg = 'Room/Bed columns are not present in studentdetails';
        if (req.xhr || (req.headers.accept || '').includes('application/json')) {
          return res.status(500).json({ success: false, message: msg });
        }
        req.flash('message', msg);
        return res.redirect('/student/profile');
      }

      // Uniqueness check
      const where = (hasBlock ? 'block = ? AND ' : '') + `${roomCol} = ? AND ${bedCol} = ? AND uid <> ?`;
      const checkSql = `SELECT uid FROM studentdetails WHERE ${where} LIMIT 1`;
      const checkParams = hasBlock ? [block, room_no, bed_no, uid] : [room_no, bed_no, uid];

      connection.query(checkSql, checkParams, function (cerr, rows) {
        if (cerr) {
          console.error('Validation error:', cerr);
          connection.release();
          const msg = 'Error validating room allocation';
          if (req.xhr || (req.headers.accept || '').includes('application/json')) {
            return res.status(500).json({ success: false, message: msg });
          }
          req.flash('message', msg);
          return res.redirect('/student/profile');
        }
        // If occupied, override by clearing previous occupant (allow override)
        const proceedUpdate = () => {
          const setParts = [];
          const params = [];
          if (hasBlock && block) { setParts.push('block = ?'); params.push(block); }
          setParts.push(`${roomCol} = ?`); params.push(room_no);
          setParts.push(`${bedCol} = ?`); params.push(bed_no);
          if (fields.has('other3')) { setParts.push('other3 = ?'); params.push('profile_allocated'); }
          const updateSql = `UPDATE studentdetails SET ${setParts.join(', ')} WHERE uid = ?`;
          params.push(uid);

          connection.query(updateSql, params, function (uerr) {
            connection.release();
            if (uerr) {
              console.error('Update error:', uerr);
              const msg = 'Failed to allocate room';
              if (req.xhr || (req.headers.accept || '').includes('application/json')) {
                return res.status(500).json({ success: false, message: msg });
              }
              req.flash('message', msg);
              return res.redirect('/student/profile');
            }
            const payload = { success: true, message: 'Room allocated successfully', block: (hasBlock && block) ? block : undefined, room_no, bed_no };
            if (req.xhr || (req.headers.accept || '').includes('application/json')) {
              return res.json(payload);
            }
            req.flash('message', payload.message);
            return res.redirect('/student/profile');
          });
        };

        if (rows && rows.length > 0) {
          const prevUid = rows[0].uid;
          // Clear previous occupant's bed and room
          const clearSql = `UPDATE studentdetails SET ${bedCol} = NULL, ${roomCol} = NULL${fields.has('other3') ? ', other3 = NULL' : ''}${hasBlock ? ', block = block' : ''} WHERE uid = ?`;
          return connection.query(clearSql, [prevUid], function (clrErr) {
            if (clrErr) {
              console.error('Clear previous occupant failed:', clrErr);
              connection.release();
              const msg = 'Failed to override previous allocation';
              if (req.xhr || (req.headers.accept || '').includes('application/json')) {
                return res.status(500).json({ success: false, message: msg });
              }
              req.flash('message', msg);
              return res.redirect('/student/profile');
            }
            return proceedUpdate();
          });
        }

        // No conflict, proceed with update
        return proceedUpdate();
      });
    });
  });
});

// API: Return available rooms by block in the format AS-01 / BS-01
app.get('/api/available-rooms', verifyStudentJwt, function (req, res) {
  const blockParam = ((req.query.block || '') + '').toUpperCase();
  // Configure floors/prefixes and counts here (adjust to your hostel)
  // Example: Block A has AS/AF/AG prefixes; Block B has BS/BF/BG prefixes
  const prefixesByBlock = { A: ['AS', 'AF', 'AG'], B: ['BS', 'BF', 'BG'] };
  const countsByPrefix = { AS: 50, AF: 50, AG: 25, BS: 50, BF: 50, BG: 50 };

  function generateAllRooms(prefixMap, countMap) {
    const out = {};
    Object.keys(prefixMap).forEach(b => {
      out[b] = [];
      (prefixMap[b] || []).forEach(pref => {
        const count = countMap[pref] || 0;
        for (let i = 1; i <= count; i++) {
          const num = String(i).padStart(2, '0');
          out[b].push(`${pref}-${num}`);
        }
      });
    });
    return out;
  }

  const allRooms = generateAllRooms(prefixesByBlock, countsByPrefix);

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    // Show ALL rooms (not just vacant). If a rooms table exists, prefer it.
    connection.query("SHOW TABLES LIKE 'rooms'", function (tErr, tRows) {
      if (!tErr && Array.isArray(tRows) && tRows.length > 0) {
        const params = blockParam ? [blockParam] : [];
        const where = blockParam ? ' WHERE block = ?' : '';
        const sql = `SELECT name as room FROM rooms${where} ORDER BY name`;
        return connection.query(sql, params, function (qerr, rows) {
          connection.release();
          if (qerr) return res.status(500).json({ success: false, message: 'Database error' });
          const rooms = (rows || []).map(r => (r.room || '').toString());
          if (blockParam) return res.json({ success: true, block: blockParam, rooms });
          return res.json({ success: true, roomsByBlock: null, rooms });
        });
      }
      // Fallback: generated list by prefixes/counts
      const out = blockParam && prefixesByBlock[blockParam] ? (allRooms[blockParam] || []) : allRooms;
      connection.release();
      if (Array.isArray(out)) return res.json({ success: true, block: blockParam, rooms: out });
      return res.json({ success: true, roomsByBlock: out });
    });
  });
});

// Student Attendance
app.get('/student/attendance', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const fromDate = req.query.fromDate;
  const toDate = req.query.toDate;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/dashboard');
    }

    // Get student details
    var studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(studentSql, [uid], function (err, studentResult) {
      if (err || studentResult.length === 0) {
        connection.release();
        return res.redirect('/student/dashboard');
      }

      const student = studentResult[0];

      // Build attendance query with date filter
      var attendanceSql = `
        SELECT *, 
        CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, outdatetime, indatetime) % 86400)/3600), ' hrs ', 
              FLOOR((TIMESTAMPDIFF(SECOND, outdatetime, indatetime) % 3600)/60), ' min') AS Duration 
        FROM log_details1 WHERE uid = ?`;

      var params = [uid];

      if (fromDate && toDate) {
        attendanceSql += " AND DATE(COALESCE(approvaldt, outdatetime, indatetime)) BETWEEN ? AND ?";
        params.push(fromDate, toDate);
      }

      attendanceSql += " ORDER BY logid DESC LIMIT 100";

      connection.query(attendanceSql, params, function (err, attendanceResult) {
        // Get statistics
        var statsSql = `
          SELECT 
            COUNT(CASE WHEN indatetime IS NOT NULL THEN 1 END) as totalEntries,
            COUNT(CASE WHEN outdatetime IS NOT NULL THEN 1 END) as totalExits,
            COUNT(CASE WHEN MONTH(COALESCE(approvaldt, outdatetime, indatetime)) = MONTH(CURDATE()) THEN 1 END) as monthMovements
          FROM log_details1 WHERE uid = ?`;

        connection.query(statsSql, [uid], function (err, statsResult) {
          // Check if currently outside
          var currentSql = "SELECT * FROM log_details1 WHERE uid = ? AND (status = 'ACTIVE' OR (outdatetime IS NOT NULL AND indatetime IS NULL)) ORDER BY logid DESC LIMIT 1";
          connection.query(currentSql, [uid], function (err, currentResult) {
            connection.release();

            const currentlyOut = currentResult.length > 0 &&
              (currentResult[0].status === 'ACTIVE' ||
                (currentResult[0].outdatetime && !currentResult[0].indatetime));

            res.render(__dirname + '/views/student_attendance', {
              student: student,
              attendance: attendanceResult || [],
              stats: statsResult[0] || { totalEntries: 0, totalExits: 0, monthMovements: 0 },
              currentlyOut: currentlyOut,
              fromDate: fromDate || '',
              toDate: toDate || '',
              message: req.flash('message')
            });
          });
        });
      });
    });
  });
});

// Student Pass History
app.get('/student/passhistory', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const fromDate = req.query.fromDate;
  const toDate = req.query.toDate;
  const passType = req.query.passType;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/dashboard');
    }

    // Get student details
    var studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(studentSql, [uid], function (err, studentResult) {
      if (err || studentResult.length === 0) {
        connection.release();
        return res.redirect('/student/dashboard');
      }

      const student = studentResult[0];

      // Build pass history query
      var passSql = `
        SELECT *,
        CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, outdatetime, indatetime) % 86400)/3600), ' hrs ', 
              FLOOR((TIMESTAMPDIFF(SECOND, outdatetime, indatetime) % 3600)/60), ' min') AS Duration,
        CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, approvaldt, hostelintime) % 86400)/3600), ' hrs ', 
              FLOOR((TIMESTAMPDIFF(SECOND, approvaldt, hostelintime) % 3600)/60), ' min') AS Durationh
        FROM log_details1 WHERE uid = ? AND passtype IS NOT NULL`;

      var params = [uid];

      if (fromDate && toDate) {
        passSql += " AND DATE(approvaldt) BETWEEN ? AND ?";
        params.push(fromDate, toDate);
      }

      if (passType) {
        passSql += " AND passtype = ?";
        params.push(passType);
      }

      passSql += " ORDER BY logid DESC LIMIT 100";

      connection.query(passSql, params, function (err, passResult) {
        // Get statistics
        var statsSql = `
          SELECT 
            COUNT(*) as totalPasses,
            COUNT(CASE WHEN passtype = 'City Pass' THEN 1 END) as cityPasses,
            COUNT(CASE WHEN passtype = 'Home Pass' THEN 1 END) as homePasses,
            COUNT(CASE WHEN MONTH(approvaldt) = MONTH(CURDATE()) AND YEAR(approvaldt) = YEAR(CURDATE()) THEN 1 END) as monthPasses
          FROM log_details1 WHERE uid = ? AND passtype IS NOT NULL`;

        connection.query(statsSql, [uid], function (err, statsResult) {
          // Get active pass
          var activeSql = "SELECT * FROM log_details1 WHERE uid = ? AND status = 'ACTIVE' AND passtype IN ('City Pass', 'Home Pass') ORDER BY logid DESC LIMIT 1";
          connection.query(activeSql, [uid], function (err, activeResult) {
            connection.release();

            res.render(__dirname + '/views/student_passhistory', {
              student: student,
              passes: passResult || [],
              stats: statsResult[0] || { totalPasses: 0, cityPasses: 0, homePasses: 0, monthPasses: 0 },
              activePass: activeResult.length > 0 ? activeResult[0] : null,
              fromDate: fromDate || '',
              toDate: toDate || '',
              passType: passType || '',
              message: req.flash('message')
            });
          });
        });
      });
    });
  });
});

// Student Request Pass Page
app.get('/student/requestpass', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/dashboard');
    }

    // Get student details
    var studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(studentSql, [uid], function (err, studentResult) {
      if (err || studentResult.length === 0) {
        connection.release();
        return res.redirect('/student/dashboard');
      }

      const student = studentResult[0];
      const todayIstDate = (formatDateToISTString(new Date()) || '').split(' ')[0];

      // Check for active pass
      var activeSql = "SELECT * FROM log_details1 WHERE uid = ? AND status = 'ACTIVE' AND passtype IN ('City Pass', 'Home Pass') ORDER BY logid DESC LIMIT 1";
      connection.query(activeSql, [uid], function (err, activeResult) {
        // Get pending requests - format datetime to ensure consistent format
        var pendingSql = `SELECT requestid, uid, passtype, 
          DATE_FORMAT(expected_out, '%Y-%m-%d %H:%i:%s') as expected_out,
          DATE_FORMAT(expected_return, '%Y-%m-%d %H:%i:%s') as expected_return,
          reason, emergency_contact, status, approved_by,
          DATE_FORMAT(approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
          rejection_reason,
          DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
          FROM pass_requests WHERE uid = ? AND status = 'pending' ORDER BY created_at DESC`;
        connection.query(pendingSql, [uid], function (err, pendingResult) {
          // Get all approved requests
          var allApprovedSql = `SELECT requestid, uid, passtype, 
          DATE_FORMAT(expected_out, '%Y-%m-%d %H:%i:%s') as expected_out,
          DATE_FORMAT(expected_return, '%Y-%m-%d %H:%i:%s') as expected_return,
          reason, emergency_contact, status, approved_by,
          DATE_FORMAT(approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
          rejection_reason,
          DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
          FROM pass_requests WHERE uid = ? AND status = 'approved' ORDER BY approved_at DESC`;
          connection.query(allApprovedSql, [uid], function (err, approvedResult) {
            // Get latest approved request (today only)
            var latestApprovedSql = `SELECT requestid, uid, passtype, 
            DATE_FORMAT(expected_out, '%Y-%m-%d %H:%i:%s') as expected_out,
            DATE_FORMAT(expected_return, '%Y-%m-%d %H:%i:%s') as expected_return,
            reason, emergency_contact, status, approved_by,
            DATE_FORMAT(approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
            rejection_reason,
            DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at,
            conversion_enabled, conversion_enabled_by
            FROM pass_requests 
            WHERE uid = ? 
              AND status = 'approved'
              AND DATE(approved_at) = ?
            ORDER BY approved_at DESC LIMIT 1`;
            connection.query(latestApprovedSql, [uid, todayIstDate], function (err, latestApprovedResult) {
              // If latest approved is a City Pass but the student has already used/activated it
              // (i.e. a corresponding pass exists in log_details1), do NOT force conversion-only UI.
              const latestApprovedPassRaw = (latestApprovedResult && latestApprovedResult.length > 0) ? latestApprovedResult[0] : null;

              function continueWithRejected(latestApprovedPassForUi) {
                // Get rejected requests
                var rejectedSql = `SELECT requestid, uid, passtype, 
            DATE_FORMAT(expected_out, '%Y-%m-%d %H:%i:%s') as expected_out,
            DATE_FORMAT(expected_return, '%Y-%m-%d %H:%i:%s') as expected_return,
            reason, emergency_contact, status, approved_by,
            DATE_FORMAT(approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
            rejection_reason,
            DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
            FROM pass_requests WHERE uid = ? AND status = 'rejected' ORDER BY created_at DESC`;
                connection.query(rejectedSql, [uid], function (err, rejectedResult) {
                  if (activeResult.length > 0 && ((activeResult[0].passtype || '') + '').trim().toLowerCase() === 'city pass') {
                    const checkActiveConvSql = "SELECT conversion_enabled, conversion_enabled_by FROM pass_requests WHERE uid = ? AND status = 'approved' AND (request_kind != 'convert' OR request_kind IS NULL) ORDER BY approved_at DESC, requestid DESC LIMIT 1";
                    connection.query(checkActiveConvSql, [uid], function (actErr, actRows) {
                      connection.release();
                      const convEnabled = (actRows && actRows.length > 0) ? actRows[0].conversion_enabled : 0;
                      const convEnabledBy = (actRows && actRows.length > 0) ? actRows[0].conversion_enabled_by : null;
                      res.render(__dirname + '/views/student_requestpass', {
                        student: student,
                        activePass: activeResult[0],
                        pendingRequests: pendingResult || [],
                        approvedRequests: approvedResult || [],
                        latestApprovedPass: latestApprovedPassForUi,
                        rejectedRequests: rejectedResult || [],
                        conversionEnabledForActive: convEnabled,
                        conversionEnabledByForActive: convEnabledBy,
                        message: req.flash('message')
                      });
                    });
                  } else {
                    connection.release();
                    res.render(__dirname + '/views/student_requestpass', {
                      student: student,
                      activePass: activeResult.length > 0 ? activeResult[0] : null,
                      pendingRequests: pendingResult || [],
                      approvedRequests: approvedResult || [],
                      latestApprovedPass: latestApprovedPassForUi,
                      rejectedRequests: rejectedResult || [],
                      conversionEnabledForActive: 0,
                      conversionEnabledByForActive: null,
                      message: req.flash('message')
                    });
                  }
                });
              }

              if (!latestApprovedPassRaw) {
                return continueWithRejected(null);
              }

              const latestType = ((latestApprovedPassRaw.passtype || '') + '').trim().toLowerCase();
              if (latestType !== 'city pass') {
                return continueWithRejected(latestApprovedPassRaw);
              }

              const approvedAt = latestApprovedPassRaw.approved_at || latestApprovedPassRaw.approvaldt || latestApprovedPassRaw.created_at;
              const usedSql = `
                SELECT logid
                FROM log_details1
                WHERE uid = ?
                  AND LOWER(passtype) = 'city pass'
                  AND approvaldt IS NOT NULL
                  AND DATE(approvaldt) >= DATE(?)
                ORDER BY logid DESC
                LIMIT 1
              `;
              connection.query(usedSql, [uid, approvedAt], function (uErr, uRows) {
                if (uErr) {
                  console.error('City pass usage check failed:', uErr);
                  return continueWithRejected(latestApprovedPassRaw);
                }
                const alreadyUsed = (uRows && uRows.length > 0);
                return continueWithRejected(alreadyUsed ? null : latestApprovedPassRaw);
              });
            });
          });
        });
      });
    });
  });
});

// Student Submit Pass Request
app.post('/student/requestpass', verifyStudentJwt, function (req, res) {
  console.log('Server-side Raw req.body:', req.body);
  const uid = req.studentUid;
  const { passType, expectedOutDate, expectedOutTime, expectedReturnDate, expectedReturnTime, reason, emergencyContact, is_emergency } = req.body;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/requestpass');
    }

    // Check if student is restricted
    var checkSql = "SELECT status, gender, emergency_pass_enabled, emergency_pass_enabled_by FROM studentdetails WHERE uid = ?";
    connection.query(checkSql, [uid], function (err, checkResult) {
      if (err || checkResult.length === 0 || checkResult[0].status === 'Restrict') {
        connection.release();
        req.flash('message', 'Cannot submit request. Account may be restricted.');
        return res.redirect('/student/requestpass');
      }

      const student = checkResult[0];
      const now = new Date();
      const istTimeShifted = new Date(now.getTime() + (5.5 * 60 * 60 * 1000));
      const dayNo = String(istTimeShifted.getUTCDay()); // "0" for Sunday, "1" for Monday ... "6" for Saturday
      const hour = String(istTimeShifted.getUTCHours()).padStart(2, '0');
      const minute = String(istTimeShifted.getUTCMinutes()).padStart(2, '0');
      const currentTimeStr = `${hour}:${minute}`; // e.g., "08:15"

      const genderClean = (student.gender || '').toUpperCase();
      const studentHostel = (genderClean === 'FEMALE' || genderClean === 'F' || genderClean === 'GIRL') ? 'Girls' : 'Boys';

      var timeboundSql = "SELECT * FROM timebound WHERE dayno = ? AND hostel = ? AND status = 'ACTIVE'";
      connection.query(timeboundSql, [dayNo, studentHostel], function (err, tbResult) {
        if (err) {
          connection.release();
          req.flash('message', 'Database error checking timebound constraints.');
          return res.redirect('/student/requestpass');
        }

        if (tbResult && tbResult.length > 0) {
          const tb = tbResult[0];
          const hasRange1 = tb.start && tb.end && tb.start.trim() !== '' && tb.end.trim() !== '';
          const hasRange2 = tb.start1 && tb.end1 && tb.start1.trim() !== '' && tb.end1.trim() !== '';

          if (!is_emergency && (hasRange1 || hasRange2)) {
            let allowed = false;
            const cleanStart = (tb.start || '').substring(0, 5);
            const cleanEnd = (tb.end || '').substring(0, 5);
            const cleanStart1 = (tb.start1 || '').substring(0, 5);
            const cleanEnd1 = (tb.end1 || '').substring(0, 5);

            if (hasRange1 && currentTimeStr >= cleanStart && currentTimeStr <= cleanEnd) {
              allowed = true;
            }
            if (hasRange2 && currentTimeStr >= cleanStart1 && currentTimeStr <= cleanEnd1) {
              allowed = true;
            }

            // Time restriction removed
          }
        }

        // Check for existing active pass (keep consistent with /student/requestpass page)
        var activeSql = "SELECT * FROM log_details1 WHERE uid = ? AND status = 'ACTIVE' AND passtype IN ('City Pass', 'Home Pass') ORDER BY logid DESC LIMIT 1";
        connection.query(activeSql, [uid], function (err, activeResult) {
          if (activeResult && activeResult.length > 0) {
            connection.release();
            req.flash('message', 'You already have an active pass');
            return res.redirect('/student/requestpass');
          }

          // Insert pass request
          var nowIST = formatDateToISTString(new Date());
          var isActualEmergency = (is_emergency === 'true' || is_emergency === true || is_emergency === '1' || is_emergency === 1) && student.emergency_pass_enabled === 1;
          var initialStatus = 'approved';
          var approvedBy = 'Roy';
          var approvedAt = nowIST;
          
          var insertSql = `
          INSERT INTO pass_requests 
          (uid, passtype, expected_out, expected_return, reason, emergency_contact, status, created_at, request_kind, is_emergency, approved_by, approved_at) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?)`;

          const formattedExpectedOut = formatDateTime(expectedOutDate, expectedOutTime);
          const formattedExpectedReturn = formatDateTime(expectedReturnDate, expectedReturnTime);

        connection.query(insertSql, [uid, passType, formattedExpectedOut, formattedExpectedReturn, reason, emergencyContact || null, initialStatus, nowIST, isActualEmergency ? 1 : 0, approvedBy, approvedAt], function (err, insertResult) {
          connection.release();
          if (err) {
            console.error('Error submitting pass request:', err);
            // If table doesn't exist, create it
            if (err.code === 'ER_NO_SUCH_TABLE') {
              req.flash('message', 'Pass request feature is being set up. Please contact admin.');
            } else if (err.code === 'ER_BAD_FIELD_ERROR') {
              // Backward compatibility if request_kind column isn't present
              req.flash('message', 'Please contact admin to update the pass request schema (missing request_kind).');
            } else {
              req.flash('message', 'Error submitting request');
            }
            return res.redirect('/student/requestpass');
          }

          if (isActualEmergency) {
            dbbconnection.getConnection(function (eErr, eConn) {
              if (eErr) {
                req.flash('message', 'Emergency pass request auto-approved successfully!');
                return res.redirect('/student/passhistory');
              }
              eConn.query("UPDATE studentdetails SET emergency_pass_enabled = 0, emergency_pass_enabled_by = NULL WHERE uid = ?", [uid], function() {
                eConn.release();
                req.flash('message', 'Emergency pass request auto-approved successfully!');
                return res.redirect('/student/passhistory');
              });
            });
          } else {
            triggerPassRequestWebhook({
              request_id: insertResult.insertId,
              uid: uid,
              student_name: student.sname || 'Student',
              pass_type: passType,
              reason: reason || 'Not specified',
              expected_out: formattedExpectedOut,
              expected_return: formattedExpectedReturn
            });
            res.redirect('/student/requestpass');
          }
        });
        });
      });
    });
  });
});

// Student Request: Convert City Pass -> Home Pass (requires admin approval)
app.post('/student/requestpass-convert', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const { expectedReturnDate, expectedReturnTime, reason } = req.body;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/requestpass');
    }

    // Allow conversion in two cases:
    // 1) Student currently has an ACTIVE City Pass
    // 2) Student has an approved City Pass request (but may not have scanned/activated yet)
    const activeSql = "SELECT * FROM log_details1 WHERE uid = ? AND status = 'ACTIVE' AND passtype IN ('City Pass', 'Home Pass') ORDER BY logid DESC LIMIT 1";
    connection.query(activeSql, [uid], function (aErr, aRows) {
      if (aErr) {
        connection.release();
        req.flash('message', 'Database error');
        return res.redirect('/student/requestpass');
      }

      const hasActive = (aRows && aRows.length > 0);

      function proceedWithConversion(originalRequestId, conversionEnabledBy) {
        const authorityName = conversionEnabledBy || 'Self-Service Conversion';
        const nowIST = formatDateToISTString(new Date());
        const formattedExpectedOut = nowIST;
        const formattedExpectedReturn = formatDateTime(expectedReturnDate, expectedReturnTime);
        const msg = 'Self-service conversion by student';

        // Insert approved Home Pass request
        const insertSql = `
          INSERT INTO pass_requests
          (uid, passtype, expected_out, expected_return, reason, emergency_contact, status, approved_by, approved_at, created_at, request_kind)
          VALUES (?, 'Home Pass', ?, ?, ?, NULL, 'approved', ?, ?, ?, 'convert')`;

        connection.query(insertSql, [uid, formattedExpectedOut, formattedExpectedReturn, msg, authorityName, nowIST, nowIST], function (iErr) {
          if (iErr) {
            connection.release();
            req.flash('message', 'Error creating converted pass request');
            return res.redirect('/student/requestpass');
          }

          // Immediately apply conversion to log_details1
          if (hasActive) {
            const active = aRows[0];
            const updPass = "UPDATE log_details1 SET passtype = 'Home Pass' WHERE logid = ?";
            connection.query(updPass, [active.logid], function (uErr) {
              if (uErr) {
                connection.release();
                req.flash('message', 'Converted, but failed to update active log');
                return res.redirect('/student/requestpass');
              }
              var notifSql1 = `
                INSERT INTO student_notifications (uid, type, title, message, created_at)
                VALUES (?, 'pass_converted', 'Pass Converted', ?, NOW())`;
              var notifMsg1 = `Your City Pass has been converted to Home Pass by ${authorityName}.`;
              connection.query(notifSql1, [uid, notifMsg1], function () {
                connection.release();
                req.flash('message', 'Your City Pass has been converted to Home Pass successfully.');
                return res.redirect('/student/requestpass');
              });
            });
          } else {
            // Convert latest incomplete log if it exists
            const selLatest = "SELECT logid, passtype, hostelintime FROM log_details1 WHERE uid = ? AND passtype = 'City Pass' ORDER BY logid DESC LIMIT 1";
            connection.query(selLatest, [uid], function (lErr, lRows) {
              if (lErr) {
                connection.release();
                req.flash('message', 'Converted, but failed to check latest log');
                return res.redirect('/student/requestpass');
              }
              if (lRows && lRows.length > 0 && (lRows[0].hostelintime === null || lRows[0].hostelintime === undefined || lRows[0].hostelintime === '')) {
                const updLatest = "UPDATE log_details1 SET passtype = 'Home Pass' WHERE logid = ?";
                connection.query(updLatest, [lRows[0].logid], function (u2Err) {
                  if (u2Err) {
                    connection.release();
                    req.flash('message', 'Converted, but failed to update latest log');
                    return res.redirect('/student/requestpass');
                  }
                  var notifSql0 = `
                    INSERT INTO student_notifications (uid, type, title, message, created_at)
                    VALUES (?, 'pass_converted', 'Pass Converted', ?, NOW())`;
                  var notifMsg0 = `Your City Pass has been converted to Home Pass by ${authorityName}.`;
                  connection.query(notifSql0, [uid, notifMsg0], function () {
                    connection.release();
                    req.flash('message', 'Your City Pass has been converted to Home Pass successfully.');
                    return res.redirect('/student/requestpass');
                  });
                });
              } else {
                // No log to update yet
                var notifSql0 = `
                  INSERT INTO student_notifications (uid, type, title, message, created_at)
                  VALUES (?, 'pass_converted', 'Pass Converted', ?, NOW())`;
                var notifMsg0 = `Your City Pass conversion to Home Pass has been applied by ${authorityName}. It will apply when your pass is activated at the gate scan.`;
                connection.query(notifSql0, [uid, notifMsg0], function () {
                  connection.release();
                  req.flash('message', 'Your City Pass has been converted to Home Pass successfully.');
                  return res.redirect('/student/requestpass');
                });
              }
            });
          }
        });
      }

      // We must check if the most recent approved City Pass has conversion_enabled = 1
      const convCheckSql = "SELECT requestid, passtype, conversion_enabled, conversion_enabled_by FROM pass_requests WHERE uid = ? AND status = 'approved' AND (request_kind != 'convert' OR request_kind IS NULL) ORDER BY approved_at DESC, requestid DESC LIMIT 1";
      connection.query(convCheckSql, [uid], function (cErr, cRows) {
        if (cErr) {
          connection.release();
          req.flash('message', 'Database error');
          return res.redirect('/student/requestpass');
        }

        if (!cRows || cRows.length === 0 || ((cRows[0].passtype || '') + '').trim().toLowerCase() !== 'city pass') {
          connection.release();
          req.flash('message', 'No approved City Pass found to convert');
          return res.redirect('/student/requestpass');
        }

        if (cRows[0].conversion_enabled != 1) {
          connection.release();
          req.flash('message', 'Conversion is not enabled for your pass. Please contact Fr. Roby.');
          return res.redirect('/student/requestpass');
        }

        if (hasActive) {
          const active = aRows[0];
          if (((active.passtype || '') + '').trim().toLowerCase() !== 'city pass') {
            connection.release();
            req.flash('message', 'Only City Pass can be converted to Home Pass');
            return res.redirect('/student/requestpass');
          }
        }

        return proceedWithConversion(cRows[0].requestid, cRows[0].conversion_enabled_by);
      });

    });
  });
});

// Cancel Pass Request
app.get('/student/cancelrequest/:id', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const requestId = req.params.id;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/requestpass');
    }

    var deleteSql = "DELETE FROM pass_requests WHERE requestid = ? AND uid = ? AND status IN ('pending', 'approved')";
    connection.query(deleteSql, [requestId, uid], function (err, result) {
      connection.release();
      if (err) {
        req.flash('message', 'Error canceling request');
      } else {
        req.flash('message', 'Request canceled successfully');
      }
      res.redirect('/student/requestpass');
    });
  });
});

// Student Notifications
app.get('/student/notifications', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const filter = req.query.filter;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/dashboard');
    }

    // Get student details
    var studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(studentSql, [uid], function (err, studentResult) {
      if (err || studentResult.length === 0) {
        connection.release();
        return res.redirect('/student/dashboard');
      }

      const student = studentResult[0];
      const studentYear = student.year || student.yr || student.syear || null;

      // Get recent passes for notifications
      var recentSql = "SELECT * FROM log_details1 WHERE uid = ? AND passtype IS NOT NULL ORDER BY logid DESC LIMIT 10";
      connection.query(recentSql, [uid], function (err, recentResult) {
        // Try to get notifications from table if exists
        var notifSql = "SELECT * FROM student_notifications WHERE uid = ? ORDER BY created_at DESC LIMIT 50";
        connection.query(notifSql, [uid], function (err, notifResult) {

          // Get announcements targeted to this student's year or all
          var announcementSql = "SELECT * FROM announcements WHERE is_active = 1 AND (target_year = 'all' OR target_year = ?) ORDER BY created_at DESC LIMIT 20";
          connection.query(announcementSql, [studentYear ? String(studentYear) : 'all'], function (err, announcementResult) {
            connection.release();

            attachStudentPhotoUrl(student);
            res.render(__dirname + '/views/student_notifications', {
              student: student,
              notifications: notifResult || [],
              recentPasses: recentResult || [],
              announcements: announcementResult || [],
              filter: filter || '',
              message: req.flash('message')
            });
          });
        });
      });
    });
  });
});

// Student Sick Leave Request
app.get('/student/sickleave', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/dashboard');
    }

    // Get student details
    var studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(studentSql, [uid], function (err, studentResult) {
      connection.release();
      if (err || studentResult.length === 0) {
        req.flash('message', 'Student not found');
        return res.redirect('/student/dashboard');
      }

      const student = studentResult[0];
      attachStudentPhotoUrl(student);

      res.render(__dirname + '/views/student_sickleave_request', {
        student: student,
        message: req.flash('message')
      });
    });
  });
});

// Student Submit Sick Leave Request
app.post('/student/sickleave', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const { illness, other_illness, details } = req.body;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/sickleave');
    }

    // Check if student is restricted
    var checkSql = "SELECT status FROM studentdetails WHERE uid = ?";
    connection.query(checkSql, [uid], function (err, checkResult) {
      if (err || checkResult.length === 0 || checkResult[0].status === 'Restrict') {
        connection.release();
        req.flash('message', 'Cannot submit request. Account may be restricted.');
        return res.redirect('/student/sickleave');
      }

      // Determine the illness value (use other_illness if provided, otherwise use illness)
      var finalIllness = other_illness && other_illness.trim() ? other_illness.trim() : (illness || 'Not specified');

      // Check for existing pending request today
      var checkPendingSql = "SELECT * FROM sick_leave_requests WHERE uid = ? AND status = 'pending' AND created_at LIKE CONCAT(?, '%')";
      var todayIST = formatDateToISTString(new Date()).substring(0, 10); // Get just the date part in IST
      connection.query(checkPendingSql, [uid, todayIST], function (err, pendingResult) {
        if (pendingResult && pendingResult.length > 0) {
          connection.release();
          req.flash('message', 'You already have a pending sick leave request for today');
          return res.redirect('/student/sickleave');
        }

        // Insert sick leave request
        var nowIST = formatDateToISTString(new Date());
        var insertSql = `
          INSERT INTO sick_leave_requests 
          (uid, illness, details, status, created_at) 
          VALUES (?, ?, ?, 'pending', ?)`;

        connection.query(insertSql, [uid, finalIllness, details || null, nowIST], function (err, insertResult) {
          connection.release();
          if (err) {
            // If table doesn't exist, create it
            if (err.code === 'ER_NO_SUCH_TABLE') {
              req.flash('message', 'Sick leave request feature is being set up. Please contact admin.');
            } else {
              req.flash('message', 'Error submitting request');
            }
            return res.redirect('/student/sickleave');
          }

          req.flash('message', 'Sick leave request submitted successfully! Awaiting approval.');
          res.redirect('/student/sickleave');
        });
      });
    });
  });
});

// Student Logout
app.get('/student/logout', function (req, res) {
  res.clearCookie('studentjwt');
  req.flash('message', 'Logged out successfully');
  res.redirect('/student/login');
});

// Student - View Own Sick Leave Requests
app.get('/student/sickleaverequests', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/dashboard');
    }

    var sql = `
      SELECT slr.requestid, slr.uid, slr.illness, slr.details, slr.status, 
            slr.approved_by, slr.rejection_reason,
            DATE_FORMAT(slr.created_at, '%Y-%m-%d %H:%i:%s') as created_at,
            DATE_FORMAT(slr.approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
            sd.sname 
      FROM sick_leave_requests slr
      LEFT JOIN studentdetails sd ON slr.uid = sd.uid
      WHERE slr.uid = ?
      ORDER BY slr.created_at DESC
    `;

    connection.query(sql, [uid], function (err, result) {
      connection.release();
      if (err) {
        req.flash('message', 'Error loading requests');
        return res.redirect('/student/dashboard');
      }

      res.render(__dirname + '/views/student_sickleaverequests', {
        requests: result,
        message: req.flash('message')
      });
    });
  });
});

// Student - Cancel Sick Leave Request
app.post('/student/cancelsickrequest/:id', verifyStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const requestId = req.params.id;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      req.flash('message', 'Database error');
      return res.redirect('/student/sickleaverequests');
    }

    // Check if request belongs to student and is pending
    var checkSql = "SELECT * FROM sick_leave_requests WHERE requestid = ? AND uid = ? AND status = 'pending'";
    connection.query(checkSql, [requestId, uid], function (err, checkResult) {
      if (err || checkResult.length === 0) {
        connection.release();
        req.flash('message', 'Request not found or cannot be cancelled');
        return res.redirect('/student/sickleaverequests');
      }

      // Update status to cancelled
      var updateSql = "UPDATE sick_leave_requests SET status = 'cancelled' WHERE requestid = ? AND uid = ?";
      connection.query(updateSql, [requestId, uid], function (err, updateResult) {
        connection.release();
        if (err) {
          req.flash('message', 'Error cancelling request');
          return res.redirect('/student/sickleaverequests');
        }

        req.flash('message', 'Sick leave request cancelled successfully');
        res.redirect('/student/sickleaverequests');
      });
    });
  });
});


// =====================================================
// ADMIN - PASS REQUEST MANAGEMENT
// =====================================================

app.get('/admin/emergency-requests', verifyjwt, function(req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/daterange');
      }

      let sql = "SELECT uid, sname, emergency_pass_enabled FROM studentdetails WHERE category = 'Hostel'";
      if (role === "BoysHostelAdmin") {
        sql += " AND gender = 'MALE'";
      } else if (role === "GirlsHostelAdmin") {
        sql += " AND gender = 'FEMALE'";
      }
      sql += " ORDER BY sname ASC";

      connection.query(sql, function (err, students) {
        connection.release();
        if (err) {
          req.flash('message', 'Failed to fetch students');
          return res.redirect('/daterange');
        }
        res.render(__dirname + '/views/emergencyrequests', { students: students || [], message: req.flash('message') });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

app.post('/admin/emergency-requests/toggle/:uid', express.json(), verifyjwt, function(req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
    }

    const uid = req.params.uid;
    const enable = req.body.enable ? 1 : 0;
    const adminuid = enable ? decode.adminuid : null;

    dbbconnection.getConnection(function (err, connection) {
      if (err) return res.status(500).json({ success: false, message: 'Database error' });

      connection.query("UPDATE studentdetails SET emergency_pass_enabled = ?, emergency_pass_enabled_by = ? WHERE uid = ?", [enable, adminuid, uid], function (err, result) {
        connection.release();
        if (err) return res.status(500).json({ success: false, message: 'Failed to update status' });
        res.json({ success: true, message: 'Updated successfully' });
      });
    });
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
});

// Admin - View Pass Requests
app.get('/admin/passrequests', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    const filterStatus = req.query.status || 'pending';
    const filterRestrictionStatus = req.query.restrictionStatus || '';
    const fromDate = req.query.fromDate || '';
    const toDate = req.query.toDate || '';
    const searchQuery = (req.query.q || '').trim();

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/daterange');
      }

      connection.query('SHOW COLUMNS FROM studentdetails', function (colErr, cols) {
        const fieldSet = new Set((cols || []).map(c => c.Field));
        const yearCandidates = ['year', 'yr', 'syear', 'stud_year', 'student_year', 'academic_year'];
        const yearCol = yearCandidates.find(c => fieldSet.has(c)) || null;
        const yearSelect = yearCol ? `sd.\`${yearCol}\` AS year,` : `NULL AS year,`;

        // Build query based on role - format dates consistently
        let baseSql = `
          SELECT pr.requestid, pr.uid, pr.passtype, pr.status, pr.reason, pr.emergency_contact, pr.conversion_enabled, pr.conversion_enabled_by, pr.request_kind, pr.is_emergency,
                CASE
                  WHEN pr.request_kind = 'convert' THEN 1
                  WHEN EXISTS (
                    SELECT 1
                    FROM pass_requests pr2
                    WHERE pr2.uid = pr.uid
                      AND pr2.status = 'approved'
                      AND pr2.request_kind = 'convert'
                      AND LOWER(COALESCE(pr2.passtype, '')) = 'home pass'
                      AND (
                        pr2.approved_at IS NULL
                        OR pr.approved_at IS NULL
                        OR pr2.approved_at >= pr.approved_at
                      )
                  ) THEN 1
                  ELSE 0
                END AS conversion_completed,
                DATE_FORMAT(pr.expected_out, '%Y-%m-%d %H:%i:%s') as expected_out,
                DATE_FORMAT(pr.expected_return, '%Y-%m-%d %H:%i:%s') as expected_return,
                DATE_FORMAT(pr.created_at, '%Y-%m-%d %H:%i:%s') as created_at,
                DATE_FORMAT(pr.approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
                pr.approved_by, pr.rejection_reason,
                    sd.sname, sd.dept, ${yearSelect} sd.mobileno, sd.gender, sd.status AS restriction_status, sd.path 
          FROM pass_requests pr 
          LEFT JOIN studentdetails sd ON pr.uid = sd.uid 
          WHERE 1=1`;

        let params = [];

        // Filter by gender based on admin role
        if (role === "BoysHostelAdmin") {
          baseSql += " AND sd.gender = 'MALE'";
        } else if (role === "GirlsHostelAdmin") {
          baseSql += " AND sd.gender = 'FEMALE'";
        }

        if (filterStatus) {
          baseSql += " AND pr.status = ?";
          params.push(filterStatus);
        }

        if (filterRestrictionStatus) {
          baseSql += " AND sd.status = ?";
          params.push(filterRestrictionStatus);
        }

        if (fromDate && toDate) {
          baseSql += " AND DATE(pr.created_at) BETWEEN ? AND ?";
          params.push(fromDate, toDate);
        } else {
          if (filterStatus === 'approved' || filterStatus === 'rejected') {
            baseSql += " AND DATE(pr.approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30'))";
          } else if (filterStatus === 'pending') {
            // No strict date filter for pending requests in the default view, 
            // since they are automatically pruned daily at 12 AM IST.
            // This ensures requests made between 12:00-05:30 AM IST (previous day in UTC) remain visible.
          } else {
            // Default "All Status" view: show only today's activity
            baseSql += " AND DATE(pr.created_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30'))";
          }
        }

        if (searchQuery) {
          baseSql += " AND (sd.sname LIKE ? OR pr.uid LIKE ?)";
          const likeTerm = `${searchQuery}%`;
          params.push(likeTerm, likeTerm);
        }

        baseSql += " ORDER BY pr.created_at DESC LIMIT 100";

        connection.query(baseSql, params, function (err, requests) {
          if (err) {
            console.error('Error fetching admin pass requests:', err);
            console.error('Admin pass request SQL:', baseSql);
            console.error('Admin pass request params:', params);
          }
          let statsSql = `
            SELECT 
              COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
              COUNT(CASE WHEN status = 'approved' AND DATE(approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) THEN 1 END) as approved,
              COUNT(CASE WHEN status = 'rejected' AND DATE(approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) THEN 1 END) as rejected,
              COUNT(CASE WHEN (status = 'pending' OR DATE(created_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30'))) THEN 1 END) as total
            FROM pass_requests`;

          // Apply same gender filtering to stats if needed
          if (role === "BoysHostelAdmin" || role === "GirlsHostelAdmin") {
            const gender = (role === "BoysHostelAdmin") ? 'MALE' : 'FEMALE';
            statsSql = `
              SELECT 
                COUNT(CASE WHEN pr.status = 'pending' THEN 1 END) as pending,
                COUNT(CASE WHEN pr.status = 'approved' AND DATE(pr.approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) THEN 1 END) as approved,
                COUNT(CASE WHEN pr.status = 'rejected' AND DATE(pr.approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) THEN 1 END) as rejected,
                COUNT(CASE WHEN (pr.status = 'pending' OR DATE(pr.created_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30'))) THEN 1 END) as total
              FROM pass_requests pr
              JOIN studentdetails sd ON pr.uid = sd.uid
              WHERE sd.gender = '${gender}'`;
          }

          connection.query(statsSql, function (statsErr, statsResult) {
            connection.release();
            if (statsErr) {
              console.error('Error fetching admin pass request stats:', statsErr);
            }
            if (requests && Array.isArray(requests)) {
              requests.forEach(attachStudentPhotoUrl);
            }
            res.render(__dirname + '/views/admin_passrequests', {
              requests: err ? [] : (requests || []),
              stats: statsResult[0] || { pending: 0, approved: 0, rejected: 0, total: 0 },
              filterStatus: filterStatus,
              filterRestrictionStatus: filterRestrictionStatus,
              fromDate: fromDate,
              toDate: toDate,
              searchQuery: searchQuery,
              message: req.flash('message')
            });
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Approve Pass Request
app.post('/admin/approverequest/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const requestId = req.params.id;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/passrequests');
      }

      // Get request details
      var getRequestSql = "SELECT * FROM pass_requests WHERE requestid = ? AND status = 'pending'";
      connection.query(getRequestSql, [requestId], function (err, requestResult) {
        if (err || requestResult.length === 0) {
          connection.release();
          req.flash('message', 'Request not found or already processed');
          return res.redirect(req.get('Referer') || '/admin/passrequests');
        }

        const request = requestResult[0];

        // Update request status
        var nowIST = formatDateToISTString(new Date());
        var updateSql = "UPDATE pass_requests SET status = 'approved', approved_by = ?, approved_at = ? WHERE requestid = ?";
        connection.query(updateSql, [adminName, nowIST, requestId], function (err, updateResult) {
          if (err) {
            connection.release();
            req.flash('message', 'Error approving request');
            return res.redirect(req.get('Referer') || '/admin/passrequests');
          }

          // If it's a conversion request, convert ACTIVE City Pass -> Home Pass immediately
          if (((request.request_kind || '') + '') === 'convert') {
            const selActive = "SELECT logid, passtype, hostelintime, status FROM log_details1 WHERE uid = ? AND status = 'ACTIVE' AND passtype IN ('City Pass', 'Home Pass') ORDER BY logid DESC LIMIT 1";
            return connection.query(selActive, [request.uid], function (sErr, sRows) {
              if (sErr) {
                connection.release();
                req.flash('message', 'Approved conversion request, but failed to check active pass');
                return res.redirect(req.get('Referer') || '/admin/passrequests');
              }
              if (!sRows || sRows.length === 0) {
                // No ACTIVE pass found. Try to convert the latest not-yet-completed City Pass log (if any).
                // This makes logs reflect Home Pass even if the student already scanned OUT and the row isn't ACTIVE.
                const selLatest = "SELECT logid, passtype, hostelintime FROM log_details1 WHERE uid = ? AND passtype = 'City Pass' ORDER BY logid DESC LIMIT 1";
                return connection.query(selLatest, [request.uid], function (lErr, lRows) {
                  if (lErr) {
                    connection.release();
                    req.flash('message', 'Conversion request approved, but failed to check latest log');
                    return res.redirect(req.get('Referer') || '/admin/passrequests');
                  }

                  if (lRows && lRows.length > 0 && (lRows[0].hostelintime === null || lRows[0].hostelintime === undefined || lRows[0].hostelintime === '')) {
                    const updLatest = "UPDATE log_details1 SET passtype = 'Home Pass' WHERE logid = ?";
                    return connection.query(updLatest, [lRows[0].logid], function (u2Err) {
                      if (u2Err) {
                        connection.release();
                        req.flash('message', 'Conversion request approved, but failed to update latest log');
                        return res.redirect(req.get('Referer') || '/admin/passrequests');
                      }
                      var notifSql0 = `
                        INSERT INTO student_notifications (uid, type, title, message, created_at)
                        VALUES (?, 'pass_converted', 'Pass Converted', ?, NOW())`;
                      var notifMsg0 = `Your City Pass has been converted to Home Pass by ${adminName}.`;
                      return connection.query(notifSql0, [request.uid, notifMsg0], function () {
                        connection.release();
                        req.flash('message', 'Conversion request approved and latest pass log updated to Home Pass.');
                        return res.redirect(req.get('Referer') || '/admin/passrequests');
                      });
                    });
                  }

                  // No log to update (student may not have scanned yet). Conversion should apply when activated via scan.
                  var notifSql0 = `
                    INSERT INTO student_notifications (uid, type, title, message, created_at)
                    VALUES (?, 'pass_converted', 'Pass Converted', ?, NOW())`;
                  var notifMsg0 = `Your City Pass conversion to Home Pass has been approved by ${adminName}. It will apply when your pass is activated at the gate scan.`;
                  return connection.query(notifSql0, [request.uid, notifMsg0], function () {
                    connection.release();
                    req.flash('message', 'Conversion request approved. It will apply on next gate scan activation.');
                    return res.redirect(req.get('Referer') || '/admin/passrequests');
                  });
                });
              }
              const active = sRows[0];
              if (((active.passtype || '') + '') !== 'City Pass') {
                connection.release();
                req.flash('message', 'Approved conversion request, but active pass is not City Pass');
                return res.redirect(req.get('Referer') || '/admin/passrequests');
              }
              const updPass = "UPDATE log_details1 SET passtype = 'Home Pass' WHERE logid = ?";
              connection.query(updPass, [active.logid], function (uErr) {
                if (uErr) {
                  connection.release();
                  req.flash('message', 'Failed to convert active pass');
                  return res.redirect(req.get('Referer') || '/admin/passrequests');
                }
                var notifSql = `
                  INSERT INTO student_notifications (uid, type, title, message, created_at)
                  VALUES (?, 'pass_converted', 'Pass Converted', ?, NOW())`;
                var notifMsg = `Your City Pass has been converted to Home Pass by ${adminName}.`;
                connection.query(notifSql, [request.uid, notifMsg], function () {
                  connection.release();
                  req.flash('message', 'Conversion request approved and active pass converted to Home Pass.');
                  return res.redirect(req.get('Referer') || '/admin/passrequests');
                });
              });
            });
          }

          // Normal request: don't create pass yet - it will be created when student scans at gate
          var notifSql = `
            INSERT INTO student_notifications (uid, type, title, message, created_at) 
            VALUES (?, 'pass_approved', 'Pass Request Approved', ?, NOW())`;
          var notifMsg = `Your ${request.passtype} request has been approved by ${adminName}. Please scan your ID at the gate to activate your pass.`;

          connection.query(notifSql, [request.uid, notifMsg], function (err, notifResult) {
            if (request.is_emergency) {
              connection.query("UPDATE studentdetails SET emergency_pass_enabled = 0, emergency_pass_enabled_by = NULL WHERE uid = ?", [request.uid], function() {
                connection.release();
                req.flash('message', 'Pass request approved. Student must scan ID at gate to activate pass.');
                res.redirect('/admin/passrequests');
              });
            } else {
              connection.release();
              req.flash('message', 'Pass request approved. Student must scan ID at gate to activate pass.');
              res.redirect('/admin/passrequests');
            }
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Reject Pass Request
app.post('/admin/rejectrequest/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const requestId = req.params.id;
    const rejectionReason = req.body.reason || 'No reason provided';

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/passrequests');
      }

      // Get request details for notification
      var getRequestSql = "SELECT * FROM pass_requests WHERE requestid = ? AND status = 'pending'";
      connection.query(getRequestSql, [requestId], function (err, requestResult) {
        if (err || requestResult.length === 0) {
          connection.release();
          req.flash('message', 'Request not found or already processed');
          return res.redirect(req.get('Referer') || '/admin/passrequests');
        }

        const request = requestResult[0];

        // Update request status
        var nowIST = formatDateToISTString(new Date());
        var updateSql = "UPDATE pass_requests SET status = 'rejected', approved_by = ?, approved_at = ?, rejection_reason = ? WHERE requestid = ?";
        connection.query(updateSql, [adminName, nowIST, rejectionReason, requestId], function (err, updateResult) {
          if (err) {
            connection.release();
            req.flash('message', 'Error rejecting request');
            return res.redirect(req.get('Referer') || '/admin/passrequests');
          }

          // Add notification for student
          var notifSql = `
            INSERT INTO student_notifications (uid, type, title, message, created_at) 
            VALUES (?, 'pass_rejected', 'Pass Request Rejected', ?, NOW())`;
          var notifMsg = `Your ${request.passtype} request has been rejected. Reason: ${rejectionReason}`;

          connection.query(notifSql, [request.uid, notifMsg], function (err, notifResult) {
            if (request.is_emergency) {
              connection.query("UPDATE studentdetails SET emergency_pass_enabled = 0, emergency_pass_enabled_by = NULL WHERE uid = ?", [request.uid], function() {
                connection.release();
                req.flash('message', 'Pass request rejected');
                res.redirect('/admin/passrequests');
              });
            } else {
              connection.release();
              req.flash('message', 'Pass request rejected');
              res.redirect('/admin/passrequests');
            }
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Reset Pass Request (Manual reset for individual requests)
app.post('/admin/resetrequest/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    const requestId = req.params.id;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/passrequests');
      }

      // Reset request to pending and clear approval/rejection info
      var resetSql = `
        UPDATE pass_requests 
        SET status = 'pending', 
            approved_by = NULL, 
            approved_at = NULL, 
            rejection_reason = NULL,
            updated_at = NOW()
        WHERE requestid = ?
      `;

      connection.query(resetSql, [requestId], function (err, result) {
        connection.release();
        if (err) {
          req.flash('message', 'Error resetting request');
          return res.redirect(req.get('Referer') || '/admin/passrequests');
        }

        if (result.affectedRows === 0) {
          req.flash('message', 'Request not found');
          return res.redirect('/admin/passrequests');
        }

        req.flash('message', 'Pass request reset to pending successfully');
        res.redirect('/admin/passrequests');
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Enable Conversion
app.post('/admin/enableconversion/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    const adminName = decode.adminname || decode.id || 'Admin';

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    const requestId = req.params.id;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect(req.get('Referer') || '/admin/passrequests');
      }

      var updateSql = "UPDATE pass_requests SET conversion_enabled = 1, conversion_enabled_by = ? WHERE requestid = ? AND status = 'approved' AND passtype = 'City Pass'";
      connection.query(updateSql, [adminName, requestId], function (err, result) {
        connection.release();
        if (err) {
          req.flash('message', 'Error enabling conversion');
          return res.redirect(req.get('Referer') || '/admin/passrequests');
        }
        if (result.affectedRows === 0) {
          req.flash('message', 'Request not found or not eligible for conversion');
          return res.redirect(req.get('Referer') || '/admin/passrequests');
        }
        req.flash('message', 'Conversion enabled successfully');
        res.redirect(req.get('Referer') || '/admin/passrequests');
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// =====================================================
// ADMIN - SICK LEAVE REQUEST MANAGEMENT
// =====================================================

// Admin - View Sick Leave Requests
app.get('/admin/sickleaverequests', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/daterange');
      }

      let sql = `
        SELECT slr.requestid, slr.uid, slr.illness, slr.details, slr.status, 
              slr.approved_by, slr.rejection_reason,
              DATE_FORMAT(slr.created_at, '%Y-%m-%d %H:%i:%s') as created_at,
              DATE_FORMAT(slr.approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
              sd.sname, sd.dept, sd.gender, sd.room_no
        FROM sick_leave_requests slr
        LEFT JOIN studentdetails sd ON slr.uid = sd.uid
        WHERE 1=1
      `;

      // Filter by gender based on admin role
      if (role === "BoysHostelAdmin") {
        sql += " AND sd.gender = 'MALE'";
      } else if (role === "GirlsHostelAdmin") {
        sql += " AND sd.gender = 'FEMALE'";
      }

      // Ensure we compare using IST calendar date to match how created_at is generated
      var todayISTDateOnly = formatDateToISTString(new Date()).slice(0, 10); // 'YYYY-MM-DD'
      sql += " AND date(slr.created_at)=date('" + todayISTDateOnly + "')";
      sql += " ORDER BY slr.created_at DESC";

      connection.query(sql, function (err, result) {
        connection.release();
        if (err) {
          req.flash('message', 'Error loading sick leave requests');
          return res.redirect('/daterange');
        }

        res.render(__dirname + '/views/admin_sickleaverequests', {
          requests: result,
          message: req.flash('message')
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Approve Sick Leave Request
app.post('/admin/sickleaverequest/approve/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const requestId = req.params.id;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/sickleaverequests');
      }

      // Check if request exists and is pending
      var checkSql = "SELECT * FROM sick_leave_requests WHERE requestid = ? AND status = 'pending'";
      connection.query(checkSql, [requestId], function (err, checkResult) {
        if (err || checkResult.length === 0) {
          connection.release();
          req.flash('message', 'Request not found or already processed');
          return res.redirect('/admin/sickleaverequests');
        }

        const request = checkResult[0];

        // Update request status to approved
        var nowIST = formatDateToISTString(new Date());
        var updateSql = "UPDATE sick_leave_requests SET status = 'approved', approved_by = ?, approved_at = ? WHERE requestid = ?";
        connection.query(updateSql, [adminName, nowIST, requestId], function (err, updateResult) {
          if (err) {
            connection.release();
            req.flash('message', 'Error approving request');
            return res.redirect('/admin/sickleaverequests');
          }

          // Insert into sick_leave_logs using IST timestamps
          var nowIST = formatDateToISTString(new Date());
          var logDateIST = nowIST.split(' ')[0];
          var logTimeIST = nowIST.split(' ')[1] + (nowIST.split(' ')[2] ? (' ' + nowIST.split(' ')[2]) : '');
          var logSql = `
            INSERT INTO sick_leave_logs (uid, illness, logdate, logtime, recorded_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `;
          connection.query(logSql, [request.uid, request.illness, logDateIST, logTimeIST, adminName, nowIST], function (err, logResult) {
            connection.release();
            if (err) {
              // Log error but don't fail the approval
              console.error('Error creating sick leave log:', err);
            }

            // Add notification for student
            var notifSql = `
              INSERT INTO student_notifications (uid, type, title, message, created_at) 
              VALUES (?, 'sick_leave_approved', 'Sick Leave Approved', ?, NOW())
            `;
            var notifMsg = `Your sick leave request for "${request.illness}" has been approved.`;

            dbbconnection.getConnection(function (err, notifConnection) {
              if (!err) {
                notifConnection.query(notifSql, [request.uid, notifMsg], function (err, notifResult) {
                  if (notifConnection) notifConnection.release();
                });
              }
            });

            req.flash('message', 'Sick leave request approved successfully');
            res.redirect('/admin/sickleaverequests');
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Reject Sick Leave Request
app.post('/admin/sickleaverequest/reject/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const requestId = req.params.id;
    const rejectionReason = req.body.reason || 'No reason provided';

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/sickleaverequests');
      }

      // Check if request exists and is pending
      var checkSql = "SELECT * FROM sick_leave_requests WHERE requestid = ? AND status = 'pending'";
      connection.query(checkSql, [requestId], function (err, checkResult) {
        if (err || checkResult.length === 0) {
          connection.release();
          req.flash('message', 'Request not found or already processed');
          return res.redirect('/admin/sickleaverequests');
        }

        const request = checkResult[0];

        // Update request status to rejected
        var nowIST = formatDateToISTString(new Date());
        var updateSql = "UPDATE sick_leave_requests SET status = 'rejected', approved_by = ?, approved_at = ?, rejection_reason = ? WHERE requestid = ?";
        connection.query(updateSql, [adminName, nowIST, rejectionReason, requestId], function (err, updateResult) {
          connection.release();
          if (err) {
            req.flash('message', 'Error rejecting request');
            return res.redirect('/admin/sickleaverequests');
          }

          // Add notification for student
          var notifSql = `
            INSERT INTO student_notifications (uid, type, title, message, created_at) 
            VALUES (?, 'sick_leave_rejected', 'Sick Leave Rejected', ?, NOW())
          `;
          var notifMsg = `Your sick leave request for "${request.illness}" has been rejected. Reason: ${rejectionReason}`;

          dbbconnection.getConnection(function (err, notifConnection) {
            if (!err) {
              notifConnection.query(notifSql, [request.uid, notifMsg], function (err, notifResult) {
                if (notifConnection) notifConnection.release();
              });
            }
          });

          req.flash('message', 'Sick leave request rejected');
          res.redirect('/admin/sickleaverequests');
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Edit Sick Leave Request (GET)
app.get('/admin/sickleaverequest/edit/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    const requestId = req.params.id;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/sickleaverequests');
      }

      var sql = `
        SELECT slr.*, sd.sname, sd.dept, sd.gender
        FROM sick_leave_requests slr
        LEFT JOIN studentdetails sd ON slr.uid = sd.uid
        WHERE slr.requestid = ?
      `;

      connection.query(sql, [requestId], function (err, result) {
        connection.release();
        if (err || result.length === 0) {
          req.flash('message', 'Request not found');
          return res.redirect('/admin/sickleaverequests');
        }

        res.render(__dirname + '/views/admin_edit_sickleave', {
          request: result[0],
          message: req.flash('message')
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Update Sick Leave Request (POST)
app.post('/admin/sickleaverequest/update/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    const requestId = req.params.id;
    const { uid, illness, details, status, logdate, logtime } = req.body;

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/sickleaverequests');
      }

      // Update the request
      // Use provided date/time or current date/time
      const requestDate = logdate || new Date().toISOString().split('T')[0];
      let requestTime = logtime || new Date().toTimeString().split(' ')[0].substring(0, 5);
      // Ensure time format is HH:MM:SS
      if (requestTime && !requestTime.includes(':')) {
        requestTime = requestTime.substring(0, 5) + ':00';
      } else if (requestTime && requestTime.split(':').length === 2) {
        requestTime = requestTime + ':00';
      } else if (!requestTime) {
        requestTime = new Date().toTimeString().split(' ')[0];
      }

      var updateSql = `
        UPDATE sick_leave_requests 
        SET uid = ?, illness = ?, details = ?, status = ?, 
            created_at = CONCAT(?, ' ', ?),
            updated_at = NOW()
        WHERE requestid = ?
      `;

      connection.query(updateSql, [uid, illness, details || null, status, requestDate, requestTime, requestId], function (err, updateResult) {
        if (err) {
          connection.release();
          req.flash('message', 'Error updating request: ' + err.message);
          return res.redirect('/admin/sickleaverequest/edit/' + requestId);
        }

        // If status is approved and logdate is provided, update or create log entry
        if (status === 'approved' && logdate) {
          var logCheckSql = "SELECT * FROM sick_leave_logs WHERE uid = ? AND logdate = ?";
          connection.query(logCheckSql, [uid, logdate], function (err, logCheckResult) {
            if (err) {
              connection.release();
              req.flash('message', 'Request updated but log update failed');
              return res.redirect('/admin/sickleaverequests');
            }

            if (logCheckResult.length > 0) {
              // Update existing log
              var updateLogSql = `
                UPDATE sick_leave_logs 
                SET illness = ?, logtime = ?, recorded_by = ?, created_at = CONCAT(?, ' ', ?)
                WHERE uid = ? AND logdate = ?
              `;
              connection.query(updateLogSql, [illness, logtime || null, adminName, requestDate, requestTime, uid, logdate], function (err, logUpdateResult) {
                connection.release();
                if (err) {
                  req.flash('message', 'Request updated but log update failed');
                } else {
                  req.flash('message', 'Sick leave request and log updated successfully');
                }
                res.redirect('/admin/sickleaverequests');
              });
            } else {
              // Create new log entry
              var insertLogSql = `
                INSERT INTO sick_leave_logs (uid, illness, logdate, logtime, recorded_by, created_at)
                VALUES (?, ?, ?, ?, ?, CONCAT(?, ' ', ?))
              `;
              connection.query(insertLogSql, [uid, illness, logdate, logtime || null, adminName, requestDate, requestTime], function (err, logInsertResult) {
                connection.release();
                if (err) {
                  req.flash('message', 'Request updated but log creation failed');
                } else {
                  req.flash('message', 'Sick leave request and log updated successfully');
                }
                res.redirect('/admin/sickleaverequests');
              });
            }
          });
        } else {
          // If status is changed from approved to something else, remove from logs if it exists
          if (status !== 'approved' && logdate) {
            var deleteLogSql = "DELETE FROM sick_leave_logs WHERE uid = ? AND logdate = ?";
            connection.query(deleteLogSql, [uid, logdate], function (err, delResult) {
              connection.release();
              req.flash('message', 'Sick leave request updated successfully');
              res.redirect('/admin/sickleaverequests');
            });
          } else {
            connection.release();
            req.flash('message', 'Sick leave request updated successfully');
            res.redirect('/admin/sickleaverequests');
          }
        }
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Create Backdated Entry (GET)
app.get('/admin/sickleave/create', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    res.render(__dirname + '/views/admin_create_sickleave', {
      message: req.flash('message')
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// Admin - Create Backdated Entry (POST)
app.post('/admin/sickleave/create', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const role = decode.role;

    if (role !== "SuperID" && role !== "BoysHostelAdmin" && role !== "GirlsHostelAdmin" && role !== "Hostelauthority") {
      req.flash('message', 'Unauthorized access');
      return res.redirect('/loginpanel');
    }

    const { uid, illness, details, logdate, logtime, create_request } = req.body;

    if (!uid || !illness || !logdate) {
      req.flash('message', 'UID, illness, and date are required');
      return res.redirect('/admin/sickleave/create');
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/sickleave/create');
      }

      // Check if student exists
      var checkStudentSql = "SELECT * FROM studentdetails WHERE uid = ?";
      connection.query(checkStudentSql, [uid], function (err, studentResult) {
        if (err || studentResult.length === 0) {
          connection.release();
          req.flash('message', 'Student not found with UID: ' + uid);
          return res.redirect('/admin/sickleave/create');
        }

        // Format time properly
        const requestDateTimeStr = formatDateToISTString(new Date(`${logdate}T${logtime || '00:00:00'}`)); // Convert logdate and logtime to IST string
        const approvedAtIST = formatDateToISTString(new Date()); // Current time in IST

        // Create request if requested
        if (create_request === 'yes') {
          var insertRequestSql = `
            INSERT INTO sick_leave_requests (uid, illness, details, status, approved_by, approved_at, created_at)
            VALUES (?, ?, ?, 'approved', ?, ?, ?)`;
          connection.query(insertRequestSql, [uid, illness, details || null, adminName, approvedAtIST, requestDateTimeStr], function (err, requestResult) {
            if (err) {
              connection.release();
              req.flash('message', 'Error creating request: ' + err.message);
              return res.redirect('/admin/sickleave/create');
            }

            // Create log entry
            var insertLogSql = `
              INSERT INTO sick_leave_logs (uid, illness, logdate, logtime, recorded_by, created_at)
              VALUES (?, ?, ?, ?, ?, ?)
            `;
            connection.query(insertLogSql, [uid, illness, logdate, logtime || null, adminName, requestDateTime], function (err, logResult) {
              connection.release();
              if (err) {
                req.flash('message', 'Request created but log creation failed: ' + err.message);
              } else {
                req.flash('message', 'Backdated sick leave entry created successfully');
              }
              res.redirect('/admin/sickleaverequests');
            });
          });
        } else {
          // Only create log entry
          var insertLogSql = `
            INSERT INTO sick_leave_logs (uid, illness, logdate, logtime, recorded_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `;
          connection.query(insertLogSql, [uid, illness, logdate, logtime || null, adminName, requestDateTime], function (err, logResult) {
            connection.release();
            if (err) {
              req.flash('message', 'Error creating log entry: ' + err.message);
              return res.redirect('/admin/sickleave/create');
            }

            req.flash('message', 'Backdated sick leave log entry created successfully');
            res.redirect('/sickleavelogs');
          });
        }
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Session expired');
    return res.redirect('/loginpanel');
  }
});

// =====================================================
// ADMIN - ROOM BOOKING MANAGEMENT
// =====================================================

// Admin - Get All Room Bookings
app.get('/api/admin/bookings', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    // Only SuperID or Hostel authority can view all bookings
    if (role !== "SuperID" && role !== "BoysHostelAdmin") {
      return res.status(403).json({ message: 'Unauthorized access' });
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Database error' });
      }

      const sql = `
        SELECT 
            b.id AS booking_id,
            b.booking_date,
            b.total_price,
            b.status AS booking_status,
            b.payment_status,
            b.created_at AS booking_created_at,
            r.name AS room_name,
            r.block,
            r.floor,
            r.room_type,
            sd.uid AS student_uid,
            sd.sname AS student_name,
            sd.mobileno AS student_mobile
        FROM 
            bookings b
        JOIN 
            rooms r ON b.room_id = r.id
        JOIN 
            studentdetails sd ON b.student_id = sd.uid
        ORDER BY 
            b.created_at DESC
      `;

      connection.query(sql, function (err, results) {
        connection.release();
        if (err) {
          console.error('Error fetching admin bookings:', err);
          return res.status(500).json({ message: 'Error fetching bookings' });
        }
        res.json(results);
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    return res.status(401).json({ message: 'Session expired or unauthorized' });
  }
});

// Admin - Confirm Payment for a Booking
app.post('/api/admin/bookings/:id/confirm_payment', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const bookingId = req.params.id;

    // Only SuperID or Hostel authority can confirm payment
    if (decode.role !== "SuperID" && decode.role !== "Hostelauthority") {
      return res.status(403).json({ message: 'Unauthorized access' });
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Database error' });
      }

      const updateSql = "UPDATE bookings SET payment_status = 'paid' WHERE id = ? AND payment_status = 'pending'";
      connection.query(updateSql, [bookingId], function (err, result) {
        connection.release();
        if (err) {
          console.error('Error confirming payment:', err);
          return res.status(500).json({ message: 'Error confirming payment' });
        }
        if (result.affectedRows === 0) {
          return res.status(404).json({ message: 'Booking not found or payment already confirmed' });
        }
        res.json({ message: 'Payment confirmed successfully' });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    return res.status(401).json({ message: 'Session expired or unauthorized' });
  }
});

// Admin - Approve a Booking
app.post('/api/admin/bookings/:id/approve', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const bookingId = req.params.id;

    // Only SuperID or Hostel authority can approve bookings
    if (decode.role !== "SuperID" && decode.role !== "Hostelauthority") {
      return res.status(403).json({ message: 'Unauthorized access' });
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Database error' });
      }

      // Ensure payment is paid before approving
      const checkPaymentSql = "SELECT payment_status, student_id, room_id, booking_date FROM bookings WHERE id = ?";
      connection.query(checkPaymentSql, [bookingId], function (err, bookingInfo) {
        if (err || bookingInfo.length === 0) {
          connection.release();
          return res.status(404).json({ message: 'Booking not found' });
        }

        if (bookingInfo[0].payment_status !== 'paid') {
          connection.release();
          return res.status(400).json({ message: 'Payment not confirmed for this booking' });
        }

        const studentUid = bookingInfo[0].student_id;
        const roomId = bookingInfo[0].room_id;
        const bookingDate = bookingInfo[0].booking_date;

        // Update booking status to confirmed
        const updateSql = "UPDATE bookings SET status = 'confirmed' WHERE id = ? AND status = 'on_hold'";
        connection.query(updateSql, [bookingId], function (err, result) {
          if (err) {
            connection.release();
            console.error('Error approving booking:', err);
            return res.status(500).json({ message: 'Error approving booking' });
          }
          if (result.affectedRows === 0) {
            connection.release();
            return res.status(404).json({ message: 'Booking not found or already approved/cancelled' });
          }

          // Add notification for student
          const notifMsg = `Your room booking for room ${roomId} on ${bookingDate.toLocaleDateString()} has been confirmed!`;
          const notifSql = "INSERT INTO student_notifications (uid, type, title, message, created_at) VALUES (?, ?, ?, ?, NOW())";
          connection.query(notifSql, [studentUid, 'room_booking_confirmed', 'Room Booking Confirmed', notifMsg], function (err, notifResult) {
            connection.release();
            if (err) {
              console.error('Error sending notification:', err);
            }
            res.json({ message: 'Booking approved successfully' });
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    return res.status(401).json({ message: 'Session expired or unauthorized' });
  }
});

// Admin - Reject/Cancel a Booking
app.post('/api/admin/bookings/:id/reject', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const adminName = decode.adminname;
    const bookingId = req.params.id;
    const rejectionReason = req.body.reason || 'No reason provided';

    // Only SuperID or Hostel authority can reject/cancel bookings
    if (decode.role !== "SuperID" && decode.role !== "Hostelauthority") {
      return res.status(403).json({ message: 'Unauthorized access' });
    }

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ message: 'Database error' });
      }

      // Update booking status to cancelled
      const updateSql = "UPDATE bookings SET status = 'cancelled', rejection_reason = ? WHERE id = ? AND status IN ('pending', 'on_hold', 'confirmed')";
      connection.query(updateSql, [rejectionReason, bookingId], function (err, result) {
        if (err) {
          connection.release();
          console.error('Error rejecting booking:', err);
          return res.status(500).json({ message: 'Error rejecting booking' });
        }
        if (result.affectedRows === 0) {
          connection.release();
          return res.status(404).json({ message: 'Booking not found or already cancelled' });
        }

        // Get student UID for notification
        const getStudentSql = "SELECT student_id, room_id, booking_date FROM bookings WHERE id = ?";
        connection.query(getStudentSql, [bookingId], function (err, bookingInfo) {
          connection.release();
          if (err || bookingInfo.length === 0) {
            console.error('Error fetching student ID for notification:', err);
            return res.json({ message: 'Booking rejected, but notification failed' });
          }
          const studentUid = bookingInfo[0].student_id;
          const roomId = bookingInfo[0].room_id;
          const bookingDate = bookingInfo[0].booking_date;

          // Add notification for student
          const notifMsg = `Your room booking for room ${roomId} on ${bookingDate.toLocaleDateString()} has been rejected. Reason: ${rejectionReason}`; // Use `roomId` instead of `room_name`
          const notifSql = "INSERT INTO student_notifications (uid, type, title, message, created_at) VALUES (?, ?, ?, ?, NOW())";
          connection.query(notifSql, [studentUid, 'room_booking_rejected', 'Room Booking Rejected', notifMsg], function (err, notifResult) {
            if (err) {
              console.error('Error sending notification:', err);
            }
            res.json({ message: 'Booking rejected successfully' });
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie("jwt");
    return res.status(401).json({ message: 'Session expired or unauthorized' });
  }
});

// 1. Permanent Grid View with Auto-Status Sync
// ==========================================
// ATTENDANCE GRID & ROOM ALLOCATION MODULE
// ==========================================

/**
 * 1. Main Attendance Grid Route
 * Fetches the permanent building layout and syncs with live student data
 */
app.get('/attendance', verifyjwt, function (req, res) {
  // Middleware provides user data via req.decode
  if (!req.decode || !req.decode.role) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
  const role = req.decode.role;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error("DB Connection Error:", err);
      return res.redirect('/loginpanel');
    }

    // Attendance should reflect the live room assignment stored on studentdetails.
    // room_no / bed_no are synchronized from approved room bookings, so the grid
    // should use that as the source of truth.
    const currentOccupancySql = `
            SELECT DISTINCT
                s.uid,
                s.sname,
                s.path,
                s.dept,
                s.year,
                s.parentnumber,
                s.mess_type,
                s.other3,
                s.gender,
                s.room_no AS room_name,
                s.block,
                vg.floor,
                s.bed_no AS bed_letter
            FROM studentdetails s
            INNER JOIN v_room_grid vg
                ON vg.block = s.block
               AND vg.room_name = s.room_no
               AND vg.bed_letter = s.bed_no
            WHERE s.category = 'Hostel'
              AND s.room_no IS NOT NULL AND TRIM(COALESCE(s.room_no, '')) <> ''
              AND s.bed_no IS NOT NULL AND TRIM(COALESCE(s.bed_no, '')) <> ''
              AND LOWER(COALESCE(s.status, '')) <> 'restrict'
        `;

    // Seed daily attendance rows for today so logs are saved on a daily basis.
    // This requires a UNIQUE KEY on (uid, date) in daily_attendance.
    const seedDailySql = `
            INSERT IGNORE INTO daily_attendance (uid, date, status, marked_by)
            SELECT DISTINCT cur.uid, CURDATE(), 'Pending', 'SYSTEM'
            FROM (${currentOccupancySql}) cur
        `;

    // Current occupancy grid:
    // 1. vg: permanent room/bed layout
    // 2. cur: students whose studentdetails room_no / bed_no match a grid slot
    // 3. CASE: syncs sick leave and home pass status automatically today
    let sql = `
              SELECT 
                vg.room_name, vg.block, vg.floor, vg.bed_letter,
                cur.uid, cur.sname, cur.path, cur.dept, cur.year, cur.parentnumber, cur.mess_type, cur.other3,
                CASE 
                    WHEN cur.uid IS NULL THEN NULL
                    WHEN EXISTS (SELECT 1 FROM sick_leave_logs sl WHERE sl.uid = cur.uid AND sl.logdate = CURDATE()) THEN 'Sick'
                    WHEN EXISTS (SELECT 1 FROM daily_attendance da WHERE da.uid = cur.uid AND da.date = CURDATE() AND da.status IN ('Present', 'Absent')) 
                        THEN (SELECT status FROM daily_attendance da WHERE da.uid = cur.uid AND da.date = CURDATE())
                    WHEN EXISTS (SELECT 1 FROM log_details1 l WHERE l.uid = cur.uid AND l.status = 'ACTIVE') THEN 'Home'
                    ELSE IFNULL((SELECT status FROM daily_attendance da WHERE da.uid = cur.uid AND da.date = CURDATE()), 'Pending')
                END AS today_status
            FROM v_room_grid vg
            LEFT JOIN (${currentOccupancySql}) cur ON vg.block = cur.block COLLATE utf8mb4_unicode_ci AND vg.room_name = cur.room_name COLLATE utf8mb4_unicode_ci AND vg.bed_letter = cur.bed_letter COLLATE utf8mb4_unicode_ci
            WHERE 1=1
        `;

    // Role-based filtering:
    // Do not hardcode blocks here; allow UI tabs to control what is shown.

    sql += " ORDER BY vg.room_name ASC, vg.bed_letter ASC";

    connection.query(seedDailySql, function (seedErr) {
      if (seedErr) {
        // Do not block page load if seeding fails
        console.error('daily_attendance seed failed:', seedErr);
      }

      // Recent daily summary (last 14 days)
      let genderFilterSql = '';
      const summaryParams = [];
      if (role === 'BoysHostelAdmin') {
        genderFilterSql = ' AND LOWER(cur.gender) = ?';
        summaryParams.push('male');
      } else if (role === 'GirlsHostelAdmin') {
        genderFilterSql = ' AND LOWER(cur.gender) = ?';
        summaryParams.push('female');
      }

      const dailySummarySql = `
                SELECT 
                    da.date as date,
                    COUNT(*) as total,
                    SUM(CASE WHEN da.status = 'Present' THEN 1 ELSE 0 END) as present,
                    SUM(CASE WHEN da.status = 'Absent' THEN 1 ELSE 0 END) as absent,
                    SUM(CASE WHEN da.status = 'Home' THEN 1 ELSE 0 END) as home,
                    SUM(CASE WHEN da.status = 'Sick' THEN 1 ELSE 0 END) as sick,
                    SUM(CASE WHEN da.status = 'Pending' THEN 1 ELSE 0 END) as pending
                FROM daily_attendance da
                JOIN (${currentOccupancySql}) cur ON cur.uid = da.uid
                WHERE da.date >= DATE_SUB(CURDATE(), INTERVAL 14 DAY)
                  ${genderFilterSql}
                GROUP BY da.date
                ORDER BY da.date DESC
            `;

      connection.query(dailySummarySql, summaryParams, function (sumErr, dailySummaryRows) {
        if (sumErr) {
          console.error('dailySummary query failed:', sumErr);
          dailySummaryRows = [];
        }

        connection.query(sql, function (err, result) {
          if (err) {
            connection.release();
            throw err;
          }

          // Calculate Statistics for the Sidebar
          const activeRows = (result || []).filter(x => x.uid);
          const activeUids = new Set(activeRows.map(x => x.uid));
          const stats = {
            Total: activeUids.size,
            InHostel: activeRows.filter(x => x.today_status === 'Present').length,
            AtCollege: activeRows.filter(x => x.today_status === 'Absent').length,
            Home: activeRows.filter(x => x.today_status === 'Home').length
          };

          connection.release();
          res.render(__dirname + '/views/attendance', {
            serverData: result,
            stats: stats,
            dailySummary: dailySummaryRows,
            role: role,
            message: req.flash('message')
          });
        });
      });
    });
  });
});

/**
 * 2. Search API for Allocation
 * Returns students who are unallocated: no (room_no, bed_no) pair in v_room_grid.
 * Same logic as studentsupdatehostel: allocated = has a bed in the grid; unallocated = rest.
 * Fallback: if room_no/bed_no columns missing, return all Hostel students.
 */
app.get('/api/search-unallocated', verifyjwt, (req, res) => {
  const term = (req.query.term || '').trim();
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      res.setHeader('Content-Type', 'application/json');
      return res.status(500).json([]);
    }
    const send = function (results) {
      res.setHeader('Content-Type', 'application/json');
      res.json(Array.isArray(results) ? results : []);
    };
    // Unallocated = Hostel students for whom no row in v_room_grid matches (room_no, bed_no)
    let sql = `
            SELECT s.uid, s.sname 
            FROM studentdetails s 
            WHERE (
                s.category = 'Hostel' 
                OR s.category IS NULL 
                OR TRIM(COALESCE(s.category, '')) = ''
                OR LOWER(TRIM(COALESCE(s.category, ''))) = 'hostel'
            )
            AND NOT EXISTS (
                SELECT 1 FROM v_room_grid vg 
                WHERE vg.room_name = s.room_no AND vg.bed_letter = s.bed_no
            )
        `;
    const params = [];
    if (term) {
      sql += " AND (s.uid LIKE ? OR s.sname LIKE ?)";
      params.push('%' + term + '%', '%' + term + '%');
    }
    sql += " ORDER BY s.sname ASC LIMIT 500";

    connection.query(sql, params, (err, results) => {
      if (err) {
        console.error('search-unallocated:', err);
        // If room_no/bed_no or v_room_grid missing, fallback: all Hostel students (treat all as unallocated)
        const fallbackSql = `
                    SELECT uid, sname FROM studentdetails 
                    WHERE (category = 'Hostel' OR category IS NULL OR TRIM(COALESCE(category, '')) = '')
                    ${term ? ' AND (uid LIKE ? OR sname LIKE ?)' : ''}
                    ORDER BY sname ASC LIMIT 500
                `;
        const fallbackParams = term ? ['%' + term + '%', '%' + term + '%'] : [];
        connection.query(fallbackSql, fallbackParams, (err2, fallbackResults) => {
          connection.release();
          if (err2) {
            console.error('search-unallocated fallback:', err2);
            return send([]);
          }
          return send(fallbackResults);
        });
        return;
      }
      connection.release();
      send(results);
    });
  });
});

/**
 * 3. Assignment / De-allocation API
 * Links a student to a room/bed constant or clears it (if room_no is null)
 */
app.post('/api/assign-room', verifyjwt, (req, res) => {
  const { uid, room_no, bed_no } = req.body;

  if (!uid) return res.status(400).json({ success: false, message: "UID is required" });

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false });

    const sql = "UPDATE studentdetails SET room_no = ?, bed_no = ?, other3 = NULL WHERE uid = ?";
    connection.query(sql, [room_no, bed_no, uid], (err, result) => {
      connection.release();
      if (err) return res.json({ success: false, message: "Database Error" });
      res.json({ success: true });
    });
  });
});

/**
 * 4. Manual Attendance API
 * Marks Present/Absent with a duplicate key check for today's date
 */
app.post('/api/mark-attendance', verifyjwt, (req, res) => {
  const { uid, status } = req.body;
  const markedBy = req.decode.adminname;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false });

    const sql = `
            INSERT INTO daily_attendance (uid, date, status, marked_by) 
            VALUES (?, CURDATE(), ?, ?) 
            ON DUPLICATE KEY UPDATE status = ?, marked_by = ?`;

    connection.query(sql, [uid, status, markedBy, status, markedBy], (err) => {
      connection.release();
      if (err) return res.status(500).json({ success: false });
      res.json({ success: true });
    });
  });
});
// =============================================================
// END: ATTENDANCE MODULE
// =============================================================
// ==========================================
// 1. GLOBAL ANALYTICS DASHBOARD (REMOVING STATUS, ADDING BLOCK BREAKDOWN)
// ==========================================
app.get('/analytics/global', verifyjwt, async function (req, res) {
  try {
    const tokenadmin = req.cookies.jwt;
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;

    dbbconnection.getConnection(async (err, connection) => {
      if (err) { console.error("DB Connection Error:", err); return res.redirect('/loginpanel'); }

      const queryAsync = (sql, args) => new Promise((resolve, reject) => {
          connection.query(sql, args, (err, rows) => {
              if (err) reject(err);
              else resolve(rows);
          });
      });

      try {
        let sql = "Select count(*) as totalstudent from studentdetails where category='Hostel'";
        let sql2 = "SELECT count(*) as insidehostel FROM log_details1 AS log JOIN studentdetails AS stu ON stu.uid = log.uid WHERE log.indatetime IS NOT NULL and stu.category='Hostel'";
        let sql3 = "select count(*) as gateout from log_details1 as log join studentdetails as stu on stu.uid=log.uid where outdatetime IS NOT NULL and DATE(outdatetime) = CURDATE() and stu.category='Hostel'";
        let sql4 = "select count(*) as hostelout from log_details1 as log join studentdetails as stu on stu.uid=log.uid where DATE(COALESCE(approvaldt, outdatetime)) = CURDATE() and stu.category='Hostel'";
        let sql5 = "select count(*) as citypass from log_details1 as log join studentdetails as stu where stu.uid=log.uid and passtype='City Pass' and outdatetime IS NOT NULL and DATE(outdatetime) = CURDATE() and stu.category='Hostel'";
        let sql6 = "select count(*) as homepass from log_details1 as log join studentdetails as stu where stu.uid=log.uid and passtype='Home Pass' and outdatetime IS NOT NULL and DATE(outdatetime) = CURDATE() and stu.category='Hostel'";
        let sql7 = "select count(DISTINCT log.uid) as vegOut from log_details1 as log join studentdetails as stu on stu.uid=log.uid where stu.mess_type='Veg' and outdatetime IS NOT NULL and hostelintime IS NULL and log.status='ACTIVE' and stu.category='Hostel'";
        let sql8 = "select count(DISTINCT log.uid) as nonVegOut from log_details1 as log join studentdetails as stu on stu.uid=log.uid where stu.mess_type='Non-Veg' and outdatetime IS NOT NULL and hostelintime IS NULL and log.status='ACTIVE' and stu.category='Hostel'";
        let sql9 = "select count(*) as reqHomePass from pass_requests as pr join studentdetails as stu on pr.uid=stu.uid where pr.passtype='Home Pass' and pr.status='approved' and DATE(pr.approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) and stu.category='Hostel'";
        let sql10 = "select count(*) as reqCityPass from pass_requests as pr join studentdetails as stu on pr.uid=stu.uid where pr.passtype='City Pass' and pr.status='approved' and DATE(pr.approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) and stu.category='Hostel'";
        let sql11 = "select count(DISTINCT log.uid) as currentlyOut from log_details1 as log join studentdetails as stu on stu.uid=log.uid where log.outdatetime IS NOT NULL and log.hostelintime IS NULL and log.status='ACTIVE' and stu.category='Hostel'";
        let totalVegSql = "SELECT COUNT(*) as count FROM studentdetails WHERE mess_type='Veg' AND category='Hostel'";
        let totalNonVegSql = "SELECT COUNT(*) as count FROM studentdetails WHERE mess_type='Non-Veg' AND category='Hostel'";

        if (role == "BoysHostelAdmin" || role == "Hostelauthority") {
            sql += " and gender='MALE'";
            sql2 += " and stu.gender='MALE'";
            sql3 += " and stu.gender='MALE'";
            sql4 += " and stu.gender='MALE'";
            sql5 += " and stu.gender='MALE'";
            sql6 += " and stu.gender='MALE'";
            sql7 += " and stu.gender='MALE'";
            sql8 += " and stu.gender='MALE'";
            sql9 += " and stu.gender='MALE'";
            sql10 += " and stu.gender='MALE'";
            sql11 += " and stu.gender='MALE'";
            totalVegSql += " AND gender='MALE'";
            totalNonVegSql += " AND gender='MALE'";
        } else if (role == "GirlsHostelAdmin") {
            sql += " and gender='FEMALE'";
            sql2 += " and stu.gender='FEMALE'";
            sql3 += " and stu.gender='FEMALE'";
            sql4 += " and stu.gender='FEMALE'";
            sql5 += " and stu.gender='FEMALE'";
            sql6 += " and stu.gender='FEMALE'";
            sql7 += " and stu.gender='FEMALE'";
            sql8 += " and stu.gender='FEMALE'";
            sql9 += " and stu.gender='FEMALE'";
            sql10 += " and stu.gender='FEMALE'";
            sql11 += " and stu.gender='FEMALE'";
            totalVegSql += " AND gender='FEMALE'";
            totalNonVegSql += " AND gender='FEMALE'";
        }

        const [rTotal, rInside, rGateOut, rHostelOut, rCityPass, rHomePass, rVegOut, rNonVegOut, rTotalVeg, rTotalNonVeg, rReqHome, rReqCity, rCurrentlyOut] = await Promise.all([
            queryAsync(sql), queryAsync(sql2), queryAsync(sql3), queryAsync(sql4), queryAsync(sql5), 
            queryAsync(sql6), queryAsync(sql7), queryAsync(sql8), queryAsync(totalVegSql), queryAsync(totalNonVegSql),
            queryAsync(sql9), queryAsync(sql10), queryAsync(sql11)
        ]);

        const currentlyOut = rCurrentlyOut[0].currentlyOut || 0;
        const reportsResult = {
            totalStudents: rTotal[0].totalstudent,
            insideHostel: rInside[0].insidehostel,
            gateOut: rGateOut[0].gateout,
            hostelOut: rHostelOut[0].hostelout,
            citypass: rCityPass[0].citypass,
            homepass: rHomePass[0].homepass,
            vegOut: rVegOut[0].vegOut,
            nonVegOut: rNonVegOut[0].nonVegOut,
            reqHomePass: rReqHome[0].reqHomePass,
            reqCityPass: rReqCity[0].reqCityPass,
            currentlyOut: currentlyOut
        };

        const totalVeg = rTotalVeg[0].count || 0;
        const totalNonVeg = rTotalNonVeg[0].count || 0;
        const vegPresent = Math.max(0, totalVeg - (reportsResult.vegOut || 0));
        const nonVegPresent = Math.max(0, totalNonVeg - (reportsResult.nonVegOut || 0));
        reportsResult.totalPresent = vegPresent + nonVegPresent;
        const todayStr = new Date().toISOString().slice(0, 10);
        const reportsLogs = [{ date: todayStr, veg: vegPresent, nonveg: nonVegPresent }];

        const sqlAttendance = `
                SELECT 
                    COUNT(s.uid) as Total,
                    SUM(CASE WHEN d.status = 'Present' THEN 1 ELSE 0 END) as Present,
                    SUM(CASE WHEN d.status = 'Absent' THEN 1 ELSE 0 END) as Absent,
                    SUM(CASE WHEN d.status = 'Home' THEN 1 ELSE 0 END) as Home
                FROM studentdetails s
                LEFT JOIN daily_attendance d ON s.uid = d.uid AND d.date = CURDATE()
                WHERE s.category='Hostel'`;

        const sqlMess = `
                SELECT mess_type, COUNT(*) as count 
                FROM studentdetails WHERE category='Hostel' GROUP BY mess_type`;

        const sqlBlock = `
                SELECT block, COUNT(*) as count 
                FROM studentdetails WHERE category='Hostel' GROUP BY block ORDER BY block ASC`;

        const sqlYear = `
                SELECT year, COUNT(*) as count 
                FROM studentdetails WHERE category='Hostel' GROUP BY year ORDER BY year ASC`;

        const [resAttendance, resMess, resBlock, resYear] = await Promise.all([
            queryAsync(sqlAttendance), queryAsync(sqlMess), queryAsync(sqlBlock), queryAsync(sqlYear)
        ]);
        
        connection.release();

        const stats = {
          attendance: resAttendance[0],
          mess: resMess,
          block: resBlock,
          year: resYear,
          citypass: reportsResult.citypass,
          homepass: reportsResult.homepass,
          todayCityPass: reportsResult.citypass,
          todayHomePass: reportsResult.homepass,
          reqHomePass: reportsResult.reqHomePass,
          reqCityPass: reportsResult.reqCityPass
        };

        res.render(__dirname + '/views/analytics', {
          stats: stats,
          result: reportsResult,
          logs: reportsLogs,
          role: role,
          message: req.flash('message')
        });

      } catch (err) {
        connection.release();
        console.error("DB Query Error:", err);
        res.status(500).send("DB Error");
      }
    });
  } catch (err) {
    console.error("Auth/Token Error:", err);
    res.redirect('/loginpanel');
  }
});

app.get('/kitchen', verifyjwt, function (req, res) {
  return res.redirect('/kitchen/mess');
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "KitchenAdmin") {
      dbbconnection.getConnection(function (err, connection) {
        if (err) {
          console.log(err);
          req.flash('message', 'Database connection error');
          return res.render(__dirname + '/views/kitchen', { message: req.flash('message'), vegCount: 0, nonVegCount: 0 });
        }
        // Calculate present students using: Total - Out logic
        var totalVegSql = "SELECT COUNT(*) as count FROM studentdetails WHERE mess_type='Veg' AND category='Hostel'";
        var totalNonVegSql = "SELECT COUNT(*) as count FROM studentdetails WHERE mess_type='Non-Veg' AND category='Hostel'";
        var vegOutSql = "SELECT COUNT(*) as count FROM log_details1 as log JOIN studentdetails as stu WHERE stu.uid=log.uid AND stu.mess_type='Veg' AND hostelintime IS NULL AND log.passtype = 'Home Pass'";

        var nonVegOutSql = "SELECT COUNT(*) as count FROM log_details1 as log JOIN studentdetails as stu WHERE stu.uid=log.uid AND stu.mess_type='Non-Veg' AND hostelintime IS NULL AND log.passtype = 'Home Pass'";


        connection.query(totalVegSql, function (err, totalVegResults) {
          if (err) {
            console.log(err);
            req.flash('message', 'Error fetching total veg data');
            connection.release();
            return res.render(__dirname + '/views/kitchen', { message: req.flash('message'), vegCount: 0, nonVegCount: 0, probableLogs: [] });
          }

          connection.query(totalNonVegSql, function (err, totalNonVegResults) {
            if (err) {
              console.log(err);
              req.flash('message', 'Error fetching total non-veg data');
              connection.release();
              return res.render(__dirname + '/views/kitchen', { message: req.flash('message'), vegCount: 0, nonVegCount: 0, probableLogs: [] });
            }

            connection.query(vegOutSql, function (err, vegOutResults) {
              if (err) {
                console.log(err);
                req.flash('message', 'Error fetching veg out data');
                connection.release();
                return res.render(__dirname + '/views/kitchen', { message: req.flash('message'), vegCount: 0, nonVegCount: 0, probableLogs: [] });
              }

              connection.query(nonVegOutSql, function (err, nonVegOutResults) {
                if (err) {
                  console.log(err);
                  req.flash('message', 'Error fetching non-veg out data');
                  connection.release();
                  return res.render(__dirname + '/views/kitchen', { message: req.flash('message'), vegCount: 0, nonVegCount: 0, probableLogs: [] });
                }

                // Calculate present students: Total - Out
                let totalVeg = totalVegResults[0].count;
                let totalNonVeg = totalNonVegResults[0].count;
                let vegOut = vegOutResults[0].count;
                let nonVegOut = nonVegOutResults[0].count;

                let vegCount = Math.max(0, totalVeg - vegOut);
                let nonVegCount = Math.max(0, totalNonVeg - nonVegOut);

                var probableSql = `
                  SELECT
                    future_dates.future_date,
                    ? + COALESCE(SUM(CASE WHEN stu.mess_type = 'Veg' THEN 1 ELSE 0 END), 0) AS veg_total,
                    ? + COALESCE(SUM(CASE WHEN stu.mess_type = 'Non-Veg' THEN 1 ELSE 0 END), 0) AS nonveg_total
                  FROM (
                    SELECT DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL n DAY), '%Y-%m-%d') AS future_date
                    FROM (SELECT 0 n UNION SELECT 1 UNION SELECT 2 UNION SELECT 3 UNION SELECT 4 UNION SELECT 5 UNION SELECT 6) t
                  ) future_dates
                  LEFT JOIN (
                    SELECT log.uid,
                      DATE((SELECT pr.expected_return FROM pass_requests pr
                            WHERE pr.uid = log.uid AND pr.status = 'approved' AND pr.expected_return IS NOT NULL
                            ORDER BY pr.approved_at DESC LIMIT 1)) AS ret_date
                    FROM log_details1 log
                    WHERE log.hostelintime IS NULL AND log.passtype = 'Home Pass'
                  ) out_students ON DATE(out_students.ret_date) <= STR_TO_DATE(future_dates.future_date, '%Y-%m-%d')
                    AND DATE(out_students.ret_date) >= CURDATE()
                  LEFT JOIN studentdetails stu ON stu.uid = out_students.uid
                  GROUP BY future_dates.future_date
                  ORDER BY future_dates.future_date ASC
                `;

                connection.query(probableSql, [vegCount, nonVegCount], function (err, probableResults) {

                  connection.release();

                  if (err) {
                    console.log(err);
                    return res.render(__dirname + '/views/kitchen', { message: req.flash('message'), vegCount, nonVegCount, probableLogs: [] });
                  }

                  let probableLogs = probableResults.map(row => ({
                    date: row.future_date,
                    veg: Number(row.veg_total) || 0,
                    nonveg: Number(row.nonveg_total) || 0
                  }));

                  res.render(__dirname + '/views/kitchen', { message: req.flash('message'), vegCount, nonVegCount, probableLogs });

                });

              });
            });
          });
        });
      });
    } else {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

app.get('/complain', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "Technician") {
      dbbconnection.getConnection(function (err, connection) {
        if (err) {
          console.log(err);
          req.flash('message', 'Database error');
          return res.render(__dirname + '/views/complain', { message: req.flash('message'), complaints: [], role: role });
        }
        const showAll = true;
        const sql = showAll
          ? 'SELECT c.*, s.sname, s.mobileno, s.room_no FROM complaints c LEFT JOIN studentdetails s ON c.student_uid = s.uid WHERE c.status IN ("approved", "resolved") ORDER BY c.timestamp DESC'
          : 'SELECT c.*, s.sname, s.mobileno, s.room_no FROM complaints c LEFT JOIN studentdetails s ON c.student_uid = s.uid WHERE c.status IN ("approved", "resolved") AND c.timestamp >= (NOW() - INTERVAL 1 DAY) ORDER BY c.timestamp DESC';
        connection.query(sql, function (err, results) {
          if (err) {
            connection.release();
            console.log(err);
            req.flash('message', 'Error fetching complaints');
            return res.render(__dirname + '/views/complain', { message: req.flash('message'), complaints: [], role: role });
          }
          connection.release();
          res.render(__dirname + '/views/complain', { message: req.flash('message'), complaints: results, role: role });
        });
      });
    } else {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

// Middleware for student verification
function verifyStudentJWT(req, res, next) {
  const token = req.cookies.studentjwt;
  if (!token) {
    req.flash('message', 'Please login first');
    return res.redirect('/student/login');
  }
  try {
    const decode = jwt.verify(token, studentSecretKey);
    req.student = decode;
    next();
  } catch (err) {
    res.clearCookie("studentjwt");
    req.flash('message', 'Session expired, please login again');
    return res.redirect('/student/login');
  }
}

// Student complain routes
app.get('/student/complain', verifyStudentJWT, function (req, res) {
  const student_uid = req.student.uid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.log(err);
      req.flash('message', 'Database error');
      return res.render(__dirname + '/views/student_complain', { message: req.flash('message'), student: null });
    }

    const sql = 'SELECT * FROM studentdetails WHERE uid = ?';
    connection.query(sql, [student_uid], function (err, results) {
      connection.release();
      if (err || results.length === 0) {
        req.flash('message', 'Student not found');
        return res.render(__dirname + '/views/student_complain', { message: req.flash('message'), student: null });
      }

      res.render(__dirname + '/views/student_complain', {
        message: req.flash('message'),
        student: results[0]
      });
    });
  });
});

app.post('/student/complain', verifyStudentJWT, function (req, res, next) {
  uploadComplainImage.single('complain_image')(req, res, function (err) {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'Image must be under 5MB.' : (err.message || 'Invalid image file. Use JPEG, PNG, GIF or WebP.');
      req.flash('message', msg);
      return res.redirect('/student/complain');
    }
    next();
  });
}, function (req, res) {
  const { category, description } = req.body;
  const student_uid = req.student.uid;
  const imagePath = req.file ? '/uploads/complaints/' + req.file.filename : null;

  // Validate required fields
  if (!category || !description) {
    req.flash('message', 'Please fill in all required fields');
    return res.redirect('/student/complain');
  }

  if (!student_uid) {
    req.flash('message', 'Student UID not found. Please login again.');
    return res.redirect('/student/login');
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      console.error('Database connection error:', err);
      req.flash('message', 'Database error');
      return res.redirect('/student/complain');
    }
    const sqlWithImage = 'INSERT INTO complaints (student_uid, description, category, image_path) VALUES (?, ?, ?, ?)';
    const sqlWithoutImage = 'INSERT INTO complaints (student_uid, description, category) VALUES (?, ?, ?)';

    function done(conn, insertErr) {
      conn.release();
      if (insertErr) {
        console.error('Error submitting complaint:', insertErr);
        req.flash('message', 'Error submitting complaint: ' + insertErr.message);
        return res.redirect('/student/complain');
      }
      req.flash('message', 'Complaint submitted successfully');
      res.redirect('/student/dashboard');
    }

    connection.query(sqlWithImage, [student_uid, description, category, imagePath], function (err, result) {
      if (err && err.errno === 1054 && err.sqlMessage && String(err.sqlMessage).indexOf('image_path') !== -1) {
        return connection.query(sqlWithoutImage, [student_uid, description, category], function (err2) {
          done(connection, err2);
        });
      }
      done(connection, err);
    });
  });
});

// Admin verify complaints
app.get('/admin/verify-complaints', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "SuperID" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      dbbconnection.getConnection(function (err, connection) {
        if (err) {
          console.log(err);
          req.flash('message', 'Database error');
          return res.render(__dirname + '/views/admin_verify_complaints', { message: req.flash('message'), complaints: [], role: role });
        }
        const showAll = String(req.query.all || '') === '1';
        let genderFilter = '';
        if (role === 'BoysHostelAdmin') genderFilter = ' AND s.gender = "MALE" ';
        if (role === 'GirlsHostelAdmin') genderFilter = ' AND s.gender = "FEMALE" ';

        // Hostel admins only verify student complaints; SuperID can also see admin-submitted complaints (student_uid may be NULL)
        const baseWhere = (role === 'SuperID')
          ? ' WHERE c.status IN ("pending_approval", "approved", "resolved", "denied") '
          : ' WHERE c.status IN ("pending_approval", "approved", "resolved", "denied") AND c.student_uid IS NOT NULL ';

        const sql = 'SELECT c.*, s.mobileno, s.room_no, s.sname FROM complaints c LEFT JOIN studentdetails s ON c.student_uid = s.uid' + baseWhere + genderFilter + ' ORDER BY c.timestamp DESC';
        connection.query(sql, function (err, results) {
          connection.release();
          if (err) {
            console.log(err);
            req.flash('message', 'Error fetching complaints');
            return res.render(__dirname + '/views/admin_verify_complaints', { message: req.flash('message'), complaints: [], role: role });
          }
          res.render(__dirname + '/views/admin_verify_complaints', { message: req.flash('message'), complaints: results, role: role });
        });
      });
    } else {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});

// Approve complaint
app.patch('/admin/approve-complain/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "SuperID" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      const id = req.params.id;
      dbbconnection.getConnection(function (err, connection) {
        if (err) {
          console.log(err);
          return res.status(500).json({ success: false, message: 'Database error' });
        }
        let sql = 'UPDATE complaints SET status = "approved" WHERE id = ?';
        let params = [id];
        if (role === 'BoysHostelAdmin') {
          sql = 'UPDATE complaints c JOIN studentdetails s ON c.student_uid = s.uid SET c.status = "approved" WHERE c.id = ? AND s.gender = "MALE"';
        } else if (role === 'GirlsHostelAdmin') {
          sql = 'UPDATE complaints c JOIN studentdetails s ON c.student_uid = s.uid SET c.status = "approved" WHERE c.id = ? AND s.gender = "FEMALE"';
        }
        connection.query(sql, params, function (err, result) {
          connection.release();
          if (err) {
            console.log(err);
            return res.status(500).json({ success: false, message: 'Error approving complaint' });
          }
          if (role !== 'SuperID' && (!result || result.affectedRows === 0)) {
            return res.status(403).json({ success: false, message: 'Unauthorised' });
          }
          res.json({ success: true, message: 'Complaint approved' });
        });
      });
    } else {
      res.status(403).json({ success: false, message: 'Unauthorised' });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: 'Something went wrong' });
  }
});

// Deny complaint
app.patch('/admin/deny-complain/:id', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "SuperID" || role == "BoysHostelAdmin" || role == "GirlsHostelAdmin") {
      const id = req.params.id;
      dbbconnection.getConnection(function (err, connection) {
        if (err) {
          console.log(err);
          return res.status(500).json({ success: false, message: 'Database error' });
        }
        let sql = 'UPDATE complaints SET status = "denied" WHERE id = ?';
        let params = [id];
        if (role === 'BoysHostelAdmin') {
          sql = 'UPDATE complaints c JOIN studentdetails s ON c.student_uid = s.uid SET c.status = "denied" WHERE c.id = ? AND s.gender = "MALE"';
        } else if (role === 'GirlsHostelAdmin') {
          sql = 'UPDATE complaints c JOIN studentdetails s ON c.student_uid = s.uid SET c.status = "denied" WHERE c.id = ? AND s.gender = "FEMALE"';
        }
        connection.query(sql, params, function (err, result) {
          connection.release();
          if (err) {
            console.log(err);
            return res.status(500).json({ success: false, message: 'Error denying complaint' });
          }
          if (role !== 'SuperID' && (!result || result.affectedRows === 0)) {
            return res.status(403).json({ success: false, message: 'Unauthorised' });
          }
          res.json({ success: true, message: 'Complaint denied' });
        });
      });
    } else {
      res.status(403).json({ success: false, message: 'Unauthorised' });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: 'Something went wrong' });
  }
});

// Admin: send complaint directly to technician (status = approved, appears on /complain)
app.post('/admin/complain-to-technician', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    const role = decode.role;
    if (role !== 'SuperID') {
      req.flash('message', 'Unauthorised');
      return res.redirect('/admin/verify-complaints');
    }
  } catch (e) {
    res.clearCookie('jwt');
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
  uploadComplainImage.single('complain_image')(req, res, function (err) {
    if (err) {
      req.flash('message', 'Error: ' + (err.message || 'Invalid file'));
      return res.redirect('/admin/verify-complaints');
    }
    const category = (req.body && req.body.category || '').trim();
    const description = (req.body && req.body.description || '').trim();
    if (!category || !description) {
      req.flash('message', 'Category and description are required.');
      return res.redirect('/admin/verify-complaints');
    }
    const imagePath = req.file ? '/uploads/complaints/' + req.file.filename : null;
    const adminName = (req.decode && req.decode.adminname) ? req.decode.adminname : 'Admin';
    dbbconnection.getConnection(function (e, conn) {
      if (e) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/verify-complaints');
      }
      const sql = 'INSERT INTO complaints (student_uid, admin_name, description, category, image_path, status) VALUES (?, ?, ?, ?, ?, ?)';
      conn.query(sql, [null, adminName, description, category, imagePath, 'approved'], function (e2) {
        conn.release();
        if (e2) {
          console.log(e2);
          req.flash('message', 'Error saving complaint.');
          return res.redirect('/admin/verify-complaints');
        }
        req.flash('message', 'Complaint sent to technician.');
        res.redirect('/admin/verify-complaints');
      });
    });
  });
});

// Update technician complain to show only approved






// Update technician complain to show only approved
app.get('/technician/complain', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "Technician") {
      dbbconnection.getConnection(function (err, connection) {
        if (err) {
          console.log(err);
          req.flash('message', 'Database error');
          return res.render(__dirname + '/views/complain', { message: req.flash('message'), complaints: [] });
        }
        const showAll = String(req.query.all || '') === '1';
        const sql = showAll
          ? 'SELECT c.*, s.sname, s.mobileno, s.room_no FROM complaints c LEFT JOIN studentdetails s ON c.student_uid = s.uid WHERE c.status = "approved" ORDER BY c.timestamp DESC'
          : 'SELECT c.*, s.sname, s.mobileno, s.room_no FROM complaints c LEFT JOIN studentdetails s ON c.student_uid = s.uid WHERE c.status = "approved" AND c.timestamp >= (NOW() - INTERVAL 1 DAY) ORDER BY c.timestamp DESC';
        connection.query(sql, function (err, results) {
          connection.release();
          if (err) {
            console.log(err);
            req.flash('message', 'Error fetching complaints');
            return res.render(__dirname + '/views/complain', { message: req.flash('message'), complaints: [] });
          }
          res.render(__dirname + '/views/complain', { message: req.flash('message'), complaints: results });
        });
      });
    } else {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }
  } catch (err) {
    res.clearCookie("jwt");
    req.flash('message', 'Something went wrong');
    return res.redirect('/loginpanel');
  }
});


// Mark complaint as resolved (Technician)
app.patch('/technician/complain/:id/resolve', verifyjwt, function (req, res) {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    role = decode.role;
    if (role == "Technician") {
      const id = req.params.id;
      dbbconnection.getConnection(function (err, connection) {
        if (err) {
          console.log(err);
          return res.status(500).json({ success: false, message: 'Database error' });
        }
        const sql = 'UPDATE complaints SET status = "resolved" WHERE id = ?';
        connection.query(sql, [id], function (err, result) {
          connection.release();
          if (err) {
            console.log(err);
            return res.status(500).json({ success: false, message: 'Error marking complaint as resolved' });
          }
          res.json({ success: true, message: 'Complaint marked as resolved' });
        });
      });
    } else {
      res.status(403).json({ success: false, message: 'Unauthorised' });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: 'Something went wrong' });
  }
});


// --- 1. SETUP MULTER FOR ADMISSIONS AND CREATE DIRECTORY ---
const multer = require('multer');

// Ensure admissions directory exists
const admissionsDir = path.join(__dirname, 'uploads', 'admissions');
if (!fs.existsSync(admissionsDir)) {
  try {
    fs.mkdirSync(admissionsDir, { recursive: true });
  } catch (err) {
    console.warn("Could not create admissions directory. This is expected in read-only environments like Vercel.");
  }
}

const admissionStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, admissionsDir);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    cb(null, file.fieldname + '-' + Date.now() + ext);
  }
});

const admissionFileFilter = function (req, file, cb) {
  const allowed = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
  if (allowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only JPEG, PNG, or WebP images are allowed.'), false);
  }
};

const uploadAdmission = multer({
  storage: admissionStorage,
  fileFilter: admissionFileFilter,
  limits: {
    fileSize: 2 * 1024 * 1024,   // 2 MB max per file
    files: 3,                     // max 3 files total
    fields: 30                    // max 30 text fields
  }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// --- 2. CREATE TABLE hostel_admission_applications ---
// (table creation remains below)
dbbconnection.getConnection((err, connection) => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  const createAdmissionTableSql = `
        CREATE TABLE IF NOT EXISTS hostel_admission_applications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            father_name VARCHAR(255) NOT NULL,
            father_occupation VARCHAR(100),
            mother_name VARCHAR(255) NOT NULL,
            mother_occupation VARCHAR(100),
            permanent_address TEXT NOT NULL,
            parent_phone VARCHAR(20) NOT NULL,
            student_mobile VARCHAR(20) NOT NULL,
            admission_year VARCHAR(10) NOT NULL,
            branch VARCHAR(100) NOT NULL,
            dob DATE NOT NULL,
            religion VARCHAR(50),
            caste_category VARCHAR(100),
            mess_preference ENUM('Veg', 'Non-Veg') NOT NULL,
            advance_amount DECIMAL(10,2) DEFAULT NULL,
            payment_mode ENUM('Cash', 'Online') DEFAULT NULL,
            decl1_signature_path VARCHAR(255),
            decl2_signature_path VARCHAR(255),
            undertaking_signature_path VARCHAR(255),
            submission_date DATE NOT NULL,
            status ENUM('Pending', 'Admitted', 'Rejected') DEFAULT 'Pending',
            allotted_block VARCHAR(50),
            allotted_room VARCHAR(50),
            allotted_bed VARCHAR(50),
            admin_remarks TEXT,
            reviewed_by VARCHAR(100),
            reviewed_at DATETIME,
            student_uid VARCHAR(50),
            hostel_id VARCHAR(50),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `;
  connection.query(createAdmissionTableSql, (err, result) => {
    connection.release();
    if (err) console.error("Error creating hostel_admission_applications table:", err);
    else console.log("Table hostel_admission_applications checked/created successfully");
  });
});

// Add student_photo_path column if missing
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
         WHERE TABLE_SCHEMA = DATABASE() 
         AND TABLE_NAME = 'hostel_admission_applications' 
         AND COLUMN_NAME = 'student_photo_path'`,
    function (err, rows) {
      if (err) {
        conn.release();
        return;
      }
      if (!rows || rows.length === 0) {
        conn.query(
          `ALTER TABLE hostel_admission_applications 
                     ADD COLUMN student_photo_path VARCHAR(255) DEFAULT NULL`,
          function (alterErr) { conn.release(); }
        );
      } else { conn.release(); }
    }
  );
});

// Add student_email column if missing
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
         WHERE TABLE_SCHEMA = DATABASE() 
         AND TABLE_NAME = 'hostel_admission_applications' 
         AND COLUMN_NAME = 'student_email'`,
    function (err, rows) {
      if (err) {
        conn.release();
        return;
      }
      if (!rows || rows.length === 0) {
        conn.query(
          `ALTER TABLE hostel_admission_applications 
                     ADD COLUMN student_email VARCHAR(255) DEFAULT NULL`,
          function (alterErr) { conn.release(); }
        );
      } else { conn.release(); }
    }
  );
});

// Add advance_amount column if missing
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'hostel_admission_applications'
         AND COLUMN_NAME = 'advance_amount'`,
    function (err, rows) {
      if (err) {
        conn.release();
        return;
      }
      if (!rows || rows.length === 0) {
        conn.query(
          `ALTER TABLE hostel_admission_applications
                     ADD COLUMN advance_amount DECIMAL(10,2) DEFAULT NULL`,
          function () { conn.release(); }
        );
      } else { conn.release(); }
    }
  );
});

// Add payment_mode column if missing
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE()
         AND TABLE_NAME = 'hostel_admission_applications'
         AND COLUMN_NAME = 'payment_mode'`,
    function (err, rows) {
      if (err) {
        conn.release();
        return;
      }
      if (!rows || rows.length === 0) {
        conn.query(
          `ALTER TABLE hostel_admission_applications
                     ADD COLUMN payment_mode ENUM('Cash', 'Online') DEFAULT NULL`,
          function () { conn.release(); }
        );
      } else { conn.release(); }
    }
  );
});


// Migration 1: Create hostel_uid_sequence table for temp UID generation
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(`CREATE TABLE IF NOT EXISTS hostel_uid_sequence (
    year SMALLINT NOT NULL PRIMARY KEY,
    last_seq INT NOT NULL DEFAULT 0
  )`, function () { conn.release(); });
});

// Migration 2: Add is_temp_uid flag to studentdetails (idempotent)
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='studentdetails'
    AND COLUMN_NAME='is_temp_uid'`, function (e, rows) {
    if (!rows || rows.length === 0) {
      conn.query(`ALTER TABLE studentdetails
        ADD COLUMN is_temp_uid TINYINT(1) DEFAULT 0`,
        function () { conn.release(); });
    } else { conn.release(); }
  });
});

// Migration 3: Add hostel_id backup column to studentdetails (idempotent)
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(`SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
    WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='studentdetails'
    AND COLUMN_NAME='hostel_id'`, function (e, rows) {
    if (!rows || rows.length === 0) {
      conn.query(`ALTER TABLE studentdetails
        ADD COLUMN hostel_id VARCHAR(50) DEFAULT NULL`,
        function () {
          conn.query(
            `UPDATE studentdetails
             SET hostel_id = uid
             WHERE is_temp_uid = 1
               AND (hostel_id IS NULL OR TRIM(hostel_id) = '')`,
            function () { conn.release(); }
          );
        }
      );
    } else {
      conn.query(
        `UPDATE studentdetails
         SET hostel_id = uid
         WHERE is_temp_uid = 1
           AND (hostel_id IS NULL OR TRIM(hostel_id) = '')`,
        function () { conn.release(); }
      );
    }
  });
});

// Migration 4: Ensure studentdetails.uid is VARCHAR(20) to support alphanumeric temp UIDs (e.g. BH26001)
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(
    `SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'studentdetails' AND COLUMN_NAME = 'uid'`,
    function (e, rows) {
      if (!rows || rows.length === 0) { conn.release(); return; }
      const dataType = (rows[0].DATA_TYPE || '').toLowerCase();
      if (dataType !== 'varchar' && dataType !== 'char') {
        conn.query(
          `ALTER TABLE studentdetails MODIFY COLUMN uid VARCHAR(20) NOT NULL`,
          function () { conn.release(); }
        );
      } else {
        conn.release();
      }
    }
  );
});

// Add parent_signature_path column if missing
dbbconnection.getConnection(function (err, conn) {
  if (err) return;
  conn.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS 
         WHERE TABLE_SCHEMA = DATABASE() 
         AND TABLE_NAME = 'hostel_admission_applications' 
         AND COLUMN_NAME = 'parent_signature_path'`,
    function (err, rows) {
      if (!rows || rows.length === 0) {
        conn.query(
          `ALTER TABLE hostel_admission_applications 
                     ADD COLUMN parent_signature_path VARCHAR(255) DEFAULT NULL`,
          function () { conn.release(); }
        );
      } else { conn.release(); }
    }
  );
});


app.get('/check-admission-status', (req, res) => {
  res.render('check_admission_status', {
    result: null,
    newApplication: req.query.new_application === 'true',
    prefillAppId: req.query.app_id || '',
    message: req.flash('message')
  });
});

app.post('/check-admission-status', (req, res) => {
  const isApi = req.headers['x-api-request'] === 'true' || req.originalUrl.includes('/api/');
  const { application_id, student_mobile } = req.body;

  if (!application_id || !student_mobile ||
    !application_id.trim() || !student_mobile.trim()) {
    if (isApi) return res.status(400).json({ success: false, message: 'Please enter both Application ID and Mobile Number.' });
    if (isApi) return res.status(400).json({ success: false, message: 'Please enter both Application ID and Mobile Number.' });
    req.flash('message', 'Please enter both Application ID and Mobile Number.');
    return res.redirect('/check-admission-status');
  }

  const appId = parseInt(application_id.trim(), 10);
  if (isNaN(appId) || appId <= 0) {
    if (isApi) return res.status(400).json({ success: false, message: 'Application ID must be a valid number.' });
    if (isApi) return res.status(400).json({ success: false, message: 'Application ID must be a valid number.' });
    req.flash('message', 'Application ID must be a valid number.');
    return res.redirect('/check-admission-status');
  }

  const sql = `
        SELECT id, full_name, status, allotted_block, allotted_room,
               allotted_bed, student_uid, admin_remarks,
               mess_preference, branch, admission_year
        FROM hostel_admission_applications
        WHERE id = ? AND student_mobile = ?
        LIMIT 1
    `;

  dbbconnection.getConnection((err, connection) => {
    if (err) {
      if (isApi) return res.status(500).json({ success: false, message: 'Database error. Please try again.' });
      if (isApi) return res.status(500).json({ success: false, message: 'Database error. Please try again.' });
      req.flash('message', 'Database error. Please try again.');
      return res.redirect('/check-admission-status');
    }
    connection.query(sql, [appId, student_mobile.trim()], (err, rows) => {
      connection.release();
      if (err) {
        console.error('Status check query error:', err);
        if (isApi) return res.status(500).json({ success: false, message: 'Error fetching status. Please try again.' });
        if (isApi) return res.status(500).json({ success: false, message: 'Error fetching status. Please try again.' });
        req.flash('message', 'Error fetching status. Please try again.');
        return res.redirect('/check-admission-status');
      }
      if (!rows || rows.length === 0) {
        if (isApi) return res.status(404).json({ success: false, message: 'No application found with these details.' });
        req.flash('message', 'No application found with these details. Please check your Application ID and mobile number.');
        return res.redirect('/check-admission-status');
      }
      if (isApi) return res.status(200).json({ success: true, result: rows[0] });
      if (isApi) return res.status(200).json({ success: true, result: rows[0] });
      res.render('check_admission_status', {
        result: rows[0],
        newApplication: false,
        prefillAppId: '',
        message: req.flash('message')
      });
    });
  });
});

// Public landing page for hostel admission
app.get('/student/admission-landing', (req, res) => {
  res.render('student_admission_landing');
});

// --- 3. STUDENT ROUTES (Public) ---
app.get('/student/admission-form', (req, res) => {
  const submissionToken = crypto.randomBytes(16).toString('hex');
  req.session.admissionSubmissionToken = submissionToken;
  res.render('student_admission_form', {
    submitted: req.query.submitted === 'true',
    message: req.flash('message'),
    submissionToken
  });
});

app.post('/student/admission-form',
  function (req, res, next) {
    uploadAdmission.fields([
      { name: 'student_photo', maxCount: 1 },
      { name: 'student_signature', maxCount: 1 },
      { name: 'parent_signature', maxCount: 1 }
    ])(req, res, function (err) {
      if (err instanceof multer.MulterError) {
        if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'File upload error: ' + err.message }); } else { req.flash('message', 'File upload error: ' + err.message); return res.redirect('/student/admission-form'); }
      } else if (err) {
        if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: err.message || 'Invalid file type.' }); } else { req.flash('message', err.message || 'Invalid file type.'); return res.redirect('/student/admission-form'); }
      }
      next();
    });
  },
  function (req, res) {
    const submissionToken = ((req.body.submission_token || '') + '').trim();
    const expectedSubmissionToken = ((req.session && req.session.admissionSubmissionToken) || '') + '';
    if (!submissionToken || !expectedSubmissionToken || submissionToken !== expectedSubmissionToken) {
      if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'Your admission form session expired. Please reopen the form and submit again.' }); } else { req.flash('message', 'Your admission form session expired. Please reopen the form and submit again.'); return res.redirect('/student/admission-form'); }
    }
    req.session.admissionSubmissionToken = null;

    const {
      full_name, father_name, father_occupation, mother_name, mother_occupation,
      permanent_address, parent_phone, student_mobile, student_email, admission_year, branch,
      dob, religion: rawReligion, caste_category: rawCaste, mess_preference,
      religion_other, caste_category_other, advance_amount, payment_mode
    } = req.body;

    // If "Other" was selected, use the custom typed value
    const religion = (rawReligion === 'Other' && religion_other && religion_other.trim()) ? religion_other.trim() : rawReligion;
    const caste_category = (rawCaste === 'Other' && caste_category_other && caste_category_other.trim()) ? caste_category_other.trim() : rawCaste;
    const advanceAmountRaw = ((advance_amount || '') + '').trim();
    const paymentMode = ((payment_mode || '') + '').trim();
    const parsedAdvanceAmount = advanceAmountRaw ? parseFloat(advanceAmountRaw) : NaN;
    const advanceAmountValue = Number.isFinite(parsedAdvanceAmount) ? parsedAdvanceAmount.toFixed(2) : null;

    // Get file paths
    const getFilePath = (fieldName) => {
      if (req.files && req.files[fieldName] && req.files[fieldName][0]) {
        return '/uploads/admissions/' + req.files[fieldName][0].filename;
      }
      return null;
    };
    const studentPhotoPath = getFilePath('student_photo');
    const studentSigPath = getFilePath('student_signature');
    const parentSigPath = getFilePath('parent_signature');

    // Server-side validation
    const required = [full_name, father_name, mother_name, permanent_address,
      parent_phone, student_mobile, student_email, admission_year, branch, dob, mess_preference,
      advanceAmountRaw, paymentMode];
    if (required.some(f => !f || !f.trim())) {
      if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'All required fields must be filled.' }); } else { req.flash('message', 'All required fields must be filled.'); return res.redirect('/student/admission-form'); }
    }
    if (!Number.isFinite(parsedAdvanceAmount) || parsedAdvanceAmount <= 0) {
      if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'Please enter a valid advance amount greater than zero.' }); } else { req.flash('message', 'Please enter a valid advance amount greater than zero.'); return res.redirect('/student/admission-form'); }
    }
    if (!['Cash', 'Online'].includes(paymentMode)) {
      if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'Please select a valid payment mode.' }); } else { req.flash('message', 'Please select a valid payment mode.'); return res.redirect('/student/admission-form'); }
    }
    if (!studentPhotoPath) {
      if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'Student passport photo is required.' }); } else { req.flash('message', 'Student passport photo is required.'); return res.redirect('/student/admission-form'); }
    }
    if (!studentSigPath || !parentSigPath) {
      if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'Both student and parent signatures are required.' }); } else { req.flash('message', 'Both student and parent signatures are required.'); return res.redirect('/student/admission-form'); }
    }

    const submission_date = typeof formatDateToISTString === 'function'
      ? formatDateToISTString(new Date()).split(' ')[0]
      : new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

    const sharp = require('sharp');
    const fs = require('fs');
    const path = require('path');

    const processPhoto = function (fieldName, cb) {
      if (!req.files || !req.files[fieldName] || !req.files[fieldName][0]) return cb();
      const diskPath = path.join(__dirname, 'uploads', 'admissions', req.files[fieldName][0].filename);
      fs.readFile(diskPath, function (readErr, rawFileBuffer) {
        if (readErr) return cb();
        sharp(rawFileBuffer).rotate().toBuffer(function (rotErr, fileBuffer) {
          if (rotErr) return cb();
          fs.writeFile(diskPath, fileBuffer, function () { cb(); });
        });
      });
    };

    // Process photo, then student signature, then parent signature, then insert into DB
    processPhoto('student_photo', function () {
      processPhoto('student_signature', function () {
        processPhoto('parent_signature', function () {

        const sql = `INSERT INTO hostel_admission_applications 
                    (full_name, father_name, father_occupation, mother_name, mother_occupation,
                     permanent_address, parent_phone, student_mobile, student_email, admission_year, branch,
                     dob, religion, caste_category, mess_preference, advance_amount, payment_mode, student_photo_path,
                     decl1_signature_path, parent_signature_path, submission_date, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'Pending')`;

        const params = [full_name, father_name, father_occupation || null,
          mother_name, mother_occupation || null, permanent_address, parent_phone,
          student_mobile, student_email, admission_year, branch, dob, religion || null,
          caste_category || null, mess_preference, advanceAmountValue, paymentMode, studentPhotoPath,
          studentSigPath, parentSigPath, submission_date];

        dbbconnection.getConnection((err, connection) => {
          if (err) {
            if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'Database error. Please try again.' }); } else { req.flash('message', 'Database error. Please try again.'); return res.redirect('/student/admission-form'); }
          }
          connection.query(sql, params, (err, result) => {
            connection.release();
            if (err) {
              console.error('Admission form insert error:', err);
              if (req.headers['x-api-request'] === 'true') { return res.status(400).json({ success: false, message: 'Error submitting application. Please try again.' }); } else { req.flash('message', 'Error submitting application. Please try again.'); return res.redirect('/student/admission-form'); }
            }
            const newAppId = result.insertId;
            if (req.headers['x-api-request'] === 'true') { return res.status(200).json({ success: true, newAppId }); } else { res.redirect('/check-admission-status?new_application=true&app_id=' + newAppId); }
          });
        });
      });
      });
    });
  }
);
// --- Mobile API: Submit Admission Form (No session token required) ---
app.post('/api/mobile/v1/admissions/submit',
  function (req, res, next) {
    uploadAdmission.fields([
      { name: 'student_photo', maxCount: 1 },
      { name: 'student_signature', maxCount: 1 },
      { name: 'parent_signature', maxCount: 1 }
    ])(req, res, function (err) {
      if (err instanceof multer.MulterError) {
        return res.status(400).json({ success: false, message: 'File upload error: ' + err.message });
      } else if (err) {
        return res.status(400).json({ success: false, message: 'Upload error: ' + err.message });
      }
      next();
    });
  },
  function (req, res) {
    const {
      full_name, father_name, father_occupation, mother_name, mother_occupation,
      permanent_address, parent_phone, student_mobile, student_email, admission_year, branch,
      dob, religion: rawReligion, caste_category: rawCaste, mess_preference,
      religion_other, caste_category_other, advance_amount, payment_mode
    } = req.body;

    const religion = (rawReligion === 'Other' && religion_other && religion_other.trim()) ? religion_other.trim() : rawReligion;
    const caste_category = (rawCaste === 'Other' && caste_category_other && caste_category_other.trim()) ? caste_category_other.trim() : rawCaste;
    const advanceAmountRaw = ((advance_amount || '') + '').trim();
    const paymentMode = ((payment_mode || '') + '').trim();
    const parsedAdvanceAmount = advanceAmountRaw ? parseFloat(advanceAmountRaw) : NaN;
    const advanceAmountValue = Number.isFinite(parsedAdvanceAmount) ? parsedAdvanceAmount.toFixed(2) : null;

    const getFilePath = (fieldName) => {
      if (req.files && req.files[fieldName] && req.files[fieldName][0]) {
        return '/uploads/admissions/' + req.files[fieldName][0].filename;
      }
      return null;
    };
    const studentPhotoPath = getFilePath('student_photo');
    const studentSigPath = getFilePath('student_signature');
    const parentSigPath = getFilePath('parent_signature');

    const required = [full_name, father_name, mother_name, permanent_address,
      parent_phone, student_mobile, student_email, admission_year, branch, dob, mess_preference,
      advanceAmountRaw, paymentMode];
    if (required.some(f => !f || !f.trim())) {
      return res.status(400).json({ success: false, message: 'All required fields must be filled.' });
    }
    if (!Number.isFinite(parsedAdvanceAmount) || parsedAdvanceAmount <= 0) {
      return res.status(400).json({ success: false, message: 'Please enter a valid advance amount greater than zero.' });
    }
    if (!['Cash', 'Online'].includes(paymentMode)) {
      return res.status(400).json({ success: false, message: 'Please select a valid payment mode (Cash or Online).' });
    }
    if (!studentPhotoPath) {
      return res.status(400).json({ success: false, message: 'Student passport photo is required.' });
    }
    if (!studentSigPath || !parentSigPath) {
      return res.status(400).json({ success: false, message: 'Both student and parent signatures are required.' });
    }

    const submission_date = typeof formatDateToISTString === 'function'
      ? formatDateToISTString(new Date()).split(' ')[0]
      : new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

    const sharp = require('sharp');
    const fs = require('fs');
    const path = require('path');

    // Process photo, then student signature, then parent signature, then insert into DB
    processPhoto('student_photo', function () {
      processPhoto('student_signature', function () {
        processPhoto('parent_signature', function () {
        const sql = `INSERT INTO hostel_admission_applications 
                            (full_name, father_name, father_occupation, mother_name, mother_occupation,
                             permanent_address, parent_phone, student_mobile, student_email, admission_year, branch,
                             dob, religion, caste_category, mess_preference, advance_amount, payment_mode, student_photo_path,
                             decl1_signature_path, parent_signature_path, submission_date, status)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'Pending')`;

        const params = [full_name, father_name, father_occupation || null,
          mother_name, mother_occupation || null, permanent_address, parent_phone,
          student_mobile, student_email, admission_year, branch, dob, religion || null,
          caste_category || null, mess_preference, advanceAmountValue, paymentMode, studentPhotoPath,
          studentSigPath, parentSigPath, submission_date];

        dbbconnection.getConnection((err, connection) => {
          if (err) {
            return res.status(500).json({ success: false, message: 'Database connection error. Please try again.' });
          }
          connection.query(sql, params, (err, result) => {
            connection.release();
            if (err) {
              console.error('Mobile admission form insert error:', err);
              return res.status(500).json({ success: false, message: 'Error submitting application. Please try again.' });
            }
            const newAppId = result.insertId;
            return res.status(200).json({ success: true, newAppId });
          });
        });
      });
      });
    });
  }
);


// --- 4. ADMIN ROUTES (Protected by SuperID) ---
// bcrypt is already required at the top

app.get('/admin/admission-applications', (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.redirect('/loginpanel');

  jwt.verify(token, "secretkeysvpcet", (err, decode) => {
    if (err || decode.role !== 'SuperID') return res.redirect('/loginpanel');

    dbbconnection.getConnection((err, connection) => {
      if (err) return res.status(500).send("Database error");
      connection.query("SELECT * FROM hostel_admission_applications ORDER BY created_at DESC", (err, result) => {
        connection.release();
        if (err) return res.status(500).send(err);
        res.render('admin_admission_applications', {
          applications: result,
          message: req.flash('message'),
          role: decode.role
        });
      });
    });
  });
});

// BoysHostelAdmin - View-only hostel admission applications
app.get('/boys/admission-applications', (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.redirect('/loginpanel');

  jwt.verify(token, "secretkeysvpcet", (err, decode) => {
    if (err || decode.role !== 'BoysHostelAdmin') return res.redirect('/loginpanel');

    dbbconnection.getConnection((dbErr, connection) => {
      if (dbErr) return res.status(500).send("Database error");
      connection.query("SELECT * FROM hostel_admission_applications ORDER BY created_at DESC", (qErr, result) => {
        connection.release();
        if (qErr) return res.status(500).send(qErr);
        res.render('boys_admission_applications', {
          applications: result || [],
          message: req.flash('message'),
          role: decode.role
        });
      });
    });
  });
});

// Feature 1: Export to Excel for hostel_admission_applications (via Python openpyxl)
app.get('/admin/admission-applications/export', (req, res) => {
  const tokenadmin = req.cookies.jwt;
  if (!tokenadmin) return res.redirect('/loginpanel');

  try {
    const decode = jwt.verify(tokenadmin, "secretkeysvpcet");
    if (decode.role !== 'SuperID') {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    const filter = (req.query.filter || 'all').toLowerCase();
    const validFilters = ['all', 'pending', 'admitted', 'rejected'];
    const safeFilter = validFilters.includes(filter) ? filter : 'all';

    let query = "SELECT * FROM hostel_admission_applications";
    if (safeFilter === 'pending') {
      query += " WHERE status = 'Pending'";
    } else if (safeFilter === 'admitted') {
      query += " WHERE status = 'Admitted'";
    } else if (safeFilter === 'rejected') {
      query += " WHERE status = 'Rejected'";
    }
    query += " ORDER BY created_at DESC";

    dbbconnection.getConnection((err, connection) => {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('back');
      }
      connection.query(query, [], async (err, results) => {
        connection.release();
        if (err) {
          req.flash('message', 'Error fetching applications for export');
          return res.redirect('back');
        }

        let finalResults = results;
        const timeFilter = req.query.time || '';
        if (timeFilter === 'today') {
          const todayStr = new Date().toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata' });
          finalResults = results.filter(row => {
            const rowDateStr = new Date(row.submission_date).toLocaleDateString('en-IN', { timeZone: 'Asia/Kolkata' });
            return rowDateStr === todayStr;
          });
        }

        const titleLabel = safeFilter.charAt(0).toUpperCase() + safeFilter.slice(1);
        const title = 'Hostel Admissions   -   ' + titleLabel + ' List' + (timeFilter === 'today' ? ' (Today)' : '');

        const rows = finalResults.map(row => ({
          allotted_room: row.allotted_room || '',
          allotted_bed: row.allotted_bed || '',
          full_name: row.full_name || '',
          branch: row.branch || '',
          admission_year: row.admission_year || '',
          student_mobile: row.student_mobile || '',
          parent_phone: row.parent_phone || '',
          father_name: row.father_name || '',
          mess_preference: row.mess_preference || ''
        }));

        const XLSX = require('xlsx');

        // Prepare worksheet data starting with Title (Row 1) and Headers (Row 2)
        const worksheetData = [
          [title],
          ['Room', 'Type', 'Bed', 'Student Name', 'Branch', 'Year', 'Contact Details', 'Mess Type']
        ];

        rows.forEach((row) => {
          if (row.not_used) {
            worksheetData.push([
              row.room || '',
              'Not Used',
              '',
              '',
              '',
              '',
              '',
              ''
            ]);
          } else {
            const mess_raw = row.mess_preference || '';
            let mess_display = 'Non-Vegitarian';
            if (mess_raw === 'Veg' || mess_raw === 'Vegetarian') {
              mess_display = 'Vegitarian';
            }

            const branch = row.branch || '';
            const year = row.admission_year || '';

            const mobile = row.student_mobile || '';
            const parent = row.parent_phone || '';
            const father = row.father_name || '';
            const contact = `${mobile}   /   ${parent} (${father})`;

            worksheetData.push([
              row.allotted_room || '',
              'Triple Room',
              row.allotted_bed || '',
              row.full_name || '',
              branch,
              year,
              contact,
              mess_display
            ]);
          }
        });

        const worksheet = XLSX.utils.aoa_to_sheet(worksheetData);

        // Set column widths
        worksheet['!cols'] = [
          { wch: 26 },
          { wch: 13 },
          { wch: 5 },
          { wch: 32 },
          { wch: 22 },
          { wch: 12 },
          { wch: 51 },
          { wch: 15 }
        ];

        const workbook = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(workbook, worksheet, 'Room_MasterList');

        const filename = 'hostel-admissions-' + safeFilter + '-' + Date.now() + '.xlsx';
        res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');

        const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
        res.send(buffer);
      });
    });

  } catch (e) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

// Feature 3: Admitted Students List
app.get('/admin/admission-applications/admitted-list', (req, res) => {
  const tokenadmin = req.cookies.jwt;
  if (!tokenadmin) return res.redirect('/loginpanel');

  try {
    const decode = jwt.verify(tokenadmin, "secretkeysvpcet");
    if (decode.role !== 'SuperID') {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    dbbconnection.getConnection((err, connection) => {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('back');
      }
      const query = "SELECT * FROM hostel_admission_applications WHERE status = 'Admitted' ORDER BY allotted_block ASC, allotted_room ASC, allotted_bed ASC";

      connection.query(query, (err, result) => {
        connection.release();
        if (err) {
          req.flash('message', 'Error fetching admitted students');
          return res.redirect('back');
        }

        const grouped = {};
        result.forEach(row => {
          const block = row.allotted_block || 'Unassigned';
          if (!grouped[block]) grouped[block] = [];
          grouped[block].push(row);
        });

        const blockKeys = Object.keys(grouped).sort();

        res.render('admin_admitted_list', {
          grouped,
          blockKeys,
          total: result.length,
          message: req.flash('message')
        });
      });
    });

  } catch (e) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

// Edit admission application details (SuperID only)
app.get('/admin/admission-applications/:id/edit', (req, res) => {
  const tokenadmin = req.cookies.jwt;
  if (!tokenadmin) return res.redirect('/loginpanel');

  try {
    const decode = jwt.verify(tokenadmin, "secretkeysvpcet");
    if (decode.role !== 'SuperID') {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    dbbconnection.getConnection((err, connection) => {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('back');
      }
      connection.query("SELECT * FROM hostel_admission_applications WHERE id = ?", [req.params.id], (err, result) => {
        connection.release();
        if (err || result.length === 0) {
          req.flash('message', 'Application not found');
          return res.redirect('/admin/admission-applications');
        }
        res.render('admin_admission_edit', {
          app: result[0],
          message: req.flash('message'),
          role: decode.role
        });
      });
    });
  } catch (e) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

app.post('/admin/admission-applications/:id/edit', (req, res) => {
  const tokenadmin = req.cookies.jwt;
  if (!tokenadmin) return res.redirect('/loginpanel');

  try {
    const decode = jwt.verify(tokenadmin, "secretkeysvpcet");
    if (decode.role !== 'SuperID') {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    const appId = req.params.id;
    const {
      full_name, father_name, father_occupation, mother_name, mother_occupation,
      permanent_address, parent_phone, student_mobile, student_email, admission_year, branch,
      dob, religion: rawReligion, caste_category: rawCaste, mess_preference,
      religion_other, caste_category_other
    } = req.body;

    // If "Other" was selected, use the custom typed value
    const religion = (rawReligion === 'Other' && religion_other && religion_other.trim()) ? religion_other.trim() : rawReligion;
    const caste_category = (rawCaste === 'Other' && caste_category_other && caste_category_other.trim()) ? caste_category_other.trim() : rawCaste;

    const updateSql = `UPDATE hostel_admission_applications SET
            full_name=?, father_name=?, father_occupation=?, mother_name=?, mother_occupation=?,
            permanent_address=?, parent_phone=?, student_mobile=?, student_email=?, admission_year=?, branch=?,
            dob=?, religion=?, caste_category=?, mess_preference=?
            WHERE id=?`;

    const params = [
      full_name, father_name, father_occupation || null, mother_name, mother_occupation || null,
      permanent_address, parent_phone, student_mobile, student_email, admission_year, branch,
      dob, religion || null, caste_category || null, mess_preference, appId
    ];

    dbbconnection.getConnection((err, connection) => {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('back');
      }

      // First fetch existing record to check if email is changing
      connection.query('SELECT student_email, status, student_uid, allotted_block, allotted_room, allotted_bed FROM hostel_admission_applications WHERE id=?', [appId], (oldErr, oldRows) => {
        if (oldErr || oldRows.length === 0) {
          connection.release();
          req.flash('message', 'Application not found');
          return res.redirect('back');
        }

        const oldEmail = oldRows[0].student_email;
        const oldApp = oldRows[0];
        const emailChanged = (oldEmail !== student_email);

        connection.query(updateSql, params, (err, result) => {
          if (err) {
            connection.release();
            console.error('Error updating admission application:', err);
            req.flash('message', 'Error updating application details');
            return res.redirect('back');
          }

          // If the student is already Admitted, we must also update their studentdetails record
          connection.query('SELECT status, student_uid FROM hostel_admission_applications WHERE id=?', [appId], (err, rows) => {
            if (!err && rows.length > 0 && rows[0].status === 'Admitted' && rows[0].student_uid) {
              const student_uid = rows[0].student_uid;

              const studentUpdateSql = `UPDATE studentdetails SET
                                sname=?, email=?, dept=?, address=?, year=?, mobileno=?, dob=?,
                                parentname=?, parentnumber=?, mess_type=?, other2=?
                                WHERE uid=?`;

              const studentParams = [
                full_name, student_email || null, branch, permanent_address, admission_year, student_mobile, dob,
                father_name, parent_phone, mess_preference, caste_category || null, student_uid
              ];

              connection.query(studentUpdateSql, studentParams, (err) => {
                connection.release();
                if (err) {
                  console.error('Error updating student details:', err);
                  req.flash('message', 'Application updated, but failed to update student profile data');
                  return res.redirect('/admin/admission-applications/' + appId);
                }

                // --- NEW: Send email if email changed and student is Admitted ---
                if (emailChanged && student_email) {
                  const academicYear = new Date().getFullYear() + '-' + (new Date().getFullYear() + 1);
                  const emailData = {
                    full_name: full_name,
                    hostel_id: student_uid,
                    uid: student_uid,
                    block: oldApp.allotted_block || 'N/A',
                    room_no: oldApp.allotted_room || 'N/A',
                    bed_no: oldApp.allotted_bed || 'N/A',
                    mess_type: mess_preference || 'N/A',
                    academic_year: academicYear,
                    contactEmail: 'tnpshostel@gmail.com'
                  };
                  const renderedAdmissionMail = ejs.render(admissionWelcomeTemplate, emailData);
                  transporter.sendMail({
                    from: process.env.MAIL_USER,
                    to: student_email,
                    subject: 'TNPS Boys Hostel - Admission Confirmed | UID: ' + student_uid,
                    html: renderedAdmissionMail,
                    attachments: [
                      { filename: 'hostellogo.png', path: hostelLogoPath, cid: 'hostel-logo' }
                    ]
                  }, function (mailErr, info) {
                    if (mailErr) console.error('Updated admission email failed:', mailErr.message);
                    else console.log('Updated admission email sent:', info.response);
                  });
                }
                // -------------------------------------------------------------

                req.flash('message', 'Application and Student Profile details updated successfully');
                res.redirect('/admin/admission-applications/' + appId);
              });
            } else {
              connection.release();
              req.flash('message', 'Application details updated successfully');
              res.redirect('/admin/admission-applications/' + appId);
            }
          });
        });
      });
    });
  } catch (e) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});


// Define this BEFORE the admission action route
function generateTempHostelUid(connection, callback) {
  const currentYear = new Date().getFullYear();
  const yearSuffix = String(currentYear).slice(-2); // e.g. "26"
  const uidPrefix = 'BH' + yearSuffix;

  connection.query(
    `SELECT uid FROM studentdetails
     WHERE is_temp_uid = 1 AND uid LIKE ?
     ORDER BY uid ASC`,
    [uidPrefix + '%'],
    function (err, rows) {
      if (err) return callback(err, null);

      const usedSeqs = new Set();
      (rows || []).forEach(function (row) {
        const uid = ((row.uid || '') + '').trim().toUpperCase();
        if (!uid.startsWith(uidPrefix)) return;
        const seq = parseInt(uid.slice(uidPrefix.length), 10);
        if (Number.isFinite(seq) && seq > 0) usedSeqs.add(seq);
      });

      let seq = 1;
      while (usedSeqs.has(seq)) seq++;

      const tempUid = uidPrefix + String(seq).padStart(3, '0'); // e.g. BH26001, BH26002...
      callback(null, tempUid);
    }
  );
}

app.get('/admin/admission-applications/:id/print', async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.redirect('/loginpanel');
    const decoded = require('jsonwebtoken').verify(token, 'secretkeysvpcet');
    if (decoded.role !== 'SuperID' && decoded.role !== 'BoysHostelAdmin') {
      req.flash('message', 'Unauthorized');
      return res.redirect('/admin/admission-applications');
    }

    dbbconnection.getConnection((err, connection) => {
      if (err) { req.flash('message', 'DB Error'); return res.redirect('back'); }

      connection.query('SELECT * FROM hostel_admission_applications WHERE id = ?', [req.params.id], (err, rows) => {
        connection.release();
        if (err || rows.length === 0 || rows[0].status !== 'Admitted') {
          req.flash('message', 'Application not found or not admitted');
          return res.redirect('back');
        }
        res.render('admission_print', { app: rows[0] });
      });
    });
  } catch (err) {
    res.clearCookie('jwt');
    res.redirect('/loginpanel');
  }
});

app.post('/admin/rotate-image', express.json(), (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });
  jwt.verify(token, "secretkeysvpcet", (err, decode) => {
    if (err || decode.role !== 'SuperID') return res.status(401).json({ success: false, message: 'Unauthorized' });

    const { imagePath, degrees } = req.body;
    if (!imagePath || typeof degrees !== 'number') return res.status(400).json({ success: false, message: 'Invalid parameters' });

    if (!imagePath.startsWith('/uploads/')) return res.status(400).json({ success: false, message: 'Invalid path' });
    
    const fs = require('fs');
    const sharp = require('sharp');
    const absolutePath = path.join(__dirname, imagePath.replace('/uploads/', 'uploads/'));
    
    fs.readFile(absolutePath, function (readErr, rawFileBuffer) {
      if (readErr) return res.status(500).json({ success: false, message: 'File not found' });
      
      sharp(rawFileBuffer).rotate(degrees).toBuffer(function(rotErr, fileBuffer) {
         if (rotErr) return res.status(500).json({ success: false, message: 'Error rotating image' });
         
         fs.writeFile(absolutePath, fileBuffer, function(writeErr) {
            if (writeErr) return res.status(500).json({ success: false, message: 'Error saving image' });
            res.json({ success: true, timestamp: Date.now() });
         });
      });
    });
  });
});

app.post('/admin/crop-image', express.json(), (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });
  jwt.verify(token, "secretkeysvpcet", (err, decode) => {
    if (err || decode.role !== 'SuperID') return res.status(401).json({ success: false, message: 'Unauthorized' });

    const { imagePath, x, y, width, height } = req.body;
    if (!imagePath || typeof x !== 'number' || typeof y !== 'number' || typeof width !== 'number' || typeof height !== 'number') {
      return res.status(400).json({ success: false, message: 'Invalid parameters' });
    }

    if (!imagePath.startsWith('/uploads/')) return res.status(400).json({ success: false, message: 'Invalid path' });
    
    const fs = require('fs');
    const sharp = require('sharp');
    const absolutePath = path.join(__dirname, imagePath.replace('/uploads/', 'uploads/'));
    
    fs.readFile(absolutePath, function (readErr, rawFileBuffer) {
      if (readErr) return res.status(500).json({ success: false, message: 'File not found' });
      
      const cropOptions = {
        left: Math.max(0, Math.floor(x)),
        top: Math.max(0, Math.floor(y)),
        width: Math.max(1, Math.floor(width)),
        height: Math.max(1, Math.floor(height))
      };

      sharp(rawFileBuffer)
        .extract(cropOptions)
        .toBuffer(function(cropErr, fileBuffer) {
           if (cropErr) {
             console.error('Crop extract error:', cropErr);
             return res.status(500).json({ success: false, message: 'Error cropping image' });
           }
           
           fs.writeFile(absolutePath, fileBuffer, function(writeErr) {
              if (writeErr) return res.status(500).json({ success: false, message: 'Error saving image' });
              res.json({ success: true, timestamp: Date.now() });
           });
        });
    });
  });
});

app.get('/admin/admission-applications/:id', (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.redirect('/loginpanel');

  jwt.verify(token, "secretkeysvpcet", (err, decode) => {
    if (err || decode.role !== 'SuperID') return res.redirect('/loginpanel');

        dbbconnection.getConnection((err, connection) => {
            if (err) return res.status(500).send("Database error");
            connection.query("SELECT * FROM hostel_admission_applications WHERE id = ?", [req.params.id], (err, result) => {
                if (err || result.length === 0) {
                    connection.release();
                    return res.status(404).send("Application not found");
                }
                connection.query(
                    "SELECT name, block, floor, capacity, is_permanent, description FROM rooms WHERE (is_available IS NULL OR is_available = TRUE) ORDER BY block, floor, name",
                    (err2, roomRows) => {
                        if (err2) {
                            connection.release();
                            return res.status(500).send("Database error loading rooms");
                        }
                        connection.query(
                            "SELECT room_no, bed_no FROM room_bookings WHERE booking_status = 'locked'",
                            (err3, lockedRows) => {
                                connection.release();
                                res.render('admin_admission_detail', {
                                    app: result[0],
                                    message: req.flash('message'),
                                    role: decode.role,
                                    rooms: roomRows || [],
                                    lockedBeds: lockedRows || [],
                                    downloadBiodata: req.query.download_biodata === 'true'
                                });
                            }
                        );
                    }
                );
            });
        });
    });
});

app.get('/admin/admission-applications/:id/download-biodata', (req, res) => {
    const token = req.cookies.jwt;
    if (!token) return res.redirect('/loginpanel');

    jwt.verify(token, "secretkeysvpcet", (err, decode) => {
        if (err || decode.role !== 'SuperID') return res.redirect('/loginpanel');

        dbbconnection.getConnection((err, connection) => {
            if (err) return res.status(500).send("Database error");
            
            var sql = `
              SELECT sd.uid, sd.sname, sd.email, sd.dept, sd.year, sd.academicyear, sd.gender, 
              sd.mobileno, sd.dob, sd.address, sd.mess_type, sd.parentname, sd.parentnumber, sd.status, 
              COALESCE(rb.room_no, sd.room_no) AS final_room_no, COALESCE(rb.block, sd.block) AS final_block, 
              COALESCE(rb.bed_no, sd.bed_no) AS final_bed_no, sd.hostel_id AS haa_hostel_id, 
              haa.full_name AS haa_full_name, haa.father_name AS haa_father_name, haa.father_occupation AS haa_father_occupation, 
              haa.mother_name AS haa_mother_name, haa.mother_occupation AS haa_mother_occupation, 
              haa.permanent_address AS haa_address, haa.parent_phone AS haa_parent_phone, haa.student_mobile AS haa_student_mobile, 
              haa.student_email AS haa_student_email, haa.religion AS haa_religion, haa.caste_category AS haa_caste, 
              haa.mess_preference AS haa_mess, haa.dob AS haa_dob, haa.admission_year AS haa_batch, 
              haa.branch AS haa_branch, haa.submission_date AS haa_submission_date, rm.capacity AS room_capacity 
              FROM hostel_admission_applications haa
              LEFT JOIN studentdetails sd ON haa.student_uid COLLATE utf8mb4_unicode_ci = sd.uid COLLATE utf8mb4_unicode_ci
              LEFT JOIN room_bookings rb ON rb.uid = sd.uid AND rb.booking_status = 'locked' AND rb.id = ( SELECT MAX(rb2.id) FROM room_bookings rb2 WHERE rb2.uid = sd.uid AND rb2.booking_status = 'locked' ) 
              LEFT JOIN rooms rm ON rm.name = COALESCE(rb.room_no, sd.room_no) AND rm.block = COALESCE(rb.block, sd.block) 
              WHERE haa.id = ?
            `;

            connection.query(sql, [req.params.id], (err, rows) => {
                connection.release();
                if (err || rows.length === 0) {
                    return res.status(404).send("Data not found");
                }

                var r = rows[0];
                function formatDob(val) {
                  if (!val) return '';
                  var d = new Date(val);
                  if (isNaN(d.getTime())) return String(val);
                  var dd = String(d.getUTCDate()).padStart(2, '0');
                  var mm = String(d.getUTCMonth() + 1).padStart(2, '0');
                  var yyyy = d.getUTCFullYear();
                  return dd + '/' + mm + '/' + yyyy;
                }

                function getRoomType(capacity) {
                  if (capacity == 1) return 'Single';
                  if (capacity == 2) return 'Double';
                  if (capacity == 3) return 'Triple';
                  if (capacity >= 4) return 'Dormitory';
                  return '';
                }

                var LABELS = [
                  'Hostel UID', 'College UID', 'Application Date', 'Student Name',
                  'Batch', 'Branch', 'Date of Birth', 'Gender',
                  'Mother Tongue', 'Religion', 'Cast', 'Community',
                  'Native Place', 'Blood Group', 'Communication Address',
                  'Student Mobile No', 'Student Mail Id', "Father's Name",
                  'Occupation', 'Mobile No.', "Mother's Name", 'Occupation',
                  'Mobile No.', 'Contact Person', 'Mobile No.', 'WhatsApp No.',
                  'Hostel Block', 'Room Type', 'Room No.', 'Bed No.',
                  'Mess Preference', 'Remarks (if any)'
                ];

                var vals = [
                  r.haa_hostel_id || '',                                             
                  r.uid || '',                                                        
                  formatDob(r.haa_submission_date),                                   
                  r.haa_full_name  || r.sname       || '',                           
                  r.haa_batch      || r.academicyear || '',                          
                  r.haa_branch     || r.dept        || '',                           
                  formatDob(r.haa_dob || r.dob),                                     
                  r.gender || '',                                                     
                  '',                                                                 
                  r.haa_religion   || '',                                            
                  r.haa_caste      || '',                                            
                  '',                                                                 
                  r.haa_address    || r.address     || '',                           
                  '',                                                                 
                  r.haa_address    || r.address     || '',                           
                  r.haa_student_mobile || r.mobileno || '',                          
                  r.haa_student_email  || r.email   || '',                           
                  r.haa_father_name    || r.parentname   || '',                      
                  r.haa_father_occupation || '',                                     
                  r.haa_parent_phone   || r.parentnumber || '',                      
                  r.haa_mother_name    || '',                                        
                  r.haa_mother_occupation || '',                                     
                  '',                                                                 
                  r.haa_father_name    || r.parentname   || '',                      
                  r.haa_parent_phone   || r.parentnumber || '',                      
                  r.haa_student_mobile || r.mobileno || '',                          
                  r.final_block    || '',                                            
                  getRoomType(r.room_capacity),                                       
                  r.final_room_no  || '',                                            
                  r.final_bed_no   || '',                                            
                  r.haa_mess       || r.mess_type   || '',                           
                  ''                                                                  
                ];

                var aoa = LABELS.map((label, index) => {
                   return [label, vals[index]];
                });

                const XLSX = require('xlsx');
                var ws = XLSX.utils.aoa_to_sheet(aoa);
                var wb = XLSX.utils.book_new();
                XLSX.utils.book_append_sheet(wb, ws, 'Student_Biodata');
                var buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
                var studentNameStr = (r.haa_full_name || r.sname || 'Student').replace(/[^a-zA-Z0-9\s]/g, '').trim().replace(/\s+/g, '_');
                var uidStr = (r.uid || r.haa_hostel_id || 'Unknown');
                var fname = (studentNameStr || 'Student') + '.xlsx';
                res.setHeader('Content-Disposition', 'attachment; filename="' + fname + '"');
                res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
                res.send(buf);
            });
        });
    });
});

// BoysHostelAdmin - View-only application details
app.get('/boys/admission-applications/:id', (req, res) => {
  const token = req.cookies.jwt;
  if (!token) return res.redirect('/loginpanel');

  jwt.verify(token, "secretkeysvpcet", (err, decode) => {
    if (err || decode.role !== 'BoysHostelAdmin') return res.redirect('/loginpanel');

    dbbconnection.getConnection((dbErr, connection) => {
      if (dbErr) return res.status(500).send("Database error");
      connection.query("SELECT * FROM hostel_admission_applications WHERE id = ?", [req.params.id], (qErr, result) => {
        connection.release();
        if (qErr || result.length === 0) {
          return res.status(404).send("Application not found");
        }
        res.render('boys_admission_detail', {
          app: result[0],
          message: req.flash('message'),
          role: decode.role
        });
      });
    });
  });
});

app.post('/admin/admission-applications/:id/action', async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.redirect('/loginpanel');
    const decoded = require('jsonwebtoken').verify(token, 'secretkeysvpcet');
    if (decoded.role !== 'SuperID') {
      req.flash('message', 'Unauthorized action');
      return res.redirect('/admin/admission-applications');
    }

    const { action, allotted_block, allotted_room, allotted_bed, admin_remarks } = req.body;
    const appId = req.params.id;

    if (action === 'Admitted') {
      if (!allotted_block || !allotted_room || !allotted_bed) {
        req.flash('message', 'Block, Room, and Bed are required to admit a student.');
        return res.redirect('back');
      }

      dbbconnection.getConnection((err, connection) => {
        if (err) { req.flash('message', 'DB Error'); return res.redirect('back'); }

        connection.query(`SELECT * FROM hostel_admission_applications WHERE id = ?`, [appId], (err, rows) => {
          if (err || rows.length === 0) {
            connection.release();
            req.flash('message', 'Application not found');
            return res.redirect('back');
          }

          const appData = rows[0];
          const parsedAppAdvanceAmount = appData.advance_amount != null && appData.advance_amount !== ''
            ? Number(appData.advance_amount)
            : NaN;
          const appAdvanceAmount = Number.isFinite(parsedAppAdvanceAmount)
            ? parsedAppAdvanceAmount.toFixed(2)
            : null;
          const appPaymentMode = ((appData.payment_mode || '') + '').trim();
          const bookingAdvanceAmount = appAdvanceAmount;
          const bookingTransactionId = ['Cash', 'Online'].includes(appPaymentMode) ? appPaymentMode : null;

          // Guard: ensure the selected bed is not already locked by another student
          connection.query(
            `SELECT id FROM room_bookings WHERE room_no = ? AND bed_no = ? AND booking_status = 'locked' LIMIT 1`,
            [allotted_room, allotted_bed],
            (bedErr, bedRows) => {
              if (bedErr) {
                connection.release();
                req.flash('message', 'DB error checking bed availability.');
                return res.redirect('back');
              }
              if (bedRows.length > 0) {
                connection.release();
                req.flash('message', `Bed ${allotted_bed} in Room ${allotted_room} is already locked for another student. Please choose a different bed.`);
                return res.redirect('back');
              }

              generateTempHostelUid(connection, function (uidErr, newUid) {
                if (uidErr) {
                  connection.release();
                  req.flash('message', 'Failed to generate student UID. Please try again.');
                  return res.redirect('back');
                }

                const studentSql = `
                  INSERT INTO studentdetails 
                  (uid, hostel_id, sname, email, password, dept, address, year, category, gender, mobileno, dob, academicyear, status, parentname, parentnumber, room_no, bed_no, mess_type, other2, block, is_temp_uid)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                `;

                require('bcrypt').hash(appData.student_mobile, 10, (err, hash) => {
                  if (err) { connection.release(); return res.redirect('back'); }

                  let formattedDob = appData.dob;
                  if (appData.dob instanceof Date) {
                    const d = appData.dob;
                    formattedDob = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
                  }

                  const studentValues = [
                    newUid, newUid, appData.full_name, appData.student_email || null, hash, appData.branch,
                    appData.permanent_address, appData.admission_year, 'Hostel',
                    'MALE', appData.student_mobile, formattedDob,
                    new Date().getFullYear() + '-' + (new Date().getFullYear() + 1),
                    'active', appData.father_name, appData.parent_phone,
                    allotted_room, allotted_bed, appData.mess_preference,
                    appData.caste_category, allotted_block
                  ];

                  connection.query(studentSql, studentValues, (err) => {
                    if (err) {
                      connection.release();
                      req.flash('message', 'Error creating student record');
                      return res.redirect('back');
                    }

                    const updateAppSql = `
                      UPDATE hostel_admission_applications 
                      SET status = 'Admitted', allotted_block = ?, allotted_room = ?, allotted_bed = ?, admin_remarks = ?, student_uid = ?, reviewed_by = ?, reviewed_at = UTC_TIMESTAMP()
                      WHERE id = ?
                    `;

                    connection.query(updateAppSql, [allotted_block, allotted_room, allotted_bed, admin_remarks, newUid, 'SuperID', appId], (err) => {
                      if (err) {
                        connection.release();
                        req.flash('message', 'Error updating application');
                        return res.redirect('back');
                      }

                      const insertBookingSql = `
                        INSERT INTO room_bookings
                          (room_no, block, floor, bed_no, uid, booking_status,
                           payment_status, advance_amount, transaction_id,
                           agreement_accepted, locked_source, locked_by)
                        SELECT ?, ?, IFNULL((SELECT floor FROM rooms WHERE name = ? AND block = ? LIMIT 1), 'Ground Floor'), ?, ?, 'locked', 'confirmed', ?, ?, 1,
                                'admin', 'SuperID-Admission'
                      `;
                      connection.query(insertBookingSql, [
                        allotted_room || null, allotted_block || null, allotted_room || null, allotted_block || null, allotted_bed || null, newUid,
                        bookingAdvanceAmount, bookingTransactionId
                      ], function (rbErr) {
                        if (rbErr) console.error('Warning: Could not create room_booking row:', rbErr.message);

                        // Send admission welcome email (fire-and-forget ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â do NOT block redirect on email)
                        if (appData.student_email) {
                          const academicYear = new Date().getFullYear() + '-' + (new Date().getFullYear() + 1);
                          const emailData = {
                            full_name: appData.full_name,
                            hostel_id: newUid,
                            uid: newUid,
                            block: allotted_block,
                            room_no: allotted_room,
                            bed_no: allotted_bed,
                            mess_type: appData.mess_preference || 'N/A',
                            academic_year: academicYear,
                            contactEmail: 'tnpshostel@gmail.com'
                          };
                          const renderedAdmissionMail = ejs.render(admissionWelcomeTemplate, emailData);
                          transporter.sendMail({
                            from: process.env.MAIL_USER,
                            to: appData.student_email,
                            subject: 'TNPS Boys Hostel - Admission Confirmed | UID: ' + newUid,
                            html: renderedAdmissionMail,
                            attachments: [
                              { filename: 'hostellogo.png', path: hostelLogoPath, cid: 'hostel-logo' }
                            ]
                          }, function (mailErr, info) {
                            if (mailErr) console.error('Admission email failed:', mailErr.message);
                            else console.log('Admission email sent:', info.response);
                          });
                        }

                        connection.release();
                        req.flash('message', 'Student admitted. Room booking created for BoysHostelAdmin.');
                        res.redirect('/admin/admission-applications/' + appId + '?download_biodata=true');
                      });
                    });
                  });
                });
              });
            }
          );
        });
      });
    } else if (action === 'Rejected') {
      dbbconnection.getConnection((err, connection) => {
        if (err) { req.flash('message', 'DB Error'); return res.redirect('back'); }
        const updateAppSql = `
          UPDATE hostel_admission_applications 
          SET status = 'Rejected', admin_remarks = ?, reviewed_by = ?, reviewed_at = UTC_TIMESTAMP()
          WHERE id = ?
        `;
        connection.query(updateAppSql, [admin_remarks, 'SuperID', appId], (err) => {
          connection.release();
          if (err) req.flash('message', 'Error rejecting application');
          else req.flash('message', 'Application rejected');
          res.redirect('back');
        });
      });
    }
  } catch (err) {
    res.clearCookie('jwt');
    res.redirect('/loginpanel');
  }
});

// Remove Application Route
app.post('/admin/admission-applications/:id/delete', async (req, res) => {
  const tokenadmin = req.cookies.jwt;
  try {
    const decode = jwt.verify(tokenadmin, secretkey);
    if (decode.role !== "SuperID") return res.redirect('/admin/admission-applications');

    const appId = req.params.id;

    dbbconnection.getConnection((err, connection) => {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('/admin/admission-applications');
      }

      connection.query('DELETE FROM hostel_admission_applications WHERE id = ?', [appId], (delErr) => {
        connection.release();
        if (delErr) {
          console.error("Error deleting application:", delErr);
          req.flash('message', 'Error removing application');
        } else {
          req.flash('message', 'Application request removed successfully');
        }
        res.redirect('/admin/admission-applications');
      });
    });
  } catch (err) {
    res.clearCookie('jwt');
    res.redirect('/loginpanel');
  }
});

app.post('/admin/admission-applications/:id/transfer', async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.redirect('/loginpanel');
    const decoded = require('jsonwebtoken').verify(token, 'secretkeysvpcet');
    if (decoded.role !== 'SuperID') {
      req.flash('message', 'Unauthorized');
      return res.redirect('/admin/admission-applications');
    }

    const { new_block, new_room, new_bed, transfer_reason } = req.body;
    if (!new_block || !new_room || !new_bed) {
      req.flash('message', 'New block, room, and bed are required');
      return res.redirect('back');
    }

    dbbconnection.getConnection((err, connection) => {
      if (err) { req.flash('message', 'DB Error'); return res.redirect('back'); }

      connection.beginTransaction((err) => {
        if (err) { connection.release(); return res.redirect('back'); }

        connection.query('SELECT student_uid FROM hostel_admission_applications WHERE id = ?', [req.params.id], (err, rows) => {
          if (err || rows.length === 0) {
            return connection.rollback(() => { connection.release(); req.flash('message', 'Application not found'); res.redirect('back'); });
          }

          const student_uid = rows[0].student_uid;
          const transferText = 'TRANSFER: ' + (transfer_reason || 'No reason provided');

          connection.query(
            `UPDATE hostel_admission_applications SET allotted_block=?, allotted_room=?, allotted_bed=?, admin_remarks=IF(IFNULL(admin_remarks,'')='', ?, CONCAT(admin_remarks, ' | ', ?)) WHERE id=?`,
            [new_block, new_room, new_bed, transferText, transferText, req.params.id],
            (err) => {
              if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error updating application'); res.redirect('back'); }); }

              if (student_uid) {
                connection.query(
                  `UPDATE studentdetails SET room_no=?, block=?, bed_no=?, other2=? WHERE uid=?`,
                  [new_room, new_block, new_bed, new_block, student_uid],
                  (err) => {
                    if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error updating student details'); res.redirect('back'); }); }

                    connection.query(
                      `UPDATE room_bookings SET room_no=?, block=?, bed_no=? WHERE uid=? AND booking_status='locked'`,
                      [new_room, new_block, new_bed, student_uid],
                      (err) => {
                        if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error updating room bookings'); res.redirect('back'); }); }

                        connection.commit((err) => {
                          if (err) { return connection.rollback(() => { connection.release(); res.redirect('back'); }); }
                          connection.release();
                          req.flash('message', 'Room transfer successful');
                          res.redirect('/admin/admission-applications/' + req.params.id);
                        });
                      }
                    );
                  }
                );
              } else {
                connection.commit((err) => {
                  if (err) { return connection.rollback(() => { connection.release(); res.redirect('back'); }); }
                  connection.release();
                  req.flash('message', 'Room transfer successful (Application updated)');
                  res.redirect('/admin/admission-applications/' + req.params.id);
                });
              }
            }
          );
        });
      });
    });
  } catch (err) {
    res.clearCookie('jwt');
    res.redirect('/loginpanel');
  }
});

app.post('/admin/admission-applications/:id/remove', async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.redirect('/loginpanel');
    const decoded = require('jsonwebtoken').verify(token, 'secretkeysvpcet');
    if (decoded.role !== 'SuperID') {
      req.flash('message', 'Unauthorized');
      return res.redirect('/admin/admission-applications');
    }

    dbbconnection.getConnection((err, connection) => {
      if (err) { req.flash('message', 'DB Error'); return res.redirect('back'); }

      connection.beginTransaction((err) => {
        if (err) { connection.release(); return res.redirect('back'); }

        connection.query('SELECT student_uid FROM hostel_admission_applications WHERE id = ?', [req.params.id], (err, rows) => {
          if (err || rows.length === 0) {
            return connection.rollback(() => { connection.release(); req.flash('message', 'Application not found'); res.redirect('back'); });
          }

          const student_uid = rows[0].student_uid;

          const removeAppUpdates = () => {
            connection.query(
              `UPDATE hostel_admission_applications SET status='Rejected', student_uid=NULL, admin_remarks=CONCAT(IFNULL(admin_remarks,''), ' | REMOVED FROM SYSTEM by SuperID at ', NOW()) WHERE id=?`,
              [req.params.id],
              (err) => {
                if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error updating application'); res.redirect('back'); }); }

                connection.commit((err) => {
                  if (err) { return connection.rollback(() => { connection.release(); res.redirect('back'); }); }
                  connection.release();
                  req.flash('message', 'Student removed from system');
                  res.redirect('/admin/admission-applications');
                });
              }
            );
          };

          if (student_uid) {
            // Delete from child tables first to avoid foreign key constraint violations
            connection.query('DELETE FROM daily_attendance WHERE uid = ?', [student_uid], (err) => {
              if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error deleting attendance records'); res.redirect('back'); }); }

              connection.query('DELETE FROM room_bookings WHERE uid = ?', [student_uid], (err) => {
                if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error deleting room bookings'); res.redirect('back'); }); }

                connection.query('DELETE FROM studentdetails WHERE uid = ?', [student_uid], (err) => {
                  if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error deleting student'); res.redirect('back'); }); }

                  removeAppUpdates();
                });
              });
            });
          } else {
            removeAppUpdates();
          }
        });
      });
    });
  } catch (err) {
    res.clearCookie('jwt');
    res.redirect('/loginpanel');
  }
});

app.get('/admin/sync-uids', async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.redirect('/loginpanel');
    const decoded = require('jsonwebtoken').verify(token, 'secretkeysvpcet');
    if (decoded.role !== 'SuperID') {
      req.flash('message', 'Unauthorized');
      return res.redirect('/admin/dashboard');
    }

    dbbconnection.getConnection((err, connection) => {
      if (err) { req.flash('message', 'DB Error'); return res.redirect('back'); }

      const countSql = `SELECT COUNT(*) as total FROM studentdetails WHERE is_temp_uid = 1`;
      const previewSql = `SELECT uid, sname, mobileno FROM studentdetails WHERE is_temp_uid = 1 ORDER BY uid ASC`;

      connection.query(countSql, (err, countRows) => {
        if (err) { connection.release(); return res.redirect('back'); }

        connection.query(previewSql, (err, previewRows) => {
          connection.release();
          if (err) return res.redirect('back');
          res.render('admin_sync_uids', {
            tempCount: countRows[0].total,
            tempStudents: previewRows,
            previewResults: null,
            role: decoded.role,
            message: req.flash('message')
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie('jwt');
    res.redirect('/loginpanel');
  }
});

app.post('/admin/sync-uids', async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.redirect('/loginpanel');
    const decoded = require('jsonwebtoken').verify(token, 'secretkeysvpcet');
    if (decoded.role !== 'SuperID') {
      req.flash('message', 'Unauthorized');
      return res.redirect('/admin/dashboard');
    }

    const { college_table, college_uid_col, college_mobile_col, action } = req.body;

    const nameRegex = /^[a-zA-Z0-9_]+$/;
    if (!nameRegex.test(college_table) || !nameRegex.test(college_uid_col) || !nameRegex.test(college_mobile_col)) {
      req.flash('message', 'Invalid table or column names.');
      return res.redirect('back');
    }

    dbbconnection.getConnection((err, connection) => {
      if (err) { req.flash('message', 'DB Error'); return res.redirect('back'); }

      if (action === 'preview') {
        const previewSql = `
          SELECT sd.uid as temp_uid, sd.sname, sd.mobileno, ct.?? as real_uid
          FROM studentdetails sd
          LEFT JOIN ?? ct ON ct.?? = sd.mobileno
          WHERE sd.is_temp_uid = 1
        `;
        connection.query(previewSql, [college_uid_col, college_table, college_mobile_col], (err, rows) => {
          if (err) {
            connection.release();
            req.flash('message', 'Error running preview. Ensure table and column names are correct.');
            return res.redirect('back');
          }

          const countSql = `SELECT COUNT(*) as total FROM studentdetails WHERE is_temp_uid = 1`;
          const allTempSql = `SELECT uid, sname, mobileno FROM studentdetails WHERE is_temp_uid = 1 ORDER BY uid ASC`;

          connection.query(countSql, (err, countRows) => {
            connection.query(allTempSql, (err, tempRows) => {
              connection.release();
              res.render('admin_sync_uids', {
                tempCount: countRows[0].total,
                tempStudents: tempRows,
                previewResults: rows,
                college_table, college_uid_col, college_mobile_col,
                role: decoded.role,
                message: req.flash('message')
              });
            });
          });
        });
      } else {
        connection.beginTransaction((err) => {
          if (err) { connection.release(); return res.redirect('back'); }

          const syncSql = `
            UPDATE studentdetails sd
            JOIN ?? ct ON ct.?? = sd.mobileno
            SET sd.uid = ct.??, sd.is_temp_uid = 0
            WHERE sd.is_temp_uid = 1
          `;

          connection.query(syncSql, [college_table, college_mobile_col, college_uid_col], (err, result) => {
            if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Sync error: ' + err.message); res.redirect('back'); }); }

            const syncBookingsSql = `
              UPDATE room_bookings rb
              JOIN studentdetails sd ON sd.mobileno = rb.uid
              SET rb.uid = sd.uid
              WHERE sd.is_temp_uid = 0 AND rb.uid != sd.uid
            `;

            connection.query(syncBookingsSql, (err) => {
              if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Bookings Sync error: ' + err.message); res.redirect('back'); }); }

              const syncAppsSql = `
                UPDATE hostel_admission_applications haa
                JOIN studentdetails sd ON sd.mobileno = haa.student_mobile
                SET haa.student_uid = sd.uid
                WHERE sd.is_temp_uid = 0 AND haa.student_uid != sd.uid AND haa.status = 'Admitted'
              `;

              connection.query(syncAppsSql, (err) => {
                if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Apps Sync error: ' + err.message); res.redirect('back'); }); }

                connection.commit((err) => {
                  if (err) { return connection.rollback(() => { connection.release(); res.redirect('back'); }); }
                  connection.release();
                  req.flash('message', `Sync complete. ${result.affectedRows} students updated.`);
                  res.redirect('/admin/sync-uids');
                });
              });
            });
          });
        });
      }
    });
  } catch (err) {
    res.clearCookie('jwt');
    res.redirect('/loginpanel');
  }
});

app.post('/admin/student/update-uid', async (req, res) => {
  try {
    const token = req.cookies.jwt;
    if (!token) return res.redirect('/loginpanel');
    const decoded = require('jsonwebtoken').verify(token, 'secretkeysvpcet');
    if (decoded.role !== 'SuperID') {
      req.flash('message', 'Unauthorized');
      return res.redirect('back');
    }

    const { old_uid, new_uid, confirm_uid } = req.body;

    if (!/^[0-9]{8}$/.test(new_uid)) {
      req.flash('message', 'New UID must be exactly 8 digits');
      return res.redirect('back');
    }

    if (new_uid !== confirm_uid) {
      req.flash('message', 'UIDs do not match');
      return res.redirect('back');
    }

    dbbconnection.getConnection((err, connection) => {
      if (err) { req.flash('message', 'DB Error'); return res.redirect('back'); }

      connection.query('SELECT uid FROM studentdetails WHERE uid = ?', [new_uid], (err, rows) => {
        if (err) { connection.release(); return res.redirect('back'); }
        if (rows.length > 0) {
          connection.release();
          req.flash('message', 'UID already exists in system');
          return res.redirect('back');
        }

        connection.beginTransaction((err) => {
          if (err) { connection.release(); return res.redirect('back'); }

          connection.query('UPDATE studentdetails SET uid=?, hostel_id = CASE WHEN is_temp_uid = 1 THEN COALESCE(NULLIF(hostel_id, ""), ?) ELSE hostel_id END, is_temp_uid=0 WHERE uid=?', [new_uid, old_uid, old_uid], (err, result) => {
            if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error updating student details'); res.redirect('back'); }); }

            connection.query('UPDATE room_bookings SET uid=? WHERE uid=?', [new_uid, old_uid], (err) => {
              if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error updating bookings'); res.redirect('back'); }); }

              connection.query('UPDATE hostel_admission_applications SET student_uid=? WHERE student_uid=?', [new_uid, old_uid], (err) => {
                if (err) { return connection.rollback(() => { connection.release(); req.flash('message', 'Error updating applications'); res.redirect('back'); }); }

                connection.query('UPDATE pass_requests SET uid=? WHERE uid=?', [new_uid, old_uid], (err) => {
                  if (err && err.code !== 'ER_NO_SUCH_TABLE') {
                    return connection.rollback(() => { connection.release(); req.flash('message', 'Error updating passes'); res.redirect('back'); });
                  }

                  connection.commit((err) => {
                    if (err) { return connection.rollback(() => { connection.release(); res.redirect('back'); }); }
                    connection.release();
                    req.flash('message', `UID updated successfully from ${old_uid} to ${new_uid}`);
                    res.redirect('back');
                  });
                });
              });
            });
          });
        });
      });
    });
  } catch (err) {
    res.clearCookie('jwt');
    res.redirect('/loginpanel');
  }
});

// Feature 2: Edit Student routes
app.get('/admin/student/edit/:uid', (req, res) => {
  const tokenadmin = req.cookies.jwt;
  if (!tokenadmin) return res.redirect('/loginpanel');

  try {
    const decode = jwt.verify(tokenadmin, "secretkeysvpcet");
    if (decode.role !== 'SuperID') {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    const uid = req.params.uid;
    dbbconnection.getConnection((err, connection) => {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('back');
      }
      connection.query("SELECT * FROM studentdetails WHERE uid = ?", [uid], (err, result) => {
        connection.release();
        if (err || result.length === 0) {
          req.flash('message', 'Student not found');
          return res.redirect('/studentsupdate');
        }
        res.render('admin_student_edit', {
          student: result[0],
          message: req.flash('message'),
          role: decode.role
        });
      });
    });
  } catch (e) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

app.post('/admin/student/edit/:uid', (req, res) => {
  const tokenadmin = req.cookies.jwt;
  if (!tokenadmin) return res.redirect('/loginpanel');

  try {
    const decode = jwt.verify(tokenadmin, "secretkeysvpcet");
    if (decode.role !== 'SuperID') {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    const uid = req.params.uid;
    const { sname, email, dept, address, year, category, gender, mobileno, dob, academicyear, status, parentname, parentnumber, room_no, bed_no, mess_type, block } = req.body;

    dbbconnection.getConnection((err, connection) => {
      if (err) {
        req.flash('message', 'Database error');
        return res.redirect('back');
      }

      const fieldsConfig = [
        { field: 'sname', val: sname },
        { field: 'email', val: email },
        { field: 'dept', val: dept },
        { field: 'address', val: address },
        { field: 'year', val: year },
        { field: 'category', val: category },
        { field: 'gender', val: gender },
        { field: 'mobileno', val: mobileno },
        { field: 'dob', val: dob },
        { field: 'academicyear', val: academicyear },
        { field: 'status', val: status },
        { field: 'parentname', val: parentname },
        { field: 'parentnumber', val: parentnumber },
        { field: 'room_no', val: room_no },
        { field: 'bed_no', val: bed_no },
        { field: 'other1', val: mess_type },
        { field: 'other2', val: block }
      ];

      const updateFields = [];
      const updateParams = [];

      fieldsConfig.forEach(item => {
        if (item.val !== undefined) {
          updateFields.push(`${item.field}=?`);
          updateParams.push(item.val);
        }
      });

      if (updateFields.length === 0) {
        connection.release();
        req.flash('message', 'Student details updated successfully');
        return res.redirect('/admin/student/edit/' + uid);
      }

      updateParams.push(uid);
      const updateSql = `UPDATE studentdetails SET ${updateFields.join(', ')} WHERE uid=?`;

      connection.query(updateSql, updateParams, (err, result) => {
        connection.release();
        if (err) {
          req.flash('message', 'Error updating student details');
          return res.redirect('back');
        }
        req.flash('message', 'Student details updated successfully');
        res.redirect('/admin/student/edit/' + uid);
      });
    });
  } catch (e) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

app.post('/admin/student/resetpassword/:uid', (req, res) => {
  const tokenadmin = req.cookies.jwt;
  if (!tokenadmin) return res.redirect('/loginpanel');

  try {
    const decode = jwt.verify(tokenadmin, "secretkeysvpcet");
    if (decode.role !== 'SuperID') {
      req.flash('message', 'Unauthorised Access');
      return res.redirect('/loginpanel');
    }

    const uid = req.params.uid;
    const newPassword = req.body.new_password;

    if (!newPassword || newPassword.length < 8) {
      req.flash('message', 'Password must be at least 8 characters');
      return res.redirect('/admin/student/edit/' + uid);
    }

    bcrypt.hash(newPassword, 10, (err, hash) => {
      if (err) {
        req.flash('message', 'Error hashing password');
        return res.redirect('/admin/student/edit/' + uid);
      }

      dbbconnection.getConnection((err, connection) => {
        if (err) {
          req.flash('message', 'Database error');
          return res.redirect('back');
        }

        connection.query("UPDATE studentdetails SET password=? WHERE uid=?", [hash, uid], (err, result) => {
          connection.release();
          if (err) {
            req.flash('message', 'Error resetting password');
            return res.redirect('back');
          }
          req.flash('message', 'Password reset successfully');
          res.redirect('/admin/student/edit/' + uid);
        });
      });
    });
  } catch (e) {
    res.clearCookie("jwt");
    return res.redirect('/loginpanel');
  }
});

// =====================================================
// BONAFIDE CERTIFICATE MODULE
// =====================================================

// --- Utility: Format academic year e.g. 2025 -> "2025-26" ---
function formatAcademicYear(year) {
  if (!year) return null;
  const y = parseInt(year, 10);
  if (isNaN(y)) return String(year);
  const next = String(y + 1).slice(-2);
  return `${y}-${next}`;
}

// --- Utility: Get current academic year based on current date ---
function getCurrentAcademicYear() {
  const today = new Date();
  let year = today.getFullYear();
  // Academic year changes in June (Month 5 is June, 0-indexed)
  if (today.getMonth() >= 5) {
    const next = String(year + 1).slice(-2);
    return `${year}-${next}`;
  } else {
    const prev = year - 1;
    const suffix = String(year).slice(-2);
    return `${prev}-${suffix}`;
  }
}

// --- Utility: Generate Certificate Number e.g. BONA/2025/0012 ---
function generateCertificateNo(id, year) {
  const y = year ? String(parseInt(year, 10) || new Date().getFullYear()) : String(new Date().getFullYear());
  const seq = String(id).padStart(4, '0');
  return `BONA/${y}/${seq}`;
}

// --- Utility: Generate formatted date DD/MM/YYYY ---
function formatCertDate(date) {
  const d = date || new Date();
  const dd = String(d.getDate()).padStart(2, '0');
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const yyyy = d.getFullYear();
  return `${dd}/${mm}/${yyyy}`;
}

// --- Utility: Calculate Hostel Boarding and Mess Fee Breakdown ---
function calculateHostelFeeBreakdown(messType, occupancy) {
  let m = (messType || '').toLowerCase().trim();
  if (m.indexOf('non') !== -1) {
    m = 'nonveg';
  } else if (m.indexOf('veg') !== -1) {
    m = 'veg';
  } else {
    m = 'veg'; // Default fallback
  }

  let o = (occupancy || '').toLowerCase().trim();
  if (o.indexOf('single') !== -1) {
    o = 'single';
  } else if (o.indexOf('double') !== -1) {
    o = 'double';
  } else if (o.indexOf('triple') !== -1) {
    o = 'triple';
  } else {
    o = 'double'; // Default fallback
  }

  const messFeeStructure = { veg: 39000, nonveg: 40000 };
  const boardingFeeStructure = { single: 40000, double: 36000, triple: 32000 };
  const mess = messFeeStructure[m] || 0;
  const boarding = boardingFeeStructure[o] || 0;
  return { boarding, mess, total: boarding + mess };
}

// --- Utility: Generate Bank Details Certificate Number e.g. BANK/2025/0012 ---
function generateBankCertificateNo(id, year) {
  const y = year ? String(parseInt(year, 10) || new Date().getFullYear()) : String(new Date().getFullYear());
  const seq = String(id).padStart(4, '0');
  return `BANK/${y}/${seq}`;
}

// --- Startup: Create all bonafide tables in ONE connection (connection-pool safe) ---
dbbconnection.getConnection(function (err, conn) {
  if (err || !conn) {
    if (err) console.warn('Bonafide startup migration skipped (no DB connection):', err.message);
    return;
  }

  function executeQuery(sql, params, cb) {
    if (typeof params === 'function') {
      cb = params;
      params = [];
    }
    conn.query(sql, params, function (e, res) {
      if (e) console.error(`Query failed [${sql.slice(0, 50)}...]:`, e.message);
      cb(e, res);
    });
  }

  function addIndexIfNotExists(tableName, indexName, columnsStr, isUnique, callback) {
    const checkSql = `
      SELECT INDEX_NAME 
      FROM INFORMATION_SCHEMA.STATISTICS 
      WHERE TABLE_SCHEMA = DATABASE() 
        AND TABLE_NAME = ? 
        AND INDEX_NAME = ? 
      LIMIT 1`;
    conn.query(checkSql, [tableName, indexName], function (err, rows) {
      if (err) {
        console.error(`Check index ${indexName} failed:`, err.message);
        return callback();
      }
      if (rows && rows.length > 0) {
        return callback(); // Index already exists
      }
      const createSql = isUnique
        ? `ALTER TABLE ${tableName} ADD UNIQUE KEY ${indexName} (${columnsStr})`
        : `CREATE INDEX ${indexName} ON ${tableName} (${columnsStr})`;
      conn.query(createSql, function (errCreate) {
        if (errCreate) {
          console.error(`Creating index ${indexName} failed:`, errCreate.message);
        }
        return callback();
      });
    });
  }

  function checkAndAddColumn(tableName, columnName, alterSql, callback) {
    conn.query(`SHOW COLUMNS FROM ${tableName} LIKE ?`, [columnName], function (err, rows) {
      if (err) {
        console.error(`Check column ${columnName} failed:`, err.message);
        return callback();
      }
      if (rows && rows.length > 0) {
        return callback(); // Column already exists
      }
      conn.query(alterSql, function (errAlter) {
        if (errAlter) {
          console.error(`Adding column ${columnName} failed:`, errAlter.message);
        }
        return callback();
      });
    });
  }

  // Chain migrations sequentially
  const createBonafide = `
    CREATE TABLE IF NOT EXISTS bonafide_requests (
      id INT AUTO_INCREMENT PRIMARY KEY,
      student_uid VARCHAR(50) NOT NULL,
      student_name VARCHAR(200) NOT NULL,
      enrollment_no VARCHAR(50),
      branch VARCHAR(200),
      year VARCHAR(20),
      hostel_fee DECIMAL(10,2),
      academic_year VARCHAR(20),
      purpose VARCHAR(500) DEFAULT 'Scholarship Purpose Only',
      occupancy VARCHAR(20) NULL,
      mess_type VARCHAR(20) NULL,
      payment_status VARCHAR(20) DEFAULT 'pending',
      status ENUM('Pending','Approved','Rejected','Printed','Collected') DEFAULT 'Pending',
      certificate_no VARCHAR(100),
      verification_token VARCHAR(200),
      request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
      approved_date DATETIME NULL,
      printed_date DATETIME NULL,
      collected_date DATETIME NULL,
      rejection_reason TEXT,
      admin_remark TEXT,
      notification_sent TINYINT(1) DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )`;

  executeQuery(createBonafide, function () {
    checkAndAddColumn('bonafide_requests', 'occupancy', 'ALTER TABLE bonafide_requests ADD COLUMN occupancy VARCHAR(20) NULL', function () {
      checkAndAddColumn('bonafide_requests', 'mess_type', 'ALTER TABLE bonafide_requests ADD COLUMN mess_type VARCHAR(20) NULL', function () {
        checkAndAddColumn('bonafide_requests', 'payment_status', "ALTER TABLE bonafide_requests ADD COLUMN payment_status VARCHAR(20) DEFAULT 'pending'", function () {

          // Create notifications table
          const createNotif = `
          CREATE TABLE IF NOT EXISTS student_notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            uid VARCHAR(50) NOT NULL,
            title VARCHAR(255) NOT NULL,
            message TEXT,
            type VARCHAR(50) DEFAULT 'GENERAL',
            is_read TINYINT(1) DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          )`;

          executeQuery(createNotif, function () {
            // Create settings table
            const createSettings = `
            CREATE TABLE IF NOT EXISTS certificate_settings (
              id INT AUTO_INCREMENT PRIMARY KEY,
              setting_key VARCHAR(100) NOT NULL UNIQUE,
              setting_value VARCHAR(200) NOT NULL,
              updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )`;

            executeQuery(createSettings, function () {
              // Safe conversion of old settings
              executeQuery("UPDATE certificate_settings SET setting_value = '3.5' WHERE setting_key = 'top_margin' AND setting_value = '145'", function () {
                executeQuery("UPDATE certificate_settings SET setting_value = '2.0' WHERE setting_key = 'left_margin' AND setting_value = '70'", function () {
                  executeQuery("UPDATE certificate_settings SET setting_value = '2.0' WHERE setting_key = 'right_margin' AND setting_value = '70'", function () {
                    executeQuery("UPDATE certificate_settings SET setting_value = '2.0' WHERE setting_key = 'line_height' AND setting_value = '1.7'", function () {
                      executeQuery("UPDATE certificate_settings SET setting_value = '3.0' WHERE setting_key = 'bottom_margin' AND setting_value = '2.0'", function () {

                        // Insert settings defaults
                        const defaults = [
                          ['top_margin', '3.5'], ['bottom_margin', '3.0'], ['left_margin', '2.0'], ['right_margin', '2.0'],
                          ['font_size', '18'], ['line_height', '2.0']
                        ];
                        let sIndex = 0;
                        function insertNextSetting() {
                          if (sIndex >= defaults.length) {
                            // Check hostel_fee column on studentdetails
                            checkAndAddColumn('studentdetails', 'hostel_fee', 'ALTER TABLE studentdetails ADD COLUMN hostel_fee DECIMAL(10,2) NULL', function () {
                              // Create audit logs table
                              const createAuditSql = `
                              CREATE TABLE IF NOT EXISTS bonafide_audit_logs (
                                id INT AUTO_INCREMENT PRIMARY KEY,
                                request_id INT NOT NULL,
                                action VARCHAR(50) NOT NULL,
                                performed_by VARCHAR(100) NOT NULL,
                                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                              )`;
                              executeQuery(createAuditSql, function () {

                                // Setup all Indexes and Unique constraints safely and idempotently
                                addIndexIfNotExists('bonafide_requests', 'idx_bonafide_uid', 'student_uid', false, function () {
                                  addIndexIfNotExists('bonafide_requests', 'idx_bonafide_status', 'status', false, function () {
                                    addIndexIfNotExists('bonafide_requests', 'idx_bonafide_year', 'academic_year', false, function () {
                                      addIndexIfNotExists('student_notifications', 'idx_sn_uid', 'uid', false, function () {
                                        addIndexIfNotExists('student_notifications', 'idx_sn_read', 'is_read', false, function () {
                                          addIndexIfNotExists('bonafide_requests', 'unique_request', 'student_uid, academic_year', true, function () {

                                            // --- Start: Hostel Bank Details Module Startup Migrations ---
                                            const createBankRequests = `
                                            CREATE TABLE IF NOT EXISTS hostel_bank_requests (
                                              id INT AUTO_INCREMENT PRIMARY KEY,
                                              student_uid VARCHAR(50) NOT NULL,
                                              student_name VARCHAR(200) NOT NULL,
                                              father_name VARCHAR(200) NOT NULL,
                                              enrollment_no VARCHAR(50),
                                              branch VARCHAR(200),
                                              year VARCHAR(20),
                                              academic_year VARCHAR(20),
                                              boarding_fee DECIMAL(10,2),
                                              mess_fee DECIMAL(10,2),
                                              total_fee DECIMAL(10,2),
                                              purpose ENUM('Hostel Fee Payment','Education Loan','Scholarship','Personal Record','Other') NOT NULL,
                                              purpose_desc VARCHAR(300),
                                              payment_status VARCHAR(20) DEFAULT 'Pending',
                                              status ENUM('Pending','Approved','Rejected','Printed','Collected','Cancelled') DEFAULT 'Pending',
                                              document_no VARCHAR(100),
                                              verification_token VARCHAR(200),
                                              bank_name VARCHAR(100),
                                              account_holder VARCHAR(200),
                                              bank_branch VARCHAR(100),
                                              account_number VARCHAR(50),
                                              ifsc VARCHAR(20),
                                              upi_number VARCHAR(50),
                                              contact_number VARCHAR(20),
                                              email VARCHAR(100),
                                              request_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                                              approved_by VARCHAR(50),
                                              approved_date DATETIME NULL,
                                              printed_date DATETIME NULL,
                                              collected_by VARCHAR(50),
                                              collected_date DATETIME NULL,
                                              rejection_reason TEXT,
                                              admin_remark TEXT,
                                              notification_sent TINYINT(1) DEFAULT 0,
                                              created_by_role VARCHAR(30),
                                              created_by_uid VARCHAR(50),
                                              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                                              updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                                            )`;

                                            const createBankSettings = `
                                            CREATE TABLE IF NOT EXISTS hostel_bank_settings (
                                              id INT PRIMARY KEY,
                                              bank_name VARCHAR(100) NOT NULL,
                                              account_holder VARCHAR(200) NOT NULL,
                                              branch VARCHAR(100) NOT NULL,
                                              account_number VARCHAR(50) NOT NULL,
                                              ifsc VARCHAR(20) NOT NULL,
                                              upi_number VARCHAR(50),
                                              contact_number VARCHAR(20),
                                              email VARCHAR(100),
                                              top_margin VARCHAR(20) DEFAULT '3.5',
                                              bottom_margin VARCHAR(20) DEFAULT '3.0',
                                              left_margin VARCHAR(20) DEFAULT '2.0',
                                              right_margin VARCHAR(20) DEFAULT '2.0',
                                              font_size VARCHAR(20) DEFAULT '18',
                                              line_height VARCHAR(20) DEFAULT '2.0',
                                              logo_path VARCHAR(200),
                                              updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                                            )`;

                                            const createBankAuditLogs = `
                                            CREATE TABLE IF NOT EXISTS hostel_bank_audit_logs (
                                              id INT AUTO_INCREMENT PRIMARY KEY,
                                              request_id INT NOT NULL,
                                              action VARCHAR(50) NOT NULL,
                                              old_status VARCHAR(20),
                                              new_status VARCHAR(20),
                                              performed_by VARCHAR(100) NOT NULL,
                                              performed_role VARCHAR(50) NOT NULL,
                                              remarks TEXT,
                                              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                                            )`;

                                            executeQuery(createBankRequests, function () {
                                              executeQuery(createBankSettings, function () {
                                                executeQuery(createBankAuditLogs, function () {
                                                  const defaultBankSettings = `
                                                  INSERT IGNORE INTO hostel_bank_settings 
                                                    (id, bank_name, account_holder, branch, account_number, ifsc, upi_number, contact_number, email, top_margin, bottom_margin, left_margin, right_margin, font_size, line_height)
                                                  VALUES 
                                                    (1, 'State Bank of India', 'TNPS BOYS HOSTEL', 'Wardha Road Branch', '12345678901', 'SBIN0001234', '1234567890@sbi', '9876543210', 'hostel@svpcet.edu.in', '3.5', '3.0', '2.0', '2.0', '18', '2.0')`;
                                                  executeQuery(defaultBankSettings, function () {
                                                    addIndexIfNotExists('hostel_bank_requests', 'idx_hbr_uid', 'student_uid', false, function () {
                                                      addIndexIfNotExists('hostel_bank_requests', 'idx_hbr_status', 'status', false, function () {
                                                        addIndexIfNotExists('hostel_bank_requests', 'idx_hbr_year', 'academic_year', false, function () {
                                                          addIndexIfNotExists('hostel_bank_requests', 'unique_bank_request', 'student_uid, academic_year', true, function () {
                                                            conn.release();
                                                            console.log('Bonafide and Hostel Bank startup migrations complete.');
                                                          });
                                                        });
                                                      });
                                                    });
                                                  });
                                                });
                                              });
                                            });
                                            // --- End: Hostel Bank Details Module Startup Migrations ---

                                          });
                                        });
                                      });
                                    });
                                  });
                                });
                              });
                            });
                            return;
                          }
                          const [key, val] = defaults[sIndex++];
                          conn.query(
                            "INSERT IGNORE INTO certificate_settings (setting_key, setting_value) VALUES (?, ?)",
                            [key, val],
                            function () { insertNextSetting(); }
                          );
                        }
                        insertNextSetting();
                      });
                    });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});


// --- Helper: Create Student Notification ---
function createStudentNotification(conn, uid, title, message, cb) {
  const notifSql = `
    INSERT INTO student_notifications (uid, title, message, type)
    VALUES (?, ?, ?, 'BONAFIDE')`;
  conn.query(notifSql, [uid, title, message], function (err) {
    if (err) console.error('Error creating notification:', err.message);
    if (cb) cb(err);
  });
}

// --- Helper: Log Bonafide Audit ---
function logBonafideAudit(conn, requestId, action, performedBy, cb) {
  const auditSql = `
    INSERT INTO bonafide_audit_logs (request_id, action, performed_by)
    VALUES (?, ?, ?)`;
  conn.query(auditSql, [requestId, action, performedBy], function (err) {
    if (err) console.error('Error logging audit:', err.message);
    if (cb) cb(err);
  });
}

// --- Helper: Log Hostel Bank Audit ---
function logHostelBankAudit(conn, requestId, action, oldStatus, newStatus, performedBy, performedRole, remarks, cb) {
  const auditSql = `
    INSERT INTO hostel_bank_audit_logs (request_id, action, old_status, new_status, performed_by, performed_role, remarks)
    VALUES (?, ?, ?, ?, ?, ?, ?)`;
  conn.query(auditSql, [requestId, action, oldStatus, newStatus, performedBy, performedRole, remarks || null], function (err) {
    if (err) console.error('Error logging bank audit:', err.message);
    if (cb) cb(err);
  });
}

// --- Helper: Format Branch Name for Bonafide ---
function formatBranchForBonafide(branch) {
  if (!branch || typeof branch !== 'string') return '';
  var b = branch.trim().toUpperCase().replace(/\s+/g, ' ');

  var exactMap = {
    'CSE(DATA SCIENCE)': 'Computer Science and Engineering (Data Science)',
    'CSE (DATA SCIENCE)': 'Computer Science and Engineering (Data Science)',
    'CSE-DATA SCIENCE': 'Computer Science and Engineering (Data Science)',
    'CSE - DATA SCIENCE': 'Computer Science and Engineering (Data Science)',
    'COMPUTER SCIENCE AND DATA SCIENCE': 'Computer Science and Engineering (Data Science)',
    'CSE DS': 'Computer Science and Engineering (Data Science)',

    'CSE(CYBER SECURITY)': 'Computer Science and Engineering (Cyber Security)',
    'CSE (CYBER SECURITY)': 'Computer Science and Engineering (Cyber Security)',
    'CSE-CYBER SECURITY': 'Computer Science and Engineering (Cyber Security)',
    'CSE - CYBER SECURITY': 'Computer Science and Engineering (Cyber Security)',
    'Computer Science & Engineering (Cyber Security)': 'Computer Science and Engineering (Cyber Security)',

    'COMPUTER SCIENCE & ENGINEERING': 'Computer Science and Engineering',
    'COMPUTER SCIENCE & ENGINEERING (CSE)': 'Computer Science and Engineering',
    'Computer Science & Engineering (CSE)': 'Computer Science and Engineering',
    'COMPUTER SCIENCE AND ENGINEERING': 'Computer Science and Engineering',
    'CSE': 'Computer Science and Engineering',

    'COMPUTER ENGINEERING': 'Computer Engineering',
    'COMPUTER SCIENCE AND BUSINESS SYSTEMS': 'Computer Science and Business Systems',
    'CSBS': 'Computer Science and Business Systems',

    'ARTIFICIAL INTELLIGENCE': 'Artificial Intelligence',
    'ARTIFICIAL INTELLIGENCE (AI)': 'Artificial Intelligence',
    'Artificial Intelligence (AI)': 'Artificial Intelligence',
    'AI': 'Artificial Intelligence',

    'ROBOTICS & ARTIFICIAL INTELLIGENCE': 'Robotics and Artificial Intelligence',
    'ROBOTICS AND ARTIFICIAL INTELLIGENCE': 'Robotics and Artificial Intelligence',

    'INFORMATION TECHNOLOGY': 'Information Technology',
    'INFORMATION TECHNOLOGY (IT)': 'Information Technology',
    'Information Technology (IT)': 'Information Technology',
    'IT': 'Information Technology',

    'ELECTRONICS & TELECOMMUNICATION': 'Electronics and Telecommunication',
    'ELECTRONICS AND TELECOMMUNICATION': 'Electronics and Telecommunication',
    'ETC': 'Electronics and Telecommunication',

    'ELECTRICAL ENGINEERING': 'Electrical Engineering',
    'ELECTIRICAL': 'Electrical Engineering',
    'EEE': 'Electrical Engineering',

    'MECHANICAL ENGINEERING': 'Mechanical Engineering',
    'MECH': 'Mechanical Engineering',

    'CIVIL ENGINEERING': 'Civil Engineering',
    'CIVIL': 'Civil Engineering',

    'MECHANICAL CAD-CAM': 'Mechanical Engineering (CAD-CAM)',
    'M.TECH CADCAM': 'M.Tech in CAD-CAM',
    'M.TECH CSE': 'M.Tech in Computer Science and Engineering',
    'INDUSTRIAL IOT': 'Industrial Internet of Things',

    'B.VOC. IN CYBER SECURITY': 'B.Voc. in Cyber Security',
    'B.VOC. IN SOFTWARE DEVELOPMENT': 'B.Voc. in Software Development',
    'B.VOC. IN VIRTUAL REALITY & AR': 'B.Voc. in Virtual Reality and Augmented Reality',
    'B.VOC. IN VIRTUAL REALITY & AUGMENTED REALITY': 'B.Voc. in Virtual Reality and Augmented Reality',
    'B.VOC. IN VIRTUAL REALITY AND AUGMENTED REALITY': 'B.Voc. in Virtual Reality and Augmented Reality',
    'B VOCATIONAL': 'B.Vocational',
    'BVOC': 'B.Vocational'
  };

  if (exactMap[b]) return exactMap[b];

  for (var key in exactMap) {
    if (b === key.toUpperCase()) return exactMap[key];
  }

  if (b.includes('DATA SCIENCE')) {
    return 'Computer Science and Engineering (Data Science)';
  }
  if (b.includes('CYBER SECURITY')) {
    return 'Computer Science and Engineering (Cyber Security)';
  }
  if (b.includes('BUSINESS SYSTEMS')) {
    return 'Computer Science and Business Systems';
  }
  if (b.includes('COMPUTER SCIENCE') || b.includes('CSE')) {
    if (b.includes('M.TECH') || b.includes('MTECH')) {
      return 'M.Tech in Computer Science and Engineering';
    }
    return 'Computer Science and Engineering';
  }
  if (b.includes('ARTIFICIAL INTELLIGENCE') || b.includes('AI')) {
    if (b.includes('ROBOTICS')) {
      return 'Robotics and Artificial Intelligence';
    }
    return 'Artificial Intelligence';
  }
  if (b.includes('INFORMATION TECHNOLOGY') || b.includes('IT')) {
    return 'Information Technology';
  }
  if (b.includes('ELECTRONICS') || b.includes('ETC')) {
    return 'Electronics and Telecommunication';
  }
  if (b.includes('ELECTRICAL') || b.includes('EEE')) {
    return 'Electrical Engineering';
  }
  if (b.includes('MECHANICAL') || b.includes('MECH')) {
    if (b.includes('CAD')) {
      return 'Mechanical Engineering (CAD-CAM)';
    }
    return 'Mechanical Engineering';
  }
  if (b.includes('CIVIL')) {
    return 'Civil Engineering';
  }
  if (b.includes('B.VOC') || b.includes('BVOC') || b.includes('B VOC')) {
    if (b.includes('CYBER')) return 'B.Voc. in Cyber Security';
    if (b.includes('SOFTWARE')) return 'B.Voc. in Software Development';
    if (b.includes('VIRTUAL') || b.includes('AR')) return 'B.Voc. in Virtual Reality and Augmented Reality';
    return 'B.Vocational';
  }

  return branch.toLowerCase().replace(/\b\w/g, function (char) { return char.toUpperCase(); });
}


// =====================================================
// STUDENT: GET /student/bonafide
// =====================================================
app.get('/student/bonafide', verifyStudentJwt, studentBonafideLimiter, csrfProtection, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      req.flash('message', 'Database connection error');
      return res.redirect('/student/dashboard');
    }

    conn.query('SELECT * FROM studentdetails WHERE uid = ? LIMIT 1', [uid], function (e, rows) {
      if (e) {
        conn.release();
        req.flash('message', 'Database error reading profile');
        return res.redirect('/student/dashboard');
      }
      if (!rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Student not found');
        return res.redirect('/student/dashboard');
      }
      const student = rows[0];
      student.dept = formatBranchForBonafide(student.dept);
      const currentAcademicYear = getCurrentAcademicYear();

      // Check existing request for this academic year (excluding rejected requests)
      conn.query(
        "SELECT * FROM bonafide_requests WHERE student_uid = ? AND academic_year = ? AND status != 'Rejected' LIMIT 1",
        [uid, currentAcademicYear],
        function (e2, existing) {
          if (e2) {
            conn.release();
            req.flash('message', 'Database error checking requests');
            return res.redirect('/student/dashboard');
          }
          // Get all history
          conn.query(
            'SELECT * FROM bonafide_requests WHERE student_uid = ? ORDER BY request_date DESC',
            [uid],
            function (e3, history) {
              conn.release();
              if (e3) {
                req.flash('message', 'Database error fetching history');
                return res.redirect('/student/dashboard');
              }
              if (history) {
                history.forEach(function (h) {
                  h.branch = formatBranchForBonafide(h.branch);
                });
              }
              attachStudentPhotoUrl(student);
              return res.render(__dirname + '/views/student_bonafide', {
                student: student,
                academicYearFormatted: currentAcademicYear,
                existingRequest: existing && existing[0] ? existing[0] : null,
                history: history || [],
                csrfToken: req.csrfToken(),
                message: req.flash('message')
              });
            }
          );
        }
      );
    });
  });
});

// =====================================================
// STUDENT: POST /student/bonafide/request
// =====================================================
app.post('/student/bonafide/request', verifyStudentJwt, studentBonafideLimiter, csrfProtection, function (req, res) {
  const uid = req.studentUid;
  let studentName = (req.body.student_name || '').trim();
  let purpose = (req.body.purpose || '').trim();
  const otherPurpose = (req.body.other_purpose || '').trim();
  const occupancy = (req.body.occupancy || '').toLowerCase().trim();
  const messType = (req.body.mess_type || '').toLowerCase().trim();

  if (purpose === 'Other') {
    purpose = otherPurpose.trim();
  }

  // --- 1. Input Validation ---
  if (!studentName || studentName.length < 3 || studentName.length > 100) {
    req.flash('message', 'Student name must be between 3 and 100 characters.');
    return res.redirect('/student/bonafide');
  }
  if (!purpose || purpose.length > 300) {
    req.flash('message', 'Purpose is required and must not exceed 300 characters.');
    return res.redirect('/student/bonafide');
  }
  if (!['single', 'double', 'triple'].includes(occupancy)) {
    req.flash('message', 'Invalid occupancy selection.');
    return res.redirect('/student/bonafide');
  }
  if (!['veg', 'nonveg'].includes(messType)) {
    req.flash('message', 'Invalid mess type selection.');
    return res.redirect('/student/bonafide');
  }

  // --- 2. Calculate hostel_fee based on occupancy and mess_type (Server-side calculation) ---
  const feeBreakdown = calculateHostelFeeBreakdown(messType, occupancy);
  const hostelFee = feeBreakdown.total;

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      req.flash('message', 'Database connection error.');
      return res.redirect('/student/bonafide');
    }

    // Fetch latest student data to verify hostel category
    conn.query('SELECT * FROM studentdetails WHERE uid = ? LIMIT 1', [uid], function (e, rows) {
      if (e) {
        conn.release();
        req.flash('message', 'Database error.');
        return res.redirect('/student/bonafide');
      }
      if (!rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Student record not found.');
        return res.redirect('/student/bonafide');
      }
      const student = rows[0];

      // Only hostellers allowed
      if (!student.category || student.category.toLowerCase() !== 'hostel') {
        conn.release();
        req.flash('message', 'Bonafide certificate is only for hostel students.');
        return res.redirect('/student/bonafide');
      }

      const currentAcademicYear = getCurrentAcademicYear();
      const formattedBranch = formatBranchForBonafide(student.dept);

      // Start transaction to clean up/update request and add audit log together
      conn.beginTransaction(function (errTx) {
        if (errTx) {
          conn.release();
          req.flash('message', 'Transaction error.');
          return res.redirect('/student/bonafide');
        }

        // Fetch request first Ã¢â‚¬â€ to check duplicates or see if we need to reuse a Rejected request
        conn.query(
          "SELECT id, status FROM bonafide_requests WHERE student_uid = ? AND academic_year = ? LIMIT 1",
          [uid, currentAcademicYear],
          function (e2, existing) {
            if (e2) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Database error.');
                return res.redirect('/student/bonafide');
              });
            }

            if (existing && existing.length > 0) {
              const reqRecord = existing[0];
              if (reqRecord.status !== 'Rejected') {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'You have already requested a Bonafide Certificate for this academic year.');
                  return res.redirect('/student/bonafide');
                });
              }

              // Row is Rejected. Update it back to Pending instead of deleting to preserve history!
              const updateSql = `
                UPDATE bonafide_requests
                SET student_name = ?, branch = ?, year = ?, hostel_fee = ?, purpose = ?, occupancy = ?, mess_type = ?, status = 'Pending', request_date = UTC_TIMESTAMP(), rejection_reason = NULL, certificate_no = NULL, verification_token = NULL
                WHERE id = ?`;
              conn.query(updateSql, [
                studentName,
                formattedBranch,
                student.year,
                hostelFee,
                purpose,
                occupancy,
                messType,
                reqRecord.id
              ], function (e3, result) {
                if (e3) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Failed to submit request. Please try again.');
                    return res.redirect('/student/bonafide');
                  });
                }

                logBonafideAudit(conn, reqRecord.id, 'Created', studentName, function (eAudit) {
                  if (eAudit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Audit log error.');
                      return res.redirect('/student/bonafide');
                    });
                  }

                  conn.commit(function (eCommit) {
                    if (eCommit) {
                      return conn.rollback(function () {
                        conn.release();
                        req.flash('message', 'Failed to save request.');
                        return res.redirect('/student/bonafide');
                      });
                    }
                    conn.release();
                    req.flash('message', 'Your request has been submitted successfully. You will be notified after verification.');
                    return res.redirect('/student/bonafide');
                  });
                });
              });
            } else {
              // No existing request, perform insert
              const insertSql = `
                INSERT INTO bonafide_requests
                  (student_uid, student_name, enrollment_no, branch, year, hostel_fee, academic_year, purpose, occupancy, mess_type, status, request_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', UTC_TIMESTAMP())`;
              conn.query(insertSql, [
                uid,
                studentName,
                student.uid,
                formattedBranch,
                student.year,
                hostelFee,
                currentAcademicYear,
                purpose,
                occupancy,
                messType
              ], function (e3, result) {
                if (e3) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Failed to submit request. Please try again.');
                    return res.redirect('/student/bonafide');
                  });
                }

                const requestId = result.insertId;

                // Log audit trail
                logBonafideAudit(conn, requestId, 'Created', studentName, function (eAudit) {
                  if (eAudit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Audit log error.');
                      return res.redirect('/student/bonafide');
                    });
                  }

                  conn.commit(function (eCommit) {
                    if (eCommit) {
                      return conn.rollback(function () {
                        conn.release();
                        req.flash('message', 'Failed to save request.');
                        return res.redirect('/student/bonafide');
                      });
                    }
                    conn.release();
                    req.flash('message', 'Your request has been submitted successfully. You will be notified after verification.');
                    return res.redirect('/student/bonafide');
                  });
                });
              });
            }
          }
        );
      });
    });
  });
});

// =====================================================
// STUDENT: POST /student/bonafide/:id/cancel
// =====================================================
app.post('/student/bonafide/:id/cancel', verifyStudentJwt, studentBonafideLimiter, csrfProtection, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const uid = req.studentUid;
  if (!id) {
    req.flash('message', 'Invalid Request ID.');
    return res.redirect('/student/bonafide');
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      req.flash('message', 'Database connection error.');
      return res.redirect('/student/bonafide');
    }

    // Check if request exists, belongs to student, and is Pending
    conn.query(
      'SELECT id, status FROM bonafide_requests WHERE id = ? AND student_uid = ? LIMIT 1',
      [id, uid],
      function (e, rows) {
        if (e) {
          conn.release();
          req.flash('message', 'Database error.');
          return res.redirect('/student/bonafide');
        }

        if (!rows || rows.length === 0) {
          conn.release();
          req.flash('message', 'Request not found.');
          return res.redirect('/student/bonafide');
        }

        const request = rows[0];
        if (request.status !== 'Pending') {
          conn.release();
          req.flash('message', 'Only pending requests can be cancelled.');
          return res.redirect('/student/bonafide');
        }

        // Start transaction to delete request and logs
        conn.beginTransaction(function (errTx) {
          if (errTx) {
            conn.release();
            req.flash('message', 'Transaction error.');
            return res.redirect('/student/bonafide');
          }

          conn.query('DELETE FROM bonafide_audit_logs WHERE request_id = ?', [id], function (e2) {
            if (e2) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Database deletion error.');
                return res.redirect('/student/bonafide');
              });
            }

            conn.query('DELETE FROM bonafide_requests WHERE id = ?', [id], function (e3) {
              if (e3) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Database deletion error.');
                  return res.redirect('/student/bonafide');
                });
              }

              conn.commit(function (errCommit) {
                if (errCommit) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Commit error.');
                    return res.redirect('/student/bonafide');
                  });
                }
                conn.release();
                req.flash('message', 'Your bonafide request has been successfully cancelled.');
                return res.redirect('/student/bonafide');
              });
            });
          });
        });
      }
    );
  });
});


// =====================================================
// STUDENT: GET /student/bank-details
// =====================================================
app.get('/student/bank-details', verifyStudentJwt, studentBankLimiter, csrfProtection, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      req.flash('message', 'Database connection error');
      return res.redirect('/student/dashboard');
    }

    const query = `
      SELECT sd.*, r.room_type AS occupancy
      FROM studentdetails sd
      LEFT JOIN rooms r ON r.name = sd.room_no AND r.block = sd.block
      WHERE sd.uid = ? LIMIT 1
    `;
    conn.query(query, [uid], function (e, rows) {
      if (e) {
        conn.release();
        req.flash('message', 'Database error reading profile');
        return res.redirect('/student/dashboard');
      }
      if (!rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Student not found');
        return res.redirect('/student/dashboard');
      }
      const student = rows[0];
      student.dept = formatBranchForBonafide(student.dept);
      const currentAcademicYear = getCurrentAcademicYear();

      // Calculate fees based on their actual database occupancy and mess type
      const messType = student.mess_type || 'veg';
      const occupancy = student.occupancy || 'double';
      const feeBreakdown = calculateHostelFeeBreakdown(messType, occupancy);

      // Check existing active request for this academic year (excluding Rejected/Cancelled requests)
      conn.query(
        "SELECT * FROM hostel_bank_requests WHERE student_uid = ? AND academic_year = ? AND status NOT IN ('Rejected', 'Cancelled') LIMIT 1",
        [uid, currentAcademicYear],
        function (e2, existing) {
          if (e2) {
            conn.release();
            req.flash('message', 'Database error checking requests');
            return res.redirect('/student/dashboard');
          }
          // Get all history
          conn.query(
            'SELECT * FROM hostel_bank_requests WHERE student_uid = ? ORDER BY request_date DESC',
            [uid],
            function (e3, history) {
              conn.release();
              if (e3) {
                req.flash('message', 'Database error fetching history');
                return res.redirect('/student/dashboard');
              }
              if (history) {
                history.forEach(function (h) {
                  h.branch = formatBranchForBonafide(h.branch);
                });
              }
              attachStudentPhotoUrl(student);
              return res.render(__dirname + '/views/student_bank_details', {
                student: student,
                academicYearFormatted: currentAcademicYear,
                feeBreakdown: feeBreakdown,
                existingRequest: existing && existing[0] ? existing[0] : null,
                history: history || [],
                csrfToken: req.csrfToken(),
                message: req.flash('message')
              });
            }
          );
        }
      );
    });
  });
});

// =====================================================
// STUDENT: POST /student/bank-details/request
// =====================================================
app.post('/student/bank-details/request', verifyStudentJwt, studentBankLimiter, csrfProtection, function (req, res) {
  const uid = req.studentUid;
  let purpose = (req.body.purpose || '').trim();
  const otherPurpose = (req.body.other_purpose || '').trim();
  const adminRemark = (req.body.admin_remark || '').trim();

  const validPurposes = ['Hostel Fee Payment', 'Education Loan', 'Scholarship', 'Personal Record', 'Other'];
  if (!validPurposes.includes(purpose)) {
    req.flash('message', 'Invalid purpose selected.');
    return res.redirect('/student/bank-details');
  }

  let purposeDesc = null;
  if (purpose === 'Other') {
    purposeDesc = otherPurpose.trim();
    if (!purposeDesc || purposeDesc.length > 300) {
      req.flash('message', 'Purpose description is required for "Other" and must not exceed 300 characters.');
      return res.redirect('/student/bank-details');
    }
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      req.flash('message', 'Database connection error.');
      return res.redirect('/student/bank-details');
    }

    const query = `
      SELECT sd.*, r.room_type AS occupancy
      FROM studentdetails sd
      LEFT JOIN rooms r ON r.name = sd.room_no AND r.block = sd.block
      WHERE sd.uid = ? LIMIT 1
    `;
    conn.query(query, [uid], function (e, rows) {
      if (e) {
        conn.release();
        req.flash('message', 'Database error.');
        return res.redirect('/student/bank-details');
      }
      if (!rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Student record not found.');
        return res.redirect('/student/bank-details');
      }
      const student = rows[0];

      // Only hostellers allowed
      if (!student.category || student.category.toLowerCase() !== 'hostel') {
        conn.release();
        req.flash('message', 'Bank details certificate is only for hostel students.');
        return res.redirect('/student/bank-details');
      }

      const currentAcademicYear = getCurrentAcademicYear();
      const formattedBranch = formatBranchForBonafide(student.dept);

      // Parse occupancy and mess type from student selections
      let selectedOccupancy = (req.body.occupancy || '').toLowerCase().trim();
      let selectedMess = (req.body.mess_type || '').toLowerCase().trim();
      if (!['single', 'double', 'triple'].includes(selectedOccupancy)) {
        selectedOccupancy = 'double';
      }
      if (!['veg', 'nonveg', 'non-veg'].includes(selectedMess)) {
        selectedMess = 'veg';
      }

      const feeBreakdown = calculateHostelFeeBreakdown(selectedMess, selectedOccupancy);

      // Start transaction
      conn.beginTransaction(function (errTx) {
        if (errTx) {
          conn.release();
          req.flash('message', 'Transaction error.');
          return res.redirect('/student/bank-details');
        }

        // Fetch request first â€” check if we can reuse a Rejected/Cancelled request
        conn.query(
          "SELECT id, status FROM hostel_bank_requests WHERE student_uid = ? AND academic_year = ? LIMIT 1",
          [uid, currentAcademicYear],
          function (e2, existing) {
            if (e2) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Database error.');
                return res.redirect('/student/bank-details');
              });
            }

            if (existing && existing.length > 0) {
              const reqRecord = existing[0];
              if (reqRecord.status !== 'Rejected' && reqRecord.status !== 'Cancelled') {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'You already have an active request for this academic year.');
                  return res.redirect('/student/bank-details');
                });
              }

              // Reuse existing row: reset status to Pending and clear approval/printed/collected info
              const updateSql = `
                UPDATE hostel_bank_requests
                SET student_name = ?, father_name = ?, enrollment_no = ?, branch = ?, year = ?,
                    boarding_fee = ?, mess_fee = ?, total_fee = ?, purpose = ?, purpose_desc = ?,
                    status = 'Pending', payment_status = 'Pending', request_date = UTC_TIMESTAMP(),
                    document_no = NULL, verification_token = NULL, bank_name = NULL, account_holder = NULL,
                    bank_branch = NULL, account_number = NULL, ifsc = NULL, upi_number = NULL,
                    contact_number = NULL, email = NULL, approved_by = NULL, approved_date = NULL,
                    printed_date = NULL, collected_by = NULL, collected_date = NULL,
                    rejection_reason = NULL, admin_remark = ?, created_by_role = 'student', created_by_uid = ?,
                    notification_sent = 0
                WHERE id = ?`;

              conn.query(updateSql, [
                student.sname,
                student.parentname || 'N/A',
                student.uid,
                formattedBranch,
                student.year,
                feeBreakdown.boarding,
                feeBreakdown.mess,
                feeBreakdown.total,
                purpose,
                purposeDesc,
                adminRemark || null,
                uid,
                reqRecord.id
              ], function (e3) {
                if (e3) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Failed to submit request.');
                    return res.redirect('/student/bank-details');
                  });
                }

                logHostelBankAudit(conn, reqRecord.id, 'Created', reqRecord.status, 'Pending', student.sname, 'student', 'Resubmitted request by student', function (eAudit) {
                  if (eAudit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Audit log error.');
                      return res.redirect('/student/bank-details');
                    });
                  }

                  createStudentNotification(conn, uid, 'Bank Details Request Submitted', 'Your request has been resubmitted successfully.', function (eNotif) {
                    if (eNotif) {
                      return conn.rollback(function () {
                        conn.release();
                        req.flash('message', 'Notification error.');
                        return res.redirect('/student/bank-details');
                      });
                    }

                    conn.commit(function (eCommit) {
                      if (eCommit) {
                        return conn.rollback(function () {
                          conn.release();
                          req.flash('message', 'Failed to commit request.');
                          return res.redirect('/student/bank-details');
                        });
                      }
                      conn.release();
                      req.flash('message', 'Your request has been resubmitted successfully.');
                      return res.redirect('/student/bank-details');
                    });
                  });
                });
              });
            } else {
              // Create new record
              const insertSql = `
                INSERT INTO hostel_bank_requests
                  (student_uid, student_name, father_name, enrollment_no, branch, year, academic_year,
                   boarding_fee, mess_fee, total_fee, purpose, purpose_desc, status, request_date,
                   admin_remark, created_by_role, created_by_uid)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', UTC_TIMESTAMP(), ?, 'student', ?)`;

              conn.query(insertSql, [
                uid,
                student.sname,
                student.parentname || 'N/A',
                student.uid,
                formattedBranch,
                student.year,
                currentAcademicYear,
                feeBreakdown.boarding,
                feeBreakdown.mess,
                feeBreakdown.total,
                purpose,
                purposeDesc,
                adminRemark || null,
                uid
              ], function (e3, result) {
                if (e3) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Failed to submit request.');
                    return res.redirect('/student/bank-details');
                  });
                }

                const requestId = result.insertId;

                logHostelBankAudit(conn, requestId, 'Created', null, 'Pending', student.sname, 'student', 'Initial request submitted by student', function (eAudit) {
                  if (eAudit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Audit log error.');
                      return res.redirect('/student/bank-details');
                    });
                  }

                  createStudentNotification(conn, uid, 'Bank Details Request Submitted', 'Your request has been submitted successfully.', function (eNotif) {
                    if (eNotif) {
                      return conn.rollback(function () {
                        conn.release();
                        req.flash('message', 'Notification error.');
                        return res.redirect('/student/bank-details');
                      });
                    }

                    conn.commit(function (eCommit) {
                      if (eCommit) {
                        return conn.rollback(function () {
                          conn.release();
                          req.flash('message', 'Failed to commit request.');
                          return res.redirect('/student/bank-details');
                        });
                      }
                      conn.release();
                      req.flash('message', 'Your request has been submitted successfully.');
                      return res.redirect('/student/bank-details');
                    });
                  });
                });
              });
            }
          }
        );
      });
    });
  });
});

// =====================================================
// STUDENT: POST /student/bank-details/:id/cancel
// =====================================================
app.post('/student/bank-details/:id/cancel', verifyStudentJwt, studentBankLimiter, csrfProtection, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const uid = req.studentUid;
  if (!id) {
    req.flash('message', 'Invalid Request ID.');
    return res.redirect('/student/bank-details');
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      req.flash('message', 'Database connection error.');
      return res.redirect('/student/bank-details');
    }

    // Check if request exists, belongs to student, and is Pending
    conn.query(
      'SELECT id, student_name, status FROM hostel_bank_requests WHERE id = ? AND student_uid = ? LIMIT 1',
      [id, uid],
      function (e, rows) {
        if (e) {
          conn.release();
          req.flash('message', 'Database error.');
          return res.redirect('/student/bank-details');
        }

        if (!rows || rows.length === 0) {
          conn.release();
          req.flash('message', 'Request not found.');
          return res.redirect('/student/bank-details');
        }

        const request = rows[0];
        if (request.status !== 'Pending') {
          conn.release();
          req.flash('message', 'Only pending requests can be cancelled.');
          return res.redirect('/student/bank-details');
        }

        // Start transaction
        conn.beginTransaction(function (errTx) {
          if (errTx) {
            conn.release();
            req.flash('message', 'Transaction error.');
            return res.redirect('/student/bank-details');
          }

          conn.query(
            "UPDATE hostel_bank_requests SET status = 'Cancelled' WHERE id = ?",
            [id],
            function (e2) {
              if (e2) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Database error.');
                  return res.redirect('/student/bank-details');
                });
              }

              logHostelBankAudit(conn, id, 'Cancelled', 'Pending', 'Cancelled', request.student_name, 'student', 'Cancelled by student', function (eAudit) {
                if (eAudit) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Audit logging error.');
                    return res.redirect('/student/bank-details');
                  });
                }

                createStudentNotification(conn, uid, 'Bank Details Request Cancelled', 'Your request has been cancelled.', function (eNotif) {
                  if (eNotif) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Notification error.');
                      return res.redirect('/student/bank-details');
                    });
                  }

                  conn.commit(function (errCommit) {
                    if (errCommit) {
                      return conn.rollback(function () {
                        conn.release();
                        req.flash('message', 'Commit error.');
                        return res.redirect('/student/bank-details');
                      });
                    }
                    conn.release();
                    req.flash('message', 'Your request has been successfully cancelled.');
                    return res.redirect('/student/bank-details');
                  });
                });
              });
            }
          );
        });
      }
    );
  });
});


// =====================================================
// UNIFIED ADMIN: GET /admin/certificate-requests
// =====================================================
app.get('/admin/certificate-requests', verifyjwt, canManageBonafide, csrfProtection, function (req, res) {
  const { q, cert_type, status, academic_year, payment_status } = req.query;
  const tab = req.query.tab === 'today' ? 'today' : 'all';
  const page = parseInt(req.query.page, 10) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      req.flash('message', 'Database connection error.');
      return res.redirect('/daterange');
    }

    let bonafideWhere = "1=1";
    let bankWhere = "1=1";
    let bonafideParams = [];
    let bankParams = [];

    if (q) {
      bonafideWhere += " AND (student_name LIKE ? OR student_uid LIKE ? OR certificate_no LIKE ? OR branch LIKE ?)";
      bonafideParams.push('%' + q + '%', '%' + q + '%', '%' + q + '%', '%' + q + '%');
      bankWhere += " AND (student_name LIKE ? OR student_uid LIKE ? OR document_no LIKE ? OR branch LIKE ?)";
      bankParams.push('%' + q + '%', '%' + q + '%', '%' + q + '%', '%' + q + '%');
    }

    if (status && status !== 'All') {
      bonafideWhere += " AND status = ?";
      bonafideParams.push(status);
      bankWhere += " AND status = ?";
      bankParams.push(status);
    }

    if (payment_status && payment_status !== 'All') {
      if (payment_status === 'Paid') {
        bonafideWhere += " AND LOWER(payment_status) = 'paid'";
        bankWhere += " AND LOWER(payment_status) = 'paid'";
      } else if (payment_status === 'Unpaid') {
        bonafideWhere += " AND LOWER(payment_status) = 'unpaid'";
        bankWhere += " AND LOWER(payment_status) = 'unpaid'";
      } else if (payment_status === 'Pending') {
        bonafideWhere += " AND (payment_status IS NULL OR LOWER(payment_status) = 'pending' OR payment_status = '')";
        bankWhere += " AND (payment_status IS NULL OR LOWER(payment_status) = 'pending' OR payment_status = '')";
      }
    }

    if (academic_year) {
      bonafideWhere += " AND academic_year LIKE ?";
      bonafideParams.push('%' + academic_year + '%');
      bankWhere += " AND academic_year LIKE ?";
      bankParams.push('%' + academic_year + '%');
    }

    if (tab === 'today') {
      const now = new Date();
      const todayStr = now.getFullYear() + '-' +
        String(now.getMonth() + 1).padStart(2, '0') + '-' +
        String(now.getDate()).padStart(2, '0');
      bonafideWhere += " AND request_date >= ? AND request_date <= ?";
      bonafideParams.push(todayStr + ' 00:00:00', todayStr + ' 23:59:59');
      bankWhere += " AND request_date >= ? AND request_date <= ?";
      bankParams.push(todayStr + ' 00:00:00', todayStr + ' 23:59:59');
    }

    let unionQuery = "";
    let queryParams = [];

    if (cert_type === 'Bonafide') {
      unionQuery = `
        SELECT id, 'Bonafide' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, certificate_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
        FROM bonafide_requests
        WHERE ${bonafideWhere}
      `;
      queryParams = bonafideParams;
    } else if (cert_type === 'Bank Statement') {
      unionQuery = `
        SELECT id, 'Bank Statement' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, document_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
        FROM hostel_bank_requests
        WHERE ${bankWhere}
      `;
      queryParams = bankParams;
    } else {
      unionQuery = `
        (SELECT id, 'Bonafide' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, certificate_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
        FROM bonafide_requests
        WHERE ${bonafideWhere})
        UNION ALL
        (SELECT id, 'Bank Statement' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, document_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
        FROM hostel_bank_requests
        WHERE ${bankWhere})
      `;
      queryParams = [...bonafideParams, ...bankParams];
    }

    const countSql = `SELECT COUNT(*) AS total FROM (${unionQuery}) AS combined`;
    const dataSql = `${unionQuery} ORDER BY request_date DESC LIMIT ? OFFSET ?`;

    conn.query(countSql, queryParams, function (errCount, countRes) {
      if (errCount) {
        conn.release();
        req.flash('message', 'Failed to count certificate requests.');
        return res.redirect('/daterange');
      }
      const totalCount = countRes && countRes[0] ? countRes[0].total : 0;
      const totalPages = Math.ceil(totalCount / limit) || 1;

      conn.query(dataSql, [...queryParams, limit, offset], function (errData, rows) {
        if (errData) {
          conn.release();
          req.flash('message', 'Failed to fetch certificate requests.');
          return res.redirect('/daterange');
        }

        const statsSql = `
          SELECT 
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Pending') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Pending') AS pendingCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Approved') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Approved') AS approvedCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Printed') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Printed') AS printedCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Collected') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Collected') AS collectedCount
        `;

        conn.query(statsSql, function (errStats, statsRes) {
          const stats = (statsRes && statsRes[0]) ? statsRes[0] : { pendingCount: 0, approvedCount: 0, printedCount: 0, collectedCount: 0 };

          conn.query("SELECT * FROM hostel_bank_settings WHERE id = 1 LIMIT 1", function (errSet, settingsRows) {
            conn.release();
            const settings = (settingsRows && settingsRows[0]) || {};

            res.render(__dirname + '/views/admin_certificate_requests', {
              requests: rows || [],
              counts: {
                pending: stats.pendingCount || 0,
                approved: stats.approvedCount || 0,
                printed: stats.printedCount || 0,
                collected: stats.collectedCount || 0,
                total: totalCount
              },
              filters: {
                q: q || '',
                cert_type: cert_type || 'All',
                status: status || 'All',
                payment_status: payment_status || 'All',
                academic_year: academic_year || '',
                tab: tab
              },
              settings: settings,
              pagination: {
                page: page,
                limit: limit,
                totalPages: totalPages,
                totalCount: totalCount
              },
              role: req.decode.role,
              csrfToken: req.csrfToken ? req.csrfToken() : '',
              message: req.flash('message')
            });
          });
        });
      });
    });
  });
});

// =====================================================
// UNIFIED HOSTELAUTHORITY: GET /hostelauthority/certificate-requests
// =====================================================
app.get('/hostelauthority/certificate-requests', verifyjwt, canAccessBonafide, csrfProtection, function (req, res) {
  const { q, cert_type, academic_year } = req.query;
  const page = parseInt(req.query.page, 10) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      req.flash('message', 'Database connection error.');
      return res.redirect('/daterange');
    }

    let bonafideWhere = "status = 'Printed'";
    let bankWhere = "status = 'Printed'";
    let bonafideParams = [];
    let bankParams = [];

    if (q) {
      bonafideWhere += " AND (student_name LIKE ? OR student_uid LIKE ? OR certificate_no LIKE ? OR branch LIKE ?)";
      bonafideParams.push('%' + q + '%', '%' + q + '%', '%' + q + '%', '%' + q + '%');
      bankWhere += " AND (student_name LIKE ? OR student_uid LIKE ? OR document_no LIKE ? OR branch LIKE ?)";
      bankParams.push('%' + q + '%', '%' + q + '%', '%' + q + '%', '%' + q + '%');
    }

    if (academic_year) {
      bonafideWhere += " AND academic_year LIKE ?";
      bonafideParams.push('%' + academic_year + '%');
      bankWhere += " AND academic_year LIKE ?";
      bankParams.push('%' + academic_year + '%');
    }

    let unionQuery = "";
    let queryParams = [];

    if (cert_type === 'Bonafide') {
      unionQuery = `
        SELECT id, 'Bonafide' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, certificate_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
        FROM bonafide_requests
        WHERE ${bonafideWhere}
      `;
      queryParams = bonafideParams;
    } else if (cert_type === 'Bank Statement') {
      unionQuery = `
        SELECT id, 'Bank Statement' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, document_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
        FROM hostel_bank_requests
        WHERE ${bankWhere}
      `;
      queryParams = bankParams;
    } else {
      unionQuery = `
        (SELECT id, 'Bonafide' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, certificate_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
        FROM bonafide_requests
        WHERE ${bonafideWhere})
        UNION ALL
        (SELECT id, 'Bank Statement' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, document_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
        FROM hostel_bank_requests
        WHERE ${bankWhere})
      `;
      queryParams = [...bonafideParams, ...bankParams];
    }

    const countSql = `SELECT COUNT(*) AS total FROM (${unionQuery}) AS combined`;
    const dataSql = `${unionQuery} ORDER BY printed_date DESC LIMIT ? OFFSET ?`;

    conn.query(countSql, queryParams, function (errCount, countRes) {
      if (errCount) {
        conn.release();
        req.flash('message', 'Failed to count requests.');
        return res.redirect('/daterange');
      }
      const totalCount = countRes && countRes[0] ? countRes[0].total : 0;
      const totalPages = Math.ceil(totalCount / limit) || 1;

      conn.query(dataSql, [...queryParams, limit, offset], function (errData, rows) {
        if (errData) {
          conn.release();
          req.flash('message', 'Failed to fetch requests.');
          return res.redirect('/daterange');
        }

        const statsSql = `
          SELECT 
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Pending') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Pending') AS pendingCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Approved') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Approved') AS approvedCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Printed') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Printed') AS printedCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Collected') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Collected') AS collectedCount
        `;

        conn.query(statsSql, function (errStats, statsRes) {
          conn.release();
          const stats = (statsRes && statsRes[0]) ? statsRes[0] : { pendingCount: 0, approvedCount: 0, printedCount: 0, collectedCount: 0 };

          res.render(__dirname + '/views/admin_certificate_requests', {
            requests: rows || [],
            counts: {
              pending: stats.pendingCount || 0,
              approved: stats.approvedCount || 0,
              printed: stats.printedCount || 0,
              collected: stats.collectedCount || 0
            },
            filters: {
              q: q || '',
              cert_type: cert_type || 'All',
              status: 'Printed',
              academic_year: academic_year || ''
            },
            pagination: {
              page: page,
              limit: limit,
              totalPages: totalPages,
              totalCount: totalCount
            },
            role: req.decode.role,
            csrfToken: req.csrfToken ? req.csrfToken() : '',
            message: req.flash('message')
          });
        });
      });
    });
  });
});

// Backward Compatibility Redirects
app.get('/admin/bonafide-requests', function (req, res) {
  const query = new URLSearchParams(req.query);
  if (!query.has('cert_type')) query.set('cert_type', 'Bonafide');
  res.redirect('/admin/certificate-requests?' + query.toString());
});

app.get('/admin/bank-requests', function (req, res) {
  const query = new URLSearchParams(req.query);
  if (!query.has('cert_type')) query.set('cert_type', 'Bank Statement');
  res.redirect('/admin/certificate-requests?' + query.toString());
});

app.get('/hostelauthority/bonafide-requests', function (req, res) {
  const query = new URLSearchParams(req.query);
  if (!query.has('cert_type')) query.set('cert_type', 'Bonafide');
  res.redirect('/hostelauthority/certificate-requests?' + query.toString());
});

app.get('/hostelauthority/bank-requests', function (req, res) {
  const query = new URLSearchParams(req.query);
  if (!query.has('cert_type')) query.set('cert_type', 'Bank Statement');
  res.redirect('/hostelauthority/certificate-requests?' + query.toString());
});

// =====================================================
// ADMIN: GET /admin/bank-details/:id
// =====================================================
app.get('/admin/bank-details/:id', verifyjwt, canManageBonafide, csrfProtection, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bank-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bank-requests'); }

    conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Request not found.');
        return res.redirect('/admin/bank-requests');
      }
      const request = rows[0];

      conn.query('SELECT * FROM hostel_bank_audit_logs WHERE request_id = ? ORDER BY created_at DESC', [id], function (e2, auditLogs) {
        conn.release();
        if (e2) {
          req.flash('message', 'Error fetching audit logs.');
          return res.redirect('/admin/bank-requests');
        }

        res.render(__dirname + '/views/admin_bank_view', {
          request: request,
          auditLogs: auditLogs || [],
          csrfToken: req.csrfToken(),
          domain: req.protocol + '://' + req.get('host'),
          message: req.flash('message')
        });
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bank-details/:id/approve
// =====================================================
app.post('/admin/bank-details/:id/approve', verifyjwt, canManageBonafide, csrfProtection, adminBankLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bank-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bank-requests'); }

    // Start transaction
    conn.beginTransaction(function (errTx) {
      if (errTx) { conn.release(); req.flash('message', 'Transaction error'); return res.redirect('/admin/bank-details/' + id); }

      // Fetch request with row lock (SELECT ... FOR UPDATE) to prevent concurrency double approvals
      conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? FOR UPDATE', [id], function (e, rows) {
        if (e || !rows || rows.length === 0) {
          return conn.rollback(function () {
            conn.release();
            req.flash('message', 'Request not found.');
            return res.redirect('/admin/bank-requests');
          });
        }
        const request = rows[0];
        if (request.status !== 'Pending') {
          return conn.rollback(function () {
            conn.release();
            req.flash('message', 'Only Pending requests can be approved.');
            return res.redirect('/admin/bank-details/' + id);
          });
        }

        // Fetch settings to snapshot bank details
        conn.query('SELECT * FROM hostel_bank_settings WHERE id = 1 LIMIT 1', function (eSet, settingRows) {
          if (eSet || !settingRows || settingRows.length === 0) {
            return conn.rollback(function () {
              conn.release();
              req.flash('message', 'Bank settings missing. Please update settings first.');
              return res.redirect('/admin/bank-details/' + id);
            });
          }
          const settings = settingRows[0];

          const docNo = generateBankCertificateNo(id, request.academic_year ? request.academic_year.split('-')[0] : null);
          const crypto = require('crypto');
          const verifyToken = crypto.randomUUID();

          const updateSql = `
            UPDATE hostel_bank_requests
            SET status = 'Approved', approved_by = ?, approved_date = UTC_TIMESTAMP(),
                document_no = ?, verification_token = ?,
                bank_name = ?, account_holder = ?, bank_branch = ?, account_number = ?,
                ifsc = ?, upi_number = ?, contact_number = ?, email = ?
            WHERE id = ? AND status = 'Pending'`;

          conn.query(updateSql, [
            req.decode.adminname || 'Admin',
            docNo,
            verifyToken,
            settings.bank_name,
            settings.account_holder,
            settings.branch,
            settings.account_number,
            settings.ifsc,
            settings.upi_number,
            settings.contact_number,
            settings.email,
            id
          ], function (eUpdate, result) {
            if (eUpdate || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Failed to approve request.');
                return res.redirect('/admin/bank-details/' + id);
              });
            }

            // Log audit
            logHostelBankAudit(conn, id, 'Approved', 'Pending', 'Approved', req.decode.adminname || 'Admin', 'admin', 'Approved by administrator', function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Audit log error.');
                  return res.redirect('/admin/bank-details/' + id);
                });
              }

              // Notification
              createStudentNotification(conn, request.student_uid, 'Bank Details Request Approved', 'Your request has been approved. Certificate No: ' + docNo, function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Notification error.');
                    return res.redirect('/admin/bank-details/' + id);
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Commit error.');
                      return res.redirect('/admin/bank-details/' + id);
                    });
                  }
                  conn.release();
                  req.flash('message', 'Request approved successfully. Document No: ' + docNo);
                  return res.redirect('/admin/bank-details/' + id);
                });
              });
            });
          });
        });
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bank-details/:id/reject
// =====================================================
app.post('/admin/bank-details/:id/reject', verifyjwt, canManageBonafide, csrfProtection, adminBankLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const reason = (req.body.rejection_reason || '').trim();
  if (!id) return res.redirect('/admin/bank-requests');
  if (!reason) {
    req.flash('message', 'Rejection reason is required.');
    return res.redirect('/admin/bank-details/' + id);
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bank-requests'); }

    conn.beginTransaction(function (errTx) {
      if (errTx) { conn.release(); req.flash('message', 'Transaction error'); return res.redirect('/admin/bank-details/' + id); }

      conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? FOR UPDATE', [id], function (e, rows) {
        if (e || !rows || rows.length === 0) {
          return conn.rollback(function () {
            conn.release();
            req.flash('message', 'Request not found.');
            return res.redirect('/admin/bank-requests');
          });
        }
        const request = rows[0];
        if (request.status !== 'Pending') {
          return conn.rollback(function () {
            conn.release();
            req.flash('message', 'Only Pending requests can be rejected.');
            return res.redirect('/admin/bank-details/' + id);
          });
        }

        conn.query(
          "UPDATE hostel_bank_requests SET status = 'Rejected', rejection_reason = ? WHERE id = ? AND status = 'Pending'",
          [reason, id],
          function (eUpdate, result) {
            if (eUpdate || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Rejection update failed.');
                return res.redirect('/admin/bank-details/' + id);
              });
            }

            logHostelBankAudit(conn, id, 'Rejected', 'Pending', 'Rejected', req.decode.adminname || 'Admin', 'admin', 'Rejected: ' + reason, function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Audit error.');
                  return res.redirect('/admin/bank-details/' + id);
                });
              }

              createStudentNotification(conn, request.student_uid, 'Bank Details Request Rejected', 'Your request has been rejected. Reason: ' + reason, function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Notification error.');
                    return res.redirect('/admin/bank-details/' + id);
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Commit error.');
                      return res.redirect('/admin/bank-details/' + id);
                    });
                  }
                  conn.release();
                  req.flash('message', 'Request rejected.');
                  return res.redirect('/admin/bank-details/' + id);
                });
              });
            });
          }
        );
      });
    });
  });
});

// =====================================================
// ADMIN: GET /admin/bank-details/:id/print
// =====================================================
app.get('/admin/bank-details/:id/print', verifyjwt, canManageBonafide, csrfProtection, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bank-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bank-requests'); }

    conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.send("Request not found");
      }
      const request = rows[0];
      if (request.status !== 'Approved' && request.status !== 'Printed' && request.status !== 'Collected') {
        conn.release();
        return res.send("This request cannot be printed as it is in state: " + request.status);
      }

      conn.query('SELECT * FROM hostel_bank_settings WHERE id = 1 LIMIT 1', function (eSet, settingsRows) {
        conn.release();
        const settings = (settingsRows && settingsRows[0]) || {
          top_margin: '2.0',
          bottom_margin: '2.0',
          left_margin: '2.0',
          right_margin: '2.0',
          font_size: '15',
          line_height: '1.4'
        };

        res.render(__dirname + '/views/admin_bank_print', {
          request: request,
          settings: settings,
          csrfToken: req.csrfToken()
        });
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bank-details/:id/printed  (called by javascript afterprint)
// =====================================================
app.post('/admin/bank-details/:id/printed', verifyjwt, canManageBonafide, csrfProtection, adminBankLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.json({ success: false, message: 'Invalid ID' });

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.json({ success: false, message: 'Database connection error' });

    conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) { conn.release(); return res.json({ success: false, message: 'Request not found' }); }
      const request = rows[0];

      // Idempotent: already printed
      if (request.status === 'Printed' || request.status === 'Collected') {
        conn.release();
        return res.json({ success: true });
      }

      if (request.status !== 'Approved') {
        conn.release();
        return res.json({ success: false, message: 'Invalid transition' });
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); return res.json({ success: false, message: 'Transaction error' }); }

        conn.query(
          "UPDATE hostel_bank_requests SET status = 'Printed', printed_date = UTC_TIMESTAMP() WHERE id = ? AND status = 'Approved'",
          [id],
          function (eUpdate, result) {
            if (eUpdate || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                return res.json({ success: false, message: 'Update failed' });
              });
            }

            logHostelBankAudit(conn, id, 'Printed', 'Approved', 'Printed', req.decode.adminname || 'Admin', 'admin', 'Certificate printed', function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  return res.json({ success: false, message: 'Audit logging failed' });
                });
              }

              createStudentNotification(conn, request.student_uid, 'Bank Details Letter Printed', 'Your letter is ready for collection.', function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    return res.json({ success: false, message: 'Notification failed' });
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      return res.json({ success: false, message: 'Commit error' });
                    });
                  }
                  conn.release();
                  return res.json({ success: true });
                });
              });
            });
          }
        );
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bank-details/:id/printed-manual
// =====================================================
app.post('/admin/bank-details/:id/printed-manual', verifyjwt, canManageBonafide, csrfProtection, adminBankLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bank-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bank-details/' + id); }

    conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) { conn.release(); req.flash('message', 'Request not found.'); return res.redirect('/admin/bank-details/' + id); }
      const request = rows[0];

      if (request.status === 'Printed' || request.status === 'Collected') {
        conn.release();
        req.flash('message', 'Already printed.');
        return res.redirect('/admin/bank-details/' + id);
      }

      if (request.status !== 'Approved') {
        conn.release();
        req.flash('message', 'Only approved requests can be printed.');
        return res.redirect('/admin/bank-details/' + id);
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); req.flash('message', 'Transaction error'); return res.redirect('/admin/bank-details/' + id); }

        conn.query(
          "UPDATE hostel_bank_requests SET status = 'Printed', printed_date = UTC_TIMESTAMP() WHERE id = ? AND status = 'Approved'",
          [id],
          function (eUpdate, result) {
            if (eUpdate || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Failed to update status.');
                return res.redirect('/admin/bank-details/' + id);
              });
            }

            logHostelBankAudit(conn, id, 'Printed', 'Approved', 'Printed', req.decode.adminname || 'Admin', 'admin', 'Manual print update', function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Audit logging failed.');
                  return res.redirect('/admin/bank-details/' + id);
                });
              }

              createStudentNotification(conn, request.student_uid, 'Bank Details Letter Printed', 'Your letter is ready for collection.', function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Notification failed.');
                    return res.redirect('/admin/bank-details/' + id);
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Commit error.');
                      return res.redirect('/admin/bank-details/' + id);
                    });
                  }
                  conn.release();
                  req.flash('message', 'Marked as printed.');
                  return res.redirect('/admin/bank-details/' + id);
                });
              });
            });
          }
        );
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bank-details/:id/collected
// =====================================================
app.post('/admin/bank-details/:id/collected', verifyjwt, canAccessBonafide, csrfProtection, adminBankLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bank-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bank-details/' + id); }

    conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) { conn.release(); req.flash('message', 'Request not found.'); return res.redirect('/admin/bank-details/' + id); }
      const request = rows[0];

      if (request.status === 'Collected') {
        conn.release();
        req.flash('message', 'Already collected.');
        return res.redirect('/admin/bank-details/' + id);
      }

      if (request.status !== 'Printed') {
        conn.release();
        req.flash('message', 'Only printed requests can be marked as collected.');
        return res.redirect('/admin/bank-details/' + id);
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); req.flash('message', 'Transaction error'); return res.redirect('/admin/bank-details/' + id); }

        conn.query(
          "UPDATE hostel_bank_requests SET status = 'Collected', collected_by = ?, collected_date = UTC_TIMESTAMP() WHERE id = ? AND status = 'Printed'",
          [req.decode.adminname || 'Authority', id],
          function (eUpdate, result) {
            if (eUpdate || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Failed to update status.');
                return res.redirect('/admin/bank-details/' + id);
              });
            }

            logHostelBankAudit(conn, id, 'Collected', 'Printed', 'Collected', req.decode.adminname || 'Authority', req.decode.role, 'Handed over to student', function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Audit logging failed.');
                  return res.redirect('/admin/bank-details/' + id);
                });
              }

              createStudentNotification(conn, request.student_uid, 'Bank Details Letter Collected', 'Your letter has been collected.', function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Notification error.');
                    return res.redirect('/admin/bank-details/' + id);
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Commit error.');
                      return res.redirect('/admin/bank-details/' + id);
                    });
                  }
                  conn.release();
                  req.flash('message', 'Marked as collected.');
                  const redirectUrl = req.decode.role === 'Hostelauthority' ? '/hostelauthority/bank-requests' : '/admin/bank-details/' + id;
                  return res.redirect(redirectUrl);
                });
              });
            });
          }
        );
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bank-details/:id/payment
// =====================================================
app.post('/admin/bank-details/:id/payment', verifyjwt, canManageBonafide, csrfProtection, adminBankLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const payment_status = req.body.payment_status;
  if (!id) return res.json({ success: false, message: 'Invalid ID' });
  if (!['Pending', 'Paid', 'Unpaid'].includes(payment_status)) return res.json({ success: false, message: 'Invalid status' });

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.json({ success: false, message: 'Database error' });

    conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) { conn.release(); return res.json({ success: false, message: 'Request not found' }); }
      const request = rows[0];

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); return res.json({ success: false, message: 'Transaction error' }); }

        conn.query(
          "UPDATE hostel_bank_requests SET payment_status = ? WHERE id = ?",
          [payment_status, id],
          function (eUpdate) {
            if (eUpdate) {
              return conn.rollback(function () {
                conn.release();
                return res.json({ success: false, message: 'Payment update failed' });
              });
            }

            logHostelBankAudit(conn, id, 'Payment Update: ' + payment_status, request.status, request.status, req.decode.adminname || 'Admin', 'admin', 'Payment status updated to: ' + payment_status, function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  return res.json({ success: false, message: 'Audit failed' });
                });
              }

              createStudentNotification(conn, request.student_uid, 'Payment Status Updated', 'Your hostel fee payment status has been updated to: ' + payment_status, function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    return res.json({ success: false, message: 'Notification failed' });
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      return res.json({ success: false, message: 'Commit failed' });
                    });
                  }
                  conn.release();
                  return res.json({ success: true });
                });
              });
            });
          }
        );
      });
    });
  });
});

// =====================================================
// ADMIN: GET /admin/bank-details/:id/docx
// =====================================================
app.get('/admin/bank-details/:id/docx', verifyjwt, canManageBonafide, adminBankLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.send('Invalid Request ID');

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.send('Database connection error');

    conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) { conn.release(); return res.send('Request not found'); }
      const request = rows[0];

      if (request.status !== 'Approved' && request.status !== 'Printed' && request.status !== 'Collected') {
        conn.release();
        return res.send("This request cannot be saved as it is in state: " + request.status);
      }

      conn.query('SELECT * FROM hostel_bank_settings WHERE id = 1 LIMIT 1', function (e2, settingsRows) {
        conn.release();
        const settings = (settingsRows && settingsRows[0]) || {
          top_margin: '2.0',
          bottom_margin: '2.0',
          left_margin: '2.0',
          right_margin: '2.0',
          font_size: '15',
          line_height: '1.4'
        };

        const dateFormatted = new Date().toLocaleDateString('en-GB', { timeZone: 'Asia/Kolkata' });

        const html = `
<html xmlns:o='urn:schemas-microsoft-com:office:office' 
      xmlns:w='urn:schemas-microsoft-com:office:word' 
      xmlns='http://www.w3.org/TR/REC-html40'>
<head>
    <meta charset="utf-8">
    <title>Bank Account Details</title>
    <!--[if gte mso 9]>
    <xml>
        <w:WordDocument>
            <w:View>Print</w:View>
            <w:Zoom>100</w:Zoom>
            <w:DoNotOptimizeForBrowser/>
        </w:WordDocument>
    </xml>
    <![endif]-->
    <style>
        @page {
            size: 21cm 28.5cm;
            margin-top: ${settings.top_margin}cm;
            margin-bottom: ${settings.bottom_margin}cm;
            margin-left: ${settings.left_margin}cm;
            margin-right: ${settings.right_margin}cm;
        }
        body {
            font-family: 'Times New Roman', serif;
            font-size: ${settings.font_size}px;
            line-height: ${settings.line_height};
            color: #000000;
        }
        .title-section {
            text-align: center;
            font-weight: bold;
            font-size: ${parseInt(settings.font_size) + 2}px;
            margin-bottom: 40px;
            text-transform: uppercase;
        }
        .title-section span {
            border-bottom: 1.5px solid #000;
            display: inline-block;
            padding-bottom: 2px;
        }
        .title-section span span {
            border-bottom: 1.5px solid #000;
            display: inline-block;
            padding-bottom: 2px;
        }
        .bank-details-table {
            width: 100%;
            margin-bottom: 30px;
            font-size: ${settings.font_size}px;
        }
        .bank-details-table td {
            vertical-align: top;
            padding: 2px 0;
        }
        .bank-details-table td.label-col {
            width: 32%;
            font-weight: bold;
        }
        .bank-details-table td.colon-col {
            width: 3%;
            text-align: center;
        }
        .bank-details-table td.value-col {
            width: 65%;
            font-weight: bold;
        }
        .instruction-list {
            margin-bottom: 40px;
            font-size: ${settings.font_size}px;
            padding-left: 20px;
        }
        .instruction-list li {
            margin-bottom: 8px;
            font-weight: bold;
        }
        .date-section {
            text-align: right;
            font-weight: bold;
            font-size: ${settings.font_size}px;
            margin-bottom: 10px;
        }
        .details-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 15px;
            font-size: ${settings.font_size}px;
        }
        .details-table th, .details-table td {
            border: 1px solid #000;
            padding: 8px;
            text-align: center;
        }
        .details-table th {
            font-weight: normal;
        }
        .details-table td {
            font-weight: bold;
        }
        .signature-section {
            margin-top: 50px;
            font-size: ${settings.font_size}px;
            line-height: 1.4;
            font-weight: bold;
        }
    </style>
</head>
<body>
<div class="certificate-container">
    <div class="title-section">
        <span>
            <span>
                BANK ACCOUNT DETAILS FOR<br>
                NEFT/RTGS/GPAY/ ONLINE PAYMENT
            </span>
        </span>
    </div>

    <table class="bank-details-table" border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td class="label-col">Name of the Bank</td>
            <td class="colon-col">:</td>
            <td class="value-col">${request.bank_name}</td>
        </tr>
        <tr>
            <td class="label-col">Account Holder</td>
            <td class="colon-col">:</td>
            <td class="value-col">${request.account_holder}</td>
        </tr>
        <tr>
            <td class="label-col">Branch</td>
            <td class="colon-col">:</td>
            <td class="value-col">${request.bank_branch}</td>
        </tr>
        <tr>
            <td class="label-col">Account Number</td>
            <td class="colon-col">:</td>
            <td class="value-col">${request.account_number}</td>
        </tr>
        <tr>
            <td class="label-col">IFSC Code</td>
            <td class="colon-col">:</td>
            <td class="value-col">${request.ifsc}</td>
        </tr>
    </table>

    <ul class="instruction-list">
        <li>Kindly send the UTR Number (Transaction ID/ Reference Number) on the same day after making the payment.</li>
        <li>Via SMS/Whatapp : Mobile No: ${request.contact_number}</li>
        <li>Or Via Email : ${request.email}</li>
    </ul>

    <div class="date-section">
        Date: ${dateFormatted}
    </div>

    <!-- Student Table 1 -->
    <table class="details-table">
        <thead>
            <tr>
                <th style="width: 50%;">Name of Student</th>
                <th style="width: 50%;">Father's Name</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>${request.student_name}</td>
                <td>${request.father_name}</td>
            </tr>
        </tbody>
    </table>

    <!-- Student Table 2 -->
    <table class="details-table">
        <thead>
            <tr>
                <th style="width: 33.33%;">Academic Year</th>
                <th style="width: 33.33%;">Branch</th>
                <th style="width: 33.33%;">Studying In</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>${request.academic_year}</td>
                <td>${request.branch}</td>
                <td>${request.year} year</td>
            </tr>
        </tbody>
    </table>

    <!-- Fee Table -->
    <table class="details-table" style="margin-bottom: 40px;">
        <thead>
            <tr>
                <th style="width: 25%;">Year</th>
                <th style="width: 25%;">Boarding</th>
                <th style="width: 25%;">Mess</th>
                <th style="width: 25%;">Total</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>${request.year}</td>
                <td>${parseFloat(request.boarding_fee).toFixed(2)}</td>
                <td>${parseFloat(request.mess_fee).toFixed(2)}</td>
                <td>${parseFloat(request.total_fee).toFixed(2)}</td>
            </tr>
        </tbody>
    </table>

    <div class="signature-section">
        Hostel Manager<br>
        Fr. Roby PA
    </div>
</div>
</body>
</html>`;

        res.setHeader('Content-Type', 'application/msword');
        res.setHeader('Content-Disposition', 'attachment; filename="' + request.student_name.replace(/\s+/g, '_') + '_bank_certificate.doc"');
        res.send(html);
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bank-settings/update
// =====================================================
app.post('/admin/bank-settings/update', verifyjwt, canManageBonafide, csrfProtection, adminBankLimiter, function (req, res) {
  const { bank_name, account_holder, branch, account_number, ifsc, upi_number, contact_number, email, top_margin, bottom_margin, left_margin, right_margin, font_size, line_height } = req.body;

  // Validate server side
  if (!bank_name || !account_holder || !branch || !account_number || !ifsc || !contact_number || !email) {
    req.flash('message', 'Please fill in all required bank settings.');
    return res.redirect('/admin/certificate-requests?cert_type=Bank+Statement');
  }

  // Margin boundary validation (fallback defaults if missing/invalid)
  let tm = parseFloat(top_margin);
  let bm = parseFloat(bottom_margin);
  let lm = parseFloat(left_margin);
  let rm = parseFloat(right_margin);
  let fs = parseInt(font_size, 10);
  let lh = parseFloat(line_height);

  if (isNaN(tm) || tm < 0 || tm > 5) tm = 2.0;
  if (isNaN(bm) || bm < 0 || bm > 5) bm = 2.0;
  if (isNaN(lm) || lm < 0 || lm > 5) lm = 2.0;
  if (isNaN(rm) || rm < 0 || rm > 5) rm = 2.0;
  if (isNaN(fs) || fs < 10 || fs > 30) fs = 15;
  if (isNaN(lh) || lh < 1.0 || lh > 3.0) lh = 1.4;

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/certificate-requests?cert_type=Bank+Statement'); }

    conn.beginTransaction(function (errTx) {
      if (errTx) { conn.release(); req.flash('message', 'Transaction error'); return res.redirect('/admin/certificate-requests?cert_type=Bank+Statement'); }

      const upsertSql = `
        INSERT INTO hostel_bank_settings
          (id, bank_name, account_holder, branch, account_number, ifsc, upi_number, contact_number, email, top_margin, bottom_margin, left_margin, right_margin, font_size, line_height)
        VALUES
          (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
          bank_name = VALUES(bank_name),
          account_holder = VALUES(account_holder),
          branch = VALUES(branch),
          account_number = VALUES(account_number),
          ifsc = VALUES(ifsc),
          upi_number = VALUES(upi_number),
          contact_number = VALUES(contact_number),
          email = VALUES(email),
          top_margin = VALUES(top_margin),
          bottom_margin = VALUES(bottom_margin),
          left_margin = VALUES(left_margin),
          right_margin = VALUES(right_margin),
          font_size = VALUES(font_size),
          line_height = VALUES(line_height)`;

      conn.query(upsertSql, [
        bank_name.trim(),
        account_holder.trim(),
        branch.trim(),
        account_number.trim(),
        ifsc.trim(),
        upi_number ? upi_number.trim() : null,
        contact_number.trim(),
        email.trim(),
        tm, bm, lm, rm, fs, lh
      ], function (eUpdate) {
        if (eUpdate) {
          return conn.rollback(function () {
            conn.release();
            req.flash('message', 'Failed to update bank settings.');
            return res.redirect('/admin/certificate-requests?cert_type=Bank+Statement');
          });
        }

        // Log audit
        const auditSql = `
          INSERT INTO hostel_bank_audit_logs (action, performed_by, performed_role, remarks)
          VALUES ('Settings Updated', ?, 'admin', 'Updated bank details')`;
        conn.query(auditSql, [req.decode.adminname || 'Admin'], function (eAudit) {
          if (eAudit) {
            return conn.rollback(function () {
              conn.release();
              req.flash('message', 'Audit log error.');
              return res.redirect('/admin/certificate-requests?cert_type=Bank+Statement');
            });
          }

          conn.commit(function (eCommit) {
            if (eCommit) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Commit error.');
                return res.redirect('/admin/certificate-requests?cert_type=Bank+Statement');
              });
            }
            conn.release();
            req.flash('message', 'Bank settings updated successfully.');
            return res.redirect('/admin/certificate-requests?cert_type=Bank+Statement');
          });
        });
      });
    });
  });
});

// =====================================================
// HOSTELAUTHORITY: GET /hostelauthority/bank-requests
// =====================================================
app.get('/hostelauthority/bank-requests', verifyjwt, canAccessBonafide, csrfProtection, function (req, res) {
  const role = req.decode.role;

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/tokenhomepage'); }

    conn.query("SELECT * FROM hostel_bank_requests WHERE status = 'Printed' ORDER BY printed_date DESC", function (e, requests) {
      conn.release();
      if (e) { req.flash('message', 'Error fetching requests.'); return res.redirect('/tokenhomepage'); }

      res.render(__dirname + '/views/hostelauthority_bank_requests', {
        requests: requests || [],
        csrfToken: req.csrfToken(),
        role: role,
        message: req.flash('message')
      });
    });
  });
});

// =====================================================
// HOSTELAUTHORITY: POST /hostelauthority/bank-details/:id/collected
// =====================================================
app.post('/hostelauthority/bank-details/:id/collected', verifyjwt, canAccessBonafide, csrfProtection, adminBankLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/hostelauthority/bank-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/hostelauthority/bank-requests'); }

    conn.beginTransaction(function (errTx) {
      if (errTx) { conn.release(); req.flash('message', 'Transaction error'); return res.redirect('/hostelauthority/bank-requests'); }

      conn.query('SELECT * FROM hostel_bank_requests WHERE id = ? FOR UPDATE', [id], function (e, rows) {
        if (e || !rows || rows.length === 0) {
          return conn.rollback(function () {
            conn.release();
            req.flash('message', 'Request not found.');
            return res.redirect('/hostelauthority/bank-requests');
          });
        }
        const request = rows[0];
        if (request.status !== 'Printed') {
          return conn.rollback(function () {
            conn.release();
            req.flash('message', 'Request is not printed.');
            return res.redirect('/hostelauthority/bank-requests');
          });
        }

        conn.query(
          "UPDATE hostel_bank_requests SET status = 'Collected', collected_by = ?, collected_date = UTC_TIMESTAMP() WHERE id = ? AND status = 'Printed'",
          [req.decode.adminname || 'Hostel Authority', id],
          function (eUpdate, result) {
            if (eUpdate || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Collection status update failed.');
                return res.redirect('/hostelauthority/bank-requests');
              });
            }

            logHostelBankAudit(conn, id, 'Collected', 'Printed', 'Collected', req.decode.adminname || 'Hostel Authority', req.decode.role, 'Handed over by Hostel Authority', function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Audit log error.');
                  return res.redirect('/hostelauthority/bank-requests');
                });
              }

              createStudentNotification(conn, request.student_uid, 'Bank Details Letter Collected', 'Your letter has been collected.', function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Notification failed.');
                    return res.redirect('/hostelauthority/bank-requests');
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Commit failed.');
                      return res.redirect('/hostelauthority/bank-requests');
                    });
                  }
                  conn.release();
                  req.flash('message', 'Marked as collected.');
                  return res.redirect('/hostelauthority/bank-requests');
                });
              });
            });
          }
        );
      });
    });
  });
});

// =====================================================
// PUBLIC VERIFICATION: GET /verify/bank/:token
// =====================================================
app.get('/verify/bank/:token', function (req, res) {
  const token = req.params.token || '';

  dbbconnection.getConnection(function (err, conn) {
    if (err) { return res.status(500).send("Database connection error"); }

    conn.query('SELECT * FROM hostel_bank_requests WHERE verification_token = ? LIMIT 1', [token], function (e, rows) {
      conn.release();
      if (e) { return res.status(500).send("Database query error"); }

      // Safe non-disclosing error handling
      const request = (rows && rows.length > 0) ? rows[0] : null;
      res.render(__dirname + '/views/bank_verify', {
        request: request
      });
    });
  });
});


// =====================================================
// HOSTELAUTHORITY: GET /hostelauthority/bonafide-requests
// =====================================================
app.get('/hostelauthority/bonafide-requests', verifyjwt, canAccessBonafide, csrfProtection, function (req, res) {
  const role = req.decode.role;

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/tokenhomepage'); }

    // Fetch only Printed certificates awaiting collection
    const sql = `
      SELECT id, student_name, certificate_no, status, printed_date
      FROM bonafide_requests
      WHERE status = 'Printed'
      ORDER BY printed_date DESC
    `;
    conn.query(sql, function (e, requests) {
      conn.release();
      if (e) {
        req.flash('message', 'Error fetching requests');
        return res.redirect('/tokenhomepage');
      }

      res.render(__dirname + '/views/hostelauthority_bonafide_requests', {
        requests: requests || [],
        csrfToken: req.csrfToken(),
        role: role,
        message: req.flash('message')
      });
    });
  });
});


// =====================================================
// ADMIN: GET /admin/bonafide-requests
// =====================================================
app.get('/admin/bonafide-requests', verifyjwt, canManageBonafide, csrfProtection, function (req, res) {
  const { q, status, academic_year } = req.query;
  const tab = req.query.tab === 'all' ? 'all' : 'today';
  const page = parseInt(req.query.page, 10) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const todayIstDate = (formatDateToISTString(new Date()) || '').slice(0, 10);

  let where = '1=1';
  const params = [];

  if (q) {
    where += ' AND (br.student_name LIKE ? OR br.student_uid LIKE ?)';
    params.push('%' + q + '%', '%' + q + '%');
  }
  if (status && ['Pending', 'Approved', 'Rejected', 'Printed', 'Collected'].includes(status)) {
    where += ' AND br.status = ?';
    params.push(status);
  }
  if (academic_year) {
    where += ' AND br.academic_year = ?';
    params.push(academic_year);
  }

  // Filter by tab (Today vs All)
  if (tab === 'today') {
    // bonafide_requests.request_date is stored in UTC, so "today" must be an IST day window
    // mapped back to UTC. This prevents requests from dropping out at the wrong local time.
    const istStart = new Date(`${todayIstDate}T00:00:00+05:30`);
    const utcStart = istStart.toISOString().slice(0, 19).replace('T', ' ');
    const utcEnd = new Date(istStart.getTime() + (24 * 60 * 60 * 1000))
      .toISOString()
      .slice(0, 19)
      .replace('T', ' ');
    where += ' AND br.request_date >= ? AND br.request_date < ?';
    params.push(utcStart, utcEnd);
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/daterange'); }

    // Count total rows matching filters
    const countSql = `SELECT COUNT(*) AS total FROM bonafide_requests br WHERE ${where}`;
    conn.query(countSql, params, function (eCount, countRows) {
      if (eCount) {
        conn.release();
        req.flash('message', 'Error counting requests');
        return res.redirect('/daterange');
      }
      const total = countRows[0].total;
      const totalPages = Math.ceil(total / limit) || 1;

      const listSql = `SELECT * FROM bonafide_requests br WHERE ${where} ORDER BY br.request_date DESC LIMIT ? OFFSET ?`;
      const listParams = [...params, limit, offset];

      conn.query(listSql, listParams, function (e, requests) {
        if (e) {
          conn.release();
          req.flash('message', 'Error fetching requests');
          return res.redirect('/daterange');
        }
        if (requests) {
          requests.forEach(function (r) {
            r.branch = formatBranchForBonafide(r.branch);
          });
        }

        // Stats
        const statsSql = `
          SELECT
            SUM(status='Pending')   AS pending,
            SUM(status='Approved')  AS approved,
            SUM(status='Printed')   AS printed,
            SUM(status='Collected') AS collected,
            SUM(status='Rejected')  AS rejected
          FROM bonafide_requests`;
        conn.query(statsSql, function (e2, statsRows) {
          conn.release();
          const stats = (statsRows && statsRows[0]) || {};
          res.render(__dirname + '/views/admin_bonafide_requests', {
            requests: requests || [],
            stats: stats,
            filters: { q: q || '', status: status || '', academic_year: academic_year || '', tab: tab },
            pagination: { page, totalPages, total },
            csrfToken: req.csrfToken(),
            role: req.decode.role,
            message: req.flash('message')
          });
        });
      });
    });
  });
});

// =====================================================
// ADMIN: GET /admin/bonafide/:id Ã¢â‚¬â€ view single request
// =====================================================
app.get('/admin/bonafide/:id', verifyjwt, canManageBonafide, csrfProtection, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bonafide-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bonafide-requests'); }

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      conn.release();
      if (e || !rows || rows.length === 0) {
        req.flash('message', 'Request not found.');
        return res.redirect('/admin/bonafide-requests');
      }
      const request = rows[0];
      request.branch = formatBranchForBonafide(request.branch);
      res.render(__dirname + '/views/admin_bonafide_view', {
        request: request,
        csrfToken: req.csrfToken(),
        message: req.flash('message')
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bonafide/:id/approve
// =====================================================
app.post('/admin/bonafide/:id/approve', verifyjwt, canManageBonafide, csrfProtection, adminBonafideLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bonafide-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bonafide-requests'); }

    // Fetch request first Ã¢â‚¬â€ validate status transition (Pending -> Approved)
    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Request not found.');
        return res.redirect('/admin/bonafide-requests');
      }
      const request = rows[0];
      if (request.status !== 'Pending') {
        conn.release();
        req.flash('message', 'Only Pending requests can be approved.');
        return res.redirect('/admin/bonafide/' + id);
      }

      const certNo = generateCertificateNo(id, request.academic_year ? request.academic_year.split('-')[0] : null);
      const crypto = require('crypto');
      const verifyToken = crypto.randomUUID();

      // Start transaction for atomic transition, notification, and audit trail
      conn.beginTransaction(function (errTx) {
        if (errTx) {
          conn.release();
          req.flash('message', 'Transaction failed to start.');
          return res.redirect('/admin/bonafide/' + id);
        }

        const updateSql = `
          UPDATE bonafide_requests
          SET status='Approved', approved_date=UTC_TIMESTAMP(), certificate_no=?, verification_token=?
          WHERE id=? AND status='Pending'`;
        conn.query(updateSql, [certNo, verifyToken, id], function (e2, result) {
          if (e2 || result.affectedRows === 0) {
            return conn.rollback(function () {
              conn.release();
              req.flash('message', 'Could not approve. Please try again.');
              return res.redirect('/admin/bonafide/' + id);
            });
          }

          // Create notification
          createStudentNotification(
            conn,
            request.student_uid,
            'Bonafide Certificate Approved',
            'Your Bonafide Certificate request has been approved. Please collect the certificate from Hostel Manager Office.',
            function (eNotif) {
              if (eNotif) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Failed to create notification.');
                  return res.redirect('/admin/bonafide/' + id);
                });
              }

              // Log audit trail
              logBonafideAudit(conn, id, 'Approved', req.decode.adminname || 'Admin', function (eAudit) {
                if (eAudit) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Failed to log audit.');
                    return res.redirect('/admin/bonafide/' + id);
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Failed to commit transaction.');
                      return res.redirect('/admin/bonafide/' + id);
                    });
                  }
                  conn.release();
                  req.flash('message', 'Request approved successfully. Certificate No: ' + certNo);
                  return res.redirect('/admin/bonafide/' + id);
                });
              });
            }
          );
        });
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bonafide/:id/reject
// =====================================================
app.post('/admin/bonafide/:id/reject', verifyjwt, canManageBonafide, csrfProtection, adminBonafideLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const reason = (req.body.rejection_reason || '').trim();
  if (!id) return res.redirect('/admin/bonafide-requests');
  if (!reason) {
    req.flash('message', 'Rejection reason is required.');
    return res.redirect('/admin/bonafide/' + id);
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bonafide-requests'); }

    // Fetch request first Ã¢â‚¬â€ validate transition (Pending -> Rejected)
    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Request not found.');
        return res.redirect('/admin/bonafide-requests');
      }
      const request = rows[0];
      if (request.status !== 'Pending') {
        conn.release();
        req.flash('message', 'Only Pending requests can be rejected.');
        return res.redirect('/admin/bonafide/' + id);
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) {
          conn.release();
          req.flash('message', 'Transaction failed to start.');
          return res.redirect('/admin/bonafide/' + id);
        }

        const updateSql = `UPDATE bonafide_requests SET status='Rejected', rejection_reason=? WHERE id=? AND status='Pending'`;
        conn.query(updateSql, [reason, id], function (e2, result) {
          if (e2 || result.affectedRows === 0) {
            return conn.rollback(function () {
              conn.release();
              req.flash('message', 'Could not reject. Please try again.');
              return res.redirect('/admin/bonafide/' + id);
            });
          }

          // Create notification
          createStudentNotification(
            conn,
            request.student_uid,
            'Bonafide Certificate Request Rejected',
            'Your Bonafide Certificate request has been rejected. Reason: ' + reason,
            function (eNotif) {
              if (eNotif) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Failed to create notification.');
                  return res.redirect('/admin/bonafide/' + id);
                });
              }

              // Log audit trail
              logBonafideAudit(conn, id, 'Rejected', req.decode.adminname || 'Admin', function (eAudit) {
                if (eAudit) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Failed to log audit.');
                    return res.redirect('/admin/bonafide/' + id);
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Failed to commit transaction.');
                      return res.redirect('/admin/bonafide/' + id);
                    });
                  }
                  conn.release();
                  req.flash('message', 'Request rejected.');
                  return res.redirect('/admin/bonafide/' + id);
                });
              });
            }
          );
        });
      });
    });
  });
});

// =====================================================
// ADMIN: GET /admin/bonafide/:id/print
// =====================================================
app.get('/admin/bonafide/:id/print', verifyjwt, canManageBonafide, csrfProtection, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bonafide-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bonafide-requests'); }

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.send("Request not found");
      }
      const request = rows[0];
      request.branch = formatBranchForBonafide(request.branch);

      // Validate print security constraint (Must be Approved, Printed, or Collected)
      if (request.status !== 'Approved' && request.status !== 'Printed' && request.status !== 'Collected') {
        conn.release();
        return res.send("This request cannot be printed as it is in '" + request.status + "' state.");
      }

      // Fetch print settings
      conn.query('SELECT setting_key, setting_value FROM certificate_settings', function (e2, settingRows) {
        conn.release();
        const settings = {
          top_margin: process.env.BONAFIDE_TOP_MARGIN || '3.5',
          bottom_margin: process.env.BONAFIDE_BOTTOM_MARGIN || '3.0',
          left_margin: '2.0',
          right_margin: '2.0',
          font_size: '18',
          line_height: '2.0'
        };
        if (settingRows) {
          settingRows.forEach(s => {
            if (s.setting_value) settings[s.setting_key] = s.setting_value;
          });
        }

        res.render(__dirname + '/views/admin_bonafide_print', {
          request: request,
          settings: settings,
          csrfToken: req.csrfToken()
        });
      });
    });
  });
});

// =====================================================
// ADMIN: GET /admin/bonafide/:id/docx  (download as Word document)
// =====================================================
app.get('/admin/bonafide/:id/docx', verifyjwt, canManageBonafide, adminBonafideLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.send('Invalid Request ID');

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.send('Database connection error');

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) { conn.release(); return res.send('Request not found'); }
      const request = rows[0];
      request.branch = formatBranchForBonafide(request.branch);

      // Validate status security constraint (Must be Approved, Printed, or Collected)
      if (request.status !== 'Approved' && request.status !== 'Printed' && request.status !== 'Collected') {
        conn.release();
        return res.send("This request cannot be saved as it is in '" + request.status + "' state.");
      }

      // Fetch print settings
      conn.query('SELECT setting_key, setting_value FROM certificate_settings', function (e2, settingRows) {
        conn.release();
        const settings = {
          top_margin: process.env.BONAFIDE_TOP_MARGIN || '3.5',
          bottom_margin: process.env.BONAFIDE_BOTTOM_MARGIN || '3.0',
          left_margin: '2.0',
          right_margin: '2.0',
          font_size: '18',
          line_height: '2.0'
        };
        if (settingRows) {
          settingRows.forEach(s => {
            if (s.setting_value) settings[s.setting_key] = s.setting_value;
          });
        }

        const dateFormatted = new Date().toLocaleDateString('en-GB', { timeZone: 'Asia/Kolkata' });
        const toTitleCase = (str) => str ? str.toLowerCase().replace(/\b\w/g, char => char.toUpperCase()) : '';
        const branchTitleCase = toTitleCase(request.branch);
        const hostelFeeInt = request.hostel_fee ? parseInt(request.hostel_fee) : '';

        // Generate Word HTML
        const html = `
<html xmlns:o='urn:schemas-microsoft-com:office:office' 
      xmlns:w='urn:schemas-microsoft-com:office:word' 
      xmlns='http://www.w3.org/TR/REC-html40'>
<head>
    <meta charset="utf-8">
    <title>Bonafide Certificate</title>
    <!--[if gte mso 9]>
    <xml>
        <w:WordDocument>
            <w:View>Print</w:View>
            <w:Zoom>100</w:Zoom>
            <w:DoNotOptimizeForBrowser/>
        </w:WordDocument>
    </xml>
    <![endif]-->
    <style>
        @page {
            size: 21cm 28.5cm;
            margin-top: ${settings.top_margin}cm;
            margin-bottom: ${settings.bottom_margin}cm;
            margin-left: ${settings.left_margin}cm;
            margin-right: ${settings.right_margin}cm;
        }
        body {
            font-family: 'Times New Roman', serif;
            font-size: ${settings.font_size}px;
            line-height: ${settings.line_height};
            color: #000000;
        }
        .date-row {
            text-align: right;
            font-weight: bold;
            margin-bottom: 30px;
        }
        .certificate-title {
            text-align: center;
            text-decoration: underline;
            font-weight: bold;
            font-size: 22px;
            margin-top: 0;
            margin-bottom: 30px;
        }
        .certificate-body {
            text-align: justify;
            line-height: 1.5;
        }
        .certificate-body p {
            text-indent: 1.5cm;
            margin-bottom: 0.5em;
            margin-top: 0;
        }
        .signature-section {
            margin-top: 40px;
            font-size: ${settings.font_size}px;
            line-height: 1.5;
        }
        .certificate-note {
            margin-top: 30px;
            font-size: 15px;
            line-height: 1.5;
            text-align: justify;
            border-top: 1px solid #000000;
            padding-top: 10px;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <!-- Date & Certificate No Section -->
    <table border="0" cellpadding="0" cellspacing="0" style="width: 100%; font-weight: bold; font-family: 'Times New Roman', serif; font-size: ${settings.font_size}px; margin-bottom: 30px; border-collapse: collapse;">
        <tr>
            <td style="text-align: left; padding: 0;">No: ${request.certificate_no}</td>
            <td style="text-align: right; padding: 0;">DATE: ${dateFormatted}</td>
        </tr>
    </table>
    <div class="certificate-title">
        TO WHOMSOEVER IT MAY CONCERN
    </div>
    <div class="certificate-body">
        <p>
            This is to certify that <strong>MR. ${request.student_name}</strong> is a bonafide student of St. Vincent Pallotti College of Engineering and Technology, Gavsi Manapur, Wardha Road, Nagpur, India, in the faculty of <strong>${branchTitleCase}</strong>. He has been admitted to the hostel for the academic year <strong>${request.academic_year}</strong>. During his stay here, the annual hostel fee would be <strong>Rs ${hostelFeeInt}/-</strong> towards his Boarding and Mess. Please note that the hostel fee is subject to change annually as per the management's assessment. The patron bank is requested to cross-check with the hostel authorities about the residential status.
        </p>
    </div>
    <div class="signature-section">
        Yours truthfully<br/><br/>
        <strong>Fr. Roby P.A. SAC</strong><br/>
        Manager<br/>
        TNPS Boys Hostel
    </div>
    <div class="certificate-note">
        This Bonafide certificate is valid only with the signature of the Hostel Authority, and to be used only for submission for the Bank loan, Income Tax, Passport and Scholarship purposes only.
    </div>
</body>
</html>
        `;

        res.setHeader('Content-Type', 'application/msword');
        res.setHeader('Content-Disposition', 'attachment; filename="' + request.student_name.replace(/\s+/g, '_') + '.doc"');
        res.send(html);
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bonafide/:id/printed  (called by JS after print)
// =====================================================
app.post('/admin/bonafide/:id/printed', verifyjwt, canManageBonafide, csrfProtection, adminBonafideLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.json({ success: false, message: 'Invalid ID' });

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.json({ success: false, message: 'Database connection error' });

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) { conn.release(); return res.json({ success: false, message: 'Request not found' }); }
      const request = rows[0];

      // Already printed Ã¢â‚¬â€ idempotent
      if (request.status === 'Printed' || request.status === 'Collected') {
        conn.release();
        return res.json({ success: true });
      }

      // Validate transition (Approved -> Printed)
      if (request.status !== 'Approved') {
        conn.release();
        return res.json({ success: false, message: 'Invalid status transition' });
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); return res.json({ success: false, message: 'Transaction error' }); }

        conn.query(
          "UPDATE bonafide_requests SET status='Printed', printed_date=UTC_TIMESTAMP() WHERE id=? AND status='Approved'",
          [id],
          function (e2, result) {
            if (e2 || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                return res.json({ success: false, message: 'Update failed' });
              });
            }

            // Create notification
            createStudentNotification(
              conn,
              request.student_uid,
              'Bonafide Certificate Ready',
              'Your Bonafide Certificate is ready. Please collect it from Hostel Manager Office.',
              function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    return res.json({ success: false, message: 'Notification failed' });
                  });
                }

                // Log audit trail
                logBonafideAudit(conn, id, 'Printed', req.decode.adminname || 'Admin', function (eAudit) {
                  if (eAudit) {
                    return conn.rollback(function () {
                      conn.release();
                      return res.json({ success: false, message: 'Audit failed' });
                    });
                  }

                  conn.commit(function (eCommit) {
                    if (eCommit) {
                      return conn.rollback(function () {
                        conn.release();
                        return res.json({ success: false, message: 'Commit failed' });
                      });
                    }
                    conn.release();
                    return res.json({ success: true });
                  });
                });
              }
            );
          }
        );
      });
    });
  });
});

// =====================================================
// ADMIN: POST /admin/bonafide/:id/printed-manual  (manual fallback button)
// =====================================================
app.post('/admin/bonafide/:id/printed-manual', verifyjwt, canManageBonafide, csrfProtection, adminBonafideLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.redirect('/admin/bonafide-requests');

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect('/admin/bonafide/' + id); }

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Request not found.');
        return res.redirect('/admin/bonafide/' + id);
      }
      const request = rows[0];

      if (request.status === 'Printed' || request.status === 'Collected') {
        conn.release();
        req.flash('message', 'Already marked as printed.');
        return res.redirect('/admin/bonafide/' + id);
      }

      if (request.status !== 'Approved') {
        conn.release();
        req.flash('message', 'Only Approved requests can be marked as Printed.');
        return res.redirect('/admin/bonafide/' + id);
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); req.flash('message', 'Transaction error'); return res.redirect('/admin/bonafide/' + id); }

        conn.query(
          "UPDATE bonafide_requests SET status='Printed', printed_date=UTC_TIMESTAMP() WHERE id=? AND status='Approved'",
          [id],
          function (e2, result) {
            if (e2 || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Failed to update status.');
                return res.redirect('/admin/bonafide/' + id);
              });
            }

            createStudentNotification(
              conn,
              request.student_uid,
              'Bonafide Certificate Ready',
              'Your Bonafide Certificate is ready. Please collect it from Hostel Manager Office.',
              function (eNotif) {
                if (eNotif) {
                  return conn.rollback(function () {
                    conn.release();
                    req.flash('message', 'Failed to create notification.');
                    return res.redirect('/admin/bonafide/' + id);
                  });
                }

                logBonafideAudit(conn, id, 'Printed', req.decode.adminname || 'Admin', function (eAudit) {
                  if (eAudit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Failed to log audit.');
                      return res.redirect('/admin/bonafide/' + id);
                    });
                  }

                  conn.commit(function (eCommit) {
                    if (eCommit) {
                      return conn.rollback(function () {
                        conn.release();
                        req.flash('message', 'Failed to commit transaction.');
                        return res.redirect('/admin/bonafide/' + id);
                      });
                    }
                    conn.release();
                    req.flash('message', 'Request marked as Printed.');
                    return res.redirect('/admin/bonafide/' + id);
                  });
                });
              }
            );
          }
        );
      });
    });
  });
});

// =====================================================
// POST /admin/bonafide/:id/collected & /hostelauthority/bonafide-details/:id/collected
// =====================================================
app.post(['/admin/bonafide/:id/collected', '/admin/bonafide-details/:id/collected', '/hostelauthority/bonafide/:id/collected', '/hostelauthority/bonafide-details/:id/collected'], verifyjwt, canAccessBonafide, csrfProtection, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const role = req.decode && req.decode.role;

  // Determine where to redirect back based on role & referer
  const referer = req.get('Referrer');
  const defaultHostelRedirect = '/hostelauthority/certificate-requests';
  const defaultAdminRedirect = id ? ('/admin/bonafide/' + id) : '/admin/certificate-requests';

  const successRedirect = (referer && (referer.includes('/hostelauthority/') || referer.includes('/admin/')))
    ? referer
    : (role === 'Hostelauthority' ? defaultHostelRedirect : defaultAdminRedirect);
  const errorRedirect = (referer && (referer.includes('/hostelauthority/') || referer.includes('/admin/')))
    ? referer
    : (role === 'Hostelauthority' ? defaultHostelRedirect : defaultAdminRedirect);
  const listRedirect = role === 'Hostelauthority'
    ? defaultHostelRedirect
    : '/admin/certificate-requests';

  if (!id) return res.redirect(listRedirect);

  dbbconnection.getConnection(function (err, conn) {
    if (err) { req.flash('message', 'Database error'); return res.redirect(listRedirect); }

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        req.flash('message', 'Request not found.');
        return res.redirect(listRedirect);
      }
      const request = rows[0];

      // Validate transition (Printed -> Collected)
      if (request.status !== 'Printed') {
        conn.release();
        req.flash('message', 'Only Printed certificates can be marked as Collected.');
        return res.redirect(errorRedirect);
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); req.flash('message', 'Transaction failed.'); return res.redirect(errorRedirect); }

        conn.query(
          "UPDATE bonafide_requests SET status='Collected', collected_date=UTC_TIMESTAMP() WHERE id=? AND status='Printed'",
          [id],
          function (e2, result) {
            if (e2 || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                req.flash('message', 'Could not update status.');
                return res.redirect(errorRedirect);
              });
            }

            // Log audit trail
            logBonafideAudit(conn, id, 'Collected', req.decode.adminname || (role === 'Hostelauthority' ? 'Hostel Authority' : 'Admin'), function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  req.flash('message', 'Audit logging failed.');
                  return res.redirect(errorRedirect);
                });
              }

              createStudentNotification(conn, request.student_uid, 'Bonafide Certificate Collected', 'Your Bonafide Certificate has been collected.', function (eNotif) {
                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      req.flash('message', 'Commit failed.');
                      return res.redirect(errorRedirect);
                    });
                  }
                  conn.release();
                  req.flash('message', 'Certificate marked as Collected.');
                  return res.redirect(successRedirect);
                });
              });
            });
          }
        );
      });
    });
  });
});


// =====================================================
// ADMIN: POST /admin/bonafide/:id/payment
// =====================================================
app.post('/admin/bonafide/:id/payment', verifyjwt, canManageBonafide, csrfProtection, adminBonafideLimiter, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const payment_status = (req.body.payment_status || '').trim().toLowerCase();

  if (!id) {
    return res.status(400).json({ success: false, message: 'Invalid request ID.' });
  }

  if (!['pending', 'paid', 'unpaid'].includes(payment_status)) {
    return res.status(400).json({ success: false, message: 'Invalid payment status.' });
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) {
      return res.status(500).json({ success: false, message: 'Database connection failed.' });
    }

    conn.beginTransaction(function (errTx) {
      if (errTx) {
        conn.release();
        return res.status(500).json({ success: false, message: 'Transaction start failed.' });
      }

      conn.query(
        'UPDATE bonafide_requests SET payment_status = ? WHERE id = ?',
        [payment_status, id],
        function (e, result) {
          if (e) {
            return conn.rollback(function () {
              conn.release();
              return res.status(500).json({ success: false, message: 'Failed to update payment status.' });
            });
          }

          if (result.affectedRows === 0) {
            return conn.rollback(function () {
              conn.release();
              return res.status(404).json({ success: false, message: 'Request not found.' });
            });
          }

          logBonafideAudit(conn, id, 'Payment Update: ' + payment_status, req.decode.adminname || 'Admin', function (eAudit) {
            if (eAudit) {
              return conn.rollback(function () {
                conn.release();
                return res.status(500).json({ success: false, message: 'Failed to log audit.' });
              });
            }

            conn.commit(function (eCommit) {
              if (eCommit) {
                return conn.rollback(function () {
                  conn.release();
                  return res.status(500).json({ success: false, message: 'Failed to commit transaction.' });
                });
              }

              conn.release();
              return res.json({ success: true });
            });
          });
        }
      );
    });
  });
});


// =====================================================
// PUBLIC: GET /verify/bonafide/:token
// =====================================================
app.get('/verify/bonafide/:token', function (req, res) {
  const token = (req.params.token || '').trim();
  if (!token) return res.render(__dirname + '/views/bonafide_verify', { request: null });

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.render(__dirname + '/views/bonafide_verify', { request: null });

    conn.query(
      "SELECT * FROM bonafide_requests WHERE verification_token = ? AND status NOT IN ('Rejected') LIMIT 1",
      [token],
      function (e, rows) {
        conn.release();
        const request = rows && rows[0] ? rows[0] : null;
        if (request) {
          request.branch = formatBranchForBonafide(request.branch);
        }
        res.render(__dirname + '/views/bonafide_verify', {
          request: request
        });
      }
    );
  });
});

// =====================================================
// END BONAFIDE CERTIFICATE MODULE
// =====================================================

app.use('/', require('./routes/mess'));
app.use('/special-food', require('./routes/special_food'));

app.use((err, req, res, next) => {
  console.error('Unhandled Server Error:', err);
  if (res.headersSent) return next(err);
  res.status(500).send('Internal Server Error');
});


// Mobile App Login Endpoint
app.post('/api/mobile/v1/login', function (req, res) {
  const uid = req.body.UID;
  const password = req.body.password;

  if (!uid || !password) {
    return res.status(400).json({ success: false, error: 'UID and password required' });
  }

  // --- DEMO LOGIN BYPASS ---
  if (uid === 'test@gmail.com' && password === 'test@1234') {
    const user = {
      role: 'SuperID',
      adminname: 'Demo Admin',
      adminuid: 'test@gmail.com',
      hostel: null,
      isDemo: true
    };
    const token = jwt.sign(user, secretkey, { expiresIn: '7d' });
    return res.json({ success: true, data: { token: token, role: 'SuperID' } });
  }

  if (uid === 'teststudent@gmail.com' && password === 'student@1234') {
    const studentData = {
      uid: 'teststudent@gmail.com',
      name: 'Demo Student',
      category: 'Veg',
      isDemo: true
    };
    const token = jwt.sign(studentData, studentSecretKey, { expiresIn: '7d' });
    return res.json({ success: true, data: { token: token, role: 'Student' } });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    // Check Student
    connection.query("SELECT * FROM studentdetails WHERE uid = ?", [uid], function (err, sResult) {
      if (err) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Database query error' });
      }

      if (sResult.length > 0) {
        const student = sResult[0];
        const studentPassword = student.password || student.mobileno;

        const verifyPassword = (cb) => {
          if (student.password && student.password.startsWith('$2')) {
            bcrypt.compare(password, student.password, cb);
          } else {
            cb(null, password === studentPassword);
          }
        };

        verifyPassword((berr, bresult) => {
          if (!bresult) {
            connection.release();
            return res.status(401).json({ success: false, error: 'Invalid credentials' });
          }

          const currentStatus = ((student.status || '') + '').trim().toLowerCase();
          if (currentStatus === 'restrict') {
            connection.release();
            return res.status(403).json({ success: false, error: 'Login blocked. Your account is restricted.' });
          }

          const studentData = {
            uid: student.uid,
            name: student.sname,
            category: student.category
          };

          jwt.sign(studentData, studentSecretKey, { expiresIn: '7d' }, (err, token) => {
            connection.release();
            if (err) return res.status(500).json({ success: false, error: 'Session creation failed' });
            return res.json({ success: true, data: { token: token, role: 'Student' } });
          });
        });
        return;
      }

      // Check Admin if not student
      connection.query("SELECT * FROM admin WHERE UID = ?", [uid], function (err, aResult) {
        if (err) {
          connection.release();
          return res.status(500).json({ success: false, error: 'Database query error' });
        }

        if (aResult.length > 0) {
          const admin = aResult[0];
          bcrypt.compare(password, admin.password, (berr, bresult) => {
            if (!bresult) {
              connection.release();
              return res.status(401).json({ success: false, error: 'Invalid credentials' });
            }

            const user = {
              role: admin.category,
              adminname: admin.name,
              adminuid: admin.uid || admin.UID,
              hostel: admin.hostel || admin.Hostel || null
            };

            jwt.sign(user, secretkey, { expiresIn: '7d' }, (err, token) => {
              connection.release();
              if (err) return res.status(500).json({ success: false, error: 'Session creation failed' });
              return res.json({ success: true, data: { token: token, role: admin.category } });
            });
          });
          return;
        }

        connection.release();
        return res.status(401).json({ success: false, error: 'User not found' });
      });
    });
  });
});


// Mobile App GET Admissions Endpoint
app.get('/api/mobile/v1/admissions', function (req, res) {
  // Simple token verification logic could go here if needed, but for now we just return the data.
  // The mobile app passes Bearer token. 
  const statusFilter = req.query.status; // Optional filter

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    let sql = "SELECT * FROM hostel_admission_applications";
    let params = [];

    if (statusFilter) {
      sql += " WHERE status = ?";
      params.push(statusFilter);
    }

    sql += " ORDER BY created_at DESC";

    connection.query(sql, params, function (err, result) {
      connection.release();

      if (err) {
        return res.status(500).json({ success: false, error: 'Database query error' });
      }

      return res.json({ success: true, data: result });
    });
  });
});


// Mobile App GET Single Admission Detail Endpoint
app.get('/api/mobile/v1/admissions/:id', function (req, res) {
  const id = req.params.id;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    connection.query("SELECT * FROM hostel_admission_applications WHERE id = ?", [id], function (err, result) {
      connection.release();

      if (err) {
        return res.status(500).json({ success: false, error: 'Database query error' });
      }

      if (result.length === 0) {
        return res.status(404).json({ success: false, error: 'Application not found' });
      }

      return res.json({ success: true, data: result[0] });
    });
  });
});


// Mobile App PUT Admission Edit Endpoint
app.put('/api/mobile/v1/admissions/:id/edit', function (req, res) {
  const appId = req.params.id;
  const {
    full_name, father_name, father_occupation, mother_name, mother_occupation,
    permanent_address, parent_phone, student_mobile, student_email, admission_year, branch,
    dob, religion: rawReligion, caste_category: rawCaste, mess_preference,
    religion_other, caste_category_other
  } = req.body;

  const religion = (rawReligion === 'Other' && religion_other && religion_other.trim()) ? religion_other.trim() : rawReligion;
  const caste_category = (rawCaste === 'Other' && caste_category_other && caste_category_other.trim()) ? caste_category_other.trim() : rawCaste;

  const updateSql = `UPDATE hostel_admission_applications SET
      full_name=?, father_name=?, father_occupation=?, mother_name=?, mother_occupation=?,
      permanent_address=?, parent_phone=?, student_mobile=?, student_email=?, admission_year=?, branch=?,
      dob=?, religion=?, caste_category=?, mess_preference=?
      WHERE id=?`;

  const params = [
    full_name, father_name, father_occupation || null, mother_name, mother_occupation || null,
    permanent_address, parent_phone, student_mobile, student_email, admission_year, branch,
    dob, religion || null, caste_category || null, mess_preference, appId
  ];

  dbbconnection.getConnection((err, connection) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    connection.query(updateSql, params, (err, result) => {
      if (err) {
        connection.release();
        console.error('Error updating admission application API:', err);
        return res.status(500).json({ success: false, error: 'Error updating application details' });
      }

      // If the student is Admitted, sync to studentdetails
      connection.query('SELECT status, student_uid FROM hostel_admission_applications WHERE id=?', [appId], (err, rows) => {
        if (!err && rows.length > 0 && rows[0].status === 'Admitted' && rows[0].student_uid) {
          const student_uid = rows[0].student_uid;

          const fieldsConfig = [
            { field: 'sname', val: full_name },
            { field: 'email', val: student_email !== undefined ? (student_email || null) : undefined },
            { field: 'dept', val: branch },
            { field: 'address', val: permanent_address },
            { field: 'year', val: admission_year },
            { field: 'mobileno', val: student_mobile },
            { field: 'dob', val: dob },
            { field: 'parentname', val: father_name },
            { field: 'parentnumber', val: parent_phone },
            { field: 'mess_type', val: mess_preference },
            { field: 'other2', val: caste_category !== undefined ? (caste_category || null) : undefined }
          ];

          const studentUpdateFields = [];
          const studentParams = [];

          fieldsConfig.forEach(item => {
            if (item.val !== undefined) {
              studentUpdateFields.push(`${item.field}=?`);
              studentParams.push(item.val);
            }
          });

          if (studentUpdateFields.length === 0) {
            connection.release();
            return res.json({ success: true, message: 'Application updated successfully' });
          }

          studentParams.push(student_uid);
          const studentUpdateSql = `UPDATE studentdetails SET ${studentUpdateFields.join(', ')} WHERE uid=?`;

          connection.query(studentUpdateSql, studentParams, (err) => {
            connection.release();
            if (err) {
              console.error('Error updating student details API:', err);
              return res.status(500).json({ success: false, error: 'Application updated, but failed to sync student profile data' });
            }
            return res.json({ success: true, message: 'Application and student profile updated successfully' });
          });
        } else {
          connection.release();
          return res.json({ success: true, message: 'Application updated successfully' });
        }
      });
    });
  });
});

const PORT = process.env.PORT || 3000;

// ==========================================
// MOBILE ADMIN: ROOM AVAILABILITY & DECISIONS
// ==========================================

app.get('/api/mobile/v1/rooms/available', function (req, res) {
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });
    const getRooms = "SELECT name, block, floor, capacity, is_permanent, description FROM rooms WHERE (is_available IS NULL OR is_available = TRUE) ORDER BY block, floor, name";
    const getLockedBeds = "SELECT room_no, bed_no FROM room_bookings WHERE booking_status = 'locked'";

    connection.query(getRooms, (err, rooms) => {
      if (err) { connection.release(); return res.status(500).json({ success: false }); }
      connection.query(getLockedBeds, (err, lockedBeds) => {
        connection.release();
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, rooms, lockedBeds });
      });
    });
  });
});

app.post('/api/mobile/v1/admissions/:id/decide', function (req, res) {
  const appId = req.params.id;
  const { decision, allotted_block, allotted_room, allotted_bed, remarks } = req.body;

  if (decision === 'Reject') {
    dbbconnection.getConnection(function (err, connection) {
      if (err) return res.status(500).json({ success: false, error: 'DB Error' });
      const sql = "UPDATE hostel_admission_applications SET status='Rejected', admin_remarks=? WHERE id=?";
      connection.query(sql, [remarks, appId], (err) => {
        connection.release();
        if (err) return res.status(500).json({ success: false });
        return res.json({ success: true });
      });
    });
    return;
  }

  // Admit Logic
  dbbconnection.getConnection((err, connection) => {
    if (err) return res.status(500).json({ success: false, error: 'DB Error' });

    connection.query("SELECT * FROM hostel_admission_applications WHERE id = ?", [appId], (err, rows) => {
      if (err || rows.length === 0) {
        connection.release();
        return res.status(404).json({ success: false, error: 'Application not found' });
      }

      const appData = rows[0];
      const parsedAppAdvanceAmount = appData.advance_amount != null && appData.advance_amount !== '' ? Number(appData.advance_amount) : NaN;
      const appAdvanceAmount = Number.isFinite(parsedAppAdvanceAmount) ? parsedAppAdvanceAmount.toFixed(2) : null;
      const appPaymentMode = ((appData.payment_mode || '') + '').trim();
      const bookingAdvanceAmount = appAdvanceAmount;
      const bookingTransactionId = ['Cash', 'Online'].includes(appPaymentMode) ? appPaymentMode : null;

      // Check bed is free
      connection.query("SELECT id FROM room_bookings WHERE room_no = ? AND bed_no = ? AND booking_status = 'locked' LIMIT 1", [allotted_room, allotted_bed], (bedErr, bedRows) => {
        if (bedErr || bedRows.length > 0) {
          connection.release();
          return res.status(400).json({ success: false, error: 'Bed is already locked' });
        }

        // Generate UID
        generateTempHostelUid(connection, function (uidErr, newUid) {
          if (uidErr) { connection.release(); return res.status(500).json({ success: false }); }

          // Create Student
          const studentSql = "INSERT INTO studentdetails (uid, hostel_id, sname, email, password, dept, address, year, category, gender, mobileno, dob, academicyear, status, parentname, parentnumber, room_no, bed_no, mess_type, other2, block, is_temp_uid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)";
          require('bcrypt').hash(appData.student_mobile, 10, (err, hash) => {
            if (err) { connection.release(); return res.status(500).json({ success: false }); }

            let formattedDob = appData.dob;
            if (appData.dob instanceof Date) {
              const d = appData.dob;
              formattedDob = d.toISOString().split('T')[0];
            }

            const studentValues = [
              newUid, newUid, appData.full_name, appData.student_email || null, hash, appData.branch,
              appData.permanent_address, appData.admission_year, 'Hostel', 'MALE', appData.student_mobile, formattedDob,
              new Date().getFullYear() + '-' + (new Date().getFullYear() + 1), 'active', appData.father_name, appData.parent_phone,
              allotted_room, allotted_bed, appData.mess_preference, appData.caste_category, allotted_block
            ];

            connection.query(studentSql, studentValues, (err) => {
              if (err) { connection.release(); return res.status(500).json({ success: false }); }

              // Update Application
              const updateAppSql = "UPDATE hostel_admission_applications SET status='Admitted', allotted_block=?, allotted_room=?, allotted_bed=?, admin_remarks=?, student_uid=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?";
              connection.query(updateAppSql, [allotted_block, allotted_room, allotted_bed, remarks, newUid, 'Super ID', appId], (err) => {
                if (err) { connection.release(); return res.status(500).json({ success: false }); }

                // Insert Booking
                const insertBookingSql = "INSERT INTO room_bookings (room_no, block, floor, bed_no, uid, booking_status, payment_status, advance_amount, transaction_id, agreement_accepted, locked_source, locked_by) SELECT ?, ?, IFNULL((SELECT floor FROM rooms WHERE name = ? AND block = ? LIMIT 1), 'Ground Floor'), ?, ?, 'locked', 'confirmed', ?, ?, 1, 'admin', 'Super ID'";
                connection.query(insertBookingSql, [allotted_room || null, allotted_block || null, allotted_room || null, allotted_block || null, allotted_bed || null, newUid, bookingAdvanceAmount, bookingTransactionId], function (rbErr) {
                  connection.release();
                  res.json({ success: true, newUid });
                });
              });
            });
          });
        });
      });
    });
  });
});

app.post('/api/mobile/v1/admissions/:id/delete', function (req, res) {
  const appId = req.params.id;
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB Error' });

    connection.query('DELETE FROM hostel_admission_applications WHERE id = ?', [appId], (err) => {
      connection.release();
      if (err) return res.status(500).json({ success: false });
      return res.json({ success: true });
    });
  });
});

app.post('/api/mobile/v1/admissions/:id/remove', function (req, res) {
  const appId = req.params.id;
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB Error' });

    connection.beginTransaction((err) => {
      if (err) { connection.release(); return res.status(500).json({ success: false }); }

      connection.query('SELECT student_uid FROM hostel_admission_applications WHERE id = ?', [appId], (err, rows) => {
        if (err || rows.length === 0) {
          return connection.rollback(() => { connection.release(); res.status(404).json({ success: false }); });
        }

        const student_uid = rows[0].student_uid;
        if (!student_uid) {
          // Not admitted yet, just reject it
          connection.query(
            "UPDATE hostel_admission_applications SET status='Rejected', admin_remarks=CONCAT(IFNULL(admin_remarks,''), ' | REMOVED FROM SYSTEM') WHERE id=?",
            [appId],
            (err) => {
              if (err) return connection.rollback(() => { connection.release(); res.status(500).json({ success: false }); });
              connection.commit(() => { connection.release(); return res.json({ success: true }); });
            }
          );
          return;
        }

        connection.query('DELETE FROM daily_attendance WHERE uid=?', [student_uid], (err) => {
          if (err) return connection.rollback(() => { connection.release(); res.status(500).json({ success: false }); });

          connection.query('DELETE FROM room_bookings WHERE uid=?', [student_uid], (err) => {
            if (err) return connection.rollback(() => { connection.release(); res.status(500).json({ success: false }); });

            connection.query('DELETE FROM studentdetails WHERE uid=?', [student_uid], (err) => {
              if (err) return connection.rollback(() => { connection.release(); res.status(500).json({ success: false }); });

              connection.query(
                "UPDATE hostel_admission_applications SET status='Rejected', student_uid=NULL, allotted_room=NULL, allotted_block=NULL, allotted_bed=NULL, admin_remarks=CONCAT(IFNULL(admin_remarks,''), ' | REMOVED FROM SYSTEM by SuperID at ', NOW()) WHERE id=?",
                [appId],
                (err) => {
                  if (err) return connection.rollback(() => { connection.release(); res.status(500).json({ success: false }); });
                  connection.commit(() => { connection.release(); return res.json({ success: true }); });
                }
              );
            });
          });
        });
      });
    });
  });
});

app.post('/api/mobile/v1/admissions/:id/transfer', function (req, res) {
  const appId = req.params.id;
  const { new_block, new_room, new_bed, transfer_reason } = req.body;

  if (!new_block || !new_room || !new_bed) {
    return res.status(400).json({ success: false, error: 'Missing transfer details' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB Error' });

    connection.beginTransaction((err) => {
      if (err) { connection.release(); return res.status(500).json({ success: false }); }

      connection.query('SELECT student_uid FROM hostel_admission_applications WHERE id = ?', [appId], (err, rows) => {
        if (err || rows.length === 0) {
          return connection.rollback(() => { connection.release(); res.status(404).json({ success: false }); });
        }

        const student_uid = rows[0].student_uid;
        const transferText = 'TRANSFER: ' + (transfer_reason || 'No reason provided');

        connection.query(
          "UPDATE hostel_admission_applications SET allotted_block=?, allotted_room=?, allotted_bed=?, admin_remarks=IF(IFNULL(admin_remarks,'')='', ?, CONCAT(admin_remarks, ' | ', ?)) WHERE id=?",
          [new_block, new_room, new_bed, transferText, transferText, appId],
          (err) => {
            if (err) return connection.rollback(() => { connection.release(); res.status(500).json({ success: false }); });

            if (student_uid) {
              connection.query(
                "UPDATE studentdetails SET room_no=?, block=?, bed_no=?, other2=? WHERE uid=?",
                [new_room, new_block, new_bed, new_block, student_uid],
                (err) => {
                  if (err) return connection.rollback(() => { connection.release(); res.status(500).json({ success: false }); });

                  connection.query(
                    "UPDATE room_bookings SET room_no=?, block=?, bed_no=? WHERE uid=? AND booking_status='locked'",
                    [new_room, new_block, new_bed, student_uid],
                    (err) => {
                      if (err) return connection.rollback(() => { connection.release(); res.status(500).json({ success: false }); });
                      connection.commit(() => { connection.release(); return res.json({ success: true }); });
                    }
                  );
                }
              );
            } else {
              connection.commit(() => { connection.release(); return res.json({ success: true }); });
            }
          }
        );
      });
    });
  });
});
// =============================================================================
// MOBILE API: GET /api/mobile/v1/admin/restrictionaudit
// =============================================================================
app.get('/api/mobile/v1/admin/restrictionaudit', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;

  if (!["SuperID", "BoysHostelAdmin", "GirlsHostelAdmin", "Hostelauthority"].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorised Access' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    const auditSql = `
      SELECT
        a.id,
        a.uid,
        s.sname,
        s.gender,
        s.category,
        a.logid,
        a.passtype,
        a.restriction_reason,
        a.restriction_source,
        a.details,
        a.restricted_at,
        l.approvaldt,
        l.outdatetime,
        l.indatetime,
        l.hostelintime,
        l.status AS log_status
      FROM pass_restriction_audit a
      LEFT JOIN studentdetails s ON s.uid = a.uid
      LEFT JOIN log_details1 l ON l.logid = a.logid
      WHERE s.status = 'Restrict'
      AND a.id = (SELECT MAX(id) FROM pass_restriction_audit WHERE uid = a.uid)
      ORDER BY a.id DESC
      LIMIT 200
    `;

    connection.query(auditSql, function (auditErr, rows) {
      connection.release();
      if (auditErr) {
        console.error('[Mobile API] /admin/restrictionaudit err:', auditErr);
        return res.status(500).json({ success: false, error: 'Failed to load restriction audit' });
      }
      return res.json({ success: true, data: rows || [] });
    });
  });
});

// =============================================================================
// MOBILE API: POST /api/mobile/v1/admin/audit/mark-scan/:logid
// =============================================================================
app.post('/api/mobile/v1/admin/audit/mark-scan/:logid', express.json(), verifyMobileJwt, function(req, res) {
  const role = req.decode && req.decode.role;
  const logid = req.params.logid;
  const type = req.body.type;
  const restrictionReason = req.body.restriction_reason || '';

  if (!["SuperID", "BoysHostelAdmin", "GirlsHostelAdmin", "Hostelauthority"].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorised Access' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });
    
    if (type === 'unrestrict') {
      const isHostelScanCase = [
        'hostel_scan_after_10pm',
        'scanned_after_10pm',
        'midnight_sweep_home_pass_late_hostel_scan'
      ].includes(restrictionReason);

      if (isHostelScanCase) {
        const auditLookupSql = `
          SELECT pra.details, l.hostelintime AS current_hostelintime, l.uid
          FROM pass_restriction_audit pra
          LEFT JOIN log_details1 l ON l.logid = pra.logid
          WHERE pra.logid = ? ORDER BY pra.id DESC LIMIT 1
        `;
        connection.query(auditLookupSql, [logid], function(lookupErr, auditRows) {
          if (lookupErr || !auditRows || auditRows.length === 0) {
            const fallbackSql = "UPDATE studentdetails SET status='Unrestrict' WHERE uid=(SELECT uid FROM log_details1 WHERE logid='" + logid + "')";
            connection.query(fallbackSql, function() {
              connection.release();
              return res.json({ success: true, message: 'Student unrestricted (fallback, audit not found)' });
            });
            return;
          }

          const auditRow = auditRows[0];
          let originalHostelInTime = null;
          try {
            const details = typeof auditRow.details === 'string'
              ? JSON.parse(auditRow.details)
              : auditRow.details;
            if (details && details.hostelintime && details.hostelintime !== 'null') {
              originalHostelInTime = details.hostelintime;
            }
          } catch (e) {}

          if (!originalHostelInTime && auditRow.current_hostelintime) {
            originalHostelInTime = auditRow.current_hostelintime;
          }

          if (!originalHostelInTime) {
            originalHostelInTime = formatDateTimeForDB(currentdate());
          }

          const markHostelInSql = "UPDATE log_details1 SET status='DEAD', hostelintime=? WHERE logid=?";
          connection.query(markHostelInSql, [originalHostelInTime, logid], function(hostelErr) {
            if (hostelErr) {
              connection.release();
              return res.status(500).json({ success: false, error: 'Failed to record hostel-in time' });
            }
            const unrestrictSql = "UPDATE studentdetails SET status='Unrestrict' WHERE uid=(SELECT uid FROM log_details1 WHERE logid='" + logid + "')";
            connection.query(unrestrictSql, function(err2) {
              connection.release();
              if (err2) return res.status(500).json({ success: false, error: 'Unrestrict failed' });
              return res.json({ success: true, message: 'Student unrestricted and hostel-in recorded with original scan time' });
            });
          });
        });
        return;
      }

      const unrestrictSql = "UPDATE studentdetails SET status='Unrestrict' WHERE uid=(SELECT uid FROM log_details1 WHERE logid='" + logid + "')";
      connection.query(unrestrictSql, function(err2) {
        connection.release();
        if (err2) return res.status(500).json({ success: false, error: 'Unrestrict failed' });
        return res.json({ success: true, message: 'Student unrestricted successfully' });
      });
      return;
    }

    let sql = '';
    const currentDateTime = formatDateTimeForDB(currentdate());
    
    if (type === 'gate_in') {
      sql = "UPDATE log_details1 SET indatetime='" + currentDateTime + "' WHERE logid='" + logid + "'";
    } else if (type === 'hostel_in') {
      sql = "UPDATE log_details1 SET status='DEAD', hostelintime='" + currentDateTime + "' WHERE logid='" + logid + "'";
    } else {
      connection.release();
      return res.status(400).json({ success: false, error: 'Invalid scan type' });
    }
    
    connection.query(sql, function(err, result) {
      connection.release();
      if (err) {
        return res.status(500).json({ success: false, error: 'Update failed' });
      }
      
      if (type === 'hostel_in') {
        res.json({ success: true, message: 'Hostel In marked successfully' });
      } else {
        res.json({ success: true, message: 'Gate In marked successfully' });
      }
    });
  });
});

// Mobile App Admin Today's Log Endpoint
app.get('/api/mobile/v1/admin/todayslog', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  let dateFrom = req.query.dateFrom;
  let dateTo = req.query.dateTo;

  // Keep the endpoint resilient if the app does not pass dates yet.
  const today = convert(formatDateTimeForDB(currentdate()));
  if (!dateFrom || !dateTo) {
    dateFrom = today;
    dateTo = today;
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    let sql = '';
    if (role === 'BoysHostelAdmin') {
      sql = "select stu.uid, stu.sname, log.indatetime, log.outdatetime, log.approvaldt, log.hostelintime, log.hosteloutauth, log.passtype, CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`, CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu on stu.uid=log.uid where stu.gender='MALE' and DATE(approvaldt) BETWEEN '" + dateFrom + "' AND '" + dateTo + "' and category='Hostel' ORDER BY log.logid desc";
    } else if (role === 'GirlsHostelAdmin') {
      sql = "select stu.uid, stu.sname, log.indatetime, log.outdatetime, log.approvaldt, log.hostelintime, log.hosteloutauth, log.passtype, CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`, CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu on stu.uid=log.uid where stu.gender='FEMALE' and (DATE(log.approvaldt) BETWEEN '" + dateFrom + "' AND '" + dateTo + "' or DATE(log.outdatetime) BETWEEN '" + dateFrom + "' AND '" + dateTo + "' or DATE(log.indatetime) BETWEEN '" + dateFrom + "' AND '" + dateTo + "' or DATE(log.hostelintime) BETWEEN '" + dateFrom + "' AND '" + dateTo + "') and category='Hostel' ORDER BY log.logid desc";
    } else {
      sql = "select stu.uid, stu.sname, log.indatetime, log.outdatetime, log.approvaldt, log.hostelintime, log.hosteloutauth, log.passtype, CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.outdatetime, log.indatetime) % 3600)/60), ' min ') AS `Duration`, CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 86400)/3600), ' hours ',FLOOR((TIMESTAMPDIFF(SECOND, log.approvaldt, log.hostelintime) % 3600)/60), ' min ') AS `Durationh` from log_details1 as log join studentdetails as stu on stu.uid=log.uid where (DATE(log.approvaldt) BETWEEN '" + dateFrom + "' AND '" + dateTo + "' or DATE(log.outdatetime) BETWEEN '" + dateFrom + "' AND '" + dateTo + "' or DATE(log.indatetime) BETWEEN '" + dateFrom + "' AND '" + dateTo + "' or DATE(log.hostelintime) BETWEEN '" + dateFrom + "' AND '" + dateTo + "') ORDER BY log.logid desc";
    }

    connection.query(sql, function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Failed to fetch logs' });
      }
      return res.json({ success: true, data: result });
    });
  });
});
// Mobile App Dashboard Counts Endpoint
app.get('/api/mobile/v1/dashboard-counts', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin', 'Hostelauthority'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    let genderJoinBase = '';
    let genderWhereBase = '';

    if (role === 'BoysHostelAdmin') {
      genderJoinBase = ' LEFT JOIN studentdetails sd ON {alias}.{col} = sd.uid ';
      genderWhereBase = " AND sd.gender = 'MALE' ";
    } else if (role === 'GirlsHostelAdmin') {
      genderJoinBase = ' LEFT JOIN studentdetails sd ON {alias}.{col} = sd.uid ';
      genderWhereBase = " AND sd.gender = 'FEMALE' ";
    }

    function getScope(alias, col) {
      if (!genderJoinBase) return '';
      return genderJoinBase.replace('{alias}', alias).replace('{col}', col) + genderWhereBase;
    }

    const sql = `
      SELECT
        (SELECT COUNT(*) FROM pass_requests pr ${getScope('pr', 'uid')} WHERE pr.status = 'pending') AS passRequests,
        (SELECT COUNT(*) FROM sick_leave_requests slr ${getScope('slr', 'uid')} WHERE slr.status = 'pending' AND DATE(slr.created_at) = CURDATE()) AS sickLeaveRequests,
        (SELECT COUNT(*) FROM bonafide_requests br ${getScope('br', 'student_uid')} WHERE br.status = 'Pending') AS bonafideRequests,
        (SELECT COUNT(*) FROM hostel_admission_applications WHERE status = 'Pending') AS pendingAdmissions,
        (SELECT COUNT(*) FROM complaints c ${getScope('c', 'student_uid')} WHERE c.status = 'pending_approval') AS verifyComplaints
    `;

    connection.query(sql, function (qErr, results) {
      connection.release();
      if (qErr || !results || results.length === 0) {
        return res.status(500).json({ success: false, error: 'Error fetching dashboard counts' });
      }

      const counts = results[0];
      return res.json({
        success: true,
        data: {
          passRequests: counts.passRequests || 0,
          sickLeaveRequests: counts.sickLeaveRequests || 0,
          bonafideRequests: counts.bonafideRequests || 0,
          pendingAdmissions: counts.pendingAdmissions || 0,
          verifyComplaints: counts.verifyComplaints || 0
        }
      });
    });
  });
});
// Mobile App Admin Pass Requests Endpoints
app.get('/api/mobile/v1/passrequests', function (req, res) {
  const filterStatus = (req.query.status || 'pending').toLowerCase();
  const filterRestrictionStatus = req.query.restrictionStatus || '';
  const fromDate = req.query.fromDate || '';
  const toDate = req.query.toDate || '';
  const searchQuery = (req.query.q || '').trim();

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    let baseSql = `
      SELECT pr.requestid as id, pr.uid, pr.passtype as type, pr.status, pr.reason as purpose, pr.emergency_contact, pr.conversion_enabled, pr.request_kind,
             DATE_FORMAT(pr.expected_out, '%Y-%m-%d') as out_date,
             DATE_FORMAT(pr.expected_out, '%H:%i') as out_time,
             DATE_FORMAT(pr.expected_return, '%Y-%m-%d') as return_date,
             DATE_FORMAT(pr.expected_return, '%H:%i') as return_time,
             DATE_FORMAT(pr.created_at, '%Y-%m-%d %H:%i:%s') as created_at,
             pr.approved_by, pr.rejection_reason, DATE_FORMAT(pr.approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
             sd.sname as name, sd.dept, sd.year, sd.mobileno, sd.gender, sd.path
      FROM pass_requests pr 
      LEFT JOIN studentdetails sd ON pr.uid = sd.uid 
      WHERE 1=1
    `;
    let params = [];

    if (filterStatus && filterStatus !== 'all') {
      baseSql += " AND pr.status = ?";
      params.push(filterStatus);
    }

    if (filterRestrictionStatus && filterRestrictionStatus !== 'All Restrictions') {
      baseSql += " AND sd.status = ?";
      params.push(filterRestrictionStatus);
    }

    if (fromDate && toDate) {
      baseSql += " AND DATE(pr.created_at) BETWEEN ? AND ?";
      params.push(fromDate, toDate);
    } else {
      if (filterStatus === 'approved' || filterStatus === 'rejected') {
        baseSql += " AND DATE(pr.approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30'))";
      } else if (filterStatus === 'pending') {
        // No date filter for pending
      } else {
        baseSql += " AND DATE(pr.created_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30'))";
      }
    }

    if (searchQuery) {
      baseSql += " AND (sd.sname LIKE ? OR pr.uid LIKE ?)";
      const likeTerm = `%${searchQuery}%`;
      params.push(likeTerm, likeTerm);
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const countSql = `SELECT COUNT(*) as totalFiltered FROM (${baseSql}) as tmp`;
    const countParams = [...params];

    baseSql += " ORDER BY pr.created_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const statsSql = `
      SELECT 
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
        COUNT(CASE WHEN status = 'approved' AND DATE(approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) THEN 1 END) as approved,
        COUNT(CASE WHEN status = 'rejected' AND DATE(approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) THEN 1 END) as rejected,
        COUNT(CASE WHEN (status = 'pending' OR DATE(created_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30'))) THEN 1 END) as total
      FROM pass_requests
    `;

    connection.query(statsSql, function (statsErr, statsResult) {
      if (statsErr) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Failed to fetch stats' });
      }
      const stats = statsResult[0];

      connection.query(countSql, countParams, function (countErr, countResult) {
        if (countErr) {
          connection.release();
          return res.status(500).json({ success: false, error: 'Failed to fetch total count' });
        }
        const totalFiltered = countResult[0].totalFiltered;

        connection.query(baseSql, params, function (err, result) {
          connection.release();
          if (err) return res.status(500).json({ success: false, error: 'Failed to fetch pass requests' });
          (result || []).forEach(attachStudentPhotoUrl);
          return res.json({ success: true, data: result, stats, totalFiltered });
        });
      });
    });
  });
});

app.post('/api/mobile/v1/passrequests/:id/approve', express.json(), function (req, res) {
  const requestId = req.params.id;

  let adminUid = 'Admin';
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    const token = req.headers.authorization.split(' ')[1];
    try {
      const decoded = jwt.verify(token, secretkey);
      if (decoded && decoded.adminuid) {
        adminUid = decoded.adminuid;
      }
    } catch (e) { }
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    // We assume formatDateToISTString is available globally in app.js
    const nowIST = formatDateToISTString(new Date());
    const sql = "UPDATE pass_requests SET status = 'approved', approved_by = ?, approved_at = ? WHERE requestid = ?";

    connection.query(sql, [adminUid, nowIST, requestId], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to approve pass request' });
      return res.json({ success: true });
    });
  });
});

app.post('/api/mobile/v1/passrequests/:id/reject', express.json(), function (req, res) {
  const requestId = req.params.id;
  const reason = req.body.reason || 'Rejected by Admin';

  let adminUid = 'Admin';
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    const token = req.headers.authorization.split(' ')[1];
    try {
      const decoded = jwt.verify(token, secretkey);
      if (decoded && decoded.adminuid) {
        adminUid = decoded.adminuid;
      }
    } catch (e) { }
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    const nowIST = formatDateToISTString(new Date());
    const sql = "UPDATE pass_requests SET status = 'rejected', approved_by = ?, approved_at = ?, rejection_reason = ? WHERE requestid = ?";

    connection.query(sql, [adminUid, nowIST, reason, requestId], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to reject pass request' });
      return res.json({ success: true });
    });
  });
});

app.post('/api/mobile/v1/passrequests/:id/reset', express.json(), function (req, res) {
  const requestId = req.params.id;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    const resetSql = `
      UPDATE pass_requests 
      SET status = 'pending', 
          approved_by = NULL, 
          approved_at = NULL, 
          rejection_reason = NULL,
          updated_at = NOW()
      WHERE requestid = ?
    `;

    connection.query(resetSql, [requestId], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to reset pass request' });
      return res.json({ success: true });
    });
  });
});

app.post('/api/mobile/v1/passrequests/:id/enableconversion', express.json(), function (req, res) {
  const requestId = req.params.id;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    const updateSql = "UPDATE pass_requests SET conversion_enabled = 1, conversion_enabled_by = ? WHERE requestid = ? AND status = 'approved' AND passtype = 'City Pass'";

    connection.query(updateSql, ['Admin', requestId], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to enable conversion' });
      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, error: 'Request not found or not eligible for conversion' });
      }
      return res.json({ success: true });
    });
  });
});

// --- MOBILE APIs FOR SICK LEAVE ---

app.get('/api/mobile/v1/sickleave', express.json(), function (req, res) {
  let adminUid = 'Admin';
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    const token = req.headers.authorization.split(' ')[1];
    try {
      const decoded = jwt.verify(token, secretkey);
      if (decoded.adminuid) adminUid = decoded.adminuid;
    } catch (e) {
      console.log('JWT Error in /api/mobile/v1/sickleave:', e.message);
    }
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var sql = `
      SELECT slr.*, sd.sname as name, sd.uid as student_uid, sd.room_no, sd.path
      FROM sick_leave_requests slr
      LEFT JOIN studentdetails sd ON slr.uid = sd.uid
      ORDER BY slr.created_at DESC
    `;

    connection.query(sql, function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });
      
      (result || []).forEach(attachStudentPhotoUrl);
      const mapped = result.map(r => ({
        id: r.requestid,
        name: r.name || 'Unknown',
        uid: r.student_uid || r.uid,
        room: r.room_no || 'N/A',
        illness: r.illness,
        status: r.status,
        request_date: r.created_at,
        details: r.details,
        recorded_by: r.approved_by,
        rejection_reason: r.rejection_reason,
        path: r.path
      }));
      return res.json({ success: true, data: mapped });
    });
  });
});

app.post('/api/mobile/v1/sickleave/record', express.json(), function (req, res) {
  const { uid, illness, details } = req.body;
  let adminUid = 'Admin';
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    const token = req.headers.authorization.split(' ')[1];
    try {
      const decoded = jwt.verify(token, secretkey);
      if (decoded.adminuid) adminUid = decoded.adminuid;
    } catch (e) { }
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });

    var nowIST = formatDateToISTString(new Date());
    var insertSql = `
      INSERT INTO sick_leave_requests (uid, illness, details, status, approved_by, approved_at, created_at)
      VALUES (?, ?, ?, 'approved', ?, ?, ?)
    `;

    connection.query(insertSql, [uid, illness, details || null, adminUid, nowIST, nowIST], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to record sick leave' });
      res.json({ success: true, message: 'Recorded successfully' });
    });
  });
});

app.post('/api/mobile/v1/sickleave/:id/approve', express.json(), function (req, res) {
  const requestId = req.params.id;
  let adminUid = 'Admin';
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    const token = req.headers.authorization.split(' ')[1];
    try {
      const decoded = jwt.verify(token, secretkey);
      if (decoded.adminuid) adminUid = decoded.adminuid;
    } catch (e) { }
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB error' });

    var nowIST = formatDateToISTString(new Date());
    var updateSql = "UPDATE sick_leave_requests SET status = 'approved', approved_by = ?, approved_at = ? WHERE requestid = ?";

    connection.query(updateSql, [adminUid, nowIST, requestId], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to approve' });
      res.json({ success: true });
    });
  });
});

app.post('/api/mobile/v1/sickleave/:id/reject', express.json(), function (req, res) {
  const requestId = req.params.id;
  const reason = req.body.reason || 'Rejected by Admin';
  let adminUid = 'Admin';
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    const token = req.headers.authorization.split(' ')[1];
    try {
      const decoded = jwt.verify(token, secretkey);
      if (decoded.adminuid) adminUid = decoded.adminuid;
    } catch (e) { }
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB error' });

    var nowIST = formatDateToISTString(new Date());
    var updateSql = "UPDATE sick_leave_requests SET status = 'rejected', approved_by = ?, approved_at = ?, rejection_reason = ? WHERE requestid = ?";

    connection.query(updateSql, [adminUid, nowIST, reason, requestId], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to reject' });
      res.json({ success: true });
    });
  });
});

// Dynamic student UID details API moved below to avoid routing conflicts

// Mobile API: Add admin
app.post('/api/mobile/v1/admin/adduser', verifyMobileJwt, async function (req, res) {
  const { uid, name, category, hostel, password } = req.body;

  if (!uid || !name || !category || !hostel || !password) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  try {
    let hashedPassword = await bcrypt.hash(password, 12);
    dbbconnection.getConnection(function (err, connection) {
      if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

      var sql = "Insert into admin (uid,name,password,category,hostel) VALUES ? ";
      var values = [[uid, name, hashedPassword, category, hostel]];

      connection.query(sql, [values], function (qErr, result) {
        connection.release();
        if (qErr) {
          if (qErr.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ success: false, error: 'UID already exists' });
          }
          return res.status(500).json({ success: false, error: 'Database query error' });
        }
        return res.json({ success: true, message: 'User added successfully' });
      });
    });
  } catch (error) {
    return res.status(500).json({ success: false, error: 'Error processing request' });
  }
});

// Mobile API: Delete admin
app.delete('/api/mobile/v1/admin/user/:uid', verifyMobileJwt, function (req, res) {
  const uid = req.params.uid;
  if (!uid) return res.status(400).json({ success: false, error: 'UID is required' });

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    connection.query("DELETE FROM admin WHERE uid = ?", [uid], function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Database query error' });
      }
      return res.json({ success: true, message: 'User deleted successfully' });
    });
  });
});

// Mobile API: Get Feature Flags
app.get('/api/mobile/v1/admin/features', verifyMobileJwt, function (req, res) {
  if (!req.decode || req.decode.role !== 'SuperID') {
    return res.status(403).json({ success: false, error: 'Unauthorized to view features' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database error' });

    loadFeatureFlagsMap(connection, function (_lErr, flagsMap) {
      connection.release();
      return res.json({ success: true, data: flagsMap || {} });
    });
  });
});

// Mobile API: Update Feature Flag
app.post('/api/mobile/v1/admin/features', express.json(), verifyMobileJwt, function (req, res) {
  if (!req.decode || req.decode.role !== 'SuperID') {
    return res.status(403).json({ success: false, error: 'Unauthorized to edit features' });
  }

  const { feature_key, enabled, value_str } = req.body;
  const adminName = req.decode.uid || req.decode.name || 'Mobile Admin';

  console.log('[Mobile API] Update Feature Flag - Received body:', JSON.stringify(req.body));

  if (!feature_key) {
    return res.status(400).json({ success: false, error: 'Feature key is required' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database error' });

    let upsertSql;
    let queryParams;

    if (value_str !== undefined && value_str !== null) {
      // Time-setting feature (mess_open_hour, mess_close_hour etc.)
      let value_int = null;
      if (value_str) {
        const parsed = parseInt(value_str.split(':')[0], 10);
        if (!isNaN(parsed)) value_int = parsed;
      }

      upsertSql = `
        INSERT INTO feature_flags (feature_key, enabled, value_str, value_int, updated_by, updated_at)
        VALUES (?, 1, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE value_str = VALUES(value_str), value_int = VALUES(value_int), updated_by = VALUES(updated_by), updated_at = NOW()
      `;
      queryParams = [feature_key, value_str, value_int, adminName];

      console.log('[Mobile API] Time feature upsert - key:', feature_key, 'value_str:', value_str, 'value_int:', value_int, 'admin:', adminName);
    } else {
      // Toggle feature (enabled/disabled)
      const enabledInt = (enabled === true || enabled === 1 || enabled === '1') ? 1 : 0;

      upsertSql = `
        INSERT INTO feature_flags (feature_key, enabled, updated_by, updated_at)
        VALUES (?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), updated_by = VALUES(updated_by), updated_at = NOW()
      `;
      queryParams = [feature_key, enabledInt, adminName];

      console.log('[Mobile API] Toggle feature upsert - key:', feature_key, 'enabled:', enabledInt, 'admin:', adminName);
    }

    connection.query(upsertSql, queryParams, function (qErr, result) {
      connection.release();
      if (qErr) {
        console.error('[Mobile API] update feature error:', qErr);
        return res.status(500).json({ success: false, error: 'Error updating feature: ' + qErr.message });
      }
      console.log('[Mobile API] Feature updated successfully. Affected rows:', result && result.affectedRows);
      return res.json({ success: true, message: 'Feature updated successfully' });
    });
  });
});

// Mobile API: Fetch admins
app.get('/api/mobile/v1/admin/users', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    let query = "";
    if (role === 'SuperID') {
      query = "SELECT * FROM admin";
    } else if (role === 'BoysHostelAdmin') {
      query = "SELECT * FROM admin WHERE hostel='Boys'";
    } else if (role === 'GirlsHostelAdmin') {
      query = "SELECT * FROM admin WHERE hostel='Girls'";
    } else {
      connection.release();
      return res.status(403).json({ success: false, error: 'Unauthorized to view admins' });
    }

    connection.query(query, function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Database query error' });
      }
      return res.json({ success: true, data: result });
    });
  });
});

// =============================================================================
// MOBILE API: GET /api/mobile/v1/admin/timebound
// =============================================================================
app.get('/api/mobile/v1/admin/timebound', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    let sql = "";
    if (role === "BoysHostelAdmin") {
      sql = "SELECT * FROM timebound WHERE hostel='Boys'";
    } else if (role === "GirlsHostelAdmin") {
      sql = "SELECT * FROM timebound WHERE hostel='Girls'";
    } else if (role === "SuperID") {
      sql = "SELECT * FROM timebound";
    } else {
      connection.release();
      return res.status(403).json({ success: false, error: 'Unauthorised Access' });
    }

    connection.query(sql, function (qErr, result) {
      connection.release();
      if (qErr) {
        console.error('[Mobile API] /admin/timebound err:', qErr);
        return res.status(500).json({ success: false, error: 'Database query error' });
      }
      return res.json({ success: true, data: result });
    });
  });
});

// =============================================================================
// MOBILE API: POST /api/mobile/v1/admin/timebound/update
// =============================================================================
app.post('/api/mobile/v1/admin/timebound/update', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  
  if (!["SuperID", "BoysHostelAdmin", "GirlsHostelAdmin"].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorised Access' });
  }

  const day = req.body.dropdownlist1;
  const start = req.body.StartTime1;
  const end = req.body.EndTime1;
  const start1 = req.body.StartTime2;
  const end1 = req.body.EndTime2;
  let hostel = req.body.hostel;

  if (role === 'BoysHostelAdmin') hostel = 'Boys';
  else if (role === 'GirlsHostelAdmin') hostel = 'Girls';

  if (!day || !start || !end || !start1 || !end1 || !hostel) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  const dayNoMap = {
    'Sunday': '0',
    'Monday': '1',
    'Tuesday': '2',
    'Wednesday': '3',
    'Thursday': '4',
    'Friday': '5',
    'Saturday': '6'
  };
  const dayno = dayNoMap[day] || '';

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var checkSql = "SELECT * FROM timebound WHERE hostel = ? AND days = ?";
    connection.query(checkSql, [hostel, day], function (cErr, cResult) {
      if (cErr) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Database check error' });
      }

      if (cResult.length > 0) {
        var updateSql = "UPDATE timebound SET start = ?, end = ?, start1 = ?, end1 = ?, dayno = ? WHERE hostel = ? AND days = ?";
        connection.query(updateSql, [start, end, start1, end1, dayno, hostel, day], function (uErr) {
          connection.release();
          if (uErr) return res.status(500).json({ success: false, error: 'Error updating time bound' });
          return res.json({ success: true, message: 'Time bound updated successfully' });
        });
      } else {
        var insertSql = "INSERT INTO timebound (days, start, end, start1, end1, dayno, hostel) VALUES (?, ?, ?, ?, ?, ?, ?)";
        connection.query(insertSql, [day, start, end, start1, end1, dayno, hostel], function (iErr) {
          connection.release();
          if (iErr) return res.status(500).json({ success: false, error: 'Error adding time bound' });
          return res.json({ success: true, message: 'Time bound added successfully' });
        });
      }
    });
  });
});

// =============================================================================
// MOBILE API: DELETE /api/mobile/v1/admin/timebound/:tbid
// =============================================================================
app.delete('/api/mobile/v1/admin/timebound/:tbid', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const tbid = req.params.tbid;
  
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var checkSql = "SELECT * FROM timebound WHERE tbid = ?";
    connection.query(checkSql, [tbid], function (cErr, cResult) {
      if (cErr) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Database check error' });
      }

      if (cResult.length > 0) {
        if (role !== "SuperID" && ((role === "BoysHostelAdmin" && cResult[0].hostel !== "Boys") || (role === "GirlsHostelAdmin" && cResult[0].hostel !== "Girls"))) {
          connection.release();
          return res.status(403).json({ success: false, error: 'Unauthorised to delete this record' });
        }
        var deleteSql = "DELETE FROM timebound WHERE tbid = ?";
        connection.query(deleteSql, [tbid], function (dErr) {
          connection.release();
          if (dErr) return res.status(500).json({ success: false, error: 'Error deleting time bound' });
          return res.json({ success: true, message: 'Time bound deleted successfully' });
        });
      } else {
        connection.release();
        return res.status(404).json({ success: false, error: 'Time bound not found' });
      }
    });
  });
});

// =============================================================================
// MOBILE API: POST /api/mobile/v1/admin/timebound/toggle/:tbid/:status
// =============================================================================
app.post('/api/mobile/v1/admin/timebound/toggle/:tbid/:status', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const tbid = req.params.tbid;
  const status = req.params.status;
  
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var checkSql = "SELECT * FROM timebound WHERE tbid = ?";
    connection.query(checkSql, [tbid], function (cErr, cResult) {
      if (cErr) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Database check error' });
      }

      if (cResult.length > 0) {
        if (role !== "SuperID" && ((role === "BoysHostelAdmin" && cResult[0].hostel !== "Boys") || (role === "GirlsHostelAdmin" && cResult[0].hostel !== "Girls"))) {
          connection.release();
          return res.status(403).json({ success: false, error: 'Unauthorised to modify this record' });
        }
        var updateSql = "UPDATE timebound SET status = ? WHERE tbid = ?";
        connection.query(updateSql, [status, tbid], function (uErr) {
          connection.release();
          if (uErr) return res.status(500).json({ success: false, error: 'Error updating status' });
          return res.json({ success: true, message: `Time bound set to ${status} successfully` });
        });
      } else {
        connection.release();
        return res.status(404).json({ success: false, error: 'Time bound not found' });
      }
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// MOBILE ATTENDANCE APIS  (AdminAttendanceScreen)
// Added for React Native mobile app — DO NOT remove or reorder
// ─────────────────────────────────────────────────────────────────────────────

// Fragment A
const currentOccupancySql = `
SELECT DISTINCT
    s.uid,
    s.sname,
    s.path,
    s.dept,
    s.year,
    s.parentnumber,
    s.mess_type,
    s.other3,
    s.gender,
    s.room_no AS room_name,
    s.block,
    vg.floor,
    s.bed_no AS bed_letter
FROM studentdetails s
INNER JOIN v_room_grid vg
    ON vg.block = s.block
   AND vg.room_name = s.room_no
   AND vg.bed_letter = s.bed_no
WHERE s.category = 'Hostel'
  AND s.room_no IS NOT NULL AND TRIM(COALESCE(s.room_no, '')) <> ''
  AND s.bed_no IS NOT NULL AND TRIM(COALESCE(s.bed_no, '')) <> ''
  AND LOWER(COALESCE(s.status, '')) <> 'restrict'
`;

// Fragment B
const mainGridSql = `
SELECT
    vg.room_name, vg.block, vg.floor, vg.bed_letter,
    cur.uid, cur.sname, cur.path, cur.dept, cur.year, cur.parentnumber, cur.mess_type, cur.other3,
    CASE
        WHEN cur.uid IS NULL THEN NULL
        WHEN EXISTS (SELECT 1 FROM sick_leave_logs sl WHERE sl.uid = cur.uid AND sl.logdate = CURDATE()) THEN 'Sick'
        WHEN EXISTS (SELECT 1 FROM daily_attendance da WHERE da.uid = cur.uid AND da.date = CURDATE() AND da.status IN ('Present', 'Absent'))
            THEN (SELECT status FROM daily_attendance da WHERE da.uid = cur.uid AND da.date = CURDATE())
        WHEN EXISTS (SELECT 1 FROM log_details1 l WHERE l.uid = cur.uid AND l.status = 'ACTIVE') THEN 'Home'
        ELSE IFNULL((SELECT status FROM daily_attendance da WHERE da.uid = cur.uid AND da.date = CURDATE()), 'Pending')
    END AS today_status
FROM v_room_grid vg
LEFT JOIN (${currentOccupancySql}) cur
    ON vg.block = cur.block
   AND vg.room_name = cur.room_name
   AND vg.bed_letter = cur.bed_letter
WHERE 1=1
ORDER BY vg.room_name ASC, vg.bed_letter ASC
`;

// Route 1: GET  /api/mobile/v1/attendance/grid
app.get('/api/mobile/v1/attendance/grid', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  let genderFilter = "";
  let summaryParams = [];

  if (role === 'BoysHostelAdmin') {
    genderFilter = "AND LOWER(cur.gender) = 'male'";
    summaryParams.push('male');
  } else if (role === 'GirlsHostelAdmin') {
    genderFilter = "AND LOWER(cur.gender) = 'female'";
    summaryParams.push('female');
  }

  // Fragment C
  const dailySummarySql = `
SELECT
    da.date AS date,
    COUNT(*) AS total,
    SUM(CASE WHEN da.status = 'Present' THEN 1 ELSE 0 END) AS present,
    SUM(CASE WHEN da.status = 'Absent'  THEN 1 ELSE 0 END) AS absent,
    SUM(CASE WHEN da.status = 'Home'    THEN 1 ELSE 0 END) AS home,
    SUM(CASE WHEN da.status = 'Sick'    THEN 1 ELSE 0 END) AS sick,
    SUM(CASE WHEN da.status = 'Pending' THEN 1 ELSE 0 END) AS pending
FROM daily_attendance da
JOIN (${currentOccupancySql}) cur ON cur.uid = da.uid
WHERE da.date >= DATE_SUB(CURDATE(), INTERVAL 14 DAY)
  ${genderFilter}
GROUP BY da.date
ORDER BY da.date DESC
`;

  // Fragment D
  const seedSql = `
INSERT IGNORE INTO daily_attendance (uid, date, status, marked_by)
SELECT DISTINCT cur.uid, CURDATE(), 'Pending', 'SYSTEM'
FROM (${currentOccupancySql}) cur
`;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });

    // Step 2: Seed
    connection.query(seedSql, [], function (seedErr) {
      if (seedErr) console.error("Seed error:", seedErr);

      // Step 4: Run Fragment C (daily summary)
      connection.query(dailySummarySql, summaryParams, function (sumErr, summaryResult) {
        let dailySummaryRows = [];
        if (!sumErr) {
          dailySummaryRows = summaryResult;
        }

        // Step 5: Run Fragment B (main grid)
        connection.query(mainGridSql, [], function (gridErr, gridResult) {
          connection.release();
          if (gridErr) return res.status(500).json({ success: false, error: 'Query failed' });

          // Step 6: Calculate stats
          const activeRows = (gridResult || []).filter(x => x.uid);
          const activeUids = new Set(activeRows.map(x => x.uid));
          const stats = {
            total: activeUids.size,
            present: activeRows.filter(x => x.today_status === 'Present').length,
            absent: activeRows.filter(x => x.today_status === 'Absent').length,
            onPass: activeRows.filter(x => x.today_status === 'Home' || x.today_status === 'Gate').length
          };

          res.json({
            success: true,
            serverData: gridResult,
            stats: stats,
            dailySummary: dailySummaryRows
          });
        });
      });
    });
  });
});

// Route 2: POST /api/mobile/v1/attendance/mark
app.post('/api/mobile/v1/attendance/mark', verifyMobileJwt, function (req, res) {
  const { uid, status } = req.body;
  if (!uid || !['Present', 'Absent'].includes(status)) {
    return res.status(400).json({ success: false, error: 'uid and valid status (Present/Absent) required' });
  }

  const markedBy = (req.decode && (req.decode.adminname || req.decode.adminuid || req.decode.uid)) || 'Mobile';

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });

    const sql = `
INSERT INTO daily_attendance (uid, date, status, marked_by)
VALUES (?, CURDATE(), ?, ?)
ON DUPLICATE KEY UPDATE status = ?, marked_by = ?
`;
    connection.query(sql, [uid, status, markedBy, status, markedBy], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });
      res.json({ success: true, message: 'Attendance marked' });
    });
  });
});

// Route 3: POST /api/mobile/v1/attendance/assign-room
app.post('/api/mobile/v1/attendance/assign-room', verifyMobileJwt, function (req, res) {
  const { uid, room_no, bed_no } = req.body;
  if (!uid) {
    return res.status(400).json({ success: false, error: 'uid is required' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });

    const sql = `UPDATE studentdetails SET room_no = ?, bed_no = ?, other3 = NULL WHERE uid = ?`;
    connection.query(sql, [room_no, bed_no, uid], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });
      res.json({ success: true, message: 'Room assignment updated' });
    });
  });
});

// Route 4: GET /api/mobile/v1/attendance/unallocated
app.get('/api/mobile/v1/attendance/unallocated', verifyMobileJwt, function (req, res) {
  const term = req.query.term || '';

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });

    let sql1 = `
SELECT s.uid, s.sname
FROM studentdetails s
WHERE (
    s.category = 'Hostel'
    OR s.category IS NULL
    OR TRIM(COALESCE(s.category, '')) = ''
    OR LOWER(TRIM(COALESCE(s.category, ''))) = 'hostel'
)
AND NOT EXISTS (
    SELECT 1 FROM v_room_grid vg
    WHERE vg.room_name = s.room_no AND vg.bed_letter = s.bed_no
)
`;
    let sql2 = `
SELECT uid, sname FROM studentdetails
WHERE (category = 'Hostel' OR category IS NULL OR TRIM(COALESCE(category, '')) = '')
`;

    let params = [];
    if (term) {
      sql1 += ` AND (s.uid LIKE ? OR s.sname LIKE ?)`;
      sql2 += ` AND (uid LIKE ? OR sname LIKE ?)`;
      params = [`%${term}%`, `%${term}%`];
    }
    sql1 += ` ORDER BY s.sname ASC LIMIT 200`;
    sql2 += ` ORDER BY sname ASC LIMIT 200`;

    connection.query(sql1, params, function (err, result) {
      if (err) {
        // Fallback SQL
        connection.query(sql2, params, function (err2, result2) {
          connection.release();
          if (err2) return res.json({ success: false, data: [] });
          res.json({ success: true, data: result2 });
        });
      } else {
        connection.release();
        res.json({ success: true, data: result });
      }
    });
  });
});

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// MOBILE STUDENT LIST APIS
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/mobile/v1/students', verifyMobileJwt, function (req, res) {
  const role = req.decode.role;
  let sql = "";
  if (role === "BoysHostelAdmin") {
    sql = "SELECT uid, sname as name, department, category, gender FROM studentdetails WHERE gender='MALE'";
  } else if (role === "GirlsHostelAdmin") {
    sql = "SELECT uid, sname as name, department, category, gender FROM studentdetails WHERE gender='FEMALE'";
  } else if (role === "SuperID") {
    sql = "SELECT uid, sname as name, department, category, gender FROM studentdetails";
  } else {
    return res.json({ success: true, data: [] });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });
    connection.query(sql, function (err, results) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });
      res.json({ success: true, data: results });
    });
  });
});

app.get('/api/mobile/v1/students/hostel', verifyMobileJwt, function (req, res) {
  const role = req.decode.role;
  let sql = "";

  const inCampusSubquery = "NOT EXISTS (SELECT 1 FROM log_details1 l WHERE l.uid = studentdetails.uid AND (LOWER(l.status) = 'active' OR (l.passtype IS NOT NULL AND l.hostelintime IS NULL))) as inCampus";

  if (role === "BoysHostelAdmin") {
    sql = `SELECT uid, sname as name, room_no, bed_no, block, status, gender, path, ${inCampusSubquery} FROM studentdetails WHERE gender='MALE' AND category='Hostel'`;
  } else if (role === "GirlsHostelAdmin") {
    sql = `SELECT uid, sname as name, room_no, bed_no, block, status, gender, path, ${inCampusSubquery} FROM studentdetails WHERE gender='FEMALE' AND category='Hostel'`;
  } else if (role === "SuperID") {
    sql = `SELECT uid, sname as name, room_no, bed_no, block, status, gender, path, ${inCampusSubquery} FROM studentdetails WHERE category='Hostel'`;
  } else {
    return res.json({ success: true, data: [] });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });
    connection.query(sql, function (err, results) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });
      (results || []).forEach(attachStudentPhotoUrl);
      res.json({ success: true, data: results });
    });
  });
});

app.get('/api/mobile/v1/complaints', verifyMobileJwt, function (req, res) {
  const role = req.decode.role;
  const statusFilter = req.query.status || 'pending_approval';

  let genderFilter = '';
  if (role === 'BoysHostelAdmin') genderFilter = ' AND s.gender = "MALE" ';
  if (role === 'GirlsHostelAdmin') genderFilter = ' AND s.gender = "FEMALE" ';

  const baseWhere = (role === 'SuperID')
    ? ' WHERE c.status = ? '
    : ' WHERE c.status = ? AND c.student_uid IS NOT NULL ';

  const sql = `
    SELECT c.id, c.status, c.timestamp as date, s.sname as student, s.room_no as room 
    FROM complaints c 
    LEFT JOIN studentdetails s ON c.student_uid = s.uid 
    ${baseWhere} ${genderFilter}
    ORDER BY c.timestamp DESC
  `;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });
    connection.query(sql, [statusFilter], function (err, results) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });

      const mapped = results.map(row => ({
        id: String(row.id),
        student: row.student || 'Unknown Student',
        room: row.room || 'N/A',
        date: row.date ? new Date(row.date).toLocaleDateString() : 'Unknown Date',
        status: row.status,
        resolved: row.status === 'resolved' || row.status === 'approved'
      }));

      res.json({ success: true, data: mapped });
    });
  });
});

app.post('/api/mobile/v1/students/restrict', verifyMobileJwt, function (req, res) {
  const { uid, action } = req.body;

  if (!uid || !['Restrict', 'Unrestrict'].includes(action)) {
    return res.status(400).json({ success: false, error: 'Invalid parameters' });
  }

  const sql = "UPDATE studentdetails SET status = ? WHERE uid = ?";
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });
    connection.query(sql, [action, uid], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });
      res.json({ success: true, message: `Student successfully ${action.toLowerCase()}ed` });
    });
  });
});

app.get('/api/mobile/v1/students/profile/:uid', verifyMobileJwt, function (req, res) {
  const uid = req.params.uid;
  const sql = "SELECT * FROM studentdetails WHERE uid = ?";
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });
    connection.query(sql, [uid], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });
      if (result.length === 0) return res.status(404).json({ success: false, error: 'Student not found' });
      res.json({ success: true, data: result[0] });
    });
  });
});

app.get('/api/mobile/v1/students/passes/summary/:uid', verifyMobileJwt, function (req, res) {
  var uid = req.params.uid;
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var passDataSql = `
      SELECT MONTH(approvaldt) AS m, passtype, DATE_FORMAT(approvaldt, '%a, %b %e, %Y') AS formatted_date, approvaldt
      FROM log_details1
      WHERE uid = ? AND passtype IS NOT NULL AND approvaldt IS NOT NULL
        AND YEAR(approvaldt) = YEAR(CURDATE())
      ORDER BY MONTH(approvaldt), approvaldt`;

    connection.query(passDataSql, [uid], function (pErr, rows) {
      if (pErr) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Failed to fetch pass data' });
      }

      var monthlyPassData = {};
      var monthNames = ['January', 'February', 'March', 'April', 'May', 'June',
        'July', 'August', 'September', 'October', 'November', 'December'];

      monthNames.forEach(function (month) {
        monthlyPassData[month] = {
          'City Pass': { count: 0, dates: [] },
          'Home Pass': { count: 0, dates: [] },
          'Sick Leave': { count: 0, dates: [] }
        };
      });

      if (rows && rows.length > 0) {
        rows.forEach(function (r) {
          var monthIndex = parseInt(r.m, 10) - 1;
          if (monthIndex >= 0 && monthIndex < 12) {
            var monthName = monthNames[monthIndex];
            var passType = (r.passtype || '').toString().trim();
            if (passType.toLowerCase() === 'city pass') {
              monthlyPassData[monthName]['City Pass'].count++;
              monthlyPassData[monthName]['City Pass'].dates.push(r.formatted_date);
            } else if (passType.toLowerCase() === 'home pass') {
              monthlyPassData[monthName]['Home Pass'].count++;
              monthlyPassData[monthName]['Home Pass'].dates.push(r.formatted_date);
            }
          }
        });
      }

      var sickLeaveDataSql = `
        SELECT MONTH(logdate) AS m, DATE_FORMAT(logdate, '%a, %b %e, %Y') AS formatted_date, logdate
        FROM sick_leave_logs
        WHERE uid = ? AND logdate IS NOT NULL
          AND YEAR(logdate) = YEAR(CURDATE())
        ORDER BY MONTH(logdate), logdate`;

      connection.query(sickLeaveDataSql, [uid], function (slErr, slRows) {
        connection.release();
        if (slErr) {
          return res.status(500).json({ success: false, error: 'Failed to fetch sick leave data' });
        }

        if (slRows && slRows.length > 0) {
          slRows.forEach(function (r) {
            var monthIndex = parseInt(r.m, 10) - 1;
            if (monthIndex >= 0 && monthIndex < 12) {
              var monthName = monthNames[monthIndex];
              monthlyPassData[monthName]['Sick Leave'].count++;
              monthlyPassData[monthName]['Sick Leave'].dates.push(r.formatted_date);
            }
          });
        }

        res.json({ success: true, data: monthlyPassData });
      });
    });
  });
});

app.put('/api/mobile/v1/students/profile/:uid', verifyMobileJwt, function (req, res) {
  const role = req.decode.role;
  if (!(role === 'SuperID' || role === 'BoysHostelAdmin' || role === 'GirlsHostelAdmin' || role === 'Hostelauthority')) {
    return res.status(403).json({ success: false, error: 'Unauthorised Access' });
  }

  const oldUid = String(req.params.uid || '').trim();
  const newUid = String(req.body.uid || oldUid).trim();

  const dept = req.body.dept;
  const academicyear = req.body.academicyear;
  const year = req.body.year;
  const category = req.body.category;
  const mobile = req.body.mobileno;
  const status = req.body.status;
  const gender = req.body.gender;
  const dob = req.body.dob;
  const address = req.body.address;
  const email = req.body.email;
  const ParentsName = req.body.parentname;
  const ParentsNumber = req.body.parentnumber;
  const block = req.body.block;
  const room_no = req.body.room_no;
  const bed_no = req.body.bed_no;
  const mess_type = req.body.mess_type;
  const newPassword = String(req.body.new_password || '').trim();

  if (!oldUid) {
    return res.status(400).json({ success: false, error: 'Invalid student UID' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database error' });
    }
    let responded = false;

    const finish = (msg, successFlag) => {
      if (responded) return;
      responded = true;
      connection.release();
      if (successFlag) {
        return res.json({ success: true, message: msg });
      } else {
        return res.status(500).json({ success: false, error: msg });
      }
    };

    const cascadeSqls = [
      { sql: 'UPDATE log_details1 SET uid = ? WHERE uid = ?', params: [newUid, oldUid] },
      { sql: 'UPDATE log_detail SET uid = ? WHERE uid = ?', params: [newUid, oldUid] },
      { sql: 'UPDATE complaints SET student_uid = ? WHERE student_uid = ?', params: [newUid, oldUid] },
      { sql: 'UPDATE pass_requests SET student_uid = ? WHERE student_uid = ?', params: [newUid, oldUid] }
    ];

    const executeUpdate = (hashedPassword) => {
      const fieldsConfig = [
        { field: 'uid', val: newUid },
        { field: 'email', val: email },
        { field: 'dept', val: dept },
        { field: 'address', val: address },
        { field: 'year', val: year },
        { field: 'category', val: category },
        { field: 'gender', val: gender },
        { field: 'mobileno', val: mobile },
        { field: 'dob', val: dob },
        { field: 'academicyear', val: academicyear },
        { field: 'status', val: status },
        { field: 'parentname', val: ParentsName },
        { field: 'parentnumber', val: ParentsNumber },
        { field: 'block', val: block },
        { field: 'room_no', val: room_no },
        { field: 'bed_no', val: bed_no },
        { field: 'mess_type', val: mess_type }
      ];

      const updateFields = [];
      const updateStudentParams = [];

      fieldsConfig.forEach(item => {
        if (item.val !== undefined) {
          updateFields.push(`${item.field} = ?`);
          updateStudentParams.push(item.val);
        }
      });

      if (hashedPassword) {
        updateFields.push('password = ?');
        updateStudentParams.push(hashedPassword);
      }

      updateStudentParams.push(oldUid);
      const updateStudentSql = `UPDATE studentdetails SET ${updateFields.join(', ')} WHERE uid = ?`;

      const runUpdateQuery = () => {
        if (newUid === oldUid) {
          return connection.query(updateStudentSql, updateStudentParams, function (uErr) {
            if (uErr) {
              console.error('API updatestudent failed:', uErr);
              return finish('Could not update student profile', false);
            }
            return finish('Updated Successfully', true);
          });
        }

        connection.beginTransaction(function (tErr) {
          if (tErr) return finish('Could not update student profile', false);

          connection.query(updateStudentSql, updateStudentParams, function (uErr) {
            if (uErr) {
              return connection.rollback(function () {
                return finish('Could not update student profile', false);
              });
            }

            const runCascade = (idx) => {
              if (idx >= cascadeSqls.length) {
                return connection.commit(function (cErr) {
                  if (cErr) {
                    return connection.rollback(function () {
                      return finish('Could not update student profile', false);
                    });
                  }
                  return finish('Updated Successfully', true);
                });
              }

              const item = cascadeSqls[idx];
              connection.query(item.sql, item.params, function (cErr) {
                if (cErr) {
                  return connection.rollback(function () {
                    return finish('Could not update student profile', false);
                  });
                }
                return runCascade(idx + 1);
              });
            };

            return runCascade(0);
          });
        });
      };

      return runUpdateQuery();
    };

    if (newPassword.length > 0) {
      if (newPassword.length < 6) {
        return finish('Password must be at least 6 characters', false);
      }
      bcrypt.hash(newPassword, 12, function (hashErr, hashedPassword) {
        if (hashErr) return finish('Could not update student profile', false);
        executeUpdate(hashedPassword);
      });
    } else {
      executeUpdate(null);
    }
  });
});

// =====================================================
// MOBILE API â€” Hostel Out (currently out students)
// Mirrors web /outstudents + /instudents/:id + restrict
// =====================================================

// GET /api/mobile/v1/admin/hostelout
// Optional query: dateFrom, dateTo (YYYY-MM-DD) â€” filters by DATE(approvaldt)
app.get('/api/mobile/v1/admin/hostelout', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const dateFrom = (req.query.dateFrom || '').trim();
  const dateTo = (req.query.dateTo || '').trim();

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
  }

  let genderClause = '';
  if (role === 'BoysHostelAdmin') {
    genderClause = " AND stu.gender='MALE' ";
  } else if (role === 'GirlsHostelAdmin') {
    genderClause = " AND stu.gender='FEMALE' ";
  }

  let dateClause = '';
  const params = [];
  if (dateFrom && dateTo) {
    dateClause = ' AND DATE(log.approvaldt) BETWEEN DATE(?) AND DATE(?) ';
    params.push(dateFrom, dateTo);
  }

  const sql =
    "SELECT log.logid, stu.uid, stu.sname, stu.status, log.hostelintime, log.approvaldt, log.passtype " +
    "FROM log_details1 AS log " +
    "JOIN studentdetails AS stu ON stu.uid = log.uid " +
    "WHERE log.hostelintime IS NULL AND stu.category='Hostel' " +
    genderClause +
    dateClause +
    "ORDER BY log.logid DESC";

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }
    connection.query(sql, params, function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Failed to fetch hostel-out students' });
      }
      return res.json({ success: true, data: result || [] });
    });
  });
});

// POST /api/mobile/v1/admin/hostelout/takein/:logid
// Same logic as web GET /instudents/:id
app.post('/api/mobile/v1/admin/hostelout/takein/:logid', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const logid = req.params.logid;

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
  }

  if (!logid) {
    return res.status(400).json({ success: false, error: 'logid is required' });
  }

  const sql =
    "UPDATE log_details1 SET hostelintime = ?, status = 'DEAD' WHERE logid = ? AND hostelintime IS NULL";

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }
    checkHostelInRestriction(connection, logid, function (restrictErr, isRestricted) {
      if (restrictErr) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Error checking restriction' });
      }

      if (isRestricted) {
        connection.release();
        return res.status(400).json({ success: false, error: 'Restricted due to 10pm rule' });
      }

      connection.query(sql, [formatDateTimeForDB(currentdate()), logid], function (qErr, result) {
        connection.release();
        if (qErr) {
          return res.status(500).json({ success: false, error: 'Failed to mark Hostel IN' });
        }
        if (!result || result.affectedRows === 0) {
          return res.status(404).json({ success: false, error: 'Pass not found or already marked Hostel IN' });
        }
        return res.json({ success: true, message: 'Student marked Hostel IN successfully' });
      });
    });
  });
});

// =====================================================
// MOBILE API â€” Gate Out (students out through gate today)
// Mirrors web /Gateoutstudents + /gateout/:id + /Gateoutdaterange
// =====================================================

// GET /api/mobile/v1/admin/gateout
// Optional query: dateFrom, dateTo (YYYY-MM-DD) â€” filters by DATE(outdatetime)
// Without dates: defaults to today's outdatetime (IST), same as web /Gateoutstudents
app.get('/api/mobile/v1/admin/gateout', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const dateFrom = (req.query.dateFrom || '').trim();
  const dateTo = (req.query.dateTo || '').trim();

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
  }

  let genderClause = '';
  let categoryClause = '';
  if (role === 'BoysHostelAdmin') {
    genderClause = " AND stu.gender='MALE' ";
    categoryClause = " AND stu.category='Hostel' ";
  } else if (role === 'GirlsHostelAdmin') {
    genderClause = " AND stu.gender='FEMALE' ";
    categoryClause = " AND stu.category='Hostel' ";
  }

  let dateClause = '';
  const params = [];
  if (dateFrom && dateTo) {
    // Date-range mode: filter by gate-out timestamp (outdatetime)
    dateClause = ' AND DATE(log.outdatetime) BETWEEN DATE(?) AND DATE(?) ';
    params.push(dateFrom, dateTo);
    // Align with /Gateoutdaterange which always scopes Hostel for all roles
    if (role === 'SuperID') {
      categoryClause = " AND stu.category='Hostel' ";
    }
  } else {
    // Default: today's gate-outs (IST), same as /Gateoutstudents
    const todayISTDateOnly = formatDateToISTString(new Date()).slice(0, 10);
    dateClause = ' AND DATE(log.outdatetime) = DATE(?) ';
    params.push(todayISTDateOnly);
  }

  const sql =
    "SELECT log.logid, stu.uid, stu.sname, log.indatetime, log.outdatetime, log.passtype " +
    "FROM log_details1 AS log " +
    "JOIN studentdetails AS stu ON stu.uid = log.uid " +
    "WHERE log.indatetime IS NULL AND log.outdatetime IS NOT NULL " +
    genderClause +
    categoryClause +
    dateClause +
    "ORDER BY log.logid DESC";

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }
    connection.query(sql, params, function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Failed to fetch gate-out students' });
      }
      return res.json({ success: true, data: result || [] });
    });
  });
});

// POST /api/mobile/v1/admin/gateout/takein/:logid
// Same logic as web GET /gateout/:id
app.post('/api/mobile/v1/admin/gateout/takein/:logid', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const logid = req.params.logid;

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
  }

  if (!logid) {
    return res.status(400).json({ success: false, error: 'logid is required' });
  }

  const sql =
    "UPDATE log_details1 SET indatetime = ? WHERE logid = ? AND indatetime IS NULL AND outdatetime IS NOT NULL";

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }
    connection.query(sql, [formatDateTimeForDB(currentdate()), logid], function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Failed to mark GATE IN' });
      }
      if (!result || result.affectedRows === 0) {
        return res.status(404).json({ success: false, error: 'Pass not found or already marked GATE IN' });
      }
      return res.json({ success: true, message: 'Student marked GATE IN successfully' });
    });
  });
});

// =====================================================
// MOBILE API â€” Hostel Monitoring (Reports dashboard)
// Mirrors web /reports + /datastatus
// =====================================================

// GET /api/mobile/v1/admin/hostel-monitoring
app.get('/api/mobile/v1/admin/hostel-monitoring', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin', 'Hostelauthority'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
  }

  let genderClause = '';
  let genderAnd = '';
  if (role === 'BoysHostelAdmin' || role === 'Hostelauthority') {
    genderClause = " AND gender='MALE' ";
    genderAnd = " AND stu.gender='MALE' ";
  } else if (role === 'GirlsHostelAdmin') {
    genderClause = " AND gender='FEMALE' ";
    genderAnd = " AND stu.gender='FEMALE' ";
  }

  const sql = `
    SELECT
      (SELECT COUNT(*) FROM studentdetails WHERE category='Hostel' ${genderClause}) AS totalStudents,
      (SELECT COUNT(*) FROM log_details1 AS log
         JOIN studentdetails AS stu ON stu.uid = log.uid
         WHERE log.indatetime IS NOT NULL AND stu.category='Hostel' ${genderAnd}) AS insideHostel,
      (SELECT COUNT(*) FROM log_details1 AS log
         JOIN studentdetails AS stu ON stu.uid = log.uid
         WHERE log.indatetime IS NULL AND log.outdatetime IS NOT NULL
           AND stu.category='Hostel' ${genderAnd}) AS gateOut,
      (SELECT COUNT(*) FROM log_details1 AS log
         JOIN studentdetails AS stu ON stu.uid = log.uid
         WHERE log.hostelintime IS NULL AND stu.category='Hostel' ${genderAnd}) AS hostelOut,
      (SELECT COUNT(*) FROM log_details1 AS log
         JOIN studentdetails AS stu ON stu.uid = log.uid
         WHERE log.passtype='City Pass' AND log.hostelintime IS NULL
           AND stu.category='Hostel' ${genderAnd}) AS cityPass,
      (SELECT COUNT(*) FROM log_details1 AS log
         JOIN studentdetails AS stu ON stu.uid = log.uid
         WHERE log.passtype='Home Pass' AND log.hostelintime IS NULL
           AND stu.category='Hostel' ${genderAnd}) AS homePass,
      (SELECT COUNT(*) FROM log_details1 AS log
         JOIN studentdetails AS stu ON stu.uid = log.uid
         WHERE stu.mess_type='Veg' AND log.hostelintime IS NULL
           AND stu.category='Hostel' ${genderAnd}) AS vegOut,
      (SELECT COUNT(*) FROM log_details1 AS log
         JOIN studentdetails AS stu ON stu.uid = log.uid
         WHERE stu.mess_type='Non-Veg' AND log.hostelintime IS NULL
           AND stu.category='Hostel' ${genderAnd}) AS nonVegOut,
      (SELECT COUNT(*) FROM studentdetails
         WHERE mess_type='Veg' AND category='Hostel' ${genderClause}) AS totalVeg,
      (SELECT COUNT(*) FROM studentdetails
         WHERE mess_type='Non-Veg' AND category='Hostel' ${genderClause}) AS totalNonVeg,
      (SELECT COUNT(*) FROM studentdetails
         WHERE status='Restrict' AND category='Hostel' ${genderClause}) AS restrictCount,
      (SELECT COUNT(*) FROM studentdetails
         WHERE status='Unrestrict' AND category='Hostel' ${genderClause}) AS unrestrictCount
  `;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }
    connection.query(sql, function (qErr, rows) {
      connection.release();
      if (qErr || !rows || !rows[0]) {
        return res.status(500).json({ success: false, error: 'Failed to fetch hostel monitoring data' });
      }

      const r = rows[0];
      const totalVeg = Number(r.totalVeg || 0);
      const totalNonVeg = Number(r.totalNonVeg || 0);
      const vegOut = Number(r.vegOut || 0);
      const nonVegOut = Number(r.nonVegOut || 0);
      // Match web reports.ejs: "Veg Count" / "Non-Veg Count" = present (total âˆ’ out)
      const vegCount = Math.max(0, totalVeg - vegOut);
      const nonVegCount = Math.max(0, totalNonVeg - nonVegOut);

      return res.json({
        success: true,
        data: {
          totalStudents: Number(r.totalStudents || 0),
          insideHostel: Number(r.insideHostel || 0),
          gateOut: Number(r.gateOut || 0),
          hostelOut: Number(r.hostelOut || 0),
          vegOut: vegOut,
          nonVegOut: nonVegOut,
          cityPass: Number(r.cityPass || 0),
          homePass: Number(r.homePass || 0),
          vegCount: vegCount,
          nonVegCount: nonVegCount,
          blockedStatus: {
            restrict: Number(r.restrictCount || 0),
            unrestrict: Number(r.unrestrictCount || 0)
          }
        }
      });
    });
  });
});

// =====================================================
// MOBILE API â€” Global Analytics (Hostel Analytics dashboard)
// Mirrors web /analytics/global + today's Home/City pass counts
// =====================================================

// GET /api/mobile/v1/admin/global-analytics
app.get('/api/mobile/v1/admin/global-analytics', verifyMobileJwt, async function (req, res) {
  const role = req.decode && req.decode.role;

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin', 'Hostelauthority'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
  }

  dbbconnection.getConnection(async (err, connection) => {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    const queryAsync = (sql, args) => new Promise((resolve, reject) => {
      connection.query(sql, args, (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });

    try {
      let sql = "Select count(*) as totalstudent from studentdetails where category='Hostel'";
      let sql2 = "SELECT count(*) as insidehostel FROM log_details1 AS log JOIN studentdetails AS stu ON stu.uid = log.uid WHERE log.indatetime IS NOT NULL and stu.category='Hostel'";
      let sql3 = "select count(*) as gateout from log_details1 as log join studentdetails as stu on stu.uid=log.uid where outdatetime IS NOT NULL and DATE(outdatetime) = CURDATE() and stu.category='Hostel'";
      let sql4 = "select count(*) as hostelout from log_details1 as log join studentdetails as stu on stu.uid=log.uid where DATE(COALESCE(approvaldt, outdatetime)) = CURDATE() and stu.category='Hostel'";
      let sql5 = "select count(*) as citypass from log_details1 as log join studentdetails as stu where stu.uid=log.uid and passtype='City Pass' and outdatetime IS NOT NULL and DATE(outdatetime) = CURDATE() and stu.category='Hostel'";
      let sql6 = "select count(*) as homepass from log_details1 as log join studentdetails as stu where stu.uid=log.uid and passtype='Home Pass' and outdatetime IS NOT NULL and DATE(outdatetime) = CURDATE() and stu.category='Hostel'";
      let sql7 = "select count(DISTINCT log.uid) as vegOut from log_details1 as log join studentdetails as stu on stu.uid=log.uid where stu.mess_type='Veg' and outdatetime IS NOT NULL and hostelintime IS NULL and log.status='ACTIVE' and stu.category='Hostel'";
      let sql8 = "select count(DISTINCT log.uid) as nonVegOut from log_details1 as log join studentdetails as stu on stu.uid=log.uid where stu.mess_type='Non-Veg' and outdatetime IS NOT NULL and hostelintime IS NULL and log.status='ACTIVE' and stu.category='Hostel'";
      let sql9 = "select count(*) as reqHomePass from pass_requests as pr join studentdetails as stu on pr.uid=stu.uid where pr.passtype='Home Pass' and pr.status='approved' and DATE(pr.approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) and stu.category='Hostel'";
      let sql10 = "select count(*) as reqCityPass from pass_requests as pr join studentdetails as stu on pr.uid=stu.uid where pr.passtype='City Pass' and pr.status='approved' and DATE(pr.approved_at) = DATE(CONVERT_TZ(NOW(), '+00:00', '+05:30')) and stu.category='Hostel'";
      let sql11 = "select count(DISTINCT log.uid) as currentlyOut from log_details1 as log join studentdetails as stu on stu.uid=log.uid where log.outdatetime IS NOT NULL and log.hostelintime IS NULL and log.status='ACTIVE' and stu.category='Hostel'";
      let totalVegSql = "SELECT COUNT(*) as count FROM studentdetails WHERE mess_type='Veg' AND category='Hostel'";
      let totalNonVegSql = "SELECT COUNT(*) as count FROM studentdetails WHERE mess_type='Non-Veg' AND category='Hostel'";
      let sqlStatus = "select CASE WHEN status = 'Restrict' THEN 'Restrict' ELSE 'Unrestrict' END as status, count(*) as count from studentdetails where category='Hostel'";

      let sqlAttendance = `
        SELECT 
            COUNT(s.uid) as Total,
            SUM(CASE WHEN d.status = 'Present' THEN 1 ELSE 0 END) as Present,
            SUM(CASE WHEN d.status = 'Absent' THEN 1 ELSE 0 END) as Absent,
            SUM(CASE WHEN d.status = 'Home' THEN 1 ELSE 0 END) as Home
        FROM studentdetails s
        LEFT JOIN daily_attendance d ON s.uid = d.uid AND d.date = CURDATE()
        WHERE s.category='Hostel'`;

      let sqlMess = "SELECT mess_type, COUNT(*) as count FROM studentdetails WHERE category='Hostel'";
      let sqlBlock = "SELECT block, COUNT(*) as count FROM studentdetails WHERE category='Hostel'";
      let sqlYear = "SELECT year, COUNT(*) as count FROM studentdetails WHERE category='Hostel'";

      if (role == "BoysHostelAdmin" || role == "Hostelauthority") {
          sql += " and gender='MALE'";
          sql2 += " and stu.gender='MALE'";
          sql3 += " and stu.gender='MALE'";
          sql4 += " and stu.gender='MALE'";
          sql5 += " and stu.gender='MALE'";
          sql6 += " and stu.gender='MALE'";
          sql7 += " and stu.gender='MALE'";
          sql8 += " and stu.gender='MALE'";
          sql9 += " and stu.gender='MALE'";
          sql10 += " and stu.gender='MALE'";
          sql11 += " and stu.gender='MALE'";
          totalVegSql += " AND gender='MALE'";
          totalNonVegSql += " AND gender='MALE'";
          sqlStatus += " AND gender='MALE'";
          sqlAttendance += " AND s.gender='MALE'";
          sqlMess += " AND gender='MALE'";
          sqlBlock += " AND gender='MALE'";
          sqlYear += " AND gender='MALE'";
      } else if (role == "GirlsHostelAdmin") {
          sql += " and gender='FEMALE'";
          sql2 += " and stu.gender='FEMALE'";
          sql3 += " and stu.gender='FEMALE'";
          sql4 += " and stu.gender='FEMALE'";
          sql5 += " and stu.gender='FEMALE'";
          sql6 += " and stu.gender='FEMALE'";
          sql7 += " and stu.gender='FEMALE'";
          sql8 += " and stu.gender='FEMALE'";
          sql9 += " and stu.gender='FEMALE'";
          sql10 += " and stu.gender='FEMALE'";
          sql11 += " and stu.gender='FEMALE'";
          totalVegSql += " AND gender='FEMALE'";
          totalNonVegSql += " AND gender='FEMALE'";
          sqlStatus += " AND gender='FEMALE'";
          sqlAttendance += " AND s.gender='FEMALE'";
          sqlMess += " AND gender='FEMALE'";
          sqlBlock += " AND gender='FEMALE'";
          sqlYear += " AND gender='FEMALE'";
      }

      sqlStatus += " group by CASE WHEN status = 'Restrict' THEN 'Restrict' ELSE 'Unrestrict' END";
      sqlMess += " GROUP BY mess_type";
      sqlBlock += " GROUP BY block ORDER BY block ASC";
      sqlYear += " GROUP BY year ORDER BY year ASC";

      const [rTotal, rInside, rGateOut, rHostelOut, rCityPass, rHomePass, rVegOut, rNonVegOut, rTotalVeg, rTotalNonVeg, rReqHome, rReqCity, rCurrentlyOut, resAttendance, resMess, resBlock, resYear, resStatus] = await Promise.all([
          queryAsync(sql), queryAsync(sql2), queryAsync(sql3), queryAsync(sql4), queryAsync(sql5), 
          queryAsync(sql6), queryAsync(sql7), queryAsync(sql8), queryAsync(totalVegSql), queryAsync(totalNonVegSql),
          queryAsync(sql9), queryAsync(sql10), queryAsync(sql11), queryAsync(sqlAttendance), queryAsync(sqlMess), queryAsync(sqlBlock), queryAsync(sqlYear), queryAsync(sqlStatus)
      ]);

      connection.release();

      const currentlyOut = rCurrentlyOut[0]?.currentlyOut || 0;
      const reportsResult = {
          totalStudents: rTotal[0]?.totalstudent || 0,
          insideHostel: rInside[0]?.insidehostel || 0,
          gateOut: rGateOut[0]?.gateout || 0,
          hostelOut: rHostelOut[0]?.hostelout || 0,
          citypass: rCityPass[0]?.citypass || 0,
          homepass: rHomePass[0]?.homepass || 0,
          vegOut: rVegOut[0]?.vegOut || 0,
          nonVegOut: rNonVegOut[0]?.nonVegOut || 0,
          reqHomePass: rReqHome[0]?.reqHomePass || 0,
          reqCityPass: rReqCity[0]?.reqCityPass || 0,
          currentlyOut: currentlyOut
      };

      const totalVeg = rTotalVeg[0]?.count || 0;
      const totalNonVeg = rTotalNonVeg[0]?.count || 0;
      const vegPresent = Math.max(0, totalVeg - (reportsResult.vegOut || 0));
      const nonVegPresent = Math.max(0, totalNonVeg - (reportsResult.nonVegOut || 0));
      reportsResult.totalPresent = vegPresent + nonVegPresent;
      reportsResult.vegPresent = vegPresent;
      reportsResult.nonVegPresent = nonVegPresent;

      let veg = 0;
      let nonVeg = 0;
      (resMess || []).forEach(item => {
        const mType = String(item.mess_type || '').toLowerCase().trim();
        const cnt = Number(item.count || 0);
        if (mType.indexOf('non') !== -1) nonVeg += cnt;
        else if (mType.indexOf('veg') !== -1) veg += cnt;
      });

      const yearBreakdown = (resYear || []).map(row => ({
        year: row.year == null || row.year === '' ? 'N/A' : String(row.year),
        count: Number(row.count || 0)
      }));

      const statusBreakdown = {
        restricted: 0,
        unrestricted: 0
      };
      (resStatus || []).forEach(item => {
        if (String(item.status || '').toLowerCase() === 'restrict') {
          statusBreakdown.restricted += Number(item.count || 0);
        } else if (String(item.status || '').toLowerCase() === 'unrestrict') {
          statusBreakdown.unrestricted += Number(item.count || 0);
        }
      });

      return res.json({
        success: true,
        data: {
          hostelReport: reportsResult,
          todayOverview: {
            totalStudents: reportsResult.totalStudents,
            todayHomePass: reportsResult.homepass,
            todayCityPass: reportsResult.citypass
          },
          requestedToday: {
            reqHomePass: reportsResult.reqHomePass,
            reqCityPass: reportsResult.reqCityPass
          },
          mess: {
            veg: veg,
            nonVeg: nonVeg
          },
          yearBreakdown: yearBreakdown,
          statusBreakdown: statusBreakdown,
          attendance: resAttendance[0] || { Total: 0, Present: 0, Absent: 0, Home: 0 },
          blockBreakdown: resBlock || []
        }
      });

    } catch (dbErr) {
      connection.release();
      console.error('[Mobile API] /global-analytics err:', dbErr);
      return res.status(500).json({ success: false, error: 'Database query failed' });
    }
  });
});

// =====================================================
// MOBILE API â€” Verify Complaints
// Mirrors web /admin/verify-complaints + approve/deny + complain-to-technician
// =====================================================

// GET /api/mobile/v1/admin/verify-complaints
// Optional query: status = pending_approval|approved|resolved|denied|all
app.get('/api/mobile/v1/admin/verify-complaints', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const statusFilter = String(req.query.status || 'all').trim().toLowerCase();

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized: access denied' });
  }

  let genderFilter = '';
  if (role === 'BoysHostelAdmin') genderFilter = ' AND s.gender = "MALE" ';
  if (role === 'GirlsHostelAdmin') genderFilter = ' AND s.gender = "FEMALE" ';

  const allowedStatuses = ['pending_approval', 'approved', 'resolved', 'denied'];
  let statusClause = ' c.status IN ("pending_approval", "approved", "resolved", "denied") ';
  const params = [];
  if (statusFilter !== 'all' && allowedStatuses.includes(statusFilter)) {
    statusClause = ' c.status = ? ';
    params.push(statusFilter);
  }

  const baseWhere = (role === 'SuperID')
    ? ' WHERE ' + statusClause
    : ' WHERE ' + statusClause + ' AND c.student_uid IS NOT NULL ';

  const sql =
    'SELECT c.id, c.student_uid, c.admin_name, c.description, c.category, c.image_path, c.status, c.timestamp, ' +
    's.sname, s.mobileno, s.room_no ' +
    'FROM complaints c LEFT JOIN studentdetails s ON c.student_uid = s.uid' +
    baseWhere + genderFilter + ' ORDER BY c.timestamp DESC';

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }
    connection.query(sql, params, function (qErr, results) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Failed to fetch complaints' });
      }

      const data = (results || []).map(function (row) {
        return {
          id: String(row.id),
          studentUid: row.student_uid || null,
          adminName: row.admin_name || null,
          studentName: row.sname || (row.admin_name ? ('Admin: ' + row.admin_name) : 'Unknown'),
          phone: row.mobileno || null,
          roomNo: row.room_no || null,
          category: row.category || 'Other',
          description: row.description || '',
          imagePath: row.image_path || null,
          status: row.status || 'pending_approval',
          submittedAt: row.timestamp || null
        };
      });

      return res.json({ success: true, data: data });
    });
  });
});

// POST /api/mobile/v1/admin/verify-complaints/:id/approve
app.post('/api/mobile/v1/admin/verify-complaints/:id/approve', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const id = req.params.id;

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }
  if (!id) {
    return res.status(400).json({ success: false, error: 'Complaint id is required' });
  }

  let sql = 'UPDATE complaints SET status = "approved" WHERE id = ?';
  const params = [id];
  if (role === 'BoysHostelAdmin') {
    sql = 'UPDATE complaints c JOIN studentdetails s ON c.student_uid = s.uid SET c.status = "approved" WHERE c.id = ? AND s.gender = "MALE"';
  } else if (role === 'GirlsHostelAdmin') {
    sql = 'UPDATE complaints c JOIN studentdetails s ON c.student_uid = s.uid SET c.status = "approved" WHERE c.id = ? AND s.gender = "FEMALE"';
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }
    connection.query(sql, params, function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Error approving complaint' });
      }
      if (role !== 'SuperID' && (!result || result.affectedRows === 0)) {
        return res.status(403).json({ success: false, error: 'Unauthorised or complaint not found' });
      }
      return res.json({ success: true, message: 'Complaint approved' });
    });
  });
});

// POST /api/mobile/v1/admin/verify-complaints/:id/deny
app.post('/api/mobile/v1/admin/verify-complaints/:id/deny', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  const id = req.params.id;

  if (!['SuperID', 'BoysHostelAdmin', 'GirlsHostelAdmin'].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized' });
  }
  if (!id) {
    return res.status(400).json({ success: false, error: 'Complaint id is required' });
  }

  let sql = 'UPDATE complaints SET status = "denied" WHERE id = ?';
  const params = [id];
  if (role === 'BoysHostelAdmin') {
    sql = 'UPDATE complaints c JOIN studentdetails s ON c.student_uid = s.uid SET c.status = "denied" WHERE c.id = ? AND s.gender = "MALE"';
  } else if (role === 'GirlsHostelAdmin') {
    sql = 'UPDATE complaints c JOIN studentdetails s ON c.student_uid = s.uid SET c.status = "denied" WHERE c.id = ? AND s.gender = "FEMALE"';
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }
    connection.query(sql, params, function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Error denying complaint' });
      }
      if (role !== 'SuperID' && (!result || result.affectedRows === 0)) {
        return res.status(403).json({ success: false, error: 'Unauthorised or complaint not found' });
      }
      return res.json({ success: true, message: 'Complaint denied' });
    });
  });
});

// POST /api/mobile/v1/admin/verify-complaints/to-technician
// SuperID only â€” multipart field: complain_image (optional)
app.post('/api/mobile/v1/admin/verify-complaints/to-technician', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  if (role !== 'SuperID') {
    return res.status(403).json({ success: false, error: 'Unauthorized: SuperID only' });
  }

  uploadComplainImage.single('complain_image')(req, res, function (uploadErr) {
    if (uploadErr) {
      return res.status(400).json({ success: false, error: uploadErr.message || 'Invalid file' });
    }

    const category = String((req.body && req.body.category) || '').trim();
    const description = String((req.body && req.body.description) || '').trim();
    if (!category || !description) {
      return res.status(400).json({ success: false, error: 'Category and description are required' });
    }

    const imagePath = req.file ? '/uploads/complaints/' + req.file.filename : null;
    const adminName = (req.decode && req.decode.adminname) ? req.decode.adminname : 'Admin';

    dbbconnection.getConnection(function (err, connection) {
      if (err) {
        return res.status(500).json({ success: false, error: 'Database connection error' });
      }
      const sql = 'INSERT INTO complaints (student_uid, admin_name, description, category, image_path, status) VALUES (?, ?, ?, ?, ?, ?)';
      connection.query(sql, [null, adminName, description, category, imagePath, 'approved'], function (qErr) {
        connection.release();
        if (qErr) {
          return res.status(500).json({ success: false, error: 'Error saving complaint' });
        }
        return res.json({ success: true, message: 'Complaint sent to technician' });
      });
    });
  });
});

// =====================================================
// MOBILE API - Announcements
// =====================================================
app.get('/api/mobile/v1/admin/announcements', verifyMobileJwt, function (req, res) {
  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    const sql = "SELECT * FROM announcements WHERE is_active = 1 ORDER BY created_at DESC LIMIT 50";
    connection.query(sql, function (err, results) {
      connection.release();
      if (err) {
        return res.status(500).json({ success: false, error: 'Error fetching announcements' });
      }
      return res.json({ success: true, data: results || [] });
    });
  });
});

app.post('/api/mobile/v1/admin/announcements', express.json(), verifyMobileJwt, function (req, res) {
  const { title, description, target_year } = req.body;
  const adminName = (req.decode && req.decode.adminuid) ? req.decode.adminuid : 'Admin';

  if (!title || !description) {
    return res.status(400).json({ success: false, error: 'Title and description are required' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    const sql = "INSERT INTO announcements (title, description, target_year, created_by) VALUES (?, ?, ?, ?)";
    connection.query(sql, [title, description, target_year || 'all', adminName], function (err, result) {
      connection.release();
      if (err) {
        console.error('Error creating announcement:', err);
        return res.status(500).json({ success: false, error: 'Error creating announcement' });
      }
      return res.json({ success: true, message: 'Announcement sent successfully!' });
    });
  });
});

app.post('/api/mobile/v1/admin/announcements/delete/:id', verifyMobileJwt, function (req, res) {
  const announcementId = req.params.id;

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error' });
    }

    const sql = "UPDATE announcements SET is_active = 0 WHERE id = ?";
    connection.query(sql, [announcementId], function (err, result) {
      connection.release();
      if (err) {
        return res.status(500).json({ success: false, error: 'Error deleting announcement' });
      }
      return res.json({ success: true, message: 'Announcement deleted successfully' });
    });
  });
});


// =====================================================
// MOBILE API: GET /api/mobile/v1/admin/emergency-requests
// =====================================================
app.get('/api/mobile/v1/admin/emergency-requests', verifyMobileJwt, function(req, res) {
  const role = req.decode && req.decode.role;
  if (!["SuperID", "BoysHostelAdmin"].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized access' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed' });

    let sql = "SELECT uid, sname, emergency_pass_enabled FROM studentdetails WHERE category = 'Hostel'";
    connection.query(sql, function (err, students) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to fetch students' });
      res.json({ success: true, students: students || [] });
    });
  });
});

// =====================================================
// MOBILE API: POST /api/mobile/v1/admin/emergency-requests/toggle/:uid
// =====================================================
app.post('/api/mobile/v1/admin/emergency-requests/toggle/:uid', express.json(), verifyMobileJwt, function(req, res) {
  const role = req.decode && req.decode.role;
  if (!["SuperID", "BoysHostelAdmin"].includes(role)) {
    return res.status(403).json({ success: false, error: 'Unauthorized access' });
  }

  const uid = req.params.uid;
  const enable = req.body.enable ? 1 : 0;
  const adminuid = enable ? (req.decode.adminuid || req.decode.uid || req.decode.email) : null;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed' });

    connection.query("UPDATE studentdetails SET emergency_pass_enabled = ?, emergency_pass_enabled_by = ? WHERE uid = ?", [enable, adminuid, uid], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Failed to update emergency pass status' });
      res.json({ success: true, message: enable ? 'Emergency pass enabled for ' + uid : 'Emergency pass disabled for ' + uid });
    });
  });
});

// =====================================================
// MOBILE API: GET /api/mobile/v1/admin/bonafide-requests
// Returns: { requests: [], stats: {}, pagination: {}, filters: {} }
// Query params: tab (today|all), q, status, academic_year, page
// =====================================================
app.get('/api/mobile/v1/admin/bonafide-requests', verifyMobileJwt, function (req, res) {
  const { q, status, academic_year } = req.query;
  const tab = req.query.tab === 'all' ? 'all' : 'today';
  const page = parseInt(req.query.page, 10) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const todayIstDate = (formatDateToISTString(new Date()) || '').slice(0, 10);

  let where = '1=1';
  const params = [];

  if (q) {
    where += ' AND (br.student_name LIKE ? OR br.student_uid LIKE ?)';
    params.push('%' + q + '%', '%' + q + '%');
  }
  if (status && ['Pending', 'Approved', 'Rejected', 'Printed', 'Collected'].includes(status)) {
    where += ' AND br.status = ?';
    params.push(status);
  }
  if (academic_year) {
    where += ' AND br.academic_year = ?';
    params.push(academic_year);
  }

  if (tab === 'today') {
    const istStart = new Date(`${todayIstDate}T00:00:00+05:30`);
    const utcStart = istStart.toISOString().slice(0, 19).replace('T', ' ');
    const utcEnd = new Date(istStart.getTime() + (24 * 60 * 60 * 1000))
      .toISOString()
      .slice(0, 19)
      .replace('T', ' ');
    where += ' AND br.request_date >= ? AND br.request_date < ?';
    params.push(utcStart, utcEnd);
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    const countSql = `SELECT COUNT(*) AS total FROM bonafide_requests br WHERE ${where}`;
    conn.query(countSql, params, function (eCount, countRows) {
      if (eCount) { conn.release(); return res.status(500).json({ success: false, error: 'Count query failed.' }); }

      const total = countRows[0].total;
      const totalPages = Math.ceil(total / limit) || 1;
      const listSql = `SELECT * FROM bonafide_requests br WHERE ${where} ORDER BY br.request_date DESC LIMIT ? OFFSET ?`;
      const listParams = [...params, limit, offset];

      conn.query(listSql, listParams, function (e, requests) {
        if (e) { conn.release(); return res.status(500).json({ success: false, error: 'List query failed.' }); }
        if (requests) {
          requests.forEach(function (r) {
            r.branch = formatBranchForBonafide(r.branch);
          });
        }

        const statsSql = `
          SELECT
            SUM(status='Pending')   AS pending,
            SUM(status='Approved')  AS approved,
            SUM(status='Printed')   AS printed,
            SUM(status='Collected') AS collected,
            SUM(status='Rejected')  AS rejected
          FROM bonafide_requests`;
        conn.query(statsSql, function (e2, statsRows) {
          conn.release();
          const stats = (statsRows && statsRows[0]) || {};
          return res.json({
            success: true,
            requests: requests || [],
            stats: stats,
            filters: { q: q || '', status: status || '', academic_year: academic_year || '', tab },
            pagination: { page, totalPages, total }
          });
        });
      });
    });
  });
});


// =====================================================
// MOBILE API: GET /api/mobile/v1/admin/certificate-requests
// Returns: Unified Bonafide & Bank Requests
// =====================================================
app.get('/api/mobile/v1/admin/certificate-requests', verifyMobileJwt, function (req, res) {
  const { q, status, academic_year } = req.query;
  const tab = req.query.tab === 'all' ? 'all' : 'today';
  const page = parseInt(req.query.page, 10) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    let bonafideWhere = "1=1";
    let bankWhere = "1=1";
    let bonafideParams = [];
    let bankParams = [];

    if (q) {
      bonafideWhere += " AND (student_name LIKE ? OR student_uid LIKE ? OR certificate_no LIKE ? OR branch LIKE ?)";
      bonafideParams.push('%' + q + '%', '%' + q + '%', '%' + q + '%', '%' + q + '%');
      bankWhere += " AND (student_name LIKE ? OR student_uid LIKE ? OR document_no LIKE ? OR branch LIKE ?)";
      bankParams.push('%' + q + '%', '%' + q + '%', '%' + q + '%', '%' + q + '%');
    }

    if (status) {
      bonafideWhere += " AND status = ?";
      bonafideParams.push(status);
      bankWhere += " AND status = ?";
      bankParams.push(status);
    }

    if (academic_year) {
      bonafideWhere += " AND academic_year LIKE ?";
      bonafideParams.push('%' + academic_year + '%');
      bankWhere += " AND academic_year LIKE ?";
      bankParams.push('%' + academic_year + '%');
    }

    if (tab === 'today') {
      const todayIstDate = (formatDateToISTString(new Date()) || '').slice(0, 10);
      const istStart = new Date(todayIstDate + 'T00:00:00+05:30');
      const utcStart = istStart.toISOString().slice(0, 19).replace('T', ' ');
      const utcEnd = new Date(istStart.getTime() + (24 * 60 * 60 * 1000)).toISOString().slice(0, 19).replace('T', ' ');
      bonafideWhere += " AND request_date >= ? AND request_date < ?";
      bonafideParams.push(utcStart, utcEnd);
      bankWhere += " AND request_date >= ? AND request_date < ?";
      bankParams.push(utcStart, utcEnd);
    }

    let unionQuery = `
      (SELECT id, 'Bonafide Certificate' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, certificate_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
      FROM bonafide_requests
      WHERE ${bonafideWhere})
      UNION ALL
      (SELECT id, 'Bank Statement' AS cert_type, student_uid, student_name, enrollment_no, branch, year, academic_year, purpose, payment_status, status, document_no AS doc_no, rejection_reason, request_date, approved_date, printed_date, collected_date
      FROM hostel_bank_requests
      WHERE ${bankWhere})
    `;
    let queryParams = [...bonafideParams, ...bankParams];

    const countSql = `SELECT COUNT(*) AS total FROM (${unionQuery}) AS combined`;
    const dataSql = `${unionQuery} ORDER BY request_date DESC LIMIT ? OFFSET ?`;

    conn.query(countSql, queryParams, function (eCount, countRows) {
      if (eCount) { conn.release(); return res.status(500).json({ success: false, error: 'Count query failed.' }); }

      const total = countRows[0].total;
      const totalPages = Math.ceil(total / limit) || 1;

      conn.query(dataSql, [...queryParams, limit, offset], function (eData, requests) {
        if (eData) { conn.release(); return res.status(500).json({ success: false, error: 'Data query failed.' }); }

        const statsSql = `
          SELECT 
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Pending') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Pending') AS pendingCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Approved') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Approved') AS approvedCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Printed') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Printed') AS printedCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Collected') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Collected') AS collectedCount,
            (SELECT COUNT(*) FROM bonafide_requests WHERE status = 'Rejected') + (SELECT COUNT(*) FROM hostel_bank_requests WHERE status = 'Rejected') AS rejectedCount
        `;

        conn.query(statsSql, function (eStats, statsRows) {
          conn.release();
          const stats = (statsRows && statsRows[0]) ? statsRows[0] : { pendingCount: 0, approvedCount: 0, printedCount: 0, collectedCount: 0, rejectedCount: 0 };
          
          return res.json({
            success: true,
            requests: requests || [],
            stats: {
              pending: stats.pendingCount,
              approved: stats.approvedCount,
              printed: stats.printedCount,
              collected: stats.collectedCount,
              rejected: stats.rejectedCount
            },
            filters: { q: q || '', status: status || '', academic_year: academic_year || '', tab },
            pagination: { page, totalPages, total }
          });
        });
      });
    });
  });
});

// =====================================================
// MOBILE API: BANK DETAILS ACTIONS
// =====================================================
app.post('/api/mobile/v1/admin/bank-details/:id/approve', verifyMobileJwt, function (req, res) {
  const id = req.params.id;
  const admin_email = req.user.email;
  dbbconnection.getConnection((err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    conn.beginTransaction((errTx) => {
      if (errTx) { conn.release(); return res.status(500).json({ success: false, error: 'Transaction start failed.' }); }
      conn.query("UPDATE hostel_bank_requests SET status='Approved', approved_date=CONVERT_TZ(NOW(), '+00:00', '+05:30'), approved_by=? WHERE id=? AND status='Pending'", [admin_email, id], (e1, r1) => {
        if (e1 || r1.affectedRows === 0) { conn.rollback(() => conn.release()); return res.status(400).json({ success: false, error: 'Failed to approve. May already be approved.' }); }
        logBonafideAudit(conn, 'hostel_bank_requests', id, admin_email, 'Approved', 'Request Approved (Mobile)', (eAudit) => {
          if (eAudit) { conn.rollback(() => conn.release()); return res.status(500).json({ success: false, error: 'Audit log failed.' }); }
          conn.commit((eCommit) => {
            conn.release();
            if (eCommit) return res.status(500).json({ success: false, error: 'Commit failed.' });
            res.json({ success: true, message: 'Bank Statement Approved' });
          });
        });
      });
    });
  });
});

app.post('/api/mobile/v1/admin/bank-details/:id/reject', verifyMobileJwt, function (req, res) {
  const id = req.params.id;
  const admin_email = req.user.email;
  const reason = req.body.rejection_reason || '';
  dbbconnection.getConnection((err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    conn.beginTransaction((errTx) => {
      if (errTx) { conn.release(); return res.status(500).json({ success: false, error: 'Transaction start failed.' }); }
      conn.query("UPDATE hostel_bank_requests SET status='Rejected', rejection_reason=?, rejected_date=CONVERT_TZ(NOW(), '+00:00', '+05:30'), rejected_by=? WHERE id=? AND (status='Pending' OR status='Approved')", [reason, admin_email, id], (e1, r1) => {
        if (e1 || r1.affectedRows === 0) { conn.rollback(() => conn.release()); return res.status(400).json({ success: false, error: 'Failed to reject.' }); }
        logBonafideAudit(conn, 'hostel_bank_requests', id, admin_email, 'Rejected', 'Reason: ' + reason, (eAudit) => {
          if (eAudit) { conn.rollback(() => conn.release()); return res.status(500).json({ success: false, error: 'Audit log failed.' }); }
          conn.commit((eCommit) => {
            conn.release();
            if (eCommit) return res.status(500).json({ success: false, error: 'Commit failed.' });
            res.json({ success: true, message: 'Bank Statement Rejected' });
          });
        });
      });
    });
  });
});

app.post('/api/mobile/v1/admin/bank-details/:id/collected', verifyMobileJwt, function (req, res) {
  const id = req.params.id;
  const admin_email = req.user.email;
  dbbconnection.getConnection((err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    conn.beginTransaction((errTx) => {
      if (errTx) { conn.release(); return res.status(500).json({ success: false, error: 'Transaction start failed.' }); }
      conn.query("UPDATE hostel_bank_requests SET status='Collected', collected_date=CONVERT_TZ(NOW(), '+00:00', '+05:30'), collected_by=? WHERE id=? AND status='Printed'", [admin_email, id], (e1, r1) => {
        if (e1 || r1.affectedRows === 0) { conn.rollback(() => conn.release()); return res.status(400).json({ success: false, error: 'Failed to mark as collected. Must be printed first.' }); }
        logBonafideAudit(conn, 'hostel_bank_requests', id, admin_email, 'Collected', 'Document handed to student (Mobile)', (eAudit) => {
          if (eAudit) { conn.rollback(() => conn.release()); return res.status(500).json({ success: false, error: 'Audit log failed.' }); }
          conn.commit((eCommit) => {
            conn.release();
            if (eCommit) return res.status(500).json({ success: false, error: 'Commit failed.' });
            res.json({ success: true, message: 'Marked as Collected' });
          });
        });
      });
    });
  });
});

app.post('/api/mobile/v1/admin/bank-details/:id/payment', verifyMobileJwt, function (req, res) {
  const id = req.params.id;
  const admin_email = req.user.email;
  const { payment_status } = req.body;
  if (!['Paid', 'Unpaid'].includes(payment_status)) {
    return res.status(400).json({ success: false, error: 'Invalid payment status' });
  }
  dbbconnection.getConnection((err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    conn.query("UPDATE hostel_bank_requests SET payment_status=? WHERE id=?", [payment_status, id], (e1, r1) => {
      if (e1 || r1.affectedRows === 0) { conn.release(); return res.status(400).json({ success: false, error: 'Failed to update payment status.' }); }
      logBonafideAudit(conn, 'hostel_bank_requests', id, admin_email, 'Payment Updated', 'Status changed to ' + payment_status + ' (Mobile)', (eAudit) => {
        conn.release();
        res.json({ success: true, message: 'Payment status updated' });
      });
    });
  });
});



// =====================================================
// MOBILE API: GET /api/mobile/v1/admin/bank-details/:id
// =====================================================
app.get('/api/mobile/v1/admin/bank-details/:id', verifyMobileJwt, function (req, res) {
  const id = req.params.id;
  dbbconnection.getConnection((err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    conn.query("SELECT * FROM hostel_bank_requests WHERE id=?", [id], (e1, r1) => {
      conn.release();
      if (e1) return res.status(500).json({ success: false, error: 'Query failed.' });
      if (!r1 || r1.length === 0) return res.status(404).json({ success: false, error: 'Request not found.' });
      const request = r1[0];
      request.cert_type = 'Bank Statement';
      request.doc_no = request.document_no;
      res.json({ success: true, request });
    });
  });
});

// =====================================================
// MOBILE API: GET /api/mobile/v1/admin/bonafide-requests/:id
// Returns single request detail
// =====================================================
app.get('/api/mobile/v1/admin/bonafide-requests/:id', verifyMobileJwt, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ success: false, error: 'Invalid request ID.' });

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      conn.release();
      if (e || !rows || rows.length === 0) {
        return res.status(404).json({ success: false, error: 'Request not found.' });
      }
      const request = rows[0];
      request.branch = formatBranchForBonafide(request.branch);
      return res.json({ success: true, request });
    });
  });
});

// =====================================================
// MOBILE API: POST /api/mobile/v1/admin/bonafide-requests/:id/approve
// Body: (none required)
// =====================================================
app.post('/api/mobile/v1/admin/bonafide-requests/:id/approve', express.json(), verifyMobileJwt, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ success: false, error: 'Invalid request ID.' });

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.status(404).json({ success: false, error: 'Request not found.' });
      }
      const request = rows[0];
      if (request.status !== 'Pending') {
        conn.release();
        return res.status(409).json({ success: false, error: 'Only Pending requests can be approved.' });
      }

      const certNo = generateCertificateNo(id, request.academic_year ? request.academic_year.split('-')[0] : null);
      const crypto = require('crypto');
      const verifyToken = crypto.randomUUID();

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); return res.status(500).json({ success: false, error: 'Transaction start failed.' }); }

        const updateSql = `
          UPDATE bonafide_requests
          SET status='Approved', approved_date=UTC_TIMESTAMP(), certificate_no=?, verification_token=?
          WHERE id=? AND status='Pending'`;
        conn.query(updateSql, [certNo, verifyToken, id], function (e2, result) {
          if (e2 || result.affectedRows === 0) {
            return conn.rollback(function () {
              conn.release();
              return res.status(500).json({ success: false, error: 'Could not approve. Please try again.' });
            });
          }

          createStudentNotification(
            conn, request.student_uid,
            'Bonafide Certificate Approved',
            'Your Bonafide Certificate request has been approved. Please collect the certificate from Hostel Manager Office.',
            function (eNotif) {
              if (eNotif) {
                return conn.rollback(function () {
                  conn.release();
                  return res.status(500).json({ success: false, error: 'Notification failed.' });
                });
              }

              logBonafideAudit(conn, id, 'Approved', req.decode.adminname || 'Admin', function (eAudit) {
                if (eAudit) {
                  return conn.rollback(function () {
                    conn.release();
                    return res.status(500).json({ success: false, error: 'Audit log failed.' });
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      return res.status(500).json({ success: false, error: 'Commit failed.' });
                    });
                  }
                  conn.release();
                  return res.json({ success: true, message: 'Request approved.', certificate_no: certNo });
                });
              });
            }
          );
        });
      });
    });
  });
});

// =====================================================
// MOBILE API: POST /api/mobile/v1/admin/bonafide-requests/:id/reject
// Body: { rejection_reason: string }
// =====================================================
app.post('/api/mobile/v1/admin/bonafide-requests/:id/reject', express.json(), verifyMobileJwt, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const reason = (req.body.rejection_reason || '').trim();

  if (!id) return res.status(400).json({ success: false, error: 'Invalid request ID.' });
  if (!reason) return res.status(400).json({ success: false, error: 'Rejection reason is required.' });

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.status(404).json({ success: false, error: 'Request not found.' });
      }
      const request = rows[0];
      if (request.status !== 'Pending') {
        conn.release();
        return res.status(409).json({ success: false, error: 'Only Pending requests can be rejected.' });
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); return res.status(500).json({ success: false, error: 'Transaction start failed.' }); }

        const updateSql = `UPDATE bonafide_requests SET status='Rejected', rejection_reason=? WHERE id=? AND status='Pending'`;
        conn.query(updateSql, [reason, id], function (e2, result) {
          if (e2 || result.affectedRows === 0) {
            return conn.rollback(function () {
              conn.release();
              return res.status(500).json({ success: false, error: 'Could not reject. Please try again.' });
            });
          }

          createStudentNotification(
            conn, request.student_uid,
            'Bonafide Certificate Request Rejected',
            'Your Bonafide Certificate request has been rejected. Reason: ' + reason,
            function (eNotif) {
              if (eNotif) {
                return conn.rollback(function () {
                  conn.release();
                  return res.status(500).json({ success: false, error: 'Notification failed.' });
                });
              }

              logBonafideAudit(conn, id, 'Rejected', req.decode.adminname || 'Admin', function (eAudit) {
                if (eAudit) {
                  return conn.rollback(function () {
                    conn.release();
                    return res.status(500).json({ success: false, error: 'Audit log failed.' });
                  });
                }

                conn.commit(function (eCommit) {
                  if (eCommit) {
                    return conn.rollback(function () {
                      conn.release();
                      return res.status(500).json({ success: false, error: 'Commit failed.' });
                    });
                  }
                  conn.release();
                  return res.json({ success: true, message: 'Request rejected.' });
                });
              });
            }
          );
        });
      });
    });
  });
});

// =====================================================
// MOBILE API: POST /api/mobile/v1/admin/bonafide-requests/:id/payment
// Body: { payment_status: 'paid' | 'unpaid' | 'pending' }
// =====================================================
app.post('/api/mobile/v1/admin/bonafide-requests/:id/payment', express.json(), verifyMobileJwt, function (req, res) {
  const id = parseInt(req.params.id, 10);
  const payment_status = (req.body.payment_status || '').trim().toLowerCase();

  if (!id) return res.status(400).json({ success: false, error: 'Invalid request ID.' });
  if (!['pending', 'paid', 'unpaid'].includes(payment_status)) {
    return res.status(400).json({ success: false, error: 'Invalid payment status. Must be paid, unpaid, or pending.' });
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    conn.beginTransaction(function (errTx) {
      if (errTx) { conn.release(); return res.status(500).json({ success: false, error: 'Transaction start failed.' }); }

      conn.query(
        'UPDATE bonafide_requests SET payment_status = ? WHERE id = ?',
        [payment_status, id],
        function (e, result) {
          if (e) {
            return conn.rollback(function () {
              conn.release();
              return res.status(500).json({ success: false, error: 'Failed to update payment status.' });
            });
          }
          if (result.affectedRows === 0) {
            return conn.rollback(function () {
              conn.release();
              return res.status(404).json({ success: false, error: 'Request not found.' });
            });
          }

          logBonafideAudit(conn, id, 'Payment Update: ' + payment_status, req.decode.adminname || 'Admin', function (eAudit) {
            if (eAudit) {
              return conn.rollback(function () {
                conn.release();
                return res.status(500).json({ success: false, error: 'Audit log failed.' });
              });
            }

            conn.commit(function (eCommit) {
              if (eCommit) {
                return conn.rollback(function () {
                  conn.release();
                  return res.status(500).json({ success: false, error: 'Commit failed.' });
                });
              }
              conn.release();
              return res.json({ success: true, message: 'Payment status updated.', payment_status });
            });
          });
        }
      );
    });
  });
});

// =====================================================
// MOBILE API: POST /api/mobile/v1/admin/bonafide-requests/:id/collected
// Transitions status from Printed -> Collected
// =====================================================
app.post('/api/mobile/v1/admin/bonafide-requests/:id/collected', express.json(), verifyMobileJwt, function (req, res) {
  const id = parseInt(req.params.id, 10);
  if (!id) return res.status(400).json({ success: false, error: 'Invalid request ID.' });

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    conn.query('SELECT * FROM bonafide_requests WHERE id = ? LIMIT 1', [id], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.status(404).json({ success: false, error: 'Request not found.' });
      }
      const request = rows[0];
      if (request.status !== 'Printed') {
        conn.release();
        return res.status(409).json({ success: false, error: 'Only Printed certificates can be marked as Collected.' });
      }

      conn.beginTransaction(function (errTx) {
        if (errTx) { conn.release(); return res.status(500).json({ success: false, error: 'Transaction start failed.' }); }

        conn.query(
          "UPDATE bonafide_requests SET status='Collected', collected_date=UTC_TIMESTAMP() WHERE id=? AND status='Printed'",
          [id],
          function (e2, result) {
            if (e2 || result.affectedRows === 0) {
              return conn.rollback(function () {
                conn.release();
                return res.status(500).json({ success: false, error: 'Could not update status.' });
              });
            }

            logBonafideAudit(conn, id, 'Collected', req.decode.adminname || 'Admin', function (eAudit) {
              if (eAudit) {
                return conn.rollback(function () {
                  conn.release();
                  return res.status(500).json({ success: false, error: 'Audit log failed.' });
                });
              }

              conn.commit(function (eCommit) {
                if (eCommit) {
                  return conn.rollback(function () {
                    conn.release();
                    return res.status(500).json({ success: false, error: 'Commit failed.' });
                  });
                }
                conn.release();
                return res.json({ success: true, message: 'Certificate marked as Collected.' });
              });
            });
          }
        );
      });
    });
  });
});
// =====================================================
// MOBILE API: GET /api/mobile/v1/admin/bank-settings
// =====================================================
app.get('/api/mobile/v1/admin/bank-settings', verifyMobileJwt, function (req, res) {
  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    conn.query('SELECT * FROM hostel_bank_settings WHERE id = 1 LIMIT 1', function (e, rows) {
      conn.release();
      if (e) return res.status(500).json({ success: false, error: 'Database query failed.' });
      
      const settings = (rows && rows.length > 0) ? rows[0] : {};
      return res.json({ success: true, settings });
    });
  });
});

// =====================================================
// MOBILE API: POST /api/mobile/v1/admin/bank-settings/update
// =====================================================
app.post('/api/mobile/v1/admin/bank-settings/update', express.json(), verifyMobileJwt, function (req, res) {
  const { bank_name, account_holder, branch, account_number, ifsc, upi_number, contact_number, email } = req.body;

  if (!bank_name || !account_holder || !branch || !account_number || !ifsc || !contact_number || !email) {
    return res.status(400).json({ success: false, error: 'Please fill in all required bank settings.' });
  }

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });

    conn.beginTransaction(function (errTx) {
      if (errTx) { conn.release(); return res.status(500).json({ success: false, error: 'Transaction error' }); }

      const upsertSql = `
        INSERT INTO hostel_bank_settings 
          (id, bank_name, account_holder, branch, account_number, ifsc, upi_number, contact_number, email, top_margin, bottom_margin, left_margin, right_margin, font_size, line_height) 
        VALUES 
          (1, ?, ?, ?, ?, ?, ?, ?, ?, 2.0, 2.0, 2.0, 2.0, 15, 1.4)
        ON DUPLICATE KEY UPDATE 
          bank_name = VALUES(bank_name), 
          account_holder = VALUES(account_holder), 
          branch = VALUES(branch), 
          account_number = VALUES(account_number), 
          ifsc = VALUES(ifsc), 
          upi_number = VALUES(upi_number), 
          contact_number = VALUES(contact_number), 
          email = VALUES(email)
      `;

      conn.query(upsertSql, [bank_name, account_holder, branch, account_number, ifsc, upi_number, contact_number, email], function (eUpsert) {
        if (eUpsert) {
          return conn.rollback(function () {
            conn.release();
            return res.status(500).json({ success: false, error: 'Failed to update settings.' });
          });
        }
        
        conn.commit(function (eCommit) {
          if (eCommit) {
            return conn.rollback(function () {
              conn.release();
              return res.status(500).json({ success: false, error: 'Failed to commit settings.' });
            });
          }
          conn.release();
          return res.json({ success: true, message: 'Bank details settings updated successfully.' });
        });
      });
    });
  });
});


// =====================================================
// MOBILE API: GET /api/mobile/v1/admin/special-food-items
// =====================================================
app.get('/api/mobile/v1/admin/special-food-items', verifyMobileJwt, async (req, res) => {
  dbbconnection.getConnection(async (err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    try {
      const [items] = await conn.promise().query("SELECT * FROM special_food_items WHERE is_active=1 ORDER BY created_at DESC");
      conn.release();
      res.json({ success: true, items });
    } catch (e) {
      conn.release();
      res.status(500).json({ success: false, error: 'Failed to fetch items' });
    }
  });
});

// =====================================================
// MOBILE API: POST /api/mobile/v1/admin/special-food-items/add
// =====================================================
app.post('/api/mobile/v1/admin/special-food-items/add', express.json(), verifyMobileJwt, async (req, res) => {
  const { food_name, quantity_desc, price_per_day, availability, duration_days } = req.body;
  const admin_id = req.decode ? (req.decode.adminuid || req.decode.uid || req.decode.email || 'mobile_a').substring(0, 8) : 'admin';
  
  if (!food_name || !quantity_desc || !price_per_day || !availability) {
    return res.status(400).json({ success: false, error: 'All fields are required.' });
  }

  const availabilityLower = typeof availability === 'string' ? availability.toLowerCase() : availability;

  dbbconnection.getConnection(async (err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    try {
      await conn.promise().query(
        "INSERT INTO special_food_items (food_name, quantity_desc, duration_days, price_per_day, availability, created_by) VALUES (?, ?, ?, ?, ?, ?)",
        [food_name, quantity_desc, duration_days || 30, price_per_day, availabilityLower, admin_id]
      );
      conn.release();
      res.json({ success: true, message: 'Item added successfully' });
    } catch (e) {
      console.error("ADD ITEM DB ERROR:", e);
      conn.release();
      res.status(500).json({ success: false, error: e.message || 'Failed to add item' });
    }
  });
});

// =====================================================
// MOBILE API: PUT /api/mobile/v1/admin/special-food-items/edit/:id
// =====================================================
app.put('/api/mobile/v1/admin/special-food-items/edit/:id', express.json(), verifyMobileJwt, async (req, res) => {
  const { id } = req.params;
  const { food_name, quantity_desc, price_per_day, availability, duration_days } = req.body;
  
  if (!food_name || !quantity_desc || !price_per_day || !availability) {
    return res.status(400).json({ success: false, error: 'All fields are required.' });
  }

  const availabilityLower = typeof availability === 'string' ? availability.toLowerCase() : availability;

  dbbconnection.getConnection(async (err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    try {
      await conn.promise().query(
        "UPDATE special_food_items SET food_name=?, quantity_desc=?, duration_days=?, price_per_day=?, availability=? WHERE id=?",
        [food_name, quantity_desc, duration_days || 30, price_per_day, availabilityLower, id]
      );
      conn.release();
      res.json({ success: true, message: 'Item updated successfully' });
    } catch (e) {
      console.error("EDIT ITEM DB ERROR:", e);
      conn.release();
      res.status(500).json({ success: false, error: e.message || 'Failed to update item' });
    }
  });
});

// =====================================================
// MOBILE API: DELETE /api/mobile/v1/admin/special-food-items/delete/:id
// =====================================================
app.delete('/api/mobile/v1/admin/special-food-items/delete/:id', verifyMobileJwt, async (req, res) => {
  const { id } = req.params;
  dbbconnection.getConnection(async (err, conn) => {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed.' });
    try {
      try {
          await conn.promise().query("DELETE FROM special_food_items WHERE id=?", [id]);
      } catch (deleteErr) {
          if (deleteErr.errno === 1451 || deleteErr.code === 'ER_ROW_IS_REFERENCED_2') {
              await conn.promise().query("UPDATE special_food_items SET is_active=0 WHERE id=?", [id]);
          } else {
              throw deleteErr;
          }
      }
      conn.release();
      res.json({ success: true, message: 'Item deleted successfully' });
    } catch (e) {
      conn.release();
      res.status(500).json({ success: false, error: 'Failed to delete item' });
    }
  });
});


// END MOBILE BONAFIDE API MODULE

// --- MOBILE STUDENT DASHBOARD API ---
app.get('/api/mobile/v1/student/dashboard', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    // Get student details
    var studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(studentSql, [uid], function (sErr, sRows) {
      if (sErr || !sRows || sRows.length === 0) {
        connection.release();
        return res.status(404).json({ success: false, error: 'Student not found' });
      }
      const student = sRows[0];
      attachStudentPhotoUrl(student);

      // Get count of total passes
      var totalSql = "SELECT COUNT(*) AS total FROM log_details1 WHERE uid = ? AND passtype IS NOT NULL";
      connection.query(totalSql, [uid], function (tErr, tRows) {
        // Get count of passes this month
        var monthSql = "SELECT COUNT(*) AS monthly FROM log_details1 WHERE uid = ? AND passtype IS NOT NULL AND MONTH(COALESCE(approvaldt, outdatetime, indatetime)) = MONTH(CURDATE()) AND YEAR(COALESCE(approvaldt, outdatetime, indatetime)) = YEAR(CURDATE())";
        connection.query(monthSql, [uid], function (mErr, mRows) {
          // Check for active pass
          var activeSql = "SELECT * FROM log_details1 WHERE uid = ? AND status = 'ACTIVE' ORDER BY logid DESC LIMIT 1";
          connection.query(activeSql, [uid], function (aErr, aRows) {
            // Get recent logs
            var logsSql = "SELECT logid, outdatetime, indatetime, status, passtype, approvaldt FROM log_details1 WHERE uid = ? ORDER BY logid DESC LIMIT 5";
            connection.query(logsSql, [uid], function (lErr, lRows) {
              connection.release();

              res.json({
                success: true,
                student: student,
                stats: {
                  totalPasses: (tRows && tRows[0]) ? tRows[0].total : 0,
                  monthPasses: (mRows && mRows[0]) ? mRows[0].monthly : 0,
                  activePass: (aRows && aRows.length > 0) ? 'OUT' : 'IN',
                  activePassDetails: (aRows && aRows.length > 0) ? aRows[0] : null
                },
                recentLogs: lRows || []
              });
            });
          });
        });
      });
    });
  });
});

// --- MOBILE STUDENT PASS HISTORY API ---
app.get('/api/mobile/v1/student/passhistory', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const fromDate = req.query.fromDate;
  const toDate = req.query.toDate;
  const passType = req.query.passType;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    let sql = "SELECT * FROM log_details1 WHERE uid = ?";
    let params = [uid];

    if (fromDate && toDate) {
      sql += " AND DATE(COALESCE(approvaldt, outdatetime, indatetime)) BETWEEN ? AND ?";
      params.push(fromDate, toDate);
    }
    if (passType) {
      sql += " AND passtype = ?";
      params.push(passType);
    }

    sql += " ORDER BY logid DESC LIMIT 100";

    connection.query(sql, params, function (qErr, rows) {
      if (qErr) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Failed to fetch pass history' });
      }

      // Check if student has a pending request in pass_requests table
      var pendingSql = "SELECT * FROM pass_requests WHERE uid = ? AND status = 'pending' ORDER BY requestid DESC";
      connection.query(pendingSql, [uid], function (pErr, pRows) {
        connection.release();
        res.json({
          success: true,
          history: rows || [],
          pendingRequests: pRows || []
        });
      });
    });
  });
});

// --- MOBILE ADMIN BOYS ADMISSION APPLICATIONS ---
app.get('/api/mobile/v1/boys/admission-applications', verifyMobileJwt, function (req, res) {
  const role = req.decode && req.decode.role;
  if (role !== 'BoysHostelAdmin' && role !== 'SuperID' && role !== 'GirlsHostelAdmin') {
    return res.status(403).json({ success: false, error: 'Unauthorized access' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed' });
    
    connection.query("SELECT * FROM hostel_admission_applications ORDER BY created_at DESC", function (qErr, result) {
      connection.release();
      if (qErr) return res.status(500).json({ success: false, error: 'Failed to fetch applications' });
      
      res.json({ success: true, data: result || [] });
    });
  });
});

// --- MOBILE STUDENT REQUEST PASS API ---
app.post('/api/mobile/v1/student/requestpass', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const sname = req.studentName;
  const { passtype, outdate, outtime, indate, intime, reason, emergencyContact, is_emergency } = req.body;

  if (!passtype || !outdate || !outtime || !indate || !intime || !reason) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  const formattedOutDate = outdate;
  const formattedInDate = indate;
  const formattedOutTime = outtime;
  const formattedInTime = intime;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    // 1. Check if student is restricted and check emergency status
    connection.query("SELECT status, gender, dept, year, emergency_pass_enabled, emergency_pass_enabled_by FROM studentdetails WHERE uid = ?", [uid], function (sErr, sRows) {
      if (sErr || !sRows || sRows.length === 0) {
        connection.release();
        return res.status(404).json({ success: false, error: 'Student record not found' });
      }

      const student = sRows[0];
      if (student.status === 'Restrict') {
        connection.release();
        return res.status(403).json({ success: false, error: 'Account restricted. Pass submission blocked.' });
      }

      // 2. Check for active pass in campus
      var activeSql = "SELECT logid FROM log_details1 WHERE uid = ? AND (status = 'ACTIVE' OR (outdatetime IS NOT NULL AND indatetime IS NULL)) ORDER BY logid DESC LIMIT 1";
      connection.query(activeSql, [uid], function (aErr, aRows) {
        if (aRows && aRows.length > 0) {
          connection.release();
          return res.status(400).json({ success: false, error: 'You are currently outside campus with an active pass. Cannot request new pass.' });
        }

        // 3. Check for pending pass requests
        var pendingSql = "SELECT requestid FROM pass_requests WHERE uid = ? AND status = 'pending' LIMIT 1";
        connection.query(pendingSql, [uid], function (pErr, pRows) {
          if (pRows && pRows.length > 0) {
            connection.release();
            return res.status(400).json({ success: false, error: 'You already have a pending pass request. Cancel it to request another.' });
          }

          // 4. Validate timebounds
          const now = new Date();
          const istTimeShifted = new Date(now.getTime() + (5.5 * 60 * 60 * 1000));
          const dayNo = String(istTimeShifted.getUTCDay());
          const hour = String(istTimeShifted.getUTCHours()).padStart(2, '0');
          const minute = String(istTimeShifted.getUTCMinutes()).padStart(2, '0');
          const currentTimeStr = `${hour}:${minute}`;

          const genderClean = (student.gender || '').toUpperCase();
          const studentHostel = (genderClean === 'FEMALE' || genderClean === 'F' || genderClean === 'GIRL') ? 'Girls' : 'Boys';
          
          var timeboundSql = "SELECT * FROM timebound WHERE dayno = ? AND hostel = ? AND status = 'ACTIVE'";
          connection.query(timeboundSql, [dayNo, studentHostel], function (tErr, tRows) {
            if (tErr) {
              connection.release();
              return res.status(500).json({ success: false, error: 'Database error checking timebound constraints.' });
            }

            if (tRows && tRows.length > 0) {
              const tb = tRows[0];
              const hasRange1 = tb.start && tb.end && tb.start.trim() !== '' && tb.end.trim() !== '';
              const hasRange2 = tb.start1 && tb.end1 && tb.start1.trim() !== '' && tb.end1.trim() !== '';
              
              if (!is_emergency && (hasRange1 || hasRange2)) {
                let allowed = false;
                const cleanStart = (tb.start || '').substring(0, 5);
                const cleanEnd = (tb.end || '').substring(0, 5);
                const cleanStart1 = (tb.start1 || '').substring(0, 5);
                const cleanEnd1 = (tb.end1 || '').substring(0, 5);
                
                if (hasRange1 && currentTimeStr >= cleanStart && currentTimeStr <= cleanEnd) {
                  allowed = true;
                }
                if (hasRange2 && currentTimeStr >= cleanStart1 && currentTimeStr <= cleanEnd1) {
                  allowed = true;
                }
                
                // Time restriction removed
              }
            }

            // 5. Insert pass request
            const outdatetime = formatDateTime(formattedOutDate, formattedOutTime);
            const indatetime = formatDateTime(formattedInDate, formattedInTime);
            const request_date = formatDateToISTString(new Date());
            
            var isActualEmergency = (is_emergency === 'true' || is_emergency === true || is_emergency === '1' || is_emergency === 1) && student.emergency_pass_enabled === 1;
            var initialStatus = 'approved';
            var approvedBy = 'Roy';
            var approvedAt = request_date;

            var insertSql = `
              INSERT INTO pass_requests 
              (uid, passtype, expected_out, expected_return, reason, emergency_contact, status, created_at, request_kind, is_emergency, approved_by, approved_at) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?)`;

            const contactNum = emergencyContact || student.parentnumber || null;
            connection.query(insertSql, [uid, passtype, outdatetime, indatetime, reason, contactNum, initialStatus, request_date, isActualEmergency ? 1 : 0, approvedBy, approvedAt], function (iErr, iResult) {
              if (iErr) {
                connection.release();
                console.error('Failed to insert pass request', iErr);
                return res.status(500).json({ success: false, error: 'Failed to record pass request' });
              }

              if (isActualEmergency) {
                connection.query("UPDATE studentdetails SET emergency_pass_enabled = 0, emergency_pass_enabled_by = NULL WHERE uid = ?", [uid], function() {
                  connection.release();
                  return res.json({ success: true, message: 'Emergency pass request auto-approved by ' + approvedBy + '.', requestId: iResult.insertId });
                });
              } else {
                connection.release();
                triggerPassRequestWebhook({
                  request_id: iResult.insertId,
                  uid: uid,
                  student_name: student.sname || 'Student',
                  pass_type: passtype,
                  reason: reason || 'Not specified',
                  expected_out: outdatetime,
                  expected_return: indatetime
                });
                res.json({ success: true, message: 'Pass request submitted successfully!', requestId: iResult.insertId });
              }
            });
          });
        });
      });
    });
  });
});

// --- MOBILE STUDENT CANCEL PASS REQUEST API ---
app.get('/api/mobile/v1/student/cancelrequest/:id', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const requestId = req.params.id;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var deleteSql = "DELETE FROM pass_requests WHERE requestid = ? AND uid = ? AND status IN ('pending', 'approved')";
    connection.query(deleteSql, [requestId, uid], function (qErr, result) {
      connection.release();
      if (qErr) {
        return res.status(500).json({ success: false, error: 'Failed to cancel pass request' });
      }
      if (result.affectedRows === 0) {
        return res.status(400).json({ success: false, error: 'Request not found or cannot be cancelled' });
      }
      res.json({ success: true, message: 'Request cancelled successfully' });
    });
  });
});

// --- MOBILE STUDENT ATTENDANCE API ---
app.get('/api/mobile/v1/student/attendance', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const fromDate = req.query.fromDate;
  const toDate = req.query.toDate;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var attendanceSql = `
      SELECT *, 
      CONCAT(FLOOR((TIMESTAMPDIFF(SECOND, outdatetime, indatetime) % 86400)/3600), ' hrs ', 
            FLOOR((TIMESTAMPDIFF(SECOND, outdatetime, indatetime) % 3600)/60), ' min') AS Duration 
      FROM log_details1 WHERE uid = ?`;

    var params = [uid];

    if (fromDate && toDate) {
      attendanceSql += " AND DATE(COALESCE(approvaldt, outdatetime, indatetime)) BETWEEN ? AND ?";
      params.push(fromDate, toDate);
    }

    attendanceSql += " ORDER BY logid DESC LIMIT 100";

    connection.query(attendanceSql, params, function (err, attendanceResult) {
      if (err) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Failed to fetch attendance logs' });
      }

      var statsSql = `
        SELECT 
          COUNT(CASE WHEN indatetime IS NOT NULL THEN 1 END) as totalEntries,
          COUNT(CASE WHEN outdatetime IS NOT NULL THEN 1 END) as totalExits,
          COUNT(CASE WHEN MONTH(COALESCE(approvaldt, outdatetime, indatetime)) = MONTH(CURDATE()) THEN 1 END) as monthMovements
        FROM log_details1 WHERE uid = ?`;

      connection.query(statsSql, [uid], function (err, statsResult) {
        connection.release();
        res.json({
          success: true,
          logs: attendanceResult || [],
          stats: statsResult ? statsResult[0] : { totalEntries: 0, totalExits: 0, monthMovements: 0 }
        });
      });
    });
  });
});

// --- MOBILE STUDENT SICK LEAVE REQUESTS (LIST) API ---
app.get('/api/mobile/v1/student/sickleaverequests', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var sql = `
      SELECT requestid, uid, illness, details, status, approved_by, rejection_reason,
            DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at,
            DATE_FORMAT(approved_at, '%Y-%m-%d %H:%i:%s') as approved_at
      FROM sick_leave_requests
      WHERE uid = ?
      ORDER BY created_at DESC
    `;

    connection.query(sql, [uid], function (err, result) {
      connection.release();
      if (err) {
        return res.status(500).json({ success: false, error: 'Failed to load sick leave requests' });
      }
      res.json({ success: true, requests: result || [] });
    });
  });
});

// --- MOBILE STUDENT SUBMIT SICK LEAVE API ---
app.post('/api/mobile/v1/student/sickleave', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const { illness, details } = req.body;

  if (!illness) {
    return res.status(400).json({ success: false, error: 'Illness / Reason is required' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    // Check restriction
    connection.query("SELECT status FROM studentdetails WHERE uid = ?", [uid], function (err, checkResult) {
      if (err || checkResult.length === 0 || checkResult[0].status === 'Restrict') {
        connection.release();
        return res.status(403).json({ success: false, error: 'Cannot submit request. Account may be restricted.' });
      }

      // Check pending request today
      var checkPendingSql = "SELECT * FROM sick_leave_requests WHERE uid = ? AND status = 'pending' AND created_at LIKE CONCAT(?, '%')";
      var todayIST = formatDateToISTString(new Date()).substring(0, 10);
      connection.query(checkPendingSql, [uid, todayIST], function (err, pendingResult) {
        if (pendingResult && pendingResult.length > 0) {
          connection.release();
          return res.status(400).json({ success: false, error: 'You already have a pending sick leave request for today' });
        }

        var nowIST = formatDateToISTString(new Date());
        var insertSql = `
          INSERT INTO sick_leave_requests 
          (uid, illness, details, status, created_at) 
          VALUES (?, ?, ?, 'pending', ?)`;

        connection.query(insertSql, [uid, illness, details || null, nowIST], function (err, insertResult) {
          connection.release();
          if (err) {
            return res.status(500).json({ success: false, error: 'Error submitting request' });
          }
          res.json({ success: true, message: 'Sick leave request submitted successfully! Awaiting approval.' });
        });
      });
    });
  });
});

// --- MOBILE STUDENT CANCEL SICK LEAVE REQUEST API ---
app.post('/api/mobile/v1/student/cancelsickrequest/:id', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const requestId = req.params.id;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var updateSql = "UPDATE sick_leave_requests SET status = 'cancelled' WHERE requestid = ? AND uid = ? AND status = 'pending'";
    connection.query(updateSql, [requestId, uid], function (err, result) {
      connection.release();
      if (err) {
        return res.status(500).json({ success: false, error: 'Error cancelling sick leave request' });
      }
      if (result.affectedRows === 0) {
        return res.status(400).json({ success: false, error: 'Request not found or cannot be cancelled' });
      }
      res.json({ success: true, message: 'Sick leave request cancelled successfully' });
    });
  });
});

// --- MOBILE STUDENT ROOMS API ---
app.get('/api/mobile/v1/student/rooms', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    loadFeatureFlagsMap(connection, function (_fErr, flagsMap) {
      const roomBookingEnabled = (flagsMap && flagsMap.room_booking) ? !!flagsMap.room_booking.enabled : true;

      const studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
      connection.query(studentSql, [uid], function (sErr, sRows) {
        if (sErr || !sRows || sRows.length === 0) {
          connection.release();
          return res.status(404).json({ success: false, error: 'Student record not found' });
        }

        const student = sRows[0];
        const category = ((student.category || '') + '').trim().toLowerCase();
        if (category !== 'hostel') {
          connection.release();
          return res.status(403).json({ success: false, error: 'Room booking is only available for Hostel students' });
        }
        if (((student.status || '') + '').trim() === 'Restrict') {
          connection.release();
          return res.status(403).json({ success: false, error: 'Account restricted. You cannot book rooms.' });
        }

        const myBookingSql = `
          SELECT rb.*, r.room_type, r.capacity, r.price_per_night
          FROM room_bookings rb
          LEFT JOIN rooms r ON r.name = rb.room_no
          WHERE rb.uid = ? AND rb.booking_status = 'locked'
          ORDER BY rb.created_at DESC
          LIMIT 1
        `;
        connection.query(myBookingSql, [uid], function (bErr, bRows) {
          if (bErr) {
            connection.release();
            return res.status(500).json({ success: false, error: 'Error loading room booking' });
          }

          const roomsSql = `
            SELECT r.name as room_no, r.block, r.floor, r.room_type, r.capacity, r.price_per_night, r.is_permanent, r.description,
                   rb.id as booking_id, rb.uid as booked_uid, rb.bed_no as booked_bed, rb.payment_status as payment_status, rb.created_at as booked_at,
                   sd.sname as booked_name
            FROM rooms r
            LEFT JOIN room_bookings rb
              ON rb.room_no = r.name
             AND rb.block = r.block
             AND rb.floor = r.floor
             AND rb.booking_status = 'locked'
            LEFT JOIN studentdetails sd
              ON sd.uid = rb.uid
            WHERE (r.is_available IS NULL OR r.is_available = TRUE)
            ORDER BY r.block, r.floor, r.name
          `;
          connection.query(roomsSql, function (rErr, roomRows) {
            connection.release();
            if (rErr) {
              return res.status(500).json({ success: false, error: 'Error loading rooms' });
            }

            res.json({
              success: true,
              roomBookingEnabled: roomBookingEnabled,
              myBooking: (bRows && bRows.length) ? bRows[0] : null,
              rooms: roomRows || []
            });
          });
        });
      });
    });
  });
});

// --- MOBILE STUDENT BOOKINGS SUBMIT API ---
app.post('/api/mobile/v1/student/bookings', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const room_no = ((req.body.room_no || '') + '').trim();
  const block = ((req.body.block || '') + '').trim();
  const floor = ((req.body.floor || '') + '').trim();
  const bed_no = ((req.body.bed_no || '') + '').trim();
  const advanceAmount = req.body.advance_amount ? parseFloat(req.body.advance_amount) : 0;
  const transactionId = ((req.body.transaction_id || '') + '').trim();

  if (!uid || !room_no || !block || !floor || !bed_no || !transactionId) {
    return res.status(400).json({ success: false, error: 'Invalid room booking request' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    loadFeatureFlagsMap(connection, function (_fErr, flagsMap) {
      const roomBookingEnabled = (flagsMap && flagsMap.room_booking) ? !!flagsMap.room_booking.enabled : true;
      if (!roomBookingEnabled) {
        connection.release();
        return res.status(403).json({ success: false, error: 'Room booking is currently disabled by admin' });
      }

      connection.beginTransaction(function (tErr) {
        if (tErr) { connection.release(); return res.status(500).json({ success: false, error: 'Transaction start failed' }); }

        const roomValidateSql = "SELECT name FROM rooms WHERE name = ? AND block = ? AND floor = ? AND (is_available IS NULL OR is_available = TRUE) AND NOT (is_permanent = 1 AND name IN ('AF-02', 'AF-31', 'AS-31', 'BG-26')) LIMIT 1";
        connection.query(roomValidateSql, [room_no, block, floor], function (vErr, vRows) {
          if (vErr || !vRows || vRows.length === 0) {
            return connection.rollback(function () {
              connection.release();
              return res.status(400).json({ success: false, error: 'Selected room is not available' });
            });
          }

          // Check if student has active booking
          const myActiveSql = "SELECT id FROM room_bookings WHERE uid = ? AND booking_status = 'locked' LIMIT 1";
          connection.query(myActiveSql, [uid], function (aErr, aRows) {
            if (aErr || (aRows && aRows.length > 0)) {
              return connection.rollback(function () {
                connection.release();
                return res.status(400).json({ success: false, error: aErr ? 'Database error' : 'You already have an active room booking' });
              });
            }

            // Check if room/bed is already occupied
            const occupiedSql = "SELECT id FROM room_bookings WHERE room_no = ? AND block = ? AND floor = ? AND bed_no = ? AND booking_status = 'locked' LIMIT 1";
            connection.query(occupiedSql, [room_no, block, floor, bed_no], function (oErr, oRows) {
              if (oErr || (oRows && oRows.length > 0)) {
                return connection.rollback(function () {
                  connection.release();
                  return res.status(400).json({ success: false, error: oErr ? 'Database error' : 'Bed is already booked by another student' });
                });
              }

              const insertSql = `
                INSERT INTO room_bookings (
                  room_no, block, floor, bed_no, uid,
                  booking_status, payment_status,
                  advance_amount, transaction_id,
                  agreement_accepted,
                  locked_source, locked_by
                )
                VALUES (?, ?, ?, ?, ?, 'locked', 'pending', ?, ?, 1, 'student', NULL)
              `;
              connection.query(insertSql, [room_no, block, floor, bed_no, uid, advanceAmount, transactionId], function (iErr) {
                if (iErr) {
                  return connection.rollback(function () {
                    connection.release();
                    return res.status(500).json({ success: false, error: 'Failed to record bed booking' });
                  });
                }

                // Update studentdetails
                connection.query("UPDATE studentdetails SET room_no = NULL, bed_no = NULL, block = NULL, other2 = NULL WHERE uid = ?", [uid], function (clearErr) {
                  if (clearErr) {
                    return connection.rollback(function () {
                      connection.release();
                      return res.status(500).json({ success: false, error: 'Database update failed' });
                    });
                  }

                  connection.commit(function (cErr) {
                    if (cErr) {
                      return connection.rollback(function () {
                        connection.release();
                        return res.status(500).json({ success: false, error: 'Transaction commit failed' });
                      });
                    }
                    connection.release();
                    res.json({ success: true, message: 'Room booked successfully (payment pending)' });
                  });
                });
              });
            });
          });
        });
      });
    });
  });
});

// --- MOBILE STUDENT NOTIFICATIONS & ANNOUNCEMENTS API ---
app.get('/api/mobile/v1/student/notifications', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    var studentSql = "SELECT * FROM studentdetails WHERE uid = ?";
    connection.query(studentSql, [uid], function (err, studentResult) {
      if (err || studentResult.length === 0) {
        connection.release();
        return res.status(404).json({ success: false, error: 'Student details not found' });
      }

      const student = studentResult[0];
      const studentYear = student.year || student.yr || student.syear || null;

      var notifSql = "SELECT * FROM student_notifications WHERE uid = ? ORDER BY created_at DESC LIMIT 50";
      connection.query(notifSql, [uid], function (err, notifResult) {
        var announcementSql = "SELECT * FROM announcements WHERE is_active = 1 AND (target_year = 'all' OR target_year = ?) ORDER BY created_at DESC LIMIT 20";
        connection.query(announcementSql, [studentYear ? String(studentYear) : 'all'], function (err, announcementResult) {
          connection.release();
          res.json({
            success: true,
            notifications: notifResult || [],
            announcements: announcementResult || []
          });
        });
      });
    });
  });
});

// --- MOBILE STUDENT BONAFIDE GET API ---
app.get('/api/mobile/v1/student/bonafide', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    conn.query('SELECT * FROM studentdetails WHERE uid = ? LIMIT 1', [uid], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.status(404).json({ success: false, error: 'Student details not found' });
      }
      const student = rows[0];
      student.dept = formatBranchForBonafide(student.dept);
      const currentAcademicYear = getCurrentAcademicYear();

      conn.query(
        "SELECT * FROM bonafide_requests WHERE student_uid = ? AND academic_year = ? AND status != 'Rejected' LIMIT 1",
        [uid, currentAcademicYear],
        function (e2, existing) {
          if (e2) { conn.release(); return res.status(500).json({ success: false, error: 'Failed to verify request' }); }

          conn.query(
            'SELECT * FROM bonafide_requests WHERE student_uid = ? ORDER BY request_date DESC',
            [uid],
            function (e3, history) {
              conn.release();
              if (e3) return res.status(500).json({ success: false, error: 'Failed to load history' });

              if (history) {
                history.forEach(function (h) {
                  h.branch = formatBranchForBonafide(h.branch);
                });
              }
              res.json({
                success: true,
                student: student,
                academicYearFormatted: currentAcademicYear,
                existingRequest: existing && existing[0] ? existing[0] : null,
                history: history || []
              });
            }
          );
        }
      );
    });
  });
});

// --- MOBILE STUDENT BONAFIDE REQUEST POST API ---
app.post('/api/mobile/v1/student/bonafide/request', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  let studentName = (req.body.student_name || '').trim();
  let purpose = (req.body.purpose || '').trim();
  const otherPurpose = (req.body.other_purpose || '').trim();
  const occupancy = (req.body.occupancy || '').toLowerCase().trim();
  const messType = (req.body.mess_type || '').toLowerCase().trim();

  if (purpose === 'Other') {
    purpose = otherPurpose.trim();
  }

  if (!studentName || studentName.length < 3) {
    return res.status(400).json({ success: false, error: 'Student name must be at least 3 characters.' });
  }
  if (!purpose) {
    return res.status(400).json({ success: false, error: 'Purpose is required.' });
  }
  if (!['single', 'double', 'triple'].includes(occupancy)) {
    return res.status(400).json({ success: false, error: 'Invalid occupancy selection.' });
  }
  if (!['veg', 'nonveg'].includes(messType)) {
    return res.status(400).json({ success: false, error: 'Invalid mess type selection.' });
  }

  const feeBreakdown = calculateHostelFeeBreakdown(messType, occupancy);
  const hostelFee = feeBreakdown.total;
  const currentAcademicYear = getCurrentAcademicYear();

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    conn.query('SELECT * FROM studentdetails WHERE uid = ? LIMIT 1', [uid], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.status(404).json({ success: false, error: 'Student not found' });
      }

      const student = rows[0];
      const category = (student.category || '').toLowerCase().trim();
      if (category !== 'hostel') {
        conn.release();
        return res.status(403).json({ success: false, error: 'Bonafide Certificate is only available for Hostel students.' });
      }

      conn.query(
        "SELECT id FROM bonafide_requests WHERE student_uid = ? AND academic_year = ? AND status != 'Rejected' LIMIT 1",
        [uid, currentAcademicYear],
        function (e2, existing) {
          if (existing && existing.length > 0) {
            conn.release();
            return res.status(400).json({ success: false, error: 'You have already applied for a Bonafide Certificate this academic year.' });
          }

          const formattedBranch = formatBranchForBonafide(student.dept);
          const insertSql = `
            INSERT INTO bonafide_requests 
            (student_uid, student_name, enrollment_no, branch, year, hostel_fee, academic_year, purpose, occupancy, mess_type, status, request_date) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', UTC_TIMESTAMP())`;

          conn.query(insertSql, [uid, studentName, student.uid, formattedBranch, student.year, hostelFee, currentAcademicYear, purpose, occupancy, messType], function (insertErr, result) {
            if (insertErr) {
              conn.release();
              console.error('Failed to submit bonafide request', insertErr);
              return res.status(500).json({ success: false, error: 'Failed to record bonafide request.' });
            }

            const requestId = result.insertId;
            logBonafideAudit(conn, requestId, 'Created', studentName, function (eAudit) {
              conn.release();
              if (eAudit) {
                console.error('Failed to write audit log', eAudit);
              }
              res.json({ success: true, message: 'Bonafide request submitted successfully!' });
            });
          });
        }
      );
    });
  });
});

// --- MOBILE STUDENT BONAFIDE CANCEL API ---
app.post('/api/mobile/v1/student/bonafide/:id/cancel', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const requestId = req.params.id;

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    conn.query(
      "UPDATE bonafide_requests SET status = 'Cancelled' WHERE id = ? AND student_uid = ? AND status = 'Pending'",
      [requestId, uid],
      function (qErr, result) {
        conn.release();
        if (qErr) return res.status(500).json({ success: false, error: 'Error cancelling request' });
        if (result.affectedRows === 0) {
          return res.status(400).json({ success: false, error: 'Request not found or cannot be cancelled' });
        }
        res.json({ success: true, message: 'Request cancelled successfully' });
      }
    );
  });
});

// --- MOBILE STUDENT BANK DETAILS GET API ---
app.get('/api/mobile/v1/student/bank-details', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    conn.query('SELECT * FROM studentdetails WHERE uid = ? LIMIT 1', [uid], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.status(404).json({ success: false, error: 'Student details not found' });
      }
      const student = rows[0];
      student.dept = formatBranchForBonafide(student.dept);
      const currentAcademicYear = getCurrentAcademicYear();

      conn.query(
        "SELECT * FROM hostel_bank_requests WHERE student_uid = ? AND academic_year = ? AND status != 'Rejected' LIMIT 1",
        [uid, currentAcademicYear],
        function (e2, existing) {
          if (e2) { conn.release(); return res.status(500).json({ success: false, error: 'Failed to verify request' }); }

          conn.query(
            'SELECT * FROM hostel_bank_requests WHERE student_uid = ? ORDER BY request_date DESC',
            [uid],
            function (e3, history) {
              conn.release();
              if (e3) return res.status(500).json({ success: false, error: 'Failed to load history' });

              if (history) {
                history.forEach(function (h) {
                  h.branch = formatBranchForBonafide(h.branch);
                });
              }

              const selectedMess = (student.mess_type || 'veg').toLowerCase().includes('non') ? 'nonveg' : 'veg';
              const selectedOccupancy = (student.occupancy || 'double').toLowerCase();
              const feeBreakdown = calculateHostelFeeBreakdown(selectedMess, selectedOccupancy);

              res.json({
                success: true,
                student: student,
                academicYearFormatted: currentAcademicYear,
                existingRequest: existing && existing[0] ? existing[0] : null,
                history: history || [],
                feeBreakdown: feeBreakdown
              });
            }
          );
        }
      );
    });
  });
});

// --- MOBILE STUDENT BANK DETAILS REQUEST POST API ---
app.post('/api/mobile/v1/student/bank-details/request', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  let purpose = (req.body.purpose || '').trim();
  const otherPurpose = (req.body.other_purpose || '').trim();
  const occupancy = (req.body.occupancy || '').toLowerCase().trim();
  const messType = (req.body.mess_type || '').toLowerCase().trim();
  const adminRemark = (req.body.admin_remark || '').trim();

  const validPurposes = ['Hostel Fee Payment', 'Education Loan', 'Scholarship', 'Personal Record', 'Other'];
  if (!validPurposes.includes(purpose)) {
    return res.status(400).json({ success: false, error: 'Invalid purpose selected.' });
  }

  let purposeDesc = null;
  if (purpose === 'Other') {
    purposeDesc = otherPurpose;
  }

  if (!purpose) {
    return res.status(400).json({ success: false, error: 'Purpose is required.' });
  }
  if (!['single', 'double', 'triple'].includes(occupancy)) {
    return res.status(400).json({ success: false, error: 'Invalid occupancy selection.' });
  }
  if (!['veg', 'nonveg'].includes(messType)) {
    return res.status(400).json({ success: false, error: 'Invalid mess type selection.' });
  }

  const feeBreakdown = calculateHostelFeeBreakdown(messType, occupancy);
  const hostelFee = feeBreakdown.total;
  const currentAcademicYear = getCurrentAcademicYear();

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    conn.query('SELECT * FROM studentdetails WHERE uid = ? LIMIT 1', [uid], function (e, rows) {
      if (e || !rows || rows.length === 0) {
        conn.release();
        return res.status(404).json({ success: false, error: 'Student not found' });
      }

      const student = rows[0];
      const category = (student.category || '').toLowerCase().trim();
      if (category !== 'hostel') {
        conn.release();
        return res.status(403).json({ success: false, error: 'Hostel Bank Details Certificate is only available for Hostel students.' });
      }

      conn.query(
        "SELECT id FROM hostel_bank_requests WHERE student_uid = ? AND academic_year = ? AND status != 'Rejected' LIMIT 1",
        [uid, currentAcademicYear],
        function (e2, existing) {
          if (existing && existing.length > 0) {
            conn.release();
            return res.status(400).json({ success: false, error: 'You have already applied for a Bank Details Certificate this academic year.' });
          }

          const formattedBranch = formatBranchForBonafide(student.dept);
          const insertSql = `
            INSERT INTO hostel_bank_requests 
              (student_uid, student_name, father_name, enrollment_no, branch, year, academic_year, 
               boarding_fee, mess_fee, total_fee, purpose, purpose_desc, status, request_date, 
               admin_remark, created_by_role, created_by_uid) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', UTC_TIMESTAMP(), ?, 'student', ?)`;

          conn.query(insertSql, [
            uid,
            student.sname,
            student.parentname || 'N/A',
            student.uid,
            formattedBranch,
            student.year,
            currentAcademicYear,
            feeBreakdown.boarding,
            feeBreakdown.mess,
            feeBreakdown.total,
            purpose,
            purposeDesc,
            adminRemark || null,
            uid
          ], function (insertErr, result) {
            if (insertErr) {
              conn.release();
              console.error('Failed to submit bank details request', insertErr);
              return res.status(500).json({ success: false, error: 'Failed to record request.' });
            }

            const requestId = result.insertId;
            logHostelBankAudit(conn, requestId, 'Created', null, 'Pending', student.sname, 'student', 'Initial request submitted by student via mobile', function (eAudit) {
              conn.release();
              if (eAudit) {
                console.error('Failed to write audit log', eAudit);
              }
              res.json({ success: true, message: 'Bank details request submitted successfully!' });
            });
          });
        }
      );
    });
  });
});

// --- MOBILE STUDENT BANK DETAILS CANCEL API ---
app.post('/api/mobile/v1/student/bank-details/:id/cancel', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const requestId = req.params.id;

  dbbconnection.getConnection(function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    conn.query(
      "UPDATE hostel_bank_requests SET status = 'Cancelled' WHERE id = ? AND student_uid = ? AND status = 'Pending'",
      [requestId, uid],
      function (qErr, result) {
        conn.release();
        if (qErr) return res.status(500).json({ success: false, error: 'Error cancelling request' });
        if (result.affectedRows === 0) {
          return res.status(400).json({ success: false, error: 'Request not found or cannot be cancelled' });
        }
        res.json({ success: true, message: 'Request cancelled successfully' });
      }
    );
  });
});

// --- MOBILE STUDENT PROFILE API ---
app.get('/api/mobile/v1/student/profile', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });

    loadFeatureFlagsMap(connection, function (_ffErr, flagsMap) {
      var sql = "SELECT * FROM studentdetails WHERE uid = ?";
      connection.query(sql, [uid], function (err, result) {
        if (err) {
          connection.release();
          return res.status(500).json({ success: false, error: 'Query failed' });
        }
        if (result.length === 0) {
          connection.release();
          return res.status(404).json({ success: false, error: 'Student not found' });
        }

        const student = result[0];
        attachStudentPhotoUrl(student);
        const profileEditEnabled = (flagsMap && flagsMap.student_profile_edit) ? !!flagsMap.student_profile_edit.enabled : true;

        // Fetch latest approved pass
        const todayIstDate = (formatDateToISTString(new Date()) || '').split(' ')[0];
        var latestApprovedSql = `SELECT requestid, uid, passtype, 
        DATE_FORMAT(expected_out, '%Y-%m-%d %H:%i:%s') as expected_out,
        DATE_FORMAT(expected_return, '%Y-%m-%d %H:%i:%s') as expected_return,
        reason, emergency_contact, status, approved_by,
        DATE_FORMAT(approved_at, '%Y-%m-%d %H:%i:%s') as approved_at,
        rejection_reason,
        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at,
        conversion_enabled, conversion_enabled_by
        FROM pass_requests 
        WHERE uid = ? 
          AND status = 'approved'
          AND DATE(approved_at) = ?
        ORDER BY approved_at DESC LIMIT 1`;
        connection.query(latestApprovedSql, [uid, todayIstDate], function (laErr, laResult) {
          connection.release();
          if (laErr) return res.status(500).json({ success: false, error: 'Query failed' });

          res.json({
            success: true,
            data: student,
            profileEditEnabled: profileEditEnabled,
            latestApprovedPass: laResult.length > 0 ? laResult[0] : null
          });
        });
      });
    });
  });
});

app.put('/api/mobile/v1/student/profile', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const sname = (req.body.sname || '').trim();
  const email = (req.body.email || '').trim();
  const gender = (req.body.gender || '').trim();
  const dob = (req.body.dob || '').trim();
  const year = (req.body.year || '').trim();
  const academicyear = (req.body.academicyear || '').trim();
  const address = (req.body.address || '').trim();
  const parentname = (req.body.parentname || '').trim();
  const parentnumber = (req.body.parentnumber || '').trim();
  const newPassword = req.body.new_password ? String(req.body.new_password).trim() : null;

  if (!sname || !email) {
    return res.status(400).json({ success: false, error: 'Please fill required fields (Name and Email).' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection error' });

    loadFeatureFlagsMap(connection, function (_ffErr, flagsMap) {
      const profileEditEnabled = (flagsMap && flagsMap.student_profile_edit) ? !!flagsMap.student_profile_edit.enabled : true;
      if (!profileEditEnabled) {
        connection.release();
        return res.status(403).json({ success: false, error: 'Profile editing is currently disabled by admin.' });
      }

      const executeUpdate = (hashedPassword) => {
        let sql = `UPDATE studentdetails
          SET sname = ?, email = ?, gender = ?, dob = ?, year = ?, academicyear = ?, address = ?, parentname = ?, parentnumber = ?`;
        const params = [sname, email, gender, dob, year, academicyear, address, parentname, parentnumber];

        if (hashedPassword) {
          sql += `, password = ?`;
          params.push(hashedPassword);
        }

        sql += ` WHERE uid = ?`;
        params.push(uid);

        connection.query(sql, params, function (qErr) {
          connection.release();
          if (qErr) {
            console.error('Mobile student updateprofile failed:', qErr);
            return res.status(500).json({ success: false, error: 'Could not update profile.' });
          }
          res.json({ success: true, message: 'Profile updated successfully.' });
        });
      };

      if (newPassword) {
        bcrypt.hash(newPassword, 10, function (hashErr, hash) {
          if (hashErr) {
            connection.release();
            return res.status(500).json({ success: false, error: 'Password hashing failed.' });
          }
          executeUpdate(hash);
        });
      } else {
        executeUpdate(null);
      }
    });
  });
});

app.post('/api/mobile/v1/student/changepassword', express.json(), verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const { currentPassword, newPassword, confirmPassword } = req.body;

  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.status(400).json({ success: false, error: 'All password fields are required.' });
  }

  if (newPassword !== confirmPassword) {
    return res.status(400).json({ success: false, error: 'New passwords do not match.' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ success: false, error: 'Password must be at least 6 characters.' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) {
      return res.status(500).json({ success: false, error: 'Database connection error.' });
    }

    connection.query("SELECT * FROM studentdetails WHERE uid = ?", [uid], async function (qErr, result) {
      if (qErr) {
        connection.release();
        return res.status(500).json({ success: false, error: 'Database query failed.' });
      }
      if (!result || result.length === 0) {
        connection.release();
        return res.status(404).json({ success: false, error: 'Student not found.' });
      }

      try {
        const student = result[0];
        const storedPassword = student.password || student.mobileno;

        let passwordMatch = false;
        if (student.password && student.password.startsWith('$2')) {
          passwordMatch = await bcrypt.compare(currentPassword, student.password);
        } else {
          passwordMatch = currentPassword === storedPassword;
        }

        if (!passwordMatch) {
          connection.release();
          return res.status(401).json({ success: false, error: 'Incorrect current password.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        connection.query("UPDATE studentdetails SET password = ? WHERE uid = ?", [hashedPassword, uid], function (updErr) {
          connection.release();
          if (updErr) {
            return res.status(500).json({ success: false, error: 'Error updating password.' });
          }
          res.json({ success: true, message: 'Password updated successfully.' });
        });
      } catch (errEx) {
        connection.release();
        console.error("Change Password exception:", errEx);
        return res.status(500).json({ success: false, error: 'Internal server error: ' + errEx.message });
      }
    });
  });
});


// --- MOBILE STUDENT GET MESS DATA API ---
app.get('/api/mobile/v1/student/mess', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;

  dbbconnection.getConnection(async function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed' });

    try {
      const queryAsync = (sql, args) => new Promise((resolve, reject) => {
        conn.query(sql, args, (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      const weeklyMenu = await queryAsync('SELECT * FROM weekly_default_menu', []);
      const weeklyOptionalMenu = await queryAsync('SELECT * FROM weekly_optional_menu', []);

      const studentSelections = await queryAsync(
        "SELECT id, student_id, selected_food, selection_type, DATE_FORMAT(selection_date, '%Y-%m-%d') AS selection_date, meal_type, selection_locked FROM mess_selections WHERE student_id = ?",
        [uid]
      );

      const studentDetails = await queryAsync("SELECT uid, sname, mess_type, category FROM studentdetails WHERE uid = ?", [uid]);
      const student = studentDetails.length > 0 ? studentDetails[0] : null;

      let openTime = "09:00";
      let closeTime = "16:00";
      try {
        const flags = await queryAsync("SELECT feature_key, value_int, value_str FROM feature_flags WHERE feature_key IN ('mess_open_hour','mess_close_hour')", []);
        (flags || []).forEach(r => {
          if (r.feature_key === 'mess_open_hour') {
            openTime = r.value_str || (r.value_int !== null ? String(r.value_int).padStart(2, '0') + ':00' : '09:00');
          }
          if (r.feature_key === 'mess_close_hour') {
            closeTime = r.value_str || (r.value_int !== null ? String(r.value_int).padStart(2, '0') + ':00' : '16:00');
          }
        });
      } catch (flagErr) {}

      const specialFoodItems = await queryAsync('SELECT * FROM special_food_items WHERE is_active = 1 ORDER BY created_at DESC', []);
      const studentSpecialRequests = await queryAsync(`
        SELECT r.*, i.food_name, i.quantity_desc, i.price_per_day, i.availability
        FROM special_food_requests r
        JOIN special_food_items i ON r.special_food_id = i.id
        WHERE r.student_id = ?
        ORDER BY r.requested_at DESC
      `, [uid]);

      conn.release();

      const now = new Date();
      const today = now.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
      const tmrw = new Date(now);
      tmrw.setDate(tmrw.getDate() + 1);
      const tomorrow = tmrw.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

      const days = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
      const todayName = days[now.getDay()];
      const tmrwName = days[tmrw.getDay()];

      res.json({
        success: true,
        data: {
          student,
          weeklyMenu: weeklyMenu || [],
          weeklyOptionalMenu: weeklyOptionalMenu || [],
          studentSelections: studentSelections || [],
          today,
          tomorrow,
          todayName,
          tmrwName,
          messOpenTime: openTime,
          messCloseTime: closeTime,
          specialFoodItems: specialFoodItems || [],
          studentSpecialRequests: studentSpecialRequests || []
        }
      });

    } catch (e) {
      conn.release();
      console.error('Error fetching mobile student mess details:', e);
      res.status(500).json({ success: false, error: 'Server error fetching mess details' });
    }
  });
});

// --- MOBILE STUDENT SUBMIT SELECTION API ---
app.post('/api/mobile/v1/student/mess', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const { meal_type, selection_date, selected_food } = req.body;

  if (!meal_type || !selection_date || !selected_food) {
    return res.status(400).json({ success: false, error: 'Meal type, date, and selected food are required' });
  }

  const nowKolkata = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));
  const currentHour = String(nowKolkata.getHours()).padStart(2, '0');
  const currentMinute = String(nowKolkata.getMinutes()).padStart(2, '0');
  const currentTimeStr = `${currentHour}:${currentMinute}`;

  dbbconnection.getConnection(async function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed' });

    try {
      const queryAsync = (sql, args) => new Promise((resolve, reject) => {
        conn.query(sql, args, (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      let openTime = "09:00";
      let closeTime = "16:00";
      try {
        const flags = await queryAsync("SELECT feature_key, value_int, value_str FROM feature_flags WHERE feature_key IN ('mess_open_hour','mess_close_hour')", []);
        (flags || []).forEach(r => {
          if (r.feature_key === 'mess_open_hour') {
            openTime = r.value_str || (r.value_int !== null ? String(r.value_int).padStart(2, '0') + ':00' : '09:00');
          }
          if (r.feature_key === 'mess_close_hour') {
            closeTime = r.value_str || (r.value_int !== null ? String(r.value_int).padStart(2, '0') + ':00' : '16:00');
          }
        });
      } catch (flagErr) {}

      if (currentTimeStr < openTime || currentTimeStr >= closeTime) {
        conn.release();
        return res.status(400).json({ success: false, error: `Meal selection is only open between ${openTime} and ${closeTime}.` });
      }

      const rows = await queryAsync(
        'SELECT selection_locked FROM mess_selections WHERE student_id=? AND meal_type=? AND selection_date=?',
        [uid, meal_type, selection_date]
      );
      if (rows.length > 0 && rows[0].selection_locked) {
        conn.release();
        return res.status(400).json({ success: false, error: "Your meal selection has already been locked." });
      }

      let type = (selected_food === 'DEFAULT') ? 'DEFAULT' : 'OPTIONAL';
      await queryAsync(
        'INSERT INTO mess_selections (student_id, selected_food, selection_type, selection_date, meal_type, selection_locked) VALUES (?, ?, ?, ?, ?, TRUE) ON DUPLICATE KEY UPDATE selected_food=?, selection_type=?, selection_locked=TRUE',
        [uid, selected_food, type, selection_date, meal_type, selected_food, type]
      );

      conn.release();
      res.json({ success: true, message: 'Selection saved successfully!' });

    } catch (e) {
      conn.release();
      console.error('Error submitting mobile student mess selection:', e);
      res.status(500).json({ success: false, error: 'Server error submitting selection' });
    }
  });
});

// --- MOBILE STUDENT SPECIAL FOOD REQUEST API ---
app.post('/api/mobile/v1/student/special-food/request', verifyMobileStudentJwt, function (req, res) {
  const uid = req.studentUid;
  const { special_food_id, quantity_multiplier, duration_days, obtain_time } = req.body;

  if (!special_food_id || !obtain_time) {
    return res.status(400).json({ success: false, error: 'Special food ID and obtain time slot are required' });
  }

  dbbconnection.getConnection(async function (err, conn) {
    if (err) return res.status(500).json({ success: false, error: 'Database connection failed' });

    try {
      const queryAsync = (sql, args) => new Promise((resolve, reject) => {
        conn.query(sql, args, (err, rows) => {
          if (err) reject(err);
          else resolve(rows);
        });
      });

      const items = await queryAsync('SELECT * FROM special_food_items WHERE id=? AND is_active=1', [special_food_id]);
      if (items.length === 0) {
        conn.release();
        return res.status(400).json({ success: false, error: 'Invalid or inactive food item' });
      }
      const item = items[0];

      const validSlot = obtain_time === item.availability || item.availability === 'both' || obtain_time === 'both';
      if (!validSlot) {
        conn.release();
        return res.status(400).json({ success: false, error: 'Selected time slot is not available for this item' });
      }
      const finalObtainTime = item.availability !== 'both' ? item.availability : obtain_time;

      const timeMultiplier = (finalObtainTime === 'both') ? 2 : 1;
      const totalPrice = parseFloat(item.price_per_day) * timeMultiplier * parseInt(quantity_multiplier || 1) * parseInt(duration_days || 1);
      const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

      const existing = await queryAsync(
        'SELECT id FROM special_food_requests WHERE student_id=? AND special_food_id=? AND (status="pending" OR (status="approved" AND ? BETWEEN start_date AND end_date))',
        [uid, special_food_id, today]
      );
      if (existing.length > 0) {
        conn.release();
        return res.status(400).json({ success: false, error: 'You already have a pending or active request for this item' });
      }

      await queryAsync(
        'INSERT INTO special_food_requests (student_id, special_food_id, quantity_multiplier, duration_days, obtain_time, total_price) VALUES (?, ?, ?, ?, ?, ?)',
        [uid, special_food_id, quantity_multiplier || 1, duration_days || 1, finalObtainTime, totalPrice]
      );

      conn.release();
      res.json({ success: true, message: 'Special food request submitted successfully! Awaiting approval.' });

    } catch (e) {
      conn.release();
      console.error('Error submitting mobile student special food request:', e);
      res.status(500).json({ success: false, error: 'Server error submitting request' });
    }
  });
});

// --- MOBILE STUDENT COMPLAINT POST API WITH OPTIONAL IMAGE UPLOAD ---
app.post('/api/mobile/v1/student/complain', verifyMobileStudentJwt, function (req, res) {
  uploadComplainImage.single('complain_image')(req, res, function (err) {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' 
        ? 'Image must be under 5MB.' 
        : (err.message || 'Invalid image file. Use JPEG, PNG, GIF or WebP.');
      return res.status(400).json({ success: false, error: msg });
    }

    const { category, description } = req.body;
    const uid = req.studentUid;
    const imagePath = req.file ? '/uploads/complaints/' + req.file.filename : null;

    if (!category || !description) {
      return res.status(400).json({ success: false, error: 'Category and description are required.' });
    }

    dbbconnection.getConnection(function (connErr, connection) {
      if (connErr) {
        console.error('Database connection error:', connErr);
        return res.status(500).json({ success: false, error: 'Database connection failed.' });
      }

      const sqlWithImage = 'INSERT INTO complaints (student_uid, description, category, image_path) VALUES (?, ?, ?, ?)';
      const sqlWithoutImage = 'INSERT INTO complaints (student_uid, description, category) VALUES (?, ?, ?)';

      function done(insertErr) {
        connection.release();
        if (insertErr) {
          console.error('Error submitting complaint:', insertErr);
          return res.status(500).json({ success: false, error: 'Error submitting complaint: ' + insertErr.message });
        }
        res.json({ success: true, message: 'Complaint submitted successfully!' });
      }

      connection.query(sqlWithImage, [uid, description, category, imagePath], function (qErr, result) {
        if (qErr && qErr.errno === 1054 && qErr.sqlMessage && String(qErr.sqlMessage).indexOf('image_path') !== -1) {
          return connection.query(sqlWithoutImage, [uid, description, category], function (qErr2) {
            done(qErr2);
          });
        }
        done(qErr);
      });
    });
  });
});

app.get('/api/mobile/v1/student/:uid', express.json(), function (req, res) {
  const uid = req.params.uid;
  if (!uid || uid.length !== 8) {
    return res.status(400).json({ success: false, error: 'Invalid UID' });
  }

  dbbconnection.getConnection(function (err, connection) {
    if (err) return res.status(500).json({ success: false, error: 'DB connection error' });

    var sql = "SELECT sname, dept, year, uid, path FROM studentdetails WHERE uid = ?";
    connection.query(sql, [uid], function (err, result) {
      connection.release();
      if (err) return res.status(500).json({ success: false, error: 'Query failed' });

      if (result.length > 0) {
        attachStudentPhotoUrl(result[0]);
        res.json({ success: true, data: result[0] });
      } else {
        res.status(404).json({ success: false, error: 'Student not found' });
      }
    });
  });
});



app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} (0.0.0.0)`);
  // Ensure complaints.image_path column exists so uploaded images can be stored and shown
  dbbconnection.getConnection(function (err, conn) {
    if (err) return;
    conn.query("SHOW COLUMNS FROM complaints LIKE 'image_path'", function (e, rows) {
      if (e) { conn.release(); return; }
      if (rows && rows.length > 0) { conn.release(); return; }
      conn.query("ALTER TABLE complaints ADD COLUMN image_path VARCHAR(500) DEFAULT NULL", function (alterErr) {
        conn.release();
        if (!alterErr) console.log("Added complaints.image_path column.");
        else if (alterErr.code !== "ER_DUP_FIELDNAME") console.warn("Could not add complaints.image_path:", alterErr.message);
      });
    });
  });
  // Ensure complaints.status ENUM includes 'denied' so deny-complain can save as denied
  dbbconnection.getConnection(function (err, conn) {
    if (err) return;
    conn.query("ALTER TABLE complaints MODIFY COLUMN status ENUM('pending_approval','approved','resolved','denied') DEFAULT 'pending_approval'", function (e) {
      conn.release();
      if (!e) console.log("Complaints status ENUM includes 'denied'.");
      else if (e.code !== "ER_DUP_FIELDNAME") console.warn("Could not update complaints.status ENUM:", e.message);
    });
  });
});
//process.env.PORT






module.exports = app;
