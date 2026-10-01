const express = require('express');
const router = express.Router();
const dbbconnection = require('../server');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

let _photoIndex = null;

function _normKey(str) {
    return String(str || '').toLowerCase().replace(/\s+/g, ' ').trim();
}

function _wordsOf(base) {
    return base.replace(/\.[^.]+$/, '').replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
}

function buildPhotoIndex() {
    const idx = Object.create(null);
    const picsRoot = path.join(__dirname, '../public/images/student_pics');
    if (!fs.existsSync(picsRoot)) return idx;
    let yearDirs = [];
    try {
        yearDirs = fs.readdirSync(picsRoot, { withFileTypes: true })
            .filter(e => e.isDirectory())
            .map(e => e.name)
            .sort((a, b) => b.localeCompare(a, undefined, { numeric: true, sensitivity: 'base' }));
    } catch (_) { return idx; }

    for (const yearDir of yearDirs) {
        const yearPath = path.join(picsRoot, yearDir);
        let files = [];
        try { files = fs.readdirSync(yearPath); } catch (_) { continue; }
        for (const filename of files) {
            if (!/\.(jpg|jpeg|png|webp|gif)$/i.test(filename)) continue;
            const webPath = '/images/student_pics/' + yearDir + '/' + filename;
            const entry = { yearDir, filename, webPath };
            const words = _wordsOf(filename);
            if (!words.length) continue;
            
            const fullKey = _normKey(words.join(' '));
            if (!idx[fullKey]) idx[fullKey] = entry;
            
            if (words.length >= 3) {
                const flKey = _normKey(words[0] + ' ' + words[words.length - 1]);
                if (!idx[flKey]) idx[flKey] = entry;
            }
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

function resolveStudentPhotoUrl(student) {
    if (!student) return '/images/blank_profile.webp';
    
    let rawUrl = (student.path || student.photo || student.student_photo_path || student.image_path || student.image || '').toString().trim();
    if (rawUrl && rawUrl !== '0' && rawUrl !== 'null') {
        if (/^https?:\/\//i.test(rawUrl) || rawUrl.startsWith('data:')) {
            return rawUrl;
        }
        if (!rawUrl.startsWith('/')) {
            rawUrl = '/' + rawUrl;
        }
        const diskPath = path.join(__dirname, '../public', rawUrl);
        if (fs.existsSync(diskPath)) {
            return rawUrl;
        }
    }

    const idx = getPhotoIndex();
    const sname = ((student && (student.sname || student.name)) || '').toString().trim();
    const uid = ((student && (student.uid || student.student_uid || student.UID)) || '').toString().trim();

    if (sname) {
        const words = sname.replace(/\s+/g, ' ').trim().split(' ').filter(Boolean);
        const fullKey = _normKey(sname);
        const firstLastKey = words.length >= 2 ? _normKey(words[0] + ' ' + words[words.length - 1]) : null;

        if (idx[fullKey]) return idx[fullKey].webPath;
        if (firstLastKey && idx[firstLastKey]) return idx[firstLastKey].webPath;
        for (let i = 0; i < words.length - 1; i++) {
            const pairKey = _normKey(words[i] + ' ' + words[i + 1]);
            if (idx[pairKey]) return idx[pairKey].webPath;
        }
        if (uid && idx[_normKey(uid)]) return idx[_normKey(uid)].webPath;
    }

    return (rawUrl && rawUrl !== '/0' && rawUrl !== '/') ? rawUrl : '/images/blank_profile.webp';
}

const dayOrder = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];

// Role Middleware for Mess
function requireRole(...roles) {
    return (req, res, next) => {
        const tokenadmin = req.cookies.jwt;
        if (!tokenadmin) return res.redirect('/loginpanel');
        try {
            const jwt = require('jsonwebtoken');
            const decode = jwt.verify(tokenadmin, 'secretkeysvpcet');
            if (roles.includes(decode.role)) {
                req.decode = decode;
                return next();
            }
            return res.status(403).send('Forbidden: Access Denied');
        } catch (err) {
            return res.redirect('/loginpanel');
        }
    };
}


// Helper to get student UID from token
// Cookie: 'studentjwt', Secret: 'studentsecretkeysvpcet', payload field: uid
const STUDENT_JWT_SECRET = 'studentsecretkeysvpcet';
function getStudentUid(req) {
    const token = req.cookies && req.cookies.studentjwt;
    if (token) {
        try {
            const decoded = jwt.verify(token, STUDENT_JWT_SECRET);
            return decoded.uid || decoded.id || decoded.studentUid || null;
        } catch(e) { }
    }
    return null;
}
// SECURITY/PRIVACY NOTE: The `fetchAllMealSelections` function returns a full roster of every student's
// food selections. This roster MUST ONLY be exposed to Super Admin, Kitchen, and Admin Review roles.
// It should NEVER be exposed on the student's own view to protect student privacy.

function formatTimeTo12Hour(timeStr) {
    if (!timeStr) return '';
    const parts = timeStr.split(':');
    let hour = parseInt(parts[0]);
    const min = parts[1] || '00';
    const ampm = hour >= 12 ? 'PM' : 'AM';
    hour = hour % 12;
    hour = hour ? hour : 12; // the hour '0' should be '12'
    return `${hour}:${min} ${ampm}`;
}

// Helper: read mess selection open/close times from feature_flags table
// Returns { openTime, closeTime } – defaults to "09:00" and "16:00" if not configured
async function getMessHours(conn) {
    try {
        const [rows] = await conn.promise().query(
            "SELECT feature_key, value_int, value_str FROM feature_flags WHERE feature_key IN ('mess_open_hour','mess_close_hour')"
        );
        let openTime = "09:00";
        let closeTime = "16:00";
        (rows || []).forEach(r => {
            if (r.feature_key === 'mess_open_hour') {
                openTime = r.value_str || (r.value_int !== null ? String(r.value_int).padStart(2, '0') + ':00' : '09:00');
            }
            if (r.feature_key === 'mess_close_hour') {
                closeTime = r.value_str || (r.value_int !== null ? String(r.value_int).padStart(2, '0') + ':00' : '16:00');
            }
        });
        return { openTime, closeTime };
    } catch(e) {
        // If columns don't exist yet, fall back to defaults
        return { openTime: "09:00", closeTime: "16:00" };
    }
}
async function fetchAllMealSelections(date, conn, mealTypeFilter = null) {
    // Only fetch ACTIVE students (exclude Inactive/Restricted)
    const [students] = await conn.promise().query(
        "SELECT uid, sname, room_no, mobileno, dept, mess_type, path FROM studentdetails WHERE IFNULL(status,'') NOT IN ('Inactive','Restricted') AND category = 'Hostel'"
    );
    const [selections] = await conn.promise().query(
        "SELECT id, student_id, selected_food, selection_type, DATE_FORMAT(selection_date, '%Y-%m-%d') AS selection_date, meal_type, selection_locked FROM mess_selections WHERE DATE(selection_date) = ?", [date]
    );

    // Get weekly default menu to map default food name
    const [yr, mo, dy] = date.split('-').map(Number);
    const targetDateObj = new Date(yr, mo - 1, dy);
    const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const weekdayName = dayNames[targetDateObj.getDay()];

    const [weeklyMenu] = await conn.promise().query('SELECT * FROM weekly_default_menu');
    const defaultMenuMap = {};
    weeklyMenu.forEach(m => {
        if (m.weekday === weekdayName) {
            defaultMenuMap[m.meal_type] = m.food_name;
        }
    });

    // Index selections by [meal_type][student_id] – keep latest per (student, meal)
    const selMap = {};
    ['breakfast', 'lunch', 'dinner'].forEach(m => { selMap[m] = {}; });
    selections.forEach(s => {
        const mt = s.meal_type || 'breakfast';
        if (!selMap[mt]) selMap[mt] = {};
        const existing = selMap[mt][s.student_id];
        if (!existing || new Date(s.updated_at) >= new Date(existing.updated_at)) {
            selMap[mt][s.student_id] = s;
        }
    });

    // Fetch approved special food for this date
    const [specialRows] = await conn.promise().query(`
        SELECT r.student_id, i.food_name as special_food_name, r.obtain_time
        FROM special_food_requests r
        JOIN special_food_items i ON r.special_food_id = i.id
        WHERE r.status = 'approved'
        AND ? BETWEEN r.start_date AND r.end_date
    `, [date]);
    const specialMap = {}; // student_id -> { special_food_name, obtain_time }
    specialRows.forEach(r => { specialMap[r.student_id] = r; });

    // Count specials (filtered by mealTypeFilter)
    const specialCountParams = [date, date];
    let specialCountQuery = `
        SELECT COUNT(DISTINCT r.student_id) as cnt
        FROM special_food_requests r
        WHERE r.status = 'approved'
        AND ? >= r.start_date AND ? <= r.end_date`;
    if (mealTypeFilter) {
        const slot = (mealTypeFilter === 'dinner') ? 'night' : 'day';
        specialCountQuery += ` AND (r.obtain_time = ? OR r.obtain_time = 'both')`;
        specialCountParams.push(slot);
    }
    const [specialRes] = await conn.promise().query(specialCountQuery, specialCountParams);

    const stats = {
        total: students.length,
        defaultCnt: 0,
        optionalCnt: 0,
        specialCnt: specialRes[0].cnt,
        present: 0,
        foodBreakdown: {}
    };

    const [attendances] = await conn.promise().query(
        'SELECT student_id, meal_type, scanned_at FROM meal_attendance WHERE meal_date = ?', [date]
    );
    const attendanceMap = {};
    attendances.forEach(a => {
        if (!attendanceMap[a.meal_type]) attendanceMap[a.meal_type] = {};
        attendanceMap[a.meal_type][a.student_id] = a.scanned_at;
    });

    // Always process all 3 meal types for groupedObj so Current Selections shows Breakfast, Lunch, and Dinner
    const allMealTypes = ['breakfast', 'lunch', 'dinner'];
    const mealTypesToProcess = mealTypeFilter ? [mealTypeFilter] : allMealTypes;

    // Grouped structure: fbKey -> { meal_type, food_name, type, students[] }
    const groupedObj = {};
    const pendingMap = {};

    students.forEach(st => {
        // Set meal_status for allStudents display (for the filtered meal)
        if (mealTypeFilter) {
            const sp = specialMap[st.uid];
            const sel = selMap[mealTypeFilter][st.uid];
            const slotOk = sp && (
                sp.obtain_time === 'both' ||
                (mealTypeFilter === 'dinner' ? sp.obtain_time === 'night' : sp.obtain_time === 'day')
            );
            if (slotOk) {
                st.meal_status = sp.special_food_name + ' (Special)';
            } else if (sel && sel.selection_type === 'OPTIONAL') {
                st.meal_status = sel.selected_food;
            } else if (sel && sel.selection_type === 'DEFAULT') {
                st.meal_status = sel.selected_food;
            } else {
                st.meal_status = defaultMenuMap[mealTypeFilter] || 'DEFAULT MENU';
            }
        } else {
            st.meal_status = '-';
        }

        allMealTypes.forEach(mt => {
            const sel = selMap[mt][st.uid];
            const sp = specialMap[st.uid];
            const slotOk = sp && (
                sp.obtain_time === 'both' ||
                (mt === 'dinner' ? sp.obtain_time === 'night' : sp.obtain_time === 'day')
            );

            // Regular meal choice: Optional vs Default (Special food does not reduce default or optional counts)
            let foodLabel, selType;
            if (sel) {
                const isExplicitOptional = sel.selection_type && sel.selection_type.toUpperCase() === 'OPTIONAL';
                const defaultFoodName = defaultMenuMap[mt];
                const isDifferentFromDefault = defaultFoodName && sel.selected_food && (sel.selected_food.trim().toLowerCase() !== defaultFoodName.trim().toLowerCase()) && sel.selected_food !== 'DEFAULT';

                if (isExplicitOptional || isDifferentFromDefault) {
                    foodLabel = sel.selected_food;
                    selType = 'OPTIONAL';
                } else {
                    foodLabel = defaultFoodName || (sel.selected_food === 'DEFAULT' ? 'DEFAULT MENU' : sel.selected_food);
                    selType = 'DEFAULT';
                }
            } else {
                foodLabel = defaultMenuMap[mt] || 'DEFAULT MENU';
                selType = 'DEFAULT';
            }

            const fbKey = mt + '|' + foodLabel;
            if (!groupedObj[fbKey]) {
                groupedObj[fbKey] = { meal_type: mt, food_name: foodLabel, type: selType, students: [] };
            }
            groupedObj[fbKey].students.push({
                student_uid: st.uid,
                student_name: st.sname,
                room_number: st.room_no,
                phone_number: st.mobileno,
                meal_type: mt,
                has_scanned: (typeof attendanceMap !== 'undefined' && attendanceMap[mt] && attendanceMap[mt][st.uid]) ? true : false
            });

            const fbStat = mt + '|' + foodLabel;
            if (!stats.foodBreakdown[fbStat]) {
                stats.foodBreakdown[fbStat] = { meal_type: mt, food_name: foodLabel, type: selType, cnt: 0, scannedCnt: 0 };
            }
            stats.foodBreakdown[fbStat].cnt++;
            if (typeof attendanceMap !== 'undefined' && attendanceMap[mt] && attendanceMap[mt][st.uid]) {
                stats.foodBreakdown[fbStat].scannedCnt++;
            }
            if (!mealTypeFilter || mt === mealTypeFilter) {
                stats.present++;
            }
        });
    });

    // Count each student AT MOST ONCE toward optionalCnt if they selected OPTIONAL for any meal in scope
    const optionalStudentUids = new Set();
    students.forEach(st => {
        mealTypesToProcess.forEach(mt => {
            const sel = selMap[mt][st.uid];
            if (sel) {
                const isExplicitOptional = sel.selection_type && sel.selection_type.toUpperCase() === 'OPTIONAL';
                const defaultFoodName = defaultMenuMap[mt];
                const isDifferentFromDefault = defaultFoodName && sel.selected_food && (sel.selected_food.trim().toLowerCase() !== defaultFoodName.trim().toLowerCase()) && sel.selected_food !== 'DEFAULT';

                if (isExplicitOptional || isDifferentFromDefault) {
                    optionalStudentUids.add(st.uid);
                }
            }
        });
    });

    stats.optionalCnt = optionalStudentUids.size;
    stats.defaultCnt = Math.max(0, students.length - stats.optionalCnt);

    const grouped = Object.values(groupedObj);
    const pendingStudents = Object.values(pendingMap);
    return { grouped, stats, pendingStudents, allStudents: students };
}

async function fetchSpecialFoodData(uid, role, conn) {
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const [items] = await conn.promise().query('SELECT * FROM special_food_items ORDER BY created_at DESC');
    
    let pendingRequests = [];
    let approvedRequests = [];
    let studentRequests = [];
    let todayAttendance = [];
    
    if (role === 'Student') {
        const [reqs] = await conn.promise().query(`
            SELECT r.*, i.food_name, i.quantity_desc, i.price_per_day, i.availability
            FROM special_food_requests r
            JOIN special_food_items i ON r.special_food_id = i.id
            WHERE r.student_id = ?
            ORDER BY r.requested_at DESC
        `, [uid]);
        studentRequests = reqs;
    } else {
        const [allReqs] = await conn.promise().query(`
            SELECT r.*, i.food_name, i.quantity_desc, i.price_per_day, s.uid as student_uid, s.sname, s.room_no, s.mobileno as phone_number, s.dept
            FROM special_food_requests r
            JOIN special_food_items i ON r.special_food_id = i.id
            JOIN studentdetails s ON r.student_id = s.uid
            WHERE s.category = 'Hostel'
            ORDER BY r.requested_at DESC
        `);
        pendingRequests = allReqs.filter(r => r.status === 'pending');
        // A request is valid if today's date is between start_date and end_date (inclusive)
        approvedRequests = allReqs.filter(r => {
            if (r.status !== 'approved' || !r.start_date || !r.end_date) return false;
            // Dates from DB might be midnight UTC, string comparison works well with en-CA format YYYY-MM-DD
            const sDate = new Date(r.start_date).toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
            const eDate = new Date(r.end_date).toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
            return today >= sDate && today <= eDate;
        });
        
        const [att] = await conn.promise().query(`
            SELECT a.*, r.special_food_id, i.food_name
            FROM special_food_attendance a
            JOIN special_food_requests r ON a.special_food_request_id = r.id
            JOIN special_food_items i ON r.special_food_id = i.id
            WHERE a.attendance_date = ?
        `, [today]);
        todayAttendance = att;
    }
    
    return {
        specialFoodItems: items,
        pendingSpecialRequests: pendingRequests,
        approvedSpecialRequests: approvedRequests,
        studentSpecialRequests: studentRequests,
        specialFoodAttendance: todayAttendance
    };
}

router.get('/admin/mess', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const tmrw = new Date(Date.now() + 86400000);
    const tomorrow = tmrw.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const targetDate = req.query.date || tomorrow;
    const mealType = req.query.meal_type || 'breakfast';
    
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const { grouped, stats, pendingStudents, allStudents } = await fetchAllMealSelections(targetDate, conn, mealType);
            
            // Fetch students with active special food approvals for targetDate
            let specialQuery = `
                SELECT DISTINCT s.uid, s.sname, s.room_no, s.mobileno, i.food_name as special_food_name
                FROM special_food_requests r
                JOIN studentdetails s ON r.student_id = s.uid
                JOIN special_food_items i ON r.special_food_id = i.id
                WHERE r.status = 'approved'
                AND ? >= r.start_date AND ? <= r.end_date
                AND s.category = 'Hostel'
            `;
            let specialParams = [targetDate, targetDate];
            const mappedTimeSlot = (mealType === 'dinner') ? 'night' : 'day';
            specialQuery += ` AND (r.obtain_time = ? OR r.obtain_time = 'both')`;
            specialParams.push(mappedTimeSlot);
            const [specialStudents] = await conn.promise().query(specialQuery, specialParams);
            
            conn.release();
            res.render('mess_main_dashboard', {
                message: '',
                targetDate: targetDate,
                mealType: mealType,
                grouped: grouped,
                stats: stats,
                pendingStudents: pendingStudents,
                allStudents: allStudents,
                specialStudents: specialStudents || [],
                role: req.decode ? req.decode.role : 'SuperID'
            });
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});

router.get('/admin/mess/menus', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const [weeklyMenu] = await conn.promise().query('SELECT * FROM weekly_default_menu');
            const [weeklyOptionalMenu] = await conn.promise().query('SELECT * FROM weekly_optional_menu');
            conn.release();
            res.render('mess_menus_editor', {
                message: '',
                weeklyMenu: weeklyMenu || [],
                weeklyOptionalMenu: weeklyOptionalMenu || [],
                dayOrder: dayOrder,
                role: req.decode ? req.decode.role : 'SuperID'
            });
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});
// ==========================================
// SPECIAL FOOD CRUD & REQUEST ROUTES
// ==========================================

router.post('/special-food/items/add', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { food_name, quantity_desc, price_per_day, availability, duration_days } = req.body;
    const created_by = (req.decode && req.decode.uid) ? req.decode.uid : ((req.decode && req.decode.id) ? req.decode.id : 'Admin');
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.redirect('/admin/mess/special-food?error=db_error');
        try {
            // Check for duplicates
            const [existing] = await conn.promise().query('SELECT id FROM special_food_items WHERE food_name = ? AND availability = ? AND is_active = 1', [food_name, availability]);
            if (existing.length > 0) {
                conn.release();
                return res.redirect('/admin/mess/special-food?error=duplicate_food');
            }
            await conn.promise().query(
                'INSERT INTO special_food_items (food_name, quantity_desc, duration_days, price_per_day, availability, created_by) VALUES (?, ?, ?, ?, ?, ?)',
                [food_name, quantity_desc, duration_days || 30, price_per_day, availability, created_by]
            );
            conn.release();
            res.redirect('/admin/mess/special-food?success=food_added');
        } catch(e) {
            const fs = require('fs');
            const path = require('path');
            const errorLogPath = path.join(process.cwd(), 'last_error.txt');
            fs.writeFileSync(errorLogPath, e.stack || e.toString());
            console.error('Error adding special food:', e);
            conn.release();
            res.redirect('/admin/mess/special-food?error=server_error');
        }
    });
});

router.post('/special-food/items/edit/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    const { food_name, quantity_desc, price_per_day, availability, duration_days } = req.body;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.redirect('/admin/mess/special-food?error=db_error');
        try {
            await conn.promise().query(
                'UPDATE special_food_items SET food_name=?, quantity_desc=?, duration_days=?, price_per_day=?, availability=? WHERE id=?',
                [food_name, quantity_desc, duration_days || 30, price_per_day, availability, id]
            );
            conn.release();
            res.redirect('/admin/mess/special-food?success=food_updated');
        } catch(e) {
            conn.release();
            res.redirect('/admin/mess/special-food?error=server_error');
        }
    });
});

router.post('/special-food/items/toggle/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.redirect('/admin/mess/special-food?error=db_error');
        try {
            await conn.promise().query('UPDATE special_food_items SET is_active = NOT is_active WHERE id=?', [id]);
            conn.release();
            res.redirect('/admin/mess/special-food?success=food_toggled');
        } catch(e) {
            conn.release();
            res.redirect('/admin/mess/special-food?error=server_error');
        }
    });
});

router.post('/special-food/requests/add', async (req, res) => {
    const uid = getStudentUid(req);
    if (!uid) return res.redirect('/student/login');
    const { special_food_id, quantity_multiplier, duration_days, obtain_time } = req.body;

    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.redirect('/student/mess?error=db_error');
        try {
            const [items] = await conn.promise().query('SELECT * FROM special_food_items WHERE id=? AND is_active=1', [special_food_id]);
            if (items.length === 0) {
                conn.release();
                return res.redirect('/student/mess?error=invalid_food');
            }
            const item = items[0];

            // Validate obtain_time against item's availability
            const validSlot = obtain_time === item.availability || item.availability === 'both' || obtain_time === 'both';
            if (!validSlot) {
                conn.release();
                return res.redirect('/student/mess?error=invalid_time_slot');
            }
            // Use the item's availability if student selected 'both' but item only allows one slot
            const finalObtainTime = item.availability !== 'both' ? item.availability : (obtain_time || item.availability);

            const timeMultiplier = (finalObtainTime === 'both') ? 2 : 1;
            const totalPrice = parseFloat(item.price_per_day) * timeMultiplier * parseInt(quantity_multiplier || 1) * parseInt(duration_days || 1);
            const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

            // Check for existing active/pending request for the same item
            const [existing] = await conn.promise().query(
                'SELECT id FROM special_food_requests WHERE student_id=? AND special_food_id=? AND (status="pending" OR (status="approved" AND ? BETWEEN start_date AND end_date))',
                [uid, special_food_id, today]
            );
            if (existing.length > 0) {
                conn.release();
                return res.redirect('/student/mess?error=duplicate_request');
            }

            await conn.promise().query(
                'INSERT INTO special_food_requests (student_id, special_food_id, quantity_multiplier, duration_days, obtain_time, total_price) VALUES (?, ?, ?, ?, ?, ?)',
                [uid, special_food_id, quantity_multiplier || 1, duration_days || 1, finalObtainTime, totalPrice]
            );
            conn.release();
            res.redirect('/student/mess?success=request_added');
        } catch(e) {
            conn.release();
            res.redirect('/student/mess?error=server_error');
        }
    });
});

router.post('/special-food/requests/approve/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    const { start_date } = req.body;
    const approved_by = req.decode ? req.decode.uid : 'Admin';
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.redirect('/admin/mess/dashboard?error=db_error');
        try {
            const [reqs] = await conn.promise().query('SELECT duration_days FROM special_food_requests WHERE id = ?', [id]);
            if (reqs.length === 0) {
                conn.release();
                return res.redirect('/admin/mess/dashboard?error=request_not_found');
            }
            const duration = reqs[0].duration_days || 1;
            const sDate = new Date(start_date);
            const eDate = new Date(start_date);
            eDate.setDate(sDate.getDate() + (duration - 1));
            
            const eDateStr = eDate.toISOString().split('T')[0];
            
            await conn.promise().query(
                'UPDATE special_food_requests SET status="approved", approved_by=?, approved_at=?, start_date=?, end_date=? WHERE id=?',
                [approved_by, new Date(), start_date, eDateStr, id]
            );
            conn.release();
            res.redirect('/admin/mess/special-food?success=request_approved');
        } catch(e) {
            conn.release();
            res.redirect('/admin/mess/special-food?error=server_error');
        }
    });
});

router.post('/special-food/requests/reject/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.redirect('/admin/mess/dashboard?error=db_error');
        try {
            await conn.promise().query(
                'UPDATE special_food_requests SET status="rejected" WHERE id=?',
                [id]
            );
            conn.release();
            res.redirect('/admin/mess/special-food?success=request_rejected');
        } catch(e) {
            conn.release();
            res.redirect('/admin/mess/special-food?error=server_error');
        }
    });
});

router.get('/admin/mess/special-food', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const msgMap = {
        food_added: 'Special food item added successfully.',
        food_updated: 'Special food item updated successfully.',
        food_toggled: 'Item status toggled.',
        request_approved: 'Request approved successfully.',
        request_rejected: 'Request rejected.',
        duplicate_food: 'An item with this name and availability already exists.',
        server_error: 'A server error occurred. Please try again.',
        db_error: 'Database connection error.'
    };
    const successKey = req.query.success;
    const errorKey = req.query.error;
    let message = '';
    if (successKey && msgMap[successKey]) message = `<i class="fas fa-check-circle me-2 text-success"></i>${msgMap[successKey]}`;
    else if (errorKey && msgMap[errorKey]) message = `<i class="fas fa-exclamation-circle me-2 text-danger"></i>${msgMap[errorKey]}`;

    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const [weeklyOptionalMenu] = await conn.promise().query('SELECT * FROM weekly_optional_menu');
            const specialFoodData = await fetchSpecialFoodData(null, 'Admin', conn);
            conn.release();
            res.render('mess_special_food_addons', {
                message: message,
                weeklyOptionalMenu: weeklyOptionalMenu || [],
                ...specialFoodData,
                role: req.decode ? req.decode.role : 'SuperID'
            });
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});

router.post('/admin/mess/edit-single', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const { meal_type, weekday, food_name, drink } = req.body;
    dbbconnection.getConnection((err, conn) => {
        if (err) return res.status(500).send("DB Error");
        conn.query('INSERT INTO weekly_default_menu (weekday, meal_type, food_name, drink) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE food_name=?, drink=?', 
        [weekday, meal_type, food_name, drink, food_name, drink], (err) => {
            conn.release();
            res.redirect('/admin/mess/menus');
        });
    });
});

router.post('/admin/mess/edit-full', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const meal_type = req.body.meal_type;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            for (let d of dayOrder) {
                let food = req.body['food_'+d];
                let drink = req.body['drink_'+d];
                if (food) {
                    await conn.promise().query('INSERT INTO weekly_default_menu (weekday, meal_type, food_name, drink) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE food_name=?, drink=?', 
                    [d, meal_type, food, drink, food, drink]);
                }
            }
        } catch(e) {}
        conn.release();
        res.redirect('/admin/mess/menus');
    });
});

router.post('/admin/mess/toggle-single', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const { meal_type, weekday, current_status } = req.body;
    const newStatus = current_status == '1' ? 0 : 1;
    dbbconnection.getConnection((err, conn) => {
        if (err) return res.status(500).send("DB Error");
        conn.query('UPDATE weekly_default_menu SET is_active=? WHERE weekday=? AND meal_type=?', [newStatus, weekday, meal_type], (err) => {
            conn.release();
            res.redirect('/admin/mess/menus');
        });
    });
});

router.post('/admin/mess/delete-single', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const { meal_type, weekday } = req.body;
    dbbconnection.getConnection((err, conn) => {
        if (err) return res.status(500).send("DB Error");
        conn.query('DELETE FROM weekly_default_menu WHERE weekday=? AND meal_type=?', [weekday, meal_type], (err) => {
            conn.release();
            res.redirect('/admin/mess/menus');
        });
    });
});

router.post('/admin/mess/edit-optional-single', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const { meal_type, weekday, veg_food, veg_drink, nonveg_food, nonveg_drink } = req.body;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            await conn.promise().query('DELETE FROM weekly_optional_menu WHERE weekday=? AND meal_type=?', [weekday, meal_type]);
            if (veg_food) {
                await conn.promise().query('INSERT INTO weekly_optional_menu (weekday, meal_type, food_type, food_name, drink) VALUES (?, ?, ?, ?, ?)', [weekday, meal_type, 'Veg', veg_food, veg_drink]);
            }
            if (nonveg_food) {
                await conn.promise().query('INSERT INTO weekly_optional_menu (weekday, meal_type, food_type, food_name, drink) VALUES (?, ?, ?, ?, ?)', [weekday, meal_type, 'Non-Veg', nonveg_food, nonveg_drink]);
            }
        } catch(e) {
            console.error(e);
        }
        conn.release();
        res.redirect('/admin/mess/menus');
    });
});

router.post('/admin/mess/edit-optional-full', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const meal_type = req.body.meal_type;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            for (let d of dayOrder) {
                let veg_food = req.body['veg_food_'+d];
                let veg_drink = req.body['veg_drink_'+d];
                let nonveg_food = req.body['nonveg_food_'+d];
                let nonveg_drink = req.body['nonveg_drink_'+d];
                
                await conn.promise().query('DELETE FROM weekly_optional_menu WHERE weekday=? AND meal_type=?', [d, meal_type]);
                if (veg_food) {
                    await conn.promise().query('INSERT INTO weekly_optional_menu (weekday, meal_type, food_type, food_name, drink) VALUES (?, ?, ?, ?, ?)', [d, meal_type, 'Veg', veg_food, veg_drink]);
                }
                if (nonveg_food) {
                    await conn.promise().query('INSERT INTO weekly_optional_menu (weekday, meal_type, food_type, food_name, drink) VALUES (?, ?, ?, ?, ?)', [d, meal_type, 'Non-Veg', nonveg_food, nonveg_drink]);
                }
            }
        } catch(e) {
            console.error(e);
        }
        conn.release();
        res.redirect('/admin/mess/menus');
    });
});

router.post('/admin/mess/toggle-optional-single', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const { meal_type, weekday, current_status } = req.body;
    const newStatus = current_status == '1' ? 0 : 1;
    dbbconnection.getConnection((err, conn) => {
        if (err) return res.status(500).send("DB Error");
        conn.query('UPDATE weekly_optional_menu SET is_active=? WHERE weekday=? AND meal_type=?', [newStatus, weekday, meal_type], (err) => {
            conn.release();
            res.redirect('/admin/mess/menus');
        });
    });
});

router.post('/admin/mess/delete-optional-single', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const { meal_type, weekday } = req.body;
    dbbconnection.getConnection((err, conn) => {
        if (err) return res.status(500).send("DB Error");
        conn.query('DELETE FROM weekly_optional_menu WHERE weekday=? AND meal_type=?', [weekday, meal_type], (err) => {
            conn.release();
            res.redirect('/admin/mess/menus');
        });
    });
});

router.get('/student/mess', async (req, res) => {
    const uid = getStudentUid(req);
    if (!uid) return res.redirect('/student/login');
    let message = req.query.msg === 'locked'
        ? '<i class="fas fa-lock me-2"></i>This selection is already locked and cannot be changed.'
        : '';
        
    // Handle error messages from special food requests
    if (req.query.error === 'db_error' || req.query.error === 'server_error') message = '<i class="fas fa-exclamation-triangle me-2"></i>Server error occurred.';
    else if (req.query.error === 'invalid_food') message = '<i class="fas fa-exclamation-circle me-2"></i>Invalid food item selected.';
    else if (req.query.error === 'invalid_time_slot') message = '<i class="fas fa-clock me-2"></i>Invalid time slot selected.';
    else if (req.query.error === 'duplicate_request') message = '<i class="fas fa-copy me-2"></i>You already have an active or pending request for this item.';
    
    // Handle success messages
    if (req.query.success === 'request_added') message = '<i class="fas fa-check-circle me-2"></i>Special food request submitted successfully.';
    
    const lockedMsg = message;
    const successMeal = req.query.success_meal || null;
    const successFood = req.query.success_food || null;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const [weeklyMenu] = await conn.promise().query('SELECT * FROM weekly_default_menu');
            const [weeklyOptionalMenu] = await conn.promise().query('SELECT * FROM weekly_optional_menu');
            const [studentSelections] = await conn.promise().query(
                "SELECT id, student_id, selected_food, selection_type, DATE_FORMAT(selection_date, '%Y-%m-%d') AS selection_date, meal_type, selection_locked FROM mess_selections WHERE student_id = ?",
                [uid]
            );
            const [studentDetailsRows] = await conn.promise().query(
                "SELECT * FROM studentdetails WHERE uid = ?", [uid]
            );
            const student = studentDetailsRows.length > 0 ? studentDetailsRows[0] : null;
            if (student && req.app.locals.attachStudentPhotoUrl) {
                req.app.locals.attachStudentPhotoUrl(student);
            } else if (student) {
                student.path = `/images/student_pics/${student.uid}.jpg`;
            }

            const now = new Date();
            const today = now.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
            const tmrw = new Date(now.getTime() + 86400000);
            const tomorrow = tmrw.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

            const days = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
            const [tYr, tMo, tDy] = today.split('-').map(Number);
            const todayName = days[new Date(tYr, tMo - 1, tDy).getDay()];
            const [tmYr, tmMo, tmDy] = tomorrow.split('-').map(Number);
            const tmrwName = days[new Date(tmYr, tmMo - 1, tmDy).getDay()];

            let todayDefaults = {};
            let tomorrowDefaults = {};
            (weeklyMenu || []).forEach(m => {
                if (m.weekday === todayName) todayDefaults[m.meal_type] = m;
                if (m.weekday === tmrwName) tomorrowDefaults[m.meal_type] = m;
            });

            // Read cutoff times from feature_flags
            const { openTime, closeTime } = await getMessHours(conn);

            const specialFoodData = await fetchSpecialFoodData(uid, 'Student', conn);
            conn.release();

            res.render('mess_student', {
                student: student,
                message: lockedMsg,
                successMeal: successMeal,
                successFood: successFood,
                weeklyMenu: weeklyMenu || [],
                weeklyOptionalMenu: weeklyOptionalMenu || [],
                todayDefaults: todayDefaults,
                tomorrowDefaults: tomorrowDefaults,
                studentSelections: studentSelections || [],
                today: today,
                tomorrow: tomorrow,
                tmrwName: tmrwName,
                role: 'Student',
                dayOrder: dayOrder,
                messOpenTime: openTime,
                messCloseTime: closeTime,
                ...specialFoodData
            });
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});

router.post('/student/mess', async (req, res) => {
    const uid = getStudentUid(req);
    if (!uid) return res.redirect('/student/login');
    const { meal_type, selection_date, selected_food } = req.body;

    const nowKolkata = new Date(new Date().toLocaleString("en-US", {timeZone: "Asia/Kolkata"}));
    const currentHour = String(nowKolkata.getHours()).padStart(2, '0');
    const currentMinute = String(nowKolkata.getMinutes()).padStart(2, '0');
    const currentTimeStr = `${currentHour}:${currentMinute}`;

    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).json({ success: false, message: "DB Error" });
        try {
            // Read cutoff times from feature_flags
            const { openTime, closeTime } = await getMessHours(conn);

            if (currentTimeStr < openTime) {
                conn.release();
                return res.status(400).json({ success: false, message: `Meal selection opens at ${formatTimeTo12Hour(openTime)}.` });
            }
            if (currentTimeStr >= closeTime) {
                conn.release();
                return res.status(400).json({ success: false, message: `Meal selection has closed at ${formatTimeTo12Hour(closeTime)}.` });
            }

            // Check if selection is already locked
            const [rows] = await conn.promise().query(
                'SELECT selection_locked FROM mess_selections WHERE student_id=? AND meal_type=? AND selection_date=?',
                [uid, meal_type, selection_date]
            );
            if (rows.length > 0 && rows[0].selection_locked) {
                conn.release();
                return res.status(400).json({ success: false, message: "Your meal selection has already been locked." });
            }

            let type = (selected_food === 'DEFAULT') ? 'DEFAULT' : 'OPTIONAL';
            await conn.promise().query(
                'INSERT INTO mess_selections (student_id, selected_food, selection_type, selection_date, meal_type, selection_locked) VALUES (?, ?, ?, ?, ?, TRUE) ON DUPLICATE KEY UPDATE selected_food=?, selection_type=?, selection_locked=TRUE',
                [uid, selected_food, type, selection_date, meal_type, selected_food, type]
            );
            conn.release();
            res.redirect(`/student/mess?success_meal=${encodeURIComponent(meal_type)}&success_food=${encodeURIComponent(selected_food)}`);
        } catch(e) {
            conn.release();
            return res.status(500).json({ success: false, message: "DB Error" });
        }
    });
});

async function getKitchenAttendanceAndLogs(conn) {
    try {
        const [totalVegRes] = await conn.promise().query(
            "SELECT COUNT(*) as count FROM studentdetails WHERE mess_type='Veg' AND category='Hostel' AND IFNULL(status,'') NOT IN ('Inactive','Restricted')"
        );
        const [totalNonVegRes] = await conn.promise().query(
            "SELECT COUNT(*) as count FROM studentdetails WHERE mess_type='Non-Veg' AND category='Hostel' AND IFNULL(status,'') NOT IN ('Inactive','Restricted')"
        );
        const [vegOutRes] = await conn.promise().query(
            "SELECT COUNT(*) as count FROM log_details1 log JOIN studentdetails stu ON stu.uid=log.uid WHERE stu.mess_type='Veg' AND stu.category='Hostel' AND log.hostelintime IS NULL AND log.passtype = 'Home Pass'"
        );
        const [nonVegOutRes] = await conn.promise().query(
            "SELECT COUNT(*) as count FROM log_details1 log JOIN studentdetails stu ON stu.uid=log.uid WHERE stu.mess_type='Non-Veg' AND stu.category='Hostel' AND log.hostelintime IS NULL AND log.passtype = 'Home Pass'"
        );

        const totalVeg = totalVegRes[0] ? (totalVegRes[0].count || 0) : 0;
        const totalNonVeg = totalNonVegRes[0] ? (totalNonVegRes[0].count || 0) : 0;
        const vegOut = vegOutRes[0] ? (vegOutRes[0].count || 0) : 0;
        const nonVegOut = nonVegOutRes[0] ? (nonVegOutRes[0].count || 0) : 0;

        const presentVeg = Math.max(0, totalVeg - vegOut);
        const presentNonVeg = Math.max(0, totalNonVeg - nonVegOut);

        const probableSql = `
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
          LEFT JOIN studentdetails stu ON stu.uid = out_students.uid AND stu.category = 'Hostel'
          GROUP BY future_dates.future_date
          ORDER BY future_dates.future_date ASC
        `;

        const [probableResults] = await conn.promise().query(probableSql, [presentVeg, presentNonVeg]);
        const probableLogs = (probableResults || []).map(row => ({
            date: row.future_date,
            veg: Number(row.veg_total) || 0,
            nonveg: Number(row.nonveg_total) || 0
        }));

        return { presentVeg, presentNonVeg, probableLogs };
    } catch(e) {
        console.error("Error in getKitchenAttendanceAndLogs:", e);
        return { presentVeg: 0, presentNonVeg: 0, probableLogs: [] };
    }
}

router.get('/kitchen', (req, res) => res.redirect('/kitchen/mess'));

router.get('/kitchen/mess', async (req, res) => {
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const tmrw = new Date(Date.now() + 86400000);
    const tomorrow = tmrw.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const targetDate = today;
    const mealType = req.query.meal_type || 'breakfast';
    
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const [weeklyMenu] = await conn.promise().query('SELECT * FROM weekly_default_menu');
            const [weeklyOptionalMenu] = await conn.promise().query('SELECT * FROM weekly_optional_menu');
            const { grouped, stats, pendingStudents } = await fetchAllMealSelections(targetDate, conn, mealType);
            const { presentVeg, presentNonVeg, probableLogs } = await getKitchenAttendanceAndLogs(conn);
            const specialFoodData = await fetchSpecialFoodData(null, 'KitchenAdmin', conn);
            
            // Fetch students with active special food approvals for targetDate
            let specialQuery = `
                SELECT DISTINCT s.uid, s.sname, s.room_no, s.mobileno, i.food_name as special_food_name
                FROM special_food_requests r
                JOIN studentdetails s ON r.student_id = s.uid
                JOIN special_food_items i ON r.special_food_id = i.id
                WHERE r.status = 'approved'
                AND ? >= r.start_date AND ? <= r.end_date
                AND s.category = 'Hostel'
            `;
            let specialParams = [targetDate, targetDate];
            const mappedTimeSlot = (mealType === 'dinner') ? 'night' : 'day';
            specialQuery += ` AND (r.obtain_time = ? OR r.obtain_time = 'both')`;
            specialParams.push(mappedTimeSlot);
            const [specialStudents] = await conn.promise().query(specialQuery, specialParams);
            
            conn.release();
            res.render('kitchen_main', {
                message: '',
                presentVeg: presentVeg,
                presentNonVeg: presentNonVeg,
                recentLogs: probableLogs,
                targetDate: targetDate,
                mealType: mealType,
                grouped: grouped,
                stats: stats,
                pendingStudents: pendingStudents,
                specialStudents: specialStudents || [],
                weeklyMenu: weeklyMenu || [],
                weeklyOptionalMenu: weeklyOptionalMenu || [],
                role: 'KitchenAdmin',
                dayOrder: dayOrder,
                ...specialFoodData
            });
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});

router.get('/kitchen/mess/menus', async (req, res) => {
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const [weeklyMenu] = await conn.promise().query('SELECT * FROM weekly_default_menu');
            const [weeklyOptionalMenu] = await conn.promise().query('SELECT * FROM weekly_optional_menu');
            conn.release();
            res.render('kitchen_menus', {
                message: '',
                weeklyMenu: weeklyMenu || [],
                weeklyOptionalMenu: weeklyOptionalMenu || [],
                dayOrder: dayOrder,
                role: 'KitchenAdmin'
            });
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});

router.get('/kitchen/mess/special-food', async (req, res) => {
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const targetDate = today;
    const mealType = req.query.meal_type || 'breakfast';
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const { grouped } = await fetchAllMealSelections(targetDate, conn);
            const specialFoodData = await fetchSpecialFoodData(null, 'KitchenAdmin', conn);
            conn.release();
            res.render('kitchen_special_food', {
                message: '',
                ...specialFoodData,
                grouped: grouped,
                mealType: mealType,
                role: 'KitchenAdmin'
            });
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});

router.get('/kitchen/scan/:barcode', async (req, res) => {
    const barcode = req.params.barcode;
    const mealType = req.query.meal_type || 'breakfast';
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const tmrw = new Date(Date.now() + 86400000);
    const tomorrow = tmrw.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const targetDate = today;
    
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const { allStudents, grouped, stats, pendingStudents } = await fetchAllMealSelections(targetDate, conn, mealType);
            const student = allStudents.find(s => s.uid === barcode);
            
            if (!student) {
                conn.release();
                return res.redirect('/kitchen/mess?meal_type=' + mealType + '&date=' + targetDate + '&err=Student Not Found');
            }
            
            let chosenFoodName = 'DEFAULT MENU';
            let chosenMenuType = 'DEFAULT';
            
            grouped.forEach(g => {
                if (g.meal_type === mealType && g.students.some(s => s.student_uid === barcode)) {
                    chosenFoodName = g.food_name;
                    chosenMenuType = g.type;
                }
            });
            
            let foodType = (student.mess_type && student.mess_type.toLowerCase() === 'veg') ? 'veg' : 'non-veg';
            
            let duplicate = false;
            let originalScanTime = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: true });
            try {
                await conn.promise().query('INSERT INTO meal_attendance (student_id, meal_date, meal_type, food_type) VALUES (?, ?, ?, ?)', [barcode, today, mealType, foodType]);
            } catch (scanErr) {
                if (scanErr.code === 'ER_DUP_ENTRY') {
                    duplicate = true;
                    const [dupRows] = await conn.promise().query('SELECT scanned_at FROM meal_attendance WHERE student_id=? AND meal_date=? AND meal_type=?', [barcode, today, mealType]);
                    if (dupRows.length > 0) {
                        originalScanTime = new Date(dupRows[0].scanned_at).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: true });
                    }
                }
                else throw scanErr;
            }
            if (!duplicate) {
                const fbStat = mealType + '|' + chosenFoodName;
                if (stats.foodBreakdown[fbStat]) {
                    stats.foodBreakdown[fbStat].scannedCnt = (stats.foodBreakdown[fbStat].scannedCnt || 0) + 1;
                }
            }
            
            const [weeklyMenu] = await conn.promise().query('SELECT * FROM weekly_default_menu');
            const [weeklyOptionalMenu] = await conn.promise().query('SELECT * FROM weekly_optional_menu');
            
            const { presentVeg, presentNonVeg, probableLogs } = await getKitchenAttendanceAndLogs(conn);
            
            const specialFoodData = await fetchSpecialFoodData(null, 'KitchenAdmin', conn);
            let scannedSpecialFood = null;
            let specialFoodMessage = '';
            
            const activeReq = specialFoodData.approvedSpecialRequests.find(r => r.student_id === barcode);
            if (activeReq) {
                const timeSlot = req.query.time_slot || 'day';
                if (activeReq.obtain_time === 'both' || activeReq.obtain_time === timeSlot) {
                    scannedSpecialFood = activeReq;
                    try {
                        await conn.promise().query(
                            "INSERT INTO special_food_attendance (special_food_request_id, student_id, attendance_date, time_slot) VALUES (?, ?, ?, ?)",
                            [activeReq.id, barcode, today, timeSlot]
                        );
                        specialFoodMessage = ' (Special Food Logged)';
                        
                        const [att] = await conn.promise().query(`
                            SELECT a.*, r.special_food_id, i.food_name
                            FROM special_food_attendance a
                            JOIN special_food_requests r ON a.special_food_request_id = r.id
                            JOIN special_food_items i ON r.special_food_id = i.id
                            WHERE a.attendance_date = ?
                        `, [today]);
                        specialFoodData.specialFoodAttendance = att;
                    } catch(err) {
                        if (err.code === 'ER_DUP_ENTRY') {
                            specialFoodMessage = ' (Special Food Already Logged)';
                        }
                    }
                } else {
                    specialFoodMessage = ` (Special food valid for ${activeReq.obtain_time} only)`;
                }
            }
            
            conn.release();
            
            let finalMessage = (duplicate ? 'Already scanned for this meal.' : 'Student scanned successfully!') + specialFoodMessage;
            
            const allMealSelections = {};
            ['breakfast', 'lunch', 'dinner'].forEach(mt => {
                let fName = 'DEFAULT MENU';
                let mType = 'DEFAULT';
                grouped.forEach(g => {
                    if (g.meal_type === mt && g.students.some(s => s.student_uid === barcode)) {
                        fName = g.food_name;
                        mType = g.type;
                    }
                });
                allMealSelections[mt] = {
                    food_name: fName,
                    type: mType
                };
            });

            res.render('kitchen_main', {
                message: finalMessage,
                presentVeg: presentVeg,
                presentNonVeg: presentNonVeg,
                recentLogs: probableLogs,
                targetDate: targetDate,
                mealType: mealType,
                grouped: grouped,
                stats: stats,
                pendingStudents: pendingStudents,
                weeklyMenu: weeklyMenu || [],
                weeklyOptionalMenu: weeklyOptionalMenu || [],
                role: 'KitchenAdmin',
                dayOrder: dayOrder,
                scannedSpecialFood: scannedSpecialFood,
                ...specialFoodData,
                scannedStudent: {
                    uid: student.uid,
                    name: student.sname,
                    dept: student.dept,
                    room_no: student.room_no,
                    mess_type: student.mess_type,
                    photo: resolveStudentPhotoUrl(student),
                    food_type: foodType,
                    meal: mealType,
                    chosenMenuType: chosenMenuType,
                    chosenFoodName: chosenFoodName,
                    allMealSelections: allMealSelections,
                    isDuplicate: duplicate,
                    scan_time: originalScanTime
                }
            });
        } catch(e) {
            conn.release();
            res.redirect('/kitchen/mess?meal_type=' + mealType + '&err=Server Error');
        }
    });
});

router.post('/admin/mess/edit-student-selection', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), (req, res) => {
    const { student_uid, meal_type, selection_date, selected_food } = req.body;
    dbbconnection.getConnection((err, conn) => {
        if (err) return res.status(500).send("DB Error");
        
        // Find if selected_food is default or optional to store the correct type
        conn.query('SELECT food_name FROM weekly_default_menu WHERE meal_type=?', [meal_type], (e, defMenus) => {
            let isDefault = defMenus && defMenus.some(m => m.food_name === selected_food);
            
            conn.query('INSERT INTO mess_selections (student_id, selected_food, selection_type, selection_date, meal_type) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE selected_food=?, selection_type=?',
            [student_uid, selected_food, isDefault ? 'DEFAULT' : 'OPTIONAL', selection_date, meal_type, selected_food, isDefault ? 'DEFAULT' : 'OPTIONAL'], (err) => {
                conn.release();
                res.redirect('/admin/mess?date=' + selection_date);
            });
        });
    });
});

function verifyMobileJwtMess(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, error: 'Missing token' });
    const jwt = require('jsonwebtoken');
    jwt.verify(token, 'secretkeysvpcet', function (err, decode) {
        if (err) return res.status(401).json({ success: false, error: 'Invalid token' });
        req.decode = decode;
        next();
    });
}

router.get('/api/mobile/v1/admin/mess-dashboard', verifyMobileJwtMess, async (req, res) => {
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const tmrw = new Date(Date.now() + 86400000);
    const tomorrow = tmrw.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const targetDate = req.query.date || tomorrow;
    const mealType = req.query.meal_type || 'breakfast';

    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).json({ success: false, error: "DB Error" });
        try {
            const { grouped, stats, pendingStudents, allStudents } = await fetchAllMealSelections(targetDate, conn, mealType);
            
            let specialQuery = `SELECT DISTINCT s.uid, s.sname, s.room_no, s.mobileno, i.food_name as special_food_name
                FROM special_food_requests r
                JOIN studentdetails s ON r.student_id = s.uid
                JOIN special_food_items i ON r.special_food_id = i.id
                WHERE r.status = 'approved'
                AND ? >= r.start_date AND ? <= r.end_date
                AND s.category = 'Hostel'
            `;
            let specialParams = [targetDate, targetDate];
            const mappedTimeSlot = (mealType === 'dinner') ? 'night' : 'day';
            specialQuery += " AND (r.obtain_time = ? OR r.obtain_time = 'both')";
            specialParams.push(mappedTimeSlot);
            const [specialStudents] = await conn.promise().query(specialQuery, specialParams);
            
            conn.release();
            res.json({
                success: true,
                data: {
                    targetDate,
                    mealType,
                    grouped,
                    stats,
                    pendingStudents,
                    allStudents,
                    specialStudents: specialStudents || []
                }
            });
        } catch(e) {
            conn.release();
            res.status(500).json({ success: false, error: e.message });
        }
    });
});

function verifyMobileJwtMess(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ success: false, error: 'Missing token' });
    const jwt = require('jsonwebtoken');
    jwt.verify(token, 'secretkeysvpcet', function (err, decode) {
        if (err) return res.status(401).json({ success: false, error: 'Invalid token' });
        req.decode = decode;
        next();
    });
}

router.get('/api/mobile/v1/admin/mess/menus', verifyMobileJwtMess, async (req, res) => {
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).json({ success: false, error: "DB Error" });
        try {
            const [weeklyMenu] = await conn.promise().query('SELECT * FROM weekly_default_menu');
            const [weeklyOptionalMenu] = await conn.promise().query('SELECT * FROM weekly_optional_menu');
            conn.release();
            res.json({
                success: true,
                data: {
                    weeklyMenu: weeklyMenu || [],
                    weeklyOptionalMenu: weeklyOptionalMenu || [],
                }
            });
        } catch(e) {
            conn.release();
            res.status(500).json({ success: false, error: e.message });
        }
    });
});

router.post('/api/mobile/v1/admin/mess/edit-single', verifyMobileJwtMess, (req, res) => {
    const { meal_type, weekday, food_name, drink } = req.body;
    dbbconnection.getConnection((err, conn) => {
        if (err) return res.status(500).json({ success: false, error: 'DB Error' });
        conn.query('INSERT INTO weekly_default_menu (weekday, meal_type, food_name, drink) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE food_name=?, drink=?', 
        [weekday, meal_type, food_name, drink, food_name, drink], (err) => {
            conn.release();
            if (err) return res.status(500).json({ success: false, error: err.message });
            res.json({ success: true, message: 'Menu updated successfully' });
        });
    });
});

router.post('/api/mobile/v1/admin/mess/edit-optional-single', verifyMobileJwtMess, (req, res) => {
    const { meal_type, weekday, veg_food, veg_drink, nonveg_food, nonveg_drink } = req.body;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).json({ success: false, error: 'DB Error' });
        try {
            await conn.promise().query('DELETE FROM weekly_optional_menu WHERE weekday=? AND meal_type=?', [weekday, meal_type]);
            if (veg_food) {
                await conn.promise().query('INSERT INTO weekly_optional_menu (weekday, meal_type, food_type, food_name, drink) VALUES (?, ?, ?, ?, ?)', [weekday, meal_type, 'Veg', veg_food, veg_drink || '']);
            }
            if (nonveg_food) {
                await conn.promise().query('INSERT INTO weekly_optional_menu (weekday, meal_type, food_type, food_name, drink) VALUES (?, ?, ?, ?, ?)', [weekday, meal_type, 'Non-Veg', nonveg_food, nonveg_drink || '']);
            }
            conn.release();
            res.json({ success: true, message: 'Optional menu updated successfully' });
        } catch(e) {
            conn.release();
            res.status(500).json({ success: false, error: e.message });
        }
    });
});

module.exports = router;






