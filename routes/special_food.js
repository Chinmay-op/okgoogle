const express = require('express');
const router = express.Router();
const dbbconnection = require('../server');
const jwt = require('jsonwebtoken');

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


// Helper to get uid
function getUid(req) {
    const token = req.cookies && (req.cookies.studentToken || req.cookies.token || req.cookies.jwt);
    if (token) {
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET || process.env.SESSION_SECRET || 'secret');
            return decoded.uid || decoded.id || decoded.studentUid || 'TEST_STUDENT02';
        } catch(e) { }
    }
    return 'TEST_STUDENT02';
}

// ----------------------------------------------------
// SUPERADMIN: Items CRUD
// ----------------------------------------------------

router.post('/items/add', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { food_name, quantity_desc, price_per_day, availability } = req.body;
    const uid = getUid(req); // Admin UID
    
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            await conn.promise().query(
                "INSERT INTO special_food_items (food_name, quantity_desc, price_per_day, availability, created_by) VALUES (?, ?, ?, ?, ?)",
                [food_name, quantity_desc, price_per_day, availability, uid]
            );
            conn.release();
            res.redirect('back');
        } catch(e) {
            conn.release();
            console.error("Error adding special food item:", e);
            res.status(500).send("Server Error");
        }
    });
});

router.post('/items/edit/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    const { food_name, quantity_desc, price_per_day, availability } = req.body;
    
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            await conn.promise().query(
                "UPDATE special_food_items SET food_name=?, quantity_desc=?, price_per_day=?, availability=? WHERE id=?",
                [food_name, quantity_desc, price_per_day, availability, id]
            );
            conn.release();
            res.redirect('back');
        } catch(e) {
            conn.release();
            console.error("Error editing special food item:", e);
            res.status(500).send("Server Error");
        }
    });
});

router.post('/items/delete/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            // Try to hard delete first
            try {
                await conn.promise().query("DELETE FROM special_food_items WHERE id=?", [id]);
            } catch (deleteErr) {
                // If it fails due to foreign key constraint (e.g. students have requested this item), fallback to soft-delete
                if (deleteErr.errno === 1451 || deleteErr.code === 'ER_ROW_IS_REFERENCED_2') {
                    await conn.promise().query("UPDATE special_food_items SET is_active=0 WHERE id=?", [id]);
                } else {
                    throw deleteErr;
                }
            }
            conn.release();
            res.redirect('back');
        } catch(e) {
            conn.release();
            console.error("Error deleting special food item:", e);
            res.status(500).send("Server Error");
        }
    });
});


// ----------------------------------------------------
// STUDENT: Requests
// ----------------------------------------------------

router.post('/requests/add', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    let { special_food_id, duration_days, quantity_multiplier, obtain_time, existing_id } = req.body;
    const student_id = getUid(req);
    
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const [items] = await conn.promise().query("SELECT price_per_day, availability FROM special_food_items WHERE id=?", [special_food_id]);
            if (!items.length) {
                conn.release();
                return res.status(404).send("Item not found");
            }
            const item = items[0];
            
            if (item.availability !== 'both' && obtain_time !== item.availability) {
                conn.release();
                return res.status(400).send(`Invalid obtain time. Item is only available for ${item.availability}.`);
            }
            
            const timeMultiplier = (obtain_time === 'both') ? 2 : 1;
            const totalPrice = item.price_per_day * timeMultiplier * duration_days * quantity_multiplier;
            
            if (existing_id) {
                // If the student is updating a rejected request
                await conn.promise().query(
                    "UPDATE special_food_requests SET special_food_id=?, quantity_multiplier=?, duration_days=?, obtain_time=?, total_price=?, status='pending' WHERE id=? AND student_id=? AND status='rejected'",
                    [special_food_id, quantity_multiplier, duration_days, obtain_time, totalPrice, existing_id, student_id]
                );
            } else {
                await conn.promise().query(
                    "INSERT INTO special_food_requests (student_id, special_food_id, quantity_multiplier, duration_days, obtain_time, total_price) VALUES (?, ?, ?, ?, ?, ?)",
                    [student_id, special_food_id, quantity_multiplier, duration_days, obtain_time, totalPrice]
                );
            }
            
            conn.release();
            res.redirect('back');
        } catch(e) {
            conn.release();
            console.error("Error requesting special food:", e);
            res.status(500).send("Server Error");
        }
    });
});

// ----------------------------------------------------
// SUPERADMIN: Approve / Reject Requests
// ----------------------------------------------------

router.post('/requests/approve/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    const { start_date } = req.body; // usually today, selected from form
    const admin_id = getUid(req);
    
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            const [reqs] = await conn.promise().query("SELECT duration_days FROM special_food_requests WHERE id=?", [id]);
            if (!reqs.length) {
                conn.release();
                return res.status(404).send("Request not found");
            }
            const duration_days = reqs[0].duration_days;
            
            const endDateObj = new Date(start_date);
            endDateObj.setDate(endDateObj.getDate() + (duration_days - 1));
            const end_date = endDateObj.toISOString().split('T')[0];
            
            await conn.promise().query(
                "UPDATE special_food_requests SET status='approved', start_date=?, end_date=?, approved_by=?, approved_at=NOW() WHERE id=?",
                [start_date, end_date, admin_id, id]
            );
            conn.release();
            res.redirect('back');
        } catch(e) {
            conn.release();
            console.error("Error approving special food:", e);
            res.status(500).send("Server Error");
        }
    });
});

router.post('/requests/reject/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            await conn.promise().query("UPDATE special_food_requests SET status='rejected' WHERE id=?", [id]);
            conn.release();
            res.redirect('back');
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});

router.post('/requests/cancel/:id', requireRole('SuperID', 'Hostelauthority', 'BoysHostelAdmin', 'GirlsHostelAdmin'), async (req, res) => {
    const { id } = req.params;
    // Set end_date to yesterday so this request is immediately excluded from active subscriptions.
    // Use status='rejected' — 'cancelled' is not a valid ENUM value in this schema.
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    dbbconnection.getConnection(async (err, conn) => {
        if (err) return res.status(500).send("DB Error");
        try {
            await conn.promise().query(
                "UPDATE special_food_requests SET status='rejected', end_date=? WHERE id=? AND status='approved'",
                [yesterdayStr, id]
            );
            conn.release();
            res.redirect('back');
        } catch(e) {
            conn.release();
            res.status(500).send("Server Error");
        }
    });
});


module.exports = router;
