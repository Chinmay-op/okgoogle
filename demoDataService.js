// Secure Backend Demo Review Mode Service
// This file is completely self-contained and serves static in-memory data for Google Play reviews.

const jwt = require('jsonwebtoken');

// --- IN-MEMORY DATABASE ---
let studentProfile = {
  uid: "teststudent@gmail.com",
  sname: "Demo Student",
  rollno: "2026STUDENT01",
  dept: "Computer Science & Engineering (CSE)",
  year: "3",
  gender: "MALE",
  mobileno: "9876543210",
  email: "teststudent@gmail.com",
  parentname: "Mr. Ramesh Student",
  parentphone: "9876543299",
  address: "123, Hostel Block A, Gavasi Manapur, Wardha Road, Nagpur",
  dob: "2005-08-15",
  bloodgroup: "O+",
  mess_type: "Veg",
  category: "Veg",
  room: "A-204",
  status: "active",
  path: null
};

let featureFlags = [
  { feature_key: "student_profile_edit", enabled: 1, value_int: null, value_str: null },
  { feature_key: "mess_open_hour", enabled: 1, value_int: null, value_str: "09:00" },
  { feature_key: "mess_close_hour", enabled: 1, value_int: null, value_str: "16:00" }
];

let studentAttendance = [
  { attendance_date: "2026-08-11", status: "present" },
  { attendance_date: "2026-08-10", status: "present" },
  { attendance_date: "2026-08-09", status: "present" },
  { attendance_date: "2026-08-08", status: "absent" },
  { attendance_date: "2026-08-07", status: "present" }
];

let passRequests = [
  {
    requestid: 101,
    uid: "teststudent@gmail.com",
    name: "Demo Student",
    passtype: "local",
    status: "approved",
    reason: "Project work at college library",
    emergency_contact: "9876543299",
    out_date: "2026-08-11",
    out_time: "17:00",
    return_date: "2026-08-11",
    return_time: "20:00",
    created_at: "2026-08-11 10:15:00",
    approved_by: "Demo Warden",
    approved_at: "2026-08-11 10:30:00",
    rejection_reason: null,
    conversion_enabled: 0,
    request_kind: "local"
  },
  {
    requestid: 102,
    uid: "teststudent@gmail.com",
    name: "Demo Student",
    passtype: "outstation",
    status: "pending",
    reason: "Going home for weekend festival",
    emergency_contact: "9876543299",
    out_date: "2026-08-14",
    out_time: "16:00",
    return_date: "2026-08-16",
    return_time: "21:00",
    created_at: "2026-08-12 09:00:00",
    approved_by: null,
    approved_at: null,
    rejection_reason: null,
    conversion_enabled: 0,
    request_kind: "outstation"
  }
];

let sickRequests = [
  {
    id: 1,
    uid: "teststudent@gmail.com",
    name: "Demo Student",
    illness: "Seasonal Viral Fever",
    duration: "2 days",
    start_date: "2026-08-08",
    end_date: "2026-08-09",
    status: "approved",
    created_at: "2026-08-08 08:30:00"
  }
];

let roomAllocations = [
  { id: 1, student_id: "teststudent@gmail.com", selected_food: "DEFAULT", selection_type: "DEFAULT", selection_date: "2026-08-12", meal_type: "breakfast", selection_locked: 1 }
];

let specialFoodItems = [
  { id: 1, food_name: "Special Chicken Biryani", quantity_desc: "Plate", price_per_day: "150.00", availability: "night", is_active: 1 },
  { id: 2, food_name: "Paneer Tikka Combo", quantity_desc: "Thali", price_per_day: "120.00", availability: "both", is_active: 1 }
];

let specialFoodRequests = [
  {
    id: 1,
    student_id: "teststudent@gmail.com",
    special_food_id: 1,
    food_name: "Special Chicken Biryani",
    quantity_desc: "Plate",
    price_per_day: "150.00",
    availability: "night",
    quantity_multiplier: 1,
    duration_days: 1,
    obtain_time: "night",
    total_price: 150.00,
    status: "approved",
    start_date: "2026-08-12",
    end_date: "2026-08-12",
    requested_at: "2026-08-11 12:00:00"
  }
];

let complaints = [
  { id: 1, student_uid: "teststudent@gmail.com", category: "Electrical", description: "Ceiling fan speed regulator not working in room A-204.", status: "pending_approval", created_at: "2026-08-12 10:00:00" }
];

let notifications = [
  { id: 1, title: "Independence Day Notice", body: "Flag hoisting ceremony is scheduled tomorrow at 8:00 AM in the central courtyard. Attendance is mandatory.", created_at: "2026-08-11 16:30:00" }
];

let bonafideRequests = [
  { id: 1, student_uid: "teststudent@gmail.com", reason: "For applying Education Loan from SBI Bank", status: "Pending", created_at: "2026-08-10 11:00:00" }
];

let bankDetailsRequests = [
  { id: 1, student_uid: "teststudent@gmail.com", bank_name: "HDFC Bank", account_no: "5010023456789", ifsc_code: "HDFC0000123", account_holder: "Demo Student", status: "pending", created_at: "2026-08-11 14:00:00" }
];

let announcements = [
  { id: 1, title: "Hostel Maintenance Schedule", content: "Water tanks will be cleaned on Saturday. There will be no water supply from 10:00 AM to 2:00 PM.", created_at: "2026-08-10 09:00:00" }
];

let adminUsers = [
  { uid: "admin1", name: "Super Admin", category: "SuperID", email: "admin@hostel.com" },
  { uid: "warden1", name: "Boys Hostel Warden", category: "BoysHostelAdmin", email: "boyswarden@hostel.com" }
];

let fakeStudentsList = [
  { uid: "teststudent@gmail.com", sname: "Demo Student", dept: "CSE", year: "3", mobileno: "9876543210", gender: "MALE", status: "active", room: "A-204", mess_type: "Veg", category: "Veg", path: null },
  { uid: "STU001", sname: "Rahul Sharma", dept: "ETC", year: "2", mobileno: "9123456780", gender: "MALE", status: "active", room: "A-102", mess_type: "Veg", category: "Veg", path: null },
  { uid: "STU002", sname: "Amit Verma", dept: "CSE", year: "3", mobileno: "9234567891", gender: "MALE", status: "active", room: "A-103", mess_type: "Non-Veg", category: "Non-Veg", path: null },
  { uid: "STU003", sname: "Priya Singh", dept: "IT", year: "4", mobileno: "9345678902", gender: "FEMALE", status: "active", room: "G-301", mess_type: "Veg", category: "Veg", path: null },
  { uid: "STU004", sname: "Neha Patel", dept: "Civil", year: "1", mobileno: "9456789013", gender: "FEMALE", status: "active", room: "G-302", mess_type: "Veg", category: "Veg", path: null },
  { uid: "STU005", sname: "Karan Johar", dept: "Mechanical", year: "2", mobileno: "9567890124", gender: "MALE", status: "restrict", room: "B-201", mess_type: "Non-Veg", category: "Non-Veg", path: null }
];

let admissionsList = [
  { id: 1, full_name: "Vikram Malhotra", branch: "Computer Science", admission_year: "1", parent_phone: "9988776655", status: "Pending", created_at: "2026-08-11" },
  { id: 2, full_name: "Simran Kapoor", branch: "Electronics", admission_year: "1", parent_phone: "9977665544", status: "Pending", created_at: "2026-08-12" }
];

let hostelOutLogs = [
  { logid: 201, uid: "STU001", sname: "Rahul Sharma", room: "A-102", passtype: "local", outdatetime: "2026-08-12 11:30:00", indatetime: null, status: "ACTIVE" }
];

let gateOutLogs = [
  { logid: 301, uid: "STU002", sname: "Amit Verma", room: "A-103", passtype: "local", outdatetime: "2026-08-12 12:00:00", indatetime: null, status: "ACTIVE" }
];

// --- HANDLER ENGINE ---
function handleRequest(req, res) {
  const method = req.method;
  const path = req.path;

  // 1. --- STUDENT APIS ---
  if (path === '/student/dashboard' && method === 'GET') {
    return res.json({
      success: true,
      student: studentProfile,
      stats: {
        totalPasses: passRequests.length,
        monthPasses: passRequests.filter(p => p.status === 'approved').length,
        activePass: 'IN',
        activePassDetails: null
      },
      recentLogs: passRequests.slice(0, 5)
    });
  }

  if (path === '/student/profile' && method === 'GET') {
    return res.json({
      success: true,
      data: studentProfile,
      profileEditEnabled: true,
      latestApprovedPass: null
    });
  }

  if (path === '/student/profile' && method === 'PUT') {
    Object.assign(studentProfile, req.body);
    return res.json({ success: true, message: "Profile updated successfully (Demo)" });
  }

  if (path === '/student/changepassword' && method === 'POST') {
    return res.json({ success: true, message: "Password updated successfully (Demo)" });
  }

  if (path === '/student/passhistory' && method === 'GET') {
    return res.json({
      success: true,
      data: passRequests
    });
  }

  if (path === '/student/requestpass' && method === 'POST') {
    const { passtype, reason, emergency_contact, out_date, out_time, return_date, return_time } = req.body;
    const newPass = {
      requestid: passRequests.length + 101,
      uid: "teststudent@gmail.com",
      name: "Demo Student",
      passtype: passtype || "local",
      status: "pending",
      reason: reason || "Testing",
      emergency_contact: emergency_contact || "9876543299",
      out_date: out_date || "2026-08-12",
      out_time: out_time || "18:00",
      return_date: return_date || "2026-08-12",
      return_time: return_time || "21:00",
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
      approved_by: null,
      approved_at: null,
      rejection_reason: null,
      conversion_enabled: 0,
      request_kind: passtype || "local"
    };
    passRequests.unshift(newPass);
    return res.json({ success: true, message: "Pass request submitted successfully! (Demo)" });
  }

  if (path.startsWith('/student/cancelrequest/') && method === 'GET') {
    const id = parseInt(path.split('/').pop(), 10);
    passRequests = passRequests.map(p => p.requestid === id ? { ...p, status: 'cancelled' } : p);
    return res.json({ success: true, message: "Request cancelled successfully (Demo)" });
  }

  if (path.startsWith('/student/attendance') && method === 'GET') {
    return res.json({
      success: true,
      data: studentAttendance
    });
  }

  if (path === '/student/sickleaverequests' && method === 'GET') {
    return res.json({
      success: true,
      data: sickRequests
    });
  }

  if (path === '/student/sickleave' && method === 'POST') {
    const { illness, duration, start_date, end_date } = req.body;
    const newSick = {
      id: sickRequests.length + 1,
      uid: "teststudent@gmail.com",
      name: "Demo Student",
      illness: illness || "Illness",
      duration: duration || "1 day",
      start_date: start_date || "2026-08-12",
      end_date: end_date || "2026-08-12",
      status: "pending",
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19)
    };
    sickRequests.unshift(newSick);
    return res.json({ success: true, message: "Sick leave request submitted successfully! (Demo)" });
  }

  if (path.startsWith('/student/cancelsickrequest/') && method === 'POST') {
    const id = parseInt(path.split('/').pop(), 10);
    sickRequests = sickRequests.map(s => s.id === id ? { ...s, status: 'cancelled' } : s);
    return res.json({ success: true, message: "Sick request cancelled successfully (Demo)" });
  }

  if (path === '/student/rooms' && method === 'GET') {
    // List of rooms with availability
    return res.json({
      success: true,
      data: [
        { block: "A", room_no: "201", occupancy: 3, capacity: 4 },
        { block: "A", room_no: "202", occupancy: 2, capacity: 4 },
        { block: "A", room_no: "204", occupancy: 1, capacity: 4 },
        { block: "B", room_no: "101", occupancy: 0, capacity: 2 }
      ]
    });
  }

  if (path === '/student/bookings' && method === 'POST') {
    return res.json({ success: true, message: "Room booked successfully! (Demo)" });
  }

  if (path === '/student/notifications' && method === 'GET') {
    return res.json({
      success: true,
      data: notifications
    });
  }

  if (path === '/student/bonafide' && method === 'GET') {
    return res.json({
      success: true,
      data: bonafideRequests
    });
  }

  if (path === '/student/bonafide/request' && method === 'POST') {
    const { reason } = req.body;
    const newBon = {
      id: bonafideRequests.length + 1,
      student_uid: "teststudent@gmail.com",
      reason: reason || "Testing",
      status: "Pending",
      created_at: new Date().toISOString().substring(0, 10)
    };
    bonafideRequests.unshift(newBon);
    return res.json({ success: true, message: "Bonafide request submitted! (Demo)" });
  }

  if (path.includes('/bonafide/') && path.endsWith('/cancel') && method === 'POST') {
    const parts = path.split('/');
    const id = parseInt(parts[parts.length - 2], 10);
    bonafideRequests = bonafideRequests.map(b => b.id === id ? { ...b, status: 'Cancelled' } : b);
    return res.json({ success: true, message: "Bonafide request cancelled (Demo)" });
  }

  if (path === '/student/bank-details' && method === 'GET') {
    return res.json({
      success: true,
      data: bankDetailsRequests
    });
  }

  if (path === '/student/bank-details/request' && method === 'POST') {
    const { bank_name, account_no, ifsc_code, account_holder } = req.body;
    const newBk = {
      id: bankDetailsRequests.length + 1,
      student_uid: "teststudent@gmail.com",
      bank_name,
      account_no,
      ifsc_code,
      account_holder,
      status: "pending",
      created_at: new Date().toISOString().substring(0, 10)
    };
    bankDetailsRequests.unshift(newBk);
    return res.json({ success: true, message: "Bank details update requested! (Demo)" });
  }

  if (path.includes('/bank-details/') && path.endsWith('/cancel') && method === 'POST') {
    const parts = path.split('/');
    const id = parseInt(parts[parts.length - 2], 10);
    bankDetailsRequests = bankDetailsRequests.map(bk => bk.id === id ? { ...bk, status: 'cancelled' } : bk);
    return res.json({ success: true, message: "Bank request cancelled (Demo)" });
  }

  if (path === '/student/mess' && method === 'GET') {
    const now = new Date();
    const today = now.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    const tmrw = new Date(now);
    tmrw.setDate(tmrw.getDate() + 1);
    const tomorrow = tmrw.toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });

    return res.json({
      success: true,
      data: {
        student: studentProfile,
        weeklyMenu: [
          { weekday: "Wednesday", meal_type: "breakfast", food_name: "Poha & Tea" },
          { weekday: "Wednesday", meal_type: "lunch", food_name: "Veg Thali (Dal, Rice, Roti, Sabzi)" },
          { weekday: "Wednesday", meal_type: "dinner", food_name: "Paneer Butter Masala & Roti" }
        ],
        weeklyOptionalMenu: [
          { weekday: "Wednesday", meal_type: "breakfast", food_name: "Idli Sambar", food_type: "Veg", is_active: 1 },
          { weekday: "Wednesday", meal_type: "dinner", food_name: "Egg Curry / Chicken Gravy", food_type: "Non-Veg", is_active: 1 }
        ],
        studentSelections: roomAllocations,
        today,
        tomorrow,
        todayName: "Tuesday",
        tmrwName: "Wednesday",
        messOpenTime: "09:00",
        messCloseTime: "23:59", // Open for demo reviews
        specialFoodItems: specialFoodItems,
        studentSpecialRequests: specialFoodRequests
      }
    });
  }

  if (path === '/student/mess' && method === 'POST') {
    const { meal_type, selection_date, selected_food } = req.body;
    roomAllocations = roomAllocations.filter(a => !(a.meal_type === meal_type && a.selection_date === selection_date));
    roomAllocations.push({
      id: roomAllocations.length + 1,
      student_id: "teststudent@gmail.com",
      selected_food,
      selection_type: selected_food === 'DEFAULT' ? 'DEFAULT' : 'OPTIONAL',
      selection_date,
      meal_type,
      selection_locked: 1
    });
    return res.json({ success: true, message: "Selection lock saved! (Demo)" });
  }

  if (path === '/student/special-food/request' && method === 'POST') {
    const { special_food_id, quantity_multiplier, duration_days, obtain_time } = req.body;
    const item = specialFoodItems.find(i => i.id === parseInt(special_food_id, 10));
    if (item) {
      const price = parseFloat(item.price_per_day) * parseInt(quantity_multiplier || 1, 10) * parseInt(duration_days || 1, 10);
      specialFoodRequests.unshift({
        id: specialFoodRequests.length + 1,
        student_id: "teststudent@gmail.com",
        special_food_id: item.id,
        food_name: item.food_name,
        quantity_desc: item.quantity_desc,
        price_per_day: item.price_per_day,
        availability: item.availability,
        quantity_multiplier: parseInt(quantity_multiplier || 1, 10),
        duration_days: parseInt(duration_days || 1, 10),
        obtain_time,
        total_price: price,
        status: "pending",
        start_date: new Date().toISOString().substring(0, 10),
        end_date: new Date().toISOString().substring(0, 10),
        requested_at: new Date().toISOString().replace('T', ' ').substring(0, 19)
      });
    }
    return res.json({ success: true, message: "Special food request submitted! (Demo)" });
  }

  if (path === '/student/complain' && method === 'POST') {
    const { category, description } = req.body;
    complaints.unshift({
      id: complaints.length + 1,
      student_uid: "teststudent@gmail.com",
      category,
      description,
      status: "pending_approval",
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19)
    });
    return res.json({ success: true, message: "Complaint posted successfully! (Demo)" });
  }

  // 2. --- ADMIN APIS ---
  if (path === '/dashboard-counts' && method === 'GET') {
    return res.json({
      success: true,
      data: {
        passRequests: passRequests.filter(p => p.status === 'pending').length,
        sickLeaveRequests: sickRequests.filter(s => s.status === 'pending').length,
        bonafideRequests: bonafideRequests.filter(b => b.status === 'Pending').length,
        pendingAdmissions: admissionsList.filter(a => a.status === 'Pending').length,
        verifyComplaints: complaints.filter(c => c.status === 'pending_approval').length
      }
    });
  }

  if (path === '/passrequests' && method === 'GET') {
    const status = req.query.status || 'pending';
    return res.json({
      success: true,
      data: passRequests.filter(p => p.status === status)
    });
  }

  if (path.startsWith('/passrequests/') && method === 'POST') {
    const parts = path.split('/');
    const id = parseInt(parts[2], 10);
    const action = parts[3]; // approve, reject, reset
    passRequests = passRequests.map(p => {
      if (p.requestid === id) {
        let newStatus = p.status;
        if (action === 'approve') newStatus = 'approved';
        if (action === 'reject') newStatus = 'rejected';
        if (action === 'reset') newStatus = 'pending';
        return { ...p, status: newStatus };
      }
      return p;
    });
    return res.json({ success: true, message: `Pass request action ${action} executed! (Demo)` });
  }

  if (path === '/sickleave' && method === 'GET') {
    return res.json({
      success: true,
      data: sickRequests
    });
  }

  if (path.startsWith('/sickleave/') && method === 'POST') {
    const parts = path.split('/');
    const id = parseInt(parts[2], 10);
    const action = parts[3]; // approve, reject
    sickRequests = sickRequests.map(s => {
      if (s.id === id) {
        return { ...s, status: action === 'approve' ? 'approved' : 'rejected' };
      }
      return s;
    });
    return res.json({ success: true, message: `Sick leave request updated! (Demo)` });
  }

  if (path === '/admissions' && method === 'GET') {
    return res.json({
      success: true,
      data: admissionsList
    });
  }

  if (path.startsWith('/admissions/') && method === 'POST') {
    const parts = path.split('/');
    const id = parseInt(parts[2], 10);
    const action = parts[3]; // decide, delete, remove, transfer
    if (action === 'decide') {
      const { status } = req.body;
      admissionsList = admissionsList.map(a => a.id === id ? { ...a, status } : a);
    } else {
      admissionsList = admissionsList.filter(a => a.id !== id);
    }
    return res.json({ success: true, message: `Admission action ${action} executed! (Demo)` });
  }

  if (path === '/admin/adduser' && method === 'POST') {
    const { name, category, email, UID } = req.body;
    adminUsers.push({ uid: UID || email, name, category, email });
    return res.json({ success: true, message: "User added successfully (Demo)" });
  }

  if (path === '/admin/users' && method === 'GET') {
    return res.json({
      success: true,
      data: adminUsers
    });
  }

  if (path.startsWith('/admin/user/') && method === 'DELETE') {
    const uid = path.split('/').pop();
    adminUsers = adminUsers.filter(u => u.uid !== uid);
    return res.json({ success: true, message: "User deleted successfully (Demo)" });
  }

  if (path === '/admin/features' && method === 'GET') {
    return res.json({
      success: true,
      data: featureFlags
    });
  }

  if (path === '/admin/features' && method === 'POST') {
    const { feature_key, enabled } = req.body;
    featureFlags = featureFlags.map(f => f.feature_key === feature_key ? { ...f, enabled } : f);
    return res.json({ success: true, message: "Feature flag updated (Demo)" });
  }

  if (path === '/admin/todayslog' && method === 'GET') {
    return res.json({
      success: true,
      data: [
        { logid: 1, uid: "STU001", name: "Rahul Sharma", room: "A-102", passtype: "local", outdatetime: "2026-08-12 11:30:00", indatetime: null, status: "OUT" },
        { logid: 2, uid: "STU002", name: "Amit Verma", room: "A-103", passtype: "local", outdatetime: "2026-08-12 12:00:00", indatetime: "2026-08-12 13:00:00", status: "IN" }
      ]
    });
  }

  if (path === '/attendance/grid' && method === 'GET') {
    return res.json({
      success: true,
      data: [
        { uid: "STU001", sname: "Rahul Sharma", room: "A-102", status: "present" },
        { uid: "STU002", sname: "Amit Verma", room: "A-103", status: "absent" }
      ]
    });
  }

  if (path === '/attendance/mark' && method === 'POST') {
    return res.json({ success: true, message: "Attendance marked successfully (Demo)" });
  }

  if (path === '/attendance/assign-room' && method === 'POST') {
    return res.json({ success: true, message: "Room assigned successfully (Demo)" });
  }

  if (path === '/attendance/unallocated' && method === 'GET') {
    return res.json({
      success: true,
      data: [
        { uid: "STU006", sname: "Demo Unallocated Student", dept: "IT", year: "1", mobileno: "9900112233" }
      ]
    });
  }

  if (path === '/students' && method === 'GET') {
    return res.json({
      success: true,
      data: fakeStudentsList
    });
  }

  if (path === '/students/hostel' && method === 'GET') {
    return res.json({
      success: true,
      data: fakeStudentsList
    });
  }

  if (path === '/complaints' && method === 'GET') {
    return res.json({
      success: true,
      data: complaints
    });
  }

  if (path === '/students/restrict' && method === 'POST') {
    const { student_id, restrict } = req.body;
    fakeStudentsList = fakeStudentsList.map(s => s.uid === student_id ? { ...s, status: restrict ? 'restrict' : 'active' } : s);
    return res.json({ success: true, message: "Student restriction toggled (Demo)" });
  }

  if (path.startsWith('/students/profile/') && method === 'GET') {
    const uid = path.split('/').pop();
    const student = fakeStudentsList.find(s => s.uid === uid) || studentProfile;
    return res.json({
      success: true,
      data: student
    });
  }

  if (path.startsWith('/students/passes/summary/') && method === 'GET') {
    return res.json({
      success: true,
      summary: { total: 5, approved: 4, rejected: 0, pending: 1 }
    });
  }

  if (path.startsWith('/students/profile/') && method === 'PUT') {
    const uid = path.split('/').pop();
    fakeStudentsList = fakeStudentsList.map(s => s.uid === uid ? { ...s, ...req.body } : s);
    return res.json({ success: true, message: "Student profile updated (Demo)" });
  }

  if (path === '/admin/hostelout' && method === 'GET') {
    return res.json({
      success: true,
      data: hostelOutLogs
    });
  }

  if (path.startsWith('/admin/hostelout/takein/') && method === 'POST') {
    const logid = parseInt(path.split('/').pop(), 10);
    hostelOutLogs = hostelOutLogs.filter(h => h.logid !== logid);
    return res.json({ success: true, message: "Taken in successfully (Demo)" });
  }

  if (path === '/admin/gateout' && method === 'GET') {
    return res.json({
      success: true,
      data: gateOutLogs
    });
  }

  if (path.startsWith('/admin/gateout/takein/') && method === 'POST') {
    const logid = parseInt(path.split('/').pop(), 10);
    gateOutLogs = gateOutLogs.filter(g => g.logid !== logid);
    return res.json({ success: true, message: "Taken in successfully (Demo)" });
  }

  if (path === '/admin/hostel-monitoring' && method === 'GET') {
    return res.json({
      success: true,
      data: {
        totalStudents: 120,
        insideCount: 110,
        outsideCount: 10,
        logs: [
          { sname: "Rahul Sharma", room: "A-102", passtype: "local", outdatetime: "2026-08-12 11:30:00", status: "OUT" }
        ]
      }
    });
  }

  if (path === '/admin/global-analytics' && method === 'GET') {
    return res.json({
      success: true,
      data: {
        totalRooms: 120,
        occupiedRooms: 98,
        availableRooms: 22,
        totalBeds: 240,
        occupiedBeds: 180,
        availableBeds: 60,
        todayAttendancePercent: 91,
        activeComplaintsCount: 4
      }
    });
  }

  if (path === '/admin/verify-complaints' && method === 'GET') {
    return res.json({
      success: true,
      data: complaints
    });
  }

  if (path.startsWith('/admin/verify-complaints/') && method === 'POST') {
    const parts = path.split('/');
    const id = parseInt(parts[3], 10);
    const action = parts[4]; // approve, deny, to-technician
    complaints = complaints.map(c => {
      if (c.id === id) {
        let status = c.status;
        if (action === 'approve') status = 'approved';
        if (action === 'deny') status = 'denied';
        if (action === 'to-technician') status = 'to_technician';
        return { ...c, status };
      }
      return c;
    });
    return res.json({ success: true, message: `Complaint action ${action} executed! (Demo)` });
  }

  if (path === '/admin/announcements' && method === 'GET') {
    return res.json({
      success: true,
      data: announcements
    });
  }

  if (path === '/admin/announcements' && method === 'POST') {
    const { title, content } = req.body;
    announcements.unshift({
      id: announcements.length + 1,
      title,
      content,
      created_at: new Date().toISOString().replace('T', ' ').substring(0, 19)
    });
    return res.json({ success: true, message: "Announcement posted successfully (Demo)" });
  }

  if (path.startsWith('/admin/announcements/delete/') && method === 'POST') {
    const id = parseInt(path.split('/').pop(), 10);
    announcements = announcements.filter(a => a.id !== id);
    return res.json({ success: true, message: "Announcement deleted (Demo)" });
  }

  if (path === '/admin/bonafide-requests' && method === 'GET') {
    return res.json({
      success: true,
      data: bonafideRequests
    });
  }

  if (path.startsWith('/admin/bonafide-requests/') && method === 'GET') {
    const id = parseInt(path.split('/').pop(), 10);
    const request = bonafideRequests.find(b => b.id === id);
    return res.json({
      success: true,
      data: request || bonafideRequests[0]
    });
  }

  if (path.startsWith('/admin/bonafide-requests/') && method === 'POST') {
    const parts = path.split('/');
    const id = parseInt(parts[3], 10);
    const action = parts[4]; // approve, reject, payment, collected
    bonafideRequests = bonafideRequests.map(b => {
      if (b.id === id) {
        let status = b.status;
        if (action === 'approve') status = 'Approved';
        if (action === 'reject') status = 'Rejected';
        if (action === 'payment') status = 'Payment';
        if (action === 'collected') status = 'Collected';
        return { ...b, status };
      }
      return b;
    });
    return res.json({ success: true, message: `Bonafide status updated to ${action} (Demo)` });
  }

  // Fallback
  return res.status(404).json({ success: false, error: `Endpoint ${method} ${path} not found in Demo mode` });
}

module.exports = {
  handleRequest
};
