// Mock Database Connection for Test App
const mockStudent = {
  uid: '23017037',
  sname: 'CHINMAY PRAFULRAO WADETTIWAR',
  email: 'CHINMAYWADETTIWAR211@GMAIL.COM',
  dept: 'INDUSTRIAL IOT',
  year: '4',
  category: 'Hostel',
  gender: 'MALE',
  mobileno: '8806827885',
  dob: '2005-06-29',
  academicyear: '2025',
  path: '',
  status: 'Unrestrict',
  password: '$2b$10$rmi6oA0VDgNUfn2UAqowEe/HO4bWbffwWECXJsxl96NH2QMNx7S/q', // 8806827885
  room_no: 'AS-03',
  block: 'A',
  restriction_status: 'active'
};

const mockAdmin = {
  UID: 'admin',
  password: '$2b$10$rmi6oA0VDgNUfn2UAqowEe/HO4bWbffwWECXJsxl96NH2QMNx7S/q', 
  Role: 'superadmin'
};

let mockPassRequests = [];
let passIdCounter = 1000;

function nowIST() {
  const now = new Date();
  const ist = new Date(now.getTime() + 5.5 * 60 * 60 * 1000);
  return ist.toISOString().slice(0, 19).replace('T', ' ');
}

function handleQuery(sql, cb) {
  const sqlLower = sql.toLowerCase();
  
  if (sqlLower.includes('insert into pass_requests')) {
    const ts = nowIST();
    passIdCounter++;
    mockPassRequests.push({ 
        requestid: passIdCounter,
        uid: '23017037', 
        sname: mockStudent.sname,
        passtype: 'City Pass',
        room_no: mockStudent.room_no,
        status: 'approved', 
        created_at: ts,
        approved_at: ts,
        approvaldt: ts,
        approved_by: 'Roy',
        expected_out: ts,
        expected_return: ts,
        reason: 'Requested via app',
        emergency_contact: null,
        rejection_reason: null,
        conversion_enabled: 0,
        conversion_enabled_by: null,
        out_date: new Date(), 
        in_date: null 
    });
    return cb(null, { insertId: passIdCounter, affectedRows: 1 });
  }
  
  if (sqlLower.includes('update pass_requests')) {
    return cb(null, { affectedRows: 1 });
  }

  if (sqlLower.includes('from studentdetails')) {
    return cb(null, [mockStudent]);
  }
  
  if (sqlLower.includes('from admin')) {
    return cb(null, [mockAdmin]);
  }

  if (sqlLower.includes('from pass_requests')) {
    return cb(null, mockPassRequests);
  }
  
  if (sqlLower.includes('from settings')) {
    return cb(null, [{ auto_approve: 1 }]);
  }
  
  if (sqlLower.includes('show columns')) {
      return cb(null, [{ Field: 'image_path' }]);
  }

  // Fallback for any other select query
  if (sqlLower.includes('select ')) {
    return cb(null, []);
  }

  // Fallback for any other update/insert/delete/alter
  return cb(null, { affectedRows: 1, insertId: 1 });
}

const mockConnection = {
  query: function(sql, paramsOrCallback, cb) {
    let callback = cb;
    if (typeof paramsOrCallback === 'function') {
      callback = paramsOrCallback;
    }
    if (!callback) callback = function(){};
    
    // Simulate async DB delay
    setTimeout(() => {
      try {
        handleQuery(sql, callback);
      } catch (err) {
        callback(null, []);
      }
    }, 10);
  },
  release: function() {},
  on: function() {}
};

const mockPool = {
  getConnection: function(cb) {
    cb(null, mockConnection);
  },
  query: function(sql, paramsOrCallback, cb) {
    mockConnection.query(sql, paramsOrCallback, cb);
  },
  on: function() {}
};

module.exports = mockPool;