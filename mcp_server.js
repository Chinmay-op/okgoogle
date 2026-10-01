const express = require('express');
const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { SSEServerTransport } = require('@modelcontextprotocol/sdk/server/sse.js');
const {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ErrorCode,
  McpError
} = require('@modelcontextprotocol/sdk/types.js');
const db = require('./server'); // Database connection

const router = express.Router();

const mcpServer = new Server({
  name: "tnps-gatepass-mcp",
  version: "1.0.0"
}, {
  capabilities: {
    resources: {},
    tools: {}
  }
});

// Setup Resources
mcpServer.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: "gatepass://summary/active_passes",
      name: "Active Passes Summary",
      mimeType: "application/json",
      description: "A summary of how many students are currently out on City vs. Home passes."
    },
    {
      uri: "gatepass://summary/post_10pm_restrictions",
      name: "Post 10PM Restrictions",
      mimeType: "application/json",
      description: "A list of students currently restricted due to the 10 PM rule."
    }
  ]
}));

mcpServer.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  if (request.params.uri === "gatepass://summary/active_passes") {
    return new Promise((resolve, reject) => {
      const sql = `SELECT passtype, COUNT(*) as count FROM log_details1 WHERE status = 'ACTIVE' GROUP BY passtype`;
      db.query(sql, (err, rows) => {
        if (err) return reject(new McpError(ErrorCode.InternalError, "Database error"));
        resolve({
          contents: [{
            uri: request.params.uri,
            mimeType: "application/json",
            text: JSON.stringify(rows)
          }]
        });
      });
    });
  }

  if (request.params.uri === "gatepass://summary/post_10pm_restrictions") {
    return new Promise((resolve, reject) => {
      const sql = `
          SELECT p.uid, s.sname, s.department, p.restriction_reason, p.restricted_at 
          FROM pass_restriction_audit p
          JOIN studentdetails s ON p.uid = s.uid
          ORDER BY p.restricted_at DESC LIMIT 50`;
      db.query(sql, (err, rows) => {
        if (err) return reject(new McpError(ErrorCode.InternalError, "Database error"));
        resolve({
          contents: [{
            uri: request.params.uri,
            mimeType: "application/json",
            text: JSON.stringify(rows)
          }]
        });
      });
    });
  }

  throw new McpError(ErrorCode.InvalidRequest, `Resource not found: ${request.params.uri}`);
});

// Setup Tools
mcpServer.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_pending_pass_requests",
      description: "Fetches all currently pending gate pass requests, enriched with student department, past restrictions, and recent pass history.",
      inputSchema: {
        type: "object",
        properties: {},
        required: []
      }
    },
    {
      name: "approve_gatepass",
      description: "Approves a specific gate pass request by ID. Returns success status and reason.",
      inputSchema: {
        type: "object",
        properties: {
          request_id: { type: "number", description: "The ID of the pass request to approve." },
          admin_name: { type: "string", description: "The name of the admin approving the pass." }
        },
        required: ["request_id", "admin_name"]
      }
    },
    {
      name: "get_student_details",
      description: "Retrieves hostel, bonafide, and pass history for a given student UID.",
      inputSchema: {
        type: "object",
        properties: {
          uid: { type: "string", description: "The UID of the student." }
        },
        required: ["uid"]
      }
    }
  ]
}));

mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (name === "get_pending_pass_requests") {
    return new Promise((resolve) => {
      const sql = `
          SELECT p.*, s.sname, s.department, s.status as hostel_status 
          FROM pass_requests p
          JOIN studentdetails s ON p.uid = s.uid
          WHERE p.status = 'pending'
        `;
      db.query(sql, (err, rows) => {
        if (err) resolve({ content: [{ type: "text", text: JSON.stringify({ success: false, reason: err.message }) }] });
        resolve({ content: [{ type: "text", text: JSON.stringify({ success: true, data: rows }) }] });
      });
    });
  }

  if (name === "approve_gatepass") {
    return new Promise((resolve) => {
      const requestId = args.request_id;
      const adminName = args.admin_name;

      // Note: A full implementation would share the exact logic from app.js /admin/approverequest/:id
      // For MCP, we execute the same approval updates.
      const getRequestSql = "SELECT * FROM pass_requests WHERE requestid = ? AND status = 'pending'";
      db.query(getRequestSql, [requestId], (err, requestResult) => {
        if (err || requestResult.length === 0) {
          return resolve({ content: [{ type: "text", text: JSON.stringify({ success: false, reason: 'Request not found or already processed' }) }] });
        }

        const requestRow = requestResult[0];

        // Convert dates to IST manually or use DB timestamps
        const updateSql = "UPDATE pass_requests SET status = 'approved', approved_by = ?, approved_at = NOW() WHERE requestid = ?";
        db.query(updateSql, [adminName, requestId], (uErr) => {
          if (uErr) return resolve({ content: [{ type: "text", text: JSON.stringify({ success: false, reason: 'Database error on update' }) }] });

          // Normal request: don't create pass yet - it will be created when student scans at gate
          const notifSql = "INSERT INTO student_notifications (uid, type, title, message, created_at) VALUES (?, 'pass_approved', 'Pass Request Approved', ?, NOW())";
          const notifMsg = `Your ${requestRow.passtype} request has been approved by ${adminName}. Please scan your ID at the gate to activate your pass.`;

          db.query(notifSql, [requestRow.uid, notifMsg], () => {
            resolve({ content: [{ type: "text", text: JSON.stringify({ success: true, reason: 'Pass request approved successfully' }) }] });
          });
        });
      });
    });
  }

  if (name === "get_student_details") {
    return new Promise((resolve) => {
      const sql = `SELECT * FROM studentdetails WHERE uid = ?`;
      db.query(sql, [args.uid], (err, rows) => {
        if (err || rows.length === 0) resolve({ content: [{ type: "text", text: JSON.stringify({ success: false, reason: 'Student not found' }) }] });
        resolve({ content: [{ type: "text", text: JSON.stringify({ success: true, data: rows[0] }) }] });
      });
    });
  }

  throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
});



// Transports Map to handle multiple sessions
const transports = new Map();

function isValidSession(sessionId) {
  return transports.has(sessionId);
}

router.get('/sse', async (req, res) => {
  res.setHeader('X-Accel-Buffering', 'no');
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');

  // SSEServerTransport expects the endpoint path where clients will POST messages
  const transport = new SSEServerTransport("/mcp/sse", res);
  await mcpServer.connect(transport);

  const sessionId = transport.sessionId;
  console.log(`[MCP Transport] Established new session: ${sessionId}`);
  transports.set(sessionId, transport);
  console.log(`[MCP Server] Connected new SSE session: ${sessionId}`);

  // Send periodic SSE keep-alive ping comment every 15s to keep ngrok & proxies from closing the connection
  const keepAlive = setInterval(() => {
    try {
      res.write(': keepalive\n\n');
    } catch (e) {
      clearInterval(keepAlive);
    }
  }, 15000);

  req.on('close', () => {
    console.log(`[MCP Server] SSE session closed: ${sessionId}`);
    clearInterval(keepAlive);
    transports.delete(sessionId);
  });
});

// Handle incoming messages from the client
router.post('/sse', async (req, res) => {
  const sessionId = req.query.sessionId;
  console.log(`[MCP POST] Received message for session ${sessionId}`);
  const transport = transports.get(sessionId);
  if (!transport) {
    console.warn(`[MCP Server] POST /sse session not found or closed: ${sessionId}`);
    return res.status(404).send("Session not found");
  }
  try {
    await transport.handlePostMessage(req, res, req.body);
  } catch (err) {
    console.error(`[MCP Server] Error in handlePostMessage for session ${sessionId}:`, err);
    if (!res.headersSent) {
      res.status(500).send("Internal Server Error processing MCP message");
    }
  }
});

// ==========================================
// Direct REST API Endpoints for HTTP Tools
// ==========================================

// 1. Get Student Details (supports /api/student/:uid or /api/student?uid=...)
router.get(['/api/student/:uid', '/api/student'], (req, res) => {
  const uid = req.params.uid || req.query.uid;
  if (!uid) {
    return res.status(400).json({ success: false, reason: 'Missing uid parameter' });
  }
  const sql = `SELECT * FROM studentdetails WHERE uid = ?`;
  db.query(sql, [uid], (err, rows) => {
    if (err || !rows || rows.length === 0) {
      return res.status(404).json({ success: false, reason: 'Student not found' });
    }
    return res.json({ success: true, data: rows[0] });
  });
});

// 2. Get Pending Pass Requests
router.get('/api/passes/pending', (req, res) => {
  const sql = `
    SELECT p.*, s.sname, s.department, s.status as hostel_status 
    FROM pass_requests p
    JOIN studentdetails s ON p.uid = s.uid
    WHERE p.status = 'pending'
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success: false, reason: err.message });
    return res.json({ success: true, data: rows || [] });
  });
});

// 3. Approve Gate Pass Request
router.post('/api/passes/approve', (req, res) => {
  const request_id = (req.body && req.body.request_id) || req.query.request_id;
  const admin_name = (req.body && req.body.admin_name) || req.query.admin_name || 'Admin';

  if (!request_id) {
    return res.status(400).json({ success: false, reason: 'Missing request_id' });
  }

  const getRequestSql = "SELECT * FROM pass_requests WHERE requestid = ? AND status = 'pending'";
  db.query(getRequestSql, [request_id], (err, requestResult) => {
    if (err || !requestResult || requestResult.length === 0) {
      return res.status(404).json({ success: false, reason: 'Request not found or already processed' });
    }

    const requestRow = requestResult[0];
    const updateSql = "UPDATE pass_requests SET status = 'approved', approved_by = ?, approved_at = NOW() WHERE requestid = ?";
    db.query(updateSql, [admin_name, request_id], (uErr) => {
      if (uErr) return res.status(500).json({ success: false, reason: 'Database error on update' });

      const notifSql = "INSERT INTO student_notifications (uid, type, title, message, created_at) VALUES (?, 'pass_approved', 'Pass Request Approved', ?, NOW())";
      const notifMsg = `Your ${requestRow.passtype} request has been approved by ${admin_name}. Please scan your ID at the gate to activate your pass.`;

      db.query(notifSql, [requestRow.uid, notifMsg], () => {
        return res.json({ success: true, message: 'Pass request approved successfully' });
      });
    });
  });
});

// 4. Active Passes Summary
router.get('/api/summary/active', (req, res) => {
  const sql = `SELECT passtype, COUNT(*) as count FROM log_details1 WHERE status = 'ACTIVE' GROUP BY passtype`;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success: false, reason: err.message });
    return res.json({ success: true, data: rows || [] });
  });
});

// 5. Post 10PM Restrictions
router.get('/api/summary/restrictions', (req, res) => {
  const sql = `
    SELECT p.uid, s.sname, s.department, p.restriction_reason, p.restricted_at 
    FROM pass_restriction_audit p
    JOIN studentdetails s ON p.uid = s.uid
    ORDER BY p.restricted_at DESC LIMIT 50`;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success: false, reason: err.message });
    return res.json({ success: true, data: rows || [] });
  });
});

module.exports = router;
module.exports.isValidSession = isValidSession;

