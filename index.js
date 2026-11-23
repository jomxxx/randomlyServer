const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const PORT = process.env.PORT || 3001;

const app = express();

// SECURITY HEADERS
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self' wss: ws: https://randomlyserver-production.up.railway.app",
      "frame-src 'none'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
    ].join("; ")
  );

  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
  );
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains; preload"
  );
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.removeHeader("X-Powered-By");

  next();
});

// BLOCK SENSITIVE PATHS
app.use((req, res, next) => {
  const BLOCKED = [
    "/admin",
    "/login",
    "/wp-admin",
    "/wp-login.php",
    "/.env",
    "/.git",
    "/.htaccess",
    "/config",
  ];

  const p = req.path.toLowerCase();

  if (BLOCKED.some((b) => p === b || p.startsWith(b + "/"))) {
    return res.status(404).json({ error: "Not found" });
  }

  next();
});

// HTTP SERVER
const server = http.createServer(app);

// SOCKET.IO CONFIGURATION — RAILWAY FIX
const io = new Server(server, {
  path: "/socket.io/",

  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },

  transports: ["polling", "websocket"],

  maxHttpBufferSize: 4 * 1024 * 1024,
  pingTimeout: 60000,
  pingInterval: 25000,
  connectTimeout: 45000,
});

// QUEUES
const maleQueue = [];
const femaleQueue = [];
const rooms = new Map();

// KEEP-CHATTING TOKENS
const keepTokens = new Map();
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;

function generateToken() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function cleanExpiredTokens() {
  const now = Date.now();

  for (const [token, data] of keepTokens.entries()) {
    if (now > data.expiresAt) {
      keepTokens.delete(token);
    }
  }
}

setInterval(cleanExpiredTokens, 30 * 60 * 1000);

// SECURITY TRACKING
const ipConnectionMap = new Map();
const abuseTracker = new Map();
const messageRateLimiter = new Map();
const rejoinTracker = new Map();
const inactivityTracker = new Map();

const SECURITY_CONFIG = {
  MAX_CONNECTIONS_PER_IP: 5,
  IP_COOLDOWN_MS: 2000,
  MESSAGES_PER_SECOND: 10,
  MAX_MESSAGE_LENGTH: 500,
  ABUSE_REPORT_THRESHOLD: 3,
  ABUSE_BLOCK_DURATION: 300000,
  REJOIN_COOLDOWN_MS: 3000,
  MAX_REJOIN_ATTEMPTS: 5,
  INACTIVITY_TIMEOUT_MS: 300000,
  RATE_LIMIT_WINDOW: 1000,
  MIN_MATCH_TIME_MS: 0,
  MAP_CLEANUP_INTERVAL_MS: 60000,
};

// HELPERS
function getClientIp(socket) {
  const forwarded =
    socket.handshake?.headers?.["x-forwarded-for"];

  const address =
    forwarded || socket.handshake?.address || "unknown";

  return String(address).split(",")[0].trim();
}

function isIpBlocked(ip) {
  const entry = abuseTracker.get(ip);

  if (!entry?.blockedUntil) return false;

  if (Date.now() > entry.blockedUntil) {
    abuseTracker.delete(ip);
    return false;
  }

  return true;
}

function trackConnectionAttempt(ip) {
  const now = Date.now();

  const entry = ipConnectionMap.get(ip) || {
    count: 0,
    lastConnection: 0,
  };

  if (now - entry.lastConnection > SECURITY_CONFIG.IP_COOLDOWN_MS) {
    entry.count = 1;
    entry.lastConnection = now;
  } else {
    entry.count += 1;
  }

  ipConnectionMap.set(ip, entry);

  return entry.count <= SECURITY_CONFIG.MAX_CONNECTIONS_PER_IP;
}

function trackRejoinAttempt(ip) {
  const now = Date.now();

  const entry = rejoinTracker.get(ip) || {
    count: 0,
    resetTime: now + SECURITY_CONFIG.REJOIN_COOLDOWN_MS,
  };

  if (now > entry.resetTime) {
    entry.count = 1;
    entry.resetTime =
      now + SECURITY_CONFIG.REJOIN_COOLDOWN_MS;
  } else {
    entry.count += 1;
  }

  rejoinTracker.set(ip, entry);

  return entry.count <= SECURITY_CONFIG.MAX_REJOIN_ATTEMPTS;
}

function trackMessageRate(socketId) {
  const now = Date.now();

  const entry = messageRateLimiter.get(socketId) || {
    count: 0,
    resetTime: now + SECURITY_CONFIG.RATE_LIMIT_WINDOW,
    violations: 0,
  };

  if (now > entry.resetTime) {
    entry.count = 1;
    entry.resetTime =
      now + SECURITY_CONFIG.RATE_LIMIT_WINDOW;
  } else {
    entry.count += 1;
  }

  messageRateLimiter.set(socketId, entry);

  if (entry.count > SECURITY_CONFIG.MESSAGES_PER_SECOND) {
    entry.violations += 1;
    messageRateLimiter.set(socketId, entry);
    return false;
  }

  return true;
}

function updateActivity(socket) {
  inactivityTracker.set(socket.id, Date.now());
}

function addReport(ip) {
  const now = Date.now();

  const entry = abuseTracker.get(ip) || {
    reportCount: 0,
    blockedUntil: 0,
  };

  entry.reportCount += 1;

  if (entry.reportCount >= SECURITY_CONFIG.ABUSE_REPORT_THRESHOLD) {
    entry.blockedUntil =
      now + SECURITY_CONFIG.ABUSE_BLOCK_DURATION;
  }

  abuseTracker.set(ip, entry);

  return entry;
}

// PERIODIC CLEANUP
setInterval(() => {
  const now = Date.now();

  for (const [ip, entry] of ipConnectionMap.entries()) {
    if (
      now - entry.lastConnection >
      SECURITY_CONFIG.IP_COOLDOWN_MS * 10
    ) {
      ipConnectionMap.delete(ip);
    }
  }

  for (const [ip, entry] of abuseTracker.entries()) {
    if (entry.blockedUntil && now > entry.blockedUntil) {
      abuseTracker.delete(ip);
    }
  }

  for (const [ip, entry] of rejoinTracker.entries()) {
    if (
      now >
      entry.resetTime + SECURITY_CONFIG.REJOIN_COOLDOWN_MS
    ) {
      rejoinTracker.delete(ip);
    }
  }

  for (const [socketId] of messageRateLimiter.entries()) {
    if (!io.sockets.sockets.get(socketId)) {
      messageRateLimiter.delete(socketId);
    }
  }
}, SECURITY_CONFIG.MAP_CLEANUP_INTERVAL_MS);

// INACTIVITY TIMEOUT
setInterval(() => {
  const now = Date.now();

  for (const [socketId, lastActive] of inactivityTracker.entries()) {
    if (now - lastActive > SECURITY_CONFIG.INACTIVITY_TIMEOUT_MS) {
      const staleSocket = io.sockets.sockets.get(socketId);

      if (staleSocket) {
        staleSocket.emit("match-error", {
          message: "Session ended due to inactivity.",
        });

        staleSocket.disconnect(true);
      }

      inactivityTracker.delete(socketId);
    }
  }
}, 30000);

// QUEUE HELPERS
function removeFromQueue(queue, socketId) {
  const idx = queue.indexOf(socketId);

  if (idx !== -1) {
    queue.splice(idx, 1);
    broadcastQueueStats();
  }
}

function removeFromAllQueues(socketId) {
  removeFromQueue(maleQueue, socketId);
  removeFromQueue(femaleQueue, socketId);
}

function broadcastQueueStats() {
  io.emit("queue-stats", {
    maleWaitingCount: maleQueue.length,
    femaleWaitingCount: femaleQueue.length,
    waitingCount: maleQueue.length + femaleQueue.length,
  });
}

function enqueue(socket) {
  if (!socket?.data?.gender) return;

  const id = socket.id;

  const queue =
    socket.data.gender === "male" ? maleQueue : femaleQueue;

  if (!queue.includes(id)) {
    queue.push(id);
  }

  socket.data.lastMatchRequest = Date.now();
  socket.data.inQueue = true;

  console.log(
    `[enqueue] ${id} (${socket.data.gender}) — male=${maleQueue.length} female=${femaleQueue.length}`
  );

  socket.emit("waiting");
  broadcastQueueStats();
}
