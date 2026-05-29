const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const PORT = process.env.PORT || 3001;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
});

// ===== QUEUES =====
const maleQueue = [];
const femaleQueue = [];
const rooms = new Map(); // roomId -> { a, b }

// ===== SECURITY TRACKING =====
const ipConnectionMap = new Map();   // IP -> { count, lastConnection }
const abuseTracker = new Map();      // IP -> { reportCount, blockedUntil }
const messageRateLimiter = new Map(); // socketId -> { count, resetTime, violations }
const rejoinTracker = new Map();     // IP -> { count, resetTime }
const inactivityTracker = new Map(); // socketId -> lastActivityTime

const SECURITY_CONFIG = {
  MAX_CONNECTIONS_PER_IP: 5,
  IP_COOLDOWN_MS: 2000,
  MESSAGES_PER_SECOND: 10,
  MAX_MESSAGE_LENGTH: 500,          // FIX: prevent huge messages
  ABUSE_REPORT_THRESHOLD: 3,
  ABUSE_BLOCK_DURATION: 300000,     // 5 minutes
  REJOIN_COOLDOWN_MS: 3000,
  MAX_REJOIN_ATTEMPTS: 5,
  INACTIVITY_TIMEOUT_MS: 300000,    // 5 minutes
  RATE_LIMIT_WINDOW: 1000,          // 1 second
  MIN_MATCH_TIME_MS: 0,
  MAP_CLEANUP_INTERVAL_MS: 60000,   // FIX: clean stale map entries every 60s
};

// ===== HELPERS =====
function getClientIp(socket) {
  const forwarded = socket.handshake?.headers?.["x-forwarded-for"];
  const address = forwarded || socket.handshake?.address || "unknown";
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
  const entry = ipConnectionMap.get(ip) || { count: 0, lastConnection: 0 };
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
    entry.resetTime = now + SECURITY_CONFIG.REJOIN_COOLDOWN_MS;
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
    entry.resetTime = now + SECURITY_CONFIG.RATE_LIMIT_WINDOW;
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
  const entry = abuseTracker.get(ip) || { reportCount: 0, blockedUntil: 0 };
  entry.reportCount += 1;
  if (entry.reportCount >= SECURITY_CONFIG.ABUSE_REPORT_THRESHOLD) {
    entry.blockedUntil = now + SECURITY_CONFIG.ABUSE_BLOCK_DURATION;
  }
  abuseTracker.set(ip, entry);
  return entry;
}

// ===== FIX: Periodic cleanup of stale map entries =====
setInterval(() => {
  const now = Date.now();

  // Clean ipConnectionMap entries older than cooldown window
  for (const [ip, entry] of ipConnectionMap.entries()) {
    if (now - entry.lastConnection > SECURITY_CONFIG.IP_COOLDOWN_MS * 10) {
      ipConnectionMap.delete(ip);
    }
  }

  // Clean expired abuse blocks
  for (const [ip, entry] of abuseTracker.entries()) {
    if (entry.blockedUntil && now > entry.blockedUntil) {
      abuseTracker.delete(ip);
    }
  }

  // Clean expired rejoin entries
  for (const [ip, entry] of rejoinTracker.entries()) {
    if (now > entry.resetTime + SECURITY_CONFIG.REJOIN_COOLDOWN_MS) {
      rejoinTracker.delete(ip);
    }
  }

  // Clean message rate entries for disconnected sockets
  for (const [socketId] of messageRateLimiter.entries()) {
    if (!io.sockets.sockets.get(socketId)) {
      messageRateLimiter.delete(socketId);
    }
  }
}, SECURITY_CONFIG.MAP_CLEANUP_INTERVAL_MS);

// ===== Inactivity timeout =====
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

// ===== QUEUE HELPERS =====
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
  const queue = socket.data.gender === "male" ? maleQueue : femaleQueue;
  if (!queue.includes(id)) queue.push(id);
  socket.data.lastMatchRequest = Date.now();
  socket.data.inQueue = true;
  console.log(`[enqueue] ${id} (${socket.data.gender}) — male=${maleQueue.length} female=${femaleQueue.length}`);
  socket.emit("waiting");
  broadcastQueueStats();
}

// ===== MATCHING =====
function matchQueues() {
  while (maleQueue.length > 0 && femaleQueue.length > 0) {
    let matchFound = false;

    for (let i = 0; i < maleQueue.length; i++) {
      const aId = maleQueue[i];
      const a = io.sockets.sockets.get(aId);
      if (!a) { removeFromQueue(maleQueue, aId); continue; }

      for (let j = 0; j < femaleQueue.length; j++) {
        const bId = femaleQueue[j];
        const b = io.sockets.sockets.get(bId);
        if (!b) { removeFromQueue(femaleQueue, bId); continue; }

        const aAcceptsB = a.data?.want === "any" || a.data?.want === b.data?.gender;
        const bAcceptsA = b.data?.want === "any" || b.data?.want === a.data?.gender;

        if (aAcceptsB && bAcceptsA) {
          // FIX: remove each socket from their own correct queue only
          removeFromQueue(maleQueue, aId);
          removeFromQueue(femaleQueue, bId);
          createRoom(a, b);
          matchFound = true;
          break;
        }
      }

      if (matchFound) break;
    }

    if (!matchFound) break;
  }
}

function createRoom(aSocket, bSocket) {
  console.log(`[createRoom] ${aSocket.id} <-> ${bSocket.id}`);
  removeFromAllQueues(aSocket.id);
  removeFromAllQueues(bSocket.id);

  const roomId = `${aSocket.id}#${bSocket.id}`;
  aSocket.join(roomId);
  bSocket.join(roomId);
  rooms.set(roomId, { a: aSocket.id, b: bSocket.id });

  const now = Date.now();
  aSocket.data.roomId = roomId;
  aSocket.data.lastMatchedAt = now;
  aSocket.data.inQueue = false;

  bSocket.data.roomId = roomId;
  bSocket.data.lastMatchedAt = now;
  bSocket.data.inQueue = false;

  aSocket.emit("matched", { roomId, partnerId: bSocket.id, partnerAvatar: bSocket.data.avatar });
  bSocket.emit("matched", { roomId, partnerId: aSocket.id, partnerAvatar: aSocket.data.avatar });
}

function teardownRoom(roomId, reason, initiatorId = null) {
  const info = rooms.get(roomId);
  if (!info) return;

  const aSocket = io.sockets.sockets.get(info.a);
  const bSocket = io.sockets.sockets.get(info.b);

  rooms.delete(roomId);
  console.log(`[teardownRoom] room=${roomId} reason=${reason} initiator=${initiatorId}`);

  if (initiatorId) {
    const otherId = info.a === initiatorId ? info.b : info.a;
    const other = io.sockets.sockets.get(otherId);

    // Clear initiator room data
    const initiator = io.sockets.sockets.get(initiatorId);
    if (initiator) {
      initiator.leave(roomId);
      initiator.data.roomId = null;
    }

    if (other) {
      other.leave(roomId);
      other.data.roomId = null;

      // Send the correct message based on reason
      if (reason === "skipped") {
        // Partner clicked "Find Next" — tell other user stranger disconnected and is searching
        other.emit("partner-left", {
          reason,
          message: "⚠️ Stranger disconnected — searching for a new match...",
        });
        // Do NOT auto-requeue other here — let the next handler do it explicitly
      } else if (reason === "left") {
        other.emit("partner-left", {
          reason,
          message: "⚠️ Stranger left the chat.",
        });
        // Requeue the remaining user when partner fully left
        enqueue(other);
        matchQueues();
      }
    }
    return;
  }

  // Notify both
  [aSocket, bSocket].forEach((s) => {
    if (s) {
      s.leave(roomId);
      s.data.roomId = null;
      s.emit("partner-left", { reason, message: "Partner left the chat" });
    }
  });
}

// ===== SOCKET EVENTS =====
io.on("connection", (socket) => {
  const ip = getClientIp(socket);

  if (isIpBlocked(ip)) {
    socket.emit("blocked", { message: "This IP is temporarily blocked due to abuse reports." });
    socket.disconnect(true);
    return;
  }

  if (!trackConnectionAttempt(ip)) {
    socket.emit("match-error", { message: "Too many connection attempts. Please wait a moment." });
    socket.disconnect(true);
    return;
  }

  socket.data = {
    gender: null,
    roomId: null,
    avatar: null,
    hasJoined: false,
    inQueue: false,
    lastMatchRequest: 0,
    lastMatchedAt: 0,
  };

  socket.emit("queue-stats", {
    maleWaitingCount: maleQueue.length,
    femaleWaitingCount: femaleQueue.length,
    waitingCount: maleQueue.length + femaleQueue.length,
  });

  updateActivity(socket);
  socket.onAny(() => updateActivity(socket));

  // ── JOIN ──────────────────────────────────────────────────
  socket.on("join", ({ gender, avatar, want }) => {
    updateActivity(socket);
    const ip = getClientIp(socket);

    if (isIpBlocked(ip)) {
      socket.emit("blocked", { message: "This IP is temporarily blocked due to abuse reports." });
      socket.disconnect(true);
      return;
    }

    if (socket.data.hasJoined && !socket.data.roomId && !socket.data.inQueue) {
      // Allow rejoin after disconnect/next — reset flag
      socket.data.hasJoined = false;
    }

    if (socket.data.hasJoined) {
      socket.emit("match-error", { message: "You are already queued. Please wait for a match." });
      return;
    }

    if (!trackRejoinAttempt(ip)) {
      socket.emit("match-error", { message: "Too many quick reconnects. Please wait before trying again." });
      return;
    }

    socket.data.hasJoined = true;
    socket.data.gender = gender === "female" ? "female" : "male";
    socket.data.want = want === "female" ? "female" : want === "male" ? "male" : "any";
    socket.data.avatar = avatar || null;

    tryMatch(socket);
  });

  // ── MESSAGE ───────────────────────────────────────────────
  socket.on("message", ({ text }) => {
    updateActivity(socket);
    const rId = socket.data.roomId;
    if (!rId || typeof text !== "string") return;

    // FIX: enforce message length limit
    if (text.length > SECURITY_CONFIG.MAX_MESSAGE_LENGTH) {
      socket.emit("rate-limit", { message: "Message too long (max 500 characters)." });
      return;
    }

    if (!trackMessageRate(socket.id)) {
      socket.emit("rate-limit", { message: "Slow down — messages are limited to prevent spam." });
      return;
    }

    socket.to(rId).emit("message", { from: socket.id, text });
  });

  // ── TYPING ────────────────────────────────────────────────
  socket.on("typing", ({ typing }) => {
    updateActivity(socket);
    const rId = socket.data.roomId;
    if (!rId) return;
    socket.to(rId).emit("typing", { from: socket.id, typing });
  });

  // ── NEXT ──────────────────────────────────────────────────
  socket.on("next", () => {
    updateActivity(socket);
    const roomId = socket.data.roomId;

    // Not in a room — make sure they are queued
    if (!roomId) {
      if (!socket.data.inQueue) {
        socket.data.hasJoined = false;
        enqueue(socket);
        matchQueues();
      }
      return;
    }

    const info = rooms.get(roomId);
    if (!info) {
      // Room already gone, just requeue initiator
      socket.data.hasJoined = false;
      enqueue(socket);
      matchQueues();
      return;
    }

    const partnerId = info.a === socket.id ? info.b : info.a;

    // Notify partner with the correct disconnect message, clean up room
    teardownRoom(roomId, "skipped", socket.id);

    // Requeue the initiator immediately
    socket.data.hasJoined = false;
    enqueue(socket);
    matchQueues();

    // Requeue the partner after short delay so their UI shows the message first
    setTimeout(() => {
      const partnerSocket = io.sockets.sockets.get(partnerId);
      if (partnerSocket && !partnerSocket.data.roomId && !partnerSocket.data.inQueue) {
        partnerSocket.data.hasJoined = false;
        enqueue(partnerSocket);
        matchQueues();
      }
    }, 1500);
  });

  // ── REPORT ────────────────────────────────────────────────
  socket.on("report", ({ roomId, reportedId }) => {
    updateActivity(socket);
    const currentRoomId = socket.data.roomId;
    if (!currentRoomId || currentRoomId !== roomId || !reportedId) return;

    const reportedSocket = io.sockets.sockets.get(reportedId);
    if (!reportedSocket) return;

    const reportedIp = getClientIp(reportedSocket);
    const reportEntry = addReport(reportedIp);

    socket.emit("report-ack", {
      message: reportEntry.blockedUntil
        ? "Report received. User is temporarily blocked."
        : "Report received. Thank you.",
    });

    if (reportEntry.blockedUntil) {
      reportedSocket.emit("reported", { reportCount: reportEntry.reportCount, blocked: true });
      reportedSocket.emit("match-error", { message: "You have been temporarily blocked due to reports." });
      reportedSocket.disconnect(true);
    }
  });

  // ── LEAVE ─────────────────────────────────────────────────
  socket.on("leave", () => {
    const roomId = socket.data.roomId;
    if (roomId) {
      teardownRoom(roomId, "left", socket.id);
    }
    removeFromAllQueues(socket.id);
    socket.data.hasJoined = false;
    socket.data.inQueue = false;
  });

  // ── DISCONNECT ────────────────────────────────────────────
  socket.on("disconnect", () => {
    removeFromAllQueues(socket.id);
    inactivityTracker.delete(socket.id);
    messageRateLimiter.delete(socket.id);

    const roomId = socket.data.roomId;
    if (roomId) {
      const info = rooms.get(roomId);
      const otherId = info ? (info.a === socket.id ? info.b : info.a) : null;

      teardownRoom(roomId, "disconnected", socket.id);

      if (otherId) {
        const other = io.sockets.sockets.get(otherId);
        if (other && !other.data.roomId) {
          other.data.hasJoined = false;
          enqueue(other);
          matchQueues();
        }
      }
    }
  });
});

function tryMatch(socket) {
  if (!socket.data.gender) return;
  enqueue(socket);
  matchQueues();
}

// ===== ROUTES =====
app.get("/", (req, res) => res.send("Randoomly server running"));

// Health + stats endpoint — useful for monitoring
app.get("/stats", (req, res) => {
  res.json({
    activeConnections: io.sockets.sockets.size,
    activeRooms: rooms.size,
    maleQueue: maleQueue.length,
    femaleQueue: femaleQueue.length,
    blockedIps: [...abuseTracker.values()].filter((e) => e.blockedUntil > Date.now()).length,
  });
});

server.listen(PORT, () => console.log(`Server listening on ${PORT}`));