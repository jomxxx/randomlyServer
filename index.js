const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const PORT = process.env.PORT || 3001;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" },
});

const maleQueue = [];
const femaleQueue = [];

// ===== SECURITY & ANTI-ABUSE TRACKING =====
const ipConnectionMap = new Map(); // IP -> { count, lastConnection }
const abuseTracker = new Map(); // IP -> { reportCount, blockedUntil }
const messageRateLimiter = new Map(); // socketId -> { count, resetTime }
const rejoinTracker = new Map(); // IP -> { count, resetTime }
const inactivityTracker = new Map(); // socketId -> lastActivityTime

const SECURITY_CONFIG = {
  MAX_CONNECTIONS_PER_IP: 5,
  IP_COOLDOWN_MS: 2000,
  MESSAGES_PER_SECOND: 10,
  ABUSE_REPORT_THRESHOLD: 3,
  ABUSE_BLOCK_DURATION: 300000, // 5 minutes
  REJOIN_COOLDOWN_MS: 3000,
  MAX_REJOIN_ATTEMPTS: 5,
  INACTIVITY_TIMEOUT_MS: 300000, // 5 minutes
  RATE_LIMIT_WINDOW: 1000, // 1 second
  MIN_MATCH_TIME_MS: 8000,
};

function getClientIp(socket) {
  const forwarded = socket.handshake?.headers?.["x-forwarded-for"];
  const address = forwarded || socket.handshake?.address || "unknown";
  return String(address).split(",")[0].trim();
}

function isIpBlocked(ip) {
  const entry = abuseTracker.get(ip);
  if (!entry || !entry.blockedUntil) return false;
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

function trackMessageRate(socket) {
  const now = Date.now();
  const entry = messageRateLimiter.get(socket.id) || {
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
  messageRateLimiter.set(socket.id, entry);
  if (entry.count > SECURITY_CONFIG.MESSAGES_PER_SECOND) {
    entry.violations += 1;
    messageRateLimiter.set(socket.id, entry);
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

/**
 * Try to pair users from the male and female queues.
 * This will repeatedly create rooms while both queues have members.
 */
function matchQueues() {
  // Attempt to match any two waiting users when both accept each other.
  while (true) {
    const allIds = [...maleQueue, ...femaleQueue];
    let matchFound = false;

    for (let i = 0; i < allIds.length; i++) {
      const aId = allIds[i];
      const a = io.sockets.sockets.get(aId);
      if (!a) {
        removeFromQueue(maleQueue, aId);
        removeFromQueue(femaleQueue, aId);
        continue;
      }

      for (let j = i + 1; j < allIds.length; j++) {
        const bId = allIds[j];
        const b = io.sockets.sockets.get(bId);
        if (!b) {
          removeFromQueue(maleQueue, bId);
          removeFromQueue(femaleQueue, bId);
          continue;
        }

        const aWant = a.data?.want || "any";
        const bWant = b.data?.want || "any";
        const aGender = a.data?.gender;
        const bGender = b.data?.gender;

        const aAcceptsB = aWant === "any" || aWant === bGender;
        const bAcceptsA = bWant === "any" || bWant === aGender;

        if (aAcceptsB && bAcceptsA) {
          removeFromQueue(maleQueue, aId);
          removeFromQueue(femaleQueue, aId);
          removeFromQueue(maleQueue, bId);
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

function enqueue(socket) {
  if (!socket || !socket.data || !socket.data.gender) return;
  const id = socket.id;
  if (socket.data.gender === "male") {
    if (!maleQueue.includes(id)) maleQueue.push(id);
  } else {
    if (!femaleQueue.includes(id)) femaleQueue.push(id);
  }
  socket.data.lastMatchRequest = Date.now();
  console.log(
    `[enqueue] ${id} (${socket.data.gender}) queued. male=${maleQueue.length} female=${femaleQueue.length}`,
  );
  socket.emit("waiting");
}

function tryMatch(socket) {
  const gender = socket.data.gender;
  if (!gender) return;
  if (gender === "male") {
    enqueue(socket);
    matchQueues();
    return;
  }

  if (gender === "female") {
    enqueue(socket);
    matchQueues();
    return;
  }
}

const rooms = new Map(); // roomId -> {a, b}

function removeFromQueue(queue, socketId) {
  const idx = queue.indexOf(socketId);
  if (idx !== -1) queue.splice(idx, 1);
}

function createRoom(aSocket, bSocket) {
  console.log(`[createRoom] creating room for ${aSocket.id} and ${bSocket.id}`);
  // ensure sockets are removed from any queues
  removeFromQueue(maleQueue, aSocket.id);
  removeFromQueue(femaleQueue, aSocket.id);
  removeFromQueue(maleQueue, bSocket.id);
  removeFromQueue(femaleQueue, bSocket.id);
  const roomId = `${aSocket.id}#${bSocket.id}`;
  aSocket.join(roomId);
  bSocket.join(roomId);
  rooms.set(roomId, { a: aSocket.id, b: bSocket.id });
  aSocket.data.roomId = roomId;
  bSocket.data.roomId = roomId;
  const now = Date.now();
  aSocket.data.lastMatchedAt = now;
  bSocket.data.lastMatchedAt = now;
  aSocket.emit("matched", {
    roomId,
    partnerId: bSocket.id,
    partnerAvatar: bSocket.data.avatar,
  });
  bSocket.emit("matched", {
    roomId,
    partnerId: aSocket.id,
    partnerAvatar: aSocket.data.avatar,
  });
}

function teardownRoom(roomId, reason, initiatorId = null) {
  const info = rooms.get(roomId);
  if (!info) return;
  const a = io.sockets.sockets.get(info.a);
  const b = io.sockets.sockets.get(info.b);
  console.log(
    `[teardownRoom] room=${roomId} reason=${reason} initiator=${initiatorId}`,
  );

  // If initiatorId provided, only notify the other peer that their partner left
  if (initiatorId) {
    const otherId = info.a === initiatorId ? info.b : info.a;
    const other = io.sockets.sockets.get(otherId);
    if (other) {
      other.leave(roomId);
      other.data.roomId = null;
      other.emit("partner-left", { reason, message: "User left the chat" });

      // Automatically requeue the remaining participant when their partner left
      if (reason === "left") {
        enqueue(other);
        matchQueues();
      }
    }
    // remove room
    rooms.delete(roomId);
    return;
  }

  // Default behavior: notify both participants
  if (a) {
    a.leave(roomId);
    a.data.roomId = null;
    a.emit("partner-left", { reason, message: "Partner left the chat" });
  }
  if (b) {
    b.leave(roomId);
    b.data.roomId = null;
    b.emit("partner-left", { reason, message: "Partner left the chat" });
  }
  rooms.delete(roomId);
}

io.on("connection", (socket) => {
  const ip = getClientIp(socket);
  if (isIpBlocked(ip)) {
    socket.emit("blocked", {
      message: "This IP is temporarily blocked due to abuse reports.",
    });
    socket.disconnect(true);
    return;
  }

  if (!trackConnectionAttempt(ip)) {
    socket.emit("match-error", {
      message:
        "Too many connection attempts from this network. Please wait a moment.",
    });
    socket.disconnect(true);
    return;
  }

  socket.data = {
    gender: null,
    roomId: null,
    avatar: null,
    hasJoined: false,
    lastMatchRequest: 0,
    lastMatchedAt: 0,
  };

  updateActivity(socket);
  socket.onAny(() => updateActivity(socket));

  socket.on("join", ({ gender, avatar, want }) => {
    updateActivity(socket);
    const ip = getClientIp(socket);
    if (isIpBlocked(ip)) {
      socket.emit("blocked", {
        message: "This IP is temporarily blocked due to abuse reports.",
      });
      socket.disconnect(true);
      return;
    }

    if (socket.data.hasJoined) {
      socket.emit("match-error", {
        message: "You are already queued. Please wait for a match.",
      });
      return;
    }

    if (!trackRejoinAttempt(ip)) {
      socket.emit("match-error", {
        message: "Too many quick reconnects. Please wait before trying again.",
      });
      return;
    }

    socket.data.hasJoined = true;
    socket.data.gender = gender === "female" ? "female" : "male";
    socket.data.want = want === "female" ? "female" : want === "male" ? "male" : "any";
    socket.data.avatar = avatar || null;
    // centralize matching logic
    tryMatch(socket);
  });

  socket.on("message", ({ roomId, text }) => {
    updateActivity(socket);
    const rId = socket.data.roomId;
    if (!rId || typeof text !== "string") return;
    if (!trackMessageRate(socket)) {
      socket.emit("rate-limit", {
        message: "Slow down — messages are limited to prevent spam.",
      });
      return;
    }
    socket.to(rId).emit("message", { from: socket.id, text });
  });

  socket.on("typing", ({ roomId, typing }) => {
    updateActivity(socket);
    const rId = socket.data.roomId;
    if (!rId) return;
    socket.to(rId).emit("typing", { from: socket.id, typing });
  });

  socket.on("next", () => {
    updateActivity(socket);
    const roomId = socket.data.roomId;
    if (!roomId) return;
    if (
      Date.now() - (socket.data.lastMatchedAt || 0) <
      SECURITY_CONFIG.MIN_MATCH_TIME_MS
    ) {
      socket.emit("match-error", {
        message: "Please wait a few seconds before skipping to a new chat.",
      });
      return;
    }
    const info = rooms.get(roomId);
    if (!info) return;
    const aId = info.a;
    const bId = info.b;
    // teardown and notify only the partner (not the initiator)
    teardownRoom(roomId, "skipped", socket.id);
    // requeue both (if still connected)
    const aSock = io.sockets.sockets.get(aId);
    const bSock = io.sockets.sockets.get(bId);
    if (aSock) {
      enqueue(aSock);
      matchQueues();
    }
    if (bSock) {
      enqueue(bSock);
      matchQueues();
    }
  });

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
      reportedSocket.emit("reported", {
        reportCount: reportEntry.reportCount,
        blocked: true,
      });
      reportedSocket.emit("match-error", {
        message: "You have been temporarily blocked due to reports.",
      });
      reportedSocket.disconnect(true);
    }
  });

  socket.on("leave", () => {
    const roomId = socket.data.roomId;
    if (roomId) {
      // notify only the partner that this user left
      teardownRoom(roomId, "left", socket.id);
      return;
    }
    // remove from queues
    removeFromQueue(maleQueue, socket.id);
    removeFromQueue(femaleQueue, socket.id);
  });

  socket.on("disconnect", () => {
    // remove from queues
    removeFromQueue(maleQueue, socket.id);
    removeFromQueue(femaleQueue, socket.id);
    const roomId = socket.data.roomId;
    if (roomId) {
      const info = rooms.get(roomId);
      const otherId = info ? (info.a === socket.id ? info.b : info.a) : null;
      // notify only the other participant
      teardownRoom(roomId, "disconnected", socket.id);
      // requeue the remaining partner if connected
      if (otherId) {
        const other = io.sockets.sockets.get(otherId);
        if (other) {
          enqueue(other);
          matchQueues();
        }
      }
    }
  });
});

app.get("/", (req, res) => res.send("Randomly server running"));

server.listen(PORT, () => console.log(`Server listening on ${PORT}`));
