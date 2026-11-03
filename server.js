const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e6
});

const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

if (ADMIN_SECRET.length < 8) {
  console.error("ADMIN_SECRETを8文字以上で設定してください。");
  process.exit(1);
}

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ==============================
// データ保存
// ==============================

const DATA_FILE = path.join(__dirname, "data.json");

const DEFAULT_PERMISSIONS = {
  Owner: [
    "kick", "ban", "unban", "mute", "unmute",
    "lock", "unlock", "slowmode", "pin", "unpin",
    "ng_add", "ng_remove", "clear",
    "rank", "set_permissions"
  ],

  Admin: [
    "kick", "ban", "unban", "mute", "unmute",
    "lock", "unlock", "slowmode", "pin", "unpin",
    "ng_add", "ng_remove", "clear",
    "rank"
  ],

  Moderator: [
    "kick", "mute", "unmute",
    "slowmode", "pin", "unpin"
  ],

  Member: [],
  Regular: []
};

const DEFAULT_DATA = {
  rooms: {
    lobby: {
      id: "lobby",
      name: "ロビー",
      passwordSalt: null,
      passwordHash: null,
      messages: [],
      pinnedMessage: null
    }
  },

  rolesByUsername: {},
  profilesByUsername: {},
  permissions: DEFAULT_PERMISSIONS,
  bannedUsers: [],
  mutedUsers: [],
  ngWords: [],
  chatLocked: false,
  slowMode: 0,
  adminLogs: []
};

function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(DEFAULT_DATA, null, 2)
      );
      return JSON.parse(JSON.stringify(DEFAULT_DATA));
    }

    const old = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

    const data = {
      ...DEFAULT_DATA,
      ...old
    };

    data.rooms = old.rooms || DEFAULT_DATA.rooms;
    data.rolesByUsername = old.rolesByUsername || {};
    data.profilesByUsername = old.profilesByUsername || {};
    data.permissions = {
      ...DEFAULT_PERMISSIONS,
      ...(old.permissions || {})
    };

    data.bannedUsers = old.bannedUsers || [];
    data.mutedUsers = old.mutedUsers || [];
    data.ngWords = old.ngWords || [];
    data.adminLogs = old.adminLogs || [];

    // 古いデータのメッセージをロビーへ移行
    if (!data.rooms.lobby) {
      data.rooms.lobby = {
        id: "lobby",
        name: "ロビー",
        passwordSalt: null,
        passwordHash: null,
        messages: old.messages || [],
        pinnedMessage: old.pinnedMessage || null
      };
    } else {
      data.rooms.lobby.messages ||= old.messages || [];
      data.rooms.lobby.pinnedMessage ??= old.pinnedMessage || null;
    }

    return data;
  } catch (error) {
    console.error("データ読み込みエラー:", error);
    return JSON.parse(JSON.stringify(DEFAULT_DATA));
  }
}

let data = loadData();

function saveData() {
  try {
    fs.writeFileSync(
      DATA_FILE,
      JSON.stringify(data, null, 2)
    );
  } catch (error) {
    console.error("データ保存エラー:", error);
  }
}

// ==============================
// ユーザー管理
// ==============================

const users = new Map();

function normalizeName(name) {
  return String(name || "").trim().toLowerCase();
}

function getRole(username) {
  return data.rolesByUsername[normalizeName(username)] || "Regular";
}

function setRole(username, role) {
  data.rolesByUsername[normalizeName(username)] = role;
  saveData();
}

function hasPermission(socket, permission) {
  if (!socket.user) return false;

  if (socket.user.role === "Owner") {
    return true;
  }

  const permissions =
    data.permissions[socket.user.role] || [];

  return permissions.includes(permission);
}

function getUserList(roomId) {
  const result = [];

  for (const [id, user] of users.entries()) {
    if (user.roomId !== roomId) continue;

    result.push({
      id,
      username: user.username,
      role: user.role,
      avatar: user.avatar
    });
  }

  return result;
}

function updateUserList(roomId) {
  io.to(roomId).emit("user_list", getUserList(roomId));
  updateRoomList();
}

function updateRoomList() {
  const rooms = Object.values(data.rooms).map(room => {
    const count = [...users.values()].filter(
      user => user.roomId === room.id
    ).length;

    return {
      id: room.id,
      name: room.name,
      hasPassword: Boolean(room.passwordHash),
      userCount: count
    };
  });

  io.emit("room_list", rooms);
}

function systemMessage(roomId, message) {
  io.to(roomId).emit("system_message", message);
}

function logAction(admin, action, target = "") {
  data.adminLogs.unshift({
    admin,
    action,
    target,
    time: new Date().toISOString()
  });

  data.adminLogs = data.adminLogs.slice(0, 500);
  saveData();
}

// ==============================
// ルームのパスワード
// ==============================

function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return {
    salt,
    hash
  };
}

function checkRoomPassword(password, salt, hash) {
  if (!salt || !hash) return true;

  try {
    const input = crypto.scryptSync(
      String(password || ""),
      salt,
      64
    );

    const stored = Buffer.from(hash, "hex");

    return (
      stored.length === input.length &&
      crypto.timingSafeEqual(input, stored)
    );
  } catch {
    return false;
  }
}

function createRoomId() {
  return crypto.randomBytes(8).toString("hex");
}

// ==============================
// ルーム参加
// ==============================

function enterRoom(socket, roomId) {
  const room = data.rooms[roomId];

  if (!room) return false;

  const oldRoomId = socket.user.roomId;

  if (oldRoomId) {
    socket.leave(oldRoomId);
    updateUserList(oldRoomId);
  }

  socket.join(roomId);
  socket.user.roomId = roomId;

  socket.emit("room_joined", {
    roomId: room.id,
    roomName: room.name,
    messages: room.messages || [],
    pinnedMessage: room.pinnedMessage || null
  });

  updateUserList(roomId);
  updateRoomList();

  systemMessage(
    roomId,
    `${socket.user.username} が入室しました。`
  );

  return true;
}

// ==============================
// 接続処理
// ==============================

io.on("connection", socket => {
  console.log("接続:", socket.id);

  // ------------------------------
  // ログイン
  // ------------------------------

  socket.on("join", payload => {
    const username = String(
      payload?.username || ""
    ).trim();

    const password = String(
      payload?.password || ""
    );

    if (!username || username.length > 20) {
      socket.emit("login_error", "名前は1〜20文字にしてください。");
      return;
    }

    const key = normalizeName(username);

    if (data.bannedUsers.includes(key)) {
      socket.emit("login_error", "この名前はBANされています。");
      return;
    }

    let role = getRole(username);

    // Ownerログイン
    if (username.toLowerCase() === "owner") {
      const input = Buffer.from(password);
      const secret = Buffer.from(ADMIN_SECRET);

      if (
        input.length !== secret.length ||
        !crypto.timingSafeEqual(input, secret)
      ) {
        socket.emit("login_error", "Ownerパスワードが違います。");
        return;
      }

      role = "Owner";
      setRole(username, "Owner");

      // 同じOwner名でログインしていた場合は古い接続を切断
      for (const [id, user] of users.entries()) {
        if (
          normalizeName(user.username) === key &&
          id !== socket.id
        ) {
          const oldSocket = io.sockets.sockets.get(id);

          if (oldSocket) {
            oldSocket.emit("system_message", "別の接続からログインしました。");
            oldSocket.disconnect(true);
          }
        }
      }
    } else {
      const alreadyOnline = [...users.values()].some(
        user => normalizeName(user.username) === key
      );

      if (alreadyOnline) {
        socket.emit("login_error", "この名前はすでに使用されています。");
        return;
      }
    }

    const avatar = data.profilesByUsername[key] || null;

    socket.user = {
      username,
      role,
      roomId: "lobby",
      avatar,
      lastMessage: 0
    };

    users.set(socket.id, socket.user);

    socket.join("lobby");

    const lobby = data.rooms.lobby;

    socket.emit("joined", {
      username,
      role,
      roomId: "lobby",
      roomName: lobby.name,
      avatar,
      messages: lobby.messages || [],
      pinnedMessage: lobby.pinnedMessage || null
    });

    updateUserList("lobby");
    updateRoomList();

    systemMessage(
      "lobby",
      `${username} が入室しました。`
    );

    console.log(`${username} がログインしました。`);
  });

  // ------------------------------
  // ルーム一覧
  // ------------------------------

  socket.on("get_rooms", () => {
    updateRoomList();
  });

  // ------------------------------
  // ルーム作成
  // ------------------------------

  socket.on("create_room", payload => {
    if (!socket.user) return;

    const name = String(payload?.name || "").trim();
    const password = String(payload?.password || "");

    if (!name || name.length > 30) {
      socket.emit("system_message", "ルーム名は1〜30文字にしてください。");
      return;
    }

    const duplicate = Object.values(data.rooms).some(
      room => room.name.toLowerCase() === name.toLowerCase()
    );

    if (duplicate) {
      socket.emit("system_message", "同じ名前のルームがあります。");
      return;
    }

    const id = createRoomId();

    let passwordData = {
      salt: null,
      hash: null
    };

    if (password.length > 0) {
      if (password.length < 4 || password.length > 50) {
        socket.emit("system_message", "ルームパスワードは4〜50文字にしてください。");
        return;
      }

      passwordData = createPasswordHash(password);
    }

    data.rooms[id] = {
      id,
      name,
      passwordSalt: passwordData.salt,
      passwordHash: passwordData.hash,
      messages: [],
      pinnedMessage: null
    };

    saveData();

    socket.emit("system_message", `ルーム「${name}」を作成しました。`);

    enterRoom(socket, id);
    updateRoomList();
  });

  // ------------------------------
  // ルーム移動
  // ------------------------------

  socket.on("join_room", payload => {
    if (!socket.user) return;

    const roomId = String(payload?.roomId || "");
    const password = String(payload?.password || "");

    const room = data.rooms[roomId];

    if (!room) {
      socket.emit("system_message", "ルームが見つかりません。");
      return;
    }

    if (
      !checkRoomPassword(
        password,
        room.passwordSalt,
        room.passwordHash
      )
    ) {
      socket.emit("system_message", "ルームパスワードが違います。");
      return;
    }

    enterRoom(socket, roomId);
  });

  // ------------------------------
  // プロフィール画像
  // ------------------------------

  socket.on("set_profile", payload => {
    if (!socket.user) return;

    const avatar = payload?.avatar;

    if (avatar !== null && avatar !== "") {
      if (typeof avatar !== "string") return;

      if (avatar.length > 150000) {
        socket.emit("system_message", "画像サイズが大きすぎます。");
        return;
      }

      const allowed = /^data:image\/(png|jpeg|jpg|gif|webp);base64,/i;

      if (!allowed.test(avatar)) {
        socket.emit("system_message", "対応していない画像形式です。");
        return;
      }
    }

    const key = normalizeName(socket.user.username);

    socket.user.avatar = avatar || null;

    if (avatar) {
      data.profilesByUsername[key] = avatar;
    } else {
      delete data.profilesByUsername[key];
    }

    saveData();

    socket.emit("profile_updated", socket.user.avatar);

    updateUserList(socket.user.roomId);
  });

  // ------------------------------
  // チャット送信
  // ------------------------------

  socket.on("chat_message", payload => {
    if (!socket.user) return;

    const roomId = socket.user.roomId;
    const room = data.rooms[roomId];

    if (!room) return;

    const text = String(
      typeof payload === "string"
        ? payload
        : payload?.text || payload?.message || ""
    ).trim();

    if (!text) return;

    if (text.length > 1000) {
      socket.emit("system_message", "メッセージは1000文字以内にしてください。");
      return;
    }

    if (data.chatLocked) {
      socket.emit("system_message", "現在チャットはロックされています。");
      return;
    }

    if (data.mutedUsers.includes(normalizeName(socket.user.username))) {
      socket.emit("system_message", "あなたはミュートされています。");
      return;
    }

    const now = Date.now();
    const slowMode = Number(data.slowMode) || 0;

    if (
      slowMode > 0 &&
      now - socket.user.lastMessage < slowMode * 1000
    ) {
      socket.emit(
        "system_message",
        `スローモード中です。${slowMode}秒待ってください。`
      );
      return;
    }

    for (const word of data.ngWords) {
      if (word && text.toLowerCase().includes(word.toLowerCase())) {
        socket.emit("system_message", "NGワードが含まれています。");
        return;
      }
    }

    socket.user.lastMessage = now;

    const message = {
      id: crypto.randomBytes(8).toString("hex"),
      username: socket.user.username,
      role: socket.user.role,
      avatar: socket.user.avatar,
      text,
      time: new Date().toISOString()
    };

    room.messages ||= [];
    room.messages.push(message);
    room.messages = room.messages.slice(-200);

    saveData();

    io.to(roomId).emit("chat_message", message);
  });

  // ------------------------------
  // 権限情報取得
  // ------------------------------

  socket.on("get_permissions", () => {
    if (!socket.user) return;

    socket.emit("permissions_data", {
      permissions: data.permissions,
      role: socket.user.role
    });
  });

  // ------------------------------
  // 管理者操作
  // ------------------------------

  socket.on("admin_action", payload => {
    if (!socket.user) return;

    const action = String(payload?.action || "");
    const target = String(payload?.target || "");
    const roomId = socket.user.roomId;
    const room = data.rooms[roomId];

    if (!action) return;

    if (!hasPermission(socket, action)) {
      socket.emit("system_message", "この操作を行う権限がありません。");
      return;
    }

    const targetUser = [...users.entries()].find(
      ([id, user]) =>
        normalizeName(user.username) === normalizeName(target)
    );

    const targetSocket = targetUser
      ? io.sockets.sockets.get(targetUser[0])
      : null;

    const adminName = socket.user.username;

    // --------------------------
    // ランク変更
    // --------------------------

    if (action === "rank") {
      const newRole = String(payload?.role || payload?.rank || "");

      const allowedRoles = [
        "Owner",
        "Admin",
        "Moderator",
        "Member",
        "Regular"
      ];

      if (!allowedRoles.includes(newRole)) {
        socket.emit("system_message", "無効なランクです。");
        return;
      }

      if (!target) return;

      if (
        newRole === "Owner" &&
        socket.user.role !== "Owner"
      ) {
        socket.emit("system_message", "Ownerへの変更はOwnerのみ可能です。");
        return;
      }

      setRole(target, newRole);

      if (targetSocket?.user) {
        targetSocket.user.role = newRole;

        targetSocket.emit("role_updated", newRole);

        updateUserList(targetSocket.user.roomId);
      }

      logAction(adminName, `ランク変更: ${target} → ${newRole}`, target);

      socket.emit("system_message", `${target} のランクを ${newRole} に変更しました。`);
      return;
    }

    // --------------------------
    // 権限変更
    // --------------------------

    if (action === "set_permissions") {
      if (socket.user.role !== "Owner") {
        socket.emit("system_message", "権限設定はOwnerのみ変更できます。");
        return;
      }

      const role = String(payload?.role || "");
      const permissions = payload?.permissions;

      const allowedRoles = [
        "Admin",
        "Moderator",
        "Member",
        "Regular"
      ];

      if (
        !allowedRoles.includes(role) ||
        !Array.isArray(permissions)
      ) {
        socket.emit("system_message", "権限設定が正しくありません。");
        return;
      }

      const allowedPermissions = [
        "kick", "ban", "unban", "mute", "unmute",
        "lock", "unlock", "slowmode", "pin", "unpin",
        "ng_add", "ng_remove", "clear", "rank"
      ];

      data.permissions[role] = permissions.filter(
        permission => allowedPermissions.includes(permission)
      );

      saveData();

      io.emit("permissions_updated", data.permissions);

      logAction(adminName, `${role} の権限を変更`);

      socket.emit("system_message", `${role} の権限を更新しました。`);
      return;
    }

    // --------------------------
    // キック
    // --------------------------

    if (action === "kick") {
      if (!targetSocket) {
        socket.emit("system_message", "対象ユーザーが見つかりません。");
        return;
      }

      if (targetSocket.user.role === "Owner") {
        socket.emit("system_message", "Ownerはキックできません。");
        return;
      }

      const targetRoom = targetSocket.user.roomId;

      targetSocket.emit("system_message", "管理者によってキックされました。");
      targetSocket.disconnect(true);

      systemMessage(targetRoom, `${target} がキックされました。`);
      logAction(adminName, "キック", target);
      return;
    }

    // --------------------------
    // BAN
    // --------------------------

    if (action === "ban") {
      if (!target) return;

      if (targetSocket?.user?.role === "Owner") {
        socket.emit("system_message", "OwnerはBANできません。");
        return;
      }

      const key = normalizeName(target);

      if (!data.bannedUsers.includes(key)) {
        data.bannedUsers.push(key);
      }

      saveData();

      if (targetSocket) {
        targetSocket.emit("system_message", "BANされました。");
        targetSocket.disconnect(true);
      }

      logAction(adminName, "BAN", target);
      socket.emit("system_message", `${target} をBANしました。`);
      return;
    }

    // --------------------------
    // BAN解除
    // --------------------------

    if (action === "unban") {
      const key = normalizeName(target);

      data.bannedUsers = data.bannedUsers.filter(
        name => name !== key
      );

      saveData();

      logAction(adminName, "BAN解除", target);
      socket.emit("system_message", `${target} のBANを解除しました。`);
      return;
    }

    // --------------------------
    // ミュート
    // --------------------------

    if (action === "mute") {
      if (!target) return;

      const key = normalizeName(target);

      if (!data.mutedUsers.includes(key)) {
        data.mutedUsers.push(key);
      }

      saveData();

      if (targetSocket) {
        targetSocket.emit("system_message", "ミュートされました。");
      }

      logAction(adminName, "ミュート", target);
      socket.emit("system_message", `${target} をミュートしました。`);
      return;
    }

    // --------------------------
    // ミュート解除
    // --------------------------

    if (action === "unmute") {
      const key = normalizeName(target);

      data.mutedUsers = data.mutedUsers.filter(
        name => name !== key
      );

      saveData();

      if (targetSocket) {
        targetSocket.emit("system_message", "ミュートが解除されました。");
      }

      logAction(adminName, "ミュート解除", target);
      socket.emit("system_message", `${target} のミュートを解除しました。`);
      return;
    }

    // --------------------------
    // チャットロック
    // --------------------------

    if (action === "lock") {
      data.chatLocked = true;
      saveData();

      io.emit("system_message", "管理者によってチャットがロックされました。");
      logAction(adminName, "チャットロック");
      return;
    }

    if (action === "unlock") {
      data.chatLocked = false;
      saveData();

      io.emit("system_message", "チャットロックが解除されました。");
      logAction(adminName, "チャットロック解除");
      return;
    }

    // --------------------------
    // スローモード
    // --------------------------

    if (action === "slowmode") {
      const seconds = Number(
        payload?.seconds ?? payload?.value ?? 0
      );

      if (
        !Number.isInteger(seconds) ||
        seconds < 0 ||
        seconds > 300
      ) {
        socket.emit("system_message", "0〜300秒で設定してください。");
        return;
      }

      data.slowMode = seconds;
      saveData();

      io.emit(
        "system_message",
        seconds === 0
          ? "スローモードが解除されました。"
          : `スローモードが ${seconds} 秒に設定されました。`
      );

      logAction(adminName, `スローモード ${seconds}秒`);
      return;
    }

    // --------------------------
    // ピン留め
    // --------------------------

    if (action === "pin") {
      if (!room) return;

      const text = String(
        payload?.text || payload?.message || ""
      ).trim();

      if (!text) {
        socket.emit("system_message", "ピン留めする文章を入力してください。");
        return;
      }

      room.pinnedMessage = {
        text,
        username: adminName,
        time: new Date().toISOString()
      };

      saveData();

      io.to(roomId).emit("pinned_message", room.pinnedMessage);

      logAction(adminName, "ピン留め", text);
      return;
    }

    // --------------------------
    // ピン留め解除
    // --------------------------

    if (action === "unpin") {
      if (!room) return;

      room.pinnedMessage = null;
      saveData();

      io.to(roomId).emit("pinned_message", null);

      logAction(adminName, "ピン留め解除");
      return;
    }

    // --------------------------
    // NGワード追加
    // --------------------------

    if (action === "ng_add") {
      const word = String(
        payload?.word || payload?.text || ""
      ).trim();

      if (!word || word.length > 50) return;

      if (!data.ngWords.includes(word)) {
        data.ngWords.push(word);
      }

      saveData();

      logAction(adminName, "NGワード追加", word);
      socket.emit("system_message", `NGワード「${word}」を追加しました。`);
      return;
    }

    // --------------------------
    // NGワード削除
    // --------------------------

    if (action === "ng_remove") {
      const word = String(
        payload?.word || payload?.text || ""
      ).trim();

      data.ngWords = data.ngWords.filter(
        item => item !== word
      );

      saveData();

      logAction(adminName, "NGワード削除", word);
      socket.emit("system_message", `NGワード「${word}」を削除しました。`);
      return;
    }

    // --------------------------
    // 履歴削除
    // --------------------------

    if (action === "clear") {
      if (!room) return;

      room.messages = [];
      saveData();

      io.to(roomId).emit("clear_messages");

      logAction(adminName, "チャット履歴削除", room.name);
      return;
    }

    socket.emit("system_message", "不明な管理者操作です。");
  });

  // ------------------------------
  // 切断
  // ------------------------------

  socket.on("disconnect", () => {
    if (!socket.user) return;

    const username = socket.user.username;
    const roomId = socket.user.roomId;

    users.delete(socket.id);

    systemMessage(
      roomId,
      `${username} が退室しました。`
    );

    updateUserList(roomId);
    updateRoomList();

    console.log(`${username} が切断しました。`);
  });
});

// ==============================
// サーバー起動
// ==============================

server.listen(PORT, () => {
  console.log(`サーバー起動: port ${PORT}`);
});const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e6
});

const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

if (ADMIN_SECRET.length < 8) {
  console.error("ADMIN_SECRETを8文字以上で設定してください。");
  process.exit(1);
}

app.use(express.static(__dirname));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ==============================
// データ保存
// ==============================

const DATA_FILE = path.join(__dirname, "data.json");

const DEFAULT_PERMISSIONS = {
  Owner: [
    "kick", "ban", "unban", "mute", "unmute",
    "lock", "unlock", "slowmode", "pin", "unpin",
    "ng_add", "ng_remove", "clear",
    "rank", "set_permissions"
  ],

  Admin: [
    "kick", "ban", "unban", "mute", "unmute",
    "lock", "unlock", "slowmode", "pin", "unpin",
    "ng_add", "ng_remove", "clear",
    "rank"
  ],

  Moderator: [
    "kick", "mute", "unmute",
    "slowmode", "pin", "unpin"
  ],

  Member: [],
  Regular: []
};

const DEFAULT_DATA = {
  rooms: {
    lobby: {
      id: "lobby",
      name: "ロビー",
      passwordSalt: null,
      passwordHash: null,
      messages: [],
      pinnedMessage: null
    }
  },

  rolesByUsername: {},
  profilesByUsername: {},
  permissions: DEFAULT_PERMISSIONS,
  bannedUsers: [],
  mutedUsers: [],
  ngWords: [],
  chatLocked: false,
  slowMode: 0,
  adminLogs: []
};

function loadData() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(DEFAULT_DATA, null, 2)
      );
      return JSON.parse(JSON.stringify(DEFAULT_DATA));
    }

    const old = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));

    const data = {
      ...DEFAULT_DATA,
      ...old
    };

    data.rooms = old.rooms || DEFAULT_DATA.rooms;
    data.rolesByUsername = old.rolesByUsername || {};
    data.profilesByUsername = old.profilesByUsername || {};
    data.permissions = {
      ...DEFAULT_PERMISSIONS,
      ...(old.permissions || {})
    };

    data.bannedUsers = old.bannedUsers || [];
    data.mutedUsers = old.mutedUsers || [];
    data.ngWords = old.ngWords || [];
    data.adminLogs = old.adminLogs || [];

    // 古いデータのメッセージをロビーへ移行
    if (!data.rooms.lobby) {
      data.rooms.lobby = {
        id: "lobby",
        name: "ロビー",
        passwordSalt: null,
        passwordHash: null,
        messages: old.messages || [],
        pinnedMessage: old.pinnedMessage || null
      };
    } else {
      data.rooms.lobby.messages ||= old.messages || [];
      data.rooms.lobby.pinnedMessage ??= old.pinnedMessage || null;
    }

    return data;
  } catch (error) {
    console.error("データ読み込みエラー:", error);
    return JSON.parse(JSON.stringify(DEFAULT_DATA));
  }
}

let data = loadData();

function saveData() {
  try {
    fs.writeFileSync(
      DATA_FILE,
      JSON.stringify(data, null, 2)
    );
  } catch (error) {
    console.error("データ保存エラー:", error);
  }
}

// ==============================
// ユーザー管理
// ==============================

const users = new Map();

function normalizeName(name) {
  return String(name || "").trim().toLowerCase();
}

function getRole(username) {
  return data.rolesByUsername[normalizeName(username)] || "Regular";
}

function setRole(username, role) {
  data.rolesByUsername[normalizeName(username)] = role;
  saveData();
}

function hasPermission(socket, permission) {
  if (!socket.user) return false;

  if (socket.user.role === "Owner") {
    return true;
  }

  const permissions =
    data.permissions[socket.user.role] || [];

  return permissions.includes(permission);
}

function getUserList(roomId) {
  const result = [];

  for (const [id, user] of users.entries()) {
    if (user.roomId !== roomId) continue;

    result.push({
      id,
      username: user.username,
      role: user.role,
      avatar: user.avatar
    });
  }

  return result;
}

function updateUserList(roomId) {
  io.to(roomId).emit("user_list", getUserList(roomId));
  updateRoomList();
}

function updateRoomList() {
  const rooms = Object.values(data.rooms).map(room => {
    const count = [...users.values()].filter(
      user => user.roomId === room.id
    ).length;

    return {
      id: room.id,
      name: room.name,
      hasPassword: Boolean(room.passwordHash),
      userCount: count
    };
  });

  io.emit("room_list", rooms);
}

function systemMessage(roomId, message) {
  io.to(roomId).emit("system_message", message);
}

function logAction(admin, action, target = "") {
  data.adminLogs.unshift({
    admin,
    action,
    target,
    time: new Date().toISOString()
  });

  data.adminLogs = data.adminLogs.slice(0, 500);
  saveData();
}

// ==============================
// ルームのパスワード
// ==============================

function createPasswordHash(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return {
    salt,
    hash
  };
}

function checkRoomPassword(password, salt, hash) {
  if (!salt || !hash) return true;

  try {
    const input = crypto.scryptSync(
      String(password || ""),
      salt,
      64
    );

    const stored = Buffer.from(hash, "hex");

    return (
      stored.length === input.length &&
      crypto.timingSafeEqual(input, stored)
    );
  } catch {
    return false;
  }
}

function createRoomId() {
  return crypto.randomBytes(8).toString("hex");
}

// ==============================
// ルーム参加
// ==============================

function enterRoom(socket, roomId) {
  const room = data.rooms[roomId];

  if (!room) return false;

  const oldRoomId = socket.user.roomId;

  if (oldRoomId) {
    socket.leave(oldRoomId);
    updateUserList(oldRoomId);
  }

  socket.join(roomId);
  socket.user.roomId = roomId;

  socket.emit("room_joined", {
    roomId: room.id,
    roomName: room.name,
    messages: room.messages || [],
    pinnedMessage: room.pinnedMessage || null
  });

  updateUserList(roomId);
  updateRoomList();

  systemMessage(
    roomId,
    `${socket.user.username} が入室しました。`
  );

  return true;
}

// ==============================
// 接続処理
// ==============================

io.on("connection", socket => {
  console.log("接続:", socket.id);

  // ------------------------------
  // ログイン
  // ------------------------------

  socket.on("join", payload => {
    const username = String(
      payload?.username || ""
    ).trim();

    const password = String(
      payload?.password || ""
    );

    if (!username || username.length > 20) {
      socket.emit("login_error", "名前は1〜20文字にしてください。");
      return;
    }

    const key = normalizeName(username);

    if (data.bannedUsers.includes(key)) {
      socket.emit("login_error", "この名前はBANされています。");
      return;
    }

    let role = getRole(username);

    // Ownerログイン
    if (username.toLowerCase() === "owner") {
      const input = Buffer.from(password);
      const secret = Buffer.from(ADMIN_SECRET);

      if (
        input.length !== secret.length ||
        !crypto.timingSafeEqual(input, secret)
      ) {
        socket.emit("login_error", "Ownerパスワードが違います。");
        return;
      }

      role = "Owner";
      setRole(username, "Owner");

      // 同じOwner名でログインしていた場合は古い接続を切断
      for (const [id, user] of users.entries()) {
        if (
          normalizeName(user.username) === key &&
          id !== socket.id
        ) {
          const oldSocket = io.sockets.sockets.get(id);

          if (oldSocket) {
            oldSocket.emit("system_message", "別の接続からログインしました。");
            oldSocket.disconnect(true);
          }
        }
      }
    } else {
      const alreadyOnline = [...users.values()].some(
        user => normalizeName(user.username) === key
      );

      if (alreadyOnline) {
        socket.emit("login_error", "この名前はすでに使用されています。");
        return;
      }
    }

    const avatar = data.profilesByUsername[key] || null;

    socket.user = {
      username,
      role,
      roomId: "lobby",
      avatar,
      lastMessage: 0
    };

    users.set(socket.id, socket.user);

    socket.join("lobby");

    const lobby = data.rooms.lobby;

    socket.emit("joined", {
      username,
      role,
      roomId: "lobby",
      roomName: lobby.name,
      avatar,
      messages: lobby.messages || [],
      pinnedMessage: lobby.pinnedMessage || null
    });

    updateUserList("lobby");
    updateRoomList();

    systemMessage(
      "lobby",
      `${username} が入室しました。`
    );

    console.log(`${username} がログインしました。`);
  });

  // ------------------------------
  // ルーム一覧
  // ------------------------------

  socket.on("get_rooms", () => {
    updateRoomList();
  });

  // ------------------------------
  // ルーム作成
  // ------------------------------

  socket.on("create_room", payload => {
    if (!socket.user) return;

    const name = String(payload?.name || "").trim();
    const password = String(payload?.password || "");

    if (!name || name.length > 30) {
      socket.emit("system_message", "ルーム名は1〜30文字にしてください。");
      return;
    }

    const duplicate = Object.values(data.rooms).some(
      room => room.name.toLowerCase() === name.toLowerCase()
    );

    if (duplicate) {
      socket.emit("system_message", "同じ名前のルームがあります。");
      return;
    }

    const id = createRoomId();

    let passwordData = {
      salt: null,
      hash: null
    };

    if (password.length > 0) {
      if (password.length < 4 || password.length > 50) {
        socket.emit("system_message", "ルームパスワードは4〜50文字にしてください。");
        return;
      }

      passwordData = createPasswordHash(password);
    }

    data.rooms[id] = {
      id,
      name,
      passwordSalt: passwordData.salt,
      passwordHash: passwordData.hash,
      messages: [],
      pinnedMessage: null
    };

    saveData();

    socket.emit("system_message", `ルーム「${name}」を作成しました。`);

    enterRoom(socket, id);
    updateRoomList();
  });

  // ------------------------------
  // ルーム移動
  // ------------------------------

  socket.on("join_room", payload => {
    if (!socket.user) return;

    const roomId = String(payload?.roomId || "");
    const password = String(payload?.password || "");

    const room = data.rooms[roomId];

    if (!room) {
      socket.emit("system_message", "ルームが見つかりません。");
      return;
    }

    if (
      !checkRoomPassword(
        password,
        room.passwordSalt,
        room.passwordHash
      )
    ) {
      socket.emit("system_message", "ルームパスワードが違います。");
      return;
    }

    enterRoom(socket, roomId);
  });

  // ------------------------------
  // プロフィール画像
  // ------------------------------

  socket.on("set_profile", payload => {
    if (!socket.user) return;

    const avatar = payload?.avatar;

    if (avatar !== null && avatar !== "") {
      if (typeof avatar !== "string") return;

      if (avatar.length > 150000) {
        socket.emit("system_message", "画像サイズが大きすぎます。");
        return;
      }

      const allowed = /^data:image\/(png|jpeg|jpg|gif|webp);base64,/i;

      if (!allowed.test(avatar)) {
        socket.emit("system_message", "対応していない画像形式です。");
        return;
      }
    }

    const key = normalizeName(socket.user.username);

    socket.user.avatar = avatar || null;

    if (avatar) {
      data.profilesByUsername[key] = avatar;
    } else {
      delete data.profilesByUsername[key];
    }

    saveData();

    socket.emit("profile_updated", socket.user.avatar);

    updateUserList(socket.user.roomId);
  });

  // ------------------------------
  // チャット送信
  // ------------------------------

  socket.on("chat_message", payload => {
    if (!socket.user) return;

    const roomId = socket.user.roomId;
    const room = data.rooms[roomId];

    if (!room) return;

    const text = String(
      typeof payload === "string"
        ? payload
        : payload?.text || payload?.message || ""
    ).trim();

    if (!text) return;

    if (text.length > 1000) {
      socket.emit("system_message", "メッセージは1000文字以内にしてください。");
      return;
    }

    if (data.chatLocked) {
      socket.emit("system_message", "現在チャットはロックされています。");
      return;
    }

    if (data.mutedUsers.includes(normalizeName(socket.user.username))) {
      socket.emit("system_message", "あなたはミュートされています。");
      return;
    }

    const now = Date.now();
    const slowMode = Number(data.slowMode) || 0;

    if (
      slowMode > 0 &&
      now - socket.user.lastMessage < slowMode * 1000
    ) {
      socket.emit(
        "system_message",
        `スローモード中です。${slowMode}秒待ってください。`
      );
      return;
    }

    for (const word of data.ngWords) {
      if (word && text.toLowerCase().includes(word.toLowerCase())) {
        socket.emit("system_message", "NGワードが含まれています。");
        return;
      }
    }

    socket.user.lastMessage = now;

    const message = {
      id: crypto.randomBytes(8).toString("hex"),
      username: socket.user.username,
      role: socket.user.role,
      avatar: socket.user.avatar,
      text,
      time: new Date().toISOString()
    };

    room.messages ||= [];
    room.messages.push(message);
    room.messages = room.messages.slice(-200);

    saveData();

    io.to(roomId).emit("chat_message", message);
  });

  // ------------------------------
  // 権限情報取得
  // ------------------------------

  socket.on("get_permissions", () => {
    if (!socket.user) return;

    socket.emit("permissions_data", {
      permissions: data.permissions,
      role: socket.user.role
    });
  });

  // ------------------------------
  // 管理者操作
  // ------------------------------

  socket.on("admin_action", payload => {
    if (!socket.user) return;

    const action = String(payload?.action || "");
    const target = String(payload?.target || "");
    const roomId = socket.user.roomId;
    const room = data.rooms[roomId];

    if (!action) return;

    if (!hasPermission(socket, action)) {
      socket.emit("system_message", "この操作を行う権限がありません。");
      return;
    }

    const targetUser = [...users.entries()].find(
      ([id, user]) =>
        normalizeName(user.username) === normalizeName(target)
    );

    const targetSocket = targetUser
      ? io.sockets.sockets.get(targetUser[0])
      : null;

    const adminName = socket.user.username;

    // --------------------------
    // ランク変更
    // --------------------------

    if (action === "rank") {
      const newRole = String(payload?.role || payload?.rank || "");

      const allowedRoles = [
        "Owner",
        "Admin",
        "Moderator",
        "Member",
        "Regular"
      ];

      if (!allowedRoles.includes(newRole)) {
        socket.emit("system_message", "無効なランクです。");
        return;
      }

      if (!target) return;

      if (
        newRole === "Owner" &&
        socket.user.role !== "Owner"
      ) {
        socket.emit("system_message", "Ownerへの変更はOwnerのみ可能です。");
        return;
      }

      setRole(target, newRole);

      if (targetSocket?.user) {
        targetSocket.user.role = newRole;

        targetSocket.emit("role_updated", newRole);

        updateUserList(targetSocket.user.roomId);
      }

      logAction(adminName, `ランク変更: ${target} → ${newRole}`, target);

      socket.emit("system_message", `${target} のランクを ${newRole} に変更しました。`);
      return;
    }

    // --------------------------
    // 権限変更
    // --------------------------

    if (action === "set_permissions") {
      if (socket.user.role !== "Owner") {
        socket.emit("system_message", "権限設定はOwnerのみ変更できます。");
        return;
      }

      const role = String(payload?.role || "");
      const permissions = payload?.permissions;

      const allowedRoles = [
        "Admin",
        "Moderator",
        "Member",
        "Regular"
      ];

      if (
        !allowedRoles.includes(role) ||
        !Array.isArray(permissions)
      ) {
        socket.emit("system_message", "権限設定が正しくありません。");
        return;
      }

      const allowedPermissions = [
        "kick", "ban", "unban", "mute", "unmute",
        "lock", "unlock", "slowmode", "pin", "unpin",
        "ng_add", "ng_remove", "clear", "rank"
      ];

      data.permissions[role] = permissions.filter(
        permission => allowedPermissions.includes(permission)
      );

      saveData();

      io.emit("permissions_updated", data.permissions);

      logAction(adminName, `${role} の権限を変更`);

      socket.emit("system_message", `${role} の権限を更新しました。`);
      return;
    }

    // --------------------------
    // キック
    // --------------------------

    if (action === "kick") {
      if (!targetSocket) {
        socket.emit("system_message", "対象ユーザーが見つかりません。");
        return;
      }

      if (targetSocket.user.role === "Owner") {
        socket.emit("system_message", "Ownerはキックできません。");
        return;
      }

      const targetRoom = targetSocket.user.roomId;

      targetSocket.emit("system_message", "管理者によってキックされました。");
      targetSocket.disconnect(true);

      systemMessage(targetRoom, `${target} がキックされました。`);
      logAction(adminName, "キック", target);
      return;
    }

    // --------------------------
    // BAN
    // --------------------------

    if (action === "ban") {
      if (!target) return;

      if (targetSocket?.user?.role === "Owner") {
        socket.emit("system_message", "OwnerはBANできません。");
        return;
      }

      const key = normalizeName(target);

      if (!data.bannedUsers.includes(key)) {
        data.bannedUsers.push(key);
      }

      saveData();

      if (targetSocket) {
        targetSocket.emit("system_message", "BANされました。");
        targetSocket.disconnect(true);
      }

      logAction(adminName, "BAN", target);
      socket.emit("system_message", `${target} をBANしました。`);
      return;
    }

    // --------------------------
    // BAN解除
    // --------------------------

    if (action === "unban") {
      const key = normalizeName(target);

      data.bannedUsers = data.bannedUsers.filter(
        name => name !== key
      );

      saveData();

      logAction(adminName, "BAN解除", target);
      socket.emit("system_message", `${target} のBANを解除しました。`);
      return;
    }

    // --------------------------
    // ミュート
    // --------------------------

    if (action === "mute") {
      if (!target) return;

      const key = normalizeName(target);

      if (!data.mutedUsers.includes(key)) {
        data.mutedUsers.push(key);
      }

      saveData();

      if (targetSocket) {
        targetSocket.emit("system_message", "ミュートされました。");
      }

      logAction(adminName, "ミュート", target);
      socket.emit("system_message", `${target} をミュートしました。`);
      return;
    }

    // --------------------------
    // ミュート解除
    // --------------------------

    if (action === "unmute") {
      const key = normalizeName(target);

      data.mutedUsers = data.mutedUsers.filter(
        name => name !== key
      );

      saveData();

      if (targetSocket) {
        targetSocket.emit("system_message", "ミュートが解除されました。");
      }

      logAction(adminName, "ミュート解除", target);
      socket.emit("system_message", `${target} のミュートを解除しました。`);
      return;
    }

    // --------------------------
    // チャットロック
    // --------------------------

    if (action === "lock") {
      data.chatLocked = true;
      saveData();

      io.emit("system_message", "管理者によってチャットがロックされました。");
      logAction(adminName, "チャットロック");
      return;
    }

    if (action === "unlock") {
      data.chatLocked = false;
      saveData();

      io.emit("system_message", "チャットロックが解除されました。");
      logAction(adminName, "チャットロック解除");
      return;
    }

    // --------------------------
    // スローモード
    // --------------------------

    if (action === "slowmode") {
      const seconds = Number(
        payload?.seconds ?? payload?.value ?? 0
      );

      if (
        !Number.isInteger(seconds) ||
        seconds < 0 ||
        seconds > 300
      ) {
        socket.emit("system_message", "0〜300秒で設定してください。");
        return;
      }

      data.slowMode = seconds;
      saveData();

      io.emit(
        "system_message",
        seconds === 0
          ? "スローモードが解除されました。"
          : `スローモードが ${seconds} 秒に設定されました。`
      );

      logAction(adminName, `スローモード ${seconds}秒`);
      return;
    }

    // --------------------------
    // ピン留め
    // --------------------------

    if (action === "pin") {
      if (!room) return;

      const text = String(
        payload?.text || payload?.message || ""
      ).trim();

      if (!text) {
        socket.emit("system_message", "ピン留めする文章を入力してください。");
        return;
      }

      room.pinnedMessage = {
        text,
        username: adminName,
        time: new Date().toISOString()
      };

      saveData();

      io.to(roomId).emit("pinned_message", room.pinnedMessage);

      logAction(adminName, "ピン留め", text);
      return;
    }

    // --------------------------
    // ピン留め解除
    // --------------------------

    if (action === "unpin") {
      if (!room) return;

      room.pinnedMessage = null;
      saveData();

      io.to(roomId).emit("pinned_message", null);

      logAction(adminName, "ピン留め解除");
      return;
    }

    // --------------------------
    // NGワード追加
    // --------------------------

    if (action === "ng_add") {
      const word = String(
        payload?.word || payload?.text || ""
      ).trim();

      if (!word || word.length > 50) return;

      if (!data.ngWords.includes(word)) {
        data.ngWords.push(word);
      }

      saveData();

      logAction(adminName, "NGワード追加", word);
      socket.emit("system_message", `NGワード「${word}」を追加しました。`);
      return;
    }

    // --------------------------
    // NGワード削除
    // --------------------------

    if (action === "ng_remove") {
      const word = String(
        payload?.word || payload?.text || ""
      ).trim();

      data.ngWords = data.ngWords.filter(
        item => item !== word
      );

      saveData();

      logAction(adminName, "NGワード削除", word);
      socket.emit("system_message", `NGワード「${word}」を削除しました。`);
      return;
    }

    // --------------------------
    // 履歴削除
    // --------------------------

    if (action === "clear") {
      if (!room) return;

      room.messages = [];
      saveData();

      io.to(roomId).emit("clear_messages");

      logAction(adminName, "チャット履歴削除", room.name);
      return;
    }

    socket.emit("system_message", "不明な管理者操作です。");
  });

  // ------------------------------
  // 切断
  // ------------------------------

  socket.on("disconnect", () => {
    if (!socket.user) return;

    const username = socket.user.username;
    const roomId = socket.user.roomId;

    users.delete(socket.id);

    systemMessage(
      roomId,
      `${username} が退室しました。`
    );

    updateUserList(roomId);
    updateRoomList();

    console.log(`${username} が切断しました。`);
  });
});

// ==============================
// サーバー起動
// ==============================

server.listen(PORT, () => {
  console.log(`サーバー起動: port ${PORT}`);
});
