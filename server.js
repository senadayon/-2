const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const DATA_FILE = path.join(__dirname, 'data.json');

if (!ADMIN_SECRET || ADMIN_SECRET.length < 8) {
    console.error('ADMIN_SECRETに8文字以上の秘密の文字列を設定してください');
    process.exit(1);
}

const ROLES = [
    'Owner',
    'Admin',
    'Moderator',
    'Member',
    'Regular'
];

const PERMISSION_LABELS = {
    kick: 'ユーザーをキック',
    ban: 'ユーザーをBAN',
    unban: 'BAN解除',
    mute: 'ユーザーをミュート',
    unmute: 'ミュート解除',
    lock: 'チャットをロック',
    unlock: 'ロック解除',
    slowmode: 'スローモード設定',
    pin: 'メッセージ固定',
    unpin: '固定解除',
    ng_add: 'NGワード追加',
    ng_remove: 'NGワード削除',
    clear: '全メッセージ削除'
};

const PERMISSION_KEYS = Object.keys(PERMISSION_LABELS);

const DEFAULT_PERMISSIONS = {
    Owner: Object.fromEntries(
        PERMISSION_KEYS.map(key => [key, true])
    ),

    Admin: Object.fromEntries(
        PERMISSION_KEYS.map(key => [key, true])
    ),

    Moderator: Object.fromEntries(
        PERMISSION_KEYS.map(key => [
            key,
            [
                'kick',
                'mute',
                'unmute',
                'slowmode',
                'pin',
                'unpin'
            ].includes(key)
        ])
    ),

    Member: Object.fromEntries(
        PERMISSION_KEYS.map(key => [key, false])
    ),

    Regular: Object.fromEntries(
        PERMISSION_KEYS.map(key => [key, false])
    )
};

function defaultData() {
    return {
        rolesByUsername: {},
        permissions: JSON.parse(
            JSON.stringify(DEFAULT_PERMISSIONS)
        ),
        bannedUsers: [],
        mutedUsers: [],
        ngWords: [],
        messages: [],
        chatLocked: false,
        slowMode: 0,
        pinnedMessage: null,
        adminLogs: []
    };
}

function loadData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            return defaultData();
        }

        const raw = JSON.parse(
            fs.readFileSync(DATA_FILE, 'utf8')
        );

        const data = {
            ...defaultData(),
            ...raw
        };

        data.permissions = {
            ...DEFAULT_PERMISSIONS,
            ...(raw.permissions || {})
        };

        for (const role of ROLES) {
            data.permissions[role] = {
                ...DEFAULT_PERMISSIONS[role],
                ...(data.permissions[role] || {})
            };

            for (const key of PERMISSION_KEYS) {
                if (role === 'Owner') {
                    data.permissions[role][key] = true;
                } else if (role === 'Regular') {
                    data.permissions[role][key] = false;
                } else {
                    data.permissions[role][key] =
                        data.permissions[role][key] === true;
                }
            }
        }

        if (
            !data.rolesByUsername ||
            typeof data.rolesByUsername !== 'object'
        ) {
            data.rolesByUsername = {};
        }

        if (!Array.isArray(data.bannedUsers)) {
            data.bannedUsers = [];
        }

        if (!Array.isArray(data.mutedUsers)) {
            data.mutedUsers = [];
        }

        if (!Array.isArray(data.ngWords)) {
            data.ngWords = [];
        }

        if (!Array.isArray(data.messages)) {
            data.messages = [];
        }

        data.messages = data.messages.slice(-200);

        if (!Array.isArray(data.adminLogs)) {
            data.adminLogs = [];
        }

        data.adminLogs = data.adminLogs.slice(-500);

        return data;
    } catch (error) {
        console.error(
            'data.jsonの読み込みに失敗しました:',
            error.message
        );

        return defaultData();
    }
}

let data = loadData();

const users = new Map();

let saveTimer;

function saveData() {
    clearTimeout(saveTimer);

    saveTimer = setTimeout(() => {
        const tempFile = DATA_FILE + '.tmp';

        try {
            fs.writeFileSync(
                tempFile,
                JSON.stringify(data, null, 2),
                { mode: 0o600 }
            );

            fs.renameSync(tempFile, DATA_FILE);
        } catch (error) {
            console.error(
                'data.jsonの保存に失敗しました:',
                error.message
            );

            try {
                if (fs.existsSync(tempFile)) {
                    fs.unlinkSync(tempFile);
                }
            } catch (_) {}
        }
    }, 100);
}

app.use(express.static(__dirname, {
    index: false
}));

app.get('/', (_req, res) => {
    res.sendFile(
        path.join(__dirname, 'index.html')
    );
});

io.on('connection', socket => {

    // 入室
    socket.on('join', (payload = {}) => {
        if (users.has(socket.id)) {
            return;
        }

        let username =
            typeof payload.username === 'string'
                ? payload.username.trim().slice(0, 20)
                : '';

        if (!username) {
            socket.emit(
                'login_error',
                'ユーザー名を入力してください'
            );
            return;
        }

        const usernameKey = username.toLowerCase();

        // Ownerパスワードを先に確認
        const isOwner = safeCompare(
            payload.adminCode,
            ADMIN_SECRET
        );

        // BANチェック
        if (data.bannedUsers.includes(usernameKey)) {
            socket.emit(
                'login_error',
                'あなたはBANされています'
            );
            return;
        }

        // ユーザー名の重複チェック
        for (const [existingSocketId, existingUser] of users.entries()) {
            if (
                existingUser.username.toLowerCase() !==
                usernameKey
            ) {
                continue;
            }

            // Owner以外は重複ログイン禁止
            if (!isOwner) {
                socket.emit(
                    'login_error',
                    'そのユーザー名はすでに使用されています'
                );
                return;
            }

            // Ownerなら既存の同名ユーザーを切断
            io.to(existingSocketId).emit(
                'system_message',
                'Ownerが再ログインしたため接続を終了しました'
            );

            users.delete(existingSocketId);

            io.in(existingSocketId).disconnectSockets(true);
        }

        // 保存されたランクを読み込む
        let role = isOwner
            ? 'Owner'
            : data.rolesByUsername[usernameKey];

        if (
            !ROLES.includes(role) ||
            role === 'Owner'
        ) {
            role = 'Regular';
        }

        if (isOwner) {
            role = 'Owner';
        }

        const user = {
            username,
            role,
            lastMessage: 0
        };

        users.set(socket.id, user);

        socket.emit('joined', {
            username,
            role,
            messages: data.messages,
            pinnedMessage: data.pinnedMessage,
            permissions: data.permissions[role]
        });

        io.emit('user_list', getUserList());

        io.emit(
            'system_message',
            `${username} が入室しました`
        );
    });


    // Ownerだけがランク別権限を取得できる
    socket.on('get_permissions', () => {
        const user = users.get(socket.id);

        if (!user || user.role !== 'Owner') {
            return;
        }

        socket.emit(
            'permissions_data',
            data.permissions
        );
    });

    // メッセージ送信
    socket.on('chat_message', text => {
        const user = users.get(socket.id);

        if (!user) {
            return;
        }

        if (
            data.chatLocked &&
            user.role !== 'Owner'
        ) {
            socket.emit(
                'system_message',
                '現在チャットはロックされています'
            );
            return;
        }

        if (
            data.mutedUsers.includes(
                user.username.toLowerCase()
            )
        ) {
            socket.emit(
                'system_message',
                'ミュート中です'
            );
            return;
        }

        if (typeof text !== 'string') {
            return;
        }

        text = text.trim().slice(0, 1000);

        if (!text) {
            return;
        }

        const now = Date.now();

        if (
            now - user.lastMessage <
            data.slowMode * 1000
        ) {
            socket.emit(
                'system_message',
                `スローモード中です。${data.slowMode}秒待ってください`
            );
            return;
        }

        for (const word of data.ngWords) {
            if (
                text.toLowerCase().includes(
                    word.toLowerCase()
                )
            ) {
                socket.emit(
                    'system_message',
                    'NGワードが含まれています'
                );
                return;
            }
        }

        user.lastMessage = now;

        const message = {
            id:
                `${now}-` +
                crypto.randomBytes(4).toString('hex'),
            username: user.username,
            role: user.role,
            text,
            time: new Date().toLocaleTimeString('ja-JP')
        };

        data.messages.push(message);

        if (data.messages.length > 200) {
            data.messages.shift();
        }

        saveData();

        io.emit('chat_message', message);
    });

    // 管理操作
    socket.on('admin_action', (payload = {}) => {
        const user = users.get(socket.id);

        if (!user) {
            return;
        }

        const action =
            typeof payload.action === 'string'
                ? payload.action
                : '';

        const target =
            typeof payload.target === 'string'
                ? payload.target.trim().slice(0, 20)
                : '';

        const value = payload.value;

        // ランク変更：Owner専用
        if (action === 'rank') {
            if (user.role !== 'Owner') {
                return notify(
                    socket,
                    'ランク変更はOwnerのみ実行できます'
                );
            }

            if (!target) {
                return notify(
                    socket,
                    '対象ユーザー名を入力してください'
                );
            }

            if (
                !ROLES.includes(value) ||
                value === 'Owner'
            ) {
                return notify(
                    socket,
                    '選択したランクは無効です'
                );
            }

            const found = findUser(target);

            if (!found) {
                return notify(
                    socket,
                    '対象ユーザーが見つかりません'
                );
            }

            if (found.user.role === 'Owner') {
                return notify(
                    socket,
                    'Ownerのランクは変更できません'
                );
            }

            found.user.role = value;

            data.rolesByUsername[
                found.user.username.toLowerCase()
            ] = value;

            saveData();

            io.to(found.id).emit('role_updated', {
                username: found.user.username,
                role: value,
                permissions: data.permissions[value]
            });

            io.emit('user_list', getUserList());

            logAction(
                user.username,
                'RANK',
                `${found.user.username} -> ${value}`
            );

            return notify(
                socket,
                `${found.user.username} のランクを ${value} に変更しました`
            );
        }

        // ランク別権限の保存：Owner専用
        if (action === 'set_permissions') {
            if (user.role !== 'Owner') {
                return notify(
                    socket,
                    '権限設定はOwnerのみ実行できます'
                );
            }

            const role = payload.role;
            const permissions = payload.permissions;

            if (
                !['Admin', 'Moderator', 'Member'].includes(role) ||
                !permissions ||
                typeof permissions !== 'object'
            ) {
                return notify(
                    socket,
                    '権限設定が無効です'
                );
            }

            for (const key of PERMISSION_KEYS) {
                data.permissions[role][key] =
                    permissions[key] === true;
            }

            // OwnerとRegularの権限は固定
            data.permissions.Regular = {
                ...DEFAULT_PERMISSIONS.Regular
            };

            data.permissions.Owner = {
                ...DEFAULT_PERMISSIONS.Owner
            };

            saveData();

            for (const [id, connected] of users.entries()) {
                io.to(id).emit('permissions_updated', {
                    role: connected.role,
                    permissions:
                        data.permissions[connected.role]
                });
            }

            logAction(
                user.username,
                'PERMISSIONS',
                role
            );

            return notify(
                socket,
                `${role} の権限設定を保存しました`
            );
        }

        // 登録されている管理操作か確認
        if (!PERMISSION_KEYS.includes(action)) {
            return notify(
                socket,
                '不明な管理者コマンドです'
            );
        }

        // サーバー側で権限を必ず確認
        if (!hasPermission(user, action)) {
            return notify(
                socket,
                'この操作を実行する権限がありません'
            );
        }

        switch (action) {

            case 'kick': {
                const found = findUser(target);

                if (!found) {
                    return notify(
                        socket,
                        'ユーザーが見つかりません'
                    );
                }

                if (
                    found.user.role === 'Owner' ||
                    roleLevel(found.user.role) >=
                    roleLevel(user.role)
                ) {
                    return notify(
                        socket,
                        '自分と同じか上位のランクはキックできません'
                    );
                }

                io.to(found.id).emit(
                    'system_message',
                    '管理者にキックされました'
                );

                users.delete(found.id);

                io.in(found.id).disconnectSockets(true);

                io.emit('user_list', getUserList());

                logAction(user.username, 'KICK', target);

                return;
            }

            case 'ban': {
                if (!target) {
                    return notify(
                        socket,
                        '対象ユーザー名を入力してください'
                    );
                }

                const found = findUser(target);

                if (
                    found &&
                    (
                        found.user.role === 'Owner' ||
                        roleLevel(found.user.role) >=
                        roleLevel(user.role)
                    )
                ) {
                    return notify(
                        socket,
                        '自分と同じか上位のランクはBANできません'
                    );
                }

                if (
                    !data.bannedUsers.includes(
                        target.toLowerCase()
                    )
                ) {
                    data.bannedUsers.push(
                        target.toLowerCase()
                    );
                }

                if (found) {
                    disconnectTarget(
                        target,
                        'BANされました'
                    );
                }

                saveData();

                logAction(user.username, 'BAN', target);

                return notify(
                    socket,
                    `${target} をBANしました`
                );
            }

            case 'unban':
                data.bannedUsers =
                    data.bannedUsers.filter(
                        name => name !== target.toLowerCase()
                    );

                saveData();

                logAction(user.username, 'UNBAN', target);

                return notify(
                    socket,
                    `${target} のBANを解除しました`
                );

            case 'mute': {
                const found = findUser(target);

                if (!found) {
                    return notify(
                        socket,
                        'ユーザーが見つかりません'
                    );
                }

                if (
                    found.user.role === 'Owner' ||
                    roleLevel(found.user.role) >=
                    roleLevel(user.role)
                ) {
                    return notify(
                        socket,
                        '自分と同じか上位のランクはミュートできません'
                    );
                }

                if (
                    !data.mutedUsers.includes(
                        target.toLowerCase()
                    )
                ) {
                    data.mutedUsers.push(
                        target.toLowerCase()
                    );
                }

                saveData();

                logAction(user.username, 'MUTE', target);

                return notify(
                    socket,
                    `${target} をミュートしました`
                );
            }

            case 'unmute':
                data.mutedUsers =
                    data.mutedUsers.filter(
                        name => name !== target.toLowerCase()
                    );

                saveData();

                logAction(user.username, 'UNMUTE', target);

                return notify(
                    socket,
                    `${target} のミュートを解除しました`
                );

            case 'lock':
                data.chatLocked = true;
                saveData();

                io.emit(
                    'system_message',
                    'チャットがロックされました'
                );

                logAction(user.username, 'LOCK', '');

                return;

            case 'unlock':
                data.chatLocked = false;
                saveData();

                io.emit(
                    'system_message',
                    'チャットのロックが解除されました'
                );

                logAction(user.username, 'UNLOCK', '');

                return;

            case 'slowmode': {
                const seconds = Number(value);

                data.slowMode = Number.isFinite(seconds)
                    ? Math.max(0, Math.min(60, seconds))
                    : 0;

                saveData();

                logAction(
                    user.username,
                    'SLOWMODE',
                    String(data.slowMode)
                );

                return notify(
                    socket,
                    `スローモードを${data.slowMode}秒に設定しました`
                );
            }

            case 'pin':
                if (
                    typeof value !== 'string' ||
                    !value.trim()
                ) {
                    return notify(
                        socket,
                        '固定する文章を入力してください'
                    );
                }

                data.pinnedMessage =
                    value.trim().slice(0, 500);

                saveData();

                io.emit(
                    'pinned_message',
                    data.pinnedMessage
                );

                logAction(
                    user.username,
                    'PIN',
                    data.pinnedMessage
                );

                return notify(
                    socket,
                    'メッセージを固定しました'
                );

            case 'unpin':
                data.pinnedMessage = null;
                saveData();

                io.emit('pinned_message', null);

                logAction(user.username, 'UNPIN', '');

                return notify(
                    socket,
                    '固定を解除しました'
                );

            case 'ng_add':
                if (
                    typeof value !== 'string' ||
                    !value.trim()
                ) {
                    return notify(
                        socket,
                        'NGワードを入力してください'
                    );
                }

                if (
                    !data.ngWords.includes(
                        value.trim().slice(0, 50)
                    )
                ) {
                    data.ngWords.push(
                        value.trim().slice(0, 50)
                    );
                }

                saveData();

                logAction(
                    user.username,
                    'NG_ADD',
                    String(value)
                );

                return notify(
                    socket,
                    'NGワードを追加しました'
                );

            case 'ng_remove':
                data.ngWords = data.ngWords.filter(
                    word =>
                        word.toLowerCase() !==
                        String(value || '').toLowerCase()
                );

                saveData();

                logAction(
                    user.username,
                    'NG_REMOVE',
                    String(value || '')
                );

                return notify(
                    socket,
                    'NGワードを削除しました'
                );

            case 'clear':
                data.messages = [];
                saveData();

                io.emit('clear_messages');

                logAction(user.username, 'CLEAR', '');

                return notify(
                    socket,
                    'チャット履歴を削除しました'
                );
        }
    });

    // 切断
    socket.on('disconnect', () => {
        const user = users.get(socket.id);

        if (!user) {
            return;
        }

        users.delete(socket.id);

        io.emit(
            'system_message',
            `${user.username} が退室しました`
        );

        io.emit('user_list', getUserList());
    });
});

// パスワード比較
function safeCompare(input, secret) {
    if (typeof input !== 'string') {
        return false;
    }

    const a = Buffer.from(input);
    const b = Buffer.from(secret);

    return (
        a.length === b.length &&
        crypto.timingSafeEqual(a, b)
    );
}

// 権限確認
function hasPermission(user, permission) {
    return (
        user.role === 'Owner' ||
        data.permissions[user.role]?.[permission] === true
    );
}

// ランクの強さ
function roleLevel(role) {
    return {
        Owner: 5,
        Admin: 4,
        Moderator: 3,
        Member: 2,
        Regular: 1
    }[role] || 0;
}

// オンライン一覧
function getUserList() {
    return [...users.values()].map(user => ({
        username: user.username,
        role: user.role
    }));
}

// ユーザー検索
function findUser(username) {
    if (!username) {
        return null;
    }

    for (const [id, user] of users.entries()) {
        if (
            user.username.toLowerCase() ===
            username.toLowerCase()
        ) {
            return { id, user };
        }
    }

    return null;
}

// 対象ユーザー切断
function disconnectTarget(username, reason) {
    const found = findUser(username);

    if (!found) {
        return;
    }

    io.to(found.id).emit(
        'system_message',
        reason
    );

    users.delete(found.id);

    io.in(found.id).disconnectSockets(true);

    io.emit('user_list', getUserList());
}

// 通知
function notify(socket, message) {
    socket.emit('system_message', message);
}

// 管理ログ
function logAction(admin, action, target) {
    data.adminLogs.push({
        admin,
        action,
        target,
        time: new Date().toISOString()
    });

    if (data.adminLogs.length > 500) {
        data.adminLogs.shift();
    }

    saveData();
}

// サーバー起動
server.listen(PORT, () => {
    console.log(`チャットサーバー起動: ポート ${PORT}`);
});
