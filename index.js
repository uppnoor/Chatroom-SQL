const express = require('express');
const app = express();
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
require('dotenv').config();

const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(express.json());

app.set('view engine', 'ejs');

function sessionValidation(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}

const expireTime = 24 * 60 * 60 * 1000;
const session_secret = process.env.NODE_SESSION_SECRET;
const mongo_password = process.env.MONGO_PASSWORD;
const mongo_user = process.env.MONGO_USER;
const mongo_session_secret = process.env.SESSION_SECRET;
const my_sql_port = process.env.MYSQL_PORT
const mysql_password = process.env.MYSQL_DB_PASSWORD;
const mysql_username = process.env.MYSQL_USERNAME;

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongo_user}:${mongo_password}@cluster0.fwhcn.mongodb.net/assignment1?retryWrites=true&w=majority`,
    collectionName: 'cookies'
});

const db = mysql.createConnection({
    host: 'chatrooms-uppnoor41-36de.f.aivencloud.com',
    port: my_sql_port,
    user: mysql_username,
    password: mysql_password,
    database: 'chatrooms',
    ssl: {
        rejectUnauthorized: true,
        ca: process.env.MYSQL_CA_CERT,
    },
});

db.connect(err => {
    if (err) {
        console.error("MySQL connection error:", err);
        return;
    }
    console.log('Connected to MySQL database.');
});

app.use(session({
    secret: session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: {
        maxAge: expireTime,
        httpOnly: true
    }
}));

app.get('/', (req, res) => {
    if (req.session.authenticated) {
        const username = req.session.username;
        res.render('loggedIn', { username });
    } else {
        res.render('index');
    }
});

app.get('/signup', (req, res) => {
    var error = req.query.error;
    res.render('signup', { error });
});

app.get('/login', (req, res) => {
    var error = req.query.error;
    res.render('login', { error });
});

app.get('/chats', sessionValidation, (req, res) => {
    const userId = req.session.userId;

    const query = `
        SELECT 
            r.room_id, 
            r.name,
            COALESCE((
                SELECT COUNT(*)
                FROM message m
                JOIN room_user ru2 
                  ON m.room_user_id = ru2.room_user_id
                WHERE ru2.room_id = r.room_id
                  AND m.message_id > COALESCE(ru.last_read_message, 0)
            ), 0) AS unread_count
        FROM room r
        JOIN room_user ru ON r.room_id = ru.room_id
        WHERE ru.user_id = ?
    `;

    db.query(query, [userId], (err, rooms) => {
        if (err) {
            console.error("MySQL error in /chats route:", err);
            return res.status(500).send('Server error');
        }
        res.render('chats', { rooms });
    });
});


app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error("Session destruction error:", err);
        }
        res.redirect("/");
    });
});

app.post('/signup-submit', async (req, res) => {
    const { username, iden, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    if (!username || !iden || !password) {
        return res.redirect('/signup?error=Please fill in all fields');
    }

    const checkEmailQuery = 'SELECT email FROM user WHERE email = ?';

    db.query(checkEmailQuery, [iden], (err, result) => {
        if (err) {
            console.error('MySQL error checking email:', err);
            return res.status(500).send('Server error');
        }

        if (result.length > 0) {
            return res.redirect('/signup?error=Email already registered');
        }

        const insertUserQuery = `
          INSERT INTO user (username, email, password_hash)
          VALUES (?, ?, ?)
        `;

        db.query(insertUserQuery, [username, iden, hashedPassword], (err) => {
            if (err) {
                console.error('MySQL error inserting user:', err);
                return res.status(500).send('Error signing up');
            }
            return res.redirect('/login');
        });
    });
});

app.get('/create-chatroom', sessionValidation, (req, res) => {
    res.render('createChatroom', { error: null });
});

app.post('/create-chatroom', sessionValidation, (req, res) => {
    const userId = req.session.userId;
    const { name } = req.body;

    if (!name) {
        return res.render('createChatroom', { error: 'Please enter a room name.' });
    }

    const insertRoomQuery = `
        INSERT INTO room (name, start_datetime)
        VALUES (?, NOW())
    `;

    db.query(insertRoomQuery, [name], (err, result) => {
        if (err) {
            console.error("MySQL error inserting new room:", err);
            return res.status(500).send('Server error');
        }

        const newRoomId = result.insertId;

        const insertRoomUserQuery = `
            INSERT INTO room_user (user_id, room_id)
            VALUES (?, ?)
        `;
        db.query(insertRoomUserQuery, [userId, newRoomId], (err2) => {
            if (err2) {
                console.error("MySQL error inserting into room_user:", err2);
                return res.status(500).send('Server error');
            }

            res.redirect('/chats');
        });
    });
});

app.post('/login-submit', async (req, res) => {
    const { iden, password } = req.body;

    if (!iden || !password) {
        return res.redirect('/login?error=Please fill in all fields');
    }

    const loginUserQuery = 'SELECT * FROM user WHERE email = ?';

    db.query(loginUserQuery, [iden], async (err, results) => {
        if (err) {
            console.error('MySQL error in login-submit:', err);
            return res.status(500).send('Error logging in');
        }

        if (results.length === 0) {
            return res.redirect('/login?error=Invalid email or password');
        }

        const user = results[0];

        try {
            const isValid = await bcrypt.compare(password, user.password_hash);

            if (isValid) {
                req.session.authenticated = true;
                req.session.username = user.username;
                req.session.userId = user.user_id;

                req.session.cookie.maxAge = expireTime;
                return res.redirect('/');
            } else {
                return res.redirect('/login?error=Invalid email or password');
            }
        } catch (bcryptError) {
            console.error('Error comparing passwords:', bcryptError);
            return res.status(500).send('Server error');
        }
    });
});

app.get('/room/:id', sessionValidation, (req, res) => {
    const roomId = req.params.id;
    const userId = req.session.userId;

    const getRoomUser = `
      SELECT room_user_id, last_read_message
      FROM room_user
      WHERE room_id = ? AND user_id = ?
    `;
    db.query(getRoomUser, [roomId, userId], (err, ruResults) => {
        if (err) {
            console.error("MySQL error retrieving room_user record:", err);
            return res.status(500).send('Server error');
        }
        if (!ruResults.length) {
            return res.status(403).send('Not in this room');
        }

        const { room_user_id, last_read_message } = ruResults[0];

        const messagesQuery = `
          SELECT 
            m.message_id,
            m.text,
            m.sent_datetime,
            u.username
          FROM message m
          JOIN room_user ru ON m.room_user_id = ru.room_user_id
          JOIN user u       ON ru.user_id = u.user_id
          WHERE ru.room_id = ?
          ORDER BY m.sent_datetime ASC
        `;
        db.query(messagesQuery, [roomId], (err2, messages) => {
            if (err2) {
                console.error("MySQL error retrieving messages:", err2);
                return res.status(500).send('Server error');
            }

            db.query('SELECT * FROM room WHERE room_id = ?', [roomId], (err3, roomRes) => {
                if (err3) {
                    console.error("MySQL error retrieving room info:", err3);
                    return res.status(500).send('Server error');
                }
                if (!roomRes.length) {
                    return res.status(404).send('Room not found');
                }
                const room = roomRes[0];

                res.render('room', {
                    room,
                    messages,
                    lastReadId: last_read_message,
                    roomUserId: room_user_id
                });
            });
        });
    });
});

app.post('/room/:id/sendMessage', (req, res) => {
    const { messageText } = req.body;
    const roomId = req.params.id;
    const userId = req.session.userId;

    const getRoomUserId = `
        SELECT room_user_id
        FROM room_user
        WHERE user_id = ? AND room_id = ?
    `;
    db.query(getRoomUserId, [userId, roomId], (err, results) => {
        if (err) {
            console.error("MySQL error finding room_user_id:", err);
            return res.status(500).send('Server error');
        }
        if (!results.length) {
            return res.status(403).send('You are not in this room');
        }

        const myRoomUserId = results[0].room_user_id;

        const insertMessage = `
            INSERT INTO message (room_user_id, sent_datetime, text)
            VALUES (?, NOW(), ?)
        `;
        db.query(insertMessage, [myRoomUserId, messageText], (err2, result) => {
            if (err2) {
                console.error("MySQL error inserting message:", err2);
                return res.status(500).send('Server error');
            }

            const newMessageId = result.insertId;
            const updateLastRead = `
                UPDATE room_user
                SET last_read_message = ?
                WHERE room_user_id = ?
            `;
            db.query(updateLastRead, [newMessageId, myRoomUserId], (err3) => {
                if (err3) {
                    console.error("MySQL error updating last_read_message:", err3);
                }
                return res.redirect(`/room/${roomId}`);
            });
        });
    });
});


app.get('/room/:id/invite', sessionValidation, (req, res) => {
    const roomId = req.params.id;

    const roomQuery = 'SELECT * FROM room WHERE room_id = ?';
    db.query(roomQuery, [roomId], (err, roomResults) => {
        if (err) {
            console.error("MySQL error in /room/:id/invite GET:", err);
            return res.status(500).send('Server error');
        }
        if (roomResults.length === 0) {
            return res.status(404).send('Room not found');
        }
        const room = roomResults[0];
        res.render('invite', { room, error: null });
    });
});

app.post('/room/:id/invite', sessionValidation, (req, res) => {
    const roomId = req.params.id;
    const { username } = req.body;

    if (!username) {
        return res.render('invite', {
            room: { room_id: roomId, name: 'Room name if needed' },
            error: 'Please enter a username.'
        });
    }

    const userQuery = 'SELECT user_id FROM user WHERE username = ?';
    db.query(userQuery, [username], (err, userResults) => {
        if (err) {
            console.error("MySQL error finding user in invite POST:", err);
            return res.status(500).send('Server error');
        }
        if (userResults.length === 0) {
            return res.render('invite', {
                room: { room_id: roomId, name: 'Room name if needed' },
                error: 'User not found.'
            });
        }

        const invitedUserId = userResults[0].user_id;

        const insertRoomUser = `
            INSERT INTO room_user (user_id, room_id)
            VALUES (?, ?)
        `;
        db.query(insertRoomUser, [invitedUserId, roomId], (err2) => {
            if (err2) {
                console.error("MySQL error inserting invite:", err2);
                return res.status(500).send('Server error');
            }
            res.redirect(`/room/${roomId}`);
        });
    });
});

app.post('/room/:id/dismissUnreadBar', sessionValidation, (req, res) => {
    const roomId = req.params.id;
    const userId = req.session.userId;

    const lastMsgQuery = `
      SELECT m.message_id AS latestId
      FROM message m
      JOIN room_user ru ON ru.room_user_id = m.room_user_id
      WHERE ru.room_id = ?
      ORDER BY m.sent_datetime DESC
      LIMIT 1
    `;
    db.query(lastMsgQuery, [roomId], (err, results) => {
        if (err) {
            console.error("MySQL error retrieving most recent message:", err);
            return res.status(500).send('Server error');
        }
        if (!results.length) {
            return res.redirect(`/room/${roomId}`);
        }
        const latestMsgId = results[0].latestId;

        const updateQuery = `
          UPDATE room_user
          SET last_read_message = ?
          WHERE user_id = ? AND room_id = ?
        `;
        db.query(updateQuery, [latestMsgId, userId, roomId], (err2) => {
            if (err2) {
                console.error("MySQL error updating last_read_message:", err2);
                return res.status(500).send('Server error');
            }
            res.redirect(`/room/${roomId}`);
        });
    });
});

app.get('*', (req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
