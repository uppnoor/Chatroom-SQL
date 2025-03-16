const express = require('express');
const app = express();
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const MongoStore = require('connect-mongo');
require('dotenv').config();

const port = process.env.PORT || 8000;

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
        console.error('Database connection failed: ' + err.stack);
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
    if(req.session.authenticated) {
        const username = req.session.username;
        res.render('loggedIn', { username });
    } else {
        res.render('index')
    }
});

app.get('/signup', (req, res) => {
    var error = req.query.error
    res.render('signup', { error });
});

app.get('/login', (req, res) => {
    var error = req.query.error
    res.render('login', { error });
});

app.get('/chats', sessionValidation, (req, res) => {
    const userId = req.session.userId; // from the session
    if (!userId) {
        return res.redirect('/login?error=Please log in again');
    }

    const query = `
        SELECT r.room_id, r.name
        FROM room r
        JOIN room_user ru ON r.room_id = ru.room_id
        WHERE ru.user_id = ?
    `;

    db.query(query, [userId], (err, rooms) => {
        if (err) {
            console.error('Error fetching user rooms:', err);
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
            console.error('Error querying email:', err);
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
                console.error('Error inserting user:', err);
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
            console.error('Error inserting new room:', err);
            return res.status(500).send('Server error');
        }

        const newRoomId = result.insertId; // The newly created room_id

        // Insert a record into room_user to link this user to the new room
        const insertRoomUserQuery = `
            INSERT INTO room_user (user_id, room_id)
            VALUES (?, ?)
        `;
        db.query(insertRoomUserQuery, [userId, newRoomId], (err2) => {
            if (err2) {
                console.error('Error inserting into room_user:', err2);
                return res.status(500).send('Server error');
            }

            // Redirect back to /chats (or wherever you want)
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
            console.error('Error checking user:', err);
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



app.get('*', (req, res) => {
    res.status(404)
    res.render('404')
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
