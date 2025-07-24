import express from 'express'
import bodyParser from 'body-parser'
import env from 'dotenv'
import db from './db.js'
import bcrypt, { hash } from 'bcrypt'
import session from 'express-session'
import passport from 'passport'
import GoogleStrategy from 'passport-google-oauth2'
import nodemailer from 'nodemailer'
import crypto from 'crypto'
import { error } from 'console'

const app = express();
const Port = 4000;
const saltRound = 10;
env.config();

db.connect()
    .then(() => {
        console.log('✅ Connected to the database');

        app.listen(process.env.PORT || 4000, () => {
            console.log(`🚀 Server running at http://localhost:${process.env.PORT || 4000}`);
        });
    })
    .catch((err) => {
        console.error('❌ Error while connecting to DB:', err);
    });

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}));

app.use(express.static('public'))
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }))
app.use(passport.initialize());
app.use(passport.session());
passport.use('google', new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://auth-system-3ufn.onrender.com/auth/google/callback",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    async (accessToken, refreshToken, profile, cb) => {
        try {
            const exits = await db.query("SELECT * FROM users WHERE email = $1", [profile.email])
            if (exits.rows.length === 0) {
                const newUser = await db.query("INSERT INTO users (username,email,password) values ($1,$2,$3)", [profile._json.name, profile.email, "google"])
                cb(null, newUser.rows[0])
            }
            else {
                // Already existing user
                cb(null, exits.rows[0])
            }
        }
        catch (err) {
            cb(err);
        }
    }
))

app.get('/auth/google', passport.authenticate("google", {
    scope: ["profile", "email"]
}))

app.get('/auth/google/callback', passport.authenticate("google", {
    successRedirect: '/',
    failureRedirect: '/failure'
}))

app.get('/failure', (req, res) => {
    res.send('failed')
})

passport.serializeUser((user, cb) => {
    cb(null, user)
})
passport.deserializeUser((user, cb) => {
    cb(null, user)
})

app.get('/', (req, res) => {
    const user = req.session.user || req.user;
    if (user || req.isAuthenticated()) {
        res.render('Jobs', { user: user });
    } else {
        res.redirect('/login');
    }
});

// Register page routes
app.get('/register', (req, res) => {
    res.status(200).render('register', { error: null })
})
app.post('/register', async (req, res) => {
    const fname = req.body.firstName
    const lname = req.body.lastName
    const Email = req.body.email
    const Password = req.body.password
    const Name = fname + ' ' + lname;
    try {
        const exist = await db.query('SELECT * FROM users WHERE email=$1', [Email])
        if (exist.rows.length > 0) {
            return res.render('register', { error: "Looks like this email is already registered. Try Sign In" });
        }
        else {
            bcrypt.hash(Password, saltRound, async (err, hash) => {
                if (err) { console.log(err) }
                else {
                    await db.query('INSERT INTO users (username,email,password) values($1,$2,$3)', [Name, Email.toLowerCase(), hash])
                    res.redirect('/login')
                }
            })
        }
    }
    catch (err) {
        console.log(err)
        res.status(500).render('500')
    }
})

// Login page routes
app.get('/login', (req, res) => {
    try {
        res.status(200).render('Login', { error: null })
    }
    catch (err) {
        console.error("🔥 Error in GET /register:", err);
        res.status(500).send("Internal Server Error");
    }
})
app.post('/login', async (req, res) => {
    const email = req.body.email;
    const password = (req.body.password);
    try {
        const checkuser = await db.query('SELECT * FROM users WHERE email = $1', [email])
        if (checkuser.rows.length > 0) {
            const user = checkuser.rows[0];
            const hashpass = user.password;
            bcrypt.compare(password, hashpass, async (err, result) => {
                if (err) { res.send('Internal server error') }
                else {
                    if (result) {
                        req.session.user = {
                            id: user.id,
                            email: user.email,
                            name: user.username
                        };
                        res.redirect('/')
                    }
                    else res.render('Login', { error: "Error: Please check your password." })
                }
            })
        } else {
            res.render('Login', { error: "Error: Please check your username." })
        }
    }
    catch (err) {
        console.log(err)
    }
})

// Reset page routes
app.get('/reset', (req, res) => {
    res.render('PassReset')
})
app.post('/reset', async (req, res) => {
    const email = req.body.email;

    const user = await db.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()])

    if (user.rows.length === 0) { res.send('No account with that email') }

    const token = crypto.randomBytes(32).toString('hex')
    const expires = new Date(Date.now() + 3600000)

    await db.query("UPDATE users SET reset_token=$1, reset_token_expires=$2 WHERE email=$3", [token, expires, email.toLowerCase()]);

    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        }
    })

    const resetLink = `${process.env.BASE_URL}/reset-password?token=${token}`;

    await transporter.sendMail({
        to: email,
        subject: "Password Reset",
        html: `<p>Click <a href="${resetLink}">here</a> to reset your password.</p>`,
    });
    res.send("Check your email for password reset link.")
})

// Reset-Password routes
app.get('/reset-password', async (req, res) => {
    const token = req.query.token
    console.log(token)
    const result = await db.query("SELECT * FROM users WHERE reset_token=$1 AND reset_token_expires>NOW()", [token])
    // console.log(result.rows[0])
    if (!result.rows[0]) { res.send('Invalid Token') }
    res.render('newPassword', { token: token })
})
app.post('/reset-pass', async (req, res) => {
    const newPassword = req.body.password;
    const token = req.body.token;
    const result = await db.query("SELECT * FROM users WHERE reset_token=$1 AND reset_token_expires > NOW()", [token])

    if (!result.rows[0]) { res.send('Invalid Token') }
    bcrypt.hash(newPassword, saltRound, async (err, hash) => {
        if (err) {
            console.log(err)
            res.send('error')
        }
        else {
            await db.query("UPDATE users SET password = $1, reset_token=NULL, reset_token_expires=NULL WHERE reset_token=$2", [hash, token])
            res.redirect('Dashboard')
        }
    })
})

// Logout routes
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/')
    })
})

// Error page route
app.use((req, res) => {
    res.status(404).render('404')
})

