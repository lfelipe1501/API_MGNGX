const express = require('express');
const bodyParser = require('body-parser');
const { db } = require('./db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const dotenv = require('dotenv');
const shell = require('shelljs');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const ipRangeCheck = require('ip-range-check');

// Determinar qué archivo .env cargar según NODE_ENV
const envFile = process.env.NODE_ENV === 'development' ? '.env.development' : '.env';
dotenv.config({ path: path.resolve(process.cwd(), envFile) });

// Obtener variables de entorno después de cargarlas
const {
    JWT_SECRET,
    RECAPTCHA_SITE_KEY,
    RECAPTCHA_SECRET_KEY,
    PORT,
    NODE_ENV
} = process.env;

// Determinar el puerto según el ambiente
const port = PORT || (NODE_ENV === 'production' ? 5001 : 3001);

// Determinar si estamos en ambiente de producción
const isProduction = NODE_ENV === 'production';

// Verificar si se está ejecutando con --check-env
const isCheckEnv = process.argv.includes('--check-env');

// Si se está ejecutando con --check-env, mostrar información y salir
if (isCheckEnv) {
    console.log('Actual Environment:', NODE_ENV);
    console.log('Port:', port);
    console.log('Enviroment File:', envFile);
    process.exit(0);
}

const app = express();
app.set('trust proxy', true);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    store: new SQLiteStore({
        db: 'database.sqlite',
        table: 'sessions'
    }),
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: NODE_ENV === 'production',
        maxAge: 5 * 60 * 1000,
        httpOnly: true
    },
    rolling: true
}));

async function verifyRecaptcha(token) {
    try {
        // Verificación diferente según el ambiente
        if (isProduction) {
            // Recaptcha V3 (producción)
            const response = await fetch(
                `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`,
                { method: 'POST' }
            );
            const data = await response.json();
            return data.success && data.score >= 0.5;
        } else {
            // Recaptcha V2 (desarrollo)
            const response = await fetch(
                `https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET_KEY}&response=${token}`,
                { method: 'POST' }
            );
            const data = await response.json();
            return data.success;
        }
    } catch (error) {
        return false;
    }
}

const verifyToken = (req, res, next) => {
    let token;
    
    // Intentar obtener el token del header de autorización
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        token = authHeader.split(' ')[1];
    }
    
    // Si no hay token en el header, intentar obtenerlo del query
    if (!token && req.query.token) {
        token = req.query.token;
    }

    if (!token) {
        return res.redirect('/');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.redirect('/');
        }
        req.token = token;
        req.user = decoded;
        next();
    });
};

const config = require('./config/security');

const checkAllowedIP = (req, res, next) => {
    if (!config.IP_WHITELIST_ENABLED) {
        return next();
    }

    const clientIP = req.ip;
    
    // Verificar si la IP está en la lista de permitidos (IP individual o rango CIDR)
    const isAllowed = config.ALLOWED_IPS.some(allowedIP => {
        // Si es un rango CIDR (contiene /)
        if (allowedIP.includes('/')) {
            return ipRangeCheck(clientIP, allowedIP);
        }
        // Si es una IP individual
        return clientIP === allowedIP;
    });
    
    if (!isAllowed) {
        return res.status(403).json({
            error: 'Access denied. Your IP is not authorized.'
        });
    }
    next();
};

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
    res.render('index', { 
        RECAPTCHA_SITE_KEY,
        isProduction
    });
});

app.get('/register', checkAllowedIP, (req, res) => {
    res.render('register');
});

// Modificar la ruta de registro para manejar JSON
app.use(express.json());

app.post('/register', checkAllowedIP, async (req, res) => {
    try {
        let { username, password, isadmin } = req.body;
        
        // Convertir username a minúsculas
        username = username.toLowerCase();

        // Validar que username y password existan
        if (!username || !password) {
            return res.status(400).send('Username and password are required');
        }

        // Validar longitud mínima
        if (username.length < 3 || password.length < 8) {
            return res.status(400).send('Username must be at least 3 characters and password at least 8 characters');
        }

        // Verificar si el usuario ya existe
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).send('Username already exists');
        }

        // Generar hash de la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generar secreto para MFA
        const secret = speakeasy.generateSecret({
            name: `LoginAPP (${username})`,
            length: 20
        });

        // Insertar usuario en la base de datos
        await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO users (username, password, secret, isadmin, created_at) VALUES (?, ?, ?, ?, datetime("now", "localtime"))',
                [username, hashedPassword, secret.base32, isadmin ? 1 : 0],
                function(err) {
                    if (err) reject(err);
                    resolve();
                }
            );
        });

        // Generar código QR
        const qrCodeUrl = await new Promise((resolve, reject) => {
            QRCode.toDataURL(secret.otpauth_url, (err, url) => {
                if (err) reject(err);
                resolve(url);
            });
        });

        // Renderizar la vista EJS en lugar de enviar HTML directamente
        res.render('mfa-config', {
            username,
            password,
            qrCodeUrl,
            secretKey: secret.base32
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).send('Error during registration. Please try again.');
    }
});


app.post('/login', async (req, res) => {
    const { password, token, recaptchaToken } = req.body;
    // Convertir username a minúsculas
    const username = req.body.username.toLowerCase();

    if (!await verifyRecaptcha(recaptchaToken)) {
        return res.status(400).json({ 
            success: false, 
            error: 'reCAPTCHA verification failed' 
        });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid credentials' 
            });
        }

        const verified = speakeasy.totp.verify({
            secret: user.secret,
            encoding: 'base32',
            token: token,
            window: 1
        });

        if (!verified) {
            return res.status(401).json({ 
                success: false, 
                error: 'Invalid MFA token' 
            });
        }

        const jwtToken = jwt.sign({ 
            id: user.id,
            username: username,
            isadmin: user.isadmin
        }, JWT_SECRET, { expiresIn: '5m' });

        req.session.user = {
            id: user.id,
            username: username,
            token: jwtToken
        };

        db.run('UPDATE users SET last_login = datetime("now", "localtime") WHERE id = ?', [user.id]);

        res.json({
            success: true,
            token: jwtToken,
            username: username
        });
    });
});

// Middleware para verificar si es admin
const isAdmin = (req, res, next) => {
    if (!req.user.isadmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
};

// Modificar la ruta de API para usuarios para incluir paginación
app.get('/api/users', verifyToken, isAdmin, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const offset = (page - 1) * limit;

    // Primero obtener el total de registros
    db.get('SELECT COUNT(*) as total FROM users', [], (err, count) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        // Luego obtener los registros paginados
        db.all(`
            SELECT id, username, isadmin, created_at 
            FROM users 
            ORDER BY created_at ASC
            LIMIT ? OFFSET ?
        `, [limit, offset], (err, users) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({
                users: users,
                totalPages: Math.ceil(count.total / limit),
                currentPage: page,
                totalRecords: count.total
            });
        });
    });
});

app.put('/api/users/:id', verifyToken, isAdmin, async (req, res) => {
    const { username, password } = req.body;
    const userId = req.params.id;
    const adminId = req.user.id;

    try {
        // Si ambos campos están vacíos, no hacer nada
        if (!username && !password) {
            return res.json({ success: true });
        }

        let updateFields = [];
        let params = [];
        let logDescription = [];

        // Agregar username a la actualización solo si no está vacío
        if (username) {
            updateFields.push('username = ?');
            params.push(username);
            logDescription.push('username');
        }

        // Agregar password a la actualización solo si no está vacío
        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updateFields.push('password = ?');
            params.push(hashedPassword);
            logDescription.push('password');
        }

        // Si hay campos para actualizar
        if (updateFields.length > 0) {
            params.push(userId);
            await new Promise((resolve, reject) => {
                db.run(
                    `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
                    params,
                    (err) => {
                        if (err) reject(err);
                        resolve();
                    }
                );
            });

            // Registrar log de los cambios realizados
            db.run(
                'INSERT INTO logs (action_type, action_description, performed_by, performed_on) VALUES (?, ?, ?, ?)',
                ['UPDATE_USER', `Updated ${logDescription.join(' and ')} for user ID: ${userId}`, adminId, userId]
            );
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

app.delete('/api/users/:id', verifyToken, isAdmin, (req, res) => {
    const userId = req.params.id;
    const adminId = req.user.id;

    db.get('SELECT username FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }

            // Registrar la acción en logs
            db.run(
                'INSERT INTO logs (action_type, action_description, performed_by, performed_on) VALUES (?, ?, ?, ?)',
                ['DELETE_USER', `Deleted user: ${user.username}`, adminId, userId]
            );

            res.json({ success: true });
        });
    });
});

// Modificar la ruta del dashboard para redirigir según el tipo de usuario
app.get('/dashboard', async (req, res) => {
    try {
        const token = req.headers.authorization?.split(' ')[1] || 
                     req.query.token || 
                     req.session?.user?.token;

        if (!token) {
            return res.redirect('/');
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!req.session.user || req.session.user.id !== decoded.id) {
                throw new Error('Invalid session');
            }

            if (decoded.isadmin) {
                res.render('user-management', {
                    token: token,
                    username: decoded.username
                });
            } else {
                res.render('user-dashboard', {
                    token: token,
                    username: decoded.username
                });
            }
        } catch (error) {
            return res.redirect('/');
        }
    } catch (error) {
        return res.redirect('/');
    }
});

app.post("/nsubdmn", verifyToken, (req, res) => {
    const { NSBDMN } = req.body;
    const userId = req.user.id;

    if (!NSBDMN) {
        return res.status(400).json({
            error: 'Subdomain name is required'
        });
    }

    shell.exec('sh NSUBDOMAIN.sh ' + NSBDMN);
    
    // Registrar la creación del subdominio
    db.run(
        'INSERT INTO logs (action_type, action_description, performed_by) VALUES (?, ?, ?)',
        ['CREATE_SUBDOMAIN', `Created subdomain: ${NSBDMN}.lfsystems.com.co`, userId]
    );

    return res.json({
        result: `Successfully created subdomain: ${NSBDMN}.lfsystems.com.co by user ${req.user.username}`
    });
});

app.post('/logout', verifyToken, (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/check-session', verifyToken, (req, res) => {
    res.json({ valid: true });
});

// Modificar la ruta de logs siguiendo el patrón de /dashboard
app.get('/dashboard-logs', async (req, res) => {
    try {
        // Intentar obtener el token del header de autorización
        const authHeader = req.headers.authorization;
        let token = authHeader ? authHeader.split(' ')[1] : null;

        // Si no hay token en el header, intentar obtenerlo de la sesión
        if (!token && req.session?.user?.token) {
            token = req.session.user.token;
        }

        // Si no hay token en ningún lado, redirigir al login
        if (!token) {
            return res.redirect('/');
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            if (!req.session.user || req.session.user.id !== decoded.id) {
                throw new Error('Invalid session');
            }

            if (decoded.isadmin) {
                res.render('logs', {
                    token: token,
                    username: decoded.username
                });
            } else {
                res.redirect('/dashboard');
            }
        } catch (error) {
            return res.redirect('/');
        }
    } catch (error) {
        return res.redirect('/');
    }
});

app.get('/api/logs', verifyToken, isAdmin, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = 5;
    const offset = (page - 1) * limit;

    // Primero obtener el total de registros
    db.get('SELECT COUNT(*) as total FROM logs', [], (err, count) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        // Luego obtener los registros paginados
        db.all(`
            SELECT 
                logs.*,
                performer.username as performed_by_username,
                target.username as performed_on_username,
                datetime(logs.created_at, 'localtime') as created_at
            FROM logs 
            LEFT JOIN users performer ON logs.performed_by = performer.id
            LEFT JOIN users target ON logs.performed_on = target.id
            ORDER BY logs.created_at DESC
            LIMIT ? OFFSET ?
        `, [limit, offset], (err, logs) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({
                logs: logs,
                totalPages: Math.ceil(count.total / limit),
                currentPage: page,
                totalRecords: count.total
            });
        });
    });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}.`);
});
