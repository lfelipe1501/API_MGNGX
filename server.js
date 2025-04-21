import express from 'express';
import bodyParser from 'body-parser';
import { db, getLocalDateTime } from './db.js';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import dotenv from 'dotenv';
import shell from 'shelljs';
import session from 'express-session';
import connectSqlite3 from 'connect-sqlite3';
import path from 'path';
import ipRangeCheck from 'ip-range-check';
import { fileURLToPath } from 'url';
import securityConfig from './config/security.js';

// Configurar __dirname para ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

// Configurar SQLiteStore para sesiones
const SQLiteStore = connectSqlite3(session);

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

const checkAllowedIP = (req, res, next) => {
    if (!securityConfig.IP_WHITELIST_ENABLED) {
        return next();
    }

    const clientIP = req.ip;
    
    // Verificar si la IP está en la lista de permitidos (IP individual o rango CIDR)
    const isAllowed = securityConfig.ALLOWED_IPS.some(allowedIP => {
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
        db.run(
            'INSERT INTO users (username, password, secret, isadmin, created_at) VALUES (?, ?, ?, ?, ?)',
            [username, hashedPassword, secret.base32, isadmin ? 1 : 0, getLocalDateTime()],
            function(err) {
                if (err) {
                    console.error('Error al registrar usuario:', err.message);
                    return res.status(500).send('Error registering user');
                }
                
                // Generar QR code para configurar la app de autenticación
                QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
                    if (err) {
                        console.error('Error al generar QR code:', err);
                        return res.status(500).send('Error generating QR code');
                    }
                    
                    // Agregar log del registro
                    const userId = this.lastID;
                    db.run(
                        'INSERT INTO logs (action_type, action_description, performed_by, performed_on, created_at) VALUES (?, ?, ?, ?, ?)',
                        ['USER_REGISTER', `New user registered: ${username}`, userId, userId, getLocalDateTime()]
                    );
                    
                    // Devolver QR code y secreto
                    res.json({
                        success: true,
                        message: 'User registered successfully',
                        qr_code: data_url,
                        secret: secret.base32
                    });
                });
            }
        );
    } catch (error) {
        console.error('Error en el registro:', error);
        res.status(500).send('Server error');
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password, token, recaptchaToken } = req.body;
        
        // Validar recaptcha
        if (!recaptchaToken) {
            return res.status(400).json({ error: 'reCAPTCHA verification failed' });
        }
        
        const isRecaptchaValid = await verifyRecaptcha(recaptchaToken);
        if (!isRecaptchaValid) {
            return res.status(400).json({ error: 'reCAPTCHA verification failed' });
        }
        
        // Buscar usuario
        db.get('SELECT * FROM users WHERE username = ?', [username.toLowerCase()], async (err, user) => {
            if (err) {
                console.error('Error al buscar usuario:', err.message);
                return res.status(500).json({ error: 'Server error' });
            }
            
            if (!user) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Verificar contraseña
            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Verificar token MFA
            const isTokenValid = speakeasy.totp.verify({
                secret: user.secret,
                encoding: 'base32',
                token: token,
                window: 1 // Permitir 1 intervalo de tiempo antes/después
            });
            
            if (!isTokenValid) {
                return res.status(401).json({ error: 'Invalid 2FA token' });
            }
            
            // Actualizar last_login
            db.run(
                'UPDATE users SET last_login = ? WHERE id = ?',
                [getLocalDateTime(), user.id]
            );
            
            // Agregar log de inicio de sesión
            db.run(
                'INSERT INTO logs (action_type, action_description, performed_by, performed_on, created_at) VALUES (?, ?, ?, ?, ?)',
                ['USER_LOGIN', `User logged in: ${username}`, user.id, user.id, getLocalDateTime()]
            );
            
            // Generar JWT
            const jwtToken = jwt.sign(
                { 
                    id: user.id, 
                    username: user.username,
                    isadmin: user.isadmin === 1
                },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            // Almacenar información en la sesión
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.isadmin = user.isadmin === 1;
            
            // Devolver información y token
            res.json({
                success: true,
                token: jwtToken,
                user: {
                    id: user.id,
                    username: user.username,
                    isadmin: user.isadmin === 1
                }
            });
        });
    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Ruta para cerrar sesión
app.post('/logout', (req, res) => {
    // Destruir la sesión
    req.session.destroy(err => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            return res.status(500).json({ error: 'Error cerrando sesión' });
        }
        
        res.json({ success: true, message: 'Sesión cerrada correctamente' });
    });
});

// Middleware para verificar si el usuario es administrador
const isAdmin = (req, res, next) => {
    if (req.user && req.user.isadmin) {
        next();
    } else {
        res.status(403).json({ error: 'Access denied. Admin privileges required.' });
    }
};

// Ruta protegida para administradores
app.get('/admin', verifyToken, isAdmin, (req, res) => {
    res.render('admin', { user: req.user });
});

// Ruta protegida para usuarios normales
app.get('/dashboard', verifyToken, (req, res) => {
    res.render('dashboard', { user: req.user });
});

// Ruta para verificar estado de autenticación
app.get('/verify-auth', (req, res) => {
    if (req.session.userId) {
        res.json({
            authenticated: true,
            user: {
                id: req.session.userId,
                username: req.session.username,
                isadmin: req.session.isadmin
            }
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Ruta para obtener logs (solo admins)
app.get('/api/logs', verifyToken, isAdmin, (req, res) => {
    db.all(`
        SELECT 
            logs.id, 
            logs.action_type, 
            logs.action_description, 
            u1.username as performed_by_user,
            u2.username as performed_on_user,
            logs.created_at
        FROM 
            logs
        LEFT JOIN 
            users u1 ON logs.performed_by = u1.id
        LEFT JOIN 
            users u2 ON logs.performed_on = u2.id
        ORDER BY 
            logs.created_at DESC
        LIMIT 100
    `, [], (err, rows) => {
        if (err) {
            console.error('Error al obtener logs:', err.message);
            return res.status(500).json({ error: 'Server error' });
        }
        
        res.json(rows);
    });
});

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Environment: ${NODE_ENV}`);
});

export default app; 