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
        maxAge: 60 * 60 * 1000,
        httpOnly: true,
        sameSite: 'lax'
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
    
    // 1. Intentar obtener el token del header de autorización (mejor práctica para APIs)
    const authHeader = req.headers['authorization'];
    if (authHeader) {
        token = authHeader.split(' ')[1];
    }
    
    // 2. Si no hay token en el header, intentar obtenerlo de la sesión (mejor para navegadores)
    if (!token && req.session.jwtToken) {
        token = req.session.jwtToken;
    }
    
    // 3. Si no hay token en la sesión, intentar obtenerlo del query (fallback)
    if (!token && req.query.token) {
        token = req.query.token;
        
        // Si el token viene en URL, redirigir a una URL limpia después de establecerlo en sesión
        req.session.jwtToken = token;
        
        // Eliminar el token de la URL por seguridad
        if (req.path === '/dashboard') {
            return res.redirect('/dashboard');
        }
    }

    if (!token) {
        return res.redirect('/');
    }

    try {
        // Verificar el token de forma segura
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Verificar que el token no haya expirado
        const now = Math.floor(Date.now() / 1000);
        if (decoded.exp && decoded.exp < now) {
            req.session.destroy();
            return res.redirect('/?session_expired=true');
        }
        
        // Establecer la información del usuario en el request
        req.token = token;
        req.user = decoded;
        
        // Guardar el token en la sesión para futuros requests
        req.session.jwtToken = token;
        
        // Continuar con el flujo normal
        next();
    } catch (err) {
        console.error('Token verification failed:', err.message);
        req.session.destroy();
        return res.redirect('/?invalid_token=true');
    }
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
        isProduction,
        sessionExpired: false,
        session_expired: req.query.session_expired || 'false',
        invalid_token: req.query.invalid_token || 'false'
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
        
        // Convert username to lowercase
        username = username.toLowerCase();

        // Validate that username and password exist
        if (!username || !password) {
            return res.status(400).send('Username and password are required');
        }

        // Validate minimum length
        if (username.length < 3 || password.length < 8) {
            return res.status(400).send('Username must be at least 3 characters and password at least 8 characters');
        }

        // Check if the user already exists
        const existingUser = await new Promise((resolve, reject) => {
            db.get('SELECT username FROM users WHERE username = ?', [username], (err, row) => {
                if (err) reject(err);
                resolve(row);
            });
        });

        if (existingUser) {
            return res.status(400).send('Username already exists');
        }

        // Generate password hash
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Generate MFA secret
        const secret = speakeasy.generateSecret({
            name: `LoginAPP (${username})`,
            length: 20
        });

        // Insert user into the database
        db.run(
            'INSERT INTO users (username, password, secret, isadmin, created_at) VALUES (?, ?, ?, ?, ?)',
            [username, hashedPassword, secret.base32, isadmin ? 1 : 0, getLocalDateTime()],
            function(err) {
                if (err) {
                    console.error('Error registering user:', err.message);
                    return res.status(500).send('Error registering user');
                }
                
                // Generate QR code for authenticator app setup
                QRCode.toDataURL(secret.otpauth_url, (err, data_url) => {
                    if (err) {
                        console.error('Error generating QR code:', err);
                        return res.status(500).send('Error generating QR code');
                    }
                    
                    // Add registration log
                    const userId = this.lastID;
                    db.run(
                        'INSERT INTO logs (action_type, action_description, performed_by, performed_on, created_at) VALUES (?, ?, ?, ?, ?)',
                        ['USER_REGISTER', `New user registered: ${username}`, userId, userId, getLocalDateTime()]
                    );
                    
                    // Return QR code and secret
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
        console.error('Error during registration:', error);
        res.status(500).send('Server error');
    }
});

// Ruta para mostrar la configuración MFA
app.get('/mfa-config', (req, res) => {
    // Esta página solo servirá para recibir parámetros y hacer un POST
    res.render('mfa-redirect');
});

// Ruta POST para MFA que recibe los datos de forma segura
app.post('/mfa-config', (req, res) => {
    const { username, password, qrCodeUrl, secretKey } = req.body;
    
    if (!username || !qrCodeUrl || !secretKey) {
        return res.redirect('/register');
    }
    
    res.render('mfa-config', {
        username,
        password: password || '',
        qrCodeUrl,
        secretKey
    });
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
            req.session.jwtToken = jwtToken;
            
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
    res.render('user-management', { 
        user: req.user,
        username: req.user.username,
        token: req.token
    });
});

// Ruta protegida para usuarios normales
app.get('/dashboard', verifyToken, (req, res) => {
    // Redirigir a la vista adecuada según el tipo de usuario
    if (req.user && req.user.isadmin) {
        res.render('user-management', { 
            user: req.user,
            username: req.user.username,
            token: req.token
        });
    } else {
        res.render('user-dashboard', { 
            user: req.user,
            username: req.user.username,
            token: req.token
        });
    }
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

// Ruta para verificar la sesión del token JWT
app.get('/check-session', verifyToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// API de gestión de usuarios (Admin)
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

// Actualizar usuario (Admin)
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
            db.run(
                `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
                params,
                function(err) {
                    if (err) {
                        console.error('Error updating user:', err);
                        return res.status(500).json({ error: 'Database error' });
                    }
                    
                    // Registrar log de los cambios realizados
                    db.run(
                        'INSERT INTO logs (action_type, action_description, performed_by, performed_on, created_at) VALUES (?, ?, ?, ?, ?)',
                        ['UPDATE_USER', `Updated ${logDescription.join(' and ')} for user ID: ${userId}`, adminId, userId, getLocalDateTime()]
                    );

                    res.json({ success: true });
                }
            );
        } else {
            res.json({ success: true });
        }
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// Eliminar usuario (Admin)
app.delete('/api/users/:id', verifyToken, isAdmin, (req, res) => {
    const userId = req.params.id;
    const adminId = req.user.id;

    db.get('SELECT username FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        db.run('DELETE FROM users WHERE id = ?', [userId], (err) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }

            // Registrar la acción en logs
            db.run(
                'INSERT INTO logs (action_type, action_description, performed_by, performed_on, created_at) VALUES (?, ?, ?, ?, ?)',
                ['DELETE_USER', `Deleted user: ${user.username}`, adminId, userId, getLocalDateTime()]
            );

            res.json({ success: true });
        });
    });
});

// Endpoint para crear subdominios
app.post("/nsubdmn", verifyToken, (req, res) => {
    const { NSBDMN } = req.body;
    const userId = req.user.id;

    if (!NSBDMN) {
        return res.status(400).json({
            error: 'Subdomain name is required'
        });
    }

    try {
        // Ejecutar el script para crear el subdominio
        const result = shell.exec('sh NSUBDOMAIN.sh ' + NSBDMN);
        
        if (result.code !== 0) {
            console.error('Error creating subdomain:', result.stderr);
            return res.status(500).json({
                error: 'Error creating subdomain'
            });
        }
        
        // Registrar la creación del subdominio
        db.run(
            'INSERT INTO logs (action_type, action_description, performed_by, performed_on, created_at) VALUES (?, ?, ?, ?, ?)',
            ['CREATE_SUBDOMAIN', `Created subdomain: ${NSBDMN}.lfsystems.com.co`, userId, userId, getLocalDateTime()]
        );

        return res.json({
            result: `Successfully created subdomain: ${NSBDMN}.lfsystems.com.co by user ${req.user.username}`
        });
    } catch (error) {
        console.error('Error executing subdomain script:', error);
        return res.status(500).json({
            error: 'Server error when creating subdomain'
        });
    }
});

// Ruta para mostrar la vista de logs para admin
app.get('/dashboard-logs', verifyToken, async (req, res) => {
    try {
        // Verificar que el usuario es admin
        if (!req.user.isadmin) {
            return res.redirect('/dashboard');
        }
        
        // Renderizar la vista de logs
        res.render('logs', {
            token: req.token,
            username: req.user.username
        });
    } catch (error) {
        console.error('Error rendering logs view:', error);
        return res.redirect('/');
    }
});

// Ruta para obtener logs (solo admins) - Con paginación
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
                logs.created_at
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

// Añadir una ruta para sesión expirada
app.get('/session-expired', (req, res) => {
    res.render('index', { 
        RECAPTCHA_SITE_KEY,
        isProduction,
        sessionExpired: true
    });
});

// Iniciar el servidor
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`Environment: ${NODE_ENV}`);
});

export default app; 