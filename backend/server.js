require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const pool = require('./db');

const app = express();

const hashPassword = (password) => {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `scrypt:${salt}:${hash}`;
};

const passwordMatches = (password, storedPassword) => {
    if (!storedPassword?.startsWith('scrypt:')) {
        return password === storedPassword;
    }

    const [, salt, storedHash] = storedPassword.split(':');
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(storedHash, 'hex'));
};

const asegurarSeguimientoRecuperacion = async (idObjeto, estado) => {
    if (estado === 'Perdido') {
        return;
    }

    const [existentes] = await pool.query(
        'SELECT id_recuperacion FROM recuperaciones WHERE id_objeto = ? LIMIT 1',
        [idObjeto]
    );
    const observacion = `Seguimiento actualizado: ${estado}`;

    if (existentes.length === 0) {
        await pool.query(
            'INSERT INTO recuperaciones (observacion, id_objeto) VALUES (?, ?)',
            [observacion, idObjeto]
        );
    } else {
        await pool.query(
            'UPDATE recuperaciones SET observacion = ? WHERE id_objeto = ?',
            [observacion, idObjeto]
        );
    }
};

app.use(cors());
app.use(express.json());

const inicializarBaseDeDatos = async () => {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id_usuario INT AUTO_INCREMENT PRIMARY KEY,
            nombre VARCHAR(100) NOT NULL,
            apellido VARCHAR(100) NOT NULL,
            correo VARCHAR(255) NOT NULL UNIQUE,
            contrasena VARCHAR(255) NOT NULL,
            rol VARCHAR(30) NOT NULL DEFAULT 'usuario',
            fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);
};

const migrarContrasenasLegadas = async () => {
    const [usuarios] = await pool.query(
        `SELECT id_usuario, contrasena
         FROM usuarios
         WHERE contrasena NOT LIKE 'scrypt:%'`
    );

    for (const usuario of usuarios) {
        await pool.query(
            'UPDATE usuarios SET contrasena = ? WHERE id_usuario = ?',
            [hashPassword(usuario.contrasena), usuario.id_usuario]
        );
    }

    if (usuarios.length > 0) {
        console.log(`${usuarios.length} contrasena(s) protegida(s) correctamente.`);
    }
};


// ==========================================
// RUTA PRINCIPAL
// ==========================================

app.get('/', (req, res) => {
    res.json({
        mensaje: 'Servidor AeroLost funcionando correctamente'
    });
});


// ==========================================
// PRUEBA DE CONEXIÓN CON MYSQL
// ==========================================

app.get('/api/prueba-db', async (req, res) => {
    try {
        const [rows] = await pool.query(
            'SELECT 1 AS conexion'
        );

        res.json({
            mensaje: 'Conexión con MySQL exitosa',
            resultado: rows
        });

    } catch (error) {
        console.error(
            'Error de conexión con MySQL:',
            error
        );

        res.status(500).json({
            mensaje: 'Error al conectar con MySQL',
            error: error.message
        });
    }
});


// ==========================================
// REGISTRAR USUARIO
// ==========================================

app.post('/api/usuarios', async (req, res) => {

    try {

        const {
            nombre,
            apellido,
            email,
            password
        } = req.body;


        // Validar campos

        if (!nombre || !apellido || !email || !password) {

            return res.status(400).json({
                mensaje: 'Todos los campos son obligatorios'
            });

        }


        // Verificar si el correo ya existe

        const [usuarioExiste] = await pool.query(
            'SELECT id_usuario FROM usuarios WHERE correo = ?',
            [email]
        );


        if (usuarioExiste.length > 0) {

            return res.status(409).json({
                mensaje: 'El correo electrónico ya está registrado'
            });

        }


        // Crear usuario

        const [resultado] = await pool.query(
            `INSERT INTO usuarios
            (nombre, apellido, correo, contrasena, rol)
            VALUES (?, ?, ?, ?, ?)`,
            [
                nombre,
                apellido,
                email,
                hashPassword(password),
                'usuario'
            ]
        );


        res.status(201).json({
            mensaje: 'Usuario registrado correctamente',
            usuario: {
                id: resultado.insertId,
                nombre,
                apellido,
                email,
                rol: 'usuario'
            }
        });


    } catch (error) {

        console.error(
            'Error al registrar usuario:',
            error
        );

        res.status(500).json({
            mensaje: 'Error al registrar usuario',
            error: error.message
        });
    }
});


// ==========================================
// INICIAR SESION
// ==========================================

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const emailNormalizado = email?.trim().toLowerCase();

        if (!emailNormalizado || !password) {
            return res.status(400).json({
                mensaje: 'El correo y la contraseña son obligatorios'
            });
        }

        const [usuarios] = await pool.query(
            `SELECT id_usuario AS id, nombre, apellido, correo AS email, contrasena, rol
             FROM usuarios
             WHERE correo = ?`,
            [emailNormalizado]
        );

        if (usuarios.length === 0 || !passwordMatches(password, usuarios[0].contrasena)) {
            return res.status(401).json({
                mensaje: 'Correo o contraseña incorrectos'
            });
        }

        delete usuarios[0].contrasena;

        res.json({
            mensaje: 'Inicio de sesión correcto',
            usuario: usuarios[0]
        });
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).json({
            mensaje: 'Error al iniciar sesión'
        });
    }
});

// ==========================================

app.get('/api/categorias', async (req, res) => {
    try {
        const [categorias] = await pool.query(
            'SELECT id_categoria, nombre, descripcion FROM categorias ORDER BY nombre'
        );
        res.json(categorias);
    } catch (error) {
        console.error('Error al consultar categorias:', error);
        res.status(500).json({ mensaje: 'Error al consultar categorias' });
    }
});

app.get('/api/objetos', async (req, res) => {
    try {
        const { buscar = '', estado = '', id_usuario } = req.query;
        const conditions = [];
        const values = [];

        if (buscar) {
            conditions.push('(o.nombre LIKE ? OR o.descripcion LIKE ? OR o.ubicacion LIKE ?)');
            const term = `%${buscar}%`;
            values.push(term, term, term);
        }
        if (estado) {
            conditions.push('o.estado = ?');
            values.push(estado);
        }
        if (id_usuario) {
            conditions.push('o.id_usuario = ?');
            values.push(id_usuario);
        }

        const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        const [objetos] = await pool.query(
            `SELECT o.id_objeto, o.nombre, o.descripcion, o.fecha_perdida,
                    o.fecha_encontrado, o.ubicacion, o.estado, o.imagen,
                    o.id_usuario, o.id_categoria, c.nombre AS categoria,
                    CONCAT(u.nombre, ' ', u.apellido) AS reportante
             FROM objetos o
             LEFT JOIN categorias c ON c.id_categoria = o.id_categoria
             LEFT JOIN usuarios u ON u.id_usuario = o.id_usuario
             ${where}
             ORDER BY o.id_objeto DESC`,
            values
        );
        res.json(objetos);
    } catch (error) {
        console.error('Error al consultar objetos:', error);
        res.status(500).json({ mensaje: 'Error al consultar objetos' });
    }
});

app.get('/api/objetos/:id', async (req, res) => {
    try {
        const [objetos] = await pool.query(
            `SELECT o.id_objeto, o.nombre, o.descripcion, o.fecha_perdida,
                    o.fecha_encontrado, o.ubicacion, o.estado, o.imagen,
                    o.id_usuario, o.id_categoria, c.nombre AS categoria,
                    CONCAT(u.nombre, ' ', u.apellido) AS reportante
             FROM objetos o
             LEFT JOIN categorias c ON c.id_categoria = o.id_categoria
             LEFT JOIN usuarios u ON u.id_usuario = o.id_usuario
             WHERE o.id_objeto = ?`,
            [req.params.id]
        );
        if (objetos.length === 0) {
            return res.status(404).json({ mensaje: 'Objeto no encontrado' });
        }
        res.json(objetos[0]);
    } catch (error) {
        console.error('Error al consultar objeto:', error);
        res.status(500).json({ mensaje: 'Error al consultar objeto' });
    }
});

app.post('/api/objetos', async (req, res) => {
    try {
        const {
            nombre, descripcion, fecha_perdida, fecha_encontrado,
            ubicacion, imagen, id_usuario, id_categoria, estado = 'PERDIDO'
        } = req.body;

        if (!nombre || !descripcion || !fecha_perdida || !ubicacion || !id_usuario || !id_categoria) {
            return res.status(400).json({ mensaje: 'Completa todos los datos del objeto' });
        }

        const [resultado] = await pool.query(
            `INSERT INTO objetos
             (nombre, descripcion, fecha_perdida, fecha_encontrado, ubicacion, estado, imagen, id_usuario, id_categoria)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [nombre.trim(), descripcion.trim(), fecha_perdida, fecha_encontrado || null,
                ubicacion.trim(), estado, imagen || null, id_usuario, id_categoria]
        );
        res.status(201).json({ mensaje: 'Objeto registrado correctamente', id_objeto: resultado.insertId });
    } catch (error) {
        console.error('Error al registrar objeto:', error);
        res.status(500).json({ mensaje: 'Error al registrar objeto' });
    }
});

app.post('/api/admin/objetos-encontrados', async (req, res) => {
    try {
        const {
            nombre, descripcion, fecha_perdida, ubicacion,
            imagen, id_usuario, id_categoria
        } = req.body;

        if (!nombre || !descripcion || !ubicacion || !id_usuario || !id_categoria) {
            return res.status(400).json({
                mensaje: 'Completa el objeto, la descripción, la zona, el usuario y la categoría'
            });
        }

        const [resultado] = await pool.query(
            `INSERT INTO objetos
             (nombre, descripcion, fecha_perdida, fecha_encontrado, ubicacion, estado, imagen, id_usuario, id_categoria)
             VALUES (?, ?, ?, CURRENT_DATE, ?, 'Encontrado', ?, ?, ?)`,
            [nombre.trim(), descripcion.trim(), fecha_perdida || null, ubicacion.trim(), imagen || null, id_usuario, id_categoria]
        );
        await asegurarSeguimientoRecuperacion(resultado.insertId, 'Encontrado');

        res.status(201).json({
            mensaje: 'Objeto encontrado registrado y usuario notificado',
            id_objeto: resultado.insertId
        });
    } catch (error) {
        console.error('Error al registrar objeto encontrado:', error);
        res.status(500).json({ mensaje: 'Error al registrar objeto encontrado' });
    }
});

app.put('/api/objetos/:id', async (req, res) => {
    try {
        const { nombre, descripcion, fecha_perdida, fecha_encontrado, ubicacion, estado, imagen, id_categoria, id_usuario } = req.body;
        const allowedStatuses = ['Perdido', 'Encontrado', 'En revision', 'Devuelto'];
        if (estado && !allowedStatuses.includes(estado)) {
            return res.status(400).json({ mensaje: 'Estado de objeto no válido' });
        }

        if (id_usuario) {
            const [ownedObjects] = await pool.query(
                'SELECT estado FROM objetos WHERE id_objeto = ? AND id_usuario = ?',
                [req.params.id, id_usuario]
            );
            if (ownedObjects.length === 0) {
                return res.status(404).json({ mensaje: 'Reporte no encontrado' });
            }
            if (ownedObjects[0].estado !== 'Perdido') {
                return res.status(409).json({
                    mensaje: 'Este reporte está cerrado porque el objeto ya fue encontrado o devuelto'
                });
            }
        }

        const ownerCondition = id_usuario ? ' AND id_usuario = ?' : '';
        const foundDate = estado === 'Encontrado' && !fecha_encontrado ? new Date() : fecha_encontrado;
        const [resultado] = await pool.query(
            `UPDATE objetos
             SET nombre = COALESCE(?, nombre), descripcion = COALESCE(?, descripcion),
                 fecha_perdida = COALESCE(?, fecha_perdida),
                 fecha_encontrado = COALESCE(?, fecha_encontrado), ubicacion = COALESCE(?, ubicacion),
                 estado = COALESCE(?, estado), imagen = COALESCE(?, imagen),
                 id_categoria = COALESCE(?, id_categoria)
             WHERE id_objeto = ?${ownerCondition}`,
            [nombre, descripcion, fecha_perdida, foundDate, ubicacion, estado, imagen, id_categoria, req.params.id, ...(id_usuario ? [id_usuario] : [])]
        );
        if (resultado.affectedRows === 0) {
            return res.status(404).json({ mensaje: 'Objeto no encontrado' });
        }
        if (estado) {
            await asegurarSeguimientoRecuperacion(req.params.id, estado);
        }
        res.json({ mensaje: 'Objeto actualizado correctamente' });
    } catch (error) {
        console.error('Error al actualizar objeto:', error);
        res.status(500).json({ mensaje: 'Error al actualizar objeto' });
    }
});

app.delete('/api/objetos/:id', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const ownerId = req.body?.id_usuario;
        const ownerCondition = ownerId ? ' AND id_usuario = ?' : '';
        await connection.beginTransaction();
        const [objeto] = await connection.query(
            `SELECT id_objeto FROM objetos WHERE id_objeto = ?${ownerCondition}`,
            [req.params.id, ...(ownerId ? [ownerId] : [])]
        );
        if (objeto.length === 0) {
            await connection.rollback();
            return res.status(404).json({ mensaje: 'Objeto no encontrado' });
        }

        await connection.query('DELETE FROM recuperaciones WHERE id_objeto = ?', [req.params.id]);
        await connection.query('DELETE FROM objetos WHERE id_objeto = ?', [req.params.id]);
        await connection.commit();
        res.json({ mensaje: 'Objeto eliminado correctamente' });
    } catch (error) {
        await connection.rollback();
        console.error('Error al eliminar objeto:', error);
        res.status(500).json({ mensaje: 'No se puede eliminar este objeto. Intenta nuevamente.' });
    } finally {
        connection.release();
    }
});

app.get('/api/notificaciones/:id_usuario', async (req, res) => {
    try {
        const [notificaciones] = await pool.query(
            `SELECT id_objeto, nombre, ubicacion, fecha_encontrado, estado
             FROM objetos
             WHERE id_usuario = ? AND estado IN ('Encontrado', 'En revision', 'Devuelto')
             ORDER BY COALESCE(fecha_encontrado, fecha_perdida) DESC`,
            [req.params.id_usuario]
        );
        res.json(notificaciones.map((item) => ({
            ...item,
            titulo: item.estado === 'Encontrado'
                ? 'Encontramos tu objeto'
                : item.estado === 'Devuelto'
                    ? 'Tu objeto fue devuelto'
                    : 'Tu solicitud está en revisión',
            mensaje: item.estado === 'Encontrado'
                ? `Tu ${item.nombre} fue encontrado en ${item.ubicacion}. Acude al área de objetos perdidos con una identificación.`
                : item.estado === 'Devuelto'
                    ? `El reporte de ${item.nombre} aparece como devuelto.`
                    : `La solicitud de ${item.nombre} está siendo revisada por el personal.`,
        })));
    } catch (error) {
        console.error('Error al consultar notificaciones:', error);
        res.status(500).json({ mensaje: 'Error al consultar notificaciones' });
    }
});

app.post('/api/recuperaciones', async (req, res) => {
    try {
        const { id_objeto, observacion = '' } = req.body;
        if (!id_objeto) {
            return res.status(400).json({ mensaje: 'Selecciona un objeto' });
        }
        const [objeto] = await pool.query('SELECT id_objeto FROM objetos WHERE id_objeto = ?', [id_objeto]);
        if (objeto.length === 0) {
            return res.status(404).json({ mensaje: 'Objeto no encontrado' });
        }
        const [resultado] = await pool.query(
            'INSERT INTO recuperaciones (fecha_recuperacion, observacion, id_objeto) VALUES (CURRENT_TIMESTAMP, ?, ?)',
            [observacion.trim(), id_objeto]
        );
        await pool.query('UPDATE objetos SET estado = ? WHERE id_objeto = ?', ['En revision', id_objeto]);
        await asegurarSeguimientoRecuperacion(id_objeto, 'En revision');
        res.status(201).json({ mensaje: 'Solicitud de recuperación registrada', id_recuperacion: resultado.insertId });
    } catch (error) {
        console.error('Error al registrar recuperación:', error);
        res.status(500).json({ mensaje: 'Error al registrar recuperación' });
    }
});

app.get('/api/recuperaciones', async (req, res) => {
    try {
        const [recuperaciones] = await pool.query(
            `SELECT r.id_recuperacion, r.fecha_recuperacion, r.observacion,
                  r.id_objeto, o.nombre AS objeto, o.estado, o.ubicacion,
                  o.id_usuario, CONCAT(u.nombre, ' ', u.apellido) AS usuario
             FROM recuperaciones r
             INNER JOIN objetos o ON o.id_objeto = r.id_objeto
              INNER JOIN usuarios u ON u.id_usuario = o.id_usuario
             ORDER BY r.id_recuperacion DESC`
        );
        res.json(recuperaciones);
    } catch (error) {
        console.error('Error al consultar recuperaciones:', error);
        res.status(500).json({ mensaje: 'Error al consultar recuperaciones' });
    }
});

app.get('/api/usuarios', async (req, res) => {
    try {
        const [usuarios] = await pool.query(
            `SELECT id_usuario, nombre, apellido, correo, rol, fecha_registro
             FROM usuarios ORDER BY id_usuario DESC`
        );
        res.json(usuarios);
    } catch (error) {
        console.error('Error al consultar usuarios:', error);
        res.status(500).json({ mensaje: 'Error al consultar usuarios' });
    }
});

// ==========================================

// INICIAR SERVIDOR
// ==========================================

const PORT = process.env.PORT || 5000;

inicializarBaseDeDatos()
    .then(migrarContrasenasLegadas)
    .then(() => {
        app.listen(PORT, () => {
            console.log(
                `Servidor AeroLost ejecutándose en http://localhost:${PORT}`
            );
        });
    })
    .catch((error) => {
        console.error('No se pudo inicializar la base de datos:', error);
        process.exit(1);
    });