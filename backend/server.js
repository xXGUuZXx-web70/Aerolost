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

app.use(cors());
app.use(express.json());

const inicializarBaseDeDatos = async () => {
    await pool.query('SELECT 1');
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

const ESTADOS_OBJETO = ['Perdido', 'Encontrado', 'En revision', 'Reclamado', 'Devuelto'];
const ESTADOS_RECLAMACION = ['Pendiente', 'Aprobada', 'Rechazada'];
const ESTADOS_ENTREGA = ['Pendiente', 'Entregado', 'Cancelado'];

const obtenerRol = async (nombre) => {
    try {
        const [roles] = await pool.query('SELECT id_rol FROM roles WHERE LOWER(nombre) = LOWER(?) LIMIT 1', [nombre]);
        if (roles[0]?.id_rol) return roles[0].id_rol;

        if (nombre.toLowerCase().includes('admin')) {
            const [adminRole] = await pool.query('SELECT id_rol FROM roles WHERE LOWER(nombre) LIKE "%admin%" LIMIT 1');
            if (adminRole[0]?.id_rol) return adminRole[0].id_rol;
        } else {
            const [userRole] = await pool.query('SELECT id_rol FROM roles WHERE LOWER(nombre) LIKE "%user%" OR LOWER(nombre) LIKE "%usuario%" LIMIT 1');
            if (userRole[0]?.id_rol) return userRole[0].id_rol;
        }

        const [anyRole] = await pool.query('SELECT id_rol FROM roles ORDER BY id_rol ASC LIMIT 1');
        return anyRole[0]?.id_rol || 2;
    } catch (e) {
        console.error('Error al obtener rol:', e);
        return 2;
    }
};

const resolverIdCatalogo = async (tabla, columnaId, valor) => {
    if (!valor) return null;
    if (/^\d+$/.test(String(valor))) return Number(valor);
    const cleanValor = String(valor).trim();
    try {
        const [rows] = await pool.query(`SELECT ${columnaId} AS id FROM ${tabla} WHERE LOWER(nombre) = LOWER(?) LIMIT 1`, [cleanValor]);
        if (rows[0]?.id) return rows[0].id;

        const [likeRows] = await pool.query(`SELECT ${columnaId} AS id FROM ${tabla} WHERE LOWER(nombre) LIKE LOWER(?) LIMIT 1`, [`%${cleanValor}%`]);
        if (likeRows[0]?.id) return likeRows[0].id;

        if (tabla === 'ubicaciones') {
            const [inserted] = await pool.query('INSERT INTO ubicaciones (nombre, descripcion) VALUES (?, ?)', [cleanValor, 'Zona del aeropuerto']);
            return inserted.insertId;
        }

        const [firstRow] = await pool.query(`SELECT ${columnaId} AS id FROM ${tabla} ORDER BY ${columnaId} ASC LIMIT 1`);
        return firstRow[0]?.id || null;
    } catch (e) {
        console.error(`Error al resolver id en ${tabla}:`, e);
        return null;
    }
};

const normalizarFecha = (fecha) => {
    if (!fecha) return null;
    try {
        if (typeof fecha === 'string') {
            const trimmed = fecha.trim();
            if (trimmed.length >= 10) return trimmed.slice(0, 10);
        }
        const d = new Date(fecha);
        if (!isNaN(d.getTime())) return d.toISOString().slice(0, 10);
        return null;
    } catch {
        return null;
    }
};

const registrarNotificacion = async (idUsuario, mensaje) => {
    if (idUsuario) {
        await pool.query('INSERT INTO notificaciones (mensaje, id_usuario) VALUES (?, ?)', [mensaje, idUsuario]);
    }
};

const registrarCambioEstado = async (idObjeto, estadoAnterior, estadoNuevo, connection = pool) => {
    if (estadoAnterior === estadoNuevo) return;
    await connection.query(
        'INSERT INTO historial_estados (estado_anterior, estado_nuevo, id_objeto) VALUES (?, ?, ?)',
        [estadoAnterior, estadoNuevo, idObjeto]
    );
    const [objeto] = await connection.query('SELECT id_usuario, nombre FROM objetos WHERE id_objeto = ?', [idObjeto]);
    if (objeto[0]) {
        await registrarNotificacion(objeto[0].id_usuario, `El objeto ${objeto[0].nombre} cambió de ${estadoAnterior || 'sin estado'} a ${estadoNuevo}.`);
    }
};

const obtenerObjetoSelect = `
    SELECT o.id_objeto, o.nombre, o.descripcion, o.fecha_perdida, o.fecha_encontrado,
           o.estado, o.id_usuario, o.id_categoria, o.id_ubicacion, o.id_aerolinea,
           c.nombre AS categoria, u.nombre AS nombre_reportante, u.apellido AS apellido_reportante,
           ub.nombre AS ubicacion, a.nombre AS aerolinea,
           (SELECT JSON_ARRAYAGG(JSON_OBJECT('id_evidencia', e.id_evidencia, 'ruta_imagen', e.ruta_imagen))
            FROM evidencias e WHERE e.id_objeto = o.id_objeto) AS evidencias
    FROM objetos o
    LEFT JOIN categorias c ON c.id_categoria = o.id_categoria
    LEFT JOIN usuarios u ON u.id_usuario = o.id_usuario
    LEFT JOIN ubicaciones ub ON ub.id_ubicacion = o.id_ubicacion
    LEFT JOIN aerolineas a ON a.id_aerolinea = o.id_aerolinea`;


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

        const { nombre, apellido, email, password, telefono } = req.body;
        const emailNormalizado = email?.trim().toLowerCase();


        // Validar campos

        if (!nombre?.trim() || !apellido?.trim() || !emailNormalizado || !password || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailNormalizado)) {

            return res.status(400).json({
                mensaje: 'Todos los campos son obligatorios'
            });

        }


        // Verificar si el correo ya existe

        const [usuarioExiste] = await pool.query(
            'SELECT id_usuario FROM usuarios WHERE correo = ?',
            [emailNormalizado]
        );


        if (usuarioExiste.length > 0) {

            return res.status(409).json({
                mensaje: 'El correo electrónico ya está registrado'
            });

        }


        // Crear usuario

        const idRol = await obtenerRol('Usuario');
        if (!idRol) return res.status(500).json({ mensaje: 'No existe el rol Usuario en la base de datos' });
        const [resultado] = await pool.query(
            'INSERT INTO usuarios (nombre, apellido, correo, contrasena, telefono, id_rol) VALUES (?, ?, ?, ?, ?, ?)',
            [nombre.trim(), apellido.trim(), emailNormalizado, hashPassword(password), telefono?.trim() || null, idRol]
        );


        res.status(201).json({
            mensaje: 'Usuario registrado correctamente',
            usuario: {
                id: resultado.insertId,
                nombre,
                apellido,
                email: emailNormalizado,
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
                `SELECT u.id_usuario AS id, u.nombre, u.apellido, u.correo AS email, u.contrasena,
                    r.nombre AS rol
                 FROM usuarios u INNER JOIN roles r ON r.id_rol = u.id_rol
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
        const { buscar = '', estado = '', id_usuario, id_categoria, id_ubicacion, id_aerolinea, fecha = '' } = req.query;
        const conditions = [];
        const values = [];

        if (buscar) {
            conditions.push('(o.nombre LIKE ? OR o.descripcion LIKE ? OR ub.nombre LIKE ? OR a.nombre LIKE ?)');
            const term = `%${buscar}%`;
            values.push(term, term, term, term);
        }
        if (estado) {
            conditions.push('o.estado = ?');
            values.push(estado);
        }
        if (id_usuario) {
            conditions.push('o.id_usuario = ?');
            values.push(id_usuario);
            if (req.query.incluir_archivados !== 'true') {
                conditions.push('(o.archivado_usuario = 0 OR o.archivado_usuario IS NULL)');
            }
        }
        if (id_categoria) { conditions.push('o.id_categoria = ?'); values.push(id_categoria); }
        if (id_ubicacion) { conditions.push('o.id_ubicacion = ?'); values.push(id_ubicacion); }
        if (id_aerolinea) { conditions.push('o.id_aerolinea = ?'); values.push(id_aerolinea); }
        if (fecha) {
            conditions.push('(DATE(o.fecha_perdida) = ? OR DATE(o.fecha_encontrado) = ?)');
            values.push(fecha, fecha);
        }

        const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        const [objetos] = await pool.query(
                `${obtenerObjetoSelect} ${where}
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
                `${obtenerObjetoSelect} WHERE o.id_objeto = ?`,
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
            ubicacion, id_ubicacion, id_aerolinea, id_usuario, id_categoria, estado = 'Perdido',
            evidencias = [], id_reporte, tipo_reporte = 'Perdido'
        } = req.body;

        if (!nombre?.trim() || !descripcion?.trim() || !id_usuario || !id_categoria || !ESTADOS_OBJETO.includes(estado)) {
            return res.status(400).json({ mensaje: 'Completa todos los datos del objeto' });
        }
        const ubicacionId = id_ubicacion || await resolverIdCatalogo('ubicaciones', 'id_ubicacion', ubicacion);
        if (!ubicacionId) return res.status(400).json({ mensaje: 'Selecciona una ubicación válida' });

        const [resultado] = await pool.query(
            `INSERT INTO objetos
             (nombre, descripcion, fecha_perdida, fecha_encontrado, estado, id_usuario, id_categoria, id_ubicacion, id_aerolinea)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [nombre.trim(), descripcion.trim(), normalizarFecha(fecha_perdida), normalizarFecha(fecha_encontrado),
                estado, id_usuario, id_categoria, ubicacionId, id_aerolinea || null]
        );
        await registrarCambioEstado(resultado.insertId, null, estado);
        await pool.query('INSERT INTO reportes (tipo, descripcion, id_usuario, id_objeto) VALUES (?, ?, ?, ?)',
            [tipo_reporte, descripcion.trim(), id_usuario, resultado.insertId]);
        if (id_reporte) await pool.query('UPDATE reportes SET id_objeto = ? WHERE id_reporte = ?', [resultado.insertId, id_reporte]);
        for (const evidencia of evidencias) {
            if (typeof evidencia === 'string' && evidencia.trim()) {
                await pool.query('INSERT INTO evidencias (ruta_imagen, id_objeto) VALUES (?, ?)', [evidencia.trim(), resultado.insertId]);
            }
        }
        res.status(201).json({ mensaje: 'Objeto registrado correctamente', id_objeto: resultado.insertId });
    } catch (error) {
        console.error('Error al registrar objeto:', error);
        res.status(500).json({ mensaje: 'Error al registrar objeto' });
    }
});

app.post('/api/admin/objetos-encontrados', async (req, res) => {
    try {
        const {
            nombre, descripcion, fecha_perdida, ubicacion, id_ubicacion,
            id_aerolinea, id_usuario, id_categoria, evidencias = []
        } = req.body;

        if (!nombre || !descripcion || !id_usuario || !id_categoria) {
            return res.status(400).json({
                mensaje: 'Completa el objeto, la descripción, la zona, el usuario y la categoría'
            });
        }

        const ubicacionId = id_ubicacion || await resolverIdCatalogo('ubicaciones', 'id_ubicacion', ubicacion);
        if (!ubicacionId) return res.status(400).json({ mensaje: 'Selecciona una ubicación válida' });
        const [resultado] = await pool.query(
            `INSERT INTO objetos
             (nombre, descripcion, fecha_perdida, fecha_encontrado, estado, id_usuario, id_categoria, id_ubicacion, id_aerolinea)
             VALUES (?, ?, ?, CURRENT_DATE, 'Encontrado', ?, ?, ?, ?)`,
            [nombre.trim(), descripcion.trim(), normalizarFecha(fecha_perdida), id_usuario, id_categoria, ubicacionId, id_aerolinea || null]
        );
        await registrarCambioEstado(resultado.insertId, null, 'Encontrado');
        await pool.query('INSERT INTO reportes (tipo, descripcion, id_usuario, id_objeto) VALUES (?, ?, ?, ?)',
            ['Encontrado', descripcion.trim(), id_usuario, resultado.insertId]);
        for (const evidencia of evidencias) {
            if (typeof evidencia === 'string' && evidencia.trim()) {
                await pool.query('INSERT INTO evidencias (ruta_imagen, id_objeto) VALUES (?, ?)', [evidencia.trim(), resultado.insertId]);
            }
        }

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
        const { nombre, descripcion, fecha_perdida, fecha_encontrado, ubicacion, id_ubicacion, id_aerolinea, estado, id_categoria, id_usuario } = req.body;
        if (estado && !ESTADOS_OBJETO.includes(estado)) {
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
        const ubicacionId = id_ubicacion || await resolverIdCatalogo('ubicaciones', 'id_ubicacion', ubicacion);
        const foundDate = estado === 'Encontrado' && !fecha_encontrado ? new Date() : fecha_encontrado;
        const cleanFechaPerdida = fecha_perdida ? normalizarFecha(fecha_perdida) : null;
        const cleanFechaEncontrado = foundDate ? normalizarFecha(foundDate) : null;

        const [actual] = await pool.query('SELECT estado, nombre, id_usuario FROM objetos WHERE id_objeto = ?', [req.params.id]);
        const [resultado] = await pool.query(
            `UPDATE objetos
             SET nombre = COALESCE(?, nombre), descripcion = COALESCE(?, descripcion),
                 fecha_perdida = COALESCE(?, fecha_perdida),
                  fecha_encontrado = COALESCE(?, fecha_encontrado), id_ubicacion = COALESCE(?, id_ubicacion),
                  estado = COALESCE(?, estado), id_categoria = COALESCE(?, id_categoria),
                  id_aerolinea = COALESCE(?, id_aerolinea)
             WHERE id_objeto = ?${ownerCondition}`,
              [nombre || null, descripcion || null, cleanFechaPerdida, cleanFechaEncontrado, ubicacionId, estado || null, id_categoria || null, id_aerolinea || null, req.params.id, ...(id_usuario ? [id_usuario] : [])]
        );
        if (resultado.affectedRows === 0) {
            return res.status(404).json({ mensaje: 'Objeto no encontrado' });
        }
        if (estado) await registrarCambioEstado(req.params.id, actual[0]?.estado, estado);

        // Si se marca como Devuelto, registrar la entrega física, recuperación y notificar al usuario
        if (estado === 'Devuelto') {
            const { id_punto_entrega, informacion, observaciones } = req.body;
            const targetUserId = actual[0]?.id_usuario || id_usuario;
            if (targetUserId) {
                const [usrRow] = await pool.query('SELECT nombre, apellido FROM usuarios WHERE id_usuario = ?', [targetUserId]);
                const puntoId = id_punto_entrega || 1;
                const [pntRow] = await pool.query('SELECT nombre, ubicacion FROM puntos_entrega WHERE id_punto_entrega = ?', [puntoId]);
                const infoFinal = (informacion || observaciones || 'Objeto devuelto y retirado formalmente en el aeropuerto').trim();
                const recibido = `${usrRow[0]?.nombre || ''} ${usrRow[0]?.apellido || ''}`.trim();

                await pool.query(
                    `INSERT INTO entregas (fecha_entrega, observacion, recibido_por, estado, id_objeto, id_punto_entrega, id_usuario)
                     VALUES (NOW(), ?, ?, 'Entregado', ?, ?, ?)`,
                    [infoFinal, recibido, req.params.id, puntoId, targetUserId]
                );
                await pool.query(
                    'INSERT INTO recuperaciones (fecha_recuperacion, observacion, id_objeto) VALUES (NOW(), ?, ?)',
                    [infoFinal, req.params.id]
                );
                const puntoTexto = pntRow[0] ? `${pntRow[0].nombre} (${pntRow[0].ubicacion})` : 'Oficina AeroLost';
                await registrarNotificacion(
                    targetUserId,
                    `¡Tu objeto "${actual[0]?.nombre || 'reportado'}" ha sido marcado como DEVUELTO! Ubicación de retiro: ${puntoTexto}. Indicaciones: ${infoFinal}. Ahora ya puedes eliminar o retirar este reporte de tu lista personal.`
                );
            }
        }

        res.json({ mensaje: 'Objeto actualizado correctamente' });
    } catch (error) {
        console.error('Error al actualizar objeto:', error);
        res.status(500).json({ mensaje: 'Error al actualizar objeto' });
    }
});

app.delete('/api/objetos/:id', async (req, res) => {
    try {
        const ownerId = req.body?.id_usuario || req.query?.id_usuario;
        if (ownerId) {
            const [objeto] = await pool.query(
                'SELECT id_objeto, estado, nombre FROM objetos WHERE id_objeto = ? AND id_usuario = ?',
                [req.params.id, ownerId]
            );
            if (objeto.length === 0) {
                return res.status(404).json({ mensaje: 'Reporte no encontrado' });
            }
            if (objeto[0].estado !== 'Devuelto') {
                return res.status(400).json({
                    mensaje: 'Solo puedes eliminar reportes que ya hayan sido entregados y devueltos por el personal del aeropuerto.'
                });
            }
            await pool.query(
                'UPDATE objetos SET archivado_usuario = 1 WHERE id_objeto = ? AND id_usuario = ?',
                [req.params.id, ownerId]
            );
            return res.json({ mensaje: 'Tu reporte devuelto ha sido retirado de tu lista personal exitosamente.' });
        }

        // Eliminación permanente exclusiva para administración
        const connection = await pool.getConnection();
        try {
            await connection.beginTransaction();
            await connection.query('DELETE FROM evidencias WHERE id_objeto = ?', [req.params.id]);
            await connection.query('DELETE FROM historial_estados WHERE id_objeto = ?', [req.params.id]);
            await connection.query('DELETE FROM reclamaciones WHERE id_objeto = ?', [req.params.id]);
            await connection.query('DELETE FROM reportes WHERE id_objeto = ?', [req.params.id]);
            await connection.query('DELETE FROM recuperaciones WHERE id_objeto = ?', [req.params.id]);
            await connection.query('DELETE FROM entregas WHERE id_objeto = ?', [req.params.id]);
            await connection.query('DELETE FROM objetos WHERE id_objeto = ?', [req.params.id]);
            await connection.commit();
            res.json({ mensaje: 'Objeto y registros eliminados permanentemente por administración.' });
        } catch (err) {
            await connection.rollback();
            throw err;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error('Error al eliminar objeto:', error);
        res.status(500).json({ mensaje: 'Error al procesar la eliminación del objeto' });
    }
});

app.get('/api/notificaciones/:id_usuario', async (req, res) => {
    try {
        const [notificaciones] = await pool.query(
            `SELECT n.id_notificacion, n.mensaje, n.leido, n.fecha_envio
             FROM notificaciones n WHERE n.id_usuario = ? ORDER BY n.fecha_envio DESC`,
            [req.params.id_usuario]
        );
        res.json(notificaciones.map((item) => ({ ...item, titulo: 'Actualización de AeroLost' })));
    } catch (error) {
        console.error('Error al consultar notificaciones:', error);
        res.status(500).json({ mensaje: 'Error al consultar notificaciones' });
    }
});

app.get('/api/notificaciones/:id_usuario/conteo', async (req, res) => {
    try {
        const [[row]] = await pool.query(
            `SELECT 
                COUNT(*) AS total,
                SUM(CASE WHEN leido = 0 THEN 1 ELSE 0 END) AS no_leidas
             FROM notificaciones WHERE id_usuario = ?`,
            [req.params.id_usuario]
        );
        res.json({ total: row.total || 0, noLeidas: row.no_leidas || 0 });
    } catch (error) {
        console.error('Error al contar notificaciones:', error);
        res.status(500).json({ mensaje: 'Error al contar notificaciones' });
    }
});

app.put('/api/notificaciones/:id/leida', async (req, res) => {
    try {
        await pool.query('UPDATE notificaciones SET leido = 1 WHERE id_notificacion = ?', [req.params.id]);
        res.json({ mensaje: 'Notificación marcada como leída' });
    } catch (error) {
        console.error('Error al marcar notificación:', error);
        res.status(500).json({ mensaje: 'Error al marcar notificación' });
    }
});

app.put('/api/notificaciones/usuario/:id_usuario/leer-todas', async (req, res) => {
    try {
        await pool.query('UPDATE notificaciones SET leido = 1 WHERE id_usuario = ?', [req.params.id_usuario]);
        res.json({ mensaje: 'Todas las notificaciones marcadas como leídas' });
    } catch (error) {
        console.error('Error al marcar todas las notificaciones:', error);
        res.status(500).json({ mensaje: 'Error al marcar notificaciones' });
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
        const [existente] = await pool.query('SELECT id_recuperacion FROM recuperaciones WHERE id_objeto = ?', [id_objeto]);
        if (existente.length > 0) return res.status(409).json({ mensaje: 'Este objeto ya tiene una recuperación registrada' });
        const [actual] = await pool.query('SELECT estado FROM objetos WHERE id_objeto = ?', [id_objeto]);
        const [resultado] = await pool.query(
            'INSERT INTO recuperaciones (fecha_recuperacion, observacion, id_objeto) VALUES (CURRENT_TIMESTAMP, ?, ?)',
            [observacion.trim(), id_objeto]
        );
        await pool.query('UPDATE objetos SET estado = ? WHERE id_objeto = ?', ['En revision', id_objeto]);
        await registrarCambioEstado(id_objeto, actual[0]?.estado, 'En revision');
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
                  r.id_objeto, o.nombre AS objeto, o.estado, ub.nombre AS ubicacion,
                  o.id_usuario, CONCAT(u.nombre, ' ', u.apellido) AS usuario
             FROM recuperaciones r
             INNER JOIN objetos o ON o.id_objeto = r.id_objeto
              LEFT JOIN ubicaciones ub ON ub.id_ubicacion = o.id_ubicacion
              INNER JOIN usuarios u ON u.id_usuario = o.id_usuario
             ORDER BY r.id_recuperacion DESC`
        );
        res.json(recuperaciones);
    } catch (error) {
        console.error('Error al consultar recuperaciones:', error);
        res.status(500).json({ mensaje: 'Error al consultar recuperaciones' });
    }
});

app.get('/api/ubicaciones', async (req, res) => {
    try { const [rows] = await pool.query('SELECT id_ubicacion, nombre, descripcion FROM ubicaciones ORDER BY nombre'); res.json(rows); }
    catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al consultar ubicaciones' }); }
});

app.get('/api/aerolineas', async (req, res) => {
    try { const [rows] = await pool.query('SELECT id_aerolinea, nombre, codigo FROM aerolineas ORDER BY nombre'); res.json(rows); }
    catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al consultar aerolíneas' }); }
});

app.get('/api/vuelos', async (req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT v.*, a.nombre AS aerolinea FROM vuelos v INNER JOIN aerolineas a ON a.id_aerolinea = v.id_aerolinea
             ORDER BY v.fecha_vuelo DESC, v.hora_salida DESC`
        );
        res.json(rows);
    } catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al consultar vuelos' }); }
});

app.get('/api/puntos-entrega', async (req, res) => {
    try { const [rows] = await pool.query('SELECT * FROM puntos_entrega WHERE activo = 1 OR activo IS NULL ORDER BY nombre'); res.json(rows); }
    catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al consultar puntos de entrega' }); }
});

app.post('/api/reportes', async (req, res) => {
    try {
        const { tipo, descripcion = '', id_usuario, id_objeto } = req.body;
        if (!['Perdido', 'Encontrado'].includes(tipo) || !id_usuario || !id_objeto) return res.status(400).json({ mensaje: 'Tipo, usuario y objeto son obligatorios' });
        const [result] = await pool.query('INSERT INTO reportes (tipo, descripcion, id_usuario, id_objeto) VALUES (?, ?, ?, ?)', [tipo, descripcion.trim(), id_usuario, id_objeto]);
        res.status(201).json({ id_reporte: result.insertId, mensaje: 'Reporte registrado correctamente' });
    } catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al registrar reporte' }); }
});

app.get('/api/objetos/:id/historial', async (req, res) => {
    try { const [rows] = await pool.query('SELECT * FROM historial_estados WHERE id_objeto = ? ORDER BY fecha_cambio DESC', [req.params.id]); res.json(rows); }
    catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al consultar historial' }); }
});

app.post('/api/objetos/:id/evidencias', async (req, res) => {
    try {
        const rutas = Array.isArray(req.body.rutas) ? req.body.rutas : [req.body.ruta_imagen];
        const validas = rutas.filter((ruta) => typeof ruta === 'string' && ruta.trim());
        if (validas.length === 0) return res.status(400).json({ mensaje: 'Envía al menos una fotografía' });
        for (const ruta of validas) await pool.query('INSERT INTO evidencias (ruta_imagen, id_objeto) VALUES (?, ?)', [ruta.trim(), req.params.id]);
        res.status(201).json({ mensaje: 'Evidencias asociadas correctamente' });
    } catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al guardar evidencias' }); }
});

app.get('/api/reclamaciones', async (req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT r.id_reclamacion, r.descripcion, r.estado, r.fecha_reclamacion, r.id_usuario, r.id_objeto,
                    o.nombre AS objeto, CONCAT(u.nombre, ' ', u.apellido) AS usuario,
                    u.correo AS correo_usuario, u.telefono AS telefono_usuario
             FROM reclamaciones r INNER JOIN objetos o ON o.id_objeto = r.id_objeto
             INNER JOIN usuarios u ON u.id_usuario = r.id_usuario
             ${req.query.id_usuario ? 'WHERE r.id_usuario = ?' : ''} ORDER BY r.fecha_reclamacion DESC`,
            req.query.id_usuario ? [req.query.id_usuario] : []
        );
        res.json(rows);
    } catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al consultar reclamaciones' }); }
});

app.post('/api/reclamaciones', async (req, res) => {
    try {
        const { descripcion = '', id_usuario, id_objeto } = req.body;
        if (!id_usuario || !id_objeto) return res.status(400).json({ mensaje: 'Usuario y objeto son obligatorios' });
        const [duplicada] = await pool.query("SELECT id_reclamacion FROM reclamaciones WHERE id_usuario = ? AND id_objeto = ? AND estado = 'Pendiente'", [id_usuario, id_objeto]);
        if (duplicada.length) return res.status(409).json({ mensaje: 'Ya existe una reclamación pendiente' });
        const [result] = await pool.query('INSERT INTO reclamaciones (descripcion, estado, id_usuario, id_objeto) VALUES (?, \'Pendiente\', ?, ?)', [descripcion.trim(), id_usuario, id_objeto]);
        res.status(201).json({ id_reclamacion: result.insertId, mensaje: 'Reclamación registrada' });
    } catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al registrar reclamación' }); }
});

app.put('/api/reclamaciones/:id', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const { estado, id_punto_entrega, informacion, observaciones } = req.body;
        if (!ESTADOS_RECLAMACION.includes(estado)) return res.status(400).json({ mensaje: 'Estado de reclamación no válido' });
        await connection.beginTransaction();

        const [rows] = await connection.query(
            `SELECT r.id_objeto, r.id_usuario, o.nombre AS objeto_nombre, o.estado AS objeto_estado,
                    u.nombre AS usuario_nombre, u.apellido AS usuario_apellido
             FROM reclamaciones r
             INNER JOIN objetos o ON o.id_objeto = r.id_objeto
             INNER JOIN usuarios u ON u.id_usuario = r.id_usuario
             WHERE r.id_reclamacion = ?`,
            [req.params.id]
        );
        if (!rows.length) {
            await connection.rollback();
            return res.status(404).json({ mensaje: 'Reclamación no encontrada' });
        }

        const claim = rows[0];
        await connection.query('UPDATE reclamaciones SET estado = ? WHERE id_reclamacion = ?', [estado, req.params.id]);

        if (estado === 'Aprobada') {
            // Se actualiza automáticamente a Devuelto
            await connection.query("UPDATE objetos SET estado = 'Devuelto' WHERE id_objeto = ?", [claim.id_objeto]);
            await registrarCambioEstado(claim.id_objeto, claim.objeto_estado, 'Devuelto', connection);

            const puntoId = id_punto_entrega || 1;
            const [puntos] = await connection.query('SELECT nombre, ubicacion FROM puntos_entrega WHERE id_punto_entrega = ?', [puntoId]);
            const punto = puntos[0] || { nombre: 'Oficina AeroLost', ubicacion: 'Terminal principal - PB' };

            const infoFinal = (informacion || observaciones || 'Objeto devuelto formalmente tras validación de reclamación').trim();
            const recibidoPor = `${claim.usuario_nombre} ${claim.usuario_apellido}`.trim();

            // Registrar entrega física
            await connection.query(
                `INSERT INTO entregas (fecha_entrega, observacion, recibido_por, estado, id_objeto, id_punto_entrega, id_usuario)
                 VALUES (NOW(), ?, ?, 'Entregado', ?, ?, ?)`,
                [infoFinal, recibidoPor, claim.id_objeto, puntoId, claim.id_usuario]
            );

            // Registrar en recuperaciones
            await connection.query(
                'INSERT INTO recuperaciones (fecha_recuperacion, observacion, id_objeto) VALUES (NOW(), ?, ?)',
                [infoFinal, claim.id_objeto]
            );

            await connection.commit();

            // Notificación al usuario con ubicación e información
            const notifMsg = `¡Tu reclamación fue aprobada y tu objeto "${claim.objeto_nombre}" ha sido marcado como DEVUELTO! Ubicación de retiro: ${punto.nombre} (${punto.ubicacion}). Indicaciones: ${infoFinal}. Tu entrega ha concluido con éxito. Ya puedes retirar o borrar tu reporte de tu lista personal.`;
            await registrarNotificacion(claim.id_usuario, notifMsg);

            res.json({ mensaje: 'Reclamación aprobada, entrega registrada y objeto marcado como Devuelto correctamente' });
        } else {
            await connection.commit();
            const motivo = (informacion || observaciones || 'No se pudo verificar la pertenencia con los datos provistos').trim();
            await registrarNotificacion(claim.id_usuario, `Tu reclamación sobre "${claim.objeto_nombre}" fue rechazada. Motivo: ${motivo}.`);
            res.json({ mensaje: 'Reclamación rechazada y usuario notificado' });
        }
    } catch (error) {
        await connection.rollback();
        console.error('Error al actualizar reclamación:', error);
        res.status(500).json({ mensaje: 'Error al actualizar reclamación' });
    } finally {
        connection.release();
    }
});

app.get('/api/admin/historial-devoluciones', async (req, res) => {
    try {
        const { anio, mes, dia, buscar = '' } = req.query;
        const conditions = ["(e.estado = 'Entregado' OR o.estado = 'Devuelto')"];
        const values = [];

        if (anio) {
            conditions.push('YEAR(e.fecha_entrega) = ?');
            values.push(anio);
        }
        if (mes) {
            conditions.push('MONTH(e.fecha_entrega) = ?');
            values.push(mes);
        }
        if (dia) {
            conditions.push('DATE(e.fecha_entrega) = ?');
            values.push(dia);
        }
        if (buscar) {
            conditions.push('(o.nombre LIKE ? OR u.nombre LIKE ? OR u.apellido LIKE ? OR u.correo LIKE ? OR p.nombre LIKE ?)');
            const term = `%${buscar}%`;
            values.push(term, term, term, term, term);
        }

        const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
        const [rows] = await pool.query(
            `SELECT e.id_entrega, e.fecha_entrega, e.observacion AS info_entrega, e.recibido_por,
                    e.estado AS estado_entrega,
                    o.id_objeto, o.nombre AS objeto, o.descripcion AS objeto_descripcion,
                    o.estado AS objeto_estado, o.fecha_perdida, o.archivado_usuario,
                    c.nombre AS categoria,
                    u.id_usuario, CONCAT(u.nombre, ' ', u.apellido) AS usuario_nombre,
                    u.correo AS usuario_correo, u.telefono AS usuario_telefono,
                    p.id_punto_entrega, p.nombre AS punto_nombre, p.ubicacion AS punto_ubicacion,
                    p.horario AS punto_horario
             FROM entregas e
             INNER JOIN objetos o ON o.id_objeto = e.id_objeto
             LEFT JOIN categorias c ON c.id_categoria = o.id_categoria
             INNER JOIN usuarios u ON u.id_usuario = e.id_usuario
             LEFT JOIN puntos_entrega p ON p.id_punto_entrega = e.id_punto_entrega
             ${where}
             ORDER BY e.fecha_entrega DESC`,
            values
        );
        res.json(rows);
    } catch (error) {
        console.error('Error al consultar historial de devoluciones:', error);
        res.status(500).json({ mensaje: 'Error al consultar historial de devoluciones' });
    }
});

app.get('/api/admin/resumen', async (req, res) => {
    try {
        const [[usuarios]] = await pool.query('SELECT COUNT(*) AS total FROM usuarios');
        const [objetos] = await pool.query('SELECT estado, COUNT(*) AS total FROM objetos GROUP BY estado');
        const [[reclamacionesPendientes]] = await pool.query("SELECT COUNT(*) AS total FROM reclamaciones WHERE estado = 'Pendiente'");
        const [[totalReclamaciones]] = await pool.query('SELECT COUNT(*) AS total FROM reclamaciones');
        const [[recuperaciones]] = await pool.query('SELECT COUNT(*) AS total FROM recuperaciones');
        const [[entregasPendientes]] = await pool.query("SELECT COUNT(*) AS total FROM entregas WHERE estado = 'Pendiente'");
        const [[totalEntregas]] = await pool.query('SELECT COUNT(*) AS total FROM entregas');
        const [[totalVuelos]] = await pool.query('SELECT COUNT(*) AS total FROM vuelos');
        const [[totalAerolineas]] = await pool.query('SELECT COUNT(*) AS total FROM aerolineas');
        const [[totalPuntosEntrega]] = await pool.query('SELECT COUNT(*) AS total FROM puntos_entrega');

        const mapaObjetos = objetos.reduce((acc, item) => ({ ...acc, [item.estado]: Number(item.total) }), {});
        const totalObjetos = Object.values(mapaObjetos).reduce((sum, n) => sum + Number(n), 0);

        res.json({
            total_objetos: totalObjetos,
            perdidos: mapaObjetos['Perdido'] || 0,
            encontrados: mapaObjetos['Encontrado'] || 0,
            en_revision: mapaObjetos['En revision'] || 0,
            reclamados: mapaObjetos['Reclamado'] || 0,
            devueltos: mapaObjetos['Devuelto'] || 0,
            reclamaciones_pendientes: Number(reclamacionesPendientes.total || 0),
            total_reclamaciones: Number(totalReclamaciones.total || 0),
            recuperaciones: Number(recuperaciones.total || 0),
            entregas_pendientes: Number(entregasPendientes.total || 0),
            total_entregas: Number(totalEntregas.total || 0),
            usuarios_registrados: Number(usuarios.total || 0),
            vuelos: Number(totalVuelos.total || 0),
            aerolineas: Number(totalAerolineas.total || 0),
            puntos_entrega: Number(totalPuntosEntrega.total || 0),
            objetos: mapaObjetos
        });
    } catch (error) {
        console.error('Error al consultar resumen administrativo:', error);
        res.status(500).json({ mensaje: 'Error al consultar resumen administrativo' });
    }
});

app.get('/api/entregas', async (req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT e.*, o.nombre AS objeto, p.nombre AS punto_entrega, p.ubicacion AS punto_ubicacion,
                    CONCAT(u.nombre, ' ', u.apellido) AS usuario, u.correo AS usuario_correo
             FROM entregas e INNER JOIN objetos o ON o.id_objeto = e.id_objeto
             INNER JOIN puntos_entrega p ON p.id_punto_entrega = e.id_punto_entrega
             INNER JOIN usuarios u ON u.id_usuario = e.id_usuario ORDER BY e.fecha_entrega DESC`
        );
        res.json(rows);
    } catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al consultar entregas' }); }
});

app.post('/api/entregas', async (req, res) => {
    try {
        const { id_objeto, id_usuario, id_punto_entrega, observacion = '', recibido_por = '', estado = 'Pendiente' } = req.body;
        if (!id_objeto || !id_usuario || !id_punto_entrega || !ESTADOS_ENTREGA.includes(estado)) {
            return res.status(400).json({ mensaje: 'Datos de entrega incompletos' });
        }
        const [result] = await pool.query(
            'INSERT INTO entregas (fecha_entrega, observacion, recibido_por, estado, id_objeto, id_punto_entrega, id_usuario) VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?)',
            [observacion.trim(), recibido_por.trim(), estado, id_objeto, id_punto_entrega, id_usuario]
        );
        const [punto] = await pool.query('SELECT nombre FROM puntos_entrega WHERE id_punto_entrega = ?', [id_punto_entrega]);
        const [objeto] = await pool.query('SELECT nombre FROM objetos WHERE id_objeto = ?', [id_objeto]);
        
        await registrarNotificacion(id_usuario, `Se programó la entrega de "${objeto[0]?.nombre || 'objeto'}" en "${punto[0]?.nombre || 'punto de entrega'}".`);

        if (estado === 'Entregado') {
            const [actual] = await pool.query('SELECT estado FROM objetos WHERE id_objeto = ?', [id_objeto]);
            await pool.query("UPDATE objetos SET estado = 'Devuelto' WHERE id_objeto = ?", [id_objeto]);
            await registrarCambioEstado(id_objeto, actual[0]?.estado, 'Devuelto');
        }
        res.status(201).json({ id_entrega: result.insertId, mensaje: 'Entrega registrada correctamente' });
    } catch (error) { console.error(error); res.status(500).json({ mensaje: 'Error al registrar entrega' }); }
});

app.put('/api/entregas/:id', async (req, res) => {
    try {
        const { estado, observacion, recibido_por } = req.body;
        if (estado && !ESTADOS_ENTREGA.includes(estado)) return res.status(400).json({ mensaje: 'Estado no válido' });
        
        const [entregaActual] = await pool.query('SELECT id_objeto, id_usuario, estado FROM entregas WHERE id_entrega = ?', [req.params.id]);
        if (!entregaActual.length) return res.status(404).json({ mensaje: 'Entrega no encontrada' });

        await pool.query(
            `UPDATE entregas SET 
                estado = COALESCE(?, estado),
                observacion = COALESCE(?, observacion),
                recibido_por = COALESCE(?, recibido_por)
             WHERE id_entrega = ?`,
            [estado || null, observacion || null, recibido_por || null, req.params.id]
        );

        if (estado === 'Entregado' && entregaActual[0].estado !== 'Entregado') {
            const [actual] = await pool.query('SELECT estado, nombre FROM objetos WHERE id_objeto = ?', [entregaActual[0].id_objeto]);
            await pool.query("UPDATE objetos SET estado = 'Devuelto' WHERE id_objeto = ?", [entregaActual[0].id_objeto]);
            await registrarCambioEstado(entregaActual[0].id_objeto, actual[0]?.estado, 'Devuelto');
            const [pnt] = await pool.query('SELECT p.nombre, p.ubicacion FROM entregas e LEFT JOIN puntos_entrega p ON p.id_punto_entrega = e.id_punto_entrega WHERE e.id_entrega = ?', [req.params.id]);
            const pntNombre = pnt[0]?.nombre ? `${pnt[0].nombre} (${pnt[0].ubicacion || ''})` : 'Oficina AeroLost';
            const infoText = observacion ? ` Indicaciones: ${observacion}.` : '';
            await registrarNotificacion(
                entregaActual[0].id_usuario,
                `¡Tu objeto "${actual[0]?.nombre || 'reportado'}" ha sido marcado como DEVUELTO! Ubicación de entrega: ${pntNombre}.${infoText} Tu proceso ha concluido exitosamente. Ya puedes retirar o borrar tu reporte de tu lista personal.`
            );
        }

        res.json({ mensaje: 'Entrega actualizada correctamente' });
    } catch (error) {
        console.error('Error al actualizar entrega:', error);
        res.status(500).json({ mensaje: 'Error al actualizar entrega' });
    }
});

app.post('/api/puntos-entrega', async (req, res) => {
    try {
        const { nombre, ubicacion, descripcion = '', horario = '' } = req.body;
        if (!nombre?.trim() || !ubicacion?.trim()) return res.status(400).json({ mensaje: 'Nombre y ubicación son obligatorios' });
        const [result] = await pool.query(
            'INSERT INTO puntos_entrega (nombre, ubicacion, descripcion, horario, activo) VALUES (?, ?, ?, ?, 1)',
            [nombre.trim(), ubicacion.trim(), descripcion.trim(), horario.trim()]
        );
        res.status(201).json({ id_punto_entrega: result.insertId, mensaje: 'Punto de entrega registrado' });
    } catch (error) {
        console.error('Error al registrar punto de entrega:', error);
        res.status(500).json({ mensaje: 'Error al registrar punto de entrega' });
    }
});

app.post('/api/aerolineas', async (req, res) => {
    try {
        const { nombre, codigo = '' } = req.body;
        if (!nombre?.trim()) return res.status(400).json({ mensaje: 'El nombre de la aerolínea es obligatorio' });
        const [result] = await pool.query(
            'INSERT INTO aerolineas (nombre, codigo) VALUES (?, ?)',
            [nombre.trim(), codigo.trim().toUpperCase()]
        );
        res.status(201).json({ id_aerolinea: result.insertId, mensaje: 'Aerolínea registrada' });
    } catch (error) {
        console.error('Error al registrar aerolínea:', error);
        res.status(500).json({ mensaje: 'Error al registrar aerolínea' });
    }
});

app.post('/api/vuelos', async (req, res) => {
    try {
        const { numero_vuelo, origen, destino, fecha_vuelo, hora_salida, hora_llegada, id_aerolinea } = req.body;
        if (!numero_vuelo?.trim() || !id_aerolinea) {
            return res.status(400).json({ mensaje: 'Número de vuelo y aerolínea son obligatorios' });
        }
        const [result] = await pool.query(
            `INSERT INTO vuelos (numero_vuelo, origen, destino, fecha_vuelo, hora_salida, hora_llegada, id_aerolinea)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [numero_vuelo.trim().toUpperCase(), origen?.trim() || null, destino?.trim() || null,
             fecha_vuelo || null, hora_salida || null, hora_llegada || null, id_aerolinea]
        );
        res.status(201).json({ id_vuelo: result.insertId, mensaje: 'Vuelo registrado exitosamente' });
    } catch (error) {
        console.error('Error al registrar vuelo:', error);
        res.status(500).json({ mensaje: 'Error al registrar vuelo' });
    }
});

app.get('/api/usuarios', async (req, res) => {
    try {
        const [usuarios] = await pool.query(
            `SELECT u.id_usuario, u.nombre, u.apellido, u.correo, u.telefono, r.nombre AS rol, u.fecha_registro
             FROM usuarios u INNER JOIN roles r ON r.id_rol = u.id_rol ORDER BY u.id_usuario DESC`
        );
        res.json(usuarios);
    } catch (error) {
        console.error('Error al consultar usuarios:', error);
        res.status(500).json({ mensaje: 'Error al consultar usuarios' });
    }
});

app.get('/api/usuarios/:id', async (req, res) => {
    try {
        const [usuarios] = await pool.query(
            `SELECT u.id_usuario, u.nombre, u.apellido, u.correo, u.telefono, r.nombre AS rol, u.fecha_registro
             FROM usuarios u INNER JOIN roles r ON r.id_rol = u.id_rol
             WHERE u.id_usuario = ?`,
            [req.params.id]
        );
        if (!usuarios.length) return res.status(404).json({ mensaje: 'Usuario no encontrado' });
        res.json(usuarios[0]);
    } catch (error) {
        console.error('Error al consultar usuario:', error);
        res.status(500).json({ mensaje: 'Error al consultar usuario' });
    }
});

app.put('/api/usuarios/:id', async (req, res) => {
    try {
        const { nombre, apellido, telefono } = req.body;
        if (!nombre?.trim() || !apellido?.trim()) {
            return res.status(400).json({ mensaje: 'Nombre y apellido son obligatorios' });
        }
        await pool.query(
            'UPDATE usuarios SET nombre = ?, apellido = ?, telefono = ? WHERE id_usuario = ?',
            [nombre.trim(), apellido.trim(), telefono?.trim() || null, req.params.id]
        );
        res.json({ mensaje: 'Perfil actualizado correctamente' });
    } catch (error) {
        console.error('Error al actualizar usuario:', error);
        res.status(500).json({ mensaje: 'Error al actualizar perfil' });
    }
});

// ==========================================

// INICIAR SERVIDOR
// ==========================================

const PORT = process.env.PORT || 5000;

inicializarBaseDeDatos()
    .then(migrarContrasenasLegadas)
    .then(() => {
        app.listen(PORT, '0.0.0.0', () => {
            console.log(
                `Servidor AeroLost ejecutándose en http://localhost:${PORT}`
            );
        });
    })
    .catch((error) => {
        console.error('No se pudo inicializar la base de datos:', error);
        process.exit(1);
    });