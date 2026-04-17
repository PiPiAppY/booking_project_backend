// Подключаем библиотеки
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();   // загружает переменные из .env в process.env

const express = require('express');
const { Pool } = require('pg');

const app = express();
const cors = require('cors');
app.use(cors()); // разрешает все запросы с любых источников (для разработки)

// Используем переменные окружения для подключения к БД
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Для обработки JSON в теле запросов (понадобится позже)
app.use(express.json());
// Middleware: проверка JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // формат "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Недействительный токен' });
        }
        req.user = user; // сохраняем { userId, isAdmin }
        next();
    });
}

// Middleware: проверка, что пользователь — администратор
function requireAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Доступ запрещён. Требуются права администратора.' });
    }
    next();
}

// Старый эндпоинт /users (можно оставить для проверки)
//app.get('/users', async (req, res) => {
    //try {
    //    const result = await pool.query('SELECT id, email, is_admin FROM users');
      //  res.json(result.rows);
    //} catch (err) {
     //   console.error(err);
      //  res.status(500).json({ error: 'Ошибка сервера' });
   // }
//});

// Регистрация
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;

    // Простая валидация
    if (!email || !password) {
        return res.status(400).json({ error: 'Email и пароль обязательны' });
    }

    try {
        // Проверяем, существует ли пользователь с таким email
        const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existing.rows.length > 0) {
            return res.status(400).json({ error: 'Пользователь с таким email уже существует' });
        }

        // Хешируем пароль
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Создаём пользователя (по умолчанию is_admin = false)
        const result = await pool.query(
            'INSERT INTO users (email, password, is_admin) VALUES ($1, $2, $3) RETURNING id, email, is_admin',
            [email, hashedPassword, false]
        );

        const user = result.rows[0];
        // Генерируем JWT токен
        const token = jwt.sign(
            { userId: user.id, isAdmin: user.is_admin },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({ token, user: { id: user.id, email: user.email, isAdmin: user.is_admin } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при регистрации' });
    }
});

// Вход
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email и пароль обязательны' });
    }

    try {
        const result = await pool.query('SELECT id, email, password, is_admin FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        // Сравниваем введённый пароль с хешем из базы
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Неверный email или пароль' });
        }

        // Генерируем токен
        const token = jwt.sign(
            { userId: user.id, isAdmin: user.is_admin },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({ token, user: { id: user.id, email: user.email, isAdmin: user.is_admin } });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при входе' });
    }
});
//запрос на список ресурсов
app.get('/api/resources', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM resources ORDER BY id');
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при получении ресурсов' });
    }
});

//запрос на наличие одного ресурса
app.get('/api/resources/:id', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        const result = await pool.query('SELECT * FROM resources WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Ресурс не найден' });
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при получении ресурса' });
    }
});

//создание нового ресурса 
app.post('/api/resources', authenticateToken, requireAdmin, async (req, res) => {
    const { name, description, type, capacity, is_active } = req.body;

    if (!name) {
        return res.status(400).json({ error: 'Название ресурса обязательно' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO resources (name, description, type, capacity, is_active)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [name, description, type, capacity, is_active !== undefined ? is_active : true]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при создании ресурса' });
    }
});

//обновление ресурса
app.put('/api/resources/:id', authenticateToken, requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    const { name, description, type, capacity, is_active } = req.body;

    try {
        // Проверяем, существует ли ресурс
        const existing = await pool.query('SELECT * FROM resources WHERE id = $1', [id]);
        if (existing.rows.length === 0) {
            return res.status(404).json({ error: 'Ресурс не найден' });
        }

        // Обновляем только те поля, которые переданы (COALESCE - если null, оставляем старое значение)
        const result = await pool.query(
            `UPDATE resources
             SET name = COALESCE($1, name),
                 description = COALESCE($2, description),
                 type = COALESCE($3, type),
                 capacity = COALESCE($4, capacity),
                 is_active = COALESCE($5, is_active)
             WHERE id = $6
             RETURNING *`,
            [name, description, type, capacity, is_active, id]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при обновлении ресурса' });
    }
});

//удаление ресурса
app.delete('/api/resources/:id', authenticateToken, requireAdmin, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        const result = await pool.query('DELETE FROM resources WHERE id = $1 RETURNING id', [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Ресурс не найден' });
        }
        res.json({ message: 'Ресурс удалён' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при удалении ресурса' });
    }
});

// Создание бронирования (доступно авторизованным)
app.post('/api/bookings', authenticateToken, async (req, res) => {
    const { resource_id, start_time, end_time, purpose } = req.body;
    const userId = req.user.userId; // из токена

    // Простая валидация
    if (!resource_id || !start_time || !end_time) {
        return res.status(400).json({ error: 'resource_id, start_time и end_time обязательны' });
    }

    // Преобразуем строки в объекты Date (на всякий случай)
    const start = new Date(start_time);
    const end = new Date(end_time);

    if (start >= end) {
        return res.status(400).json({ error: 'start_time должно быть меньше end_time' });
    }

    try {
        // Проверяем, существует ли ресурс
        const resourceCheck = await pool.query('SELECT id FROM resources WHERE id = $1', [resource_id]);
        if (resourceCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Ресурс не найден' });
        }

        // Начинаем транзакцию (чтобы гарантировать атомарность)
        await pool.query('BEGIN');

        // Проверяем, нет ли пересекающихся бронирований (хотя exclusion constraint сделает то же самое,
        // но мы выдадим понятное сообщение)
        const conflictCheck = await pool.query(
            `SELECT id FROM bookings
             WHERE resource_id = $1
               AND tstzrange(start_time, end_time) && tstzrange($2, $3)
               AND status = 'active'`,
            [resource_id, start, end]
        );
        if (conflictCheck.rows.length > 0) {
            await pool.query('ROLLBACK');
            return res.status(409).json({ error: 'Это время уже занято' });
        }

        // Вставляем бронирование
        const result = await pool.query(
            `INSERT INTO bookings (user_id, resource_id, start_time, end_time, purpose, status)
             VALUES ($1, $2, $3, $4, $5, 'active')
             RETURNING *`,
            [userId, resource_id, start, end, purpose]
        );

        await pool.query('COMMIT');
        res.status(201).json(result.rows[0]);
    } catch (err) {
        await pool.query('ROLLBACK');
        console.error(err);
        // Если ошибка связана с exclusion constraint, выдаём понятный текст
        if (err.code === '23P01') { // код ошибки уникальности для EXCLUDE
            return res.status(409).json({ error: 'Конфликт: это время уже забронировано (ограничение БД)' });
        }
        res.status(500).json({ error: 'Ошибка при создании бронирования' });
    }
});

// Получить все бронирования текущего пользователя
app.get('/api/bookings/me', authenticateToken, async (req, res) => {
    const userId = req.user.userId;
    try {
        const result = await pool.query(
            `SELECT b.*, r.name as resource_name
             FROM bookings b
             JOIN resources r ON b.resource_id = r.id
             WHERE b.user_id = $1
             ORDER BY b.start_time DESC`,
            [userId]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при получении бронирований' });
    }
});

// Отмена бронирования (владелец или админ)
app.delete('/api/bookings/:id', authenticateToken, async (req, res) => {
    const bookingId = parseInt(req.params.id);
    const userId = req.user.userId;
    const isAdmin = req.user.isAdmin;

    try {
        // Сначала получаем бронирование, чтобы проверить права
        const bookingResult = await pool.query(
            'SELECT user_id FROM bookings WHERE id = $1',
            [bookingId]
        );
        if (bookingResult.rows.length === 0) {
            return res.status(404).json({ error: 'Бронирование не найдено' });
        }

        const ownerId = bookingResult.rows[0].user_id;

        // Проверка: либо владелец, либо админ
        if (ownerId !== userId && !isAdmin) {
            return res.status(403).json({ error: 'Вы не можете отменить это бронирование' });
        }

        // Обновляем статус на 'cancelled' (мягкое удаление)
        await pool.query(
            'UPDATE bookings SET status = $1 WHERE id = $2',
            ['cancelled', bookingId]
        );
        res.json({ message: 'Бронирование отменено' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при отмене бронирования' });
    }
});

// Получить занятые слоты для ресурса на определённую дату
app.get('/api/resources/:id/slots', authenticateToken, async (req, res) => {
    const resourceId = parseInt(req.params.id);
    const { date } = req.query; // ожидаем формат YYYY-MM-DD

    if (!date) {
        return res.status(400).json({ error: 'Параметр date обязателен (YYYY-MM-DD)' });
    }

    // Создаём временной интервал на весь день (локальное время, но преобразуем в UTC)
    const startOfDay = new Date(`${date}T00:00:00`);
    const endOfDay = new Date(`${date}T23:59:59.999`);

    try {
        const result = await pool.query(
            `SELECT start_time, end_time, purpose, user_id, status
             FROM bookings
             WHERE resource_id = $1
               AND start_time >= $2
               AND end_time <= $3
               AND status = 'active'
             ORDER BY start_time`,
            [resourceId, startOfDay, endOfDay]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка при получении слотов' });
    }
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});
