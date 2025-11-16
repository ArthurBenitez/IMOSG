// app.js
const express = require('express');
const path = require('path');
const helmet = require('helmet');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const ejs = require('ejs');

const app = express();

// Segurança básica - variavel helmet
app.use(helmet({ contentSecurityPolicy: false }));

// Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Sessões - variavel session
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
        resave: false,
        saveUninitialized: false,
        cookie: { httpOnly: true, sameSite: 'lax' },
    })
);

// Banco de dados MySQL (conectado a partir de pool, e não createConnection)
let pool;
(async () => {
    pool = await mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASS || 'Frida123@kkk',
        database: process.env.DB_NAME || 'imoveis',
        waitForConnections: true,
        connectionLimit: 10,
    });
})();

// EJS com extensão .html, mantendo tudo na raiz
app.engine('html', ejs.renderFile);
app.set('view engine', 'html');
app.set('views', __dirname);

// Servir apenas assets estáticos (CSS, imagens, JS), nunca páginas .html diretamente
const staticMiddleware = express.static(__dirname, { index: false });
app.use((req, res, next) => {
    // Redireciona acessos a *.html para a versão sem extensão (ex.: /login.html -> /login)
    if (req.path.toLowerCase().endsWith('.html')) {
        return res.redirect(req.path.replace(/\.html$/i, ''));
    }
    return staticMiddleware(req, res, next);
});

// Disponibiliza o usuário nas views
app.use((req, res, next) => {
    res.locals.currentUser = req.session.user || null;
    next();
});

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    next();
}

// Rotas de autenticação
app.get('/register', (req, res) => {
    res.render('register.html', { error: null });
});

app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).render('register.html', { error: 'Preencha todos os campos.' });
        }

        const [exists] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (exists.length) {
            return res.status(400).render('register.html', { error: 'Email já cadastrado.' });
        }

        const hash = await bcrypt.hash(password, 12);
        await pool.query('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, hash]);
        return res.redirect('/login');
    } catch (err) {
        console.error(err);
        return res.status(500).render('register.html', { error: 'Erro ao registrar.' });
    }
});

app.get('/login', (req, res) => {
    res.render('login.html', { error: null });
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).render('login.html', { error: 'Preencha todos os campos.' });
        }
        const [rows] = await pool.query('SELECT id, name, password_hash FROM users WHERE email = ?', [email]);
        if (!rows.length) {
            return res.status(401).render('login.html', { error: 'Credenciais inválidas.' });
        }
        const user = rows[0];
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            return res.status(401).render('login.html', { error: 'Credenciais inválidas.' });
        }
        req.session.user = { id: user.id, name: user.name, email };
        return res.redirect('/listings');
    } catch (err) {
        console.error(err);
        return res.status(500).render('login.html', { error: 'Erro ao logar.' });
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

// Visualização pública
app.get('/', async (req, res) => {
    try {
        const [listings] = await pool.query(
            'SELECT l.*, u.name as owner_name FROM listings l JOIN users u ON u.id = l.user_id ORDER BY l.created_at DESC'
        );
        res.render('index.html', { listings });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar anúncios.');
    }
});

// Listagens do usuário
app.get('/listings', requireAuth, async (req, res) => {
    try {
        const [listings] = await pool.query('SELECT * FROM listings WHERE user_id = ?', [req.session.user.id]);
        res.render('my-listings.html', { listings });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar seus anúncios.');
    }
});

// Criar anúncio
app.get('/listings/new', requireAuth, (req, res) => {
    res.render('new-listing.html', { error: null });
});

app.post('/listings/new', requireAuth, async (req, res) => {
    try {
        const { title, type, price, location, description } = req.body;
        if (!title || !type || !price || !location) {
            return res.status(400).render('new-listing.html', { error: 'Campos obrigatórios ausentes.' });
        }
        await pool.query(
            'INSERT INTO listings (user_id, title, type, price, location, description) VALUES (?, ?, ?, ?, ?, ?)',
            [req.session.user.id, title, type, price, location, description || null]
        );
        res.redirect('/listings');
    } catch (err) {
        console.error(err);
        res.status(500).render('new-listing.html', { error: 'Erro ao criar anúncio.' });
    }
});

// Editar anúncio
app.get('/listings/:id/edit', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM listings WHERE id = ?', [id]);
        if (!rows.length) {
            return res.status(404).send('Anúncio não encontrado.');
        }
        const listing = rows[0];
        if (listing.user_id !== req.session.user.id) {
            return res.status(403).send('Não autorizado.');
        }
        res.render('edit-listing.html', { listing, error: null });
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao carregar anúncio.');
    }
});

app.post('/listings/:id/edit', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, type, price, location, description } = req.body;
        const [rows] = await pool.query('SELECT user_id FROM listings WHERE id = ?', [id]);
        if (!rows.length) {
            return res.status(404).send('Anúncio não encontrado.');
        }
        if (rows[0].user_id !== req.session.user.id) {
            return res.status(403).send('Não autorizado.');
        }
        await pool.query(
            'UPDATE listings SET title = ?, type = ?, price = ?, location = ?, description = ?, updated_at = NOW() WHERE id = ?',
            [title, type, price, location, description || null, id]
        );
        res.redirect('/listings');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao atualizar anúncio.');
    }
});

// Excluir anúncio
app.post('/listings/:id/delete', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT user_id FROM listings WHERE id = ?', [id]);
        if (!rows.length) {
            return res.status(404).send('Anúncio não encontrado.');
        }
        if (rows[0].user_id !== req.session.user.id) {
            return res.status(403).send('Não autorizado.');
        }
        await pool.query('DELETE FROM listings WHERE id = ?', [id]);
        res.redirect('/listings');
    } catch (err) {
        console.error(err);
        res.status(500).send('Erro ao excluir anúncio.');
    }
});

// Inicialização
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});
