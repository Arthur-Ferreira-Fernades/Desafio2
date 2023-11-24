const express = require('express');
const bodyParser = require('body-parser');
const uuid = require('uuid');
const db = require('./dbUsuarios');
const jwt = require('jsonwebtoken');
const dbUsuarios = require('./dbUsuarios');
const app = express();
const PORT = 3000;

require('dotenv').config();
const jwtSecret = process.env.JWT_SECRET;

app.use(bodyParser.json());

app.post('/signup', async (req, res) => {
    const { nome, email, senha, telefone } = req.body;

    try {
        const [existeEmail] = await db.execute('SELECT * FROM usuarios WHERE email = ?', [email]);

        if (existeEmail.length > 0) {
            return res.status(400).json({ error: 'E-mail já existente.' });
        }

        const novoUsuario = {
            id: uuid.v4(),
            nome,
            email,
            senha,
            telefone,
            data_criacao: new Date(),
            data_atualizacao: new Date(),
            ultimo_login: null,
            token: null,
        };

        await db.execute('INSERT INTO usuarios (id, nome, email, senha, telefone, data_criacao, data_atualizacao) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [novoUsuario.id, novoUsuario.nome, novoUsuario.email, novoUsuario.senha, JSON.stringify(novoUsuario.telefone), novoUsuario.data_criacao, novoUsuario.data_atualizacao]);

        res.status(201).json({
            id: novoUsuario.id,
            data_criacao: novoUsuario.data_criacao,
            data_atualizacao: novoUsuario.data_atualizacao,
            ultimo_login: novoUsuario.ultimo_login,
            token: novoUsuario.token,
        });
    } catch (error) {
        console.error('Erro ao cadastrar usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});


const autenticaToken = (req, res, next) => {
    const tokenHeader = req.headers['authorization'];

    if (!tokenHeader) {
        return res.status(401).json({ error: 'Não autorizado. Token não fornecido.' });
    }

    const [bearer, token] = tokenHeader.split(' ');

    if (bearer !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'Não autorizado. Formato de token inválido.' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, usuario) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(401).json({ error: 'Sessão inválida. Token expirado.' });
            }
            return res.status(401).json({ error: 'Não autorizado. Token inválido.' });
        }

        req.usuario = usuario;
        next();
    });
};

app.post('/signin', async (req, res) => {
    const { email, senha } = req.body;

    try {
        const [usuario] = await db.execute('SELECT * FROM usuarios WHERE email = ? AND senha = ?', [email, senha]);

        if (usuario.length === 0) {
            return res.status(401).json({ error: 'Usuário e/ou senha inválidos.' });
        }

        await db.execute('UPDATE usuarios SET ultimo_login = ?, data_atualizacao = ?, token = ? WHERE id = ?',
            [new Date(), new Date(), jwt.sign({ usuarioId: usuario[0].id }, process.env.JWT_SECRET, { expiresIn: '30m' }), usuario[0].id]);

        res.json({
            id: usuario[0].id,
            data_criacao: usuario[0].data_criacao,
            data_atualizacao: usuario[0].data_atualizacao,
            ultimo_login: new Date(),
            token: jwt.sign({ usuarioId: usuario[0].id }, process.env.JWT_SECRET, { expiresIn: '30m' }),
        });
    } catch (error) {
        console.error('Erro ao autenticar usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.get('/usuario/:id', autenticaToken, async (req, res) => {

    const { id } = req.params;

    try {
        const [dadosUsuario] = await db.execute('SELECT id, nome, email, telefone FROM usuarios WHERE id = ?', [id]);

        if (dadosUsuario.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }

        res.json({
            id: dadosUsuario[0].id,
            nome: dadosUsuario[0].nome,
            email: dadosUsuario[0].email,
            telefone: JSON.parse(dadosUsuario[0].telefone),
        });
    } catch (error) {
        console.error('Erro ao obter informações do usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
