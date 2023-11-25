const express = require('express');
const bodyParser = require('body-parser');
const uuid = require('uuid');
const db = require('./dbUsuarios');
const jwt = require('jsonwebtoken');
const dbUsuarios = require('./dbUsuarios');
const app = express();
const PORT = 3000;
const readline = require('readline');
const axios = require('axios');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });


require('dotenv').config();
const jwtSecret = process.env.JWT_SECRET;

app.use(bodyParser.json());

let authToken = '';
let usuarioId = '';

const authenticateToken = async (req, res, next) => {
    const tokenHeader = req.headers['authorization'];

    if (!tokenHeader) {
        return res.status(401).json({ error: 'Não autorizado. Token não fornecido.' });
    }

    const [bearer, authToken] = tokenHeader.split(' ');

    if (bearer !== 'Bearer' || !authToken) {
        return res.status(401).json({ error: 'Não autorizado. Formato de token inválido.' });
    }

    try {
        const decoded = await jwt.verify(authToken, process.env.JWT_SECRET);
        usuarioId = decoded.usuarioId;
        req.usuario = { usuarioId: decoded.usuarioId };
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Sessão inválida. Token expirado.' });
        }
        return res.status(401).json({ error: 'Não autorizado. Token inválido.' });
    }
};

function realizarSignIn() {
    app.post('/signin', async (req, res) => {
        const { email, senha } = req.body;

        try {
            const [usuario] = await db.execute('SELECT * FROM usuarios WHERE email = ? AND senha = ?', [email, senha]);

            if (usuario.length === 0) {
                return res.status(401).json({ error: 'Usuário e/ou senha inválidos.' });
            }
            const usuarioId = usuario[0].id;
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
    rl.question('Digite seu e-mail: ', (email) => {
        rl.question('Digite sua senha: ', async (senha) => {
            try {
                const resposta = await axios.post('http://localhost:3000/signin', {
                    email,
                    senha,
                });
                console.log('Login bem sucessido:', resposta.data);
                if (resposta.data.token) {
                    authToken = resposta.data.token;
                    usuarioId = resposta.data.id;
                } else {
                    console.error('Token não encontrado na resposta da API.');
                }
            } catch (erro) {
                if (erro.response.status === 401) {
                    console.error('Usuário e/ou senha inválidos');
                    mostrarOpcoes();
                } else {
                    console.error('Erro na chamada da API:', erro.message);
                }
            }
            mostrarOpcoes();
        });
    });
}

 
function realizarSignUp(nome, email, senha, telefoneNumero, telefoneDDD) {
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
    rl.question('Digite seu nome: ', (nome) => {
        rl.question('Digite seu e-mail: ', (email) => {
            rl.question('Digite sua senha: ', (senha) => {
                rl.question('Digite o número de telefone: ', (telefoneNumero) => {
                    rl.question('Digite o DDD do telefone: ', async (telefoneDDD) => {
                        const telefone = [{ numero: telefoneNumero, ddd: telefoneDDD }];
                        return axios.post('http://localhost:3000/signup', { nome, email, senha, telefone })
                        .then((resposta) => {
                            authToken = resposta.data.token;
                            console.log('Cadastro bem-sucedido!');
                            mostrarOpcoes();
                        })
                        .catch((erro) => {
                            if (erro.response.status === 400) {
                                console.error('E-mail já existente.');
                                mostrarOpcoes();
                            } else {
                                console.error('Erro na chamada da API:', erro.message);
                            }
                        });
                    });
                });
            });
        });
    });
}

app.get('/usuario', authenticateToken, async (req, res) => {
    try {
        const [usuario] = await db.execute('SELECT * FROM usuarios WHERE id = ?', [usuarioId]);
        if (usuario.length === 0) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }
        res.json({
            id: usuario[0].id,
            nome: usuario[0].nome,
            email: usuario[0].email,
            telefone: usuario[0].telefone,
        });
    } catch (error) {
        console.error('Erro ao recuperar informações do usuário:', error);
        res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});

async function RecuperaDados(authToken) {
    try {
        const resposta = await axios.get('http://localhost:3000/usuario', {
            headers: {
                Authorization: `Bearer ${authToken}`,
            },
        });
        console.log('Dados do usuário:', resposta.data);
        mostrarOpcoes();
    } catch (erro) {
        console.error('Erro na chamada da API:', erro.message);
    }
}

  
function mostrarOpcoes() {
    console.log('Escolha uma opção:');
    console.log('1. Sign In');
    console.log('2. Sign Up');
    console.log('3. Recuperar Dados');
    console.log('4. Sair');
  
    rl.question('Digite o número da opção desejada: ', async (opcao) => {
        switch (opcao) {
            case '1':
                realizarSignIn();
                break;
            case '2':
                await realizarSignUp();
                break;
            case '3':
                RecuperaDados();
            break;
        case '4':
            console.log('Saindo...');
            rl.close();
            process.exit();
          break;
        default:
          console.log('Opção inválida. Tente novamente.');
          mostrarOpcoes();
      }
    });
  }

mostrarOpcoes();

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
