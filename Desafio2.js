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
let userId = '';

const authenticateToken = async (req, res, next) => {
    const tokenHeader = req.headers['authorization'];

    if (!tokenHeader) {
        return res.status(401).json({ error: 'Não autorizado. Token não fornecido.' });
    }

    const [bearer, token] = tokenHeader.split(' ');

    if (bearer !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'Não autorizado. Formato de token inválido.' });
    }

    try {
        const decoded = await jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.usuarioId;  // Atribui o userId à variável global
        req.user = { userId: decoded.usuarioId };
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
            const userId = usuario[0].id;
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
                console.log('Resposta da API:', resposta.data);
                if (resposta.data.token) {
                    authToken = resposta.data.token;
                    userId = resposta.data.id;
                } else {
                    console.error('Token não encontrado na resposta da API.');
                }
            } catch (erro) {
                console.error('Erro na chamada da API:', erro.message);
            }
            mostrarOpcoes(); // Continua mostrando as opções
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
                            mostrarOpcoes(); // Chama a próxima opção automaticamente após o cadastro
                        })
                        .catch((erro) => {
                            console.error('Erro na chamada da API:', erro.message);
                        });
                    });
                });
            });
        });
    });
}

function RecuperaDados() {
    app.get('/user', authenticateToken, async (req, res) => {
        // Lógica para recuperar informações do usuário
        try {
            const [user] = await db.execute('SELECT * FROM usuarios WHERE id = ?', [userId]);
            if (user.length === 0) {
                return res.status(404).json({ error: 'Usuário não encontrado.' });
            }
            res.json({
                id: user[0].id,
                nome: user[0].nome,
                email: user[0].email,
                telefone: user[0].telefone,
            });
        } catch (error) {
            console.error('Erro ao recuperar informações do usuário:', error);
            res.status(500).json({ error: 'Erro interno do servidor.' });
        }
    });
    mostrarOpcoes();
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
                realizarSignUp();
                break;
            case '3':
                try {
                    const resposta = await axios.get('http://localhost:3000/user', {
                        headers: {
                            Authorization: `Bearer ${authToken}`,
                        },
                    });
                    console.log('Dados do usuário:', resposta.data);
                } catch (erro) {
                    console.error('Erro na chamada da API:', erro.message);
                }
                RecuperaDados();
            break;
        case '4':
          console.log('Saindo...');
          rl.close();
          break;
  
        default:
          console.log('Opção inválida. Tente novamente.');
          mostrarOpcoes();
      }
    });
  }
  
  // Inicia a interface do usuário
mostrarOpcoes();

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
