const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt'); 

const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', 
    password: 'Juju12', 
    database: 'doacao_sangue' 
});


app.get('/cadastro', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'cadastro.html'));
});


app.post('/cadastro', async (req, res) => {
    const { nome, sobrenome, idade, sexo, tipo_sanguineo, telefone, localizacao, email, senha } = req.body;
    const idadeNumero = parseInt(idade, 10);

   
    const sqlVerificaDuplicidade = 'SELECT * FROM usuarios WHERE email = ? OR telefone = ?';
    db.query(sqlVerificaDuplicidade, [email, telefone], async (err, results) => {
        if (err) {
            console.error('Erro ao verificar duplicidade:', err);
            return res.status(500).json({ error: 'Erro ao cadastrar usuário.' });
        }

        if (results.length > 0) {
            return res.status(400).json({ error: 'Email ou telefone já cadastrado.' });
        }

        try {
            
            const saltRounds = 10; 
            const hashedPassword = await bcrypt.hash(senha, saltRounds);

            
            const sql = 'INSERT INTO usuarios (nome, sobrenome, idade, sexo, tipo_sanguineo, telefone, localizacao, email, senha) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
            db.query(sql, [nome, sobrenome, idadeNumero, sexo, tipo_sanguineo, telefone, localizacao, email, hashedPassword], (err, result) => {
                if (err) {
                    console.error('Erro ao cadastrar usuário:', err);
                    return res.status(500).json({ error: 'Erro ao cadastrar usuário.' });
                }
                res.json({ message: 'Usuário cadastrado com sucesso! Seja bem-vindo ao Banco de Sangue.' });
            });
        } catch (hashError) {
            console.error('Erro ao hashear a senha:', hashError);
            res.status(500).json({ error: 'Erro ao cadastrar usuário.' });
        }
    });
});


app.post('/login', (req, res) => {
    const { email, senha } = req.body;

    
    const sqlVerificaUsuario = 'SELECT * FROM usuarios WHERE email = ?';
    db.query(sqlVerificaUsuario, [email], async (err, results) => {
        if (err) {
            console.error('Erro ao verificar login:', err);
            return res.status(500).json({ error: 'Erro ao realizar login.' });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'Email ou senha incorretos.' });
        }

        const usuario = results[0];
        
        
        const senhaValida = await bcrypt.compare(senha, usuario.senha);
        
        if (!senhaValida) {
            return res.status(401).json({ error: 'Email ou senha incorretos.' });
        }

        res.json({ message: 'Login realizado com sucesso!' });
    });
});

// Iniciar o servidor
app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
