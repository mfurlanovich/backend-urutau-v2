// --- SGM URUTAU: Backend em Node.js (Com Sistema de Usuários e JWT) ---

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// 🔒 O SEGREDO ESTÁ AQUI: 
// Em vez de colocar a URL com senha, usamos process.env.MONGO_URI.
// O Node.js vai procurar essa variável no Render (ou no arquivo .env local)
const MONGO_URI = process.env.MONGO_URI;

const JWT_SECRET = process.env.JWT_SECRET || 'chave-secreta-super-segura-urutau-2026';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Verifica se a variável de ambiente foi configurada antes de tentar conectar
if (!MONGO_URI) {
    console.error('❌ ERRO FATAL: Variável MONGO_URI não foi configurada!');
    process.exit(1); 
}

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Conectado ao MongoDB Atlas com sucesso!'))
  .catch(err => console.error('❌ Erro ao conectar ao banco de dados:', err));

// ==========================================
// MODELAGEM DOS DADOS
// ==========================================
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', UserSchema);

const MilitarySchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    userId: { type: String, required: true },
    matricula: String,
    name: String
}, { strict: false }); 
const Military = mongoose.model('Military', MilitarySchema);

// ==========================================
// MIDDLEWARE DE SEGURANÇA (O Porteiro)
// ==========================================
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: 'Acesso negado. Token não fornecido.' });
    
    try {
        const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
        req.userId = decoded.id;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Sessão inválida ou expirada.' });
    }
};

// ==========================================
// ROTAS DE AUTENTICAÇÃO
// ==========================================
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ error: 'Nome de usuário já está em uso.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Conta criada com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao criar conta.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: 'Senha incorreta.' });

        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: user.username });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao fazer login.' });
    }
});

// ==========================================
// ROTAS DA API
// ==========================================
app.get('/api/personnel', verifyToken, async (req, res) => {
    try {
        const personnel = await Military.find({ userId: req.userId }, '-_id -__v');
        res.json({ personnel });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar dados.' });
    }
});

app.post('/api/personnel', verifyToken, async (req, res) => {
    try {
        const militaryData = req.body;
        militaryData.userId = req.userId;
        const newMil = new Military(militaryData);
        await newMil.save();
        res.status(201).json({ message: 'Militar registrado!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao salvar militar.' });
    }
});

app.put('/api/personnel/:id', verifyToken, async (req, res) => {
    try {
        const updatedMil = await Military.findOneAndUpdate(
            { id: req.params.id, userId: req.userId }, 
            req.body, 
            { new: true, overwrite: true }
        );
        if (!updatedMil) return res.status(404).json({ error: 'Militar não encontrado.' });
        res.json({ message: 'Sincronizado com sucesso.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao atualizar.' });
    }
});

app.delete('/api/personnel/:id', verifyToken, async (req, res) => {
    try {
        const deletedMil = await Military.findOneAndDelete({ id: req.params.id, userId: req.userId });
        if (!deletedMil) return res.status(404).json({ error: 'Militar não encontrado.' });
        res.json({ message: 'Baixa efetuada.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao deletar.' });
    }
});

app.delete('/api/personnel-purge/all', verifyToken, async (req, res) => {
    try {
        await Military.deleteMany({ userId: req.userId });
        res.json({ message: 'Banco de dados purgado.' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao purgar dados.' });
    }
});

app.listen(PORT, () => {
    console.log(`🛡️ SGM URUTAU Backend rodando na porta ${PORT}.`);
});