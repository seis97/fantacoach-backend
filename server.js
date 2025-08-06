require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const stripe = require('stripe')(process.env.STRIPE_SECRET);

// ===== DEBUG VARIABILI D'AMBIENTE =====
console.log("🔍 FRONTEND_URL:", process.env.FRONTEND_URL);
console.log("🔍 MONGO_URI:", process.env.MONGO_URI ? "[OK]" : "[MANCANTE]");
console.log("🔍 SECRET_KEY:", process.env.SECRET_KEY ? "[OK]" : "[MANCANTE]");
console.log("🔍 STRIPE_SECRET:", process.env.STRIPE_SECRET ? "[OK]" : "[MANCANTE]");
console.log("🔍 API_FOOTBALL_KEY:", process.env.API_FOOTBALL_KEY ? "[OK]" : "[MANCANTE]");

const User = mongoose.model('User', new mongoose.Schema({
  email: String,
  password: String,
  premium: { type: Boolean, default: false },
  freeUsages: { type: Number, default: 4 }
}));

const Rosa = require('./models/Rosa');

const giocatoreStatsSchema = new mongoose.Schema({
  nome: String,
  ruolo: String,
  dataAggiornamento: String,
  stats: Object
});
const GiocatoreStats = mongoose.model('GiocatoreStats', giocatoreStatsSchema);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://fantacoach.vercel.app';
const API_FOOTBALL_KEY = process.env.API_FOOTBALL_KEY;

// ===== DEBUG REGISTRAZIONE MIDDLEWARE =====
console.log("➡ Registrazione CORS");
const allowedOrigins = [
  'http://localhost:5173',
  'https://fantacoach.vercel.app'
];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS non permesso per questa origine: ${origin}`));
    }
  },
  credentials: true
}));

console.log("➡ Registrazione preflight OPTIONS");
app.options('*', cors());

console.log("➡ Registrazione express.json");
app.use(express.json());
console.log("➡ Registrazione cookieParser");
app.use(cookieParser());

console.log("➡ Connessione MongoDB");
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connesso'))
  .catch(err => console.error('❌ Errore MongoDB:', err));

function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const token = bearerHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = decoded;
      next();
    } catch {
      return res.status(401).json({ errore: 'Token non valido.' });
    }
  } else {
    return res.status(403).json({ errore: 'Token mancante.' });
  }
}

const DEV_EMAILS = ['premium@premium.com'];

// ===== DEBUG REGISTRAZIONE ROUTE =====
console.log("➡ Registrazione /api/search-player");
app.get('/api/search-player', verifyToken, async (req, res) => {
  const query = req.query.query;
  const roleFilter = req.query.role;

  if (!query || query.length < 2) {
    return res.json({ success: false, players: [] });
  }

  try {
    const response = await axios.get('https://api-football-v1.p.rapidapi.com/v3/players', {
      headers: {
        'x-rapidapi-key': API_FOOTBALL_KEY,
        'x-rapidapi-host': 'api-football-v1.p.rapidapi.com'
      },
      params: {
        search: query,
        league: 135,
        season: 2024
      }
    });

    let players = response.data.response.map(p => ({
      nome: p.player.name,
      ruolo: p.statistics[0]?.games?.position || 'N/A',
      squadra: p.statistics[0]?.team?.name || 'Sconosciuta'
    }));

    if (roleFilter) {
      const mappaRuoli = {
        POR: ['Goalkeeper'],
        DIF: ['Defender'],
        CEN: ['Midfielder'],
        ATT: ['Attacker']
      };
      players = players.filter(pl => mappaRuoli[roleFilter]?.includes(pl.ruolo));
    }

    res.json({ success: true, players });
  } catch (err) {
    console.error('❌ Errore ricerca giocatore:', err.response?.data || err.message);
    res.status(500).json({ success: false, players: [] });
  }
});

// ... (Mantieni tutte le tue altre route identiche, ma aggiungi un console.log prima di ciascuna)
// Esempio:
console.log("➡ Registrazione /api/formazionepreview");
app.post('/api/formazionepreview', verifyToken, async (req, res) => { /* codice originale */ });

console.log("➡ Registrazione /api/register");
app.post('/api/register', async (req, res) => { /* codice originale */ });

console.log("➡ Registrazione /api/login");
app.post('/api/login', async (req, res) => { /* codice originale */ });

console.log("➡ Registrazione /api/rosa/save");
app.post('/api/rosa/save', verifyToken, async (req, res) => { /* codice originale */ });

console.log("➡ Registrazione /api/rosa/all");
app.get('/api/rosa/all', verifyToken, async (req, res) => { /* codice originale */ });

console.log("➡ Registrazione /api/rosa/me");
app.get('/api/rosa/me', verifyToken, async (req, res) => { /* codice originale */ });

console.log("➡ Registrazione /api/premium");
app.post('/api/premium', verifyToken, async (req, res) => { /* codice originale */ });

console.log("➡ Registrazione /api/create-checkout-session");
app.post('/api/create-checkout-session', verifyToken, async (req, res) => { /* codice originale */ });

// ===== AVVIO SERVER =====
app.listen(PORT, () => {
  console.log(`✅ Backend avviato su http://localhost:${PORT}`);
});
