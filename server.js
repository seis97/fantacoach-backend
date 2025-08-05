require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const stripe = require('stripe')(process.env.STRIPE_SECRET);

const User = mongoose.model('User', new mongoose.Schema({
  email: String,
  password: String,
  premium: { type: Boolean, default: false },
  freeUsages: { type: Number, default: 4 }
}));

const Rosa = require('./models/Rosa');

// 📌 Nuovo modello per cache statistiche giocatori
const giocatoreStatsSchema = new mongoose.Schema({
  nome: String,
  ruolo: String,
  dataAggiornamento: String, // formato YYYY-MM-DD
  stats: Object
});
const GiocatoreStats = mongoose.model('GiocatoreStats', giocatoreStatsSchema);

const app = express();
const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const API_FOOTBALL_KEY = process.env.API_FOOTBALL_KEY;

app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());
app.use(cookieParser());

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
// 📌 Cerca giocatore da API-Football

// 📌 Cerca giocatore in Serie A con filtro ruolo
app.get('/api/search-player', verifyToken, async (req, res) => {
  const query = req.query.query;
  const roleFilter = req.query.role; // "POR", "DIF", "CEN", "ATT"

  console.log("🔍 [Backend] Ricerca:", query, "Ruolo filtro:", roleFilter);

  if (!query || query.length < 2) {
    return res.json({ success: false, players: [] });
  }

  try {
    const response = await axios.get('https://api-football-v1.p.rapidapi.com/v3/players', {
      headers: {
        'x-rapidapi-key': process.env.API_FOOTBALL_KEY,
        'x-rapidapi-host': 'api-football-v1.p.rapidapi.com'
      },
      params: {
        search: query,
        league: 135,       // 📌 Solo Serie A
        season: 2024       // 📌 Stagione corrente
      }
    });

    let players = response.data.response.map(p => ({
      nome: p.player.name,
      ruolo: p.statistics[0]?.games?.position || 'N/A',
      squadra: p.statistics[0]?.team?.name || 'Sconosciuta'
    }));

    // 📌 Filtro per ruolo (se presente)
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





// 📌 Funzione per prendere statistiche con cache
async function getPlayerStats(nome, ruolo) {
  const oggi = new Date().toISOString().split('T')[0];

  // 1. Controlla cache
  const cached = await GiocatoreStats.findOne({ nome, dataAggiornamento: oggi });
  if (cached) {
    return cached.stats;
  }

  // 2. Se non in cache, chiama RapidAPI
  try {
    const res = await axios.get(`https://api-football-v1.p.rapidapi.com/v3/players`, {
      headers: {
        'x-rapidapi-host': 'api-football-v1.p.rapidapi.com',
        'x-rapidapi-key': API_FOOTBALL_KEY
      },
      params: { search: nome, season: 2024 }
    });

    const player = res.data.response?.[0]?.statistics?.[0] || {};
    const stats = {
      rating: parseFloat(player?.games?.rating) || 0,
      goals: player?.goals?.total || 0,
      assists: player?.goals?.assists || 0,
      shots: player?.shots?.total || 0
    };

    // Salva in cache
    await GiocatoreStats.findOneAndUpdate(
      { nome, dataAggiornamento: oggi },
      { nome, ruolo, dataAggiornamento: oggi, stats },
      { upsert: true }
    );

    return stats;
  } catch (err) {
    console.error(`Errore API per ${nome}:`, err.message);
    return { rating: 0, goals: 0, assists: 0, shots: 0 };
  }
}

// 📌 Funzione AI per generare formazione
async function generaFormazioneIntelligente(squadra) {
  const valutazioni = [];

  for (const g of squadra) {
    const stats = await getPlayerStats(g.nome, g.ruolo);
    const punteggio = stats.rating + stats.goals * 2 + stats.assists * 1.5 + stats.shots * 0.2;
    valutazioni.push({ ...g, punteggio });
  }

  // Ordina per punteggio
  valutazioni.sort((a, b) => b.punteggio - a.punteggio);

  const moduli = {
    '4-3-3': { POR: 1, DIF: 4, CEN: 3, ATT: 3 },
    '4-4-2': { POR: 1, DIF: 4, CEN: 4, ATT: 2 },
    '3-5-2': { POR: 1, DIF: 3, CEN: 5, ATT: 2 }
  };

  let migliorModulo = '4-3-3';
  let migliorScore = 0;

  // Scegli il miglior modulo
  for (const [mod, ruoli] of Object.entries(moduli)) {
    let score = 0;
    for (const [ruolo, num] of Object.entries(ruoli)) {
      const top = valutazioni.filter(g => g.ruolo === ruolo).slice(0, num);
      score += top.reduce((sum, g) => sum + g.punteggio, 0);
    }
    if (score > migliorScore) {
      migliorScore = score;
      migliorModulo = mod;
    }
  }

  // Seleziona titolari
  const selezionati = [];
  for (const [ruolo, num] of Object.entries(moduli[migliorModulo])) {
    const top = valutazioni.filter(g => g.ruolo === ruolo).slice(0, num);
    selezionati.push(...top);
  }

  const titolari = selezionati.slice(0, 11);
  const panchina = valutazioni.filter(g => !titolari.includes(g)).slice(0, 7);

  return { titolari, panchina, modulo: migliorModulo };
}

// 📌 Route formazione AI
app.post('/api/formazionepreview', verifyToken, async (req, res) => {
  const userEmail = req.user.email;
  const isDev = DEV_EMAILS.includes(userEmail);

  try {
    const user = await User.findOne({ email: userEmail });
    if (!user) return res.status(404).json({ errore: 'Utente non trovato.' });

    // Se NON è premium o dev → usa tentativi gratis
    if (!user.premium && !isDev) {
      if (user.freeUsages > 0) {
        user.freeUsages -= 1;
        await user.save();
      } else {
        return res.status(403).json({ errore: 'Hai esaurito le generazioni gratuite. Diventa Premium!' });
      }
    }

    const squadra = req.body.squadra;

// Verifica che ogni giocatore abbia nome e ruolo
if (!Array.isArray(squadra) || squadra.some(g => !g.nome || !g.ruolo)) {
  return res.status(400).json({ errore: 'Rosa non valida: assicurati di scegliere i giocatori dai suggerimenti.' });
}


    const { titolari, panchina, modulo } = await generaFormazioneIntelligente(squadra);
    res.json({
      formazione: titolari.map(g => g.nome),
      panchina: panchina.map(g => g.nome),
      modulo
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ errore: 'Errore generazione AI.' });
  }
});


// 📌 Registrazione
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ errore: 'Email e password obbligatori.' });

  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ errore: 'Utente già registrato.' });

  const hashed = bcrypt.hashSync(password, 8);
  const nuovoUtente = new User({ email, password: hashed });
  await nuovoUtente.save();

  const token = jwt.sign({ email, premium: false }, SECRET_KEY, { expiresIn: '7d' });
  res.json({ token, premium: false });
});

// 📌 Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ errore: 'Utente non trovato.' });

  const valido = bcrypt.compareSync(password, user.password);
  if (!valido) return res.status(400).json({ errore: 'Password errata.' });

  const token = jwt.sign({ email: user.email, premium: user.premium }, SECRET_KEY, { expiresIn: '7d' });
  res.json({ token, premium: user.premium });
});

// 📌 Salva o aggiorna rosa
// 📌 Salva o aggiorna rosa (accetta anche incomplete)
app.post('/api/rosa/save', verifyToken, async (req, res) => {
  let { nomeSquadra, modulo, titolari, panchina } = req.body;
  const userEmail = req.user.email;

  try {
    // Controllo utente
    const user = await User.findOne({ email: userEmail });
    if (!user) return res.status(404).json({ errore: 'Utente non trovato.' });

    // 📌 Se nome squadra mancante → errore
    if (!nomeSquadra || nomeSquadra.trim() === '') {
      return res.status(400).json({ errore: 'Nome squadra obbligatorio.' });
    }

    // 📌 Normalizza titolari e panchina in modo che abbiano oggetti con {nome, ruolo}
    titolari = (titolari || []).map(g => ({
      nome: g?.nome || '',
      ruolo: g?.ruolo || ''
    }));

    panchina = (panchina || []).map(g => ({
      nome: g?.nome || '',
      ruolo: g?.ruolo || ''
    }));

    // 📌 Trova rosa esistente
    let rosa = await Rosa.findOne({ userId: user._id, nomeSquadra });

    if (rosa) {
      rosa.modulo = modulo || '4-3-3';
      rosa.titolari = titolari;
      rosa.panchina = panchina;
      await rosa.save();
      return res.json({
        success: true,
        message: titolari.length < 11 ? 'Rosa aggiornata (incompleta)' : 'Rosa aggiornata con successo'
      });
    }

    // 📌 Crea nuova rosa
    await Rosa.create({
      userId: user._id,
      nomeSquadra,
      modulo: modulo || '4-3-3',
      titolari,
      panchina
    });

    res.json({
      success: true,
      message: titolari.length < 11 ? 'Nuova rosa salvata (incompleta)' : 'Nuova rosa salvata con successo'
    });
  } catch (err) {
    console.error("❌ Errore salvataggio rosa:", err);
    res.status(500).json({ errore: 'Errore salvataggio rosa.' });
  }
});

// 📌 Recupera rose utente
app.get('/api/rosa/all', verifyToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ errore: 'Utente non trovato.' });

    const rose = await Rosa.find({ userId: user._id });
    res.json({ success: true, rose });
  } catch (err) {
    res.status(500).json({ errore: 'Errore nel recupero rose.' });
  }
});

// 📌 Recupera rosa specifica
app.get('/api/rosa/me', verifyToken, async (req, res) => {
  const user = await User.findOne({ email: req.user.email });
  const rosa = await Rosa.findOne({ userId: user._id, nomeSquadra: req.query.nomeRosa });
  if (!rosa) return res.status(404).json({ errore: 'Rosa non trovata.' });
  res.json({ success: true, rosa });
});

// 📌 Premium
app.post('/api/premium', verifyToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ errore: 'Utente non trovato.' });

    user.premium = true;
    await user.save();

    res.json({ messaggio: '✅ Premium attivato!' });
  } catch {
    res.status(500).json({ errore: 'Errore interno.' });
  }
});

// 📌 Stripe Checkout
app.post('/api/create-checkout-session', verifyToken, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: {
            name: 'FantaCoach Premium',
            description: 'Accesso illimitato a tutte le funzionalità.',
          },
          unit_amount: 499,
        },
        quantity: 1
      }],
      mode: 'payment',
      success_url: `${FRONTEND_URL}/premium-success`,
      cancel_url: `${FRONTEND_URL}/premium`
    });

    res.json({ url: session.url });
  } catch {
    res.status(500).json({ errore: 'Errore con Stripe' });
  }
});



// 📌 Avvio server
app.listen(PORT, () => {
  console.log(`✅ Backend avviato su http://localhost:${PORT}`);
});
