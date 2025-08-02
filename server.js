require('dotenv').config(); // ✅ Carica le variabili da .env

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const stripe = require('stripe')(process.env.STRIPE_SECRET);

const app = express();
const PORT = 3000;
const SECRET_KEY = process.env.SECRET_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL;

app.use(express.json());
app.use(cookieParser());

// ✅ CORS configurato per frontend su Vercel
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST']
}));

// 🔗 Connessione MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('✅ MongoDB connesso'))
  .catch(err => console.error('❌ Errore MongoDB:', err));

// 📄 Schema Utente
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  premium: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

// 🔐 Middleware verifica token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const token = bearerHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ errore: 'Token non valido.' });
    }
  } else {
    return res.status(403).json({ errore: 'Token mancante.' });
  }
}

// 📌 Funzione simulata "AI" per la formazione
function generaFormazione(squadra) {
  const portieri = squadra.filter(g => g.ruolo === 'POR').slice(0, 1);
  const difensori = squadra.filter(g => g.ruolo === 'DIF').slice(0, 4);
  const centrocampisti = squadra.filter(g => g.ruolo === 'CEN').slice(0, 3);
  const attaccanti = squadra.filter(g => g.ruolo === 'ATT').slice(0, 3);
  return [...portieri, ...difensori, ...centrocampisti, ...attaccanti].slice(0, 11);
}

const DEV_EMAILS = ['premium@premium.com']; // ✅ Email che bypassano il check Premium

// 📌 REGISTRAZIONE
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

// 📌 LOGIN
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ errore: 'Utente non trovato.' });

  const valido = bcrypt.compareSync(password, user.password);
  if (!valido) return res.status(400).json({ errore: 'Password errata.' });

  const token = jwt.sign({ email: user.email, premium: user.premium }, SECRET_KEY, { expiresIn: '7d' });
  res.json({ token, premium: user.premium });
});

// 📌 DASHBOARD
app.get('/api/dashboard', verifyToken, (req, res) => {
  res.json({ messaggio: `🎉 Benvenuto ${req.user.email}` });
});

// 📌 FORMAZIONE BASE
app.post('/api/formazione', verifyToken, (req, res) => {
  const userEmail = req.user.email;
  const isDev = DEV_EMAILS.includes(userEmail);

  if (!req.user.premium && !isDev) {
    return res.status(403).json({ errore: '⚠️ Solo per utenti Premium.' });
  }

  const { portieri, difensori, centrocampisti, attaccanti } = req.body;

  if (
    !portieri || !difensori || !centrocampisti || !attaccanti ||
    portieri.length !== 3 ||
    difensori.length !== 8 ||
    centrocampisti.length !== 8 ||
    attaccanti.length !== 6
  ) {
    return res.status(400).json({
      errore: '❌ Inserisci esattamente 3 portieri, 8 difensori, 8 centrocampisti e 6 attaccanti.'
    });
  }

  const formazione = [
    portieri[0],
    ...difensori.slice(0, 3),
    ...centrocampisti.slice(0, 3),
    ...attaccanti.slice(0, 1)
  ];

  res.json({ formazione });
});

// 📌 FORMAZIONE AI
app.post('/api/formazione-ai', verifyToken, (req, res) => {
  const userEmail = req.user.email;
  const isDev = DEV_EMAILS.includes(userEmail);

  if (!req.user.premium && !isDev) {
    return res.status(403).json({ errore: 'Solo gli utenti Premium possono usare questa funzione.' });
  }

  const squadra = req.body.squadra;
  if (!squadra || squadra.length < 11) {
    return res.status(400).json({ errore: 'Devi inserire almeno 11 giocatori.' });
  }

  const formazione = generaFormazione(squadra);
  res.json({ formazione });
});

// 📌 ATTIVA PREMIUM
app.post('/api/premium', verifyToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ errore: 'Utente non trovato.' });

    user.premium = true;
    await user.save();

    res.json({ messaggio: '✅ Premium attivato con successo!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ errore: 'Errore interno.' });
  }
});

// 📌 STRIPE SESSION
app.post('/api/create-checkout-session', verifyToken, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'eur',
          product_data: {
            name: 'FantaCoach Premium',
            description: 'Sblocca tutte le funzionalità Premium',
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
  } catch (err) {
    console.error(err);
    res.status(500).json({ errore: 'Errore creazione sessione Stripe' });
  }
});

// 📌 AVVIO SERVER
app.listen(PORT, () => {
  console.log(`✅ Backend avviato su http://localhost:${PORT}`);
});
module.exports = app;
