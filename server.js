const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
require("dotenv").config();
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);



const app = express();

// ✅ Middleware CORS
app.use(cors({
  origin: ["http://localhost:5173", "https://fantacoach-frontend.vercel.app"],
  credentials: true
}));

// ✅ Gestione preflight (OPTIONS)
app.options("*", cors({
  origin: ["http://localhost:5173", "https://fantacoach-frontend.vercel.app"],
  credentials: true
}));

app.use(express.json());

// 🔽 da qui in poi lascia invariato il resto del tuo codice

// ========= CONFIG =========
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.SECRET_KEY || process.env.JWT_SECRET || 'changeme';
const API_FOOTBALL_KEY = process.env.API_FOOTBALL_KEY;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// SOLO SERIE A 2025/26
const LEAGUE = 135;   // Serie A
const SEASON = Number(process.env.SEASON || 2025); // stagione 2025 => 2025/26

// ========= DB =========
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB connesso'))
  .catch(err => console.error('❌ Errore MongoDB:', err.message));

// ========= AUTH =========
function verifyToken(req, res, next) {
  const bearer = req.headers['authorization'];
  if (!bearer) return res.status(403).json({ errore: 'Token mancante.' });
  const token = bearer.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ errore: 'Token non valido.' });
  }
}

// Autenticazione “soft” per l’autocomplete (funziona anche senza token)
function softVerify(req, res, next) {
  const bearer = req.headers['authorization'];
  if (bearer) {
    try { req.user = jwt.verify(bearer.split(' ')[1], JWT_SECRET); } catch {}
  }
  next();
}

// ========= MODELS =========
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,

  // Premium
  premium: { type: Boolean, default: false },
  premiumType: { type: String, enum: ['none', 'lifetime', 'monthly'], default: 'none' },
  premiumUntil: { type: Date, default: null },

  // Conteggio prove gratuite (per utenti non premium)
  freeGenerationsUsed: { type: Number, default: 0 },

  // (opzionali, se in futuro usi il Customer Portal)
  stripeCustomerId: { type: String, default: null },
  stripeSubscriptionId: { type: String, default: null },
}));

const Rosa = mongoose.model('Rosa', new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  nomeSquadra: { type: String, required: true },
  modulo: { type: String, default: '4-3-3' },
  titolari: [String],
  panchina: [String],
  portieri: [String],
  difensori: [String],
  centrocampisti: [String],
  attaccanti: [String],
}, { timestamps: true }));

// ========= UTILS =========
const roleHintMap = {
  portieri: 'Goalkeeper',
  difensori: 'Defender',
  centrocampisti: 'Midfielder',
  attaccanti: 'Attacker'
};
function normalizeRole(apiRole = '') {
  const r = String(apiRole).toLowerCase();
  if (r.includes('keeper') || r === 'gk' || r === 'goalkeeper') return 'Goalkeeper';
  if (r.includes('def')) return 'Defender';
  if (r.includes('mid')) return 'Midfielder';
  if (r.includes('att') || r.includes('forw') || r === 'fw' || r === 'st') return 'Attacker';
  return 'Unknown';
}
function pickLatestStat(stats = []) {
  if (!Array.isArray(stats) || !stats.length) return null;
  return stats.reduce((best, cur) => {
    const by = (x) => (x?.league?.season ?? 0);
    return by(cur) > by(best) ? cur : best;
  }, stats[0]);
}

// Piccolo fallback locale (SOLO Serie A)
const LOCAL_FALLBACK_PLAYERS = [
  { nome: 'Lautaro Martinez', ruolo: 'Attacker', squadra: 'Inter' },
  { nome: 'Marcus Thuram', ruolo: 'Attacker', squadra: 'Inter' },
  { nome: 'Nicolò Barella', ruolo: 'Midfielder', squadra: 'Inter' },
  { nome: 'Davide Frattesi', ruolo: 'Midfielder', squadra: 'Inter' },
  { nome: 'Rafael Leão', ruolo: 'Attacker', squadra: 'Milan' },
  { nome: 'Mike Maignan', ruolo: 'Goalkeeper', squadra: 'Milan' },
  { nome: 'Alessandro Buongiorno', ruolo: 'Defender', squadra: 'Napoli' },
  { nome: 'Khvicha Kvaratskhelia', ruolo: 'Attacker', squadra: 'Napoli' },
  { nome: 'Gleison Bremer', ruolo: 'Defender', squadra: 'Juventus' },
  { nome: 'Dusan Vlahovic', ruolo: 'Attacker', squadra: 'Juventus' },
];

// ========= CACHE SUGGERIMENTI =========
const suggestCache = new Map(); // key: `${query}|${roleWanted}|${LEAGUE}|${SEASON}`
const SUGGEST_TTL_MS = 1000 * 60 * 10; // 10 min
function getCached(k) {
  const hit = suggestCache.get(k);
  if (!hit) return null;
  if (Date.now() - hit.when > SUGGEST_TTL_MS) {
    suggestCache.delete(k);
    return null;
  }
  return hit.players;
}
function setCached(k, players) {
  suggestCache.set(k, { when: Date.now(), players });
  if (suggestCache.size > 500) {
    const first = suggestCache.keys().next().value;
    suggestCache.delete(first);
  }
}

// ========= CORS & WEBHOOK (ordine importante) =========
app.use(cors({
  origin: ["https://fantacoach-frontend.vercel.app"],
  credentials: true
}));

// Webhook Stripe DEVE usare il raw parser e va definito PRIMA del json parser
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('❌ Errore webhook Stripe:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      const userId = session.metadata?.userId || null;

      if (userId) {
        const isLifetime = session.mode === 'payment';
        const isMonthly = session.mode === 'subscription';

        const update = {
          premium: true,
          premiumType: isLifetime ? 'lifetime' : (isMonthly ? 'monthly' : 'unknown'),
        };

        // Se è subscription, sincronizza premiumUntil dal current_period_end
        if (isMonthly && session.subscription) {
          const sub = await stripe.subscriptions.retrieve(session.subscription);
          update.premiumUntil = new Date(sub.current_period_end * 1000);
          update.stripeSubscriptionId = sub.id;
        }

        if (session.customer) update.stripeCustomerId = session.customer;

        await User.findByIdAndUpdate(userId, update);
        console.log(`✅ Premium attivato per user ${userId} (${update.premiumType})`);
      }
    }

    // (opzionale) gestisci rinnovi/cancellazioni per tenere allineato premiumUntil
    if (event.type === 'customer.subscription.updated' || event.type === 'invoice.payment_succeeded') {
      const sub = event.data.object;
      const user = await User.findOne({ stripeSubscriptionId: sub.id });
      if (user) {
        await User.findByIdAndUpdate(user._id, {
          premium: true,
          premiumType: 'monthly',
          premiumUntil: new Date(sub.current_period_end * 1000),
        });
        console.log(`🔁 Subscription aggiornata per user ${user._id}`);
      }
    }

    if (event.type === 'customer.subscription.deleted') {
      const sub = event.data.object;
      const user = await User.findOne({ stripeSubscriptionId: sub.id });
      if (user) {
        await User.findByIdAndUpdate(user._id, {
          premium: false,
          premiumType: 'none',
          premiumUntil: null,
        });
        console.log(`⛔ Subscription cancellata per user ${user._id}`);
      }
    }
  } catch (err) {
    console.error('❌ Errore gestione evento Stripe:', err.message);
  }

  res.json({ received: true });
});

// Parser JSON per tutte le altre route
app.use(express.json());

// ========= API STATO UTENTE =========
app.get('/api/me', verifyToken, async (req, res) => {
  try {
    const u = await User.findById(req.user.id).select('email premium premiumType premiumUntil freeGenerationsUsed');
    if (!u) return res.status(404).json({ success: false, errore: 'Utente non trovato' });

    const FREE_LIMIT = 2;
    const used = u.freeGenerationsUsed || 0;
    const left = u.premium ? null : Math.max(0, FREE_LIMIT - used);

    res.json({ success: true, me: u, freeGenerationsLeft: left });
  } catch (e) {
    console.error('❌ /api/me error:', e.message);
    res.status(500).json({ success: false, errore: 'Errore stato utente' });
  }
});

// ========= AUTOCOMPLETE: SOLO SERIE A 2025/26 =========
app.get('/api/search-player', softVerify, async (req, res) => {
  const q = req.query.query?.trim();
  const roleKey = String(req.query.role || '').toLowerCase(); // portieri|difensori|centrocampisti|attaccanti
  const roleWanted = roleHintMap[roleKey] || null;

  if (!q || q.length < 2) return res.json({ success: true, players: [] });

  const cacheKey = `${q}|${roleWanted || 'all'}|${LEAGUE}|${SEASON}`;
  const cached = getCached(cacheKey);
  if (cached) return res.json({ success: true, players: cached });

  try {
    // (1) Serie A + stagione (PRINCIPALE)
    let r = await axios.get('https://api-football-v1.p.rapidapi.com/v3/players', {
      headers: {
        'x-rapidapi-key': API_FOOTBALL_KEY,
        'x-rapidapi-host': 'api-football-v1.p.rapidapi.com'
      },
      params: { search: q, league: LEAGUE, season: SEASON }
    });
    let items = Array.isArray(r?.data?.response) ? r.data.response : [];

    // (2) Se vuoto, riprova SOLO Serie A SENZA season
    if (!items.length) {
      r = await axios.get('https://api-football-v1.p.rapidapi.com/v3/players', {
        headers: {
          'x-rapidapi-key': API_FOOTBALL_KEY,
          'x-rapidapi-host': 'api-football-v1.p.rapidapi.com'
        },
        params: { search: q, league: LEAGUE }
      });
      items = Array.isArray(r?.data?.response) ? r.data.response : [];
    }

    // Mappatura
    let players = items.map(item => {
      const latest = pickLatestStat(item?.statistics);
      const ruolo = normalizeRole(latest?.games?.position || '');
      return {
        id: item?.player?.id,
        nome: item?.player?.name || '',
        ruolo,
        squadra: latest?.team?.name || ''
      };
    }).filter(p => p.nome);

    // De-dup per nome
    players = players.filter((p, i, arr) =>
      i === arr.findIndex(t => (t.nome || '').toLowerCase() === p.nome.toLowerCase())
    );

    // Filtro ruolo “gentile”
    if (roleWanted) {
      const filtered = players.filter(p => p.ruolo === roleWanted);
      if (filtered.length) players = filtered;
    }

    // Fallback locale
    if (!players.length) {
      const fb = LOCAL_FALLBACK_PLAYERS.filter(p =>
        p.nome.toLowerCase().includes(q.toLowerCase()) &&
        (!roleWanted || p.ruolo === roleWanted)
      );
      setCached(cacheKey, fb);
      return res.json({ success: true, players: fb, note: 'fallback' });
    }

    setCached(cacheKey, players);
    res.json({ success: true, players });
  } catch (err) {
    console.error('❌ /api/search-player ERROR:', err?.response?.status, err?.message);
    const fb = LOCAL_FALLBACK_PLAYERS.filter(p =>
      p.nome.toLowerCase().includes((q || '').toLowerCase()) &&
      (!roleWanted || p.ruolo === roleWanted)
    );
    return res.json({ success: true, players: fb, note: 'fallback-error' });
  }
});

// ========= ROSE =========
app.post('/api/rosa/save', verifyToken, async (req, res) => {
  try {
    const { nomeSquadra, modulo, titolari, panchina, portieri, difensori, centrocampisti, attaccanti } = req.body;
    if (!nomeSquadra?.trim()) return res.status(400).json({ success: false, errore: 'Nome squadra obbligatorio.' });

    let rosa = await Rosa.findOne({ userId: req.user.id, nomeSquadra: nomeSquadra.trim() });
    if (!rosa) rosa = new Rosa({ userId: req.user.id, nomeSquadra: nomeSquadra.trim() });

    const onlyNames = arr => (arr || []).map(g => (typeof g === 'string' ? g : (g?.nome || ''))).filter(Boolean);

    rosa.modulo = modulo ?? rosa.modulo;
    rosa.titolari = onlyNames(titolari);
    rosa.panchina = onlyNames(panchina);
    rosa.portieri = onlyNames(portieri);
    rosa.difensori = onlyNames(difensori);
    rosa.centrocampisti = onlyNames(centrocampisti);
    rosa.attaccanti = onlyNames(attaccanti);

    await rosa.save();
    res.json({ success: true, rosa });
  } catch (err) {
    console.error('❌ Errore salvataggio rosa:', err.message);
    res.status(500).json({ success: false, errore: 'Errore salvataggio rosa.' });
  }
});

app.get('/api/rosa/all', verifyToken, async (req, res) => {
  const rose = await Rosa.find({ userId: req.user.id }).sort({ updatedAt: -1 });
  res.json({ success: true, rose });
});

app.get('/api/rosa/me', verifyToken, async (req, res) => {
  const nomeRosa = req.query.nomeRosa?.trim();
  if (!nomeRosa) return res.status(400).json({ success: false, errore: 'Nome rosa mancante.' });

  try {
    const rosa = await Rosa.findOne({
      userId: req.user.id,
      nomeSquadra: { $regex: new RegExp(`^${nomeRosa}$`, 'i') }
    });

    if (!rosa) return res.status(404).json({ success: false, errore: 'Rosa non trovata.' });
    res.json({ success: true, rosa });
  } catch (err) {
    console.error('❌ Errore caricamento rosa:', err.message);
    res.status(500).json({ success: false, errore: 'Errore caricamento rosa.' });
  }
});

// ========= AI: GENERAZIONE FORMAZIONE (ESCLUDE INFORTUNATI/SQUALIFICATI) =========
function scoreByRole(role, s = {}) {
  const rating = s?.games?.rating ? parseFloat(s.games.rating) : 0;
  const goals = s?.goals?.total || 0;
  const assists = s?.goals?.assists || 0;
  const shots = s?.shots?.total || 0;
  const keyPasses = s?.passes?.key || 0;
  const conceded = s?.goals?.conceded || 0;
  const cleanSheet = conceded === 0 ? 1 : 0;

  if (role === 'Goalkeeper') return rating * 10 + cleanSheet * 3 - conceded * 0.2;
  if (role === 'Defender')    return rating * 10 + cleanSheet * 2 + goals * 4 + assists * 3;
  if (role === 'Midfielder')  return rating * 10 + goals * 5 + assists * 4 + keyPasses * 0.5;
  return rating * 10 + goals * 6 + assists * 3 + shots * 0.2; // Attacker/Unknown
}

async function fetchOnePlayerSerieA(name) {
  const pickBest = (arr) => {
    if (!Array.isArray(arr) || !arr.length) return null;
    const exact = arr.find(x => String(x?.player?.name || '').toLowerCase() === name.toLowerCase());
    return exact || arr[0];
  };

  try {
    // SOLO SERIE A 2025, poi fallback SERIE A senza season
    let r = await axios.get('https://api-football-v1.p.rapidapi.com/v3/players', {
      headers: { 'x-rapidapi-key': API_FOOTBALL_KEY, 'x-rapidapi-host': 'api-football-v1.p.rapidapi.com' },
      params: { search: name, league: LEAGUE, season: SEASON }
    });
    let item = pickBest(r?.data?.response);

    if (!item) {
      r = await axios.get('https://api-football-v1.p.rapidapi.com/v3/players', {
        headers: { 'x-rapidapi-key': API_FOOTBALL_KEY, 'x-rapidapi-host': 'api-football-v1.p.rapidapi.com' },
        params: { search: name, league: LEAGUE }
      });
      item = pickBest(r?.data?.response);
    }

    if (!item) return { id: null, nome: name, role: 'Unknown', score: 0 };

    const stats = Array.isArray(item?.statistics) ? item.statistics : [];
    const latest = pickLatestStat(stats) || {};
    const role = normalizeRole(latest?.games?.position || '');
    const score = scoreByRole(role, latest || {});
    return { id: item?.player?.id || null, nome: item?.player?.name || name, role, score };
  } catch {
    return { id: null, nome: name, role: 'Unknown', score: 0 };
  }
}

// Controllo indisponibilità (infortuni + squalifiche) SOLO SERIE A
async function getUnavailablePlayerIds(playerIds) {
  const unavailable = new Set();
  const ids = Array.from(new Set((playerIds || []).filter(Boolean)));
  const CHUNK = 20;

  const callInjuries = async (chunk) => {
    const results = await Promise.all(chunk.map(id =>
      axios.get('https://api-football-v1.p.rapidapi.com/v3/injuries', {
        headers: { 'x-rapidapi-key': API_FOOTBALL_KEY, 'x-rapidapi-host': 'api-football-v1.p.rapidapi.com' },
        params: { player: id, season: SEASON, league: LEAGUE }
      }).catch(() => ({ data: { response: [] } }))
    ));
    results.forEach(r => {
      const resp = r?.data?.response || [];
      if (resp.length) {
        const pid = resp[0]?.player?.id;
        if (pid) unavailable.add(pid);
      }
    });
  };

  const callSidelined = async (chunk) => {
    const results = await Promise.all(chunk.map(id =>
      axios.get('https://api-football-v1.p.rapidapi.com/v3/sidelined', {
        headers: { 'x-rapidapi-key': API_FOOTBALL_KEY, 'x-rapidapi-host': 'api-football-v1.p.rapidapi.com' },
        params: { player: id }
      }).catch(() => ({ data: { response: [] } }))
    ));
    results.forEach(r => {
      const resp = r?.data?.response || [];
      if (resp.length) {
        const pid = resp[0]?.player?.id;
        if (pid) unavailable.add(pid);
      }
    });
  };

  for (let i = 0; i < ids.length; i += CHUNK) {
    const chunk = ids.slice(i, i + CHUNK);
    await Promise.all([callInjuries(chunk), callSidelined(chunk)]);
  }

  return unavailable;
}

function chooseBestModule(pools, candidates) {
  let best = { modulo: '4-3-3', score: -Infinity, selection: [] };
  for (const c of candidates) {
    const need = c.need;
    const chosen = [];
    let total = 0;
    const POR = pools.POR.slice(0, need.POR);
    const DIF = pools.DIF.slice(0, need.DIF);
    const CEN = pools.CEN.slice(0, need.CEN);
    const ATT = pools.ATT.slice(0, need.ATT);
    [POR, DIF, CEN, ATT].forEach(group => group.forEach(x => { chosen.push(x); total += x.score; }));

    const used = new Set(chosen.map(x => x.nome));
    const remaining = [...pools.POR, ...pools.DIF, ...pools.CEN, ...pools.ATT, ...pools.UNKNOWN]
      .filter(x => !used.has(x.nome))
      .sort((a, b) => b.score - a.score);

    while (chosen.length < 11 && remaining.length) {
      const x = remaining.shift();
      chosen.push(x);
      total += x.score;
    }

    if (chosen.length === 11 && total > best.score) {
      best = { modulo: c.modulo, score: total, selection: chosen.map(x => x.nome) };
    }
  }
  if (best.selection.length < 11) {
    const top11 = [...pools.POR, ...pools.DIF, ...pools.CEN, ...pools.ATT, ...pools.UNKNOWN]
      .sort((a, b) => b.score - a.score)
      .slice(0, 11)
      .map(x => x.nome);
    return { modulo: '4-3-3', selection: top11 };
  }
  return best;
}

// ========= FREE TRIAL MIDDLEWARE (max 2 generazioni non-premium) =========
async function canGenerate(req, res, next) {
  try {
    const u = await User.findById(req.user.id).select('premium premiumType premiumUntil freeGenerationsUsed');
    if (!u) return res.status(404).json({ success: false, errore: 'Utente non trovato' });

    // Se premium attivo passa
    if (u.premium) return next();

    // Failsafe: premium mensile scaduto -> spegni flag
    if (u.premiumType === 'monthly' && u.premiumUntil && u.premiumUntil < new Date()) {
      await User.findByIdAndUpdate(u._id, { premium: false, premiumType: 'none', premiumUntil: null });
    }

    const FREE_LIMIT = 2;
    const used = u.freeGenerationsUsed || 0;

    if (used >= FREE_LIMIT) {
      return res.status(402).json({
        success: false,
        errore: 'FREE_LIMIT_REACHED',
        message: 'Hai esaurito le generazioni gratuite. Passa al Premium per continuare.',
        redirect: '/premium'
      });
    }

    // Passa e memorizza per incremento successivo
    req._trialUser = u;
    req._freeUsed = used;
    req._freeLimit = FREE_LIMIT;
    next();
  } catch (e) {
    console.error('❌ canGenerate error:', e.message);
    res.status(500).json({ success: false, errore: 'Errore permessi generazione.' });
  }
}

// ========= GENERAZIONE FORMAZIONE =========
app.post('/api/rosa/formazione/genera/:id', verifyToken, canGenerate, async (req, res) => {
  try {
    const rosa = await Rosa.findOne({ _id: req.params.id, userId: req.user.id });
    if (!rosa) return res.status(404).json({ success: false, errore: 'Rosa non trovata.' });

    const hints = new Map();
    (rosa.portieri || []).forEach(n => hints.set(String(n).toLowerCase(), 'Goalkeeper'));
    (rosa.difensori || []).forEach(n => hints.set(String(n).toLowerCase(), 'Defender'));
    (rosa.centrocampisti || []).forEach(n => hints.set(String(n).toLowerCase(), 'Midfielder'));
    (rosa.attaccanti || []).forEach(n => hints.set(String(n).toLowerCase(), 'Attacker'));

    const nomi = [
      ...(rosa.portieri || []),
      ...(rosa.difensori || []),
      ...(rosa.centrocampisti || []),
      ...(rosa.attaccanti || []),
      ...(rosa.titolari || []),
      ...(rosa.panchina || []),
    ].map(n => (typeof n === 'string' ? n : '')).filter(Boolean);

    const uniq = Array.from(new Set(nomi));
    if (!uniq.length) return res.status(400).json({ success: false, errore: 'La rosa non contiene giocatori.' });

    // 1) Fetch player data SOLO SERIE A
    let scored = await Promise.all(uniq.map(fetchOnePlayerSerieA));

    // 2) Escludi indisponibili (infortuni/squalifiche)
    const idList = scored.map(x => x.id).filter(Boolean);
    const unavailableIds = await getUnavailablePlayerIds(idList);
    scored = scored.map(x => unavailableIds.has(x.id) ? { ...x, score: -Infinity, unavailable: true } : x);

    // 3) Applica hint se Unknown
    scored = scored.map(x => {
      if (x.role === 'Unknown') {
        const h = hints.get(x.nome.toLowerCase());
        if (h) return { ...x, role: h };
      }
      return x;
    });

    const pools = {
      POR: scored.filter(x => x.role === 'Goalkeeper').sort((a, b) => b.score - a.score),
      DIF: scored.filter(x => x.role === 'Defender').sort((a, b) => b.score - a.score),
      CEN: scored.filter(x => x.role === 'Midfielder').sort((a, b) => b.score - a.score),
      ATT: scored.filter(x => x.role === 'Attacker').sort((a, b) => b.score - a.score),
      UNKNOWN: scored.filter(x => x.role === 'Unknown').sort((a, b) => b.score - a.score),
    };

    const candidates = [
      { modulo: '4-3-3', need: { POR: 1, DIF: 4, CEN: 3, ATT: 3 } },
      { modulo: '4-4-2', need: { POR: 1, DIF: 4, CEN: 4, ATT: 2 } },
      { modulo: '3-5-2', need: { POR: 1, DIF: 3, CEN: 5, ATT: 2 } },
      { modulo: '3-4-3', need: { POR: 1, DIF: 3, CEN: 4, ATT: 3 } },
    ];

    const best = chooseBestModule(pools, candidates);
    const titolari = best.selection.slice(0, 11);
    const used = new Set(titolari);
    const panchina = scored
      .filter(x => !used.has(x.nome))
      .sort((a, b) => b.score - a.score)
      .map(x => x.nome + (x.unavailable ? ' (out)' : ''));

    rosa.modulo = best.modulo;
    rosa.titolari = titolari;
    rosa.panchina = panchina;
    await rosa.save();

    // Incrementa l'uso del free trial se NON premium
    try {
      if (!req._trialUser?.premium) {
        await User.findByIdAndUpdate(req._trialUser._id, { $inc: { freeGenerationsUsed: 1 } });
      }
    } catch (e) {
      console.error('⚠️ impossibile incrementare freeGenerationsUsed:', e.message);
    }

    const left = req._trialUser?.premium
      ? null
      : Math.max(0, (req._freeLimit || 2) - ((req._freeUsed || 0) + 1));

    return res.json({
      success: true,
      modulo: best.modulo,
      titolari,
      panchina,
      note: unavailableIds.size ? 'Esclusi indisponibili (infortunio/squalifica).' : undefined,
      freeGenerationsLeft: left
    });
  } catch (err) {
    console.error('❌ Errore generazione formazione:', err.message);
    res.status(500).json({ success: false, errore: 'Errore interno AI.' });
  }
});

// ========= STRIPE CHECKOUT PREMIUM =========

// Lifetime (una tantum 4,99 €)
app.post('/api/checkout/lifetime', verifyToken, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'payment',
      line_items: [
        {
          price: process.env.STRIPE_PRICE_LIFETIME, // ID prezzo da Stripe Dashboard (price_...)
          quantity: 1,
        },
      ],
      success_url: `${FRONTEND_URL}/premium-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/premium`,
      metadata: { userId: req.user.id },
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('❌ Errore checkout lifetime:', err.message);
    res.status(500).json({ error: 'Errore creazione checkout.' });
  }
});

// Mensile (abbonamento 1,99 €/mese)
app.post('/api/checkout/monthly', verifyToken, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [
        {
          price: process.env.STRIPE_PRICE_MONTHLY, // ID prezzo mensile (price_...)
          quantity: 1,
        },
      ],
      success_url: `${FRONTEND_URL}/premium-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${FRONTEND_URL}/premium`,
      metadata: { userId: req.user.id },
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('❌ Errore checkout monthly:', err.message);
    res.status(500).json({ error: 'Errore creazione checkout.' });
  }
});

// ========= START =========
app.listen(PORT, () => {
  console.log(`🚀 Server avviato su http://localhost:${PORT} — Serie A ${SEASON}/${SEASON+1}`);
});
