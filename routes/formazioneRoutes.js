const express = require('express');
const router = express.Router();
const axios = require('axios');
const verifyToken = require('../middleware/verifyToken');
const Rosa = require('../models/Rosa');
const GiocatoreStats = require('../models/GiocatoreStats');

const API_FOOTBALL_KEY = process.env.API_FOOTBALL_KEY;

// ---- Helpers -------------------------------------------------
const roleMap = { POR: 'Goalkeeper', DIF: 'Defender', CEN: 'Midfielder', ATT: 'Attacker' };
const CACHING_DAYS = 7;

function daysDiff(iso) {
  if (!iso) return Infinity;
  const d = (Date.now() - new Date(iso).getTime()) / (1000 * 60 * 60 * 24);
  return Math.abs(d);
}

function safe(v, def = 0) {
  if (v === null || v === undefined || v === '' || Number.isNaN(v)) return def;
  const n = Number(v);
  return Number.isNaN(n) ? def : n;
}

// Scoring per ruolo (semplice ma efficace con rating/goals/assists ecc.)
function scorePlayer(role, s) {
  const rating = safe(s.rating, 0); // API-Football rating è stringa tipo "6.9"
  const goals = safe(s.goals?.total);
  const assists = safe(s.goals?.assists);
  const shots = safe(s.shots?.total);
  const keyPasses = safe(s.passes?.key);
  const cleanSheets = safe(s.goals?.conceded) === 0 ? 1 : safe(s.clean_sheets || s.goals?.conceded === 0 ? 1 : 0); // fallback
  const conceded = safe(s.goals?.conceded);

  if (role === 'POR') {
    return rating * 10 + cleanSheets * 3 - conceded * 0.2;
  }
  if (role === 'DIF') {
    return rating * 10 + cleanSheets * 2 + goals * 4 + assists * 3;
  }
  if (role === 'CEN') {
    return rating * 10 + goals * 5 + assists * 4 + keyPasses * 0.5;
  }
  // ATT
  return rating * 10 + goals * 6 + assists * 3 + shots * 0.2;
}

// Estrae lo “stats blob” dalla risposta API-Football
function extractStats(apiItem) {
  const st = apiItem?.statistics?.[0];
  return {
    rating: safe(st?.games?.rating),
    goals: { total: safe(st?.goals?.total), assists: safe(st?.goals?.assists) },
    shots: { total: safe(st?.shots?.total) },
    passes: { key: safe(st?.passes?.key) },
    clean_sheets: safe(st?.goals?.conceded) === 0 ? 1 : 0,
    goals: { conceded: safe(st?.goals?.conceded) }
  };
}

// Recupera/cacha stats per giocatore
async function getPlayerStats(nome, ruolo) {
  // 1) cache DB
  const cached = await GiocatoreStats.findOne({ nome, ruolo });
  if (cached && daysDiff(cached.dataAggiornamento) <= CACHING_DAYS) {
    return cached.stats;
  }

  // 2) API call
  const resp = await axios.get('https://api-football-v1.p.rapidapi.com/v3/players', {
    headers: {
      'x-rapidapi-key': API_FOOTBALL_KEY,
      'x-rapidapi-host': 'api-football-v1.p.rapidapi.com',
    },
    params: { search: nome, league: 135, season: 2024 }
  });

  // match per ruolo
  const items = resp.data?.response || [];
  const desired = items.find(p => p?.statistics?.[0]?.games?.position === roleMap[ruolo]) || items[0];
  if (!desired) return {};

  const stats = extractStats(desired);

  // 3) salva cache
  await GiocatoreStats.findOneAndUpdate(
    { nome, ruolo },
    { nome, ruolo, dataAggiornamento: new Date().toISOString(), stats },
    { upsert: true }
  );

  return stats;
}

// Prova moduli e sceglie il migliore
function pickBestModule(scored) {
  // scored = { POR:[{n,score}], DIF:[...], CEN:[...], ATT:[...] }
  const candidates = [
    { modulo: '4-3-3', need: { POR:1, DIF:4, CEN:3, ATT:3 } },
    { modulo: '4-4-2', need: { POR:1, DIF:4, CEN:4, ATT:2 } },
    { modulo: '3-5-2', need: { POR:1, DIF:3, CEN:5, ATT:2 } },
  ];

  let best = { modulo: '4-3-3', total: -Infinity };
  for (const c of candidates) {
    const sum =
      scored.POR.slice(0, c.need.POR).reduce((a, x) => a + x.score, 0) +
      scored.DIF.slice(0, c.need.DIF).reduce((a, x) => a + x.score, 0) +
      scored.CEN.slice(0, c.need.CEN).reduce((a, x) => a + x.score, 0) +
      scored.ATT.slice(0, c.need.ATT).reduce((a, x) => a + x.score, 0);
    if (sum > best.total) best = { modulo: c.modulo, total: sum, need: c.need };
  }
  return best;
}
// ---------------------------------------------------------------

// POST /api/formazione/genera  { rosaId }
router.post('/genera', verifyToken, async (req, res) => {
  try {
    const { rosaId } = req.body;
    if (!rosaId) return res.status(400).json({ success: false, errore: 'rosaId mancante.' });

    const rosa = await Rosa.findOne({ _id: rosaId, userId: req.user.id });
    if (!rosa) return res.status(404).json({ success: false, errore: 'Rosa non trovata.' });

    const gruppi = {
      POR: rosa.portieri || [],
      DIF: rosa.difensori || [],
      CEN: rosa.centrocampisti || [],
      ATT: rosa.attaccanti || []
    };

    // prendi stats per tutti (in parallelo) e calcola score
    const scored = { POR: [], DIF: [], CEN: [], ATT: [] };

    for (const ruolo of ['POR', 'DIF', 'CEN', 'ATT']) {
      const arr = gruppi[ruolo];
      const statsArr = await Promise.all(
        arr.map(async g => {
          const stats = await getPlayerStats(g.nome, ruolo);
          const sc = scorePlayer(ruolo, stats);
          return { nome: g.nome, ruolo, score: sc };
        })
      );
      // ordina per punteggio decrescente
      scored[ruolo] = statsArr.sort((a, b) => b.score - a.score);
    }

    // scegli miglior modulo
    const best = pickBestModule(scored);

    // compone titolari
    const titolari = [
      ...scored.POR.slice(0, best.need.POR),
      ...scored.DIF.slice(0, best.need.DIF),
      ...scored.CEN.slice(0, best.need.CEN),
      ...scored.ATT.slice(0, best.need.ATT)
    ];

    // panchina = tutti i restanti ordinati per score
    const rest = [
      ...scored.POR.slice(best.need.POR),
      ...scored.DIF.slice(best.need.DIF),
      ...scored.CEN.slice(best.need.CEN),
      ...scored.ATT.slice(best.need.ATT)
    ].sort((a, b) => b.score - a.score);

    res.json({
      success: true,
      modulo: best.modulo,
      formazione: titolari.map(x => x.nome),
      panchina: rest.map(x => x.nome)
    });
  } catch (err) {
    console.error('❌ Errore generazione formazione:', err?.response?.data || err.message);
    res.status(500).json({ success: false, errore: 'Errore nella generazione formazione.' });
  }
});

module.exports = router;
