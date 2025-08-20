// backend/routes/rosaRoutes.js
const express = require('express');
const router = express.Router();
const verifyToken = require('../middleware/verifyToken');
const axios = require('axios');
const Rosa = require('../models/Rosa');

const API_FOOTBALL_KEY = process.env.API_FOOTBALL_KEY;

// 📌 Genera formazione AI in base alle statistiche
router.post('/formazione/genera/:id', verifyToken, async (req, res) => {
  try {
    const rosa = await Rosa.findOne({ _id: req.params.id, userId: req.user.id });
    if (!rosa) return res.status(404).json({ success: false, errore: 'Rosa non trovata' });

    const giocatori = [
      ...rosa.portieri,
      ...rosa.difensori,
      ...rosa.centrocampisti,
      ...rosa.attaccanti
    ];

    // 📡 Recupera statistiche da API-Football
    const statsPromises = giocatori.map(async nome => {
      try {
        const resp = await axios.get('https://api-football-v1.p.rapidapi.com/v3/players', {
          headers: {
            'x-rapidapi-key': API_FOOTBALL_KEY,
            'x-rapidapi-host': 'api-football-v1.p.rapidapi.com'
          },
          params: {
            search: nome,
            league: 135,
            season: 2024
          }
        });

        if (resp.data.response.length > 0) {
          const player = resp.data.response[0];
          const stats = player.statistics[0];
          return {
            nome: player.player.name,
            ruolo: stats.games.position,
            rating: stats.games.rating ? parseFloat(stats.games.rating) : 0
          };
        }
        return null;
      } catch (err) {
        console.error(`Errore recupero stats per ${nome}:`, err.message);
        return null;
      }
    });

    const statsGiocatori = (await Promise.all(statsPromises)).filter(Boolean);

    // 📊 Calcolo modulo migliore
    const countRoles = {
      Attacker: statsGiocatori.filter(g => g.ruolo === 'Attacker').length,
      Midfielder: statsGiocatori.filter(g => g.ruolo === 'Midfielder').length,
      Defender: statsGiocatori.filter(g => g.ruolo === 'Defender').length
    };

    let modulo;
    if (countRoles.Attacker >= 3) modulo = '4-3-3';
    else if (countRoles.Midfielder >= 4) modulo = '4-4-2';
    else modulo = '3-5-2';

    // 📌 Ordina per rating e scegli titolari
    const titolari = [];
    const panchina = [];

    const portieri = statsGiocatori.filter(g => g.ruolo === 'Goalkeeper').sort((a, b) => b.rating - a.rating);
    if (portieri.length > 0) titolari.push(portieri[0].nome);
    panchina.push(...portieri.slice(1).map(p => p.nome));

    const difensori = statsGiocatori.filter(g => g.ruolo === 'Defender').sort((a, b) => b.rating - a.rating);
    titolari.push(...difensori.slice(0, parseInt(modulo.split('-')[0])).map(p => p.nome));
    panchina.push(...difensori.slice(parseInt(modulo.split('-')[0])).map(p => p.nome));

    const centrocampisti = statsGiocatori.filter(g => g.ruolo === 'Midfielder').sort((a, b) => b.rating - a.rating);
    titolari.push(...centrocampisti.slice(0, parseInt(modulo.split('-')[1])).map(p => p.nome));
    panchina.push(...centrocampisti.slice(parseInt(modulo.split('-')[1])).map(p => p.nome));

    const attaccanti = statsGiocatori.filter(g => g.ruolo === 'Attacker').sort((a, b) => b.rating - a.rating);
    titolari.push(...attaccanti.slice(0, parseInt(modulo.split('-')[2])).map(p => p.nome));
    panchina.push(...attaccanti.slice(parseInt(modulo.split('-')[2])).map(p => p.nome));

    // 📌 Salva nella rosa
    rosa.modulo = modulo;
    rosa.titolari = titolari;
    rosa.panchina = panchina;
    await rosa.save();

    res.json({
      success: true,
      modulo,
      formazione: titolari,
      panchina
    });
  } catch (err) {
    console.error('Errore generazione formazione:', err);
    res.status(500).json({ success: false, errore: 'Errore interno AI' });
  }
});
// 📌 Recupera una rosa per nome
router.get('/me', verifyToken, async (req, res) => {
  const nomeRosa = req.query.nomeRosa?.trim();
  if (!nomeRosa) {
    return res.status(400).json({ success: false, errore: 'Nome rosa mancante.' });
  }

  try {
    const rosa = await Rosa.findOne({
      userId: req.user.id,
      nomeSquadra: { $regex: new RegExp(`^${nomeRosa}$`, 'i') }
    });

    if (!rosa) {
      return res.status(404).json({ success: false, errore: 'Rosa non trovata.' });
    }

    res.json({ success: true, rosa });
  } catch (err) {
    console.error('❌ Errore caricamento rosa:', err);
    res.status(500).json({ success: false, errore: 'Errore caricamento rosa.' });
  }
});


module.exports = router;
