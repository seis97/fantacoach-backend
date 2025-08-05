// models/GiocatoreStats.js
const mongoose = require('mongoose');

const giocatoreStatsSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  ruolo: { type: String, required: true },
  dataAggiornamento: { type: String, required: true }, // YYYY-MM-DD
  stats: { type: Object, default: {} }
});

// indice per agevolare le query
giocatoreStatsSchema.index({ nome: 1, dataAggiornamento: 1 }, { unique: true });

module.exports = mongoose.model('GiocatoreStats', giocatoreStatsSchema);
