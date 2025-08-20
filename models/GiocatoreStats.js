// backend/models/GiocatoreStats.js
const mongoose = require('mongoose')

const giocatoreStatsSchema = new mongoose.Schema({
  nome: String,
  ruolo: String,
  dataAggiornamento: String,
  stats: Object
})

// Evita OverwriteModelError
module.exports = mongoose.models.GiocatoreStats || mongoose.model('GiocatoreStats', giocatoreStatsSchema)
