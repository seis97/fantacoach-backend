const mongoose = require('mongoose');
const rosaSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  nomeSquadra: { type: String, required: true },
  portieri: [{ nome: String, ruolo: String }],
  difensori: [{ nome: String, ruolo: String }],
  centrocampisti: [{ nome: String, ruolo: String }],
  attaccanti: [{ nome: String, ruolo: String }]
}, { timestamps: true });

module.exports = mongoose.models.Rosa || mongoose.model('Rosa', rosaSchema);
