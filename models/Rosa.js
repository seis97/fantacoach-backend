const mongoose = require('mongoose');

const rosaSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  nomeSquadra: { type: String, required: true },
  modulo: { type: String, default: '4-3-3' },
  titolari: [String],
  panchina: [String]
}, { timestamps: true });

rosaSchema.index({ userId: 1, nomeSquadra: 1 }, { unique: true }); // nome squadra unico per utente

module.exports = mongoose.model('Rosa', rosaSchema);
