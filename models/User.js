const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  premium: { type: Boolean, default: false },
  freeUsages: { type: Number, default: 4 }
});

// ✅ Evita OverwriteModelError in sviluppo
module.exports = mongoose.models.User || mongoose.model('User', userSchema);
