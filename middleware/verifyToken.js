// backend/middleware/verifyToken.js
const jwt = require('jsonwebtoken');
const User = require('../models/User'); // assicurati che esista
const SECRET_KEY = process.env.SECRET_KEY;

module.exports = async function verifyToken(req, res, next) {
  try {
    const bearerHeader = req.headers['authorization'];
    if (!bearerHeader) return res.status(403).json({ errore: 'Token mancante.' });

    const token = bearerHeader.split(' ')[1];
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded || {};

    // Se il token non contiene id, lo recupero dal DB con l'email
    if (!req.user.id && req.user.email) {
      const u = await User.findOne({ email: req.user.email }).select('_id email');
      if (!u) return res.status(401).json({ errore: 'Utente non trovato.' });
      req.user.id = u._id.toString();
    }

    if (!req.user.id) return res.status(401).json({ errore: 'Token non valido (manca id utente).' });

    next();
  } catch (err) {
    return res.status(401).json({ errore: 'Token non valido.' });
  }
};
