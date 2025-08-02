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
const FRONTEND_URL = 'https://fantacoach-frontend.vercel.app'; // <- URL fisso per evitare problemi

// ✅ CORS configurato correttamente
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true,
  methods: ['GET', 'POST'],
  optionsSuccessStatus: 200
}));

app.use(express.json());
app.use(cookieParser());

// 🔗 Connessione MongoDB (senza opzioni deprecate)
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connesso'))
  .catch(err => console.error('❌ Errore MongoDB:', err));

// ... (da qui in poi il tuo codice resta identico)
