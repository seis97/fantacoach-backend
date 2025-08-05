import express from "express";
import Rosa from "../models/Rosa.js";

const router = express.Router();

// Salva o aggiorna la rosa
router.post("/save", async (req, res) => {
  const { userId, nomeSquadra, modulo, titolari, panchina } = req.body;

  try {
    const existing = await Rosa.findOne({ userId });

    if (existing) {
      existing.nomeSquadra = nomeSquadra;
      existing.modulo = modulo;
      existing.titolari = titolari;
      existing.panchina = panchina;
      await existing.save();
      return res.json({ success: true, message: "Rosa aggiornata" });
    }

    await Rosa.create({ userId, nomeSquadra, modulo, titolari, panchina });
    res.json({ success: true, message: "Rosa salvata" });

  } catch (error) {
    res.status(500).json({ success: false, message: "Errore salvataggio", error });
  }
});

// Recupera rosa
router.get("/:userId", async (req, res) => {
  try {
    const rosa = await Rosa.findOne({ userId: req.params.userId });
    if (!rosa) return res.status(404).json({ success: false, message: "Rosa non trovata" });
    res.json({ success: true, rosa });
  } catch (err) {
    res.status(500).json({ success: false, message: "Errore recupero", error: err });
  }
});

export default router;
