// routes/team.js
import express from "express";
import Team from "../models/Team.js";
import { requireAuth } from "../auth.js";
const router = express.Router();

// Crea nuova rosa (BASE: max 1)
router.post("/teams", requireAuth, async (req, res) => {
  const { name, players } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: "TEAM_NAME_REQUIRED" });
  if (!Array.isArray(players) || players.length === 0) {
    return res.status(400).json({ error: "PLAYERS_REQUIRED" });
  }
  const count = await Team.countDocuments({ userId: req.user.id });
  if (!req.user.isPremium && count >= 1) {
    return res.status(403).json({ error: "TEAM_LIMIT_REACHED" });
  }
  const team = await Team.create({ userId: req.user.id, name: name.trim(), players });
  res.json({ team });
});

// Aggiorna rosa esistente (sempre consentito al proprietario)
router.put("/teams/:id", requireAuth, async (req, res) => {
  const team = await Team.findOne({ _id: req.params.id, userId: req.user.id });
  if (!team) return res.status(404).json({ error: "NOT_FOUND" });
  const { name, players } = req.body;
  if (typeof name === "string") team.name = name.trim();
  if (Array.isArray(players)) team.players = players;
  await team.save();
  res.json({ team });
});

// Lista rose dell'utente (per sapere se ha già la sua rosa)
router.get("/teams", requireAuth, async (req, res) => {
  const teams = await Team.find({ userId: req.user.id }).sort("-updatedAt");
  res.json({ teams });
});

export default router;
