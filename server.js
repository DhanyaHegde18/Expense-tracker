// ===== Spending Navigator Backend (Single File) =====
require("dotenv").config();
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

// --- CONFIG ---
const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecret";
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error(" Missing MONGO_URI. Create a .env file (see .env.example) with your MongoDB Atlas connection string.");
  process.exit(1);
}

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname))); // serves index.html at "/"

// --- CONNECT DB ---
mongoose.connect(MONGO_URI)
  .then(()=> console.log(" MongoDB connected"))
  .catch(err=> console.error(" MongoDB error:", err));

// --- MODELS ---
const User = mongoose.model("User", new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true },
  password: String, // hashed
  budget: { type: Number, default: 0 }
}));

const Expense = mongoose.model("Expense", new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  category: String,
  amount: Number,
  date: Date,
  note: String
}));

// --- AUTH MIDDLEWARE ---
function auth(req,res,next){
  const token = req.header("x-auth-token");
  if(!token) return res.status(401).json({ msg:"No token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded.id;
    next();
  } catch(err){ res.status(401).json({ msg:"Invalid token" }); }
}

// --- ROUTES ---

// REGISTER
app.post("/api/auth/register", async (req,res)=>{
  try {
    const { firstName, lastName, email, password } = req.body;
    const existing = await User.findOne({ email });
    if(existing) return res.status(400).json({ msg:"User exists" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, email, password: hash });
    await user.save();
    res.json({ msg:"Registered successfully" });
  } catch(err){ res.status(500).json({ msg: err.message }); }
});

// LOGIN
app.post("/api/auth/login", async (req,res)=>{
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if(!user) return res.status(400).json({ msg:"Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if(!match) return res.status(400).json({ msg:"Invalid credentials" });

    const token = jwt.sign({ id:user._id }, JWT_SECRET, { expiresIn:"7d" });
    res.json({ 
      token, 
      user:{ id:user._id, firstName:user.firstName, email:user.email, budget:user.budget } 
    });
  } catch(err){ res.status(500).json({ msg: err.message }); }
});

// GET CURRENT USER (used to restore session on page reload)
app.get("/api/me", auth, async (req,res)=>{
  try {
    const user = await User.findById(req.user);
    if(!user) return res.status(404).json({ msg:"User not found" });
    res.json({ id:user._id, firstName:user.firstName, email:user.email, budget:user.budget });
  } catch(err){ res.status(500).json({ msg: err.message }); }
});

// SET BUDGET
app.post("/api/budget", auth, async (req,res)=>{
  try {
    const { budget } = req.body;
    const user = await User.findById(req.user);
    if(!user) return res.status(404).json({ msg:"User not found" });
    user.budget = budget;
    await user.save();
    res.json({ msg:"Budget updated", budget:user.budget });
  } catch(err){ res.status(500).json({ msg: err.message }); }
});

// ADD EXPENSE
app.post("/api/expenses", auth, async (req,res)=>{
  try {
    const { category, amount, date, note } = req.body;
    const exp = new Expense({ user:req.user, category, amount, date, note });
    await exp.save();
    res.json(exp);
  } catch(err){ res.status(500).json({ msg: err.message }); }
});

// GET EXPENSES
app.get("/api/expenses", auth, async (req,res)=>{
  try {
    const list = await Expense.find({ user:req.user }).sort({ date:-1 });
    res.json(list);
  } catch(err){ res.status(500).json({ msg: err.message }); }
});

// ANALYTICS
app.get("/api/analytics", auth, async (req,res)=>{
  try {
    const user = await User.findById(req.user);
    const expenses = await Expense.find({ user:req.user });

    const total = expenses.reduce((s,e)=>s+e.amount,0);
    const byCategory = {};
    expenses.forEach(e=>{
      byCategory[e.category] = (byCategory[e.category]||0) + e.amount;
    });

    res.json({
      budget: user.budget,
      totalSpent: total,
      remaining: Math.max(0, user.budget - total),
      byCategory
    });
  } catch(err){ res.status(500).json({ msg: err.message }); }
});

// --- START SERVER ---
app.listen(PORT, ()=> console.log(`Server running on http://localhost:${PORT}`));