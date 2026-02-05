import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { db, run, get, all } from "./db.js";

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 4000;
const JWT_SECRET = "dev_secret_change_me"; // en prod => .env
app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

// --- init tables + seed ---
async function init() {
  await run(`
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      gov TEXT,
      skills TEXT,
      role TEXT NOT NULL DEFAULT 'user'
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS associations(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      slug TEXT NOT NULL UNIQUE,
      name_fr TEXT NOT NULL,
      name_ar TEXT NOT NULL,
      gov TEXT,
      address TEXT,
      phone TEXT,
      email TEXT,
      website TEXT,
      donate_url TEXT,
      img TEXT,
      summary_fr TEXT,
      summary_ar TEXT,
      domains TEXT,   -- JSON string
      needs TEXT,     -- JSON string
      lat REAL,
      lng REAL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS donations(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      association_slug TEXT NOT NULL,
      donor_name TEXT,
      amount REAL NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  // seed admin
  const admin = await get(`SELECT id FROM users WHERE email=?`, ["admin@tuniaid.tn"]);
  if (!admin) {
    const hash = await bcrypt.hash("admin123", 10);
    await run(
      `INSERT INTO users(name,email,password_hash,role,gov,skills) VALUES(?,?,?,?,?,?)`,
      ["Admin", "admin@tuniaid.tn", hash, "admin", "Tunis", "admin"]
    );
  }

  // seed associations if empty (avec coords)
  const c = await get(`SELECT COUNT(*) as n FROM associations`);
  if (c.n === 0) {
    const seeds = [
      {
        slug:"croissant-rouge",
        name_fr:"Croissant-Rouge Tunisien", name_ar:"الهلال الأحمر التونسي",
        gov:"Tunis", address:"Tunis, Tunisie", phone:"+216 71 000 000",
        email:"contact@croissant-rouge.tn", website:"https://croissant-rouge.tn/",
        donate_url:"https://croissant-rouge.tn/",
        domains:["humanitaire","sante"], needs:["secourisme","collecte","volontaires"],
        summary_fr:"Secours, aide humanitaire et volontariat au niveau national.",
        summary_ar:"إغاثة ومساعدات إنسانية وتطوع على المستوى الوطني.",
        img:"https://images.unsplash.com/photo-1488521787991-ed7bbaae773c?auto=format&fit=crop&w=1200&q=80",
        lat:36.8065, lng:10.1815
      },
      {
        slug:"sosve",
        name_fr:"SOS Villages d’Enfants Tunisie", name_ar:"قرى الأطفال س و س تونس",
        gov:"Tunis", address:"Tunis, Tunisie", phone:"+216 71 000 001",
        email:"contact@sosve.tn", website:"https://www.sosve.tn/",
        donate_url:"https://www.sosve.tn/",
        domains:["enfants","education"], needs:["mentorat","soutien_scolaire","volontaires"],
        summary_fr:"Accompagnement des enfants vulnérables et soutien familial.",
        summary_ar:"مرافقة الأطفال في وضعية هشاشة ودعم الأسرة.",
        img:"https://images.unsplash.com/photo-1520975958225-23fd3be3baf7?auto=format&fit=crop&w=1200&q=80",
        lat:36.8065, lng:10.1815
      },
      {
        slug:"atcc",
        name_fr:"ATCC — Lutte Contre le Cancer", name_ar:"الجمعية التونسية لمقاومة السرطان",
        gov:"Tunis", address:"Tunis, Tunisie", phone:"+216 71 000 002",
        email:"contact@atcc.tn", website:"https://atcc.com.tn/",
        donate_url:"https://atcc.com.tn/",
        domains:["sante"], needs:["sensibilisation","accompagnement","benevolat"],
        summary_fr:"Prévention, soutien aux patients, actions de sensibilisation.",
        summary_ar:"وقاية، دعم للمرضى، وحملات توعية.",
        img:"https://images.unsplash.com/photo-1545165533-41b4e0e7932?auto=format&fit=crop&w=1200&q=80",
        lat:36.8065, lng:10.1815
      },
      {
        slug:"amc",
        name_fr:"AMC Tunisie — Malades du Cancer", name_ar:"جمعية مرضى السرطان",
        gov:"Tunis", address:"Tunis, Tunisie", phone:"+216 71 000 003",
        email:"contact@amc.tn", website:"https://amc.tn/",
        donate_url:"https://amc.tn/",
        domains:["sante","humanitaire"], needs:["dons","accompagnement","logistique"],
        summary_fr:"Aide financière et sociale, accompagnement médical et administratif.",
        summary_ar:"مساعدة مالية واجتماعية ومرافقة طبية وإدارية.",
        img:"https://images.unsplash.com/photo-1580283186565-826e-e379f3cc?auto=format&fit=crop&w=1200&q=80",
        lat:36.8065, lng:10.1815
      },
      {
        slug:"nourane",
        name_fr:"Association Nourane", name_ar:"جمعية نوران",
        gov:"Tunis", address:"Tunis, Tunisie", phone:"+216 71 000 004",
        email:"contact@associationnourane.tn", website:"https://associationnourane.tn/",
        donate_url:"https://associationnourane.tn/",
        domains:["sante"], needs:["sensibilisation","don","volontaires"],
        summary_fr:"Prévention, sensibilisation et actions de soutien.",
        summary_ar:"الوقاية والتوعية وأعمال الدعم.",
        img:"https://images.unsplash.com/photo-1576765607924-3f7b8410f0db?auto=format&fit=crop&w=1200&q=80",
        lat:36.8065, lng:10.1815
      },
      {
        slug:"tunisie-telethon",
        name_fr:"Téléthon Tunisie (Solidarité)", name_ar:"تيليتون تونس (تضامن)",
        gov:"Ariana", address:"Ariana, Tunisie", phone:"+216 71 000 005",
        email:"info@telethon.tn", website:"https://www.facebook.com/",
        donate_url:"https://www.facebook.com/",
        domains:["humanitaire","sante"], needs:["dons","collecte","volontaires"],
        summary_fr:"Campagnes de solidarité et collecte pour causes médicales/sociales.",
        summary_ar:"حملات تضامن وجمع تبرعات لقضايا طبية واجتماعية.",
        img:"https://images.unsplash.com/photo-1526256262350-7da7584cf5eb?auto=format&fit=crop&w=1200&q=80",
        lat:36.8665, lng:10.1647
      },
      {
        slug:"tunisian-food-bank",
        name_fr:"Banque Alimentaire (Tunisie)", name_ar:"بنك الطعام (تونس)",
        gov:"Ben Arous", address:"Ben Arous, Tunisie", phone:"+216 71 000 006",
        email:"contact@foodbank.tn", website:"https://www.facebook.com/",
        donate_url:"https://www.facebook.com/",
        domains:["humanitaire"], needs:["collecte","distribution","volontaires"],
        summary_fr:"Collecte et redistribution alimentaire pour familles vulnérables.",
        summary_ar:"جمع وتوزيع مساعدات غذائية للعائلات الهشة.",
        img:"https://images.unsplash.com/photo-1606787366850-de6330128bfc?auto=format&fit=crop&w=1200&q=80",
        lat:36.7531, lng:10.2189
      },
      {
        slug:"education-for-all",
        name_fr:"Éducation Pour Tous (Tunisie)", name_ar:"التعليم للجميع (تونس)",
        gov:"Sfax", address:"Sfax, Tunisie", phone:"+216 74 000 007",
        email:"contact@education.tn", website:"https://www.facebook.com/",
        donate_url:"https://www.facebook.com/",
        domains:["education","enfants"], needs:["tutorat","materiel_scolaire","volontaires"],
        summary_fr:"Soutien scolaire, mentorat et accès au matériel éducatif.",
        summary_ar:"دعم مدرسي ومرافقة وتوفير أدوات تعليمية.",
        img:"https://images.unsplash.com/photo-1523240795612-9a054b0db644?auto=format&fit=crop&w=1200&q=80",
        lat:34.7406, lng:10.7603
      },
      {
        slug:"green-tunisia",
        name_fr:"Green Tunisia (Environnement)", name_ar:"تونس الخضراء (البيئة)",
        gov:"Sousse", address:"Sousse, Tunisie", phone:"+216 73 000 008",
        email:"contact@green.tn", website:"https://www.facebook.com/",
        donate_url:"https://www.facebook.com/",
        domains:["humanitaire"], needs:["nettoyage","plantation","volontaires"],
        summary_fr:"Actions terrain : nettoyage, sensibilisation, plantation.",
        summary_ar:"أنشطة ميدانية: تنظيف، توعية، تشجير.",
        img:"https://images.unsplash.com/photo-1450101499163-c8848c66ca85?auto=format&fit=crop&w=1200&q=80",
        lat:35.8256, lng:10.6084
      }
    ];

    for (const a of seeds) {
      await run(
        `INSERT INTO associations
         (slug,name_fr,name_ar,gov,address,phone,email,website,donate_url,img,summary_fr,summary_ar,domains,needs,lat,lng)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          a.slug, a.name_fr, a.name_ar, a.gov, a.address, a.phone, a.email,
          a.website, a.donate_url, a.img, a.summary_fr, a.summary_ar,
          JSON.stringify(a.domains || []),
          JSON.stringify(a.needs || []),
          a.lat, a.lng
        ]
      );
    }
  }
}

function safeJson(s, fallback) {
  try { return JSON.parse(s); } catch { return fallback; }
}

function sign(user) {
  return jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.auth?.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

// --- routes expected by your front (script.js) :contentReference[oaicite:2]{index=2} ---

app.get("/api/associations", async (req, res) => {
  const rows = await all(`SELECT * FROM associations ORDER BY id ASC`);
  res.json({
    items: rows.map(r => ({
      id: r.id,
      slug: r.slug,
      name_fr: r.name_fr,
      name_ar: r.name_ar,
      gov: r.gov,
      address: r.address,
      phone: r.phone,
      email: r.email,
      website: r.website,
      donate_url: r.donate_url,
      img: r.img,
      summary_fr: r.summary_fr,
      summary_ar: r.summary_ar,
      domains: safeJson(r.domains, []),
      needs: safeJson(r.needs, []),
      lat: r.lat,
      lng: r.lng
    }))
  });
});

app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password, gov, skills } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: "name/email/password required" });

  const exists = await get(`SELECT id FROM users WHERE email=?`, [email]);
  if (exists) return res.status(400).json({ error: "Email already used" });

  const hash = await bcrypt.hash(password, 10);
  const r = await run(
    `INSERT INTO users(name,email,password_hash,gov,skills,role) VALUES(?,?,?,?,?,?)`,
    [name, email, hash, gov || "", skills || "", "user"]
  );
  const user = { id: r.lastID, name, email, gov: gov || "", skills: skills || "", role: "user" };
  res.json({ token: sign(user), user });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "email/password required" });

  const u = await get(`SELECT * FROM users WHERE email=?`, [email]);
  if (!u) return res.status(400).json({ error: "Invalid credentials" });

  const ok = await bcrypt.compare(password, u.password_hash);
  if (!ok) return res.status(400).json({ error: "Invalid credentials" });

  const user = { id: u.id, name: u.name, email: u.email, gov: u.gov, skills: u.skills, role: u.role };
  res.json({ token: sign(user), user });
});

app.post("/api/donations", auth, async (req, res) => {
  const { association_slug, donor_name, amount } = req.body || {};
  if (!association_slug || !amount || Number(amount) <= 0) return res.status(400).json({ ok:false, error: "Invalid donation" });

  const asso = await get(`SELECT slug FROM associations WHERE slug=?`, [association_slug]);
  if (!asso) return res.status(400).json({ ok:false, error: "Association not found" });

  await run(
    `INSERT INTO donations(association_slug, donor_name, amount) VALUES(?,?,?)`,
    [association_slug, donor_name || "", Number(amount)]
  );
  res.json({ ok: true });
});

app.get("/api/stats", async (req, res) => {
  const total = await get(`SELECT COALESCE(SUM(amount),0) as total_amount FROM donations`);
  const top = await all(`
    SELECT association_slug, COUNT(*) as count, COALESCE(SUM(amount),0) as total_amount
    FROM donations
    GROUP BY association_slug
    ORDER BY total_amount DESC
    LIMIT 6
  `);

  // join to get FR name
  const map = new Map();
  const assos = await all(`SELECT slug, name_fr FROM associations`);
  assos.forEach(a => map.set(a.slug, a.name_fr));

  res.json({
    total_amount: total.total_amount,
    top: top.map(r => ({
      association: map.get(r.association_slug) || r.association_slug,
      count: r.count,
      total_amount: r.total_amount
    }))
  });
});

app.post("/api/admin/associations", auth, adminOnly, async (req, res) => {
  const p = req.body || {};
  if (!p.name_fr || !p.name_ar || !p.gov) return res.status(400).json({ error: "name_fr/name_ar/gov required" });

  const slug = (p.name_fr || "")
    .toLowerCase()
    .replace(/[^\w]+/g, "-")
    .replace(/(^-|-$)/g, "") + "-" + Date.now().toString().slice(-4);

  const r = await run(
    `INSERT INTO associations
     (slug,name_fr,name_ar,gov,address,phone,email,website,donate_url,img,summary_fr,summary_ar,domains,needs,lat,lng)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      slug,
      p.name_fr, p.name_ar,
      p.gov || "", p.address || "",
      p.phone || "", p.email || "",
      p.website || "", p.donate_url || "",
      p.img || "",
      p.summary_fr || "", p.summary_ar || "",
      JSON.stringify(p.domains || []),
      JSON.stringify(p.needs || []),
      Number(p.lat ?? null),
      Number(p.lng ?? null)
    ]
  );

  res.json({ id: r.lastID, slug });
});

// route photos (pour ton fetch en bas de script.js)
app.get("/api/photos", async (req, res) => {
  const rows = await all(`SELECT img FROM associations WHERE img IS NOT NULL AND img != '' ORDER BY id ASC LIMIT 12`);
  res.json({
    items: rows.map(r => r.img),
    image: rows[0]?.img || null
  });
});

// mini AI (réponse simple + mémoire)
app.post("/api/ai/chat", async (req, res) => {
  const { text = "", memory = {} } = req.body || {};
  const q = text.toLowerCase();

  // exemple: "contact atcc"
  const rows = await all(`SELECT * FROM associations`);
  const assos = rows.map(r => ({
    slug: r.slug,
    name_fr: r.name_fr,
    name_ar: r.name_ar,
    phone: r.phone,
    email: r.email,
    website: r.website,
    address: r.address,
    lat: r.lat, lng: r.lng
  }));

  let found = assos.find(a => q.includes((a.name_fr||"").toLowerCase()) || q.includes((a.slug||"").toLowerCase()));

  // si l'utilisateur dit "sa localisation" => reprendre la dernière asso
  if (!found && (q.includes("localisation") || q.includes("adresse") || q.includes("maps")) && memory?.last_asso_slug) {
    found = assos.find(a => a.slug === memory.last_asso_slug);
  }

  let answer = "Je peux t’aider : contact, lien, localisation, don…";
  if (found) {
    const maps = found.address
      ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(found.address)}`
      : (found.lat && found.lng)
        ? `https://www.google.com/maps?q=${found.lat},${found.lng}`
        : null;

    answer =
      `**${found.name_fr}**<br>` +
      `📞 ${found.phone || "-"}<br>` +
      `✉️ ${found.email || "-"}<br>` +
      `🌐 <a href="${found.website || "#"}" target="_blank" rel="noreferrer">Site</a><br>` +
      (maps ? `📍 <a href="${maps}" target="_blank" rel="noreferrer">Localisation</a>` : `📍 -`);

    return res.json({
      answer,
      memory: { ...memory, last_asso_slug: found.slug, last_asso_name: found.name_fr },
      quick_replies: [
        { label: "Voir associations", type: "openTab", tab: "assos" },
        { label: "Faire un don", type: "openTab", tab: "donate" }
      ]
    });
  }

  res.json({ answer, memory });
});

init().then(() => {
  app.listen(PORT, () => console.log(`API ready on http://localhost:${PORT}/api`));
});

