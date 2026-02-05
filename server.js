import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { run, get, all } from "./db.js";

const app = express();
app.use(cors({
  origin: [
    "https://tuniaid.netlify.app",   // <-- mets ton vrai lien netlify ici
    "http://localhost:5173",
    "http://localhost:3000"
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));

app.use(express.json());

const PORT = process.env.PORT || 4000;

const JWT_SECRET = "dev_secret_change_me";

const safeJson = (s, fallback) => { try { return JSON.parse(s); } catch { return fallback; } };
const sign = (user) => jwt.sign({ id: user.id, role: user.role, email: user.email }, JWT_SECRET, { expiresIn: "7d" });

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try { req.auth = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: "Invalid token" }); }
}
function adminOnly(req, res, next) {
  if (req.auth?.role !== "admin") return res.status(403).json({ error: "Admin only" });
  next();
}

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
      address_fr TEXT,
      address_ar TEXT,
      phone TEXT,
      email TEXT,
      website TEXT,
      donate_url TEXT,
      img TEXT,
      summary_fr TEXT,
      summary_ar TEXT,
      domains TEXT,  -- JSON
      needs TEXT,    -- JSON
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

  // seed associations
  const c = await get(`SELECT COUNT(*) as n FROM associations`);
  if (c.n === 0) {
    const seeds = [
      {
        slug:"atcc",
        name_fr:"ATCC — Association Tunisienne de Lutte Contre le Cancer",
        name_ar:"الجمعية التونسية لمقاومة السرطان",
        gov:"Tunis",
        address_fr:"Tunis, Tunisie",
        address_ar:"تونس، تونس",
        phone:"+216 71 000 002",
        email:"contact@atcc.tn",
        website:"https://atcc.com.tn/",
        donate_url:"https://atcc.com.tn/",
        img:"https://images.unsplash.com/photo-1580283186565-826e-e379f3cc?auto=format&fit=crop&w=1200&q=80",
        summary_fr:"Prévention, soutien aux patients et sensibilisation.",
        summary_ar:"الوقاية ودعم المرضى وحملات التوعية.",
        domains:["sante"],
        needs:["benevolat","sensibilisation","accompagnement"],
        lat:36.8065, lng:10.1815
      },
      {
        slug:"croissant-rouge",
        name_fr:"Croissant-Rouge Tunisien",
        name_ar:"الهلال الأحمر التونسي",
        gov:"Tunis",
        address_fr:"Tunis, Tunisie",
        address_ar:"تونس، تونس",
        phone:"+216 71 000 000",
        email:"contact@croissant-rouge.tn",
        website:"https://croissant-rouge.tn/",
        donate_url:"https://croissant-rouge.tn/",
        img:"https://images.unsplash.com/photo-1488521787991-ed7bbaae773c?auto=format&fit=crop&w=1200&q=80",
        summary_fr:"Aide humanitaire, secours et volontariat au niveau national.",
        summary_ar:"مساعدات إنسانية وإغاثة وتطوع على المستوى الوطني.",
        domains:["humanitaire","sante"],
        needs:["volontaires","collecte","secourisme"],
        lat:36.8065, lng:10.1815
      },
      {
        slug:"tunisian-food-bank",
        name_fr:"Banque Alimentaire (Tunisie)",
        name_ar:"بنك الطعام (تونس)",
        gov:"Ben Arous",
        address_fr:"Ben Arous, Tunisie",
        address_ar:"بن عروس، تونس",
        phone:"+216 71 000 006",
        email:"contact@foodbank.tn",
        website:"https://www.facebook.com/",
        donate_url:"https://www.facebook.com/",
        img:"https://images.unsplash.com/photo-1606787366850-de6330128bfc?auto=format&fit=crop&w=1200&q=80",
        summary_fr:"Collecte et redistribution alimentaire pour les familles vulnérables.",
        summary_ar:"جمع وتوزيع مساعدات غذائية للعائلات الهشة.",
        domains:["humanitaire"],
        needs:["collecte","distribution","volontaires"],
        lat:36.7531, lng:10.2189
      }
    ];

    for (const a of seeds) {
      await run(
        `INSERT INTO associations
         (slug,name_fr,name_ar,gov,address_fr,address_ar,phone,email,website,donate_url,img,summary_fr,summary_ar,domains,needs,lat,lng)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          a.slug, a.name_fr, a.name_ar, a.gov,
          a.address_fr, a.address_ar,
          a.phone, a.email, a.website, a.donate_url, a.img,
          a.summary_fr, a.summary_ar,
          JSON.stringify(a.domains||[]),
          JSON.stringify(a.needs||[]),
          a.lat, a.lng
        ]
      );
    }
  }
}

function toAssociation(r){
  return {
    id: r.id,
    slug: r.slug,
    gov: r.gov,
    name_fr: r.name_fr,
    name_ar: r.name_ar,
    address_fr: r.address_fr,
    address_ar: r.address_ar,
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
  };
}

function makeMapsLink(a){
  if (a.lat && a.lng) return `https://www.google.com/maps?q=${a.lat},${a.lng}`;
  const addr = a.address_fr || a.address_ar || "";
  if (!addr) return null;
  return `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(addr)}`;
}

// health
app.get("/api/health", (req,res)=>res.json({ ok:true }));

// associations
app.get("/api/associations", async (req,res)=>{
  const rows = await all(`SELECT * FROM associations ORDER BY id ASC`);
  res.json({ items: rows.map(r => ({ ...toAssociation(r), maps: makeMapsLink(toAssociation(r)) })) });
});

// photos (from associations img)
app.get("/api/photos", async (req,res)=>{
  const rows = await all(`SELECT img FROM associations WHERE img IS NOT NULL AND img != '' ORDER BY id ASC LIMIT 24`);
  res.json({ items: rows.map(r=>r.img), image: rows[0]?.img || null });
});

// auth
app.post("/api/auth/signup", async (req,res)=>{
  const { name, email, password, gov, skills } = req.body || {};
  if(!name || !email || !password) return res.status(400).json({ error:"name/email/password required" });
  const exists = await get(`SELECT id FROM users WHERE email=?`, [email]);
  if(exists) return res.status(400).json({ error:"Email already used" });

  const hash = await bcrypt.hash(password, 10);
  const r = await run(
    `INSERT INTO users(name,email,password_hash,gov,skills,role) VALUES(?,?,?,?,?,?)`,
    [name, email, hash, gov||"", skills||"", "user"]
  );
  const user = { id:r.lastID, name, email, gov:gov||"", skills:skills||"", role:"user" };
  res.json({ token: sign(user), user });
});

app.post("/api/auth/login", async (req,res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ error:"email/password required" });

  const u = await get(`SELECT * FROM users WHERE email=?`, [email]);
  if(!u) return res.status(400).json({ error:"Invalid credentials" });

  const ok = await bcrypt.compare(password, u.password_hash);
  if(!ok) return res.status(400).json({ error:"Invalid credentials" });

  const user = { id:u.id, name:u.name, email:u.email, gov:u.gov, skills:u.skills, role:u.role };
  res.json({ token: sign(user), user });
});

// donations + stats
app.post("/api/donations", auth, async (req,res)=>{
  const { association_slug, donor_name, amount } = req.body || {};
  if(!association_slug || !amount || Number(amount) <= 0) return res.status(400).json({ ok:false, error:"Invalid donation" });

  const asso = await get(`SELECT slug FROM associations WHERE slug=?`, [association_slug]);
  if(!asso) return res.status(400).json({ ok:false, error:"Association not found" });

  await run(`INSERT INTO donations(association_slug, donor_name, amount) VALUES(?,?,?)`,
    [association_slug, donor_name||"", Number(amount)]
  );
  res.json({ ok:true });
});

app.get("/api/stats", async (req,res)=>{
  const total = await get(`SELECT COALESCE(SUM(amount),0) as total_amount FROM donations`);
  const top = await all(`
    SELECT association_slug, COUNT(*) as count, COALESCE(SUM(amount),0) as total_amount
    FROM donations
    GROUP BY association_slug
    ORDER BY total_amount DESC
    LIMIT 6
  `);
  const map = new Map((await all(`SELECT slug, name_fr FROM associations`)).map(x => [x.slug, x.name_fr]));
  res.json({
    total_amount: total.total_amount,
    top: top.map(r => ({
      association: map.get(r.association_slug) || r.association_slug,
      count: r.count,
      total_amount: r.total_amount
    }))
  });
});

// admin: add association (FR/AR + contacts + links + coords + photo)
app.post("/api/admin/associations", auth, adminOnly, async (req,res)=>{
  const p = req.body || {};
  if(!p.name_fr || !p.name_ar || !p.gov) return res.status(400).json({ error:"name_fr/name_ar/gov required" });

  const slug =
    (p.name_fr||"").toLowerCase().replace(/[^\w]+/g,"-").replace(/(^-|-$)/g,"") +
    "-" + Date.now().toString().slice(-4);

  const r = await run(
    `INSERT INTO associations
     (slug,name_fr,name_ar,gov,address_fr,address_ar,phone,email,website,donate_url,img,summary_fr,summary_ar,domains,needs,lat,lng)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    [
      slug, p.name_fr, p.name_ar, p.gov||"",
      p.address_fr||"", p.address_ar||"",
      p.phone||"", p.email||"",
      p.website||"", p.donate_url||"",
      p.img||"",
      p.summary_fr||"", p.summary_ar||"",
      JSON.stringify(p.domains||[]),
      JSON.stringify(p.needs||[]),
      Number(p.lat ?? null),
      Number(p.lng ?? null)
    ]
  );

  res.json({ id: r.lastID, slug });
});

// CHATBOT (dynamique + mémoire + FR/AR + maps)
app.post("/api/ai/chat", async (req,res)=>{
  const { text = "", memory = {}, lang = "fr" } = req.body || {};
  const q = text.toLowerCase();
  const rows = await all(`SELECT * FROM associations`);
  const assos = rows.map(r => {
    const a = toAssociation(r);
    return { ...a, maps: makeMapsLink(a) };
  });

  // find association by name/slug (FR/AR)
  let found = assos.find(a =>
    q.includes(a.slug.toLowerCase()) ||
    q.includes((a.name_fr||"").toLowerCase()) ||
    q.includes((a.name_ar||"").toLowerCase())
  );

  // reuse last association from memory if user asks localisation/contact etc.
  const wantsLocation = q.includes("localisation") || q.includes("adresse") || q.includes("maps") || q.includes("location") || q.includes("خريطة") || q.includes("العنوان");
  const wantsContact = q.includes("contact") || q.includes("téléphone") || q.includes("tel") || q.includes("email") || q.includes("هاتف") || q.includes("بريد");

  if(!found && (wantsLocation || wantsContact) && memory?.last_asso_slug){
    found = assos.find(a => a.slug === memory.last_asso_slug);
  }

  const say = (fr, ar) => (lang === "ar" ? ar : fr);

  if(found){
    const name = lang === "ar" ? found.name_ar : found.name_fr;
    const addr = lang === "ar" ? found.address_ar : found.address_fr;

    // intent
    if(wantsLocation){
      return res.json({
        answer: `${say("📍 Localisation de", "📍 موقع")} <b>${name}</b><br>` +
                `${addr || "—"}<br>` +
                (found.maps ? `🗺️ <a href="${found.maps}" target="_blank" rel="noreferrer">${say("Ouvrir Google Maps","فتح خرائط Google")}</a>` : "—"),
        memory: { ...memory, last_asso_slug: found.slug, last_asso_name: found.name_fr },
      });
    }

    if(wantsContact){
      return res.json({
        answer:
          `<b>${name}</b><br>` +
          `📞 ${found.phone || "—"}<br>` +
          `✉️ ${found.email || "—"}<br>` +
          `🌐 <a href="${found.website || "#"}" target="_blank" rel="noreferrer">${say("Site","الموقع")}</a><br>` +
          `💙 <a href="${found.donate_url || "#"}" target="_blank" rel="noreferrer">${say("Don","تبرع")}</a>`,
        memory: { ...memory, last_asso_slug: found.slug, last_asso_name: found.name_fr },
      });
    }

    // default “card”
    return res.json({
      answer:
        `<b>${name}</b><br>` +
        `${say("Gouvernorat","الولاية")}: ${found.gov || "—"}<br>` +
        `${say("📍 Coordonnées","📍 الإحداثيات")}: ${found.lat ?? "—"}, ${found.lng ?? "—"}<br>` +
        (found.maps ? `🗺️ <a href="${found.maps}" target="_blank" rel="noreferrer">${say("Google Maps","خرائط Google")}</a>` : ""),
      memory: { ...memory, last_asso_slug: found.slug, last_asso_name: found.name_fr },
    });
  }

  // global intents
  if(q.includes("don") || q.includes("تبرع")){
    return res.json({ answer: say("💙 Va à l’onglet Dons, choisis une association + montant.", "💙 اذهب إلى صفحة التبرع واختر جمعية والمبلغ."), memory });
  }

  if(q.includes("voir toutes") || q.includes("toutes") || q.includes("الكل")){
    const list = assos.slice(0, 10).map(a => `• ${lang==="ar"?a.name_ar:a.name_fr}`).join("<br>");
    return res.json({ answer: say("Voici quelques associations :<br>"+list, "بعض الجمعيات:<br>"+list), memory });
  }

  // filter example: "associations santé Tunis"
  if(q.includes("sant") || q.includes("صحة")){
    const matches = assos.filter(a => (a.domains||[]).includes("sante") && (a.gov||"").toLowerCase().includes("tunis"));
    const list = matches.map(a => `• ${lang==="ar"?a.name_ar:a.name_fr}`).join("<br>") || "—";
    return res.json({ answer: say("Associations santé à Tunis :<br>"+list, "جمعيات الصحة في تونس:<br>"+list), memory });
  }

  res.json({ answer: say("Je peux t’aider : contact, lien, localisation, don… (ex: « contact ATCC »)", "أستطيع مساعدتك: اتصال، رابط، موقع، تبرع… (مثال: «اتصال ATCC» )"), memory });
});

await init();
app.listen(PORT, () => console.log(`✅ API ready on port ${PORT}`));

