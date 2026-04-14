import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Sequelize, DataTypes, Op } from "sequelize";
import session from "express-session";
import bcrypt from "bcryptjs";
import { authenticator } from "otplib";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import fs from "fs";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Extend express-session to include user info
declare module "express-session" {
  interface SessionData {
    userId: number;
    username: string;
    mobileNumber: string;
    mfaSecret: string;
    pendingUserId: number; // For MFA flow
    appVerified: boolean; // Step 1: App Auth
    emailVerified: boolean; // Step 2: Email Auth
    emailOtp: string; // Random code for email auth
  }
}

console.log("Starting server initialization...");

// Persistent Database Path for Railway
// To use this, add a Volume in Railway and mount it to /data
const PERSISTENT_DIR = "/data";
const dbPath = fs.existsSync(PERSISTENT_DIR) 
  ? path.join(PERSISTENT_DIR, "database.sqlite") 
  : path.join(__dirname, "database.sqlite");

console.log(`[DB] Using database at: ${dbPath}`);

const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: dbPath,
  logging: false,
});

// Define User Model
const User = sequelize.define("User", {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
    },
  },
  mobileNumber: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  mfaSecret: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

// Configure Nodemailer
// Configure Nodemailer as per requirements
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS ? process.env.SMTP_PASS.replace(/\s/g, "") : "",
  },
});

async function sendOTPEmail(email: string, otp: string) {
  console.log("SMTP_USER:", process.env.SMTP_USER ? "OK" : "MISSING");
  console.log("SMTP_PASS:", process.env.SMTP_PASS ? "OK" : "MISSING");
  console.log("Step 3: Sending email to:", email);

  const mailOptions = {
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP is: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Step 4: Email sent successfully");
  } catch (error) {
    console.error("Email error:", error);
  }
}

const app = express();

// Middleware to ensure DB is synced before handling requests
let isDbSynced = false;
app.use(async (req, res, next) => {
  if (!isDbSynced) {
    try {
      await sequelize.sync();
      isDbSynced = true;
      console.log("Database synced successfully.");
    } catch (error) {
      console.error("Database sync failed:", error);
    }
  }
  next();
});

const PORT = Number(process.env.PORT) || 3000;
app.set('trust proxy', 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(session({
  name: 'sid', 
  secret: "secure-mfa-secret-key",
  resave: true,
  saveUninitialized: true,
  proxy: true,
  cookie: { 
    secure: false,
    maxAge: 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

  app.use((req, res, next) => {
    console.log(`[SESSION] Path: ${req.path}, Proto: ${req.headers['x-forwarded-proto']}, SessionID: ${req.sessionID}, Pending: ${req.session.pendingUserId}`);
    next();
  });

  const authLimiter = (req: any, res: any, next: any) => next();

  app.use((req, res, next) => {
    res.locals.user = req.session.userId ? { 
      id: req.session.userId, 
      username: req.session.username,
      mobileNumber: req.session.mobileNumber,
      mfaSecret: req.session.mfaSecret
    } : null;
    next();
  });

  const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!req.session.userId) return res.redirect("/login");
    next();
  };

  app.get("/", (req, res) => res.render("index"));
  app.get("/register", (req, res) => res.render("register"));

  app.post("/register", authLimiter, async (req, res) => {
    const { username, email, mobileNumber, password } = req.body;
    try {
      const existingUser = await User.findOne({ 
        where: { [Op.or]: [{ username }, { email }, { mobileNumber }] } 
      });
      if (existingUser) {
        let field = "Account";
        if ((existingUser as any).username === username) field = "Username";
        else if ((existingUser as any).email === email) field = "Email";
        else if ((existingUser as any).mobileNumber === mobileNumber) field = "Mobile number";
        return res.render("register", { error: `${field} already registered.` });
      }
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      const secret = authenticator.generateSecret();
      await User.create({ username, email, mobileNumber, password: hashedPassword, mfaSecret: secret });
      res.render("register", { success: "Account created successfully!", mfaSecret: secret });
    } catch (error: any) {
      res.render("register", { error: "Registration failed." });
    }
  });

  app.get("/login", (req, res) => {
    if (req.session.userId) return res.redirect("/dashboard");
    res.render("login");
  });

  app.post("/login", authLimiter, async (req, res) => {
    const { identifier, password } = req.body;
    try {
      const user = await User.findOne({ 
        where: { [Op.or]: [{ email: identifier }, { mobileNumber: identifier }] } 
      }) as any;
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.render("login", { error: "Invalid credentials." });
      }
      
      console.log("Step 1: Password verified");
      
      req.session.pendingUserId = user.id;
      req.session.appVerified = false;
      req.session.emailVerified = false;

      // Generate and send OTP immediately after password success
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      req.session.emailOtp = otp;
      
      console.log("Step 2: OTP generated:", otp);
      
      // Wait for email to send before redirecting to ensure we catch errors
      await sendOTPEmail(user.email, otp);

      req.session.save(() => res.redirect("/verify-app"));
    } catch (error) {
      res.render("login", { error: "Login failed." });
    }
  });

  app.get("/verify-app", (req, res) => {
    if (!req.session.pendingUserId) return res.redirect("/login");
    res.render("verify-app");
  });

  app.post("/verify-app", async (req, res) => {
    const { code } = req.body;
    const userId = req.session.pendingUserId;
    if (!userId) return res.redirect("/login");
    try {
      const user = await User.findByPk(userId) as any;
      if (!user || !authenticator.check(code, user.mfaSecret)) {
        return res.render("verify-app", { error: "Invalid code." });
      }
      req.session.appVerified = true;
      // OTP was already sent in /login
      req.session.save(() => res.redirect("/verify-email"));
    } catch (error) {
      res.render("verify-app", { error: "Verification failed." });
    }
  });

  app.get("/verify-email", (req, res) => {
    if (!req.session.pendingUserId || !req.session.appVerified) return res.redirect("/login");
    res.render("verify-email");
  });

  app.post("/verify-email", async (req, res) => {
    const { otp } = req.body;
    const userId = req.session.pendingUserId;
    if (!userId || !req.session.appVerified) return res.redirect("/login");
    if (otp !== req.session.emailOtp) return res.render("verify-email", { error: "Invalid OTP." });
    try {
      const user = await User.findByPk(userId) as any;
      if (!user) return res.redirect("/login");
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.mobileNumber = user.mobileNumber;
      req.session.mfaSecret = user.mfaSecret;
      delete req.session.pendingUserId;
      delete req.session.appVerified;
      delete req.session.emailVerified;
      delete req.session.emailOtp;
      req.session.save(() => res.redirect("/dashboard"));
    } catch (error) {
      res.render("verify-email", { error: "Verification failed." });
    }
  });

  app.get("/dashboard", requireAuth, (req, res) => res.render("dashboard"));
  
  app.get("/resend-otp", async (req, res) => {
    const userId = req.session.pendingUserId;
    if (!userId || !req.session.appVerified) return res.redirect("/login");
    
    try {
      const user = await User.findByPk(userId) as any;
      if (!user) return res.redirect("/login");
      
      const emailOtp = Math.floor(100000 + Math.random() * 900000).toString();
      req.session.emailOtp = emailOtp;
      sendOTPEmail(user.email, emailOtp);
      
      req.session.save(() => {
        res.render("verify-email", { success: "A new OTP has been sent to your email." });
      });
    } catch (error) {
      res.render("verify-email", { error: "Failed to resend OTP." });
    }
  });

  app.get("/logout", (req, res) => req.session.destroy(() => res.redirect("/")));
  app.get("/api/health", (req, res) => res.json({ status: "ok" }));

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is running on port ${PORT}`);
  });

export default app;


