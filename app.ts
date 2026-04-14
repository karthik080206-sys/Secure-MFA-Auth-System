import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { Sequelize, DataTypes, Op } from "sequelize";
import session from "express-session";
import bcrypt from "bcrypt";
import { authenticator } from "otplib";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
import { rateLimit } from "express-rate-limit";

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

// Initialize Sequelize with SQLite
const sequelize = new Sequelize({
  dialect: "sqlite",
  storage: path.join(__dirname, "database.sqlite"),
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
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendOTPEmail(email: string, otp: string) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.warn("SMTP credentials not configured. Skipping email send.");
    console.log(`[MOCK EMAIL] To: ${email}, OTP: ${otp}`);
    return;
  }

  const mailOptions = {
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to: email,
    subject: "Your Secure Login OTP",
    text: `Your one-time password for login is: ${otp}. It will expire in 30 seconds.`,
    html: `
      <div style="font-family: sans-serif; padding: 20px; border: 1px solid #e5e7eb; border-radius: 12px; max-width: 500px;">
        <h2 style="font-weight: 300; color: #111827;">Security Verification</h2>
        <p style="color: #6b7280; font-size: 14px;">Please use the following code to complete your login:</p>
        <div style="background: #f9fafb; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
          <span style="font-family: monospace; font-size: 32px; letter-spacing: 8px; font-weight: bold; color: #111827;">${otp}</span>
        </div>
        <p style="color: #9ca3af; font-size: 10px; text-transform: uppercase; letter-spacing: 1px;">This code expires in 30 seconds.</p>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`OTP email sent to ${email}`);
  } catch (error) {
    console.error("Error sending OTP email:", error);
  }
}

async function startServer() {
  // Sync Database
  try {
    await sequelize.authenticate();
    console.log("Connection to SQLite has been established successfully.");
    await sequelize.sync(); // Schema is now up to date
    console.log("Database & tables created!");
  } catch (error) {
    console.error("Unable to connect to the database:", error);
  }

  const app = express();
  const PORT = 3000;

  app.set('trust proxy', 1); // Trust the first proxy (AI Studio's load balancer)

  // Set EJS as the template engine
  app.set("view engine", "ejs");
  app.set("views", path.join(__dirname, "views"));

  // Middleware
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());
  app.use(express.static(path.join(__dirname, "public")));
  
  // 1. Session Configuration (Simplified for maximum reliability)
  app.use(session({
    name: 'sid', 
    secret: "secure-mfa-secret-key",
    resave: true,
    saveUninitialized: true,
    proxy: true,
    cookie: { 
      secure: false, // Changed to false because logs show 'Proto: http'
      maxAge: 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax'
    }
  }));

  // Session Debugging
  app.use((req, res, next) => {
    console.log(`[SESSION] Path: ${req.path}, Proto: ${req.headers['x-forwarded-proto']}, SessionID: ${req.sessionID}, Pending: ${req.session.pendingUserId}`);
    next();
  });

  // CSRF protection temporarily disabled for demo purposes
  
  // Rate Limiting (Brute Force Protection)
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20,
    message: "Too many attempts from this IP, please try again after 15 minutes",
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Global middleware to pass user info to templates
  app.use((req, res, next) => {
    res.locals.user = req.session.userId ? { 
      id: req.session.userId, 
      username: req.session.username,
      mobileNumber: req.session.mobileNumber,
      mfaSecret: req.session.mfaSecret
    } : null;
    next();
  });

  // Authentication Middleware (equivalent to @login_required)
  const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (!req.session.userId) {
      return res.redirect("/login");
    }
    next();
  };

  // Routes
  app.get("/", (req, res) => {
    res.render("index");
  });

  app.get("/register", (req, res) => {
    res.render("register");
  });

  app.post("/register", authLimiter, async (req, res) => {
    const { username, email, mobileNumber, password } = req.body;

    try {
      // Validation: Check if username, email or mobile already exists
      const existingUser = await User.findOne({ 
        where: { 
          [Op.or]: [{ username }, { email }, { mobileNumber }] 
        } 
      });
      
      if (existingUser) {
        let field = "Account";
        if ((existingUser as any).username === username) field = "Username";
        else if ((existingUser as any).email === email) field = "Email";
        else if ((existingUser as any).mobileNumber === mobileNumber) field = "Mobile number";
        
        return res.render("register", { error: `${field} already registered. Please use a different one.` });
      }

      // Hash password
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Generate MFA Secret
      const secret = authenticator.generateSecret();

      await User.create({ 
        username, 
        email, 
        mobileNumber, 
        password: hashedPassword,
        mfaSecret: secret
      });
      
      res.render("register", { 
        success: "Account created successfully!", 
        mfaSecret: secret // Show secret so user can setup their app
      });
    } catch (error: any) {
      console.error("Registration error details:", error);
      if (error.stack) console.error("Stack trace:", error.stack);
      
      let errorMessage = "An error occurred during registration. Please try again.";
      
      if (error.name === 'SequelizeValidationError' || error.name === 'SequelizeUniqueConstraintError') {
        errorMessage = error.errors.map((e: any) => e.message).join(", ");
      } else if (error.message && error.message !== 'Error') {
        errorMessage = error.message;
      } else if (typeof error === 'string') {
        errorMessage = error;
      }
      
      res.render("register", { error: errorMessage });
    }
  });

  app.get("/login", (req, res) => {
    if (req.session.userId) {
      return res.redirect("/dashboard");
    }
    res.render("login");
  });

  app.post("/login", authLimiter, async (req, res) => {
    const { identifier, password } = req.body; // identifier can be email or mobileNumber
    console.log(`[LOGIN] Attempt for identifier: ${identifier}`);

    try {
      const user = await User.findOne({ 
        where: { 
          [Op.or]: [{ email: identifier }, { mobileNumber: identifier }] 
        } 
      }) as any;
      
      if (!user) {
        console.log(`[LOGIN] User not found for: ${identifier}`);
        return res.render("login", { error: "Invalid credentials." });
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        console.log(`[LOGIN] Invalid password for: ${identifier}`);
        return res.render("login", { error: "Invalid credentials." });
      }

      // Start MFA Flow
      req.session.pendingUserId = user.id;
      req.session.appVerified = false;
      req.session.emailVerified = false;
      
      console.log(`[LOGIN] Success. Initiating MFA Step 1 (App Auth) for user: ${user.id}`);

      req.session.save((err) => {
        if (err) {
          console.error("[LOGIN] Session save error:", err);
          return res.render("login", { error: "Session error. Please try again." });
        }
        console.log(`[LOGIN] Session saved successfully. Redirecting to /verify-app. SessionID: ${req.sessionID}`);
        res.redirect("/verify-app");
      });
    } catch (error) {
      console.error("Login error:", error);
      res.render("login", { error: "An error occurred during login. Please try again." });
    }
  });

  // STEP 1: App Authenticator (TOTP)
  app.get("/verify-app", (req, res) => {
    console.log(`[GET /verify-app] SessionID: ${req.sessionID}, pendingUserId: ${req.session.pendingUserId}`);
    if (!req.session.pendingUserId) {
      console.log(`[GET /verify-app] No pendingUserId found. Redirecting back to /login.`);
      return res.redirect("/login");
    }
    res.render("verify-app");
  });

  app.post("/verify-app", async (req, res) => {
    const { code } = req.body;
    const userId = req.session.pendingUserId;

    if (!userId) return res.redirect("/login");

    try {
      const user = await User.findByPk(userId) as any;
      if (!user) return res.redirect("/login");

      const isValid = authenticator.check(code, user.mfaSecret);
      if (!isValid) {
        return res.render("verify-app", { error: "Invalid authenticator code. Please try again." });
      }

      // Step 1 Success
      req.session.appVerified = true;
      
      // Prepare Step 2: Email OTP
      const emailOtp = Math.floor(100000 + Math.random() * 900000).toString();
      req.session.emailOtp = emailOtp;
      
      await sendOTPEmail(user.email, emailOtp);
      console.log(`[MFA] App Auth Success. Sent Email OTP to ${user.email}`);

      req.session.save(() => {
        res.redirect("/verify-email");
      });
    } catch (error) {
      console.error("App verification error:", error);
      res.render("verify-app", { error: "An error occurred. Please try again." });
    }
  });

  // STEP 2: Email OTP
  app.get("/verify-email", (req, res) => {
    if (!req.session.pendingUserId || !req.session.appVerified) {
      return res.redirect("/login");
    }
    res.render("verify-email");
  });

  app.post("/verify-email", async (req, res) => {
    const { otp } = req.body;
    const userId = req.session.pendingUserId;

    if (!userId || !req.session.appVerified) return res.redirect("/login");

    if (otp !== req.session.emailOtp) {
      return res.render("verify-email", { error: "Invalid email OTP. Please check your inbox." });
    }

    try {
      const user = await User.findByPk(userId) as any;
      if (!user) return res.redirect("/login");

      // Final Success: Complete login
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.mobileNumber = user.mobileNumber;
      req.session.mfaSecret = user.mfaSecret;
      
      // Cleanup
      delete req.session.pendingUserId;
      delete req.session.appVerified;
      delete req.session.emailVerified;
      delete req.session.emailOtp;

      req.session.save(() => {
        res.redirect("/dashboard");
      });
    } catch (error) {
      console.error("Email verification error:", error);
      res.render("verify-email", { error: "An error occurred. Please try again." });
    }
  });

  app.get("/dashboard", requireAuth, (req, res) => {
    res.render("dashboard");
  });

  app.get("/logout", (req, res) => {
    req.session.destroy((err) => {
      if (err) {
        console.error("Logout error:", err);
      }
      res.redirect("/");
    });
  });

  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
  });
}

console.log("Calling startServer()...");
startServer().catch(err => {
  console.error("FATAL ERROR during startServer:", err);
});


