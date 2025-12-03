// server.js
// BIT Lost-Found Portal - consolidated MongoDB version
// Keep this file as the single backend entrypoint for Render/local.

// Removed dotenv override as Render injects env vars directly.
// require("dotenv").config({ override: true }); 
const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const fs = require("fs"); // Added for file system operations
const LocalStrategy = require("passport-local").Strategy; // For username/password login
const bcrypt = require("bcryptjs"); // For password comparison
const CloudinaryStorage = require("multer-storage-cloudinary");

const Student = require("./models/Student"); // Import Student model
const Item = require("./models/Item");     // Import Item model

// production additions
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cors = require("cors");
const morgan = require("morgan");
const winston = require("winston");
const MongoStore = require("connect-mongo");


const app = express();

// ---- logging (winston + morgan) ----
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
  winston.format.colorize(),
  winston.format.simple()
),

  transports: [
    new winston.transports.Console({ handleExceptions: true }),
    // in production add file transports or remote logging
    process.env.NODE_ENV === "production"
      ? new winston.transports.File({ filename: "logs/error.log", level: "error" })
      : null,
    process.env.NODE_ENV === "production"
      ? new winston.transports.File({ filename: "logs/combined.log" })
      : null,
  ].filter(Boolean),
});
app.locals.logger = logger;

// morgan to log HTTP requests (shorter format to winston)
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev", {
  stream: {
    write: message => logger.info(message.trim())
  }
}));


/* ---------------------------
   Middleware & static files
   --------------------------- */
const compression = require("compression"); // you may need to install it

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      fontSrc: ["'self'", "https:", "data:"],
      formAction: ["'self'"],
      frameAncestors: ["'self'"],
      imgSrc: ["'self'", "data:", "https://res.cloudinary.com", "https://www.gstatic.com"], // Allow Cloudinary images and Google static images
      objectSrc: ["'none'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"], // Allow 'unsafe-inline' for attributes
      styleSrc: ["'self'", "https:", "'unsafe-inline'"], // 'unsafe-inline' often needed for local CSS
      upgradeInsecureRequests: [],
    },
  },
})); // set secure headers
app.use(compression()); // gzip responses
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json({ limit: "2mb" })); // limit JSON body size
app.use(express.static(path.join(__dirname, "public"), { maxAge: "30d" }));

// Basic CORS — restrict origin in production
// const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, callback) => {
    logger.debug(`CORS Check: Origin = '${origin}', NODE_ENV = '${process.env.NODE_ENV}'`);
    const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
    logger.debug(`CORS Check: Allowed Origins = [${allowedOrigins.join(', ')}]`);

    if (process.env.NODE_ENV !== "production") {
      logger.debug("CORS: Allowing all origins in development.");
      // In development, allow all origins.
      return callback(null, true);
    }

    // In production, explicitly allow requests with no origin (e.g., direct server requests, health checks).
    // Also explicitly allow the string 'null' often sent by some clients/environments for non-browser requests.
    if (!origin || origin === 'null') {
      logger.debug("CORS: Allowing request with null/undefined/\'null\' origin in production.");
      return callback(null, true);
    }

    // For requests with an origin, check if it's in the allowed list.
    if (allowedOrigins.includes(origin)) {
      logger.debug(`CORS: Allowing origin '${origin}' as it is in the allowed list.`);
      return callback(null, true);
    }

    logger.warn(`CORS: Origin '${origin}' not allowed.`);
    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true
}));

// Rate limiter - basic protection
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: parseInt(process.env.RATE_LIMIT_MAX || "120"), // requests per minute
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Trust proxy for secure cookies if behind proxy (Render, Heroku, etc.)
if (process.env.TRUST_PROXY === "true" || process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// Session store: connect-mongo (persistent)
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGO_URI,
  ttl: 14 * 24 * 60 * 60, // 14 days
  autoRemove: 'native'
});

app.use(
  session({
    name: process.env.SESSION_NAME || "bit_lf_sid",
    secret: process.env.SESSION_SECRET, // No default, must be set
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // Set secure to true in production
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    },
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport Google OAuth 2.0 Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const studentEmail = profile.emails[0].value;

        // Allowed test emails for testing purposes
        const allowedTestEmails = [
          "bitlostfoundportal@gmail.com", // Super admin
          "fake120824@gmail.com",         // Test email 1
          "vasanth51575@gmail.com"        // Test email 2
        ];

        // Domain restriction: Only allow @bitsathy.ac.in emails, EXCEPT for super admin and test emails.
        if (!allowedTestEmails.includes(studentEmail) && !studentEmail.endsWith("@bitsathy.ac.in")) {
          return done(new Error("Only @bitsathy.ac.in email addresses are allowed."), null);
        }

        let student = await Student.findOne({ college_email: studentEmail }); // Find by full email

        if (!student) {
          // If student not found by college_email, it means this email does not exist in the pre-populated database.
          // This should be treated as an authentication failure if all students are pre-populated.
          logger.warn(`Authentication failed: No student found with email ${studentEmail}.`);
          return done(new Error("Authentication failed: Student record not found."), null);
        } else {
          // If student found by college_email, update name and googleId if they've changed
          student.name = profile.displayName; // Ensure name is collected
          student.googleId = profile.id;
          student.google_display_name = profile.displayName; // Store Google display name separately
          await student.save();
        }

        // At this point, `student.rollno` *must* exist because it's required in the schema
        // and we are only finding/updating existing students from the pre-populated database.
        // No longer need to warn about missing rollno for new students here.

        done(null, student);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// Passport Local Strategy for username/password login
passport.use(
  new LocalStrategy(
    { usernameField: "rollno" }, // Use 'rollno' as the username field
    async (rollno, password, done) => {
      try {
        const student = await Student.findOne({ rollno }).select("+password"); // Select password field
        if (!student) {
          return done(null, false, { message: "No student found with that Roll No." });
        }
        if (!student.password) {
          return done(null, false, { message: "This account does not have a local password set. Please use Google login." });
        }
        const isMatch = await student.isValidPassword(password);
        if (!isMatch) {
          return done(null, false, { message: "Incorrect Password." });
        }
        return done(null, student); // Authenticated successfully
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Serialize user (store user id in session)
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user (retrieve user from database based on id)
passport.deserializeUser(async (id, done) => {
  try {
    const student = await Student.findById(id);
    done(null, student);
  } catch (err) {
    done(err, null);
  }
});


/* ---------------------------
   Email (Nodemailer) setup
   --------------------------- */
const EMAIL_USER = process.env.EMAIL_USER || "bitlostfoundportal@gmail.com";
const EMAIL_PASS = process.env.EMAIL_PASS;
logger.info(`Nodemailer config: NODE_ENV=${process.env.NODE_ENV}, rejectUnauthorized=${process.env.NODE_ENV === "production"}`);
const transporter = nodemailer.createTransport({
  service: 'gmail',
  // Removed explicit host, port, secure, requireTLS, relying on 'service: gmail'
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: process.env.NODE_ENV === "production", // Explicitly set rejectUnauthorized within tls
  },
  connectionTimeout: 10000, // Keep the 10-second connection timeout
});

// verify transporter at startup (non-blocking)
transporter.verify().then(() => {
  logger.info("Nodemailer transporter verified");
}).catch(err => {
  logger.warn("Nodemailer verification failed", { error: err.message });
});


/* ---------------------------
   File uploads (Cloudinary)
   --------------------------- */
const cloudinary = require('cloudinary');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'bit-lost-found',
    allowed_formats: ['jpg', 'png', 'jpeg'],
    transformation: [{ width: 800, height: 800, crop: 'limit' }]
  }
});


const upload = multer({ storage });


/* ---------------------------
   MongoDB Connection
   --------------------------- */
const MONGO_URI = process.env.MONGO_URI;


mongoose.connect(process.env.MONGO_URI)

  .then(() => logger.info("✅ MongoDB Connected Successfully")) // Changed console.log to logger.info
  .catch((err) => {
    logger.error("❌ MongoDB Connection Error:", { error: err.message, stack: err.stack }); // Changed console.error to logger.error
    if (process.env.NODE_ENV === "production") {
      logger.error("Exiting due to MongoDB connection error in production.");
      process.exit(1);
    }
  });

/* ---------------------------
   Schemas & Models (Moved to separate files)
   --------------------------- */
// The schemas were moved to `models/Student.js` and `models/Item.js`

/* ---------------------------
   Helper middleware
   --------------------------- */
function requireLogin(req, res, next) {
  if (!req.isAuthenticated()) { // Updated to use Passport's isAuthenticated
    return res.redirect("/?msg=Please login first.&type=error");
  }

  next();
}

/* ---------------------------
   Routes - Login / Dashboard / APIs
   --------------------------- */

// Serve login page - now redirects to Google OAuth based on authentication status
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.redirect("/dashboard?msg=Already logged in!&type=info");
  } else {
    res.sendFile(path.join(__dirname, "views", "login.html")); // Serve login.html directly
  }
});

// API endpoint to get Google Client ID for frontend
app.get("/api/google-client-id", (req, res) => {
  res.json({ clientId: process.env.GOOGLE_CLIENT_ID || "" });
});

// Google OAuth routes (already defined, ensure the callback route is correct)
// Note: The /auth/google initiation is now handled by the root route if unauthenticated.
app.get("/auth/google", (req, res, next) => {
  logger.info("Redirecting to Google for OAuth...");
  passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

// Placeholder for username/password login
app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      logger.error("Local login error:", { error: err.message, stack: err.stack });
      return res.redirect("/?msg=An unexpected authentication error occurred.&type=error");
    }
    if (!user) {
      return res.redirect(`/?msg=${info.message || "Invalid credentials."}&type=error`);
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      // Redirect super admin to /admin, others to /dashboard
      if (user.college_email === "bitlostfoundportal@gmail.com") {
        return res.redirect("/admin?msg=Admin Login successful!&type=success");
      } else {
        return res.redirect("/dashboard?msg=Login successful!&type=success");
      }
    });
  })(req, res, next);
});

app.get("/auth/google/callback",
  (req, res, next) => {
    logger.info("Google OAuth callback received.");
    passport.authenticate("google", { failureRedirect: "/?msg=Google login failed!&type=error" }, (err, user, info) => {
      if (err) {
        if (err.message === "Only @bitsathy.ac.in email addresses are allowed.") {
          return res.redirect("/?msg=Only @bitsathy.ac.in emails are allowed for login.&type=error");
        }
        // For other errors, log and redirect to a generic error page
        logger.error("Google OAuth callback error:", { error: err.message, stack: err.stack });
        return res.redirect("/?msg=An unexpected authentication error occurred.&type=error");
      }
      if (!user) {
        // Passport failed for other reasons (e.g., info.message)
        return res.redirect("/?msg=Google login failed!&type=error");
      }
      req.logIn(user, (err) => {
        if (err) { return next(err); }
        // Redirect super admin to /admin, others to /dashboard
        if (user.college_email === "bitlostfoundportal@gmail.com") {
          res.redirect("/admin?msg=Admin Login successful!&type=success");
        } else {
          res.redirect("/dashboard?msg=Login successful!&type=success");
        }
      });
    })(req, res, next); // Ensure authenticate middleware is called with req, res, next
  }
);

// Dashboard data API (counts)
app.get("/api/user", requireLogin, async (req, res) => {
  try {
    const userInstitutionalRollno = req.user.rollno;
    const userEmail = req.user.college_email;

    const lostCount = await Item.countDocuments({
      $or: [
        { status: "lost", rollno: { $ne: userInstitutionalRollno } }, // Exclude current user's lost items from general count
        { status: "found", contact_email_sent: false, rollno: { $ne: userInstitutionalRollno } }, // Exclude current user's found items from general count
      ],
    });

    const foundCount = await Item.countDocuments({
      $or: [
        { status: "done", rollno: { $ne: userInstitutionalRollno } }, // Exclude current user's done items from general count
        { status: "found", contact_email_sent: true, rollno: { $ne: userInstitutionalRollno } }, // Exclude current user's contacted items from general count
      ],
    });

    const myReportsCount = await Item.countDocuments({ rollno: userInstitutionalRollno }); // Count items belonging to current user

    res.json({
      name: req.user.name,
      rollno: req.user.rollno, // Display the institutional rollno
      lostCount,
      foundCount,
      myReportsCount,
    });
  } catch (err) {
    logger.error("/api/user error:", { error: err.message, stack: err.stack });
    res.json({ error: "DB error" });
  }
});

// Dashboard page
app.get("/dashboard", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "dashboard.html"));
});

/* ---------------------------
   Report Lost / Found
   --------------------------- */
app.get("/report-lost", requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, "views/report-lost.html"))
);

app.post("/submit-lost", requireLogin, upload.single("photo"), async (req, res) => {
  const s = req.user;
  const {
    item_name,
    item_type,
    item_block,
    item_place,
    mobile_number,
    description,
    remarks,
  } = req.body;

  // Server-side validation
  if (item_name.length < 6) {
    return res.redirect("/report-lost?msg=Item Name must be at least 6 characters long.&type=error");
  }
  if (!/^[0-9]{10}$/.test(mobile_number)) {
    return res.redirect("/report-lost?msg=Mobile Number must be 10 digits only.&type=error");
  }

  const photo = req.file ? req.file.secure_url : null; // Handle single photo

  logger.info("Photo uploaded via Multer/Cloudinary:", { file: req.file });

  try {
    await Item.create({
      item_name,
      item_type,
      item_block,
      item_place,
      description,
      photo, // Store single photo
      remarks,
      status: "lost",
      initial_status: "lost", // Track initial status
      reporter: {
        rollno: s.rollno,
        name: s.name,
        email: s.college_email,
        mobile_number,
        email_sent: false,
      },
      // legacy duplicates for backward compatibility
      rollno: s.rollno,
      college_email: s.college_email,
      mobile_number,
      email_sent: false,
    });
    res.redirect("/dashboard?msg=Lost item reported successfully!&type=success");
  } catch (err) {
    logger.error("/submit-lost error:", { error: err.message, stack: err.stack });
    res.redirect("/report-lost?msg=Error saving lost item.&type=error");
  }
});

app.get("/report-found", requireLogin, (req, res) =>
  res.sendFile(path.join(__dirname, "views/report-found.html"))
);

app.post("/submit-found", requireLogin, upload.single("photo"), async (req, res) => {
  const s = req.user;
  const {
    item_name,
    item_type,
    item_block,
    item_place,
    mobile_number,
    description,
    remarks,
  } = req.body;

  // Server-side validation
  if (item_name.length < 6) {
    return res.redirect("/report-found?msg=Item Name must be at least 6 characters long.&type=error");
  }
  if (!/^[0-9]{10}$/.test(mobile_number)) {
    return res.redirect("/report-found?msg=Mobile Number must be 10 digits only.&type=error");
  }

  const photo = req.file ? req.file.secure_url : null; // Handle single photo

  logger.info("Photo uploaded via Multer/Cloudinary:", { file: req.file });

  try {
    await Item.create({
      item_name,
      item_type,
      item_block,
      item_place,
      description,
      photo, // Store single photo
      remarks,
      status: "found",
      initial_status: "found", // Track initial status
      reporter: {
        rollno: s.rollno,
        name: s.name,
        email: s.college_email,
        mobile_number,
        email_sent: false,
      },
      // legacy duplicates for backward compatibility
      rollno: s.rollno,
      college_email: s.college_email,
      mobile_number,
      contact_email_sent: false,
    });
    res.redirect("/dashboard?msg=Found item reported successfully!&type=success");
  } catch (err) {
    logger.error("/submit-found error:", { error: err.message, stack: err.stack });
    res.redirect("/report-found?msg=Error saving found item.&type=error");

  }
});

/* ---------------------------
   SEARCH: all reported items except current user
   --------------------------- */
app.get("/search", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/search.html"));
});

app.get("/search/data", requireLogin, async (req, res) => {
  try {
    const currentUserInstitutionalRollno = req.user.rollno; // Use institutional rollno
    const results = await Item.find({ rollno: { $ne: currentUserInstitutionalRollno } }).sort({ date_reported: -1 }).lean();

    const maskedData = results.map((r) => ({
      _id: r._id,
      item_name: r.item_name,
      item_type: r.item_type,
      item_block: r.item_block,
      item_place: r.item_place,
      mobile_number: r.mobile_number ? r.mobile_number.replace(/.(?=.{4})/g, "*") : "N/A",
      college_email: r.college_email ? r.college_email.replace(/.(?=.{4})/g, "*") : "N/A",
      description: r.description,
      photo: r.photo || "",
      remarks: r.remarks,
      status: r.status,
      email_sent: r.email_sent,
      contact_email_sent: r.contact_email_sent,
    }));

    res.json(maskedData);
  } catch (err) {
    logger.error("/search/data error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "DB error" });
  }
});

/* ---------------------------
   MY REPORTS
   --------------------------- */
app.get("/my-reports", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/my-reports.html"));
});

app.get("/my-reports/data", requireLogin, async (req, res) => {
  try {
    const userInstitutionalRollno = req.user.rollno; // Use institutional rollno
    const results = await Item.find({ rollno: userInstitutionalRollno }).sort({ date_reported: -1 }).lean();
    res.json(results);
  } catch (err) {
    logger.error("/my-reports/data error:", { error: err.message, stack: err.stack });
    res.status(500).json([]);
  }
});

app.post("/update-item/:id", requireLogin, upload.single("photo"), async (req, res) => {
  try {
    const itemId = req.params.id;
    const currentUserInstitutionalRollno = req.user.rollno; // Use institutional rollno for ownership check
    const { item_name, item_type, item_block, item_place, description, remarks } = req.body;
    const newPhoto = req.file ? req.file.path : null; // Handle single photo

    const updateData = { item_name, item_type, item_block, item_place, description, remarks };

    // If a new photo is uploaded, replace existing photo
    if (newPhoto) {
      updateData.photo = newPhoto;
    }

    const result = await Item.updateOne({ _id: itemId, rollno: currentUserInstitutionalRollno }, { $set: updateData }); // Filter by institutional rollno

    if (result.matchedCount === 0) {
      return res.json({ success: false, message: "Item not found or unauthorized" });
    }

    res.json({ success: true, message: "Report updated successfully!" });
  } catch (err) {
    logger.error("/update-item error:", { error: err.message, stack: err.stack });
    res.json({ success: false, message: "Error updating item." });
  }
});

/* ---------------------------
   DELETE ITEM
   --------------------------- */
app.delete("/delete-item/:id", requireLogin, async (req, res) => {
  try {
    const itemId = req.params.id;
    const currentUserInstitutionalRollno = req.user.rollno;
    
    logger.info(`Attempting to delete item. ID: ${itemId}, User Roll No: ${currentUserInstitutionalRollno}`);
    
    if (!itemId || itemId === "undefined") {
      return res.status(400).json({ message: "Invalid item ID" });
    }
    
    // Log the item before attempting to delete to verify rollno
    const itemToDelete = await Item.findById(itemId).lean();
    if (itemToDelete) {
      logger.info(`Found item in DB for deletion check: ID: ${itemToDelete._id}, DB Roll No: ${itemToDelete.rollno}`);
    } else {
      logger.warn(`Item not found in DB for deletion check: ${itemId}`);
    }
    
    const result = await Item.deleteOne({ _id: itemId, rollno: currentUserInstitutionalRollno });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Item not found or unauthorized" });
    }
    
    res.json({ message: "Item deleted successfully!" });
  } catch (err) {
    logger.error("/delete-item error:", { error: err.message, stack: err.stack });
    res.status(500).json({ message: "Error deleting item." });
  }
});


/* ---------------------------
   EDIT ITEM (serve page + data)
   --------------------------- */
app.get("/edit-item/:id", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/edit-report.html"));
});

app.get("/edit-item/:id/data", requireLogin, async (req, res) => {
  try {
    const itemId = req.params.id;
    const currentUserInstitutionalRollno = req.user.rollno; // Use institutional rollno for ownership check

    let item;
    // Check if the logged-in user is the super admin
    if (req.user.college_email === "bitlostfoundportal@gmail.com") {
      item = await Item.findById(itemId).lean(); // Super admin can fetch any item without ownership check
    } else {
      item = await Item.findOne({ _id: itemId, rollno: currentUserInstitutionalRollno }).lean(); // Regular user: Filter by institutional rollno
    }

    if (!item) return res.status(404).json({ error: "Item not found or unauthorized" });

    res.json(item);
  } catch (err) {
    logger.error("/edit-item/:id/data error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "DB error" });
  }
});

/* ---------------------------
   MARK FOUND (notify owners)
   --------------------------- */
app.post("/mark-found/:id", requireLogin, async (req, res) => {
  const itemId = req.params.id;
  const currentUser = req.user;
  const currentUserEmail = currentUser.college_email;

  try {
    const foundItem = await Item.findById(itemId).lean();
    if (!foundItem) return res.json({ success: false, message: "Item not found." });


    const photoUrl = foundItem.photo || null;


    // Find lost items of same item_name and attach student info
    const lostItems = await Item.aggregate([
      { $match: { item_name: foundItem.item_name, status: "lost" } },
      {
        $lookup: {
          from: "students",
          localField: "rollno", // Match item.rollno with student.rollno
          foreignField: "rollno",
          as: "owner_info",
        },
      },
      { $unwind: { path: "$owner_info", preserveNullAndEmptyArrays: true } },
    ]);

    let emailLog = [];

    for (const lost of lostItems) {
      const ownerEmail = lost.college_email;
      const ownerName = lost.owner_info?.name || "Unknown";

      // Email to owner
      const mailOwner = {
        from: EMAIL_USER,
        to: ownerEmail,
        subject: `Your lost item has been found: ${foundItem.item_name}`,
        html: generateEmail("found_report_owner", {
          item: foundItem,
          owner_name: ownerName,
          owner_email: ownerEmail,
          finder_name: currentUser.name,
          finder_rollno: currentUser.rollno,
          finder_email: currentUserEmail,
          photo: photoUrl,
        }),
      };

      // Email to finder (the currentUser)
      const mailFinder = {
        from: EMAIL_USER,
        to: currentUserEmail,
        subject: `Lost item match found: ${foundItem.item_name}`,
        html: generateEmail("found_report_identifier", {
          item: foundItem,
          owner_name: ownerName,
          owner_email: ownerEmail,
          finder_name: currentUser.name,
          finder_rollno: currentUser.rollno,
          finder_email: currentUserEmail,
          photo: photoUrl,
        }),
      };

      try {
        await transporter.sendMail(mailOwner);
        emailLog.push(`✅ Owner email sent to ${ownerEmail}`);
      } catch (err) {
        emailLog.push(`❌ Owner email failed: ${ownerEmail}`);
        logger.error("sendMail owner error:", err);
      }

      try {
        await transporter.sendMail(mailFinder);
        emailLog.push(`✅ Finder email sent to ${currentUserEmail}`);
      } catch (err) {
        emailLog.push(`❌ Finder email failed: ${currentUserEmail}`);
        logger.error("sendMail finder error:", err);
      }
    }

    // Update found item status and store contactor info
    await Item.updateOne({ _id: itemId }, {
      $set: { 
        status: "done", 
        found_by: currentUser.rollno, 
        found_date: new Date(), 
        email_sent: true,
        contactor: {
          rollno: currentUser.rollno,
          name: currentUser.name,
          email: currentUserEmail,
          email_sent: true
        }
      },
    });

    res.json({ success: true, message: "Item marked DONE! Emails sent." });
  } catch (err) {
    logger.error("/mark-found error:", { error: err.message, stack: err.stack });
    res.json({ success: false, message: "Failed to mark item as done or send emails." });
  }
});

/* ---------------------------
   IMAGE ACCESS HANDLER
   --------------------------- */
// If the photo is a Cloudinary URL, serve it directly.
// Otherwise, serve it from local /uploads folder for backward compatibility.
app.get("/uploads/:file", (req, res, next) => {
  const imageUrl = decodeURIComponent(req.params.file);
  if (imageUrl.startsWith("https://res.cloudinary.com")) {
    return res.redirect(imageUrl);
  } else {
    return res.sendFile(path.join(__dirname, "public/uploads", imageUrl), (err) => {
      if (err) next();
    });
  }
});





/* ---------------------------
   SEND CONTACT (finder contacts owner)
   --------------------------- */
app.post("/send-contact", requireLogin, async (req, res) => {
  const { itemId } = req.body;
  const currentUser = req.user;
  const currentUserEmail = currentUser.college_email;

  try {
    // Get item + owner info via aggregate
    const results = await Item.aggregate([
      { $match: { _id: new mongoose.Types.ObjectId(itemId) } },
      {
        $lookup: {
          from: "students",
          localField: "rollno", // Match item.rollno with student.rollno
          foreignField: "rollno",
          as: "owner_info",
        },
      },
      { $unwind: { path: "$owner_info", preserveNullAndEmptyArrays: true } },
    ]);

    if (!results.length) return res.json({ success: false, message: "Item not found." });


    const foundItem = results[0];
    const ownerEmail = foundItem.college_email;
    const ownerName = foundItem.owner_info?.name || "Unknown";
    const photoUrl = foundItem.photo || null;


    // Mail to owner
    const mailToOwner = {
      from: EMAIL_USER,
      to: ownerEmail,
      subject: `Contact request: ${foundItem.item_name}`,
      html: generateEmail("contact_request_owner_only", {
        item: foundItem,
        owner_name: ownerName,
        owner_email: ownerEmail,
        finder_name: currentUser.name,
        finder_rollno: currentUser.rollno,
        finder_email: currentUserEmail,
        photo: photoUrl,
      }),
    };

    // Mail to finder as confirmation
    const mailToFinder = {
      from: EMAIL_USER,
      to: currentUserEmail,
      subject: `You contacted about item: ${foundItem.item_name}`,
      html: generateEmail("contact_request_finder_only", {
        item: foundItem,
        owner_name: ownerName,
        owner_email: ownerEmail,
        finder_name: currentUser.name,
        finder_rollno: currentUser.rollno,
        finder_email: currentUserEmail,
        photo: photoUrl,
      }),
    };

    let emailLog = [];
    try {
      await transporter.sendMail(mailToOwner);
      emailLog.push(`✅ Owner email sent to ${ownerEmail}`);
    } catch (err) {
      emailLog.push(`❌ Owner email failed: ${ownerEmail}`);
      logger.error("send-contact owner email error:", err);
    }

    try {
      await transporter.sendMail(mailToFinder);
      emailLog.push(`✅ Finder email sent to ${currentUserEmail}`);
    } catch (err) {
      emailLog.push(`❌ Finder email failed: ${currentUserEmail}`);
      logger.error("send-contact finder email error:", err);
    }

    // Update DB flag contact_email_sent, mark status as Contacted, and store contactor info
    await Item.updateOne({ _id: itemId }, { 
      $set: { 
        contact_email_sent: true, 
        status: "Contacted",
        found_date: new Date(), // Set found_date when contact is sent
        contactor: {
          rollno: currentUser.rollno,
          name: currentUser.name,
          email: currentUserEmail,
          email_sent: true
        },
        // Update legacy field for backward compatibility
        found_by: currentUser.rollno
      } 
    });

    res.json({ success: true, message: "Contact emails sent successfully!" });
  } catch (err) {
    logger.error("/send-contact error:", { error: err.message, stack: err.stack });
    res.json({ success: false, message: "Error sending contact email." });
  }
});

/* ---------------------------
   LOGOUT
   --------------------------- */
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Admin route - accessible only by a specific email
function requireSuperAdmin(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect("/?msg=Please login first.&type=error");
  }
  // Check for the specific admin email
  if (req.user.college_email === "bitlostfoundportal@gmail.com") {
    return next();
  }
  res.redirect("/dashboard?msg=Unauthorized access to admin page.&type=error");
}

app.get("/admin", requireLogin, requireSuperAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/admin.html"));
});

// Admin Edit Item Page
app.get("/admin/edit-item/:id", requireLogin, requireSuperAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/admin-edit-item.html"));
});

// Admin Manage Items Page
app.get("/admin/manage-items", requireLogin, requireSuperAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/admin-manage-items.html"));
});

// Admin Manage Students Page
app.get("/admin/manage-students", requireLogin, requireSuperAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/admin-manage-students.html"));
});

// Admin Add Student Page
app.get("/admin/add-student", requireLogin, requireSuperAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/admin-add-student.html"));
});

// Admin Edit Student Page
app.get("/admin/edit-student/:id", requireLogin, requireSuperAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/admin-edit-student.html"));
});

// Admin API to create a new student
app.post("/api/admin/student", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const { rollno, name, college_email, google_display_name, password } = req.body;

    // Validate required fields
    if (!rollno || !name) {
      return res.status(400).json({ success: false, message: "Roll No. and Name are required fields." });
    }

    // Check if rollno already exists
    const existingRollno = await Student.findOne({ rollno });
    if (existingRollno) {
      return res.status(400).json({ success: false, message: "A student with this Roll No. already exists." });
    }

    // Check if college_email already exists (if provided)
    if (college_email) {
      const existingEmail = await Student.findOne({ college_email });
      if (existingEmail) {
        return res.status(400).json({ success: false, message: "A student with this College Email already exists." });
      }
    }

    // Create student data object
    const studentData = {
      rollno,
      name,
    };

    // Add optional fields if provided
    if (college_email) {
      studentData.college_email = college_email;
    }
    if (google_display_name) {
      studentData.google_display_name = google_display_name;
    }
    if (password) {
      studentData.password = password; // Will be hashed by the pre-save hook
    }

    // Create the student
    const newStudent = await Student.create(studentData);

    res.json({ success: true, message: "Student created successfully!", studentId: newStudent._id });
  } catch (err) {
    logger.error("/api/admin/student (POST) error:", { error: err.message, stack: err.stack });
    
    // Handle duplicate key errors
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      return res.status(400).json({ 
        success: false, 
        message: `A student with this ${field === 'rollno' ? 'Roll No.' : 'College Email'} already exists.` 
      });
    }
    
    res.status(500).json({ success: false, message: "Error creating student by admin." });
  }
});

// Admin API to update a specific student
app.put("/api/admin/student/:id", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const studentId = req.params.id;
    const { rollno, name, college_email } = req.body;
    const google_display_name = req.body.google_display_name; // Get new google_display_name

    const updateData = { rollno, name, college_email };
    if (google_display_name !== undefined) {
      updateData.google_display_name = google_display_name; // Add to updateData if provided
    }

    const result = await Student.updateOne({ _id: studentId }, { $set: updateData });

    if (result.matchedCount === 0) {
      return res.json({ success: false, message: "Student not found." });
    }

    res.json({ success: true, message: "Student updated successfully by admin!" });
  } catch (err) {
    logger.error("/api/admin/student/:id (PUT) error:", { error: err.message, stack: err.stack });
    res.status(500).json({ success: false, message: "Error updating student by admin." });
  }
});

/* ---------------------------
   ADMIN API ENDPOINTS
   --------------------------- */
// Admin API to get all reports (bypasses user-specific filters)
app.get("/api/admin/reports", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 100;
    const searchTerm = req.query.searchTerm || '';
    const skip = (page - 1) * limit;

    let query = {};
    if (searchTerm) {
      const searchRegex = new RegExp(searchTerm, 'i'); // Case-insensitive search
      query = {
        $or: [
          { item_name: searchRegex },
          { item_type: searchRegex },
          { rollno: searchRegex },
          { reporter_name: searchRegex },
          { reporter_email: searchRegex }
        ],
      };
    }

    const totalReports = await Item.countDocuments(query);
    const reports = await Item.aggregate([
      { $match: query }, // Apply search filter
      {
        $lookup: {
          from: "students", // The collection to join with for reporter info
          localField: "rollno", // Field from the Item collection
          foreignField: "rollno", // Field from the Student collection
          as: "reporter_info" // Output array field
        }
      },
      {
        $lookup: {
          from: "students", // The collection to join with for found_by info
          localField: "found_by", // Field from the Item collection
          foreignField: "rollno", // Field from the Student collection
          as: "found_by_info" // Output array field
        }
      },
      {
        $lookup: {
          from: "students", // The collection to join with for contactor info
          localField: "contactor.rollno", // Field from the Item collection's contactor object
          foreignField: "rollno", // Field from the Student collection
          as: "contactor_info" // Output array field
        }
      },
      {
        $addFields: {
          reporter_info: { $arrayElemAt: ["$reporter_info", 0] }, // Deconstruct the array to a single object
          found_by_info: { $arrayElemAt: ["$found_by_info", 0] }, // Deconstruct the array to a single object
          contactor_info: { $arrayElemAt: ["$contactor_info", 0] } // Deconstruct the array to a single object
        }
      },
      {
        $project: {
          _id: 1,
          item_name: 1,
          item_type: 1,
          item_block: 1,
          item_place: 1,
          rollno: 1,
          mobile_number: 1,
          description: 1,
          photo: 1,
          remarks: 1,
          status: 1,
          initial_status: {
            $ifNull: ["$initial_status", {
              $cond: {
                if: { $in: ["$status", ["lost", "found"]] },
                then: "$status",
                else: "lost" // Default fallback for old items
              }
            }]
          },
          email_sent: 1,
          contact_email_sent: 1,
          // Use found_by from legacy field, or fallback to contactor.rollno
          found_by: {
            $ifNull: ["$found_by", "$contactor.rollno"]
          },
          // Use found_by_name from lookup, or fallback to contactor.name, or contactor_info.name
          found_by_name: {
            $ifNull: [
              "$found_by_info.name",
              {
                $ifNull: [
                  "$contactor.name",
                  "$contactor_info.name"
                ]
              }
            ]
          },
          found_date: 1,
          date_reported: 1,
          reporter_name: "$reporter_info.name", // Add reporter's name from student collection
          reporter_email: "$reporter_info.college_email", // Add reporter's email from student collection
          // Use contactor.email, or fallback to contactor.college_email, or contactor_info.college_email
          contact_email: {
            $ifNull: [
              "$contactor.email",
              {
                $ifNull: [
                  "$contactor.college_email",
                  "$contactor_info.college_email"
                ]
              }
            ]
          },
        }
      }
    ])
    .sort({ date_reported: -1 })
    .skip(skip)
    .limit(limit);

    res.json({ reports, totalReports, currentPage: page, totalPages: Math.ceil(totalReports / limit) });
  } catch (err) {
    logger.error("/api/admin/reports error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Failed to fetch all reports for admin", reports: [], totalReports: 0, currentPage: page, totalPages: 0 });
  }
});

// Admin API to get data for a specific item (bypasses ownership check)
app.get("/api/admin/item/:id/data", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const itemId = req.params.id;
    const item = await Item.findById(itemId).lean(); // No ownership check
    if (!item) return res.status(404).json({ error: "Item not found" });
    res.json(item);
  } catch (err) {
    logger.error("/api/admin/item/:id/data error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "DB error" });
  }
});

// Admin API to update a specific item (bypasses ownership check)
app.put("/api/admin/item/:id", requireLogin, requireSuperAdmin, upload.single("photo"), async (req, res) => {
  try {
    const itemId = req.params.id;
    const { item_name, item_type, item_block, item_place, description, remarks, status } = req.body; // Added status for admin control
    const newPhoto = req.file ? req.file.path : null;

    const updateData = { item_name, item_type, item_block, item_place, description, remarks, status };
    if (newPhoto) updateData.photo = newPhoto;

    const result = await Item.updateOne({ _id: itemId }, { $set: updateData }); // No ownership check

    if (result.matchedCount === 0) {
      return res.json({ success: false, message: "Item not found." });
    }

    res.json({ success: true, message: "Item updated successfully by admin!" });
  } catch (err) {
    logger.error("/api/admin/item/:id (PUT) error:", { error: err.message, stack: err.stack });
    res.status(500).json({ success: false, message: "Error updating item by admin." });
  }
});

// Admin API to delete a specific item (bypasses ownership check)
app.delete("/api/admin/item/:id", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const itemId = req.params.id;

    if (!itemId || itemId === "undefined") {
      return res.status(400).json({ message: "Invalid item ID" });
    }

    const result = await Item.deleteOne({ _id: itemId }); // No ownership check
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Item not found" });
    }

    res.json({ message: "Item deleted successfully by admin!" });
  } catch (err) {
    logger.error("/api/admin/item/:id (DELETE) error:", { error: err.message, stack: err.stack });
    res.status(500).json({ message: "Error deleting item by admin." });
  }
});

// Admin API to get all students
app.get("/api/admin/students", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1; // Default to page 1
    const limit = parseInt(req.query.limit) || 100; // Default to 100 students per page
    const searchTerm = req.query.searchTerm || ''; // Get search term from query
    const skip = (page - 1) * limit;

    let query = {};
    if (searchTerm) {
      const searchRegex = new RegExp(searchTerm, 'i'); // Case-insensitive search
      query = {
        $or: [
          { rollno: searchRegex },
          { name: searchRegex },
          { college_email: searchRegex },
        ],
      };
    }

    const students = await Student.find(query)
      .skip(skip)
      .limit(limit)
      .lean();

    const studentsWithEmailName = students.map(student => {
        const emailNameMatch = student.college_email.match(/^([^@]+)/);
        const nameFromEmail = emailNameMatch ? emailNameMatch[1].replace(/\./g, ' ').replace(/\d/g, '').trim() : '';
        // Simple normalization: convert to lower case and remove extra spaces for comparison
        const normalizedNameDb = student.name ? student.name.toLowerCase().replace(/\s+/g, ' ') : '';
        const normalizedNameFromEmail = student.google_display_name ? student.google_display_name.toLowerCase().replace(/\s+/g, ' ') : '';
        
        return {
            ...student,
            name_from_email: nameFromEmail,
            names_match: normalizedNameDb === normalizedNameFromEmail
        };
    });

    const totalStudents = await Student.countDocuments(query); // Count documents matching the search query

    res.json({ students: studentsWithEmailName, totalStudents, currentPage: page, totalPages: Math.ceil(totalStudents / limit) });
  } catch (err) {
    logger.error("/api/admin/students error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Failed to fetch all student data for admin" });
  }
});

// Admin API to get data for a specific student (bypasses ownership check)
app.get("/api/admin/student/:id/data", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const studentId = req.params.id;
    const student = await Student.findById(studentId).lean();
    if (!student) return res.status(404).json({ error: "Student not found" });

    const emailNameMatch = student.college_email.match(/^([^@]+)/);
    const nameFromEmail = emailNameMatch ? emailNameMatch[1].replace(/\./g, ' ').replace(/\d/g, '').trim() : '';

    const normalizedNameDb = student.name ? student.name.toLowerCase().replace(/\s+/g, ' ') : '';
    const normalizedNameFromEmail = student.google_display_name ? student.google_display_name.toLowerCase().replace(/\s+/g, ' ') : '';

    const studentWithDerivedData = {
        ...student,
        name_from_email: nameFromEmail, // This is still the derived name from the email string
        names_match: normalizedNameDb === normalizedNameFromEmail // Now compares DB name with Google Display Name
    };

    res.json(studentWithDerivedData);
  } catch (err) {
    logger.error("/api/admin/student/:id/data error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "DB error" });
  }
});

// Admin API to delete a specific student
app.delete("/api/admin/student/:id", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const studentId = req.params.id;

    if (!studentId || studentId === "undefined") {
      return res.status(400).json({ message: "Invalid student ID" });
    }

    const result = await Student.deleteOne({ _id: studentId });
    if (result.deletedCount === 0) {
      return res.status(404).json({ message: "Student not found" });
    }

    res.json({ message: "Student deleted successfully by admin!" });
  } catch (err) {
    logger.error("/api/admin/student/:id (DELETE) error:", { error: err.message, stack: err.stack });
    res.status(500).json({ message: "Error deleting student by admin." });
  }
});

// Admin API to get total reports count
app.get("/api/admin/reports-count", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const totalCount = await Item.countDocuments();
    // Count by exact status values
    const lostCount = await Item.countDocuments({ status: "lost" });
    const foundCount = await Item.countDocuments({ status: "found" });
    // Resolved Reports = items with status "Contacted"
    const doneCount = await Item.countDocuments({ status: "Contacted" });

    res.json({ totalCount, lostCount, foundCount, doneCount });
  } catch (err) {
    logger.error("/api/admin/reports-count error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Failed to fetch reports count" });
  }
});

// Admin API to get total students count
app.get("/api/admin/students-count", requireLogin, requireSuperAdmin, async (req, res) => {
  try {
    const count = await Student.countDocuments();
    res.json({ count });
  } catch (err) {
    logger.error("/api/admin/students-count error:", { error: err.message, stack: err.stack });
    res.status(500).json({ error: "Failed to fetch students count" });
  }
});

/* ---------------------------
   EMAIL TEMPLATE GENERATOR (unchanged logic)
   --------------------------- */
const emailTemplates = {};

// Load email templates
function loadEmailTemplates() {
  const templatesDir = path.join(__dirname, "views", "emails");
  fs.readdirSync(templatesDir).forEach(file => {
    if (file.endsWith(".html")) {
      const templateName = file.replace(".html", "");
      emailTemplates[templateName] = fs.readFileSync(path.join(templatesDir, file), "utf8");
      logger.info(`Loaded email template: ${templateName}`);
    }
  });
}

// Load templates on startup
loadEmailTemplates();

function generateEmail(templateType, data) {
  const safe = (val) => val || "N/A";

  // Item details
  const item = data.item || {};
  const itemName = safe(item.item_name || data.item_name);
  const itemType = safe(item.item_type);
  const itemBlock = safe(item.item_block);
  const itemPlace = safe(item.item_place);
  const description = safe(item.description);
  const remarks = safe(item.remarks);
  const photoUrl = data.photo || item.photo || null;

  // Owner details
  const ownerName = safe(data.owner_name);
  const ownerRoll = safe(data.owner_rollno);
  const ownerEmail = safe(data.owner_email);

  // Finder details
  const finderName = safe(data.finder_name);
  const finderRoll = safe(data.finder_rollno);
  const finderEmail = safe(data.finder_email);

  // Photo HTML
  const photoHtml = photoUrl
    ? `<p><b>Photo of the Item:</b><br><img src="${photoUrl}" style="max-width:250px;border-radius:8px;border:1px solid #ccc;"/></p>`
    : `<p><b>Photo of the Item:</b> No photo available</p>`;

  // Prepare data for template replacement
  const templateData = {
    item_name: itemName,
    item_type: itemType,
    item_block: itemBlock,
    item_place: itemPlace,
    description: description,
    remarks: remarks,
    photo_html: photoHtml,
    owner_name: ownerName,
    owner_rollno: ownerRoll,
    owner_email: ownerEmail,
    finder_name: finderName,
    finder_rollno: finderRoll,
    finder_email: finderEmail,
  };

  let template = emailTemplates[templateType];

  if (!template) {
    logger.error(`Email template not found: ${templateType}`);
    return `<p>Error: Email template not found for ${templateType}</p>`;
  }

  // Simple string replacement for template variables
  for (const key in templateData) {
    template = template.replace(new RegExp(`{{${key}}}`, "g"), templateData[key]);
  }

  return template;
}
// Example: Public endpoint for sheet sync
app.get("/api/all-reports", async (req, res) => {
  try {
    const reports = await Item.find().lean();
    res.json(reports);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch reports" });
  }
});

/* ---------------------------
   Start Server
   --------------------------- */
// ---- Healthcheck ----
app.get("/health", async (req, res) => {
  try {
    const mongoState = mongoose.connection.readyState; // 1 = connected
    res.json({ status: "ok", mongo: mongoState === 1 ? "connected" : "disconnected" });
  } catch (err) {
    res.status(500).json({ status: "error" });
  }
});

// centralized error handler
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  logger.error("Unhandled error", { 
    status: statusCode, 
    message: err.message, 
    stack: process.env.NODE_ENV === "production" ? "(production stack hidden)" : err.stack,
    path: req.path,
    method: req.method,
    ip: req.ip,
  });

  // Respond to the client
  if (process.env.NODE_ENV === "production") {
    res.status(statusCode).json({ error: "Internal Server Error" });
  } else {
    res.status(statusCode).json({ error: err.message, stack: err.stack });
  }
});

// graceful shutdown
const server = app.listen(process.env.PORT || 3000, () => {
  logger.info(`🚀 Server running at http://localhost:${process.env.PORT || 3000}`);
});

function gracefulShutdown(signal) {
  logger.info(`Received ${signal}, shutting down gracefully...`);
  server.close(async () => {
    logger.info("HTTP server closed.");
    try {
      await mongoose.disconnect();
      logger.info("MongoDB disconnected.");
      process.exit(0);
    } catch (err) {
      logger.error("Error during shutdown", { error: err.message });
      process.exit(1);
    }
  });

  setTimeout(() => {
    logger.error("Forcing shutdown...");
    process.exit(1);
  }, 30000); // force exit after 30s
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

// Set Node.js to development by default
process.env.NODE_ENV = process.env.NODE_ENV || 'development';
