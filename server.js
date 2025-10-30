// server.js
const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const nodemailer = require("nodemailer");
const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: "secret_key",
    resave: false,
    saveUninitialized: true,
  })
);

// --- Nodemailer transporter ---
const EMAIL_USER =  "bitlostfoundportal@gmail.com";
const EMAIL_PASS =  "voxm znht xtkq azus";
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
  tls: { rejectUnauthorized: false },
});

// --- Multer for uploads ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "./public/uploads"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage: storage });

// --- MySQL connection ---
const db = mysql.createConnection({
  host: "sql100.infinityfree.com",            // InfinityFree MySQL Host
  user: "if0_40286640",                      // InfinityFree MySQL Username
  password: "Vasanth51575",              // 🔒 Replace with your actual MySQL password
  database: "if0_40286640_bitlostfound_db",  // Your InfinityFree database name
  port: 3306                                 // Default MySQL port
});

db.connect((err) => {
  if (err) {
    console.error("❌ MySQL connect error:", err);
    process.exit(1);
  }
  console.log("✅ MySQL Connected");
});

// --- Require login middleware ---
function requireLogin(req, res, next) {
  if (!req.session.student) {
    return res.send("<h3>❌ Please login first.</h3><a href='/'>Go Back</a>");
  }
  next();
}

// --- Routes ---
// Login page
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "views/login.html")));

app.post("/login", (req, res) => {
  const { rollno, name, college_email } = req.body;
  if (!rollno || !name || !college_email) {
    return res.send("<h3>❌ All fields are required.</h3><a href='/'>Go Back</a>");
  }

  db.query(
    "SELECT * FROM students WHERE rollno = ? AND name = ?",
    [rollno, name],
    (err, results) => {
      if (err) return res.send("<h3>⚠️ DB error.</h3><a href='/'>Go Back</a>");
      if (results.length === 0)
        return res.send("<h3>❌ Roll number or name do not match.</h3><a href='/'>Go Back</a>");

      req.session.student = { ...results[0], college_email };
      res.redirect("/dashboard");
    }
  );
});
app.get("/api/user", requireLogin, (req, res) => {
  const roll = req.session.student.rollno;

  // Lost items not yet contacted
  db.query(
    "SELECT COUNT(*) AS lostCount FROM lost_found_items WHERE (status='lost' OR (status='found' AND contact_email_sent=0))",
    [roll],
    (err, lostRes) => {
      if (err) return res.json({ error: "DB error" });

      // Found items with emails sent
      db.query(
        "SELECT COUNT(*) AS foundCount FROM lost_found_items WHERE (status='done' OR (status='found' AND contact_email_sent=1))",
        [roll],
        (err, foundRes) => {
          if (err) return res.json({ error: "DB error" });

          // All reports by this user
          db.query(
            "SELECT COUNT(*) AS myReportsCount FROM lost_found_items WHERE rollno = ?",
            [roll],
            (err, reportsRes) => {
              if (err) return res.json({ error: "DB error" });

              res.json({
                name: req.session.student.name,
                rollno: roll,
                lostCount: lostRes[0].lostCount,
                foundCount: foundRes[0].foundCount,
                myReportsCount: reportsRes[0].myReportsCount
              });
            }
          );
        }
      );
    }
  );
});




// Dashboard page
app.get("/dashboard", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views", "dashboard.html"));
});


// Report Lost
app.get("/report-lost", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "views/report-lost.html")));

app.post("/submit-lost", requireLogin, upload.single("photo"), (req, res) => {
  const s = req.session.student;
  const { item_name, item_type, item_block, item_place, mobile_number, college_email, description, remarks } = req.body;
  const photo = req.file ? req.file.filename : null;

  const sql = `INSERT INTO lost_found_items 
  (rollno, item_name, item_type, item_block, item_place, mobile_number, college_email, description, photo, remarks, status) 
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'lost')`;

  db.query(sql, [s.rollno, item_name, item_type, item_block, item_place, mobile_number, college_email, description, photo, remarks], (err) => {
    if (err) return res.send("DB insert error");
    res.send("<h3>✅ Lost item reported successfully!</h3><a href='/dashboard'>Go Back</a>");
  });
});

// Report Found
app.get("/report-found", requireLogin, (req, res) => res.sendFile(path.join(__dirname, "views/report-found.html")));

app.post("/submit-found", requireLogin, upload.single("photo"), (req, res) => {
  const s = req.session.student;
  const { item_name, item_type, item_block, item_place, mobile_number, college_email, description, remarks } = req.body;
  const photoUrl = req.file ? `${req.protocol}://${req.get("host")}/uploads/${req.file.filename}` : null;

  const sqlInsert = `INSERT INTO lost_found_items 
  (rollno, item_name, item_type, item_block, item_place, mobile_number, college_email, description, photo, remarks, status)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'found')`;

  db.query(sqlInsert, [s.rollno, item_name, item_type, item_block, item_place, mobile_number, college_email, description, req.file ? req.file.filename : null, remarks], (err, result) => {
    if (err) return res.send("<h3>⚠️ DB insert error</h3>");

    res.send("<h3>✅ Found item reported successfully!</h3><a href='/dashboard'>Go Back</a>");
  });
});

// Serve search.html
app.get("/search", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/search.html"));
});

// API endpoint to get all reported items
app.get("/search/data", requireLogin, (req, res) => {
  const currentUserRoll = req.session.student.rollno;

  db.query(
    "SELECT * FROM lost_found_items WHERE rollno <> ? ORDER BY date_reported DESC",
    [currentUserRoll],
    (err, results) => {
      if (err) return res.status(500).json({ error: "DB error" });

      const maskedData = results.map(r => ({
        item_id: r.item_id,
        item_name: r.item_name,
        item_type: r.item_type,
        item_block: r.item_block,
        item_place: r.item_place,
        mobile_number: r.mobile_number ? r.mobile_number.replace(/.(?=.{4})/g, "*") : "N/A",
        college_email: r.college_email ? r.college_email.replace(/.(?=.{4})/g, "*") : "N/A",
        description: r.description,
        photo: r.photo ? `/uploads/${r.photo}` : "",
        remarks: r.remarks,
        status: r.status,
        email_sent: r.email_sent,
        contact_email_sent: r.contact_email_sent
      }));

      res.json(maskedData);
    }
  );
});


// --- My Reports Page ---
app.get("/my-reports", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/my-reports.html"));
});

// My Reports JSON data
app.get("/my-reports/data", requireLogin, (req, res) => {
  const roll = req.session.student.rollno;
  db.query("SELECT * FROM lost_found_items WHERE rollno = ? ORDER BY date_reported DESC", [roll], (err, results) => {
    if(err) return res.status(500).json([]);
    res.json(results);
  });
});

//update-item
app.post("/update-item/:id", requireLogin, upload.single("photo"), (req, res) => {
  const itemId = req.params.id;
  const currentRoll = req.session.student.rollno;
  const { item_name, item_type, item_block, item_place, description, remarks } = req.body;
  const newPhoto = req.file ? req.file.filename : null;

  const updateQuery = newPhoto
    ? `UPDATE lost_found_items 
       SET item_name=?, item_type=?, item_block=?, item_place=?, description=?, remarks=?, photo=? 
       WHERE item_id=? AND rollno=?`
    : `UPDATE lost_found_items 
       SET item_name=?, item_type=?, item_block=?, item_place=?, description=?, remarks=? 
       WHERE item_id=? AND rollno=?`;

  const params = newPhoto
    ? [item_name, item_type, item_block, item_place, description, remarks, newPhoto, itemId, currentRoll]
    : [item_name, item_type, item_block, item_place, description, remarks, itemId, currentRoll];

  db.query(updateQuery, params, (err, result) => {
    if (err) return res.status(500).json({ success: false, message: "DB error while updating item." });
    res.json({ success: true, message: "✅ Report updated successfully!" });
  });
});


// delete-item
app.delete("/delete-item/:id", requireLogin, (req, res) => {
  const itemId = req.params.id;
  const currentRoll = req.session.student.rollno;

  db.query(
    "DELETE FROM lost_found_items WHERE item_id = ? AND rollno = ?",
    [itemId, currentRoll],
    (err, result) => {
      if (err)
        return res.json({ success: false, message: "DB error while deleting" });
      if (result.affectedRows === 0)
        return res.json({ success: false, message: "Item not found" });
      res.json({ success: true, message: "✅ Item deleted successfully!" });
    }
  );
});

// Serve the HTML file
app.get("/edit-item/:id", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "views/edit-report.html"));
});

// Serve the item data as JSON for the form
app.get("/edit-item/:id/data", requireLogin, (req, res) => {
  const itemId = req.params.id;
  const currentRoll = req.session.student.rollno;

  db.query(
    "SELECT * FROM lost_found_items WHERE item_id = ? AND rollno = ?",
    [itemId, currentRoll],
    (err, results) => {
      if (err || results.length === 0) return res.status(404).json({ error: "Item not found" });
      res.json(results[0]);
    }
  );
});

// --- Mark Found Route ---
app.post("/mark-found/:id", requireLogin, async (req, res) => {
  const itemId = req.params.id;
  const currentUser = req.session.student;
  const currentUserEmail = currentUser.college_email;

  try {
    // Get found item details
    const foundItem = await new Promise((resolve, reject) => {
      db.query("SELECT * FROM lost_found_items WHERE item_id = ?", [itemId], (err, rows) => {
        if (err) return reject(err);
        if (!rows.length) return reject(new Error("Item not found"));
        resolve(rows[0]);
      });
    });

    const photoUrl = foundItem.photo ? `${req.protocol}://${req.get("host")}/uploads/${foundItem.photo}` : null;

    // Find lost items with same name and get owner name from students table
    const lostItems = await new Promise((resolve, reject) => {
      db.query(
        `
        SELECT l.*, s.name AS owner_name
        FROM lost_found_items l
        LEFT JOIN students s ON l.rollno = s.rollno
        WHERE l.item_name = ? AND l.status = 'lost'
        `,
        [foundItem.item_name],
        (err, rows) => err ? reject(err) : resolve(rows)
      );
    });

    let emailLog = [];

    for (const lost of lostItems) {
      const ownerEmail = lost.college_email;
      const ownerName = lost.owner_name;  // fixed owner name

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
          photo: photoUrl
        }),
      };

      // Email to finder
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
          photo: photoUrl
        }),
      };

      try { await transporter.sendMail(mailOwner); emailLog.push(`✅ Owner email sent to ${ownerEmail}`); } 
      catch (err) { emailLog.push(`❌ Owner email failed: ${ownerEmail}`); console.error(err); }

      try { await transporter.sendMail(mailFinder); emailLog.push(`✅ Finder email sent to ${currentUserEmail}`); } 
      catch (err) { emailLog.push(`❌ Finder email failed: ${currentUserEmail}`); console.error(err); }
    }

    // Update status
    await new Promise((resolve, reject) => {
      db.query("UPDATE lost_found_items SET status='done', found_by=?, found_date=NOW(), email_sent=1 WHERE item_id=?", [currentUser.rollno, itemId], (err) => err ? reject(err) : resolve());
    });

    res.json({ success: true, message: "✅ Item marked DONE! Emails sent.", emailLog });

  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "⚠️ Failed to mark item as done or send emails." });
  }
});

// --- Send Contact Email Route ---
app.post("/send-contact", requireLogin, async (req, res) => {
  const { itemId } = req.body;
  const currentUser = req.session.student;
  const currentUserEmail = currentUser.college_email;

  try {
    // Get item and owner name from students table
    const item = await new Promise((resolve, reject) => {
      db.query(
        `
        SELECT l.*, s.name AS owner_name
        FROM lost_found_items l
        LEFT JOIN students s ON l.rollno = s.rollno
        WHERE l.item_id = ?
        `,
        [itemId],
        (err, rows) => {
          if (err) return reject(err);
          if (!rows.length) return reject(new Error("Item not found"));
          resolve(rows[0]);
        }
      );
    });

    const ownerEmail = item.college_email;
    const ownerName = item.owner_name;  // fixed owner name
    const photoUrl = item.photo ? `${req.protocol}://${req.get("host")}/uploads/${item.photo}` : null;

    const mailToOwner = {
      from: EMAIL_USER,
      to: ownerEmail,
      subject: `Contact request: ${item.item_name}`,
      html: generateEmail("contact_request_owner_only", {
        item,
        owner_name: ownerName,
        owner_email: ownerEmail,
        finder_name: currentUser.name,
        finder_rollno: currentUser.rollno,
        finder_email: currentUserEmail,
        photo: photoUrl
      })
    };

    const mailToFinder = {
      from: EMAIL_USER,
      to: currentUserEmail,
      subject: `You contacted about item: ${item.item_name}`,
      html: generateEmail("contact_request_finder_only", {
        item,
        owner_name: ownerName,
        owner_email: ownerEmail,
        finder_name: currentUser.name,
        finder_rollno: currentUser.rollno,
        finder_email: currentUserEmail,
        photo: photoUrl
      })
    };

    let emailLog = [];
    await transporter.sendMail(mailToOwner); emailLog.push(`✅ Owner email sent to ${ownerEmail}`);
    await transporter.sendMail(mailToFinder); emailLog.push(`✅ Finder email sent to ${currentUserEmail}`);

    // Update DB flag
    await new Promise((resolve, reject) => {
      db.query("UPDATE lost_found_items SET contact_email_sent=1 WHERE item_id=?", [itemId], (err) => err ? reject(err) : resolve());
    });

    res.json({ success: true, message: "Contact emails sent successfully!", emailLog });

  } catch (err) {
    console.error(err);
    res.json({ success: false, message: "⚠️ Error sending contact email: " + err.message });
  }
});

// --- Logout ---
app.get("/logout", (req,res)=>{
  req.session.destroy();
  res.redirect("/");
});

// --- Email HTML generator ---
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

  // Item details HTML
  const itemDetailsHtml = `
    <ul style="list-style:none;padding:0;font-size:14px;color:#333;">
      <li><b>Name:</b> ${itemName}</li>
      <li><b>Type:</b> ${itemType}</li>
      <li><b>Block:</b> ${itemBlock}</li>
      <li><b>Place:</b> ${itemPlace}</li>
    </ul>
    <p><b>Description:</b> ${description}</p>
    <p><b>Remarks:</b> ${remarks}</p>
    ${photoHtml}
  `;

  // Email footer
  const footerHtml = `
    <p style="font-size:13px;color:#555;margin-top:20px;">
      With regards,<br>
      <b>BIT Lost-Found Portal</b><br>
      For any queries, contact: <a href="mailto:bitlostfoundportal@gmail.com">bitlostfoundportal@gmail.com</a>
    </p>
  `;

  switch (templateType) {
    case "found_report_owner":
      return `
        <div style="font-family:'Segoe UI',sans-serif;padding:20px;color:#333;">
          <h2 style="color:#004aad;margin-bottom:10px;">💌 Notification: Your Lost Item Has Been Found</h2>
          <p>Dear ${ownerName} (${ownerEmail}),</p>
          <p>We are pleased to inform you that <b>${finderName}</b> (Roll No: <b>${finderRoll}</b>, Email: <b>${finderEmail}</b>) has located your lost item and wishes to contact you regarding its retrieval.</p>
          <h3 style="color:#007bff;margin-bottom:5px;">Item Details:</h3>
          ${itemDetailsHtml}
          <p>You may contact <b>${finderName}</b> directly at <a href="mailto:${finderEmail}">${finderEmail}</a> for further coordination.</p>
          ${footerHtml}
        </div>
      `;

    case "found_report_identifier":
      return `
        <div style="font-family:'Segoe UI',sans-serif;padding:20px;color:#333;">
          <h2 style="color:#004aad;margin-bottom:10px;">💌 Confirmation: Your Report Has Been Shared</h2>
          <p>Dear ${finderName} (${finderEmail}),</p>
          <p>This is to confirm that your report regarding the found item "<b>${itemName}</b>" has been successfully shared with the owner, <b>${ownerName}</b> (${ownerEmail}). They have been notified and may reach out to you directly.</p>
          <h3 style="color:#007bff;margin-bottom:5px;">Item Details:</h3>
          ${itemDetailsHtml}
          ${footerHtml}
        </div>
      `;

    case "contact_request_owner_only":
      return `
        <div style="font-family:'Segoe UI',sans-serif;padding:20px;color:#333;">
          <h2 style="color:#004aad;margin-bottom:15px;">💌 Message for Owner</h2>
          <p>Dear <b>${ownerName}</b> (${ownerEmail}),</p>
          <p><b>${finderName}</b> (Roll No: <b>${finderRoll}</b>, Email: <b>${finderEmail}</b>) has requested to contact you regarding the following item:</p>
          <h4 style="color:#007bff;margin-bottom:5px;">Item Details:</h4>
          ${itemDetailsHtml}
          <p>You may reach out directly to <b>${finderName}</b> at <a href="mailto:${finderEmail}">${finderEmail}</a> or via any provided contact details.</p>
          ${footerHtml}
        </div>
      `;

    case "contact_request_finder_only":
      return `
        <div style="font-family:'Segoe UI',sans-serif;padding:20px;color:#333;">
          <h2 style="color:#004aad;margin-bottom:15px;">💌 Confirmation for Finder</h2>
          <p>Dear <b>${finderName}</b> (${finderEmail}),</p>
          <p>This is a confirmation that your contact request regarding the item "<b>${itemName}</b>" has been sent to the owner, <b>${ownerName}</b> (${ownerEmail}). They may reach out to you directly.</p>
          <h4 style="color:#007bff;margin-bottom:5px;">Item Details:</h4>
          ${itemDetailsHtml}
          ${footerHtml}
        </div>
      `;

    default:
      return `<p>Item: ${itemName}</p>`;
  }
}

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 Server running at http://localhost:${PORT}`));
