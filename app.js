//jshint esversion:6

require('dotenv').config();
currentYear = new Date().getFullYear();
const {parse, stringify} = require('flatted');
let {PythonShell} = require('python-shell')
const express = require("express"); 
var multer  =   require('multer');  
const download = require('download');
const fs = require('fs');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// --- PHASE 3: EMAIL PACKAGE ---
const nodemailer = require('nodemailer'); 

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// MongoDB Connection
const dbLink = process.env.DB_LINK || "mongodb://127.0.0.1:27017/nids_db";
mongoose.connect(dbLink)
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch(err => console.log("❌ MongoDB Connection Error: ", err));

// --- USER SCHEMA (Existing) ---
const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId:String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user,done) {
    done(null,user.id);
});
passport.deserializeUser(function(id,done) {
    User.findById(id,function(err,user) {
        done(err,user);
    });
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: process.env.CALL_BACK_URL,
  userProfileUrl:   process.env.URL
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ googleId: profile.id, username:profile.id}, function (err, user) {
    return cb(err, user);
  });
}
));

// --- PHASE 3: ALERT LOG SCHEMA (AUDIT TRAIL) ---
// This stores a permanent record of every analysis for security auditing
const alertLogSchema = new mongoose.Schema({
    timestamp: { type: Date, default: Date.now },
    filename: String,
    total_packets: Number,
    threats_detected: Number,
    severity_distribution: {
        Low: Number,
        Medium: Number,
        High: Number,
        Critical: Number
    },
    status: String // e.g., "CLEAN", "THREAT DETECTED"
});

const AlertLog = mongoose.model("AlertLog", alertLogSchema);

// --- PHASE 3: EMAIL CONFIGURATION ---
// Configure the email sender
const transporter = nodemailer.createTransport({
    service: 'gmail', // You can use 'hotmail', 'yahoo', etc.
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com', // Replace with real email or set in .env
        pass: process.env.EMAIL_PASS || 'your-app-password'     // Replace with App Password
    }
});

// --- VARIABLES ---
let submitted_csv_file="";

// Legacy Variables (Preserved)
let knn_bin_cls="", knn_mul_cls="", knn_desc="", knn_bin_acc="0.976", knn_mul_acc="0.974";
let rf_bin_cls="", rf_mul_cls="", rf_desc="", rf_bin_acc="0.974", rf_mul_acc="0.973";
let cnn_bin_cls="", cnn_mul_cls="", cnn_desc="", cnn_bin_acc="0.958", cnn_mul_acc="0.950";
let lstm_bin_cls="", lstm_mul_cls="", lstm_desc="", lstm_bin_acc="0.956", lstm_mul_acc="0.959";

let p_knn_bin_cls="", p_knn_mul_cls="", p_knn_desc="", p_knn_bin_acc="0.976", p_knn_mul_acc="0.974";
let p_rf_bin_cls="", p_rf_mul_cls="", p_rf_desc="", p_rf_bin_acc="0.974", p_rf_mul_acc="0.973";
let p_cnn_bin_cls="", p_cnn_mul_cls="", p_cnn_desc="", p_cnn_bin_acc="0.958", p_cnn_mul_acc="0.950";
let p_lstm_bin_cls="", p_lstm_mul_cls="", p_lstm_desc="", p_lstm_bin_acc="0.956", p_lstm_mul_acc="0.959";

var storage = multer.diskStorage({  
  destination: function (req, file, callback) {  
    callback(null, './Uploaded_files');  
  },  
  filename: function (req, file, callback) {  
    submitted_csv_file=file.originalname;
    console.log("File Uploaded:", submitted_csv_file);
    callback(null, file.originalname);  
  }  
});  

var upload = multer({ storage : storage}).single('myfile');  

// --- ROUTES ---

app.get("/", function(req, res){
  res.render("home");
});

app.get("/secrets",function(req,res){
  res.render("secrets");
  // Legacy code execution kept for structure
  let options={ args:[] };
  PythonShell.run('nids_random_updated.py',options, (err,response)=>{
      // Original logic...
  });
});

app.get("/secrets_2",function(req,res){
  res.render("secrets_2", { knn_bin_cls, knn_mul_cls, knn_desc, rf_bin_cls, rf_mul_cls, rf_desc, cnn_bin_cls, cnn_mul_cls, cnn_desc, lstm_bin_cls, lstm_mul_cls, lstm_desc, knn_bin_acc, knn_mul_acc, rf_bin_acc, rf_mul_acc, cnn_bin_acc, cnn_mul_acc, lstm_bin_acc, lstm_mul_acc });
});

app.get("/paramsecrets",function(req,res){
  res.render("paramsecrets", { p_knn_bin_cls, p_knn_mul_cls, p_knn_desc, p_rf_bin_cls, p_rf_mul_cls, p_rf_desc, p_cnn_bin_cls, p_cnn_mul_cls, p_cnn_desc, p_lstm_bin_cls, p_lstm_mul_cls, p_lstm_desc, p_knn_bin_acc, p_knn_mul_acc, p_rf_bin_acc, p_rf_mul_acc, p_cnn_bin_acc, p_cnn_mul_acc, p_lstm_bin_acc, p_lstm_mul_acc });
});

app.post("/parameters",function(req,res){
  let options={ args:[req.body.protocol_type, req.body.service, req.body.flag, req.body.logged_in, req.body.count, req.body.srv_serror_rate, req.body.srv_rerror_rate, req.body.same_srv_rate, req.body.diff_srv_rate, req.body.dst_host_count, req.body.dst_host_srv_count, req.body.dst_host_same_srv_rate, req.body.dst_host_diff_srv_rate, req.body.dst_host_same_src_port_rate, req.body.dst_host_serror_rate, req.body.dst_host_rerror_rate] };
  PythonShell.run('nids_parameter_updated.py',options, (err,response)=>{
    if(response) res.redirect("/paramsecrets");
  });
});

app.get("/csv",function(req,res) {
  if (req.isAuthenticated()){
    res.render("csv");
  } else {
    res.redirect("/login");
  }
});

// --- UPDATED ANALYSIS ROUTE (Alerting & Logging Implemented) ---
app.post('/uploadjavatpoint', function(req, res) {
    upload(req, res, function(err) {
        if(err) {
            return res.end("Error uploading file.");
        }
        console.log("Analyzing File:", submitted_csv_file);
        
        // Run the Phase 1/2/3 Python Script
        let options = {
            args: ['hybrid', submitted_csv_file]
        };

        PythonShell.run('nids_csv_updated.py', options, async (err, results) => {
            if (err) {
                console.log("Python Script Error:", err);
                return res.render("dashboard", { data: null });
            }
            
            if(results && results.length > 0) {
                try {
                    // Extract JSON data
                    const jsonString = results.find(r => r.trim().startsWith('{'));
                    const data = JSON.parse(jsonString);
                    
                    if(data.status === 'success') {
                        // --- 1. CALCULATE SEVERITY ---
                        // (If python script didn't return 'severity' object, we map it here manually as fallback)
                        let severity = data.severity || { Low: 0, Medium: 0, High: 0, Critical: 0 };
                        
                        // Fallback Calculation if Python didn't provide it
                        if (!data.severity) {
                             severity.Low = data.stats['Normal'] || 0;
                             severity.Medium = data.stats['Probe'] || 0;
                             severity.High = data.stats['Dos'] || 0;
                             severity.Critical = (data.stats['R2L'] || 0) + (data.stats['U2R'] || 0);
                        }

                        const totalThreats = severity.Medium + severity.High + severity.Critical;

                        // --- 2. DATABASE LOGGING (Audit Trail) ---
                        const newLog = new AlertLog({
                            filename: submitted_csv_file,
                            total_packets: data.total,
                            threats_detected: totalThreats,
                            severity_distribution: severity,
                            status: totalThreats > 0 ? "THREAT DETECTED" : "CLEAN"
                        });
                        
                        await newLog.save();
                        console.log("✅ Audit Log saved to MongoDB");

                        // --- 3. EMAIL ALERTS (High/Critical Only) ---
                        const dangerousThreats = severity.High + severity.Critical;
                        
                        if (dangerousThreats > 0 && process.env.EMAIL_USER) {
                            console.log(`⚠️  ${dangerousThreats} High/Critical threats! Sending Alert...`);
                            
                            const mailOptions = {
                                from: process.env.EMAIL_USER,
                                to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER, // Send to yourself
                                subject: `🚨 SECURITY ALERT: ${dangerousThreats} Critical Threats Detected`,
                                text: `Intrusion Detection System Alert.\n\n` +
                                      `File: ${submitted_csv_file}\n` + 
                                      `Total Threats: ${totalThreats}\n` + 
                                      `Severity Breakdown:\n` +
                                      `- Critical: ${severity.Critical}\n` +
                                      `- High: ${severity.High}\n` +
                                      `- Medium: ${severity.Medium}\n\n` +
                                      `Please access the dashboard immediately.`
                            };
                            
                            transporter.sendMail(mailOptions, function(error, info){
                                if (error) {
                                    console.log("❌ Email Failed:", error);
                                } else {
                                    console.log('📧 Alert Email Sent: ' + info.response);
                                }
                            });
                        }

                        // Render Dashboard
                        res.render("dashboard", { data: data });
                    } else {
                        res.send("Analysis Error: " + data.message);
                    }
                } catch (parseErr) {
                    console.log("JSON Parse Error:", parseErr);
                    res.send("Error parsing analysis results.");
                }
            } else {
                res.send("No results generated.");
            }
        });
    });
});

app.get('/download-file', (req, res) => {
    if (!submitted_csv_file) {
        return res.redirect('/csv');
    }
    const path = './Uploaded_files/' + submitted_csv_file;
    res.download(path);
});

// Standard Pages
app.get("/features",function(req,res){ res.render("features"); })
app.get("/attacks",function(req,res){ res.render("attacks"); })
app.get("/about",function(req,res){ res.render("about"); })
app.get("/stats",function(req,res){ res.render("stats"); })
app.get("/parameters",function(req,res){ res.render("parameters"); })
app.get("/contact",function(req,res){ res.render("contact"); })
app.get("/knn_bin_table",function(req,res){ res.render("knn_bin_table"); });
app.get("/rf_bin_table",function(req,res){ res.render("rf_bin_table"); });
app.get("/cnn_bin_table",function(req,res){ res.render("cnn_bin_table"); });
app.get("/lstm_bin_table",function(req,res){ res.render("lstm_bin_table"); });
app.get("/knn_table",function(req,res){ res.render("knn_table"); });
app.get("/rf_table",function(req,res){ res.render("rf_table"); });
app.get("/cnn_table",function(req,res){ res.render("cnn_table"); });
app.get("/lstm_table",function(req,res){ res.render("lstm_table"); });

// Auth Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get("/auth/google/NIDS",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/submit");
  }
);

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/submit",function(req,res) {
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res){
  req.logout();
  
  if(submitted_csv_file !== ""){
    const path = './Uploaded_files/' + submitted_csv_file;
    fs.unlink(path, (err) => {
        if (err) console.log(err);
        else console.log('Temp file deleted');
        submitted_csv_file = "";
    });
  }
  res.redirect("/");
});

app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/submit");
      });
    }
  });
});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, function(err){
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/submit");
      });
    }
  });
});

let port = process.env.PORT;
if (port == null || port == "") {
  port = 3000;
}
app.listen(port, function() {
  console.log("Server started on port 3000.");
});