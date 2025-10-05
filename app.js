// Core setup
const express = require('express');
const session = require('express-session');
const dotenv = require('dotenv');
const path = require('path');

// View engine
const ejs = require('ejs');

// Authentication
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// Validation
const { body, validationResult } = require('express-validator');

// File uploads
const multer = require('multer');
const fs = require('fs');
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, './uploads')
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9)
    cb(null, file.originalname)
  }
})

const upload = multer({ storage: storage })

// Password hashing
const bcrypt = require('bcryptjs');

// Prisma ORM
const { PrismaClient } = require('@prisma/client');
const PrismaSessionStore = require('@quixo3/prisma-session-store').PrismaSessionStore;

// Initialize environment variables
dotenv.config();

// Initialize Prisma
const prisma = new PrismaClient();

const app = express()
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public"))); //serve css from public folder 
app.set('view engine', 'ejs');
//express.urlencoded() is a method inbuilt in express to recognize the incoming Request Object as strings or arrays
app.use(express.urlencoded({ extended: true }));

passport.use(new LocalStrategy(
    {usernameField: "email"}, async(email, password,done)=>{
        try{
            const user = await prisma.user.findUnique({where: {
                email: email
            }})

            if (!user) return done(null, false, {message: "No user found with given email"})

            const match = await bcrypt.compare(password, user.password)
            
            if (!match) return done (null, false, {message: "Incorrect Password"})

            return done(null , user)

        }catch(err){
            return done(err)
        }
    }
))

app.use(
  session({
    cookie: {
     maxAge: 7 * 24 * 60 * 60 * 1000 // ms
    },
    secret: process.env.SECRET_CODE,
    resave: true,
    saveUninitialized: true,
    store: new PrismaSessionStore(
      new PrismaClient(),
      {
        checkPeriod: 2 * 60 * 1000,  //ms
        dbRecordIdIsSessionId: true,
        dbRecordIdFunction: undefined,
      }
    )
  })
);

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({where:{
        id: id
    }})
    done(null, user)
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

//check if logged in

function ensureAuthenticated(req, res, next) {
        if (req.isAuthenticated()) {
            return next(); // User is authenticated, proceed to the route handler
        }
        res.redirect('/login'); // User is not authenticated, redirect to login page
    }

app.get("/", (req,res)=>{
    res.render("index", {user: req.user})
})

app.get("/signup", (req,res)=>{
    res.render("signup")
})

app.get("/login", (req,res)=>{
    res.render("login")
})

app.post("/signup", [
    //validation check
    body("email").isEmail(),
    body("password"),
    body("cpassword").custom((value, {req})=>{
        if (value !== req.body.password){
            throw new Error("Password Mismatch")
        }
        return true
    })
],async (req,res)=>{
    try{
        const hashed = await bcrypt.hash(req.body.password, 10)
        const newUser = await prisma.user.create({data:{
            email: req.body.email,
            password: hashed
        }
        })
        req.login(newUser,err =>{
            if (err){
                console.error("Error logging in after signup:", err)
                res.redirect("/login")
            }
            res.redirect("/")
        })
    }catch (err){
        //err code for unique constraint with prisma
        if (err.code === 'P2002') {
            return res.render("signup", {
                errors: [{ msg: "An account with this email already exists." }],
                email: req.body.email
            });
        }
        console.log(err)
        return (err)
    }
})

app.post("/login", passport.authenticate("local",{
    successRedirect: "/",
    failureRedirect: "/signup"
}))

app.get("/files", ensureAuthenticated, async (req, res) => {
  try {
    const files = await prisma.file.findMany({
      where: { ownerId: req.user.id }
    });

    res.render("files", { files });
  } catch (err) {
    console.error("Error fetching files:", err);
    res.status(500).send("Something went wrong");
  }
});

app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).send("Unauthorized");
    }

    const file = req.file;

    const savedFile = await prisma.file.create({
      data: {
        name: file.originalname,
        path: file.path,
        size: file.size,
        mimeType: file.mimetype,
        ownerId: req.user.id
      }
    });

    res.redirect("/files");
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).send("Something went wrong");
  }
});

// Add a GET route to handle file downloads
app.get("/download/:fileId", async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).send("Unauthorized");
    }

    const fileId = parseInt(req.params.fileId);

    // 1. Find the file in the database
    const file = await prisma.file.findUnique({
      where: { id: fileId },
    });

    if (!file) {
      return res.status(404).send("File not found");
    }

    // 2. Security check: Ensure the user owns the file
    if (file.ownerId !== req.user.id) {
      return res.status(403).send("Forbidden");
    }

    // 3. Use res.download to send the file
    // file.path is the full path on the server (e.g., './uploads/my-file.txt')
    res.download(file.path, file.name, (err) => {
      if (err) {
        // Handle errors, e.g., file not found on disk
        console.error("Download error:", err);
        if (res.headersSent) return; // Prevent double response
        res.status(500).send("Could not download the file");
      }
    });
  } catch (err) {
    console.error("Error retrieving file for download:", err);
    res.status(500).send("Something went wrong");
  }
});

app.post("/delete/:fileId", async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).send("Unauthorized");
    }

    const fileId = parseInt(req.params.fileId);

    // 1. Find the file in the database
    const file = await prisma.file.findUnique({
      where: { id: fileId },
    });

    if (!file) {
      return res.status(404).send("File not found in DB");
    }

    // 2. Security check: Ensure the user owns the file
    if (file.ownerId !== req.user.id) {
      return res.status(403).send("Forbidden");
    }

    const filePath = file.path;

    // 3. Delete the file from the database
    await prisma.file.delete({
      where: { id: fileId },
    });

    // 4. Delete the file from the disk using fs.unlink
    fs.unlink(filePath, (err) => {
      if (err) {
        // Log the error, but still proceed as the DB entry is gone
        console.error("Failed to delete file from disk:", filePath, err);
      }
      // Redirect back to the files page after deletion
      res.redirect("/files");
    });
  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).send("Something went wrong during deletion");
  }
});

app.post("/rename/:fileId", async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).send("Unauthorized");
    }

    const fileId = parseInt(req.params.fileId);
    const newName = req.body.newName; // Get new name from the form body

    if (!newName || typeof newName !== 'string' || newName.trim() === '') {
        return res.status(400).send("Invalid new name");
    }

    // 1. Find the file in the database
    const file = await prisma.file.findUnique({
      where: { id: fileId },
    });

    if (!file) {
      return res.status(404).send("File not found");
    }

    // 2. Security check: Ensure the user owns the file
    if (file.ownerId !== req.user.id) {
      return res.status(403).send("Forbidden");
    }
    
    // Construct the new path. Assumes the file is in './uploads'
    const newPath = `./uploads/${newName}`; 

    // 3. Rename the file on the disk
    fs.rename(file.path, newPath, async (err) => {
        if (err) {
            console.error("Failed to rename file on disk:", err);
            // Check if the file name already exists (EEXIST) or other error
            return res.status(500).send("Could not rename file on disk. Name might be taken.");
        }

        // 4. Update the database entry
        await prisma.file.update({
          where: { id: fileId },
          data: {
            name: newName,
            path: newPath // Update the path to reflect the new filename
          },
        });
        
        // Redirect back to the files page after renaming
        res.redirect("/files");
    });
  } catch (err) {
    console.error("Rename error:", err);
    res.status(500).send("Something went wrong during renaming");
  }
});


app.listen(8000, ()=>{console.log("Listening on port 8000")})