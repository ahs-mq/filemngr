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
    done(null, user[0]);
  } catch (err) {
    done(err);
  }
});
app.get("/", (req,res)=>{
    res.render("index")
})

app.use(passport.initialize());
app.use(passport.session());


app.get("/signup", (req,res)=>{
    res.render("signup")
})

app.get("/login", (req,res)=>{
    res.render("login")
})

app.post("/signup", [
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
        res.redirect("/")
    }catch (err){
        if (err.code === 'P2002') {
            return res.render("signup", {
                // Pass an error object back to the view
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

app.listen(8000, ()=>{console.log("Listening on port 8000")})