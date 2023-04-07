//jshint esversion:6

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const { default: mongoose } = require('mongoose');
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

 
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// initialize session
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

// initialize passport 

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets"
},

function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));
 
app.get("/", function(req, res){
  res.render("home");
});

// using google strategy to autenticate, the strategy is the one mentioned above;
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
  );

app.get('/auth/google/secrets', 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
  // Successful authentication, redirect home.
  res.redirect('/secrets');
});


app.get("/register", function(req, res){
  res.render("register");
}) 

app.get("/login", function(req, res){
  res.render("login");
}); 

// using passport local mongoose for this

app.get("/secrets", function(req, res){
  User.find({ secret: { $ne: null } })
  .then(foundUsers=>{
    if (foundUsers) {
      res.render("secrets", { usersWithSecrets: foundUsers });
    }
  })
  .catch(err =>{console.log(err)});
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post('/submit', (req, res) => {
  const submittedSecret = req.body.secret;

  console.log(req.user) //It is user object saved by passport in http 'req' object.

  
  User.findById(req.user._id)
  .then (foundUser => {
    if (foundUser) {
      foundUser.secret = submittedSecret;
      foundUser.save(); 
      res.redirect("/secrets")
    }
  })
  .catch(err=> {console.log(err)});

});

app.get("/logout", function(req, res){
  req.logOut(function(err){
    if (err) {
      return next(err);
    } else {
      res.redirect("/");
    }
  });
});


app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("secrets");
      })
    }
  })
});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      })
    }
  })

});
 
app.listen(3000, () => {
  console.log('Server started on port 3000');
});