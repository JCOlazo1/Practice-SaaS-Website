var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var mongoose = require('mongoose');
require('./models');
var bcrypt = require('bcrypt');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

var User = mongoose.model('User');


// Set your secret key. Remember to switch to your live secret key in production!
// See your keys here: https://dashboard.stripe.com/account/apikeys
const stripe = require('stripe')('sk_test_51H9vhbAkZ1kK6rBvkGcYSt8ewhyGTJDleZvHdVOh1iuaoslCFhnPRVM6FkMePdEefEKWSe3hM67oMaWXv4VopPwU003gyg074b');



mongoose.connect('mongodb://localhost:27017/test-db-2', {useNewUrlParser: true, useUnifiedTopology:true});


var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
}, function(email, password, next) {
  // Check if a user exists:
  User.findOne({
    email: email
  }, function(err, user) {
    if (err) return next(err);
    if(!user || !bcrypt.compareSync(password, user.passwordHash)) {
      return next({message: 'Email/password incorrect'})
    }
    next(null, user);
  })
}));

passport.use('signup-local', new LocalStrategy({
  usernameField: "email",
  passwordField: "password"
}, function(email, password, next) {
  User.findOne({
    email: email
  }, function(err, user) {
    if (err) return next(err);
    if (user) return next({message: "User already exists"})
    let newUser = new User({
      email: email,
      passwordHash: bcrypt.hashSync(password, 10)
    })
    // after a successful login (parameters in .save() and
    // the 'if' code after are performed after step 26):
    newUser.save(function(err) {
      next(err, newUser);
    });
  });
}));

passport.serializeUser(function(user, next) {
  next(null, user._id);
});

passport.deserializeUser(function(id, next) {
  User.findById(id, function(err, user) {
    next(err, user);
  });
});

app.get('/', function(req, res, next) {
  res.render('index', {title: "Practice website 1"})
})

app.get('/main', function(req, res, next) {
  res.render('main')
})

app.get('/billing', function(req, res, next) {

  stripe.checkout.sessions.create(
      {
        customer_email: req.body.email,
        success_url: 'http://localhost:3000/billing?session_id={CHECKOUT_SESSION_ID}',
        cancel_url: 'http://localhost:3000/billing',
        payment_method_types: ['card'],
        line_items: [
          {
            price: 'price_1H9vrXAkZ1kK6rBvOsje3YIf',
            quantity: 1,
          },
        ],
        mode: 'subscription',
      },
      function(err, session) {
        if (err) next (err);
        res.render('billing', {sessionId: session.id, subscriptionActive: req.user.subscriptionActive})
      }
  );
})
// if(err) return next(err);
// res.render('billing', {sessionId: session.id, subscriptionActive: req.user.subscriptionActive})
app.get('/logout', function(req, res, next) {
  // thanks to passport, its as easy as that:
  req.logout();
  // Send to landing page after logging out
  res.redirect('/');
})

app.post('/login',
    passport.authenticate('local', { failureRedirect: '/login-page' }),
    function(req, res) {
  // if successful, go to /main page
      res.redirect('/main');
    });

app.get('/login-page', function(req, res, next) {
  res.render('login-page')
})

app.post('/signup',
    passport.authenticate('signup-local', { failureRedirect: '/' }),
    function(req, res) {
      // if successful, go to /main page
      res.redirect('/main');
    });

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
