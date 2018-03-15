const
  express = require('express'),
  usersRouter = new express.Router(),
  passport = require('passport')

usersRouter.get('/login', (req, res) => {
  res.render('login', {message: req.flash('loginMessage')})
})

usersRouter.post('/login', passport.authenticate('local-login', {
  successRedirect: '/users/profile',
  failureRedirect: '/users/login'
}))

usersRouter.get('/signup', (req, res) => {
  res.render('signup', {message: req.flash('signupMessage'), message: req.flash('noFieldMessage')})
})

usersRouter.post('/signup', passport.authenticate('local-signup', {
  successRedirect: '/users/profile',
  failureRedirect: '/users/signup'
}))

usersRouter.get('/profile', isLoggedIn, (req, res) => {
  res.render('profile', {user: req.user, message: req.flash('welcomeMessage')})
})

usersRouter.get('/logout', (req, res) => {
  req.logout()
  res.redirect('/')
})

function isLoggedIn(req, res, next){
  if(req.isAuthenticated()) return next()
  res.redirect('/users/login')
}

module.exports = usersRouter