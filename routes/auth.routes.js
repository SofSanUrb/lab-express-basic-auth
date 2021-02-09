const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const UserModel = require('../models/User.model.js');
const { render } = require('../app.js');

router.get('/signup', (req, res) => res.render('auth/signup.hbs'));

router.get('/login', (req, res) => res.render('auth/login.hbs'))

router.post('/signup', (req, res, next) => {
    const {username, password} = req.body
    //validate first
    //checking if the user has entered all fields
    if (!username.length || !password.length) {
        res.render('auth/signup', {msg: 'Please enter all fields'})
        return;
    }
    //check for password
    let regexPass = /^(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[a-zA-Z!#$%&? "])[a-zA-Z0-9!#$%&?]{8,20}$/;
     if (!regexPass.test(password)) {
        res.render('auth/signup', {msg: 'Password needs to have special characters, some numbers and be 6 characters at least'})
        return;
     }

    //password goes through bcryptjs library
    let salt = bcrypt.genSaltSync(10);
    let hash = bcrypt.hashSync(password, salt);

    UserModel.findOne({username: username})
     .then((user) => {
         if(user) {
             res.render('auth/signup', {msg: 'This username already exists, try a different one'})
             return;
         }
     })
     .catch((err) => next(err))

    UserModel.create({username, password:hash})
        .then(() => res.redirect('/'))
        .catch((err) => next(err))
})

router.post('/login', (req, res, next) => {
    const {username, password} = req.body

    if (!username.length || !password.length) {
        res.render('auth/login', {msg: 'Please enter all fields'})
        return;
    }

    UserModel.findOne({username: username})
        .then((user) => {

            if(user) {
                bcrypt.compare(password, user.password)
                    .then((response) => {
                        
                        if (response) {
                            req.session.loggedInUser = user
                            
                            res.redirect('/usermainpage')
                        }
                        else {
                            res.render('auth/login.hbs', {msg: 'Password not found'})
                        }})
            }
            else {
                res.render('auth/login.hbs' , {msg: 'Username not found'})
            }
        })
        .catch((err) => next(err))
})

//custom middleware
const isUserOnline = (req, res, next) => {
    (req.session.loggedInUser) ? next() : res.redirect('/login')
}

//protected routes
router.get('/usermainpage', isUserOnline, (req, res) => {
    let username = req.session.loggedInUser.username
    res.render('auth/usermainpage.hbs', {username})
})

router.get('/usermainpage/main', isUserOnline, (req, res) => {
    let username = req.session.loggedInUser.username
    res.render('auth/catmain.hbs', {username})
})

router.get('/usermainpage/private', isUserOnline, (req, res) => {
    let username = req.session.loggedInUser.username
    res.render('auth/private.hbs', {username})
})

router.get('/logout', (req, res) => {
    req.session.destroy()
    res.redirect('/')
})

module.exports = router;
