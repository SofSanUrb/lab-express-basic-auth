// ℹ️ Gets access to environment variables/settings
// https://www.npmjs.com/package/dotenv
require('dotenv/config');

// ℹ️ Connects to the database
require('./db');

// Handles http requests (express is node js framework)
// https://www.npmjs.com/package/express
const express = require('express');

// Handles the handlebars
// https://www.npmjs.com/package/hbs
const hbs = require('hbs');

const app = express();

// ℹ️ This function is getting exported from the config folder. It runs most middlewares
require('./config')(app);

// default value for title local
const projectName = 'lab-express-basic-auth';
const capitalized = (string) => string[0].toUpperCase() + string.slice(1).toLowerCase();

app.locals.title = `${capitalized(projectName)}- Generated with IronGenerator`;

//Set up connect mongo
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);
const mongoose = require('mongoose')

app.use(session({
    //random secret key
    secret: 'MySuperSecret',
    saveUninitialized: false, // don't create session until something stored
    resave: false, //don't save session if unmodified
    cookie : {
      maxAge: 1000*60*60*24 //in milliseconds, one day
    },
    store: new MongoStore({
      mongooseConnection: mongoose.connection,
      //time to live ttl in seconds, in this case, in one day
      ttl: 60*60*24
    })
}));

// 👇 Start handling routes here
const index = require('./routes/index');
app.use('/', index);

const AuthRoutes = require('./routes/auth.routes')
app.use('/', AuthRoutes)

// ❗ To handle errors. Routes that don't exist or errors that you handle in specific routes
require('./error-handling')(app);

module.exports = app;
