# express-account-pages

```bash
npm i express-account-pages
```

## Features

- [X] Drop-in login/signup page
- [X] Drop-in account management page
- [ ] Store last logged date for users
- [X] Logged middleware
- [X] Use Bootstrap 
- [ ] Google OAuth
- [ ] Facebook OAuth
- [ ] Better README

## Usage

```javascript

// Init express
const express 		= require('express')
const app 			= express()

// Add your DB
const mongoose      = require('mongoose')
const mongoURI 		= process.env.MONGO_URL || 'mongodb://localhost:27017/myappdb'
mongoose.connect(mongoURI, { useNewUrlParser: true })

// Your db schmeas
const db 			= require('./helpers/db')

// For signup and login
require('express-account-pages')(app, {
	siteName: 'My Web App',
	primaryColor: '#b90577',
	// background: 'red',
	// logoUrl: '/favicon.png',
	mongoose: mongoose,
	redirectLogin: '/account',
	redirectSignup: '/account',
	mongoUser: db.User
})

```
