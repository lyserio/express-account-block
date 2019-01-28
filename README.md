# express-account-pages

```bash
npm i express-account-pages
```

## Todo

- [ ] Store last logged date for users
- [ ] Logged middleware
- [ ] Google login
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
	fontFamily: 'Lato, Avenir, -apple-system, Roboto, Arial, sans-serif',
	mongoose: mongoose,
	redirectLogin: '/account',
	redirectSignup: '/account',
	mongoUser: db.User
})

```
