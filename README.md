# express-account-pages

```bash
npm i express-account-pages
```

A simple to use module for Express that handles authentification (signup and login) and provide a basic account page you can place in your app.

Based on JQuery and Bootstrap.

## Features

- [X] Drop-in login/signup page
- [X] Drop-in account management page
- [ ] Store last logged date for users
- [X] Logged middleware
- [X] Use Bootstrap 
- [X] OAuth (Google and Github)

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

// Parse from html forms and post payload
app.use(express.json()) 
app.use(express.urlencoded({ extended: true }))

// For signup and login
require('express-account-pages')(app, {
	siteName: 'My Web App',
	primaryColor: '#b90577',
	// background: 'red',
	// logoUrl: '/favicon.png',
	mongoose: mongoose,
	useAccessToken: true, // Access token management
	redirectLogin: '/account',
	redirectSignup: '/account',
	// signupMailExtra: 'You can now create your first app.',
	mongoUser: db.User,
	connectors: {
		github: {
			clientId: "xxxxxxx",
			clientSecret: "xxxxxx",
			redirectUri: "https://my.app/auth/github/callback"
		},
		google: {
			clientId: 'xxxxxxx.apps.googleusercontent.com',
			clientSecret: 'xxxxxxxxx',
			redirectUri: 'https://my.app/auth/google/callback'
		}
	}
})

```

## Account page

Will require Bootstrap and jQuery.

In your express route:

```javascript
app.get("/account", (req, res, next) => {

	res.render("myaccountpage", { // Where account is your page structure
		accountTemplate: require.resolve("express-account-pages/account.ejs")
	})
})
```


Then, in your ejs:

```html
<body>
	<%- include(accountTemplate) %>
</body>

<script src="/account/account.js" defer></script>
```

## Oauth

Currently the module supports Github and Google oauth.

The redirect URIs are predefined paths:

- */auth/github/callback* for Github
- */auth/google/callback* for Github
