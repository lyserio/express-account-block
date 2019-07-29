# express-account-pages

```bash
npm i express-account-pages
```

A simple to use module for Express that handles authentification (signup and login) and provide a basic account page you can place in your app.

Requires JQuery and Bootstrap 4 (JS + CSS) on the client side.

## Features

- [X] OAuth (Google and Github)
- [X] Drop-in login/signup page
- [X] Drop-in account management page
- [ ] Store last logged date for users
- [X] Logged middleware
- [ ] Magic link option
- [X] Use Bootstrap


## Who uses it?

<table>
<tr>
	<td align="center">
		<a href="https://nucleus.sh"><img src="https://nucleus.sh/logo_color.svg" height="64" /></a>
	</td>
	<td align="center">
		<a href="https://eliopay.com"><img src="https://eliopay.com/logo_black.svg" height="64" /></a>
	</td>
	<td align="center">
		<a href="https://backery.io"><img src="https://backery.io/logo_color.svg" height="64" /></a>
	</td>
	<td align="center">
		<a href="https://lttrfeed.com"><img src="https://lttrfeed.com/icon.svg" height="64" /></a>
	</td>
</tr>
<tr>
	<td align="center">Nucleus</td>
	<td align="center">ElioPay</td>
	<td align="center">Backery</td>
	<td align="center">Lttrfeed</td>
</tr>
</table>

_👋 Want to be listed there? [Contact me](mailto:vince@lyser.io)._



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

	res.render("my_account_view", { // Where account is your page structure
		accountTemplate: require.resolve("express-account-pages/account.ejs")
	})
})
```


Make sure to have Bootstrap.js and jQuery included.
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
