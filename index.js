const session       = require('express-session')
const flash         = require('connect-flash')
const MongoStore    = require('connect-mongo')(session)
const cookieParser  = require('cookie-parser')
const bodyParser  	= require('body-parser')

const crypto 		= require('crypto')
const bcrypt 		= require('bcrypt-nodejs')

const passport 		= require('passport')
const LocalStrategy = require('passport-local').Strategy
const GitHubStrategy = require('passport-github').Strategy
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy

let options = {}

// Catching errors when using async functions
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next)

const generateAccessToken = (seed) => {
	return (crypto.createHash('md5').update('s0mew31rderSAlt'+seed+'j+333'+new Date()).digest("hex")).substring(0,20)
}

const createUser = async (profile, done) => {
	
	const user = await options.mongoUser.findOne({ 'email' :  profile.email }).exec()

	if (user) return done(null, false, { message: 'That email is already registered. Try to login.' })
	
	const timestamp = new Date().toISOString()
	const accessToken = generateAccessToken(profile.email)

	let newUser = new options.mongoUser({
		email: profile.email,
		name: profile.provider === 'google' ? profile.displayName: profile.name,
		pswd: profile.password ? bcrypt.hashSync(profile.password, bcrypt.genSaltSync(8), null) : null,
		created: timestamp,
		accessToken: accessToken
	})

	if (profile.provider === 'github') {
		newUser.github = {
			id: profile.id,
			username: profile.username
		}
	} else if (profile.provider === 'google') {
		newUser.google = { id: profile.id }
	}

	if (options.sendMail) {
		options.sendMail(`Welcome to ${options.siteName} 🚀!`, 
`Hi 👋!\n
Your account has been successfully created, welcome to ${options.siteName} :)\n
${options.signupMailExtra ? options.signupMailExtra + '\n' : ''}
I hope you'll enjoy using it.\n
If you have any question or suggestion, just reply to this email.\n
Glad to have you on board!`, newUser.email)
	}

	await newUser.save()

	done(null, newUser)

}

// The rest isn't as promise because passport doesn't support yet
passport.use('local-login', new LocalStrategy( {
	usernameField: 'email',
	passwordField: 'password'
}, (email, password, done) => {
	
	options.mongoUser.findOne({ email: email }, (err, user) => {

		if (err) return done(err)
		if (!user) return done(null, false, { message: 'Incorrect email.' })

		// Switch legacy fields to new ones
		let legacyPassword = user.password || user.pswdHash 
		if (legacyPassword && !user.pswd) {
			user.pswd = legacyPassword
			user.save()
		}

		if (!user.pswd) return done(null,false,{ message: "You haven't set a password. Try logging in via another method." })
		if (!bcrypt.compareSync(password, user.pswd)) return done(null, false, { message: 'Incorrect password.' })
		
		return done(null, user)
	})

}))

passport.use('local-signup', new LocalStrategy({
		usernameField : 'email',
		passwordField : 'password',
		passReqToCallback: true
	}, (req, email, password, done) => {

		createUser({
			email: email,
			password: password,
			name: req.body.name,
		}, done).catch(e => done(e))
	}
))


module.exports = (app, opts) => {
	if (opts) options = opts


	if (options.connectors && options.connectors.github) {
		passport.use(new GitHubStrategy({
				clientID: options.connectors.github.clientId,
				clientSecret: options.connectors.github.clientSecret,
				callbackURL: options.connectors.github.redirectUri,
				scope: 'user:email',
			}, (accessToken, refreshToken, profile, done) => {

				profile.email = profile.emails.find(e => e.primary).value

				options.mongoUser.findOne({ "github.id": profile.id }, (err, user) => {
					if (user) return done(null, user)

					createUser(profile, done).catch(e => done(e))
				})
		  	}
		))
	}

	if (options.connectors && options.connectors.google) {
		passport.use(new GoogleStrategy({
				clientID: options.connectors.google.clientId,
				clientSecret: options.connectors.google.clientSecret,
				callbackURL: options.connectors.google.redirectUri
			}, (accessToken, tokenSecret, profile, done) => {
				profile.email = profile.emails[0].value

				options.mongoUser.findOne({ "google.id": profile.id }, (err, user) => {
					if (user) return done(null, user)

					createUser(profile, done).catch(e => done(e))
				})
		  	}
		))
	}

	passport.serializeUser((user, done) => {
		done(null, user._id)
	})

	passport.deserializeUser((id, done) => {
		options.mongoUser.findById(id, (err, user) => {
			if (err) return done (err)
			
			user.useAccessToken = options.useAccessToken // So it doesn't show for nothing
			
			done(null, user)
		})
	})

	app.use(session({ 
		secret: 'hey super cat secret key', // session secret
		resave: false, 
		saveUninitialized: false,
		store: new MongoStore({ mongooseConnection: options.mongoose.connection })
	}))

	app.use(flash()) // error messages during login
	app.use(cookieParser()) // read cookies

	// get information from html forms and post payload
	app.use(bodyParser.json()) 
	app.use(bodyParser.urlencoded({ extended: true }))

	app.use(passport.initialize())
	app.use(passport.session()) // persistent login sessions

	app.post('/login', passport.authenticate('local-login', { successRedirect: options.redirectLogin, failureRedirect: '/login', failureFlash: true }) )
	app.post('/signup', passport.authenticate('local-signup', { successRedirect : options.redirectSignup, failureRedirect : '/signup', failureFlash : true }))

	if (options.connectors) {
		if (options.connectors.github) {
			app.get('/auth/github', passport.authenticate('github'))
			app.get('/auth/github/callback', passport.authenticate('github', { successRedirect: options.redirectLogin, failureRedirect: '/login', failureFlash : true  }))
		}

		if (options.connectors.google) {
			app.get('/auth/google', passport.authenticate('google', { scope: [ 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email' ] }))
			app.get('/auth/google/callback', passport.authenticate('google', { successRedirect: options.redirectLogin, failureRedirect: '/login', failureFlash : true  }))
		}
	}

	app.get('/signup', (req, res) => {
		res.render(__dirname+'/login', { 
			page: 'signup',
			message: req.flash('error'),
			logoUrl: options.logoUrl,
			connectors: options.connectors,
			siteName: options.siteName,
			background: options.background,
			primaryColor: options.primaryColor
		})
	})

	app.get('/login', (req, res) => {
		if (req.isAuthenticated()) return res.redirect(options.redirectLogin)

		res.render(__dirname+'/login', {
			page: 'login',
			message: req.flash('error'),
			logoUrl: options.logoUrl,
			connectors: options.connectors,
			siteName: options.siteName,
			background: options.background,
			primaryColor: options.primaryColor
		})
	})

	app.get('/logout', (req, res) => {
		req.session.destroy( err => {
			res.redirect('/login')
		})
	})

	app.get('/account/accessToken', asyncHandler(async (req, res, next) => {
		if (!req.isAuthenticated()) return res.redirect('/login')

		let user = await options.mongoUser.findById(req.user.id).exec()
		if (!user) return next(403)
			
		user.accessToken = generateAccessToken(req.body.userEmail)

		await user.save()

		if (typeof options.sendMail === 'function') {
			options.sendMail(`⚠️ ${options.siteName} - Access token renewed`, `Hello,\n\nWe inform you that you have successfully renewed your API access token.\nIf you are not behind this operation, reply to this email immediately.\n\nHave a great day.\n\nThe ${options.siteName} team.`, user.email)
		}
	
		res.redirect(options.redirectLogin)

	}))


	app.post('/account/password', asyncHandler(async (req, res, next) => {
		if (!req.isAuthenticated()) return next(403)

		let oldPswd = req.body.old

		let newPswd = req.body.new
		let confirm = req.body.confirm

		if (newPswd !== confirm) return next("Passwords don't match.")

		let user = await options.mongoUser.findById(req.user.id).exec()
		if (!user) return next(403)

		if (user.pswd && !bcrypt.compareSync(oldPswd, user.pswd)) return next("Invalid password.")

		user.pswd = bcrypt.hashSync(newPswd, bcrypt.genSaltSync(8), null)

		await user.save()

		if (typeof options.sendMail === 'function') {
			options.sendMail(`⚠️ ${options.siteName} - Password updated`, `Hello,\n\nWe inform you that you have successfully updated your ${options.siteName} password.\nIf you are not behind this operation, reply to this email immediately.\n\nHave a great day.\n\nThe ${options.siteName} team.`, user.email)
		}

		res.send({})

	}))

	app.get('/account/account.js', (req, res, next) => {
		res.sendFile(__dirname+'/account.js')
	})


}
