const session       = require('express-session')
const flash         = require('connect-flash')
const MongoStore    = require('connect-mongo')(session)
const cookieParser  = require('cookie-parser')

const bcrypt 		= require('bcrypt-nodejs')
const jwt 			= require('jsonwebtoken')

const passport 		= require('passport')
const LocalStrategy = require('passport-local').Strategy
const GitHubStrategy = require('passport-github').Strategy
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy

const { 
	asyncHandler, 
	generateAccessToken, 
	secureHeaders, 
	mergeDeep
} = require('./utils')

const createUser = async (profile, done) => {
	
	const user = await options.mongoUser.findOne({ 'email' :  profile.email }).exec()

	if (user) return done(null, false, { message: 'That email is already registered. Try to login.' })
	
	const timestamp = new Date().toISOString()
	const accessToken = generateAccessToken()

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
	
	options.sendMail(`Welcome to ${options.siteName} 🚀`, 
`Hello,\n
Your account has been successfully created. Welcome to ${options.siteName}.\n
${options.signupMailExtra ? options.signupMailExtra + '\n' : ''}
If you have any question or suggestion, just reply to this email.\n
Glad to have you on board!`, newUser.email)

	await newUser.save()

	done(null, newUser)

}

// The rest isn't as promise because passport doesn't support yet
passport.use('local-login', new LocalStrategy( {
	usernameField: 'email',
	passwordField: 'password'
}, (email, password, done) => {

	const emailClean = email.toLowerCase().trim()
	
	options.mongoUser.findOne({ email: emailClean }, (err, user) => {

		if (err) return done(err)
		if (!user) return done(null, false, { message: 'Incorrect email or password.' })

		// Switch legacy fields to new ones
		let legacyPassword = user.password || user.pswdHash 
		if (legacyPassword && !user.pswd) {
			user.pswd = legacyPassword
			user.save()
		}

		if (!user.pswd) return done(null, false, { message: "You haven't set a password. Try logging in via another method." })
		if (!bcrypt.compareSync(password, user.pswd)) return done(null, false, { message: 'Incorrect email or password.' })
		
		return done(null, user)
	})

}))

passport.use('local-signup', new LocalStrategy({
		usernameField : 'email',
		passwordField : 'password',
		passReqToCallback: true
	}, (req, email, password, done) => {

		const emailClean = email.toLowerCase().trim()

		createUser({
			email: emailClean,
			password: password,
			name: req.body.name,
		}, done).catch(e => done(e))
	}
))

let options = {
	siteName: "",
	secret: "k1235fhjazc8678gg9",
	siteUrl: "",
	sendMail: (subject, content, recipient, type) => {
		console.warn('Warning, no email sending function set.')
		console.log("Mail to send: ", subject)
	},
	useAccessToken: true,
	signupMailExtra: null,
	redirectLogin: "/",
	redirectSignup: "/",
	connectors: {},
	pages: {
		logoUrl: null,
		customHeadHtml: '',
		signup: {
			title: 'Sign Up',
			subtitle: "Takes less than 30 seconds."
		},
		login: {
			title: 'Log In',
			subtitle: "Welcome back!"
		},
		forgot: {
			title: "Reset your password"
		},
		reset: {
			title: "Change your password"
		}
	}
}

module.exports = (app, opts) => {
	
	if (opts) options = mergeDeep(options, opts)

	if (options.connectors.github) {
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

	if (options.connectors.google) {
		passport.use(new GoogleStrategy({
				clientID: options.connectors.google.clientId,
				clientSecret: options.connectors.google.clientSecret,
				callbackURL: options.connectors.google.redirectUri,
				userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
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
			if (!user) return done("User not found")
			
			user.useAccessToken = options.useAccessToken // So it doesn't show for nothing
			
			done(null, user)
		})
	})

	// Less targetted attacks
	app.disable('x-powered-by')

	app.set('trust proxy', 1) // trust first proxy

	app.use(session({ 
		secret: 'hey super cat secret key', // session secret
		resave: false, 
		saveUninitialized: true,
		store: new MongoStore({ 
			mongooseConnection: options.mongoose.connection 
		}),
		cookie: {
			domain: options.cookieDomain
		}
	}))

	app.use(flash()) // error messages during login
	// app.use(cookieParser()) // read cookies (useless for new express-session)

	app.use(passport.initialize())
	app.use(passport.session()) // persistent login sessions

	app.post('/login', passport.authenticate('local-login', { 
			failureRedirect: '/login', 
			failureFlash: true 
		}), (req, res, next) => {
		
		const redirect = req.session.redirectTo || options.redirectLogin
		res.redirect(redirect)
	})

	app.post('/signup', passport.authenticate('local-signup', {
			failureRedirect : '/signup',
			failureFlash : true 
		}), (req, res, next) => {
		
		const redirect = req.session.redirectTo || options.redirectSignup
		res.redirect(redirect)
	})

	if (options.connectors.github) {
		app.get('/auth/github', passport.authenticate('github'))
		app.get('/auth/github/callback', 
			passport.authenticate('github', {
				failureRedirect: '/login',
				failureFlash : true
			})
		, (req, res, next) => {
			const redirect = req.session.redirectTo || options.redirectLogin
			res.redirect(redirect)
		})
	}

	if (options.connectors.google) {
		app.get('/auth/google', 
			passport.authenticate('google', {
				scope: [ 
					'https://www.googleapis.com/auth/userinfo.profile', 
					'https://www.googleapis.com/auth/userinfo.email' 
				]
			})
		)
		
		app.get('/auth/google/callback',
			passport.authenticate('google', {
				failureRedirect: '/login',
				failureFlash : true
			})
		, (req, res, next) => {
			const redirect = req.session.redirectTo || options.redirectLogin
			res.redirect(redirect)
		})
	}


	app.get('/signup', secureHeaders, (req, res, next) => {
		if (options.disableSignup) {
			return next('Sorry, signups are disabled for the time being.')
		} 

		const pageOptions = options.pages.signup

		res.render(__dirname+'/views/login', { 
			title: pageOptions.title,
			subtitle: pageOptions.subtitle,
			page: 'Sign Up',
			error: req.flash('error'),
			info: req.flash('info'),
			options: options
		})
	})

	app.get('/login', secureHeaders, (req, res) => {
		if (req.isAuthenticated()) return res.redirect(options.redirectLogin)

		const pageOptions = options.pages.login

		res.render(__dirname+'/views/login', {
			title: pageOptions.title,
			subtitle: pageOptions.subtitle,
			page: 'Log In',
			error: req.flash('error'),
			info: req.flash('info'),
			options: options
		})
	})

	app.get('/reset', secureHeaders, (req, res) => {
		const token = req.query.t
		const pageOptions = options.pages.reset

		res.render(__dirname+'/views/reset', {
			title: pageOptions.title,
			subtitle: pageOptions.subtitle,
			page: 'Reset password',
			message: req.flash('error'),
			options: options,
			token: token
		})
	})

	app.get('/forgot', secureHeaders, (req, res) => {
		
		const pageOptions = options.pages.forgot

		res.render(__dirname+'/views/forgot', {
			title: pageOptions.title,
			subtitle: pageOptions.subtitle,
			page: 'Forgot password',
			options: options
		})
	})

	app.get('/logout', (req, res) => {
		req.session.destroy( err => {
			res.redirect('/login')
		})
	})

	app.post('/forgot', asyncHandler(async (req, res, next) => {
		const email = req.body.email.toLowerCase().trim()

		const user = await options.mongoUser.findOne({ email: email })
		if (user) {
			const token = jwt.sign({ userId: user._id }, options.secret, { expiresIn: '1h' })
			const link = `https://${options.siteUrl}/reset?t=${token}`

			options.sendMail(`Reset your password`, `Hi,\n\nPlease follow this link to reset your password: ${link}`, user.email)
		}

		req.flash('info', 'Check your mailbox for a link to reset your password.')
		res.redirect('/login')
	}))

	app.post('/reset', asyncHandler(async (req, res, next) => {
		const token = req.body.token
		const newPswd = req.body.password

		const payload = jwt.verify(token, options.secret)

		const user = await options.mongoUser.findByIdAndUpdate(payload.userId, {
			pswd: bcrypt.hashSync(newPswd, bcrypt.genSaltSync(8), null)
		})

		options.sendMail(`⚠️ Password reset`, `Hello,\n\nWe inform you that your ${options.siteName} password was reset.\nIf you are not behind this operation, reply to this email immediately.\n\nHave a great day.\n\nThe ${options.siteName} team.`, user.email)
		
		req.flash('info', 'Your password was successfully changed.')
		res.redirect('/login')
	}))

	app.get('/account/accessToken', asyncHandler(async (req, res, next) => {
		if (!req.isAuthenticated()) return res.redirect('/login')

		await options.mongoUser.findByIdAndUpdate(req.user.id, {
			accessToken: generateAccessToken()
		})

		options.sendMail(`⚠️ Access token renewed`, `Hello,\n\nWe inform you that you have successfully renewed your API access token.\nIf you are not behind this operation, reply to this email immediately.\n\nHave a great day.\n\nThe ${options.siteName} team.`, req.user.email)
	
		res.redirect(options.redirectLogin)
	}))

	app.use('/api', (req, res, next) => {
		if (!req.isAuthenticated()) {
			res.status(403)
			return next("Unauthorized.")
		}
	})

	/** API for using without front part (like custom react) */
	app.get('/api/account', asyncHandler(async (req, res, next) => {
		res.send({ data: req.user })
	}))

	app.post('/api/account/accesstoken', asyncHandler(async (req, res, next) => {
		await options.mongoUser.findByIdAndUpdate(req.user.id, {
			accessToken: generateAccessToken()
		})

		options.sendMail(`⚠️ Access token renewed`, `Hello,\n\nWe inform you that you have successfully renewed your API access token.\nIf you are not behind this operation, reply to this email immediately.\n\nHave a great day.\n\nThe ${options.siteName} team.`, req.user.email)
	
		res.send({})
	}))
	
	app.post('/api/account/password', asyncHandler(async (req, res, next) => {
		const { current, newPassword } = req.body

		const user = await options.mongoUser.findById(req.user.id).exec()
		if (!user) return next(403)

		if (user.pswd && !bcrypt.compareSync(current, user.pswd)) return next("Invalid current password.")

		user.pswd = bcrypt.hashSync(newPassword, bcrypt.genSaltSync(8), null)

		await user.save()

		options.sendMail(`⚠️ Password changed`, `Hello,\n\nWe inform you that you have successfully changed your ${options.siteName} password.\nIf you are not behind this operation, reply to this email immediately.\n\nHave a great day.\n\nThe ${options.siteName} team.`, req.user.email)

		res.send({})
	}))


	app.get('/account/account.js', (req, res, next) => {
		res.sendFile(__dirname+'/account.js')
	})
}
