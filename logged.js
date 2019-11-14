/*
* Middleware that can make sure an user is logged
* Before accessing a certain page
* Supports APIs with access token
*/

const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next)

module.exports = (dbUser) => {

	return asyncHandler(async (req, res, next) => {

		const token = req.body.token || req.get('x-access-token') || req.get("authorization")
		
		let user = null

		if (token) {
			user = await dbUser.findOne({ accessToken: token }).exec()
			
			if (!user) return next('Invalid access token')
		} else  {
			if (!req.user) {
				req.session.redirectTo = req.originalUrl
				return res.redirect('/login')
			}

			user = req.user
		}

		res.locals.user = user

		next()
	})
}