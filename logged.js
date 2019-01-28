module.exports = (req, res, next) => {
	if (req.user) { 
		res.locals.user = req.user
		return next() 
	}
	
	//req.session.returnTo = req.originalUrl
	
	res.redirect('/login')
}