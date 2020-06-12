const crypto = require('crypto')

const isObject = (item) => (item && typeof item === 'object' && !Array.isArray(item))

function mergeDeep(...objects) {
  const isObject = obj => obj && typeof obj === 'object'
  
  return objects.reduce((prev, obj) => {
    Object.keys(obj).forEach(key => {
      const pVal = prev[key]
      const oVal = obj[key]
      
      if (Array.isArray(pVal) && Array.isArray(oVal)) {
        prev[key] = pVal.concat(...oVal)
      }
      else if (isObject(pVal) && isObject(oVal)) {
        prev[key] = mergeDeep(pVal, oVal)
      }
      else {
        prev[key] = oVal
      }
    })
    
    return prev
  }, {})
}

module.exports = {
	// Catching errors when using async functions
	asyncHandler: fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next),

  // URL Safe random string generator
	generateAccessToken: () => crypto.randomBytes(32).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, ''),

	// clickjacking protection
	secureHeaders: (req, res, next) => {
		res.set('X-Frame-Options', 'DENY')
		next()
	},

	mergeDeep: mergeDeep

}