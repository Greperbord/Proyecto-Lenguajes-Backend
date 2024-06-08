const jwt = require('jsonwebtoken')
require('dotenv').config()

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']
    const access = token.split(' ')
    console.log('@@ token => ', token)
    if (!access[1]) {
        return res.status(401).json({
            message: 'Unathorized'
        })
    }

    jwt.verify(access[1], process.env.SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({
                message: 'Forbidden'
            })
        }

        req.user = user
        next()
    })
}

module.exports = authenticateToken
