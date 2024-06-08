const express = require('express')
const router = express.Router()
const { registerUser, loginUser, getAllUsers } = require('./../controller/userController')
const authenticateToken = require('./../auth/authMiddleware')

router.post('/register', registerUser)
router.post('/login', loginUser)
router.get('/get-all-users', authenticateToken, getAllUsers)

module.exports = router
