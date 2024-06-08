const jwt = require('jsonwebtoken')
const User = require('../models/User')

const loginUser = async(req, res) => {
    try {
        const { email, password } = req.body

        // Buscamos el usuario para verificar que existe el correo electrónico
        // ahora con firebase-admin solo lo podemos poner así.
        const userDoc = await User.findByEmail(email)

        // Si no existe el usuario.
        if (!userDoc) {
            return res.status(404).json({
                message: 'User not found:C'
            })
        }

        // Verificar si el password es correcto.
        const isValidPass = await userDoc.verifyPassword(password)

        if(!isValidPass) {
            return res.status(401).json({
                message: 'Invalid credentials(❁´◡`❁)'
            })
        }

        // Generar el TOKEN.
        const token = jwt.sign({ email: userDoc.email }, process.env.SECRET, { expiresIn: '1h' })
        res.status(200).json({ 
            message: 'success',
            token 
        })
    } catch (error) {
        res.status(500).json({
            message: 'Internal Server Error😭'
        })
    }
}

const registerUser = async(req, res) => {
    try {
        const { email, password, nombre, apellido, telefono } = req.body
        const existingUser = await User.findByEmail(email)

        if (existingUser) {
            return res.status(404).json({
                message: 'User already exists🫣'
            })
        }

        const newUser = await User.createUser(email, password, nombre, apellido, telefono)

        res.status(201).json({
            message: 'User registered successfully',
            user: newUser
        })
    } catch (error) {
        res.status(500).json({
            message: 'Internal Server Error😭'
        })
    }
}

const getAllUsers = async(req, res) => {
    try {
        const users = await User.getAllUsers()
        res.json({
            users,
            message: 'success'
        })
    } catch (error) {
        res.status(500).json({
            message: 'Internal Server Error😭'
        })
    }
}

module.exports = { registerUser, loginUser, getAllUsers }
