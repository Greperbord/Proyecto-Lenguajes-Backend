const bcrypt = require('bcrypt')
const jsonwebtoken = require('jsonwebtoken')
const { createUser, findUserByEmail } = require('../services/userService')

exports.signup = async (req, res) => {
    try {
        //Codigo Para Registrarse
        const { email, password, id } = req.body
        const existingUser = await findUserByEmail(email)
        if(existingUser.success) {
            return res.status(400).json({
                message: 'El Usuario ya Existe'
            })
        }

        const saltRounds = 10
        const hashedPassword = await bcrypt.hash(password, saltRounds)

        const newUser = {
            email: email,
            password: hashedPassword,
            id: id
            // Agregar otros campos
        }
        console.log(newUser)
        const userResult = await createUser(newUser)
        console.log(userResult)
        if (userResult.success) {
            res.status(201).json({
                message: 'Usuario Registrado Correctamente'
            })
        } else {
            res.status(500).json({
                message: 'Error al Registrar el Usuario'
            })
        }
    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}

exports.login = async (req, res) => {
    try {
        //Codigo Para loggearnos
        const { email, password } = req.body
        const findEmail = await findUserByEmail(email)

        if (!findEmail.success) {
            res.status(401).json({
                message: 'Usuario No Encontrado'
            })
        }

        const user = findEmail.user
        const findPassword = await bcrypt.compare(password, user.password)
        
        if (!findPassword) {
            res.status(401).json({
                message: 'Contraseña Incorrecta'
            })
        }

        const token = jsonwebtoken.sign({
            email: user.email,
            userId: user.id
        }, process.env.TOP_SECRET, {
            expiresIn: '1h'
        })

        res.status(200).json({
            token: token
        })

    } catch (error) {
        res.status(500).json({
            message: error.message
        })
    }
}
