const bcrypt = require('bcrypt')
const admin = require('../config/firebase')
const IUser = require('../interfaces/IUser')
const firestore = admin.firestore()

class User extends IUser {
    constructor (email, password, nombre, apellido, telefono) {
        super()
        this.email = email
        this.password = password
        this.nombre = nombre
        this.apellido = apellido
        this.telefono = telefono
    }

    static async createUser (email, password, nombre, apellido, telefono) {
        try {
            const hash = await bcrypt.hash(password, 10)    
            const user = firestore.collection('users').doc(email)
            await user.set({
                email, 
                password: hash,
                nombre,
                apellido,
                telefono
            })

            return new User(email, password, nombre, apellido, telefono)
        } catch (error) {
            console.log('@@ Error => ', error)
            throw new Error ('Error creating user')
        }
    }

    async verifyPassword (password) {
        return await bcrypt.compare(password, this.password)
    }

    static async getAllUsers() {
        try {
            const users = await firestore.collection('users').get()
            const foundUsers = []
            users.forEach(doc => {
                foundUsers.push({
                    email: doc.email,
                    ...doc.data()
                })
            })
            return foundUsers
        } catch (error) {
            throw error
        }
    }

    static async findByEmail(email) {
        try {
            const user = firestore.collection('users').doc(email)
            const userDoc = await user.get()
            if(userDoc.exists) {
                const userData = userDoc.data()

                return new User(userData.email, userData.password)
            }
            return null
        } catch (error) {
            console.log('@@ Error => ', error)
            throw new Error ('Error finding user')
        }
    }
}

module.exports = User