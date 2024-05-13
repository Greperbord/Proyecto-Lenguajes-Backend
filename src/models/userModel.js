const firebase = require('../config/firebase')
const usersCollection = firebase.firestore().collection('users')

exports.createUser = async (userData) => {
    try {
        await usersCollection.doc(userData.id).set(userData)
        return {
            success: true
        }
    } catch (error) {
        return {
            success: false,
            error: error.message
        }
    }
}

exports.findUserById = async (userId) => {
    try {
        const userFound = await usersCollection.doc(userId).get()
        if (userFound.exists) {
            return {
                success: true,
                user: userDoc.data()
            }
        } else {
            return {
                success: false,
                user: 'User Not Found'
            }
        }
    } catch (error) {
        return { 
        success: false,
        error: error.message
        }
    }
}

exports.findUserByEmail = async (email) => {
    try {
       const userEmail = await usersCollection.where('email', '==', email).get()
       if (!userEmail.empty) {
            const userFound = userEmail.docs[0]
            return {
                success: true,
                user: userFound.data()
            }
       } else {
        return {
            success: false,
            error: 'User Not Found'
        }
       }
    } catch (error) {
        return { 
            success: false,
            error: error.message
            }
    }
}