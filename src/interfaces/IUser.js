class IUser {
    /*
    Crear un nuevo usuario
    @param {string} email -> correo del usuario.
    @param {string} password -> contraseña del usuario.
    @returns {Promise<User>}.
    @throws {error} si hay algún error en la creación.
    */
    static async createUser (email, password) {}
    static async findByEmail (email) {}
    static async getAllUsers() {}
    async verifyPassword(password) {}
}

module.exports = IUser