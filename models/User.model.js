const mongoose = require('mongoose')

let UserSchema = new mongoose.Schema({
    username: {
        type:String,
        unique: true,
        required: true
    },
    password: {
        type:String,
        required: true
    }
})
let UserModel = mongoose.model('users', UserSchema)

module.exports = UserModel