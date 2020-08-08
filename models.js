var mongoose = require('mongoose');

mongoose.model('User', mongoose.Schema({
    email: String,
    passwordHash: String,
    subscriptionActive: {type: Boolean, default: false}
}))