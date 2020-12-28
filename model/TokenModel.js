const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
    user_uid: String,
    uid_token: String,
    is_revoke: Boolean, // check logout
    created_at: Number,
    updated_at: Number,
});

module.exports = mongoose.model('Tokens', tokenSchema);