const User = require('./UserModel');
const Token = require('./TokenModel');
const bcrypt = require('bcrypt');
const jws = require('jws');
const crypto = require('crypto');
const { v4: uuidV4  } = require('uuid');
const dotenv = require('dotenv');
dotenv.config();

const saltRounds = parseInt(process.env.BCRYPT_SALT || 12);
const secret = process.env.API_KEY || "12345678";
const duration = parseInt(process.env.JWT_DURATION || 3600);
const hmac = crypto.createHmac('sha256', secret);

async function createUser(req, res) {
    const {username, password} = req.body;
    console.log('createUser: ', username, password);
    try {
        const salt = await bcrypt.genSalt(saltRounds);
        const hashPassword = await bcrypt.hash(password, salt);
        const newUser = new User({username, password: hashPassword});
        const user = await newUser.save();
        const iat = Math.floor(new Date()/1000);
        const exp = iat + duration;

        const signature = jws.sign({
            header: {alg: 'HS256', type: "JWT"},
            payload: {uid: user._id, iat, exp},
            secret
        });
        const uid_token = uuidV4();
        hmac.update(uid_token);
        const refresh_token = new Buffer(hmac.digest('hex')).toString('base64');
        const newToken = new Token({user_uid: user._id, uid_token: uid_token, is_revoke: false, created_at: iat, updated_at: iat});
        await newToken.save();
        res.status = 201;
        res.send({user, accessToken: signature, refresh_token});
    } catch (err) {
        res.status = 400;
        res.send(err)
    }
}

module.exports = {
    register: createUser
}