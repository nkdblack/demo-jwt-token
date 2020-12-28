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
const refreshTokenDuration = parseInt(process.env.REFRESH_TOKEN_DURATION || 31563000);

function encrypt(uid_token, key) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, 'e59656c34b0f3b67');
    let refresh_token = cipher.update(uid_token, 'utf8', 'hex');
    refresh_token += cipher.final('hex');
    refresh_token = new Buffer.from(refresh_token).toString('base64');
    return refresh_token
}

function decrypt(refresh_token, key) {
    const decryptBase64 = new Buffer.from(refresh_token, 'base64').toString('utf8');
    const cipher = crypto.createDecipheriv('aes-256-cbc', key, 'e59656c34b0f3b67');
    let decrypted = cipher.update(decryptBase64, 'hex', 'utf8');
    decrypted += cipher.final('utf8');
    return decrypted;
}

async function createUser(req, res) {
    const {username, password} = req.body;
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
        const refresh_token = encrypt(uid_token, secret);

        const newToken = new Token({user_uid: user._id, uid_token: uid_token, is_revoke: false, created_at: iat, updated_at: iat});
        await newToken.save();
        res.status = 200;
        res.send({user, accessToken: signature, refresh_token});
    } catch (err) {
        res.status = 400;
        res.send(err)
    }
}

async function refreshToken(req, res) {
    const {refreshToken} = req.body;
    try {
        const accessToken = req.headers.authorization.split("Bearer ")[1];
        const {alg} = jws.decode(accessToken).header;
        if(!jws.verify(accessToken, alg, secret))
            res.status(301)
                .location('http://mydomain.com/login')
                .send("OK");

        const {uid} = JSON.parse(jws.decode(accessToken).payload);
        // let payload = accessToken.split('.')[1]
        // payload =  new Buffer.from(payload, 'base64').toString('utf8');
        // const {uid} = JSON.parse(payload);

        const uidToken = decrypt(refreshToken, secret);
        if(!uidToken)
            res.status(301)
                .location('http://mydomain.com/login')
                .send("OK");

        console.log("uid User: ", uid);
        console.log("uid Token: ", uidToken);

        res.send(uidToken)
    } catch (err) {
        res.status(301)
            .location('http://mydomain.com/login')
            .send("OK");
    }
}

module.exports = {
    register: createUser,
    refreshToken: refreshToken
}