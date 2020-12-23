const crypto = require('crypto');

const SECRETKEY = "635552f2395643d2b716d400de11cd2c";
const DURATION = 1800;
const ALGORITHMS = [
    'HS256', 'HS384', 'HS512',
];

function jwsSecuredInput(header, payload, duration = 3600){
    const encodeHeader = Buffer.from(JSON.stringify(header)).toString('base64');
    const iat = Math.floor(new Date().getTime()/1000);
    payload.iat = iat;
    payload.exp = iat + duration;
    const encodePayload = Buffer.from(JSON.stringify(payload)).toString('base64');
    return `${encodeHeader}.${encodePayload}`
}

function sign(header, securedInput, secretKey) {
    const match = header.alg.match(/^(HS)(256|384|512)$|^(none)$/);
    if(!match)
        return console.log(header.alg + ' is not a valid algorithm.\nSupported algorithms are:\n  ', JSON.stringify(ALGORITHMS));
    const bits = match[2];

    // const md5 = crypto.createHash('md5')
    //     .update(securedInput)
    //     .digest('hex');

    const hash = crypto.createHmac('sha' + bits, secretKey)
        .update(securedInput)
        .digest('hex');
    return Buffer.from(hash).toString('base64')
}

const header = {
    "alg": "HS256",
    "typ": "JWT"
}

const payload = {
    "sub": "123456789",
    "iss": "tuannv191292@gmail.com"
}

const securedInput = jwsSecuredInput(header, payload, DURATION);
const signature = sign(header, securedInput, SECRETKEY);

// check jwt https://jwt.io/
console.log("jwt: %s.%s", securedInput, signature);
