const express = require('express');
const router = express.Router();
const UserController = require('../UserController');

router.post('/login', function (req, res) {
    const {username, password} = req.body;
    console.log("login: ", username, password);
    res.send('hello login')
});

router.post('/register', UserController.register);

module.exports = router;