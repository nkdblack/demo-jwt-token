const express = require('express');
const router = express.Router();

router.get('/change-password', function (req, res) {
    res.send('hello login')
})

router.get('/refresh-token', function (req, res) {
    res.send('hello login 2')

})

module.exports = router;