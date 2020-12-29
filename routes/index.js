const Guest = require ('./Guest');
const User = require ('./User');


function Routes(app, rootApp) {
    app.get('/login', (req, res) => {
        const file = rootApp + '/views/login.html';

        res.sendFile(file)
    });
    app.use('/', Guest);
    app.use('/user', function(req, res, next) {
        next();
        console.log(res);
    }, User);
}

module.exports = Routes;