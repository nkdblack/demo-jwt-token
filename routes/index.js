const Guest = require ('./Guest');
const User = require ('./User');


function Routes(app) {
    app.use('/', Guest);
    app.use('/user', function(req, res, next) {
        next();
        console.log(res);
    }, User);
}

module.exports = Routes;