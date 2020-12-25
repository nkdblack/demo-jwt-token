const express = require('express');
const dotenv = require('dotenv');
const Routes = require('./routes');
const mongoose = require('mongoose');

dotenv.config();
const PORT = process.env.PORT || 4000;
const DATABASE_URI = process.env.DATABASE_URI || '';
mongoose.connect(DATABASE_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const app = express();
app.use(express.json({extended: false}));

Routes(app);

app.listen(PORT, function () {
    console.log("app listen " + PORT)
});