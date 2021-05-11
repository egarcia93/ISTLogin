const express = require('express');
const app = express();
const dotenv = require ('dotenv');
const mongoose = require('mongoose');

//Import Routes

const authRoute = require('./routes/auth');
const postsRoute = require('./routes/posts');

dotenv.config();
//Connect to DB
mongoose.connect(process.env.DB_CONNECT,
{ useNewUrlParser: true },


() => console.log('connected to db')

);

//Middleware
app.use(express.json());


//Route Middleware
app.use('/api/user',authRoute);
app.use('/api/posts',postsRoute);

app.listen(3000, () => console.log('Server running'));

