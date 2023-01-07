const { Timestamp } = require('mongodb');
const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
    fname:{
        type:String,
    },
    lname:{
        type:String,
    },
    email:{
        type:String,
    },
    phone:{
        type:String,
    },
    service:{
        type:String,
    },
    subject:{
        type:String,
    },
    message:{
        type:String,
    }
}, {timestamps : true});

module.exports= mongoose.model('Contact', contactSchema);

