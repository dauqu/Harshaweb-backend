const mongoose = require('mongoose');
const web_reqSchema= new mongoose.Schema({
    url:{
        type:String,
    },
    frontend:{
        type:String,
    },
    backend:{
        type:String,
    },
    database:{
        type:String,
    },
    webType:{
        type:String,
    },
    name:{
        type:String,
    },
    email:{
        type:String,
    },
    phoneNumber:{
        type:String,
    },
    message:{
        type:String,
    },
    totalEstimate:{
        type:String,
    },
    numberOfPages:{
        type:String,
    },
},{timestamps:true});
module.exports= mongoose.model('web_req',web_reqSchema);