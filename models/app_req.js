const mongoose= require('mongoose');
const app_reqSchema= new mongoose.Schema({
    url:{
        type:String,
    },
    appTech:{
        type:String,
    },
    appType:{
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
module.exports= mongoose.model('app_req',app_reqSchema);