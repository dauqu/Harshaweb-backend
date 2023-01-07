const express = require("express");
const router = express.Router();
const Register_Models = require("../models/User");
// const { route } = require("./Userprofile");
require("dotenv").config();


// router.get("/",(req,res) =>{
//     res.send("hello from usr list")
// })


router.get("/", async(req,res) =>{

    try {
        
        const user_list= await Register_Models.find();
        res.status(200).json(user_list);
    } catch (error) {
        res.status(400).json({message: error.message});
    }

})
module.exports=router;