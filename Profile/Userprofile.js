const express = require("express");
const router = express.Router();
const Register_Models = require("../models/User");
const jwt = require("jsonwebtoken");

require("dotenv").config();

router.get("/", async (req, res) => {

    const user_token = req.cookies.auth_token || req.body.token || req.headers["x-auth-token"]
   
    if(user_token==undefined || user_token == null || user_token == " "){
        return res.status(401).json({message: "unauthorized"})
    }

    const decode = jwt.verify(user_token , process.env.JWT_SECRET)  
    if(!decode){
        return res.json(false)    
    }
    console.log(decode)

    
    try {
        const user= await Register_Models.findOne({  _id: decode.id })
        res.status(200).json(user);
        console.log(user)
       
    } catch (error) {
        res.status(500).json({ message: error.message, status: "error" })
    }
    
})


module.exports = router;