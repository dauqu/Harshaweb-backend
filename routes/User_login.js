const express = require("express");
const router = express.Router();
const user = require("../models/User");
require("dotenv").config();
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookiParser = require("cookie-parser");

router.use(cookiParser());

router.post("/", async (req, res) => {
    try {
        const { email, password } = req.body;
        // console.log(req.body)
        const user_collection = await user.findOne({ email }).lean();
        if (!user_collection)
            return res.status(400).json({ message: "email is wrong ", status: "warning" });

        const hash_psw = user_collection.password;

        if (!bcryptjs.compareSync(password, hash_psw))
            return res.status(400).json({ message: "  passord is wrong ", status: "warning" });


        // token
        const token = jwt.sign({
            id: user_collection._id,
            name: user_collection.name,
            username: user_collection.username,
            address: user_collection.address,
            email: user_collection.email,
            age: user_collection.age
        }, 
           process.env.JWT_SECRET,
        {
            algorithm: "HS256",
        }
        )
        // cookies
        res.cookie("auth_token", token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 300,
            sameSite: "none",
            secure: true,
        })

        // // set localstorage 
        // res.locals.user = {
        //     id: user_collection._id,
        //     email: user_collection.email, 
        // }; 
        
        res.setHeader("x-auth-token", token);
        res.cookie("auth_token", token);
        res.status(200).json({ message: "login success", status: "success", token: token });
 
    } catch (error) {
        res.status(500).json({ message: error.message, status: "error" })
    }
})


// check user is login or not 
router.get("/check_have_token", (req, res) => {
    try {
        const have_valid_token = jwt.verify(
            req.cookies.token,
            process.env.JWT_SECRET
        )

        // get user if from token
        const id_from_token = have_valid_token.id;
        const email= have_valid_token.email;
        console.log(email); 
        res.send(email);


        // check same id have database
        const user_id = Admin.findById(id_from_token);
        if (user_id == undefined) {
            res.json(false)
        }
        else {
            res.json(true);
        }
    } catch (error) {
        res.json(false)
    }
})

// check valid token 
router.get("/check_valid_token", (req, res) => {
    try {
        const have_valid_token = jwt.verify(
            req.cookies.token,
            process.env.JWT_SECRET
        )
        res.json(true);
    } catch (error) {
        res.json(false);
    }
});

// check token id is same with user id 
router.get("/checkLogin", (req, res) => {
    try {
        const have_valid_token = jwt.verify(
            req.cookies.token,
            process.env.JWT_SECRET
        )
        // get user id from token 
        const id_from_token = have_valid_token.id;

        // check same id have same database
        const user_id = Admin.findById(id_from_token);
        if (user_id == undefined) {
            res.json(false)
        }
        else {
            res.json(true)
        }
    } catch (error) {
        res.json(false)
    }
})


module.exports = router;