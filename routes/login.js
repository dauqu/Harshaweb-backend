const express = require("express");
const router = express.Router();
const Admin = require("../models/Admin");
require("dotenv").config();
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookiParser = require("cookie-parser");
const AdminSchema = require("./../models/Admin");

router.use(cookiParser());

router.post("/", async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(req.body);
        const admin_collection = await Admin.findOne({ email }).lean();
        if (!admin_collection)
            return res.status(400).json({ message: "email is wrong ", status: "warning" });

        const hash_psw = admin_collection.password;

        if (!bcryptjs.compareSync(password, hash_psw))
            return res.status(400).json({ message: "  passord is wrong ", status: "warning" });


        // token
        const token = jwt.sign({
            id: admin_collection._id,
            email: admin_collection.email
        }, process.env.JWT_SECRET)

        // cookies
        res.cookie("auth_token", token, {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 30,
            sameSite: "none",
            secure: true,
        })

        // // set localstorage 
        // res.locals.admin = {
        //     id: admin._id,
        //     email: admin.email,
        // };

        res.setHeader("x-auth-token", token);
        res.cookie("auth-token", token);

        res.status(200).json({ message: "login success", status: "success", token: token });

    } catch (error) {
        res.status(500).json({ message: error.message, status: "error" })
    }
})


// check valid token 
router.get("/check_valid_token", async (req, res) => {
    //Check user have token or not
  const token = req.cookies.auth_token || req.body.token || req.headers["x-auth-token"];

  if (token == undefined || token == null || token == "") {
    return res.json(false);
  }

  const have_valid_tokem = jwt.verify(token, process.env.JWT_SECRET, {
    algorithm: "HS256",
  });

  if (!have_valid_tokem) {
    return res.json(false);
  }

  const id_from_token = have_valid_tokem.id;

  //Check Same id have database
  const user = await AdminSchema.findOne({ id_from_token }).lean();

  if (user == undefined || user == null || user == "") {
    res.json(false);
  } else {
    res.json(true);
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