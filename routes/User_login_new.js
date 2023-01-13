const express = require("express");
const router = express.Router();
const User = require("../models/User");
require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


router.post("/", async (req, res) => {
  try {
    const { email, password } = req.body;
    const admin_collection = await User.findOne({ email });
    if (!admin_collection)
      return res
        .status(400)
        .json({ message: "email is wrong ", status: "warning" });

    const valid_password = await bcrypt.compare(
      password,
      admin_collection.password
    );

    if (!valid_password)
      return res
        .status(400)
        .json({ message: "  passord is wrong ", status: "warning" });

    // token
    const token = jwt.sign(
      { id: admin_collection._id, email: admin_collection.email },
      process.env.JWT_SECRET
    );

    // cookies
    res.cookie("auth_token", token, {
      maxAge: 24 * 60 * 60 * 1000,
      sameSite: "none",
      secure: true
    });


    res.status(200).json({ message: "login success !!", status: "success", token: token });
  } catch (error) {
    res.status(500).json({ message: error.message, status: "error" });
  }
});

// check valid token
router.get("/check_valid_token", async (req, res) => {
  //Check user have token or not
  const token =
  req.cookies.auth_token || req.body.token || req.headers["x-auth-token"];
  console.log("token "+ token);
  try {
    if (token == undefined || token == null || token == "") {
      return res.json(false);
    }

    const have_valid_tokem = await jwt.verify(token, process.env.JWT_SECRET);
    if (!have_valid_tokem) {
      return res.json(false);
    }

    const id_from_token = have_valid_tokem.id;

    //Check Same id have database
    const user = await User.findById(id_from_token);

    if (user == undefined || user == null || user == "") {
      res.json(false);
    } else {
      res.json(true);
    }
  } catch (error) {
    return res.json({ message: error.message, status: "error" });
  }
});

// check token id is same with user id
router.get("/checkLogin", async (req, res) => {
  try {
    const have_valid_token = await jwt.verify(
      req.cookies.token,
      process.env.JWT_SECRET
    );
    // get user id from token
    const id_from_token = have_valid_token.id;

    // check same id have same database
    const user_id = User.findById(id_from_token);
    if (user_id == undefined) {
      res.json(false);
    } else {
      res.json(true);
    }
  } catch (error) {
    res.json(false);
  }
});

module.exports = router;
