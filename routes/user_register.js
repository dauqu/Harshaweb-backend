const express = require("express");
const router = express.Router();
const user = require("../models/User");
const bcryptjs = require("bcryptjs");

// get user
router.get("/", async (req, res) => {
  // res.json({ message: "Getting signup API" })
  try {
    const user_collection = await user.find();
    res.json(user_collection);
  } catch (error) {
    res.status(500).json({ message: "error in getting user", status: "error" });
  }
});

//  getting user by id from database 
router.get("/:id", async (req, res) => {
  try {
    const user_collection = await user.findById(req.params.id);
    res.json(user_collection);
  } catch (error) {
    res.status(500).json({ message: "error in getting user", status: "error" });
  }
});

// update uniqueKey of user by getting user
router.patch("/update/:id", async (req, res) => {
  try {
    const user_collection = await user.findById(req.params.id);
    if (user_collection == null) {
      return res.status(404).json({ message: "user not found" });
    }
    if (req.body.uniqueKey != null) {
      user.uniqueKey = req.body.uniqueKey;
    }
    const updatedUser = await user_collection.save();
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ message: error.message, status: "error" });
  }
});

// create user
router.post("/",SignupValidation,   async (req, res) => {
  console.log(req.body);

  // hashing password
  const salt = await bcryptjs.genSalt();
  const hashed_password = await bcryptjs.hash(req.body.password, salt);

  const user_collection = new user({
    name: req.body.name,
    username: req.body.username,
    phone: req.body.phone,
    address: req.body.address,
    email: req.body.email,
    password: hashed_password,
    age: req.body.age,
  });

  try {
    const newUser = await user_collection.save();
    res.json(newUser);
  } catch (error) {
    res.status(500).json({ message: error.message, status: "error" });
  }
});

// middleware for register user validation
async function SignupValidation(req, res, next) {
  // check if user exist
  const user_exist = await user.findOne({ email: req.body.email });
  if (user_exist)
    return res
      .status(400)
      .json({ message: "User already exists", status: "error" });

  // check email is valid
  const email = req.body.email;
  const email_regex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
  if (!email_regex.test(email))
    return res
      .status(400)
      .json({ message: "Email is not valid ", status: "error" });

  //Check username is valid
  const username = req.body.username;
  const username_regex = /^[a-zA-Z0-9]{3,20}$/;
  if (!username_regex.test(username))
    return res.status(400).json({
      message: "Username is not valid",
      status: "error",
    });

  //Check Phone Number is valid
  if (req.body.phone) {
    const phone = req.body.phone;
    const phone_regex = /^[0-9]{10}$/;
    if (!phone_regex.test(phone))
      return res.status(400).json({
        message: "Phone Number is not valid",
        status: "error",
      });
  }

  //check age
  if (req.body.age) {
    const age = req.body.age;
    const min_age = 18;
    if (age < min_age)
      return res
        .status(400)
        .json({
          message: "You are not eligible because of your age is less than 18",
          status: "error",
        });
  }

  next();
}

module.exports = router;
