const express = require("express");
const router = express.Router();
// const Admin = require("../models/User");
require("dotenv").config();
// const bcryptjs = require("bcryptjs");
// const cookieParser =require("cookie-parser");

router.get("/", (req, res) => {
    res.clearCookie("auth_token")
    res.json({ message: "Logout Success", status: "success" })
})
module.exports = router;