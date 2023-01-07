const express = require("express");
const router = express.Router();
const Register_Models = require("../models/Admin");
const JWT = require("jsonwebtoken");
 
require("dotenv").config();

router.get("/", async (req, res) => {
    const token = req.cookies.token != undefined || req.cookies.token != null || req.cookies.token != "";
    if (token) {
        return res.send("")
    } 
    try {
        if (token) {
            const have_valid_token = JWT.verify(
                req.cookies.token,
                process.env.JWT_SECRET
            );
            const id_from_token = have_valid_token.id;
            const admin_data = await Register_Models.findById(id_from_token);
            res.json(admin_data);
        }
        else {
            req.json({ message: "You are not login", status: "warning" });

        }
    } catch (error) {
        res.status(500).json({ message: error.message, status: "error" })
    }


})
module.exports = router;