const express = require("express");
const router = express.Router();
const User_Schema = require("../models/User");
const app = express()


// router.get("/", (req, res) => {
//     res.json({ message: "Image Getting Api" })
// })


router.use("/", express.static("./uploads"));


router.post("/", async (req, res) => {
    try {
        if (!req.files) {
            res.send({
                status: "error",
                message: "Error: No file uploaded",
            });
        } else {
            // Send File on Location
            const uploadedFile = req.files.uploadedFile;
            uploadedFile.mv("./uploads/" + uploadedFile.name);
            res.send({
                status: "success",
                message: "File successfully uploaded",
                url: `http://localhost:4000/api/imageupload/${uploadedFile.name}`,
            });
        }
    } catch (err) {
        res.status(500).json({ message: "error.message" });
    }
});

module.exports = router;