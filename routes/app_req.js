const express= require('express');
const router= express.Router();
const app_req= require('../models/app_req');
const upload_app = require("../file_upload_app");

//post upload file
router.post("/", upload_app.single("file"), async (req, res) => {

    const {name, email, phoneNumber} = req.body;

    //check if email is valid
    const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
    if (!emailRegex.test(email))
      return res.status(400).json({ message: "Email is not valid" });
      
  
    //check if phone number is valid const phoneRegex = /^\d{10}$/;
       const phoneRegex = /^\d{10}$/;
      if(!phoneRegex.test(phoneNumber)) return res.status(400).json({message:"Phone number must be 10 digits long"});
      
  
       //check if name is valid
       const nameRegex = /^[a-zA-Z ]{2,30}$/;
       if(!nameRegex.test(name)) return res.status(400).json({message:"Name is not valid"});

    try {
        const url = req.protocol + "://" + req.get("host") + "/" + req.file.filename;
        const post_file = new app_req({
            ...req.body,
            url: url,
        });
        await post_file.save();
        return res.json({ message: "File uploaded ", status: "success", app_req: post_file });
    } catch (error) {
        return res.json({ message: "File not uploaded ", status: "failed" });
        
    }
});

//get all files
router.get("/", async (req, res) => {
    try {
        const all_files = await app_req.find();
        return res.json({ message: "All files", status: "success", all_files });
    } catch (error) {
        return res.json({ message: "No files", status: "failed" });
    }
});

//get single file
router.get("/:id", async (req, res) => {
    try {
        const single_file = await app_req.findById(req.params.id);
        return res.json({ message: "Single file", status: "success", single_file });
    } catch (error) {
        return res.json({ message: "No file", status: "failed" });
    }
});

// //update single file
// router.put("/:id", async (req, res) => {
//     try {
//         const {appTech, appType, name, email, phoneNumber, message, totalEstimate, numberOfPages} = req.body;
//         const update_file = await app_req.findByIdAndUpdate(req.params.id,req.body, {new:true});
        

//         console.log(update_file);
//         const udpate_app= await update_file.save();
//         return res.json({ message: "File updated", status: "success", udpate_app });
//     } catch (error) {
//         return res.json({ message: "File not updated", status: "failed" });
//     }
// });

//update single file
router.put("/:id", upload_app.single("file"), async (req, res) => {
    try {
        const url = req.protocol + "://" + req.get("host") + "/" + req.file.filename;
        const update_file = await app_req.findByIdAndUpdate(req.params.id, {...req.body, url: url,}, { new: true });
        return res.json({ message: "File updated", status: "success", update_file });
    } catch (error) {
        return res.json({ message: "File not updated", status: "failed" });
    }
});


//delete single file
router.delete("/:id", async (req, res) => {
    try {
        const delete_file = await app_req.findByIdAndDelete(req.params.id, req.body);
        return res.json({ message: "File deleted", status: "success", delete_file });
    } catch (error) {
        return res.json({ message: "File not deleted", status: "failed" });
    }
});



module.exports = router;