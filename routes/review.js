const express= require('express')
const router= express.Router();
const reviewSchema= require("../models/review");
const jwt = require("jsonwebtoken");


//add a review
router.post("/", async(req,res) =>{

const {name, email}= req.body;
   //check if email is valid
const emailRegex = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
if (!emailRegex.test(email))
  return res.status(400).json({ message: "Email is not valid" });
 
  
      //check if name is valid
      const nameRegex = /^[a-zA-Z ]{2,30}$/;
      if(!nameRegex.test(name)) return res.status(400).json({message:"Name is not valid"});
      


    const review_collection= new reviewSchema({
       
        name:req.body.name,
        email:req.body.email,
        review:req.body.review, 
        rating:req.body.rating,
    });
    try {
        await review_collection.save();
        res.status(201).json("Review added");
    } catch (error) {
        res.status(400).send(error);
    }
});

//get all reviews
router.get("/", async(req,res) =>{
    const review_collection= await reviewSchema.find();
    try {
        res.status(200).json(review_collection);
    } catch (error) {
        res.status(400).send(error);
    }
});

//get a review
router.get("/:id", async(req,res) =>{
    const review_collection= await reviewSchema.findById(req.params.id);
    try {
        res.status(200).send(review_collection);
    } catch (error) {
        res.status(400).send(error);
    }
});

//update a review
router.patch("/:id", async(req,res) =>{
    const review_collection= await reviewSchema.findByIdAndUpdate(req.params.id, req.body);
    try {
        res.status(200).json("Review updated");
    } catch (error) {
        res.status(400).send(error);
    }
});

//delete a review
router.delete("/:id", async(req,res) =>{
    const review_collection= await reviewSchema.findByIdAndDelete(req.params.id);
    try {
        res.status(200).json("Review deleted");
    } catch (error) {
        res.status(400).send(error);
    }
});

module.exports= router;