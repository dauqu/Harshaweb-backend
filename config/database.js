require("dotenv").config();
const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.DB);
    console.log("itSolve Database Connected Successfuly");
  } catch (error) {
    console.log("(itSolve Database Connection error) ", error);
  }
};
module.exports = connectDB;
