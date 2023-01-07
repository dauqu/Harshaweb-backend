const express = require("express");
const bcryptjs = require("bcryptjs");
const router = express.Router();
const vendor_schema = require("../models/Vendors");

// get vendor
router.get("/", async (req, res) => {
  try {
    const user = await vendor_schema.find();
    res.json(user);
  } catch (error) {
    res
      .status(500)
      .json({ message: "error in getting Vendors", status: "error" });
  }
});

// create vendor
router.post("/",   async (req, res) => {
  console.log(req.body);

  // hashing password
//   const salt = await bcryptjs.genSalt();
//   const hashed_password = await bcryptjs.hash(req.body.password, salt);

  const vendors = new vendor_schema({
    company_name: req.body.company_name,
    state: req.body.state,
    city: req.body.city,
    vendorType: req.body.vendorType,
    category: req.body.category,
    vendor_email: req.body.vendor_email,
    vendor_password: req.body.vendor_password,
    vendor_phone: req.body.vendor_phone,
    vendor_fees: req.body.vendor_fees,
    referred_by: req.body.referred_by,
  });

  try {
    const NewVendor = await vendors.save();
    res.json(NewVendor);
  } catch (error) {
    res.status(500).json({ message: error.message, status: "error" });
  }
});

module.exports = router;
