const vendor_reg_model = require("../models/Vendors");

async function vendor_reg_validation(req, res, next) {
  try {
    const {
      company_name,
      state,
      city,
      vendorType,
      category,
      vendor_email,
      vendor_password,
      vendor_phone,
      vendor_fees,
      referred_by,
    } = req.body;

    // checking all field is filled or not
    if (
      !company_name ||
      !state ||
      !city ||
      !vendorType ||
      !category ||
      !vendor_email ||
      !vendor_password ||
      !vendor_phone ||
      !vendor_fees ||
      !referred_by
    )
      return res.status(400).json({
        message: "Please fill all fields",
        status: "warning",
      });

    //   code for validating phone number
    const chk_phone = await vendor_reg_model.findOne({ vendor_phone });
    if (chk_phone)
      return res
        .status(400)
        .json({ message: "phone is already exists", status: "warning" });

    if (vendor_phone.length != 10)
      return res.status(400).json({
        message: "Please  enter valid phone number ",
        status: "warning",
      });
  } catch (error) {}
}
