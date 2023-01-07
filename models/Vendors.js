require('dotenv').config()
const mongoose = require("mongoose");

// schema for vendors 
const vendor_schema = new mongoose.Schema({
    company_name: {
        type: String,
        required: true,
    },
    state: {
        type: String,
        reqired: true,
    },
    city: {
        type: String,
        reqired: true,
    },
    vendorType: {
        type: String,
        reqired: true,
    },
    category: {
        type: String,
        reqired: true,
    },
    vendor_email: {
        type: String,
        required: true,
    },
    vendor_password: {
        type: String,
        reqired: true,
    },
    vendor_phone: {
        type: String,
        reqired: true,
    },
    vendor_fees: {
        type: String,
        reqired: true,
    },
    referred_by: {
        type: String,
        reqired: true,
    },

})
module.exports = mongoose.model("vendors", vendor_schema);