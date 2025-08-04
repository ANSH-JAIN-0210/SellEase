const mongoose = require('mongoose');

const userSchema = mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: Number, required: true },
    password: { type: String, required: true },
    dob: { type: Date, required: true },
    firmName: { type: String, required: true },
    GSTIN: { type: String, required: true },
    buildingNo: { type: String, required: true },
    streetNo: { type: String, required: true },
    area: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    pincode: { type: Number, required: true },
    logo: { type: String, required: false },
    website: { type: String, required: false },
    signature: { type: String, required: false },
    otp: String,
    otpExpiry: Date,

})
module.exports = mongoose.model('User', userSchema)