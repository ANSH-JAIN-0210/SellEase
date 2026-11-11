const mongoose = require('mongoose');

const staffSchema = new mongoose.Schema({
    staffId: { type: String, unique: true },
    name: { type: String, required: true },
    email: { type: String },
    phone: { type: Number, required: true },
    gender: { type: String, required: true },
    role: { type: String, required: true },
    address: { type: String },
    bankName: { type: String },
    accountNumber: { type: Number },
    accountHolderName: { type: String },
    IFSC: { type: String },
    UPI: { type: String },
}, { timestamps: true });

staffSchema.pre("save", async function (next) {
    if (this.isNew) {
        const lastStaff = await mongoose.model("Staff").findOne().sort({ createdAt: -1 });
        let nextId = "STF001";
        if (lastStaff && lastStaff.staffId) {
            const lastNum = parseInt(lastStaff.staffId.replace("STF", "")) || 0;
            nextId = "STF" + String(lastNum + 1).padStart(3, "0");
        }
        this.staffId = nextId;
    }
    next();
});

module.exports = mongoose.model('Staff', staffSchema);
