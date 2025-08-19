const mongoose = require('mongoose');

const supplierSchema = new mongoose.Schema({
    supplierId: { type: String, unique: true },
    name: { type: String, required: true },
    email: { type: String },
    phone: { type: Number, required: true },
    description: { type: String, required: true },
    firmName: { type: String, required: true },
    GSTIN: { type: String, required: true },
    address: { type: String },
    city: { type: String },
    state: { type: String },
    pincode: { type: Number },
    bankName: { type: String },
    accountNumber: { type: Number },
    accountHolderName: { type: String },
    IFSC: { type: String },
    UPI: { type: String },
}, { timestamps: true });

supplierSchema.pre("save", async function (next) {
    if (this.isNew) {
        const lastSupplier = await mongoose.model("Supplier").findOne().sort({ createdAt: -1 });
        let nextId = "SUP001";
        if (lastSupplier && lastSupplier.supplierId) {
            const lastNum = parseInt(lastSupplier.supplierId.replace("SUP", "")) || 0;
            nextId = "SUP" + String(lastNum + 1).padStart(3, "0");
        }
        this.supplierId = nextId;
    }
    next();
});

module.exports = mongoose.model('Supplier', supplierSchema);
