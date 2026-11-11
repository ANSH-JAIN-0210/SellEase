const mongoose = require('mongoose');

const categorySchema = new mongoose.Schema({
    categoryId: { type: String, unique: true },
    name: { type: String, required: true },
    description: { type: String, required: true },
    status: { type: String, required: true },
}, { timestamps: true });

categorySchema.pre("save", async function (next) {
    if (this.isNew) {
        const lastCategory = await mongoose.model("Category").findOne().sort({ createdAt: -1 });
        let nextId = "CAT001";
        if (lastCategory && lastCategory.categoryId) {
            const lastNum = parseInt(lastCategory.categoryId.replace("CAT", "")) || 0;
            nextId = "CAT" + String(lastNum + 1).padStart(3, "0");
        }
        this.categoryId = nextId;
    }
    next();
});

module.exports = mongoose.model('Category', categorySchema);
