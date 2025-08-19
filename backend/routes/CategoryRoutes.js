const express = require('express')
const Category = require('../models/category');
const category = require('../models/category');
const router = express.Router()

router.get('/get-category', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = 10;
        let searchQuery = {};
        try {
            if (req.query.search) {
                const parsed = JSON.parse(req.query.search);
                for (let key in parsed) {
                    if (parsed[key] && parsed[key].trim() !== '') {
                        searchQuery[key] = { $regex: parsed[key], $options: 'i' };
                    }
                }
            }
        } catch (error) {
            return res.status(400).json({ message: 'Invalid search query' })
        }


        const query = Object.keys(searchQuery).length > 0 ? searchQuery : {};

        const allIds = await Category.find(query, { _id: 1 }).sort({ _id: 1 }).lean();

        const totalDataItems = allIds.length;
        const totalPages = Math.ceil(totalDataItems / limit);

        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;

        const pageIds = allIds.slice(startIndex, endIndex).map(item => item._id);

        const data = await Category.find({ _id: { $in: pageIds } }).sort({ _id: 1 });

        res.json({
            success: true,
            message: 'Categories fetched successfully',
            data: data,
            totalDataItems: totalDataItems,
            totalPages: totalPages,
            currentPage: page,
            limit: limit
        })
    } catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
});


router.post('/add-category', async (req, res) => {
    try {
        const { name, description, status } = req.body;

        if (!name || !description) {
            return res.status(400).json({ success: false, message: 'Please fill all the required fields' })
        }

        const newCat = new Category({ name, description, status:'active' });

        await newCat.save();

        return res.status(201).json({ success: true, message: "Category added successfully", category: newCat });

    }
    catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

router.put('/edit-category/:categoryId', async (req, res) => {
    try {
        const { categoryId } = req.params;
        const { name, description, status } = req.body;
        const existing = await Category.findOne({ categoryId });
        if (!existing) {
            return res.status(404).json({ success: false, message: "Category not found" });
        }
        if (status !== 'active' && status !== 'inactive' && status !== 'deleted') {
            return res.status(400).json({ success: false, message: 'Invalid status' })
        }

        existing.name = name || existing.name;
        existing.description = description || existing.description;
        existing.status = status || existing.status;

        await existing.save();

        return res.status(200).json({ success: true, message: "Category updated successfully", category: existing });

    } catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

router.delete('/delete-category/:categoryId', async (req, res) => {
    try {
        const { categoryId } = req.params;
        const existing = await Category.findOne({ categoryId });
        if (!existing) {
            return res.status(404).json({ success: false, message: "Category not found" });
        }
        await existing.deleteOne({ categoryId });
        return res.status(200).json({ success: true, message: "Category deleted successfully" });
    }
    catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

module.exports = router;