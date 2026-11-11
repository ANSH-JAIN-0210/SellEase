const express = require('express')
const Supplier = require('../models/supplier');
const router = express.Router()


router.get('/get-suppliers', async (req, res) => {
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
            return res.status(400).json({ error: error, message: 'Invalid search query' })
        }


        const query = Object.keys(searchQuery).length > 0 ? searchQuery : {};

        const allIds = await Supplier.find(query, { _id: 1 }).sort({ _id: 1 }).lean();

        const totalDataItems = allIds.length;
        const totalPages = Math.ceil(totalDataItems / limit);

        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;

        const pageIds = allIds.slice(startIndex, endIndex).map(item => item._id);

        const data = await Supplier.find({ _id: { $in: pageIds } }).sort({ _id: 1 });

        res.json({
            success: true,
            message: 'Suppliers fetched successfully',
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

router.post('/add-supplier', async (req, res) => {
    try {
        const { name, email, phone, description, firmName, GSTIN, address, city, state, pincode, bankName, accountNumber, accountHolderName, IFSC, UPI } = req.body;

        if (!name || !phone || !description || !firmName || GSTIN) {
            return res.status(400).json({ success: false, message: 'Please fill all the required fields' })
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Invalid email format." });
        }
        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone)) {
            return res.status(400).json({ success: false, message: 'Phone must be a 10-digit number' });
        }
        if (pincode) {
            const pincodeRegex = /^[1-9][0-9]{5}$/;
            if (pincode && !pincodeRegex.test(pincode)) {
                return res.status(400).json({ success: false, message: "Invalid pincode format." });
            }
        }
        if (accountNumber) {
            const accountNumberRegex = /^\d{9,18}$/;
            if (accountNumber && !accountNumberRegex.test(accountNumber)) {
                return res.status(400).json({ success: false, message: "Invalid account number format." });
            }
        }

        const existingSupplier = await Supplier.findOne({ $or: [{ email }, { phone }] });
        if (existingSupplier) {
            return res.status(400).json({ success: false, message: "Supplier with this email or phone already exists." });
        }

        const newSupplier = new Supplier({
            name,
            email,
            phone,
            description,
            firmName,
            GSTIN,
            address,
            city,
            state,
            pincode,
            bankName,
            accountNumber,
            accountHolderName,
            IFSC,
            UPI
        });

        await newSupplier.save();

        return res.status(201).json({ success: true, message: "Supplier added successfully", supplier: newSupplier });

    }
    catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

router.put('/edit-supplier/:supplierId', async (req, res) => {
    try {
        const { supplierId } = req.params;
        const { name, email, phone, description, firmName, GSTIN, address, city, state, pincode, bankName, accountNumber, accountHolderName, IFSC, UPI } = req.body;
        const existing = await Supplier.findOne({ supplierId });
        if (!existing) {
            return res.status(404).json({ success: false, message: "Supplier not found" });
        }

        if (email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ success: false, message: "Invalid email format." });
            }
        }
        if (phone) {
            const phoneRegex = /^\d{10}$/;
            if (!phoneRegex.test(phone)) {
                return res.status(400).json({ success: false, message: 'Phone must be a 10-digit number' });
            }
        }
        if (pincode) {
            const pincodeRegex = /^[1-9][0-9]{5}$/;
            if (pincode && !pincodeRegex.test(pincode)) {
                return res.status(400).json({ success: false, message: "Invalid pincode format." });
            }
        }
        if (accountNumber) {
            const accountNumberRegex = /^\d{9,18}$/;
            if (accountNumber && !accountNumberRegex.test(accountNumber)) {
                return res.status(400).json({ success: false, message: "Invalid account number format." });
            }
        }

        existing.name = name || existing.name;
        existing.email = email || existing.email;
        existing.phone = phone || existing.phone;
        existing.description = description || existing.description;
        existing.firmName = firmName || existing.firmName;
        existing.GSTIN = GSTIN || existing.GSTIN;
        existing.address = address || existing.address;
        existing.city = city || existing.city;
        existing.state = state || existing.state;
        existing.pincode = pincode || existing.pincode;
        existing.bankName = bankName || existing.bankName;
        existing.accountNumber = accountNumber || existing.accountNumber;
        existing.accountHolderName = accountHolderName || existing.accountHolderName;
        existing.IFSC = IFSC || existing.IFSC;
        existing.UPI = UPI || existing.UPI;

        await existing.save();

        return res.status(200).json({ success: true, message: "Supplier updated successfully", supplier: existing });

    } catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

router.delete('/delete-supplier/:supplierId', async (req, res) => {
    try {
        const { supplierId } = req.params;
        const existing = await Supplier.findOne({ supplierId });
        if (!existing) {
            return res.status(404).json({ success: false, message: "Supplier not found" });
        }
        await existing.deleteOne({ supplierId });
        return res.status(200).json({ success: true, message: "Supplier deleted successfully" });
    }
    catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

module.exports = router;