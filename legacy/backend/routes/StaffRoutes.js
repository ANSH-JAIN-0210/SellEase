const express = require('express')
const Staff = require('../models/staff');
const router = express.Router()

router.get('/get-staffs', async (req, res) => {
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

        const allIds = await Staff.find(query, { _id: 1 }).sort({ _id: 1 }).lean();

        const totalDataItems = allIds.length;
        const totalPages = Math.ceil(totalDataItems / limit);

        const startIndex = (page - 1) * limit;
        const endIndex = startIndex + limit;

        const pageIds = allIds.slice(startIndex, endIndex).map(item => item._id);

        const data = await Staff.find({ _id: { $in: pageIds } }).sort({ _id: 1 });

        res.json({
            success: true,
            message: 'Staffs fetched successfully',
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

router.post('/add-staff', async (req, res) => {
    try {
        const { name, email, phone, gender, role, address, bankName, accountNumber, accountHolderName, IFSC, UPI } = req.body;

        if (!name || !phone || !role || !gender) {
            return res.status(400).json({ success: false, message: 'Please fill all the required fields' })
        }

        if (email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ success: false, message: "Invalid email format." });
            }
        }
        const phoneRegex = /^\d{10}$/;
        if (!phoneRegex.test(phone)) {
            return res.status(400).json({ success: false, message: 'Phone must be a 10-digit number' });
        }
        if (accountNumber) {
            const accountNumberRegex = /^\d{9,18}$/;
            if (accountNumber && !accountNumberRegex.test(accountNumber)) {
                return res.status(400).json({ success: false, message: "Invalid account number format." });
            }
        }

        const existingStaff = await Staff.findOne({ phone });
        if (existingStaff) {
            return res.status(400).json({ success: false, message: "Staff with this phone already exists." });
        }

        const newStaff = new Staff({
            name, email, phone, gender, role, address, bankName, accountNumber, accountHolderName, IFSC, UPI
        });

        await newStaff.save();

        return res.status(201).json({ success: true, message: "Staff added successfully", staff: newStaff });

    }
    catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

router.put('/edit-staff/:staffId', async (req, res) => {
    try {
        const { staffId } = req.params;
        const { name, email, phone, gender, role, address, bankName, accountNumber, accountHolderName, IFSC, UPI } = req.body;
        const existing = await Staff.findOne({ staffId });
        if (!existing) {
            return res.status(404).json({ success: false, message: "Staff not found" });
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
        if (accountNumber) {
            const accountNumberRegex = /^\d{9,18}$/;
            if (accountNumber && !accountNumberRegex.test(accountNumber)) {
                return res.status(400).json({ success: false, message: "Invalid account number format." });
            }
        }

        existing.name = name || existing.name;
        existing.email = email || existing.email;
        existing.phone = phone || existing.phone;
        existing.gender = gender || existing.gender;
        existing.role = role || existing.role;
        existing.address = address || existing.address;
        existing.bankName = bankName || existing.bankName;
        existing.accountNumber = accountNumber || existing.accountNumber;
        existing.accountHolderName = accountHolderName || existing.accountHolderName;
        existing.IFSC = IFSC || existing.IFSC;
        existing.UPI = UPI || existing.UPI;

        await existing.save();

        return res.status(200).json({ success: true, message: "Staff updated successfully", staff: existing });

    } catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

router.delete('/delete-staff/:staffId', async (req, res) => {
    try {
        const { staffId } = req.params;
        const existing = await Staff.findOne({ staffId });
        if (!existing) {
            return res.status(404).json({ success: false, message: "Staff not found" });
        }
        await existing.deleteOne({ staffId });
        return res.status(200).json({ success: true, message: "Staff deleted successfully" });
    }
    catch (error) {
        return res.status(500).json({ error: error, message: 'Internal server error' })
    }
})

module.exports = router;