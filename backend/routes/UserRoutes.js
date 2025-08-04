const express = require('express')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const nodemailer = require('nodemailer');
const User = require('../models/user');
const router = express.Router()
const SECRET_KEY = process.env.JWT_SECRET || '8882345228'

const generateToken = (userId) => {
    return jwt.sign({ userId }, SECRET_KEY, { expiresIn: '3h' });
}
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const sendEmail = async (to, otp) => {
    const subject = "SellEase Password Reset OTP";
    const body = `
Hello,

You have requested to reset your password for your SellEase account.

🔐 Your OTP is: ${otp}
🕒 This OTP is valid for 10 minutes.

If you didn't request this, please ignore this email.

Regards,  
SellEase Support Team
    `;

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER || "anshjain7683@gmail.com",
            pass: process.env.EMAIL_PASS || "lzin ykgl wrvg dlqi",
        },
    });

    await transporter.sendMail({
        from: `"SellEase Support Team" <${process.env.EMAIL_USER || "anshjain7683@gmail.com"}>`,
        to,
        subject,
        text: body,
    });
};

const sendEmailPassword = async (to, password) => {
    const subject = "Your SellEase Account Credentials";
    const body = `
Hello,

Your SellEase account has been created successfully.

🔐 Temporary Password: ${password}
🕒 Please change your password after logging in.

Regards,  
SellEase Support Team
    `;

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER || "anshjain7683@gmail.com",
            pass: process.env.EMAIL_PASS || "lzin ykgl wrvg dlqi",
        },
    });

    await transporter.sendMail({
        from: `"SellEase Support Team" <${process.env.EMAIL_USER || "anshjain7683@gmail.com"}>`,
        to,
        subject,
        text: body,
    });
};


router.post('/register', async (req, res) => {
    const { name, email, phone, password, dob, firmName, GSTIN, buildingNo, streetNo, area, city, state, pincode, logo, website, signature } = req.body

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const gstinRegex = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[A-Z0-9]{1}[Z]{1}[A-Z0-9]{1}$/;
    const phoneRegex = /^\d{10}$/;

    if (!name || !email || !phone || !password || !dob || !firmName || !GSTIN ||
        !buildingNo || !streetNo || !area || !city || !state || !pincode) {
        return res.status(400).json({ success: false, message: "All fields except logo, website, and signature are required." });
    }

    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: "Invalid email format." });
    }

    if (!gstinRegex.test(GSTIN)) {
        return res.status(400).json({ success: false, message: "Invalid GSTIN format." });
    }

    const dobDate = new Date(dob);
    if (isNaN(dobDate.getTime())) {
        return res.status(400).json({ success: false, message: "Invalid date of birth." });
    }

    if (!phoneRegex.test(phone)) {
        return res.status(400).json({ success: false, message: "Phone must be a 10-digit number." });
    }

    if (password.length < 8) {
        return res.status(400).json({ success: false, message: "Password must be at least 8 characters long." });
    }
    try {
        const existing = await User.findOne({ email });
        const existing2 = await User.findOne({ GSTIN });
        if (existing) return res.status(409).json({ success: false, message: "User Already Exists" });
        if (existing2) return res.status(409).json({ success: false, message: "GSTIN Already Exists" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, phone, password: hashedPassword, dob, firmName, GSTIN, buildingNo, streetNo, area, city, state, pincode, logo, website, signature })
        await newUser.save();
        const token = generateToken(newUser._id);
        res.status(201).json({ success: true, message: "Register Successful" });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error: error.message })
    }
})

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: "Invalid email format." });
    }
    try {
        const existing = await User.findOne({ email });
        if (!existing) return res.status(409).json({ success: false, message: "User not found" });

        if (password.length < 8) {
            return res.status(400).json({ success: false, message: "Password must be at least 8 characters long." });
        }

        const isValid = await bcrypt.compare(password, existing.password);
        if (!isValid) return res.status(400).json({ success: false, message: "Incorrect Password" });

        const token = generateToken(existing._id);

        res.status(200).json({ success: true, message: "Login Successfull", token });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error: error.message })
    }
})

router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: "Invalid email format." });
    }
    try {
        const existing = await User.findOne({ email });
        if (!existing) return res.status(404).json({ success: false, message: "User not found" });

        const otp = generateOTP();
        const expiry = new Date(Date.now() + 10 * 60 * 1000);

        existing.otp = otp;
        existing.otpExpiry = expiry;
        await existing.save();

        await sendEmail(email, otp);

        res.status(200).json({ success: true, message: 'OTP sent to your email' });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error", error: error.message });
    }
});

router.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: "Invalid email format." });
    }
    try {
        const existing = await User.findOne({ email });
        if (!existing) return res.status(409).json({ success: false, message: "User not found" });

        if (otp.length !== 6) return res.status(400).json({ success: false, message: "OTP must be of length 6" })

        if (existing.otp !== otp) {
            return res.status(400).json({ success: false, message: "Invalid OTP" });
        }

        if (existing.otpExpiry < new Date()) {
            return res.status(400).json({ success: false, message: "OTP expired" });
        }

        existing.otp = undefined
        existing.otpExpiry = undefined
        await existing.save();

        res.status(200).json({ success: true, message: "OTP verified" })
    } catch (error) {
        res.status(500).json({ message: 'Internal Server Error', error: error.message })
    }
})
router.put('/reset-password', async (req, res) => {
    const { email, new_password, confirm_password } = req.body;
    if (!email || !new_password || !confirm_password) {
        return res.status(400).json({ success: false, message: "All fields are required." });
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: "Invalid email format." });
    }
    try {
        const exisiting = await User.findOne({ email })
        if (!exisiting) return res.status(409).json({ success: false, message: "User not found" });

        if (new_password !== confirm_password) return res.status(400).json({ success: false, message: "Password Mismatch" })
        const hashedPassword = await bcrypt.hash(new_password, 10)
        exisiting.password = hashedPassword
        await exisiting.save()
        res.status(200).json({ success: true, message: "Password reset successfully" })
    }
    catch (error) {
        res.status(500).json({ message: "Internal Server Error", error: error.message })
    }
})

router.get('/get-profile', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Authorization token missing or invalid' });
        }
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.userId;
        if (!userId) {
            return res.status(400).json({ success: false, message: 'ID not found in token' });
        }
        const user = await User.findOne({ _id: userId }).select('-password');
        if (!user) {
            return res.status(409).json({ success: false, message: 'User not found' });
        }
        res.status(200).json({ success: true, message: "User data fetched", user: user });

    } catch (error) {
        res.status(401).json({ message: 'Invalid or expired token', error: error.message });
    }
});


router.get('/get-all-profile', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Authorization token missing or invalid' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.userId;

        if (!userId) {
            return res.status(400).json({ success: false, message: 'ID not found in token' });
        }

        const currentUser = await User.findById(userId);
        if (!currentUser) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const users = await User.find(
            { GSTIN: currentUser.GSTIN },
            'name email phone dob'
        );

        res.status(200).json({ success: true, users });

    } catch (error) {
        res.status(401).json({ success: false, message: 'Invalid or expired token', error: error.message });
    }
});


router.put('/edit-user-details', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Authorization token missing or invalid' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.userId;

        const { name, email, phone, dob } = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const phoneRegex = /^\d{10}$/;

        if (email) {
            if (!emailRegex.test(email)) {
                return res.status(400).json({ success: false, message: 'Invalid email format' });
            }
        }

        if (phone) {
            if (!phoneRegex.test(phone)) {
                return res.status(400).json({ success: false, message: 'Phone must be a 10-digit number' });
            }
        }


        if (dob) {
            const dobDate = new Date(dob);
            if (isNaN(dobDate.getTime())) {
                return res.status(400).json({ success: false, message: 'Invalid date of birth' });
            }
        }

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $set: { name, email, phone, dob } },
            { new: true, runValidators: true }
        ).select('-password');

        if (!updatedUser) {
            return res.status(409).json({ success: false, message: 'User not found' });
        }

        res.status(200).json({ success: true, message: 'Profile edited successfully', user: updatedUser });

    } catch (error) {
        res.status(400).json({ success: false, message: 'Error editing profile', error: error.message });
    }
});

router.put('/edit-shop-details', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Authorization token missing or invalid' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.userId;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const {
            firmName, buildingNo, streetNo,
            area, city, state, pincode,
            logo, website, signature
        } = req.body;

        if (pincode) {
            const pincodeRegex = /^\d{6}$/;
            if (!pincodeRegex.test(pincode)) {
                return res.status(400).json({ success: false, message: 'Pincode must be a 6-digit number.' });
            }
        }

        const updates = {
            firmName, buildingNo, streetNo, area, city, state, pincode
        };

        if (logo !== undefined) updates.logo = logo;
        if (website !== undefined) updates.website = website;
        if (signature !== undefined) updates.signature = signature;

        const result = await User.updateMany(
            { GSTIN: user.GSTIN },
            { $set: updates }
        );

        res.status(200).json({
            success: true,
            message: `Shop details updated for ${result.modifiedCount} account(s) with GSTIN ${user.GSTIN}`
        });

    } catch (error) {
        res.status(400).json({ success: false, message: 'Error editing shop details', error: error.message });
    }
});

router.put('/update-password', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Authorization token missing or invalid' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.userId;

        if (!userId) {
            return res.status(401).json({ success: false, message: "User ID not found in token" });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const { old_password, new_password, confirm_password } = req.body;

        const isMatch = await bcrypt.compare(old_password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Old password is incorrect" });
        }

        if (new_password !== confirm_password) {
            return res.status(400).json({ success: false, message: "New passwords do not match" });
        }
        if ( new_password.length < 8) {
            return res.status(400).json({ success: false, message: "Password must be contain 8 characters." });
        }

        const hashedPassword = await bcrypt.hash(new_password, 10);
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({ success: true, message: 'Password updated successfully' });

    } catch (error) {
        res.status(400).json({ message: 'Error updating password', error: error.message });
    }
});

router.delete('/delete-user/:id', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Authorization token missing or invalid' });
        }

        const id = req.params.id;
        const user = await User.findByIdAndDelete(id);
        if (!user) {
            return res.status(409).json({ success: false, message: "User not found" });
        }
        res.status(200).json({ success: true, message: "User deleted successfully" });
    } catch (error) {
        res.status(400).json({ message: "Error deleting user", error: error.message });
    }
})

router.post('/add-user', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: 'Authorization token missing or invalid' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, SECRET_KEY);
        const userId = decoded.userId;

        const admin = await User.findById(userId);
        if (!admin) {
            return res.status(409).json({ success: false, message: "Invalid Admin" });
        }

        const { name, email, phone, dob } = req.body;

        if (!name || !email || !phone || !dob) {
            return res.status(400).json({ success: false, message: "All fields (name, email, phone, dob) are required." });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const phoneRegex = /^\d{10}$/;
        const dobDate = new Date(dob);

        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: "Invalid email format." });
        }

        if (!phoneRegex.test(phone)) {
            return res.status(400).json({ success: false, message: "Phone must be a 10-digit number." });
        }

        if (isNaN(dobDate.getTime())) {
            return res.status(400).json({ success: false, message: "Invalid date of birth." });
        }

        const existing = await User.findOne({ email });
        if (existing) {
            return res.status(409).json({ success: false, message: "User already exists." });
        }

        const plainPassword = Math.random().toString(36).slice(-8);
        const hashedPassword = await bcrypt.hash(plainPassword, 10);

        const new_user = new User({
            name, email, phone, dob,
            password: hashedPassword,
            firmName: admin.firmName,
            GSTIN: admin.GSTIN,
            buildingNo: admin.buildingNo,
            streetNo: admin.streetNo,
            area: admin.area,
            city: admin.city,
            state: admin.state,
            pincode: admin.pincode,
            logo: admin.logo,
            website: admin.website,
            signature: admin.signature
        });

        await new_user.save();

        await sendEmailPassword(email, plainPassword);

        res.status(201).json({ success: true, message: "User created and password sent via email" });

    } catch (error) {
        res.status(400).json({ success: false, message: "Error creating user", error: error.message });
    }
});

module.exports = router
