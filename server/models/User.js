// file: server/models/User.js (Đã cập nhật)

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { getNextSequenceValue } = require('../utils/counterUtils');

const userSchema = new mongoose.Schema({

    user_id: {
        type: String,
        unique: true,
    },
    email: {
        type: String,
        required: [true, 'Please provide an email.'],
        unique: true,
        lowercase: true,
        match: [/.+\@.+\..+/, 'Please fill a valid email address'],
    },
    username: {
        type: String,
        required: [true, 'Please provide a username.'],
        unique: true,
        trim: true,
    },
    password: {
        type: String,
        required: [true, 'Please provide a password.'],
        minlength: 8,
        select: false,
    },
    role: {
        type: String,
        enum: ['user', 'admin'],
        default: 'user',
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    otp: String,
    otpExpires: Date,
}, {
    timestamps: true 
});

userSchema.pre('save', async function(next) {
    if (this.isNew && !this.user_id) { 
        try {
            const sequenceValue = await getNextSequenceValue('userid');
            
            const formattedId = sequenceValue.toString().padStart(8, '0');
            
            this.user_id = 'user_' + formattedId; 

        } catch (error) {
            console.error('Lỗi khi sinh user ID:', error);
            return next(error); 
        }
    }
    
    next(); 
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;