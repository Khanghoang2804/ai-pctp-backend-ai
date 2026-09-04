// file: server/models/Conversation.js

const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
    role: {
        type: String,
        enum: ['user', 'assistant'],
        required: true
    },
    content: {
        type: String,
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    }
}, { _id: false }); // _id: false nghĩa là không tạo ID tự động cho từng tin nhắn

const conversationSchema = new mongoose.Schema({
    // Khóa ngoại liên kết với User
    user_id: {
        type: String,
        required: true,
        ref: 'User'
    },
    // Tiêu đề cuộc trò chuyện
    title: {
        type: String,
        trim: true,
        default: 'Cuộc trò chuyện mới'
    },
    messages: [messageSchema]
}, {
    timestamps: true
});

const Conversation = mongoose.model('Conversation', conversationSchema, 'conversations');

module.exports = Conversation;