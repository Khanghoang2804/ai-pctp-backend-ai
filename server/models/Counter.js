const mongoose = require('mongoose');

const CounterSchema = new mongoose.Schema({
    // Tên của chuỗi đếm (ví dụ: 'userid')
    _id: {
        type: String,
        required: true,
    },
    // Giá trị đếm hiện tại
    seq: {
        type: Number,
        default: 0
    }
});

module.exports = mongoose.model('Counter', CounterSchema);