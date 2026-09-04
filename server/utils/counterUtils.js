// file: server/utils/counterUtils.js

const Counter = require('../models/Counter');

/**
 * Tìm và tăng giá trị đếm trong collection 'counters' một cách an toàn.
 * @param {string} sequenceName - Tên chuỗi đếm (ví dụ: 'userid').
 * @returns {number} Giá trị đếm tiếp theo.
 */
async function getNextSequenceValue(sequenceName) {
    const sequenceDocument = await Counter.findOneAndUpdate(
        { _id: sequenceName },
        { $inc: { seq: 1 } },
        { 
            new: true,
            upsert: true
        } 
    );
    return sequenceDocument.seq;
}

module.exports = { getNextSequenceValue };