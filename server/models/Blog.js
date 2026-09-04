// file: server/models/Blog.js
const mongoose = require('mongoose');
const { blogConn } = require('../index');

const BlogSchema = new mongoose.Schema({
    title: { type: String, required: true },
    link: { type: String, required: true, unique: true },
    content_html: { type: String, required: true },

    description: String,
    content_text: String,
    image: String,
    author: String,
    source: String,
    date_string: String, // VD: "9 Tháng Một 2026"

    publishedAt: { type: Date },
    updatedAt: { type: Date }
}, {
    collection: 'posts'
});

const Blog = blogConn.model('Blog', BlogSchema);

module.exports = Blog;