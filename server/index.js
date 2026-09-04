// file: server/index.js

const dns = require('dns');
dns.setServers(["8.8.8.8", "8.8.4.4"]);

const express = require('express');
const https = require('https');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cors = require('cors');
require('dotenv').config();
const jwt = require('jsonwebtoken');


// Scan File
const fs = require('fs');
const tempUploadDir = path.join(__dirname, 'temp_uploads');
if (!fs.existsSync(tempUploadDir)) {
    fs.mkdirSync(tempUploadDir);
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, tempUploadDir)
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
});

// Giới hạn 100MB
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 } 
});

// OpenRouter
const { OpenRouter } = require("@openrouter/sdk");
const openrouter = new OpenRouter({
    apiKey: process.env.OPENROUTER_API_KEY
});


// const fetch = require('node-fetch');
const FormData = require('form-data');
const { sendOTPEmail } = require('./utils/mailer');
const User = require('./models/User');
const Conversation = require('./models/Conversation');

const app = express();
const PORT = process.env.PORT || 5000;

// const Groq = require('groq-sdk');
// const groq = new Groq({
//     apiKey: process.env.GROQ_API_KEY,
// });

app.use(cors({ origin: "*" }));
app.use(express.json());

const DB_NAME = 'aicp_db';
mongoose.connect(process.env.MONGO_URI, { dbName: DB_NAME })
    .then(() => console.log(`MongoDB connected successfully to database: ${DB_NAME}`))
    .catch(err => console.error('MongoDB connection error:', err));

// // Turso DB
// const { createClient } = require('@libsql/client');
// const tursoClient = createClient({
//     url: process.env.TURSO_DATABASE_URL,
//     authToken: process.env.TURSO_AUTH_TOKEN
// });
// const { searchCVEs } = require('./utils/cveSearch');
// console.log('Đã cấu hình kết nối Turso DB.');

// Neon Tech
const { Pool } = require('pg');
const isLocal = process.env.NEON_DB_URL && (process.env.NEON_DB_URL.includes('localhost') || process.env.NEON_DB_URL.includes('127.0.0.1'));

const pool = new Pool({
    connectionString: process.env.NEON_DB_URL,
    ssl: isLocal ? false : { rejectUnauthorized: false }
});
const { searchCVEs } = require('./utils/cveSearch');
console.log('Đã cấu hình kết nối Neon PostgreSQL DB.');


const getUserIdFromToken = (req) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer') ? authHeader.split(' ')[1] : null;

    if (!token) return 'GUEST_DEFAULT';

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        return decoded.id;
    } catch (error) {
        return 'GUEST_INVALID';
    }
};

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer') ? authHeader.split(' ')[1] : null;

    if (!token) {
        return res.status(401).json({ message: 'Không tìm thấy token xác thực. Vui lòng đăng nhập.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Phiên đăng nhập đã hết hạn hoặc không hợp lệ.' });
    }
};

app.post('/api/signup', async (req, res) => {
    try {
        const { email, username, password } = req.body;
        if (!email || !username || !password) {
            return res.status(400).json({ message: 'Please provide email, username, and password.' });
        }

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser && existingUser.isVerified) {
            return res.status(400).json({ message: 'This account already exists and is verified.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

        const emailSent = await sendOTPEmail(email, otp);
        if (!emailSent) {
            return res.status(500).json({ message: 'Failed to send OTP email.' });
        }

        if (existingUser) {
            existingUser.password = password;
            existingUser.username = username;
            existingUser.otp = otp;
            existingUser.otpExpires = otpExpires;
            await existingUser.save();
        } else {
            const newUser = new User({ email, username, password, otp, otpExpires });
            await newUser.save();
        }

        res.status(201).json({ message: 'OTP sent to email! Please verify.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ message: 'Email and OTP are required.' });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        if (user.otp !== otp || user.otpExpires < new Date()) {
            return res.status(400).json({ message: 'Invalid or expired OTP.' });
        }

        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;

        await user.save();
        res.status(200).json({ message: 'Account verified successfully!' });

    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        const user = await User.findOne({ email }).select('+password');

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Account not verified. Please check your email for the OTP.' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );

        return res.status(200).json({
            status: 'success',
            message: 'Login successful!',
            token: token,
            data: {
                user: {
                    id: user._id,
                    username: user.username,
                    email: user.email
                }
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        if (!res.headersSent) {
            return res.status(500).json({ message: 'Server error.' });
        }
    }
});

app.post('/api/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) return res.status(404).json({ message: 'User not found.' });
        if (user.isVerified) return res.status(400).json({ message: 'Tài khoản đã được xác minh.' });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
        await user.save();

        await sendOTPEmail(email, otp);
        res.status(200).json({ message: 'Mã OTP đã được gửi lại vào email của bạn.' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server khi gửi lại OTP.' });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: 'Email không tồn tại trong hệ thống.' });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
        await user.save();

        await sendOTPEmail(email, otp);
        res.status(200).json({ message: 'Mã xác nhận đã được gửi đến email của bạn.' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server.' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        const user = await User.findOne({ email }).select('+password');
        
        if (!user) return res.status(404).json({ message: 'Không tìm thấy người dùng.' });
        if (user.otp !== otp || user.otpExpires < new Date()) {
            return res.status(400).json({ message: 'Mã OTP không hợp lệ hoặc đã hết hạn.' });
        }

        user.password = newPassword;
        user.otp = undefined;
        user.otpExpires = undefined;
        user.isVerified = true;
        await user.save();

        res.status(200).json({ message: 'Đổi mật khẩu thành công! Bạn có thể đăng nhập.' });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi server.' });
    }
});

const baseSystemPrompt = `Bạn là AICP Assistant, một Chuyên gia Trí tuệ nhân tạo cấp cao về An ninh mạng. Nhiệm vụ của bạn là tư vấn và phân tích các vấn đề bảo mật.

TUÂN THỦ NGHIÊM NGẶT CÁC NGUYÊN TẮC:
- NGUYÊN TẮC SỐ 1 (SỰ THẬT TUYỆT ĐỐI): BẠN TUYỆT ĐỐI CHỈ ĐƯỢC PHÉP trả lời dựa trên thông tin nằm trong thẻ <context> bên dưới. KHÔNG tự ý bịa ra mã CVE hoặc thông tin ngoài luồng.
- ẨN DANH DỮ LIỆU (CRITICAL): TUYỆT ĐỐI KHÔNG nhắc đến các từ như "theo thẻ <context>", "trong context", hay "nguồn dữ liệu cung cấp" trong câu trả lời. Hãy trả lời một cách tự nhiên như thể đó là kiến thức của chính bạn.
- YÊU CẦU TRÍCH DẪN: Bắt buộc phải ghi rõ mã [CVE-ID] ở phần đầu khi phân tích bất kỳ lỗ hổng nào.
- XỬ LÝ KHI THIẾU DỮ LIỆU: Nếu người dùng chào hỏi, nói chuyện phiếm hoặc hỏi ngoài lề, hãy giao tiếp lại một cách thân thiện, đơn giản (ví dụ: chào lại và giới thiệu mình là AICP Assistant). Chỉ khi người dùng HỎI về một lỗ hổng cụ thể mà thẻ <context> trống, bạn mới BẮT BUỘC trả lời: 'Rất tiếc, cơ sở dữ liệu hiện tại của tôi chưa cập nhật lỗ hổng cụ thể này.' và giải thích cơ chế phòng tránh chung, tuyệt đối không tự bịa ra CVE.
- ĐẠO ĐỨC: KHÔNG hướng dẫn cách tấn công hệ thống thực tế. KHÔNG cung cấp mã độc.
- CẤU TRÚC TRÌNH BÀY: Dùng Markdown để định dạng. Khi giải thích về một CVE, BẮT BUỘC phải chia rõ ràng thành các phần:
  1. Mô tả lỗ hổng
  2. Hậu quả & Mức độ nguy hiểm
  3. Cách khắc phục / Phòng tránh (Nếu thông tin không có, hãy đưa ra lời khuyên bảo mật tiêu chuẩn).`;

app.post('/api/chat', async (req, res) => {
    const userId = getUserIdFromToken(req);

    try {
        const { messages: userMessages, conversationId, vulnContext } = req.body;
        if (!userMessages || userMessages.length === 0) {
            return res.status(400).json({ message: 'Messages are required.' });
        }

        const latestUserMessageContent = userMessages[userMessages.length - 1].content;

        // RAG
        const relatedCVEs = await searchCVEs(latestUserMessageContent);
        let ragContext = "\n\n<context>\n";
        let retrievedSources = [];
        
        if (vulnContext) {
            ragContext += `[NGỮ CẢNH HIỆN TẠI TỪ MÀN HÌNH CỦA NGƯỜI DÙNG]\n${vulnContext}\n\n`;
        }

        if (relatedCVEs && relatedCVEs.length > 0) {
            console.log(`Tìm thấy ${relatedCVEs.length} CVE liên quan.`);
            relatedCVEs.forEach(cve => {
                ragContext += `[Mã lỗ hổng: ${cve.id}]\n- Tiêu đề: ${cve.title}\n- Điểm CVSS: ${cve.cvss_score || 'N/A'}\n- Sản phẩm: ${cve.vendor_product}\n- Ngày công bố: ${cve.published_date}\n- Mô tả: ${cve.description}\n---\n`;
                retrievedSources.push({ id: cve.id, score: cve.cvss_score }); 
            });
        }
        ragContext += "</context>\n\nHãy nhớ: Chỉ sử dụng thông tin trong thẻ <context> để trả lời. Nếu người dùng hỏi về thông tin đang hiển thị trên màn hình, hãy ưu tiên sử dụng [NGỮ CẢNH HIỆN TẠI TỪ MÀN HÌNH CỦA NGƯỜI DÙNG] ở trên.";

        const currentSystemPrompt = baseSystemPrompt + ragContext;
        const recentMessages = userMessages.slice(-4);
        const messagesForGroq = [
            { role: "system", content: currentSystemPrompt },
            ...recentMessages
        ];

        let conversation;
        if (conversationId) {
            conversation = await Conversation.findOne({ _id: conversationId, user_id: userId });
        }

        if (!conversation) {
            conversation = new Conversation({
                user_id: userId,
                title: latestUserMessageContent.substring(0, 30) + (latestUserMessageContent.length > 30 ? '...' : ''),
                messages: []
            });
        }

        conversation.messages.push({ role: 'user', content: latestUserMessageContent });
        const assistantPlaceholder = { role: 'assistant', content: '...' };
        conversation.messages.push(assistantPlaceholder);
        await conversation.save();
        const lastMessageIndex = conversation.messages.length - 1;

        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');

        let accumulatedContent = '';
        
        const openRouterResponse = await fetch("https://openrouter.ai/api/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${process.env.OPENROUTER_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                model: "google/gemini-2.5-flash",
                messages: messagesForGroq,
                stream: true,
                temperature: 0.1,
                max_tokens: 9000
            })
        });

        if (!openRouterResponse.ok) {
            throw new Error(`Lỗi kết nối OpenRouter: ${openRouterResponse.status}`);
        }

        const decoder = new TextDecoder("utf-8");
        let buffer = "";

        for await (const chunk of openRouterResponse.body) {
            buffer += decoder.decode(chunk, { stream: true });
            
            let boundary = buffer.indexOf('\n');
            while (boundary !== -1) {
                const line = buffer.slice(0, boundary).trim();
                buffer = buffer.slice(boundary + 1);
                
                if (line.startsWith('data: ') && line !== 'data: [DONE]') {
                    try {
                        const jsonPayload = line.slice(6);
                        const parsed = JSON.parse(jsonPayload);
                        const content = parsed.choices[0]?.delta?.content || "";
                        
                        if (content) {
                            accumulatedContent += content;
                            res.write(`data: ${JSON.stringify({ content })}\n\n`);
                        }
                    } catch (e) {
                        console.error("Lỗi parse JSON mảnh:", e.message);
                    }
                }
                boundary = buffer.indexOf('\n');
            }
        }

        conversation.messages[lastMessageIndex].content = accumulatedContent;
        conversation.last_updated = new Date();
        await conversation.save();

        res.write(`data: ${JSON.stringify({ 
            type: 'metadata', 
            conversationId: conversation._id.toString(),
            rag_sources: retrievedSources 
        })}\n\n`);
        
        res.write('data: [DONE]\n\n');
        res.end();

    } catch (error) {
        console.error('Chat API error:', error);
        if (!res.headersSent) {
            res.status(500).json({ message: 'Error communicating with AI service.' });
        } else {
            res.end();
        }
    }
});

app.get('/api/conversations', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const conversations = await Conversation.find({ user_id: userId })
            .select('_id title last_updated')
            .sort({ updatedAt: -1 })
        res.status(200).json({ conversations });
    } catch (error) {
        console.error('Lỗi khi lấy lịch sử hội thoại:', error);
        res.status(500).json({ message: 'Server error when fetching conversations.' });
    }
});

app.get('/api/conversations/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const conversationId = req.params.id;
        const conversation = await Conversation.findOne({ _id: conversationId, user_id: userId });

        if (!conversation) {
            return res.status(404).json({ message: 'Conversation not found or you do not have permission.' });
        }
        res.status(200).json({ conversation });
    } catch (error) {
        console.error('Lỗi khi lấy chi tiết hội thoại:', error);
        if (error.kind === 'ObjectId') {
            return res.status(404).json({ message: 'Invalid conversation ID format.' });
        }
        res.status(500).json({ message: 'Server error when fetching conversation details.' });
    }
});

app.delete('/api/conversations/:id', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const conversationId = req.params.id;

        const deletedConv = await Conversation.findOneAndDelete({ _id: conversationId, user_id: userId });
        if (!deletedConv) {
            return res.status(404).json({ message: 'Không tìm thấy cuộc trò chuyện hoặc không có quyền.' });
        }
        res.status(200).json({ message: 'Đã xóa cuộc trò chuyện thành công.' });
    } catch (error) {
        console.error('Lỗi khi xóa hội thoại:', error);
        res.status(500).json({ message: 'Lỗi server khi xóa hội thoại.' });
    }
});

app.get('/api/profile-dashboard', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const userPromise = User.findById(userId).select('-password');
        const chatCountPromise = Conversation.countDocuments({ user_id: userId });
        const scanCountPromise = 0;

        const [user, chatCount, scanCount] = await Promise.all([userPromise, chatCountPromise, scanCountPromise]);

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({ user: user, chatCount: chatCount, scanCount: scanCount });
    } catch (error) {
        console.error('Error fetching dashboard profile:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { username } = req.body;

        if (!username) {
            return res.status(400).json({ message: 'Username is required.' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { username: username },
            { new: true, runValidators: true }
        ).select('-password');

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({ user: updatedUser });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ message: 'Server error.' });
    }
});

app.put('/api/profile/password', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'Vui lòng nhập đủ mật khẩu cũ và mới.' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ message: 'Mật khẩu mới phải có ít nhất 8 ký tự.' });
        }

        const user = await User.findById(userId).select('+password');
        if (!user) {
            return res.status(404).json({ message: 'Không tìm thấy người dùng.' });
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Mật khẩu hiện tại không chính xác.' });
        }

        user.password = newPassword;
        await user.save();

        res.status(200).json({ message: 'Đổi mật khẩu thành công!' });
    } catch (error) {
        console.error('Lỗi khi đổi mật khẩu:', error);
        res.status(500).json({ message: 'Lỗi server.' });
    }
});

app.delete('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        await Conversation.deleteMany({ user_id: userId });
        
        const deletedUser = await User.findByIdAndDelete(userId);
        
        if (!deletedUser) {
            return res.status(404).json({ message: 'Không tìm thấy người dùng.' });
        }

        res.status(200).json({ message: 'Tài khoản đã được xóa vĩnh viễn.' });
    } catch (error) {
        console.error('Lỗi khi xóa tài khoản:', error);
        res.status(500).json({ message: 'Lỗi server.' });
    }
});

app.post('/api/scan-image', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No image file uploaded.' });
        }

        const formData = new FormData();
        formData.append('image', req.file.buffer, {
            filename: req.file.originalname,
            contentType: req.file.mimetype,
        });

        const aiResponse = await fetch('http://localhost:8010/api/analyze', { 
            method: 'POST',
            body: formData,
            headers: formData.getHeaders()
        });
        // dns.setServers(["8.8.8.8", "8.8.4.4"]);

        const data = await aiResponse.json();

        if (!aiResponse.ok) {
            return res.status(aiResponse.status).json(data);
        }
        res.status(200).json(data);
    } catch (error) {
        console.error('Image scan proxy error:', error);
        res.status(500).json({ message: 'Server error during image processing.' });
    }
});

// Verify
app.post('/api/check-whois', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: 'URL is required.' });

    try {
        let domainToParse = url;
        if (!domainToParse.startsWith('http://') && !domainToParse.startsWith('https://')) {
            domainToParse = 'http://' + domainToParse;
        }
        
        const urlObj = new URL(domainToParse);
        const domain = urlObj.hostname.replace(/^www\./, '');

        const response = await fetch(`https://networkcalc.com/api/dns/whois/${domain}`);
        
        if (!response.ok) {
            return res.status(response.status).json({ message: 'Không thể lấy thông tin WHOIS lúc này.' });
        }

        const data = await response.json();
        res.status(200).json(data);
    } catch (error) {
        console.error('WHOIS Check Error:', error);
        res.status(500).json({ message: 'Lỗi server khi phân tích tên miền.' });
    }
});

const dnsPromises = require('dns').promises;
app.post('/api/check-safebrowsing', async (req, res) => {
    const { url } = req.body;
    try {
        const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
        const body = {
            client: { clientId: "aicp-dashboard", clientVersion: "1.0.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "THREAT_TYPE_UNSPECIFIED"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url }]
            }
        };
        const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
        });
        const data = await response.json();
        res.status(200).json(data);
    } catch (error) { res.status(500).json({ error: 'Lỗi Google Safe Browsing' }); }
});

app.post('/api/check-urlscan', async (req, res) => {
    const { url } = req.body;
    try {
        const domain = new URL(url.startsWith('http') ? url : `http://${url}`).hostname;
        const response = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}`, {
            headers: { 'API-Key': process.env.URLSCAN_API_KEY }
        });
        const data = await response.json();
        res.status(200).json(data);
    } catch (error) { res.status(500).json({ error: 'Lỗi Urlscan.io' }); }
});

app.post('/api/check-abuseipdb', async (req, res) => {
    const { url } = req.body;
    try {
        const domain = new URL(url.startsWith('http') ? url : `http://${url}`).hostname;
        const { address } = await dnsPromises.lookup(domain); // Lấy IP từ Domain
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${address}&maxAgeInDays=90`, {
            headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' }
        });
        const data = await response.json();
        res.status(200).json(data);
    } catch (error) { res.status(500).json({ error: 'Lỗi AbuseIPDB (Có thể domain không tồn tại)' }); }
});

app.post('/api/check-phish', async (req, res) => {
    const { url } = req.body;
    try {
        const apiKey = process.env.CHECKPHISH_API_KEY;

        const scanRes = await fetch('https://developers.bolster.ai/api/neo/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ apiKey, urlInfo: { url }, scanType: "quick" })
        });

        if (!scanRes.ok) return res.status(scanRes.status).json({ error: 'Lỗi khi gọi API CheckPhish' });
        
        const scanData = await scanRes.json();
        const jobID = scanData.jobID;

        if (!jobID) return res.status(500).json({ error: 'Không lấy được JobID' });

        const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
        const maxAttempts = 10;

        for (let i = 0; i < maxAttempts; i++) {
            await delay(3000);

            const statusRes = await fetch('https://developers.bolster.ai/api/neo/scan/status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ apiKey, jobID, insights: true })
            });

            if (statusRes.ok) {
                const statusData = await statusRes.json();
                
                if (statusData.status === 'DONE') {
                    return res.status(200).json(statusData);
                }
            }
        }

        res.status(408).json({ error: 'CheckPhish phân tích quá lâu (Timeout).' });

    } catch (error) { 
        console.error('CheckPhish Error:', error);
        res.status(500).json({ error: 'Lỗi server CheckPhish' }); 
    }
});

app.post('/api/check-virustotal', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: 'URL is required.' });

    try {
        const urlId = Buffer.from(url).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
        const vtApiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
        
        const response = await fetch(vtApiUrl, {
            method: 'GET',
            headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
        });

        if (response.status === 404) {
            return res.status(200).json({ notFound: true });
        }

        if (!response.ok) {
            const errorData = await response.json();
            return res.status(response.status).json(errorData);
        }

        const data = await response.json();
        res.status(200).json(data);
    } catch (error) {
        console.error('VirusTotal check error:', error);
        res.status(500).json({ message: 'Server error during VirusTotal check.' });
    }
});

app.post('/api/check-visual', async (req, res) => {
    const { url } = req.body;
    if (!url) return res.status(400).json({ message: 'URL is required.' });

    try {
        const aiResponse = await fetch('http://localhost:5010/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        if (!aiResponse.ok) {
            return res.status(aiResponse.status).json({ message: 'Error from AI Server' });
        }

        const data = await aiResponse.json();
        res.status(200).json(data);
    } catch (error) {
        console.error('Visual Check Error:', error);
        res.status(500).json({ message: 'Server error during visual analysis.' });
    }
});

let defaultCveCache = { data: null, lastFetch: 0 };
const CVE_CACHE_TTL = 10 * 60 * 1000; // Cache lưu trong 10 phút

app.get('/api/cves', async (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = parseInt(req.query.limit) || 20;
        const search = (req.query.search || '').trim();
        const skip = (page - 1) * limit;

        if (page === 1 && search === '' && limit === 20) {
            const now = Date.now();
            if (defaultCveCache.data && (now - defaultCveCache.lastFetch < CVE_CACHE_TTL)) {
                return res.json(defaultCveCache.data);
            }
        }

        let sql = `SELECT id, title, description, vendor_product, cvss_score, published_date FROM cves`;
        let countSql = `SELECT COUNT(*) as total FROM cves`;
        let args = [];
        let whereClause = "";

        if (search) {
            const isCveId = search.toUpperCase().startsWith('CVE-');
            if (isCveId) {
                whereClause = ` WHERE id ILIKE $1`;
                args = [`${search.toUpperCase()}%`];
            } else {
                whereClause = ` WHERE title ILIKE $1 OR vendor_product ILIKE $1`;
                args = [`%${search}%`];
            }
        }

        countSql += whereClause;
        
        sql += whereClause + ` ORDER BY published_date DESC NULLS LAST LIMIT $${args.length + 1} OFFSET $${args.length + 2}`;

        const [dataResult, countResult] = await Promise.all([
            pool.query(sql, [...args, limit, skip]),
            pool.query(countSql, args)
        ]);

        const cleanedRows = dataResult.rows.map(row => {
            if (row.vendor_product) {
                let cleanStr = row.vendor_product.replace(/[,_]/g, ' ').trim();
                let words = cleanStr.split(/\s+/);
                let uniqueWords = [...new Set(words.map(w => w.toLowerCase()))];
                row.vendor_product = uniqueWords.map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
            }
            return row;
        });

        const responseData = {
            data: cleanedRows,
            page: page,
            limit: limit,
            total: parseInt(countResult.rows[0].total, 10) 
        };

        if (page === 1 && search === '' && limit === 20) {
            defaultCveCache = { data: responseData, lastFetch: Date.now() };
        }

        res.json(responseData);
    } catch (error) {
        console.error('Lỗi khi lấy danh sách CVE từ Neon:', error);
        res.status(500).json({ message: 'Lỗi server khi lấy dữ liệu CVE' });
    }
});

function calculateTrend(data) {
    const n = data.length;
    let sumX = 0, sumY = 0, sumXY = 0, sumXX = 0;

    data.forEach((point, index) => {
        const x = index;
        const y = point.count;
        sumX += x;
        sumY += y;
        sumXY += x * y;
        sumXX += x * x;
    });

    const slope = (n * sumXY - sumX * sumY) / (n * sumXX - sumX * sumX);
    const intercept = (sumY - slope * sumX) / n;

    return { slope, intercept };
}

app.post('/api/ai/explain-cve', async (req, res) => {
    try {
        const { cveId, description } = req.body;

        const prompt = `Bạn là một chuyên gia an ninh mạng phân tích cho người dùng phổ thông (không giỏi kỹ thuật).
Hãy giải thích ngắn gọn, dễ hiểu về lỗ hổng ${cveId}.
Dữ liệu gốc tiếng Anh: "${description}"

Cấu trúc yêu cầu (Trả lời hoàn toàn bằng tiếng Việt):
1. **Lỗ hổng này là gì?** (Ví dụ: Đây là lỗi tràn bộ đệm...)
2. **Kẻ gian có thể làm gì?** (Hậu quả: Lấy cắp mật khẩu, điều khiển máy tính...)
3. **Cách phòng tránh:** (Cập nhật ứng dụng, tắt cổng...)`;

        const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${process.env.OPENROUTER_API_KEY}`,
                "Content-Type": "application/json",
                "X-Title": "AICP Security Dashboard"
            },
            body: JSON.stringify({
                model: "minimax/minimax-m2.5",
                messages: [
                    { role: "user", content: prompt }
                ],
            })
        });

        if (!response.ok) {
            const errData = await response.text();
            throw new Error(`OpenRouter API bị lỗi: ${response.status} - ${errData}`);
        }

        const data = await response.json();
        
        const textResponse = data.choices[0]?.message?.content || "Không có phản hồi từ AI.";

        res.json({ explanation: textResponse });

    } catch (error) {
        console.error("❌ AI Explain Error:", error);
        res.status(500).json({ error: "Lỗi kết nối với AI OpenRouter." });
    }
});

app.get('/api/stats/severity', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                CASE 
                    WHEN severity IS NULL OR TRIM(severity) = '' OR UPPER(severity) = 'N/A' THEN 'UNKNOWN'
                    ELSE UPPER(severity)
                END as severity, 
                COUNT(*) as count 
            FROM cves 
            GROUP BY 
                CASE 
                    WHEN severity IS NULL OR TRIM(severity) = '' OR UPPER(severity) = 'N/A' THEN 'UNKNOWN'
                    ELSE UPPER(severity)
                END
            ORDER BY count DESC
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Severity Stats Error:', error);
        res.status(500).json({ message: 'Error fetching severity stats' });
    }
});

app.get('/api/stats/products', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                -- SỬA LỖI LẶP TỪ: Dùng REGEXP_REPLACE để xóa các từ giống nhau đứng cạnh nhau
                INITCAP(
                    REGEXP_REPLACE(
                        REPLACE(vendor_product, '_', ' '), 
                        '\\b(\\w+)(?:\\s+\\1\\b)+', 
                        '\\1', 
                        'ig'
                    )
                ) as vendor_product, 
                COUNT(*) as count 
            FROM cves 
            WHERE vendor_product IS NOT NULL 
              AND vendor_product != ''
              AND vendor_product NOT ILIKE 'n/a%'
              AND vendor_product NOT ILIKE '-%'
              AND vendor_product != '*'
              AND LENGTH(vendor_product) > 2
            GROUP BY INITCAP(
                REGEXP_REPLACE(
                    REPLACE(vendor_product, '_', ' '), 
                    '\\b(\\w+)(?:\\s+\\1\\b)+', 
                    '\\1', 
                    'ig'
                )
            )
            ORDER BY count DESC
            LIMIT 5
        `);
        res.json(result.rows);
    } catch (error) {
        console.error('Product Stats Error:', error);
        res.status(500).json({ message: 'Error fetching product stats' });
    }
});

app.get('/api/stats/cve-trend', async (req, res) => {
    const { year, month } = req.query;
    try {
        const dateExpr = "NULLIF(published_date::text, '')::timestamp";
        
        let selectClause, groupByClause, whereClause = "WHERE published_date IS NOT NULL AND published_date::text != ''";
        let params = [];

        if (year && month && year !== 'all' && month !== 'all') {
            selectClause = `EXTRACT(DAY FROM ${dateExpr}) as label`;
            groupByClause = `EXTRACT(DAY FROM ${dateExpr})`;
            whereClause += ` AND EXTRACT(YEAR FROM ${dateExpr}) = $1::int AND EXTRACT(MONTH FROM ${dateExpr}) = $2::int`;
            params = [year, month];
        } else if (year && year !== 'all') {
            selectClause = `EXTRACT(MONTH FROM ${dateExpr}) as label`;
            groupByClause = `EXTRACT(MONTH FROM ${dateExpr})`;
            whereClause += ` AND EXTRACT(YEAR FROM ${dateExpr}) = $1::int`;
            params = [year];
        } else {
            selectClause = `EXTRACT(YEAR FROM ${dateExpr}) as label`;
            groupByClause = `EXTRACT(YEAR FROM ${dateExpr})`;
        }

        const result = await pool.query(`
            SELECT 
                ${selectClause}, 
                COUNT(*) as count
            FROM cves 
            ${whereClause}
            GROUP BY ${groupByClause}
            ORDER BY label ASC
        `, params);

        res.json(result.rows);
    } catch (error) {
        console.error('Trend Stats Error:', error);
        res.status(500).json({ message: 'Error fetching CVE trends' });
    }
});

app.get('/api/stats/cves-by-date', async (req, res) => {
    const { year, month, day } = req.query;
    if (!year || !month || !day) return res.status(400).json({ message: "Thiếu tham số thời gian" });
    
    try {
        const dateExpr = "NULLIF(published_date::text, '')::timestamp";
        const result = await pool.query(`
            SELECT id, title, cvss_score, vendor_product
            FROM cves
            WHERE published_date IS NOT NULL AND published_date::text != ''
              AND EXTRACT(YEAR FROM ${dateExpr}) = $1::int 
              AND EXTRACT(MONTH FROM ${dateExpr}) = $2::int
              AND EXTRACT(DAY FROM ${dateExpr}) = $3::int
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT 50
        `, [year, month, day]);
        res.json(result.rows);
    } catch (error) {
        console.error('Get CVE by Date Error:', error);
        res.status(500).json({ message: 'Lỗi server' });
    }
});

let threatCache = {
    phishing: { data: null, lastFetch: 0 },
    criticalCves: { data: null, lastFetch: 0 }
};

const CACHE_DURATION = 15 * 60 * 1000;

app.get('/api/stats/phishing-feed', async (req, res) => {
    try {
        const now = Date.now();
        if (threatCache.phishing.data && (now - threatCache.phishing.lastFetch < CACHE_DURATION)) {
            return res.json(threatCache.phishing.data);
        }

        const response = await fetch('https://openphish.com/feed.txt');
        if (!response.ok) throw new Error('Failed to fetch OpenPhish');

        const text = await response.text();
        const urls = text.split('\n').filter(url => url.trim() !== '').slice(0, 10);

        const result = {
            source: 'OpenPhish',
            updatedAt: new Date(),
            data: urls.map(url => ({ url: url, type: 'Phishing', target: 'Unknown (Zero-day)', risk: 'High' }))
        };

        threatCache.phishing = { data: result, lastFetch: now };
        res.json(result);
    } catch (error) {
        console.error('Phishing Feed Error:', error);
        res.status(500).json({ message: 'Error fetching phishing feed' });
    }
});

app.get('/api/stats/critical-cves', async (req, res) => {
    try {
        const now = Date.now();
        if (threatCache.criticalCves.data && (now - threatCache.criticalCves.lastFetch < CACHE_DURATION)) {
            return res.json(threatCache.criticalCves.data);
        }

        const endDate = new Date();
        const startDate = new Date();
        startDate.setDate(endDate.getDate() - 30);

        const startStr = startDate.toISOString().split('.')[0];
        const endStr = endDate.toISOString().split('.')[0];
        const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startStr}&pubEndDate=${endStr}&cvssV3Severity=CRITICAL&resultsPerPage=5`;

        const response = await fetch(nvdUrl);
        if (!response.ok) throw new Error(`NVD API Error: ${response.status}`);

        const data = await response.json();
        const cves = data.vulnerabilities.map(item => {
            const cve = item.cve;
            const metrics = cve.metrics.cvssMetricV31 || cve.metrics.cvssMetricV30;
            const score = metrics ? metrics[0].cvssData.baseScore : 'N/A';

            return {
                id: cve.id,
                score: score,
                description: cve.descriptions[0].value,
                published: cve.published,
                link: `https://nvd.nist.gov/vuln/detail/${cve.id}`
            };
        });

        const result = { source: 'NVD NIST', data: cves };
        threatCache.criticalCves = { data: result, lastFetch: now };
        res.json(result);
    } catch (error) {
        console.error('NVD API Error:', error);
        res.json({ source: 'NVD (Error)', data: [] });
    }
});

const blogConn = mongoose.createConnection(process.env.MONGO_URI, { dbName: 'aicp_blog' });
blogConn.on('connected', () => console.log('MongoDB: Connected to aicp_blog'));
module.exports = { blogConn };

const Blog = require('./models/Blog');

app.get('/api/image-proxy', async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send('Missing URL parameter');

    try {
        const axios = require('axios');
        const https = require('https');

        const agent = new https.Agent({ 
            ciphers: 'DEFAULT:@SECLEVEL=0', 
            rejectUnauthorized: false 
        });

        const response = await axios.get(url, {
            httpsAgent: agent,
            responseType: 'arraybuffer',
            timeout: 10000,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Referer': 'https://sec.vnpt.vn/',
                'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8'
            }
        });

        const contentType = response.headers['content-type'];
        res.setHeader('Content-Type', contentType);
        res.send(response.data);

    } catch (error) {
        console.error(`Image Proxy Error (${url}):`, error.message);
        res.status(500).send('Error fetching image');
    }
});

app.get('/api/blogs', async (req, res) => {
    try {
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = parseInt(req.query.limit) || 9;
        const skip = (page - 1) * limit;

        const [blogs, total] = await Promise.all([
            Blog.find().select('title description image date_string author source publishedAt _id').sort({ publishedAt: -1 }).skip(skip).limit(limit),
            Blog.countDocuments()
        ]);

        res.json({
            status: 'success',
            data: blogs,
            pagination: {
                currentPage: page,
                totalPages: Math.ceil(total / limit),
                totalItems: total,
                itemsPerPage: limit,
                hasNextPage: page < Math.ceil(total / limit),
                hasPrevPage: page > 1
            }
        });
    } catch (error) {
        console.error('Error fetching blogs:', error);
        res.status(500).json({ status: 'error', message: 'Server Error', error: error.message });
    }
});

app.get('/api/blogs/:id', async (req, res) => {
    try {
        const blog = await Blog.findById(req.params.id).select('-content_text');
        if (!blog) return res.status(404).json({ message: 'Blog not found' });
        res.json(blog);
    } catch (error) {
        console.error('Error fetching blog detail:', error);
        if (error.kind === 'ObjectId') return res.status(404).json({ message: 'Invalid Blog ID' });
        res.status(500).json({ message: 'Server Error' });
    }
});

const scanController = require('./controllers/scanController');
app.post('/api/scan/upload', authenticateToken, upload.single('projectFile'), scanController.uploadAndExtract);
app.post('/api/scan/graph/more', authenticateToken, scanController.loadMoreGraph);
app.post('/api/scan/analyze', authenticateToken, scanController.analyzeAstAndLlm);
app.post('/api/scan/patch', authenticateToken, scanController.generatePatch);
app.get('/api/scan/graph', authenticateToken, scanController.getFullGraph);
app.post('/api/scan/explain', authenticateToken, scanController.explainVulnerability);
app.get('/api/scan/progress/:scanId', authenticateToken, scanController.getScanProgress);

app.post('/api/scan/github/token', scanController.getGithubAccessToken);
app.get('/api/scan/github/repos', scanController.getGithubRepos);

app.get('/api/cwe/:id', async (req, res) => {
    try {
        const cweId = req.params.id.toUpperCase();
        
        const cweRes = await pool.query('SELECT cwe_name, cwe_description FROM cwe_dictionary WHERE cwe_id = $1', [cweId]);
        const cweName = cweRes.rows.length > 0 ? cweRes.rows[0].cwe_name : 'Unknown Vulnerability (Chưa có trong từ điển)';

        const cveRes = await pool.query(`
            SELECT c.id, COALESCE(c.cvss_score, 0) as score, c.description as desc
            FROM cves c
            JOIN cve_cwe_mapping m ON c.id = m.cve_id
            WHERE m.cwe_id = $1
            ORDER BY c.cvss_score DESC NULLS LAST
            LIMIT 15
        `, [cweId]);

        res.json({
            success: true,
            cwe: { id: cweId, name: cweName },
            cves: cveRes.rows
        });
    } catch (error) {
        console.error("Lỗi khi lấy lịch sử CWE-CVE:", error);
        res.status(500).json({ success: false, message: "Lỗi server khi truy xuất Database." });
    }
});

// =================================================================
const clientBuildPath = path.join(__dirname, '..', 'client', 'dist'); 

app.use(express.static(clientBuildPath));

app.use((req, res) => {
    if (req.method === 'GET' && !req.path.startsWith('/api/')) {
        const indexPath = path.join(clientBuildPath, 'index.html');
        if (fs.existsSync(indexPath)) {
            res.sendFile(indexPath);
        } else {
            res.status(404).send("Client build dist/index.html not found. Please run 'npm run build'.");
        }
    } else {
        res.status(404).json({ message: "API Endpoint Not Found" });
    }
});
// =================================================================

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});