// file: server/utils/mailer.js

const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const sendOTPEmail = async (recipientEmail, otp) => {
    try {
        const mailOptions = {
            from: `"AICP Service" <${process.env.EMAIL_USER}>`,
            to: recipientEmail,
            subject: `Your AICP Verification Code is ${otp}`,
            html: `
                <div style="font-family: Arial, sans-serif; text-align: center; color: #333;">
                    <h2>Welcome to AICP!</h2>
                    <p>Your One-Time Password (OTP) for verification is:</p>
                    <p style="font-size: 24px; font-weight: bold; letter-spacing: 2px; background: #f0f0f0; padding: 10px 20px; border-radius: 5px; display: inline-block;">
                        ${otp}
                    </p>
                    <p>This code will expire in 10 minutes.</p>
                    <p>If you did not request this, please ignore this email.</p>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);
        console.log(`OTP email sent to ${recipientEmail}`);
        return true;
    } catch (error) {
        console.error("Error sending OTP email:", error);
        return false;
    }
};

module.exports = { sendOTPEmail };
