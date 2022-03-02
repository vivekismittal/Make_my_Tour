const nodemailer = require('nodemailer');

const sendEmail = async options => {
    //1) transporter
    const transporter = nodemailer.createTransport({
        host : process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            username: process.env.EMAIL_USERNAME,
            password: process.env.EMAIL_PASSWORD
        }
    });

    //2) define the email option
    const mailoptions = {
        from: 'Vivek mittal <itsme@gmail.com>',
        to: options.email,
        subject: options.subject,
        text: options.message
        //html
    };
    await transporter.sendEmail(mailoptions);
    //3) actually send the email
}
module.exports = sendEmail;