import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

type MailOptions = {
  recipient: string | string[];
  subject: string;
  text?: string;
  html?: string;
};

async function sendMail(recipient: string | string[], subject: string, text?: string, html?: string) {
  const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : undefined;
  const secure = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : (port === 465);

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure,
    auth: process.env.SMTP_USER && process.env.SMTP_PASS ? {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    } : undefined,
  });

  const from = process.env.SMTP_USERNAME && process.env.SMTP_USER ? `"${process.env.SMTP_USERNAME}" <${process.env.SMTP_USER}>` : process.env.SMTP_USER || undefined;

  try {
    const info = await transporter.sendMail({
      from,
      to: recipient,
      subject,
      text,
      html,
    });
    // prefer logger when available
    // eslint-disable-next-line no-console
    console.log('Message sent: %s', info.messageId);
    return info;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Error sending email', err);
    throw err;
  }
}

export default sendMail;
export { sendMail, MailOptions };
