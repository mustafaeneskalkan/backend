import nodemailer from 'nodemailer';
import logger from './logger.js';
import { loadEnv } from './env.js';

loadEnv();

type MailOptions = {
  recipient: string | string[];
  subject: string;
  text?: string;
  html?: string;
};

let cachedTransporter: nodemailer.Transporter | null = null;

function getTransporter(): nodemailer.Transporter {
  if (cachedTransporter) return cachedTransporter;

  const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT, 10) : undefined;
  const secure = process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : (port === 465);

  cachedTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure,
    auth: process.env.SMTP_USER && process.env.SMTP_PASS ? {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    } : undefined,
  });

  return cachedTransporter;
}

async function sendMail(recipient: string | string[], subject: string, text?: string, html?: string) {
  const transporter = getTransporter();

  const from = process.env.SMTP_USERNAME && process.env.SMTP_USER ? `"${process.env.SMTP_USERNAME}" <${process.env.SMTP_USER}>` : process.env.SMTP_USER || undefined;

  try {
    const info = await transporter.sendMail({
      from,
      to: recipient,
      subject,
      text,
      html,
    });
    logger.info('Email sent', { messageId: info.messageId });
    return info;
  } catch (err) {
    logger.error('Error sending email', { error: err instanceof Error ? err.message : String(err) });
    throw err;
  }
}

export default sendMail;
export { sendMail, MailOptions };
