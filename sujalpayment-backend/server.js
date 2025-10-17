require('dotenv').config();
const express = require('express');
const Razorpay = require('razorpay');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const winston = require('winston');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Logger setup (professional logging)
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ],
});
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Middleware
app.use(bodyParser.json());
app.use(cors({
  origin: ['http://localhost:3000', 'https://your-github-username.github.io'], // Add your frontend URL
  credentials: true
}));

// Rate limiting for security (100 requests per 15 min per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// Initialize Razorpay instance
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Create order endpoint (matches your frontend)
app.post('/create-order', async (req, res) => {
  try {
    const { amount } = req.body; // Amount in INR (e.g., 100 for ₹100)
    if (!amount || amount < 1) {
      return res.status(400).json({ success: false, message: 'Invalid amount' });
    }

    const options = {
      amount: amount * 100, // Razorpay expects paise (multiply by 100)
      currency: 'INR',
      receipt: `receipt_${Date.now()}`
    };

    const order = await razorpayInstance.orders.create(options);
    logger.info(`Order created: ${order.id} for amount ${amount}`);
    res.status(200).json({
      success: true,
      order_id: order.id,
      amount: order.amount,
      currency: order.currency
    });
  } catch (error) {
    logger.error(`Order creation error: ${error.message}`);
    res.status(500).json({ success: false, message: 'Failed to create order' });
  }
});

// Verify payment endpoint (matches your frontend)
app.post('/verify-payment', async (req, res) => {
  try {
    const { razorpay_payment_id, razorpay_order_id, razorpay_signature, amount } = req.body;

    // Create payload string for signature verification
    const sign = razorpay_payment_id + '|' + razorpay_order_id;
    const expectedSign = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest('hex');

    if (expectedSign === razorpay_signature) {
      // Fetch payment details for additional verification
      const payment = await razorpayInstance.payments.fetch(razorpay_payment_id);
      if (payment.status === 'captured' && payment.amount === amount * 100) {
        logger.info(`Payment verified: ${razorpay_payment_id}`);
        res.status(200).json({ success: true, message: 'Payment verified successfully' });
      } else {
        res.status(400).json({ success: false, message: 'Payment not captured or amount mismatch' });
      }
    } else {
      logger.warn(`Signature mismatch for payment: ${razorpay_payment_id}`);
      res.status(400).json({ success: false, message: 'Invalid signature' });
    }
  } catch (error) {
    logger.error(`Payment verification error: ${error.message}`);
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

// Webhook endpoint for payment events (e.g., success notifications)
app.post('/webhook', (req, res) => {
  try {
    const { event } = req.body;
    const expectedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
      .update(JSON.stringify(req.body))
      .digest('hex');

    if (expectedSignature !== req.headers['x-razorpay-signature']) {
      return res.status(400).json({ success: false, message: 'Invalid webhook signature' });
    }

    if (event === 'payment.captured') {
      const { payload: { payment: { id } } } = req.body;
      logger.info(`Webhook: Payment ${id} captured`);
      // Add your logic here (e.g., update database, send email)
    }

    res.status(200).json({ success: true });
  } catch (error) {
    logger.error(`Webhook error: ${error.message}`);
    res.status(500).json({ success: false });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  console.log(`Server running on http://localhost:${PORT}`);
});
