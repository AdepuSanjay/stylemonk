require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const { OAuth2Client } = require('google-auth-library');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

// ==========================================
// 1. CONFIGURATIONS
// ==========================================
// Hardcoded Cloudinary configuration
cloudinary.config({
  cloud_name: "dppiuypop",
  api_key: "412712715735329",
  api_secret: "m04IUY0-awwtr4YoS-1xvxOOIzU",
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: { folder: 'stylemonk_products', allowed_formats: ['jpg', 'png', 'jpeg', 'webp'] },
});
const upload = multer({ storage });

// Hardcoded Nodemailer configuration
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "adepusanjay444@gmail.com",
    pass: "lmcibicocbphqbbs",
  }
});

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Razorpay Configuration
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_YOUR_KEY_HERE',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'YOUR_SECRET_HERE',
});

// ==========================================
// 2. DATABASE MODELS
// ==========================================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  googleId: { type: String },
  role: { type: String, enum: ['customer', 'admin'], default: 'customer' },
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  createdAt: { type: Date, default: Date.now, expires: 300 }
});
const OTP = mongoose.model('OTP', otpSchema);

const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  category: { type: String, enum: ['Shirts', 'Trousers', 'Jackets', 'Accessories'], required: true },
  price: { type: Number, required: true },
  sizes: [{ type: String, enum: ['S', 'M', 'L', 'XL', 'XXL'] }],
  colors: [{ type: String }],
  images: [{ url: String, public_id: String }],
  stock: { type: Number, required: true, default: 0 },
}, { timestamps: true });
const Product = mongoose.model('Product', productSchema);

const cartSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    quantity: { type: Number, default: 1 },
    size: String,
    color: String
  }]
}, { timestamps: true });
const Cart = mongoose.model('Cart', cartSchema);

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  orderItems: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    name: String, quantity: Number, price: Number, size: String, color: String, image: String
  }],
  shippingAddress: { address: String, city: String, postalCode: String, country: String },
  paymentMethod: { type: String, required: true },
  paymentResult: { id: String, status: String, update_time: String, email_address: String },
  totalPrice: { type: Number, required: true, default: 0.0 },
  isPaid: { type: Boolean, required: true, default: false },
  paidAt: { type: Date },
  isDelivered: { type: Boolean, required: true, default: false },
  deliveredAt: { type: Date },
}, { timestamps: true });
const Order = mongoose.model('Order', orderSchema);

// ==========================================
// 3. MIDDLEWARES (Auth & Protection)
// ==========================================
const protect = async (req, res, next) => {
  let token = req.headers.authorization?.startsWith('Bearer') ? req.headers.authorization.split(' ')[1] : null;
  if (!token) return res.status(401).json({ message: 'Not authorized, no token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
    req.user = await User.findById(decoded.id).select('-password');
    next();
  } catch (error) {
    res.status(401).json({ message: 'Not authorized, token failed' });
  }
};

const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') next();
  else res.status(401).json({ message: 'Not authorized as an admin' });
};

const generateToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET || 'fallback_secret', { expiresIn: '30d' });

const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ==========================================
// 4. AUTHENTICATION API
// ==========================================
app.post('/api/auth/send-otp', asyncHandler(async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  await OTP.deleteMany({ email });
  await OTP.create({ email, otp });

  await transporter.sendMail({
    from: "adepusanjay444@gmail.com",
    to: email,
    subject: 'Stylemonk OTP Verification',
    text: `Your OTP is ${otp}. It is valid for 5 minutes.`
  });
  res.json({ message: 'OTP sent to email' });
}));

app.post('/api/auth/register', asyncHandler(async (req, res) => {
  const { name, email, password, otp } = req.body;
  const validOtp = await OTP.findOne({ email, otp });
  if (!validOtp) return res.status(400).json({ message: 'Invalid or expired OTP' });

  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json({ message: 'User already exists' });

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  const user = await User.create({ name, email, password: hashedPassword });
  await OTP.deleteOne({ email });

  res.status(201).json({ _id: user._id, name: user.name, email: user.email, role: user.role, token: generateToken(user._id) });
}));

app.post('/api/auth/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user && user.password && (await bcrypt.compare(password, user.password))) {
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email });
    await OTP.create({ email, otp });

    await transporter.sendMail({
      from: "adepusanjay444@gmail.com",
      to: email,
      subject: 'Stylemonk Login Verification',
      text: `Your login OTP is ${otp}. It is valid for 5 minutes.`
    });
    res.json({ message: 'Credentials valid. OTP sent to email for verification.', requiresOtp: true });
  } else {
    res.status(401).json({ message: 'Invalid email or password' });
  }
}));

app.post('/api/auth/verify-login', asyncHandler(async (req, res) => {
  const { email, otp } = req.body;
  const validOtp = await OTP.findOne({ email, otp });
  if (!validOtp) return res.status(400).json({ message: 'Invalid or expired OTP' });

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: 'User not found' });

  await OTP.deleteOne({ email });
  res.json({ _id: user._id, name: user.name, email: user.email, role: user.role, token: generateToken(user._id) });
}));

app.post('/api/auth/create-admin', asyncHandler(async (req, res) => {
  const { name, email, password, adminSecret } = req.body;
  if (adminSecret !== (process.env.ADMIN_SECRET || 'stylemonk2024')) {
    return res.status(401).json({ message: 'Unauthorized: Invalid Admin Secret' });
  }

  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json({ message: 'User already exists' });

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  const user = await User.create({ name, email, password: hashedPassword, role: 'admin' });

  res.status(201).json({ message: 'Admin created successfully', _id: user._id, email: user.email, role: user.role });
}));

app.post('/api/auth/admin-login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user && user.password && (await bcrypt.compare(password, user.password))) {
    if (user.role !== 'admin') return res.status(403).json({ message: 'Access denied: You are not an admin.' });
    res.json({ _id: user._id, name: user.name, email: user.email, role: user.role, token: generateToken(user._id) });
  } else {
    res.status(401).json({ message: 'Invalid email or password' });
  }
}));

app.post('/api/auth/google', asyncHandler(async (req, res) => {
  const { tokenId } = req.body;
  const ticket = await googleClient.verifyIdToken({ idToken: tokenId, audience: process.env.GOOGLE_CLIENT_ID });
  const { email, name, sub: googleId } = ticket.getPayload();

  let user = await User.findOne({ email });
  if (!user) user = await User.create({ name, email, googleId });

  res.json({ _id: user._id, name: user.name, email: user.email, role: user.role, token: generateToken(user._id) });
}));

// ==========================================
// 5. PRODUCTS API
// ==========================================
app.get('/api/products', asyncHandler(async (req, res) => {
  const category = req.query.category ? { category: req.query.category } : {};
  const products = await Product.find({ ...category });
  res.json(products);
}));

app.get('/api/products/:id', asyncHandler(async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (product) res.json(product);
  else res.status(404).json({ message: 'Product not found' });
}));

app.post('/api/products', protect, admin, upload.array('images', 5), asyncHandler(async (req, res) => {
  const { name, description, category, price, sizes, colors, stock } = req.body;

  const parsedSizes = sizes ? sizes.split(',') : [];
  const parsedColors = colors ? colors.split(',') : [];
  const images = req.files ? req.files.map(file => ({ url: file.path, public_id: file.filename })) : [];

  const product = await Product.create({ 
    name, description, category, price, stock,
    sizes: parsedSizes, colors: parsedColors, images 
  });
  res.status(201).json(product);
}));

// ==========================================
// 6. CART API
// ==========================================
app.get('/api/cart', protect, asyncHandler(async (req, res) => {
  let cart = await Cart.findOne({ user: req.user._id }).populate('items.product', 'name price images');
  if (!cart) cart = await Cart.create({ user: req.user._id, items: [] });
  res.json(cart);
}));

app.post('/api/cart', protect, asyncHandler(async (req, res) => {
  const { productId, quantity, size, color } = req.body;
  let cart = await Cart.findOne({ user: req.user._id });
  if (!cart) cart = new Cart({ user: req.user._id, items: [] });

  const itemIndex = cart.items.findIndex(i => i.product.toString() === productId && i.size === size && i.color === color);
  if (itemIndex > -1) {
    cart.items[itemIndex].quantity = quantity;
  } else {
    cart.items.push({ product: productId, quantity, size, color });
  }
  await cart.save();
  res.json(cart);
}));

app.delete('/api/cart/:itemId', protect, asyncHandler(async (req, res) => {
  const cart = await Cart.findOne({ user: req.user._id });
  if (cart) {
    cart.items = cart.items.filter(item => item._id.toString() !== req.params.itemId);
    await cart.save();
    res.json(cart);
  } else {
    res.status(404).json({ message: 'Cart not found' });
  }
}));

// ==========================================
// 7. ORDERS API (Including Razorpay)
// ==========================================
app.post('/api/orders', protect, asyncHandler(async (req, res) => {
  const { shippingAddress, paymentMethod } = req.body;
  const cart = await Cart.findOne({ user: req.user._id }).populate('items.product');

  if (!cart || cart.items.length === 0) return res.status(400).json({ message: 'No items in cart' });

  let totalPrice = 0;
  const orderItems = [];
  for (let item of cart.items) {
    if (item.product.stock < item.quantity) {
      return res.status(400).json({ message: `${item.product.name} is out of stock` });
    }
    orderItems.push({
      product: item.product._id,
      name: item.product.name,
      quantity: item.quantity,
      price: item.product.price,
      size: item.size,
      color: item.color,
      image: item.product.images[0]?.url
    });
    totalPrice += item.product.price * item.quantity;
    item.product.stock -= item.quantity;
    await item.product.save();
  }

  const order = await Order.create({ user: req.user._id, orderItems, shippingAddress, paymentMethod, totalPrice });
  cart.items = [];
  await cart.save();
  res.status(201).json(order);
}));

app.get('/api/orders/myorders', protect, asyncHandler(async (req, res) => {
  const orders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
  res.json(orders);
}));

// Generate Razorpay Order
app.post('/api/orders/:id/razorpay', protect, asyncHandler(async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ message: 'Order not found' });

  const options = {
    amount: Math.round(order.totalPrice * 100), // Razorpay works in smallest currency unit (paise)
    currency: "INR",
    receipt: `receipt_${order._id}`,
  };

  const razorpayOrder = await razorpay.orders.create(options);
  res.json(razorpayOrder);
}));

// Verify Razorpay Payment Signature
app.post('/api/orders/:id/verify-razorpay', protect, asyncHandler(async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

  const body = razorpay_order_id + "|" + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET || 'YOUR_SECRET_HERE')
    .update(body.toString())
    .digest("hex");

  if (expectedSignature === razorpay_signature) {
    const order = await Order.findById(req.params.id);
    order.isPaid = true;
    order.paidAt = Date.now();
    order.paymentResult = {
      id: razorpay_payment_id,
      status: 'COMPLETED',
      update_time: new Date().toISOString(),
      email_address: req.user.email,
    };
    await order.save();
    res.json({ message: "Payment verified successfully", order });
  } else {
    res.status(400).json({ message: "Invalid signature" });
  }
}));

// ==========================================
// 8. ERROR HANDLING MIDDLEWARES
// ==========================================
app.use((req, res, next) => {
  const error = new Error(`Route Not Found - ${req.originalUrl}`);
  res.status(404);
  next(error);
});

app.use((err, req, res, next) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(statusCode);
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'production' ? null : err.stack,
  });
});

// ==========================================
// 9. SERVER INITIALIZATION
// ==========================================
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/stylemonk')
  .then(() => {
    console.log('MongoDB Connected to Stylemonk DB');
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch(err => console.error('MongoDB connection error:', err));
