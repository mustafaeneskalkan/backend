import mongoose from 'mongoose';

const connectDB = async (mongoUri?: string) => {
  const uri = mongoUri || process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI is not set in environment');
  }

  // Use the new URL parser and unified topology by default in mongoose 7+
  await mongoose.connect(uri);
  console.log('Connected to MongoDB');
};

export default connectDB;
