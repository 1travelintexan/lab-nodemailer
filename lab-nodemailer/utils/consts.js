const MONGO_URI =
  process.env.MONGODB_URI || "mongodb://127.0.0.1/lab-nodemailer";

module.exports = MONGO_URI;
