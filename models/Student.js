const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const StudentSchema = new mongoose.Schema({
  googleId: { type: String, unique: true, sparse: true },
  rollno: { type: String, required: true, unique: true, index: true }, // Institutional roll number, required and unique as per DB
  name: { type: String, required: true },
  college_email: { type: String, unique: true, sparse: true, index: true }, // Optional (sparse) for existing empty data, but unique
  password: { type: String, select: false }, // Store hashed password, 'select: false' prevents it from being returned in queries by default
  google_display_name: { type: String, default: null }, // Store the name collected during Google login
});

StudentSchema.pre("save", async function (next) {
    if (this.isModified("password")) {
      this.password = await bcrypt.hash(this.password, 10);
    }
    next();
  });

StudentSchema.methods.isValidPassword = async function (password) {
    const student = this;
    return await bcrypt.compare(password, student.password);
  };

module.exports = mongoose.model("Student", StudentSchema);
