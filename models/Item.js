const mongoose = require("mongoose");

const ItemSchema = new mongoose.Schema({
  // Item details
  item_name: { type: String, required: true },
  item_type: { type: String, required: true },
  item_block: { type: String, required: true },
  item_place: { type: String, required: true },
  description: String,
  photo: String, // Changed from photos: [String] back to photo: String
  remarks: String,
  status: { type: String, default: "lost" }, // 'lost' | 'found' | 'done' | 'Contacted'
  initial_status: { type: String }, // 'lost' | 'found' - tracks the original status when item was reported
  
  // Reporter information (person who reported the item)
  reporter: {
    rollno: { type: String, required: true },
    name: { type: String, required: true },
    email: { type: String, required: true },
    mobile_number: String,
    email_sent: { type: Boolean, default: false } // when match emails have been sent to reporter
  },
  
  // Contactor information (person who found the item)
  contactor: {
    rollno: String,
    name: String,
    email: String,
    email_sent: { type: Boolean, default: false } // when contact email sent to finder
  },
  
  // Legacy fields (kept for backward compatibility)
  rollno: { type: String, index: true }, // Duplicate of reporter.rollno
  college_email: String, // Duplicate of reporter.email
  mobile_number: String, // Duplicate of reporter.mobile_number
  email_sent: Boolean, // Duplicate of reporter.email_sent
  contact_email_sent: Boolean, // Duplicate of contactor.email_sent
  found_by: String, // Duplicate of contactor.rollno
  
  // Timestamps
  found_date: Date,
  date_reported: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Item", ItemSchema);
