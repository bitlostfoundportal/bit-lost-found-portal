const mongoose = require('mongoose');
require('dotenv').config();
const Item = require('../models/Item');
const Student = require('../models/Student');

async function migrate() {
  try {
    // Connect to MongoDB
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');

    // Get all items
    const items = await Item.find({}).lean();
    console.log(`Found ${items.length} items to migrate`);

    // Process each item
    for (const item of items) {
      try {
        const update = {
          // Move reporter info to the new structure
          reporter: {
            rollno: item.rollno || '',
            name: '', // Will be filled from student data
            email: item.college_email || '',
            mobile_number: item.mobile_number || '',
            email_sent: item.email_sent || false,
          },
          // Initialize contactor info
          contactor: {
            rollno: item.found_by || '',
            name: '', // Will be filled from student data
            email: '', // Will be filled from student data
            email_sent: item.contact_email_sent || false,
          },
        };

        // Get reporter's name from student data
        if (item.rollno) {
          const reporter = await Student.findOne({ rollno: item.rollno }).lean();
          if (reporter) {
            update.reporter.name = reporter.name || '';
            update.reporter.email = reporter.college_email || update.reporter.email;
            update.reporter.mobile_number = reporter.mobile_number || update.reporter.mobile_number;
          }
        }

        // Get contactor's details if found_by exists
        if (item.found_by) {
          const contactor = await Student.findOne({ rollno: item.found_by }).lean();
          if (contactor) {
            update.contactor.name = contactor.name || '';
            update.contactor.email = contactor.college_email || '';
          }
        }

        // Update the item
        await Item.updateOne(
          { _id: item._id },
          { $set: update }
        );

        console.log(`Migrated item ${item._id}`);
      } catch (error) {
        console.error(`Error migrating item ${item._id}:`, error.message);
      }
    }

    console.log('Migration completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    process.exit(1);
  }
}

// Run the migration
migrate();
