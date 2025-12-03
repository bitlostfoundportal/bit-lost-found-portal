# BIT Lost-Found Portal

## Table of Contents

*   [Project Description](#project-description)
*   [Features](#features)
*   [Technologies Used](#technologies-used)
*   [Getting Started](#getting-started)
    *   [Prerequisites](#prerequisites)
    *   [Installation](#installation)
    *   [Environment Variables](#environment-variables)
    *   [Running the Server](#running-the-server)
*   [Usage](#usage)
*   [Admin Credentials (Example)](#admin-credentials-example)
*   [Deployment Notes](#deployment-notes)
*   [Contact](#contact)
*   [License](#license)

## Project Description

The BIT Lost-Found Portal is a full-stack web application designed to help students and staff at the institute report and find lost or found items. The platform facilitates communication between users, with administrative features for managing students and reported items. It includes features like user authentication (local and Google OAuth), item reporting with image uploads, item search, and a dashboard for managing personal reports.

## Features

*   **User Authentication**: Secure login for students using either Roll No./Password or Google OAuth.
*   **Admin Panel**: Separate authentication and management interface for administrators.
*   **Item Reporting**: Users can report lost or found items with details and a single photo upload.
*   **Item Search**: Search functionality to find reported lost/found items.
*   **My Reports**: Users can view and manage their own reported items.
*   **Responsive Design**: UI is optimized for various screen sizes (desktop, tablet, mobile).
*   **Secure API Endpoints**: Protected routes with proper authentication and authorization.
*   **Image Uploads**: Cloudinary integration for secure and efficient image storage.
*   **Email Notifications**: (If implemented) for status updates or contact.

## Technologies Used

**Backend (Node.js/Express):**
*   Node.js
*   Express.js
*   MongoDB (with Mongoose ODM)
*   Passport.js (for authentication - Local, Google OAuth)
*   `bcryptjs` (for password hashing)
*   `express-session` & `connect-mongo` (for session management)
*   `Multer` & `Cloudinary` (for image uploads)
*   `Nodemailer` (for email functionality)
*   `express-rate-limit` (for API rate limiting)
*   `Helmet.js` (for security headers)
*   `Winston` (for logging)

**Frontend (HTML/CSS/JavaScript):**
*   HTML5
*   CSS3 (with Flexbox and Media Queries for responsiveness)
*   Vanilla JavaScript (for DOM manipulation and API interactions)

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Make sure you have the following installed:

*   Node.js (LTS version recommended)
*   MongoDB (local installation or access to a cloud instance like MongoDB Atlas)
*   npm (Node Package Manager) - typically comes with Node.js

### Installation

1.  Clone the repository:

    ```bash
    git clone <repository-url>
    cd campu-lost-found
    ```

2.  Install NPM dependencies:

    ```bash
    npm install
    ```

### Environment Variables

Create a `.env` file in the root directory of the project and add the following environment variables. **Do NOT commit your `.env` file to version control.**

```
NODE_ENV=development
PORT=3000

// MongoDB
MONGO_URI=mongodb://localhost:27017/lostfounddb

// Session Management
SESSION_SECRET=your_long_random_secret_string
SESSION_NAME=bit_lf_sid

// Cloudinary (for image uploads)
CLOUDINARY_CLOUD_NAME=your_cloudinary_cloud_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret

// Google OAuth
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

// CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000

// Rate Limiting
RATE_LIMIT_MAX=100

// Nodemailer (for email notifications - if implemented and used)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_email_password

// Trust Proxy (for production environments behind a proxy/load balancer)
TRUST_PROXY=false
```

**Note**: For production, ensure `NODE_ENV=production` and `TRUST_PROXY=true` if your app is behind a proxy (like on Render, Heroku, etc.). Also, update `MONGO_URI`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK_URL`, `CORS_ALLOWED_ORIGINS`, `CLOUDINARY_*`, `EMAIL_*` with your production URLs and credentials.

### Running the Server

To start the development server:

```bash
npm start
```

The server will be accessible at `http://localhost:3000` (or the port specified in your `.env` file).

## Usage

Once the server is running, you can access the application through your web browser:

*   **Student Login**: Navigate to `/login` to log in or register. Students can use their Roll No./Password or Google account.
*   **Admin Login**: Access administrator functionalities via `/admin/login`. Admin accounts typically require specific credentials or a `isSuperAdmin` flag in the database.
*   **Report Lost/Found**: Use the respective pages (`/report-lost` and `/report-found`) to report items.
*   **My Reports**: View and manage your own reported items on the `/my-reports` page.
*   **Search**: Search for items using the `/search` page.

## Admin Credentials (Example)

For initial setup or development, you might need to manually create an admin user in your MongoDB. An example structure could be:

```json
{
    "rollno": "admin",
    "name": "Admin User",
    "college_email": "admin@example.com",
    "password": "$2a$10$YourHashedPasswordHere", // Hash a password like 'admin123' using bcrypt
    "isSuperAdmin": true
}
```

**Important**: Always use strong, unique passwords for production admin accounts and manage them securely.

## Deployment Notes

When deploying this application to a live platform, consider the following best practices:

*   **Environment Variables**: Securely configure all necessary environment variables on your hosting platform (e.g., Render, Heroku, AWS, Google Cloud). Each platform has a specific way to manage these.
*   **Database**: Utilize a managed database service like MongoDB Atlas for enhanced reliability, scalability, and automated backups in production.
*   **HTTPS**: Ensure your application is served over HTTPS to encrypt data in transit. Most cloud providers offer easy configuration for this when you attach a custom domain.
*   **Domain Name**: Acquire a custom domain name and point it to your deployed application.
*   **Security Audits**: Regularly run security audits (`npm audit`) and keep all project dependencies updated to mitigate vulnerabilities.
*   **Monitoring & Logging**: Implement robust monitoring and centralized logging to quickly identify and troubleshoot issues in the production environment.

## Contact

For any questions or further information about this project, please contact:

*   **Author**: VASANTHARAJ M

## License

This project is private and all rights are reserved by the author. Unauthorized use, distribution, or modification is prohibited.
