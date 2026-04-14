# 🔐 Secure Authentication System (MFA-Based)

## 📌 Overview
This project is a **Secure Authentication System** that implements **Multi-Factor Authentication (MFA)** using Email OTP verification. It enhances security by adding an extra layer beyond traditional username and password login.

---

## 🚀 Features
- User Registration
- Secure Login System
- Password Hashing (Bcrypt)
- Email OTP Verification (MFA)
- Session Management
- Protected Dashboard Access
- Logout Functionality

---

## 🛠️ Tech Stack
- **Backend:** Node.js, Express.js
- **Database:** SQLite (Sequelize ORM)
- **Authentication:** Sessions + Bcrypt
- **Email Service:** Brevo API
- **Deployment:** Railway

---

## 🔐 How It Works
1. User logs in with email and password  
2. System verifies credentials  
3. OTP is generated  
4. OTP is sent to user’s email  
5. User enters OTP  
6. Access is granted after verification  

---

## ⚙️ Environment Variables
Create a `.env` file and add:


---

## ▶️ Running the Project

### Install dependencies

### Start the server


---

## 🌐 Deployment
The application is deployed on **Railway** and uses **Brevo API** for sending OTP emails.

---

## 📌 Future Enhancements
- OTP Expiry Timer
- Resend OTP Feature
- Mobile OTP Integration
- JWT Authentication
- Improved UI/UX

---

## 👨‍💻 Author
Developed as a project for implementing secure authentication using MFA.

---

## 📄 License
This project is for educational purposes.
