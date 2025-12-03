# Secure End-to-End Encrypted Messaging & File-Sharing System

A secure communication system providing **end-to-end encryption (E2EE)** for text messaging and file sharing, built as part of the Information Security course (BSSE 7th Semester).

## 🔐 Security Features

- **End-to-End Encryption**: Messages and files are encrypted client-side using AES-256-GCM
- **Hybrid Cryptography**: Combines asymmetric (ECC/RSA) with symmetric encryption (AES-GCM)
- **Secure Key Exchange**: Custom ECDH-based protocol with digital signatures (ECDSA)
- **Zero-Knowledge Server**: Server cannot decrypt or view any user content
- **Replay Attack Protection**: Timestamps, nonces, and sequence numbers
- **Two-Factor Authentication**: TOTP-based 2FA with backup codes
- **Security Logging**: Comprehensive audit logs for security events

## 🛠️ Technology Stack

### Frontend
- React.js
- Web Crypto API (SubtleCrypto) for all cryptographic operations
- IndexedDB for secure private key storage
- Socket.io-client for real-time communication
- Tailwind CSS + shadcn/ui for UI components

### Backend
- Node.js + Express
- MongoDB for encrypted message/metadata storage
- Socket.io for real-time messaging
- Winston for security logging
- bcrypt for password hashing

## 📋 Prerequisites

- Node.js (v18 or higher)
- MongoDB (local instance or MongoDB Atlas)
- npm or yarn

## 🚀 Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/MuhammadAhmadFarooq/InfoSec-Project.git
cd InfoSec-Project
```

### 2. Backend Setup

```bash
# Navigate to server directory
cd server

# Install dependencies
npm install

# Create environment file
# Create a .env file with the following variables:
```

Create `server/.env`:
```env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/secure-messenger
JWT_SECRET=your-secure-random-jwt-secret-here
NODE_ENV=development
```

> **Note**: For MongoDB Atlas, use your connection string:
> `MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname`

```bash
# Start the server
node server.js
```

The server will run on `http://localhost:5000`

### 3. Frontend Setup

```bash
# Open a new terminal
# Navigate to client directory
cd client

# Install dependencies
npm install

# Start the development server
npm run dev
```

The client will run on `http://localhost:5173`

### 4. Access the Application

1. Open `http://localhost:5173` in your browser
2. Create a new account (keys are generated automatically)
3. Open another browser/incognito window for a second user
4. Start secure messaging!

## 📁 Project Structure

```
InfoSec-Project/
├── client/                     # React Frontend
│   ├── src/
│   │   ├── components/         # UI Components
│   │   ├── contexts/           # React Context (Auth)
│   │   ├── hooks/              # Custom hooks
│   │   ├── lib/
│   │   │   ├── crypto.js       # All cryptographic operations
│   │   │   ├── storage.js      # IndexedDB key storage
│   │   │   ├── api.js          # API client
│   │   │   └── utils.js        # Utility functions
│   │   └── pages/
│   │       ├── Auth.jsx        # Login/Register
│   │       └── Chat.jsx        # Main chat interface
│   └── package.json
│
├── server/                     # Node.js Backend
│   ├── controllers/
│   │   ├── authController.js   # Authentication logic
│   │   ├── fileController.js   # File upload/download
│   │   ├── messageController.js
│   │   └── userController.js
│   ├── middleware/
│   │   ├── auth.js             # JWT verification
│   │   └── socketAuth.js       # Socket authentication
│   ├── models/
│   │   ├── User.js
│   │   ├── Message.js
│   │   ├── FileChunk.js
│   │   └── KeyExchange.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── files.js
│   │   ├── keyexchange.js
│   │   ├── messages.js
│   │   └── users.js
│   ├── sockets/
│   │   └── index.js            # Real-time message handling
│   ├── utils/
│   │   ├── logger.js           # Winston logging
│   │   └── totp.js             # 2FA implementation
│   ├── logs/                   # Security logs
│   ├── server.js               # Entry point
│   └── package.json
│
└── README.md
```

## 🔒 Cryptographic Design

### Key Generation (On Registration)
- **ECC Mode**: ECDH (P-256) for key exchange + ECDSA (P-256) for signatures
- **RSA Mode**: RSA-OAEP (2048-bit) for encryption

### Key Exchange Protocol
1. **Initiator** generates ephemeral ECDH keypair
2. **Initiator** signs the public key with ECDSA
3. **Responder** receives, verifies signature, generates own ephemeral keypair
4. **Responder** derives shared secret using ECDH
5. **Both parties** derive AES-256-GCM session key
6. **Key Confirmation** messages exchanged to verify matching keys

### Message Encryption
- Algorithm: AES-256-GCM
- Fresh random 12-byte IV per message
- 128-bit authentication tag for integrity
- Sequence numbers for replay protection

### File Encryption
- Files chunked for large file support
- Each chunk encrypted with AES-256-GCM
- Separate IV and tag per chunk

## 🛡️ Security Measures

### Replay Attack Protection
- Timestamp validation (5-minute window)
- Sequence number tracking
- Duplicate detection on server

### MITM Prevention
- Digital signatures on key exchange
- Public key verification

### Secure Storage
- Private keys stored in IndexedDB (never sent to server)
- Passwords hashed with bcrypt (salt rounds: 12)
- Session keys derived per conversation

## 📊 Security Logging

The system logs the following security events:

**Server-side (`logs/combined.log`):**
- Authentication attempts (success/failure)
- Key exchange initiation/completion
- Replay attack detections
- Message delivery status

**Client-side (Security Logs panel):**
- Socket connections
- Key exchanges
- Key confirmations
- Detected security events

## 🧪 Testing Security Features

### Test Replay Attack Protection
1. Send a message between two users
2. Check server logs for sequence number tracking
3. Attempt to resend the same message (will be rejected)

### Test Key Exchange
1. Select a user to chat with
2. Observe "Waiting for key exchange..." toast
3. Key exchange completes automatically
4. "Secure Channel" badge appears

### View Security Logs
1. Click the alert icon in the chat sidebar
2. View real-time security events

## 🔧 Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PORT` | Server port | `5000` |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/db` |
| `JWT_SECRET` | Secret for JWT signing | Random secure string |
| `NODE_ENV` | Environment mode | `development` or `production` |

## 👥 Team Members

- Muhammad Ahmad 22i-2711
- Usaid Afzal 22i-8783

## 📝 License

This project is created for educational purposes as part of the Information Security course project at FAST-NUCES.

---

**Note**: This is an academic project. For production use, additional security measures such as HTTPS, rate limiting, and security audits would be required.
