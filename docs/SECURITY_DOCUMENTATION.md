# Security Documentation & Demonstration Guide

This document provides comprehensive security analysis, attack demonstrations, and architectural documentation for the Secure E2EE Messaging System.

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Key Exchange Protocol](#2-key-exchange-protocol)
3. [STRIDE Threat Modeling](#3-stride-threat-modeling)
4. [MITM Attack Demonstration](#4-mitm-attack-demonstration)
5. [Replay Attack Demonstration](#5-replay-attack-demonstration)
6. [Wireshark Packet Capture Guide](#6-wireshark-packet-capture-guide)
7. [Security Controls Summary](#7-security-controls-summary)

---

## 1. System Architecture

### 1.1 High-Level Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           SECURE E2EE MESSAGING SYSTEM                          │
└─────────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐                              ┌──────────────────────┐
│      CLIENT A        │                              │      CLIENT B        │
│  (React + WebCrypto) │                              │  (React + WebCrypto) │
├──────────────────────┤                              ├──────────────────────┤
│                      │                              │                      │
│  ┌────────────────┐  │                              │  ┌────────────────┐  │
│  │  Private Keys  │  │                              │  │  Private Keys  │  │
│  │  (IndexedDB)   │  │                              │  │  (IndexedDB)   │  │
│  │  - ECDH Key    │  │                              │  │  - ECDH Key    │  │
│  │  - ECDSA Key   │  │                              │  │  - ECDSA Key   │  │
│  │  - Session Key │  │                              │  │  - Session Key │  │
│  └────────────────┘  │                              │  └────────────────┘  │
│                      │                              │                      │
│  ┌────────────────┐  │    Encrypted Messages        │  ┌────────────────┐  │
│  │   Crypto.js    │  │◄────────────────────────────►│  │   Crypto.js    │  │
│  │  - AES-256-GCM │  │    (Only ciphertext flows)   │  │  - AES-256-GCM │  │
│  │  - ECDH P-256  │  │                              │  │  - ECDH P-256  │  │
│  │  - ECDSA P-256 │  │                              │  │  - ECDSA P-256 │  │
│  └────────────────┘  │                              │  └────────────────┘  │
│                      │                              │                      │
└──────────┬───────────┘                              └───────────┬──────────┘
           │                                                      │
           │ HTTPS + WSS                                          │ HTTPS + WSS
           │ (TLS 1.3)                                            │ (TLS 1.3)
           │                                                      │
           ▼                                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              SERVER (Node.js + Express)                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                 │
│  │   Socket.io     │  │   REST API      │  │   Middleware    │                 │
│  │   Real-time     │  │   Endpoints     │  │   - JWT Auth    │                 │
│  │   Messages      │  │   - /auth       │  │   - Socket Auth │                 │
│  │                 │  │   - /messages   │  │   - Rate Limit  │                 │
│  │                 │  │   - /files      │  │                 │                 │
│  │                 │  │   - /keyexchange│  │                 │                 │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                 │
│                                                                                 │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                    ZERO-KNOWLEDGE DESIGN                                │   │
│  │  • Server NEVER sees plaintext messages                                 │   │
│  │  • Server NEVER has access to private keys                              │   │
│  │  • Server only stores/relays encrypted blobs                            │   │
│  │  • Server cannot decrypt any user content                               │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
└────────────────────────────────────┬────────────────────────────────────────────┘
                                     │
                                     ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              MONGODB DATABASE                                   │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐                 │
│  │     Users       │  │    Messages     │  │   FileChunks    │                 │
│  │  - username     │  │  - ciphertext   │  │  - encrypted    │                 │
│  │  - password     │  │  - iv           │  │    chunk data   │                 │
│  │    (bcrypt)     │  │  - authTag      │  │  - iv, authTag  │                 │
│  │  - publicKey    │  │  - timestamp    │  │  - chunkIndex   │                 │
│  │  - signingKey   │  │  - seqNum       │  │                 │                 │
│  │  - totp secret  │  │                 │  │                 │                 │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘                 │
│                                                                                 │
│  ┌─────────────────┐  ┌─────────────────────────────────────────────────────┐  │
│  │  KeyExchange    │  │                    STORED DATA                      │  │
│  │  - ephemeral    │  │  • All message content is encrypted (AES-256-GCM)   │  │
│  │    public keys  │  │  • Passwords are hashed (bcrypt, 12 rounds)         │  │
│  │  - signatures   │  │  • Only public keys stored, never private keys      │  │
│  │  - state        │  │  • TOTP secrets encrypted at rest                   │  │
│  └─────────────────┘  └─────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FRONTEND COMPONENTS                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│    Auth.jsx     │     │    Chat.jsx     │     │   NavLink.tsx   │
│  Login/Register │     │  Main Interface │     │   Navigation    │
└────────┬────────┘     └────────┬────────┘     └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CORE LIBRARIES                                  │
├─────────────────┬─────────────────┬─────────────────┬─────────────────────┤
│   crypto.js     │   storage.js    │     api.js      │    AuthContext.jsx  │
│                 │                 │                 │                     │
│ • generateKeys  │ • savePrivKey   │ • login()       │ • User state        │
│ • deriveShared  │ • getPrivKey    │ • register()    │ • Token management  │
│ • encryptMsg    │ • saveSessionKey│ • sendMessage() │ • Auth persistence  │
│ • decryptMsg    │ • getSessionKey │ • fetchUsers()  │                     │
│ • signData      │ • saveLogs      │ • uploadFile()  │                     │
│ • verifySign    │ • getLogs       │ • downloadFile()│                     │
└─────────────────┴─────────────────┴─────────────────┴─────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                              BACKEND COMPONENTS                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                                server.js                                     │
│                         (Express + Socket.io Setup)                          │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│     Routes      │          │   Controllers   │          │   Middleware    │
├─────────────────┤          ├─────────────────┤          ├─────────────────┤
│ • auth.js       │──────────│ authController  │          │ • auth.js       │
│ • messages.js   │──────────│ messageController│         │   (JWT verify)  │
│ • files.js      │──────────│ fileController  │          │ • socketAuth.js │
│ • keyexchange.js│──────────│ userController  │          │   (Socket auth) │
│ • users.js      │          │                 │          │                 │
└─────────────────┘          └─────────────────┘          └─────────────────┘
         │                            │
         ▼                            ▼
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│     Models      │          │     Sockets     │          │     Utils       │
├─────────────────┤          ├─────────────────┤          ├─────────────────┤
│ • User.js       │          │ • index.js      │          │ • logger.js     │
│ • Message.js    │          │   (Real-time    │          │   (Winston)     │
│ • FileChunk.js  │          │    messaging)   │          │ • totp.js       │
│ • KeyExchange.js│          │                 │          │   (2FA)         │
└─────────────────┘          └─────────────────┘          └─────────────────┘
```

### 1.3 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           MESSAGE FLOW (Sending)                             │
└─────────────────────────────────────────────────────────────────────────────┘

  User A                    Client A                  Server                Client B                  User B
    │                          │                        │                      │                        │
    │  Types message           │                        │                      │                        │
    │─────────────────────────►│                        │                      │                        │
    │                          │                        │                      │                        │
    │                   ┌──────┴──────┐                 │                      │                        │
    │                   │ 1. Get      │                 │                      │                        │
    │                   │ session key │                 │                      │                        │
    │                   │ from        │                 │                      │                        │
    │                   │ IndexedDB   │                 │                      │                        │
    │                   └──────┬──────┘                 │                      │                        │
    │                          │                        │                      │                        │
    │                   ┌──────┴──────┐                 │                      │                        │
    │                   │ 2. Generate │                 │                      │                        │
    │                   │ random IV   │                 │                      │                        │
    │                   │ (12 bytes)  │                 │                      │                        │
    │                   └──────┬──────┘                 │                      │                        │
    │                          │                        │                      │                        │
    │                   ┌──────┴──────┐                 │                      │                        │
    │                   │ 3. Encrypt  │                 │                      │                        │
    │                   │ AES-256-GCM │                 │                      │                        │
    │                   │ plaintext   │                 │                      │                        │
    │                   │ → ciphertext│                 │                      │                        │
    │                   └──────┬──────┘                 │                      │                        │
    │                          │                        │                      │                        │
    │                          │  4. Send encrypted     │                      │                        │
    │                          │  {ciphertext, iv, tag} │                      │                        │
    │                          │───────────────────────►│                      │                        │
    │                          │                        │                      │                        │
    │                          │                 ┌──────┴──────┐               │                        │
    │                          │                 │ 5. Validate │               │                        │
    │                          │                 │ - JWT token │               │                        │
    │                          │                 │ - Timestamp │               │                        │
    │                          │                 │ - Seq number│               │                        │
    │                          │                 └──────┬──────┘               │                        │
    │                          │                        │                      │                        │
    │                          │                 ┌──────┴──────┐               │                        │
    │                          │                 │ 6. Store    │               │                        │
    │                          │                 │ encrypted   │               │                        │
    │                          │                 │ in MongoDB  │               │                        │
    │                          │                 └──────┬──────┘               │                        │
    │                          │                        │                      │                        │
    │                          │                        │ 7. Relay via Socket  │                        │
    │                          │                        │─────────────────────►│                        │
    │                          │                        │                      │                        │
    │                          │                        │               ┌──────┴──────┐                 │
    │                          │                        │               │ 8. Decrypt  │                 │
    │                          │                        │               │ AES-256-GCM │                 │
    │                          │                        │               │ ciphertext  │                 │
    │                          │                        │               │ → plaintext │                 │
    │                          │                        │               └──────┬──────┘                 │
    │                          │                        │                      │                        │
    │                          │                        │                      │  Display message       │
    │                          │                        │                      │───────────────────────►│
    │                          │                        │                      │                        │
```

---

## 2. Key Exchange Protocol

### 2.1 ECDH Key Exchange with ECDSA Signatures

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    KEY EXCHANGE PROTOCOL DIAGRAM                             │
└─────────────────────────────────────────────────────────────────────────────┘

    Alice (Initiator)                 Server                    Bob (Responder)
         │                              │                              │
         │                              │                              │
    ┌────┴────┐                         │                              │
    │ Generate│                         │                              │
    │ephemeral│                         │                              │
    │ECDH pair│                         │                              │
    │(P-256)  │                         │                              │
    └────┬────┘                         │                              │
         │                              │                              │
    ┌────┴────┐                         │                              │
    │ Sign    │                         │                              │
    │ public  │                         │                              │
    │ key with│                         │                              │
    │ ECDSA   │                         │                              │
    └────┬────┘                         │                              │
         │                              │                              │
         │    1. KEY_EXCHANGE_INIT      │                              │
         │    {ephemeralPubKey,         │                              │
         │     signature,               │                              │
         │     signingPubKey}           │                              │
         │─────────────────────────────►│                              │
         │                              │                              │
         │                              │    2. Forward to Bob         │
         │                              │─────────────────────────────►│
         │                              │                              │
         │                              │                         ┌────┴────┐
         │                              │                         │ Verify  │
         │                              │                         │ Alice's │
         │                              │                         │signature│
         │                              │                         │ (ECDSA) │
         │                              │                         └────┬────┘
         │                              │                              │
         │                              │                         ┌────┴────┐
         │                              │                         │ Generate│
         │                              │                         │ephemeral│
         │                              │                         │ECDH pair│
         │                              │                         └────┬────┘
         │                              │                              │
         │                              │                         ┌────┴────┐
         │                              │                         │ ECDH    │
         │                              │                         │ Derive  │
         │                              │                         │ shared  │
         │                              │                         │ secret  │
         │                              │                         └────┬────┘
         │                              │                              │
         │                              │                         ┌────┴────┐
         │                              │                         │ Derive  │
         │                              │                         │ AES-256 │
         │                              │                         │ session │
         │                              │                         │ key     │
         │                              │                         └────┬────┘
         │                              │                              │
         │                              │    3. KEY_EXCHANGE_RESPONSE  │
         │                              │    {ephemeralPubKey,         │
         │                              │     signature}               │
         │                              │◄─────────────────────────────│
         │                              │                              │
         │    4. Forward to Alice       │                              │
         │◄─────────────────────────────│                              │
         │                              │                              │
    ┌────┴────┐                         │                              │
    │ Verify  │                         │                              │
    │ Bob's   │                         │                              │
    │signature│                         │                              │
    └────┬────┘                         │                              │
         │                              │                              │
    ┌────┴────┐                         │                              │
    │ ECDH    │                         │                              │
    │ Derive  │                         │                              │
    │ shared  │                         │                              │
    │ secret  │                         │                              │
    └────┬────┘                         │                              │
         │                              │                              │
    ┌────┴────┐                         │                              │
    │ Derive  │                         │                              │
    │ AES-256 │                         │                              │
    │ session │                         │                              │
    │ key     │                         │                              │
    └────┬────┘                         │                              │
         │                              │                              │
         │    5. KEY_CONFIRM            │                              │
         │    {confirmHash}             │                              │
         │─────────────────────────────►│─────────────────────────────►│
         │                              │                              │
         │                              │    6. KEY_CONFIRM            │
         │                              │    {confirmHash}             │
         │◄─────────────────────────────│◄─────────────────────────────│
         │                              │                              │
    ┌────┴────┐                         │                         ┌────┴────┐
    │ Verify  │                         │                         │ Verify  │
    │ confirm │                         │                         │ confirm │
    │ hash    │                         │                         │ hash    │
    └────┬────┘                         │                         └────┬────┘
         │                              │                              │
         │                              │                              │
    ═════╪══════════════════════════════╪══════════════════════════════╪═════
         │        SECURE CHANNEL ESTABLISHED                           │
         │        (AES-256-GCM with shared session key)                │
    ═════╪══════════════════════════════╪══════════════════════════════╪═════
         │                              │                              │
```

### 2.2 Key Derivation Process

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         KEY DERIVATION FUNCTION                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌───────────────────┐     ┌───────────────────┐
│  Alice's Private  │     │   Bob's Public    │
│  ECDH Key         │     │   ECDH Key        │
│  (P-256)          │     │   (P-256)         │
└─────────┬─────────┘     └─────────┬─────────┘
          │                         │
          └───────────┬─────────────┘
                      │
                      ▼
            ┌─────────────────┐
            │   ECDH Derive   │
            │   (P-256)       │
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  Shared Secret  │
            │  (32 bytes)     │
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │   HKDF-SHA256   │
            │   Key Derivation│
            │                 │
            │   Salt: fixed   │
            │   Info: context │
            └────────┬────────┘
                     │
                     ▼
            ┌─────────────────┐
            │  AES-256 Key    │
            │  (256 bits)     │
            │                 │
            │  Used for all   │
            │  message/file   │
            │  encryption     │
            └─────────────────┘
```

---

## 3. STRIDE Threat Modeling

### 3.1 STRIDE Analysis Table

| Threat Category | Threat Description | Asset Affected | Mitigation Implemented |
|----------------|-------------------|----------------|----------------------|
| **S**poofing | Attacker impersonates a user | User Identity | JWT authentication with secure tokens; TOTP-based 2FA; bcrypt password hashing (12 rounds) |
| **S**poofing | Attacker impersonates server | Server Trust | TLS/HTTPS for transport; Certificate validation |
| **T**ampering | Message modification in transit | Message Integrity | AES-256-GCM authentication tag (128-bit); ECDSA digital signatures on key exchange |
| **T**ampering | Database modification | Stored Data | Encrypted storage; Authentication required for all DB operations |
| **R**epudiation | User denies sending message | Audit Trail | Winston security logging; Timestamp recording; Sequence numbers |
| **I**nformation Disclosure | Eavesdropping on messages | Message Confidentiality | End-to-end AES-256-GCM encryption; Zero-knowledge server design |
| **I**nformation Disclosure | Key theft | Private Keys | IndexedDB browser storage (never transmitted); Session keys derived per conversation |
| **D**enial of Service | Server overload | Availability | Rate limiting (planned); Input validation |
| **E**levation of Privilege | Unauthorized access | User Accounts | JWT token verification; Role-based access control |

### 3.2 Threat Model Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           THREAT MODEL DIAGRAM                               │
└─────────────────────────────────────────────────────────────────────────────┘

                              TRUST BOUNDARY
    ┌─────────────────────────────┬─────────────────────────────┐
    │         UNTRUSTED           │          TRUSTED            │
    │                             │                             │
    │  ┌──────────────────┐       │    ┌──────────────────┐    │
    │  │    ATTACKER      │       │    │   CLIENT APP     │    │
    │  │                  │       │    │                  │    │
    │  │  ► Eavesdropper  │       │    │  ► Crypto.js     │    │
    │  │  ► MITM          │       │    │  ► Storage.js    │    │
    │  │  ► Replay        │       │    │  ► IndexedDB     │    │
    │  │                  │       │    │                  │    │
    │  └────────┬─────────┘       │    └────────┬─────────┘    │
    │           │                 │             │              │
    │           │ Attack Vectors  │             │ Protected    │
    │           │                 │             │ by E2EE      │
    │           ▼                 │             ▼              │
    │  ┌──────────────────────────┼─────────────────────────┐  │
    │  │                    NETWORK                         │  │
    │  │                                                    │  │
    │  │  Threats:                    Mitigations:          │  │
    │  │  • Packet sniffing           • TLS encryption      │  │
    │  │  • Traffic analysis          • E2EE (even if TLS   │  │
    │  │  • Connection hijack           is compromised)     │  │
    │  │                                                    │  │
    │  └────────────────────────────────────────────────────┘  │
    │                             │                            │
    └─────────────────────────────┼────────────────────────────┘
                                  │
                                  ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                            SERVER                                        │
    │                                                                         │
    │   Trust Level: SEMI-TRUSTED (Zero-Knowledge Design)                     │
    │                                                                         │
    │   ┌─────────────────────┐    ┌─────────────────────┐                   │
    │   │   What Server       │    │   What Server       │                   │
    │   │   CAN See:          │    │   CANNOT See:       │                   │
    │   │                     │    │                     │                   │
    │   │   • Encrypted blobs │    │   • Plaintext msgs  │                   │
    │   │   • Metadata        │    │   • Private keys    │                   │
    │   │   • User public keys│    │   • Session keys    │                   │
    │   │   • Timestamps      │    │   • File contents   │                   │
    │   │                     │    │                     │                   │
    │   └─────────────────────┘    └─────────────────────┘                   │
    │                                                                         │
    └─────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Attack Surface Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          ATTACK SURFACE                                      │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  ENTRY POINT          │  ATTACK TYPE           │  PROTECTION               │
├───────────────────────┼────────────────────────┼───────────────────────────┤
│  Login Form           │  Brute Force           │  Rate limiting, 2FA       │
│                       │  Credential Stuffing   │  bcrypt hashing           │
├───────────────────────┼────────────────────────┼───────────────────────────┤
│  WebSocket Connection │  Session Hijacking     │  JWT verification         │
│                       │  Unauthorized Access   │  Socket authentication    │
├───────────────────────┼────────────────────────┼───────────────────────────┤
│  REST API Endpoints   │  Injection Attacks     │  Input validation         │
│                       │  Unauthorized Access   │  JWT middleware           │
├───────────────────────┼────────────────────────┼───────────────────────────┤
│  Key Exchange         │  MITM Attack           │  ECDSA signatures         │
│                       │  Key Substitution      │  Public key verification  │
├───────────────────────┼────────────────────────┼───────────────────────────┤
│  Message Channel      │  Replay Attack         │  Timestamps, seq numbers  │
│                       │  Message Tampering     │  AES-GCM auth tags        │
├───────────────────────┼────────────────────────┼───────────────────────────┤
│  File Upload          │  Malicious Files       │  Encryption before upload │
│                       │  Data Exfiltration     │  Chunked encryption       │
└───────────────────────┴────────────────────────┴───────────────────────────┘
```

---

## 4. MITM Attack Demonstration

### 4.1 Overview

This section demonstrates how the system prevents Man-in-the-Middle attacks through digital signatures on key exchange.

### 4.2 Setup BurpSuite for Interception

#### Step 1: Configure BurpSuite Proxy

```
1. Open BurpSuite
2. Go to Proxy → Options
3. Add proxy listener:
   - Bind to port: 8080
   - Bind to address: 127.0.0.1
   
4. Configure browser proxy:
   - HTTP Proxy: 127.0.0.1:8080
   - HTTPS Proxy: 127.0.0.1:8080
   
5. Install BurpSuite CA certificate in browser
```

#### Step 2: Intercept Key Exchange

```
Target URL: http://localhost:5000/api/keyexchange

1. In BurpSuite, go to Proxy → Intercept
2. Turn intercept ON
3. Start a chat with a new user (triggers key exchange)
4. Capture the KEY_EXCHANGE_INIT request
```

### 4.3 Attack Scenario: DH Without Signatures (Would Fail)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│            MITM ATTACK ON UNSIGNED KEY EXCHANGE (Vulnerable)                 │
└─────────────────────────────────────────────────────────────────────────────┘

    Alice                      Attacker (Eve)                     Bob
      │                              │                              │
      │    DH Public Key (Ga)        │                              │
      │─────────────────────────────►│                              │
      │                              │                              │
      │                              │    DH Public Key (Ge1)       │
      │                              │─────────────────────────────►│
      │                              │                              │
      │                              │    DH Public Key (Gb)        │
      │                              │◄─────────────────────────────│
      │                              │                              │
      │    DH Public Key (Ge2)       │                              │
      │◄─────────────────────────────│                              │
      │                              │                              │
      │                              │                              │
   Key: Ga·e2                     Keys:                        Key: Ge1·b
   (Alice-Eve)                 Ga·e2 (with Alice)              (Eve-Bob)
                               Ge1·b (with Bob)
      │                              │                              │
      │    Encrypted Message         │                              │
      │─────────────────────────────►│                              │
      │                              │                              │
      │                        ┌─────┴─────┐                        │
      │                        │ Decrypt   │                        │
      │                        │ with Ga·e2│                        │
      │                        │ READ/MODIFY│                       │
      │                        │ Re-encrypt│                        │
      │                        │ with Ge1·b│                        │
      │                        └─────┬─────┘                        │
      │                              │                              │
      │                              │    Modified Message          │
      │                              │─────────────────────────────►│
      │                              │                              │

    ⚠️  WITHOUT SIGNATURES, ATTACKER CAN:
        • Read all messages
        • Modify messages in transit
        • Impersonate either party
```

### 4.4 Our System: Signed Key Exchange (Protected)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│            MITM ATTACK ON SIGNED KEY EXCHANGE (Protected)                    │
└─────────────────────────────────────────────────────────────────────────────┘

    Alice                      Attacker (Eve)                     Bob
      │                              │                              │
      │    DH Pub Key + Signature    │                              │
      │    (Signed with Alice's      │                              │
      │     ECDSA private key)       │                              │
      │─────────────────────────────►│                              │
      │                              │                              │
      │                              │    Forward OR Substitute?    │
      │                              │                              │
      │                              │                              │
      │                   ┌──────────┴──────────┐                   │
      │                   │                     │                   │
      │                   ▼                     ▼                   │
      │          Option A: Forward      Option B: Substitute        │
      │          (No modification)      (Eve's key + Eve's sig)     │
      │                   │                     │                   │
      │                   │                     │                   │
      │                   │                     ▼                   │
      │                   │           ┌─────────────────┐           │
      │                   │           │ Bob verifies    │           │
      │                   │           │ signature using │           │
      │                   │           │ Alice's PUBLIC  │           │
      │                   │           │ signing key     │           │
      │                   │           │                 │           │
      │                   │           │ ❌ SIGNATURE    │           │
      │                   │           │    MISMATCH!    │           │
      │                   │           │                 │           │
      │                   │           │ Connection      │           │
      │                   │           │ REJECTED        │           │
      │                   │           └─────────────────┘           │
      │                   │                                         │
      │                   ▼                                         │
      │          ┌─────────────────┐                                │
      │          │ If forwarded    │                                │
      │          │ unmodified,     │                                │
      │          │ Eve cannot      │                                │
      │          │ derive the      │                                │
      │          │ session key!    │                                │
      │          └─────────────────┘                                │
      │                                                             │
      
    ✅  WITH SIGNATURES, ATTACKER CANNOT:
        • Substitute their own key (signature verification fails)
        • Derive the session key (doesn't have private keys)
        • Read or modify messages (encrypted with unknown key)
```

### 4.5 BurpSuite Demonstration Steps

```markdown
## MITM Attack Demo with BurpSuite

### Prerequisites
- BurpSuite Community/Pro installed
- System running on localhost

### Step-by-Step Demo

1. **Setup Interception**
   - Configure browser to use BurpSuite proxy (127.0.0.1:8080)
   - Enable intercept in BurpSuite

2. **Capture Key Exchange**
   - Login as User A in one browser
   - Login as User B in another browser (through proxy)
   - User A clicks on User B to start chat
   - Capture the POST to /api/keyexchange/initiate

3. **Examine the Request**
   ```json
   {
     "toUserId": "user_b_id",
     "ephemeralPublicKey": "BASE64_ENCODED_KEY",
     "signature": "BASE64_ENCODED_SIGNATURE",
     "signingPublicKey": "BASE64_ENCODED_SIGNING_KEY"
   }
   ```

4. **Attempt Key Substitution**
   - Generate your own ECDH keypair
   - Replace ephemeralPublicKey with your key
   - Forward the modified request

5. **Observe the Result**
   - Bob's client will verify the signature
   - Signature verification FAILS because:
     - The signature was made with Alice's private signing key
     - The signature is over Alice's original public key
     - Modified key doesn't match the signature
   - Key exchange is REJECTED

6. **Check Security Logs**
   - Open Security Logs panel in the app
   - See "Signature verification failed" error
   - Key exchange does not complete

### Evidence to Capture
- Screenshot of BurpSuite showing intercepted request
- Screenshot of modified request
- Screenshot of error in browser console
- Screenshot of security logs showing rejection
```

---

## 5. Replay Attack Demonstration

### 5.1 Overview

This section demonstrates how the system detects and prevents replay attacks using timestamps and sequence numbers.

### 5.2 How Replay Protection Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      REPLAY ATTACK PROTECTION                                │
└─────────────────────────────────────────────────────────────────────────────┘

  Original Message Flow:
  
    Alice                         Server                          Bob
      │                              │                              │
      │   Message #1                 │                              │
      │   {                          │                              │
      │     ciphertext: "...",       │                              │
      │     iv: "random_iv_1",       │                              │
      │     timestamp: 1701619200,   │                              │
      │     sequenceNumber: 1        │                              │
      │   }                          │                              │
      │─────────────────────────────►│                              │
      │                              │                              │
      │                       ┌──────┴──────┐                       │
      │                       │ Validate:   │                       │
      │                       │ • Timestamp │                       │
      │                       │   within 5  │                       │
      │                       │   minutes   │                       │
      │                       │ • SeqNum    │                       │
      │                       │   > last    │                       │
      │                       │   seen      │                       │
      │                       │             │                       │
      │                       │ Store:      │                       │
      │                       │ lastSeqNum=1│                       │
      │                       └──────┬──────┘                       │
      │                              │                              │
      │                              │─────────────────────────────►│
      │                              │                              │
```

### 5.3 Replay Attack Attempt

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      REPLAY ATTACK DETECTION                                 │
└─────────────────────────────────────────────────────────────────────────────┘

  Attack Scenario: Attacker captures and replays a message

    Attacker                      Server                         
      │                              │                            
      │   Replayed Message #1        │                            
      │   {                          │                            
      │     ciphertext: "...",       │  (Same as original)        
      │     iv: "random_iv_1",       │                            
      │     timestamp: 1701619200,   │  (Old timestamp)           
      │     sequenceNumber: 1        │  (Already seen)            
      │   }                          │                            
      │─────────────────────────────►│                            
      │                              │                            
      │                       ┌──────┴──────┐                     
      │                       │ Check #1:   │                     
      │                       │ Timestamp   │                     
      │                       │             │                     
      │                       │ Current:    │                     
      │                       │ 1701620000  │                     
      │                       │             │                     
      │                       │ Message:    │                     
      │                       │ 1701619200  │                     
      │                       │             │                     
      │                       │ Diff: 800s  │                     
      │                       │ > 300s max  │                     
      │                       │             │                     
      │                       │ ❌ REJECTED │                     
      │                       │ "Timestamp  │                     
      │                       │  expired"   │                     
      │                       └──────┬──────┘                     
      │                              │                            
      │   OR (if within time window) │                            
      │                              │                            
      │                       ┌──────┴──────┐                     
      │                       │ Check #2:   │                     
      │                       │ SeqNumber   │                     
      │                       │             │                     
      │                       │ Last: 5     │                     
      │                       │ This: 1     │                     
      │                       │             │                     
      │                       │ 1 <= 5      │                     
      │                       │             │                     
      │                       │ ❌ REJECTED │                     
      │                       │ "Duplicate  │                     
      │                       │  or old     │                     
      │                       │  sequence"  │                     
      │                       └─────────────┘                     
      │                                                           
```

### 5.4 Demonstration Steps

```markdown
## Replay Attack Demo Steps

### Method 1: Using Browser DevTools

1. **Capture Original Message**
   - Open browser DevTools (F12)
   - Go to Network tab
   - Send a message to another user
   - Find the POST request to /api/messages
   - Right-click → Copy → Copy as cURL

2. **Wait and Replay**
   - Wait 5+ minutes (timestamp expiry)
   - Open terminal
   - Paste and execute the cURL command
   
3. **Observe Rejection**
   ```bash
   # Response will show:
   {
     "error": "Message timestamp expired - possible replay attack"
   }
   ```

### Method 2: Using Postman/Insomnia

1. **Capture Request**
   - Use proxy to capture message request
   - Save the full request including:
     - Headers (Authorization)
     - Body (ciphertext, iv, timestamp, seqNum)

2. **Replay Immediately**
   - Send the same request again
   - Should fail with: "Duplicate sequence number"

3. **Modify and Replay**
   - Change timestamp to current time
   - Send again
   - Should fail with: "Invalid sequence number"

### Method 3: Check Server Logs

After replay attempt, check logs:

```bash
# In server directory
Get-Content logs/combined.log -Tail 20
```

Expected log entries:
```
[SECURITY] Replay attack detected - expired timestamp
[SECURITY] Replay attack detected - duplicate sequence number
```

### Evidence to Capture
1. Screenshot of original message in Network tab
2. Screenshot of replay attempt in terminal/Postman
3. Screenshot of error response
4. Screenshot of server logs showing detection
```

---

## 6. Wireshark Packet Capture Guide

### 6.1 Setup Wireshark

```markdown
## Wireshark Capture Setup

### Prerequisites
- Wireshark installed
- Run as Administrator (Windows) or root (Linux)

### Capture Filter
Use this filter to capture only relevant traffic:

```
tcp port 5000 or tcp port 5173
```

### Display Filter (after capture)
```
http or websocket
```
```

### 6.2 What to Capture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      WIRESHARK CAPTURE POINTS                                │
└─────────────────────────────────────────────────────────────────────────────┘

Capture Point 1: WebSocket Messages
───────────────────────────────────

Filter: websocket

You will see:
┌─────────────────────────────────────────────────────────────────────────────┐
│ No. │ Time     │ Source        │ Destination   │ Protocol  │ Info          │
├─────┼──────────┼───────────────┼───────────────┼───────────┼───────────────┤
│ 1   │ 0.000    │ 127.0.0.1     │ 127.0.0.1     │ WebSocket │ Text [FIN]    │
│ 2   │ 0.015    │ 127.0.0.1     │ 127.0.0.1     │ WebSocket │ Text [FIN]    │
└─────────────────────────────────────────────────────────────────────────────┘

Payload content (ENCRYPTED):
{
  "ciphertext": "A7Kx8mN2pQ4R5tU6...",  ← Base64 encoded ciphertext
  "iv": "3F5H7J9L2M4N6P8R",              ← Initialization vector
  "authTag": "Z9Y8X7W6V5U4T3S2R1Q0"      ← Authentication tag
}

⚠️ NOTE: Actual message content is NOT visible - only encrypted blobs!


Capture Point 2: Key Exchange
─────────────────────────────

Filter: http.request.uri contains "keyexchange"

You will see:
┌─────────────────────────────────────────────────────────────────────────────┐
│ POST /api/keyexchange/initiate HTTP/1.1                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ {                                                                           │
│   "toUserId": "6574a8b2c1d2e3f4a5b6c7d8",                                  │
│   "ephemeralPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",         │
│   "signature": "MEYCIQDvB5N8xK7L9mP2qR4sT6uW8xY0zA2bC4dE6fG...",           │
│   "signingPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE..."            │
│ }                                                                           │
└─────────────────────────────────────────────────────────────────────────────┘

⚠️ NOTE: Only PUBLIC keys are transmitted - private keys never leave client!


Capture Point 3: Authentication
───────────────────────────────

Filter: http.request.uri contains "auth"

Login Request:
┌─────────────────────────────────────────────────────────────────────────────┐
│ POST /api/auth/login HTTP/1.1                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ {                                                                           │
│   "username": "alice",                                                      │
│   "password": "********"      ← Transmitted (should use HTTPS in prod)     │
│ }                                                                           │
└─────────────────────────────────────────────────────────────────────────────┘

Login Response:
┌─────────────────────────────────────────────────────────────────────────────┐
│ {                                                                           │
│   "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",                      │
│   "user": { "id": "...", "username": "alice" }                             │
│ }                                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.3 Screenshot Guide

```markdown
## Required Wireshark Screenshots

### Screenshot 1: WebSocket Traffic Overview
- Show multiple WebSocket frames
- Highlight encrypted payload
- Circle the ciphertext field showing it's not readable

### Screenshot 2: Message Payload Detail
- Right-click a WebSocket frame → Follow → TCP Stream
- Show the JSON payload with encrypted content
- Add annotation: "Message content encrypted - server cannot read"

### Screenshot 3: Key Exchange Capture
- Filter: http contains "keyexchange"
- Show the request/response
- Highlight: "Only public keys transmitted"

### Screenshot 4: Comparison - Before/After Encryption
- Create a side-by-side showing:
  - Left: What user typed ("Hello, how are you?")
  - Right: What appears in Wireshark (encrypted blob)

### Screenshot 5: Full Conversation Flow
- Show timeline of:
  1. Login request
  2. Key exchange init
  3. Key exchange response
  4. Encrypted messages
```

### 6.4 Sample Annotations for Report

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SAMPLE WIRESHARK ANNOTATION                               │
└─────────────────────────────────────────────────────────────────────────────┘

[Wireshark Screenshot Here]

Annotations to add:

┌─ Red Box ────────────────────────────────────────────────────────┐
│  "Encrypted Payload - Even with network capture,                 │
│   message content remains confidential"                          │
└──────────────────────────────────────────────────────────────────┘

┌─ Green Box ──────────────────────────────────────────────────────┐
│  "AES-256-GCM with 12-byte IV provides                          │
│   both confidentiality and integrity"                            │
└──────────────────────────────────────────────────────────────────┘

┌─ Blue Arrow ─────────────────────────────────────────────────────┐
│  "This is what an eavesdropper sees:                            │
│   Meaningless encrypted data"                                    │
└──────────────────────────────────────────────────────────────────┘
```

---

## 7. Security Controls Summary

### 7.1 Security Controls Matrix

| Control Category | Control | Implementation | Verification Method |
|-----------------|---------|----------------|-------------------|
| **Confidentiality** | End-to-End Encryption | AES-256-GCM | Wireshark capture shows encrypted data |
| **Confidentiality** | Zero-Knowledge Server | Encryption/decryption client-side only | Server logs contain no plaintext |
| **Integrity** | Message Authentication | GCM authentication tag | Tamper with ciphertext → decryption fails |
| **Integrity** | Digital Signatures | ECDSA on key exchange | MITM demo shows signature verification |
| **Authentication** | User Authentication | JWT + bcrypt | Invalid credentials rejected |
| **Authentication** | Two-Factor Auth | TOTP (RFC 6238) | Login requires valid 6-digit code |
| **Non-Repudiation** | Security Logging | Winston logger | Audit trail in server logs |
| **Non-Repudiation** | Sequence Numbers | Per-conversation counter | Replay attack detection |
| **Availability** | Connection Management | Socket.io reconnection | Client auto-reconnects |

### 7.2 Cryptographic Algorithms Used

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CRYPTOGRAPHIC ALGORITHMS                                  │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  Purpose              │  Algorithm         │  Key Size    │  Standard      │
├───────────────────────┼────────────────────┼──────────────┼────────────────┤
│  Symmetric Encryption │  AES-GCM           │  256 bits    │  NIST SP 800-38D│
│  Key Exchange         │  ECDH              │  P-256       │  NIST FIPS 186-4│
│  Digital Signatures   │  ECDSA             │  P-256       │  NIST FIPS 186-4│
│  Password Hashing     │  bcrypt            │  12 rounds   │  OpenBSD        │
│  Key Derivation       │  HKDF-SHA256       │  256 bits    │  RFC 5869       │
│  2FA                  │  TOTP-SHA1         │  160 bits    │  RFC 6238       │
│  Random Generation    │  crypto.getRandomValues │  -      │  Web Crypto API │
└───────────────────────┴────────────────────┴──────────────┴────────────────┘
```

---

## Appendix A: Quick Reference Commands

```bash
# Start Wireshark capture
wireshark -i lo -f "tcp port 5000"

# Check server logs for security events
Get-Content logs/combined.log -Tail 50 | Select-String "SECURITY"

# View all key exchange logs
Get-Content logs/combined.log | Select-String "keyexchange"

# Monitor logs in real-time
Get-Content logs/combined.log -Wait -Tail 10
```

## Appendix B: Report Checklist

- [ ] System architecture diagram included
- [ ] Key exchange protocol diagram included
- [ ] STRIDE threat model table completed
- [ ] MITM attack demo screenshots (BurpSuite)
- [ ] Replay attack demo screenshots
- [ ] Wireshark packet captures (3-5 screenshots)
- [ ] Security controls matrix included
- [ ] Cryptographic algorithms table included

---

**Document Version**: 1.0  
**Last Updated**: December 2024  
**Authors**: Muhammad Ahmad (22i-2711), Usaid Afzal (22i-8783)
