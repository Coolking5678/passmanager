# Vault – Local Password Manager

A lightweight, secure desktop password manager built with CustomTkinter.
All credentials are **encrypted locally** — nothing ever leaves your machine.

---

## Features

- **Master Password** protected vault using bcrypt hashing
- **AES-based encryption** (Fernet / PBKDF2HMAC) for all stored passwords
- **Password strength indicator** with real-time feedback
- **Secure password generator** using Python's secrets module
- **One-click copy** to clipboard with auto-clear visual feedback
- **Search** credentials by website or username
- **Lock vault** to return to the login screen without restarting

---

## Quick Setup

### 1. Create a virtual environment (recommended)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install dependencies
```powershell
pip install -r requirements.txt
```

### 3. Run the app
```powershell
python main.py
```

---

## First Run
On the **first launch** the app will ask you to create a Master Password.
- Choose something strong (8+ chars, mixed case, numbers, special chars).
- **This password cannot be recovered if forgotten** — it is never stored in plaintext.

---

## Project Structure

```
passmanager/
 src/
   crypto_utils.py   # bcrypt hashing + Fernet encryption
   database.py       # SQLite CRUD (vault.db created automatically)
   password_logic.py # Strength checker + password generator
 gui/
   app_ui.py         # CustomTkinter UI (Login + Vault screens)
 main.py             # Entry point
 requirements.txt
```

---

## Security Notes

| Aspect | Implementation |
|--------|---------------|
| Master password storage | bcrypt (cost factor 12, random salt) |
| Vault key derivation | PBKDF2HMAC-SHA256, 480 000 iterations |
| Credential encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Password generation | secrets.choice() — cryptographically random |
| Database | Local SQLite (ault.db) — never transmitted |

> **Warning**: Keep ault.db and your master password safe.
> Losing the master password means the encrypted data is unrecoverable.
