#!/usr/bin/env python3
"""
SecureBox WebUI — Password Setup Helper
Run this to generate your WEBUI_PASSWORD_HASH for the .env file.

Usage:
    python3 gen_password.py
"""
import hashlib
import getpass

print("=" * 50)
print("  SecureBox WebUI — Password Setup")
print("=" * 50)
print()
pw = getpass.getpass("Enter a password for the WebUI: ")
pw2 = getpass.getpass("Confirm password: ")

if pw != pw2:
    print("\n❌ Passwords don't match. Try again.")
    exit(1)

if len(pw) < 6:
    print("\n⚠️  Warning: Password is very short.")

hash_val = hashlib.sha256(pw.encode()).hexdigest()

print()
print("✅ Add this line to your .env file:")
print()
print(f"WEBUI_PASSWORD_HASH={hash_val}")
print()
print("Then restart the bot / webui server.")
