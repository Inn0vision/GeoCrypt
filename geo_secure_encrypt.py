#!/usr/bin/env python3
"""
GeoSecureEncrypt - Terminal-based Geo-location AES Encryption Tool
A cybersecurity prototype demonstrating location-based encryption using AES-GCM
with SHA-256 key derivation.

Author: Cybersecurity Student
Purpose: Educational demonstration for college project
"""

import hashlib
import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class GeoSecureEncrypt:
    """
    A geo-location based encryption tool that derives AES keys from 
    password and GPS coordinates using SHA-256 hashing.
    """
    
    def __init__(self):
        self.debug = True  # Always show debug info for educational purposes
    
    def print_debug(self, message):
        """Print debug information with formatting"""
        if self.debug:
            print(f"[DEBUG] {message}")
    
    def print_separator(self):
        """Print a separator line for better readability"""
        print("=" * 60)
    
    def canonicalize_coordinates(self, latitude, longitude):
        """
        Canonicalize GPS coordinates to 5 decimal places for consistency.
        This ensures that small GPS variations don't break decryption.
        
        Args:
            latitude (float): GPS latitude
            longitude (float): GPS longitude
            
        Returns:
            tuple: (canonical_lat, canonical_lon) as strings
        """
        canon_lat = f"{float(latitude):.5f}"
        canon_lon = f"{float(longitude):.5f}"
        return canon_lat, canon_lon
    
    def derive_key(self, password, latitude, longitude):
        """
        Derive AES-256 key from password and GPS coordinates using SHA-256.
        
        Key derivation process:
        1. Canonicalize coordinates to 5 decimal places
        2. Create string: password|lat|lon
        3. Compute SHA-256 hash
        4. Use 32-byte hash as AES key
        
        Args:
            password (str): User password
            latitude (float): GPS latitude
            longitude (float): GPS longitude
            
        Returns:
            bytes: 32-byte AES key
        """
        self.print_separator()
        self.print_debug("KEY DERIVATION PROCESS")
        
        # Canonicalize coordinates
        canon_lat, canon_lon = self.canonicalize_coordinates(latitude, longitude)
        
        # Create input string for hashing
        input_string = f"{password}|{canon_lat}|{canon_lon}"
        
        # Compute SHA-256 hash
        sha256_hash = hashlib.sha256(input_string.encode('utf-8')).digest()
        
        # Debug output
        self.print_debug(f"Password: '{password}'")
        self.print_debug(f"Location: ({canon_lat}, {canon_lon})")
        self.print_debug(f"Concatenated string: '{input_string}'")
        self.print_debug(f"SHA-256 hash (hex): {sha256_hash.hex()}")
        self.print_debug(f"AES key (hex): {sha256_hash.hex()}")
        
        return sha256_hash
    
    def encrypt_message(self, plaintext, password, latitude, longitude):
        """
        Encrypt a message using AES-GCM with geo-location derived key.
        
        Args:
            plaintext (str): Message to encrypt
            password (str): User password
            latitude (float): GPS latitude
            longitude (float): GPS longitude
            
        Returns:
            str: Base64 encoded ciphertext (nonce + tag + ciphertext)
        """
        self.print_separator()
        self.print_debug("ENCRYPTION PROCESS")
        
        # Derive encryption key
        key = self.derive_key(password, latitude, longitude)
        
        # Generate random nonce (12 bytes for GCM)
        nonce = get_random_bytes(12)
        
        # Create AES-GCM cipher
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # Encrypt the message
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        
        # Combine nonce + tag + ciphertext for storage
        encrypted_data = nonce + tag + ciphertext
        
        # Encode as Base64 for easy transmission/storage
        base64_result = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Debug output
        self.print_debug(f"Plaintext: '{plaintext}'")
        self.print_debug(f"Nonce (hex): {nonce.hex()}")
        self.print_debug(f"Ciphertext (hex): {ciphertext.hex()}")
        self.print_debug(f"Authentication tag (hex): {tag.hex()}")
        self.print_debug(f"Combined data (hex): {encrypted_data.hex()}")
        self.print_debug(f"Base64 encoded result: {base64_result}")
        
        return base64_result
    
    def decrypt_message(self, base64_ciphertext, password, latitude, longitude):
        """
        Decrypt a message using AES-GCM with geo-location derived key.
        
        Args:
            base64_ciphertext (str): Base64 encoded encrypted data
            password (str): User password
            latitude (float): GPS latitude
            longitude (float): GPS longitude
            
        Returns:
            str: Decrypted plaintext message or None if decryption fails
        """
        try:
            self.print_separator()
            self.print_debug("DECRYPTION PROCESS")
            
            # Derive decryption key
            key = self.derive_key(password, latitude, longitude)
            
            # Decode from Base64
            encrypted_data = base64.b64decode(base64_ciphertext.encode('utf-8'))
            
            # Extract components (nonce: 12 bytes, tag: 16 bytes, rest: ciphertext)
            nonce = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            # Debug output
            self.print_debug(f"Base64 input: {base64_ciphertext}")
            self.print_debug(f"Encrypted data (hex): {encrypted_data.hex()}")
            self.print_debug(f"Extracted nonce (hex): {nonce.hex()}")
            self.print_debug(f"Extracted tag (hex): {tag.hex()}")
            self.print_debug(f"Extracted ciphertext (hex): {ciphertext.hex()}")
            
            # Create AES-GCM cipher for decryption
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt and verify
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            decrypted_message = plaintext.decode('utf-8')
            self.print_debug(f"Decrypted plaintext: '{decrypted_message}'")
            
            return decrypted_message
            
        except Exception as e:
            self.print_debug(f"Decryption failed: {str(e)}")
            return None


def main():
    """Main interactive menu for the GeoSecureEncrypt tool"""
    
    # Create encryption tool instance
    geo_encrypt = GeoSecureEncrypt()
    
    # Print welcome banner
    print("=" * 60)
    print("    GeoSecureEncrypt - Location-Based AES Encryption Tool")
    print("=" * 60)
    print("Educational cybersecurity prototype for college project")
    print("Demonstrates geo-location based encryption using AES-GCM")
    print("=" * 60)
    
    while True:
        # Display menu
        print("\nChoose an operation:")
        print("[1] Encrypt a message")
        print("[2] Decrypt a message")
        print("[3] Run demo example")
        print("[4] Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == '1':
            # Encryption mode
            print("\n--- ENCRYPTION MODE ---")
            
            try:
                # Get inputs
                message = input("Enter secret message to encrypt: ")
                password = input("Enter password: ")
                latitude = float(input("Enter latitude (e.g., 37.12345): "))
                longitude = float(input("Enter longitude (e.g., -122.67890): "))
                
                # Encrypt
                ciphertext = geo_encrypt.encrypt_message(message, password, latitude, longitude)
                
                print(f"\n✓ ENCRYPTION SUCCESSFUL!")
                print(f"Encrypted message (Base64): {ciphertext}")
                
            except ValueError:
                print("❌ Error: Invalid latitude/longitude format. Please use decimal numbers.")
            except Exception as e:
                print(f"❌ Encryption error: {str(e)}")
        
        elif choice == '2':
            # Decryption mode
            print("\n--- DECRYPTION MODE ---")
            
            try:
                # Get inputs
                ciphertext = input("Enter Base64 ciphertext to decrypt: ")
                password = input("Enter password: ")
                latitude = float(input("Enter latitude: "))
                longitude = float(input("Enter longitude: "))
                
                # Decrypt
                plaintext = geo_encrypt.decrypt_message(ciphertext, password, latitude, longitude)
                
                if plaintext:
                    print(f"\n✓ DECRYPTION SUCCESSFUL!")
                    print(f"Decrypted message: '{plaintext}'")
                else:
                    print(f"\n❌ DECRYPTION FAILED!")
                    print("Wrong password or location coordinates.")
                    
            except ValueError:
                print("❌ Error: Invalid latitude/longitude format. Please use decimal numbers.")
            except Exception as e:
                print(f"❌ Decryption error: {str(e)}")
        
        elif choice == '3':
            # Demo mode
            print("\n--- DEMO EXAMPLE ---")
            print("Demonstrating complete encryption/decryption cycle")
            
            # Demo parameters
            demo_message = "Secret meeting at midnight!"
            demo_password = "MySecretKey123"
            demo_lat = 37.12345
            demo_lon = -122.67890
            
            print(f"\nDemo parameters:")
            print(f"Message: '{demo_message}'")
            print(f"Password: '{demo_password}'")
            print(f"Location: ({demo_lat}, {demo_lon})")
            
            # Encrypt
            print("\n🔒 ENCRYPTING...")
            ciphertext = geo_encrypt.encrypt_message(demo_message, demo_password, demo_lat, demo_lon)
            print(f"\nEncrypted: {ciphertext}")
            
            # Decrypt with correct credentials
            print("\n🔓 DECRYPTING WITH CORRECT CREDENTIALS...")
            plaintext = geo_encrypt.decrypt_message(ciphertext, demo_password, demo_lat, demo_lon)
            print(f"\nResult: '{plaintext}'")
            
            # Try to decrypt with wrong location
            print("\n🔓 TRYING DECRYPTION WITH WRONG LOCATION...")
            wrong_plaintext = geo_encrypt.decrypt_message(ciphertext, demo_password, 40.0, -120.0)
            if wrong_plaintext:
                print(f"Result: '{wrong_plaintext}'")
            else:
                print("❌ Decryption failed with wrong location!")
        
        elif choice == '4':
            # Exit
            print("\nThank you for using GeoSecureEncrypt!")
            print("Stay secure! 🔐")
            break
        
        else:
            print("❌ Invalid choice. Please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()