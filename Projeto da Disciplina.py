# Alunos: Jose Vitor Santos Rocha, Gabriel Martins Rodrigues, Daniel Rodrigues Chaves. 
# Importing necessary libraries
from PIL import Image # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, padding # type: ignore
from cryptography.hazmat.primitives import serialization, hashes # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # type: ignore
import hashlib
import os

# --- Utility Functions ---

def embed_text(image_path, text, output_path="stego_image.png"):
    """Embed text into an image using LSB steganography."""
    img = Image.open(image_path)
    binary_text = ''.join([format(ord(i), '08b') for i in text]) + '1111111111111110'  # EOF marker
    pixels = img.load()
    width, height = img.size
    
    data_idx = 0
    for y in range(height):
        for x in range(width):
            if data_idx < len(binary_text):
                r, g, b = pixels[x, y]
                new_r = (r & ~1) | int(binary_text[data_idx])
                pixels[x, y] = (new_r, g, b)
                data_idx += 1
            else:
                break

    img.save(output_path)
    print(f"Text embedded in image saved as {output_path}")
    return output_path

def recover_text(stego_image_path):
    """Recover text from an image using LSB steganography."""
    img = Image.open(stego_image_path)
    binary_text = ""
    pixels = img.load()
    width, height = img.size
    
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_text += str(r & 1)
            if binary_text[-16:] == '1111111111111110':  # EOF marker
                binary_text = binary_text[:-16]  # Remove EOF marker
                break

    text = ''.join([chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text), 8)])
    return text

def generate_hash(image_path):
    """Generate SHA-256 hash of an image."""
    with open(image_path, "rb") as f:
        image_data = f.read()
    return hashlib.sha256(image_data).hexdigest()

def encrypt_message(public_key, message):
    """Encrypt message using the public key."""
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_message

def decrypt_message(private_key, encrypted_message):
    """Decrypt message using the private key."""
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_message.decode()

def generate_keys():
    """Generate RSA public and private keys."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# --- Main Application ---

def main():
    print("Welcome to the Steganography and Cryptography Application!")
    private_key, public_key = generate_keys()
    encrypted_text = None

    while True:
        print("\nOptions Menu:")
        print("(1) Embed text in an image using Steganography")
        print("(2) Recover text from an image altered by Steganography")
        print("(3) Generate hash of the original and altered images")
        print("(4) Encrypt a message using public and private key cryptography")
        print("(5) Decrypt a message from an altered image using cryptography")
        print("(S) Exit")
        
        choice = input("Choose an option: ").strip().lower()
        
        if choice == "1":
            image_path = input("Enter the path of the image: ").strip()
            text = input("Enter the text to embed: ").strip()
            output_path = input("Enter output path for the stego image (default: stego_image.png): ").strip() or "stego_image.png"
            embed_text(image_path, text, output_path)
        
        elif choice == "2":
            stego_image_path = input("Enter the path of the stego image: ").strip()
            recovered_text = recover_text(stego_image_path)
            print(f"Recovered text: {recovered_text}")
        
        elif choice == "3":
            original_image_path = input("Enter the path of the original image: ").strip()
            stego_image_path = input("Enter the path of the stego image: ").strip()
            original_hash = generate_hash(original_image_path)
            stego_hash = generate_hash(stego_image_path)
            print(f"Original image hash: {original_hash}")
            print(f"Stego image hash: {stego_hash}")
        
        elif choice == "4":
            message = input("Enter the message to encrypt: ").strip()
            encrypted_text = encrypt_message(public_key, message)
            print("Message encrypted successfully!")
        
        elif choice == "5":
            if encrypted_text is not None:
                decrypted_message = decrypt_message(private_key, encrypted_text)
                print(f"Decrypted message: {decrypted_message}")
            else:
                print("No encrypted message found. Use option (4) to encrypt a message first.")
        
        elif choice == "s":
            print("Exiting the application.")
            break
        
        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()
