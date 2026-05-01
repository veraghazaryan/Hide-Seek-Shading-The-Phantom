# Hide&Seek: Shading the Phantom

## Overview
Hide&Seek: Shading the Phantom is a steganography application developed in C# using Windows Forms. The purpose of the project is to securely hide secret messages inside image files by combining compression, encryption, and data hiding techniques.

The system is designed both as a learning project and as a practical tool for protecting private information.

## Features
- Hide secret messages inside images (PNG, JPG, BMP)
- AES-256-GCM encryption for data security
- PBKDF2 key derivation with salt
- GZip compression to reduce message size
- Hamming(7,4) error correction for reliability
- Entropy-based pixel selection for better hiding
- Password-dependent embedding positions
- Dual-layer system (real message + decoy message)

## How It Works
The encoding process follows several steps:

1. The message is compressed using GZip  
2. The compressed data is encrypted using AES-256-GCM  
3. A secure key is generated from the password using PBKDF2  
4. Hamming(7,4) error correction is applied  
5. The data is embedded into high-entropy regions of the image using least significant bits  

For dual-layer mode:
- The main message is stored in bit-0  
- The second message is stored in bit-1  
- Unused bit-1 space is filled with random noise  

## How to Use

### Encoding (Hide Message)
1. Load an image  
2. Enter a message and password  
3. (Optional) Enable dual-layer and enter a second message  
4. Click **Execute Shielding**  
5. Save the output image as PNG  

### Decoding (Reveal Message)
1. Open the encoded PNG image  
2. Enter the password  
3. Click **Reveal Data**  
4. The hidden message will be displayed  

## Technologies Used
- C#
- Windows Forms
- System.Security.Cryptography (AES, PBKDF2)
- System.IO.Compression (GZip)
- System.Drawing (image processing)

## Notes
- The output image must be saved as PNG (lossless format)  
- Recompressing the image (e.g. via messaging apps) may destroy hidden data  
- If the password is incorrect, the message will not be revealed  

## Project Purpose
This project demonstrates how concepts from Information Theory and object-oriented programming can be combined into a real application. It focuses on secure data handling, reliability, and practical implementation.

---
