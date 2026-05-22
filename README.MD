# Video Steganography with AES Encryption

A Python desktop application that securely hides encrypted secret messages inside video files and extracts them using a password.

## Features

- AES-256 Encryption
- Password Protected Message Extraction
- Video-Based Steganography
- Modern Tkinter GUI
- Message Embedding and Extraction
- Progress Tracking
- Multi-Threaded Processing
- Error Handling and Validation

## Technologies Used

- Python
- Tkinter
- Cryptography
- OpenCV
- NumPy

## Project Structure

```
video-steganography-aes-python/
│
├── video_stego.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
└── screenshots/
```

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/video-steganography-aes-python.git
```

Move into the project folder:

```bash
cd video-steganography-aes-python
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run Application

```bash
python video_stego.py
```

## How to Use

### Embed Message

1. Open the application
2. Select a video file
3. Enter the secret message
4. Enter an encryption password
5. Click **Embed & Export Video**
6. Save the generated video

### Extract Message

1. Open the encoded video
2. Enter the correct password
3. Click **Extract & Decrypt Message**
4. View the hidden message

## Security

The application uses:

- AES Encryption
- SHA-256 Key Derivation
- Password-Based Message Protection

Without the correct password, the hidden message cannot be decrypted.

## Screenshots

Add screenshots of:

- Main Window
- Embed Message Screen
- Extract Message Screen

inside the `screenshots` folder.

## Author

Mohammed Suhail

## License

This project is licensed under the MIT License.