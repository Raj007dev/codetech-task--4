NAME:  RAJKUMAR ATTRI
COMPANY: CODTECH IT SOLUTIONS
ID: CT04DR203
DOMAIN: CYBER SECURITY AND ETHICAL HACKING 
DURATION: OCTOBER TO NOVEMBER 2025
MENTOR: NEELA SANTOSH KUMAR



Advanced Encryption Tool Code Overview
​This application is a single-file, client-side web utility designed for secure text encryption and decryption using the AES-256 algorithm. The code is entirely contained within an index.html file, leveraging external libraries for styling and cryptography.
Core Cryptography Logic (AES-256)
​The primary security functions are encryptData and decryptData, which rely on the crypto-js library.
​Key Derivation
​The application uses a password-based key derivation function (KDF), which is handled implicitly by CryptoJS.AES.encrypt() when a string password is provided. This mechanism, similar to OpenSSL's EVP_BytesToKey, salts the password before deriving a strong key, making it resistant to simple dictionary attacks and significantly more secure than using the raw password as the key.
​Encryption (encryptData)
​It takes the plaintext and the secret password as input.
​It calls CryptoJS.AES.encrypt(plaintext, password).
​The output is a secure, Base64-encoded string known as the ciphertext, which includes the salt, IV (Initialization Vector), and the encrypted data bundled in a standard format.
​Decryption (decryptData)
​It takes the ciphertext and the secret password as input.
​It calls CryptoJS.AES.decrypt(ciphertext, password).
​Critical Error Handling: The function contains checks (bytes.sigBytes <= 0 and check for empty plaintext) to verify the output. If the password is incorrect or the data is corrupted, the decryption fails safely, and a custom error message is returned to the user, preventing the display of gibberish.
​3. User Interface and Interactivity
​The UI is divided into four main sections:
​Input Data: A textarea where the user enters plaintext to encrypt or ciphertext to decrypt.
​Configuration: Includes the disabled Algorithm selector (fixed at AES-256) and the essential Secret Password input field.
​Actions: Two distinct buttons, Encrypt Data and Decrypt Data, which trigger the main logic handlers (handleEncrypt and handleDecrypt).
​Output Data: A read-only textarea displaying the result.
​Status and Feedback
​The crucial utility function, showStatus(message, type), is used throughout the application. It provides non-blocking, visual feedback (success, error, or info) to the user via a dynamically styled alert box, replacing the use of insecure or blocked browser alerts (alert()).
​Utility
​The Copy Output button uses a robust clipboard fallback method (document.execCommand('copy')) to ensure the feature works reliably even within restricted iframe environments.
