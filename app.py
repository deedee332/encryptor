from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
import os, hashlib

app = Flask(__name__)

# Function to derive AES key from password
def get_aes_key(password):
    return hashlib.sha256(password.encode()).digest()  # 32-byte key

# Encrypt text
def encrypt_text(text, password):
    key = get_aes_key(password)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(text.encode('utf-8'))
    return (cipher.nonce + tag + ciphertext).hex()

# Decrypt text
def decrypt_text(encrypted_text, password):
    key = get_aes_key(password)
    encrypted_data = bytes.fromhex(encrypted_text)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

# Encrypt file
def encrypt_file(file_path, password):
    key = get_aes_key(password)
    with open(file_path, "rb") as f:
        file_data = f.read()

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)

    encrypted_filename = "encrypted_" + os.path.basename(file_path)
    with open(encrypted_filename, "wb") as f:
        f.write(cipher.nonce + tag + ciphertext)

    return encrypted_filename

# Decrypt file
def decrypt_file(file_path, password):
    key = get_aes_key(password)
    with open(file_path, "rb") as f:
        file_data = f.read()

    nonce, tag, ciphertext = file_data[:16], file_data[16:32], file_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

    decrypted_filename = "decrypted_" + os.path.basename(file_path)
    with open(decrypted_filename, "wb") as f:
        f.write(decrypted_data)

    return decrypted_filename

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt_text', methods=['POST'])
def encrypt_text_route():
    text = request.form['text']
    password = request.form['password']
    encrypted_text = encrypt_text(text, password)
    return f"Encrypted Text (Hex): {encrypted_text}"

@app.route('/decrypt_text', methods=['POST'])
def decrypt_text_route():
    encrypted_text = request.form['text']
    password = request.form['password']
    try:
        decrypted_text = decrypt_text(encrypted_text, password)
        return f"Decrypted Text: {decrypted_text}"
    except Exception:
        return "Invalid password or text."

@app.route('/encrypt_file', methods=['POST'])
def encrypt_file_route():
    file = request.files['file']
    password = request.form['password']
    if file:
        file.save(file.filename)
        encrypted_filename = encrypt_file(file.filename, password)
        return send_file(encrypted_filename, as_attachment=True)

@app.route('/decrypt_file', methods=['POST'])
def decrypt_file_route():
    file = request.files['file']
    password = request.form['password']
    if file:
        file.save(file.filename)
        decrypted_filename = decrypt_file(file.filename, password)
        return send_file(decrypted_filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
import os

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Use Render's assigned PORT or default to 5000
    app.run(debug=True, host='0.0.0.0', port=port)
