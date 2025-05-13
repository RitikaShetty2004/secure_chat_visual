from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import base64
from time import perf_counter
import time
import io
import matplotlib

# Use non-GUI backend for Matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app)

# Padding function
def pad(text, block_size):
    if isinstance(text, str):
        text = text.encode()
    padding_len = block_size - len(text) % block_size
    return text + bytes([padding_len] * padding_len)

# AES Encryption & Decryption
def aes_encrypt_decrypt(message):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(message, 16)

    start = perf_counter()
    encrypted = cipher.encrypt(padded)
    enc_time = (perf_counter() - start) * 1000

    start = perf_counter()
    decrypted = cipher.decrypt(encrypted).decode().rstrip()
    dec_time = (perf_counter() - start) * 1000

    encrypted_b64 = base64.b64encode(encrypted).decode()

    steps = [
        f"Key: {key.hex()}",
        f"Padded Message (hex): {padded.hex()}",
        f"Encrypted (base64): {encrypted_b64}",
        f"Decrypted: {decrypted}"
    ]
    return {
        "encrypted": encrypted_b64,
        "decrypted": decrypted,
        "steps": steps,
        "enc_time": round(enc_time, 4),
        "dec_time": round(dec_time, 4)
    }

# DES Encryption & Decryption
def des_encrypt_decrypt(message):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(message, 8)

    start = perf_counter()
    encrypted = cipher.encrypt(padded)
    enc_time = (perf_counter() - start) * 1000

    start = perf_counter()
    decrypted = cipher.decrypt(encrypted).decode().rstrip()
    dec_time = (perf_counter() - start) * 1000

    encrypted_b64 = base64.b64encode(encrypted).decode()

    steps = [
        f"Key: {key.hex()}",
        f"Padded Message (hex): {padded.hex()}",
        f"Encrypted (base64): {encrypted_b64}",
        f"Decrypted: {decrypted}"
    ]
    return {
        "encrypted": encrypted_b64,
        "decrypted": decrypted,
        "steps": steps,
        "enc_time": round(enc_time, 4),
        "dec_time": round(dec_time, 4)
    }

# Routes
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        msg = request.form["msg"]
        aes_result = aes_encrypt_decrypt(msg)
        des_result = des_encrypt_decrypt(msg)

        session["original_message"] = msg
        session["aes_result"] = aes_result
        session["des_result"] = des_result

        return redirect(url_for("steps"))
    return render_template("index.html")

@app.route("/steps")
def steps():
    aes = session.get("aes_result")
    des = session.get("des_result")

    if not aes or not des:
        return redirect(url_for("index"))

    return render_template("steps.html", aes=aes, des=des)

@app.route("/graph")
def graph():
    aes = session.get("aes_result")
    des = session.get("des_result")
    if not aes or not des:
        return redirect(url_for("index"))

    aes_time = aes["enc_time"]
    des_time = des["enc_time"]

    return render_template("graph.html", aes_time=aes_time, des_time=des_time)



@app.route("/chat_simulation")
def chat_simulation():
    message = session.get("original_message")
    aes = session.get("aes_result")
    des = session.get("des_result")
    if not aes or not des:
        return redirect(url_for("index"))
    return render_template("chat_simulation.html", message=message, aes=aes, des=des)

@app.route("/benchmark")
def benchmark():
    sizes = [16, 64, 256, 1024, 4096, 8192]
    aes_times = []
    des_times = []

    for size in sizes:
        message = "A" * size
        aes_time = encrypt_aes_time(message)
        des_time = encrypt_des_time(message)
        aes_times.append(aes_time)
        des_times.append(des_time)

    fig, ax = plt.subplots()
    ax.plot(sizes, aes_times, marker='o', label='AES Encryption Time')
    ax.plot(sizes, des_times, marker='o', label='DES Encryption Time')
    ax.set_xlabel("Message Size (bytes)")
    ax.set_ylabel("Time (ms)")
    ax.set_title("AES vs DES Encryption Time Comparison")
    ax.legend()
    ax.grid(True)

    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode()
    buf.close()

    return render_template("benchmark.html", graph_image=img_base64)

# Helper timing functions
def encrypt_aes_time(msg):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(msg.encode(), AES.block_size)
    start = time.perf_counter()
    cipher.encrypt(padded)
    end = time.perf_counter()
    return (end - start) * 1000

def encrypt_des_time(msg):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(msg.encode(), DES.block_size)
    start = time.perf_counter()
    cipher.encrypt(padded)
    end = time.perf_counter()
    return (end - start) * 1000

# Safe server startup for Windows + SocketIO
if __name__ == '__main__':
    socketio.run(app, debug=True, use_reloader=False)