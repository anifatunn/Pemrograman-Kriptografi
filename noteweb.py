import streamlit as st
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

# ---------- Helper Functions ---------- #
def derive_key(password: str) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000, dklen=32)

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def encrypt_data(data: str, password: str) -> str:
    key = derive_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data)
    ct_bytes = cipher.encrypt(padded_data.encode())
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

def decrypt_data(enc_data: str, password: str) -> str:
    key = derive_key(password)
    raw = base64.b64decode(enc_data)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ct).decode('utf-8')
    return unpad(decrypted)

# ---------- Session State Setup ---------- #
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False
if 'notes' not in st.session_state:
    st.session_state.notes = {}

# ---------- Navigation ---------- #
menu = st.sidebar.selectbox("Navigasi", ["Login", "Enkripsi", "Dekripsi", "Buku Catatan", "Tentang"])

# ---------- Login Page ---------- #
def login_page():
    st.title("🔐 Login Pengguna")
    username = st.text_input("Nama Pengguna")
    password = st.text_input("Kata Sandi", type="password")
    if st.button("Login"):
        if username and password:
            st.session_state.is_logged_in = True
            st.session_state.username = username
            st.success("Berhasil login!")
        else:
            st.error("Isi semua kolom.")

# ---------- Encryption Page ---------- #
def encryption_page():
    st.title("🔏 Enkripsi Catatan")
    note = st.text_area("Masukkan catatan:")
    password = st.text_input("Kata sandi enkripsi", type="password")
    if st.button("Enkripsi"):
        if note and password:
            encrypted_note = encrypt_data(note, password)
            st.session_state.notes[encrypted_note] = "Encrypted"
            st.text_area("Hasil Enkripsi", encrypted_note, height=200)
        else:
            st.error("Masukkan catatan dan kata sandi.")

# ---------- Decryption Page ---------- #
def decryption_page():
    st.title("🔓 Dekripsi Catatan")
    encrypted_note = st.text_area("Tempelkan catatan terenkripsi:")
    password = st.text_input("Kata sandi dekripsi", type="password")
    if st.button("Dekripsi"):
        try:
            decrypted = decrypt_data(encrypted_note, password)
            st.text_area("Catatan asli:", decrypted, height=200)
            st.session_state.notes[encrypted_note] = decrypted
        except:
            st.error("Gagal mendekripsi. Periksa kembali kata sandi dan data.")

# ---------- Notes Book Page ---------- #
def notes_book():
    st.title("📚 Buku Catatan")
    if not st.session_state.notes:
        st.info("Belum ada catatan disimpan.")
    else:
        for idx, (enc, content) in enumerate(st.session_state.notes.items()):
            with st.expander(f"Catatan {idx + 1}"):
                st.code(enc if content == "Encrypted" else content, language='text')
                st.caption("Status: {}".format("Terenkripsi" if content == "Encrypted" else "Didekripsi"))

# ---------- About Page ---------- #
def about_page():
    st.title("ℹ️ Tentang Aplikasi")
    st.markdown("""
    Aplikasi ini dibangun menggunakan **Streamlit** dan memanfaatkan **AES (Advanced Encryption Standard)**
    untuk mengamankan catatan pribadi Anda. Setiap catatan dapat dienkripsi dan disimpan secara lokal di sesi saat ini.

    **Fitur:**
    - Login pengguna
    - Enkripsi dan dekripsi catatan
    - Penyimpanan lokal sementara
    - Navigasi mudah dan UI interaktif
    
    _Catatan tidak disimpan permanen. Silakan simpan catatan terenkripsi secara eksternal jika diperlukan._
    """)

# ---------- Main Render ---------- #
if menu == "Login":
    login_page()
elif not st.session_state.is_logged_in:
    st.warning("Silakan login terlebih dahulu.")
    login_page()
elif menu == "Enkripsi":
    encryption_page()
elif menu == "Dekripsi":
    decryption_page()
elif menu == "Buku Catatan":
    notes_book()
elif menu == "Tentang":
    about_page()
