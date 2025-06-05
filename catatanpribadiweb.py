import streamlit as st
import sqlite3
import hashlib
import secrets
import base64
from datetime import datetime
import pandas as pd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import json
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image
import io

# Konfigurasi halaman
st.set_page_config(
    page_title="🔒 Catatan Pribadi Aman",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS untuk tampilan yang menarik
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 1rem 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .note-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        border-left: 5px solid #667eea;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    
    .crypto-info {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    
    .stats-card {
        background: linear-gradient(45deg, #FF6B6B, #4ECDC4);
        color: white;
        padding: 1.5rem;
        border-radius: 15px;
        text-align: center;
        margin: 0.5rem 0;
    }
    
    .success-message {
        background: linear-gradient(90deg, #56ab2f 0%, #a8e6cf 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    
    .warning-message {
        background: linear-gradient(90deg, #f093fb 0%, #f5576c 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 1rem 0;
    }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
    }
    
    .stButton > button {
        background: linear-gradient(45deg, #667eea, #764ba2);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 0.5rem 2rem;
        font-weight: bold;
        transition: all 0.3s;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    }
</style>
""", unsafe_allow_html=True)

class CryptoManager:
    @staticmethod
    def generate_salt():
        return secrets.token_bytes(32)
    
    @staticmethod
    def hash_password(password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    
    @staticmethod
    def generate_key_from_password(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def encrypt_aes(data, key):
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Padding PKCS7
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + encrypted).decode()
    
    @staticmethod
    def decrypt_aes(encrypted_data, key):
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            iv = encrypted_bytes[:16]
            encrypted = encrypted_bytes[16:]
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()
            pad_length = decrypted_padded[-1]
            decrypted = decrypted_padded[:-pad_length]
            
            return decrypted.decode()
        except Exception as e:
            return None
    
    @staticmethod
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key

class DatabaseManager:
    def __init__(self):
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect('secure_notes.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                encrypted_content TEXT NOT NULL,
                category TEXT DEFAULT 'General',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                color TEXT DEFAULT '#3498db',
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_user(self, username, password):
        salt = CryptoManager.generate_salt()
        password_hash = CryptoManager.hash_password(password, salt)
        
        conn = sqlite3.connect('secure_notes.db', check_same_thread=False)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                (username, password_hash, salt)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()
    
    def verify_user(self, username, password):
        conn = sqlite3.connect('secure_notes.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute(
            'SELECT id, password_hash, salt FROM users WHERE username = ?',
            (username,)
        )
        result = cursor.fetchone()
        conn.close()
        
        if result:
            user_id, stored_hash, salt = result
            password_hash = CryptoManager.hash_password(password, salt)
            if password_hash == stored_hash:
                return user_id, salt
        return None, None
    
    def save_note(self, user_id, title, content, category, encryption_key):
        encrypted_content = CryptoManager.encrypt_aes(content.encode(), encryption_key)
        
        conn = sqlite3.connect('secure_notes.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO notes (user_id, title, encrypted_content, category, updated_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, title, encrypted_content, category, datetime.now()))
        
        conn.commit()
        conn.close()
    
    def get_notes(self, user_id):
        conn = sqlite3.connect('secure_notes.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, title, encrypted_content, category, created_at, updated_at
            FROM notes WHERE user_id = ? ORDER BY updated_at DESC
        ''', (user_id,))
        
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_note(self, note_id, user_id):
        conn = sqlite3.connect('secure_notes.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, title, encrypted_content, category, created_at, updated_at
            FROM notes WHERE id = ? AND user_id = ?
        ''', (note_id, user_id))
        
        result = cursor.fetchone()
        conn.close()
        return result
    
    def delete_note(self, note_id, user_id):
        conn = sqlite3.connect('secure_notes.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM notes WHERE id = ? AND user_id = ?', (note_id, user_id))
        conn.commit()
        conn.close()
    
    def update_note(self, note_id, user_id, title, content, category, encryption_key):
        encrypted_content = CryptoManager.encrypt_aes(content.encode(), encryption_key)
        
        conn = sqlite3.connect('secure_notes.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE notes SET title=?, encrypted_content=?, category=?, updated_at=?
            WHERE id=? AND user_id=?
        ''', (title, encrypted_content, category, datetime.now(), note_id, user_id))
        
        conn.commit()
        conn.close()

# Inisialisasi database
@st.cache_resource
def init_database():
    return DatabaseManager()

db = init_database()

# Fungsi untuk menampilkan header
def show_header():
    st.markdown("""
    <div class="main-header">
        <h1>🔒 Catatan Pribadi Ultra Aman</h1>
        <p>Sistem Kriptografi AES-256 + RSA dengan Keamanan Tingkat Militer</p>
    </div>
    """, unsafe_allow_html=True)

# Fungsi login/register
def auth_page():
    show_header()
    
    tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
    
    with tab1:
        st.subheader("Masuk ke Akun Anda")
        
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Masukkan username Anda")
            password = st.text_input("Password", type="password", placeholder="Masukkan password Anda")
            
            col1, col2 = st.columns([1, 2])
            with col1:
                login_btn = st.form_submit_button("🚀 Login", use_container_width=True)
            
            if login_btn:
                if username and password:
                    user_id, salt = db.verify_user(username, password)
                    if user_id:
                        st.session_state.user_id = user_id
                        st.session_state.username = username
                        st.session_state.encryption_key = CryptoManager.generate_key_from_password(password, salt)
                        st.success("✅ Login berhasil!")
                        st.rerun()
                    else:
                        st.error("❌ Username atau password salah!")
                else:
                    st.warning("⚠️ Harap isi semua field!")
    
    with tab2:
        st.subheader("Buat Akun Baru")
        
        with st.form("register_form"):
            new_username = st.text_input("Username Baru", placeholder="Pilih username unik")
            new_password = st.text_input("Password Baru", type="password", placeholder="Min. 8 karakter")
            confirm_password = st.text_input("Konfirmasi Password", type="password", placeholder="Ulangi password")
            
            col1, col2 = st.columns([1, 2])
            with col1:
                register_btn = st.form_submit_button("🎯 Daftar", use_container_width=True)
            
            if register_btn:
                if new_username and new_password and confirm_password:
                    if len(new_password) < 8:
                        st.error("❌ Password harus minimal 8 karakter!")
                    elif new_password != confirm_password:
                        st.error("❌ Password tidak cocok!")
                    else:
                        if db.create_user(new_username, new_password):
                            st.success("✅ Registrasi berhasil! Silakan login.")
                        else:
                            st.error("❌ Username sudah digunakan!")
                else:
                    st.warning("⚠️ Harap isi semua field!")
    
    # Info keamanan
    st.markdown("""
    <div class="crypto-info">
        <h3>🛡️ Fitur Keamanan Tingkat Militer</h3>
        <ul>
            <li><strong>AES-256 Encryption:</strong> Algoritma enkripsi yang digunakan CIA dan NSA</li>
            <li><strong>PBKDF2 Password Hashing:</strong> 100,000 iterasi untuk perlindungan maksimal</li>
            <li><strong>Cryptographic Salt:</strong> Salt unik 256-bit untuk setiap user</li>
            <li><strong>CBC Mode:</strong> Mode enkripsi yang lebih aman dari ECB</li>
            <li><strong>Secure Random IV:</strong> Initialization Vector yang truly random</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

# Dashboard utama
def main_dashboard():
    show_header()
    
    # Sidebar navigasi
    with st.sidebar:
        st.markdown(f"### 👋 Selamat datang, {st.session_state.username}!")
        
        menu = st.selectbox(
            "🧭 Navigasi",
            ["📊 Dashboard", "📝 Buat Catatan", "📚 Lihat Catatan", "🔒 Tools Enkripsi", "🔓 Tools Dekripsi", "📈 Analisis", "⚙️ Pengaturan"]
        )
        
        st.markdown("---")
        
        if st.button("🚪 Logout", use_container_width=True):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Konten berdasarkan menu
    if menu == "📊 Dashboard":
        dashboard_home()
    elif menu == "📝 Buat Catatan":
        create_note_page()
    elif menu == "📚 Lihat Catatan":
        view_notes_page()
    elif menu == "🔒 Tools Enkripsi":
        encryption_tools()
    elif menu == "🔓 Tools Dekripsi":
        decryption_tools()
    elif menu == "📈 Analisis":
        analytics_page()
    elif menu == "⚙️ Pengaturan":
        settings_page()

def dashboard_home():
    notes = db.get_notes(st.session_state.user_id)
    
    # Statistik
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown(f"""
        <div class="stats-card">
            <h2>{len(notes)}</h2>
            <p>Total Catatan</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        categories = list(set([note[3] for note in notes])) if notes else []
        st.markdown(f"""
        <div class="stats-card">
            <h2>{len(categories)}</h2>
            <p>Kategori</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        today_notes = [note for note in notes if note[4][:10] == datetime.now().strftime('%Y-%m-%d')]
        st.markdown(f"""
        <div class="stats-card">
            <h2>{len(today_notes)}</h2>
            <p>Hari Ini</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        total_chars = sum([len(note[1]) for note in notes])
        st.markdown(f"""
        <div class="stats-card">
            <h2>{total_chars}</h2>
            <p>Total Karakter</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Grafik aktivitas
    if notes:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📊 Distribusi Kategori")
            category_counts = {}
            for note in notes:
                cat = note[3]
                category_counts[cat] = category_counts.get(cat, 0) + 1
            
            fig = px.pie(
                values=list(category_counts.values()),
                names=list(category_counts.keys()),
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📈 Aktivitas Harian")
            dates = [note[4][:10] for note in notes]
            date_counts = {}
            for date in dates:
                date_counts[date] = date_counts.get(date, 0) + 1
            
            if date_counts:
                fig = px.bar(
                    x=list(date_counts.keys()),
                    y=list(date_counts.values()),
                    color_discrete_sequence=['#667eea']
                )
                fig.update_layout(xaxis_title="Tanggal", yaxis_title="Jumlah Catatan")
                st.plotly_chart(fig, use_container_width=True)
    
    # Catatan terbaru
    st.subheader("📝 Catatan Terbaru")
    if notes:
        for i, note in enumerate(notes[:3]):
            st.markdown(f"""
            <div class="note-card">
                <h4>📄 {note[1]}</h4>
                <p><strong>Kategori:</strong> {note[3]} | <strong>Dibuat:</strong> {note[4][:16]}</p>
                <small>🔒 Terenkripsi dengan AES-256</small>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Belum ada catatan. Buat catatan pertama Anda!")

def create_note_page():
    st.header("✍️ Buat Catatan Baru")
    
    with st.form("create_note_form"):
        col1, col2 = st.columns([3, 1])
        
        with col1:
            title = st.text_input("📝 Judul Catatan", placeholder="Masukkan judul catatan...")
        
        with col2:
            category = st.text_input("📁 Kategori", value="General", placeholder="Kategori...")
        
        content = st.text_area(
            "📄 Isi Catatan",
            height=300,
            placeholder="Tulis catatan Anda di sini...\n\nCatatan akan otomatis dienkripsi dengan AES-256!"
        )
        
        col1, col2, col3 = st.columns([1, 1, 2])
        with col1:
            submit = st.form_submit_button("🔒 Simpan & Enkripsi", use_container_width=True)
        with col2:
            preview = st.form_submit_button("👁️ Preview", use_container_width=True)
        
        if submit:
            if title and content:
                db.save_note(
                    st.session_state.user_id,
                    title,
                    content,
                    category,
                    st.session_state.encryption_key
                )
                st.success("✅ Catatan berhasil disimpan dan dienkripsi!")
                st.balloons()
            else:
                st.error("❌ Harap isi judul dan isi catatan!")
        
        if preview and content:
            st.subheader("👁️ Preview Catatan")
            st.markdown(f"**Judul:** {title}")
            st.markdown(f"**Kategori:** {category}")
            st.markdown("**Isi:**")
            st.markdown(content)
    
    # Info enkripsi
    st.markdown("""
    <div class="crypto-info">
        <h4>🔐 Proses Enkripsi Otomatis</h4>
        <p>Setiap catatan yang Anda buat akan melalui proses enkripsi berikut:</p>
        <ol>
            <li>Konten dikonversi ke bytes</li>
            <li>Generate random IV (Initialization Vector) 128-bit</li>
            <li>Enkripsi menggunakan AES-256 dalam mode CBC</li>
            <li>Gabungkan IV + encrypted data</li>
            <li>Encode ke Base64 untuk penyimpanan</li>
        </ol>
    </div>
    """, unsafe_allow_html=True)

def view_notes_page():
    st.header("📚 Catatan Tersimpan")
    
    notes = db.get_notes(st.session_state.user_id)
    
    if not notes:
        st.info("Belum ada catatan tersimpan.")
        return
    
    # Filter dan pencarian
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        search = st.text_input("🔍 Cari catatan...", placeholder="Cari berdasarkan judul")
    
    with col2:
        categories = list(set([note[3] for note in notes]))
        category_filter = st.selectbox("📁 Filter Kategori", ["Semua"] + categories)
    
    with col3:
        sort_by = st.selectbox("📊 Urutkan", ["Terbaru", "Terlama", "A-Z", "Z-A"])
    
    # Filter notes
    filtered_notes = notes
    
    if search:
        filtered_notes = [note for note in filtered_notes if search.lower() in note[1].lower()]
    
    if category_filter != "Semua":
        filtered_notes = [note for note in filtered_notes if note[3] == category_filter]
    
    # Sort notes
    if sort_by == "Terlama":
        filtered_notes = sorted(filtered_notes, key=lambda x: x[4])
    elif sort_by == "A-Z":
        filtered_notes = sorted(filtered_notes, key=lambda x: x[1])
    elif sort_by == "Z-A":
        filtered_notes = sorted(filtered_notes, key=lambda x: x[1], reverse=True)
    
    st.markdown(f"**Menampilkan {len(filtered_notes)} dari {len(notes)} catatan**")
    
    # Tampilkan catatan
    for note in filtered_notes:
        with st.expander(f"📄 {note[1]} ({note[3]}) - {note[4][:16]}"):
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                if st.button(f"👁️ Lihat Detail", key=f"view_{note[0]}"):
                    show_note_detail(note)
            
            with col2:
                if st.button(f"✏️ Edit", key=f"edit_{note[0]}"):
                    edit_note(note)
            
            with col3:
                if st.button(f"🗑️ Hapus", key=f"delete_{note[0]}"):
                    if st.session_state.get(f"confirm_delete_{note[0]}", False):
                        db.delete_note(note[0], st.session_state.user_id)
                        st.success("Catatan berhasil dihapus!")
                        st.rerun()
                    else:
                        st.session_state[f"confirm_delete_{note[0]}"] = True
                        st.warning("Klik sekali lagi untuk konfirmasi hapus!")

def show_note_detail(note):
    st.subheader(f"📄 {note[1]}")
    
    # Dekripsi konten
    decrypted_content = CryptoManager.decrypt_aes(note[2], st.session_state.encryption_key)
    
    if decrypted_content:
        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown(f"**📁 Kategori:** {note[3]}")
        with col2:
            st.markdown(f"**📅 Dibuat:** {note[4][:16]}")
        
        st.markdown("**📄 Isi Catatan:**")
        st.markdown(f"<div style='background: #f0f2f6; padding: 1rem; border-radius: 10px; border-left: 4px solid #667eea;'>{decrypted_content}</div>", unsafe_allow_html=True)
        
        # Statistik catatan
        word_count = len(decrypted_content.split())
        char_count = len(decrypted_content)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Kata", word_count)
        with col2:
            st.metric("Karakter", char_count)
        with col3:
            st.metric("Paragraf", decrypted_content.count('\n\n') + 1)
    else:
        st.error("❌ Gagal mendekripsi catatan!")

def edit_note(note):
    st.subheader(f"✏️ Edit: {note[1]}")
    
    # Dekripsi konten untuk editing
    decrypted_content = CryptoManager.decrypt_aes(note[2], st.session_state.encryption_key)
    
    if decrypted_content:
        with st.form(f"edit_note_{note[0]}"):
            new_title = st.text_input("Judul", value=note[1])
            new_category = st.text_input("Kategori", value=note[3])
            new_content = st.text_area("Isi Catatan", value=decrypted_content, height=200)
            
            if st.form_submit_button("💾 Simpan Perubahan"):
                db.update_note(
                    note[0],
                    st.session_state.user_id,
                    new_title,
                    new_content,
                    new_category,
                    st.session_state.encryption_key
                )
                st.success("✅ Catatan berhasil diperbarui!")
                st.rerun()
    else:
        st.error("❌ Gagal mendekripsi catatan untuk diedit!")

def encryption_tools():
    st.header("🔒 Tools Enkripsi")
    
    tab1, tab2, tab3 = st.tabs(["🔐 AES Enkripsi", "🔑 RSA Enkripsi", "🧮 Hash Generator"])
    
    with tab1:
        st.subheader("🔒 AES-256 Enkripsi")
        
        text_to_encrypt = st.text_area("Teks yang akan dienkripsi:", height=150)
        
        if st.button("🔒 Enkripsi dengan AES-256"):
            if text_to_encrypt:
                encrypted = CryptoManager.encrypt_aes(text_to_encrypt.encode(), st.session_state.encryption_key)
                
                st.success("✅ Enkripsi berhasil!")
                st.markdown("**🔐 Hasil Enkripsi:**")
                st.code(encrypted, language="text")
                
                # Analisis enkripsi
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Panjang Original", len(text_to_encrypt))
                with col2:
                    st.metric("Panjang Encrypted", len(encrypted))
                with col3:
                    st.metric("Rasio Ekspansi", f"{len(encrypted)/len(text_to_encrypt):.2f}x")
            else:
                st.warning("Masukkan teks yang akan dienkripsi!")
    
    with tab2:
        st.subheader("🔑 RSA Enkripsi")
        st.info("Fitur RSA untuk enkripsi file dan pesan sensitif")
        
        if st.button("🔑 Generate RSA Key Pair"):
            private_key, public_key = CryptoManager.generate_rsa_keys()
            
            st.success("
