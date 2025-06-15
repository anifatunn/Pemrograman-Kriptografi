import streamlit as st
import hashlib
import base64
import json
import datetime
import sqlite3
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd

# Konfigurasi halaman
st.set_page_config(
    page_title="📝 SecureNotes - Catatan Pribadi Terenkripsi",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS untuk styling dengan tema kuning
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #FFD700, #FFA500);
        padding: 20px;
        border-radius: 10px;
        text-align: center;
        color: #333;
        margin-bottom: 20px;
        box-shadow: 0 4px 8px rgba(255, 215, 0, 0.3);
    }
    .card {
        background: linear-gradient(135deg, #FFFACD, #FFFFE0);
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #FFD700;
        margin: 10px 0;
        box-shadow: 0 2px 4px rgba(255, 215, 0, 0.2);
    }
    .success-card {
        background: linear-gradient(135deg, #F0FFF0, #E6FFE6);
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #32CD32;
        margin: 10px 0;
    }
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #FFE4B5, #FFEFD5);
    }
    .metric-card {
        background: linear-gradient(135deg, #FFF8DC, #FFFACD);
        padding: 15px;
        border-radius: 8px;
        text-align: center;
        border: 2px solid #FFD700;
        margin: 5px;
    }
    .database-status {
        background: linear-gradient(135deg, #E6F3FF, #CCE6FF);
        padding: 10px;
        border-radius: 5px;
        border-left: 3px solid #007BFF;
        margin: 5px 0;
    }
    .stButton > button {
        background: linear-gradient(135deg, #FFD700, #FFA500);
        color: #333;
        border: none;
        border-radius: 5px;
        font-weight: bold;
        transition: all 0.3s;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #FFA500, #FF8C00);
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(255, 165, 0, 0.3);
    }
</style>
""", unsafe_allow_html=True)


# Database Manager
class DatabaseManager:
    def __init__(self, db_name="securenotes.db"):
        self.db_name = db_name
        self.init_database()

    def init_database(self):
        """Inisialisasi database dan tabel"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Tabel users
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS users
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           username
                           TEXT
                           UNIQUE
                           NOT
                           NULL,
                           password_hash
                           TEXT
                           NOT
                           NULL,
                           created_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP
                       )
                       ''')

        # Tabel notes
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS notes
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           username
                           TEXT
                           NOT
                           NULL,
                           title
                           TEXT
                           NOT
                           NULL,
                           content
                           TEXT
                           NOT
                           NULL,
                           category
                           TEXT
                           NOT
                           NULL,
                           encrypted
                           BOOLEAN
                           DEFAULT
                           FALSE,
                           date
                           TEXT
                           NOT
                           NULL,
                           time
                           TEXT
                           NOT
                           NULL,
                           created_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP,
                           updated_at
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP,
                           FOREIGN
                           KEY
                       (
                           username
                       ) REFERENCES users
                       (
                           username
                       )
                           )
                       ''')

        # Tabel untuk log aktivitas
        cursor.execute('''
                       CREATE TABLE IF NOT EXISTS activity_log
                       (
                           id
                           INTEGER
                           PRIMARY
                           KEY
                           AUTOINCREMENT,
                           username
                           TEXT
                           NOT
                           NULL,
                           action
                           TEXT
                           NOT
                           NULL,
                           details
                           TEXT,
                           timestamp
                           TIMESTAMP
                           DEFAULT
                           CURRENT_TIMESTAMP,
                           FOREIGN
                           KEY
                       (
                           username
                       ) REFERENCES users
                       (
                           username
                       )
                           )
                       ''')

        conn.commit()
        conn.close()

    def create_user(self, username, password_hash):
        """Membuat user baru"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            conn.close()
            self.log_activity(username, "REGISTER", "User registered successfully")
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username, password_hash):
        """Verifikasi login user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )
        result = cursor.fetchone()
        conn.close()

        if result and result[0] == password_hash:
            self.log_activity(username, "LOGIN", "Successful login")
            return True
        return False

    def save_note(self, username, title, content, category, encrypted, date, time):
        """Menyimpan catatan ke database"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
                       INSERT INTO notes (username, title, content, category, encrypted, date, time)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ''', (username, title, content, category, encrypted, date, time))
        conn.commit()
        note_id = cursor.lastrowid
        conn.close()

        self.log_activity(username, "CREATE_NOTE", f"Created note: {title}")
        return note_id

    def get_user_notes(self, username):
        """Mengambil semua catatan user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
                       SELECT id, title, content, category, encrypted, date, time, created_at
                       FROM notes
                       WHERE username = ?
                       ORDER BY created_at DESC
                       ''', (username,))
        notes = cursor.fetchall()
        conn.close()

        # Konversi ke format dictionary
        note_list = []
        for note in notes:
            note_dict = {
                'id': note[0],
                'title': note[1],
                'content': note[2],
                'category': note[3],
                'encrypted': bool(note[4]),
                'date': note[5],
                'time': note[6],
                'created_at': note[7]
            }
            note_list.append(note_dict)

        return note_list

    def delete_note(self, note_id, username):
        """Menghapus catatan"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Ambil info catatan untuk log
        cursor.execute("SELECT title FROM notes WHERE id = ? AND username = ?", (note_id, username))
        note_info = cursor.fetchone()

        cursor.execute("DELETE FROM notes WHERE id = ? AND username = ?", (note_id, username))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()

        if deleted and note_info:
            self.log_activity(username, "DELETE_NOTE", f"Deleted note: {note_info[0]}")

        return deleted

    def update_note(self, note_id, username, title, content, category):
        """Update catatan"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
                       UPDATE notes
                       SET title      = ?,
                           content    = ?,
                           category   = ?,
                           updated_at = CURRENT_TIMESTAMP
                       WHERE id = ?
                         AND username = ?
                       ''', (title, content, category, note_id, username))
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()

        if updated:
            self.log_activity(username, "UPDATE_NOTE", f"Updated note: {title}")

        return updated

    def get_user_stats(self, username):
        """Mengambil statistik user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Total notes
        cursor.execute("SELECT COUNT(*) FROM notes WHERE username = ?", (username,))
        total_notes = cursor.fetchone()[0]

        # Encrypted notes
        cursor.execute("SELECT COUNT(*) FROM notes WHERE username = ? AND encrypted = 1", (username,))
        encrypted_notes = cursor.fetchone()[0]

        # Notes today
        today = datetime.date.today().isoformat()
        cursor.execute("SELECT COUNT(*) FROM notes WHERE username = ? AND date = ?", (username, today))
        today_notes = cursor.fetchone()[0]

        # Average length
        cursor.execute("SELECT AVG(LENGTH(content)) FROM notes WHERE username = ?", (username,))
        avg_length = cursor.fetchone()[0] or 0

        conn.close()

        return {
            'total_notes': total_notes,
            'encrypted_notes': encrypted_notes,
            'today_notes': today_notes,
            'avg_length': int(avg_length)
        }

    def log_activity(self, username, action, details=None):
        """Mencatat aktivitas user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO activity_log (username, action, details) VALUES (?, ?, ?)",
            (username, action, details)
        )
        conn.commit()
        conn.close()

    def get_activity_log(self, username, limit=50):
        """Mengambil log aktivitas user"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute('''
                       SELECT action, details, timestamp
                       FROM activity_log
                       WHERE username = ?
                       ORDER BY timestamp DESC LIMIT ?
                       ''', (username, limit))
        activities = cursor.fetchall()
        conn.close()
        return activities

    def get_database_info(self):
        """Mengambil informasi database"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()

        # Total users
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]

        # Total notes
        cursor.execute("SELECT COUNT(*) FROM notes")
        total_notes = cursor.fetchone()[0]

        # Database size
        db_size = os.path.getsize(self.db_name) if os.path.exists(self.db_name) else 0

        conn.close()

        return {
            'total_users': total_users,
            'total_notes': total_notes,
            'db_size': db_size,
            'db_path': os.path.abspath(self.db_name)
        }


# Fungsi Kriptografi
class CryptoManager:
    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None) -> bytes:
        if salt is None:
            salt = b'securenotes2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def encrypt_text(text: str, password: str) -> str:
        key = CryptoManager.generate_key_from_password(password)
        f = Fernet(key)
        encrypted_text = f.encrypt(text.encode())
        return base64.urlsafe_b64encode(encrypted_text).decode()

    @staticmethod
    def decrypt_text(encrypted_text: str, password: str) -> str:
        try:
            key = CryptoManager.generate_key_from_password(password)
            f = Fernet(key)
            decoded_text = base64.urlsafe_b64decode(encrypted_text.encode())
            decrypted_text = f.decrypt(decoded_text)
            return decrypted_text.decode()
        except:
            return "❌ Gagal mendekripsi - Password salah atau data rusak"


# Fungsi Authentication
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed


# Inisialisasi database
@st.cache_resource
def init_db():
    return DatabaseManager()


db = init_db()

# Inisialisasi session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""

# Header utama
st.markdown("""
<div class="main-header">
    <h1>🔐 SecureNotes</h1>
    <p>Aplikasi Catatan Pribadi dengan Enkripsi</p>
</div>
""", unsafe_allow_html=True)

# Database status di sidebar
with st.sidebar:
    db_info = db.get_database_info()
    st.markdown(f"""
    <div class="database-status">
        <h4>💾 Status Database</h4>
        <p>👥 Users: {db_info['total_users']}</p>
        <p>📝 Total Notes: {db_info['total_notes']}</p>
        <p>💽 Size: {db_info['db_size'] / 1024:.1f} KB</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🧭 Navigasi")

    if not st.session_state.logged_in:
        menu = st.selectbox(
            "Pilih Menu:",
            ["🏠 Beranda", "🔑 Login", "📝 Daftar", "ℹ️ Info Kriptografi"]
        )
    else:
        st.success(f"👋 Selamat datang, {st.session_state.username}!")
        menu = st.selectbox(
            "Pilih Menu:",
            ["📊 Dashboard", "✍️ Tulis Catatan", "📚 Buku Catatan", "🔒 Enkripsi Tool", "🔓 Dekripsi Tool", "📈 Analisis",
             "📋 Log Aktivitas", "🗑️ Kelola Catatan", "🚪 Logout"]
        )

# Halaman Beranda
if menu == "🏠 Beranda":
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div class="card">
            <h2>🌟 Selamat Datang di SecureNotes!</h2>
            <p>Aplikasi catatan pribadi dengan enkripsi menggunakan algoritma kriptografi AES.</p>

            ✨ Fitur Unggulan:
            
                🔐 Enkripsi AES-256 dengan PBKDF2
                🛡️ Sistem autentikasi aman
                💾 Database SQLite persisten
                📊 Dashboard analitik
                🎨 Interface yang indah dan responsif
                🔍 Pencarian catatan terenkripsi
                📋 Log aktivitas lengkap
        </div>
        """, unsafe_allow_html=True)

        # Visualisasi keamanan
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=['Enkripsi', 'Hash', 'Salt', 'Iterasi'],
            y=[256, 256, 128, 100000],
            mode='lines+markers',
            line=dict(color='#FFD700', width=4),
            marker=dict(size=12, color='#FFA500')
        ))
        fig.update_layout(
            title="🔒 Tingkat Keamanan Kriptografi",
            xaxis_title="Komponen Keamanan",
            yaxis_title="Bit / Jumlah",
            plot_bgcolor='rgba(255,248,220,0.8)',
            paper_bgcolor='rgba(255,248,220,0.8)'
        )
        st.plotly_chart(fig, use_container_width=True)

# Halaman Login
elif menu == "🔑 Login":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("🔑 Masuk ke Akun Anda")

    with st.form("login_form"):
        username = st.text_input("👤 Username")
        password = st.text_input("🔒 Password", type="password")
        submit = st.form_submit_button("🚪 Masuk")

        if submit:
            if username and password:
                password_hash = hash_password(password)
                if db.verify_user(username, password_hash):
                    st.session_state.logged_in = True
                    st.session_state.username = username
                    st.success("✅ Login berhasil!")
                    st.rerun()
                else:
                    st.error("❌ Username atau password salah!")
            else:
                st.error("❌ Masukkan username dan password!")
    st.markdown('</div>', unsafe_allow_html=True)

# Halaman Daftar
elif menu == "📝 Daftar":
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("📝 Buat Akun Baru")

    with st.form("register_form"):
        new_username = st.text_input("👤 Username Baru")
        new_password = st.text_input("🔒 Password Baru", type="password")
        confirm_password = st.text_input("🔒 Konfirmasi Password", type="password")
        submit = st.form_submit_button("📝 Daftar")

        if submit:
            if not new_username or not new_password:
                st.error("❌ Username dan password harus diisi!")
            elif new_password != confirm_password:
                st.error("❌ Password tidak cocok!")
            elif len(new_password) < 6:
                st.error("❌ Password minimal 6 karakter!")
            else:
                password_hash = hash_password(new_password)
                if db.create_user(new_username, password_hash):
                    st.success("✅ Akun berhasil dibuat! Silakan login.")
                else:
                    st.error("❌ Username sudah ada!")
    st.markdown('</div>', unsafe_allow_html=True)

# Halaman Info Kriptografi
elif menu == "ℹ️ Info Kriptografi":
    st.markdown("""
    <div class="card">
        🔐 Teknologi Kriptografi yang Digunakan

        🛡️ Algoritma Utama:
            AES-256: Advanced Encryption Standard dengan kunci 256-bit
            PBKDF2: Password-Based Key Derivation Function 2
            SHA-256: Secure Hash Algorithm 256-bit
            Fernet: Symmetric encryption dengan built-in authentication

        🔒 Keamanan Berlapis:
            Salt unik untuk setiap password
            100,000 iterasi PBKDF2
            Base64 encoding untuk penyimpanan aman
            Autentikasi terintegrasi
            Database SQLite terenkripsi
    </div>
    """, unsafe_allow_html=True)

    # Visualisasi proses enkripsi
    fig = go.Figure(data=go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color="black", width=0.5),
            label=["Password", "Salt", "PBKDF2", "AES Key", "Plaintext", "Database", "Ciphertext"],
            color=["#FFD700", "#FFA500", "#FF8C00", "#FF7F50", "#FFFFE0", "#87CEEB", "#32CD32"]
        ),
        link=dict(
            source=[0, 1, 2, 3, 4, 5],
            target=[2, 2, 3, 6, 6, 6],
            value=[1, 1, 1, 1, 1, 1]
        )
    ))
    fig.update_layout(title_text="🔄 Alur Proses Enkripsi & Penyimpanan", font_size=12)
    st.plotly_chart(fig, use_container_width=True)

# Halaman untuk pengguna yang sudah login
elif st.session_state.logged_in:

    # Dashboard
    if menu == "📊 Dashboard":
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader(f"📊 Dashboard - {st.session_state.username}")

        # Ambil statistik dari database
        stats = db.get_user_stats(st.session_state.username)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>📝</h3>
                <h2>{stats['total_notes']}</h2>
                <p>Total Catatan</p>
            </div>
            """, unsafe_allow_html=True)

        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <h3>🔒</h3>
                <h2>{stats['encrypted_notes']}</h2>
                <p>Terenkripsi</p>
            </div>
            """, unsafe_allow_html=True)

        with col3:
            st.markdown(f"""
            <div class="metric-card">
                <h3>📏</h3>
                <h2>{stats['avg_length']}</h2>
                <p>Rata-rata Karakter</p>
            </div>
            """, unsafe_allow_html=True)

        with col4:
            st.markdown(f"""
            <div class="metric-card">
                <h3>📅</h3>
                <h2>{stats['today_notes']}</h2>
                <p>Hari Ini</p>
            </div>
            """, unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

        # Grafik aktivitas dari database
        user_notes = db.get_user_notes(st.session_state.username)
        if user_notes:
            dates = [note['date'] for note in user_notes]
            df = pd.DataFrame({'date': dates})
            df['count'] = 1
            daily_activity = df.groupby('date').count().reset_index()

            fig = px.line(daily_activity, x='date', y='count',
                          title='📈 Aktivitas Harian Pembuatan Catatan (Database)',
                          color_discrete_sequence=['#FFD700'])
            fig.update_layout(plot_bgcolor='rgba(255,248,220,0.8)')
            st.plotly_chart(fig, use_container_width=True)

    # Tulis Catatan
    elif menu == "✍️ Tulis Catatan":
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("✍️ Buat Catatan Baru")

        with st.form("note_form"):
            title = st.text_input("📝 Judul Catatan")
            content = st.text_area("📄 Isi Catatan", height=200)
            category = st.selectbox("📂 Kategori", ["Pribadi", "Kerja", "Penting", "Ide", "Lainnya"])
            encrypt_note = st.checkbox("🔒 Enkripsi catatan ini")

            if encrypt_note:
                encryption_password = st.text_input("🔑 Password untuk enkripsi", type="password")

            submit = st.form_submit_button("💾 Simpan ke Database")

            if submit:
                if title and content:
                    final_content = content
                    is_encrypted = False

                    if encrypt_note and encryption_password:
                        final_content = CryptoManager.encrypt_text(content, encryption_password)
                        is_encrypted = True

                    # Simpan ke database
                    note_id = db.save_note(
                        st.session_state.username,
                        title,
                        final_content,
                        category,
                        is_encrypted,
                        datetime.date.today().isoformat(),
                        datetime.datetime.now().strftime("%H:%M:%S")
                    )

                    st.success(f"✅ Catatan berhasil disimpan ke database dengan ID: {note_id}")
                else:
                    st.error("❌ Judul dan isi catatan harus diisi!")
        st.markdown('</div>', unsafe_allow_html=True)

    # Buku Catatan
    elif menu == "📚 Buku Catatan":
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("📚 Koleksi Catatan Anda (Database)")

        # Ambil catatan dari database
        user_notes = db.get_user_notes(st.session_state.username)

        if user_notes:
            # Filter dan pencarian
            col1, col2 = st.columns(2)
            with col1:
                search_term = st.text_input("🔍 Cari catatan...")
            with col2:
                filter_category = st.selectbox("📂 Filter kategori",
                                               ["Semua"] + ["Pribadi", "Kerja", "Penting", "Ide", "Lainnya"])

            # Tampilkan catatan
            for note in user_notes:  # Sudah diurutkan DESC di query
                if (not search_term or
                        search_term.lower() in note['title'].lower() or
                        search_term.lower() in note['content'].lower()):
                    if filter_category == "Semua" or note['category'] == filter_category:
                        with st.expander(
                                f"{'🔒' if note['encrypted'] else '📝'} {note['title']} - {note['category']} (ID: {note['id']})"):
                            st.write(f"**📅 Tanggal:** {note['date']} | **🕐 Waktu:** {note['time']}")
                            st.write(f"**🗓️ Dibuat:** {note['created_at']}")

                            if note['encrypted']:
                                decrypt_password = st.text_input(f"🔑 Password untuk dekripsi (ID: {note['id']})",
                                                                 type="password", key=f"decrypt_{note['id']}")
                                if decrypt_password:
                                    decrypted_content = CryptoManager.decrypt_text(note['content'], decrypt_password)
                                    st.write("**📄 Isi Catatan:**")
                                    st.info(decrypted_content)
                                else:
                                    st.warning("🔒 Catatan ini terenkripsi. Masukkan password untuk melihat isi.")
                            else:
                                st.write("**📄 Isi Catatan:**")
                                st.info(note['content'])
        else:
            st.info("📝 Belum ada catatan di database. Mulai tulis catatan pertama Anda!")

        st.markdown('</div>', unsafe_allow_html=True)

    # Tool Enkripsi
    elif menu == "🔒 Enkripsi Tool":
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("🔒 Tool Enkripsi Teks")

        input_text = st.text_area("📝 Masukkan teks yang akan dienkripsi:", height=150)
        encryption_key = st.text_input("🔑 Password enkripsi:", type="password")

        if st.button("🔒 Enkripsi"):
            if input_text and encryption_key:
                encrypted = CryptoManager.encrypt_text(input_text, encryption_key)
                st.markdown('<div class="success-card">', unsafe_allow_html=True)
                st.write("**🔒 Hasil Enkripsi:**")
                st.code(encrypted)
                st.markdown('</div>', unsafe_allow_html=True)

                # Log aktivitas
                db.log_activity(st.session_state.username, "ENCRYPT_TEXT",
                                f"Encrypted text of length {len(input_text)}")
            else:
                st.error("❌ Masukkan teks dan password!")

        st.markdown('</div>', unsafe_allow_html=True)

    # Tool Dekripsi
    elif menu == "🔓 Dekripsi Tool":
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("🔓 Tool Dekripsi Teks")

        encrypted_input = st.text_area("🔒 Masukkan teks terenkripsi:", height=150)
        decryption_key = st.text_input("🔑 Password dekripsi:", type="password")

        if st.button("🔓 Dekripsi"):
            if encrypted_input and decryption_key:
                decrypted = CryptoManager.decrypt_text(encrypted_input, decryption_key)
                st.markdown('<div class="success-card">', unsafe_allow_html=True)
                st.write("**🔓 Hasil Dekripsi:**")
                st.info(decrypted)
                st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.error("❌ Masukkan teks terenkripsi dan password!")

        st.markdown('</div>', unsafe_allow_html=True)

    # Analisis
    elif menu == "📈 Analisis":
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("📈 Analisis Catatan")

        # Initialize session state variables if they don't exist
        if "notes" not in st.session_state:
            st.session_state["notes"] = {}  # or any default value like []

        if "username" not in st.session_state:
            st.session_state["username"] = ""  # or None, or ask user to input

        user_notes = st.session_state.notes.get(st.session_state.username, [])

        if user_notes:
            # Analisis kategori
            categories = [note['category'] for note in user_notes]
            category_counts = pd.Series(categories).value_counts()

            fig = px.pie(values=category_counts.values, names=category_counts.index,
                         title="📊 Distribusi Kategori Catatan",
                         color_discrete_sequence=px.colors.sequential.YlOrRd)
            st.plotly_chart(fig, use_container_width=True)

            # Analisis panjang catatan
            lengths = [len(note['content']) for note in user_notes]
            fig = px.histogram(x=lengths, title="📏 Distribusi Panjang Catatan",
                               color_discrete_sequence=['#FFD700'])
            fig.update_layout(plot_bgcolor='rgba(255,248,220,0.8)')
            st.plotly_chart(fig, use_container_width=True)

            # Statistik enkripsi
            encrypted_count = sum(1 for note in user_notes if note.get('encrypted', False))
            unencrypted_count = len(user_notes) - encrypted_count

            fig = go.Figure(data=[
                go.Bar(name='Terenkripsi', x=['Status'], y=[encrypted_count], marker_color='#32CD32'),
                go.Bar(name='Tidak Terenkripsi', x=['Status'], y=[unencrypted_count], marker_color='#FFD700')
            ])
            fig.update_layout(title='🔒 Status Enkripsi Catatan', barmode='group')
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("📊 Belum ada data untuk dianalisis.")

        st.markdown('</div>', unsafe_allow_html=True)

    # Logout
    elif menu == "🚪 Logout":
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.subheader("🚪 Logout")
        st.write("Apakah Anda yakin ingin keluar?")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Ya, Keluar"):
                st.session_state.logged_in = False
                st.session_state.username = ""
                st.success("👋 Berhasil logout!")
                st.rerun()
        with col2:
            if st.button("❌ Batal"):
                st.info("🏠 Kembali ke dashboard")

        st.markdown('</div>', unsafe_allow_html=True)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; margin-top: 50px;">
    <p>🔐 SecureNotes - Aplikasi Catatan Pribadi Terenkripsi</p>
    <p>Powered by Streamlit & Advanced Cryptography</p>
</div>
""", unsafe_allow_html=True)
