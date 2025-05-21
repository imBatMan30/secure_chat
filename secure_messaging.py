import tkinter as tk
from tkinter import messagebox, scrolledtext
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import mysql.connector
import os
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# =============================================
# DATABASE FUNCTIONS
# =============================================

def create_database():
    """Create the database and tables if they don't exist"""
    try:
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host="localhost",
            user="kuldeep",
            password="kuldeep30" 
        )
        
        cursor = connection.cursor()
        
        # Create database
        cursor.execute("CREATE DATABASE IF NOT EXISTS secure_messaging")
        print("Database created successfully")
        
        # Use the database
        cursor.execute("USE secure_messaging")
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                public_key TEXT NOT NULL,
                private_key_encrypted TEXT NOT NULL
            )
        """)
        
        # Create messages table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                sender_id INT NOT NULL,
                receiver_id INT NOT NULL,
                encrypted_message TEXT NOT NULL,
                encrypted_aes_key TEXT NOT NULL,
                iv VARCHAR(255) NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        """)
        
        # Create conversation keys table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS conversation_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user1_id INT NOT NULL,
                user2_id INT NOT NULL,
                key_hash VARCHAR(255) NOT NULL,
                FOREIGN KEY (user1_id) REFERENCES users(id),
                FOREIGN KEY (user2_id) REFERENCES users(id),
                UNIQUE KEY unique_conversation (user1_id, user2_id)
            )
        """)
        
        print("Tables created successfully")
        
    except mysql.connector.Error as e:
        print(f"Database Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

def get_db_connection():
    """Get a connection to the database"""
    return mysql.connector.connect(
        host="localhost",
        user="kuldeep",
        password="kuldeep30",  
        database="secure_messaging"
    )

# =============================================
# ENCRYPTION FUNCTIONS
# =============================================

def generate_rsa_key_pair():
    """Generate a new RSA key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

def encrypt_private_key(private_key_pem, password):
    """Encrypt the private key with a password"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    )
    
    return encrypted_pem.decode('utf-8')

def decrypt_private_key(encrypted_private_key_pem, password):
    """Decrypt the private key with a password"""
    try:
        private_key = serialization.load_pem_private_key(
            encrypted_private_key_pem.encode('utf-8'),
            password=password.encode('utf-8'),
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        print(f"Error decrypting private key: {e}")
        return None

def load_public_key(public_key_pem):
    """Load a public key from PEM format"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    return public_key

def generate_aes_key():
    """Generate a random AES key"""
    return os.urandom(32)  # 256-bit key

def encrypt_with_rsa(public_key, data):
    """Encrypt data with RSA public key"""
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_with_rsa(private_key, encrypted_data):
    """Decrypt data with RSA private key"""
    if isinstance(encrypted_data, str):
        encrypted_data = base64.b64decode(encrypted_data)
        
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def encrypt_with_aes(key, data):
    """Encrypt data with AES key"""
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padded_data = data + b'\0' * (16 - len(data) % 16)
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return {
        'encrypted': base64.b64encode(encrypted_data).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

def decrypt_with_aes(key, encrypted_data, iv):
    """Decrypt data with AES key"""
    if isinstance(encrypted_data, str):
        encrypted_data = base64.b64decode(encrypted_data)
    if isinstance(iv, str):
        iv = base64.b64decode(iv)
        
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    return decrypted_data.rstrip(b'\0')

# =============================================
# USER AUTHENTICATION FUNCTIONS
# =============================================

def hash_password(password):
    """Hash a password with salt"""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.hex() + ':' + key.hex()

def verify_password(stored_password, provided_password):
    """Verify a password against its hash"""
    salt, key = stored_password.split(':')
    salt = bytes.fromhex(salt)
    key = bytes.fromhex(key)
    new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return key == new_key

def register_user(username, password):
    """Register a new user"""
    try:
        password_hash = hash_password(password)
        private_key, public_key = generate_rsa_key_pair()
        encrypted_private_key = encrypt_private_key(private_key, password)
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        query = """
            INSERT INTO users (username, password_hash, public_key, private_key_encrypted)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (username, password_hash, public_key, encrypted_private_key))
        connection.commit()
        
        user_id = cursor.lastrowid
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'user_id': user_id,
            'message': f"User {username} registered successfully"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

def login_user(username, password):
    """Login a user"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not user:
            return {
                'success': False,
                'message': "User not found"
            }
        
        if not verify_password(user['password_hash'], password):
            return {
                'success': False,
                'message': "Incorrect password"
            }
        
        private_key = decrypt_private_key(
            user['private_key_encrypted'],
            password
        )
        
        if not private_key:
            return {
                'success': False,
                'message': "Failed to decrypt private key"
            }
        
        return {
            'success': True,
            'user_id': user['id'],
            'username': user['username'],
            'public_key': user['public_key'],
            'private_key': private_key,
            'message': "Login successful"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

# =============================================
# CONVERSATION KEY FUNCTIONS
# =============================================

def set_conversation_key(user1_id, user2_id, key):
    """Set a conversation key between two users"""
    try:
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id
            
        key_hash = hash_password(key)
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        query = """
            SELECT id FROM conversation_keys
            WHERE user1_id = %s AND user2_id = %s
        """
        cursor.execute(query, (user1_id, user2_id))
        existing_key = cursor.fetchone()
        
        if existing_key:
            query = """
                UPDATE conversation_keys
                SET key_hash = %s
                WHERE user1_id = %s AND user2_id = %s
            """
            cursor.execute(query, (key_hash, user1_id, user2_id))
        else:
            query = """
                INSERT INTO conversation_keys (user1_id, user2_id, key_hash)
                VALUES (%s, %s, %s)
            """
            cursor.execute(query, (user1_id, user2_id, key_hash))
            
        connection.commit()
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'message': "Conversation key set successfully"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

def verify_conversation_key(user1_id, user2_id, key):
    """Verify a conversation key between two users"""
    try:
        if user1_id > user2_id:
            user1_id, user2_id = user2_id, user1_id
            
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = """
            SELECT key_hash FROM conversation_keys
            WHERE user1_id = %s AND user2_id = %s
        """
        cursor.execute(query, (user1_id, user2_id))
        result = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not result:
            return {
                'success': False,
                'message': "No conversation key found"
            }
        
        if verify_password(result['key_hash'], key):
            return {
                'success': True,
                'message': "Conversation key verified successfully"
            }
        else:
            return {
                'success': False,
                'message': "Invalid conversation key"
            }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

# =============================================
# MESSAGE FUNCTIONS
# =============================================

def get_users(current_user_id):
    """Get all users except the current user"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT id, username FROM users WHERE id != %s"
        cursor.execute(query, (current_user_id,))
        users = cursor.fetchall()
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'users': users,
            'message': f"Retrieved {len(users)} users"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

def get_user_public_key(username):
    """Get a user's public key and ID"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT id, public_key FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not user:
            return {
                'success': False,
                'message': "User not found"
            }
        
        return {
            'success': True,
            'user_id': user['id'],
            'public_key': user['public_key'],
            'message': "Public key retrieved successfully"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

def send_message(sender_id, receiver_username, message, private_key):
    """Send an encrypted message to a user"""
    try:
        receiver_result = get_user_public_key(receiver_username)
        
        if not receiver_result['success']:
            return receiver_result
        
        receiver_id = receiver_result['user_id']
        receiver_public_key = load_public_key(receiver_result['public_key'])
        
        aes_key = generate_aes_key()
        
        encrypted_message = encrypt_with_aes(aes_key, message)
        
        encrypted_aes_key = encrypt_with_rsa(receiver_public_key, aes_key)
        
        connection = get_db_connection()
        cursor = connection.cursor()
        
        query = """
            INSERT INTO messages (sender_id, receiver_id, encrypted_message, encrypted_aes_key, iv)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (
            sender_id,
            receiver_id,
            encrypted_message['encrypted'],
            encrypted_aes_key,
            encrypted_message['iv']
        ))
        connection.commit()
        
        message_id = cursor.lastrowid
        
        cursor.close()
        connection.close()
        
        return {
            'success': True,
            'message_id': message_id,
            'message': f"Message sent to {receiver_username} successfully"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

def get_messages(user_id, private_key, other_user_id=None):
    """Get all messages for a user"""
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        
        query = """
            SELECT m.id, m.sender_id, m.receiver_id, m.encrypted_message, m.encrypted_aes_key, m.iv, m.timestamp,
                   u.username as sender_username
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.receiver_id = %s OR m.sender_id = %s)
        """
        params = [user_id, user_id]
        
        if other_user_id:
            query += " AND (m.sender_id = %s OR m.receiver_id = %s)"
            params.extend([other_user_id, other_user_id])
            
        query += " ORDER BY m.timestamp DESC"
        
        cursor.execute(query, params)
        encrypted_messages = cursor.fetchall()
        
        cursor.close()
        connection.close()
        
        decrypted_messages = []
        for msg in encrypted_messages:
            try:
                if msg['receiver_id'] == user_id:
                    encrypted_aes_key = base64.b64decode(msg['encrypted_aes_key'])
                    aes_key = decrypt_with_rsa(private_key, encrypted_aes_key)
                    
                    decrypted_message = decrypt_with_aes(
                        aes_key,
                        msg['encrypted_message'],
                        msg['iv']
                    ).decode('utf-8')
                    
                    decrypted_messages.append({
                        'id': msg['id'],
                        'sender_id': msg['sender_id'],
                        'receiver_id': msg['receiver_id'],
                        'sender_username': msg['sender_username'],
                        'message': decrypted_message,
                        'timestamp': msg['timestamp']
                    })
                else:
                    decrypted_messages.append({
                        'id': msg['id'],
                        'sender_id': msg['sender_id'],
                        'receiver_id': msg['receiver_id'],
                        'sender_username': msg['sender_username'],
                        'message': "[Message sent by you]",
                        'timestamp': msg['timestamp']
                    })
            except Exception as e:
                print(f"Error decrypting message {msg['id']}: {e}")
        
        return {
            'success': True,
            'messages': decrypted_messages,
            'message': f"Retrieved {len(decrypted_messages)} messages"
        }
        
    except mysql.connector.Error as e:
        return {
            'success': False,
            'message': f"Database error: {e}"
        }
    except Exception as e:
        return {
            'success': False,
            'message': f"Error: {e}"
        }

# =============================================
# TKINTER APPLICATION
# =============================================

class SecureMessagingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messaging App")
        self.root.geometry("800x600")
        
        # Apply ttkbootstrap theme
        self.style = ttk.Style("flatly")
        
        self.current_user = None
        self.private_key = None
        self.selected_user = None
        self.conversation_key = None
        
        self.create_login_frame()
    
    def create_login_frame(self):
        """Create the login frame with themed widgets"""
        self.login_frame = ttk.Frame(self.root, padding=20)
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(
            self.login_frame,
            text="Secure Messaging App",
            font=("Arial", 18, "bold"),
            bootstyle="primary"
        ).pack(pady=10)
        ttk.Label(
            self.login_frame,
            text="Login or Register",
            font=("Arial", 12),
            bootstyle="secondary"
        ).pack(pady=5)
        
        ttk.Label(self.login_frame, text="Username:", bootstyle="default").pack(anchor=tk.W, pady=(10, 0))
        self.username_var = tk.StringVar()
        ttk.Entry(
            self.login_frame,
            textvariable=self.username_var,
            width=30,
            bootstyle="info"
        ).pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(self.login_frame, text="Password:", bootstyle="default").pack(anchor=tk.W, pady=(0, 0))
        self.password_var = tk.StringVar()
        ttk.Entry(
            self.login_frame,
            textvariable=self.password_var,
            show="*",
            width=30,
            bootstyle="info"
        ).pack(fill=tk.X, pady=(0, 10))
        
        button_frame = ttk.Frame(self.login_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            button_frame,
            text="Login",
            command=self.login,
            bootstyle="primary"
        ).pack(side=tk.LEFT, padx=5)
        ttk.Button(
            button_frame,
            text="Register",
            command=self.register,
            bootstyle="success"
        ).pack(side=tk.LEFT, padx=5)
    
    def create_main_frame(self):
        """Create the main application frame with themed widgets"""
        self.login_frame.destroy()
        
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_frame = ttk.Frame(self.main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(
            title_frame,
            text="Secure Messaging",
            font=("Arial", 16, "bold"),
            bootstyle="primary"
        ).pack(side=tk.LEFT)
        ttk.Label(
            title_frame,
            text=f"Logged in as: {self.current_user['username']}",
            font=("Arial", 10),
            bootstyle="info"
        ).pack(side=tk.RIGHT)
        
        paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL, bootstyle="primary")
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        users_frame = ttk.Frame(paned_window, padding=10)
        paned_window.add(users_frame, weight=1)
        
        ttk.Label(
            users_frame,
            text="Users",
            font=("Arial", 12, "bold"),
            bootstyle="primary"
        ).pack(anchor=tk.W)
        
        self.users_listbox = ttk.Treeview(
            users_frame,
            columns=("Username",),
            show="headings",
            height=20,
            bootstyle="info"
        )
        self.users_listbox.heading("Username", text="Username")
        self.users_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        self.users_listbox.bind('<<TreeviewSelect>>', self.on_user_select)
        
        ttk.Button(
            users_frame,
            text="Refresh Users",
            command=self.load_users,
            bootstyle="info-outline"
        ).pack(fill=tk.X, pady=5)
        
        chat_frame = ttk.Frame(paned_window, padding=10)
        paned_window.add(chat_frame, weight=3)
        
        self.chat_header = ttk.Label(
            chat_frame,
            text="Select a user to start chatting",
            font=("Arial", 12, "bold"),
            bootstyle="primary"
        )
        self.chat_header.pack(anchor=tk.W, pady=(0, 5))
        
        self.key_frame = ttk.Frame(chat_frame)
        self.key_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(
            self.key_frame,
            text="Conversation Key:",
            bootstyle="default"
        ).pack(side=tk.LEFT)
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(
            self.key_frame,
            textvariable=self.key_var,
            show="*",
            bootstyle="info"
        )
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(
            self.key_frame,
            text="Set Key",
            command=self.set_key,
            bootstyle="primary"
        ).pack(side=tk.LEFT)
        
        self.messages_text = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            height=15,
            state=tk.DISABLED,
            font=("Arial", 10)
        )
        self.messages_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttk.Label(
            chat_frame,
            text="Message:",
            bootstyle="default"
        ).pack(anchor=tk.W)
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(
            chat_frame,
            textvariable=self.message_var,
            bootstyle="info"
        )
        self.message_entry.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            chat_frame,
            text="Send Message",
            command=self.send_message,
            bootstyle="success"
        ).pack(anchor=tk.E, pady=5)
        
        ttk.Button(
            self.main_frame,
            text="Logout",
            command=self.logout,
            bootstyle="danger-outline"
        ).pack(anchor=tk.E, pady=10)
        
        self.load_users()
    
    def login(self):
        """Login a user"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        result = login_user(username, password)
        
        if result['success']:
            self.current_user = result
            self.private_key = result['private_key']
            messagebox.showinfo("Success", result['message'])
            self.create_main_frame()
        else:
            messagebox.showerror("Error", result['message'])
    
    def register(self):
        """Register a new user"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        result = register_user(username, password)
        
        if result['success']:
            messagebox.showinfo("Success", result['message'])
        else:
            messagebox.showerror("Error", result['message'])
    
    def logout(self):
        """Logout the current user"""
        self.current_user = None
        self.private_key = None
        self.selected_user = None
        self.conversation_key = None
        
        self.main_frame.destroy()
        
        self.create_login_frame()
    
    def load_users(self):
        """Load all users into Treeview"""
        if not self.current_user:
            return
        
        result = get_users(self.current_user['user_id'])
        
        if result['success']:
            for item in self.users_listbox.get_children():
                self.users_listbox.delete(item)
            
            self.users_data = {}
            for user in result['users']:
                self.users_listbox.insert("", tk.END, values=(user['username'],))
                self.users_data[user['username']] = user
        else:
            messagebox.showerror("Error", result['message'])
    
    def on_user_select(self, event):
        """Handle user selection from Treeview"""
        if not self.users_listbox.selection():
            return
        
        selected_item = self.users_listbox.selection()[0]
        username = self.users_listbox.item(selected_item, "values")[0]
        
        self.selected_user = self.users_data[username]
        self.chat_header.config(text=f"Chat with {username}")
        
        self.conversation_key = None
        self.key_var.set("")
        
        self.messages_text.config(state=tk.NORMAL)
        self.messages_text.delete(1.0, tk.END)
        self.messages_text.insert(tk.END, "Enter the conversation key to view messages\n")
        self.messages_text.config(state=tk.DISABLED)
    
    def set_key(self):
        """Set the conversation key"""
        if not self.current_user or not self.selected_user:
            messagebox.showerror("Error", "Please select a user first")
            return
        
        key = self.key_var.get()
        
        if not key:
            messagebox.showerror("Error", "Please enter a conversation key")
            return
        
        result = verify_conversation_key(
            self.current_user['user_id'],
            self.selected_user['id'],
            key
        )
        
        if result['success']:
            self.conversation_key = key
            self.load_messages()
        else:
            response = messagebox.askyesno(
                "Conversation Key",
                "This conversation key doesn't exist. Would you like to set it?"
            )
            
            if response:
                result = set_conversation_key(
                    self.current_user['user_id'],
                    self.selected_user['id'],
                    key
                )
                
                if result['success']:
                    self.conversation_key = key
                    messagebox.showinfo("Success", "Conversation key set successfully")
                    self.messages_text.config(state=tk.NORMAL)
                    self.messages_text.delete(1.0, tk.END)
                    self.messages_text.insert(tk.END, "Conversation started with new key. No previous messages.\n")
                    self.messages_text.config(state=tk.DISABLED)
                else:
                    messagebox.showerror("Error", result['message'])
    
    def load_messages(self):
        """Load messages for the selected user"""
        if not self.current_user or not self.selected_user or not self.conversation_key:
            return
        
        result = get_messages(
            self.current_user['user_id'],
            self.private_key,
            self.selected_user['id']
        )
        
        if result['success']:
            self.messages_text.config(state=tk.NORMAL)
            self.messages_text.delete(1.0, tk.END)
            
            if not result['messages']:
                self.messages_text.insert(tk.END, "No messages in this conversation yet.\n")
            else:
                sorted_messages = sorted(result['messages'], key=lambda x: x['timestamp'])
                
                for msg in sorted_messages:
                    timestamp = msg['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
                    sender = "You" if msg['sender_id'] == self.current_user['user_id'] else msg['sender_username']
                    self.messages_text.insert(tk.END, f"[{timestamp}] {sender}: {msg['message']}\n\n")
            
            self.messages_text.config(state=tk.DISABLED)
        else:
            messagebox.showerror("Error", result['message'])
    
    def send_message(self):
        """Send a message to the selected user"""
        if not self.current_user or not self.selected_user:
            messagebox.showerror("Error", "Please select a user to send a message to")
            return
        
        if not self.conversation_key:
            messagebox.showerror("Error", "Please set a conversation key first")
            return
        
        message = self.message_var.get()
        
        if not message:
            messagebox.showerror("Error", "Please enter a message")
            return
        
        result = send_message(
            self.current_user['user_id'],
            self.selected_user['username'],
            message,
            self.private_key
        )
        
        if result['success']:
            self.message_var.set("")
            messagebox.showinfo("Success", result['message'])
            self.load_messages()
        else:
            messagebox.showerror("Error", result['message'])

# =============================================
# MAIN APPLICATION
# =============================================

def main():
    create_database()
    root = ttk.Window(themename="flatly")
    app = SecureMessagingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()