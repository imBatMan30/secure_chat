import tkinter as tk
from tkinter import messagebox, scrolledtext
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
from auth import login_user, register_user, reset_password, verify_security_answer
from messaging import get_users, set_conversation_key, verify_conversation_key, send_message, get_messages
from database import delete_user, delete_messages

class SecureMessagingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Messaging App")
        self.root.geometry("800x600")
        
        self.style = ttkb.Style("flatly")
        
        self.current_user = None
        self.private_key = None
        self.selected_user = None
        self.conversation_key = None
        
        self.create_login_frame()
    
    def create_login_frame(self):
        """Create the login frame with themed widgets"""
        self.login_frame = ttkb.Frame(self.root, padding=20)
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        ttkb.Label(
            self.login_frame,
            text="Secure Messaging App",
            font=("Arial", 18, "bold"),
            bootstyle="primary"
        ).pack(pady=10)
        ttkb.Label(
            self.login_frame,
            text="Login or Register (Use Gmail ID)",
            font=("Arial", 12),
            bootstyle="secondary"
        ).pack(pady=5)
        
        ttkb.Label(self.login_frame, text="Gmail ID:", bootstyle="default").pack(anchor=tk.W, pady=(10, 0))
        self.username_var = tk.StringVar()
        ttkb.Entry(
            self.login_frame,
            textvariable=self.username_var,
            width=30,
            bootstyle="info"
        ).pack(fill=tk.X, pady=(0, 10))
        
        ttkb.Label(self.login_frame, text="Password:", bootstyle="default").pack(anchor=tk.W, pady=(0, 0))
        self.password_var = tk.StringVar()
        ttkb.Entry(
            self.login_frame,
            textvariable=self.password_var,
            show="*",
            width=30,
            bootstyle="info"
        ).pack(fill=tk.X, pady=(0, 10))
        
        button_frame = ttkb.Frame(self.login_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttkb.Button(
            button_frame,
            text="Login",
            command=self.login,
            bootstyle="primary"
        ).pack(side=tk.LEFT, padx=5)
        ttkb.Button(
            button_frame,
            text="Register",
            command=self.show_register_dialog,
            bootstyle="success"
        ).pack(side=tk.LEFT, padx=5)
        ttkb.Button(
            button_frame,
            text="Delete User",
            command=self.delete_user_action,
            bootstyle="danger"
        ).pack(side=tk.LEFT, padx=5)
        ttkb.Button(
            button_frame,
            text="Forgot Password",
            command=self.show_forgot_password_dialog,
            bootstyle="warning"
        ).pack(side=tk.LEFT, padx=5)
    
    def show_register_dialog(self):
        """Show dialog for registration with security question"""
        from encryption import is_valid_gmail
        if not is_valid_gmail(self.username_var.get()):
            messagebox.showerror("Error", "Please enter a valid Gmail ID (e.g., user@gmail.com)")
            return
        
        register_dialog = tk.Toplevel(self.root)
        register_dialog.title("Register")
        register_dialog.geometry("400x400")
        register_dialog.transient(self.root)
        register_dialog.grab_set()
        
        ttkb.Label(register_dialog, text="Register New User", font=("Arial", 14, "bold"), bootstyle="primary").pack(pady=10)
        
        ttkb.Label(register_dialog, text="Gmail ID:", bootstyle="default").pack(anchor=tk.W, padx=10)
        username_entry = ttkb.Entry(register_dialog, textvariable=self.username_var, width=30, bootstyle="info")
        username_entry.pack(fill=tk.X, padx=10, pady=5)
        username_entry.config(state='readonly')
        
        ttkb.Label(register_dialog, text="Password:", bootstyle="default").pack(anchor=tk.W, padx=10)
        password_var = tk.StringVar()
        ttkb.Entry(register_dialog, textvariable=password_var, show="*", width=30, bootstyle="info").pack(fill=tk.X, padx=10, pady=5)
        
        ttkb.Label(register_dialog, text="Security Question:", bootstyle="default").pack(anchor=tk.W, padx=10)
        security_question_var = tk.StringVar()
        security_question_combobox = ttkb.Combobox(
            register_dialog,
            textvariable=security_question_var,
            values=[
                "What is your mother's maiden name?",
                "What was the name of your first pet?",
                "What is your favorite book?",
                "Where were you born?"
            ],
            state="readonly",
            bootstyle="info"
        )
        security_question_combobox.pack(fill=tk.X, padx=10, pady=5)
        security_question_combobox.current(0)
        
        ttkb.Label(register_dialog, text="Security Answer:", bootstyle="default").pack(anchor=tk.W, padx=10)
        security_answer_var = tk.StringVar()
        ttkb.Entry(register_dialog, textvariable=security_answer_var, show="*", width=30, bootstyle="info").pack(fill=tk.X, padx=10, pady=5)
        
        def submit_registration():
            password = password_var.get()
            security_question = security_question_var.get()
            security_answer = security_answer_var.get()
            
            if not password or not security_question or not security_answer:
                messagebox.showerror("Error", "All fields are required")
                return
            
            result = register_user(self.username_var.get(), password, security_question, security_answer)
            if result['success']:
                messagebox.showinfo("Success", result['message'])
                register_dialog.destroy()
                self.username_var.set("")
                self.password_var.set("")
            else:
                messagebox.showerror("Error", result['message'])
        
        ttkb.Button(
            register_dialog,
            text="Submit",
            command=submit_registration,
            bootstyle="success"
        ).pack(pady=20)
    
    def show_forgot_password_dialog(self):
        """Show dialog for password reset"""
        forgot_dialog = tk.Toplevel(self.root)
        forgot_dialog.title("Forgot Password")
        forgot_dialog.geometry("400x400")
        forgot_dialog.transient(self.root)
        forgot_dialog.grab_set()
        
        ttkb.Label(forgot_dialog, text="Reset Password", font=("Arial", 14, "bold"), bootstyle="primary").pack(pady=10)
        
        ttkb.Label(forgot_dialog, text="Gmail ID:", bootstyle="default").pack(anchor=tk.W, padx=10)
        username_var = tk.StringVar()
        ttkb.Entry(forgot_dialog, textvariable=username_var, width=30, bootstyle="info").pack(fill=tk.X, padx=10, pady=5)
        
        ttkb.Label(forgot_dialog, text="Security Question:", bootstyle="default").pack(anchor=tk.W, padx=10)
        security_question_label = ttkb.Label(forgot_dialog, text="Enter Gmail ID to see question", bootstyle="secondary")
        security_question_label.pack(anchor=tk.W, padx=10, pady=5)
        
        ttkb.Label(forgot_dialog, text="Security Answer:", bootstyle="default").pack(anchor=tk.W, padx=10)
        security_answer_var = tk.StringVar()
        ttkb.Entry(forgot_dialog, textvariable=security_answer_var, show="*", width=30, bootstyle="info").pack(fill=tk.X, padx=10, pady=5)
        
        ttkb.Label(forgot_dialog, text="New Password:", bootstyle="default").pack(anchor=tk.W, padx=10)
        new_password_var = tk.StringVar()
        ttkb.Entry(forgot_dialog, textvariable=new_password_var, show="*", width=30, bootstyle="info").pack(fill=tk.X, padx=10, pady=5)
        
        def verify_and_update_question():
            username = username_var.get()
            from encryption import is_valid_gmail
            if not is_valid_gmail(username):
                messagebox.showerror("Error", "Please enter a valid Gmail ID")
                return
            result = verify_security_answer(username, "")
            security_question_label.config(text=result['security_question'] or "User not found")
        
        def submit_reset():
            username = username_var.get()
            security_answer = security_answer_var.get()
            new_password = new_password_var.get()
            
            if not username or not security_answer or not new_password:
                messagebox.showerror("Error", "All fields are required")
                return
            result = reset_password(username, new_password, security_answer)
            if result['success']:
                messagebox.showinfo("Success", result['message'])
                forgot_dialog.destroy()
            else:
                messagebox.showerror("Error", result['message'])
        
        ttkb.Button(
            forgot_dialog,
            text="Check Question",
            command=verify_and_update_question,
            bootstyle="info"
        ).pack(pady=5)
        ttkb.Button(
            forgot_dialog,
            text="Reset Password",
            command=submit_reset,
            bootstyle="success"
        ).pack(pady=10)
    
    def create_main_frame(self):
        """Create the main application frame with themed widgets"""
        self.login_frame.destroy()
        
        self.main_frame = ttkb.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        title_frame = ttkb.Frame(self.main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttkb.Label(
            title_frame,
            text="Secure Messaging",
            font=("Arial", 16, "bold"),
            bootstyle="primary"
        ).pack(side=tk.LEFT)
        ttkb.Label(
            title_frame,
            text=f"Logged in as: {self.current_user['username']}",
            font=("Arial", 10),
            bootstyle="info"
        ).pack(side=tk.RIGHT)
        
        paned_window = ttkb.PanedWindow(self.main_frame, orient=tk.HORIZONTAL, bootstyle="primary")
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        users_frame = ttkb.Frame(paned_window, padding=10)
        paned_window.add(users_frame, weight=1)
        
        ttkb.Label(
            users_frame,
            text="Users",
            font=("Arial", 12, "bold"),
            bootstyle="primary"
        ).pack(anchor=tk.W)
        
        self.users_listbox = ttkb.Treeview(
            users_frame,
            columns=("Username",),
            show="headings",
            height=20,
            bootstyle="info"
        )
        self.users_listbox.heading("Username", text="Username")
        self.users_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        self.users_listbox.bind('<<TreeviewSelect>>', self.on_user_select)
        
        ttkb.Button(
            users_frame,
            text="Refresh Users",
            command=self.load_users,
            bootstyle="info-outline"
        ).pack(fill=tk.X, pady=5)
        
        chat_frame = ttkb.Frame(paned_window, padding=10)
        paned_window.add(chat_frame, weight=3)
        
        self.chat_header = ttkb.Label(
            chat_frame,
            text="Select a user to start chatting",
            font=("Arial", 12, "bold"),
            bootstyle="primary"
        )
        self.chat_header.pack(anchor=tk.W, pady=(0, 5))
        
        self.key_frame = ttkb.Frame(chat_frame)
        self.key_frame.pack(fill=tk.X, pady=5)
        
        ttkb.Label(
            self.key_frame,
            text="Conversation Key:",
            bootstyle="default"
        ).pack(side=tk.LEFT)
        self.key_var = tk.StringVar()
        self.key_entry = ttkb.Entry(
            self.key_frame,
            textvariable=self.key_var,
            show="*",
            bootstyle="info"
        )
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttkb.Button(
            self.key_frame,
            text="Set Key",
            command=self.set_key,
            bootstyle="primary"
        ).pack(side=tk.LEFT)
        ttkb.Button(
            self.key_frame,
            text="Delete Chat",
            command=self.delete_chat,
            bootstyle="danger-outline"
        ).pack(side=tk.LEFT, padx=5)
        
        self.messages_text = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            height=15,
            state=tk.DISABLED,
            font=("Arial", 10)
        )
        self.messages_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        ttkb.Label(
            chat_frame,
            text="Message:",
            bootstyle="default"
        ).pack(anchor=tk.W)
        self.message_var = tk.StringVar()
        self.message_entry = ttkb.Entry(
            chat_frame,
            textvariable=self.message_var,
            bootstyle="info"
        )
        self.message_entry.pack(fill=tk.X, pady=5)
        
        ttkb.Button(
            chat_frame,
            text="Send Message",
            command=self.send_message,
            bootstyle="success"
        ).pack(anchor=tk.E, pady=5)
        
        ttkb.Button(
            self.main_frame,
            text="Logout",
            command=self.logout,
            bootstyle="danger-outline"
        ).pack(anchor=tk.E, pady=10)
        
        self.load_users()
    
    def delete_user_action(self):
        """Delete the current user from login screen"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        from encryption import is_valid_gmail
        if not is_valid_gmail(username):
            messagebox.showerror("Error", "Please enter a valid Gmail ID")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter password")
            return
        
        login_result = login_user(username, password)
        
        if not login_result['success']:
            messagebox.showerror("Error", login_result['message'])
            return
            
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete user {username}?")
        if confirm:
            result = delete_user(login_result['user_id'])
            if result['success']:
                messagebox.showinfo("Success", result['message'])
                self.username_var.set("")
                self.password_var.set("")
            else:
                messagebox.showerror("Error", result['message'])
    
    def delete_chat(self):
        """Delete conversation with selected user"""
        if not self.current_user or not self.selected_user:
            messagebox.showerror("Error", "Please select a user first")
            return
            
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to delete chat with {self.selected_user['username']}?")
        if confirm:
            result = delete_messages(self.current_user['user_id'], self.selected_user['id'])
            if result['success']:
                messagebox.showinfo("Success", result['message'])
                self.load_messages()
            else:
                messagebox.showerror("Error", result['message'])
    
    def login(self):
        """Login a user"""
        username = self.username_var.get()
        password = self.password_var.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter Gmail ID and password")
            return
        
        result = login_user(username, password)
        
        if result['success']:
            self.current_user = result
            self.private_key = result['private_key']
            messagebox.showinfo("Success", result['message'])
            self.create_main_frame()
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

def main():
    from database import create_database
    create_database()
    root = ttkb.Window(themename="flatly")
    app = SecureMessagingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()