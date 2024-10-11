import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import bcrypt
import mysql.connector

class LoginApplication:
    def __init__(self, root):
        self.root = root
        self.root.title("User Login")
        self.frm = ttk.Frame(self.root, padding=10)
        self.frm.grid()

        # Create labels and entries for username and password
        ttk.Label(self.frm, text="Username:").grid(column=0, row=0)
        self.username_entry = ttk.Entry(self.frm, width=20)
        self.username_entry.grid(column=1, row=0)

        ttk.Label(self.frm, text="Password:").grid(column=0, row=1)
        self.password_entry = ttk.Entry(self.frm, width=20, show="*")
        self.password_entry.grid(column=1, row=1)

        # Create login button
        self.login_button = ttk.Button(self.frm, text="Login", command=self.check_credentials)
        self.login_button.grid(column=1, row=2)

        # Create quit button
        ttk.Button(self.frm, text="Quit", command=self.root.destroy).grid(column=1, row=3)

        # Initialize database
        self.init_db()

    def init_db(self):
        self.conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="password",
            database="banking"
        )
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username VARCHAR(255) PRIMARY KEY,
                password BLOB
            )
        ''')
        self.conn.commit()

    def check_credentials(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and Password cannot be empty")
            return

        # Fetch hashed password from the database
        stored_hashed_password = self.get_stored_hashed_password(username)

        if stored_hashed_password and bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
            messagebox.showinfo("Success", "Login successful")
        else:
            messagebox.showerror("Error", "Invalid credentials")

    def get_stored_hashed_password(self, username):
        self.cursor.execute('SELECT password FROM users WHERE username = %s', (username,))
        result = self.cursor.fetchone()
        return result[0] if result else None

    def add_user(self, username, password):
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.cursor.execute('INSERT INTO users (username, password) VALUES (%s, %s)', (username, hashed_password))
        self.conn.commit()

root = tk.Tk()
app = LoginApplication(root)

# Add a user to the database
#app.add_user('admin', 'password')

root.mainloop()