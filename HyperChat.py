import tkinter as tk
from tkinter import scrolledtext, font, messagebox
import socket
import threading
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
from PIL import Image, ImageTk
import emoji

class CyberWelatChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberWelat Secure Chat")
        self.root.geometry("900x700")
        self.root.configure(bg="#2c3e50")
        self.root.resizable(True, True)
        
        # Stil ayarları
        self.bg_color = "#2c3e50"
        self.text_bg = "#34495e"
        self.text_fg = "#ecf0f1"
        self.button_bg = "#3498db"
        self.button_active = "#2980b9"
        self.entry_bg = "#bdc3c7"
        
        # Font ayarları
        self.default_font = font.Font(family="Helvetica", size=12)
        self.title_font = font.Font(family="Helvetica", size=14, weight="bold")
        
        # Emoji desteği
        self.emojis = ["😀", "😂", "😍", "😎", "👍", "❤️", "🔥", "🎉"]
        
        self.create_widgets()
        self.client_socket = None
        self.running = False
        self.key = None
        
    def create_widgets(self):
        # Bağlantı çerçevesi
        connection_frame = tk.Frame(self.root, bg=self.bg_color)
        connection_frame.pack(pady=10, padx=10, fill=tk.X)
        
        tk.Label(connection_frame, text="Sunucu IP:", bg=self.bg_color, fg="white", 
                font=self.default_font).grid(row=0, column=0, padx=5)
        self.server_ip = tk.Entry(connection_frame, width=20, font=self.default_font, 
                                bg=self.entry_bg)
        self.server_ip.grid(row=0, column=1, padx=5)
        self.server_ip.insert(0, "3jkyk6cbotfmpsjnmz42fsmeze7ah7tjsfpo6a3mcijvxbqju66wqqyd.onion")
        
        tk.Label(connection_frame, text="Port:", bg=self.bg_color, fg="white", 
                font=self.default_font).grid(row=0, column=2, padx=5)
        self.port = tk.Entry(connection_frame, width=10, font=self.default_font, 
                            bg=self.entry_bg)
        self.port.grid(row=0, column=3, padx=5)
        self.port.insert(0, "5555")
        
        tk.Label(connection_frame, text="Anahtar:", bg=self.bg_color, fg="white", 
                font=self.default_font).grid(row=0, column=4, padx=5)
        self.key_entry = tk.Entry(connection_frame, width=30, font=self.default_font, 
                                 bg=self.entry_bg)
        self.key_entry.grid(row=0, column=5, padx=5)
        
        tk.Label(connection_frame, text="Kullanıcı Adı:", bg=self.bg_color, fg="white", 
                font=self.default_font).grid(row=1, column=0, padx=5, pady=5)
        self.username = tk.Entry(connection_frame, width=20, font=self.default_font, 
                                bg=self.entry_bg)
        self.username.grid(row=1, column=1, padx=5, pady=5)
        
        self.connect_button = tk.Button(connection_frame, text="Bağlan", 
                                      command=self.connect_to_server,
                                      bg=self.button_bg, fg="white",
                                      activebackground=self.button_active,
                                      font=self.default_font)
        self.connect_button.grid(row=1, column=6, padx=10)
        
        # Sohbet alanı
        chat_frame = tk.Frame(self.root, bg=self.bg_color)
        chat_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        self.chat_area = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, 
                                                  width=80, height=25,
                                                  bg=self.text_bg, fg=self.text_fg,
                                                  font=self.default_font)
        self.chat_area.pack(fill=tk.BOTH, expand=True)
        self.chat_area.config(state=tk.DISABLED)
        
        # Mesaj gönderme alanı
        message_frame = tk.Frame(self.root, bg=self.bg_color)
        message_frame.pack(pady=10, padx=10, fill=tk.X)
        
        self.message_entry = tk.Entry(message_frame, width=60, font=self.default_font, 
                                    bg=self.entry_bg)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        
        # Emoji butonları
        emoji_frame = tk.Frame(message_frame, bg=self.bg_color)
        emoji_frame.pack(side=tk.LEFT, padx=5)
        
        for e in self.emojis:
            btn = tk.Button(emoji_frame, text=e, command=lambda em=e: self.insert_emoji(em),
                          bg=self.bg_color, fg="white", borderwidth=0,
                          font=self.default_font)
            btn.pack(side=tk.LEFT, padx=2)
        
        self.send_button = tk.Button(message_frame, text="Gönder", 
                                   command=self.send_message,
                                   bg=self.button_bg, fg="white",
                                   activebackground=self.button_active,
                                   font=self.default_font)
        self.send_button.pack(side=tk.LEFT, padx=5)
        
        # Durum çubuğu
        self.status_bar = tk.Label(self.root, text="Bağlantı bekleniyor...", 
                                 bg="#34495e", fg="white", anchor=tk.W,
                                 font=self.default_font)
        self.status_bar.pack(fill=tk.X, padx=10, pady=5)
        
        # Geliştirici bilgisi
        dev_label = tk.Label(self.root, text="CyberWelat © 2023 - Secure Chat", 
                           bg=self.bg_color, fg="#7f8c8d",
                           font=("Helvetica", 8))
        dev_label.pack(side=tk.BOTTOM, pady=5)
    
    def insert_emoji(self, emoji_char):
        self.message_entry.insert(tk.END, emoji_char)
        self.message_entry.focus()
    
    def connect_to_server(self):
        if self.running:
            return
            
        server_ip = self.server_ip.get()
        port = int(self.port.get())
        username = self.username.get()
        key = self.key_entry.get()
        
        if not all([server_ip, port, username, key]):
            messagebox.showerror("Hata", "Lütfen tüm alanları doldurun!")
            return
            
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_ip, port))
            self.running = True
            
            self.key = base64.b64decode(key)
            self.username_str = username
            
            # Kullanıcı adını gönder
            encrypted_nick = self.encrypt_message(username)
            self.client_socket.send(encrypted_nick.encode())
            
            # Sunucudan gelen ilk mesajı oku
            response = self.client_socket.recv(1024).decode()
            response_msg = self.decrypt_message(response)
            
            if response_msg and response_msg.startswith("HATA"):
                messagebox.showerror("Hata", response_msg)
                self.client_socket.close()
                return
                
            self.update_chat("Sistem", f"Sunucuya bağlandınız: {server_ip}:{port}")
            self.status_bar.config(text=f"Bağlı: {server_ip}:{port} | Kullanıcı: {username}")
            
            # Mesaj alma thread'ini başlat
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
        except Exception as e:
            messagebox.showerror("Bağlantı Hatası", f"Sunucuya bağlanılamadı: {str(e)}")
            self.status_bar.config(text="Bağlantı hatası!")
    
    def encrypt_message(self, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()
    
    def decrypt_message(self, encrypted):
        try:
            data = base64.b64decode(encrypted)
            iv, ciphertext = data[:16], data[16:]
            cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            return (decryptor.update(ciphertext) + decryptor.finalize()).decode()
        except:
            return None
    
    def receive_messages(self):
        while self.running:
            try:
                encrypted_msg = self.client_socket.recv(1024).decode()
                if not encrypted_msg:
                    break
                    
                message = self.decrypt_message(encrypted_msg)
                if message:
                    # Mesaj formatı: "Kullanıcı: Mesaj"
                    if ": " in message:
                        user, msg = message.split(": ", 1)
                        self.update_chat(user, msg)
                    else:
                        self.update_chat("Sistem", message)
                        
            except Exception as e:
                self.update_chat("Sistem", f"Bağlantı hatası: {str(e)}")
                self.running = False
                break
    
    def send_message(self):
        if not self.running:
            messagebox.showwarning("Uyarı", "Sunucuya bağlı değilsiniz!")
            return
            
        message = self.message_entry.get()
        if not message:
            return
            
        try:
            encrypted_msg = self.encrypt_message(message)
            self.client_socket.send(encrypted_msg.encode())
            self.update_chat("Sen", message, is_me=True)
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            self.update_chat("Sistem", f"Mesaj gönderilemedi: {str(e)}")
            self.running = False
    
    def update_chat(self, sender, message, is_me=False):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        
        self.chat_area.config(state=tk.NORMAL)
        
        if sender == "Sistem":
            self.chat_area.insert(tk.END, f"[{now}] ", "system_time")
            self.chat_area.insert(tk.END, f"{message}\n", "system_msg")
        elif is_me:
            self.chat_area.insert(tk.END, f"[{now}] ", "my_time")
            self.chat_area.insert(tk.END, f"Sen: {message}\n", "my_msg")
        else:
            self.chat_area.insert(tk.END, f"[{now}] ", "other_time")
            self.chat_area.insert(tk.END, f"{sender}: {message}\n", "other_msg")
            
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.see(tk.END)
    
    def on_closing(self):
        if self.running:
            self.running = False
            self.client_socket.close()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    
    # Özel tag'ler için stil ayarları
    root.option_add("*Font", "Helvetica 12")
    
    # Renkli mesajlar için tag'ler
    text_styles = {
        "system_time": {"foreground": "#95a5a6", "font": ("Helvetica", 10)},
        "system_msg": {"foreground": "#95a5a6", "font": ("Helvetica", 10, "italic")},
        "my_time": {"foreground": "#3498db", "font": ("Helvetica", 10)},
        "my_msg": {"foreground": "#3498db", "font": ("Helvetica", 12)},
        "other_time": {"foreground": "#2ecc71", "font": ("Helvetica", 10)},
        "other_msg": {"foreground": "#ecf0f1", "font": ("Helvetica", 12)}
    }
    
    client = CyberWelatChatClient(root)
    root.protocol("WM_DELETE_WINDOW", client.on_closing)
    root.mainloop()
