import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json
import base64

class SecureChatServer:
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()
        self.clients = {}
        self.rooms = {'main': set()}
        
        # AES için anahtar ve IV oluştur
        self.key = os.urandom(32)  # 256-bit key
        print(f"Sunucu {self.host}:{self.port} adresinde çalışıyor...")
        print(f"Sunucu anahtarı (istemcilerle paylaşılmalı): {base64.b64encode(self.key).decode()}")

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

    def broadcast(self, room, message, sender_nick):
        encrypted_msg = self.encrypt_message(f"{sender_nick}: {message}")
        for client in self.rooms[room]:
            if client != sender_nick:
                self.clients[client].send(encrypted_msg.encode())

    def handle_client(self, client, address):
        nick = None
        try:
            # İlk mesaj kullanıcı adı olmalı
            initial_data = client.recv(1024).decode()
            nick = self.decrypt_message(initial_data)
            
            if not nick or nick in self.clients:
                error_msg = self.encrypt_message("HATA: Bu kullanıcı adı zaten alınmış veya geçersiz!")
                client.send(error_msg.encode())
                client.close()
                return
                
            self.clients[nick] = client
            self.rooms['main'].add(nick)
            print(f"{nick} sunucuya bağlandı.")
            
            welcome_msg = self.encrypt_message(f"Sunucu: {nick} olarak 'main' odasına katıldınız!")
            client.send(welcome_msg.encode())
            
            join_msg = self.encrypt_message(f"Sunucu: {nick} odaya katıldı!")
            self.broadcast('main', join_msg, "Sunucu")
            
            while True:
                try:
                    encrypted_msg = client.recv(1024).decode()
                    if not encrypted_msg:
                        break
                        
                    message = self.decrypt_message(encrypted_msg)
                    if not message:
                        continue
                        
                    print(f"{nick}: {message}")
                    self.broadcast('main', message, nick)
                    
                except Exception as e:
                    print(f"{nick} ile iletişim hatası: {e}")
                    break
                    
        except Exception as e:
            print(f"{address} bağlantı hatası: {e}")
            
        finally:
            if nick:
                if nick in self.clients:
                    del self.clients[nick]
                if nick in self.rooms['main']:
                    self.rooms['main'].remove(nick)
                    
                leave_msg = self.encrypt_message(f"Sunucu: {nick} odadan ayrıldı!")
                self.broadcast('main', leave_msg, "Sunucu")
                print(f"{nick} sunucudan ayrıldı.")
                
            client.close()

    def run(self):
        while True:
            client, address = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(client, address))
            thread.start()

if __name__ == "__main__":
    server = SecureChatServer()
    server.run()