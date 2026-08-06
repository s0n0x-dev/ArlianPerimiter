#GNU GPL v3
import os
import sqlite3
import secrets
import base64
import sys
import re
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ========== CORE: ШИФРОВАНИЕ И МАСКИРОВКА (GCM EDITION) ==========

class LegacyEngineGCM:
    def __init__(self, key: str, salt: bytes):
        # PBKDF2 для генерации 32-байтного ключа
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        self.key = kdf.derive(key.encode())
        self.aesgcm = AESGCM(self.key)
        
        self.junk_start = "$%72874-+$7$68$+-38$("
        # Твой фирменный мусор
        self.punjabi = ["ਟਰੈਫਿਕ", "ਦੇ", "ਲਾਲਚ", "ਨੂੰ", "ਮੈਂ", "ਮਾਂ", "ਚੁਗ", "ਲਿਆ"]
        self.noise = ["iejisue", "лвлалал", "dvdalalashk", "kladalsch", "shshkklad"]
        self.all_junk = self.punjabi + self.noise

    def encrypt(self, data: str) -> str:
        """AES-GCM + Babel Wrapper"""
        # GCM требует 12-байтный nonce
        nonce = os.urandom(12)
        # Шифруем (тег аутентификации добавляется в конец автоматически)
        ciphertext = self.aesgcm.encrypt(nonce, data.encode(), None)
        
        # Склеиваем nonce + ciphertext для передачи
        full_payload = nonce + ciphertext
        b64_str = base64.b64encode(full_payload).decode()
        
        # Маскировка с использованием secrets (крипто-стойкий рандом)
        result = self.junk_start
        for char in b64_str:
            result += char
            # 25% шанс вставить мусор после каждого символа для усложнения паттерна
            if secrets.randbelow(100) < 25:
                result += secrets.choice(self.all_junk)
        return result

    def decrypt(self, masked_data: str) -> str:
        """Снятие маскировки и GCM-дешифровка с проверкой целостности"""
        try:
            # Чистим мусор через регулярку
            clean_pattern = '|'.join(map(re.escape, self.all_junk))
            b64_cleaned = re.sub(clean_pattern, '', masked_data.replace(self.junk_start, ''))
            
            full_payload = base64.b64decode(b64_cleaned)
            
            # Извлекаем nonce и данные
            nonce = full_payload[:12]
            ciphertext = full_payload[12:]
            
            # Дешифровка (автоматически проверяет тег аутентификации)
            decrypted_data = self.aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_data.decode()
        except Exception:
            raise ValueError("!!! КРИТИЧЕСКАЯ ОШИБКА: Ключ неверен или данные были модифицированы !!!")

# ========== DATABASE: ХРАНЕНИЕ И ЗАЧИСТКА ==========

class LegacyDB:
    def __init__(self):
        self.db_name = "legacymac_vault.db"
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute('CREATE TABLE IF NOT EXISTS config (param TEXT, value BLOB)')
        self.cursor.execute('CREATE TABLE IF NOT EXISTS logs (id INTEGER PRIMARY KEY, tag TEXT, data TEXT, time TEXT)')
        self.conn.commit()

    def get_salt(self):
        self.cursor.execute("SELECT value FROM config WHERE param = 'salt'")
        row = self.cursor.fetchone()
        if row: return row[0]
        
        new_salt = os.urandom(16)
        self.cursor.execute("INSERT INTO config (param, value) VALUES ('salt', ?)", (new_salt,))
        self.conn.commit()
        return new_salt

    def wipe_all(self):
        """Тройная перезапись с принудительным сбросом кэша (os.fsync)"""
        if not os.path.exists(self.db_name): return
        size = os.path.getsize(self.db_name)
        self.conn.close()
        
        with open(self.db_name, "br+") as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno()) # Важный момент для SSD
        os.remove(self.db_name)

# ========== ТЕРМИНАЛ: УПРАВЛЕНИЕ ==========

def main():
    # Цвета
    RED, GREEN, YELLOW, END = "\033[91m", "\033[92m", "\033[93m", "\033[0m"

    db = LegacyDB()
    salt = db.get_salt()
    
    print(f"{RED}{'='*50}\n LegacyMac 1.3 | AES-GCM SECURED\n{'='*50}{END}")
    
    master_key = input("[?] Введите мастер-ключ: ")
    engine = LegacyEngineGCM(master_key, salt)
    del master_key # Удаляем пароль из памяти

    while True:
        print(f"\n[{GREEN}MENU{END}]: 1:Зашифровать | 2:Расшифровать | 3:SHRED | 4:Выход")
        cmd = input(">> ")

        if cmd == "1":
            text = input("Текст: ")
            masked = engine.encrypt(text)
            db.cursor.execute("INSERT INTO logs (tag, data, time) VALUES ('SESS', ?, ?)", 
                               (masked, datetime.now().strftime("%H:%M")))
            db.conn.commit()
            print(f"\n{YELLOW}Результат (маскировка):{END}\n{masked}")

        elif cmd == "2":
            masked_input = input("Введите данные для дешифровки: ")
            try:
                decrypted = engine.decrypt(masked_input)
                print(f"\n{GREEN}[✓] Расшифровано:{END} {decrypted}")
            except Exception as e:
                print(f"\n{RED}{e}{END}")

        elif cmd == "3":
            if input(f"{RED}УНИЧТОЖИТЬ ВСЁ? (y/n): {END}").lower() == 'y':
                db.wipe_all()
                print(f"{RED}[!!!] База данных уничтожена.{END}")
                del engine.key
                break

        elif cmd == "4":
            del engine.key
            print("Выход.")
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)

