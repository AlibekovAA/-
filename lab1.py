import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA512
from Crypto.PublicKey import RSA
from ecdsa import SigningKey, SECP256k1
import os

class KeyManager:
    def __init__(self):
        self.users = {}

    def add_user(self, username):
        if username not in self.users:
            self.users[username] = {'private_key': None, 'public_key': None, 'imported_keys': {}, 'public_key_ecdsa': {}}
            messagebox.showinfo("Успех", f"Пользователь {username} успешно добавлен.")
        else:
            messagebox.showwarning("Предупреждение", f"Пользователь {username} уже существует.")

    def add_key(self, username):
        try:
            private_key = RSA.generate(2048)
            public_key = private_key.publickey()
            if username in self.users:
                self.users[username]['private_key'] = private_key
                self.users[username]['public_key'] = public_key
            else:
                messagebox.showwarning("Предупреждение", f"Пользователь {username} не найден.")
                return False
            return True
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось создать ключи: {str(e)}")
            return False

    def remove_key(self, username):
        if username in self.users:
            del self.users[username]
        else:
            messagebox.showwarning("Предупреждение", f"Пользователь {username} не найден.")

    def import_public_key(self, username):
        if username not in self.users:
            self.add_user(username)
            self.add_key(username)
        filetypes = [ 
            ("Public_key_file", "*.pub")]
        try:
            filename = filedialog.askopenfilename(filetypes=filetypes, 
                                                    title="Выберите файл с открытым ключом",  
                                                    initialdir="C:\\Users\\aslan\\Рабочий стол\\ЗД\\lab1")
            if not filename:
                messagebox.showwarning("Предупреждение", "Не выбран файл для импорта.")
                return

            with open(filename, "rb") as file:
                owner_name_length = int.from_bytes(file.read(2), 'big')
                public_key_length = int.from_bytes(file.read(2), 'big')
                owner_name = file.read(owner_name_length).decode()
                public_key_blob = file.read(public_key_length)

                signing_key = SigningKey.generate(curve=SECP256k1)
                self.users[username]['public_key_ecdsa'][owner_name] = signing_key.verifying_key
                hashed_public_key = SHA512.new(public_key_blob)
                signature = signing_key.sign(hashed_public_key.digest())

                if not os.path.isdir("PK"):
                    os.mkdir(f"PK")
                if not os.path.isdir(f"PK\\{username}"):
                    os.mkdir(f"PK\\{username}")
                save_directory = f"C:\\Users\\aslan\\Рабочий стол\\ЗД\\lab1\\PK\\{username}"
                filename = filedialog.asksaveasfilename(defaultextension=".pub", 
                                                        title="Выберите место для сохранения подписанного ключа", 
                                                        initialdir=save_directory)
                if filename:
                    owner_name = owner_name.encode()

                    with open(filename, "wb") as file:
                        owner_name_length = len(owner_name).to_bytes(2, 'big')
                        public_key_length = len(public_key_blob).to_bytes(2, 'big')

                        file.write(owner_name_length)
                        file.write(public_key_length)
                        file.write(owner_name)
                        file.write(public_key_blob)
                        file.write(signature)
                            
                    messagebox.showinfo("Успех", f"Публичный ключ от {owner_name} успешно импортирован для пользователя {username}.")
                    messagebox.showinfo("Успех", f"Подписанный ключ от {username} успешно сохранен в файле: {filename}.")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")

    def export_public_key(self, username):
        if username in self.users:
            public_key = self.users[username]['public_key']
            if public_key:
                try:
                    filename = filedialog.asksaveasfilename(defaultextension=".pub", 
                                                            title="Выберите место для экспорта открытого ключа", 
                                                            initialfile=f"{username}.pub")
                    if filename:
                        owner_name = username.encode()
                        owner_name_length = len(owner_name).to_bytes(2, 'big')

                        public_key_blob = public_key.exportKey(format='PEM')
                        public_key_blob_length = len(public_key_blob).to_bytes(2, 'big')

                        with open(filename, "wb") as file:
                            file.write(owner_name_length)
                            file.write(public_key_blob_length)
                            file.write(owner_name)
                            file.write(public_key_blob)
                        messagebox.showinfo("Информация", f"Открытый ключ успешно экспортирован в файл: {filename}")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Не удалось экспортировать открытый ключ: {str(e)}")
            else:
                messagebox.showwarning("Предупреждение", f"Открытый ключ пользователя {username} не найден.")
        else:
            messagebox.showwarning("Предупреждение", f"Пользователь {username} не найден.")

    def get_key(self, username):
        if username in self.users:
            return self.users[username]['public_key']
        else:
            return None
        
class DocumentSigning:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def sign_document(self, document, private_key):
        hasher = SHA256.new()
        hasher.update(document.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(hasher)
        return signature

class DocumentExchangeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Приложение для обмена документами")
        self.key_manager = KeyManager()
        self.document_signing = DocumentSigning()
        self.create_widgets()

    def create_widgets(self):
        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(side=tk.TOP, fill=tk.X)

        self.save_document_button = tk.Button(self.button_frame, text="Сохранить документ", command=self.save_document)
        self.save_document_button.pack(side=tk.RIGHT)

        self.load_document_button = tk.Button(self.button_frame, text="Загрузить документ", command=self.load_document)
        self.load_document_button.pack(side=tk.RIGHT)

        self.create_document_button = tk.Button(self.button_frame, text="Создать документ", command=self.create_document)
        self.create_document_button.pack(side=tk.RIGHT)

        self.select_user_button = tk.Button(self.button_frame, text="Выбрать пользователя", command=self.select_user)
        self.select_user_button.pack(side=tk.RIGHT)

        self.username_label = tk.Label(self.button_frame, text="Имя пользователя:")
        self.username_label.pack(side=tk.TOP)

        self.username_entry = tk.Entry(self.button_frame, state='disabled')
        self.username_entry.pack(side=tk.TOP)
        self.username_entry.bind("<Return>", self.block_username_entry)

        self.document_text = tk.Text(self.root)
        self.document_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.menu_bar = tk.Menu(self.root)

        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.file_menu.add_command(label="Создать", command=self.create_document)
        self.file_menu.add_command(label="Сохранить", command=self.save_document)
        self.file_menu.add_command(label="Загрузить", command=self.load_document)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="О программе", command=self.about_program)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Выход", command=self.root.quit)

        self.keys_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.keys_menu.add_command(label="Экспорт открытого ключа", 
                                   command=lambda: self.key_manager.export_public_key(self.username_entry.get().strip()))
        self.keys_menu.add_command(label="Импорт открытого ключа",
                                   command=lambda: self.key_manager.import_public_key(self.username_entry.get().strip()))
        self.keys_menu.add_separator()
        self.keys_menu.add_command(label="Удаление пары ключей", command=self.delete_key_pair)
        self.keys_menu.add_command(label="Выбор закрытого ключа", command=self.select_private_key)

        self.menu_bar.add_cascade(label="Файл", menu=self.file_menu)
        self.menu_bar.add_cascade(label="Управление ключами", menu=self.keys_menu)

        self.root.config(menu=self.menu_bar)

    def run(self):
        self.root.mainloop()

    def select_user(self):
        self.document_text.delete(1.0, tk.END)
        self.username_entry.config(state=tk.NORMAL)
        self.username_entry.delete(0, tk.END)
        self.username_entry.focus_set()

    def block_username_entry(self, event=None):
        self.username_entry.config(state=tk.DISABLED)

    def create_document(self):
        self.document_text.delete(1.0, tk.END)
        self.root.title("Подписанный документ")

    def save_document(self):
        document_content = self.document_text.get(1.0, tk.END)
        if not document_content.strip():
            messagebox.showwarning("Предупреждение", "Документ пустой. Нечего сохранять.")
            return

        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Предупреждение", "Введите имя пользователя.")
            return

        if not self.key_manager.get_key(username):
            self.key_manager.add_user(username)
            self.key_manager.add_key(username)

        private_key_pair = self.key_manager.users[username]['private_key']
        signature = self.document_signing.sign_document(document_content, private_key_pair)

        filename = filedialog.asksaveasfilename(defaultextension=".sd", filetypes=[("Signed documents", "*.sd")], 
                                                title="Сохранить документ как",
                                                initialdir="C:\\Users\\aslan\\Рабочий стол\\ЗД\\lab1")
        if filename:
            with open(filename, "wb") as file:
                file.write(len(username).to_bytes(2, 'big'))
                file.write(len(signature).to_bytes(2, 'big'))
                file.write(username.encode())
                file.write(signature)
                file.write(document_content.encode())

            messagebox.showinfo("Сохранение документа", f"Документ успешно сохранен как {filename}")

    def load_document(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Предупреждение", "Введите имя пользователя.")
            return

        filename = filedialog.askopenfilename(
            filetypes=[("Signed documents", "*.sd")],
            title="Выберите файл для загрузки",
            initialdir="C:\\Users\\aslan\\Рабочий стол\\ЗД\\lab1"
        )

        if not filename:
            return

        try:
            with open(filename, "rb") as file:
                username_length = int.from_bytes(file.read(2), 'big')
                signature_length = int.from_bytes(file.read(2), 'big')
                loaded_username = file.read(username_length).decode()
                signature = file.read(signature_length)
                document_content = file.read().decode()

            user_directory = f"PK\\{username}"

            if not os.path.exists(user_directory) or not os.listdir(user_directory):
                messagebox.showerror("Ошибка", "Папке-хранилище с публичными ключами пуста или не существует.")
                return

            for key_filename in os.listdir(user_directory):
                if key_filename.endswith(".pub"):
                    with open(os.path.join(user_directory, key_filename), "rb") as key_file:
                        key_username_length = int.from_bytes(key_file.read(2), 'big')
                        key_public_length = int.from_bytes(key_file.read(2), 'big')
                        key_username = key_file.read(key_username_length).decode('utf-8')
                        key_content = key_file.read(key_public_length)
                        key_signature = key_file.read()

                    if loaded_username == key_username:
                        public_key_ecdsa = self.key_manager.users[username]['public_key_ecdsa'][key_username]
                        key_hash = SHA512.new(key_content)
                        break
            else:
                messagebox.showerror("Ошибка", "Папке-хранилище с публичными ключами пуста или не существует.")
                return

            public_key_ecdsa.verify(key_signature, key_hash.digest())
            hashed_document = SHA256.new(document_content.encode('utf-8'))
            imported_public_key = RSA.import_key(key_content)
            pkcs1_15.new(imported_public_key).verify(hashed_document, signature)

            self.document_text.delete(1.0, tk.END)
            self.document_text.insert(tk.END, document_content)
            self.root.title(f"Подписанный документ - {loaded_username}")

        except FileNotFoundError:
            messagebox.showerror("Ошибка", "Файл не найден.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при проверке подписи ключа: {str(e)}")

    def about_program(self):
        messagebox.showinfo("О программе", "Автор: Алибеков Аслан\nГруппа: А-13а-20\nВариант: 22")

    def delete_key_pair(self):
        container_name = self.username_entry.get().strip()
        if container_name:
            self.key_manager.remove_key(container_name)
            self.username_entry.config(state=tk.NORMAL)
            self.username_entry.delete(0, tk.END)
            self.username_entry.config(state=tk.DISABLED)
            self.document_text.delete(1.0, tk.END)
            messagebox.showinfo("Удаление ключей", "Пара ключей успешно удалена.")
        else:
            messagebox.showwarning("Предупреждение", "Введите имя пользователя.")

    def select_private_key(self):
        self.username_entry.config(state=tk.NORMAL)
        self.username_entry.focus_set()

        def block_username_entry(event=None):
            self.username_entry.config(state=tk.DISABLED)

        self.username_entry.bind("<Return>", block_username_entry)
        
if __name__ == "__main__":
    root = tk.Tk()
    app = DocumentExchangeApp(root)
    app.run()
