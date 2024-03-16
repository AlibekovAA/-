import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from typing import Any, Dict, Optional

from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID


class KeyManager:
    def __init__(self) -> None:
        self.users: Dict[str, Dict[str, Any]] = {}

    def add_user(self, username: str, private_key: str, public_key: str, certificate: str) -> None:
        if username not in self.users:
            self.users[username] = {'private_key': private_key, 'public_key': public_key, 'certificate': certificate}
        else:
            messagebox.showwarning("Предупреждение", f"Пользователь {username} уже существует.")

    def remove_user(self, username: str) -> None:
        if username in self.users:
            del self.users[username]
            messagebox.showinfo("Успех", f"Пользователь {username} успешно удален.")
        else:
            messagebox.showwarning("Предупреждение", f"Пользователь {username} не найден.")

    def get_key(self, username: str) -> Optional[str]:
        return self.users[username]['private_key'] if username in self.users else None

    def get_certificate(self, username: str) -> Optional[str]:
        return self.users[username]['certificate'] if username in self.users else None

    def set_certificate(self, username: str, certificate: str) -> None:
        if username in self.users:
            self.users[username]['certificate'] = certificate
        else:
            messagebox.showwarning("Предупреждение", f"Пользователь {username} не найден.")


class DocumentExchangeApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Приложение для обмена документами")
        self.key_manager = KeyManager()
        self.create_widgets()
        self.center_window()

    def center_window(self) -> None:
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        window_width = self.root.winfo_reqwidth()
        window_height = self.root.winfo_reqheight()

        coordinate_x = (screen_width - window_width - 300) // 2
        coordinate_y = (screen_height - window_height - 350) // 2

        self.root.geometry(f"+{coordinate_x}+{coordinate_y}")

    def create_widgets(self) -> None:
        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(side=tk.TOP, fill=tk.X)

        self.save_document_button = tk.Button(self.button_frame, text="Сохранить документ", command=self.save_document)
        self.save_document_button.pack(side=tk.RIGHT)

        self.load_document_button = tk.Button(self.button_frame, text="Загрузить документ", command=self.load_document)
        self.load_document_button.pack(side=tk.RIGHT)

        self.create_document_button = tk.Button(self.button_frame, text="Создать документ", command=self.create_document)
        self.create_document_button.pack(side=tk.RIGHT)

        self.select_certificate_button = tk.Button(self.button_frame, text="Выбрать сертификат", command=self.select_certificate)
        self.select_certificate_button.pack(side=tk.RIGHT)

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
        self.keys_menu.add_command(label="Удалить", command=self.delete_user)
        self.keys_menu.add_command(label="Выбрать", command=self.select_certificate)

        self.menu_bar.add_cascade(label="Файл", menu=self.file_menu)
        self.menu_bar.add_cascade(label="Управление пользователями", menu=self.keys_menu)

        self.root.config(menu=self.menu_bar)

    def run(self) -> None:
        self.root.mainloop()

    def block_username_entry(self, event: tk.Event = None) -> None:
        self.username_entry.config(state=tk.DISABLED)

    def create_document(self) -> None:
        self.document_text.delete(1.0, tk.END)
        self.root.title("Подписанный документ")

    def save_document(self) -> None:
        document_content = self.document_text.get(1.0, tk.END).encode('utf-8')
        if not document_content.strip():
            messagebox.showwarning("Предупреждение", "Документ пустой. Нечего сохранять.")
            return

        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Предупреждение", "Введите имя пользователя.")
            return

        certificate = self.key_manager.get_certificate(username)
        if certificate is None:
            messagebox.showwarning("Предупреждение", "Выберите сертификат пользователя.")
            return

        private_key = self.key_manager.get_key(username)
        if private_key is None:
            messagebox.showwarning("Предупреждение", "Приватный ключ пользователя не найден.")
            return

        hasher = SHA1.new()
        hasher.update(document_content)

        rsa_private_key = RSA.import_key(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

        signature = pkcs1_15.new(rsa_private_key).sign(hasher)

        if filename := filedialog.asksaveasfilename(
            defaultextension=".sd",
            filetypes=[("Signed documents", "*.sd")],
            title="Сохранить документ как",
        ):
            with open(filename, "wb") as file:
                self._extracted_from_save_document(
                    certificate, file, signature, document_content
                )
            messagebox.showinfo("Сохранение документа", f"Документ успешно сохранен как {filename}")

    def _extracted_from_save_document(self, certificate: str, filename: str, signature: str, document_content: str) -> None:
        certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)
        filename.write(len(certificate_bytes).to_bytes(4, 'big'))
        filename.write(len(signature).to_bytes(4, 'big'))
        filename.write(certificate_bytes)
        filename.write(signature)
        filename.write(document_content)

    def load_document(self) -> None:
        filename = filedialog.askopenfilename(
            filetypes=[("Signed documents", "*.sd")],
            title="Выберите файл для загрузки"
        )

        if not filename:
            return

        try:
            with open(filename, "rb") as file:
                certificate_length = int.from_bytes(file.read(4), 'big')
                signature_length = int.from_bytes(file.read(4), 'big')
                certificate_bytes = file.read(certificate_length)
                signature = file.read(signature_length)
                document_content = file.read().decode('utf-8')

            certificate = load_pem_x509_certificate(certificate_bytes, default_backend())

            owner_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

            if owner_name not in self.key_manager.users:
                messagebox.showwarning("Предупреждение", "Сертификат пользователя не найден.")
                return

            public_key = self.key_manager.users[owner_name]['public_key']
            rsa_public_key = RSA.import_key(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
            hasher = SHA1.new()
            hasher.update(document_content.encode('utf-8'))
            try:
                pkcs1_15.new(rsa_public_key).verify(hasher, signature)
            except ValueError:
                messagebox.showerror("Ошибка", "Подпись документа неверна.")
                return

            self.document_text.delete(1.0, tk.END)
            self.document_text.insert(tk.END, document_content)
            self.root.title(f"Подписанный документ - {owner_name}")

        except FileNotFoundError:
            messagebox.showerror("Ошибка", "Файл не найден.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при загрузке документа: {str(e)}")

    def about_program(self) -> None:
        messagebox.showinfo("О программе", "Автор: Алибеков Аслан\nГруппа: А-13а-20\nВариант: 22")

    def select_certificate(self) -> None:
        self.document_text.delete(1.0, tk.END)
        if filename := filedialog.askopenfilename(
            title="Выберите сертификат", filetypes=[("Certificate files", "*.pfx")]
        ):
            try:
                password = simpledialog.askstring("Введите пароль", "Введите пароль для сертификата:", show='*')
                if password is None:
                    messagebox.showerror("Ошибка", "Пароль для сертификата не введен.")
                    return

                with open(filename, "rb") as f:
                    (private_key, cert, _) = pkcs12.load_key_and_certificates(
                        f.read(), password.encode())

                owner_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                public_key = private_key.public_key()

                self.key_manager.add_user(owner_name, private_key, public_key, cert)

                self.username_entry.config(state=tk.NORMAL)
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, owner_name)
                self.username_entry.config(state=tk.DISABLED)

            except ValueError:
                messagebox.showerror("Ошибка", "Неверный пароль для сертификата.")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка при загрузке сертификата: {str(e)}")

    def delete_user(self) -> None:
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Предупреждение", "Введите имя пользователя.")
            return
        try:
            self.key_manager.remove_user(username)
            messagebox.showinfo("Удаление пользователя", f"Пользователь {username} успешно удален.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось удалить пользователя: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DocumentExchangeApp(root)
    app.run()
