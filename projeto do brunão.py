import tkinter as tk
from tkinter import messagebox
from pymongo import MongoClient
from cryptography.fernet import Fernet
import hashlib
import time


MONGO_URI = "mongodb+srv://Arthur:brunaosigma@cluster0.lo8iz.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
DB_NAME = "projetoBD"
COLLECTION_NAME = "pagamentos"


def load_or_generate_key():
    try:
        
        with open("key.key", "rb") as key_file:
            print("Chave carregada com sucesso.")
            return key_file.read()
    except FileNotFoundError:
        
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        print("Nova chave gerada e salva.")
        return key


key = load_or_generate_key()
cipher = Fernet(key)


client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]


def encrypt_card_data(card_number, cvv, expiry_date):
    card_info = f"{card_number}|{cvv}|{expiry_date}"
    encrypted_data = cipher.encrypt(card_info.encode())
    print(f"Dados criptografados: {encrypted_data}")
    return encrypted_data


def decrypt_card_data(encrypted_data):
    try:
        decrypted_data = cipher.decrypt(encrypted_data).decode()
        card_number, cvv, expiry_date = decrypted_data.split('|')
        print(f"Dados descriptografados: {decrypted_data}")
        return {
            "card_number": card_number,
            "cvv": cvv,
            "expiry_date": expiry_date
        }
    except Exception as e:
        print(f"Erro ao descriptografar dados: {e}")
        messagebox.showerror("Erro", "Falha ao descriptografar os dados. Verifique a chave de criptografia.")
        return None


def generate_transaction_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


def validate_card_info(card_number, cvv, expiry_date):
    if not card_number.isdigit() or len(card_number) != 16:
        messagebox.showwarning("Erro", "O número do cartão deve conter exatamente 16 dígitos numéricos.")
        return False
    if not cvv.isdigit() or len(cvv) != 3:
        messagebox.showwarning("Erro", "O CVV deve conter exatamente 3 dígitos numéricos.")
        return False
    if len(expiry_date) != 5 or expiry_date[2] != '/':
        messagebox.showwarning("Erro", "A data de validade deve estar no formato MM/AA.")
        return False

    month, year = expiry_date.split('/')
    if not (month.isdigit() and year.isdigit()) or not (1 <= int(month) <= 12):
        messagebox.showwarning("Erro", "O mês deve estar entre 01 e 12 e o ano deve ser numérico.")
        return False
    return True


def process_payment():
    card_number = entry_card_number.get()
    cvv = entry_cvv.get()
    expiry_date = entry_expiry_date.get()

    if not validate_card_info(card_number, cvv, expiry_date):
        return

    encrypted_card_data = encrypt_card_data(card_number, cvv, expiry_date)

    transaction_data = f"{card_number}{cvv}{expiry_date}{time.time()}"
    transaction_hash = generate_transaction_hash(transaction_data)
    token = Fernet.generate_key().decode()

    transaction_record = {
        "encrypted_data": encrypted_card_data.decode('utf-8'), 
        "transaction_hash": transaction_hash,
        "token": token,
        "timestamp": time.time()
    }

    result = collection.insert_one(transaction_record)
    if result.inserted_id:
        print(f"Documento inserido com sucesso! ID: {result.inserted_id}")
        messagebox.showinfo("Sucesso", "Transação processada e armazenada com sucesso.")
        entry_card_number.delete(0, tk.END)
        entry_cvv.delete(0, tk.END)
        entry_expiry_date.delete(0, tk.END)
    else:
        messagebox.showerror("Erro", "Falha ao armazenar a transação.")


def show_transaction_history():
    transactions = collection.find()
    history = []
    for txn in transactions:
        encrypted_data = txn["encrypted_data"].encode('utf-8')
        decrypted_data = decrypt_card_data(encrypted_data)
        if decrypted_data:
            history.append(f"Cartão: {decrypted_data['card_number']} | Expira: {decrypted_data['expiry_date']} | Hash: {txn['transaction_hash']}")
    messagebox.showinfo("Histórico de Transações", "\n".join(history) if history else "Nenhuma transação encontrada.")


root = tk.Tk()
root.title("Sistema de Pagamentos Seguro")

label_info = tk.Label(root, text="Insira os dados do cartão para processar o pagamento", font=("Arial", 12))
label_info.pack(pady=10)

label_card_number = tk.Label(root, text="Número do Cartão:")
label_card_number.pack()
entry_card_number = tk.Entry(root)
entry_card_number.pack(pady=5)

label_cvv = tk.Label(root, text="CVV:")
label_cvv.pack()
entry_cvv = tk.Entry(root, show="*")
entry_cvv.pack(pady=5)

label_expiry_date = tk.Label(root, text="Data de Validade (MM/AA):")
label_expiry_date.pack()
entry_expiry_date = tk.Entry(root)
entry_expiry_date.pack(pady=5)

process_button = tk.Button(root, text="Processar Pagamento", command=process_payment)
process_button.pack(pady=10)

history_button = tk.Button(root, text="Ver Histórico de Transações", command=show_transaction_history)
history_button.pack(pady=10)

root.mainloop()