import tkinter as tk
from PIL import ImageTk, Image
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import secrets
from Crypto.Random import get_random_bytes
root = tk.Tk()
root.title("Cryptography")
class Win1:

    def __init__(self, master):
        self.master = master
        self.master.geometry("580x640+10+10")
        self.img = ImageTk.PhotoImage(Image.open("AESencryptALgo/crypt.jpeg").resize((580, 260)))
        self.l0 = tk.Label(self.master, text='Encryption using simple AES cipher', font=("times", 24, "bold"), bg='blue',
                      fg='white')
        self.l0.pack(side="top", fill="both", expand="yes")
        self.panel = tk.Label(self.master, image=self.img)
        self.panel.pack(side="top", fill="both", expand="yes")
        self.frame = tk.Frame(self.master)
        self.l1 = tk.Label(self.master,text='Protect your valuable data from hackers by encryption',font=("times",16,"bold"),fg='blue')
        self.l1.pack()
        self.butnew("Click to Encrypt",  Win2)
        self.butnew("Click to Decrypt",  Win3)
        self.frame.pack(expand="true")


    def butnew(self, text, _class):
        tk.Button(self.frame, text=text,command=lambda: self.new_window( _class),width=15,height=3,font=("times",14,"bold"), bg="purple",fg="yellow").pack(side="left",padx=15)

    def new_window(self,  _class):
        self.new = tk.Toplevel(self.master)
        _class(self.new)

secret_key = get_random_bytes(16) 
class Win2:
    BLOCK_SIZE = 16

    def encrypts(self):
        message = self.t1.get("1.0", tk.END)
        message = message.strip()
        pass_phrase = self.tkey.get().encode()
        pp = self.tkey.get()
        private_key = hashlib.sha256(pp.encode("utf-8")).digest()
        cipher = AES.new(private_key, AES.MODE_CBC, self.iv)
        padded_message = pad(message.encode("utf-8"), self.BLOCK_SIZE)
        cipher_text = cipher.encrypt(padded_message)
        ciphertext_with_iv = self.iv + cipher_text
        cptxt = base64.b64encode(ciphertext_with_iv)

        self.t2.delete('1.0', tk.END)
        self.t2.insert("1.0", cptxt)


    def __init__(self, master):
        self.master = master
        self.master.geometry("550x500+470+150")
        self.master.title("Encrypt your data")
        self.master.configure(background="palegreen")
        self.frame = tk.Frame(self.master,borderwidth=2)
        self.l1 = tk.Label(self.master, text='Plain Text (Text to Encrypt)',font=("times", 16, "bold"),bg="palegreen", fg='red2')
        self.l1.pack(expand="yes")
        self.t1 = tk.Text(self.master, height=5, width=40, borderwidth=1,relief="solid")
        self.t1.pack(expand="yes")

        self.lkey = tk.Label(self.master, text='Secret key', font=("times", 16, "bold"), bg="palegreen", fg='red2')
        self.lkey.pack(expand="yes")
        self.tkey = tk.Entry(self.master, width=55,show="*", borderwidth=1, relief="solid")
        self.tkey.pack(expand="yes")

        self.b1 = tk.Button(self.master,text="Encrypt",command=self.encrypts,font=("times", 16, "bold"),bg="maroon",fg="white",width=10)
        self.b1.pack(expand="yes")
        self.l2 = tk.Label(self.master, text='Cipher Text (Encrypted Text)', font=("times", 16, "bold"),bg="palegreen", fg='red2')
        self.l2.pack(expand="yes")
        self.t2 = tk.Text(self.master, height=8, width=40, borderwidth=1, relief="solid",state="normal")
        self.t2.pack(expand="yes")
        self.quit = tk.Button(self.frame, text="Close", command=self.close_window,font=("times", 16, "bold"),bg="maroon",fg="white",width=10)
        self.quit.pack()
        self.frame.pack(expand="true")
        self.iv = Random.new().read(AES.block_size)

    def close_window(self):
        self.master.destroy()


class Win3:
    BLOCK_SIZE = 16

    def decrypts(self):
        ciphertext = base64.b64decode(self.t1.get("1.0", tk.END))
        pp = self.tkey.get()
        private_key = hashlib.sha256(pp.encode("utf-8")).digest()
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(ciphertext[AES.block_size:]), self.BLOCK_SIZE).decode("utf-8")

        self.t2.delete('1.0', tk.END)
        self.t2.insert("1.0", decrypted_text)


    def __init__(self, master):
        self.master = master
        self.master.geometry("550x500+900+150")
        self.master.title("Decrypt your data")
        self.master.configure(background="pink")
        self.frame = tk.Frame(self.master, borderwidth=2)
        self.l1 = tk.Label(self.master, text='Cipher Text (Encrypted data)', font=("times", 16, "bold"), bg="pink",fg='blue')
        self.l1.pack(expand="yes")
        self.t1 = tk.Text(self.master, height=8, width=40, borderwidth=1, relief="solid")
        self.t1.pack(expand="yes")

        self.lkey = tk.Label(self.master, text='Secret key', font=("times", 16, "bold"), bg="pink", fg='blue')
        self.lkey.pack(expand="yes")
        self.tkey = tk.Entry(self.master, width=55, show="*", borderwidth=1, relief="solid")
        self.tkey.pack(expand="yes")

        self.b1 = tk.Button(self.master, text="Decrypt", command=self.decrypts, font=("times", 16, "bold"), bg="blue",
                            fg="white", width=10)
        self.b1.pack(expand="yes")
        self.l2 = tk.Label(self.master, text='Plain Text(Original message)', font=("times", 16, "bold"), bg="pink",
                           fg='blue')
        self.l2.pack(expand="yes")
        self.t2 = tk.Text(self.master, height=5, width=40, borderwidth=1, relief="solid", state="normal")
        self.t2.pack(expand="yes")
        self.quit = tk.Button(self.frame, text="Close", command=self.close_window, font=("times", 16, "bold"),
                              bg="blue", fg="white", width=10)
        self.quit.pack()
        self.frame.pack(expand="true")

    def close_window(self):
        self.master.destroy()


app = Win1(root)
root.mainloop()
