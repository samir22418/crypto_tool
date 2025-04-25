import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64
import hashlib

# -----------------------------------
# Fun, old-school ciphers for the Classical tab
# -----------------------------------
def caesar_cipher(text, shift=3):
    """Shifts each letter in the text by a few spots, like a secret code."""
    return "".join(chr((ord(c) - (65 if c.isupper() else 97) + shift) % 26 + (65 if c.isupper() else 97))
                   if c.isalpha() else c for c in text)

def vigenere_cipher(text, key="crypto"):
    """Uses a keyword to shift letters, making a tougher code."""
    key = key.lower()
    result, key_idx = "", 0
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            shift = ord(key[key_idx % len(key)]) - 97
            result += chr((ord(char) - base + shift) % 26 + base)
            key_idx += 1
        else:
            result += char
    return result

# -----------------------------------
# Main app: A friendly crypto playground
# -----------------------------------
class SamirCryptoTool:
    def __init__(self, window):
        self.window = window
        self.window.title(" Samir Crypto Tool")
        self.window.geometry("700x900")  # Adjusted to match the edited image: narrower and taller
        self.window.configure(bg="#1e1e2e")  # Dark, cozy background
        self.window.resizable(True, True)  # Let users resize the window

        self.setup_look_and_feel()

        # Make the app scrollable so nothing gets hidden
        canvas = tk.Canvas(window, bg="#1e1e2e")
        scrollbar = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
        self.main_area = ttk.Frame(canvas)
        canvas.create_window((0, 0), window=self.main_area, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        self.main_area.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Big, friendly title
        tk.Label(self.main_area, text="Samir's Crypto Toolkit", font=("Montserrat", 26, "bold"),
                 bg="#1e1e2e", fg="#5eead4").pack(pady=15)

        # Tabs for different crypto tools
        self.tab_control = ttk.Notebook(self.main_area)
        self.tab_control.pack(fill="both", expand=True)
        self.setup_tabs()

        # Status bar to show what's happening
        self.status = tk.StringVar(value="Ready to go!")
        ttk.Label(self.main_area, textvariable=self.status, background="#27272a",
                  foreground="#a1a1aa", padding=5, relief="sunken").pack(fill="x", pady=10)

        # Keep track of encryption keys
        self.aes_key = self.des_key = self.private_key = self.public_key = None

    def setup_look_and_feel(self):
        """Set up a sleek, dark theme for the app."""
        style = ttk.Style()
        style.theme_create("crypto", parent="clam", settings={
            "TNotebook": {"configure": {"background": "#27272a"}},
            "TNotebook.Tab": {"configure": {"padding": [15, 8], "background": "#27272a", "foreground": "#d4d4d8",
                                           "font": ("Montserrat", 11)},
                              "map": {"background": [("selected", "#3f3f46")],
                                      "foreground": [("selected", "#5eead4")]}},
            "TFrame": {"configure": {"background": "#27272a"}},
            "TButton": {"configure": {"background": "#3b82f6", "foreground": "#ffffff", "padding": [10, 5],
                                     "font": ("Montserrat", 10)},
                        "map": {"background": [("active", "#2563eb")]}},
            "TLabel": {"configure": {"background": "#27272a", "foreground": "#d4d4d8",
                                     "font": ("Montserrat", 11)}},
            "TCombobox": {"configure": {"fieldbackground": "#3f3f46", "foreground": "#ffffff"},
                          "map": {"fieldbackground": [("readonly", "#3f3f46")]}},
            "TText": {"configure": {"background": "#3f3f46", "foreground": "#ffffff",
                                    "font": ("Consolas", 11)}}
        })
        style.theme_use("crypto")

    # -----------------------------------
    # Tab setup: Create each tool section
    # -----------------------------------
    def create_tab(self, name, input_label="Message", has_keys=True, key_label="Key", options=None,
                   button_text="Go!", extra_fields=None):
        """Build a tab with input, output, and buttons, customized for each tool."""
        frame = ttk.Frame(self.tab_control, padding=10)
        self.tab_control.add(frame, text=name)

        # Message input
        input_frame = ttk.LabelFrame(frame, text=input_label, padding=10)
        input_frame.pack(fill="both", expand=True, pady=5)
        message_input = tk.Text(input_frame, height=5)  # Slightly reduced height to fit proportions
        message_input.pack(fill="both", padx=5)
        message_input.bind("<Control-a>", lambda e: self.select_all(message_input))

        # Add extra fields (like signature input)
        extra = {}
        if extra_fields:
            extra = extra_fields(frame)

        # Key inputs
        keys = {}
        if has_keys:
            key_frame = ttk.LabelFrame(frame, text=key_label, padding=10)
            key_frame.pack(fill="both", expand=True, pady=5)
            if name == "Symmetric":
                key_input = ttk.Entry(key_frame, width=40)  # Reduced width for narrower window
                key_input.pack(fill="x", padx=5, pady=5)
                ttk.Button(key_frame, text="Make New Key",
                           command=self.generate_symmetric_key).pack(pady=5)
                keys["key"] = key_input
            else:  # RSA or Digital Signature
                ttk.Label(key_frame, text="Public Key:").pack(anchor="w", padx=5)
                public_key = tk.Text(key_frame, height=3)
                public_key.pack(fill="both", padx=5, pady=2)
                ttk.Label(key_frame, text="Private Key:").pack(anchor="w", padx=5)
                private_key = tk.Text(key_frame, height=3)
                private_key.pack(fill="both", padx=5, pady=2)
                ttk.Button(key_frame, text="Make RSA Keys",
                           command=self.generate_rsa_keys).pack(pady=5)
                keys["public"] = public_key
                keys["private"] = private_key

        # File and clear buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=10)
        ttk.Button(btn_frame, text="📂 Load File",
                   command=lambda: self.load_file(message_input)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🗑 Clear",
                   command=lambda: message_input.delete("1.0", tk.END)).pack(side="left", padx=5)

        # Option picker
        option = tk.StringVar(value=options[0] if options else "")
        if options:
            ttk.Combobox(frame, textvariable=option, values=options,
                         state="readonly", width=25).pack(pady=10)  # Reduced width for narrower window

        # Action button
        actions = {
            "Symmetric": self.run_symmetric,
            "Asymmetric (RSA)": self.run_rsa,
            "Classical": self.run_classic,
            "Hashing": self.run_hashing,
            "Digital Signature": self.run_digital_signature
        }
        ttk.Button(frame, text=f"🔄 {button_text}",
                   command=actions.get(name, lambda: None)).pack(pady=10)

        # Output area
        output_frame = ttk.LabelFrame(frame, text="Result", padding=10)
        output_frame.pack(fill="both", expand=True, pady=5)
        result_output = tk.Text(output_frame, height=7)  # Slightly reduced height to fit proportions
        result_output.pack(fill="both", padx=5)
        ttk.Button(frame, text="💾 Save Result",
                   command=lambda: self.save_output(result_output)).pack(pady=10)

        return {"input": message_input, "output": result_output, "option": option, **keys, **extra}

    def setup_tabs(self):
        """Set up all the crypto tools in tabs."""
        # Symmetric: AES and DES encryption
        self.symmetric = self.create_tab(
            "Symmetric", options=["AES Encrypt", "AES Decrypt", "DES Encrypt", "DES Decrypt"]
        )

        # Asymmetric: RSA encryption
        self.rsa = self.create_tab(
            "Asymmetric (RSA)", key_label="RSA Keys", options=["RSA Encrypt", "RSA Decrypt"]
        )

        # Classical: Fun, old ciphers
        self.classic = self.create_tab(
            "Classical", has_keys=False, options=["Caesar Cipher", "Vigenere Cipher"]
        )

        # Hashing: Create message digests
        self.hashing = self.create_tab(
            "Hashing", has_keys=False, options=["MD5", "SHA-1", "SHA-256", "SHA-512"], button_text="Hash It!"
        )

        # Digital Signature: Sign and verify messages
        def add_signature_input(frame):
            sig_frame = ttk.LabelFrame(frame, text="Signature (for Verify)", padding=10)
            sig_frame.pack(fill="both", expand=True, pady=5)
            sig_input = tk.Text(sig_frame, height=3)
            sig_input.pack(fill="both", padx=5)
            return {"signature": sig_input}

        self.signature = self.create_tab(
            "Digital Signature", key_label="RSA Keys", options=["Sign", "Verify"],
            extra_fields=add_signature_input
        )

    # -----------------------------------
    # Key generation
    # -----------------------------------
    def generate_symmetric_key(self):
        """Make a new key for AES or DES."""
        op = self.symmetric["option"].get()
        if "AES" in op:
            self.aes_key = get_random_bytes(16)
            key = base64.b64encode(self.aes_key).decode()
            self.status.set("New AES key ready!")
        else:
            self.des_key = get_random_bytes(8)
            key = base64.b64encode(self.des_key).decode()
            self.status.set("New DES key ready!")
        self.symmetric["key"].delete(0, tk.END)
        self.symmetric["key"].insert(0, key)

    def generate_rsa_keys(self):
        """Create a new RSA key pair for encryption or signing."""
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        pub_key = self.public_key.public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        priv_key = self.private_key.private_bytes(serialization.Encoding.PEM,
                                                 serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()).decode()
        for tab in [self.rsa, self.signature]:
            tab["public"].delete("1.0", tk.END)
            tab["public"].insert(tk.END, pub_key)
            tab["private"].delete("1.0", tk.END)
            tab["private"].insert(tk.END, priv_key)
        self.status.set("New RSA keys created!")

    # -----------------------------------
    # Crypto actions
    # -----------------------------------
    def run_symmetric(self):
        """Encrypt or decrypt with AES or DES."""
        message = self.symmetric["input"].get("1.0", tk.END).strip()
        op = self.symmetric["option"].get()
        key = self.symmetric["key"].get()
        try:
            if not key:
                raise ValueError("Need a key!")
            key_bytes = base64.b64decode(key)
            if "AES" in op and len(key_bytes) not in [16, 24, 32]:
                raise ValueError("AES key needs 16, 24, or 32 bytes")
            if "DES" in op and len(key_bytes) != 8:
                raise ValueError("DES key needs 8 bytes")
            cipher = (AES if "AES" in op else DES).new(key_bytes, (AES if "AES" in op else DES).MODE_ECB)
            if "Encrypt" in op:
                result = cipher.encrypt(pad(message.encode(), 16 if "AES" in op else 8)).hex()
            else:
                result = unpad(cipher.decrypt(bytes.fromhex(message)), 16 if "AES" in op else 8).decode()
            self.status.set(f"{op} worked!")
        except Exception as e:
            result = f"Oops: {e}"
            self.status.set(f"Problem with {op}")
        self.symmetric["output"].delete("1.0", tk.END)
        self.symmetric["output"].insert(tk.END, result)

    def run_rsa(self):
        """Encrypt or decrypt with RSA."""
        message = self.rsa["input"].get("1.0", tk.END).strip()
        op = self.rsa["option"].get()
        try:
            if op == "RSA Encrypt":
                pem = self.rsa["public"].get("1.0", tk.END).strip()
                if not pem:
                    raise ValueError("Need a public key!")
                key = serialization.load_pem_public_key(pem.encode())
                result = base64.b64encode(key.encrypt(message.encode(),
                                                     rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA256()),
                                                                      algorithm=hashes.SHA256(), label=None))).decode()
                self.status.set("RSA encryption done!")
            else:
                pem = self.rsa["private"].get("1.0", tk.END).strip()
                if not pem:
                    raise ValueError("Need a private key!")
                key = serialization.load_pem_private_key(pem.encode(), None)
                result = key.decrypt(base64.b64decode(message),
                                     rsa_padding.OAEP(mgf=rsa_padding.MGF1(hashes.SHA256()),
                                                      algorithm=hashes.SHA256(), label=None)).decode()
                self.status.set("RSA decryption done!")
        except Exception as e:
            result = f"Oops: {e}"
            self.status.set(f"Problem with {op}")
        self.rsa["output"].delete("1.0", tk.END)
        self.rsa["output"].insert(tk.END, result)

    def run_classic(self):
        """Apply a classic cipher like Caesar or Vigenere."""
        message = self.classic["input"].get("1.0", tk.END).strip()
        op = self.classic["option"].get()
        try:
            result = caesar_cipher(message) if op == "Caesar Cipher" else vigenere_cipher(message)
            self.status.set(f"{op} applied!")
        except Exception as e:
            result = f"Oops: {e}"
            self.status.set(f"Problem with {op}")
        self.classic["output"].delete("1.0", tk.END)
        self.classic["output"].insert(tk.END, result)

    def run_hashing(self):
        """Create a hash (digital fingerprint) of the message."""
        message = self.hashing["input"].get("1.0", tk.END).strip()
        op = self.hashing["option"].get()
        try:
            if not message:
                raise ValueError("Need a message!")
            hash_func = {"MD5": hashlib.md5, "SHA-1": hashlib.sha1,
                         "SHA-256": hashlib.sha256, "SHA-512": hashlib.sha512}[op]
            result = hash_func(message.encode()).hexdigest()
            self.status.set(f"{op} hash created!")
        except Exception as e:
            result = f"Oops: {e}"
            self.status.set(f"Problem with {op}")
        self.hashing["output"].delete("1.0", tk.END)
        self.hashing["output"].insert(tk.END, result)

    def run_digital_signature(self):
        """Sign a message or verify a signature."""
        message = self.signature["input"].get("1.0", tk.END).strip()
        op = self.signature["option"].get()
        try:
            if not message:
                raise ValueError("Need a message!")
            if op == "Sign":
                pem = self.signature["private"].get("1.0", tk.END).strip()
                if not pem:
                    raise ValueError("Need a private key!")
                key = serialization.load_pem_private_key(pem.encode(), None)
                signature = key.sign(message.encode(),
                                     rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()),
                                                     salt_length=rsa_padding.PSS.MAX_LENGTH),
                                     hashes.SHA256())
                result = base64.b64encode(signature).decode()
                self.status.set("Message signed!")
            else:
                pem = self.signature["public"].get("1.0", tk.END).strip()
                sig = self.signature["signature"].get("1.0", tk.END).strip()
                if not pem:
                    raise ValueError("Need a public key!")
                if not sig:
                    raise ValueError("Need a signature!")
                key = serialization.load_pem_public_key(pem.encode())
                key.verify(base64.b64decode(sig), message.encode(),
                           rsa_padding.PSS(mgf=rsa_padding.MGF1(hashes.SHA256()),
                                           salt_length=rsa_padding.PSS.MAX_LENGTH),
                           hashes.SHA256())
                result = "Signature checks out!"
                self.status.set("Signature verified!")
        except Exception as e:
            result = f"Oops: {e}" if op == "Sign" else "Signature doesn't match!"
            self.status.set(f"Problem with {op}")
        self.signature["output"].delete("1.0", tk.END)
        self.signature["output"].insert(tk.END, result)

    # -----------------------------------
    # File handling
    # -----------------------------------
    def load_file(self, text_area):
        """Load a text file into the input area."""
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            try:
                with open(path, "r", encoding="utf-8") as file:
                    text_area.delete("1.0", tk.END)
                    text_area.insert(tk.END, file.read())
                self.status.set(f"Loaded {path.split('/')[-1]}")
            except Exception as e:
                self.status.set(f"Oops: {e}")
                messagebox.showerror("Error", f"Couldn't load: {e}")

    def save_output(self, text_area):
        """Save the result to a text file."""
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                           filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            try:
                with open(path, "w", encoding="utf-8") as file:
                    file.write(text_area.get("1.0", tk.END))
                self.status.set(f"Saved to {path.split('/')[-1]}")
                messagebox.showinfo("Saved", "Result saved!")
            except Exception as e:
                self.status.set(f"Oops: {e}")
                messagebox.showerror("Error", f"Couldn't save: {e}")

    def select_all(self, text_area):
        """Select all text in an input area (Ctrl+A)."""
        text_area.tag_add(tk.SEL, "1.0", tk.END)
        text_area.mark_set(tk.INSERT, "1.0")
        text_area.see(tk.INSERT)
        return "break"

# -----------------------------------
# Launch the app
# -----------------------------------
if __name__ == "__main__":
    window = tk.Tk()
    app = SamirCryptoTool(window)
    window.mainloop()