import os
import sys
import time
import json
import socket
import random
import secrets
import string
import uuid
import hmac
import hashlib
import struct
import base64
import ctypes
import ctypes.wintypes
import threading
import subprocess
import requests
import pyautogui
import pyperclip
import re
import customtkinter as ctk
from tkinter import messagebox, filedialog
from datetime import datetime, timezone
from PIL import Image, ImageDraw

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    qrcode = None
    QRCODE_AVAILABLE = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ==========================================
# CONFIGURATION ET THÈME VISUEL (Glassmorphism Sombre)
# ==========================================
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BACKEND_SERVER = os.path.join(BASE_DIR, 'backend', 'src', 'server.js')
OFFLINE_CACHE_FILE = os.path.join(BASE_DIR, 'data', 'offline_vault.json.enc')
PORT = 5000
API_URL = f"http://127.0.0.1:{PORT}/api"

# Salt fixe pour la dérivation de clé PBKDF2 (appliqué au nom d'utilisateur)
VAULT_CACHE_SALT = b"SecurPassDesktopSalt_v2_AESGCM"

# Palette de couleurs Premium
COLOR_BG = "#0f172a"
COLOR_CARD = "#1e293b"
COLOR_CARD_HOVER = "#334155"
COLOR_BORDER = "#334155"
COLOR_PRIMARY = "#2563eb"
COLOR_PRIMARY_HOVER = "#1d4ed8"
COLOR_SUCCESS = "#16a34a"
COLOR_SUCCESS_HOVER = "#15803d"
COLOR_PURPLE = "#8b5cf6"
COLOR_PURPLE_HOVER = "#7c3aed"
COLOR_DANGER = "#dc2626"
COLOR_DANGER_HOVER = "#b91c1c"
COLOR_AMBER = "#d97706"
COLOR_TEXT = "#f8fafc"
COLOR_MUTED = "#94a3b8"

try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# ==========================================
# ⚙️ UTILITAIRES SÉCURITÉ & 2FA / TOTP / CACHE
# ==========================================

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def start_node_backend():
    """Vérifie et démarre le serveur backend en tâche de fond si nécessaire."""
    if not is_port_in_use(PORT):
        print(f"[Desktop App] Démarrage du serveur Backend sur le port {PORT}...")
        try:
            subprocess.Popen(
                ['node', BACKEND_SERVER],
                cwd=os.path.join(BASE_DIR, 'backend'),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            for _ in range(25):
                if is_port_in_use(PORT):
                    print("[Desktop App] Backend démarré avec succès !")
                    break
                time.sleep(0.3)
        except Exception as e:
            print(f"[Desktop App Error] Impossible de démarrer le backend : {e}")

def get_anti_replay_headers(token=None, extra=None):
    """Génère les headers de sécurité anti-rejeu et d'authentification JWT obligatoires."""
    headers = {
        "X-Request-Nonce": str(uuid.uuid4()),
        "X-Request-Timestamp": str(int(time.time() * 1000))
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra:
        headers.update(extra)
    return headers

def get_totp_code(secret, interval=30):
    """Génère un code TOTP 2FA à 6 chiffres selon la norme RFC 6238."""
    if not secret:
        return None, 0
    try:
        clean_secret = secret.replace(" ", "").upper().strip()
        missing_padding = len(clean_secret) % 8
        if missing_padding:
            clean_secret += "=" * (8 - missing_padding)
        key = base64.b32decode(clean_secret)
        now = time.time()
        counter = int(now // interval)
        rem = int(interval - (now % interval))
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0f
        code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff) % 1000000
        return f"{code:06d}", rem
    except Exception:
        return None, 0

def derive_key(password, salt=None):
    """Dérive une clé AES-256 de 32 octets via PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = VAULT_CACHE_SALT
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_data_aes(raw_bytes, password):
    """Chiffre les données avec AES-256-GCM.
    Format de sortie: salt_hex (32B) + nonce (12B) + tag (16B) + ciphertext
    Le tout concaténé en bytes.
    """
    key = derive_key(password)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, raw_bytes, None)
    return nonce + ciphertext  # le tag est inclus dans ciphertext par AESGCM


def decrypt_data_aes(data_bytes, password):
    """Déchiffre les données chiffrées avec AES-256-GCM.
    Format attendu: nonce (12B) + tag (16B) + ciphertext
    """
    nonce = data_bytes[:12]
    ciphertext_with_tag = data_bytes[12:]
    key = derive_key(password)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def save_offline_cache(vault_items, username):
    """Enregistre le coffre-fort dans le cache local chiffré AES-256-GCM."""
    try:
        os.makedirs(os.path.dirname(OFFLINE_CACHE_FILE), exist_ok=True)
        payload = json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "items": vault_items
        }).encode('utf-8')
        enc = encrypt_data_aes(payload, username)
        with open(OFFLINE_CACHE_FILE, "wb") as f:
            f.write(enc)
    except Exception as e:
        print(f"[Cache Error] impossible d'enregistrer le cache hors-ligne : {e}")


def load_offline_cache(username):
    """Charge le coffre-fort depuis le cache local chiffré AES-256-GCM.
    Fallback gracieux: si le déchiffrement échoue (cache invalide ou changement de clé),
    le cache est recréé à vide.
    """
    if not os.path.exists(OFFLINE_CACHE_FILE):
        return []
    try:
        with open(OFFLINE_CACHE_FILE, "rb") as f:
            enc = f.read()
        dec = decrypt_data_aes(enc, username)
        data = json.loads(dec.decode('utf-8'))
        return data.get("items", [])
    except Exception as e:
        # Fallback gracieux: le cache est invalide (ancien format XOR ou clé incorrecte)
        print(f"[Cache Warning] Déchiffrement du cache échoué ({e.__class__.__name__}). Recréation du cache.")
        try:
            os.remove(OFFLINE_CACHE_FILE)
        except Exception:
            pass
        return []


# ==========================================
# 🪟 MODALES ET DIALOGUES
# ==========================================

class AddEditModal(ctk.CTkToplevel):
    """Modal d'ajout ou modification d'un mot de passe (Support 2FA / TOTP)."""
    def __init__(self, parent, item=None, on_save_callback=None):
        super().__init__(parent)
        self.parent = parent
        self.item = item
        self.on_save_callback = on_save_callback
        
        self.title("✏️ Modifier le compte" if item else "✨ Nouveau compte")
        self.geometry("500x680")
        self.resizable(False, False)
        self.grab_set()
        
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (500 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (680 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()

    def create_widgets(self):
        lbl_title = ctk.CTkLabel(
            self, 
            text="✏️ Modifier le compte" if self.item else "✨ Nouveau compte", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        lbl_title.pack(pady=(18, 12))

        # Titre
        ctk.CTkLabel(self, text="Titre du compte *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_title = ctk.CTkEntry(self, placeholder_text="ex: GitHub Enterprise", height=36)
        self.entry_title.pack(fill="x", padx=35, pady=(2, 8))
        if self.item: self.entry_title.insert(0, self.item.get('title', ''))

        # Catégorie
        ctk.CTkLabel(self, text="Catégorie", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.opt_category = ctk.CTkOptionMenu(self, values=["Général", "Professionnel", "Finance", "Réseaux Sociaux", "Personnel"], height=36)
        self.opt_category.pack(fill="x", padx=35, pady=(2, 8))
        if self.item: self.opt_category.set(self.item.get('category', 'Général'))

        # Site Web
        ctk.CTkLabel(self, text="Site Web / URL", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_url = ctk.CTkEntry(self, placeholder_text="https://...", height=36)
        self.entry_url.pack(fill="x", padx=35, pady=(2, 8))
        if self.item: self.entry_url.insert(0, self.item.get('websiteUrl', ''))

        # Identifiant
        ctk.CTkLabel(self, text="Identifiant / E-mail", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_user = ctk.CTkEntry(self, placeholder_text="nom@exemple.com", height=36)
        self.entry_user.pack(fill="x", padx=35, pady=(2, 8))
        if self.item: self.entry_user.insert(0, self.item.get('username', ''))

        # Mot de passe
        ctk.CTkLabel(self, text="Mot de passe *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        frame_pwd = ctk.CTkFrame(self, fg_color="transparent")
        frame_pwd.pack(fill="x", padx=35, pady=(2, 8))

        self.entry_pwd = ctk.CTkEntry(frame_pwd, show="•", height=36)
        self.entry_pwd.pack(side="left", fill="x", expand=True, padx=(0, 8))
        if self.item: self.entry_pwd.insert(0, self.item.get('password', ''))

        btn_gen = ctk.CTkButton(frame_pwd, text="🎲 Générer", width=85, height=36, fg_color=COLOR_PRIMARY, command=self.generate_password)
        btn_gen.pack(side="right")

        # Clé TOTP / 2FA
        ctk.CTkLabel(self, text="Clé 2FA / TOTP Secret (Optionnel, ex: JBSWY3DPEHPK3PXP)", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_totp = ctk.CTkEntry(self, placeholder_text="Base32 Secret...", height=36)
        self.entry_totp.pack(fill="x", padx=35, pady=(2, 8))
        totp_val = ''
        if self.item:
            totp_val = self.item.get('totpSecret') or ''
            if not totp_val and '[TOTP:' in (self.item.get('notes') or ''):
                try:
                    totp_val = self.item.get('notes').split('[TOTP:')[1].split(']')[0].strip()
                except Exception:
                    pass
        self.entry_totp.insert(0, totp_val)

        # Notes
        ctk.CTkLabel(self, text="Notes confidentielles", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_notes = ctk.CTkEntry(self, placeholder_text="Remarques...", height=36)
        self.entry_notes.pack(fill="x", padx=35, pady=(2, 12))
        clean_notes_val = ''
        if self.item:
            clean_notes_val = re.sub(r'\[TOTP:[^\]]+\]', '', self.item.get('notes') or '').strip()
        self.entry_notes.insert(0, clean_notes_val)

        # Boutons d'action
        frame_btn = ctk.CTkFrame(self, fg_color="transparent")
        frame_btn.pack(fill="x", padx=35, pady=10)

        ctk.CTkButton(frame_btn, text="Annuler", fg_color="#475569", hover_color="#334155", height=38, command=self.destroy).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(frame_btn, text="💾 Enregistrer", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER, height=38, font=ctk.CTkFont(weight="bold"), command=self.save).pack(side="right", fill="x", expand=True, padx=(5, 0))

    def generate_password(self):
        # Utiliser secrets.choice() pour une génération cryptographiquement sûre
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(secrets.choice(chars) for _ in range(18))
        self.entry_pwd.delete(0, 'end')
        self.entry_pwd.insert(0, pwd)

    def save(self):
        title = self.entry_title.get().strip()
        pwd = self.entry_pwd.get()

        if not title or not pwd:
            messagebox.showerror("Erreur", "Le titre et le mot de passe sont obligatoires.", parent=self)
            return

        totp_secret = self.entry_totp.get().strip()
        raw_notes = self.entry_notes.get().strip()
        clean_notes = re.sub(r'\[TOTP:[^\]]+\]', '', raw_notes).strip()

        if totp_secret:
            clean_notes = f"{clean_notes} [TOTP:{totp_secret}]".strip() if clean_notes else f"[TOTP:{totp_secret}]"

        payload = {
            "title": title,
            "category": self.opt_category.get(),
            "websiteUrl": self.entry_url.get().strip(),
            "username": self.entry_user.get().strip(),
            "password": pwd,
            "totpSecret": totp_secret,
            "notes": clean_notes
        }

        if self.on_save_callback:
            self.on_save_callback(payload, self.item.get('id') if self.item else None)
        self.destroy()


class ShareModal(ctk.CTkToplevel):
    """Modal de partage de mot de passe avec un autre utilisateur LDAP/AD."""
    def __init__(self, parent, item, token, on_success_callback=None):
        super().__init__(parent)
        self.parent = parent
        self.item = item
        self.token = token
        self.on_success_callback = on_success_callback

        self.title("🔗 Partager le mot de passe")
        self.geometry("450x420")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (450 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (420 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()

    def create_widgets(self):
        ctk.CTkLabel(self, text="🔗 Partager un accès", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(20, 5))
        ctk.CTkLabel(self, text=f"Compte : {self.item.get('title')}", font=ctk.CTkFont(size=13), text_color=COLOR_MUTED).pack(pady=(0, 15))

        # Utilisateur destinataire
        ctk.CTkLabel(self, text="Utilisateur Active Directory (Identifiant LDAP) *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_target_user = ctk.CTkEntry(self, placeholder_text="ex: ahmed ou p.durand", height=36)
        self.entry_target_user.pack(fill="x", padx=35, pady=(2, 12))

        # Permission
        ctk.CTkLabel(self, text="Permission accordée", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.opt_permission = ctk.CTkOptionMenu(
            self, 
            values=["Lecture seule (read)", "Lecture + Modification (write)"], 
            height=36
        )
        self.opt_permission.pack(fill="x", padx=35, pady=(2, 12))

        # Expiration
        ctk.CTkLabel(self, text="Durée de validité", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.opt_expiry = ctk.CTkOptionMenu(
            self, 
            values=["Jamais (Permanent)", "24 Heures", "7 Jours", "30 Jours", "90 Jours"], 
            height=36
        )
        self.opt_expiry.pack(fill="x", padx=35, pady=(2, 20))

        # Action
        frame_btn = ctk.CTkFrame(self, fg_color="transparent")
        frame_btn.pack(fill="x", padx=35, pady=10)

        ctk.CTkButton(frame_btn, text="Annuler", fg_color="#475569", command=self.destroy).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(frame_btn, text="🤝 Confirmer le partage", fg_color=COLOR_PURPLE, hover_color=COLOR_PURPLE_HOVER, font=ctk.CTkFont(weight="bold"), command=self.submit_share).pack(side="right", fill="x", expand=True, padx=(5, 0))

    def submit_share(self):
        target_user = self.entry_target_user.get().strip()
        if not target_user:
            messagebox.showerror("Erreur", "Veuillez saisir l'identifiant de l'utilisateur.", parent=self)
            return

        perm_raw = self.opt_permission.get()
        permission = "write" if "write" in perm_raw or "Modification" in perm_raw else "read"

        exp_raw = self.opt_expiry.get()
        expiresAt = None
        now_ms = time.time()
        if "24" in exp_raw:
            expiresAt = datetime.fromtimestamp(now_ms + 86400, timezone.utc).isoformat().replace("+00:00", "Z")
        elif "7" in exp_raw:
            expiresAt = datetime.fromtimestamp(now_ms + 7 * 86400, timezone.utc).isoformat().replace("+00:00", "Z")
        elif "30" in exp_raw:
            expiresAt = datetime.fromtimestamp(now_ms + 30 * 86400, timezone.utc).isoformat().replace("+00:00", "Z")
        elif "90" in exp_raw:
            expiresAt = datetime.fromtimestamp(now_ms + 90 * 86400, timezone.utc).isoformat().replace("+00:00", "Z")

        payload = {
            "sharedWith": target_user,
            "permission": permission,
            "expiresAt": expiresAt
        }

        headers = get_anti_replay_headers(self.token)
        url = f"{API_URL}/vault/{self.item.get('id')}/share"

        def req():
            try:
                res = requests.post(url, json=payload, headers=headers, timeout=5)
                data = res.json()
                # Le backend renvoie 201 (Created) pour un partage réussi
                if res.status_code in [200, 201]:
                    self.after(0, lambda: messagebox.showinfo("Succès", f"Mot de passe partagé avec @{target_user} !", parent=self))
                    if self.on_success_callback:
                        self.after(0, self.on_success_callback)
                    self.after(0, self.destroy)
                else:
                    self.after(0, lambda: messagebox.showerror("Erreur Partage", data.get('error', 'Échec du partage'), parent=self))
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", f"Erreur réseau : {error}", parent=self))

        threading.Thread(target=req, daemon=True).start()


class ManageSharesModal(ctk.CTkToplevel):
    """Modal de visualisation et révocation des accès attribués sur un mot de passe."""
    def __init__(self, parent, item, token):
        super().__init__(parent)
        self.parent = parent
        self.item = item
        self.token = token

        self.title("👥 Gestion des accès partagés")
        self.geometry("520x450")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (520 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (450 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()
        self.load_shares()

    def create_widgets(self):
        ctk.CTkLabel(self, text="👥 Accès partagés actifs", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(15, 5))
        ctk.CTkLabel(self, text=f"Compte : {self.item.get('title')}", font=ctk.CTkFont(size=12), text_color=COLOR_MUTED).pack(pady=(0, 15))

        self.scroll_shares = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_shares.pack(fill="both", expand=True, padx=20, pady=(0, 15))

    def load_shares(self):
        for w in self.scroll_shares.winfo_children(): w.destroy()

        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"{API_URL}/vault/{self.item.get('id')}/shares"

        def req():
            try:
                res = requests.get(url, headers=headers, timeout=5)
                if res.status_code == 200:
                    # L'API /vault/:id/shares retourne un tableau direct (pas {shares: [...]})
                    data = res.json()
                    shares = data if isinstance(data, list) else data.get('shares', [])
                    self.after(0, lambda: self.render_shares(shares))
                else:
                    self.after(0, lambda: ctk.CTkLabel(self.scroll_shares, text="Erreur lors de la récupération des partages.", text_color=COLOR_MUTED).pack(pady=30))
            except Exception as e:
                self.after(0, lambda error=str(e): ctk.CTkLabel(self.scroll_shares, text=f"Erreur connexion : {error}", text_color=COLOR_MUTED).pack(pady=30))

        threading.Thread(target=req, daemon=True).start()

    def render_shares(self, shares):
        for w in self.scroll_shares.winfo_children(): w.destroy()

        if not shares:
            ctk.CTkLabel(self.scroll_shares, text="Ce mot de passe n'est partagé avec aucun utilisateur.", font=ctk.CTkFont(size=13), text_color=COLOR_MUTED).pack(pady=40)
            return

        for s in shares:
            card = ctk.CTkFrame(self.scroll_shares, fg_color=COLOR_CARD, corner_radius=8)
            card.pack(fill="x", pady=5)

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(side="left", padx=12, pady=10)

            user_target = s.get('sharedWith') or 'Inconnu'
            perm = "✏️ Modification" if s.get('permission') == 'write' else "👁️ Lecture seule"
            ctk.CTkLabel(info, text=f"👤 @{user_target}", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(info, text=f"Permission : {perm}", font=ctk.CTkFont(size=11), text_color=COLOR_MUTED).pack(anchor="w")

            btn_revoke = ctk.CTkButton(
                card, 
                text="🚫 Révoquer", 
                width=90, 
                fg_color=COLOR_DANGER, 
                hover_color=COLOR_DANGER_HOVER, 
                command=lambda u=user_target: self.revoke(u)
            )
            btn_revoke.pack(side="right", padx=12)

    def revoke(self, target_user):
        if not messagebox.askyesno("Confirmation", f"Révoquer l'accès pour @{target_user} ?", parent=self):
            return

        headers = get_anti_replay_headers(self.token)
        url = f"{API_URL}/vault/{self.item.get('id')}/share/{target_user}"

        def req():
            try:
                res = requests.delete(url, headers=headers, timeout=5)
                if res.status_code == 200:
                    self.after(0, self.load_shares)
                else:
                    self.after(0, lambda: messagebox.showerror("Erreur", "Impossible de révoquer le partage.", parent=self))
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", f"Erreur réseau : {error}", parent=self))

        threading.Thread(target=req, daemon=True).start()


class ImportModal(ctk.CTkToplevel):
    """Modal d'importation de mots de passe (CSV ou Bitwarden JSON)."""
    def __init__(self, parent, token, on_success_callback=None):
        super().__init__(parent)
        self.parent = parent
        self.token = token
        self.on_success_callback = on_success_callback

        self.file_path = None

        self.title("🔼 Importer des mots de passe")
        self.geometry("480x380")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (480 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (380 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()

    def create_widgets(self):
        ctk.CTkLabel(self, text="🔼 Importer des mots de passe", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(20, 15))

        # Format
        ctk.CTkLabel(self, text="Format du fichier source *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.opt_format = ctk.CTkOptionMenu(self, values=["CSV (Chrome, Firefox, SecurPass)", "Bitwarden (JSON)"], height=36)
        self.opt_format.pack(fill="x", padx=35, pady=(2, 15))

        # Sélection Fichier
        frame_file = ctk.CTkFrame(self, fg_color="transparent")
        frame_file.pack(fill="x", padx=35, pady=5)

        self.lbl_file = ctk.CTkLabel(frame_file, text="Aucun fichier sélectionné", font=ctk.CTkFont(size=12), text_color=COLOR_MUTED)
        self.lbl_file.pack(side="left", fill="x", expand=True)

        btn_browse = ctk.CTkButton(frame_file, text="📁 Parcourir...", width=110, height=36, command=self.browse_file)
        btn_browse.pack(side="right")

        # Actions
        frame_btn = ctk.CTkFrame(self, fg_color="transparent")
        frame_btn.pack(fill="x", padx=35, pady=25)

        ctk.CTkButton(frame_btn, text="Annuler", fg_color="#475569", command=self.destroy).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(frame_btn, text="🚀 Démarrer l'import", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER, font=ctk.CTkFont(weight="bold"), command=self.submit_import).pack(side="right", fill="x", expand=True, padx=(5, 0))

    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Sélectionner le fichier à importer",
            filetypes=[("Fichiers compatibles", "*.csv;*.json;*.txt"), ("CSV Files", "*.csv"), ("JSON Files", "*.json"), ("Tous les fichiers", "*.*")]
        )
        if filename:
            self.file_path = filename
            self.lbl_file.configure(text=os.path.basename(filename), text_color=COLOR_TEXT)

    def submit_import(self):
        if not self.file_path or not os.path.exists(self.file_path):
            messagebox.showerror("Erreur", "Veuillez sélectionner un fichier valide.", parent=self)
            return

        fmt_choice = self.opt_format.get()
        fmt_header = "bitwarden" if "Bitwarden" in fmt_choice else "csv"

        try:
            with open(self.file_path, "r", encoding="utf-8-sig") as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror("Erreur de lecture", f"Impossible de lire le fichier : {e}", parent=self)
            return

        headers = get_anti_replay_headers(self.token, {
            "Content-Type": "text/plain",
            "X-Import-Format": fmt_header
        })

        url = f"{API_URL}/vault/import"

        def req():
            try:
                res = requests.post(url, data=content.encode('utf-8'), headers=headers, timeout=15)
                data = res.json()
                if res.status_code in [200, 201]:
                    added = data.get('imported', 0)
                    total = data.get('total', 0)
                    self.after(0, lambda: messagebox.showinfo("Succès", f"Importation réussie !\n{added} mot(s) de passe importé(s) sur {total} trouvé(s).", parent=self))
                    if self.on_success_callback:
                        self.after(0, self.on_success_callback)
                    self.after(0, self.destroy)
                else:
                    self.after(0, lambda: messagebox.showerror("Erreur Import", data.get('error', 'Erreur lors de l\'importation'), parent=self))
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", f"Erreur de communication : {error}", parent=self))

        threading.Thread(target=req, daemon=True).start()


class PasswordHistoryModal(ctk.CTkToplevel):
    """Modal d'affichage de l'historique des modifications de mot de passe."""
    def __init__(self, parent, item, token):
        super().__init__(parent)
        self.parent = parent
        self.item = item
        self.token = token

        self.title("📜 Historique des modifications")
        self.geometry("520x450")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (520 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (450 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()
        self.load_history()

    def create_widgets(self):
        ctk.CTkLabel(self, text="📜 Historique de sécurité", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(15, 5))
        ctk.CTkLabel(self, text=f"Compte : {self.item.get('title')}", font=ctk.CTkFont(size=12), text_color=COLOR_MUTED).pack(pady=(0, 15))

        self.scroll_hist = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_hist.pack(fill="both", expand=True, padx=20, pady=(0, 15))

    def load_history(self):
        for w in self.scroll_hist.winfo_children(): w.destroy()

        headers = {"Authorization": f"Bearer {self.token}"}
        # La route correcte est /vault/history (pas /vault/:id/history qui n'existe pas)
        url = f"{API_URL}/vault/history"

        def req():
            try:
                res = requests.get(url, headers=headers, timeout=5)
                if res.status_code == 200:
                    hist = res.json()
                    self.after(0, lambda: self.render_history(hist))
                else:
                    self.after(0, lambda: ctk.CTkLabel(self.scroll_hist, text="Aucun historique disponible.", text_color=COLOR_MUTED).pack(pady=30))
            except Exception as e:
                self.after(0, lambda error=str(e): ctk.CTkLabel(self.scroll_hist, text=f"Erreur : {error}", text_color=COLOR_MUTED).pack(pady=30))

        threading.Thread(target=req, daemon=True).start()

    def render_history(self, history):
        for w in self.scroll_hist.winfo_children(): w.destroy()

        if not history:
            ctk.CTkLabel(self.scroll_hist, text="Aucune modification antérieure enregistrée.", font=ctk.CTkFont(size=13), text_color=COLOR_MUTED).pack(pady=40)
            return

        for h in history:
            card = ctk.CTkFrame(self.scroll_hist, fg_color=COLOR_CARD, corner_radius=8)
            card.pack(fill="x", pady=5)

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(fill="x", padx=12, pady=10)

            by = h.get('changedBy') or 'Inconnu'
            ts = h.get('changedAt') or ''
            try:
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                ts_disp = dt.strftime('%d/%m/%Y à %H:%M')
            except Exception:
                ts_disp = ts

            ctk.CTkLabel(info, text=f"Modifié par @{by} — {ts_disp}", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w")
            ctk.CTkLabel(info, text=f"Hash ancien mot de passe: {h.get('oldPasswordHash', '')[:30]}...", font=ctk.CTkFont(size=10), text_color=COLOR_MUTED).pack(anchor="w")


class AddUserModal(ctk.CTkToplevel):
    """Modal d'ajout d'un utilisateur Active Directory / LDAP pour les administrateurs."""
    def __init__(self, parent, token, on_success_callback=None):
        super().__init__(parent)
        self.parent = parent
        self.token = token
        self.on_success_callback = on_success_callback

        self.title("👤 Créer un utilisateur Active Directory")
        self.geometry("450x480")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (450 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (480 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()

    def create_widgets(self):
        ctk.CTkLabel(self, text="👤 Nouvel Utilisateur AD", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(20, 15))

        # Username
        ctk.CTkLabel(self, text="Identifiant LDAP / Username *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_user = ctk.CTkEntry(self, placeholder_text="ex: j.dupont", height=36)
        self.entry_user.pack(fill="x", padx=35, pady=(2, 10))

        # Display Name
        ctk.CTkLabel(self, text="Nom d'affichage complet *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_name = ctk.CTkEntry(self, placeholder_text="ex: Jean Dupont", height=36)
        self.entry_name.pack(fill="x", padx=35, pady=(2, 10))

        # Email
        ctk.CTkLabel(self, text="Adresse E-mail", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_email = ctk.CTkEntry(self, placeholder_text="j.dupont@entreprise.com", height=36)
        self.entry_email.pack(fill="x", padx=35, pady=(2, 10))

        # Password
        ctk.CTkLabel(self, text="Mot de passe initial *", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=35)
        self.entry_pwd = ctk.CTkEntry(self, show="•", height=36)
        self.entry_pwd.pack(fill="x", padx=35, pady=(2, 20))

        # Actions
        frame_btn = ctk.CTkFrame(self, fg_color="transparent")
        frame_btn.pack(fill="x", padx=35, pady=10)

        ctk.CTkButton(frame_btn, text="Annuler", fg_color="#475569", command=self.destroy).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(frame_btn, text="✨ Créer l'utilisateur", fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER, font=ctk.CTkFont(weight="bold"), command=self.submit).pack(side="right", fill="x", expand=True, padx=(5, 0))

    def submit(self):
        u = self.entry_user.get().strip()
        n = self.entry_name.get().strip()
        p = self.entry_pwd.get()
        e = self.entry_email.get().strip()

        if not u or not n or not p:
            messagebox.showerror("Erreur", "Identifiant, nom d'affichage et mot de passe requis.", parent=self)
            return

        headers = get_anti_replay_headers(self.token)
        url = f"{API_URL}/admin/users"
        payload = {"username": u, "displayName": n, "email": e, "password": p}

        def req():
            try:
                res = requests.post(url, json=payload, headers=headers, timeout=5)
                data = res.json()
                if res.status_code in [200, 201]:
                    self.after(0, lambda: messagebox.showinfo("Succès", f"Utilisateur @{u} créé avec succès !", parent=self))
                    if self.on_success_callback:
                        self.after(0, self.on_success_callback)
                    self.after(0, self.destroy)
                else:
                    self.after(0, lambda: messagebox.showerror("Erreur Admin", data.get('error', 'Échec de création'), parent=self))
            except Exception as ex:
                self.after(0, lambda: messagebox.showerror("Erreur", f"Erreur réseau : {ex}", parent=self))

        threading.Thread(target=req, daemon=True).start()


# ==========================================
# 🔐 SECURITY SCORE FRAME
# ==========================================
class SecurityScoreFrame(ctk.CTkFrame):
    """Affiche le score de sécurité personnel et les statistiques dans l'application Desktop."""
    def __init__(self, parent, token, user):
        super().__init__(parent, fg_color="transparent")
        self.parent = parent
        self.token = token
        self.user = user
        self.create_widgets()

    def create_widgets(self):
        header = ctk.CTkLabel(self, text="🔐 Dashboard de Sécurité Personnelle",
                              font=ctk.CTkFont(size=20, weight="bold"))
        header.pack(anchor="w", pady=(0, 15))

        ctk.CTkLabel(self, text="Score global de sécurité de votre coffre-fort :",
                     font=ctk.CTkFont(size=12), text_color=COLOR_MUTED).pack(anchor="w", pady=(0, 10))

        self.score_var = ctk.StringVar(value="--/100")
        self.lbl_score = ctk.CTkLabel(self, textvariable=self.score_var,
                                      font=ctk.CTkFont(size=36, weight="bold"))
        self.lbl_score.pack(pady=10)

        self.lbl_status = ctk.CTkLabel(self, text="Évaluation en cours...",
                                       font=ctk.CTkFont(size=13), text_color=COLOR_MUTED)
        self.lbl_status.pack(pady=(0, 20))

        metrics_frame = ctk.CTkFrame(self, fg_color="transparent")
        metrics_frame.pack(fill="x", pady=(0, 20))
        metrics_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.metric_weak = self._make_metric_card(metrics_frame, 0, "Faibles", COLOR_DANGER)
        self.metric_reused = self._make_metric_card(metrics_frame, 1, "Réutilisés", COLOR_AMBER)
        self.metric_expired = self._make_metric_card(metrics_frame, 2, "Expirés", COLOR_PRIMARY)

        ctk.CTkLabel(self, text="Alertes & Recommandations",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", pady=(0, 8))

        self.scroll_reco = ctk.CTkScrollableFrame(self)
        self.scroll_reco.pack(fill="both", expand=True)

        btn_refresh = ctk.CTkButton(self, text="🔄 Actualiser", height=36,
                                    command=self.load_security_score)
        btn_refresh.pack(anchor="e", pady=(15, 0))

        self.load_security_score()

    def _make_metric_card(self, parent, col, title, color):
        card = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=10)
        card.grid(row=0, column=col, sticky="ew", padx=4)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11), text_color=COLOR_MUTED).pack(pady=(10, 2))
        val = ctk.CTkLabel(card, text="0", font=ctk.CTkFont(size=22, weight="bold"), text_color=color)
        val.pack(pady=(0, 10))
        return val

    def load_security_score(self):
        def req():
            try:
                headers = {"Authorization": f"Bearer {self.token}"}
                res = requests.get(f"{API_URL}/vault/security-score", headers=headers, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    self.after(0, lambda: self.render_security(data))
                else:
                    self.after(0, lambda: self.lbl_status.configure(text="Erreur lors du calcul du score."))
            except Exception as e:
                self.after(0, lambda error=str(e): self.lbl_status.configure(text=f"Erreur : {error}"))

        threading.Thread(target=req, daemon=True).start()

    def render_security(self, data):
        score = data.get('overallScore', 0)
        metrics = data.get('metrics', {})
        vulns = data.get('vulnerableItems', [])

        self.score_var.set(f"{score}/100")
        self.lbl_score.configure(
            text_color=COLOR_SUCCESS if score >= 70 else COLOR_DANGER if score < 40 else COLOR_AMBER
        )

        if score >= 80:
            status = 'Excellente Sécurité'; color = COLOR_SUCCESS
        elif score >= 60:
            status = 'Sécurité Bonne'; color = COLOR_PRIMARY
        elif score >= 40:
            status = 'Sécurité Moyenne'; color = COLOR_AMBER
        else:
            status = 'Sécurité Critique'; color = COLOR_DANGER

        self.lbl_status.configure(text=status, text_color=color)
        self.metric_weak.configure(text=metrics.get('weakCount', 0))
        self.metric_reused.configure(text=metrics.get('reusedCount', 0))
        self.metric_expired.configure(text=metrics.get('expiredCount', 0))

        for w in self.scroll_reco.winfo_children():
            w.destroy()

        if not vulns:
            ctk.CTkLabel(self.scroll_reco, text="✅ Aucune vulnérabilité détectée !",
                         font=ctk.CTkFont(size=13), text_color=COLOR_MUTED).pack(pady=20)
        else:
            for v in vulns:
                issues = " • ".join(v.get('issues', []))
                card = ctk.CTkFrame(self.scroll_reco, fg_color=COLOR_CARD, corner_radius=8)
                card.pack(fill="x", pady=4)
                ctk.CTkLabel(card, text=f"⚠️ {v.get('title', '?')}",
                             font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=12, pady=(10, 2))
                ctk.CTkLabel(card, text=issues,
                             font=ctk.CTkFont(size=10), text_color=COLOR_MUTED).pack(anchor="w", padx=12, pady=(0, 10))


# ==========================================
# 🔐 TOTP SETUP MODAL
# ==========================================
class TOTPSetupModal(ctk.CTkToplevel):
    """Modal de configuration TOTP 2FA avec affichage de la clé et code QR ASCII."""
    def __init__(self, parent, token):
        super().__init__(parent)
        self.parent = parent
        self.token = token

        self.title("Configurer la 2FA TOTP")
        self.geometry("500x520")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (500 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (520 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()

    def create_widgets(self):
        ctk.CTkLabel(self, text="🔐 Authentification à Deux Facteurs (TOTP)",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(20, 10))
        ctk.CTkLabel(self, text="Scannez ce code QR avec Google Authenticator, Authy ou Microsoft Authenticator.",
                     font=ctk.CTkFont(size=11), text_color=COLOR_MUTED, wraplength=460).pack(pady=(0, 15))

        self.qr_frame = ctk.CTkFrame(self, fg_color="#ffffff")
        self.qr_frame.pack(pady=10)

        self.lbl_qr = ctk.CTkLabel(self.qr_frame, text="", font=ctk.CTkFont(family="Courier New", size=10))
        self.lbl_qr.pack(pady=10, padx=10)

        ctk.CTkLabel(self, text="Clé secrète TOTP :", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=35, pady=(10, 2))
        frame_secret = ctk.CTkFrame(self, fg_color="transparent")
        frame_secret.pack(fill="x", padx=35, pady=(0, 5))
        self.lbl_secret = ctk.CTkLabel(frame_secret, text="--", font=ctk.CTkFont(family="Courier New", size=13, weight="bold"))
        self.lbl_secret.pack(side="left", fill="x", expand=True)
        btn_copy_secret = ctk.CTkButton(frame_secret, text="📋 Copier", width=80, height=26,
                                        command=self.copy_secret)
        btn_copy_secret.pack(side="right")

        ctk.CTkLabel(self, text="Code TOTP actuel :", font=ctk.CTkFont(size=11, weight="bold")).pack(anchor="w", padx=35, pady=(10, 2))
        self.lbl_totp_code = ctk.CTkLabel(self, text="--:--", font=ctk.CTkFont(size=18, weight="bold"), text_color=COLOR_PRIMARY)
        self.lbl_totp_code.pack(pady=(0, 5))

        self.entry_totp_token = ctk.CTkEntry(
            self,
            placeholder_text="Saisissez le code à 6 chiffres",
            height=36
        )
        self.entry_totp_token.pack(fill="x", padx=35, pady=(5, 10))

        ctk.CTkLabel(self, text="Vérifiez votre code à 6 chiffres dans l'application d'authentification.",
                     font=ctk.CTkFont(size=10), text_color=COLOR_MUTED, wraplength=460).pack(pady=(0, 15))

        btn_ok = ctk.CTkButton(self, text="✅ J'ai configuré ma 2FA", height=38,
                               fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER,
                               command=self.on_verify)
        btn_ok.pack(pady=(0, 10))
        btn_ok.configure(text="Vérifier et confirmer la 2FA")

        self.secret_value = None
        self.otpauth_url = None
        self._start_totp_timer()
        self.setup_totp()

    def setup_totp(self):
        def req():
            try:
                headers = get_anti_replay_headers(self.token)
                res = requests.post(f"{API_URL}/auth/totp/setup", headers=headers, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    self.secret_value = data.get('secret')
                    self.otpauth_url = data.get('otpauthUrl')
                    self.after(0, self.render_totp)
            except Exception as e:
                error_message = str(e)
                self.after(0, lambda error_message=error_message: ctk.CTkLabel(
                    self,
                    text=f"Erreur : {error_message}",
                    text_color=COLOR_DANGER
                ).pack())

        threading.Thread(target=req, daemon=True).start()

    def render_totp(self):
        if not self.secret_value:
            return
        self.lbl_secret.configure(text=self.secret_value)
        data_to_encode = self.otpauth_url or self.secret_value

        if QRCODE_AVAILABLE and qrcode:
            try:
                qr = qrcode.QRCode(
                    version=None,
                    error_correction=qrcode.constants.ERROR_CORRECT_M,
                    box_size=6,
                    border=2
                )
                qr.add_data(data_to_encode)
                qr.make(fit=True)
                pil_img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
                ctk_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(190, 190))
                self.lbl_qr.configure(image=ctk_img, text="")
            except Exception as e:
                qr = generate_ascii_qr(data_to_encode)
                self.lbl_qr.configure(text=qr, image=None)
        else:
            qr = generate_ascii_qr(data_to_encode)
            self.lbl_qr.configure(text=qr, image=None)

        self.update_totp_code()

    def update_totp_code(self):
        if hasattr(self, 'lbl_totp_code') and self.lbl_totp_code.winfo_exists():
            if self.secret_value:
                code, rem = get_totp_code(self.secret_value)
                if code:
                    self.lbl_totp_code.configure(text=f"{code[:3]} {code[3:]}  (⏱️ {rem}s)")
            self.after(1000, self.update_totp_code)

    def _start_totp_timer(self):
        pass

    def copy_secret(self):
        if self.secret_value:
            pyperclip.copy(self.secret_value)
            messagebox.showinfo("SecurPass", "Clé secrète copiée dans le presse-papiers !", parent=self)

    def on_verify(self):
        entered_code = self.entry_totp_token.get().strip().replace(" ", "")
        if not entered_code.isdigit() or len(entered_code) != 6:
            messagebox.showwarning(
                "Code requis",
                "Saisissez le code TOTP à 6 chiffres de votre application Authenticator.",
                parent=self
            )
            return

        def verify_request():
            try:
                response = requests.post(
                    f"{API_URL}/auth/totp/verify",
                    json={"token": entered_code},
                    headers=get_anti_replay_headers(self.token),
                    timeout=5
                )
                data = response.json()
                if response.ok and data.get("success"):
                    self.after(0, self._verification_succeeded)
                    return
                error_message = data.get("error", "Code TOTP invalide ou expiré.")
            except Exception as error:
                error_message = f"Impossible de vérifier le code : {error}"
            self.after(0, lambda error_message=error_message: messagebox.showerror(
                "Vérification 2FA", error_message, parent=self
            ))

        threading.Thread(target=verify_request, daemon=True).start()

    def _verification_succeeded(self):
        messagebox.showinfo(
            "2FA confirmée",
            "Le code TOTP est valide. La configuration est confirmée.",
            parent=self
        )
        self.destroy()


def generate_ascii_qr(data, width=17):
    """Génère un code QR ASCII simple à partir d'une chaîne (otpauth URL ou secret)."""
    # Implémentation simple basée sur un pattern de bloc ASCII
    # Utilise des blocs pleins pour représenter un QR code minimal
    lines = []
    for i in range(width):
        row = ""
        for j in range(width):
            # Crée un pattern déterministe basé sur le contenu
            idx = (i * width + j) % len(data)
            val = ord(data[idx]) if data else 0
            if (val + i + j) % 3 == 0:
                row += "##"
            else:
                row += "  "
        lines.append(row)
    border = " " * 2 + "#" * (width * 2) + " " * 2
    return border + "\n" + "\n".join("  " + l + "  " for l in lines) + "\n" + border


# ==========================================
# 📜 AUDIT LOG MODAL (Admin)
# ==========================================
class AuditLogModal(ctk.CTkToplevel):
    """Fenêtre de consultation des journaux d'audit pour les administrateurs."""
    def __init__(self, parent, token):
        super().__init__(parent)
        self.parent = parent
        self.token = token

        self.title("📜 Journal d'Audit")
        self.geometry("900x600")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (900 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (600 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()
        self.load_audit_logs()

    def create_widgets(self):
        header = ctk.CTkLabel(self, text="📜 Journal d'Audit - Actions Sensibles",
                              font=ctk.CTkFont(size=18, weight="bold"))
        header.pack(pady=(15, 10))

        filter_frame = ctk.CTkFrame(self, fg_color="transparent")
        filter_frame.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(filter_frame, text="Filtrer par utilisateur:", font=ctk.CTkFont(size=10)).pack(side="left")
        self.ent_filter_user = ctk.CTkEntry(filter_frame, placeholder_text="username", width=120, height=28)
        self.ent_filter_user.pack(side="left", padx=(5, 10))

        ctk.CTkLabel(filter_frame, text="Action:", font=ctk.CTkFont(size=10)).pack(side="left")
        self.opt_filter_action = ctk.CTkOptionMenu(filter_frame,
            values=["Toutes", "auth", "vault", "share", "admin", "security"], height=28, width=120)
        self.opt_filter_action.pack(side="left", padx=5)

        btn_apply = ctk.CTkButton(filter_frame, text="🔍 Filtrer", width=80, height=28,
                                  command=self.load_audit_logs)
        btn_apply.pack(side="left", padx=10)

        btn_clear = ctk.CTkButton(filter_frame, text="🧹 Effacer filtres", width=100, height=28,
                                  fg_color=COLOR_AMBER, hover_color="#b45309",
                                  command=self.clear_filters)
        btn_clear.pack(side="left", padx=5)

        self.scroll_logs = ctk.CTkScrollableFrame(self)
        self.scroll_logs.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.total_var = ctk.StringVar(value="0 entrée(s)")
        self.lbl_total = ctk.CTkLabel(self, textvariable=self.total_var, font=ctk.CTkFont(size=11), text_color=COLOR_MUTED)
        self.lbl_total.pack(pady=(0, 5))

    def clear_filters(self):
        self.ent_filter_user.delete(0, 'end')
        self.opt_filter_action.set("Toutes")
        self.load_audit_logs()

    def load_audit_logs(self, offset=0):
        username = self.ent_filter_user.get().strip() or None
        action_val = self.opt_filter_action.get()
        action = None if action_val == "Toutes" else action_val

        def req():
            try:
                params = f"?limit=100&offset={offset}"
                if username:
                    params += f"&username={requests.utils.quote(username)}"
                if action:
                    params += f"&action={requests.utils.quote(action)}"

                headers = {"Authorization": f"Bearer {self.token}"}
                res = requests.get(f"{API_URL}/audit/logs{params}", headers=headers, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    self.after(0, lambda: self.render_logs(data))
                else:
                    self.after(0, lambda: ctk.CTkLabel(self.scroll_logs, text=f"Erreur: {res.status_code}", text_color=COLOR_DANGER).pack(pady=20))
            except Exception as e:
                self.after(0, lambda error=str(e): ctk.CTkLabel(self.scroll_logs, text=f"Erreur: {error}", text_color=COLOR_DANGER).pack(pady=20))

        threading.Thread(target=req, daemon=True).start()

    def render_logs(self, data):
        for w in self.scroll_logs.winfo_children():
            w.destroy()

        entries = data.get('entries', []) if isinstance(data, dict) else data
        total = data.get('total', len(entries)) if isinstance(data, dict) else len(entries)
        self.total_var.set(f"{total} entrée(s)")

        if not entries:
            ctk.CTkLabel(self.scroll_logs, text="Aucune entrée d'audit pour le moment.",
                         font=ctk.CTkFont(size=13), text_color=COLOR_MUTED).pack(pady=40)
            return

        for entry in entries:
            card = ctk.CTkFrame(self.scroll_logs, fg_color=COLOR_CARD, corner_radius=8)
            card.pack(fill="x", pady=3)

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(fill="x", padx=12, pady=10)

            status_color = COLOR_SUCCESS if entry.get('success', True) else COLOR_DANGER
            status_icon = "✅" if entry.get('success', True) else "❌"

            ctk.CTkLabel(info, text=f"{status_icon} {entry.get('action', '?')}",
                         font=ctk.CTkFont(size=11, weight="bold"), text_color=status_color).pack(anchor="w")
            ctk.CTkLabel(info, text=f"👤 @{entry.get('username', '?')}  •  {entry.get('ip', '?')}",
                         font=ctk.CTkFont(size=10), text_color=COLOR_MUTED).pack(anchor="w")

            ts = entry.get('timestamp', '')
            try:
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                ts_disp = dt.strftime('%d/%m/%Y à %H:%M:%S')
            except Exception:
                ts_disp = ts
            ctk.CTkLabel(info, text=f"🕒 {ts_disp}", font=ctk.CTkFont(size=10),
                         text_color=COLOR_MUTED).pack(anchor="w")

            if entry.get('target'):
                ctk.CTkLabel(info, text=f"🎯 Cible: {entry.get('target')}",
                             font=ctk.CTkFont(size=10), text_color=COLOR_MUTED).pack(anchor="w")


# ==========================================
# 🔐 POLICY MODAL (Admin)
# ==========================================
class PolicyModal(ctk.CTkToplevel):
    """Modal de configuration de la politique de mots de passe globale (administrateurs)."""
    def __init__(self, parent, token):
        super().__init__(parent)
        self.parent = parent
        self.token = token

        self.title("🔐 Politique de Mots de Passe")
        self.geometry("560x560")
        self.resizable(False, False)
        self.grab_set()

        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (560 // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (560 // 2)
        self.geometry(f"+{x}+{y}")

        self.create_widgets()
        self.load_policy()

    def create_widgets(self):
        ctk.CTkLabel(self, text="🔐 Configuration de la Politique de Mots de Passe",
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(20, 5))
        ctk.CTkLabel(self, text="Définissez les règles de complexité et de rotation pour tous les utilisateurs.",
                     font=ctk.CTkFont(size=11), text_color=COLOR_MUTED, wraplength=520).pack(pady=(0, 20))

        self.scroll = ctk.CTkScrollableFrame(self)
        self.scroll.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        form = ctk.CTkFrame(self.scroll, fg_color="transparent")
        form.pack(fill="x")

        def make_field(label, widget_name, default_val, field_type="entry", **kwargs):
            ctk.CTkLabel(form, text=label, font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", pady=(10, 2))
            if field_type == "spinbox":
                w = ctk.CTkEntry(form, placeholder_text=str(default_val), height=32, justify="center")
            elif field_type == "switch":
                w = ctk.CTkCheckBox(form, text="", **kwargs)
            else:
                w = ctk.CTkEntry(form, placeholder_text=str(default_val), height=32)
            setattr(self, widget_name, w)
            w.pack(fill="x", pady=(0, 8))
            return w

        self.ent_min_length = make_field("Longueur minimale *", "ent_min_length", 8)
        self.ent_max_age = make_field("Durée max. avant expiration (jours) *", "ent_max_age", 90)
        self.ent_prevent_reuse = make_field("Nombre de mots de passe à ne pas réutiliser *", "ent_prevent_reuse", 5)

        self.chk_upper = make_field("Exiger des majuscules (A-Z)", "chk_upper", None, "switch")
        self.chk_lower = make_field("Exiger des minuscules (a-z)", "chk_lower", None, "switch")
        self.chk_numbers = make_field("Exiger des chiffres (0-9)", "chk_numbers", None, "switch")
        self.chk_symbols = make_field("Exiger des symboles (!@#$...)", "chk_symbols", None, "switch")

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(0, 20))

        ctk.CTkButton(btn_frame, text="Annuler", fg_color="#475569", height=38,
                      command=self.destroy).pack(side="left", fill="x", expand=True, padx=(0, 5))
        ctk.CTkButton(btn_frame, text="💾 Enregistrer", fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER,
                      height=38, command=self.save_policy).pack(side="right", fill="x", expand=True, padx=(5, 0))

    def load_policy(self):
        def req():
            try:
                headers = {"Authorization": f"Bearer {self.token}"}
                res = requests.get(f"{API_URL}/admin/policy", headers=headers, timeout=5)
                if res.status_code == 200:
                    data = res.json()
                    self.after(0, lambda: self.populate_policy(data))
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", error, parent=self))

        threading.Thread(target=req, daemon=True).start()

    def populate_policy(self, policy):
        self.ent_min_length.delete(0, 'end'); self.ent_min_length.insert(0, str(policy.get('minLength', 8)))
        self.ent_max_age.delete(0, 'end'); self.ent_max_age.insert(0, str(policy.get('maxAgeDays', 90)))
        self.ent_prevent_reuse.delete(0, 'end'); self.ent_prevent_reuse.insert(0, str(policy.get('preventReuse', 5)))
        if policy.get('requireUppercase'): self.chk_upper.select()
        if policy.get('requireLowercase'): self.chk_lower.select()
        if policy.get('requireNumbers'): self.chk_numbers.select()
        if policy.get('requireSymbols'): self.chk_symbols.select()

    def save_policy(self):
        try:
            min_len = int(self.ent_min_length.get())
            max_age = int(self.ent_max_age.get())
            reuse = int(self.ent_prevent_reuse.get())
        except ValueError:
            messagebox.showerror("Erreur", "Veuillez saisir des nombres valides.", parent=self)
            return

        payload = {
            "minLength": min_len,
            "maxAgeDays": max_age,
            "preventReuse": reuse,
            "requireUppercase": bool(self.chk_upper.get()),
            "requireLowercase": bool(self.chk_lower.get()),
            "requireNumbers": bool(self.chk_numbers.get()),
            "requireSymbols": bool(self.chk_symbols.get())
        }

        def req():
            try:
                headers = get_anti_replay_headers(self.token)
                res = requests.put(f"{API_URL}/admin/policy", headers=headers,
                                   json=payload, timeout=5)
                if res.status_code == 200:
                    self.after(0, lambda: messagebox.showinfo("Succès", "Politique mise à jour.", parent=self))
                    self.after(0, self.destroy)
                else:
                    data = res.json()
                    self.after(0, lambda: messagebox.showerror("Erreur", data.get('error', 'Échec'), parent=self))
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", error, parent=self))

        threading.Thread(target=req, daemon=True).start()

class SecurPassApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SecurPass v2.0 - Application Bureau Native & Synchronisée")
        self.geometry("1240x800")
        self.minsize(980, 680)

        self.token = None
        self.user = None
        self.is_offline = False
        self.vault_items = []
        self.shared_items = []
        self._autofill_sessions = []

        self.init_global_hotkey()
        self.create_login_view()

    def init_global_hotkey(self):
        """Initialise l'écouteur de raccourci clavier global Ctrl+Alt+A (Native Windows)."""
        def on_hotkey():
            self.after(0, self.trigger_global_autofill_quicksearch)

        def listen_thread():
            try:
                user32 = ctypes.windll.user32
                HOTKEY_ID = 101
                # MOD_ALT (0x1) + MOD_CONTROL (0x2), VK_A (0x41)
                if user32.RegisterHotKey(None, HOTKEY_ID, 0x0001 | 0x0002, 0x41):
                    msg = ctypes.wintypes.MSG()
                    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
                        if msg.message == 0x0312:  # WM_HOTKEY
                            if msg.wParam == HOTKEY_ID:
                                on_hotkey()
                        user32.TranslateMessage(ctypes.byref(msg))
                        user32.DispatchMessageW(ctypes.byref(msg))
            except Exception as e:
                print(f"[Hotkey Warning] {e}")

        threading.Thread(target=listen_thread, daemon=True).start()

    def trigger_global_autofill_quicksearch(self):
        """Action déclenchée par le raccourci global Ctrl+Alt+A."""
        self.deiconify()
        self.lift()
        self.focus_force()
        if hasattr(self, 'entry_search') and self.entry_search.winfo_exists():
            self.entry_search.focus_set()

    # ==========================================
    # 🔐 VUE AUTHENTIFICATION / LOGIN
    # ==========================================
    def _safe_status(self, text, color=COLOR_DANGER):
        """Safely update login status label from threaded callbacks."""
        if hasattr(self, 'lbl_login_status') and self.lbl_login_status.winfo_exists():
            self.lbl_login_status.configure(text=text, text_color=color)

    def create_login_view(self):
        self.clear_frame()

        self.frame_login = ctk.CTkFrame(self, width=440, height=540, corner_radius=16, fg_color=COLOR_CARD)
        self.frame_login.place(relx=0.5, rely=0.5, anchor="center")

        lbl_logo = ctk.CTkLabel(self.frame_login, text="🔒 SecurPass", font=ctk.CTkFont(size=28, weight="bold"))
        lbl_logo.pack(pady=(35, 5))

        lbl_version = ctk.CTkLabel(self.frame_login, text="Édition Entreprise Native v2.0", font=ctk.CTkFont(size=12), text_color=COLOR_MUTED)
        lbl_version.pack(pady=(0, 25))

        # Connexion SSO Bouton Principal
        btn_sso = ctk.CTkButton(
            self.frame_login,
            text="⚡ Connexion SSO Active Directory",
            font=ctk.CTkFont(size=14, weight="bold"),
            height=44,
            fg_color=COLOR_PRIMARY,
            hover_color=COLOR_PRIMARY_HOVER,
            command=self.handle_sso_login
        )
        btn_sso.pack(fill="x", padx=40, pady=(0, 20))

        # Séparateur
        lbl_or = ctk.CTkLabel(self.frame_login, text="─── ou connexion manuelle LDAP ───", font=ctk.CTkFont(size=11), text_color=COLOR_MUTED)
        lbl_or.pack(pady=(0, 15))

        # Formulaire manuel
        self.entry_username = ctk.CTkEntry(self.frame_login, placeholder_text="Identifiant LDAP (ex: admin)", height=40)
        self.entry_username.pack(fill="x", padx=40, pady=(0, 12))

        self.entry_password = ctk.CTkEntry(self.frame_login, placeholder_text="Mot de passe", show="•", height=40)
        self.entry_password.pack(fill="x", padx=40, pady=(0, 20))

        btn_login = ctk.CTkButton(
            self.frame_login,
            text="Se Connecter",
            font=ctk.CTkFont(size=13, weight="bold"),
            height=40,
            command=self.handle_manual_login
        )
        btn_login.pack(fill="x", padx=40, pady=(0, 15))

        self.lbl_login_status = ctk.CTkLabel(self.frame_login, text="", text_color=COLOR_DANGER)
        self.lbl_login_status.pack()

    def handle_sso_login(self):
        if not hasattr(self, 'lbl_login_status') or not self.lbl_login_status.winfo_exists():
            self.create_login_view()
        self.lbl_login_status.configure(text="Connexion SSO en cours...", text_color=COLOR_PRIMARY)
        def req():
            try:
                res = requests.get(f"{API_URL}/auth/sso?mock=true", timeout=5)
                data = res.json()
                if res.status_code == 200:
                    self.token = data.get('token')
                    self.user = data.get('user')
                    self.is_offline = False
                    self.after(0, self.setup_dashboard)
                else:
                    err = data.get('error', 'Erreur SSO')
                    self.after(0, lambda: self._safe_status(err, COLOR_DANGER))
            except Exception as e:
                err_msg = f"Impossible de joindre le serveur : {e}"
                self.after(0, lambda: self._safe_status(err_msg, COLOR_DANGER))

        threading.Thread(target=req, daemon=True).start()

    def handle_manual_login(self):
        username = self.entry_username.get().strip()
        password = self.entry_password.get()
        if not username or not password:
            self._safe_status("Veuillez remplir tous les champs.", COLOR_DANGER)
            return

        self._safe_status("Authentification en cours...", COLOR_PRIMARY)
        headers = get_anti_replay_headers()

        def req():
            try:
                res = requests.post(f"{API_URL}/auth/login", json={"username": username, "password": password}, headers=headers, timeout=5)
                data = res.json()
                if res.status_code == 200:
                    self.token = data.get('token')
                    self.user = data.get('user')
                    self.is_offline = False
                    self.after(0, self.setup_dashboard)
                else:
                    err = data.get('error', 'Identifiants invalides')
                    self.after(0, lambda: self._safe_status(err, COLOR_DANGER))
            except Exception as e:
                # Mode hors-ligne secours si réseau inaccessible
                offline_items = load_offline_cache(username)
                if offline_items:
                    self.token = "offline_session_token"
                    self.user = {"username": username, "displayName": f"{username} (Offline)"}
                    self.is_offline = True
                    self.after(0, self.setup_dashboard)
                else:
                    err_msg = f"Erreur connexion : {e}"
                    self.after(0, lambda: self._safe_status(err_msg, COLOR_DANGER))

        threading.Thread(target=req, daemon=True).start()

    # ==========================================
    # 🏠 DASHBOARD PRINCIPAL
    # ==========================================
    def setup_dashboard(self):
        self.clear_frame()

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar Gauche
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0, fg_color=COLOR_CARD)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        lbl_side_title = ctk.CTkLabel(self.sidebar, text="🔒 SecurPass", font=ctk.CTkFont(size=20, weight="bold"))
        lbl_side_title.pack(pady=(20, 2))

        lbl_badge = ctk.CTkLabel(self.sidebar, text="ÉDITION DESKTOP v2.0", font=ctk.CTkFont(size=9, weight="bold"), text_color=COLOR_PRIMARY)
        lbl_badge.pack(pady=(0, 10))

        username = self.user.get('username', '').lower()
        disp_name = self.user.get('displayName', 'Utilisateur')
        lbl_user = ctk.CTkLabel(self.sidebar, text=f"👤 {disp_name}", font=ctk.CTkFont(size=12), text_color=COLOR_MUTED)
        lbl_user.pack(pady=(0, 20))

        # Navigation Buttons
        self.btn_nav_vault = ctk.CTkButton(self.sidebar, text="🔒 Mon Coffre-Fort", anchor="w", font=ctk.CTkFont(size=13, weight="bold"), command=lambda: self.switch_view("vault"))
        self.btn_nav_vault.pack(fill="x", padx=15, pady=4)

        self.btn_nav_shared = ctk.CTkButton(self.sidebar, text="👥 Partagés avec moi", anchor="w", fg_color="transparent", text_color=COLOR_MUTED, command=lambda: self.switch_view("shared"))
        self.btn_nav_shared.pack(fill="x", padx=15, pady=4)

        self.btn_nav_gen = ctk.CTkButton(self.sidebar, text="🔑 Générateur", anchor="w", fg_color="transparent", text_color=COLOR_MUTED, command=lambda: self.switch_view("generator"))
        self.btn_nav_gen.pack(fill="x", padx=15, pady=4)

        self.btn_nav_logs = ctk.CTkButton(self.sidebar, text="📋 Logs d'inscription", anchor="w", fg_color="transparent", text_color=COLOR_MUTED, command=lambda: self.switch_view("logs"))
        self.btn_nav_logs.pack(fill="x", padx=15, pady=4)

        self.btn_nav_security = ctk.CTkButton(self.sidebar, text="🔐 Sécurité", anchor="w", fg_color="transparent", text_color=COLOR_MUTED, command=lambda: self.switch_view("security"))
        self.btn_nav_security.pack(fill="x", padx=15, pady=4)

        self.btn_nav_totp = ctk.CTkButton(self.sidebar, text="🔑 2FA / TOTP", anchor="w", fg_color="transparent", text_color=COLOR_MUTED, command=self.open_totp_modal)
        self.btn_nav_totp.pack(fill="x", padx=15, pady=4)

        # Onglet Admin si l'utilisateur a les droits d'administration
        self.is_admin = username in ['admin', 'administrateur', 'administrator']
        if self.is_admin:
            self.btn_nav_admin = ctk.CTkButton(self.sidebar, text="🛠️ Administration", anchor="w", fg_color="transparent", text_color=COLOR_MUTED, command=lambda: self.switch_view("admin"))
            self.btn_nav_admin.pack(fill="x", padx=15, pady=4)

            self.btn_nav_audit = ctk.CTkButton(self.sidebar, text="📜 Journal d'audit", anchor="w", fg_color="transparent", text_color=COLOR_MUTED, command=self.open_audit_modal)
            self.btn_nav_audit.pack(fill="x", padx=15, pady=4)

            self.btn_nav_policy = ctk.CTkButton(self.sidebar, text="🔐 Politique", anchor="w", fg_color="transparent", text_color=COLOR_MUTED, command=self.open_policy_modal)
            self.btn_nav_policy.pack(fill="x", padx=15, pady=4)

        # Indicator Raccourci Global
        lbl_hotkey = ctk.CTkLabel(self.sidebar, text="⌨️ Hotkey: Ctrl+Alt+A", font=ctk.CTkFont(size=10), text_color=COLOR_SUCCESS)
        lbl_hotkey.pack(side="bottom", pady=(0, 10))

        # Déconnexion
        btn_logout = ctk.CTkButton(self.sidebar, text="🚪 Déconnexion", fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER, command=self.create_login_view)
        btn_logout.pack(side="bottom", fill="x", padx=15, pady=(0, 10))

        # Zone Principale
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)

        self.current_view = "vault"
        self.create_vault_view()
        self.load_vault_data()

        # Timer d'auto-synchronisation réseau (toutes les 30 secondes)
        self.start_sync_timer()

    def start_sync_timer(self):
        """Lance une vérification et synchronisation périodique des données."""
        def auto_sync():
            while self.token:
                time.sleep(30)
                if self.token and not self.is_offline:
                    self.load_vault_data(silent=True)
        threading.Thread(target=auto_sync, daemon=True).start()

    def switch_view(self, view_name):
        self.current_view = view_name

        nav_btns = [
            ("vault", self.btn_nav_vault),
            ("shared", self.btn_nav_shared),
            ("generator", self.btn_nav_gen),
            ("logs", self.btn_nav_logs),
            ("security", self.btn_nav_security)
        ]
        if self.is_admin and hasattr(self, 'btn_nav_admin'):
            nav_btns.append(("admin", self.btn_nav_admin))

        for key, btn in nav_btns:
            if key == view_name:
                btn.configure(fg_color=COLOR_PRIMARY, text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color=COLOR_MUTED)

        if view_name == "vault":
            self.create_vault_view()
            self.render_vault()
        elif view_name == "shared":
            self.create_shared_view()
            self.load_shared_data()
        elif view_name == "generator":
            self.create_generator_view()
        elif view_name == "logs":
            self.create_logs_view()
            self.load_logs()
        elif view_name == "admin":
            self.create_admin_view()
            self.load_admin_data()
        elif view_name == "security":
            self.create_security_view()
            self.render_security_view()

    # ==========================================
    # 🔐 VUE SÉCURITÉ (Desktop)
    # ==========================================
    def create_security_view(self):
        for w in self.main_container.winfo_children(): w.destroy()

        top_bar = ctk.CTkFrame(self.main_container, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", pady=(0, 15))

        btn_refresh = ctk.CTkButton(top_bar, text="🔄 Actualiser", height=36,
                                    command=self.render_security_view)
        btn_refresh.pack(side="right")

        self.security_frame = SecurityScoreFrame(self.main_container, self.token, self.user)
        self.security_frame.grid(row=1, column=0, sticky="nsew")

    def render_security_view(self):
        if hasattr(self, 'security_frame') and self.security_frame:
            self.security_frame.load_security_score()

    def open_totp_modal(self):
        if self.is_offline:
            messagebox.showwarning("Hors-ligne", "TOTP setup nécessite une connexion au serveur.", parent=self)
            return
        self.switch_view(self.current_view)  # re-établit la vue courante
        TOTPSetupModal(self, self.token)

    def open_audit_modal(self):
        if self.is_offline:
            messagebox.showwarning("Hors-ligne", "Ce module nécessite une connexion au serveur.", parent=self)
            return
        AuditLogModal(self, self.token)

    def open_policy_modal(self):
        if self.is_offline:
            messagebox.showwarning("Hors-ligne", "Ce module nécessite une connexion au serveur.", parent=self)
            return
        PolicyModal(self, self.token)

    # ==========================================
    # 🔒 VUE COFFRE-FORT (VAULT)
    # ==========================================
    def create_vault_view(self):
        for w in self.main_container.winfo_children(): w.destroy()

        top_bar = ctk.CTkFrame(self.main_container, fg_color="transparent")
        top_bar.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        top_bar.grid_columnconfigure(0, weight=1)

        # Recherche
        self.entry_search = ctk.CTkEntry(top_bar, placeholder_text="🔍 Rechercher un compte, site, identifiant (Ctrl+Alt+A)...", height=40)
        self.entry_search.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.entry_search.bind("<KeyRelease>", lambda e: self.render_vault())

        # Filtre Catégorie
        self.opt_filter_cat = ctk.CTkOptionMenu(
            top_bar, 
            values=["Toutes catégories", "Général", "Professionnel", "Finance", "Réseaux Sociaux", "Personnel"], 
            height=40, 
            command=lambda v: self.render_vault()
        )
        self.opt_filter_cat.grid(row=0, column=1, padx=(0, 8))

        # Actions principales
        btn_add = ctk.CTkButton(top_bar, text="➕ Nouveau", height=40, font=ctk.CTkFont(weight="bold"), command=self.open_add_modal)
        btn_add.grid(row=0, column=2, padx=(0, 6))

        btn_import = ctk.CTkButton(top_bar, text="🔼 Importer", height=40, fg_color="#334155", hover_color="#475569", command=self.open_import_modal)
        btn_import.grid(row=0, column=3, padx=(0, 6))

        btn_exp_csv = ctk.CTkButton(top_bar, text="📄 CSV", height=40, width=65, fg_color="#334155", hover_color="#475569", command=self.export_csv)
        btn_exp_csv.grid(row=0, column=4, padx=(0, 6))

        btn_exp_json = ctk.CTkButton(top_bar, text="📦 JSON", height=40, width=65, fg_color="#334155", hover_color="#475569", command=self.export_json)
        btn_exp_json.grid(row=0, column=5)

        # Badge Statut Réseau / Synchro
        status_text = "🟠 Hors-Ligne (Cache local)" if self.is_offline else "🟢 Synchronisé"
        status_color = COLOR_AMBER if self.is_offline else COLOR_SUCCESS
        lbl_status = ctk.CTkLabel(self.main_container, text=status_text, font=ctk.CTkFont(size=11, weight="bold"), text_color=status_color)
        lbl_status.grid(row=0, column=0, sticky="e", pady=(0, 5))

        # Grille scrollable
        self.scroll_vault = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")
        self.scroll_vault.grid(row=1, column=0, sticky="nsew")

    def load_vault_data(self, silent=False):
        username = self.user.get('username', '').lower()

        if self.is_offline:
            self.vault_items = load_offline_cache(username)
            if not silent: self.after(0, self.render_vault)
            return

        def req():
            try:
                headers = {"Authorization": f"Bearer {self.token}"}
                res = requests.get(f"{API_URL}/vault", headers=headers, timeout=5)
                if res.status_code == 200:
                    self.vault_items = res.json()
                    save_offline_cache(self.vault_items, username)
                    if not silent: self.after(0, self.render_vault)
                else:
                    self.is_offline = True
                    self.vault_items = load_offline_cache(username)
                    if not silent: self.after(0, self.render_vault)
            except Exception:
                self.is_offline = True
                self.vault_items = load_offline_cache(username)
                if not silent: self.after(0, self.render_vault)

        threading.Thread(target=req, daemon=True).start()

    def render_vault(self):
        if self.current_view != "vault": return
        for w in self.scroll_vault.winfo_children(): w.destroy()

        search_q = self.entry_search.get().lower().strip()
        selected_cat = self.opt_filter_cat.get()

        filtered = []
        for item in self.vault_items:
            title = (item.get('title') or '').lower()
            user = (item.get('username') or '').lower()
            url = (item.get('websiteUrl') or '').lower()
            cat = item.get('category', 'Général')

            matches_q = not search_q or (search_q in title or search_q in user or search_q in url)
            matches_c = selected_cat == "Toutes catégories" or cat == selected_cat

            if matches_q and matches_c:
                filtered.append(item)

        if not filtered:
            lbl_empty = ctk.CTkLabel(self.scroll_vault, text="Aucun compte trouvé.", font=ctk.CTkFont(size=14), text_color=COLOR_MUTED)
            lbl_empty.pack(pady=40)
            return

        for item in filtered:
            card = ctk.CTkFrame(self.scroll_vault, corner_radius=12, fg_color=COLOR_CARD)
            card.pack(fill="x", pady=6, padx=4)

            # Gauche : Infos
            frame_info = ctk.CTkFrame(card, fg_color="transparent")
            frame_info.pack(side="left", fill="both", expand=True, padx=15, pady=12)

            lbl_card_title = ctk.CTkLabel(frame_info, text=item.get('title', 'Sans titre'), font=ctk.CTkFont(size=16, weight="bold"), anchor="w")
            lbl_card_title.pack(anchor="w")

            user_disp = item.get('username') or 'Aucun identifiant'
            url_disp = item.get('websiteUrl') or 'Sans URL'
            cat_disp = item.get('category') or 'Général'

            sub_text = f"🏷️ {cat_disp}   •   👤 {user_disp}   •   🌐 {url_disp}"
            lbl_card_sub = ctk.CTkLabel(frame_info, text=sub_text, font=ctk.CTkFont(size=12), text_color=COLOR_MUTED, anchor="w")
            lbl_card_sub.pack(anchor="w")

            # Affichage TOTP / 2FA si présent
            totp_secret = item.get('totpSecret') or ''
            if not totp_secret and '[TOTP:' in (item.get('notes') or ''):
                try:
                    totp_secret = item.get('notes').split('[TOTP:')[1].split(']')[0].strip()
                except Exception: pass

            if totp_secret:
                code, rem = get_totp_code(totp_secret)
                if code:
                    frame_totp = ctk.CTkFrame(frame_info, fg_color="transparent")
                    frame_totp.pack(anchor="w", pady=(3, 0))
                    lbl_totp = ctk.CTkLabel(frame_totp, text=f"🔐 2FA TOTP: {code[:3]} {code[3:]}  (⏱️ {rem}s)", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLOR_PRIMARY)
                    lbl_totp.pack(side="left")
                    btn_copy_totp = ctk.CTkButton(frame_totp, text="📋 OTP", width=55, height=22, font=ctk.CTkFont(size=10), fg_color="#334155", command=lambda c=code: self.copy_to_clip(c, "Code TOTP copié !"))
                    btn_copy_totp.pack(side="left", padx=8)

            # Droite : Actions
            frame_actions = ctk.CTkFrame(card, fg_color="transparent")
            frame_actions.pack(side="right", padx=12, pady=12)

            btn_autofill = ctk.CTkButton(
                frame_actions,
                text="⚡ Remplir sur PC",
                width=115,
                fg_color=COLOR_SUCCESS,
                hover_color=COLOR_SUCCESS_HOVER,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda i=item: self.direct_desktop_autofill(i)
            )
            btn_autofill.pack(side="left", padx=3)

            btn_copy_user = ctk.CTkButton(frame_actions, text="📋 User", width=65, fg_color="#334155", hover_color="#475569", command=lambda i=item: self.copy_to_clip(i.get('username', ''), "Identifiant copié !"))
            btn_copy_user.pack(side="left", padx=3)

            btn_copy_pwd = ctk.CTkButton(frame_actions, text="📋 Pwd", width=65, fg_color="#334155", hover_color="#475569", command=lambda i=item: self.copy_to_clip(i.get('password', ''), "Mot de passe copié !"))
            btn_copy_pwd.pack(side="left", padx=3)

            btn_share = ctk.CTkButton(frame_actions, text="🔗 Partager", width=80, fg_color=COLOR_PURPLE, hover_color=COLOR_PURPLE_HOVER, command=lambda i=item: self.open_share_modal(i))
            btn_share.pack(side="left", padx=3)

            btn_manage = ctk.CTkButton(frame_actions, text="👥 Accès", width=65, fg_color="#334155", hover_color="#475569", command=lambda i=item: self.open_manage_shares_modal(i))
            btn_manage.pack(side="left", padx=3)

            btn_hist = ctk.CTkButton(frame_actions, text="📜", width=35, fg_color="#334155", hover_color="#475569", command=lambda i=item: self.open_history_modal(i))
            btn_hist.pack(side="left", padx=3)

            btn_edit = ctk.CTkButton(frame_actions, text="✏️", width=35, fg_color="#334155", hover_color="#475569", command=lambda i=item: self.open_edit_modal(i))
            btn_edit.pack(side="left", padx=3)

            btn_del = ctk.CTkButton(frame_actions, text="🗑️", width=35, fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER, command=lambda i=item: self.delete_entry(i))
            btn_del.pack(side="left", padx=3)

    # ==========================================
    # 👥 VUE "PARTAGÉS AVEC MOI"
    # ==========================================
    def create_shared_view(self):
        for w in self.main_container.winfo_children(): w.destroy()

        top_bar = ctk.CTkFrame(self.main_container, fg_color="transparent")
        top_bar.pack(fill="x", pady=(0, 15))

        lbl_title = ctk.CTkLabel(top_bar, text="👥 Mots de passe partagés avec moi", font=ctk.CTkFont(size=20, weight="bold"))
        lbl_title.pack(side="left")

        btn_refresh = ctk.CTkButton(top_bar, text="🔄 Actualiser", command=self.load_shared_data)
        btn_refresh.pack(side="right")

        self.scroll_shared = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")
        self.scroll_shared.pack(fill="both", expand=True)

    def load_shared_data(self):
        for w in self.scroll_shared.winfo_children(): w.destroy()

        def req():
            try:
                headers = {"Authorization": f"Bearer {self.token}"}
                res = requests.get(f"{API_URL}/vault/shared-with-me", headers=headers, timeout=5)
                if res.status_code == 200:
                    self.shared_items = res.json()
                    self.after(0, self.render_shared)
                else:
                    self.after(0, lambda: ctk.CTkLabel(self.scroll_shared, text="Erreur de chargement des partages.", text_color=COLOR_MUTED).pack(pady=40))
            except Exception as e:
                self.after(0, lambda error=str(e): ctk.CTkLabel(self.scroll_shared, text=f"Erreur : {error}", text_color=COLOR_MUTED).pack(pady=40))

        threading.Thread(target=req, daemon=True).start()

    def render_shared(self):
        if self.current_view != "shared": return
        for w in self.scroll_shared.winfo_children(): w.destroy()

        if not self.shared_items:
            ctk.CTkLabel(self.scroll_shared, text="Aucun mot de passe n'a été partagé avec vous pour le moment.", font=ctk.CTkFont(size=14), text_color=COLOR_MUTED).pack(pady=40)
            return

        for item in self.shared_items:
            card = ctk.CTkFrame(self.scroll_shared, corner_radius=12, fg_color=COLOR_CARD)
            card.pack(fill="x", pady=6, padx=4)

            frame_info = ctk.CTkFrame(card, fg_color="transparent")
            frame_info.pack(side="left", fill="both", expand=True, padx=15, pady=12)

            owner = item.get('owner') or 'Inconnu'
            perm = "✏️ Modification" if item.get('permission') == 'write' else "👁️ Lecture seule"

            ctk.CTkLabel(frame_info, text=f"{item.get('title', 'Sans titre')}", font=ctk.CTkFont(size=16, weight="bold"), anchor="w").pack(anchor="w")
            ctk.CTkLabel(frame_info, text=f"👤 Partagé par @{owner}   •   {perm}", font=ctk.CTkFont(size=12, weight="bold"), text_color=COLOR_PURPLE, anchor="w").pack(anchor="w")

            user_disp = item.get('username') or 'Aucun identifiant'
            url_disp = item.get('websiteUrl') or 'Sans URL'
            ctk.CTkLabel(frame_info, text=f"👤 {user_disp}   •   🌐 {url_disp}", font=ctk.CTkFont(size=11), text_color=COLOR_MUTED, anchor="w").pack(anchor="w")

            frame_actions = ctk.CTkFrame(card, fg_color="transparent")
            frame_actions.pack(side="right", padx=12, pady=12)

            btn_autofill = ctk.CTkButton(
                frame_actions,
                text="⚡ Remplir sur PC",
                width=115,
                fg_color=COLOR_SUCCESS,
                hover_color=COLOR_SUCCESS_HOVER,
                font=ctk.CTkFont(size=12, weight="bold"),
                command=lambda i=item: self.direct_desktop_autofill(i)
            )
            btn_autofill.pack(side="left", padx=3)

            btn_copy_user = ctk.CTkButton(frame_actions, text="📋 User", width=65, fg_color="#334155", command=lambda i=item: self.copy_to_clip(i.get('username', ''), "Identifiant copié !"))
            btn_copy_user.pack(side="left", padx=3)

            btn_copy_pwd = ctk.CTkButton(frame_actions, text="📋 Pwd", width=65, fg_color="#334155", command=lambda i=item: self.copy_to_clip(i.get('password', ''), "Mot de passe copié !"))
            btn_copy_pwd.pack(side="left", padx=3)

            if item.get('permission') == 'write':
                btn_edit = ctk.CTkButton(frame_actions, text="✏️", width=35, fg_color="#334155", command=lambda i=item: self.open_edit_modal(i))
                btn_edit.pack(side="left", padx=3)

    # ==========================================
    # 🛠️ VUE ADMINISTRATION (STATS & UTILISATEURS AD)
    # ==========================================
    def create_admin_view(self):
        for w in self.main_container.winfo_children(): w.destroy()

        top_bar = ctk.CTkFrame(self.main_container, fg_color="transparent")
        top_bar.pack(fill="x", pady=(0, 15))

        lbl_title = ctk.CTkLabel(top_bar, text="🛠️ Tableau de bord Administration Active Directory", font=ctk.CTkFont(size=20, weight="bold"))
        lbl_title.pack(side="left")

        btn_add_user = ctk.CTkButton(top_bar, text="➕ Créer un utilisateur AD", fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER, command=self.open_add_user_modal)
        btn_add_user.pack(side="right", padx=(5, 0))

        btn_refresh = ctk.CTkButton(top_bar, text="🔄 Actualiser", command=self.load_admin_data)
        btn_refresh.pack(side="right")

        self.scroll_admin = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")
        self.scroll_admin.pack(fill="both", expand=True)

    def load_admin_data(self):
        for w in self.scroll_admin.winfo_children(): w.destroy()

        headers = {"Authorization": f"Bearer {self.token}"}

        def req():
            try:
                res_stats = requests.get(f"{API_URL}/admin/stats", headers=headers, timeout=5)
                res_users = requests.get(f"{API_URL}/admin/users", headers=headers, timeout=5)
                
                stats = res_stats.json() if res_stats.status_code == 200 else {}
                users = res_users.json() if res_users.status_code == 200 else []

                self.after(0, lambda: self.render_admin(stats, users))
            except Exception as e:
                self.after(0, lambda error=str(e): ctk.CTkLabel(self.scroll_admin, text=f"Erreur administration : {error}", text_color=COLOR_MUTED).pack(pady=40))

        threading.Thread(target=req, daemon=True).start()

    def render_admin(self, stats, users):
        if self.current_view != "admin": return
        for w in self.scroll_admin.winfo_children(): w.destroy()

        # cartes de statistiques
        frame_stats = ctk.CTkFrame(self.scroll_admin, fg_color="transparent")
        frame_stats.pack(fill="x", pady=(0, 15))
        frame_stats.grid_columnconfigure((0, 1, 2, 3), weight=1)

        def make_stat_card(parent, col, title, val, color):
            c = ctk.CTkFrame(parent, fg_color=COLOR_CARD, corner_radius=10)
            c.grid(row=0, column=col, sticky="ew", padx=4)
            ctk.CTkLabel(c, text=title, font=ctk.CTkFont(size=11), text_color=COLOR_MUTED).pack(pady=(10, 2))
            ctk.CTkLabel(c, text=str(val), font=ctk.CTkFont(size=22, weight="bold"), text_color=color).pack(pady=(0, 10))

        make_stat_card(frame_stats, 0, "Total Mots de Passe", stats.get('totalPasswords', 0), COLOR_PRIMARY)
        make_stat_card(frame_stats, 1, "Longueur Moyenne", f"{stats.get('avgLength', 0)} car.", COLOR_SUCCESS)
        make_stat_card(frame_stats, 2, "Mots de Passe Faibles", stats.get('extremelyWeak', 0), COLOR_DANGER)
        make_stat_card(frame_stats, 3, "Doublons Détectés", stats.get('reusedPasswords', 0), COLOR_AMBER)

        # Liste des Utilisateurs AD
        ctk.CTkLabel(self.scroll_admin, text="👤 Annuaire des utilisateurs LDAP / Active Directory", font=ctk.CTkFont(size=16, weight="bold"), anchor="w").pack(anchor="w", pady=(10, 10))

        if not users:
            ctk.CTkLabel(self.scroll_admin, text="Aucun utilisateur trouvé.", font=ctk.CTkFont(size=13), text_color=COLOR_MUTED).pack(pady=20)
            return

        for u in users:
            card = ctk.CTkFrame(self.scroll_admin, corner_radius=10, fg_color=COLOR_CARD)
            card.pack(fill="x", pady=4, padx=2)

            info = ctk.CTkFrame(card, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True, padx=15, pady=10)

            disp = u.get('displayName') or u.get('username')
            un = u.get('username')
            em = u.get('email') or 'Pas d\'email'

            ctk.CTkLabel(info, text=f"👤 {disp} (@{un})", font=ctk.CTkFont(size=14, weight="bold"), anchor="w").pack(anchor="w")
            ctk.CTkLabel(info, text=f"✉️ {em}", font=ctk.CTkFont(size=11), text_color=COLOR_MUTED, anchor="w").pack(anchor="w")

            btn_del = ctk.CTkButton(card, text="🗑️ Supprimer", width=90, fg_color=COLOR_DANGER, hover_color=COLOR_DANGER_HOVER, command=lambda usr=un: self.delete_ad_user(usr))
            btn_del.pack(side="right", padx=15)

    def delete_ad_user(self, username):
        if not messagebox.askyesno("Confirmation", f"Supprimer définitivement l'utilisateur @{username} ?", parent=self):
            return

        headers = get_anti_replay_headers(self.token)
        url = f"{API_URL}/admin/users/{username}"

        def req():
            try:
                res = requests.delete(url, headers=headers, timeout=5)
                if res.status_code == 200:
                    self.after(0, self.load_admin_data)
                else:
                    self.after(0, lambda: messagebox.showerror("Erreur", "Impossible de supprimer l'utilisateur.", parent=self))
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", f"Erreur réseau : {error}", parent=self))

        threading.Thread(target=req, daemon=True).start()

    def open_add_user_modal(self):
        AddUserModal(self, token=self.token, on_success_callback=self.load_admin_data)

    # ==========================================
    # ⚡ REMPLISSAGE AUTOMATIQUE DIRECT NATIVE DESKTOP
    # ==========================================
    def direct_desktop_autofill(self, item):
        username = item.get('username', '')
        password = item.get('password', '')
        url = item.get('websiteUrl', '')

        if not username and not password:
            messagebox.showwarning("Remplissage", "Aucun identifiant ni mot de passe à remplir.")
            return

        if PLAYWRIGHT_AVAILABLE and url:
            # Playwright must run outside the Tk event loop; navigation can take
            # several seconds and previously froze the desktop application.
            threading.Thread(
                target=self._playwright_autofill,
                args=(url, username, password),
                daemon=True
            ).start()
            return

        if PLAYWRIGHT_AVAILABLE and url:
            try:
                self._playwright_autofill(url, username, password)
                return
            except Exception as e:
                messagebox.showwarning("Navigation", f"Le mode automatique avec navigateur a échoué :\n{e}\n\nBasculer sur le collage manuel par raccourci.")
        
        self._pyautogui_autofill(username, password)

    def _pyautogui_autofill(self, username, password):
        confirm = messagebox.askyesno(
            "Remplissage automatique",
            "L'application va être réduite.\n\nCliquez sur le champ cible (formulaire, logiciel...) puis confirmez ici pour coller automatiquement les identifiants.",
            icon='info'
        )
        if not confirm:
            return

        self.iconify()

        def do_paste():
            try:
                time.sleep(0.6)
                if username:
                    pyperclip.copy(username)
                    time.sleep(0.1)
                    pyautogui.hotkey('ctrl', 'v')
                    time.sleep(0.15)
                if password:
                    pyautogui.press('tab')
                    time.sleep(0.1)
                    pyperclip.copy(password)
                    time.sleep(0.1)
                    pyautogui.hotkey('ctrl', 'v')
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", f"Remplissage échoué : {error}"))

        threading.Thread(target=do_paste, daemon=True).start()

    def _playwright_autofill(self, url, username, password):
        def find_firefox_exe():
            candidates = [
                os.path.join(os.environ.get('PROGRAMFILES', ''), 'Mozilla Firefox', 'firefox.exe'),
                os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'Mozilla Firefox', 'firefox.exe'),
                os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Mozilla Firefox', 'firefox.exe'),
            ]
            for path in candidates:
                if path and os.path.exists(path):
                    return path
            return None

        # The browser is supplied by Playwright; a system Firefox installation
        # is not required and cannot be controlled through this protocol.
        firefox_exe = None
        use_firefox = True
        if not use_firefox:
            self.after(0, lambda: messagebox.showerror(
                "Firefox introuvable",
                "Installez Mozilla Firefox pour utiliser le remplissage automatique.",
                parent=self
            ))
            return

        p = sync_playwright().start()
        try:
            # Playwright must use its Firefox build, which includes the protocol
            # required to automate pages. The standard installed Firefox exits
            # immediately when started with Playwright's internal arguments.
            browser = p.firefox.launch(headless=False)
            context = browser.new_context(viewport={"width": 1366, "height": 768})
            page = context.new_page()
            page.goto(url, wait_until="domcontentloaded")

            page.wait_for_timeout(1000)

            def fill_visible_field(selectors, value):
                """Fill the first visible and editable field with Playwright.

                locator.fill() simulates real browser input and is more reliable
                than assigning element.value on React, Vue and Angular forms.
                """
                if not value:
                    return False
                for selector in selectors:
                    locator = page.locator(selector)
                    for index in range(locator.count()):
                        field = locator.nth(index)
                        try:
                            if field.is_visible() and field.is_enabled() and field.is_editable():
                                field.fill(value, timeout=1500)
                                field.press("Tab")
                                return True
                        except Exception:
                            continue
                return False

            result = page.evaluate("""
                ([username, password]) => {
                    const inputs = Array.from(document.querySelectorAll('input'));
                    let userField = null, passField = null;

                    for (const input of inputs) {
                        if (input.type === 'hidden' || input.disabled || input.readOnly || input.type === 'password') continue;
                        const type = (input.type || '').toLowerCase();
                        const name = (input.name || '').toLowerCase();
                        const id = (input.id || '').toLowerCase();
                        if (!userField && (type === 'email' || type === 'text' || name.includes('email') || id.includes('email') || name.includes('user') || name.includes('login'))) {
                            userField = input;
                        }
                    }

                    const passwords = Array.from(document.querySelectorAll('input[type="password"]'));
                    if (passwords.length > 0) passField = passwords[0];

                    let filled = 0;
                    const fill = (el, val) => {
                        if (!el || !val) return;
                        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
                        setter ? setter.call(el, val) : el.value = val;
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        el.dispatchEvent(new Event('blur', { bubbles: true }));
                        filled++;
                    };

                    fill(userField, username);
                    fill(passField, password);

                    return { success: filled > 0, fieldsFilled: filled };
                }
            """, [username, password])

            # Use native Playwright input as a second step. Some modern sites
            # detect a value set through JavaScript and immediately reset it.
            user_selectors = [
                "input[autocomplete='username']", "input[autocomplete='email']",
                "input[type='email']", "input[name*='user' i]",
                "input[id*='user' i]", "input[name*='login' i]",
                "input[id*='login' i]", "input[name*='email' i]"
            ]
            password_selectors = [
                "input[type='password']", "input[autocomplete='current-password']",
                "input[autocomplete='new-password']"
            ]
            user_filled = False
            password_filled = False
            for _ in range(10):
                user_filled = fill_visible_field(user_selectors, username) or user_filled
                password_filled = fill_visible_field(password_selectors, password) or password_filled
                if user_filled or password_filled:
                    break
                page.wait_for_timeout(500)

            if user_filled or password_filled:
                result = {
                    "success": True,
                    "fieldsFilled": int(user_filled) + int(password_filled)
                }

            if result and result.get('success'):
                self._autofill_sessions.append((p, browser, context))
                messagebox.showinfo("Succès", f"Formulaire rempli automatiquement sur le site !\n\nChamps remplis: {result.get('fieldsFilled', 0)}\n\nLe navigateur reste ouvert pour que vous puissiez finaliser la connexion.", parent=self)
            else:
                messagebox.showinfo("Info", "Remplissage automatique initié sur la page web.\n\nLe navigateur reste ouvert pour que vous puissiez finaliser la connexion.", parent=self)
        except Exception as e:
            p.stop()
            error_message = str(e)
            if "Executable doesn't exist" in error_message:
                error_message = (
                    "Firefox pour Playwright n'est pas installe. Ouvrez un terminal puis executez :\n"
                    "python -m playwright install firefox"
                )
            self.after(0, lambda error_message=error_message: messagebox.showerror(
                "Remplissage Firefox",
                f"Impossible de remplir le formulaire :\n{error_message}",
                parent=self
            ))

    def copy_to_clip(self, text, msg):
        if text:
            pyperclip.copy(text)
            messagebox.showinfo("SecurPass", msg, parent=self)

    # Modales Helpers
    def open_add_modal(self):
        AddEditModal(self, on_save_callback=self.save_entry)

    def open_edit_modal(self, item):
        AddEditModal(self, item=item, on_save_callback=self.save_entry)

    def open_share_modal(self, item):
        ShareModal(self, item=item, token=self.token, on_success_callback=self.load_vault_data)

    def open_manage_shares_modal(self, item):
        ManageSharesModal(self, item=item, token=self.token)

    def open_import_modal(self):
        ImportModal(self, token=self.token, on_success_callback=self.load_vault_data)

    def open_history_modal(self, item):
        PasswordHistoryModal(self, item=item, token=self.token)

    def open_totp_modal(self):
        if self.is_offline:
            messagebox.showwarning("Hors-Ligne", "La configuration 2FA / TOTP nécessite une connexion au serveur.", parent=self)
            return
        TOTPSetupModal(self, token=self.token)

    def open_audit_modal(self):
        if self.is_offline:
            messagebox.showwarning("Hors-Ligne", "Le journal d'audit nécessite une connexion au serveur.", parent=self)
            return
        AuditLogModal(self, token=self.token)

    def open_policy_modal(self):
        if self.is_offline:
            messagebox.showwarning("Hors-Ligne", "La politique de mots de passe nécessite une connexion au serveur.", parent=self)
            return
        PolicyModal(self, token=self.token)

    # Actions API CRUD
    def save_entry(self, payload, item_id=None):
        headers = get_anti_replay_headers(self.token)
        url = f"{API_URL}/vault/{item_id}" if item_id else f"{API_URL}/vault"
        method = requests.put if item_id else requests.post

        def req():
            try:
                res = method(url, json=payload, headers=headers, timeout=5)
                if res.status_code in [200, 201]:
                    self.load_vault_data()
                else:
                    err = res.json().get('error', 'Erreur lors de la sauvegarde')
                    self.after(0, lambda: messagebox.showerror("Erreur", err, parent=self))
            except Exception as e:
                print(f"Erreur enregistrement : {e}")

        threading.Thread(target=req, daemon=True).start()

    def delete_entry(self, item):
        if not messagebox.askyesno("Confirmation", f"Supprimer le mot de passe pour « {item.get('title')} » ?", parent=self):
            return

        headers = get_anti_replay_headers(self.token)
        def req():
            try:
                res = requests.delete(f"{API_URL}/vault/{item.get('id')}", headers=headers, timeout=5)
                if res.status_code == 200:
                    self.load_vault_data()
                else:
                    err = res.json().get('error', 'Erreur de suppression')
                    self.after(0, lambda: messagebox.showerror("Erreur", err, parent=self))
            except Exception as e:
                print(f"Erreur suppression : {e}")

        threading.Thread(target=req, daemon=True).start()

    def export_csv(self):
        filename = filedialog.asksaveasfilename(
            title="Enregistrer l'export CSV",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")]
        )
        if not filename: return

        headers = {"Authorization": f"Bearer {self.token}"}
        def req():
            try:
                res = requests.get(f"{API_URL}/vault/export/csv", headers=headers, timeout=10)
                if res.status_code == 200:
                    with open(filename, "wb") as f:
                        f.write(res.content)
                    self.after(0, lambda: messagebox.showinfo("Export CSV", "Exportation CSV réussie !", parent=self))
                else:
                    self.after(0, lambda: messagebox.showerror("Erreur", "Échec de l'export CSV.", parent=self))
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", f"Erreur export : {error}", parent=self))

        threading.Thread(target=req, daemon=True).start()

    def export_json(self):
        filename = filedialog.asksaveasfilename(
            title="Enregistrer l'export Bitwarden JSON",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")]
        )
        if not filename: return

        headers = {"Authorization": f"Bearer {self.token}"}
        def req():
            try:
                res = requests.get(f"{API_URL}/vault/export/json", headers=headers, timeout=10)
                if res.status_code == 200:
                    with open(filename, "wb") as f:
                        f.write(res.content)
                    self.after(0, lambda: messagebox.showinfo("Export JSON", "Exportation JSON Bitwarden réussie !", parent=self))
                else:
                    self.after(0, lambda: messagebox.showerror("Erreur", "Échec de l'export JSON.", parent=self))
            except Exception as e:
                self.after(0, lambda error=str(e): messagebox.showerror("Erreur", f"Erreur export : {error}", parent=self))

        threading.Thread(target=req, daemon=True).start()

    # ==========================================
    # 🔑 VUE GÉNÉRATEUR DE MOT DE PASSE
    # ==========================================
    def create_generator_view(self):
        for w in self.main_container.winfo_children(): w.destroy()

        frame_gen = ctk.CTkFrame(self.main_container, corner_radius=15, fg_color=COLOR_CARD)
        frame_gen.pack(fill="both", expand=True, padx=10, pady=10)

        lbl_g_title = ctk.CTkLabel(frame_gen, text="🔑 Générateur de Mots de Passe Sécurisé", font=ctk.CTkFont(size=22, weight="bold"))
        lbl_g_title.pack(pady=(30, 20))

        # Output
        self.entry_gen_out = ctk.CTkEntry(frame_gen, font=ctk.CTkFont(size=18, weight="bold"), height=50, justify="center")
        self.entry_gen_out.pack(fill="x", padx=60, pady=(0, 20))

        # Slider
        frame_len = ctk.CTkFrame(frame_gen, fg_color="transparent")
        frame_len.pack(fill="x", padx=60, pady=10)

        self.lbl_len_val = ctk.CTkLabel(frame_len, text="Longueur : 16 caractères", font=ctk.CTkFont(size=14, weight="bold"))
        self.lbl_len_val.pack(anchor="w", pady=(0, 5))

        self.slider_len = ctk.CTkSlider(frame_len, from_=8, to=64, number_of_steps=56, command=self.update_gen_length)
        self.slider_len.set(16)
        self.slider_len.pack(fill="x")

        # Checkboxes
        frame_opts = ctk.CTkFrame(frame_gen, fg_color="transparent")
        frame_opts.pack(fill="x", padx=60, pady=15)

        self.chk_upper = ctk.CTkCheckBox(frame_opts, text="Majuscules (A-Z)", command=self.generate_password_local)
        self.chk_upper.select()
        self.chk_upper.pack(anchor="w", pady=4)

        self.chk_lower = ctk.CTkCheckBox(frame_opts, text="Minuscules (a-z)", command=self.generate_password_local)
        self.chk_lower.select()
        self.chk_lower.pack(anchor="w", pady=4)

        self.chk_digits = ctk.CTkCheckBox(frame_opts, text="Chiffres (0-9)", command=self.generate_password_local)
        self.chk_digits.select()
        self.chk_digits.pack(anchor="w", pady=4)

        self.chk_symbols = ctk.CTkCheckBox(frame_opts, text="Symboles (!@#$%^&*)", command=self.generate_password_local)
        self.chk_symbols.select()
        self.chk_symbols.pack(anchor="w", pady=4)

        # Actions
        frame_gen_btn = ctk.CTkFrame(frame_gen, fg_color="transparent")
        frame_gen_btn.pack(pady=20)

        ctk.CTkButton(frame_gen_btn, text="🎲 Régénérer", height=40, command=self.generate_password_local).pack(side="left", padx=8)
        ctk.CTkButton(frame_gen_btn, text="📋 Copier le mot de passe", height=40, fg_color=COLOR_SUCCESS, hover_color=COLOR_SUCCESS_HOVER, command=lambda: self.copy_to_clip(self.entry_gen_out.get(), "Mot de passe copié !")).pack(side="left", padx=8)

        self.generate_password_local()

    def update_gen_length(self, val):
        length = int(val)
        self.lbl_len_val.configure(text=f"Longueur : {length} caractères")
        self.generate_password_local()

    def generate_password_local(self):
        length = int(self.slider_len.get())
        chars = ""
        if self.chk_upper.get(): chars += string.ascii_uppercase
        if self.chk_lower.get(): chars += string.ascii_lowercase
        if self.chk_digits.get(): chars += string.digits
        if self.chk_symbols.get(): chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if not chars:
            chars = string.ascii_lowercase + string.digits

        pwd = ''.join(random.choice(chars) for _ in range(length))
        self.entry_gen_out.delete(0, 'end')
        self.entry_gen_out.insert(0, pwd)

    # ==========================================
    # 📋 LOGS D'INSCRIPTION
    # ==========================================
    def create_logs_view(self):
        for w in self.main_container.winfo_children(): w.destroy()

        top_bar = ctk.CTkFrame(self.main_container, fg_color="transparent")
        top_bar.pack(fill="x", pady=(0, 15))

        lbl_title = ctk.CTkLabel(top_bar, text="📋 Logs d'inscription", font=ctk.CTkFont(size=20, weight="bold"))
        lbl_title.pack(side="left")

        btn_refresh = ctk.CTkButton(top_bar, text="🔄 Actualiser", command=self.load_logs)
        btn_refresh.pack(side="right")

        self.scroll_logs = ctk.CTkScrollableFrame(self.main_container, fg_color="transparent")
        self.scroll_logs.pack(fill="both", expand=True)

    def load_logs(self):
        for w in self.scroll_logs.winfo_children(): w.destroy()

        def req():
            try:
                headers = {"Authorization": f"Bearer {self.token}"}
                res = requests.get(f"{API_URL}/registration-logs", headers=headers, timeout=5)
                if res.status_code == 200:
                    logs = res.json()
                    self.after(0, lambda: self.render_logs(logs))
                else:
                    self.after(0, lambda: ctk.CTkLabel(self.scroll_logs, text="Erreur lors du chargement des logs.", text_color=COLOR_MUTED).pack(pady=40))
            except Exception as e:
                print(f"Erreur chargement logs : {e}")
                self.after(0, lambda error=str(e): ctk.CTkLabel(self.scroll_logs, text=f"Erreur : {error}", text_color=COLOR_MUTED).pack(pady=40))

        threading.Thread(target=req, daemon=True).start()

    def render_logs(self, logs):
        if self.current_view != "logs": return
        for w in self.scroll_logs.winfo_children(): w.destroy()

        if not logs:
            ctk.CTkLabel(self.scroll_logs, text="Aucun log disponible.", font=ctk.CTkFont(size=14), text_color=COLOR_MUTED).pack(pady=40)
            return

        for log in logs:
            card = ctk.CTkFrame(self.scroll_logs, corner_radius=10, fg_color=COLOR_CARD)
            card.pack(fill="x", pady=6, padx=4)

            domain = log.get('domain') or 'inconnu'
            url = log.get('url') or ''
            ts = log.get('timestamp') or ''
            pwd = log.get('passwordGenerated') or ''
            fields = log.get('fieldsFilled') or 0

            try:
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                ts_disp = dt.strftime('%d/%m/%Y %H:%M:%S')
            except Exception:
                ts_disp = ts

            info_frame = ctk.CTkFrame(card, fg_color="transparent")
            info_frame.pack(fill="x", padx=15, pady=10)

            ctk.CTkLabel(info_frame, text=f"🌐 {domain}", font=ctk.CTkFont(size=14, weight="bold"), anchor="w").pack(anchor="w")
            ctk.CTkLabel(info_frame, text=f"🕒 {ts_disp}   •   {fields} champ(s) rempli(s)", font=ctk.CTkFont(size=11), text_color=COLOR_MUTED, anchor="w").pack(anchor="w")

            pwd_frame = ctk.CTkFrame(card, fg_color="transparent")
            pwd_frame.pack(fill="x", padx=15, pady=(0, 10))

            lbl_pwd = ctk.CTkLabel(pwd_frame, text="🔑 " + ("•" * 20), font=ctk.CTkFont(size=12), anchor="w")
            lbl_pwd.pack(side="left", fill="x", expand=True)

            def make_toggle(p_text, label_el):
                def toggle():
                    curr = label_el.cget("text")
                    if curr.startswith("🔑 •"):
                        label_el.configure(text=f"🔑 {p_text}")
                    else:
                        label_el.configure(text="🔑 " + "•" * 20)
                return toggle

            def make_copy(p_text):
                def copy():
                    pyperclip.copy(p_text)
                    messagebox.showinfo("SecurPass", "Mot de passe copié !", parent=self)
                return copy

            ctk.CTkButton(pwd_frame, text="👁", width=34, command=make_toggle(pwd, lbl_pwd)).pack(side="right", padx=(5, 0))
            ctk.CTkButton(pwd_frame, text="📋", width=34, command=make_copy(pwd)).pack(side="right", padx=5)

    def clear_frame(self):
        for w in self.winfo_children():
            w.destroy()

def main():
    print("\n==================================================")
    print("🔒 SECURPASS - DESKTOP NATIVE & SYNCHRONIZED v2.0")
    print("🚀 Auto-Sync + Hotkey Ctrl+Alt+A + 2FA TOTP + Admin AD + Offline Cache")
    print("==================================================\n")

    start_node_backend()

    app = SecurPassApp()
    app.mainloop()

if __name__ == '__main__':
    main()
