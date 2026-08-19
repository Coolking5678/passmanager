"""
app_ui.py
CustomTkinter-based desktop UI for the Password Manager.

Two screens:
    LoginScreen  – Create master password (first run) or unlock the vault.
    VaultScreen  – Add / view / copy / delete stored credentials.
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import messagebox

import sys
import os

# Allow running the file directly or as part of the package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.crypto_utils import (
    hash_master_password,
    verify_master_password,
    derive_fernet_key,
    generate_pbkdf2_salt,
    encrypt_password,
    decrypt_password,
)
from src.database import (
    initialize_database,
    save_master_config,
    get_master_config,
    add_credential,
    get_all_credentials,
    delete_credential,
)
from src.password_logic import check_strength, get_strength_level, generate_strong_password

# ─────────────────────────────────────────────────────────────────────────────
# Global theme constants
# ─────────────────────────────────────────────────────────────────────────────
PRIMARY        = "#6C63FF"     # Indigo accent
PRIMARY_HOVER  = "#5A52D5"
DANGER         = "#FF5370"
DANGER_HOVER   = "#D63D58"
SUCCESS        = "#43D9A2"
WARNING_CLR    = "#FFB547"
BG_DARK        = "#1A1A2E"     # Deep navy background
CARD_BG        = "#16213E"     # Card / frame background
SURFACE        = "#0F3460"     # Input surface
TEXT_PRIMARY   = "#E0E0FF"
TEXT_SECONDARY = "#8B8FA8"

FONT_HEADING   = ("Segoe UI", 26, "bold")
FONT_SUB       = ("Segoe UI", 13)
FONT_LABEL     = ("Segoe UI", 11)
FONT_SMALL     = ("Segoe UI", 10)
FONT_MONO      = ("Consolas", 11)


# ─────────────────────────────────────────────────────────────────────────────
# Helper: copy text to clipboard using tkinter
# ─────────────────────────────────────────────────────────────────────────────
def _copy_to_clipboard(root: ctk.CTk, text: str) -> None:
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()


# ─────────────────────────────────────────────────────────────────────────────
# Login / Setup Screen
# ─────────────────────────────────────────────────────────────────────────────
class LoginScreen(ctk.CTkFrame):
    """
    Shown on application start.
    - First run  → prompts to create a master password.
    - Subsequent → prompts to enter the master password to unlock the vault.
    """

    def __init__(self, parent: ctk.CTk, on_success):
        super().__init__(parent, fg_color=BG_DARK)
        self._parent     = parent
        self._on_success = on_success   # Callable[(fernet_key: bytes)]
        self._is_setup   = get_master_config() is None

        self._build_ui()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.pack(fill="both", expand=True)

        # Outer centering wrapper
        wrapper = ctk.CTkFrame(self, fg_color="transparent")
        wrapper.place(relx=0.5, rely=0.5, anchor="center")

        # ── Logo / icon emoji
        ctk.CTkLabel(
            wrapper,
            text="🔐",
            font=("Segoe UI Emoji", 60),
            text_color=PRIMARY,
        ).pack(pady=(0, 8))

        # ── App title
        ctk.CTkLabel(
            wrapper,
            text="Vault",
            font=("Segoe UI", 34, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack()

        ctk.CTkLabel(
            wrapper,
            text="Your personal password manager",
            font=FONT_SUB,
            text_color=TEXT_SECONDARY,
        ).pack(pady=(0, 32))

        # ── Card frame
        card = ctk.CTkFrame(wrapper, fg_color=CARD_BG, corner_radius=20, width=360)
        card.pack(padx=20)

        heading_text = "Create Master Password" if self._is_setup else "Unlock Vault"
        ctk.CTkLabel(
            card,
            text=heading_text,
            font=("Segoe UI", 16, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(pady=(28, 4))

        sub_text = (
            "Choose a strong password you won't forget."
            if self._is_setup
            else "Enter your master password to access your vault."
        )
        ctk.CTkLabel(
            card, text=sub_text, font=FONT_SMALL, text_color=TEXT_SECONDARY, wraplength=310
        ).pack(pady=(0, 20))

        # ── Password entry
        self._pw_entry = ctk.CTkEntry(
            card,
            placeholder_text="Master Password",
            show="•",
            width=300,
            height=44,
            font=FONT_SUB,
            fg_color=SURFACE,
            border_color=PRIMARY,
            border_width=1,
            text_color=TEXT_PRIMARY,
        )
        self._pw_entry.pack(pady=(0, 10))
        self._pw_entry.bind("<Return>", lambda e: self._handle_submit())

        # ── Confirm entry (setup only)
        if self._is_setup:
            self._confirm_entry = ctk.CTkEntry(
                card,
                placeholder_text="Confirm Password",
                show="•",
                width=300,
                height=44,
                font=FONT_SUB,
                fg_color=SURFACE,
                border_color=PRIMARY,
                border_width=1,
                text_color=TEXT_PRIMARY,
            )
            self._confirm_entry.pack(pady=(0, 10))
            self._confirm_entry.bind("<Return>", lambda e: self._handle_submit())

            # Strength label
            self._strength_var = tk.StringVar()
            self._strength_lbl = ctk.CTkLabel(
                card,
                textvariable=self._strength_var,
                font=FONT_SMALL,
                text_color=TEXT_SECONDARY,
            )
            self._strength_lbl.pack(pady=(0, 6))
            self._pw_entry.bind("<KeyRelease>", self._on_pw_keyrelease)
        else:
            self._confirm_entry = None
            self._strength_var  = None
            self._strength_lbl  = None

        # ── Error label
        self._error_var = tk.StringVar()
        ctk.CTkLabel(
            card,
            textvariable=self._error_var,
            font=FONT_SMALL,
            text_color=DANGER,
        ).pack()

        # ── Submit button
        btn_text = "Create Vault" if self._is_setup else "Unlock  →"
        self._submit_btn = ctk.CTkButton(
            card,
            text=btn_text,
            command=self._handle_submit,
            width=300,
            height=44,
            font=("Segoe UI", 13, "bold"),
            fg_color=PRIMARY,
            hover_color=PRIMARY_HOVER,
            corner_radius=10,
        )
        self._submit_btn.pack(pady=(10, 28))

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_pw_keyrelease(self, _event=None) -> None:
        """Update strength label as the user types the master password."""
        pw    = self._pw_entry.get()
        level = get_strength_level(pw)
        color_map = {"Strong": SUCCESS, "Medium": WARNING_CLR, "Weak": DANGER, "": TEXT_SECONDARY}
        self._strength_var.set(level)
        self._strength_lbl.configure(text_color=color_map.get(level, TEXT_SECONDARY))

    def _handle_submit(self) -> None:
        """Validate input and either create the vault or unlock it."""
        pw = self._pw_entry.get().strip()
        self._error_var.set("")

        if not pw:
            self._error_var.set("Password cannot be empty.")
            return

        if self._is_setup:
            self._handle_setup(pw)
        else:
            self._handle_login(pw)

    def _handle_setup(self, pw: str) -> None:
        confirm = self._confirm_entry.get().strip()
        if pw != confirm:
            self._error_var.set("Passwords do not match.")
            return
        is_strong, feedback = check_strength(pw)
        if not is_strong:
            self._error_var.set(feedback)
            return

        salt       = generate_pbkdf2_salt()
        pw_hash    = hash_master_password(pw)
        fernet_key = derive_fernet_key(pw, salt)

        save_master_config(pw_hash, salt)
        self._on_success(fernet_key)

    def _handle_login(self, pw: str) -> None:
        config = get_master_config()
        if config is None:
            self._error_var.set("Vault not initialised. Restart the app.")
            return

        stored_hash = bytes(config["master_password_hash"])
        pbkdf2_salt = bytes(config["pbkdf2_salt"])

        if not verify_master_password(pw, stored_hash):
            self._error_var.set("Incorrect password. Try again.")
            return

        fernet_key = derive_fernet_key(pw, pbkdf2_salt)
        self._on_success(fernet_key)


# ─────────────────────────────────────────────────────────────────────────────
# Vault Screen
# ─────────────────────────────────────────────────────────────────────────────
class VaultScreen(ctk.CTkFrame):
    """
    Main vault interface shown after successful login.
    Allows adding, viewing, copying, and deleting credentials.
    """

    def __init__(self, parent: ctk.CTk, fernet_key: bytes):
        super().__init__(parent, fg_color=BG_DARK)
        self._parent     = parent
        self._key        = fernet_key
        self._copy_flash: str | None = None  # Tracks which row is showing "Copied!"

        self._build_ui()
        self._refresh_credentials()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.pack(fill="both", expand=True)

        # ── Top header bar ────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color=CARD_BG, height=60, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header, text="🔐 Vault", font=("Segoe UI", 18, "bold"), text_color=PRIMARY
        ).pack(side="left", padx=24, pady=15)

        ctk.CTkLabel(
            header,
            text="Your credentials are encrypted and stored locally.",
            font=FONT_SMALL,
            text_color=TEXT_SECONDARY,
        ).pack(side="left", pady=15)

        ctk.CTkButton(
            header,
            text="Lock Vault",
            command=self._lock_vault,
            width=110,
            height=34,
            font=FONT_LABEL,
            fg_color=DANGER,
            hover_color=DANGER_HOVER,
            corner_radius=8,
        ).pack(side="right", padx=20, pady=13)

        # ── Main content area ─────────────────────────────────────────────────
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=24, pady=16)

        # Left column: Add credential form
        left = ctk.CTkFrame(content, fg_color=CARD_BG, corner_radius=16, width=360)
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)
        self._build_add_form(left)

        # Right column: Credential list
        right = ctk.CTkFrame(content, fg_color=CARD_BG, corner_radius=16)
        right.pack(side="left", fill="both", expand=True)
        self._build_credential_list(right)

    # ── Add credential form ───────────────────────────────────────────────────

    def _build_add_form(self, parent: ctk.CTkFrame) -> None:
        ctk.CTkLabel(
            parent, text="Add New Credential",
            font=("Segoe UI", 15, "bold"), text_color=TEXT_PRIMARY
        ).pack(pady=(24, 4), padx=20, anchor="w")

        ctk.CTkLabel(
            parent, text="Fill in the details below and hit Add.",
            font=FONT_SMALL, text_color=TEXT_SECONDARY
        ).pack(padx=20, anchor="w")

        # Website
        ctk.CTkLabel(parent, text="Website / App", font=FONT_LABEL, text_color=TEXT_SECONDARY
                     ).pack(padx=20, pady=(18, 2), anchor="w")
        self._website_entry = self._make_entry(parent, "e.g. github.com")

        # Username
        ctk.CTkLabel(parent, text="Username / Email", font=FONT_LABEL, text_color=TEXT_SECONDARY
                     ).pack(padx=20, pady=(10, 2), anchor="w")
        self._username_entry = self._make_entry(parent, "e.g. john@example.com")

        # Password
        ctk.CTkLabel(parent, text="Password", font=FONT_LABEL, text_color=TEXT_SECONDARY
                     ).pack(padx=20, pady=(10, 2), anchor="w")

        pw_row = ctk.CTkFrame(parent, fg_color="transparent")
        pw_row.pack(padx=20, fill="x")

        self._password_entry = ctk.CTkEntry(
            pw_row, placeholder_text="Enter or generate",
            show="•", height=40, font=FONT_MONO,
            fg_color=SURFACE, border_color=PRIMARY, border_width=1,
            text_color=TEXT_PRIMARY,
        )
        self._password_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self._password_entry.bind("<KeyRelease>", self._on_pw_change)

        ctk.CTkButton(
            pw_row, text="⚡ Gen", command=self._generate_pw,
            width=68, height=40, font=FONT_SMALL,
            fg_color=SURFACE, hover_color=PRIMARY,
            border_color=PRIMARY, border_width=1, corner_radius=8,
        ).pack(side="left")

        # Strength indicator
        strength_row = ctk.CTkFrame(parent, fg_color="transparent")
        strength_row.pack(padx=20, fill="x", pady=(4, 0))

        self._strength_bar = ctk.CTkProgressBar(
            strength_row, height=4, corner_radius=2, fg_color=SURFACE, progress_color=DANGER
        )
        self._strength_bar.pack(fill="x", pady=(0, 3))
        self._strength_bar.set(0)

        self._strength_label = ctk.CTkLabel(
            strength_row, text="", font=FONT_SMALL, text_color=TEXT_SECONDARY
        )
        self._strength_label.pack(anchor="w")

        # Feedback / error
        self._form_error_var = tk.StringVar()
        ctk.CTkLabel(
            parent, textvariable=self._form_error_var,
            font=FONT_SMALL, text_color=DANGER, wraplength=300
        ).pack(padx=20, pady=(6, 0), anchor="w")

        # Add button
        ctk.CTkButton(
            parent, text="+ Add Credential",
            command=self._add_credential,
            height=44, font=("Segoe UI", 13, "bold"),
            fg_color=PRIMARY, hover_color=PRIMARY_HOVER, corner_radius=10
        ).pack(padx=20, pady=(12, 24), fill="x")

    @staticmethod
    def _make_entry(parent, placeholder: str) -> ctk.CTkEntry:
        e = ctk.CTkEntry(
            parent, placeholder_text=placeholder,
            height=40, font=FONT_MONO,
            fg_color=SURFACE, border_color=PRIMARY, border_width=1,
            text_color=TEXT_PRIMARY,
        )
        e.pack(padx=20, fill="x")
        return e

    # ── Credential list ───────────────────────────────────────────────────────

    def _build_credential_list(self, parent: ctk.CTkFrame) -> None:
        # Header row
        hdr = ctk.CTkFrame(parent, fg_color="transparent")
        hdr.pack(fill="x", padx=20, pady=(20, 6))

        ctk.CTkLabel(
            hdr, text="Saved Credentials",
            font=("Segoe UI", 15, "bold"), text_color=TEXT_PRIMARY
        ).pack(side="left")

        self._count_label = ctk.CTkLabel(
            hdr, text="", font=FONT_SMALL, text_color=TEXT_SECONDARY
        )
        self._count_label.pack(side="right")

        # Search bar
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._filter_credentials())

        ctk.CTkEntry(
            parent,
            textvariable=self._search_var,
            placeholder_text="🔍 Search by website or username...",
            height=36, font=FONT_LABEL,
            fg_color=SURFACE, border_color=PRIMARY, border_width=1,
            text_color=TEXT_PRIMARY,
        ).pack(padx=20, fill="x", pady=(0, 10))

        # Scrollable frame for rows
        self._cred_scroll = ctk.CTkScrollableFrame(
            parent, fg_color="transparent", label_text=""
        )
        self._cred_scroll.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    # ── Data operations ───────────────────────────────────────────────────────

    def _refresh_credentials(self) -> None:
        """Reload all credentials from the DB and redraw the list."""
        self._all_credentials = get_all_credentials()
        self._filter_credentials()

    def _filter_credentials(self) -> None:
        """Filter the list by the current search term and redraw."""
        query = self._search_var.get().lower() if hasattr(self, "_search_var") else ""
        filtered = [
            row for row in self._all_credentials
            if query in row["website"].lower() or query in row["username"].lower()
        ]
        self._draw_credentials(filtered)
        total = len(self._all_credentials)
        shown = len(filtered)
        self._count_label.configure(
            text=f"{shown} of {total}" if query else f"{total} stored"
        )

    def _draw_credentials(self, rows) -> None:
        """Clear and redraw credential cards in the scrollable frame."""
        for widget in self._cred_scroll.winfo_children():
            widget.destroy()

        if not rows:
            ctk.CTkLabel(
                self._cred_scroll,
                text="No credentials found.\nAdd one using the form on the left!",
                font=FONT_SUB, text_color=TEXT_SECONDARY, justify="center"
            ).pack(pady=40)
            return

        for row in rows:
            self._create_credential_card(row)

    def _create_credential_card(self, row) -> None:
        """Render a single credential card with Website, Username, and action buttons."""
        card = ctk.CTkFrame(
            self._cred_scroll, fg_color=SURFACE,
            corner_radius=12, border_width=1, border_color=PRIMARY
        )
        card.pack(fill="x", pady=5)

        # Icon + info
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True, padx=16, pady=12)

        ctk.CTkLabel(
            info_frame, text="🌐  " + row["website"],
            font=("Segoe UI", 12, "bold"), text_color=TEXT_PRIMARY, anchor="w"
        ).pack(anchor="w")

        ctk.CTkLabel(
            info_frame, text="👤  " + row["username"],
            font=FONT_SMALL, text_color=TEXT_SECONDARY, anchor="w"
        ).pack(anchor="w", pady=(2, 0))

        # Buttons
        btn_frame = ctk.CTkFrame(card, fg_color="transparent")
        btn_frame.pack(side="right", padx=12, pady=12)

        copy_btn = ctk.CTkButton(
            btn_frame, text="Copy", width=72, height=32, font=FONT_SMALL,
            fg_color=PRIMARY, hover_color=PRIMARY_HOVER, corner_radius=8,
            command=lambda r=row, b=None: self._copy_password(r, copy_btn),
        )
        copy_btn.pack(side="left", padx=(0, 6))
        # fix forward-reference: pass the button directly
        copy_btn.configure(command=lambda r=row, b=copy_btn: self._copy_password(r, b))

        ctk.CTkButton(
            btn_frame, text="Delete", width=72, height=32, font=FONT_SMALL,
            fg_color=DANGER, hover_color=DANGER_HOVER, corner_radius=8,
            command=lambda r=row: self._delete_credential(r),
        ).pack(side="left")

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_pw_change(self, _event=None) -> None:
        """Update the strength bar and label as the user types a password."""
        pw    = self._password_entry.get()
        level = get_strength_level(pw)
        _, feedback = check_strength(pw)

        level_props = {
            "Strong": (1.0,  SUCCESS,     SUCCESS),
            "Medium": (0.55, WARNING_CLR, WARNING_CLR),
            "Weak":   (0.2,  DANGER,      DANGER),
            "":       (0.0,  DANGER,      TEXT_SECONDARY),
        }
        progress, bar_color, lbl_color = level_props.get(level, (0.0, DANGER, TEXT_SECONDARY))

        self._strength_bar.set(progress)
        self._strength_bar.configure(progress_color=bar_color)
        self._strength_label.configure(text=feedback, text_color=lbl_color)

    def _generate_pw(self) -> None:
        """Generate a strong password and populate the password field."""
        pw = generate_strong_password(16)
        self._password_entry.configure(show="")
        self._password_entry.delete(0, "end")
        self._password_entry.insert(0, pw)
        self._password_entry.configure(show="•")
        self._on_pw_change()

    def _add_credential(self) -> None:
        """Validate form inputs, encrypt the password, and save to the database."""
        website  = self._website_entry.get().strip()
        username = self._username_entry.get().strip()
        password = self._password_entry.get()

        self._form_error_var.set("")

        if not website:
            self._form_error_var.set("Website / App field is required.")
            return
        if not username:
            self._form_error_var.set("Username / Email field is required.")
            return
        if not password:
            self._form_error_var.set("Password field is required.")
            return

        encrypted = encrypt_password(self._key, password)
        add_credential(website, username, encrypted)

        # Clear the form
        self._website_entry.delete(0, "end")
        self._username_entry.delete(0, "end")
        self._password_entry.delete(0, "end")
        self._strength_bar.set(0)
        self._strength_label.configure(text="")

        self._refresh_credentials()

    def _copy_password(self, row, btn: ctk.CTkButton) -> None:
        """Decrypt and copy a credential's password to the clipboard."""
        try:
            plaintext = decrypt_password(self._key, bytes(row["encrypted_password"]))
            _copy_to_clipboard(self._parent, plaintext)

            # Brief visual feedback on the button
            original_text = btn.cget("text")
            btn.configure(text="✓ Copied!", fg_color=SUCCESS)
            self.after(1800, lambda: btn.configure(text=original_text, fg_color=PRIMARY))
        except Exception:
            messagebox.showerror("Decryption Error", "Failed to decrypt the password.")

    def _delete_credential(self, row) -> None:
        """Confirm and delete a credential from the database."""
        confirm = messagebox.askyesno(
            "Delete Credential",
            f"Remove credentials for '{row['website']}'?\nThis action cannot be undone.",
        )
        if confirm:
            delete_credential(row["id"])
            self._refresh_credentials()

    def _lock_vault(self) -> None:
        """Destroy the vault screen and return to the login screen."""
        self._key = None   # Wipe the key from memory
        self.destroy()
        app = self._parent
        # Re-show the login screen
        LoginScreen(app, lambda key: _switch_to_vault(app, key))


# ─────────────────────────────────────────────────────────────────────────────
# Application entry point helpers
# ─────────────────────────────────────────────────────────────────────────────

def _switch_to_vault(root: ctk.CTk, fernet_key: bytes) -> None:
    """Tear down all existing frames and show the vault screen."""
    for widget in root.winfo_children():
        widget.destroy()
    VaultScreen(root, fernet_key)


def run_app() -> None:
    """Initialize the database, configure CTk, and launch the main window."""
    initialize_database()

    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    root.title("Vault – Password Manager")
    root.geometry("1000x660")
    root.minsize(900, 600)
    root.configure(fg_color=BG_DARK)

    # Centre the window on screen
    root.update_idletasks()
    w, h = 1000, 660
    x = (root.winfo_screenwidth()  - w) // 2
    y = (root.winfo_screenheight() - h) // 2
    root.geometry(f"{w}x{h}+{x}+{y}")

    def on_login_success(fernet_key: bytes) -> None:
        _switch_to_vault(root, fernet_key)

    LoginScreen(root, on_login_success)
    root.mainloop()
