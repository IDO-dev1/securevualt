"""
SecureVault
Encrypted local password manager

Built by Ido
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import secrets
import string
import pyperclip
from vault_core import SecureVault, WrongPasswordError, TamperedVaultError, VaultError

VAULT_FILE = "my_vault.sv1"

BG       = "#0f1117"
BG2      = "#1a1d27"
BG3      = "#252836"
ACCENT   = "#5b8dee"
DANGER   = "#e05c5c"
SUCCESS  = "#4eca8b"
TEXT     = "#e8eaf0"
SUBTEXT  = "#8b90a0"
BORDER   = "#2e3244"

FONT_TITLE  = ("Segoe UI", 18, "bold")
FONT_HEADER = ("Segoe UI", 11, "bold")
FONT_BODY   = ("Segoe UI", 10)
FONT_MONO   = ("Consolas", 10)
FONT_SMALL  = ("Segoe UI", 9)


def styled_button(parent, text, command, color=ACCENT, **kw):
    btn = tk.Button(
        parent, text=text, command=command,
        bg=color, fg="white", activebackground=color,
        activeforeground="white", relief="flat", cursor="hand2",
        font=FONT_BODY, padx=12, pady=6, bd=0, **kw
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=_lighten(color)))
    btn.bind("<Leave>", lambda e: btn.config(bg=color))
    return btn


def _lighten(hex_color: str) -> str:
    r, g, b = int(hex_color[1:3], 16), int(hex_color[3:5], 16), int(hex_color[5:7], 16)
    r, g, b = min(r + 25, 255), min(g + 25, 255), min(b + 25, 255)
    return f"#{r:02x}{g:02x}{b:02x}"


def styled_entry(parent, show="", **kw):
    return tk.Entry(
        parent, bg=BG3, fg=TEXT, insertbackground=TEXT,
        relief="flat", font=FONT_MONO, show=show,
        highlightthickness=1, highlightcolor=ACCENT,
        highlightbackground=BORDER, **kw
    )



class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureVault")
        self.iconbitmap(r"C:\Users\User\Desktop\securevualt\icon.ico")
        self.configure(bg=BG)
        self.resizable(False, False)
        self._center(400, 360)
        self.vault: SecureVault | None = None
        self._build()

    def _center(self, w, h):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _build(self):
        pad = dict(padx=40)
        tk.Label(self, text="🔐", font=("Segoe UI", 40), bg=BG, fg=ACCENT).pack(pady=(40, 4))
        tk.Label(self, text="SecureVault", font=FONT_TITLE, bg=BG, fg=TEXT).pack()
        tk.Label(self, text="Local encrypted password manager",
                 font=FONT_SMALL, bg=BG, fg=SUBTEXT).pack(pady=(2, 24))

        import os
        is_new = not os.path.exists(VAULT_FILE)
        label = "Create master password" if is_new else "Master password"
        tk.Label(self, text=label, font=FONT_SMALL, bg=BG, fg=SUBTEXT, anchor="w").pack(fill="x", **pad)
        self.pw_entry = styled_entry(self, show="•")
        self.pw_entry.pack(fill="x", ipady=8, pady=(4, 0), **pad)
        self.pw_entry.bind("<Return>", lambda e: self._submit())

        if is_new:
            tk.Label(self, text="Confirm password", font=FONT_SMALL, bg=BG, fg=SUBTEXT, anchor="w").pack(
                fill="x", pady=(10, 0), **pad)
            self.pw_confirm = styled_entry(self, show="•")
            self.pw_confirm.pack(fill="x", ipady=8, pady=(4, 0), **pad)
            self.pw_confirm.bind("<Return>", lambda e: self._submit())
        else:
            self.pw_confirm = None

        self.status_var = tk.StringVar()
        tk.Label(self, textvariable=self.status_var, font=FONT_SMALL,
                 bg=BG, fg=DANGER).pack(pady=(8, 0))

        action = "Create Vault" if is_new else "Unlock"
        styled_button(self, action, self._submit).pack(pady=(12, 0), fill="x", **pad)
        self.pw_entry.focus()

    def _submit(self):
        pw = self.pw_entry.get()
        if not pw:
            self.status_var.set("Password cannot be empty.")
            return

        vault = SecureVault(VAULT_FILE)
        import os
        is_new = not os.path.exists(VAULT_FILE)

        if is_new:
            confirm = self.pw_confirm.get() if self.pw_confirm else pw
            if pw != confirm:
                self.status_var.set("Passwords do not match.")
                return
            if len(pw) < 10:
                self.status_var.set("Master password must be ≥ 10 characters.")
                return
            self.status_var.set("Creating vault… (key derivation may take a moment)")
            self.update()

        def work():
            try:
                if is_new:
                    vault.create(pw)
                else:
                    vault.unlock(pw)
                self.vault = vault
                self.after(0, self._open_main)
            except WrongPasswordError:
                self.after(0, lambda: self.status_var.set("❌ Wrong password."))
            except Exception as ex:
                self.after(0, lambda: self.status_var.set(f"Error: {ex}"))

        threading.Thread(target=work, daemon=True).start()

    def _open_main(self):
        self.withdraw()
        app = MainWindow(self.vault, self)
        app.mainloop()



class MainWindow(tk.Toplevel):
    def __init__(self, vault: SecureVault, login_win: LoginWindow):
        super().__init__()
        self.vault = vault
        self.login_win = login_win
        self.title("SecureVault")
        self.configure(bg=BG)
        self._center(860, 560)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._build()
        self._refresh_list()

    def _center(self, w, h):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

    def _build(self):
        # ── Sidebar ──────────────────────────────────────────────────────────
        sidebar = tk.Frame(self, bg=BG2, width=220)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="🔐  SecureVault", font=FONT_HEADER,
                 bg=BG2, fg=TEXT).pack(padx=16, pady=(20, 12), anchor="w")

        # Search
        tk.Label(sidebar, text="Search", font=FONT_SMALL,
                 bg=BG2, fg=SUBTEXT).pack(padx=16, anchor="w")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._refresh_list())
        search = styled_entry(sidebar, textvariable=self.search_var)
        search.pack(fill="x", padx=16, pady=(4, 12), ipady=6)

        # List
        list_frame = tk.Frame(sidebar, bg=BG2)
        list_frame.pack(fill="both", expand=True, padx=8)

        scrollbar = tk.Scrollbar(list_frame, bg=BG2, troughcolor=BG2,
                                  activebackground=ACCENT, relief="flat", width=6)
        self.service_list = tk.Listbox(
            list_frame, bg=BG2, fg=TEXT, selectbackground=ACCENT,
            selectforeground="white", relief="flat", font=FONT_BODY,
            activestyle="none", cursor="hand2", yscrollcommand=scrollbar.set,
            borderwidth=0, highlightthickness=0,
        )
        scrollbar.config(command=self.service_list.yview)
        scrollbar.pack(side="right", fill="y")
        self.service_list.pack(fill="both", expand=True)
        self.service_list.bind("<<ListboxSelect>>", self._on_select)

        # Sidebar buttons
        btn_frame = tk.Frame(sidebar, bg=BG2)
        btn_frame.pack(fill="x", padx=8, pady=12)
        styled_button(btn_frame, "+ Add Entry", self._show_add_form).pack(
            fill="x", pady=2)
        styled_button(btn_frame, "⚙ Settings", self._show_settings,
                      color=BG3).pack(fill="x", pady=2)

        self.detail = tk.Frame(self, bg=BG)
        self.detail.pack(side="right", fill="both", expand=True)
        self._show_placeholder()


    def _refresh_list(self):
        q = self.search_var.get().strip()
        self.service_list.delete(0, tk.END)
        services = self.vault.search(q) if q else self.vault.list_services()
        for s in services:
            self.service_list.insert(tk.END, f"  {s}")
        self._all_services = services  # keep in sync

    def _on_select(self, _event):
        sel = self.service_list.curselection()
        if not sel:
            return
        service = self._all_services[sel[0]]
        self._show_detail(service)


    def _show_placeholder(self):
        for w in self.detail.winfo_children():
            w.destroy()
        tk.Label(self.detail, text="Select an entry or add a new one",
                 font=FONT_BODY, bg=BG, fg=SUBTEXT).pack(expand=True)

    def _show_detail(self, service: str):
        entry = self.vault.get(service)
        if not entry:
            return
        for w in self.detail.winfo_children():
            w.destroy()

        pad = dict(padx=32, pady=6)

        tk.Label(self.detail, text=service, font=("Segoe UI", 16, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=32, pady=(28, 4))
        tk.Label(self.detail, text=f"Modified: {entry.get('modified','')[:10]}",
                 font=FONT_SMALL, bg=BG, fg=SUBTEXT).pack(anchor="w", padx=32)

        sep = tk.Frame(self.detail, bg=BORDER, height=1)
        sep.pack(fill="x", padx=32, pady=14)

        def field_row(label, value, is_secret=False):
            row = tk.Frame(self.detail, bg=BG)
            row.pack(fill="x", **pad)
            tk.Label(row, text=label, font=FONT_SMALL, bg=BG,
                     fg=SUBTEXT, width=12, anchor="w").pack(side="left")
            disp = "•" * len(value) if is_secret else value
            val_lbl = tk.Label(row, text=disp, font=FONT_MONO, bg=BG3,
                               fg=TEXT, padx=8, pady=4, relief="flat")
            val_lbl.pack(side="left", fill="x", expand=True)

            def copy_val():
                try:
                    pyperclip.copy(value)
                    original = copy_btn.cget("text")
                    copy_btn.config(text="✓ Copied!", bg=SUCCESS)
                    self.after(1500, lambda: copy_btn.config(text=original, bg=ACCENT))
                except Exception:
                    pass

            copy_btn = styled_button(row, "Copy", copy_val)
            copy_btn.pack(side="left", padx=(8, 0))

            if is_secret:
                shown = [False]
                def toggle():
                    shown[0] = not shown[0]
                    val_lbl.config(text=value if shown[0] else "•" * len(value))
                    eye_btn.config(text="Hide" if shown[0] else "Show")
                eye_btn = styled_button(row, "Show", toggle, color=BG3)
                eye_btn.pack(side="left", padx=(4, 0))

        field_row("Username", entry.get("username", ""))
        field_row("Password", entry.get("password", ""), is_secret=True)
        if entry.get("notes"):
            field_row("Notes", entry.get("notes", ""))
        if entry.get("totp_secret"):
            field_row("TOTP", entry.get("totp_secret", ""), is_secret=True)

        sep2 = tk.Frame(self.detail, bg=BORDER, height=1)
        sep2.pack(fill="x", padx=32, pady=14)

        btn_row = tk.Frame(self.detail, bg=BG)
        btn_row.pack(fill="x", padx=32)
        styled_button(btn_row, "✏ Edit", lambda: self._show_edit_form(service),
                      color=BG3).pack(side="left", padx=(0, 8))
        styled_button(btn_row, "🗑 Delete", lambda: self._delete_entry(service),
                      color=DANGER).pack(side="left")

    def _show_add_form(self, service_to_edit: str | None = None):
        entry = self.vault.get(service_to_edit) if service_to_edit else {}
        for w in self.detail.winfo_children():
            w.destroy()

        title = "Edit Entry" if service_to_edit else "New Entry"
        tk.Label(self.detail, text=title, font=("Segoe UI", 16, "bold"),
                 bg=BG, fg=TEXT).pack(anchor="w", padx=32, pady=(28, 16))

        fields: dict[str, tk.Entry] = {}

        def form_row(label, key, show=""):
            row = tk.Frame(self.detail, bg=BG)
            row.pack(fill="x", padx=32, pady=5)
            tk.Label(row, text=label, font=FONT_SMALL, bg=BG,
                     fg=SUBTEXT, width=12, anchor="w").pack(side="left")
            e = styled_entry(row, show=show)
            e.pack(side="left", fill="x", expand=True, ipady=6)
            e.insert(0, entry.get(key, "") or "")
            fields[key] = e
            return e

        if not service_to_edit:
            form_row("Service", "service")
        form_row("Username", "username")
        pw_entry = form_row("Password", "password", show="•")
        form_row("Notes", "notes")
        form_row("TOTP Secret", "totp_secret", show="•")

        # Password generator
        gen_row = tk.Frame(self.detail, bg=BG)
        gen_row.pack(fill="x", padx=32, pady=(0, 12))
        tk.Label(gen_row, text="", width=12, bg=BG).pack(side="left")

        def gen_password():
            chars = string.ascii_letters + string.digits + "!@#$%^&*()"
            pw = "".join(secrets.choice(chars) for _ in range(20))
            fields["password"].delete(0, tk.END)
            fields["password"].insert(0, pw)

        styled_button(gen_row, "⚡ Generate Password", gen_password,
                      color=BG3).pack(side="left")

        def save():
            service = service_to_edit or fields.get("service", None)
            if isinstance(service, tk.Entry):
                service = service.get().strip()
            if not service:
                messagebox.showerror("Error", "Service name cannot be empty.", parent=self)
                return
            username = fields["username"].get().strip()
            password = fields["password"].get()
            notes = fields["notes"].get().strip()
            totp = fields["totp_secret"].get().strip()
            try:
                if service_to_edit:
                    self.vault.update(service_to_edit, username=username,
                                      password=password, notes=notes, totp_secret=totp)
                else:
                    self.vault.add(service, username, password, notes, totp)
                self._refresh_list()
                self._show_detail(service)
            except Exception as e:
                messagebox.showerror("Save Error", str(e), parent=self)

        btn_row = tk.Frame(self.detail, bg=BG)
        btn_row.pack(fill="x", padx=32, pady=8)
        styled_button(btn_row, "💾 Save", save).pack(side="left", padx=(0, 8))
        styled_button(btn_row, "Cancel", self._show_placeholder,
                      color=BG3).pack(side="left")

    def _show_edit_form(self, service: str):
        self._show_add_form(service_to_edit=service)

    def _delete_entry(self, service: str):
        if messagebox.askyesno("Delete", f"Delete '{service}'? This cannot be undone.",
                               icon="warning", parent=self):
            self.vault.delete(service)
            self._refresh_list()
            self._show_placeholder()


    def _show_settings(self):
        win = tk.Toplevel(self)
        win.title("Settings")
        win.configure(bg=BG)
        win.geometry("360x260")
        win.resizable(False, False)

        tk.Label(win, text="Settings", font=FONT_HEADER, bg=BG, fg=TEXT).pack(
            pady=(20, 14))

        def change_pw():
            old = simpledialog.askstring("Change Password", "Current password:",
                                          show="•", parent=win)
            if not old:
                return
            new = simpledialog.askstring("Change Password", "New password (≥10 chars):",
                                          show="•", parent=win)
            if not new or len(new) < 10:
                messagebox.showerror("Error", "New password too short.", parent=win)
                return
            try:
                self.vault.change_master_password(old, new)
                messagebox.showinfo("Done", "Master password changed successfully.", parent=win)
            except Exception as e:
                messagebox.showerror("Error", str(e), parent=win)

        styled_button(win, "🔑 Change Master Password", change_pw).pack(
            fill="x", padx=40, pady=6)

        tk.Label(win, text=f"Vault: {VAULT_FILE}", font=FONT_SMALL,
                 bg=BG, fg=SUBTEXT).pack(pady=(12, 0))
        tk.Label(win, text="Encryption: AES-256-GCM  |  KDF: Argon2id",
                 font=FONT_SMALL, bg=BG, fg=SUBTEXT).pack()
        styled_button(win, "Close", win.destroy, color=BG3).pack(pady=16)

    def _on_close(self):
        self.vault.lock()
        self.login_win.destroy()
        self.destroy()


if __name__ == "__main__":
    app = LoginWindow()
    app.mainloop()
