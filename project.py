

from __future__ import annotations

import csv
import math
import os
import secrets
import string
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk


PASSWORD_FILE = Path(__file__).resolve().with_name("password.csv")
PASSWORD_LENGTH = 20
MIN_PASSWORD_LENGTH = 12

LIGHT_COLORS = {
    "background": "#F5F7FB",
    "surface": "#FFFFFF",
    "ink": "#182230",
    "muted": "#667085",
    "border": "#E4E7EC",
    "primary": "#5548D9",
    "primary_hover": "#4438C4",
    "soft_primary": "#EFEDFF",
    "warning_bg": "#FFF8E8",
    "warning_ink": "#8A5A00",
    "danger": "#B42318",
    "success": "#067647",
    "shadow": "#E7EAF2",
    "primary_text": "#FFFFFF",
}
DARK_COLORS = {
    "background": "#10131D",
    "surface": "#191E2B",
    "ink": "#F2F4F7",
    "muted": "#A4ADBD",
    "border": "#30384A",
    "primary": "#A79BFF",
    "primary_hover": "#B9B0FF",
    "soft_primary": "#302B50",
    "warning_bg": "#332B1A",
    "warning_ink": "#F2C96D",
    "danger": "#FDA29B",
    "success": "#6CE9A6",
    "shadow": "#0C0F17",
    "primary_text": "#18132D",
}
COLORS = dict(LIGHT_COLORS)


class PasswordStore:
    """Read and write the compatible ``aim,password`` CSV format."""

    def __init__(self, path: Path = PASSWORD_FILE) -> None:
        self.path = path

    def load(self) -> list[dict[str, str]]:
        if not self.path.exists():
            return []

        with self.path.open("r", newline="", encoding="utf-8-sig") as csv_file:
            reader = csv.DictReader(csv_file)
            if not reader.fieldnames:
                return []
            if "aim" not in reader.fieldnames or "password" not in reader.fieldnames:
                raise ValueError("The vault CSV must have 'aim' and 'password' columns.")

            entries = []
            for row in reader:
                aim = (row.get("aim") or "").strip()
                password = row.get("password") or ""
                if aim:
                    entries.append(
                        {
                            "aim": aim,
                            "username": row.get("username") or "",
                            "password": password,
                            "favorite": (row.get("favorite") or "").strip().casefold() in {"true", "yes", "1"},
                        }
                    )
            return entries

    def save(self, entries: list[dict[str, str]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                newline="",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f"{self.path.name}.",
                suffix=".tmp",
                delete=False,
            ) as csv_file:
                temp_path = Path(csv_file.name)
                writer = csv.DictWriter(csv_file, fieldnames=["aim", "username", "password", "favorite"])
                writer.writeheader()
                writer.writerows(entries)
            os.replace(temp_path, self.path)
        except OSError:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise


def generate_password(
    length: int = PASSWORD_LENGTH,
    *,
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> str:
    """Generate a password with a guaranteed character from each enabled set."""
    groups = []
    if lowercase:
        groups.append(string.ascii_lowercase)
    if uppercase:
        groups.append(string.ascii_uppercase)
    if digits:
        groups.append(string.digits)
    if symbols:
        groups.append(string.punctuation)
    if not groups:
        raise ValueError("Select at least one character type.")
    if length < len(groups):
        raise ValueError("Password length is too short for the selected character types.")

    password_chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    password_chars.extend(secrets.choice(alphabet) for _ in range(length - len(password_chars)))
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def estimate_password_strength(password: str) -> tuple[str, float, int]:
    """Return a rough entropy estimate, displayed as guidance rather than a proof."""
    pool_size = 0
    if any(char in string.ascii_lowercase for char in password):
        pool_size += 26
    if any(char in string.ascii_uppercase for char in password):
        pool_size += 26
    if any(char in string.digits for char in password):
        pool_size += 10
    if any(char in string.punctuation for char in password):
        pool_size += len(string.punctuation)
    bits = round(len(password) * math.log2(pool_size)) if pool_size else 0
    if password:
        bits = round(bits * len(set(password)) / len(password))
    normalized = password.casefold()
    if any(token in normalized for token in ("password", "qwerty", "letmein", "welcome", "admin", "123456", "abcdef")):
        bits = min(bits, 24)
    if bits < 40:
        label, score = "Weak", 20
    elif bits < 60:
        label, score = "Fair", 45
    elif bits < 80:
        label, score = "Good", 70
    else:
        label, score = "Strong", 100
    return label, score, bits


class PasswordManagerApp:
    def __init__(self, root: tk.Tk, store: PasswordStore) -> None:
        self.root = root
        self.store = store
        self.entries: list[dict[str, str]] = []
        self.visible_entries: dict[str, dict[str, str]] = {}
        self.selected_entry: dict[str, str] | None = None
        self.vault_readable = True
        self.password_visible = False
        self.dark_mode = False
        self.search_var = tk.StringVar()
        self.favorites_only_var = tk.BooleanVar(value=False)
        self.search_var.trace_add("write", self._on_search)

        self._configure_window()
        self._configure_styles()
        self._build_layout()
        self._load_vault()

    def _configure_window(self) -> None:
        self.root.title("Keepsake · Password Manager")
        self.root.geometry("1120x760")
        self.root.minsize(880, 620)
        self.root.configure(bg=COLORS["background"])

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("App.TFrame", background=COLORS["background"])
        style.configure("Card.TFrame", background=COLORS["surface"])
        style.configure("App.TLabel", background=COLORS["background"], foreground=COLORS["ink"], font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=COLORS["surface"], foreground=COLORS["ink"], font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=COLORS["surface"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure("Eyebrow.TLabel", background=COLORS["surface"], foreground=COLORS["primary"], font=("Segoe UI", 9, "bold"))
        style.configure("Title.TLabel", background=COLORS["background"], foreground=COLORS["ink"], font=("Segoe UI Semibold", 25))
        style.configure("Subtitle.TLabel", background=COLORS["background"], foreground=COLORS["muted"], font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=COLORS["surface"], foreground=COLORS["ink"], font=("Segoe UI Semibold", 17))
        style.configure("Count.TLabel", background=COLORS["surface"], foreground=COLORS["muted"], font=("Segoe UI", 9))
        style.configure(
            "Primary.TButton",
            background=COLORS["primary"],
            foreground=COLORS["primary_text"],
            padding=(16, 10),
            borderwidth=0,
            font=("Segoe UI Semibold", 10),
        )
        style.map("Primary.TButton", background=[("active", COLORS["primary_hover"]), ("disabled", "#B8B4E8")])
        style.configure(
            "Secondary.TButton",
            background=COLORS["surface"],
            foreground=COLORS["ink"],
            padding=(12, 8),
            borderwidth=1,
            relief="solid",
            bordercolor=COLORS["border"],
            font=("Segoe UI", 9),
        )
        style.map("Secondary.TButton", background=[("active", "#F8F9FC")])
        style.configure(
            "Danger.TButton",
            background=COLORS["surface"],
            foreground=COLORS["danger"],
            padding=(12, 8),
            borderwidth=1,
            relief="solid",
            bordercolor=COLORS["border"],
            font=("Segoe UI", 9),
        )
        style.map("Danger.TButton", background=[("active", "#FEF3F2")])
        style.configure(
            "Vault.Treeview",
            background=COLORS["surface"],
            fieldbackground=COLORS["surface"],
            foreground=COLORS["ink"],
            rowheight=44,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Vault.Treeview.Heading",
            background=COLORS["surface"],
            foreground=COLORS["muted"],
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Vault.Treeview", background=[("selected", COLORS["soft_primary"])], foreground=[("selected", COLORS["primary"])])
        style.configure("TEntry", padding=(10, 9), fieldbackground=COLORS["surface"], foreground=COLORS["ink"])
        style.configure("Filter.TCheckbutton", background=COLORS["background"], foreground=COLORS["ink"], font=("Segoe UI", 9))
        style.map("Filter.TCheckbutton", background=[("active", COLORS["background"])], foreground=[("disabled", COLORS["muted"])])
        style.configure("GeneratorCheck.TCheckbutton", background=COLORS["surface"], foreground=COLORS["ink"], font=("Segoe UI", 10))
        style.map("GeneratorCheck.TCheckbutton", background=[("active", COLORS["surface"])])
        style.configure("Strength.Horizontal.TProgressbar", troughcolor=COLORS["border"], background=COLORS["primary"], bordercolor=COLORS["border"], lightcolor=COLORS["primary"], darkcolor=COLORS["primary"])

    def _build_layout(self) -> None:
        self.page = ttk.Frame(self.root, style="App.TFrame", padding=(34, 24, 34, 24))
        self.page.pack(fill="both", expand=True)
        page = self.page

        header = ttk.Frame(page, style="App.TFrame")
        header.pack(fill="x", pady=(0, 30))

        brand = ttk.Frame(header, style="App.TFrame")
        brand.pack(side="left")
        logo = tk.Label(
            brand,
            text="K",
            bg=COLORS["primary"],
            fg=COLORS["primary_text"],
            font=("Segoe UI Semibold", 15),
            width=2,
            height=1,
            padx=2,
            pady=5,
        )
        logo.pack(side="left", padx=(0, 11))
        brand_text = ttk.Frame(brand, style="App.TFrame")
        brand_text.pack(side="left")
        ttk.Label(brand_text, text="Keepsake", style="App.TLabel", font=("Segoe UI Semibold", 13)).pack(anchor="w")
        ttk.Label(brand_text, text="PERSONAL VAULT", style="App.TLabel", foreground=COLORS["muted"], font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(1, 0))

        self.storage_badge = tk.Label(
            header,
            text="●  Local CSV vault",
            bg=COLORS["warning_bg"],
            fg=COLORS["warning_ink"],
            font=("Segoe UI", 9),
            padx=12,
            pady=7,
        )
        self.storage_badge.pack(side="right", pady=4)
        self.theme_button = ttk.Button(
            header,
            text="☾  Dark mode" if not self.dark_mode else "☀  Light mode",
            style="Secondary.TButton",
            command=self._toggle_theme,
        )
        self.theme_button.pack(side="right", padx=(0, 10), pady=2)

        title_row = ttk.Frame(page, style="App.TFrame")
        title_row.pack(fill="x", pady=(0, 22))
        heading_block = ttk.Frame(title_row, style="App.TFrame")
        heading_block.pack(side="left", fill="x", expand=True)
        ttk.Label(heading_block, text="Your vault", style="Title.TLabel").pack(anchor="w")
        ttk.Label(heading_block, text="Keep saved logins organized and easy to find.", style="Subtitle.TLabel").pack(anchor="w", pady=(5, 0))
        self.add_button = ttk.Button(title_row, text="＋  Add password", style="Primary.TButton", command=self._open_add_dialog)
        self.add_button.pack(side="right", anchor="s")
        if not self.vault_readable:
            self.add_button.configure(state="disabled")

        toolbar = ttk.Frame(page, style="App.TFrame")
        toolbar.pack(fill="x", pady=(0, 16))
        search_wrap = ttk.Frame(toolbar, style="Card.TFrame", padding=(12, 2))
        search_wrap.pack(side="left", fill="x", expand=True, padx=(0, 12))
        tk.Label(search_wrap, text="⌕", bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 17)).pack(side="left", padx=(0, 8))
        search = ttk.Entry(search_wrap, textvariable=self.search_var)
        search.pack(side="left", fill="x", expand=True, ipady=5)
        search.bind("<Escape>", lambda _event: self.search_var.set(""))
        self.count_label = ttk.Label(toolbar, text="0 entries", style="App.TLabel", foreground=COLORS["muted"])
        self.count_label.pack(side="right", padx=(14, 0))
        ttk.Checkbutton(
            toolbar,
            text="★ Favorites",
            variable=self.favorites_only_var,
            command=self._refresh_list,
            style="Filter.TCheckbutton",
        ).pack(side="right", padx=(8, 0))

        content = ttk.Frame(page, style="App.TFrame")
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=4, minsize=290)
        content.columnconfigure(1, weight=6, minsize=390)
        content.rowconfigure(0, weight=1)

        list_card = ttk.Frame(content, style="Card.TFrame", padding=(0, 0, 0, 8))
        list_card.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        list_header = ttk.Frame(list_card, style="Card.TFrame", padding=(18, 17, 18, 10))
        list_header.pack(fill="x")
        ttk.Label(list_header, text="SAVED LOGINS", style="Eyebrow.TLabel").pack(side="left")
        self.list_count = ttk.Label(list_header, text="0", style="Count.TLabel")
        self.list_count.pack(side="right")

        tree_wrap = ttk.Frame(list_card, style="Card.TFrame", padding=(10, 0, 10, 0))
        tree_wrap.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tree_wrap, columns=("service", "username"), show="headings", selectmode="browse", style="Vault.Treeview")
        self.tree.heading("service", text="SERVICE", anchor="w")
        self.tree.heading("username", text="ACCOUNT", anchor="w")
        self.tree.column("service", anchor="w", width=170, minwidth=110, stretch=True)
        self.tree.column("username", anchor="w", width=130, minwidth=90, stretch=True)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        detail_card = ttk.Frame(content, style="Card.TFrame", padding=(26, 24, 26, 22))
        detail_card.grid(row=0, column=1, sticky="nsew")
        self.detail_card = detail_card
        self.detail_content = ttk.Frame(detail_card, style="Card.TFrame")
        self.detail_content.pack(fill="both", expand=True, anchor="n")
        self._show_empty_state()

        footer = ttk.Frame(page, style="App.TFrame")
        footer.pack(fill="x", pady=(17, 0))
        self.status_label = ttk.Label(footer, text="Saved on this device", style="App.TLabel", foreground=COLORS["muted"])
        self.status_label.pack(side="left")
        ttk.Label(footer, text="Your vault file is not encrypted", style="App.TLabel", foreground=COLORS["warning_ink"]).pack(side="right")

    def _load_vault(self) -> None:
        try:
            self.entries = self.store.load()
        except (OSError, csv.Error, ValueError) as error:
            messagebox.showerror("Could not open vault", f"The password file could not be read.\n\n{error}", parent=self.root)
            self.entries = []
            self.vault_readable = False
            self.add_button.configure(state="disabled")
            self._set_status("Vault could not be read · editing is disabled", COLORS["danger"])
        self._refresh_list()

    def _on_search(self, *_args: object) -> None:
        self._refresh_list()

    def _toggle_theme(self) -> None:
        selected = self.selected_entry
        self.dark_mode = not self.dark_mode
        COLORS.update(DARK_COLORS if self.dark_mode else LIGHT_COLORS)
        self.root.configure(bg=COLORS["background"])
        self.page.destroy()
        self._configure_styles()
        self._build_layout()
        self.selected_entry = selected
        self._refresh_list()

    def _refresh_list(self) -> None:
        previously_selected = self.selected_entry
        query = self.search_var.get().strip().casefold()
        self.tree.delete(*self.tree.get_children())
        self.visible_entries.clear()
        favorites_only = self.favorites_only_var.get()
        matching = [
            (index, entry)
            for index, entry in enumerate(self.entries)
            if query in entry["aim"].casefold() and (not favorites_only or entry["favorite"])
        ]
        for index, entry in matching:
            item_id = str(index)
            self.visible_entries[item_id] = entry
            service = f"★   {entry['aim']}" if entry["favorite"] else f"   {entry['aim']}"
            self.tree.insert("", "end", iid=item_id, values=(service, entry.get("username") or "No username"))

        total = len(self.entries)
        shown = len(matching)
        if query or favorites_only:
            self.count_label.configure(text=f"{shown} of {total} entries")
        else:
            self.count_label.configure(text=f"{total} {('entry' if total == 1 else 'entries')}")
        self.list_count.configure(text=str(shown))

        selected_item = None
        if previously_selected is not None:
            selected_item = next((item_id for item_id, entry in self.visible_entries.items() if entry is previously_selected), None)
        if selected_item is not None:
            self.tree.selection_set(selected_item)
            self.tree.focus(selected_item)
        elif shown:
            first = str(matching[0][0])
            self.tree.selection_set(first)
            self.tree.focus(first)
            self._display_entry(self.visible_entries[first])
        else:
            self.selected_entry = None
            if not self.vault_readable:
                self._show_empty_state("Vault unavailable", "Fix the password.csv file format to continue.")
            elif favorites_only and not query:
                self._show_empty_state("No favorites yet", "Star a login to keep it easy to find.")
            else:
                self._show_empty_state("No matches" if query else "Your vault is empty", "Try another search or add a login to get started." if query else "Add your first login and it will appear here.")

    def _on_select(self, _event: tk.Event | None = None) -> None:
        selection = self.tree.selection()
        if selection:
            entry = self.visible_entries.get(selection[0])
            if entry is not None:
                self._display_entry(entry)

    def _clear_detail(self) -> None:
        for child in self.detail_content.winfo_children():
            child.destroy()

    def _show_empty_state(self, title: str = "Choose a saved login", subtitle: str = "Select a service on the left to view its password.") -> None:
        self._clear_detail()
        self.selected_entry = None
        panel = ttk.Frame(self.detail_content, style="Card.TFrame")
        panel.pack(fill="both", expand=True)
        icon = tk.Label(panel, text="✦", bg=COLORS["soft_primary"], fg=COLORS["primary"], font=("Segoe UI", 22), width=3, height=1, pady=8)
        icon.pack(anchor="w", pady=(8, 21))
        ttk.Label(panel, text=title, style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(panel, text=subtitle, style="Muted.TLabel", wraplength=350, justify="left").pack(anchor="w", pady=(8, 0))
        if not self.entries and self.vault_readable:
            ttk.Button(panel, text="＋  Add your first password", style="Primary.TButton", command=self._open_add_dialog).pack(anchor="w", pady=(22, 0))

    def _display_entry(self, entry: dict[str, str]) -> None:
        self.selected_entry = entry
        self.password_visible = False
        self._clear_detail()

        ttk.Label(self.detail_content, text="SAVED LOGIN", style="Eyebrow.TLabel").pack(anchor="w", pady=(4, 12))
        ttk.Label(self.detail_content, text=entry["aim"], style="CardTitle.TLabel", wraplength=430).pack(anchor="w")
        ttk.Label(self.detail_content, text="Password details", style="Muted.TLabel").pack(anchor="w", pady=(5, 22))

        username_row = ttk.Frame(self.detail_content, style="Card.TFrame")
        username_row.pack(fill="x", pady=(0, 20))
        username_info = ttk.Frame(username_row, style="Card.TFrame")
        username_info.pack(side="left", fill="x", expand=True)
        ttk.Label(username_info, text="USERNAME / EMAIL", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        username = entry.get("username", "")
        ttk.Label(username_info, text=username or "Not added", style="Muted.TLabel").pack(anchor="w", pady=(5, 0))
        if username:
            ttk.Button(username_row, text="Copy", style="Secondary.TButton", command=lambda: self._copy_password(username, "Username")).pack(side="right")

        label_row = ttk.Frame(self.detail_content, style="Card.TFrame")
        label_row.pack(fill="x", pady=(0, 8))
        ttk.Label(label_row, text="PASSWORD", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Label(label_row, text="Saved locally", style="Muted.TLabel").pack(side="right")

        password_row = ttk.Frame(self.detail_content, style="Card.TFrame")
        password_row.pack(fill="x")
        self.password_var = tk.StringVar(value=entry["password"])
        self.password_field = ttk.Entry(password_row, textvariable=self.password_var, show="●", state="readonly", font=("Consolas", 11))
        self.password_field.pack(side="left", fill="x", expand=True, ipady=4, padx=(0, 8))
        self.reveal_button = ttk.Button(password_row, text="Show", style="Secondary.TButton", command=self._toggle_password)
        self.reveal_button.pack(side="left", padx=(0, 7))
        ttk.Button(password_row, text="Copy", style="Secondary.TButton", command=lambda: self._copy_password(entry["password"])).pack(side="left")

        strength_label, strength_score, strength_bits = estimate_password_strength(entry["password"])
        strength_row = ttk.Frame(self.detail_content, style="Card.TFrame")
        strength_row.pack(fill="x", pady=(12, 0))
        ttk.Label(strength_row, text="Password strength", style="Muted.TLabel").pack(side="left")
        ttk.Label(strength_row, text=f"{strength_label}  ·  ~{strength_bits} bit estimate", style="Card.TLabel", foreground=COLORS["success"] if strength_label == "Strong" else COLORS["warning_ink"] if strength_label in {"Weak", "Fair"} else COLORS["primary"]).pack(side="right")
        ttk.Progressbar(self.detail_content, maximum=100, value=strength_score, style="Strength.Horizontal.TProgressbar").pack(fill="x", pady=(7, 0))

        ttk.Separator(self.detail_content, orient="horizontal").pack(fill="x", pady=(27, 20))
        actions = ttk.Frame(self.detail_content, style="Card.TFrame")
        actions.pack(fill="x")
        ttk.Button(actions, text="Edit password", style="Primary.TButton", command=lambda: self._open_edit_dialog(entry)).pack(side="left")
        ttk.Button(actions, text="Delete", style="Danger.TButton", command=lambda: self._delete_entry(entry)).pack(side="left", padx=(9, 0))
        self.favorite_button = ttk.Button(
            actions,
            text="★  Favorited" if entry["favorite"] else "☆  Add favorite",
            style="Secondary.TButton",
            command=lambda: self._toggle_favorite(entry),
        )
        self.favorite_button.pack(side="right")

        warning = tk.Frame(self.detail_content, bg=COLORS["warning_bg"], padx=13, pady=12)
        warning.pack(fill="x", side="bottom", pady=(25, 0))
        tk.Label(warning, text="Storage note", bg=COLORS["warning_bg"], fg=COLORS["warning_ink"], font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(
            warning,
            text="Passwords in password.csv are plain text. Anyone who can open that file can read them.",
            bg=COLORS["warning_bg"],
            fg=COLORS["warning_ink"],
            font=("Segoe UI", 9),
            wraplength=390,
            justify="left",
        ).pack(anchor="w", pady=(4, 0))

    def _toggle_password(self) -> None:
        self.password_visible = not self.password_visible
        self.password_field.configure(show="" if self.password_visible else "●")
        self.reveal_button.configure(text="Hide" if self.password_visible else "Show")

    def _toggle_favorite(self, entry: dict[str, str]) -> None:
        if not self.vault_readable:
            return
        candidate = [dict(row) for row in self.entries]
        index = self.entries.index(entry)
        updated = dict(entry)
        updated["favorite"] = not entry["favorite"]
        candidate[index] = updated
        try:
            self.store.save(candidate)
        except OSError as error:
            messagebox.showerror("Could not update favorite", str(error), parent=self.root)
            return
        self.entries = candidate
        self.selected_entry = updated
        self._refresh_list()
        self._set_status("Added to favorites" if updated["favorite"] else "Removed from favorites", COLORS["success"])

    def _copy_password(self, password: str, label: str = "Password") -> None:
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            self.root.update_idletasks()
        except tk.TclError as error:
            messagebox.showerror("Could not copy password", str(error), parent=self.root)
            return

        self._set_status(f"{label} copied · clipboard clears in 30 seconds", COLORS["success"])

        def clear_if_unchanged() -> None:
            try:
                if self.root.clipboard_get() == password:
                    self.root.clipboard_clear()
                    self._set_status("Clipboard cleared", COLORS["muted"])
            except tk.TclError:
                pass

        self.root.after(30_000, clear_if_unchanged)

    def _set_status(self, message: str, color: str = COLORS["muted"]) -> None:
        self.status_label.configure(text=message, foreground=color)

    def _open_add_dialog(self) -> None:
        self._open_entry_dialog()

    def _open_edit_dialog(self, entry: dict[str, str]) -> None:
        self._open_entry_dialog(entry)

    def _open_entry_dialog(self, existing: dict[str, str] | None = None) -> None:
        if not self.vault_readable:
            return
        is_edit = existing is not None
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit password" if is_edit else "Add password")
        dialog.configure(bg=COLORS["background"])
        dialog.resizable(True, True)
        dialog.transient(self.root)
        dialog.grab_set()

        width = 540
        self.root.update_idletasks()
        height = min(560, max(420, self.root.winfo_screenheight() - 100))
        dialog.minsize(460, min(420, height))
        x = self.root.winfo_rootx() + max(0, (self.root.winfo_width() - width) // 2)
        y = self.root.winfo_rooty() + max(0, (self.root.winfo_height() - height) // 2)
        dialog.geometry(f"{width}x{height}+{x}+{y}")

        panel = ttk.Frame(dialog, style="Card.TFrame", padding=(20, 14, 20, 14))
        panel.pack(fill="both", expand=True, padx=14, pady=14)
        button_row = ttk.Frame(panel, style="Card.TFrame")
        button_row.pack(fill="x", side="bottom", pady=(12, 0))
        ttk.Button(button_row, text="Cancel", style="Secondary.TButton", command=dialog.destroy).pack(side="right", padx=(8, 0))

        form_canvas = tk.Canvas(panel, bg=COLORS["surface"], highlightthickness=0, borderwidth=0)
        form_scroll = ttk.Scrollbar(panel, orient="vertical", command=form_canvas.yview)
        form_canvas.configure(yscrollcommand=form_scroll.set)
        form_canvas.pack(side="left", fill="both", expand=True)
        form = ttk.Frame(form_canvas, style="Card.TFrame", padding=(8, 6, 8, 10))
        form_window = form_canvas.create_window((0, 0), window=form, anchor="nw")

        def sync_form_scroll(_event: tk.Event | None = None) -> None:
            form_canvas.configure(scrollregion=form_canvas.bbox("all"))
            form_canvas.itemconfigure(form_window, width=form_canvas.winfo_width())
            needs_scroll = form.winfo_reqheight() > form_canvas.winfo_height() + 2
            if needs_scroll and not form_scroll.winfo_ismapped():
                form_scroll.pack(side="right", fill="y")
            elif not needs_scroll and form_scroll.winfo_ismapped():
                form_scroll.pack_forget()

        form.bind("<Configure>", lambda _event: dialog.after_idle(sync_form_scroll))
        form_canvas.bind("<Configure>", lambda event: (form_canvas.itemconfigure(form_window, width=event.width), dialog.after_idle(sync_form_scroll)))
        form_canvas.bind("<MouseWheel>", lambda event: form_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units"))

        ttk.Label(form, text="EDIT LOGIN" if is_edit else "NEW LOGIN", style="Eyebrow.TLabel").pack(anchor="w")
        ttk.Label(form, text="Update your password" if is_edit else "Add a password", style="CardTitle.TLabel").pack(anchor="w", pady=(5, 10))

        ttk.Label(form, text="Service or website", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        aim_var = tk.StringVar(value=existing["aim"] if existing else "")
        aim_input = ttk.Entry(form, textvariable=aim_var)
        aim_input.pack(fill="x", pady=(0, 9))

        ttk.Label(form, text="Username or email  ·  optional", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        username_var = tk.StringVar(value=existing.get("username", "") if existing else "")
        username_input = ttk.Entry(form, textvariable=username_var)
        username_input.pack(fill="x", pady=(0, 9))

        ttk.Label(form, text="Password", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        password_var = tk.StringVar(value=existing["password"] if existing else generate_password())
        password_input = ttk.Entry(form, textvariable=password_var, show="●", font=("Consolas", 10))
        password_input.pack(fill="x")

        tools_row = ttk.Frame(form, style="Card.TFrame")
        tools_row.pack(fill="x", pady=(7, 10))
        ttk.Label(tools_row, text=f"For best strength, use {MIN_PASSWORD_LENGTH}+ characters.", style="Muted.TLabel").pack(side="left")

        ttk.Button(tools_row, text="⚙ Generator", style="Secondary.TButton", command=lambda: self._open_generator_dialog(dialog, password_var)).pack(side="right")
        password_revealed = tk.BooleanVar(value=False)

        def toggle_dialog_password() -> None:
            password_revealed.set(not password_revealed.get())
            password_input.configure(show="" if password_revealed.get() else "●")
            reveal_dialog_button.configure(text="Hide" if password_revealed.get() else "Show")

        reveal_dialog_button = ttk.Button(tools_row, text="Show", style="Secondary.TButton", command=toggle_dialog_password)
        reveal_dialog_button.pack(side="right", padx=(0, 7))

        dialog_status = ttk.Label(form, text="", style="Muted.TLabel")
        dialog_status.pack(anchor="w", pady=(0, 6))

        def save_entry() -> None:
            aim = aim_var.get().strip()
            password = password_var.get()
            if not aim:
                dialog_status.configure(text="Enter a service or website name.", foreground=COLORS["danger"])
                aim_input.focus_set()
                return
            if not password:
                dialog_status.configure(text="Enter a password or generate one.", foreground=COLORS["danger"])
                password_input.focus_set()
                return
            username = username_var.get().strip()
            if any(
                row["aim"].casefold() == aim.casefold()
                and row.get("username", "").casefold() == username.casefold()
                and row is not existing
                for row in self.entries
            ):
                dialog_status.configure(text="That service and username already have a saved login.", foreground=COLORS["danger"])
                aim_input.focus_set()
                return

            updated = {
                "aim": aim,
                "username": username,
                "password": password,
                "favorite": existing["favorite"] if existing else False,
            }
            candidate = list(self.entries)
            if existing is None:
                candidate.append(updated)
            else:
                candidate[candidate.index(existing)] = updated
            try:
                self.store.save(candidate)
            except OSError as error:
                dialog_status.configure(text=f"Could not save vault: {error}", foreground=COLORS["danger"])
                return

            self.entries = candidate
            self.selected_entry = updated
            self.search_var.set("")
            self._refresh_list()
            self._display_entry(updated)
            self._set_status("Password added" if not is_edit else "Password updated", COLORS["success"])
            dialog.destroy()

        ttk.Button(button_row, text="Save password", style="Primary.TButton", command=save_entry).pack(side="right")
        dialog.bind("<Return>", lambda _event: save_entry())
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        aim_input.focus_set()

    def _open_generator_dialog(self, parent: tk.Toplevel, password_var: tk.StringVar) -> None:
        generator = tk.Toplevel(parent)
        generator.title("Password generator")
        generator.configure(bg=COLORS["background"])
        generator.resizable(True, True)
        generator.transient(parent)
        generator.grab_set()

        width = 500
        parent.update_idletasks()
        height = min(500, max(400, self.root.winfo_screenheight() - 100))
        generator.minsize(420, min(400, height))
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 2)
        generator.geometry(f"{width}x{height}+{x}+{y}")

        panel = ttk.Frame(generator, style="Card.TFrame", padding=(20, 14, 20, 14))
        panel.pack(fill="both", expand=True, padx=14, pady=14)
        button_row = ttk.Frame(panel, style="Card.TFrame")
        button_row.pack(fill="x", side="bottom", pady=(12, 0))
        ttk.Button(button_row, text="Cancel", style="Secondary.TButton", command=generator.destroy).pack(side="right", padx=(8, 0))

        form_canvas = tk.Canvas(panel, bg=COLORS["surface"], highlightthickness=0, borderwidth=0)
        form_scroll = ttk.Scrollbar(panel, orient="vertical", command=form_canvas.yview)
        form_canvas.configure(yscrollcommand=form_scroll.set)
        form_canvas.pack(side="left", fill="both", expand=True)
        form = ttk.Frame(form_canvas, style="Card.TFrame", padding=(8, 6, 8, 10))
        form_window = form_canvas.create_window((0, 0), window=form, anchor="nw")

        def sync_generator_scroll(_event: tk.Event | None = None) -> None:
            form_canvas.configure(scrollregion=form_canvas.bbox("all"))
            form_canvas.itemconfigure(form_window, width=form_canvas.winfo_width())
            needs_scroll = form.winfo_reqheight() > form_canvas.winfo_height() + 2
            if needs_scroll and not form_scroll.winfo_ismapped():
                form_scroll.pack(side="right", fill="y")
            elif not needs_scroll and form_scroll.winfo_ismapped():
                form_scroll.pack_forget()

        form.bind("<Configure>", lambda _event: generator.after_idle(sync_generator_scroll))
        form_canvas.bind("<Configure>", lambda event: (form_canvas.itemconfigure(form_window, width=event.width), generator.after_idle(sync_generator_scroll)))
        form_canvas.bind("<MouseWheel>", lambda event: form_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units"))

        ttk.Label(form, text="PASSWORD LAB", style="Eyebrow.TLabel").pack(anchor="w")
        ttk.Label(form, text="Build a stronger password", style="CardTitle.TLabel").pack(anchor="w", pady=(5, 10))

        size_row = ttk.Frame(form, style="Card.TFrame")
        size_row.pack(fill="x")
        ttk.Label(size_row, text="Length", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(side="left")
        length_var = tk.DoubleVar(value=PASSWORD_LENGTH)
        length_label = ttk.Label(size_row, text=f"{PASSWORD_LENGTH} characters", style="Muted.TLabel")
        length_label.pack(side="right")
        ttk.Scale(
            form,
            from_=MIN_PASSWORD_LENGTH,
            to=64,
            variable=length_var,
            command=lambda value: length_label.configure(text=f"{round(float(value))} characters"),
        ).pack(fill="x", pady=(8, 19))

        ttk.Label(form, text="Include character types", style="Card.TLabel", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 8))
        options = {
            "lowercase": ("a–z  Lowercase", tk.BooleanVar(value=True)),
            "uppercase": ("A–Z  Uppercase", tk.BooleanVar(value=True)),
            "digits": ("0–9  Numbers", tk.BooleanVar(value=True)),
            "symbols": ("!&?  Symbols", tk.BooleanVar(value=True)),
        }
        option_grid = ttk.Frame(form, style="Card.TFrame")
        option_grid.pack(fill="x")
        for index, (_key, (label, variable)) in enumerate(options.items()):
            ttk.Checkbutton(
                option_grid,
                text=label,
                variable=variable,
                style="GeneratorCheck.TCheckbutton",
            ).grid(row=index // 2, column=index % 2, sticky="w", padx=(0, 22), pady=5)

        generator_status = ttk.Label(form, text="Every selected character type is guaranteed to appear.", style="Muted.TLabel", wraplength=380)
        generator_status.pack(anchor="w", pady=(14, 14))

        def create_password() -> None:
            selected = {key: variable.get() for key, (_label, variable) in options.items()}
            if not any(selected.values()):
                generator_status.configure(text="Select at least one character type.", foreground=COLORS["danger"])
                return
            length = round(length_var.get())
            if length < sum(selected.values()):
                generator_status.configure(text="Increase the length to fit each selected character type.", foreground=COLORS["danger"])
                return
            password_var.set(generate_password(length, **selected))
            generator.destroy()

        ttk.Button(button_row, text="Generate password", style="Primary.TButton", command=create_password).pack(side="right")
        generator.bind("<Escape>", lambda _event: generator.destroy())

    def _delete_entry(self, entry: dict[str, str]) -> None:
        confirmed = messagebox.askyesno(
            "Delete password?",
            f"Remove the saved login for {entry['aim']}? This cannot be undone.",
            icon="warning",
            parent=self.root,
        )
        if not confirmed:
            return

        candidate = [row for row in self.entries if row is not entry]
        try:
            self.store.save(candidate)
        except OSError as error:
            messagebox.showerror("Could not delete password", str(error), parent=self.root)
            return

        self.entries = candidate
        self.selected_entry = None
        self._refresh_list()
        self._set_status("Password deleted", COLORS["success"])


def main() -> None:
    root = tk.Tk()
    PasswordManagerApp(root, PasswordStore())
    root.mainloop()


if __name__ == "__main__":
    main()
