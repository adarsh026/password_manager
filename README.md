# Keepsake Password Manager

Keepsake is a desktop password manager built with Python and Tkinter. It gives your local vault a searchable interface with quick password actions and a configurable generator.

## Run the app

Requires Python 3.10 or later with Tkinter available. No third-party packages are required.

```bash
python project.py
```

The app reads and writes `password.csv` next to `project.py`.

## Features

- Switch between light and dark themes.
- Search logins or filter the vault to favorites.
- Save multiple accounts per service with optional usernames or emails.
- Generate passwords from 12 to 64 characters and choose which character types to include.
- View a rough password-strength estimate, reveal or copy passwords, and copy usernames.
- Add, edit, favorite, and delete logins.
- Clear a copied password from the clipboard after 30 seconds if it is still there.
- Save CSV updates atomically to reduce the chance of file damage if a write is interrupted.

Existing CSV files with the `aim,password` columns remain readable. On the next save, the app writes the expanded `aim,username,password,favorite` format.

## Storage and security

The CSV file contains passwords as plain text. It is not protected by a master password or encryption, so anyone with access to the file can read the saved passwords. Keep the file on a device you trust and restrict access to it. This project is a basic local utility, not a secure vault for important accounts.

Keep a backup of `password.csv` before moving or changing the project. The `aim` column stores the service or website name.
