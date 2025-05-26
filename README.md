# 🔐 Zapdos – Encrypted Password Manager with Git Sync

Zapdos is a simple terminal-based password manager written in Python. It encrypts your credentials using AES encryption and stores them in a YAML file with Git version control. You can optionally sync the file to a remote Git repository.

```
 ________                            __                     
/        |                          /  |                    
$$$$$$$$/   ______    ______    ____$$ |  ______    _______ 
    /$$/   /      \  /      \  /    $$ | /      \  /       |
   /$$/    $$$$$$  |/$$$$$$  |/$$$$$$$ |/$$$$$$  |/$$$$$$$/ 
  /$$/     /    $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$      \ 
 /$$/____ /$$$$$$$ |$$ |__$$ |$$ \__$$ |$$ \__$$ | $$$$$$  |
/$$      |$$    $$ |$$    $$/ $$    $$ |$$    $$/ /     $$/ 
$$$$$$$$/  $$$$$$$/ $$$$$$$/   $$$$$$$/  $$$$$$/  $$$$$$$/  
                    $$ |                                    
                    $$ |                                    
                    $$/                                     
```

## 🚀 Getting Started

### Prerequisites

* Python 3.6+
* Git
* `cryptography` and `pyyaml` libraries

Install dependencies:

```
pip install cryptography pyyaml
```

## 🛠 Usage

### Start the app:

```
python zapdos.py
```

### Available commands:

* `add` – Add a new account
* `find` – Search for an account (by website, email, or username)
* `change` – Update an existing account
* `delete` – Remove an account
* `sync` – Push encrypted data to a remote Git repository
* `cls` – Clear the terminal screen
* `exit` – Quit the app

## 🔐 Encryption Details

* **Algorithm**: AES (CFB mode)
* **Key Derivation**: PBKDF2 with SHA-256
* **Salt & IV**: Generated per encryption
* **Encrypted file**: `zapdos.yaml.enc`

Your master password is never stored; it’s required each time to decrypt your data.

## 🌐 Remote Syncing

When you run `sync`:

* Initializes a Git repository if needed
* Prompts for the remote URL (once)
* Adds/commits the encrypted file
* Pushes to the `master` branch of the remote

The remote URL is stored in a `remote_url` file, which is git-ignored.
