import os
import re
import yaml
import subprocess
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def get_user_input():

    try:
        website = input("\nwebsite: ")
        while not website:
            print("website can't be empty")
            website = input("website: ")

        email = input("\nemail: ")
        while email and not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            print("invalid email format")
            email = input("email: ")
        if not email:
            email = ''

        username = input("\nusername: ")
        if not username:
            username = ''

        password = input("\npassword: ")
        while not password:
            print("password can't be empty")
            password = input("password: ")

        passphrase = input("\npassphrase: ")
        if not passphrase:
            passphrase = ''

        return {
            'website': website,
            'email': email,
            'username': username,
            'password': password,
            'passphrase': passphrase
        }
    except KeyboardInterrupt:
        pass

def encrypt_file(file_path, master_password):
    salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = encryptor.update(file_data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as f:
        f.write(salt + iv + encrypted_data)


def decrypt_file(file_path, master_password):
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_data = encrypted_data[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return yaml.safe_load(decrypted_data)
    except Exception:
        print("incorrect master password")
        return None

def add_account(data, master_password):
    new_account = get_user_input()

    if not new_account:
        return

    data['accounts'].append(new_account)
    print("\nadded\n")
    add_to_yaml(data, master_password)
    add_files()
    commit_repo(f"added {new_account.get('website').split('.')[0]}")

def find_account(data, search_term):
    if search_term == '*':
        return data['accounts']

    if search_term == '':
        return None

    results = []
    for account in data['accounts']:
        if re.match(r"[^@]+@[^@]+\.[^@]+", search_term.lower()):
            if search_term.lower() in account.get('email', '').lower():
                results.append(account)

        if (search_term.lower() in account.get('website', '').lower() or
                search_term.lower() in account.get('username', '').lower()):
            results.append(account)
    if results:
        return results
    return None

def change_account(data, website, master_password):
    results = []
    for account in data['accounts']:
        if website.lower() in account.get('website', '').lower():
            results.append(account)
    
    if not results:
        print("does not exist")
        return

    choice = 1
    if len(results) != 1:

        for idx, account in enumerate(results):
            print(f"\n ID: {idx + 1}\n\t--------\n\t{account.get('website')}\n\t--------\n\t\temail: {account.get('email')}\n\t\tusername: {account.get('username')}\n\t\tpassword: {account.get('password')}\n\t\tpassphrase: {account.get('passphrase')}")
        try:
            choice = input("\nID number to change: ").strip()
            if not choice.isdigit() or int(choice) < 1 or int(choice) > len(results):
                print("invalid")
                return
        except KeyboardInterrupt:
            return

    selected_account = results[int(choice) - 1]
    print(f"\n------ site: {selected_account.get('website')} ------")
    print("enter new details. leave blank to keep current value")

    try:
        new_email = input(f"\nemail ({selected_account.get('email')}): ").strip()
        new_username = input(f"\nusername ({selected_account.get('username')}): ").strip()
        new_password = input("\npassword: ").strip()
        new_passphrase = input(f"\npassphrase ({selected_account.get('passphrase')}): ").strip()

        if new_email:
            selected_account['email'] = new_email
        if new_username:
            selected_account['username'] = new_username
        if new_password:
            selected_account['password'] = new_password
        if new_passphrase:
            selected_account['passphrase'] = new_passphrase

        print("\nupdated\n")
        add_to_yaml(data, master_password)
        add_files()
        commit_repo(f"updated {selected_account.get('website').split('.')[0]}")
    except KeyboardInterrupt:
        return

def delete_account(data, website, master_password):
    if website == '*':
        try:
            confirm = input("sure you wanna delete all? (yes/no): ").strip().lower()
            if confirm in ['yes','y']:
                data['accounts'].clear()
                print("all deleted")
            else:
                print("cancelled")
            add_to_yaml(data, master_password)
            add_files()
            commit_repo("deleted all accounts")
            return
        except KeyboardInterrupt:
            return

    results = []
    for account in data['accounts']:
        if website.lower() in account.get('website', '').lower():
            results.append(account)

    if not results:
        print("does not exist")
        return

    if len(results) == 1:
        data['accounts'].remove(results[0])
        print("deleted")
        add_to_yaml(data, master_password)
        add_files()
        commit_repo(f"deleted {results[0].get('website').split('.')[0]}")
        return

    for idx, account in enumerate(results):
        print(f"\n ID: {idx + 1}\n\t--------\n\t{account.get('website')}\n\t--------\n\t\temail: {account.get('email')}\n\t\tusername: {account.get('username')}\n\t\tpassword: {account.get('password')}\n\t\tpassphrase: {account.get('passphrase')}")

    try:
        choice = input("\nID number to delete: ").strip()
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(results):
            print("invalid")
            return
    except KeyboardInterrupt:
        return

    selected_account = results[int(choice) - 1]
    data['accounts'].remove(selected_account)
    print("deleted")
    add_to_yaml(data, master_password)
    add_files()
    commit_repo(f"deleted {selected_account.get('website').split('.')[0]}")

def pretty_print(data):
    print()
    for item in data:
        for key, value in item.items():
            if value:
                print(" "*4+f"{key}: {value}")
        print()

def add_to_yaml(data, master_password):
    with open('zapdos.yaml', 'w') as file:
        yaml.dump(data, file)

    encrypt_file('zapdos.yaml', master_password)
    os.remove('zapdos.yaml')

def init_repo():
    try:
        subprocess.run(['git', 'init'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while initializing the git repository: {e}")

def add_files(is_init=False):
    try:
        if is_init:
            subprocess.run(['git', 'add', '.'], check=True)
        else:
            subprocess.run(['git', 'add', 'zapdos.yaml.enc'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while adding files to the git repository: {e}")

def commit_repo(commit_message):
    try:
        subprocess.run(['git', 'commit', '-m', f'{commit_message}'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while committing files to the git repository: {e}")

def push_repo(remote_url, is_init=False):
    try:
        if is_init:
            subprocess.run(['git', 'remote', 'add', 'origin', remote_url], check=True)
        subprocess.run(['git', 'push', '-u', 'origin', 'master'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while pushing files to the git repository: {e}")

def has_remote_changes():
    try:
        subprocess.run(['git', 'fetch'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = subprocess.run(['git', 'status', '--porcelain'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if result.stdout.decode().strip() == 'M zapdos.yaml.enc' or result.stdout.decode().strip() == '?? zapdos.yaml.enc':
            return True

        local_commit = subprocess.run(['git', 'rev-parse', 'HEAD'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        remote_commit = subprocess.run(['git', 'rev-parse', 'origin/master'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        local_commit_hash = local_commit.stdout.decode().strip()
        remote_commit_hash = remote_commit.stdout.decode().strip()

        if local_commit_hash != remote_commit_hash:
            return True
        return False

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while checking for changes: {e}")
        return False

def get_remote_url():
    if os.path.exists('remote_url'):
        with open('remote_url', 'r') as file:
            return file.read().strip()
    return None

def main():
    try:
        master_password = getpass.getpass("master password: ")
    except KeyboardInterrupt:
        exit()

    if not os.path.exists('.gitignore'):
        with open('.gitignore', 'w') as file:
            file.write('remote_url')
            file.flush()
        init_repo()

    if os.path.exists('zapdos.yaml.enc'):
        data = decrypt_file('zapdos.yaml.enc', master_password)
        if data is None:
            return
    else:
        data = {'accounts': []}


    print("""
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
    """)

    print("\n\n 1. add\n 2. find\n 3. change\n 4. delete\n 5. sync\n 6. cls\n 7. exit")

    while True:
        try:
            choice = input("\nx__> ").strip().lower()
        except KeyboardInterrupt:
            exit()

        if choice in ['add', '1', 'a']:
            add_account(data, master_password)

        elif choice in ['find', '2', 'f']:
            try:
                website = input("\nsearch: ").strip()
                account = find_account(data, website)
                if account:
                    pretty_print(account)
                else:
                    print("not found")
            except KeyboardInterrupt:
                pass

        elif choice in ['change', '3', 'c']:
            try:
                website = input("website: ").strip()
                change_account(data, website, master_password)
            except KeyboardInterrupt:
                pass

        elif choice in ['delete', '4', 'd']:
            try:
                website = input("website to delete: ").strip()
                delete_account(data, website, master_password)
            except KeyboardInterrupt:
                pass

        elif choice in ['sync', '5', 's']:
            if not os.path.exists('.git'):
                print("Initing repo")
                init_repo()

            if not os.path.exists('remote_url'):
                print('Remote URL not found')
                try:
                    remote_url = input("repository URL: ").strip()
                    with open('remote_url', 'w') as file:
                        file.write(remote_url)
                    add_files(is_init=True)
                    commit_repo("initial commit")
                    push_repo(remote_url, is_init=False)
                except KeyboardInterrupt:
                    pass
            else:
                remote_url = open('remote_url', 'r').read().strip()
                if has_remote_changes():
                    add_files()
                    push_repo(remote_url, is_init=False)
                else:
                    print("all synced")

        elif choice in ['cls', '6', 'cl']:
            os.system('cls' if os.name == 'nt' else 'clear')

        elif choice in ['exit', '7', 'e']:
            break

if __name__ == "__main__":
    main()