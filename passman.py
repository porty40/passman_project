# PORTY40 PROPERTY
import click
from click.exceptions import UsageError
from expiringdict import ExpiringDict
import os
import json
import base64
import re
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from argon2.exceptions import VerifyMismatchError
import clipboard
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ph = PasswordHasher(time_cost=1, memory_cost=512, parallelism=4)

enckexp = ExpiringDict(max_age_seconds=120, max_len=1)
enckexp["maspass"] = ""
ms = b'02d0086a7342f2b47db970833b55a39f'

session = {"logged_in": False, "username": ""}

log_req = ["pass-reset", "slot-add", "slot-edit", "slot-del", "slot-show", "slot-list"]

users_dir = "./users"
accounts = 'acc.json'

salt_len = 16
key_len = 32
blk_size = AES.block_size

inv_usr_name = "Invalid username format:\n\tUsername should contain from 2 to 10\n\talphanumerical characters without spaces."
inv_pass = "Invalid password format:\n\tPassword should contain a minimum of 8 characters,\n\tincluding at least one uppercase letter,\n\tone lowercase letter, one digit,\n\tand one special character (@#$!%*?&)."
inv_slot_name = "Invalid slot name format:\n\tSlot name should contain from 2 to 10\n\talphanumerical characters without spaces."


def is_valid_name(username: str) -> bool:
    rx = r'^([a-zA-Z\d]{2,10})$'
    return bool(re.fullmatch(rx, username.strip()))


def is_valid_password(password: str) -> bool:
    rx = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$!%*?&])[A-Za-z\d@#$!%*?&]{8,16}$'
    return bool(re.fullmatch(rx, password.strip()))


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),     # Password as bytes
        salt=salt,                      # Salt as bytes
        time_cost=2,                    # Time cost (number of iterations)
        memory_cost=102400,             # Memory cost (in KiB)
        parallelism=8,                  # Degree of parallelism (threads)
        hash_len=key_len,               # Desired length of the output key
        type=Type.I                     # Argon2 type: I for Argon2i, ID for hybrid, or D for Argon2d
    )


def encrypt_vault(vault_data: dict, master_password: str, vault_path: str) -> None:
    try:
        key = derive_key(master_password, ms)

        vault_json = json.dumps(vault_data).encode()

        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(vault_json, blk_size)
        encrypted_data = cipher.encrypt(padded_data)

        with open(vault_path, 'wb') as file:
            file.write(cipher.iv)
            file.write(encrypted_data)

    except Exception as e:
        click.echo(f"Error encrypting the vault: {e}")


def decrypt_vault(master_password: str, vault_path: str) -> dict:
    try:
        key = derive_key(master_password, ms)

        with open(vault_path, 'rb') as file:
            iv = file.read(16)
            encrypted_data = file.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), blk_size)

        return json.loads(decrypted_data.decode('utf-8'))

    except Exception as e:
        click.echo(f"Error decrypting the vault: {e}")
        return {}


def get_pass_in() -> None:
    password = str(input("Your password has timed out!\nType it in again to proceed: "))
    try:
        with open(accounts, 'r') as file:
            users = json.load(file)
        ph.verify(users[session["username"]], password)
        enckexp["maspass"] = password
    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


@click.group()
def cli() -> None:
    """A simple command line password manager."""
    pass


# password slot operations section
@cli.command()
@click.option('--slot-name', prompt='Enter the slot name', help='Create specified slot')
@click.option('--slot-content', prompt='Enter the content of the slot',
              help='Specify the content of the slot', hide_input=True)
#@click.option('--password', prompt='Enter the master password', hide_input=True)
def slot_add(slot_name: str, slot_content: str) -> None:
    """Creates a slot in the vault."""
    if not is_valid_name(slot_name):
        click.echo(inv_slot_name)
        return
    if not enckexp["maspass"]:
        get_pass_in()

    try:
        with open(accounts, 'r') as file:
            users = json.load(file)
        ph.verify(users[session["username"]], enckexp["maspass"])

        user_path = f'{users_dir}/{session["username"]}'
        if not os.path.exists(user_path):
            os.makedirs(user_path)

        vault_path = f'{user_path}/vault.json'
        slot_path = f'{user_path}/{slot_name}.bin'

        # Decrypt the vault before loading
        if os.path.exists(vault_path):
            slots = decrypt_vault(enckexp["maspass"], vault_path)
        else:
            slots = {}

        if slot_name in slots:
            click.echo(f"Slot '{slot_name}' already exists.")
            return

        # Create and encrypt the slot
        slot_salt = os.urandom(salt_len)
        enc_key = derive_key(enckexp["maspass"], slot_salt)

        cipher = AES.new(enc_key, AES.MODE_CBC)
        padded_data = pad(slot_content.encode(), blk_size)
        encrypted_data = cipher.encrypt(padded_data)

        with open(slot_path, 'wb') as file:
            file.write(cipher.iv)  # Write the IV to the file first
            file.write(encrypted_data)

        # Update vault with the new slot
        slots[slot_name] = base64.b64encode(slot_salt).decode('utf-8')

        # Encrypt the vault after updating
        encrypt_vault(slots, enckexp["maspass"], vault_path)

        click.echo(f"Slot '{slot_name}' created successfully.")

    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option('--slot-name', prompt='Enter the slot name', help='Specify the slot to edit')
@click.option('--new-content', prompt='Enter the new content of the slot', help='Specify the new content of the slot',
              hide_input=True)
#@click.option('--password', prompt='Enter the master password', hide_input=True)
def slot_edit(slot_name: str, new_content: str) -> None:
    """Edits the content of an existing slot in the vault, creating a new salt."""
    if not is_valid_name(slot_name):
        click.echo(inv_slot_name)
        return
    if not enckexp["maspass"]:
        get_pass_in()
    try:
        with open(accounts, 'r') as file:
            users = json.load(file)
        ph.verify(users[session["username"]], enckexp["maspass"])

        user_path = f'{users_dir}/{session["username"]}'
        vault_path = f'{user_path}/vault.json'

        if not os.path.exists(vault_path):
            click.echo("Vault file not found.")
            return

        if os.path.exists(vault_path):
            slots = decrypt_vault(enckexp["maspass"], vault_path)
        else:
            slots = {}

        if slot_name not in slots:
            click.echo(f"Slot '{slot_name}' does not exist.")
            return

        new_salt = os.urandom(salt_len)
        enc_key = derive_key(enckexp["maspass"], new_salt)

        cipher = AES.new(enc_key, AES.MODE_CBC)

        # Encrypt new content with new key
        padded_data = pad(new_content.encode(), blk_size)
        encrypted_data = cipher.encrypt(padded_data)

        # Write new encrypted slot content
        slot_path = f'{user_path}/{slot_name}.bin'
        with open(slot_path, 'wb') as file:
            file.write(cipher.iv)
            file.write(encrypted_data)

        # Update the vault file
        slots[slot_name] = base64.b64encode(new_salt).decode('utf-8')

        encrypt_vault(slots, enckexp["maspass"], vault_path)

        click.echo(f"Slot '{slot_name}' content updated successfully.")

    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option('--slot-name', prompt='Enter the slot name', help='Create specified slot')
#@click.option('--password', prompt='Enter the master password', hide_input=True, confirmation_prompt=True)
def slot_del(slot_name: str) -> None:
    """Deletes a slot in the vault."""
    if not is_valid_name(slot_name):
        click.echo(inv_slot_name)
        return
    if not enckexp["maspass"]:
        get_pass_in()
    try:
        with open(accounts, 'r') as file:
            users = json.load(file)
        ph.verify(users[session["username"]], enckexp["maspass"])

        user_path = f'{users_dir}/{session["username"]}'
        vault_path = f'{user_path}/vault.json'

        if os.path.exists(vault_path):
            slots = decrypt_vault(enckexp["maspass"], vault_path)
        else:
            slots = {}

        if slot_name not in slots:
            click.echo(f"Slot '{slot_name}' does not exist.")
            return

        slot_path = f'{user_path}/{slot_name}.bin'

        if os.path.exists(f"{slot_path}"):
            os.remove(f"{slot_path}")
        slots.pop(slot_name)

        encrypt_vault(slots, enckexp["maspass"], vault_path)

        click.echo(f"Slot '{slot_name}' deleted successfully.")

    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option('--slot-name', prompt='Enter the slot name', help='Access specified slot')
#@click.option('--password', prompt='Enter the master password', hide_input=True)
@click.option('--no-clip', is_flag=True, help='Copy the revealed slot to the clipboard')
def slot_show(slot_name: str, no_clip: bool) -> None:
    """Reveals specified slot or copies it to the clipboard."""
    if not is_valid_name(slot_name):
        click.echo(inv_slot_name)
        return
    if not enckexp["maspass"]:
        get_pass_in()
    try:
        with open(accounts, 'r') as file:
            users = json.load(file)
        ph.verify(users[session["username"]], enckexp["maspass"])

        user_path = f'{users_dir}/{session["username"]}'
        vault_path = f'{user_path}/vault.json'

        if os.path.exists(vault_path):
            slots = decrypt_vault(enckexp["maspass"], vault_path)
        else:
            slots = {}

        if slot_name not in slots:
            click.echo(f"Slot '{slot_name}' does not exist.")
            return

        slot_path = f'{user_path}/{slot_name}.bin'

        with open(slot_path, 'rb') as file:
            iv = file.read(16)
            encrypted_data = file.read()

        slot_salt = base64.b64decode(slots[slot_name])
        dec_key = derive_key(enckexp["maspass"], slot_salt)

        cipher = AES.new(dec_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), blk_size)
        slot_content = decrypted_data.decode()

        if no_clip:
            click.echo(f"Slot '{slot_name}' content: {slot_content}")
        else:
            clipboard.copy(slot_content)
            click.echo(f"Slot '{slot_name}' has been copied to the clipboard.")

    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


@cli.command()
#@click.option('--password', prompt='Enter the master password', hide_input=True)
def slot_list() -> None:
    """Lists all the slots of the vault."""
    if not enckexp["maspass"]:
        get_pass_in()
    try:
        with open(accounts, 'r') as file:
            users = json.load(file)
        ph.verify(users[session["username"]], enckexp["maspass"])

        user_path = f'{users_dir}/{session["username"]}'
        vault_path = f'{user_path}/vault.json'

        if os.path.exists(vault_path):
            slots = decrypt_vault(enckexp["maspass"], vault_path)
        else:
            slots = {}

        click.echo(f"{session['username']} VAULT:")
        if not slots:
            click.echo(f"  < Empty >")
            return
        for slot in slots:
            click.echo(f"  ->  {slot}")

    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


# user/ master password operations section
@cli.command()
@click.option('--username', prompt='Enter the username')
@click.option('--password', prompt='Enter the master password', hide_input=True, confirmation_prompt=True)
def user_set(username: str, password: str) -> None:
    """Sets up a user account (username: master password)."""
    if session["logged_in"]:
        click.echo("Log out to create new user account.")
        return
    if not is_valid_name(username):
        click.echo(inv_usr_name)
        return
    if not is_valid_password(password):
        click.echo(inv_pass)
        return
    try:
        if os.path.exists(accounts):
            with open(accounts, 'r') as file:
                users = json.load(file)
            if username in users:
                click.echo(f"User '{username}' already exists.")
                return
        else:
            users = {}

        users[username] = ph.hash(password)

        with open(accounts, 'w') as file:
            json.dump(users, file, indent=4)

        user_path = f'{users_dir}/{username}'
        os.makedirs(user_path)

        vault = {}
        vault_path = f'{user_path}/vault.json'

        cipher = AES.new(derive_key(password, ms), AES.MODE_CBC)
        padded_data = pad(json.dumps(vault).encode(), blk_size)
        encrypted_data = cipher.encrypt(padded_data)

        with open(vault_path, 'wb') as file:
            file.write(cipher.iv)
            file.write(encrypted_data)

        click.echo(f"User '{username}' has been added successfully.")
    except (IOError, json.JSONDecodeError) as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option('--username', prompt='Enter the username')
@click.option('--password', prompt='Enter the master password', hide_input=True, confirmation_prompt=True)
def user_del(username: str, password: str) -> None:
    """Deletes all user records."""
    try:
        if not os.path.exists(accounts):
            click.echo(f"'{accounts}' file is missing")
            return

        with open(accounts, 'r') as file:
            users = json.load(file)

        if username not in users:
            click.echo(f"User '{username}' does not exist.")
            return

        if ph.verify(users[username], password):
            user_path = f'{users_dir}/{username}'
            vault_path = f'{user_path}/vault.json'

            with open(vault_path, 'r') as file:
                slots = json.load(file)
            for slot in slots:
                slot_path = f"{user_path}/{slot}.bin"
                os.remove(slot_path)
            os.remove(vault_path)
            os.rmdir(user_path)
        else:
            click.echo("Old password does not match.")
            return
        session["logged_in"] = False
        session["username"] = ""
        click.echo(f"'{username}' records deleted successfully.")
    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


@cli.command()
@click.option('--old-password', prompt='Enter the old master password', hide_input=True)
@click.option('--new-password', prompt='Enter the new master password', hide_input=True, confirmation_prompt=True)
def pass_reset(old_password: str, new_password: str) -> None:
    """Resets the master password for the current user."""
    username = session["username"]
    try:
        if not os.path.exists(accounts):
            click.echo(f"'{accounts}' file is missing")
            return

        with open(accounts, 'r') as file:
            users = json.load(file)

        if username not in users:
            click.echo(f"User '{username}' does not exist. Potential integrity loss: {accounts}")
            return

        if ph.verify(users[username], old_password):
            users[username] = ph.hash(new_password)
        else:
            click.echo("Old password does not match.")
            return

        with open(accounts, 'w') as file:
            json.dump(users, file, indent=4)

        user_path = f'{users_dir}/{username}'
        vault_path = f'{user_path}/vault.json'

        if not os.path.exists(vault_path):
            click.echo(f"Vault file is missing for user '{username}'")
            return

        # Load and decrypt existing slots with the old password
        if os.path.exists(vault_path):
            slots = decrypt_vault(enckexp["maspass"], vault_path)
        else:
            slots = {}

        decrypted_slots = {}
        for slot_name, encoded_salt in slots.items():
            slot_path = f'{user_path}/{slot_name}.bin'

            # Decrypt slot content using old password
            with open(slot_path, 'rb') as slot_file:
                iv = slot_file.read(16)
                encrypted_data = slot_file.read()

            old_salt = base64.b64decode(encoded_salt)
            old_key = derive_key(old_password, old_salt)

            cipher = AES.new(old_key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), blk_size)
            decrypted_slots[slot_name] = decrypted_data.decode()

            # Re-encrypt all the slots with the new password
        for slot_name, slot_content in decrypted_slots.items():
            new_salt = os.urandom(salt_len)  # Generate new salt for the new password
            new_key = derive_key(new_password, new_salt)

            cipher = AES.new(new_key, AES.MODE_CBC)
            padded_data = pad(slot_content.encode(), blk_size)
            encrypted_data = cipher.encrypt(padded_data)

            # Save new encrypted slot data
            slot_path = f'{user_path}/{slot_name}.bin'
            with open(slot_path, 'wb') as slot_file:
                slot_file.write(cipher.iv)
                slot_file.write(encrypted_data)

            slots[slot_name] = base64.b64encode(new_salt).decode('utf-8')

        encrypt_vault(slots, enckexp["maspass"], vault_path)

        click.echo(f"Master password for '{username}' has been changed successfully.")
    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


# assistive functions (login/logout/session_terminal)
@cli.command()
@click.option('--username', prompt='Enter the username')
@click.option('--password', prompt='Enter your password', hide_input=True)
def login(username: str, password: str) -> None:
    """Login"""
    try:
        if not os.path.exists(accounts):
            click.echo("No users available. Please create a user first.")
            return

        with open(accounts, 'r') as file:
            users = json.load(file)

        if username not in users:
            click.echo(f"User '{username}' does not exist.")
            return

        ph.verify(users[username], password)
        session["logged_in"] = True
        session["username"] = username
        enckexp["maspass"] = password
        click.echo(f"User '{username}' logged in successfully.")
    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")


@cli.command()
def logout() -> None:
    """Logout"""
    session["logged_in"] = False
    #click.echo(f"User '{session['username']}' logged out successfully.")
    session["username"] = ""


def terminal():
    """Starts the session."""
    click.echo("Type 'exit' to quit.")
    try:
        while True:
            cmd = input(f"[{session['username']}]~# ")
            if cmd == "exit":
                if session["logged_in"]:
                    logout()
                break
            if cmd in log_req and session['username'] == "":
                click.echo(f"Login required for '{cmd}' execution.")
            else:
                try:
                    cli.main(args=cmd.split(), prog_name="passman", standalone_mode=False)
                except UsageError as e:
                    click.echo(f"Error: {e}. Please enter a valid command.")
                except SystemExit:
                    pass
                except click.exceptions.Abort:
                    click.echo("Process interrupted by the user.")
    except KeyboardInterrupt:
        # Handle Ctrl+C to logout
        click.echo("\nSession interrupted. Clearing session and exiting......")
        session["logged_in"] = False
        session["username"] = ""


if __name__ == '__main__':
    terminal()
