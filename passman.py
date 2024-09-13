# PORTY40 PROPERTY
import click
from click.exceptions import UsageError
import os
import json
import base64
import re
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
#import pyperclip
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

ph = PasswordHasher(time_cost=1, memory_cost=512, parallelism=4)

session = {"logged_in": False, "username": ""}

users_dir = "./users"
accounts = 'acc.json'
user_path = f'{users_dir}/{session["username"]}'

salt_len = 16
key_len = 32
iter = 100000
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

'''
def sanitize(input: str) -> str:
    allowed = r'[^a-zA-Z0-9@#$!%*?&]'
    sanitized = input.strip()
    sanitized = re.sub(allowed, '', sanitized)
    return sanitized
'''

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iter,
        key_len
    )

def require_login(func):
    """Decorator to ensure the user is logged in before executing the command."""
    @click.pass_context
    def wrapper(ctx, *args, **kwargs):
        if not session.get("logged_in"):
            click.echo("No user is currently logged in. Please log in first.")
            ctx.exit()  # Exit the command, preventing further execution or prompts
        return func(*args, **kwargs)

    #wrapper.__name__ = func.__name__
    #wrapper.__doc__ = func.__doc__
    #wrapper.__module__ = func.__module__

    return wrapper

@click.group()
def cli() -> None:
    """A simple command line password manager."""
    pass

#password slot operations section
@cli.command()
@require_login
@click.option('--slot-name', prompt='Enter the slot name: ', help='Create specified slot')
@click.option('--slot-content', prompt='Enter the content of the slot: ', help='Specify the content of the slot', hide_input=True)
@click.option('--password', prompt='Enter the master password: ', hide_input=True)
def add_slot(slot_name: str, slot_content: str, password: str) -> None:
    """Creates a slot in the vault."""
    if not is_valid_name(slot_name):
        click.echo(inv_slot_name)
        return
    try:
        with open(accounts, 'r') as file:
            users = json.load(file)
        ph.verify(users[session["username"]], password)

        if not os.path.exists(user_path):
            os.makedirs(user_path)

        vault_path = f'{user_path}/vault.json'
        slot_path = f'{user_path}/{slot_name}.bin'

        slot_salt = os.urandom(salt_len)
        enc_key = derive_key(password, slot_salt)

        cipher = AES.new(enc_key, AES.MODE_CBC)
        padded_data = pad(slot_content.encode(), blk_size)
        encrypted_data = cipher.encrypt(padded_data)

        with open(slot_path, 'wb') as file:
            file.write(cipher.iv)  # Write the IV to the file first
            file.write(encrypted_data)

        slots = {}
        if os.path.exists(vault_path):
            with open(vault_path, 'r') as file:
                slots = json.load(file)
        slots[slot_name] = base64.b64encode(slot_salt).decode('utf-8')

        with open(vault_path, 'w') as file:
            json.dump(slots, file, indent=4)

        click.echo(f"Slot '{slot_name}' created successfully.")

    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")

@cli.command()
@require_login
@click.option('--slot-name', prompt='Enter the slot name: ', help='Create specified slot')
@click.option('--password', prompt='Enter the master password: ', hide_input=True, confirmation_prompt=True)
def del_slot(slot_name: str, password: str) -> None:
    """Creates a slot in the vault."""
    pass

@cli.command()
@require_login
@click.option('--slot-name', prompt='Enter the slot name: ', help='Access specified slot')
@click.option('--password', prompt='Enter the master password: ', hide_input=True)
@click.option('--clip', help='Copy the revealed slot to the clipboard')
def show_slot(slot: str, password: str) -> None:
    """Reveals specified slot or copies it to the clipboard."""
    pass

@cli.command()
@require_login
@click.option('--password', prompt='Enter the master password: ', hide_input=True)
def list_slots(password: str) -> None:
    """Lists all the slots of the vault."""
    pass

#user/ master password operations section
@cli.command()
@click.argument('username')
@click.option('--password', prompt='Enter the master password: ', hide_input=True, confirmation_prompt=True)
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

        click.echo(f"User '{username}' has been added successfully.")
    except (IOError, json.JSONDecodeError) as e:
        click.echo(f"Error: {e}")

@cli.command()
@require_login
@click.option('--old-password', prompt='Enter the old master password: ', hide_input=True)
@click.option('--new-password', prompt='Enter the new master password: ', hide_input=True, confirmation_prompt=True)
def pass_reset(old_password: str, new_password: str) -> None:
    """Resets the master password for the current user."""
    accounts = 'acc.json'
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

        click.echo(f"Master password for '{username}' has been changed successfully.")
    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")

#assistive functions (login/logout/session_terminal)
@cli.command()
@click.argument('username')
@click.option('--password', prompt='Enter your password: ', hide_input=True)
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
        click.echo(f"User '{username}' logged in successfully.")
    except (IOError, json.JSONDecodeError, VerifyMismatchError) as e:
        click.echo(f"Error: {e}")

@cli.command()
@require_login
def logout() -> None:
    """Logout"""
    session["logged_in"] = False
    click.echo(f"User '{session['username']}' logged out successfully.")
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
            else:
                try:
                    cli.main(args=cmd.split(), prog_name="passman", standalone_mode=False)
                except UsageError as e:
                    click.echo(f"Error: {e}. Please enter a valid command.")
                except SystemExit:
                    pass
    except KeyboardInterrupt:
        # Handle Ctrl+C to logout
        click.echo("\nSession interrupted. Clearing session and exiting......")
        session["logged_in"] = False
        session["username"] = ""

if __name__ == '__main__':
    terminal()