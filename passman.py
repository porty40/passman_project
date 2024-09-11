# PORTY40 PROPERTY
import click
from click.exceptions import UsageError
import os
import json
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
#import pyperclip
#from Crypto.Cipher import AES

ph = PasswordHasher(time_cost=1, memory_cost=512, parallelism=4)

session = {"logged_in": False, "username": None}

@click.group()
def cli() -> None:
    """A simple command line password manager."""

#password slot operations section
@cli.command()
@click.option('--slot-name', prompt='Enter the slot name: ', help='Create specified slot')
@click.option('--slot-content', prompt='Enter the content of the slot: ', help='Specify the content of the slot', hide_input=True)
@click.option('--password', prompt='Enter the master password: ', hide_input=True)
def add_slot(slot_name: str, slot_content: str, password: str) -> None:
    """Creates a slot in the vault."""
    pass

@cli.command()
@click.option('--slot-name', prompt='Enter the slot name: ', help='Create specified slot')
@click.option('--password', prompt='Enter the master password: ', hide_input=True, confirmation_prompt=True)
def delete_slot(slot_name: str, password: str) -> None:
    """Creates a slot in the vault."""
    pass

@cli.command()
@click.option('--slot-name', prompt='Enter the slot name: ', help='Access specified slot')
@click.option('--password', prompt='Enter the master password: ', hide_input=True)
@click.option('--clip', help='Copy the revealed slot to the clipboard')
def reveal_slot(slot: str, password: str) -> None:
    """Reveals specified slot or copies it to the clipboard."""
    pass

@cli.command()
@click.option('--password', prompt='Enter the master password: ', hide_input=True)
def list_slots(password: str) -> None:
    """Lists all the slots of the vault."""
    pass

#user/ master password operations section
@cli.command()
@click.argument('username') #SHOULD LOG OUT TO CREATE A USER?
@click.option('--password', prompt='Enter the master password: ', hide_input=True, confirmation_prompt=True)
def user_set(username: str, password: str) -> None:
    """Sets up a user account (username: master password)."""
    accounts = 'acc.json'
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

        click.echo(f"User '{username}' has been added successfully.")
    except (IOError, json.JSONDecodeError) as e:
        click.echo(f"Error: {e}")

@cli.command()
@click.option('--old-password', prompt='Enter the old master password: ', hide_input=True)
@click.option('--new-password', prompt='Enter the new master password: ', hide_input=True, confirmation_prompt=True)
def mp_reset(old_password: str, new_password: str) -> None:
    """Resets the master password for the current user."""
    accounts = 'acc.json'
    if not session["logged_in"]:
        click.echo("You must log in first.")
        return
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

#assistive functions
def input_valid(input: str) -> bool:
    pass

def logout() -> None:
    """Logout"""
    if not session["logged_in"]:
        click.echo("No user is currently logged in.")
        return

    session["logged_in"] = False
    click.echo(f"User '{session['username']}' logged out successfully.")
    session["username"] = None

def session():
    """Starts the session."""
    try:
        while True:
            cmd = input("('exit' to quit)~# ")
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
        session["username"] = None
        
@cli.command()
@click.argument('username')
@click.option('--password', prompt='Enter your password: ', hide_input=True)
def login(username: str, password: str) -> None:
    """Login"""
    accounts = 'acc.json'
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

if __name__ == '__main__':
    session()