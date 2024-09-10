# PORTY40 PROPERTY
import click
import os
import json
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
#import pyperclip
#from Crypto.Cipher import AES

ph = PasswordHasher(time_cost=1, memory_cost=512, parallelism=4)

@click.group()
def cli() -> None:
    """A simple command line password manager."""

#password slot operations section
@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.option('--list-all', help='List all password slots')
def list_slots(password: str) -> None:
    pass

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.option('--slot', prompt='Enter the password slot name: ', help='Access specified password slot')
@click.option('--clip', help='Copy the revealed slot to the clipboard')
def reveal_slot(slot: str, password: str) -> None:
    pass

#user/ master password operations section
@cli.command()
@click.argument('username')
@click.option('--password', prompt='Enter the password: ', hide_input=True, confirmation_prompt=True)
def user_set(username: str, password: str) -> None:
    accounts = 'acc.json'
    if os.path.exists(accounts):
        with open(accounts, 'r') as file:
            users = json.load(file)
        if username in users:
            click.echo(f"User '{username}' already exists.")
            return
    else:
        users = {}
    password_hash = ph.hash(password)
    users[username] = password_hash

    with open(accounts, 'w') as file:
        json.dump(users, file, indent=4)

    click.echo(f"User '{username}' has been added successfully.")


@cli.command()
@click.argument('username')
@click.option('--old-password', prompt='Enter the old password: ', hide_input=True)
@click.option('--new-password', prompt='Enter the new password: ', hide_input=True, confirmation_prompt=True)
def mp_reset(username: str, old_password: str, new_password: str) -> None:
    pass

#assistive functions
def master_pass_valid(m_password: str) -> bool:
    pass

def input_valid(input: str) -> bool:
    pass

def user_exists(username: str) -> bool:
    pass

if __name__ == '__main__':
    cli()