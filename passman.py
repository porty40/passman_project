# PORTY40 PROPERTY
import click
from argon2 import PasswordHasher
#import pyperclip
#from Crypto.Cipher import AES

@click.group()
def cli() -> None:
    try:
        with open("intro.txt", "r") as f:
            print(f.read())
    except FileNotFoundError:
        print("intro.txt file not found")

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

#master password operations section
@cli.command()
@click.option('--password', prompt='Enter the password: ', hide_input=True, confirmation_prompt=True)
def mp_set(password: str) -> None:
    pass

@cli.command()
@click.option('--old-password', prompt='Enter the old password: ', hide_input=True)
@click.option('--new-password', prompt='Enter the new password: ', hide_input=True, confirmation_prompt=True)
def mp_reset(old_password: str, new_password: str) -> None:
    pass

#assistive functions
def master_pass_valid(m_password: str) -> bool:
    pass

def input_valid(input: str) -> bool:
    pass

if __name__ == '__main__':
    cli()