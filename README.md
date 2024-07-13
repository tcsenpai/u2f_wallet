# HMyWallet

## Description
This is a small proof of concept yet functional and working utility to safely manage a 24 words mnemonic seed using a FIDO2 authenticator and a password.

You can use it to reliably manage your mnemonic seed and to recover it later without having to remember it or to write it down.

## Usage
The script will create a set of credentials from your FIDO2 authenticator during the first run. This set of credentials only works with your FIDO2 authenticator and must be in the data/credential.pkl file. If you lose your FIDO2 authenticator or your credential file, you will not be able to recover your mnemonic seed.

The script will then ask you to enter your password to authenticate your FIDO2 authenticator.
As the password is not stored anywhere, it cannot be compromised by anyone with access to your computer.
For the same reason, you will lose access to your mnemonic seed if you lose your password.

Using the provided password, the script will then generate a 24 words mnemonic seed and print it to the console.

You can then use this mnemonic seed to access or recover your wallet anywhere.

# How it works
The password is hashed using SHA256, and is used as a seed to generate a hmac_secret from the provided credential.pkl file.
This hmac_secret is then used to generate a 24 words mnemonic seed using a wordlist.txt file.
This way, both the password and the hmac_secret are only kept in memory until the mnemonic seed is generated, and are not stored anywhere.

# Credits
This script is based on the fido2 library by Yubico.

## Disclaimer
This script is provided as is and should be used with caution. It is not tested for usage in managing mnemonic seeds in a production environment.