# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Connects to the first FIDO device found which supports the HmacSecret extension,
creates a new credential for it with the extension enabled, and uses it to
derive two separate secrets.
"""
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction
from getpass import getpass
import libs.word_gen as word_gen
import libs.cred_manager as cred_manager
import hashlib
import sys
import os

# Utilities

def sha256(data):
    enc = hashlib.sha256()
    enc.update(data.encode())
    return enc.digest()

# FIDO2

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev

# Handle user interaction
class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch your authenticator device now...\n")

    def request_pin(self, permissions, rd_id):
        return getpass("Enter PIN: ")

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True

    def locate_device():
        # Locate a device
        for dev in enumerate_devices():
            client = Fido2Client(dev, "https://localhost", user_interaction=CliInteraction())
            if "hmac-secret" in client.info.extensions:
                break
        else:
            print("No Authenticator with the HmacSecret extension found!")
            sys.exit(1)
        return client

# Main
if __name__ == "__main__":
    # Prepare parameters for makeCredential and getAssertion
    rp = {"id": "localhost", "name": "HMyWallet"}
    user = {"id": b"1", "name": "HMyWalletUser"}

    # Locate a device
    client = CliInteraction.locate_device()

    # Loading or creating a new credential
    credential = cred_manager.load_credential()
    if not credential:
        credential = cred_manager.create_credential(client, rp, user)

    # Prepare parameters for getAssertion
    challenge = os.urandom(16)  # Use a new challenge for each call.
    allow_list = [{"type": "public-key", "id": credential.credential_id}]

    # Ask user for password
    password = getpass("[+] Enter your password: ")
    # Generate a salt for HmacSecret:
    password_hash = sha256(password) #os.urandom(32)
    print("[OK] Password hashed and ready for authentication")

    # Authenticate the credential
    result = client.get_assertion(
        {
            "rpId": rp["id"],
            "challenge": challenge,
            "allowCredentials": allow_list,
            "extensions": {"hmacGetSecret": {"salt1": password_hash}},
        },
    ).get_response(
        0
    )  # Only one cred in allowList, only one response.

    secret = result.extension_results["hmacGetSecret"]["output1"]
    print("[OK] Authenticated and secret retrieved")

    mnemonic_words = word_gen.gen_from_data(secret)
    mnemonic_string = " ".join(mnemonic_words)
    print("\nALERT: This is your mnemonic seed. Keep it in a safe place. You will need it to recover your wallet.")
    print("If you lose it, you will lose access to your wallet. There is no way to recover it later.")
    print("Anyone with access to your mnemonic seed can recover your wallet. Keep it in a secure location.")
    print("For security reasons, it is adviced to not save it in plain text: you can use your password and this script to recover it.")
    print("\nMnemonic words:\n", mnemonic_string)