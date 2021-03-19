from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.hid import CtapHidDevice
from fido2.pcsc import CtapPcscDevice
from fido2.ctap import CtapError, STATUS
from fido2.client import Fido2Client, WindowsClient
from fido2.server import Fido2Server
from fido2 import cbor

import base64
import click

RELYING_PARTY = "https://greenaddress.it"

def on_keepalive(status):
    if status == STATUS.UPNEEDED:  # Waiting for touch
        click.echo("Press the button on your u2f device")

def _get_hid_device():
    return next(CtapHidDevice.list_devices(), None)

def _get_pcsc_device():
    return next(CtapPcscDevice.list_devices(), None)

def _get_device():
    return _get_hid_device() or _get_pcsc_device()

def _get_client():
    return Fido2Client(_get_device(), RELYING_PARTY)

def register(auth_data):
    registration_data = cbor.decode(base64.b64decode(auth_data['registration_data']))
    client = _get_client()
    result = client.make_credential(registration_data['publicKey'], on_keepalive=on_keepalive)
    return base64.b64encode(cbor.encode(result)).decode('ascii')

def authenticate(request):
    request = cbor.decode(base64.b64decode(request['challenge']))
    client = _get_client()
    result = client.get_assertion(request, on_keepalive=on_keepalive)
    return base64.b64encode(cbor.encode(result.get_response(0))).decode('ascii')
