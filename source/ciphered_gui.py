import logging
import os
import base64
from basic_gui import BasicGUI # on importe la classe BasicGUI

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import dearpygui.dearpygui as dpg

from chat_client import ChatClient
from generic_callback import GenericCallback

# default values used to populate connection window
DEFAULT_VALUES = {
    "host" : "127.0.0.1",
    "port" : "6666",
    "name" : "client"
}

class CipheredGUI(BasicGUI): # héritage de BasicGUI
    """
    GUI for a chat client. Secured using AES-128
    """
    
    def __init__(self):
        super().__init__() # on appelle le constructeur de la classe BasicGUI
        self._key = None
        self._salt = b'' # salt utilisé pour généré la clef de chiffrement, on la définie en tant que bytes

    def _create_connection_window(self):
        # connection window  with password
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            all_fields = ["host", "port", "name", "password"] # tous nos champs du formulaire pour la connexion
            for field in all_fields:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    if field == "password":
                        dpg.add_input_text(password=True, tag="password") # ajout du champ password
                    else:
                        dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")

            dpg.add_button(label="Connect", callback=self.run_chat)

    def run_chat(self, sender, app_data):
        # callback used by the connection windows to start a chat session
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("password") # on récupère le contenu du champ password
        self._log.info(f"Connecting {name}@{host}:{port}")

        # on utilise PBKDF2HMAC pour faire la dérivation grâce à la documentation sur internet "https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC"
        kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16, # on utilise 16 bytes soit 128 bits
        salt=self._salt,
        iterations=480000,
        )

        # on génère la clef de chiffrement encodé en UTF-8
        self._key = kdf.derive(password.encode("utf-8"))

        self._callback = GenericCallback()

        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

        super().run_chat(sender, app_data)

    def encrypt(self, message_to_encrypt: str) -> tuple:
        """
        Function "encrypt"used to encrypt a message
        Take a message and return an encrypted message in tuple
        """
        iv = os.urandom(16) # on définit un IV aléatoire de 16 bytes
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv)) # on crée un cipher pour configurer le chiffrement du message avec de l'AES
        encryption = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder() # on utilise le schéma de remplissage PKCS7 pour que les données soient remplies jusqu'à la taille du bloc
        data_padder = padder.update(message_to_encrypt.encode("utf-8")) + padder.finalize() # on ajoute le message
        data_encrypted = encryption.update(data_padder) + encryption.finalize() # on effectue le chiffrement
        iv64 = base64.b64encode(iv).decode("utf-8") # on encode l'IV en base 64
        data_encrypted64 = base64.b64encode(data_encrypted).decode("utf-8") # on encode le message chiffre en base 64
        
        return (iv64, data_encrypted64)

    def decrypt(self, encrypted_message: tuple) -> str:
        """
        Function "decrypt" used to decrypt a message
        Take the encrypted message and return the decrypted message (string UTF-8)
        """
        iv64, data_encrypted64 = encrypted_message # on prend l'IV et le message chiffré
        iv_normal = base64.b64decode(iv64) # on déchiffre l'IV
        data_encrypted = base64.b64decode(data_encrypted64) # on déchiffre le message en commeçant par enlever l'encodage base64
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(iv_normal)) # le reste est similaire à la fonction encrypt sauf qu'on déchiffre maintenant
        decryption = cipher.decryptor()
        decrypted_data = decryption.update(data_encrypted) + decryption.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data_decrypted = (unpadder.update(decrypted_data) + unpadder.finalize()).decode("utf-8")

        return data_decrypted

    def send(self, text)->None:
        # function called to send a message
        iv64, data_encrypted64 = self.encrypt(text)
        message_encrypted = {"message": data_encrypted64, "iv": iv64}
        self._client.send_message(message_encrypted)
        
    def recv(self):
        # function called to get incoming messages
        if self._callback is not None:
            for user, data_encrypted in self._callback.get():
                    self._log.debug(f"Data received: {data_encrypted}")
                    if isinstance(data_encrypted, dict) and 'iv' in data_encrypted and 'message' in data_encrypted:
                        iv64 = data_encrypted['iv']
                        data_encrypted64 = data_encrypted['message']
                        encrypted_message = (iv64, data_encrypted64)
                    else:
                        self._log.error("ERROR INVALID DATA")
                        continue
                    message = self.decrypt(encrypted_message)
                    self.update_text_screen(f"{user} : {message}")
            self._callback.clear()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    client = CipheredGUI()
    client.create()
    client.loop()
