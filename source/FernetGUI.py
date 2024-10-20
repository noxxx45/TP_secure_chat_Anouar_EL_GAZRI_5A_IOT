import hashlib
import logging
import base64
from cryptography.fernet import Fernet
import dearpygui.dearpygui as dpg
from chat_client import ChatClient, GenericCallback
from ciphered_gui import CipheredGUI  # on importe la classe CipheredGUI

# default values used to populate connection window
DEFAULT_VALUES = {
    "host" : "127.0.0.1",
    "port" : "6666",
    "name" : "client"
}

class FernetGUI(CipheredGUI): # héritage de CipheredGUI
    def __init__(self):
        super().__init__()  # on appelle le constructeur de la classe CipheredGUI
        self._key = None
        self._fernet_key = None # fernet key
        self._salt = b''

    def _create_connection_window(self): # similaire aux classes précédentes
        # Create connection window with password input
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            fields = ["host", "port", "name", "password"]
            for field in fields:
                with dpg.group(horizontal=True):
                    dpg.add_text(field)
                    if field == "password":
                        dpg.add_input_text(password=True, tag="password")
                    else:
                        dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}")

            dpg.add_button(label="Connect", callback=self.run_chat)

    def run_chat(self, sender, app_data):
        # Connect to the chat with host, port, name, and password
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("password")

        self._log.info(f"Connecting {name}@{host}:{port}")

        # on génère la clef de chiffrement à partir du password avec SHA256
        self._key = hashlib.sha256(password.encode()).digest()
        self._fernet_key = base64.urlsafe_b64encode(self._key)  # on encode en base 64 pour la clef Fernet

        self._callback = GenericCallback()
        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    def encrypt(self, message_to_encrypt: str) -> str:
        """
        Function "encrypt" used to encrypt a message
        Take a message and return an encrypted message in String.
        """
        # chiffrement du message avec Fernet
        cipher = Fernet(self._fernet_key) # on utilise la clef Fernet pour configurer le chiffrement
        encrypted_message = (cipher.encrypt(message_to_encrypt.encode('utf-8'))).decode('utf-8') # on chiffre le message

        return encrypted_message # on retourne le message chiffré

    def decrypt(self, message_to_decrypt: str) -> str:
        """
        Function "decrypt" used to decrypt a message
        Take the encrypted message and return the decrypted message in String.
        """
        # déchiffrement du message avec Fernet
        cipher = Fernet(self._fernet_key)
        decrypted_message = (cipher.decrypt(message_to_decrypt.encode('utf-8'))).decode('utf-8')

        return decrypted_message # on retourne le message déchiffré

    def send(self, message_to_send: str) -> None:
        """
        Function called to send a message. Fernet includes the IV in the message.
        """
        encrypted_message = self.encrypt(message_to_send) # on chiffre le message
        message_encrypted = {"message": encrypted_message} # on le met dans un dictionnaire

        self._client.send_message(message_encrypted)  # on envoie le message

    def recv(self) -> None:
        """
        Receive and decrypt incoming messages.
        """
        if self._callback is not None:
            for user, data_encrypted in self._callback.get():
                self._log.debug(f"Data received: {data_encrypted}")
                # on véirifie que les données reçues sont le message chiffré sous forme de dictionnaire
                if isinstance(data_encrypted, dict) and 'message' in data_encrypted:
                    encrypted_message = data_encrypted['message']
                    decrypted_message = self.decrypt(encrypted_message) # on déchiffre le message
                    self.update_text_screen(f"{user}: {decrypted_message}")
                else:
                    self._log.error("ERROR INVALID DATA")
                    continue
            
            self._callback.clear()
    
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    client = FernetGUI()
    client.create()
    client.loop()