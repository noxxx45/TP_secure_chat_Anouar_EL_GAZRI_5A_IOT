import hashlib
import logging
import base64
from cryptography.fernet import Fernet, InvalidToken
import dearpygui.dearpygui as dpg
from chat_client import ChatClient, GenericCallback
from FernetGUI import FernetGUI  # on importe la classe FernetGUI
import time

# default values used to populate connection window
DEFAULT_VALUES = {
    "host" : "127.0.0.1",
    "port" : "6666",
    "name" : "client"
}


class TimeFernetGUI(FernetGUI):
    def __init__(self):
        super().__init__()  # on appelle le constructeur de la classe FernetGUI
        self.TTL = 30  # TTL 30 secondes

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
        actual_time = int(time.time())  # temps actuel
        logging.debug(f"Encryption current time: {actual_time}")
        try:
            fernet = Fernet(self._fernet_key)
            # chiffrement avec l'horodatage
            encrypted_message = (fernet.encrypt_at_time(message_to_encrypt.encode('utf-8'), actual_time)).decode('utf-8')
            return encrypted_message
        except Exception as e:
            logging.error(f"ERROR ENCRYPTION: {e}")
            return None
    
    def decrypt(self, message_to_decrypt: str) -> str:
        """
        Function to decrypt a message using TTL of 30 seconds.
        """
        actual_time = int(time.time()) # temps actuel
        logging.debug(f"Decryption current time: {actual_time}")
        try:
            fernet = Fernet(self._fernet_key)
            # déchiffrement avec le TTL
            decrypted_message = fernet.decrypt_at_time(
                message_to_decrypt.encode('utf-8'),
                ttl=self.TTL, # durée de vie du message
                current_time=actual_time # on fait la comparaison avec le temps actuel
            ).decode('utf-8')

            return decrypted_message

        except InvalidToken as e:
            # gestion d'erreurs
            logging.error(f"ERROR DECRYPTION: {e}")
            return "<invalid token>"


    def send(self, message_to_send: str) -> None:
        """
        Function called to send a message. Fernet includes the IV in the message.
        """
        encrypted_message = self.encrypt(message_to_send)  # on chiffre le message
        if encrypted_message:  # on vérifie que le message a bien été chiffré
            message_encrypted = {"message": encrypted_message}  # on le met dans un dictionnaire
            self._client.send_message(message_encrypted)  # on envoie le message
        else:
            logging.error("ERROR MESSAGE SENDING!")
    
    
    def recv(self) -> None:
        if self._callback is not None:
            for user, data_encrypted in self._callback.get():
                self._log.debug(f"Data received: {data_encrypted}")
                #time.sleep(10) # pour tester d'abord sans le TTL de 30 secondes
                time.sleep(35) # pour tester avec le TTL de 30 secondes, cad si le client 2 mets 35 avant de lire le message, cela dépasse 30 secondes donc ça doit afficher "MESSAGE EXPIRED!"
                # partie similaire aux autres classes
                if isinstance(data_encrypted, dict) and 'message' in data_encrypted:
                    encrypted_message = data_encrypted['message']
                    decrypted_message = self.decrypt(encrypted_message) # déchiffrement du message

                    if decrypted_message == "<invalid token>":  # si le token est invalide
                        self.update_text_screen(f"{user}: MESSAGE EXPIRED!")
                    else:
                        self.update_text_screen(f"{user}: {decrypted_message}")
                else:
                    self._log.error("ERROR INVALID DATA")
                    continue

            self._callback.clear()

    
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    client = TimeFernetGUI()
    client.create()
    client.loop()