EL GAZRI Anouar 5A IoT

Prise en main :

1) Cette topology s'appelle "Client-Serveur". On a deux clients "basic_gui" avec un seul serveur central "chat_server". Les deux clients communiquent à travers le serveur.

2) Dans les logs du terminal "chat_serveur", on a les informations concernant les messages échangés entre les 2 clients. 
On retrouve cela:
DEBUG:ChatServer:User list : ['client1', 'Client2']
INFO:ChatServer:client1 send message : bonjour
INFO:ChatServer:message send to Client2
INFO:ChatServer:Client2 send message : rebonjour
INFO:ChatServer:message send to client1

On a le message envoyé du client 1 et le message envoyé du client 2 qui sont affichés.
Les messages passent donc tous par le serveur et sont visibles côté serveur.

3) Le serveur a accès à tout, il voit tous les messages échangés etre les 2 clients, il voit le contenu de chaque message de la discussion.
Les messages échangés ne sont pas chiffrés. Donc n'importe qui ayant accès au serveur peut voir les données des messages qui transitent entre les clients.

4) Le moyen serait de chiffrer le contenu des messages afin que le serveur ne puisse pas avoir accès en notamment par exemple utilisant un chiffrement symétrique comme l'AES.


Chiffrement :

1) Oui on peut l'utiliser et c'est préférable d'utiliser urandom car il nous permet de générer une chaîne d'octets aléatoire qui est adaptée à une utilisation cryptographique (documentation: https://manpages.ubuntu.com/manpages/trusty/fr/man4/random.4.html).

2) Généralement, l'utilisation des primitives cryptographiques peut être dangereux si elles sont mal utilisées. Par exemple, si elles sont mal gérés au niveau des clefs, des IV alors un attaquant peut essayer de trouver une faille et de contourner le chiffrement.

3) Du côté réseau, le serveur malveillant peut analyser le trafic (messages...) à l'aide d'outils réseaux comme Wireshark, captés des trames et en déduire des informations qui lui seront utiles pour essayer de contourner le chiffrement des données.

4) Il manque une authentification car pour l'instant même si les messages sont chiffrés, on ne peut pas prouver que le message provient d'une source fiable.


Authenticated Symetric Encryption :

1) Fernet est moins risqué que ce qui a été utilisé dans la précédente section pour de nombreuses raisons. Premièrement, Fernet permet de générer l'IV (vecteur d'initialisation) automatiquement. On ne le génère plus manuellement, cela peut donc réduire le risque d'erreurs lors de la génération d'un IV de manière manuelle. Deuxièmement, Fernet contient une signature HMAC dans le chiffrement du message pour garantir l'authenticité de celui-ci. Le but principale de l'utilisation d'une signature HMAC est de garantir que le message provient bien d'une source fiable qui connaît la clé secrète et que le message n'a pas été modifié durant la période d'envoie.

2) Ce type d'attaque se nomme "Replay attack". C'est l'attaquant qui a réussi à intercepter le message et qui répète malicieusement le message falsifié au receveur.

3) Une méthode simple permettant de s'en affranchir serait d'utiliser un timestamp. À chaque envoie de message, le message est horodaté. Ainsi grâce à l'horodatage, le destinataire pourra vérifier si le message a été envoyée récemment ou non.



TTL (Time To Leave):

1) Comparé à ce qui a été effectué précédemment, ici la durée des messages chiffrés est limitée à 30 secondes. Si le message est déchiffré après 30 secondes (expiration du TTL), alors il est rejeté avec une erreur 'InvalidToken'.

2) Lorsqu'on soustrait 45 au temps lors de l'émission avec un TTL de 30 secondes, alors le message est immédiatement rejeté lors du chiffrement car il sera considéré comme expiré étant donné que le message sera considéré comme si il est a déjà été chiffré 45 secondes avant.

3) Oui cette solution est plutôt efficace car si l'attaquant intercèpte le message et essaye d'envoyer un ancien message alors il aura que 30 secondes pour le faire. Mais il reste encore des failles car si l'attaquant intercèpte le message dans les 30 secondes alors il pourra envoyer un message avant l'expiration du TTL.

4) En pratique, on peut avoir quelques soucis. Par exemple, les messages peuvent être rejetés trop tôt si le réseau est faible et possède une grande latence. On peut également avoir une nécessité d'avoir un TTL plus long que 30 secondes dans certaines applications. 


Regard critique:

Premièrement, l'utilisation des librairies tiers peut être une vulnérabilité. En effet, si par exemple un de ces librairies contient une faille qui n'a pas été mise à jour, l'attaquant pourra alors continuer à utiliser cette faille. Pour cela, il faut donc se documenter sur la version de la librairie et voir les possibles failles qui ont été mise à jour.

Deuxièmement, sur la partie code, en plus de l'ajout de la fonctionnalité TTL, on pourrait ajouter un id unique pour chaque message qui est envoyé pour rendre encore plus sécurisé le chat.

