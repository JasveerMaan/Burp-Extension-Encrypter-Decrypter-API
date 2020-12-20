# Burp-Extension-Encrypter-Decrypter(API)

During web application pentest, the application sends and receives PGP encrypted data. Since the clients has API to encrypt and decrypt the data, I have created Burp Extension that allows me to use Burp Repeater to send cleartext data to the server and view the response in cleartext (The cleartext body will encrypted when sent to the server. Cleartext will be only shown in Repeater). The response from the server will be decrypted.
