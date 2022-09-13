from pyfiglet import figlet_format
import rsa

#printing the banner on the terminal
print('-'*80)
ascii_banner = figlet_format("TARUN", font="isometric1")
print(ascii_banner)
print('-'*34, 'USING RSA', '-'*35)
#End of the banner code.


#function for generating keys
def generatekeys():
    """Writing two files with the two different keys."""
    #getting the keys of size 1024bytes.
    publickey, privatekey = rsa.newkeys(1024)
    #writing a file for the publice key and will be saved as publickey.pem
    with open("publickey.pem", 'wb') as f:
        f.write(publickey.save_pkcs1('PEM'))
    #writing a file for the private key and will be saved as privatekey.pem
    with open("privatekey.pem", 'wb') as f:
        f.write(privatekey.save_pkcs1('PEM'))

#function for the loading the generated keys.
def loadkeys():
    """getting the key value from the files."""
    #opening to read the private key and intializing the value to privatekey variable.
    with open("privatekey.pem", 'rb') as f:
        privatekey = rsa.PrivateKey.load_pkcs1(f.read())
    #opening to read the public key and intializing the value to publickey variable.
    with open("publickey.pem", 'rb') as f:
        publickey = rsa.PublicKey.load_pkcs1(f.read())

    return publickey, privatekey


#function for the encrytion of the message.
def encrypt(message,key):
    """returns the encrypted message which is in ascii format."""
    return rsa.encrypt(message.encode('ascii'), key)


#fucntion for decryption.
def decrypt(encryptedtext, key):
    """returns the decryption of the message result."""
    try:
        return rsa.decrypt(encryptedtext,key).decode('ascii')
    #catching the error condition.
    except:
        return "You're UnAuthorised to this Activity."


#function for the purpose of signing the message.
def sign(message, key):
    """returns the value of the signed text."""
    return rsa.sign(message.encode('ascii'),key, 'SHA-256')


#fucntion for verifying the signature to the message.
def verify_sign(message, signature, key):
    """To verify the signed text."""
    try:
        return rsa.verify(message.encode('ascii'), signature, key) == 'SHA-256'
    except:
        return False
    

#main fucntion.
def main():
    """Main function. """
    print("> What would you like to do : ")
    print("---> 1. Encrypt/Decrypt of a text")
    print("---> 2. Sigining a Message")
    print('-'*80)

    #assinging the loadkeys to keys.
    keys = loadkeys()

    #getting the user option.
    option = int(input("--> Option: "))

    #message to encrypt/decrypt or sign and verify.
    message = input("--> Text message to Encrpyt and Decrypt: ")

    #if user.input selects for 1 it shows the encryption and decryption of the text.
    if option == 1:
        #assigning the encrypted text with keys.
        encryptedtext = encrypt(message, keys[0])
        print("[*] Succesfully Encrypted the Message. ")
        print('-'*80)
        print("\033[32m", encryptedtext , "\033[0m")
        print('-'*80)

        #prompting for whether to decrypt or not.
        dec = input("> Want to decrypt this message (y/n) ? ")
        #if user asks for yes.
        if dec == 'y':
            decrypt_result = decrypt(encryptedtext, keys[1])
            print("Decrypted Message --> \033[32m", decrypt_result , "\033[0m")
            print('-'*80)
    
    #And if the user selects for the second option.
    else:
        #assinging the signature value.
        signature = sign(message, keys[1])
        print("[*] Successfully SIGNED the message. ")
        #asking whether to verify or not.
        ver = input("> Would you like to VERIFY the integrity of the message (y/n) ? ")

        #if the user asks for verification.
        if ver == 'y':
            verify_result = verify_sign(message, signature, keys[0])
            #if it is true tells the message is not tampered.
            if verify_result:
                print('-'*80)
                print("\033[032m No Intrusion Occured to this file. \033[0m")
                print('-'*80)
            #tells that the message is tampered.
            else:
                print('-'*80)
                print("\033[31m Someone modified this file. \033[0m")
                print('-'*80)

#calling the main function.
main()

