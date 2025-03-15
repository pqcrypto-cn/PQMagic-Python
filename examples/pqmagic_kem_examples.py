# Input & output are all in bytes.
# A KEM object is created with a specific algorithm, its operations could use 
# either its attached key-pair, or the ones temprarily entered by the user.
from binascii import hexlify
from pqmagic import KEM

def example_kem(): # Example of Key Encapsulation Mechanism

    # taking ML_KEM_512 as an example
    kem = KEM("ML_KEM_512")

    # generate key pair (or update the object's attached key pair)
    pk, sk = kem.keypair()
    print("Public Key:", hexlify(pk))
    print("Secret Key:", hexlify(sk))

    # encapsulation
    ciphertext, shared_secret_enc = kem.encaps() # or kem.encaps(user_pk)
    print("Ciphertext:", hexlify(ciphertext))
    print("Shared Secret (Encapsulation):", hexlify(shared_secret_enc))

    # decapsulation
    shared_secret_dec = kem.decaps(ciphertext) # or kem.decaps(ciphertext, user_sk)
    print("Shared Secret (Decapsulation):", hexlify(shared_secret_dec))

    # verify the shared secret
    if(shared_secret_enc == shared_secret_dec):
        print("Shared secret verification succeeded.")
    else:
        print("Shared secret verification failed.")

if __name__ == "__main__":
    print("=== Key Encapsulation Mechanism Example ===")
    example_kem()






