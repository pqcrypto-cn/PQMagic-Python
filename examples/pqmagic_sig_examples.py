# Input & output are all in bytes.
# A KEM object is created with a specific algorithm, its operations could use 
# either its attached key-pair, or the ones temprarily entered by the user.

from binascii import hexlify
from pqmagic import Sig, PQMAGIC_SUCCESS

def example_sig(): # Example of Signature Scheme

    message = b"This is a test message."
    context = b"Test context."

    # taking ML_DSA_44 as an example
    sig = Sig("ML_DSA_44")

    # generate key pair (or update the object's attached key pair)
    pk, sk = sig.keypair()
    print("Public Key:", hexlify(pk))
    print("Secret Key:", hexlify(sk))

    # sign message
    signature = sig.sign(message, context, sk) 
    # or sig.sign(message, context), but note that the key should be 
    # explicitly provided if the context is empty: sign(m, pk = b'xxxx')
    print("Signature:", hexlify(signature))

    # verify signature
    result = sig.verify(signature, message, context, pk)
    # or sig.verify(signature, message, context), but note that the key 
    # should be explicitly provided if the context is empty: verify(sig, m, pk = b'xxxx')
    if result == PQMAGIC_SUCCESS:
        print("Signature verification succeeded.")
    else:
        print("Signature verification failed.")

    # sign and pack message
    signed_message = sig.sign_pack(message, context, sk)
    # or sig.sign_pack(message, context), but note that the key 
    # should be explicitly provided if the context is empty: sign_pack(m, pk = b'xxxx')
    print("Signed Message:", hexlify(signed_message))

    # open and verify signed message
    result = sig.open(message, signed_message, context, pk)
    # or sig.open(message, signed_message, context), but note that 
    # the key should be provided if the context is empty: open(m, sm, pk = b'xxxx')
    if result == PQMAGIC_SUCCESS:
        print("Signed message verification succeeded.")
    else:
        print("Signed message verification failed.")

if __name__ == "__main__":
    print("=== Signature And Verification Example ===")
    example_sig()