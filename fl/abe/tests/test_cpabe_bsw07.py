import unittest
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
from abe.cpabe_bsw07 import CPabe_BSW07

class TestABE(unittest.TestCase):
    def test_abe(self):
        groupObj = PairingGroup('SS512')
        debug = True

        cpabe = CPabe_BSW07(groupObj)
        attrs = ['ONE', 'TWO', 'THREE']
        access_policy = '((four or three) and (three or one))'
        if debug:
            print("Attributes =>", attrs); print("Policy =>", access_policy)

        (pk, mk) = cpabe.setup()

        sk = cpabe.keygen(pk, mk, attrs)
        print("sk :=>", sk)

        rand_msg = groupObj.random(GT)
        if debug: print("msg =>", rand_msg)
        ct = cpabe.encrypt(pk, rand_msg, access_policy)
        if debug: print("\n\nCiphertext...\n")
        groupObj.debug(ct)

        rec_msg = cpabe.decrypt(pk, sk, ct)
        if debug: print("\n\nDecrypt...\n")
        if debug: print("Rec msg =>", rec_msg)

        assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
        if debug: print("Successful Decryption!!!")
