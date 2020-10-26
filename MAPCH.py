import chamwithemp
import MAABE
from charm.toolbox.integergroup import InitBenchmark, StartBenchmark, EndBenchmark, GetBenchmark
from charm.toolbox.pairinggroup import PairingGroup,GT

def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

def main():
    groupObj = PairingGroup('SS512')

    maabe = MAABE.MaabeRW15(groupObj)
    attrs1 = ['ONE', 'TWO']
    attrs2 = ['THREE', 'FOUR']

    access_policy = '((STUDENT@UT or PROFESSOR@OU) and (STUDENT@UT or MASTERS@OU))'
    if debug:
        print("attrs1 =>", attrs1);
        print("attrs2 =>", attrs2);
        print("Policy =>", access_policy)

    # setup
    assert groupObj.InitBenchmark(), "failed to init benchmark"
    groupObj.StartBenchmark(["RealTime"])
    public_parameters = maabe.setup()
    groupObj.EndBenchmark()
    setuptime1 = groupObj.GetBenchmark("RealTime")

    # authsetup 2AA
    groupObj.StartBenchmark(["RealTime"])
    (pk1, sk1) = maabe.authsetup(public_parameters, 'UT')
    (pk2, sk2) = maabe.authsetup(public_parameters, 'OU')
    groupObj.EndBenchmark()
    authsetuptime = groupObj.GetBenchmark("RealTime")
    maabepk = {'UT': pk1, 'OU': pk2}

    # keygen
    chamHash = chamwithemp.Chamwithemp()
    assert InitBenchmark(), "failed to init benchmark"
    StartBenchmark(["RealTime"])
    (pk, sk) = chamHash.keygen(1024)
    EndBenchmark()
    keygentime1 = GetBenchmark("RealTime")

    # keygen Bob
    groupObj.StartBenchmark(["RealTime"])
    gid = "bob"
    user_attr1 = ['STUDENT@UT']
    user_attr2 = ['STUDENT@OU']

    user_sk1 = maabe.multiple_attributes_keygen(public_parameters, sk1, gid, user_attr1)
    user_sk2 = maabe.multiple_attributes_keygen(public_parameters, sk2, gid, user_attr2)

    user_sk = {'GID': gid, 'keys': merge_dicts(user_sk1, user_sk2)}
    groupObj.EndBenchmark()
    keygentime = groupObj.GetBenchmark("RealTime")

    # encrypt
    groupObj.StartBenchmark(["RealTime"])
    rand_msg = groupObj.random(GT)
    if debug: print("msg =>", rand_msg)
    ct = maabe.encrypt(public_parameters, maabepk, rand_msg, access_policy)
    groupObj.EndBenchmark()
    encrypttime = groupObj.GetBenchmark("RealTime")
    if debug: print("\n\nCiphertext...\n")
    groupObj.debug(ct)
    print("ciphertext:=>", ct)

    # hash
    assert InitBenchmark(), "failed to init benchmark"
    StartBenchmark(["RealTime"])
    msg = "Video provides a powerful way to help you prove your point. When you click Online Video, you can paste in the embed code for t"
    xi = chamHash.hash(pk, msg)
    if debug: print("Hash...")
    if debug: print("hash result =>", xi)
    EndBenchmark()
    hashtime = GetBenchmark("RealTime")

    # decrypt
    groupObj.StartBenchmark(["RealTime"])
    rec_msg = maabe.decrypt(public_parameters, user_sk, ct)
    groupObj.EndBenchmark()
    decrypttime = groupObj.GetBenchmark("RealTime")
    if debug: print("\n\nDecrypt...\n")
    if debug: print("Rec msg =>", rec_msg)

    assert rand_msg == rec_msg, "FAILED Decryption: message is incorrect"
    if debug: print("Successful Decryption!!!")

    # collision
    assert InitBenchmark(), "failed to init benchmark"
    StartBenchmark(["RealTime"])
    msg1 = "Video provides a powerful way to help you prove your point. When you click Online Video, you can paste in the embed code for p"
    r1 = chamHash.collision(msg, msg1, xi, sk, pk)
    if debug: print("new randomness =>", r1)
    EndBenchmark()
    collisiontime = GetBenchmark("RealTime")

    if debug: print("collision generated correctly!!!")


if __name__ == '__main__':
    debug = True
    main()
