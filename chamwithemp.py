from charm.toolbox.Hash import ChamHash
from charm.toolbox.integergroup import IntegerGroupQ,gcd,randomPrime,isPrime,random,InitBenchmark,GetBenchmark,StartBenchmark,EndBenchmark
from charm.toolbox.conversion import Conversion

debug = False


class Chamwithemp(ChamHash):

    def __init__(self):
        global group
        group = IntegerGroupQ(0)

    #generate pk sk
    def keygen(self, secparam):
        while True:
            p, q = randomPrime(secparam), randomPrime(secparam)
            print("p,q=>", p, q)
            if isPrime(p) and isPrime(q) and p != q:
                N = p * q
                phi_N = N - p - q + 1
                break
        pk = {'secparam': secparam, 'N': N, 'phi_N': phi_N}
        sk = {'p': p, 'q': q}
        return (pk, sk)

    #generate chameleon hash
    def hash(self, pk, message, r=0):
        #generate ephemeral trapdoors(p1,q1)
        while True:
            p1, q1 = randomPrime(pk['secparam']), randomPrime(pk['secparam'])
            print("p1,q1=>",p1,q1)
            if isPrime(p1) and isPrime(q1) and p1 != q1:
                N1 = p1 * q1
                if not gcd(N1,pk['N']) == 1:
                    continue
                break

        if r == 0:
            r = random(N1 * pk['N'])
        print("r=>",r)
        print("(p1,q1,N1)=>", (p1,q1,N1))
        print("N*N1=>",N1 * pk['N'])
        phi_NN1 = pk['phi_N'] * (N1 - p1 - q1 + 1)

        #find e inverse mod N1 * N, so gcd(e,phi_NN1)==1
        while True:
            e = random(pk['secparam'])
            if not gcd(e, phi_NN1) == 1:
                continue
            break

        M = Conversion.bytes2integer(message)
        print("M =>",M)

        #to set hash modular N * N1()
        group.q = N1 * pk['N']
        group.p = group.q * 2 + 1
        print("q=>",group.q)
        print("M hash=>", group.hash(M))

        h = (group.hash(M) * (r ** e)) % (N1 * pk['N'])
        xi = {'h': h, 'r': r, 'N1': N1, 'p1': p1, 'q1':q1, 'e':e}
        print("e=>",xi['e'])
        return xi

    def hashcheck(self, pk, message, xi):
        M = Conversion.bytes2integer(message)
        h1 = group.hash(M) * (xi['r'] ** xi['e']) % (pk['N'] * xi['N1'])
        if h1 == xi['h']:
            return True
        else:
            return False

    def collision(self, m, m1, xi, sk, pk):
        if xi['N1'] == xi['p1'] * xi['q1'] and pk['N'] == sk['p'] * sk['q']:
            if (self.hashcheck(pk, m, xi) == 1):
                print("e=>", xi['e'])
                print("N*N1=>",pk['N'] * xi['N1'])
                d = (xi['e'] ** -1) % (pk['N'] * xi['N1'])
                r1 = (((group.hash(m1) ** (-1)) * xi['h']) ** d) % (pk['N'] * xi['N1'])
                print("r1 =>", r1)
                return r1
            else:
                print("hash check failed")
        else:
            print("trapdoor key error")


def main():
        # test p and q primes for unit tests only
        #p = integer(
            #164960892556379843852747960442703555069442262500242170785496141408191025653791149960117681934982863436763270287998062485836533436731979391762052869620652382502450810563192532079839617163226459506619269739544815249458016088505187490329968102214003929285843634017082702266003694786919671197914296386150563930299)
        #q = integer(
            #82480446278189921926373980221351777534721131250121085392748070704095512826895574980058840967491431718381635143999031242918266718365989695881026434810326191251225405281596266039919808581613229753309634869772407624729008044252593745164984051107001964642921817008541351133001847393459835598957148193075281965149)

        #keygen
        chamHash = Chamwithemp()
        assert InitBenchmark(), "failed to init benchmark"
        StartBenchmark(["RealTime"])
        (pk, sk) = chamHash.keygen(1024)
        EndBenchmark()

        # hash
        assert InitBenchmark(), "failed to init benchmark"
        StartBenchmark(["RealTime"])
        msg = "Hello world this is the first message!"
        xi = chamHash.hash(pk, msg)
        if debug: print("Hash...")
        if debug: print("hash result =>", xi)
        EndBenchmark()

        # collision
        assert InitBenchmark(), "failed to init benchmark"
        StartBenchmark(["RealTime"])
        msg1 = "Hello world this is the second message!"
        r1 = chamHash.collision(msg, msg1, xi, sk, pk)
        if debug: print("new randomness =>", r1)
        EndBenchmark()

        if debug: print("collision generated correctly!!!")

if __name__ == '__main__':
    debug = True
    main()
