# MAPCH
We use python with charm framework to implement the multi-authority policy-based chameleon hash function (MAPCH). 

The instantiation of MAPCH includes the following primitives: a multi-authority ciphertext-policy attribute-based encryption (Efficient statically-secure large-universe multi-authority attribute-based encryption, FC 2015), a chameleon hash with ephemeral trapdoor (CHET: Chameleon-hashes with ephemeral trapdoors, PKC 2017), and a symmetric encryption scheme (e.g., AES).

The implementation includes 5 algorithms (see MAPCH.py), including MSetup, MKeyGen, MHash, MHVer and MHCol.
