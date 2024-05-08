# crypto
 
Randomly generate Bitcoin private keys and compute their addresses. Private keys associated with funded bitcoin addresses will be printed to the console and written to a log file.

## Instructions

1) Download and extract the latest list of all funded bitcoin addresses from here: http://addresses.loyce.club/
   * Choose the list that does not show the balances.

2) Run "app_database.js" to create the database.
   * Inside the script, replace the values for "dbPath" and "addressPath".
   * This might take up to an hour to complete.
   * It is highly recommended that "dbPath" points to a location on an SSD.

3) Run "app_search.js" to randomly search for private keys that are associated with funded bitcoin addresses.
   * Inside the script, replace the value for "dbPath" with the same value you used above.
   * Note that the probability of actually finding such a private key is extremely low!
  
   If a result is found, you will see a hexadecimal private key in the console and the log file.

   Example Output:
   ```
   55c8c38eb853501d2c73359a60e9081eaf5acb25bbd9da3c974f3ae6ce149520
   ```

5) If step 3 finds a private key, then run "app_display.js" to see all the different public keys that can be derived from that private key.
   * Inside the script, replace the value for "privateKey" with the key from step 3.

   Example Output:
   ```
   privateKey
       55c8c38eb853501d2c73359a60e9081eaf5acb25bbd9da3c974f3ae6ce149520
   publicKey(c)
       03c770b38b32953ecf18f756044b759bce138c153ef2b53427adfce8ed76e66059
   publicKey(u)
       04c770b38b32953ecf18f756044b759bce138c153ef2b53427adfce8ed76e660593fe2112e78cfec62424b6353300b9ba294a5c4a7f95b1aa338c5eb321d22229f
   WIF(c)
       Kz6Tsu14UztLZJeqCqjCMEG3PrHLYpDD69z8o1eFWkSzcj5Mx6pf
   WIF(u)
       5JU4pnK93GP459XmuXXQR4uoJs8nDC9f5nzMLwXBzVRU6utgCxA
   Bech32(c)
       bc1q4vd3uuc4je7jfy88fcl2y23jrayx49uckd3lgl
   Bech32(u)
       bc1qefcx9q02jmeeydv9edmju5kmua28hckcstf373
   P2PKH(c)
       1Gbj34Vd7wGdDW7QSj3c2hoT8sCNfp2Dxg
   P2PKH(u)
       1KTQ8PAgCDhxcyBXD8jfxQDTUaAFSruHf5
   P2SH(c)
       3NudjdQcov9Ff39HpFQF8txAtQdRLgF9ZK
   P2SH(u)
       33Rtyx57taNALRSbhgVstgWxC9RYNfu3Fk
   Bech32(c) Script Hash
       99d89de45bdb70d968e7c9632a75756422162f82142ef07a6e19f92d138adcaf
   Bech32(u) Script Hash
       8e16828942380fcdc5e7d51ebd71c7561c9ee1918f2f8b96755e95159a1871a6
   P2PKH(c) Script Hash
       38175e85447ac245b4405692dbaf09c262460e1a2c4e300e099156fd8f7ac4fa
   P2PKH(u) Script Hash
       11623e8d8b7cf20abe3dd7cbb21b2c624075fda4823f5af7930b5b7d57505186
   P2SH(c) Script Hash
       2ff2022074443246befeefedc634579e5e57e53b7ef4db1e9ce2628e9529285a
   P2SH(u) Script Hash
       08f9b05ff1c350f103ba513bf7a4e2c1cc55773106fd8974cc7db8ec2bc45e4f
   BIP39 Words
       fiction ecology together idle crush attend range grit omit also dragon diary volcano grain notice kite surface tool stable into hollow apart fee add
   ```