import rustcrypto/algorithm/secp256k1

let secretKey = Secp256k1.generateSecretKey()
let publicKey = Secp256k1.publicKeyCompressed(secretKey)
let signature = Secp256k1.sign("abc", secretKey)
let verification = Secp256k1.verify("abc", publicKey, signature)

echo("secretKey: ", secretKey)
echo("publicKey: ", publicKey)
echo("signature: ", signature)
echo("verification: ", verification)
