import rustcrypto/algorithm/secp256k1
import rustcrypto/algorithm/sha256

let secretKey = randomSecretKey()
let publicKey = secp256k1PublicKeyCompressed(secretKey)
let signature = secp256k1EcdsaSignSha256("abc", secretKey)
let verification = secp256k1EcdsaVerifySha256("abc", publicKey, signature)

echo("secretKey: ", secretKey)
echo("publicKey: ", publicKey)
echo("signature: ", signature)
echo("verification: ", verification)
