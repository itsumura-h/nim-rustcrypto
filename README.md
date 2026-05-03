# RustCrypto FFI wrapper

RustCrypto: https://github.com/RustCrypto

RustCrypto を Nim から安全に呼び出すための FFI ラッパーです。`nim_rustcrypto/algorithm/*` は SHA-256、HMAC-SHA256、HKDF-SHA256、PBKDF2-HMAC-SHA256、scrypt、Argon2id、PHC 文字列の検証・正規化、AES-256-GCM、AES-256-GCM-SIV、BLAKE2b-512、BLAKE2s-256、secp256k1 公開鍵導出、ECDSA 署名・検証、SHA-256 / SHA3-256 / Keccak-256 を使う secp256k1 ECDSA 署名・検証、`nim_rustcrypto/algorithm/schnorr.nim` から使う secp256k1 Schnorr の低水準公開鍵導出・署名・検証、Ed25519 の公開鍵導出・署名・検証、PKCS#8/SPKI 変換と PEM 変換、P-256 / P-384 ECDSA、X.509 証明書の最小読み取り、RSA-PSS 署名、RSA PKCS#1 v1.5 署名、RSA-OAEP 暗号化、RSA PKCS#1 v1.5 暗号化の低水準 API を提供します。その上に `nim_rustcrypto/bitcoin`、`nim_rustcrypto/lightning`、`nim_rustcrypto/ethereum`、`nim_rustcrypto/jwt` の高水準 API を重ね、プロトコル別の前処理や署名形式変換をまとめて扱えるようにしています。Schnorr は ECDSA とは別形式で、公開鍵と署名は互換ではありません。

## 開発優先順位

- [x] 1. `digest` trait
  - 用途: ハッシュ関数を共通FFIで包むための基盤。
  - 依存先: なし。
- [x] 2. `sha2`
  - 用途: Bitcoinのtxid/block hash、Lightningの各種ハッシュ、関連する周辺実装。
  - 依存先: `digest`。
- [x] 3. `k256` (secp256k1)
  - 用途: Bitcoin、Ethereum、Lightningの公開鍵・秘密鍵・曲線演算。
  - 依存先: 署名APIでは`signature`、プロトコル上は`sha2`やKeccak系ハッシュと組み合わせる。
- [x] 4. `signature` trait
  - 用途: ECDSA、Ed25519、RSA署名を同じFFI設計で扱うための基盤。
  - 依存先: なし。
- [x] 5. `ecdsa`
  - 用途: Bitcoin/Ethereum/Lightningのsecp256k1署名の土台。
  - 依存先: `signature`, `k256`, `sha2`またはKeccak系ハッシュ。
- [x] 6. `sha3`
  - 用途: Ethereum互換のKeccak/SHA-3系ハッシュ、アドレス・署名対象データの処理。
  - 依存先: `digest`。
- [x] 7. `keccak`
  - 用途: EthereumのKeccak-256互換性を低水準で明確に扱う場合。
  - 依存先: `digest`相当のFFI設計。`sha3`で足りる範囲との切り分けが必要。
- [x] 8. `hmac`
  - 用途: メッセージ認証、鍵導出、プロトコル内検証。
  - 依存先: `digest`、主に`sha2`。
- [x] 9. `hkdf`
  - 用途: Lightning/BOLT系や暗号化プロトコルでの鍵素材展開。
  - 依存先: `hmac`, `digest`, 主に`sha2`。
- [x] 10. `aead` trait
  - 用途: 認証付き暗号を共通FFIで包むための基盤。
  - 依存先: なし。
- [x] 11. `cipher` trait
  - 用途: 対称暗号の低水準共通API設計。
  - 依存先: なし。
- [x] 12. `chacha20poly1305`
  - 用途: Lightning/BOLT系の通信暗号化、ソフトウェア実装向けAEAD。
  - 依存先: `aead`, `cipher`。実プロトコルでは`hkdf`で導出した鍵を使う。
- [x] 13. `der`
  - 用途: ECDSA署名、公開鍵、証明書系データのDER入出力。
  - 依存先: `ecdsa`, `rsa`, `p256`, `p384`, `const-oid`。
- [x] 14. `pkcs8`
  - 用途: 秘密鍵・公開鍵の標準形式での保存と読み込み。
  - 依存先: `der`, `const-oid`, `k256`, `p256`, `p384`, `rsa`, `ed25519`。
- [x] 15. `pem-rfc7468`
  - 用途: PEM形式の鍵・証明書をCLIや外部ツールと交換する。
  - 依存先: `der`, `pkcs8`, `x509-cert`。
- [x] 16. `const-oid`
  - 用途: DER/PKCS#8/X.509内のアルゴリズム識別子。
  - 依存先: なし。`der`, `pkcs8`, `x509-cert`から利用される。
- [x] 17. `ed25519`
  - 用途: Nostrなど暗号資産周辺エコシステム、軽量な署名用途。
  - 依存先: `signature`。必要に応じて`pkcs8`と`pem-rfc7468`。
- [x] 18. `pbkdf2`
  - 用途: 互換性重視のパスワード由来鍵生成、ウォレットファイル保護。
  - 依存先: `hmac`, `digest`, `password-hash`。
- [x] 19. `password-hash` trait
  - 用途: `pbkdf2`、`scrypt`、`argon2`の出力形式と検証APIの共通化。
  - 依存先: なし。
- [x] 20. `scrypt`
  - 用途: ウォレット・ローカル秘密鍵のパスワード保護。
  - 依存先: `password-hash`。
  - 実装メモ: N は 2 の冪として受け取り、Rust 側で `log_n` に変換する。
- [x] 21. `argon2`
  - 用途: 新規アプリでの強いパスワードハッシュ。
  - 依存先: `password-hash`。
  - 実装メモ: Argon2id のみを公開し、`m_cost`、`t_cost`、`p_cost`、`salt`、`hashLen` を明示する。
- [x] 22. `aes-gcm`
  - 用途: 一般的なAEAD暗号化、他システムとの互換用途。
  - 依存先: `aead`, `cipher`。必要に応じて`hkdf`や`pbkdf2`。
- [x] 23. `aes-gcm-siv`
  - 用途: nonce再利用リスクに強いAEAD暗号化。
  - 依存先: `aead`, `cipher`。
- [x] 24. `blake2`
  - 用途: 高速ハッシュ、暗号資産周辺プロトコルやアプリ内部ID。
  - 依存先: `digest`。
- [x] 25. `p256`
  - 用途: WebAuthn、証明書、一般Web/PKI連携。
  - 依存先: `signature`、`ecdsa`、`der`、`pkcs8`。
- [x] 26. `p384`
  - 用途: 高セキュリティ寄りのPKI/証明書連携。
  - 依存先: `signature`、`ecdsa`、`der`、`pkcs8`。
- [x] 27. `x509-cert`
  - 用途: 証明書の読み書き、TLS/PKI系ツールとの連携。
  - 依存先: `der`, `const-oid`, `p256`, `p384`, `rsa`。
- [x] 28. `rsa` signatures
  - 用途: 既存PKIや古いシステムとの署名互換。
  - 依存先: `signature`, `digest`, `rsa`, `der`, `pkcs8`。
- [x] 29. `rsa` asymmetric encryption
  - 用途: 互換用途の公開鍵暗号化。Bitcoin/Ethereum/Lightningの中核ではない。
  - 依存先: `rsa`, `der`, `pkcs8`, `pem-rfc7468`。
- [ ] 30. `dsa`
  - 用途: レガシー署名互換。
  - 依存先: `signature`, `digest`, `der`。
- [ ] 31. `elliptic-curves` asymmetric encryption
  - 用途: ECDH/ECIES風の鍵共有・暗号化設計が必要になった場合。
  - 依存先: 対象曲線、`hkdf`, `aead`。
- [ ] 32. `ascon`
  - 用途: 軽量暗号・軽量スポンジ関数の実験的または組み込み向け用途。
  - 依存先: `digest`相当のFFI設計。AEADとして扱う場合は`aead`。
- [ ] 33. `ml-kem`
  - 用途: 将来の耐量子KEM対応。現時点のBitcoin/Ethereum/Lightning中核では後回し。
  - 依存先: KEM用のFFI設計。必要に応じて`hkdf`や`aead`と組み合わせる。

## 使い方

### Rust

Rust 側は `src/rustcrypto-ffi` でビルドします。

```bash
cd src/rustcrypto-ffi
cargo test
cargo build --release --lib
```

### Nim

Nim 側は `src/nim-rustcrypto` でビルドします。`nim_rustcrypto` を import すると、低水準 FFI と高水準 API の両方を使えます。

```bash
cd src/nim-rustcrypto
nimble test -y
```

## 提供 API

- `sha256`, `sha256Hex`
- `hmacSha256`, `hmacSha256Hex`
- `pbkdf2HmacSha256`
- `scrypt`
- `argon2idDerive`, `argon2idHashPassword`, `argon2idVerifyPassword`
- `passwordHashValidate`, `passwordHashCanonicalize`
- `hkdfSha256Extract`, `hkdfSha256Expand`, `hkdfSha256Derive`
- `chacha20poly1305Encrypt`, `chacha20poly1305Decrypt`
- `aes256gcmEncrypt`, `aes256gcmDecrypt`
- `aes256gcmsivEncrypt`, `aes256gcmsivDecrypt`
- `secp256k1PublicKeyCompressed`, `secp256k1PublicKeyUncompressed`
- `secp256k1EcdsaSign`, `secp256k1EcdsaVerify`
- `secp256k1EcdsaSignSha256`, `secp256k1EcdsaVerifySha256`
- `secp256k1EcdsaSignSha3_256`, `secp256k1EcdsaVerifySha3_256`
- `secp256k1EcdsaSignKeccak256`, `secp256k1EcdsaVerifyKeccak256`
- `secp256k1EcdsaSignatureToDer`, `secp256k1EcdsaSignatureFromDer`
- `schnorrPublicKey`, `schnorrSign`, `schnorrVerify` (`nim_rustcrypto/algorithm/schnorr.nim` の低水準 API)
- `ed25519PublicKeyFromSecretKey`, `ed25519Sign`, `ed25519Verify`
- `ed25519PrivateKeyToPkcs8Der`, `ed25519PrivateKeyFromPkcs8Der`
- `ed25519PublicKeyToSpkiDer`, `ed25519PublicKeyFromSpkiDer`
- `ed25519PrivateKeyToPkcs8Pem`, `ed25519PrivateKeyFromPkcs8Pem`
- `ed25519PublicKeyToSpkiPem`, `ed25519PublicKeyFromSpkiPem`
- `sha3_256`, `sha3_256Hex`
- `keccak256`, `keccak256Hex`
- `blake2b512`, `blake2b512Hex`
- `blake2s256`, `blake2s256Hex`
- `p256PublicKeyCompressed`, `p256PublicKeyUncompressed`
- `p256EcdsaSignSha256`, `p256EcdsaVerifySha256`
- `p256EcdsaSignPrehash`, `p256EcdsaVerifyPrehash`
- `p256PrivateKeyToPkcs8Der`, `p256PrivateKeyFromPkcs8Der`
- `p256PublicKeyToSpkiDer`, `p256PublicKeyFromSpkiDer`
- `p384PublicKeyCompressed`, `p384PublicKeyUncompressed`
- `p384EcdsaSignSha384`, `p384EcdsaVerifySha384`
- `p384EcdsaSignPrehash`, `p384EcdsaVerifyPrehash`
- `p384PrivateKeyToPkcs8Der`, `p384PrivateKeyFromPkcs8Der`
- `p384PublicKeyToSpkiDer`, `p384PublicKeyFromSpkiDer`
- `x509CertValidateDer`, `x509CertFromPem`, `x509CertToPem`
- `x509CertSubjectPublicKeyInfoDer`, `x509CertSignatureAlgorithmOid`
- `x509CertSubjectDer`, `x509CertIssuerDer`
- `rsaPrivateKeyToPkcs8Der`, `rsaPrivateKeyFromPkcs8Der`
- `rsaPublicKeyToSpkiDer`, `rsaPublicKeyFromSpkiDer`
- `rsaPssSignSha256`, `rsaPssVerifySha256`
- `rsaPkcs1v15SignSha256`, `rsaPkcs1v15VerifySha256`
- `rsaOaepSha256Encrypt`, `rsaOaepSha256Decrypt`
- `rsaPkcs1v15Encrypt`, `rsaPkcs1v15Decrypt`

## 高水準 API

- `bitcoin`: Bitcoin Signed Message、BIP340 tagged hash、Taproot 向け署名補助
- `lightning`: BOLT 11 invoice の hash と recoverable ECDSA 署名補助
- `ethereum`: Keccak-256、アドレス導出、EIP-191/EIP-712 の署名補助
- `jwt`: JWS Compact Serialization の `HS256`、`ES256`、`EdDSA`、`RS256`、`PS256`

注意:

- `jwt` は `alg: none` を受け付けません
- `bitcoin` / `lightning` / `ethereum` はフルノード、ウォレット、トランザクション完全実装ではありません
- `jwt` は JSON の正規化、claim 検証、JWKS 取得を行いません

## テストベクトル

- `SHA256("abc")`
- `HMAC-SHA256` RFC 4231 test case 1/2
- `PBKDF2-HMAC-SHA256` 既知ベクトル
- `scrypt` RFC 7914 test vector 1/2/3
- `Argon2id` 既知ベクトルと PHC 文字列の round-trip
- `PHC` 文字列の既知ベクトルと round-trip
- `HKDF-SHA256` RFC 5869 test case 1/3
- `ChaCha20-Poly1305` RFC 8439 AEAD test vector
- `AES-256-GCM` NIST SP 800-38D test vector と改ざん tag
- `AES-256-GCM-SIV` RFC 8452 test vector と改ざん tag
- `BLAKE2b-512` RFC 7693 test vector
- `BLAKE2s-256` RFC 7693 test vector
- secp256k1 秘密鍵 `0x...01` からの公開鍵導出
- secp256k1 `abc` ダイジェストでの ECDSA 署名・検証
- secp256k1 ECDSA SHA-256 / SHA3-256 / Keccak-256 の本文入力 API
- secp256k1 ECDSA raw 64 バイト署名と DER 署名の相互変換
- secp256k1 Schnorr の公開鍵導出、署名・検証、改ざん署名の失敗
- Ed25519 RFC 8032 の公開鍵導出、署名・検証、改ざん署名の失敗
- Ed25519 PKCS#8 / SPKI / PEM RFC 8410 / RFC 7468 の既知ベクトル
- `SHA3-256("abc")`
- `Keccak-256("abc")`
- P-256 RFC 6979 test vector
- P-384 RFC 6979 test vector
- X.509 DER/PEM fixture の round-trip と SPKI 抽出
- RSA-PSS / RSA PKCS#1 v1.5 の署名・検証
- RSA-OAEP / RSA PKCS#1 v1.5 の暗号化・復号
