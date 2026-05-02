# RustCrypto FFI wrapper

RustCrypto: https://github.com/RustCrypto

RustCrypto を Nim から安全に呼び出すための FFI ラッパーです。現時点では SHA-256、HMAC-SHA256、HKDF-SHA256、secp256k1 公開鍵導出、ECDSA 署名・検証、SHA3-256、Keccak-256、Ed25519 の公開鍵導出・署名・検証、PKCS#8/SPKI 変換と PEM 変換を提供しています。

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
- [ ] 18. `pbkdf2`
  - 用途: 互換性重視のパスワード由来鍵生成、ウォレットファイル保護。
  - 依存先: `hmac`, `digest`, `password-hash`。
- [ ] 19. `password-hash` trait
  - 用途: `pbkdf2`、`scrypt`、`argon2`の出力形式と検証APIの共通化。
  - 依存先: なし。
- [ ] 20. `scrypt`
  - 用途: ウォレット・ローカル秘密鍵のパスワード保護。
  - 依存先: `password-hash`。
- [ ] 21. `argon2`
  - 用途: 新規アプリでの強いパスワードハッシュ。
  - 依存先: `password-hash`。
- [ ] 22. `aes-gcm`
  - 用途: 一般的なAEAD暗号化、他システムとの互換用途。
  - 依存先: `aead`, `cipher`。必要に応じて`hkdf`や`pbkdf2`。
- [ ] 23. `aes-gcm-siv`
  - 用途: nonce再利用リスクに強いAEAD暗号化。
  - 依存先: `aead`, `cipher`。
- [ ] 24. `blake2`
  - 用途: 高速ハッシュ、暗号資産周辺プロトコルやアプリ内部ID。
  - 依存先: `digest`。
- [ ] 25. `p256`
  - 用途: WebAuthn、証明書、一般Web/PKI連携。
  - 依存先: `signature`、`ecdsa`、`der`、`pkcs8`。
- [ ] 26. `p384`
  - 用途: 高セキュリティ寄りのPKI/証明書連携。
  - 依存先: `signature`、`ecdsa`、`der`、`pkcs8`。
- [ ] 27. `x509-cert`
  - 用途: 証明書の読み書き、TLS/PKI系ツールとの連携。
  - 依存先: `der`, `const-oid`, `p256`, `p384`, `rsa`。
- [ ] 28. `rsa` signatures
  - 用途: 既存PKIや古いシステムとの署名互換。
  - 依存先: `signature`, `digest`, `rsa`, `der`, `pkcs8`。
- [ ] 29. `rsa` asymmetric encryption
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
- `hkdfSha256Extract`, `hkdfSha256Expand`, `hkdfSha256Derive`
- `chacha20poly1305Encrypt`, `chacha20poly1305Decrypt`
- `secp256k1PublicKeyCompressed`, `secp256k1PublicKeyUncompressed`
- `secp256k1EcdsaSign`, `secp256k1EcdsaVerify`
- `secp256k1EcdsaSignatureToDer`, `secp256k1EcdsaSignatureFromDer`
- `ed25519PublicKeyFromSecretKey`, `ed25519Sign`, `ed25519Verify`
- `ed25519PrivateKeyToPkcs8Der`, `ed25519PrivateKeyFromPkcs8Der`
- `ed25519PublicKeyToSpkiDer`, `ed25519PublicKeyFromSpkiDer`
- `ed25519PrivateKeyToPkcs8Pem`, `ed25519PrivateKeyFromPkcs8Pem`
- `ed25519PublicKeyToSpkiPem`, `ed25519PublicKeyFromSpkiPem`
- `sha3_256`, `sha3_256Hex`
- `keccak256`, `keccak256Hex`

## テストベクトル

- `SHA256("abc")`
- `HMAC-SHA256` RFC 4231 test case 1/2
- `HKDF-SHA256` RFC 5869 test case 1/3
- `ChaCha20-Poly1305` RFC 8439 AEAD test vector
- secp256k1 秘密鍵 `0x...01` からの公開鍵導出
- secp256k1 `abc` ダイジェストでの ECDSA 署名・検証
- secp256k1 ECDSA raw 64 バイト署名と DER 署名の相互変換
- Ed25519 RFC 8032 の公開鍵導出、署名・検証、改ざん署名の失敗
- Ed25519 PKCS#8 / SPKI / PEM RFC 8410 / RFC 7468 の既知ベクトル
- `SHA3-256("abc")`
- `Keccak-256("abc")`
