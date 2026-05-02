import unittest

import nim_rustcrypto


suite "sha256":
  test "sha256 high-level abc matches the known vector":
    let expected = Sha256Digest.fromHex(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

    check sha256("abc") == expected
    check sha256Hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

  test "sha256 high-level empty string matches the known vector":
    let expected = Sha256Digest.fromHex(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    check sha256("") == expected

  test "sha256 raw accepts empty input via null pointer":
    var output: Sha256Digest
    let status = sha256Raw(
      nil,
      0,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoOk
    check output == Sha256Digest.fromHex(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

  test "sha256 raw rejects null input when length is non-zero":
    var output: Sha256Digest
    let status = sha256Raw(
      nil,
      1,
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrNullInputWithData

  test "sha256 raw rejects null output":
    let message = "abc"
    let status = sha256Raw(
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      nil,
      csize_t(SHA256DigestLen),
    )

    check status == RustCryptoErrNullOutput

  test "sha256 raw rejects short output buffer":
    let message = "abc"
    var output: array[SHA256DigestLen - 1, byte]
    let status = sha256Raw(
      cast[ptr uint8](unsafeAddr message[0]),
      csize_t(message.len),
      cast[ptr uint8](addr output[0]),
      csize_t(output.len),
    )

    check status == RustCryptoErrOutputTooShort
