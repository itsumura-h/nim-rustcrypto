import ./ffi
import ./utils

type
  HkdfSha256Prk* = array[HkdfSha256PrkLen, byte]
  HkdfSha256Okm* = seq[byte]

proc hkdfSha256Extract*(salt, ikm: string): HkdfSha256Prk =
  var output: HkdfSha256Prk
  let status = hkdfSha256ExtractRaw(
    bytesPtr(salt),
    csize_t(salt.len),
    bytesPtr(ikm),
    csize_t(ikm.len),
    cast[ptr uint8](addr output[0]),
    csize_t(output.len),
  )
  raiseIfError(
    status,
    "rustcrypto_hkdf_sha256_extract",
    nullOutputMessage = "rustcrypto_hkdf_sha256_extract failed: null output",
    outputTooShortMessage = "rustcrypto_hkdf_sha256_extract failed: output too short",
    nullInputWithDataMessage = "rustcrypto_hkdf_sha256_extract failed: null input with data",
    panicMessage = "rustcrypto_hkdf_sha256_extract failed: panic",
  )
  output

proc hkdfSha256Expand*(prk: HkdfSha256Prk, info: string, okmLen: int): HkdfSha256Okm =
  if okmLen < 0:
    raise newException(ValueError, "hkdfSha256Expand failed: negative output length")
  if okmLen > HkdfSha256MaxOkmLen:
    raise newException(ValueError, "hkdfSha256Expand failed: invalid length")

  result = newSeq[byte](okmLen)
  if okmLen == 0:
    return

  let status = hkdfSha256ExpandRaw(
    bytesPtr(prk),
    csize_t(prk.len),
    bytesPtr(info),
    csize_t(info.len),
    bytesPtr(result),
    csize_t(result.len),
  )
  raiseIfError(
    status,
    "rustcrypto_hkdf_sha256_expand",
    nullOutputMessage = "rustcrypto_hkdf_sha256_expand failed: null output",
    nullInputWithDataMessage = "rustcrypto_hkdf_sha256_expand failed: null input with data",
    invalidPrkLengthMessage = "rustcrypto_hkdf_sha256_expand failed: invalid PRK length",
    invalidLengthMessage = "rustcrypto_hkdf_sha256_expand failed: invalid length",
    panicMessage = "rustcrypto_hkdf_sha256_expand failed: panic",
  )

proc hkdfSha256Derive*(salt, ikm, info: string, okmLen: int): HkdfSha256Okm =
  if okmLen < 0:
    raise newException(ValueError, "hkdfSha256Derive failed: negative output length")
  if okmLen > HkdfSha256MaxOkmLen:
    raise newException(ValueError, "hkdfSha256Derive failed: invalid length")

  result = newSeq[byte](okmLen)
  if okmLen == 0:
    return

  let status = hkdfSha256DeriveRaw(
    bytesPtr(salt),
    csize_t(salt.len),
    bytesPtr(ikm),
    csize_t(ikm.len),
    bytesPtr(info),
    csize_t(info.len),
    bytesPtr(result),
    csize_t(result.len),
  )
  raiseIfError(
    status,
    "rustcrypto_hkdf_sha256_derive",
    nullOutputMessage = "rustcrypto_hkdf_sha256_derive failed: null output",
    nullInputWithDataMessage = "rustcrypto_hkdf_sha256_derive failed: null input with data",
    invalidLengthMessage = "rustcrypto_hkdf_sha256_derive failed: invalid length",
    panicMessage = "rustcrypto_hkdf_sha256_derive failed: panic",
  )
