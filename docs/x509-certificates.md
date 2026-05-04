# X.509 certificates (minimal)

Module: `rustcrypto/algorithm/x509`

Small helpers to validate certificates, convert between PEM and DER, and extract a few DER blobs (SubjectPublicKeyInfo, signature algorithm OID, subject, issuer).

## Validate DER

```nim
import rustcrypto/algorithm/x509

if x509CertValidateDer(certDer):
  echo "DER parses as a supported certificate"
```

## PEM ↔ DER

```nim
let der = x509CertFromPem(pemString)
let pem = x509CertToPem(der)
```

## Extract fields

```nim
let spki = x509CertSubjectPublicKeyInfoDer(der)
let sigAlgOid = x509CertSignatureAlgorithmOid(der)
let subject = x509CertSubjectDer(der)
let issuer = x509CertIssuerDer(der)
```

This is **not** a full PKIX path validator: no chain building, revocation, or name constraints.
