# Cryptography

RSA uses OpenSSL RSA-4096 with RSA-PSS and SHA-256. The GGH implementation is an educational reference of the historical GGH hash-and-sign construction: a SHA-256 target is rounded with a private short lattice basis, then verified as a nearby point in the public lattice. GGH is not standardized or production secure; the original family has known cryptanalytic weaknesses.

Hybrid signing signs the exact same length-delimited canonical command bytes with both schemes. Verification retains the individual outcomes and reports overall validity only when both are valid.
