sfv repo for sfv tests - git@github.com:ucarion/sfv.git
For message signing I used: https://github.com/igor-pavlenko/httpsignatures-go (for ecdsa and sha256 functions) and https://github.com/yaronf/httpsign (for structure)

From this crypto file: borrow the ideas (ECDSA + x509 usage), but not the exact functions.

Build your own small helpers:

parseIPK(ipkB64) → *ecdsa.PublicKey (using x509.ParsePKIXPublicKey on DER)

verifyECDSARaw(pub, message, sig) → matches Lua’s ecdsa_use_raw=true

Glue those into your approov.go message-signature verifier.

That way your Go quickstart behaves like your existing Lua approov.verify + http-message-sign combo, and you’re not fighting a different signature encoding.
