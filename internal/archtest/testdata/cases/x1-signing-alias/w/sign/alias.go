package sign

import signed "crypto/ed25519"

func Alias(k signed.PrivateKey, m []byte) []byte { return signed.Sign(k, m) }
