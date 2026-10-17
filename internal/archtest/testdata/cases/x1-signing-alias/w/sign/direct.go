package sign

import "crypto/ed25519"

func Direct(k ed25519.PrivateKey, m []byte) []byte { return ed25519.Sign(k, m) }
