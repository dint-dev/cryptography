[![Pub Package](https://img.shields.io/pub/v/noise.svg)](https://pub.dev/packages/noise)
[![Github Actions CI](https://github.com/dint-dev/cryptography/workflows/Dart%20CI/badge.svg)](https://github.com/dint-dev/cryptography/actions?query=workflow%3A%22Dart+CI%22)

# Overview
This is a Dart implementation of [Noise framework](https://noiseprotocol.org/noise.html), a secure
handshake protocol.

The Noise protocol has been analyzed by professional cryptographers and it has been adopted by products/companies
such as _WhatsApp_ ([whitepaper](https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf))
and Slack ([blog post](https://slack.engineering/introducing-nebula-the-open-source-global-overlay-network-from-slack-884110a5579)).

__Important: this early version doesn't pass acceptance tests yet.__

## Links
  * [Github project](https://github.com/dint-dev/cryptography)
  * [Issue tracker](https://github.com/dint-dev/cryptography/issues)
  * [Pub package](https://pub.dev/packages/noise)
  * [API reference](https://pub.dev/documentation/noise/latest/)

# A short introduction
Noise protocol defines 24 possible _handshake patterns_. You need to choose one that's relevant
for your requirements. For example:
  * KK
    * A two-message handshake in which both parties know each other's static keys.
  * XX
    * A three-message handshake in which both parties lack any pre-existing knowledge about
      each other.
  * XXpsk3
    * A three-message handshake in which both parties know a symmetric secret.
  * IK
    * A two-message handshake in which initiator knows the responder's static key.
  * N
    * A one-message handshake in which initiator knows the responder's static key. Suitable for use
      cases such as file encryption.

You also need to choose a key exchange algorithm, a cipher, and a hash algorithm. This
implementation supports:
  * Key exchange algorithms:
    * X25519
  * Ciphers:
    * AES-GCM
    * ChaCha20-Poly1305 AEAD
  * Hashes:
    * BLAKE2s
    * SHA2-256

Please remember that you also need to use of _prologue_ and/or _payload_ to prevent replay attacks
and identity probing.

The output of a Noise handshake is two symmetric encryption keys: one for encrypting, one for
decrypting.

Please read more at [noiseprotocol.org](https://noiseprotocol.org/noise.html).