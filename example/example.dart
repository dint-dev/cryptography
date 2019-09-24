import 'package:cryptography/cryptography.dart';

void chacha20_example() {
  // Generate a random 256-bit secret key
  final secretKey = chacha20.newSecretKey();

  // Generate a random 96-bit nonce.
  final nonce = chacha20.newNonce();

  // Encrypt
  final result = chacha20.encrypt(
    [1, 2, 3],
    secretKey,
    nonce: nonce,
  );
  print(result);
}

void x25519_example() async {
  // Let's generate two asymmetric keypair.
  final keypair1 = x25519.newKeyPair();
  final keypair2 = x25519.newKeyPair();

  // We can now calculate a shared secret
  var sharedSecret = x25519.sharedSecret(
    keypair1.secretKey,
    keypair2.publicKey,
  );
  print(sharedSecret.toHex());
}
