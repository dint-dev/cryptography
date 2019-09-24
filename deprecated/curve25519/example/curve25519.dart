import 'package:curve25519/curve25519.dart';

void main() async {
  // Let's generate two asymmetric keypair.
  final keypair1 = x25519.newKeyPair();
  final keypair2 = x25519.newKeyPair();

  // We can now calculate a shared secret using the (sender's) private key and
  // the (recipient's) public key.
  var sharedSecret = x25519.sharedSecret(
    keypair1.secretKey,
    keypair2.publicKey,
  );
  print("#1 -> #2: ${sharedSecret.toHex()}");

  sharedSecret = x25519.sharedSecret(
    keypair2.secretKey,
    keypair1.publicKey,
  );
  print("#2 -> #1: ${sharedSecret.toHex()}"); // Same as #1 --> #2
}
