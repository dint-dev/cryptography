import 'package:curve25519/curve25519.dart';

void main() async {
  // Let's generate two asymmetric keypair.
  final keypair1 = await X25519().generateKeyPair();
  final keypair2 = await X25519().generateKeyPair();

  // We can now calculate a shared secret using the (sender's) private key and
  // the (recipient's) public key.
  var sharedSecret = await X25519().calculateSharedSecret(
    keypair1.secretKey,
    keypair2.publicKey,
  );
  print("#1 -> #2: ${sharedSecret.toHex()}");

  sharedSecret = await X25519().calculateSharedSecret(
    keypair2.secretKey,
    keypair1.publicKey,
  );
  print("#2 -> #1: ${sharedSecret.toHex()}"); // Same as #1 --> #2
}
