import 'package:kms/kms.dart';

Future<void> main() async {
  // Choose some KMS
  final kms = MemoryKms();

  // Create a digital signature key
  final key = await kms.collection('default').createKeyPair(
        keyExchangeType: null,
        signatureType: SignatureType.ed25519,
      );

  // Sign
  final signature = await key.sign([1, 2, 3]);

  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey}');
}
