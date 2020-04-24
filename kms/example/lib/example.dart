import 'package:kms/kms.dart';

Future<void> main() async {
  final kms = MemoryKms();
  final kmsKey = await kms.createKeyPair(
    keyRingId: 'example',
    keyExchangeType: null,
    signatureType: SignatureType.ed25519,
  );
  final signature = await kms.sign(
    [1, 2, 3],
    kmsKey: kmsKey,
    signatureType: SignatureType.ed25519,
  );
  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey}');
}
