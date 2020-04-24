import 'package:kms/kms.dart';
import 'package:kms_adapter_cupertino/kms.dart';

Future<void> main() async {
  final kms = CupertinoKms();
  final kmsKey = await kms.createKeyPair(
    keyRingId: 'example',
    keyExchangeType: null,
    signatureType: SignatureType.p256,
  );
  final signature = await kms.sign(
    [1, 2, 3],
    kmsKey: kmsKey,
    signatureType: SignatureType.p256,
  );
  print('Signature: ${signature.bytes}');
  print('Public key: ${signature.publicKey}');
}
