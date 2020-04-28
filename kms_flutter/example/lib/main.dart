import 'package:kms/kms.dart';
import 'package:kms_flutter/kms_flutter.dart';

Future<void> main() async {
  // In browsers, returns BrowserKms.
  // In other platforms, returns PluginKms.
  final kms = flutterKms();

  // Create a key pair.
  final keyPairDocument = await kms.collection('example').createKeyPair(
        keyExchangeType: null,
        signatureType: SignatureType.ed25519,
        keyDocumentSecurity: KeyDocumentSecurity.highest,
      );

  // Sign a message
  final signature = await keyPairDocument.sign([1, 2, 3]);
  print('Public key: ${signature.publicKey}');
  print('Signature: $signature');

  // ...

  // Delete
  await keyPairDocument.delete();
}
