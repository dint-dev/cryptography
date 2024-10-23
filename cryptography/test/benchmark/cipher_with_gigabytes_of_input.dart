import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography_plus/cryptography_plus.dart';

Future<void> main() async {
  final stopwatch = Stopwatch()..start();
  final timer = Timer.periodic(const Duration(seconds: 5), (timer) {
    print('${stopwatch.elapsed.inSeconds} seconds');
  });
  final algo = Chacha20(macAlgorithm: MacAlgorithm.empty);
  final secretKey = await algo.newSecretKey();
  final nonce = algo.newNonce();
  final encryptedStream = algo.encryptStream(
    _stream(),
    secretKey: secretKey,
    nonce: nonce,
    onMac: (_) {},
  );
  var n = 0;
  await for (var _ in encryptedStream) {
    n++;
    if (n % million == 0) {
      print('Encrypted ${n ~/ million} GB');
    }
  }
  timer.cancel();
}

const million = 1000000;

// 1 kilobyte
final data = Uint8List(1024);

Stream<List<int>> _stream() async* {
  for (var i = 0; i < 64 * million; i++) {
    yield data;
  }
}
