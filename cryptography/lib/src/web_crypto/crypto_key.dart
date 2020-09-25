@JS()
library crypto_key;

import 'package:js/js.dart';

@JS()
class CryptoKey {
  external factory CryptoKey._();
  external dynamic get algorithm;
  external bool get extractable;
  external String get type;
  external List<String> get usages;
}
