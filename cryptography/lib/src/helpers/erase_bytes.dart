import 'dart:typed_data';

final _typeOfModifiableUint8List = Uint8List.fromList(const []).runtimeType;

void tryEraseBytes(List<int> bytes, {List<int>? unlessUsedIn}) {
  if (unlessUsedIn != null) {
    if (identical(bytes, unlessUsedIn) ||
        bytes is Uint8List &&
            unlessUsedIn is Uint8List &&
            identical(bytes.buffer, unlessUsedIn.buffer)) {
      return;
    }
  }
  try {
    if (identical(bytes.runtimeType, _typeOfModifiableUint8List)) {
      bytes.fillRange(0, bytes.length, 0);
    }
  } catch (error) {
    assert(false, '$error');
  }
}
