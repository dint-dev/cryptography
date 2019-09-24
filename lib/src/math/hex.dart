// Copyright 2019 Gohilla (opensource@gohilla.com).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import 'dart:typed_data';

/// Example: [0x0A, 0xABCD] --> "A ABCD"
String hexFromBytes(Iterable<int> list) {
  if (list == null) {
    return "null";
  }
  return list.map((v) => v.toRadixString(16)).join(" ");
}

/// Example: ["0a 0b:0c"] --> [10,11,12]
Uint8List hexToBytes(String input) {
  if (input == null) {
    return null;
  }
  final s = input.replaceAll(" ", "").replaceAll(":", "").replaceAll("\n", "");
  final result = <int>[];
  for (var i = 0; i < s.length; i++) {
    var value = int.tryParse(s.substring(i, i + 1), radix: 16);
    if (value == null) {
      throw ArgumentError.value(input, "input");
    }
    if (i % 2 == 0) {
      result.add(16 * value);
    } else {
      result[i ~/ 2] += value;
    }
  }
  return Uint8List.fromList(result);
}
