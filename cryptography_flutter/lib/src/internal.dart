// Copyright 2019-2020 Gohilla Ltd.
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

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

const MethodChannel channel = MethodChannel('cryptography_flutter');

Future<Map> invokeMethod(String name, Map<String, Object> arguments) async {
  final result = await channel.invokeMethod(name, arguments);
  if (result is Map) {
    return result;
  }
  throw StateError('"package:cryptography_flutter": error: $result');
}

mixin FlutterCryptographyImplementation {
  void reportError(Object error, StackTrace stackTrace) {
    if (kDebugMode) {
      if (error is UnsupportedError) {
        // ignore: avoid_print
        print(
            '$runtimeType does not have native support in this operating system. Using Dart implementation instead.');
      } else {
        // ignore: avoid_print
        print(
            '----\nCRYPTOGRAPHY PLUGIN HAD UNEXPECTED ERROR:\n$error\n$stackTrace\n----');
      }
    }
  }
}
