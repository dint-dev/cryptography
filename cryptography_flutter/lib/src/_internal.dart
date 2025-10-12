// Copyright 2019-2020 Gohilla.
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

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../cryptography_flutter_plus.dart';
import '_internal_impl_non_browser.dart'
    if (dart.library.html) '_internal_impl_browser.dart';

export '_internal_impl_non_browser.dart'
    if (dart.library.html) '_internal_impl_browser.dart';

const MethodChannel _methodChannel = MethodChannel('cryptography_flutter');

bool hasSeenMissingPluginException = false;

/// True if the platform is iOS and Mac OS X.
bool get isCupertino => isIOS || isMacOS;

/// Returns the bytes as [Uint8List].
Uint8List asUint8List(List<int> bytes) {
  // It's important that it's NOT something like UnmodifiableUint8ListView.
  // That's why we check runtimeType.
  return (bytes is Uint8List && bytes.runtimeType == Uint8List)
      ? bytes
      : Uint8List.fromList(bytes);
}

final Future<bool> _isPluginAvailable = () async {
  try {
    await _methodChannel.invokeMethod('encrypt', {});
    return true;
  } on MissingPluginException {
    hasSeenMissingPluginException = true;
    return false;
  } catch (e) {
    return true;
  }
}();

/// Invokes plugin method.
///
/// Throws [CryptographyUnsupportedError] if the platform is web or plugin is
/// not available.
Future<Map> invokeMethod(String name, Map<String, Object?> arguments,
    {bool useQueue = true}) async {
  if (kIsWeb) {
    throw UnsupportedError('Running in a browser.');
  }
  final isPluginAvailable = await _isPluginAvailable;
  if (!isPluginAvailable) {
    throw UnsupportedError('Unsupported platform.');
  }
  final waitGroup = CryptographyChannelQueue.defaultInstance;

  CryptographyChannelCall? lock;
  if (useQueue) {
    // Estimate size of the input.
    final size = CryptographyChannelQueue.estimateSize(arguments);

    // Check limits.
    lock = waitGroup.newLock(size: size);
    await lock.lock();
  }
  try {
    return await _methodChannel.invokeMethod(name, arguments) as Map;
  } on MissingPluginException catch (error, stackTrace) {
    // Update the top-level variable
    hasSeenMissingPluginException = true;
    throw UnsupportedError('Caught: $error\n$stackTrace');
  } on PlatformException catch (error) {
    if (error.code == 'UNSUPPORTED_ALGORITHM') {
      throw UnsupportedError(
        'cryptography_flutter caught error: ${error.message ?? 'Algorithm "$name" is not supported on this platform.'}',
      );
    }
    rethrow;
  } finally {
    lock?.unlock();
  }
}
