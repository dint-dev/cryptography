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
import 'dart:collection';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '_internal.dart';

class CryptographyChannelCall {
  final CryptographyChannelQueue _queue;
  final int _size;
  Completer? _completer = Completer();

  CryptographyChannelCall(this._queue, this._size);

  bool get isWaitingExpected {
    final queue = _queue;
    final currentTotalRequests = queue._totalRequests;
    if (currentTotalRequests == 0) {
      return false;
    }
    final size = _size;
    return currentTotalRequests + 1 > queue.maxConcurrentRequests ||
        _queue._totalSize + size > queue.maxConcurrentSize;
  }

  Future lock() async {
    final queue = _queue;
    final size = _size;
    if (isWaitingExpected) {
      final completer = Completer();
      _completer = completer;
      queue._locks.add(this);
      await completer.future;
    } else {
      queue._totalRequests++;
      queue._totalSize += size;
    }
  }

  void unlock() {
    // Update total size
    final queue = _queue;
    var currentTotalSize = queue._totalSize - _size;
    queue._totalSize = currentTotalSize;
    assert(currentTotalSize >= 0);

    // Update total requests
    var currentTotalRequests = queue._totalRequests - 1;
    queue._totalRequests = currentTotalRequests;
    assert(currentTotalRequests >= 0);

    // Try to handle waiting calls
    while (queue._locks.isNotEmpty &&
        currentTotalRequests < queue.maxConcurrentRequests) {
      final call = queue._locks.first;
      final size = call._size;
      if (currentTotalRequests > 0 &&
          currentTotalSize + size >= queue.maxConcurrentSize) {
        // Need to wait more.
        break;
      }

      // Increment total size
      currentTotalSize += size;
      queue._totalSize = currentTotalSize;

      // Increment total requests
      currentTotalRequests++;
      assert(currentTotalRequests > 0);
      queue._totalRequests = currentTotalRequests;

      // Remove and complete ticket
      queue._locks.removeFirst();
      call._completer!.complete();
      call._completer = null;
    }
  }
}

/// Waiting group used for preventing copying too much data to a channel such
/// as [compute] channel or [MethodChannel].
///
/// This should reduce risk of memory exhaustion.
class CryptographyChannelQueue {
  /// Default queue in this platform.
  static final CryptographyChannelQueue defaultInstance = () {
    if (isCupertino) {
      return _defaultInstanceForCupertino;
    }
    return _defaultInstanceForAndroid;
  }();

  /// Default queue for iOS and Mac OS X
  static final CryptographyChannelQueue _defaultInstanceForCupertino =
      CryptographyChannelQueue(
    maxConcurrentRequests: 100,

    // 100MB
    maxConcurrentSize: 100 * 1024 * 1024,
  );

  /// Default queue for Android.
  static final CryptographyChannelQueue _defaultInstanceForAndroid =
      CryptographyChannelQueue(
    maxConcurrentRequests: 100,

    // We observed crashes when this was too high (e.g. >50MB)
    // 20MB should be ok.
    maxConcurrentSize: 20 * 1024 * 1024,
  );

  /// Maximum total size of all concurrent requests.
  final int maxConcurrentSize;

  /// Maximum number of concurrent requests.
  final int maxConcurrentRequests;

  final _locks = Queue<CryptographyChannelCall>();

  var _totalSize = 0;
  var _totalRequests = 0;

  CryptographyChannelQueue({
    required this.maxConcurrentSize,
    required this.maxConcurrentRequests,
  });

  int get totalRequests => _totalRequests;

  int get totalSize => _totalSize;

  CryptographyChannelCall newLock({required int size}) {
    return CryptographyChannelCall(this, size);
  }

  static int estimateSize(Object? value, {int maxDepth = 5}) {
    maxDepth--;
    if (maxDepth < 0) {
      throw StateError('Reached maximum depth');
    }
    if (value is Uint8List) {
      return value.lengthInBytes;
    }
    if (value is String) {
      // Length is in UTF-16 code units.
      // Therefore, we multiply by 2.
      return 2 * value.length;
    }
    if (value is Iterable) {
      var sum = 0;
      for (var item in value) {
        sum += estimateSize(item, maxDepth: maxDepth);
      }
      return 64 + sum + value.length * 8;
    }
    if (value is Map) {
      var sum = 0;
      for (var item in value.keys) {
        sum += estimateSize(item, maxDepth: maxDepth);
      }
      for (var item in value.values) {
        sum += estimateSize(item, maxDepth: maxDepth);
      }
      return 64 + sum + value.length * 16;
    }
    return 8;
  }
}
