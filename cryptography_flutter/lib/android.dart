/// Helpers for Android.
library cryptography_flutter_plus.android;

import 'package:flutter/services.dart';

const MethodChannel _methodChannel = MethodChannel('cryptography_flutter');

/// Java cryptography provider in Android.
class AndroidCryptoProvider {
  final String name;
  final double version;
  final String className;
  final List<AndroidCryptoService> services;

  AndroidCryptoProvider({
    required this.name,
    required this.version,
    required this.className,
    required this.services,
  });

  static final _addedCryptoProvidersByClassName = <String, Future>{};

  /// Adds an Android Crypto Provider.
  static Future<void> add({required String className}) async {
    // Do a bit validation of the input
    if (!RegExp(r'^[a-zA-Z\d_.]+$').hasMatch(className)) {
      throw ArgumentError.value(className);
    }
    return _addedCryptoProvidersByClassName[className] ??=
        _methodChannel.invokeMethod(
      'androidCryptoProvidersAdd',
      className,
    );
  }

  /// Returns all cryptography providers in Android.
  static Future<List<AndroidCryptoProvider>> all() async {
    final result = await _methodChannel.invokeMethod(
      'androidCryptoProviders',
    ) as List;
    return result.map((e) {
      e as Map;
      return AndroidCryptoProvider(
        name: e['name'],
        className: e['className'],
        version: e['version'],
        services: (e['services'] as List).map((e) {
          e as Map;
          return AndroidCryptoService(
            type: e['type'],
            name: e['name'],
          );
        }).toList(),
      );
    }).toList();
  }

  @override
  String toString() {
    final sb = StringBuffer();
    sb.write('AndroidCryptoProvider(\n');
    sb.write('  name: "$name",\n');
    sb.write('  className: "$className",\n');
    sb.write('  version: $version,\n');
    sb.write('  services: [\n');
    for (var service in services) {
      sb.write('    $service,\n');
    }
    sb.write('  ],\n');
    sb.write(')\n');
    return sb.toString();
  }
}

/// Java cryptography service in Android.
class AndroidCryptoService {
  final String type;
  final String name;

  AndroidCryptoService({
    required this.type,
    required this.name,
  });

  @override
  String toString() => 'AndroidCryptoService(type: "$type", name: "$name")';
}
