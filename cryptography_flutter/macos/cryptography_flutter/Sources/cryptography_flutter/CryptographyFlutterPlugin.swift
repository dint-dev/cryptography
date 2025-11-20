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

import Cocoa
import CryptoKit
import FlutterMacOS

public class CryptographyFlutterPlugin: NSObject, FlutterPlugin {
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "cryptography_flutter", binaryMessenger: registrar.messenger)
        let instance = CryptographyFlutterPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }

    // ---------------------------------------------------------------------------------------------
    // IMPORTANT
    //
    // If you modify this file, copy-paste everything BELOW this comment to the following files:
    //  * ios/Classes/CryptographyFlutterPlugin.swift
    //  * macos/Classes/CryptographyFlutterPlugin.swift
    //
    // You must NOT copy-paste anything ABOVE this comment because it is different in each platform.
    // (You would see a compile-time error if you did that.)
    //
    // ---------------------------------------------------------------------------------------------

   public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard let args = call.arguments as? [String: Any] else {
            result(FlutterError(
                code: "CAUGHT_ERROR",
                message:"Invalid arguments",
                details: nil))
            return
        }
        do {
            switch call.method {
            case "encrypt":
                try self.encrypt(args: args, result:result)

            case "decrypt":
                try self.decrypt(args: args, result: result)

            case "hmac":
                try self.hmac(args: args, result: result)

            case "Ecdh.sharedSecretKey":
                try self.ecdhSharedSecretKey(args: args, result: result)

            case "Ecdh.newKeyPair":
                // ECDSA and ECDH share the same key pair
                try self.ecdsaNewKeyPair(args: args, result: result)

            case "Ecdsa.newKeyPair":
                try self.ecdsaNewKeyPair(args: args, result: result)

            case "Ecdsa.sign":
                try self.ecdsaSign(args: args, result: result)

            case "Ecdsa.verify":
                try self.ecdsaVerify(args: args, result: result)

            case "Ed25519.newKeyPair":
                try self.ed25519NewKeyPair(args: args, result: result)

            case "Ed25519.sign":
                try self.ed25519Sign(args: args, result: result)

            case "Ed25519.verify":
                try self.ed25519Verify(args: args, result: result)

            case "X25519.newKeyPair":
                try self.x25519NewKeyPair(args: args, result: result)

            case "X25519.sharedSecretKey":
                try self.x25519SharedSecretKey(args: args, result: result)

            default:
                result(FlutterMethodNotImplemented)
            }
        } catch let error as NSError {
            result(FlutterError(
                code: "CAUGHT_ERROR",
                message:"\(error.domain), \(error.code), \(error.description)",
                details: nil))
        } catch {
            result(FlutterError(
                code: "CAUGHT_ERROR",
                message:"\(error)",
                details: nil))
        }
    }

    // ---------------------------------------------------------------------------------------------
    //
    // Ciphers
    //
    // ---------------------------------------------------------------------------------------------

    private func encrypt(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            guard let algo = args["algo"] as? String else {
                result(parameterError(name: "algo"))
                return
            }
            guard let clearText = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "data"))
                return
            }
            guard let secretKey = (args["key"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "key"))
                return
            }
            guard let nonce = (args["nonce"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "nonce"))
                return
            }
            guard let aad = (args["aad"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "aad"))
                return
            }

            switch algo {
            case "AES_GCM":
                let symmetricKey = SymmetricKey(data: secretKey)
                let sealedBox = try AES.GCM.seal(
                    clearText,
                    using: symmetricKey,
                    nonce: AES.GCM.Nonce(data: nonce),
                    authenticating: aad)
                result([
                    "cipherText": FlutterStandardTypedData(bytes: sealedBox.ciphertext),
                    "mac": FlutterStandardTypedData(bytes: sealedBox.tag),
                ] as [String: Any])
                return

            case "CHACHA20_POLY1305_AEAD":
                let symmetricKey = SymmetricKey(data: secretKey)
                let sealedBox = try ChaChaPoly.seal(
                    clearText,
                    using: symmetricKey,
                    nonce: ChaChaPoly.Nonce(data: nonce),
                    authenticating: aad)
                result([
                    "cipherText": FlutterStandardTypedData(bytes: sealedBox.ciphertext),
                    "mac": FlutterStandardTypedData(bytes: sealedBox.tag),
                ] as [String: Any])
                return

            default:
                break
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func decrypt(args: [String: Any], result: @escaping FlutterResult) throws{
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            guard let algo = args["algo"] as? String else {
                result(parameterError(name: "algo"))
                return
            }
            guard let cipherText = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "data"))
                return
            }
            guard let secretKey = (args["key"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "key"))
                return
            }
            guard let nonce = (args["nonce"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "nonce"))
                return
            }
            guard let aad = (args["aad"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "aad"))
                return
            }
            guard let mac = (args["mac"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "mac"))
                return
            }

            switch algo {
            case "AES_GCM":
                let symmetricKey = SymmetricKey(data: secretKey)
                let sealedBox = try AES.GCM.SealedBox(
                    nonce: AES.GCM.Nonce(data: nonce),
                    ciphertext: cipherText,
                    tag: mac)
                do {
                    let clearText = try AES.GCM.open(
                        sealedBox,
                        using:symmetricKey,
                        authenticating: aad)
                    result([
                        "clearText": FlutterStandardTypedData(bytes: clearText),
                    ] as [String: Any])
                    return
                } catch CryptoKitError.authenticationFailure {
                    result(FlutterError(
                        code: "INCORRECT_MAC",
                        message: "",
                        details: nil
                    ))
                    return
                }

            case "CHACHA20_POLY1305_AEAD":
                let symmetricKey = SymmetricKey(data: secretKey)
                let sealedBox = try ChaChaPoly.SealedBox(
                    nonce: ChaChaPoly.Nonce(data: nonce),
                    ciphertext: cipherText,
                    tag: mac)
                do {
                    let clearText = try ChaChaPoly.open(
                        sealedBox,
                        using:symmetricKey,
                        authenticating: aad)
                    result([
                        "clearText": FlutterStandardTypedData(bytes: clearText),
                    ] as [String: Any])
                    return
                } catch CryptoKitError.authenticationFailure {
                    result(FlutterError(
                        code: "INCORRECT_MAC",
                        message: "",
                        details: nil
                    ))
                    return
                }

            default:
                break
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    // ---------------------------------------------------------------------------------------------
    //
    // HMAC
    //
    // ---------------------------------------------------------------------------------------------
    private func hmac(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
           guard let hash = args["hash"] as? String else {
                result(parameterError(name: "hash"))
                return
           }
           guard let key = (args["key"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "key"))
                return
            }
           guard let data = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "data"))
                return
            }
            switch hash {
            case "SHA-256":
                let mac = HMAC<SHA256>.authenticationCode(
                  for: data,
                  using: SymmetricKey(data: key))
                let macData = mac.withUnsafeBytes {
                    return Data(Array($0))
                }
                result([
                    "mac": FlutterStandardTypedData(bytes: macData),
                ] as [String: Any])
                return
            case "SHA-512":
                let mac = HMAC<SHA512>.authenticationCode(
                  for: data,
                  using: SymmetricKey(data: key))
                let macData = mac.withUnsafeBytes {
                    return Data(Array($0))
                }
                result([
                    "mac": FlutterStandardTypedData(bytes: macData),
                ] as [String: Any])
                return
            default:
                break;
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    // ---------------------------------------------------------------------------------------------
    //
    // ECDH
    //
    // ---------------------------------------------------------------------------------------------

    private func ecdhSharedSecretKey(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 14.0, OSX 11.0, tvOS 15.0, watchOS 8.0, *) {
           guard let curve = args["curve"] as? String else {
                result(parameterError(name: "curve"))
                return
           }
            guard let localDer = (args["localDer"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "localDer"))
                return
            }
            guard let remoteDer = (args["remoteDer"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "remoteDer"))
                return
            }
            switch curve {
            case "p256":
                let privateKey = try P256.KeyAgreement.PrivateKey(derRepresentation: localDer)
                let publicKey = try P256.KeyAgreement.PublicKey(derRepresentation: remoteDer)
                let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
                let sharedSecretData = sharedSecret.withUnsafeBytes {
                    return Data(Array($0))
                }
                result([
                    "bytes": FlutterStandardTypedData(bytes: sharedSecretData),
                ] as [String: Any])
                return
            case "p384":
                let privateKey = try P384.KeyAgreement.PrivateKey(derRepresentation: localDer)
                let publicKey = try P384.KeyAgreement.PublicKey(derRepresentation: remoteDer)
                let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
                let sharedSecretData = sharedSecret.withUnsafeBytes {
                    return Data(Array($0))
                }
                result([
                    "bytes": FlutterStandardTypedData(bytes: sharedSecretData),
                ] as [String: Any])
                return
            case "p521":
                let privateKey = try P521.KeyAgreement.PrivateKey(derRepresentation: localDer)
                let publicKey = try P521.KeyAgreement.PublicKey(derRepresentation: remoteDer)
                let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
                let sharedSecretData = sharedSecret.withUnsafeBytes {
                    return Data(Array($0))
                }
                result([
                    "bytes": FlutterStandardTypedData(bytes: sharedSecretData),
                ] as [String: Any])
                return
            default:
                break;
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    // ---------------------------------------------------------------------------------------------
    //
    // ECDSA
    //
    // ---------------------------------------------------------------------------------------------

    private func ecdsaNewKeyPair(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 14.0, OSX 11.0, tvOS 15.0, watchOS 8.0, *) {
            guard let curve = args["curve"] as? String else {
                result(parameterError(name: "curve"))
                return
            }
            // TDDO: Support this as a parameter?
            let compact = true
            let seed = (args["seed"] as? FlutterStandardTypedData)?.data
            switch curve {
            case "p256":
                var privateKey: P256.Signing.PrivateKey
                if seed == nil {
                    privateKey = P256.Signing.PrivateKey(compactRepresentable: compact)
                } else {
                    privateKey = try P256.Signing.PrivateKey(rawRepresentation: seed!)
                }
                // Unfortunately CryptoKit does not offer a way to extract d, x, y.
                // Currently we are using the DER representation as a workaround.
                result([
                    "der": FlutterStandardTypedData(bytes: privateKey.derRepresentation),
                    "publicKeyDer": FlutterStandardTypedData(bytes: privateKey.publicKey.derRepresentation),
                    "publicKeyPem": privateKey.publicKey.pemRepresentation,
                ] as [String: Any])
                return
            case "p384":
                var privateKey: P384.Signing.PrivateKey
                if seed == nil {
                    privateKey = P384.Signing.PrivateKey(compactRepresentable: compact)
                } else {
                    privateKey = try P384.Signing.PrivateKey(rawRepresentation: seed!)
                }
                // Unfortunately CryptoKit does not offer a way to extract d, x, y.
                // Currently we are using the DER representation as a workaround.
                result([
                    "der": FlutterStandardTypedData(bytes: privateKey.derRepresentation),
                    "publicKeyDer": FlutterStandardTypedData(bytes: privateKey.publicKey.derRepresentation),
                    "publicKeyPem": privateKey.publicKey.pemRepresentation,
                ] as [String: Any])
                return
            case "p521":
                var privateKey: P521.Signing.PrivateKey
                if seed == nil {
                    privateKey = P521.Signing.PrivateKey(compactRepresentable: compact)
                } else {
                    privateKey = try P521.Signing.PrivateKey(rawRepresentation: seed!)
                }
                // Unfortunately CryptoKit does not offer a way to extract d, x, y.
                // Currently we are using the DER representation as a workaround.
                result([
                    "der": FlutterStandardTypedData(bytes: privateKey.derRepresentation),
                    "publicKeyDer": FlutterStandardTypedData(bytes: privateKey.publicKey.derRepresentation),
                    "publicKeyPem": privateKey.publicKey.pemRepresentation,
                ] as [String: Any])
                return
            default:
                break;
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }


    private func ecdsaSign(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 14.0, OSX 11.0, tvOS 15.0, watchOS 8.0, *) {
            guard let curve = args["curve"] as? String else {
                result(parameterError(name: "curve"))
                return
            }
            guard let data = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "data"))
                return
            }
            guard let der = (args["der"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "der"))
                return
            }
            switch curve {
            case "p256":
                let privateKey = try P256.Signing.PrivateKey(derRepresentation: der)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ] as [String: Any])
                return
            case "p384":
                let privateKey = try P384.Signing.PrivateKey(derRepresentation: der)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ] as [String: Any])
                return
            case "p521":
                let privateKey = try P521.Signing.PrivateKey(derRepresentation: der)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ] as [String: Any])
                return
            default:
                break;
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func ecdsaVerify(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 14.0, OSX 11.0, tvOS 15.0, watchOS 8.0, *) {
            guard let curve = args["curve"] as? String else {
                result(parameterError(name: "curve"))
                return
            }
            guard let data = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "data"))
                return
            }
            guard let signatureBytes = (args["signature"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "signature"))
                return
            }
            guard let der = (args["der"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "der"))
                return
            }
            var ok = false
            switch curve {
            case "p256":
                let publicKey = try P256.Signing.PublicKey(derRepresentation: der)
                let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "result": ok,
                ] as [String: Any])
                return
            case "p384":
                let publicKey = try P384.Signing.PublicKey(derRepresentation: der)
                let signature = try P384.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "result": ok,
                ] as [String: Any])
                return
            case "p521":
                let publicKey = try P521.Signing.PublicKey(derRepresentation: der)
                let signature = try P521.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "result": ok,
                ] as [String: Any])
                return
            default:
                break
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }


    // ---------------------------------------------------------------------------------------------
    //
    // Ed25519
    //
    // ---------------------------------------------------------------------------------------------
    private func ed25519NewKeyPair(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            let privateKey = CryptoKit.Curve25519.Signing.PrivateKey()
            let publicKey = privateKey.publicKey
            result([
                "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
            ] as [String: Any])
            return
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func ed25519Sign(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            guard let data = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(FlutterError(code: "INVALID_ARGUMENT", message: "data is null", details: nil))
                return
            }
           guard let privateKeyBytes = (args["privateKey"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "privateKey"))
                return
            }
            let privateKey = try CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
            let signature = try privateKey.signature(for: data)
            result([
                "signature": FlutterStandardTypedData(bytes: signature),
            ] as [String: Any])
            return
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func ed25519Verify(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            guard let data = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "data"))
                return
            }
            guard let signature = (args["signature"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "signature"))
                return
            }
           guard let publicKeyBytes = (args["publicKey"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "publicKey"))
                return
            }
            let publicKey = try CryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: publicKeyBytes)
            let ok = publicKey.isValidSignature(signature, for: data)
            result([
                "ok": ok,
            ] as [String: Any])
            return
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }


    // ---------------------------------------------------------------------------------------------
    //
    // X25519
    //
    // ---------------------------------------------------------------------------------------------
    private func x25519NewKeyPair(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            let privateKey = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
            let publicKey = privateKey.publicKey
            result([
                "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
            ] as [String: Any])
            return
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func x25519SharedSecretKey(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
           guard let privateKeyBytes = (args["privateKey"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "privateKey"))
                return
            }
           guard let publicKeyBytes = (args["publicKey"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "publicKey"))
                return
            }
            let privateKey = try CryptoKit.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyBytes)
            let publicKey = try CryptoKit.Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyBytes)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
            let sharedSecretData = sharedSecret.withUnsafeBytes {
                return Data(Array($0))
            }
            result([
                "sharedSecretKey": FlutterStandardTypedData(bytes: sharedSecretData),
            ] as [String: Any])
            return
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func parameterError(name: String) -> FlutterError {
        return FlutterError(code: "INVALID_ARGUMENT", message: "Parameter '\(name)' is missing or invalid", details: nil)
    }
}
