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
                ])

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
                ])

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
                    ])
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
                    ])
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

    private func ecdsaNewKeyPair(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            guard let curve = args["curve"] as? String else {
                result(parameterError(name: "curve"))
                return
            }
            guard let seed = (args["seed"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "seed"))
                return
            }
            switch curve {
            case "p256":
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: seed)
                let publicKey = privateKey.publicKey
                result([
                    "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                    "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
                    "publicKeyCompact": FlutterStandardTypedData(bytes: publicKey.compactRepresentation!),
                ])
                return
            case "p384":
                let privateKey = try P384.Signing.PrivateKey(rawRepresentation: seed)
                let publicKey = privateKey.publicKey
                result([
                    "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                    "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
                    "publicKeyCompact": FlutterStandardTypedData(bytes: publicKey.compactRepresentation!),
                ])
                return
            case "p521":
                let privateKey = try P521.Signing.PrivateKey(rawRepresentation: seed)
                let publicKey = privateKey.publicKey
                result([
                    "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                    "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
                    "publicKeyCompact": FlutterStandardTypedData(bytes: publicKey.compactRepresentation!),
                ])
                return
            default:
                break;
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }


    private func ecdsaSign(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            guard let curve = args["curve"] as? String else {
                result(parameterError(name: "curve"))
                return
            }
            guard let data = (args["data"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "data"))
                return
            }
            guard let privateKeyBytes = (args["privateKey"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "privateKey"))
                return
            }
            switch curve {
            case "p256":
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ])
                return
            case "p384":
                let privateKey = try P384.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ])
                return
            case "p521":
                let privateKey = try P521.Signing.PrivateKey(rawRepresentation: privateKeyBytes)
                let signature = try privateKey.signature(for: data)
                result([
                    "signature": FlutterStandardTypedData(bytes: signature.rawRepresentation),
                ])
                return
            default:
                break;
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func ecdsaVerify(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
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
            guard let publicKeyBytes = (args["publicKey"] as? FlutterStandardTypedData)?.data else {
                result(parameterError(name: "publicKey"))
                return
            }
            var ok = false
            switch curve {
            case "p256":
                let publicKey = try P256.Signing.PublicKey(rawRepresentation: publicKeyBytes)
                let signature = try P256.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "ok": ok,
                ])
                return
            case "p384":
                let publicKey = try P384.Signing.PublicKey(rawRepresentation: publicKeyBytes)
                let signature = try P384.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "ok": ok,
                ])
                return
            case "p521":
                let publicKey = try P521.Signing.PublicKey(rawRepresentation: publicKeyBytes)
                let signature = try P521.Signing.ECDSASignature(rawRepresentation: signatureBytes)
                ok = publicKey.isValidSignature(signature, for: data)
                result([
                    "ok": ok,
                ])
                return
            default:
                break
            }
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func ed25519NewKeyPair(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            let privateKey = CryptoKit.Curve25519.Signing.PrivateKey()
            let publicKey = privateKey.publicKey
            result([
                "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
            ])
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
            ])
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
            ])
            return
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func x25519NewKeyPair(args: [String: Any], result: @escaping FlutterResult) throws {
        if #available(iOS 13.0, OSX 10.15, tvOS 15.0, watchOS 8.0, *) {
            let privateKey = CryptoKit.Curve25519.KeyAgreement.PrivateKey()
            let publicKey = privateKey.publicKey
            result([
                "privateKey": FlutterStandardTypedData(bytes: privateKey.rawRepresentation),
                "publicKey": FlutterStandardTypedData(bytes: publicKey.rawRepresentation),
            ])
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
            ])
            return
        }
        result(FlutterError(code: "UNSUPPORTED_ALGORITHM", message:nil, details: nil))
    }

    private func parameterError(name: String) -> FlutterError {
        return FlutterError(code: "INVALID_ARGUMENT", message: "\(name) is invalid", details: nil)
    }
}
