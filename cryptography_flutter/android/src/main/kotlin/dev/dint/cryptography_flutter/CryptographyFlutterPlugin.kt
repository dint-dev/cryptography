// Copyright 2019-2020 Gohilla.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dev.dint.cryptography_flutter

import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Provider
import java.security.Security
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Flutter plugin for Android cryptography helpers used by the Dart package.
 *
 * This class uses the Android embedding v2 API (FlutterPlugin + MethodChannel).
 * No v1 Registrar is used or imported anymore.
 */
class CryptographyFlutterPlugin : FlutterPlugin, MethodCallHandler {

    /** Channel used to communicate with Dart side. */
    private lateinit var channel: MethodChannel

    /**
     * Called when the plugin is attached to a FlutterEngine.
     * Sets up the MethodChannel and registers this instance as the handler.
     */
    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        // NOTE: Channel name must match the Dart side initialization.
        // The historical channel name for this plugin is "cryptography_flutter".
        channel = MethodChannel(binding.binaryMessenger, "cryptography_flutter")
        channel.setMethodCallHandler(this)
    }

    /**
     * Called when the plugin is detached from a FlutterEngine.
     * Cleans up the MethodChannel to avoid leaks.
     */
    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    /**
     * Dispatch method calls coming from Dart.
     */
    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "androidCryptoProviders" -> androidCryptoProviders(call, result)
                "androidCryptoProvidersAdd" -> androidCryptoProvidersAdd(call, result)

                // Ciphers
                "encrypt" -> encrypt(call, result)
                "decrypt" -> decrypt(call, result)

                // ECDH
                "Ecdh.newKeyPair" -> ecNewKeyPair(call, result)
                "Ecdh.sharedSecretKey" -> ecdhSharedSecretKey(call, result)

                // ECDSA
                "Ecdsa.newKeyPair" -> ecNewKeyPair(call, result)
                "Ecdsa.sign" -> ecdsaSign(call, result)
                "Ecdsa.verify" -> ecdsaVerify(call, result)

                // Ed25519 (not implemented on Android in this plugin)
                "Ed25519.newKeyPair",
                "Ed25519.sign",
                "Ed25519.verify" -> result.error("UNSUPPORTED_ALGORITHM", null, null)

                // X25519 (not implemented on Android in this plugin)
                "X25519.newKeyPair",
                "X25519.sign" /* historical name for shared secret */ ,
                "X25519.sharedSecretKey" -> result.error("UNSUPPORTED_ALGORITHM", null, null)

                // HMAC / PBKDF2
                "hmac" -> hmac(call, result)
                "pbkdf2" -> pbkdf2(call, result)

                else -> result.notImplemented()
            }
        } catch (e: Throwable) {
            result.error(
                "CAUGHT_ERROR",
                "Unexpected error $e: ${e.message}\nCause: ${e.cause}\nStack trace:\n${e.stackTraceToString()}",
                null
            )
        }
    }

    // ---------------------------------------------------------------------
    // Providers
    // ---------------------------------------------------------------------

    /** Returns a list of installed security providers and their services. */
    private fun androidCryptoProviders(call: MethodCall, result: Result) {
        val providers = Security.getProviders()
        val list = mutableListOf<Map<String, Any>>()
        for (provider in providers) {
            val resultProvider = mutableMapOf<String, Any>()
            resultProvider["name"] = provider.name
            resultProvider["info"] = provider.info
            resultProvider["version"] = provider.version
            resultProvider["className"] = provider.javaClass.name

            val resultServices = mutableListOf<Map<String, Any>>()
            for (service in provider.services) {
                resultServices.add(
                    hashMapOf(
                        "type" to service.type,
                        "name" to service.algorithm,
                    )
                )
            }
            resultProvider["services"] = resultServices
            list.add(resultProvider)
        }
        result.success(list)
    }

    /** Dynamically add a provider by class name (advanced usage). */
    private fun androidCryptoProvidersAdd(call: MethodCall, result: Result) {
        val provider = Class.forName(call.arguments as String).getConstructor().newInstance()
        Security.addProvider(provider as Provider)
        result.success(null)
    }

    // ---------------------------------------------------------------------
    // Symmetric Ciphers (AES-GCM, ChaCha20-Poly1305)
    // ---------------------------------------------------------------------

    /** Maps Dart algorithm names to Android transformation names. */
    private fun androidCipherAlgo(dartAlgo: String?): String? =
        when (dartAlgo) {
            "AES_GCM" -> "AES/GCM/NoPadding"
            "CHACHA20_POLY1305_AEAD" -> "ChaCha20/Poly1305/NoPadding"
            else -> null
        }

    /** Returns MAC length in bytes for the given AEAD algorithm. */
    private fun cipherMacLength(dartMacAlgo: String?): Int? =
        when (dartMacAlgo) {
            "AES_GCM" -> 16
            "CHACHA20_POLY1305_AEAD" -> 16
            else -> null
        }

    /** Decrypts data using AES-GCM or ChaCha20-Poly1305. */
    private fun decrypt(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")
        val androidAlgo = androidCipherAlgo(dartAlgo)
        val macLength = cipherMacLength(dartAlgo)
        if (androidAlgo == null || macLength == null) {
            result.error("UNSUPPORTED_ALGORITHM", "Unsupported algorithm $dartAlgo", null)
            return
        }

        val cipher = try {
            Cipher.getInstance(androidAlgo)
        } catch (_: Throwable) {
            result.error("UNSUPPORTED_ALGORITHM", "Your Android version does not support $androidAlgo.", null)
            return
        }

        val cipherText = call.argument<ByteArray>("data")!!
        val secretKey = call.argument<ByteArray>("key")!!
        val nonce = call.argument<ByteArray>("nonce")!!
        val aad = call.argument<ByteArray>("aad")
        val mac = call.argument<ByteArray>("mac")
        val params = if (dartAlgo == "AES_GCM") GCMParameterSpec(16 * 8, nonce) else IvParameterSpec(nonce)

        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(secretKey, androidAlgo), params)
        if (aad != null) cipher.updateAAD(aad)

        cipher.update(cipherText)
        try {
            val clearText = cipher.doFinal(mac)
            result.success(hashMapOf("clearText" to clearText))
        } catch (e: AEADBadTagException) {
            result.error("INCORRECT_MAC", "AEAD tag verification failed: ${e.message}", null)
        } catch (e: Throwable) {
            result.error("CAUGHT_ERROR", "Decrypt error for $androidAlgo: ${e.message}", null)
        }
    }

    /** Encrypts data using AES-GCM or ChaCha20-Poly1305 and splits ciphertext/MAC. */
    private fun encrypt(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")
        val androidAlgo = androidCipherAlgo(dartAlgo)
        val macLength = cipherMacLength(dartAlgo)
        if (androidAlgo == null || macLength == null) {
            result.error("UNSUPPORTED_ALGORITHM", "Unsupported algorithm $dartAlgo", null)
            return
        }

        val cipher = try {
            Cipher.getInstance(androidAlgo)
        } catch (_: Throwable) {
            result.error("UNSUPPORTED_ALGORITHM", "Your Android version does not support $androidAlgo.", null)
            return
        }

        val clearText = call.argument<ByteArray>("data")!!
        val secretKey = call.argument<ByteArray>("key")!!
        val nonce = call.argument<ByteArray>("nonce")!!
        val aad = call.argument<ByteArray>("aad")

        val params = if (dartAlgo == "AES_GCM") GCMParameterSpec(macLength * 8, nonce) else IvParameterSpec(nonce)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(secretKey, androidAlgo), params)
        if (aad != null) cipher.updateAAD(aad)

        val cipherTextAndMac = cipher.doFinal(clearText)
        val cipherTextEnd = cipherTextAndMac.size - macLength
        val cipherText = cipherTextAndMac.copyOfRange(0, cipherTextEnd)
        val mac = cipherTextAndMac.copyOfRange(cipherTextEnd, cipherTextAndMac.size)
        result.success(hashMapOf("cipherText" to cipherText, "mac" to mac))
    }

    // ---------------------------------------------------------------------
    // ECDH / ECDSA
    // ---------------------------------------------------------------------

    /** Generates a new EC key pair for the requested curve. */
    private fun ecNewKeyPair(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("curve")!!
        val curve = when (dartAlgo) {
            "p256" -> "prime256v1"
            "p384" -> "secp384r1"
            "p521" -> "secp521r1"
            else -> null
        } ?: run {
            result.error("UNSUPPORTED_ALGORITHM", null, null); return
        }

        val provider = call.argument<String>("androidProvider")
        val generator = if (provider == null) KeyPairGenerator.getInstance("EC")
        else KeyPairGenerator.getInstance("EC", provider)

        generator.initialize(ECGenParameterSpec(curve))
        val keyPair = generator.generateKeyPair()
        val privateKey = keyPair.private as ECPrivateKey
        val publicKey = keyPair.public as ECPublicKey

        result.success(
            hashMapOf(
                "d" to privateKey.s.toByteArray(),
                "x" to publicKey.w.affineX.toByteArray(),
                "y" to publicKey.w.affineY.toByteArray(),
            )
        )
    }

    /** Computes an ECDH shared secret from local private and remote public keys. */
    private fun ecdhSharedSecretKey(call: MethodCall, result: Result) {
        val dartCurve = call.argument<String>("curve")!!
        val curve = when (dartCurve) {
            "p256" -> "prime256v1"
            "p384" -> "secp384r1"
            "p521" -> "secp521r1"
            else -> null
        } ?: run {
            result.error("UNSUPPORTED_ALGORITHM", null, null); return
        }

        val d = call.argument<ByteArray>("localD")!!
        val remoteX = call.argument<ByteArray>("remoteX")!!
        val remoteY = call.argument<ByteArray>("remoteY")!!
        val provider = call.argument<String>("androidProvider")

        val parameters = if (provider == null) AlgorithmParameters.getInstance("EC")
        else AlgorithmParameters.getInstance("EC", provider)
        parameters.init(ECGenParameterSpec(curve))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)

        val privateKeySpec = ECPrivateKeySpec(BigInteger(d), ecParameters)
        val remotePublicPoint = ECPoint(BigInteger(remoteX), BigInteger(remoteY))
        val remotePublicKeySpec = ECPublicKeySpec(remotePublicPoint, ecParameters)

        val keyFactory = if (provider == null) KeyFactory.getInstance("EC")
        else KeyFactory.getInstance("EC", provider)
        val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey
        val remotePublicKey = keyFactory.generatePublic(remotePublicKeySpec) as ECPublicKey

        val keyAgreement = if (provider == null) KeyAgreement.getInstance("ECDH")
        else KeyAgreement.getInstance("ECDH", provider)
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(remotePublicKey, true)
        val secretKey = keyAgreement.generateSecret()
        result.success(hashMapOf("bytes" to secretKey))
    }

    /** Signs a message with an EC private key (ECDSA). */
    private fun ecdsaSign(call: MethodCall, result: Result) {
        val dartCurve = call.argument<String>("curve")!!
        val curve = when (dartCurve) {
            "p256" -> "prime256v1"
            "p384" -> "secp384r1"
            "p521" -> "secp521r1"
            else -> null
        } ?: run {
            result.error("UNSUPPORTED_ALGORITHM", null, null); return
        }
        val signatureName = when (dartCurve) {
            "p256" -> "SHA256withECDSA"
            "p384" -> "SHA384withECDSA"
            "p521" -> "SHA512withECDSA"
            else -> null
        }!!

        val message = call.argument<ByteArray>("data")!!
        val d = call.argument<ByteArray>("d")!!
        val provider = call.argument<String>("androidProvider")

        val parameters = if (provider == null) AlgorithmParameters.getInstance("EC")
        else AlgorithmParameters.getInstance("EC", provider)
        parameters.init(ECGenParameterSpec(curve))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
        val privateKeySpec = ECPrivateKeySpec(BigInteger(d), ecParameters)

        val keyFactory = if (provider == null) KeyFactory.getInstance("EC")
        else KeyFactory.getInstance("EC", provider)
        val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

        val signature = if (provider == null) Signature.getInstance(signatureName)
        else Signature.getInstance(signatureName, provider)
        signature.initSign(privateKey)
        signature.update(message)
        val signatureBytes = signature.sign()
        result.success(hashMapOf("signature" to signatureBytes))
    }

    /** Verifies an ECDSA signature with a public key (x,y). */
    private fun ecdsaVerify(call: MethodCall, result: Result) {
        val dartCurve = call.argument<String>("curve")!!
        val curve = when (dartCurve) {
            "p256" -> "secp256r1"
            "p384" -> "secp384r1"
            "p521" -> "secp521r1"
            else -> null
        } ?: run {
            result.error("UNSUPPORTED_ALGORITHM", null, null); return
        }
        val signatureName = when (dartCurve) {
            "p256" -> "SHA256withECDSA"
            "p384" -> "SHA384withECDSA"
            "p521" -> "SHA512withECDSA"
            else -> null
        }!!

        val message = call.argument<ByteArray>("data")!!
        val x = BigInteger(call.argument<ByteArray>("x")!!)
        val y = BigInteger(call.argument<ByteArray>("y")!!)
        val verifiedSignatureBytes = call.argument<ByteArray>("signature")!!
        val provider = call.argument<String>("androidProvider")

        val parameters = if (provider == null) AlgorithmParameters.getInstance("EC")
        else AlgorithmParameters.getInstance("EC", provider)
        parameters.init(ECGenParameterSpec(curve))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)

        val publicKeyPoint = ECPoint(x, y)
        val publicKeySpec = ECPublicKeySpec(publicKeyPoint, ecParameters)

        val keyFactory = if (provider == null) KeyFactory.getInstance("EC")
        else KeyFactory.getInstance("EC", provider)
        val publicKey = keyFactory.generatePublic(publicKeySpec) as ECPublicKey

        val signature = if (provider == null) Signature.getInstance(signatureName)
        else Signature.getInstance(signatureName, provider)
        signature.initVerify(publicKey)
        signature.update(message)
        val ok = signature.verify(verifiedSignatureBytes)
        result.success(hashMapOf("result" to ok))
    }

    // ---------------------------------------------------------------------
    // HMAC / PBKDF2
    // ---------------------------------------------------------------------

    /** Computes HMAC using one of SHA-1/224/256/384/512. */
    private fun hmac(call: MethodCall, result: Result) {
        val hash = call.argument<String>("hash")!!
        val instanceId = when (hash) {
            "SHA-1" -> "HmacSHA1"
            "SHA-224" -> "HmacSHA224"
            "SHA-256" -> "HmacSHA256"
            "SHA-384" -> "HmacSHA384"
            "SHA-512" -> "HmacSHA512"
            else -> null
        } ?: run {
            result.error("UNSUPPORTED_ALGORITHM", null, null); return
        }
        val key = call.argument<ByteArray>("key")!!
        val data = call.argument<ByteArray>("data")!!
        val instance = Mac.getInstance(instanceId)
        instance.init(SecretKeySpec(key, instanceId))
        val mac = instance.doFinal(data)
        result.success(hashMapOf("mac" to mac))
    }

    /** Computes PBKDF2 with HMAC-* (SHA1/224/256/384/512). */
    private fun pbkdf2(call: MethodCall, result: Result) {
        val mac = call.argument<String>("mac")!!
        val instanceId = when (mac) {
            "HMAC-SHA1" -> "PBKDF2WithHmacSHA1"
            "HMAC-SHA224" -> "PBKDF2WithHmacSHA224"
            "HMAC-SHA256" -> "PBKDF2WithHmacSHA256"
            "HMAC-SHA384" -> "PBKDF2WithHmacSHA384"
            "HMAC-SHA512" -> "PBKDF2WithHmacSHA512"
            else -> null
        } ?: run {
            result.error("UNSUPPORTED_ALGORITHM", null, null); return
        }
        val bits = call.argument<Int>("bits")!!
        val iterations = call.argument<Int>("iterations")!!
        val password = call.argument<String>("password")!!
        val nonce = call.argument<ByteArray>("nonce")!!

        val secretKeyFactory = try {
            SecretKeyFactory.getInstance(instanceId)
        } catch (_: Throwable) {
            result.error("UNSUPPORTED_ALGORITHM", null, null); return
        }

        val secretKey = secretKeyFactory.generateSecret(
            PBEKeySpec(password.toCharArray(), nonce, iterations, bits)
        )
        result.success(hashMapOf("hash" to secretKey.encoded))
    }
}
