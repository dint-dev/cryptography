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

package dev.dint.cryptography_flutter

import android.os.Build
import androidx.annotation.RequiresApi
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.math.BigInteger
import java.security.*
import java.security.interfaces.*
import java.security.spec.*
import javax.crypto.*
import javax.crypto.spec.*

/** CryptographyFlutterPlugin */
class CryptographyFlutterPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "cryptography_flutter")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        try {
            when (call.method) {
                "androidCryptoProviders" -> androidCryptoProviders(call, result)
                "androidCryptoProvidersAdd" -> androidCryptoProvidersAdd(call, result)

                // Ciphers
                "encrypt" -> encrypt(call, result)
                "decrypt" -> decrypt(call, result)

                // Ecdh
                "Ecdh.newKeyPair" -> ecNewKeyPair(call, result)
                "Ecdh.sharedSecretKey" -> ecdhSharedSecretKey(call, result)

                // Ecdsa
                "Ecdsa.newKeyPair" -> ecNewKeyPair(call, result)
                "Ecdsa.sign" -> ecdsaSign(call, result)
                "Ecdsa.verify" -> ecdsaVerify(call, result)

                // Ed25519
                "Ed25519.newKeyPair" -> ed25519NewKeyPair(call, result)
                "Ed25519.sign" -> ed25519Sign(call, result)
                "Ed25519.verify" -> ed25519Verify(call, result)

                // X25519
                "X25519.newKeyPair" -> x25519NewKeyPair(call, result)
                "X25519.sign" -> x25519SharedSecretKey(call, result)

                // Other
                "hmac" -> hmac(call, result)
                "pbkdf2" -> pbkdf2(call, result)
                else -> {
                    result.notImplemented()
                }
            }
        } catch (e: Throwable) {
            result.error(
                "CAUGHT_ERROR",
                "Unexpected error ${e}: ${e.message}\nCause: ${e.cause}\nStack stace:\n${e.stackTraceToString()}",
                null
            )
        }
    }

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


    private fun androidCryptoProvidersAdd(call: MethodCall, result: Result) {
        val provider = Class.forName(call.arguments as String).getConstructor().newInstance()
        Security.addProvider(provider as Provider)
    }

    private fun androidCipherAlgo(dartAlgo: String?): String? {
        return when (dartAlgo) {
            "AES_GCM" -> "AES/GCM/NoPadding"
            "CHACHA20_POLY1305_AEAD" -> "ChaCha20/Poly1305/NoPadding"
            else -> null
        }
    }

    private fun cipherMacLength(dartMacAlgo: String?): Int? {
        return when (dartMacAlgo) {
            "AES_GCM" -> 16
            "CHACHA20_POLY1305_AEAD" -> 16
            else -> null
        }
    }

    private fun decrypt(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")
        val androidAlgo = androidCipherAlgo(dartAlgo)
        val macLength = cipherMacLength(dartAlgo)
        if (androidAlgo == null || macLength == null) {
            result.error(
                "UNSUPPORTED_ALGORITHM",
                "cryptography_flutter does not support algorithm ${dartAlgo} in Android.",
                null
            )
            return
        }
        var cipher: Cipher;
        try {
            cipher = Cipher.getInstance(androidAlgo)
        } catch (error: NoSuchAlgorithmException) {
            result.error(
                "UNSUPPORTED_ALGORITHM",
                "Your version of Android does not support ${androidAlgo}.",
                null
            )
            return
        }

        val cipherText = call.argument<ByteArray>("data")!!
        val secretKey = call.argument<ByteArray>("key")!!
        val nonce = call.argument<ByteArray>("nonce")!!
        val aad = call.argument<ByteArray>("aad")
        var mac = call.argument<ByteArray>("mac")
        val params = if (dartAlgo == "AES_GCM") {
            GCMParameterSpec(16 * 8, nonce)
        } else {
            IvParameterSpec(nonce)
        }
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(secretKey, androidAlgo),
            params,
        )

        // AAD
        if (aad != null) {
            cipher.updateAAD(aad)
        }

        cipher.update(cipherText)
        try {
            val clearText = cipher.doFinal(mac)
            result.success(
                hashMapOf(
                    "clearText" to clearText,
                )
            )
        } catch (e: AEADBadTagException) {
            result.error(
                "INCORRECT_MAC",
                "Caught error when decrypting ${androidAlgo}: ${e.message}",
                null
            )
        } catch (e: BadPaddingException) {
            result.error(
                "INCORRECT_PADDING",
                "Caught error when decrypting ${androidAlgo}: ${e.message}",
                null
            )
        } catch (e: Throwable) {
            result.error(
                "CAUGHT_ERROR",
                "Caught error when decrypting ${androidAlgo}: ${e.message}",
                null
            )
        }
    }

    private fun encrypt(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("algo")
        val androidAlgo = androidCipherAlgo(dartAlgo)
        val macLength = cipherMacLength(dartAlgo)
        if (androidAlgo == null || macLength == null) {
            result.error(
                "UNSUPPORTED_ALGORITHM",
                "cryptography_flutter does not support algorithm ${dartAlgo} in Android.",
                null
            )
            return
        }
        var cipher: Cipher;
        try {
            cipher = Cipher.getInstance(androidAlgo)
        } catch (error: NoSuchAlgorithmException) {
            result.error(
                "UNSUPPORTED_ALGORITHM",
                "Your version of Android does not support ${androidAlgo}.",
                null
            )
            return
        }

        val clearText = call.argument<ByteArray>("data")!!
        val secretKey = call.argument<ByteArray>("key")
        val nonce = call.argument<ByteArray>("nonce")
        val aad = call.argument<ByteArray>("aad")
        val dartMacAlgo = call.argument<String>("macAlgo")

        val params = if (dartAlgo == "AES_GCM") {
            GCMParameterSpec(macLength * 8, nonce)
        } else {
            IvParameterSpec(nonce)
        }
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(secretKey, androidAlgo),
            params,
        )

        // AAD
        if (aad != null) {
            cipher.updateAAD(aad)
        }
        val cipherTextAndMac = cipher.doFinal(clearText)
        val cipherTextEnd = cipherTextAndMac.size - macLength
        val cipherText = cipherTextAndMac.copyOfRange(0, cipherTextEnd)
        val mac = cipherTextAndMac.copyOfRange(cipherTextEnd, cipherTextAndMac.size)
        result.success(
            hashMapOf(
                "cipherText" to cipherText,
                "mac" to mac,
            )
        )
    }

    //
    // ECDH
    //
    private fun ecNewKeyPair(call: MethodCall, result: Result) {
        val dartAlgo = call.argument<String>("curve")!!
        val curve = when (dartAlgo) {
            "p256" -> "prime256v1"
            "p384" -> "secp384r1"
            "p521" -> "secp521r1"
            else -> null
        }
        if (curve == null) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
        }
        val provider = call.argument<String>("androidProvider")
        val generator = when (provider) {
            null -> KeyPairGenerator.getInstance("EC")
            else -> KeyPairGenerator.getInstance("EC", provider)
        }
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

    private fun ecdhSharedSecretKey(call: MethodCall, result: Result) {
        val dartCurve = call.argument<String>("curve")!!
        val curve = when (dartCurve) {
            "p256" -> "prime256v1"
            "p384" -> "secp384r1"
            "p521" -> "secp521r1"
            else -> null
        }
        if (curve == null) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
        }
        val d = call.argument<ByteArray>("localD")!!
        val x = call.argument<ByteArray>("localX")!!
        val y = call.argument<ByteArray>("localY")!!
        val provider = call.argument<String>("androidProvider")

        val parameters = when (provider) {
            null -> AlgorithmParameters.getInstance("EC")
            else -> AlgorithmParameters.getInstance("EC", provider)
        }
        parameters.init(ECGenParameterSpec(curve))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
        val privateKeySpec = ECPrivateKeySpec(
            BigInteger(d),
            ecParameters
        )

        val remoteX = call.argument<ByteArray>("remoteX")!!
        val remoteY = call.argument<ByteArray>("remoteY")!!
        val remotePublicPoint = ECPoint(BigInteger(remoteX), BigInteger(remoteY))
        val remotePublicKeySpec = ECPublicKeySpec(remotePublicPoint, ecParameters)

        val keyFactory = when (provider) {
            null -> KeyFactory.getInstance("EC")
            else -> KeyFactory.getInstance("EC", provider)
        }
        val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey
        val remotePublicKey = keyFactory.generatePublic(remotePublicKeySpec) as ECPublicKey

        val keyAgreement = when (provider) {
            null -> KeyAgreement.getInstance("ECDH")
            else -> KeyAgreement.getInstance("ECDH", provider)
        }
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(remotePublicKey, true)
        val secretKey = keyAgreement.generateSecret()
        result.success(
            hashMapOf(
                "bytes" to secretKey,
            )
        )
    }

    //
    // ECDSA
    //
    private fun ecdsaSign(call: MethodCall, result: Result) {
        val dartCurve = call.argument<String>("curve")!!
        val curve = when (dartCurve) {
            "p256" -> "prime256v1"
            "p384" -> "secp384r1"
            "p521" -> "secp521r1"
            else -> null
        }
        if (curve == null) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
        }
        val signatureName = when (dartCurve) {
            "p256" -> "SHA256withECDSA"
            "p384" -> "SHA384withECDSA"
            "p521" -> "SHA512withECDSA"
            else -> null
        }!!

        val message = call.argument<ByteArray>("data")!!
        val d = call.argument<ByteArray>("d")!!
        val x = call.argument<ByteArray>("x")!!
        val y = call.argument<ByteArray>("y")!!
        val provider = call.argument<String>("androidProvider")

        val parameters = when (provider) {
            null -> AlgorithmParameters.getInstance("EC")
            else -> AlgorithmParameters.getInstance("EC", provider)
        }
        parameters.init(ECGenParameterSpec(curve))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)
        val privateKeySpec = ECPrivateKeySpec(
            BigInteger(d),
            ecParameters
        )

        val keyFactory = when (provider) {
            null -> KeyFactory.getInstance("EC")
            else -> KeyFactory.getInstance("EC", provider)
        }
        val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

        val signature = when (provider) {
            null -> Signature.getInstance(signatureName)
            else -> Signature.getInstance(signatureName, provider)
        }
        signature.initSign(privateKey)
        signature.update(message)
        val signatureBytes = signature.sign()
        result.success(
            hashMapOf(
                "signature" to signatureBytes,
            )
        )
    }

    private fun ecdsaVerify(call: MethodCall, result: Result) {
        val dartCurve = call.argument<String>("curve")!!
        val curve = when (dartCurve) {
            "p256" -> "secp256r1"
            "p384" -> "secp384r1"
            "p521" -> "secp521r1"
            else -> null
        }
        if (curve == null) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
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

        val parameters = when (provider) {
            null -> AlgorithmParameters.getInstance("EC")
            else -> AlgorithmParameters.getInstance("EC", provider)
        }
        parameters.init(ECGenParameterSpec(curve))
        val ecParameters = parameters.getParameterSpec(ECParameterSpec::class.java)

        val publicKeyPoint = ECPoint(x, y)
        val publicKeySpec = ECPublicKeySpec(publicKeyPoint, ecParameters)

        val keyFactory = when (provider) {
            null -> KeyFactory.getInstance("EC")
            else -> KeyFactory.getInstance("EC", provider)
        }
        val publicKey = keyFactory.generatePublic(publicKeySpec) as ECPublicKey

        val signature = when (provider) {
            null -> Signature.getInstance(signatureName)
            else -> Signature.getInstance(signatureName, provider)
        }
        signature.initVerify(publicKey)
        signature.update(message)
        val ok = signature.verify(verifiedSignatureBytes)
        result.success(
            hashMapOf(
                "result" to ok,
            )
        )
    }

    //
    // ED25519
    //
    private fun ed25519NewKeyPair(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun ed25519Sign(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun ed25519Verify(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    //
    // X25519
    //
    private fun x25519NewKeyPair(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    private fun x25519SharedSecretKey(call: MethodCall, result: Result) {
        result.error("UNSUPPORTED_ALGORITHM", null, null)
    }

    //
    // HMAC
    //
    private fun hmac(call: MethodCall, result: Result) {
        val hash = call.argument<String>("hash")!!
        val instanceId = when (hash) {
            "SHA-1" -> "HmacSHA1"
            "SHA-224" -> "HmacSHA224"
            "SHA-256" -> "HmacSHA256"
            "SHA-384" -> "HmacSHA384"
            "SHA-512" -> "HmacSHA512"
            else -> null
        }
        if (instanceId == null) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
        }
        val key = call.argument<ByteArray>("key")!!
        val data = call.argument<ByteArray>("data")!!
        val instance = Mac.getInstance(instanceId);
        instance.init(SecretKeySpec(key, instanceId));
        val mac = instance.doFinal(data);
        result.success(
            hashMapOf(
                "mac" to mac,
            )
        )
    }

    //
    // PBKDF2
    //
    private fun pbkdf2(call: MethodCall, result: Result) {
        val mac = call.argument<String>("mac")!!
        val instanceId = when (mac) {
            "HMAC-SHA1" -> "PBKDF2WithHmacSHA1"
            "HMAC-SHA224" -> "PBKDF2WithHmacSHA224"
            "HMAC-SHA256" -> "PBKDF2WithHmacSHA256"
            "HMAC-SHA384" -> "PBKDF2WithHmacSHA384"
            "HMAC-SHA512" -> "PBKDF2WithHmacSHA512"
            else -> null
        }
        if (instanceId==null) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
        }
        val bits = call.argument<Int>("bits")!!
        val iterations = call.argument<Int>("iterations")!!
        val password = call.argument<String>("password")!!
        val nonce = call.argument<ByteArray>("nonce")!!
        var secretKeyFactory: SecretKeyFactory
        try {
            secretKeyFactory = SecretKeyFactory.getInstance(instanceId)
        } catch (e: NoSuchAlgorithmException) {
            result.error("UNSUPPORTED_ALGORITHM", null, null)
            return
        }
        val secretKey = secretKeyFactory.generateSecret(
            PBEKeySpec(
                password.toCharArray(),
                nonce,
                iterations,
                bits
            )
        )
        result.success(
            hashMapOf(
                "hash" to secretKey.getEncoded(),
            )
        )
    }
}
