package ch.admin.foitt.openid4vc.domain.usecase.jwe.implementation

import ch.admin.foitt.openid4vc.domain.model.jwe.CreateJWEError
import ch.admin.foitt.openid4vc.domain.model.jwe.JWEError
import ch.admin.foitt.openid4vc.domain.model.jwk.Jwk
import ch.admin.foitt.openid4vc.domain.usecase.jwe.CreateJWE
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.crypto.XWingEncrypter
import com.nimbusds.jose.jwk.Curve.parse
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.jwk.XWingKey
import com.nimbusds.jose.util.Base64URL
import timber.log.Timber
import javax.inject.Inject

internal class CreateJWEImpl @Inject constructor() : CreateJWE {
    override fun invoke(
        algorithm: String,
        encryptionMethod: String,
        compressionAlgorithm: String?,
        payload: String,
        encryptionKey: Jwk
    ): Result<String, CreateJWEError> = runSuspendCatching {
        val algorithm = JWEAlgorithm.parse(algorithm)
        val encryptionMethod = EncryptionMethod.parse(encryptionMethod)

        val jweHeader = JWEHeader.Builder(algorithm, encryptionMethod)
            .keyID(encryptionKey.kid)
            .apply {
                if (compressionAlgorithm == CompressionAlgorithm.DEF.name) {
                    compressionAlgorithm(CompressionAlgorithm.DEF)
                }
            }
            .build()

        val jwePayload = Payload(payload)
        val jwe = JWEObject(jweHeader, jwePayload)

        val encrypter = when (encryptionKey.kty) {
            KeyType.EC.value -> {
                val issuerPublicKey = ECKey.Builder(
                    parse(encryptionKey.crv),
                    Base64URL.from(encryptionKey.x),
                    Base64URL.from(checkNotNull(encryptionKey.y) { "EC encryption key is missing the y coordinate" }),
                ).build()
                ECDHEncrypter(issuerPublicKey)
            }

            // X-Wing hybrid post-quantum KEM. "XWING" is the kty of the nimbus fork's
            // XWingKey JWK (raw public key in "x"); "AKP" is accepted for the raw-"pub"
            // variant this project also emits for post-quantum keys.
            XWingKey.KEY_TYPE.value, "AKP" -> {
                val rawPublicKey = encryptionKey.x ?: checkNotNull(encryptionKey.pubKey) {
                    "XWING encryption key is missing the public key (\"x\"/\"pub\")"
                }
                val issuerPublicKey = XWingKey.Builder(Base64URL.from(rawPublicKey))
                    .keyID(encryptionKey.kid)
                    .build()
                XWingEncrypter(issuerPublicKey)
            }

            else -> error("unsupported key type for jwe creation: ${encryptionKey.kty}")
        }

        jwe.encrypt(encrypter)

        jwe.serialize()
    }.mapError { throwable ->
        Timber.e(t = throwable, message = "error during jwe creation")
        JWEError.Unexpected(throwable)
    }
}
