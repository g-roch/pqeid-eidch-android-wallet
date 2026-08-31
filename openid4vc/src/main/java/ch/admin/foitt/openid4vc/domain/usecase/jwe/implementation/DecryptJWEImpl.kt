package ch.admin.foitt.openid4vc.domain.usecase.jwe.implementation

import ch.admin.foitt.openid4vc.domain.model.jwe.DecryptJWEError
import ch.admin.foitt.openid4vc.domain.model.jwe.JWEError
import ch.admin.foitt.openid4vc.domain.model.jwe.PayloadSizeExceededException
import ch.admin.foitt.openid4vc.domain.usecase.jwe.DecryptJWE
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import com.nimbusds.jose.JWEDecrypterOption
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.crypto.XWingDecrypter
import com.nimbusds.jose.crypto.opts.MaxCompressedCipherTextLength
import com.nimbusds.jose.jwk.XWingKey
import timber.log.Timber
import javax.inject.Inject

internal class DecryptJWEImpl @Inject constructor() : DecryptJWE {
    override fun invoke(
        jweString: String,
        xWingKey: XWingKey,
        jweMaxCompressedCipherTextLength: Int,
        jweMaxDecompressedPayloadSize: Int,
    ): Result<String, DecryptJWEError> = runSuspendCatching {
        val jwe = JWEObject.parse(jweString)

        jwe.decrypt(
            XWingDecrypter(xWingKey),
            setOf<JWEDecrypterOption>(MaxCompressedCipherTextLength(jweMaxCompressedCipherTextLength))
        )

        val payloadBytes = jwe.payload.toBytes()
        if (payloadBytes.size > jweMaxDecompressedPayloadSize) {
            throw PayloadSizeExceededException(
                "Decompressed JWE payload exceeds limit: ${payloadBytes.size} > $jweMaxDecompressedPayloadSize"
            )
        }

        jwe.payload.toString()
    }.mapError { throwable ->
        Timber.e(t = throwable, message = "Error during JWE decryption")
        when (throwable) {
            is PayloadSizeExceededException -> JWEError.PayloadSizeExceeded
            else -> JWEError.Unexpected(throwable)
        }
    }
}
