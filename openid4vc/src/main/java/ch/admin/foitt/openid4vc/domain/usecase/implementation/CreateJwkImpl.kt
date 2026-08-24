package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.CreateJwkError
import ch.admin.foitt.openid4vc.domain.model.JwkError
import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.jwk.mlDsaPublicKeyToJwk
import ch.admin.foitt.openid4vc.domain.usecase.CreateJwk
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.map
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.toErrorIfNull
import kotlinx.serialization.json.Json
import java.security.KeyPair
import javax.inject.Inject

internal class CreateJwkImpl @Inject constructor() : CreateJwk {
    override suspend fun invoke(
        keyPair: KeyPair,
        algorithm: SigningAlgorithm,
    ): Result<String, CreateJwkError> =
        keyPair.toJwkString(algorithm).map { it }

    private fun KeyPair.toJwkString(algorithm: SigningAlgorithm): Result<String, CreateJwkError> = runSuspendCatching {
        when (algorithm) {
            // public.encoded is the X.509/SubjectPublicKeyInfo encoding for an AndroidKeyStore
            // ML-DSA-65 key; per Android 17's initial docs there's no getEncoded()-shaped "raw
            // ML-DSA public key point" accessor documented yet, so this uses the standard
            // PublicKey#getEncoded() and lets the receiving party parse SPKI. Confirm this
            // matches whatever encoding issuers/verifiers actually expect once that's settled.
            SigningAlgorithm.ML_DSA_65 -> mlDsaPublicKeyToJwk(
                rawPublicKey = public.encoded,
                kid = null,
                certificateChainBase64 = null,
            )
        }
    }.mapError { throwable ->
        JwkError.Unexpected(throwable)
    }.toErrorIfNull {
        JwkError.UnsupportedCryptographicSuite
    }.map { jwk -> Json.encodeToString(jwk) }
}
