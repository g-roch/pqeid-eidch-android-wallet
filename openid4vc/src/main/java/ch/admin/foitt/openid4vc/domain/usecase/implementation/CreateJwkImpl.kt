package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.CreateJwkError
import ch.admin.foitt.openid4vc.domain.model.JwkError
import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.jwk.toEcJwk
import ch.admin.foitt.openid4vc.domain.model.toCurve
import ch.admin.foitt.openid4vc.domain.usecase.CreateJwk
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.toErrorIfNull
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.MLDSAKey
import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import javax.inject.Inject

internal class CreateJwkImpl @Inject constructor() : CreateJwk {
    override suspend fun invoke(
        keyPair: KeyPair,
        algorithm: SigningAlgorithm,
    ): Result<String, CreateJwkError> = keyPair.toJwkString(algorithm)

    private fun KeyPair.toJwkString(algorithm: SigningAlgorithm): Result<String, CreateJwkError> = runSuspendCatching {
        when (algorithm) {
            SigningAlgorithm.ML_DSA_44 -> MLDSAKey.Builder(public)
                .algorithm(JWSAlgorithm.ML_DSA_44)
                .build()
                .toJSONString()
            SigningAlgorithm.ES256 -> (public as? ECPublicKey)?.let { ecPublicKey ->
                ECKey.Builder(algorithm.toCurve(), ecPublicKey).build().toEcJwk(certificateChainBase64 = null)
                    .let { jwk -> kotlinx.serialization.json.Json.encodeToString(jwk) }
            }
        }
    }.mapError { throwable ->
        JwkError.Unexpected(throwable)
    }.toErrorIfNull {
        JwkError.UnsupportedCryptographicSuite
    }
}
