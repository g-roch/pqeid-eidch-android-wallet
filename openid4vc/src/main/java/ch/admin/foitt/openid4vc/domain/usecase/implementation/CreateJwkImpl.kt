package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.CreateJwkError
import ch.admin.foitt.openid4vc.domain.model.JwkError
import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.jwk.mlDsaPublicKeyToJwk
import ch.admin.foitt.openid4vc.domain.model.jwk.toEcJwk
import ch.admin.foitt.openid4vc.domain.model.toCurve
import ch.admin.foitt.openid4vc.domain.usecase.CreateJwk
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.map
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.toErrorIfNull
import com.nimbusds.jose.jwk.ECKey
import kotlinx.serialization.json.Json
import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import javax.inject.Inject

internal class CreateJwkImpl @Inject constructor() : CreateJwk {
    override suspend fun invoke(
        keyPair: KeyPair,
        algorithm: SigningAlgorithm,
    ): Result<String, CreateJwkError> =
        keyPair.toJwkString(algorithm).map { it }

    private fun KeyPair.toJwkString(algorithm: SigningAlgorithm): Result<String, CreateJwkError> = runSuspendCatching {
        when (algorithm) {
            SigningAlgorithm.ML_DSA_44 -> mlDsaPublicKeyToJwk(
                rawPublicKey = public.encoded,
                kid = null,
                certificateChainBase64 = null,
            )
            SigningAlgorithm.ES256 -> (public as? ECPublicKey)?.let { ecPublicKey ->
                ECKey.Builder(algorithm.toCurve(), ecPublicKey).build().toEcJwk(certificateChainBase64 = null)
            }
        }
    }.mapError { throwable ->
        JwkError.Unexpected(throwable)
    }.toErrorIfNull {
        JwkError.UnsupportedCryptographicSuite
    }.map { jwk -> Json.encodeToString(jwk) }
}
