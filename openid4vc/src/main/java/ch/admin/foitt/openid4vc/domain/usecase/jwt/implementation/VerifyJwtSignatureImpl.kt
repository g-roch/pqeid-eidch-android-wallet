package ch.admin.foitt.openid4vc.domain.usecase.jwt.implementation

import ch.admin.foitt.openid4vc.domain.model.jwk.Jwk
import ch.admin.foitt.openid4vc.domain.model.jwt.Jwt
import ch.admin.foitt.openid4vc.domain.model.jwt.JwtError
import ch.admin.foitt.openid4vc.domain.model.jwt.VerifyJwtSignatureError
import ch.admin.foitt.openid4vc.domain.model.jwt.toVerifyJwtSignatureError
import ch.admin.foitt.openid4vc.domain.usecase.jwt.VerifyJwtSignature
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.binding
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.util.Base64URL
import javax.inject.Inject

internal class VerifyJwtSignatureImpl @Inject constructor() : VerifyJwtSignature {
    override fun invoke(jwt: Jwt, publicKey: Jwk): Result<Unit, VerifyJwtSignatureError> = binding {
        val valid = runSuspendCatching {
            val verifier = createVerifier(publicKey)
            jwt.signedJwt.verify(verifier)
        }.mapError { throwable ->
            throwable.toVerifyJwtSignatureError("jwt signature validation failed")
        }.bind()

        if (!valid) {
            return@binding Err(JwtError.InvalidJwt).bind<Unit>()
        }
    }

    // "AKP" is the placeholder key type used here for ML-DSA JWKs — the JOSE working group
    // hadn't finalized the kty/field names for ML-DSA public keys as of this codebase's last
    // update, so confirm the actual value the issuer/verifier side sends before relying on this.
    private fun createVerifier(publicKey: Jwk): JWSVerifier = when (publicKey.kty) {
        "AKP" -> MLDsaJWSVerifier(
            MLDsaJWSVerifier.publicKeyFromRawBytes(Base64URL(publicKey.x).decode())
        )
        else -> error("unsupported key type '${publicKey.kty}' for jwt signature verification")
    }
}
