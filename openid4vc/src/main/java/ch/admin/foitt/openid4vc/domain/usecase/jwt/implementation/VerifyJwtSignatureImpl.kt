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
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyType
import com.nimbusds.jose.crypto.MLDSAVerifier
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import com.nimbusds.jose.jwk.OctetKeyPair
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
    // EC and OKP are kept alongside it: issuer metadata, trust statements, and presentation
    // requests from the live swiyu Trust Infrastructure are still ES256/EdDSA-signed, so removing
    // these would make the wallet unable to verify anything it receives from a real issuer or
    // verifier today.
    private fun createVerifier(publicKey: Jwk): JWSVerifier = when (publicKey.kty) {
        KeyType.EC.value -> {
            val key = ECKey.Builder(
                Curve(checkNotNull(publicKey.crv) { "EC public key is missing the crv parameter" }),
                Base64URL(publicKey.x),
                Base64URL(checkNotNull(publicKey.y) { "EC public key is missing the y coordinate" }),
            ).build()
            ECDSAVerifier(key)
        }
        KeyType.OKP.value -> {
            val key = OctetKeyPair.Builder(
                Curve(checkNotNull(publicKey.crv) { "OKP public key is missing the crv parameter" }),
                Base64URL(publicKey.x),
            ).build()
            Ed25519Verifier(key)
        }
        "AKP" -> MLDSAVerifier(
            KeyFactory.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME).generatePublic(
                MLDSAPublicKeySpec(
                    MLDSAParameterSpec.ml_dsa_44,
                    Base64URL(checkNotNull(publicKey.pubKey) { "AKP key missing pub" }).decode(),
                    )
            )
        )
        else -> error("unsupported key type '${publicKey.kty}' for jwt signature verification")
    }
}
