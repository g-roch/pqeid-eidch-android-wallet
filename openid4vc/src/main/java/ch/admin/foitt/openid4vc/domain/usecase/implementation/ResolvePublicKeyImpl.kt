package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.eid.didresolver.did_sidekicks.DidDoc
import ch.admin.foitt.didResolver.domain.DidResolverHelper
import ch.admin.foitt.openid4vc.domain.model.ResolveDidError
import ch.admin.foitt.openid4vc.domain.model.jwk.Jwk
import ch.admin.foitt.openid4vc.domain.model.vcSdJwt.ResolvePublicKeyError
import ch.admin.foitt.openid4vc.domain.model.vcSdJwt.VcSdJwtError
import ch.admin.foitt.openid4vc.domain.model.vcSdJwt.toResolvePublicKeyError
import ch.admin.foitt.openid4vc.domain.usecase.ResolveDid
import ch.admin.foitt.openid4vc.domain.usecase.ResolvePublicKey
import com.github.michaelbull.result.Err
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import javax.inject.Inject

internal class ResolvePublicKeyImpl @Inject constructor(
    private val didResolverHelper: DidResolverHelper,
    private val resolveDid: ResolveDid,
) : ResolvePublicKey {
    override suspend fun invoke(kid: String): Result<Jwk, ResolvePublicKeyError> = coroutineBinding {
        val did = didResolverHelper.getDidStringFromAbsoluteKeyId(kid)
            .mapError { _ -> VcSdJwtError.InvalidDid }
            .bind()

        val didDoc = resolveDid(did)
            .mapError(ResolveDidError::toResolvePublicKeyError)
            .bind()

        if (didDoc.getDeactivated()) {
            Err(VcSdJwtError.DidDocumentDeactivated).bind()
        }

        didDoc.getPublicKey(kid = kid).bind()
    }

    private fun DidDoc.getPublicKey(kid: String): Result<Jwk, VcSdJwtError.InvalidJwt> = runSuspendCatching {
        val publicKey = getKeyByMethodId(kid)
        val kty = checkNotNull(publicKey.kty)

        when (kty) {
            com.nimbusds.jose.jwk.KeyType.EC.value -> {
                val x = checkNotNull(publicKey.x)
                val y = checkNotNull(publicKey.y)
                val crv = checkNotNull(publicKey.crv)
                Jwk(kty = kty, crv = crv, x = x, y = y)
            }
            "AKP" -> {
                // ML-DSA (PQEID) — public key material is in `pubKey`, alg identifies the parameter set
                val alg = checkNotNull(publicKey.alg)
                val pubKey = checkNotNull(publicKey.pubKey)
                Jwk(kty = kty, alg = alg, pubKey = pubKey)
            }
            else -> error("Unsupported key type: $kty")
        }
    }.mapError { _ -> VcSdJwtError.InvalidJwt }
}
