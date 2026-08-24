package ch.admin.foitt.openid4vc.domain.usecase.jwt.implementation

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.jca.JCAContext
import com.nimbusds.jose.util.Base64URL
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature

/**
 * Nimbus [JWSVerifier] for ML-DSA-65 public keys.
 *
 * Unlike [MLDsaJWSSigner], this deliberately does NOT go through `AndroidKeyStore`: verification
 * only ever touches a *public* key received from a third party (issuer/verifier), so there's no
 * hardware-backing benefit to gate this behind, and — per Android 17's initial documentation —
 * KeyFactory/Signature for "ML-DSA-65" are exposed through the AndroidKeyStore provider for keys
 * generated in that store, not confirmed as a general-purpose import path for arbitrary raw
 * public key bytes from a JWK. BouncyCastle's software ML-DSA implementation is used here
 * instead, which is the same trust model Nimbus already uses for its own signature verifiers.
 *
 * Requires `org.bouncycastle:bcprov-jdk18on` (or `bc-fips`) on the classpath, with
 * `BouncyCastleProvider` registered once at process start.
 */
class MLDsaJWSVerifier(private val publicKey: PublicKey) : JWSVerifier {

    private val jcaContext = JCAContext()

    override fun supportedJWSAlgorithms(): Set<JWSAlgorithm> = MLDsaJWSSigner.SUPPORTED_ALGORITHMS
    override fun getJCAContext(): JCAContext = jcaContext

    override fun verify(header: JWSHeader, signingInput: ByteArray, signature: Base64URL): Boolean {
        if (header.algorithm !in supportedJWSAlgorithms()) return false
        return Signature.getInstance("ML-DSA-65", BouncyCastleProvider.PROVIDER_NAME).apply {
            initVerify(publicKey)
            update(signingInput)
        }.verify(signature.decode())
    }

    companion object {
        /**
         * Builds an ML-DSA-65 [PublicKey] from raw key bytes (e.g. the decoded "x" value of a
         * JWK). The final JOSE "kty"/"crv" naming for ML-DSA JWKs isn't settled yet
         * (draft-ietf-jose-pqc-kem / draft-ietf-cose-dilithium are still in progress) — confirm
         * the actual field names against whatever the issuing party sends before wiring this
         * into VerifyJwtSignatureImpl.
         */
        fun publicKeyFromRawBytes(rawKey: ByteArray): PublicKey =
            KeyFactory.getInstance("ML-DSA", BouncyCastleProvider.PROVIDER_NAME)
                .generatePublic(MLDSAPublicKeySpec(MLDSAParameterSpec.ml_dsa_65, rawKey))
    }
}
