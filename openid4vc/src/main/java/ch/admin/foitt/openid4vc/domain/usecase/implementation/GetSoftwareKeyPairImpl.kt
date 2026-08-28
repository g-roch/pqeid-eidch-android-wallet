package ch.admin.foitt.openid4vc.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.GetSoftwareKeyPairError
import ch.admin.foitt.openid4vc.domain.model.KeyPairError
import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.usecase.GetSoftwareKeyPair
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.inject.Inject

internal class GetSoftwareKeyPairImpl @Inject constructor() : GetSoftwareKeyPair {
    override suspend fun invoke(
        algorithm: SigningAlgorithm,
        publicKeyBytes: ByteArray,
        privateKeyBytes: ByteArray,
    ): Result<KeyPair, GetSoftwareKeyPairError> = runSuspendCatching {
        // The keys were persisted as X.509 (public) / PKCS#8 (private) `.encoded` bytes by
        // CreateJWSKeyPairInSoftwareImpl, so the matching KeyFactory rebuilds them. ML-DSA has
        // no JDK KeyFactory — it is only available through BouncyCastle.
        val keyFactory = when (algorithm) {
            SigningAlgorithm.ML_DSA_44 ->
                KeyFactory.getInstance(ML_DSA_JCA_NAME, BouncyCastleProvider.PROVIDER_NAME)
            SigningAlgorithm.ES256 ->
                KeyFactory.getInstance("EC")
        }

        val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
        val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

        KeyPair(publicKey, privateKey)
    }.mapError { throwable ->
        KeyPairError.Unexpected(throwable)
    }

    private companion object {
        private const val ML_DSA_JCA_NAME = "ML-DSA"
    }
}
