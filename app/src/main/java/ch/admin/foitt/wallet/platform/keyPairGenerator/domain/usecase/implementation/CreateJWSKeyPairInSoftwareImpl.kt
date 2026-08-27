package ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWSKeyPair
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.model.KeyPairError
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.CreateJWSKeyPairInSoftware
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.inject.Inject

internal class CreateJWSKeyPairInSoftwareImpl @Inject constructor() : CreateJWSKeyPairInSoftware {

    override suspend operator fun invoke(signingAlgorithm: SigningAlgorithm) = runSuspendCatching {
        val keyId = UUID.randomUUID().toString()
        val keyPair = createKeyPairInSoftware(signingAlgorithm)

        JWSKeyPair(
            keyId = keyId,
            algorithm = signingAlgorithm,
            keyPair = keyPair,
            bindingType = KeyBindingType.SOFTWARE,
        )
    }.mapError { throwable ->
        KeyPairError.Unexpected(throwable)
    }

    private fun createKeyPairInSoftware(signingAlgorithm: SigningAlgorithm): KeyPair = when (signingAlgorithm) {
        SigningAlgorithm.ML_DSA_44 -> {
            val generator = KeyPairGenerator.getInstance(ML_DSA_44_JCA_NAME, BouncyCastleProvider.PROVIDER_NAME)
            generator.initialize(MLDSAParameterSpec.ml_dsa_44)
            generator.generateKeyPair()
        }
        SigningAlgorithm.ES256 -> {
            val generator = KeyPairGenerator.getInstance("EC")
            val spec = ECGenParameterSpec("secp256r1")
            generator.initialize(spec)
            generator.generateKeyPair()
        }
    }

    private companion object {
        private const val ML_DSA_44_JCA_NAME = "ML-DSA-44"
    }
}
