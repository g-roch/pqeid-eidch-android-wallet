package ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWSKeyPair
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.model.KeyPairError
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.CreateJWSKeyPairInSoftware
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.inject.Inject

internal class CreateJWSKeyPairInSoftwareImpl @Inject constructor() : CreateJWSKeyPairInSoftware {

    override suspend operator fun invoke(signingAlgorithm: SigningAlgorithm) = runSuspendCatching {
        val keyId = UUID.randomUUID().toString()
        val keyPair = createKeyPairInSoftware()

        JWSKeyPair(
            keyId = keyId,
            algorithm = signingAlgorithm,
            keyPair = keyPair,
            bindingType = KeyBindingType.SOFTWARE,
        )
    }.mapError { throwable ->
        KeyPairError.Unexpected(throwable)
    }

    // NOT CHANGED — deliberately left on EC/secp256r1. Android 17's ML-DSA-65 support was
    // shipped as a AndroidKeyStore/KeyMint HAL feature (TEE/StrongBox-backed), not as an
    // addition to the default software JCA provider (Conscrypt). "ML-DSA-65" via
    // KeyPairGenerator.getInstance("ML-DSA-65") with no provider argument, or with the default
    // provider, throws NoSuchAlgorithmException on current devices. This use case is only ever
    // called for payload-encryption keys (ephemeral, ECDH-based — see CreatePayloadEncryptionKeyPairImpl),
    // which is a different primitive from ML-DSA signing anyway, so there is no in-place swap
    // here regardless of platform support. If a software-only ML-DSA-65 signing path is ever
    // needed, it requires bundling BouncyCastle's PQC provider explicitly.
    private fun createKeyPairInSoftware(): KeyPair {
        val generator = KeyPairGenerator.getInstance("EC")
        val spec = ECGenParameterSpec("secp256r1")
        generator.initialize(spec)
        return generator.generateKeyPair()
    }
}
