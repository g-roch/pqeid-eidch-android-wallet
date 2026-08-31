package ch.admin.foitt.wallet.platform.payloadEncryption.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.KeyExchangeAlgorithm
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWEKeyPair
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.metadata.CredentialResponseEncryption
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType
import ch.admin.foitt.openid4vc.domain.model.payloadEncryption.PayloadEncryptionKeyPair
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.model.CreatePayloadEncryptionKeyPairError
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.model.toCreatePayloadEncryptionKeyPairError
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.usecase.CreatePayloadEncryptionKeyPair
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import com.nimbusds.jose.jwk.gen.XWingKeyGenerator
import java.util.UUID
import javax.inject.Inject

class CreatePayloadEncryptionKeyPairImpl @Inject constructor() : CreatePayloadEncryptionKeyPair {
    override suspend fun invoke(
        credentialResponseEncryption: CredentialResponseEncryption,
    ): Result<PayloadEncryptionKeyPair, CreatePayloadEncryptionKeyPairError> = coroutineBinding {
        // X-Wing hybrid post-quantum KEM (X25519 + ML-KEM-768). Generated in software:
        // BouncyCastle has no JCA KeyPairGenerator/keystore support for X-Wing, so the
        // key is kept as the raw XWingKey JWK (see JWEKeyPair).
        val jwk = runSuspendCatching {
            XWingKeyGenerator()
                .keyID(UUID.randomUUID().toString())
                .generate()
        }.mapError { throwable ->
            throwable.toCreatePayloadEncryptionKeyPairError()
        }.bind()

        PayloadEncryptionKeyPair(
            keyPair = JWEKeyPair(
                algorithm = KeyExchangeAlgorithm.X_WING,
                jwk = jwk,
                keyId = jwk.keyID,
                bindingType = KeyBindingType.SOFTWARE,
            ),
            alg = KeyExchangeAlgorithm.X_WING.stdName,
            enc = credentialResponseEncryption.encValuesSupported.first(),
            zip = credentialResponseEncryption.zipValuesSupported?.firstOrNull(),
        )
    }
}
