package ch.admin.foitt.wallet.platform.payloadEncryption.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.metadata.CredentialResponseEncryption
import ch.admin.foitt.openid4vc.domain.model.payloadEncryption.PayloadEncryptionKeyPair
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.JWSKeyPair
import ch.admin.foitt.openid4vc.domain.model.keyBinding.KeyBindingType
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.model.CreateJWSKeyPairError
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.model.toCreateJWSKeyPairError
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.CreateJWSKeyPairInSoftware
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.model.CreatePayloadEncryptionKeyPairError
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.model.toCreatePayloadEncryptionKeyPairError
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.usecase.CreatePayloadEncryptionKeyPair
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import com.github.michaelbull.result.coroutines.runSuspendCatching
import org.bouncycastle.jce.provider.BouncyCastleProvider
import com.nimbusds.jose.jwk.gen.XWingKeyGenerator;
import java.security.KeyPairGenerator
import javax.inject.Inject
import java.util.UUID

class CreatePayloadEncryptionKeyPairImpl @Inject constructor(
    private val createJWSKeyPairInSoftware: CreateJWSKeyPairInSoftware,
) : CreatePayloadEncryptionKeyPair {
    override suspend fun invoke(
        credentialResponseEncryption: CredentialResponseEncryption,
    ): Result<PayloadEncryptionKeyPair, CreatePayloadEncryptionKeyPairError> = coroutineBinding {

        // TODO for now sitll ES256
        /*val keyPair = createJWSKeyPairInSoftware(SigningAlgorithm.)
            .mapError(CreateJWSKeyPairError::toCreatePayloadEncryptionKeyPairError)
            .bind()

        PayloadEncryptionKeyPair(
            keyPair = keyPair,
            alg = credentialResponseEncryption.algValuesSupported.first(),
            enc = credentialResponseEncryption.encValuesSupported.first(),
            zip = credentialResponseEncryption.zipValuesSupported?.firstOrNull(),
        )*/

        /*val keyPair = runSuspendCatching {
            val generator = KeyPairGenerator.getInstance(XWING_JCA_NAME, BouncyCastleProvider.PROVIDER_NAME)
            generator.generateKeyPair()
        }.mapError ( CreateJWSKeyPairError::toCreatePayloadEncryptionKeyPairError()
            ).bind()*/

        val keyPair = XWingKeyGenerator().keyID(UUID.randomUUID().toString()).generate().toKeyPair()

        val jwsKeyPair = JWSKeyPair(
            keyId = UUID.randomUUID().toString(),
            algorithm = SigningAlgorithm.ES256, // TODO NOT actually used for signing — X-Wing key, no SigningAlgorithm exists for it
            keyPair = keyPair,
            bindingType = KeyBindingType.SOFTWARE,
        )

        PayloadEncryptionKeyPair(
            keyPair = jwsKeyPair,
            alg = credentialResponseEncryption.algValuesSupported.first(),
            enc = credentialResponseEncryption.encValuesSupported.first(),
            zip = credentialResponseEncryption.zipValuesSupported?.firstOrNull(),
        )
    }
}
