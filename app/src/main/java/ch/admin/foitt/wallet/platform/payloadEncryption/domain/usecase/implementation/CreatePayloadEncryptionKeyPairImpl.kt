package ch.admin.foitt.wallet.platform.payloadEncryption.domain.usecase.implementation

import ch.admin.foitt.openid4vc.domain.model.SigningAlgorithm
import ch.admin.foitt.openid4vc.domain.model.credentialoffer.metadata.CredentialResponseEncryption
import ch.admin.foitt.openid4vc.domain.model.payloadEncryption.PayloadEncryptionKeyPair
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.model.CreateJWSKeyPairError
import ch.admin.foitt.wallet.platform.keyPairGenerator.domain.usecase.CreateJWSKeyPairInSoftware
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.model.CreatePayloadEncryptionKeyPairError
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.model.toCreatePayloadEncryptionKeyPairError
import ch.admin.foitt.wallet.platform.payloadEncryption.domain.usecase.CreatePayloadEncryptionKeyPair
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.mapError
import javax.inject.Inject

class CreatePayloadEncryptionKeyPairImpl @Inject constructor(
    private val createJWSKeyPairInSoftware: CreateJWSKeyPairInSoftware,
) : CreatePayloadEncryptionKeyPair {
    override suspend fun invoke(
        credentialResponseEncryption: CredentialResponseEncryption,
    ): Result<PayloadEncryptionKeyPair, CreatePayloadEncryptionKeyPairError> = coroutineBinding {
        // NOTE — this key pair is still EC/P-256, not ML-KEM. CreateJWSKeyPairInSoftwareImpl
        // hardcodes secp256r1 regardless of the SigningAlgorithm passed in (see the comment
        // there), and CreateCredentialRequestImpl's createCredentialRequestCredentialResponseEncryption()
        // hardcodes `P_256` + casts to ECPublicKey when building the JWE-header JWK — so this
        // whole payload-encryption path is unaffected by the ML-DSA signature migration and
        // is NOT yet migrated to ML-KEM. Passing SigningAlgorithm.ML_DSA_65 here only satisfies
        // the compiler; the resulting JWSKeyPair.algorithm field mislabels an EC key.
        //
        // SigningAlgorithm was already a slightly awkward type to reuse for an encryption
        // (ECDH) key pair before this migration — it happened to work because ES256 implied a
        // usable curve. Now that SigningAlgorithm has no curve concept at all, that reuse is
        // actively misleading. The real fix is a dedicated KeyAgreementAlgorithm type (with an
        // ML-KEM case once Android/AndroidKeyStore expose it) rather than continuing to borrow
        // the signing enum — flagging rather than doing that larger refactor here.
        val keyPair = createJWSKeyPairInSoftware(SigningAlgorithm.ML_DSA_44)
            .mapError(CreateJWSKeyPairError::toCreatePayloadEncryptionKeyPairError)
            .bind()

        PayloadEncryptionKeyPair(
            keyPair = keyPair,
            alg = credentialResponseEncryption.algValuesSupported.first(),
            enc = credentialResponseEncryption.encValuesSupported.first(),
            zip = credentialResponseEncryption.zipValuesSupported?.firstOrNull(),
        )
    }
}
