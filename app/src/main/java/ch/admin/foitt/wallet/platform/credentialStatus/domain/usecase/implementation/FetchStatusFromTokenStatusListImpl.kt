package ch.admin.foitt.wallet.platform.credentialStatus.domain.usecase.implementation

import ch.admin.foitt.didResolver.domain.DidResolverHelper
import ch.admin.foitt.wallet.platform.credentialStatus.domain.model.CredentialStatusError
import ch.admin.foitt.wallet.platform.credentialStatus.domain.model.FetchStatusFromTokenStatusListError
import ch.admin.foitt.wallet.platform.credentialStatus.domain.model.ParseTokenStatusStatusListError
import ch.admin.foitt.wallet.platform.credentialStatus.domain.model.TokenStatusListProperties
import ch.admin.foitt.wallet.platform.credentialStatus.domain.model.ValidateTokenStatusStatusListError
import ch.admin.foitt.wallet.platform.credentialStatus.domain.model.toFetchStatusFromParseTokenStatusListError
import ch.admin.foitt.wallet.platform.credentialStatus.domain.model.toFetchStatusFromTokenStatusListError
import ch.admin.foitt.wallet.platform.credentialStatus.domain.repository.CredentialStatusRepository
import ch.admin.foitt.wallet.platform.credentialStatus.domain.usecase.FetchStatusFromTokenStatusList
import ch.admin.foitt.wallet.platform.credentialStatus.domain.usecase.ParseTokenStatusList
import ch.admin.foitt.wallet.platform.credentialStatus.domain.usecase.ValidateTokenStatusList
import ch.admin.foitt.wallet.platform.database.domain.model.CredentialStatus
import ch.admin.foitt.wallet.platform.environmentSetup.domain.repository.EnvironmentSetupRepository
import com.github.michaelbull.result.Result
import com.github.michaelbull.result.coroutines.coroutineBinding
import com.github.michaelbull.result.coroutines.runSuspendCatching
import com.github.michaelbull.result.mapError
import timber.log.Timber
import java.net.URI
import javax.inject.Inject

class FetchStatusFromTokenStatusListImpl @Inject constructor(
    private val didResolverHelper: DidResolverHelper,
    private val environmentSetupRepository: EnvironmentSetupRepository,
    private val credentialStatusRepository: CredentialStatusRepository,
    private val validateTokenStatusList: ValidateTokenStatusList,
    private val parseTokenStatusList: ParseTokenStatusList,
) : FetchStatusFromTokenStatusList {

    override suspend fun invoke(
        credentialIssuer: String,
        statusProperties: TokenStatusListProperties,
    ): Result<CredentialStatus, FetchStatusFromTokenStatusListError> = coroutineBinding {
        val statusList = statusProperties.statusList

        val issuerDidUrl = didResolverHelper.getHttpsUrl(credentialIssuer)
            .mapError { throwable ->
                throwable.toFetchStatusFromTokenStatusListError("Fetch status from token status list error")
            }.bind()
        val trustedStatusListHost = environmentSetupRepository.statusListMapping[issuerDidUrl.host]

        runSuspendCatching {
            val statusListHost = URI(statusList.uri).host
            if (trustedStatusListHost != null) {
                check(trustedStatusListHost == statusListHost) { "status list host is not trusted" }
            } else {
                // POC: issuer's DID host has no entry in the swiyu status list registry mapping,
                // so there is no trusted host to compare against. Accept the status list URI the
                // issuer itself referenced instead of rejecting it outright.
                Timber.w("No status list mapping for issuer host ${issuerDidUrl.host}; accepting status list host $statusListHost")
            }
        }.mapError { throwable ->
            Timber.e(t = throwable, message = "status list not in swiyu registry")
            CredentialStatusError.UnknownRegistry
        }.bind()

        val jwt = credentialStatusRepository.fetchTokenStatusListJwt(statusList.uri).bind()

        val responseResult = validateTokenStatusList(credentialIssuer, jwt, statusList.uri)
            .mapError(ValidateTokenStatusStatusListError::toFetchStatusFromTokenStatusListError)
            .bind()

        val value = parseTokenStatusList(statusList = responseResult.statusList, index = statusList.index)
            .mapError(ParseTokenStatusStatusListError::toFetchStatusFromParseTokenStatusListError)
            .bind()

        mapStatus(value)
    }

    private fun mapStatus(status: Int): CredentialStatus {
        return when (status) {
            0 -> CredentialStatus.VALID
            1 -> CredentialStatus.REVOKED
            2 -> CredentialStatus.SUSPENDED
            else -> CredentialStatus.UNSUPPORTED
        }
    }
}
