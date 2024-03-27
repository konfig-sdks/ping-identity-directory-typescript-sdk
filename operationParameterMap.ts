type Parameter = {
    name: string
}
type Entry = {
    parameters: Parameter[]
}
export const operationParameterMap: Record<string, Entry> = {
    '/access-control-handler-GET': {
        parameters: [
        ]
    },
    '/access-control-handler-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/access-token-validators-POST': {
        parameters: [
            {
                name: 'validatorName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'clientID'
            },
            {
                name: 'clientSecret'
            },
            {
                name: 'clientSecretPassphraseProvider'
            },
            {
                name: 'includeAudParameter'
            },
            {
                name: 'accessTokenManagerID'
            },
            {
                name: 'endpointCacheRefresh'
            },
            {
                name: 'evaluationOrderIndex'
            },
            {
                name: 'authorizationServer'
            },
            {
                name: 'identityMapper'
            },
            {
                name: 'subjectClaimName'
            },
            {
                name: 'enabled'
            },
            {
                name: 'allowedSigningAlgorithm'
            },
            {
                name: 'signingCertificate'
            },
            {
                name: 'jwksEndpointPath'
            },
            {
                name: 'encryptionKeyPair'
            },
            {
                name: 'allowedKeyEncryptionAlgorithm'
            },
            {
                name: 'allowedContentEncryptionAlgorithm'
            },
            {
                name: 'clockSkewGracePeriod'
            },
            {
                name: 'clientIDClaimName'
            },
            {
                name: 'scopeClaimName'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/access-token-validators/{access-token-validator-name}-DELETE': {
        parameters: [
            {
                name: 'access-token-validator-name'
            },
        ]
    },
    '/access-token-validators/{access-token-validator-name}-GET': {
        parameters: [
            {
                name: 'access-token-validator-name'
            },
        ]
    },
    '/access-token-validators-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/access-token-validators/{access-token-validator-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'access-token-validator-name'
            },
        ]
    },
    '/account-status-notification-handlers-POST': {
        parameters: [
            {
                name: 'handlerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'emailAddressAttributeType'
            },
            {
                name: 'emailAddressJSONField'
            },
            {
                name: 'emailAddressJSONObjectFilter'
            },
            {
                name: 'recipientAddress'
            },
            {
                name: 'sendMessageWithoutEndUserAddress'
            },
            {
                name: 'senderAddress'
            },
            {
                name: 'messageSubject'
            },
            {
                name: 'messageTemplateFile'
            },
            {
                name: 'enabled'
            },
            {
                name: 'asynchronous'
            },
            {
                name: 'accountAuthenticationNotificationResultCriteria'
            },
            {
                name: 'accountCreationNotificationRequestCriteria'
            },
            {
                name: 'accountDeletionNotificationRequestCriteria'
            },
            {
                name: 'accountUpdateNotificationRequestCriteria'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'accountStatusNotificationType'
            },
            {
                name: 'accountTemporarilyFailureLockedMessageTemplate'
            },
            {
                name: 'accountPermanentlyFailureLockedMessageTemplate'
            },
            {
                name: 'accountIdleLockedMessageTemplate'
            },
            {
                name: 'accountResetLockedMessageTemplate'
            },
            {
                name: 'accountUnlockedMessageTemplate'
            },
            {
                name: 'accountDisabledMessageTemplate'
            },
            {
                name: 'accountEnabledMessageTemplate'
            },
            {
                name: 'accountNotYetActiveMessageTemplate'
            },
            {
                name: 'accountExpiredMessageTemplate'
            },
            {
                name: 'passwordExpiredMessageTemplate'
            },
            {
                name: 'passwordExpiringMessageTemplate'
            },
            {
                name: 'passwordResetMessageTemplate'
            },
            {
                name: 'passwordChangedMessageTemplate'
            },
            {
                name: 'accountAuthenticatedMessageTemplate'
            },
            {
                name: 'accountCreatedMessageTemplate'
            },
            {
                name: 'accountDeletedMessageTemplate'
            },
            {
                name: 'accountUpdatedMessageTemplate'
            },
            {
                name: 'bindPasswordFailedValidationMessageTemplate'
            },
            {
                name: 'mustChangePasswordMessageTemplate'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/account-status-notification-handlers/{account-status-notification-handler-name}-DELETE': {
        parameters: [
            {
                name: 'account-status-notification-handler-name'
            },
        ]
    },
    '/account-status-notification-handlers/{account-status-notification-handler-name}-GET': {
        parameters: [
            {
                name: 'account-status-notification-handler-name'
            },
        ]
    },
    '/account-status-notification-handlers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/account-status-notification-handlers/{account-status-notification-handler-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'account-status-notification-handler-name'
            },
        ]
    },
    '/alarm-manager-GET': {
        parameters: [
        ]
    },
    '/alarm-manager-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/alert-handlers-POST': {
        parameters: [
            {
                name: 'handlerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'asynchronous'
            },
            {
                name: 'senderAddress'
            },
            {
                name: 'recipientAddress'
            },
            {
                name: 'messageSubject'
            },
            {
                name: 'messageBody'
            },
            {
                name: 'includeMonitorDataFilter'
            },
            {
                name: 'enabled'
            },
            {
                name: 'enabledAlertSeverity'
            },
            {
                name: 'enabledAlertType'
            },
            {
                name: 'disabledAlertType'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'serverHostName'
            },
            {
                name: 'serverPort'
            },
            {
                name: 'communityName'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'twilioAccountSID'
            },
            {
                name: 'twilioAuthToken'
            },
            {
                name: 'twilioAuthTokenPassphraseProvider'
            },
            {
                name: 'senderPhoneNumber'
            },
            {
                name: 'recipientPhoneNumber'
            },
            {
                name: 'longMessageBehavior'
            },
            {
                name: 'command'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/alert-handlers/{alert-handler-name}-DELETE': {
        parameters: [
            {
                name: 'alert-handler-name'
            },
        ]
    },
    '/alert-handlers/{alert-handler-name}-GET': {
        parameters: [
            {
                name: 'alert-handler-name'
            },
        ]
    },
    '/alert-handlers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/alert-handlers/{alert-handler-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'alert-handler-name'
            },
        ]
    },
    '/attribute-syntaxes-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/attribute-syntaxes/{attribute-syntax-name}-GET': {
        parameters: [
            {
                name: 'attribute-syntax-name'
            },
        ]
    },
    '/attribute-syntaxes/{attribute-syntax-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'attribute-syntax-name'
            },
        ]
    },
    '/azure-authentication-methods-POST': {
        parameters: [
            {
                name: 'methodName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'tenantID'
            },
            {
                name: 'clientID'
            },
            {
                name: 'clientSecret'
            },
            {
                name: 'username'
            },
            {
                name: 'password'
            },
        ]
    },
    '/azure-authentication-methods/{azure-authentication-method-name}-DELETE': {
        parameters: [
            {
                name: 'azure-authentication-method-name'
            },
        ]
    },
    '/azure-authentication-methods-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/azure-authentication-methods/{azure-authentication-method-name}-GET': {
        parameters: [
            {
                name: 'azure-authentication-method-name'
            },
        ]
    },
    '/azure-authentication-methods/{azure-authentication-method-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'azure-authentication-method-name'
            },
        ]
    },
    '/backends-POST': {
        parameters: [
            {
                name: 'backendName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'uncachedId2entryCacheMode'
            },
            {
                name: 'uncachedAttributeCriteria'
            },
            {
                name: 'uncachedEntryCriteria'
            },
            {
                name: 'writabilityMode'
            },
            {
                name: 'setDegradedAlertForUntrustedIndex'
            },
            {
                name: 'returnUnavailableForUntrustedIndex'
            },
            {
                name: 'processFiltersWithUndefinedAttributeTypes'
            },
            {
                name: 'isPrivateBackend'
            },
            {
                name: 'dbDirectory'
            },
            {
                name: 'dbDirectoryPermissions'
            },
            {
                name: 'compactCommonParentDN'
            },
            {
                name: 'compressEntries'
            },
            {
                name: 'hashEntries'
            },
            {
                name: 'dbNumCleanerThreads'
            },
            {
                name: 'dbCleanerMinUtilization'
            },
            {
                name: 'dbEvictorCriticalPercentage'
            },
            {
                name: 'dbCheckpointerWakeupInterval'
            },
            {
                name: 'dbBackgroundSyncInterval'
            },
            {
                name: 'dbUseThreadLocalHandles'
            },
            {
                name: 'dbLogFileMax'
            },
            {
                name: 'dbLoggingLevel'
            },
            {
                name: 'jeProperty'
            },
            {
                name: 'dbCachePercent'
            },
            {
                name: 'defaultCacheMode'
            },
            {
                name: 'id2entryCacheMode'
            },
            {
                name: 'dn2idCacheMode'
            },
            {
                name: 'id2childrenCacheMode'
            },
            {
                name: 'id2subtreeCacheMode'
            },
            {
                name: 'dn2uriCacheMode'
            },
            {
                name: 'primeMethod'
            },
            {
                name: 'primeThreadCount'
            },
            {
                name: 'primeTimeLimit'
            },
            {
                name: 'primeAllIndexes'
            },
            {
                name: 'systemIndexToPrime'
            },
            {
                name: 'systemIndexToPrimeInternalNodesOnly'
            },
            {
                name: 'backgroundPrime'
            },
            {
                name: 'indexEntryLimit'
            },
            {
                name: 'compositeIndexEntryLimit'
            },
            {
                name: 'id2childrenIndexEntryLimit'
            },
            {
                name: 'id2subtreeIndexEntryLimit'
            },
            {
                name: 'importTempDirectory'
            },
            {
                name: 'importThreadCount'
            },
            {
                name: 'exportThreadCount'
            },
            {
                name: 'dbImportCachePercent'
            },
            {
                name: 'dbTxnWriteNoSync'
            },
            {
                name: 'deadlockRetryLimit'
            },
            {
                name: 'externalTxnDefaultBackendLockBehavior'
            },
            {
                name: 'singleWriterLockBehavior'
            },
            {
                name: 'subtreeDeleteSizeLimit'
            },
            {
                name: 'numRecentChanges'
            },
            {
                name: 'offlineProcessDatabaseOpenTimeout'
            },
            {
                name: 'backendID'
            },
            {
                name: 'enabled'
            },
            {
                name: 'baseDN'
            },
            {
                name: 'setDegradedAlertWhenDisabled'
            },
            {
                name: 'returnUnavailableWhenDisabled'
            },
            {
                name: 'notificationManager'
            },
        ]
    },
    '/backends/{backend-name}-DELETE': {
        parameters: [
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/backends/{backend-name}-GET': {
        parameters: [
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/certificate-mappers-POST': {
        parameters: [
            {
                name: 'mapperName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'subjectAttribute'
            },
            {
                name: 'userBaseDN'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'subjectAttributeMapping'
            },
            {
                name: 'fingerprintAttribute'
            },
            {
                name: 'fingerprintAlgorithm'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/certificate-mappers/{certificate-mapper-name}-DELETE': {
        parameters: [
            {
                name: 'certificate-mapper-name'
            },
        ]
    },
    '/certificate-mappers/{certificate-mapper-name}-GET': {
        parameters: [
            {
                name: 'certificate-mapper-name'
            },
        ]
    },
    '/certificate-mappers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/certificate-mappers/{certificate-mapper-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'certificate-mapper-name'
            },
        ]
    },
    '/change-subscriptions-POST': {
        parameters: [
            {
                name: 'subscriptionName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'connectionCriteria'
            },
            {
                name: 'requestCriteria'
            },
            {
                name: 'resultCriteria'
            },
            {
                name: 'expirationTime'
            },
        ]
    },
    '/change-subscriptions/{change-subscription-name}-DELETE': {
        parameters: [
            {
                name: 'change-subscription-name'
            },
        ]
    },
    '/change-subscriptions/{change-subscription-name}-GET': {
        parameters: [
            {
                name: 'change-subscription-name'
            },
        ]
    },
    '/change-subscriptions-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/change-subscriptions/{change-subscription-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'change-subscription-name'
            },
        ]
    },
    '/change-subscription-handlers-POST': {
        parameters: [
            {
                name: 'handlerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'enabled'
            },
            {
                name: 'changeSubscription'
            },
            {
                name: 'logFile'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/change-subscription-handlers/{change-subscription-handler-name}-DELETE': {
        parameters: [
            {
                name: 'change-subscription-handler-name'
            },
        ]
    },
    '/change-subscription-handlers/{change-subscription-handler-name}-GET': {
        parameters: [
            {
                name: 'change-subscription-handler-name'
            },
        ]
    },
    '/change-subscription-handlers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/change-subscription-handlers/{change-subscription-handler-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'change-subscription-handler-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}/cipher-secret-keys-GET': {
        parameters: [
            {
                name: 'server-instance-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/server-instances/{server-instance-name}/cipher-secret-keys/{cipher-secret-key-name}-GET': {
        parameters: [
            {
                name: 'cipher-secret-key-name'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}/cipher-secret-keys/{cipher-secret-key-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'cipher-secret-key-name'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/cipher-stream-providers-POST': {
        parameters: [
            {
                name: 'providerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'encryptedPassphraseFile'
            },
            {
                name: 'awsExternalServer'
            },
            {
                name: 'awsAccessKeyID'
            },
            {
                name: 'awsSecretAccessKey'
            },
            {
                name: 'awsRegionName'
            },
            {
                name: 'kmsEncryptionKeyArn'
            },
            {
                name: 'iterationCount'
            },
            {
                name: 'enabled'
            },
            {
                name: 'secretID'
            },
            {
                name: 'secretFieldName'
            },
            {
                name: 'secretVersionID'
            },
            {
                name: 'secretVersionStage'
            },
            {
                name: 'encryptionMetadataFile'
            },
            {
                name: 'keyVaultURI'
            },
            {
                name: 'azureAuthenticationMethod'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'secretName'
            },
            {
                name: 'passwordFile'
            },
            {
                name: 'waitForPasswordFile'
            },
            {
                name: 'conjurExternalServer'
            },
            {
                name: 'conjurSecretRelativePath'
            },
            {
                name: 'pkcs11ProviderClass'
            },
            {
                name: 'pkcs11ProviderConfigurationFile'
            },
            {
                name: 'keyStorePin'
            },
            {
                name: 'keyStorePinFile'
            },
            {
                name: 'keyStorePinEnvironmentVariable'
            },
            {
                name: 'pkcs11KeyStoreType'
            },
            {
                name: 'sslCertNickname'
            },
            {
                name: 'vaultExternalServer'
            },
            {
                name: 'vaultServerBaseURI'
            },
            {
                name: 'vaultAuthenticationMethod'
            },
            {
                name: 'vaultSecretPath'
            },
            {
                name: 'vaultSecretFieldName'
            },
            {
                name: 'vaultEncryptionMetadataFile'
            },
            {
                name: 'trustStoreFile'
            },
            {
                name: 'trustStorePin'
            },
            {
                name: 'trustStoreType'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/cipher-stream-providers/{cipher-stream-provider-name}-DELETE': {
        parameters: [
            {
                name: 'cipher-stream-provider-name'
            },
        ]
    },
    '/cipher-stream-providers/{cipher-stream-provider-name}-GET': {
        parameters: [
            {
                name: 'cipher-stream-provider-name'
            },
        ]
    },
    '/cipher-stream-providers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/cipher-stream-providers/{cipher-stream-provider-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'cipher-stream-provider-name'
            },
        ]
    },
    '/client-connection-policies-POST': {
        parameters: [
            {
                name: 'policyName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'policyID'
            },
            {
                name: 'enabled'
            },
            {
                name: 'evaluationOrderIndex'
            },
            {
                name: 'connectionCriteria'
            },
            {
                name: 'terminateConnection'
            },
            {
                name: 'sensitiveAttribute'
            },
            {
                name: 'excludeGlobalSensitiveAttribute'
            },
            {
                name: 'resultCodeMap'
            },
            {
                name: 'includedBackendBaseDN'
            },
            {
                name: 'excludedBackendBaseDN'
            },
            {
                name: 'allowedOperation'
            },
            {
                name: 'requiredOperationRequestCriteria'
            },
            {
                name: 'prohibitedOperationRequestCriteria'
            },
            {
                name: 'allowedRequestControl'
            },
            {
                name: 'deniedRequestControl'
            },
            {
                name: 'allowedExtendedOperation'
            },
            {
                name: 'deniedExtendedOperation'
            },
            {
                name: 'allowedAuthType'
            },
            {
                name: 'allowedSASLMechanism'
            },
            {
                name: 'deniedSASLMechanism'
            },
            {
                name: 'allowedFilterType'
            },
            {
                name: 'allowUnindexedSearches'
            },
            {
                name: 'allowUnindexedSearchesWithControl'
            },
            {
                name: 'minimumSubstringLength'
            },
            {
                name: 'maximumConcurrentConnections'
            },
            {
                name: 'maximumConnectionDuration'
            },
            {
                name: 'maximumIdleConnectionDuration'
            },
            {
                name: 'maximumOperationCountPerConnection'
            },
            {
                name: 'maximumConcurrentOperationsPerConnection'
            },
            {
                name: 'maximumConcurrentOperationWaitTimeBeforeRejecting'
            },
            {
                name: 'maximumConcurrentOperationsPerConnectionExceededBehavior'
            },
            {
                name: 'maximumConnectionOperationRate'
            },
            {
                name: 'connectionOperationRateExceededBehavior'
            },
            {
                name: 'maximumPolicyOperationRate'
            },
            {
                name: 'policyOperationRateExceededBehavior'
            },
            {
                name: 'maximumSearchSizeLimit'
            },
            {
                name: 'maximumSearchTimeLimit'
            },
            {
                name: 'maximumSearchLookthroughLimit'
            },
            {
                name: 'maximumLDAPJoinSizeLimit'
            },
            {
                name: 'maximumSortSizeLimitWithoutVLVIndex'
            },
        ]
    },
    '/client-connection-policies/{client-connection-policy-name}-DELETE': {
        parameters: [
            {
                name: 'client-connection-policy-name'
            },
        ]
    },
    '/client-connection-policies-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/client-connection-policies/{client-connection-policy-name}-GET': {
        parameters: [
            {
                name: 'client-connection-policy-name'
            },
        ]
    },
    '/client-connection-policies/{client-connection-policy-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'client-connection-policy-name'
            },
        ]
    },
    '/conjur-authentication-methods-POST': {
        parameters: [
            {
                name: 'methodName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'username'
            },
            {
                name: 'password'
            },
            {
                name: 'apiKey'
            },
        ]
    },
    '/conjur-authentication-methods/{conjur-authentication-method-name}-DELETE': {
        parameters: [
            {
                name: 'conjur-authentication-method-name'
            },
        ]
    },
    '/conjur-authentication-methods/{conjur-authentication-method-name}-GET': {
        parameters: [
            {
                name: 'conjur-authentication-method-name'
            },
        ]
    },
    '/conjur-authentication-methods-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/conjur-authentication-methods/{conjur-authentication-method-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'conjur-authentication-method-name'
            },
        ]
    },
    '/connection-criteria-POST': {
        parameters: [
            {
                name: 'criteriaName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'includedClientAddress'
            },
            {
                name: 'excludedClientAddress'
            },
            {
                name: 'includedConnectionHandler'
            },
            {
                name: 'excludedConnectionHandler'
            },
            {
                name: 'includedProtocol'
            },
            {
                name: 'excludedProtocol'
            },
            {
                name: 'communicationSecurityLevel'
            },
            {
                name: 'userAuthType'
            },
            {
                name: 'authenticationSecurityLevel'
            },
            {
                name: 'includedUserSASLMechanism'
            },
            {
                name: 'excludedUserSASLMechanism'
            },
            {
                name: 'includedUserBaseDN'
            },
            {
                name: 'excludedUserBaseDN'
            },
            {
                name: 'allIncludedUserGroupDN'
            },
            {
                name: 'anyIncludedUserGroupDN'
            },
            {
                name: 'notAllIncludedUserGroupDN'
            },
            {
                name: 'noneIncludedUserGroupDN'
            },
            {
                name: 'allIncludedUserFilter'
            },
            {
                name: 'anyIncludedUserFilter'
            },
            {
                name: 'notAllIncludedUserFilter'
            },
            {
                name: 'noneIncludedUserFilter'
            },
            {
                name: 'allIncludedUserPrivilege'
            },
            {
                name: 'anyIncludedUserPrivilege'
            },
            {
                name: 'notAllIncludedUserPrivilege'
            },
            {
                name: 'noneIncludedUserPrivilege'
            },
            {
                name: 'allIncludedConnectionCriteria'
            },
            {
                name: 'anyIncludedConnectionCriteria'
            },
            {
                name: 'notAllIncludedConnectionCriteria'
            },
            {
                name: 'noneIncludedConnectionCriteria'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/connection-criteria/{connection-criteria-name}-DELETE': {
        parameters: [
            {
                name: 'connection-criteria-name'
            },
        ]
    },
    '/connection-criteria/{connection-criteria-name}-GET': {
        parameters: [
            {
                name: 'connection-criteria-name'
            },
        ]
    },
    '/connection-criteria-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/connection-criteria/{connection-criteria-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'connection-criteria-name'
            },
        ]
    },
    '/connection-handlers-POST': {
        parameters: [
            {
                name: 'handlerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'listenPort'
            },
            {
                name: 'useSSL'
            },
            {
                name: 'sslCertNickname'
            },
            {
                name: 'keyManagerProvider'
            },
            {
                name: 'enabled'
            },
            {
                name: 'allowedClient'
            },
            {
                name: 'deniedClient'
            },
            {
                name: 'listenAddress'
            },
            {
                name: 'allowStartTLS'
            },
            {
                name: 'trustManagerProvider'
            },
            {
                name: 'allowLDAPV2'
            },
            {
                name: 'useTCPKeepAlive'
            },
            {
                name: 'sendRejectionNotice'
            },
            {
                name: 'failedBindResponseDelay'
            },
            {
                name: 'maxRequestSize'
            },
            {
                name: 'maxCancelHandlers'
            },
            {
                name: 'numAcceptHandlers'
            },
            {
                name: 'numRequestHandlers'
            },
            {
                name: 'requestHandlerPerConnection'
            },
            {
                name: 'sslClientAuthPolicy'
            },
            {
                name: 'acceptBacklog'
            },
            {
                name: 'sslProtocol'
            },
            {
                name: 'sslCipherSuite'
            },
            {
                name: 'maxBlockedWriteTimeLimit'
            },
            {
                name: 'autoAuthenticateUsingClientCertificate'
            },
            {
                name: 'closeConnectionsWhenUnavailable'
            },
            {
                name: 'closeConnectionsOnExplicitGC'
            },
            {
                name: 'ldifDirectory'
            },
            {
                name: 'pollInterval'
            },
            {
                name: 'httpServletExtension'
            },
            {
                name: 'webApplicationExtension'
            },
            {
                name: 'httpOperationLogPublisher'
            },
            {
                name: 'keepStats'
            },
            {
                name: 'allowTCPReuseAddress'
            },
            {
                name: 'idleTimeLimit'
            },
            {
                name: 'lowResourcesConnectionThreshold'
            },
            {
                name: 'lowResourcesIdleTimeLimit'
            },
            {
                name: 'enableMultipartMIMEParameters'
            },
            {
                name: 'useForwardedHeaders'
            },
            {
                name: 'httpRequestHeaderSize'
            },
            {
                name: 'responseHeader'
            },
            {
                name: 'useCorrelationIDHeader'
            },
            {
                name: 'correlationIDResponseHeader'
            },
            {
                name: 'correlationIDRequestHeader'
            },
            {
                name: 'enableSniHostnameChecks'
            },
        ]
    },
    '/connection-handlers/{connection-handler-name}-DELETE': {
        parameters: [
            {
                name: 'connection-handler-name'
            },
        ]
    },
    '/connection-handlers/{connection-handler-name}-GET': {
        parameters: [
            {
                name: 'connection-handler-name'
            },
        ]
    },
    '/connection-handlers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/connection-handlers/{connection-handler-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'connection-handler-name'
            },
        ]
    },
    '/consent-definitions-POST': {
        parameters: [
            {
                name: 'definitionName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'uniqueID'
            },
            {
                name: 'displayName'
            },
            {
                name: 'parameter'
            },
        ]
    },
    '/consent-definitions/{consent-definition-name}-DELETE': {
        parameters: [
            {
                name: 'consent-definition-name'
            },
        ]
    },
    '/consent-definitions/{consent-definition-name}-GET': {
        parameters: [
            {
                name: 'consent-definition-name'
            },
        ]
    },
    '/consent-definitions-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/consent-definitions/{consent-definition-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'consent-definition-name'
            },
        ]
    },
    '/consent-definitions/{consent-definition-name}/consent-definition-localizations-POST': {
        parameters: [
            {
                name: 'localizationName'
            },
            {
                name: 'consent-definition-name'
            },
            {
                name: 'version'
            },
            {
                name: 'schemas'
            },
            {
                name: 'locale'
            },
            {
                name: 'titleText'
            },
            {
                name: 'dataText'
            },
            {
                name: 'purposeText'
            },
        ]
    },
    '/consent-definitions/{consent-definition-name}/consent-definition-localizations/{consent-definition-localization-name}-DELETE': {
        parameters: [
            {
                name: 'consent-definition-localization-name'
            },
            {
                name: 'consent-definition-name'
            },
        ]
    },
    '/consent-definitions/{consent-definition-name}/consent-definition-localizations-GET': {
        parameters: [
            {
                name: 'consent-definition-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/consent-definitions/{consent-definition-name}/consent-definition-localizations/{consent-definition-localization-name}-GET': {
        parameters: [
            {
                name: 'consent-definition-localization-name'
            },
            {
                name: 'consent-definition-name'
            },
        ]
    },
    '/consent-definitions/{consent-definition-name}/consent-definition-localizations/{consent-definition-localization-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'consent-definition-localization-name'
            },
            {
                name: 'consent-definition-name'
            },
        ]
    },
    '/consent-service-GET': {
        parameters: [
        ]
    },
    '/consent-service-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/constructed-attributes-POST': {
        parameters: [
            {
                name: 'attributeName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'attributeType'
            },
            {
                name: 'valuePattern'
            },
        ]
    },
    '/constructed-attributes/{constructed-attribute-name}-DELETE': {
        parameters: [
            {
                name: 'constructed-attribute-name'
            },
        ]
    },
    '/constructed-attributes/{constructed-attribute-name}-GET': {
        parameters: [
            {
                name: 'constructed-attribute-name'
            },
        ]
    },
    '/constructed-attributes-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/constructed-attributes/{constructed-attribute-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'constructed-attribute-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views-POST': {
        parameters: [
            {
                name: 'viewName'
            },
            {
                name: 'scim-resource-type-name'
            },
            {
                name: 'schemas'
            },
            {
                name: 'structuralLDAPObjectclass'
            },
            {
                name: 'auxiliaryLDAPObjectclass'
            },
            {
                name: 'includeBaseDN'
            },
            {
                name: 'includeFilter'
            },
            {
                name: 'includeOperationalAttribute'
            },
            {
                name: 'createDNPattern'
            },
            {
                name: 'primaryCorrelationAttribute'
            },
            {
                name: 'secondaryCorrelationAttribute'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views/{correlated-ldap-data-view-name}-DELETE': {
        parameters: [
            {
                name: 'correlated-ldap-data-view-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views-GET': {
        parameters: [
            {
                name: 'scim-resource-type-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views/{correlated-ldap-data-view-name}-GET': {
        parameters: [
            {
                name: 'correlated-ldap-data-view-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views/{correlated-ldap-data-view-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'correlated-ldap-data-view-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/crypto-manager-GET': {
        parameters: [
        ]
    },
    '/crypto-manager-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/plugin-root/plugins/{plugin-name}/custom-logged-stats-POST': {
        parameters: [
            {
                name: 'statsName'
            },
            {
                name: 'plugin-name'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'monitorObjectclass'
            },
            {
                name: 'includeFilter'
            },
            {
                name: 'attributeToLog'
            },
            {
                name: 'columnName'
            },
            {
                name: 'statisticType'
            },
            {
                name: 'headerPrefix'
            },
            {
                name: 'headerPrefixAttribute'
            },
            {
                name: 'regexPattern'
            },
            {
                name: 'regexReplacement'
            },
            {
                name: 'divideValueBy'
            },
            {
                name: 'divideValueByAttribute'
            },
            {
                name: 'decimalFormat'
            },
            {
                name: 'nonZeroImpliesNotIdle'
            },
        ]
    },
    '/plugin-root/plugins/{plugin-name}/custom-logged-stats/{custom-logged-stats-name}-DELETE': {
        parameters: [
            {
                name: 'custom-logged-stats-name'
            },
            {
                name: 'plugin-name'
            },
        ]
    },
    '/plugin-root/plugins/{plugin-name}/custom-logged-stats/{custom-logged-stats-name}-GET': {
        parameters: [
            {
                name: 'custom-logged-stats-name'
            },
            {
                name: 'plugin-name'
            },
        ]
    },
    '/plugin-root/plugins/{plugin-name}/custom-logged-stats-GET': {
        parameters: [
            {
                name: 'plugin-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/plugin-root/plugins/{plugin-name}/custom-logged-stats/{custom-logged-stats-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'custom-logged-stats-name'
            },
            {
                name: 'plugin-name'
            },
        ]
    },
    '/data-security-auditors-POST': {
        parameters: [
            {
                name: 'auditorName'
            },
            {
                name: 'schemas'
            },
            {
                name: 'reportFile'
            },
            {
                name: 'includeAttribute'
            },
            {
                name: 'passwordEvaluationAge'
            },
            {
                name: 'enabled'
            },
            {
                name: 'auditBackend'
            },
            {
                name: 'auditSeverity'
            },
            {
                name: 'idleAccountWarningInterval'
            },
            {
                name: 'idleAccountErrorInterval'
            },
            {
                name: 'neverLoggedInAccountWarningInterval'
            },
            {
                name: 'neverLoggedInAccountErrorInterval'
            },
            {
                name: 'weakPasswordStorageScheme'
            },
            {
                name: 'weakCryptEncoding'
            },
            {
                name: 'includePrivilege'
            },
            {
                name: 'maximumIdleTime'
            },
            {
                name: 'filter'
            },
            {
                name: 'accountExpirationWarningInterval'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/data-security-auditors/{data-security-auditor-name}-DELETE': {
        parameters: [
            {
                name: 'data-security-auditor-name'
            },
        ]
    },
    '/data-security-auditors/{data-security-auditor-name}-GET': {
        parameters: [
            {
                name: 'data-security-auditor-name'
            },
        ]
    },
    '/data-security-auditors-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/data-security-auditors/{data-security-auditor-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'data-security-auditor-name'
            },
        ]
    },
    '/log-publishers/{log-publisher-name}/debug-targets-POST': {
        parameters: [
            {
                name: 'targetName'
            },
            {
                name: 'log-publisher-name'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'debugScope'
            },
            {
                name: 'debugLevel'
            },
            {
                name: 'debugCategory'
            },
            {
                name: 'omitMethodEntryArguments'
            },
            {
                name: 'omitMethodReturnValue'
            },
            {
                name: 'includeThrowableCause'
            },
            {
                name: 'throwableStackFrames'
            },
        ]
    },
    '/log-publishers/{log-publisher-name}/debug-targets/{debug-target-name}-DELETE': {
        parameters: [
            {
                name: 'debug-target-name'
            },
            {
                name: 'log-publisher-name'
            },
        ]
    },
    '/log-publishers/{log-publisher-name}/debug-targets/{debug-target-name}-GET': {
        parameters: [
            {
                name: 'debug-target-name'
            },
            {
                name: 'log-publisher-name'
            },
        ]
    },
    '/log-publishers/{log-publisher-name}/debug-targets-GET': {
        parameters: [
            {
                name: 'log-publisher-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/log-publishers/{log-publisher-name}/debug-targets/{debug-target-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'debug-target-name'
            },
            {
                name: 'log-publisher-name'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-attributes-POST': {
        parameters: [
            {
                name: 'rest-resource-type-name'
            },
            {
                name: 'attributeType'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'allowedMIMEType'
            },
            {
                name: 'displayName'
            },
            {
                name: 'mutability'
            },
            {
                name: 'multiValued'
            },
            {
                name: 'attributeCategory'
            },
            {
                name: 'displayOrderIndex'
            },
            {
                name: 'referenceResourceType'
            },
            {
                name: 'attributePresentation'
            },
            {
                name: 'dateTimeFormat'
            },
            {
                name: 'includeInSummary'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-attributes/{delegated-admin-attribute-name}-DELETE': {
        parameters: [
            {
                name: 'delegated-admin-attribute-name'
            },
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-attributes-GET': {
        parameters: [
            {
                name: 'rest-resource-type-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-attributes/{delegated-admin-attribute-name}-GET': {
        parameters: [
            {
                name: 'delegated-admin-attribute-name'
            },
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-attributes/{delegated-admin-attribute-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'delegated-admin-attribute-name'
            },
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/delegated-admin-attribute-categories-POST': {
        parameters: [
            {
                name: 'displayName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'displayOrderIndex'
            },
        ]
    },
    '/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}-DELETE': {
        parameters: [
            {
                name: 'delegated-admin-attribute-category-name'
            },
        ]
    },
    '/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}-GET': {
        parameters: [
            {
                name: 'delegated-admin-attribute-category-name'
            },
        ]
    },
    '/delegated-admin-attribute-categories-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'delegated-admin-attribute-category-name'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-correlated-rest-resources-POST': {
        parameters: [
            {
                name: 'resourceName'
            },
            {
                name: 'rest-resource-type-name'
            },
            {
                name: 'schemas'
            },
            {
                name: 'displayName'
            },
            {
                name: 'correlatedRESTResource'
            },
            {
                name: 'primaryRESTResourceCorrelationAttribute'
            },
            {
                name: 'secondaryRESTResourceCorrelationAttribute'
            },
            {
                name: 'useSecondaryValueForLinking'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-correlated-rest-resources/{delegated-admin-correlated-rest-resource-name}-DELETE': {
        parameters: [
            {
                name: 'delegated-admin-correlated-rest-resource-name'
            },
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-correlated-rest-resources/{delegated-admin-correlated-rest-resource-name}-GET': {
        parameters: [
            {
                name: 'delegated-admin-correlated-rest-resource-name'
            },
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-correlated-rest-resources-GET': {
        parameters: [
            {
                name: 'rest-resource-type-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}/delegated-admin-correlated-rest-resources/{delegated-admin-correlated-rest-resource-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'delegated-admin-correlated-rest-resource-name'
            },
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/delegated-admin-rights/{delegated-admin-rights-name}/delegated-admin-resource-rights-POST': {
        parameters: [
            {
                name: 'restResourceType'
            },
            {
                name: 'delegated-admin-rights-name'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'adminPermission'
            },
            {
                name: 'adminScope'
            },
            {
                name: 'resourceSubtree'
            },
            {
                name: 'resourcesInGroup'
            },
        ]
    },
    '/delegated-admin-rights/{delegated-admin-rights-name}/delegated-admin-resource-rights/{delegated-admin-resource-rights-name}-DELETE': {
        parameters: [
            {
                name: 'delegated-admin-resource-rights-name'
            },
            {
                name: 'delegated-admin-rights-name'
            },
        ]
    },
    '/delegated-admin-rights/{delegated-admin-rights-name}/delegated-admin-resource-rights/{delegated-admin-resource-rights-name}-GET': {
        parameters: [
            {
                name: 'delegated-admin-resource-rights-name'
            },
            {
                name: 'delegated-admin-rights-name'
            },
        ]
    },
    '/delegated-admin-rights/{delegated-admin-rights-name}/delegated-admin-resource-rights-GET': {
        parameters: [
            {
                name: 'delegated-admin-rights-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/delegated-admin-rights/{delegated-admin-rights-name}/delegated-admin-resource-rights/{delegated-admin-resource-rights-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'delegated-admin-resource-rights-name'
            },
            {
                name: 'delegated-admin-rights-name'
            },
        ]
    },
    '/delegated-admin-rights-POST': {
        parameters: [
            {
                name: 'rightsName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'adminUserDN'
            },
            {
                name: 'adminGroupDN'
            },
        ]
    },
    '/delegated-admin-rights/{delegated-admin-rights-name}-DELETE': {
        parameters: [
            {
                name: 'delegated-admin-rights-name'
            },
        ]
    },
    '/delegated-admin-rights/{delegated-admin-rights-name}-GET': {
        parameters: [
            {
                name: 'delegated-admin-rights-name'
            },
        ]
    },
    '/delegated-admin-rights-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/delegated-admin-rights/{delegated-admin-rights-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'delegated-admin-rights-name'
            },
        ]
    },
    '/dn-maps-POST': {
        parameters: [
            {
                name: 'mapName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'fromDNPattern'
            },
            {
                name: 'toDNPattern'
            },
        ]
    },
    '/dn-maps/{dn-map-name}-DELETE': {
        parameters: [
            {
                name: 'dn-map-name'
            },
        ]
    },
    '/dn-maps/{dn-map-name}-GET': {
        parameters: [
            {
                name: 'dn-map-name'
            },
        ]
    },
    '/dn-maps-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/dn-maps/{dn-map-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'dn-map-name'
            },
        ]
    },
    '/entry-caches-POST': {
        parameters: [
            {
                name: 'cacheName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'maxMemoryPercent'
            },
            {
                name: 'maxEntries'
            },
            {
                name: 'onlyCacheFrequentlyAccessed'
            },
            {
                name: 'includeFilter'
            },
            {
                name: 'excludeFilter'
            },
            {
                name: 'minCacheEntryValueCount'
            },
            {
                name: 'minCacheEntryAttribute'
            },
            {
                name: 'enabled'
            },
            {
                name: 'cacheLevel'
            },
            {
                name: 'cacheUnindexedSearchResults'
            },
        ]
    },
    '/entry-caches/{entry-cache-name}-DELETE': {
        parameters: [
            {
                name: 'entry-cache-name'
            },
        ]
    },
    '/entry-caches-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/entry-caches/{entry-cache-name}-GET': {
        parameters: [
            {
                name: 'entry-cache-name'
            },
        ]
    },
    '/entry-caches/{entry-cache-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'entry-cache-name'
            },
        ]
    },
    '/extended-operation-handlers-POST': {
        parameters: [
            {
                name: 'handlerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'sharedSecretAttributeType'
            },
            {
                name: 'timeIntervalDuration'
            },
            {
                name: 'adjacentIntervalsToCheck'
            },
            {
                name: 'preventTOTPReuse'
            },
            {
                name: 'enabled'
            },
            {
                name: 'allowRemotelyProvidedCertificates'
            },
            {
                name: 'allowedOperation'
            },
            {
                name: 'connectionCriteria'
            },
            {
                name: 'requestCriteria'
            },
            {
                name: 'passwordGenerator'
            },
            {
                name: 'defaultOTPDeliveryMechanism'
            },
            {
                name: 'defaultSingleUseTokenValidityDuration'
            },
            {
                name: 'defaultTokenDeliveryMechanism'
            },
            {
                name: 'passwordResetTokenValidityDuration'
            },
            {
                name: 'identityMapper'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/extended-operation-handlers/{extended-operation-handler-name}-DELETE': {
        parameters: [
            {
                name: 'extended-operation-handler-name'
            },
        ]
    },
    '/extended-operation-handlers/{extended-operation-handler-name}-GET': {
        parameters: [
            {
                name: 'extended-operation-handler-name'
            },
        ]
    },
    '/extended-operation-handlers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/extended-operation-handlers/{extended-operation-handler-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'extended-operation-handler-name'
            },
        ]
    },
    '/external-servers-POST': {
        parameters: [
            {
                name: 'serverName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'serverHostName'
            },
            {
                name: 'serverPort'
            },
            {
                name: 'smtpSecurity'
            },
            {
                name: 'userName'
            },
            {
                name: 'password'
            },
            {
                name: 'passphraseProvider'
            },
            {
                name: 'smtpTimeout'
            },
            {
                name: 'smtpConnectionProperties'
            },
            {
                name: 'verifyCredentialsMethod'
            },
            {
                name: 'useAdministrativeOperationControl'
            },
            {
                name: 'location'
            },
            {
                name: 'bindDN'
            },
            {
                name: 'connectionSecurity'
            },
            {
                name: 'authenticationMethod'
            },
            {
                name: 'healthCheckConnectTimeout'
            },
            {
                name: 'maxConnectionAge'
            },
            {
                name: 'minExpiredConnectionDisconnectInterval'
            },
            {
                name: 'connectTimeout'
            },
            {
                name: 'maxResponseSize'
            },
            {
                name: 'keyManagerProvider'
            },
            {
                name: 'trustManagerProvider'
            },
            {
                name: 'initialConnections'
            },
            {
                name: 'maxConnections'
            },
            {
                name: 'defunctConnectionResultCode'
            },
            {
                name: 'abandonOnTimeout'
            },
            {
                name: 'jdbcDriverType'
            },
            {
                name: 'jdbcDriverURL'
            },
            {
                name: 'databaseName'
            },
            {
                name: 'validationQuery'
            },
            {
                name: 'validationQueryTimeout'
            },
            {
                name: 'jdbcConnectionProperties'
            },
            {
                name: 'transactionIsolationLevel'
            },
            {
                name: 'transportMechanism'
            },
            {
                name: 'basicAuthenticationUsername'
            },
            {
                name: 'basicAuthenticationPassphraseProvider'
            },
            {
                name: 'hostnameVerificationMethod'
            },
            {
                name: 'responseTimeout'
            },
            {
                name: 'baseURL'
            },
            {
                name: 'sslCertNickname'
            },
            {
                name: 'conjurServerBaseURI'
            },
            {
                name: 'conjurAuthenticationMethod'
            },
            {
                name: 'conjurAccountName'
            },
            {
                name: 'httpConnectTimeout'
            },
            {
                name: 'httpResponseTimeout'
            },
            {
                name: 'trustStoreFile'
            },
            {
                name: 'trustStorePin'
            },
            {
                name: 'trustStoreType'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'awsAccessKeyID'
            },
            {
                name: 'awsSecretAccessKey'
            },
            {
                name: 'awsRegionName'
            },
            {
                name: 'vaultServerBaseURI'
            },
            {
                name: 'vaultAuthenticationMethod'
            },
        ]
    },
    '/external-servers/{external-server-name}-DELETE': {
        parameters: [
            {
                name: 'external-server-name'
            },
        ]
    },
    '/external-servers/{external-server-name}-GET': {
        parameters: [
            {
                name: 'external-server-name'
            },
        ]
    },
    '/external-servers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/external-servers/{external-server-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'external-server-name'
            },
        ]
    },
    '/failure-lockout-actions-POST': {
        parameters: [
            {
                name: 'actionName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'delay'
            },
            {
                name: 'allowBlockingDelay'
            },
            {
                name: 'generateAccountStatusNotification'
            },
        ]
    },
    '/failure-lockout-actions/{failure-lockout-action-name}-DELETE': {
        parameters: [
            {
                name: 'failure-lockout-action-name'
            },
        ]
    },
    '/failure-lockout-actions/{failure-lockout-action-name}-GET': {
        parameters: [
            {
                name: 'failure-lockout-action-name'
            },
        ]
    },
    '/failure-lockout-actions-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/failure-lockout-actions/{failure-lockout-action-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'failure-lockout-action-name'
            },
        ]
    },
    '/gauges-POST': {
        parameters: [
            {
                name: 'gaugeName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'gaugeDataSource'
            },
            {
                name: 'criticalValue'
            },
            {
                name: 'majorValue'
            },
            {
                name: 'minorValue'
            },
            {
                name: 'warningValue'
            },
            {
                name: 'enabled'
            },
            {
                name: 'overrideSeverity'
            },
            {
                name: 'alertLevel'
            },
            {
                name: 'updateInterval'
            },
            {
                name: 'samplesPerUpdateInterval'
            },
            {
                name: 'includeResource'
            },
            {
                name: 'excludeResource'
            },
            {
                name: 'serverUnavailableSeverityLevel'
            },
            {
                name: 'serverDegradedSeverityLevel'
            },
            {
                name: 'criticalExitValue'
            },
            {
                name: 'majorExitValue'
            },
            {
                name: 'minorExitValue'
            },
            {
                name: 'warningExitValue'
            },
        ]
    },
    '/gauges/{gauge-name}-DELETE': {
        parameters: [
            {
                name: 'gauge-name'
            },
        ]
    },
    '/gauges/{gauge-name}-GET': {
        parameters: [
            {
                name: 'gauge-name'
            },
        ]
    },
    '/gauges-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/gauges/{gauge-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'gauge-name'
            },
        ]
    },
    '/gauge-data-sources-POST': {
        parameters: [
            {
                name: 'sourceName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'additionalText'
            },
            {
                name: 'monitorObjectclass'
            },
            {
                name: 'monitorAttribute'
            },
            {
                name: 'includeFilter'
            },
            {
                name: 'resourceAttribute'
            },
            {
                name: 'resourceType'
            },
            {
                name: 'minimumUpdateInterval'
            },
            {
                name: 'dataOrientation'
            },
            {
                name: 'statisticType'
            },
            {
                name: 'divideValueBy'
            },
            {
                name: 'divideValueByAttribute'
            },
            {
                name: 'divideValueByCounterAttribute'
            },
        ]
    },
    '/gauge-data-sources/{gauge-data-source-name}-DELETE': {
        parameters: [
            {
                name: 'gauge-data-source-name'
            },
        ]
    },
    '/gauge-data-sources/{gauge-data-source-name}-GET': {
        parameters: [
            {
                name: 'gauge-data-source-name'
            },
        ]
    },
    '/gauge-data-sources-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/gauge-data-sources/{gauge-data-source-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'gauge-data-source-name'
            },
        ]
    },
    '/global-configuration-GET': {
        parameters: [
        ]
    },
    '/global-configuration-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/group-implementations/{group-implementation-name}-GET': {
        parameters: [
            {
                name: 'group-implementation-name'
            },
        ]
    },
    '/group-implementations-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/group-implementations/{group-implementation-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'group-implementation-name'
            },
        ]
    },
    '/http-configuration-GET': {
        parameters: [
        ]
    },
    '/http-configuration-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/http-servlet-cross-origin-policies-POST': {
        parameters: [
            {
                name: 'policyName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'corsAllowedMethods'
            },
            {
                name: 'corsAllowedOrigins'
            },
            {
                name: 'corsExposedHeaders'
            },
            {
                name: 'corsAllowedHeaders'
            },
            {
                name: 'corsPreflightMaxAge'
            },
            {
                name: 'corsAllowCredentials'
            },
        ]
    },
    '/http-servlet-cross-origin-policies/{http-servlet-cross-origin-policy-name}-DELETE': {
        parameters: [
            {
                name: 'http-servlet-cross-origin-policy-name'
            },
        ]
    },
    '/http-servlet-cross-origin-policies/{http-servlet-cross-origin-policy-name}-GET': {
        parameters: [
            {
                name: 'http-servlet-cross-origin-policy-name'
            },
        ]
    },
    '/http-servlet-cross-origin-policies-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/http-servlet-cross-origin-policies/{http-servlet-cross-origin-policy-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'http-servlet-cross-origin-policy-name'
            },
        ]
    },
    '/http-servlet-extensions-POST': {
        parameters: [
            {
                name: 'extensionName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'server'
            },
            {
                name: 'crossOriginPolicy'
            },
            {
                name: 'responseHeader'
            },
            {
                name: 'correlationIDResponseHeader'
            },
            {
                name: 'baseContextPath'
            },
            {
                name: 'availableStatusCode'
            },
            {
                name: 'degradedStatusCode'
            },
            {
                name: 'unavailableStatusCode'
            },
            {
                name: 'overrideStatusCode'
            },
            {
                name: 'includeResponseBody'
            },
            {
                name: 'additionalResponseContents'
            },
            {
                name: 'includeInstanceNameLabel'
            },
            {
                name: 'includeProductNameLabel'
            },
            {
                name: 'includeLocationNameLabel'
            },
            {
                name: 'alwaysIncludeMonitorEntryNameLabel'
            },
            {
                name: 'includeMonitorObjectClassNameLabel'
            },
            {
                name: 'includeMonitorAttributeNameLabel'
            },
            {
                name: 'labelNameValuePair'
            },
            {
                name: 'OAuthTokenHandler'
            },
            {
                name: 'basicAuthEnabled'
            },
            {
                name: 'identityMapper'
            },
            {
                name: 'resourceMappingFile'
            },
            {
                name: 'includeLDAPObjectclass'
            },
            {
                name: 'excludeLDAPObjectclass'
            },
            {
                name: 'includeLDAPBaseDN'
            },
            {
                name: 'excludeLDAPBaseDN'
            },
            {
                name: 'entityTagLDAPAttribute'
            },
            {
                name: 'temporaryDirectory'
            },
            {
                name: 'temporaryDirectoryPermissions'
            },
            {
                name: 'maxResults'
            },
            {
                name: 'bulkMaxOperations'
            },
            {
                name: 'bulkMaxPayloadSize'
            },
            {
                name: 'bulkMaxConcurrentRequests'
            },
            {
                name: 'debugEnabled'
            },
            {
                name: 'debugLevel'
            },
            {
                name: 'debugType'
            },
            {
                name: 'includeStackTrace'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'documentRootDirectory'
            },
            {
                name: 'enableDirectoryIndexing'
            },
            {
                name: 'indexFile'
            },
            {
                name: 'mimeTypesFile'
            },
            {
                name: 'defaultMIMEType'
            },
            {
                name: 'requireAuthentication'
            },
            {
                name: 'allowedAuthenticationType'
            },
            {
                name: 'accessTokenValidator'
            },
            {
                name: 'idTokenValidator'
            },
            {
                name: 'requireFileServletAccessPrivilege'
            },
            {
                name: 'requireGroup'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}-DELETE': {
        parameters: [
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}-GET': {
        parameters: [
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/id-token-validators-POST': {
        parameters: [
            {
                name: 'validatorName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'issuerURL'
            },
            {
                name: 'OpenIDConnectProvider'
            },
            {
                name: 'OpenIDConnectMetadataCacheDuration'
            },
            {
                name: 'enabled'
            },
            {
                name: 'identityMapper'
            },
            {
                name: 'subjectClaimName'
            },
            {
                name: 'clockSkewGracePeriod'
            },
            {
                name: 'jwksCacheDuration'
            },
            {
                name: 'evaluationOrderIndex'
            },
            {
                name: 'allowedSigningAlgorithm'
            },
            {
                name: 'signingCertificate'
            },
            {
                name: 'jwksEndpointPath'
            },
        ]
    },
    '/id-token-validators/{id-token-validator-name}-DELETE': {
        parameters: [
            {
                name: 'id-token-validator-name'
            },
        ]
    },
    '/id-token-validators/{id-token-validator-name}-GET': {
        parameters: [
            {
                name: 'id-token-validator-name'
            },
        ]
    },
    '/id-token-validators-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/id-token-validators/{id-token-validator-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'id-token-validator-name'
            },
        ]
    },
    '/identity-mappers-POST': {
        parameters: [
            {
                name: 'mapperName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'matchAttribute'
            },
            {
                name: 'matchBaseDN'
            },
            {
                name: 'matchFilter'
            },
            {
                name: 'enabled'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'matchPattern'
            },
            {
                name: 'replacePattern'
            },
            {
                name: 'allIncludedIdentityMapper'
            },
            {
                name: 'anyIncludedIdentityMapper'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/identity-mappers/{identity-mapper-name}-DELETE': {
        parameters: [
            {
                name: 'identity-mapper-name'
            },
        ]
    },
    '/identity-mappers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/identity-mappers/{identity-mapper-name}-GET': {
        parameters: [
            {
                name: 'identity-mapper-name'
            },
        ]
    },
    '/identity-mappers/{identity-mapper-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'identity-mapper-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}/server-instance-listeners/{server-instance-listener-name}/inter-server-authentication-info/{inter-server-authentication-info-name}-GET': {
        parameters: [
            {
                name: 'inter-server-authentication-info-name'
            },
            {
                name: 'server-instance-listener-name'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}/server-instance-listeners/{server-instance-listener-name}/inter-server-authentication-info-GET': {
        parameters: [
            {
                name: 'server-instance-listener-name'
            },
            {
                name: 'server-instance-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/server-instances/{server-instance-name}/server-instance-listeners/{server-instance-listener-name}/inter-server-authentication-info/{inter-server-authentication-info-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'inter-server-authentication-info-name'
            },
            {
                name: 'server-instance-listener-name'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/json-attribute-constraints-POST': {
        parameters: [
            {
                name: 'attributeType'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'allowUnnamedFields'
            },
        ]
    },
    '/json-attribute-constraints/{json-attribute-constraints-name}-DELETE': {
        parameters: [
            {
                name: 'json-attribute-constraints-name'
            },
        ]
    },
    '/json-attribute-constraints-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/json-attribute-constraints/{json-attribute-constraints-name}-GET': {
        parameters: [
            {
                name: 'json-attribute-constraints-name'
            },
        ]
    },
    '/json-attribute-constraints/{json-attribute-constraints-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'json-attribute-constraints-name'
            },
        ]
    },
    '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints-POST': {
        parameters: [
            {
                name: 'jsonField'
            },
            {
                name: 'json-attribute-constraints-name'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'valueType'
            },
            {
                name: 'isRequired'
            },
            {
                name: 'isArray'
            },
            {
                name: 'allowNullValue'
            },
            {
                name: 'allowEmptyObject'
            },
            {
                name: 'indexValues'
            },
            {
                name: 'indexEntryLimit'
            },
            {
                name: 'primeIndex'
            },
            {
                name: 'cacheMode'
            },
            {
                name: 'tokenizeValues'
            },
            {
                name: 'allowedValue'
            },
            {
                name: 'allowedValueRegularExpression'
            },
            {
                name: 'minimumNumericValue'
            },
            {
                name: 'maximumNumericValue'
            },
            {
                name: 'minimumValueLength'
            },
            {
                name: 'maximumValueLength'
            },
            {
                name: 'minimumValueCount'
            },
            {
                name: 'maximumValueCount'
            },
        ]
    },
    '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}-DELETE': {
        parameters: [
            {
                name: 'json-field-constraints-name'
            },
            {
                name: 'json-attribute-constraints-name'
            },
        ]
    },
    '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}-GET': {
        parameters: [
            {
                name: 'json-field-constraints-name'
            },
            {
                name: 'json-attribute-constraints-name'
            },
        ]
    },
    '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints-GET': {
        parameters: [
            {
                name: 'json-attribute-constraints-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'json-field-constraints-name'
            },
            {
                name: 'json-attribute-constraints-name'
            },
        ]
    },
    '/key-manager-providers-POST': {
        parameters: [
            {
                name: 'providerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'keyStoreFile'
            },
            {
                name: 'keyStoreType'
            },
            {
                name: 'keyStorePin'
            },
            {
                name: 'keyStorePinFile'
            },
            {
                name: 'keyStorePinPassphraseProvider'
            },
            {
                name: 'privateKeyPin'
            },
            {
                name: 'privateKeyPinFile'
            },
            {
                name: 'privateKeyPinPassphraseProvider'
            },
            {
                name: 'enabled'
            },
            {
                name: 'pkcs11ProviderClass'
            },
            {
                name: 'pkcs11ProviderConfigurationFile'
            },
            {
                name: 'pkcs11KeyStoreType'
            },
            {
                name: 'pkcs11MaxCacheDuration'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/key-manager-providers/{key-manager-provider-name}-DELETE': {
        parameters: [
            {
                name: 'key-manager-provider-name'
            },
        ]
    },
    '/key-manager-providers/{key-manager-provider-name}-GET': {
        parameters: [
            {
                name: 'key-manager-provider-name'
            },
        ]
    },
    '/key-manager-providers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/key-manager-providers/{key-manager-provider-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'key-manager-provider-name'
            },
        ]
    },
    '/key-pairs-POST': {
        parameters: [
            {
                name: 'pairName'
            },
            {
                name: 'schemas'
            },
            {
                name: 'keyAlgorithm'
            },
            {
                name: 'selfSignedCertificateValidity'
            },
            {
                name: 'subjectDN'
            },
            {
                name: 'certificateChain'
            },
            {
                name: 'privateKey'
            },
        ]
    },
    '/key-pairs/{key-pair-name}-DELETE': {
        parameters: [
            {
                name: 'key-pair-name'
            },
        ]
    },
    '/key-pairs/{key-pair-name}-GET': {
        parameters: [
            {
                name: 'key-pair-name'
            },
        ]
    },
    '/key-pairs-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/key-pairs/{key-pair-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'key-pair-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views/{correlated-ldap-data-view-name}/ldap-correlation-attribute-pairs-POST': {
        parameters: [
            {
                name: 'pairName'
            },
            {
                name: 'correlated-ldap-data-view-name'
            },
            {
                name: 'scim-resource-type-name'
            },
            {
                name: 'schemas'
            },
            {
                name: 'primaryCorrelationAttribute'
            },
            {
                name: 'secondaryCorrelationAttribute'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views/{correlated-ldap-data-view-name}/ldap-correlation-attribute-pairs/{ldap-correlation-attribute-pair-name}-DELETE': {
        parameters: [
            {
                name: 'ldap-correlation-attribute-pair-name'
            },
            {
                name: 'correlated-ldap-data-view-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views/{correlated-ldap-data-view-name}/ldap-correlation-attribute-pairs/{ldap-correlation-attribute-pair-name}-GET': {
        parameters: [
            {
                name: 'ldap-correlation-attribute-pair-name'
            },
            {
                name: 'correlated-ldap-data-view-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views/{correlated-ldap-data-view-name}/ldap-correlation-attribute-pairs-GET': {
        parameters: [
            {
                name: 'correlated-ldap-data-view-name'
            },
            {
                name: 'scim-resource-type-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/correlated-ldap-data-views/{correlated-ldap-data-view-name}/ldap-correlation-attribute-pairs/{ldap-correlation-attribute-pair-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'ldap-correlation-attribute-pair-name'
            },
            {
                name: 'correlated-ldap-data-view-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/ldap-sdk-debug-logger-GET': {
        parameters: [
        ]
    },
    '/ldap-sdk-debug-logger-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/license-GET': {
        parameters: [
        ]
    },
    '/license-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/backends/{backend-name}/local-db-composite-indexes-POST': {
        parameters: [
            {
                name: 'indexName'
            },
            {
                name: 'backend-name'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'indexFilterPattern'
            },
            {
                name: 'indexBaseDNPattern'
            },
            {
                name: 'indexEntryLimit'
            },
            {
                name: 'primeIndex'
            },
            {
                name: 'primeInternalNodesOnly'
            },
            {
                name: 'cacheMode'
            },
        ]
    },
    '/backends/{backend-name}/local-db-composite-indexes/{local-db-composite-index-name}-DELETE': {
        parameters: [
            {
                name: 'local-db-composite-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}/local-db-composite-indexes/{local-db-composite-index-name}-GET': {
        parameters: [
            {
                name: 'local-db-composite-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}/local-db-composite-indexes-GET': {
        parameters: [
            {
                name: 'backend-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/backends/{backend-name}/local-db-composite-indexes/{local-db-composite-index-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'local-db-composite-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}/local-db-indexes-POST': {
        parameters: [
            {
                name: 'indexName'
            },
            {
                name: 'backend-name'
            },
            {
                name: 'schemas'
            },
            {
                name: 'attribute'
            },
            {
                name: 'indexEntryLimit'
            },
            {
                name: 'substringIndexEntryLimit'
            },
            {
                name: 'maintainMatchCountForKeysExceedingEntryLimit'
            },
            {
                name: 'indexType'
            },
            {
                name: 'substringLength'
            },
            {
                name: 'primeIndex'
            },
            {
                name: 'primeInternalNodesOnly'
            },
            {
                name: 'equalityIndexFilter'
            },
            {
                name: 'maintainEqualityIndexWithoutFilter'
            },
            {
                name: 'cacheMode'
            },
        ]
    },
    '/backends/{backend-name}/local-db-indexes/{local-db-index-name}-DELETE': {
        parameters: [
            {
                name: 'local-db-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}/local-db-indexes-GET': {
        parameters: [
            {
                name: 'backend-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/backends/{backend-name}/local-db-indexes/{local-db-index-name}-GET': {
        parameters: [
            {
                name: 'local-db-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}/local-db-indexes/{local-db-index-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'local-db-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}/local-db-vlv-indexes-POST': {
        parameters: [
            {
                name: 'indexName'
            },
            {
                name: 'backend-name'
            },
            {
                name: 'schemas'
            },
            {
                name: 'baseDN'
            },
            {
                name: 'scope'
            },
            {
                name: 'filter'
            },
            {
                name: 'sortOrder'
            },
            {
                name: 'name'
            },
            {
                name: 'maxBlockSize'
            },
            {
                name: 'cacheMode'
            },
        ]
    },
    '/backends/{backend-name}/local-db-vlv-indexes/{local-db-vlv-index-name}-DELETE': {
        parameters: [
            {
                name: 'local-db-vlv-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}/local-db-vlv-indexes/{local-db-vlv-index-name}-GET': {
        parameters: [
            {
                name: 'local-db-vlv-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/backends/{backend-name}/local-db-vlv-indexes-GET': {
        parameters: [
            {
                name: 'backend-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/backends/{backend-name}/local-db-vlv-indexes/{local-db-vlv-index-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'local-db-vlv-index-name'
            },
            {
                name: 'backend-name'
            },
        ]
    },
    '/locations-POST': {
        parameters: [
            {
                name: 'locationName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
        ]
    },
    '/locations/{location-name}-GET': {
        parameters: [
            {
                name: 'location-name'
            },
        ]
    },
    '/locations-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/locations/{location-name}-DELETE': {
        parameters: [
            {
                name: 'location-name'
            },
        ]
    },
    '/locations/{location-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'location-name'
            },
        ]
    },
    '/log-field-behaviors-POST': {
        parameters: [
            {
                name: 'behaviorName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'preserveField'
            },
            {
                name: 'preserveFieldName'
            },
            {
                name: 'omitField'
            },
            {
                name: 'omitFieldName'
            },
            {
                name: 'redactEntireValueField'
            },
            {
                name: 'redactEntireValueFieldName'
            },
            {
                name: 'redactValueComponentsField'
            },
            {
                name: 'redactValueComponentsFieldName'
            },
            {
                name: 'tokenizeEntireValueField'
            },
            {
                name: 'tokenizeEntireValueFieldName'
            },
            {
                name: 'tokenizeValueComponentsField'
            },
            {
                name: 'tokenizeValueComponentsFieldName'
            },
            {
                name: 'defaultBehavior'
            },
        ]
    },
    '/log-field-behaviors/{log-field-behavior-name}-DELETE': {
        parameters: [
            {
                name: 'log-field-behavior-name'
            },
        ]
    },
    '/log-field-behaviors-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/log-field-behaviors/{log-field-behavior-name}-GET': {
        parameters: [
            {
                name: 'log-field-behavior-name'
            },
        ]
    },
    '/log-field-behaviors/{log-field-behavior-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'log-field-behavior-name'
            },
        ]
    },
    '/log-field-mappings-POST': {
        parameters: [
            {
                name: 'mappingName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'logFieldTimestamp'
            },
            {
                name: 'logFieldConnectionID'
            },
            {
                name: 'logFieldStartupid'
            },
            {
                name: 'logFieldProductName'
            },
            {
                name: 'logFieldInstanceName'
            },
            {
                name: 'logFieldOperationID'
            },
            {
                name: 'logFieldMessageType'
            },
            {
                name: 'logFieldOperationType'
            },
            {
                name: 'logFieldMessageID'
            },
            {
                name: 'logFieldResultCode'
            },
            {
                name: 'logFieldMessage'
            },
            {
                name: 'logFieldOrigin'
            },
            {
                name: 'logFieldRequesterDN'
            },
            {
                name: 'logFieldDisconnectReason'
            },
            {
                name: 'logFieldDeleteOldRDN'
            },
            {
                name: 'logFieldAuthenticatedUserDN'
            },
            {
                name: 'logFieldProcessingTime'
            },
            {
                name: 'logFieldRequestedAttributes'
            },
            {
                name: 'logFieldSASLMechanismName'
            },
            {
                name: 'logFieldNewRDN'
            },
            {
                name: 'logFieldBaseDN'
            },
            {
                name: 'logFieldBindDN'
            },
            {
                name: 'logFieldMatchedDN'
            },
            {
                name: 'logFieldRequesterIPAddress'
            },
            {
                name: 'logFieldAuthenticationType'
            },
            {
                name: 'logFieldNewSuperiorDN'
            },
            {
                name: 'logFieldFilter'
            },
            {
                name: 'logFieldAlternateAuthorizationDN'
            },
            {
                name: 'logFieldEntryDN'
            },
            {
                name: 'logFieldEntriesReturned'
            },
            {
                name: 'logFieldAuthenticationFailureID'
            },
            {
                name: 'logFieldRequestOID'
            },
            {
                name: 'logFieldResponseOID'
            },
            {
                name: 'logFieldTargetProtocol'
            },
            {
                name: 'logFieldTargetPort'
            },
            {
                name: 'logFieldTargetAddress'
            },
            {
                name: 'logFieldTargetAttribute'
            },
            {
                name: 'logFieldTargetHost'
            },
            {
                name: 'logFieldProtocolVersion'
            },
            {
                name: 'logFieldProtocolName'
            },
            {
                name: 'logFieldAuthenticationFailureReason'
            },
            {
                name: 'logFieldAdditionalInformation'
            },
            {
                name: 'logFieldUnindexed'
            },
            {
                name: 'logFieldScope'
            },
            {
                name: 'logFieldReferralUrls'
            },
            {
                name: 'logFieldSourceAddress'
            },
            {
                name: 'logFieldMessageIDToAbandon'
            },
            {
                name: 'logFieldResponseControls'
            },
            {
                name: 'logFieldRequestControls'
            },
            {
                name: 'logFieldIntermediateClientResult'
            },
            {
                name: 'logFieldIntermediateClientRequest'
            },
            {
                name: 'logFieldReplicationChangeID'
            },
            {
                name: 'logFieldCategory'
            },
            {
                name: 'logFieldSeverity'
            },
        ]
    },
    '/log-field-mappings/{log-field-mapping-name}-DELETE': {
        parameters: [
            {
                name: 'log-field-mapping-name'
            },
        ]
    },
    '/log-field-mappings-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/log-field-mappings/{log-field-mapping-name}-GET': {
        parameters: [
            {
                name: 'log-field-mapping-name'
            },
        ]
    },
    '/log-field-mappings/{log-field-mapping-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'log-field-mapping-name'
            },
        ]
    },
    '/log-field-syntaxes-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/log-field-syntaxes/{log-field-syntax-name}-GET': {
        parameters: [
            {
                name: 'log-field-syntax-name'
            },
        ]
    },
    '/log-field-syntaxes/{log-field-syntax-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'log-field-syntax-name'
            },
        ]
    },
    '/log-file-rotation-listeners-POST': {
        parameters: [
            {
                name: 'listenerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'awsExternalServer'
            },
            {
                name: 's3BucketName'
            },
            {
                name: 'targetThroughputInMegabitsPerSecond'
            },
            {
                name: 'maximumConcurrentTransferConnections'
            },
            {
                name: 'maximumFileCountToRetain'
            },
            {
                name: 'maximumFileAgeToRetain'
            },
            {
                name: 'fileRetentionPattern'
            },
            {
                name: 'enabled'
            },
            {
                name: 'outputDirectory'
            },
            {
                name: 'copyToDirectory'
            },
            {
                name: 'compressOnCopy'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/log-file-rotation-listeners/{log-file-rotation-listener-name}-DELETE': {
        parameters: [
            {
                name: 'log-file-rotation-listener-name'
            },
        ]
    },
    '/log-file-rotation-listeners/{log-file-rotation-listener-name}-GET': {
        parameters: [
            {
                name: 'log-file-rotation-listener-name'
            },
        ]
    },
    '/log-file-rotation-listeners-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/log-file-rotation-listeners/{log-file-rotation-listener-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'log-file-rotation-listener-name'
            },
        ]
    },
    '/log-publishers-POST': {
        parameters: [
            {
                name: 'publisherName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'syslogExternalServer'
            },
            {
                name: 'syslogFacility'
            },
            {
                name: 'syslogSeverity'
            },
            {
                name: 'syslogMessageHostName'
            },
            {
                name: 'syslogMessageApplicationName'
            },
            {
                name: 'queueSize'
            },
            {
                name: 'writeMultiLineMessages'
            },
            {
                name: 'useReversibleForm'
            },
            {
                name: 'softDeleteEntryAuditBehavior'
            },
            {
                name: 'includeOperationPurposeRequestControl'
            },
            {
                name: 'includeIntermediateClientRequestControl'
            },
            {
                name: 'obscureAttribute'
            },
            {
                name: 'excludeAttribute'
            },
            {
                name: 'suppressInternalOperations'
            },
            {
                name: 'includeProductName'
            },
            {
                name: 'includeInstanceName'
            },
            {
                name: 'includeStartupID'
            },
            {
                name: 'includeThreadID'
            },
            {
                name: 'includeRequesterDN'
            },
            {
                name: 'includeRequesterIPAddress'
            },
            {
                name: 'includeRequestControls'
            },
            {
                name: 'includeResponseControls'
            },
            {
                name: 'includeReplicationChangeID'
            },
            {
                name: 'logSecurityNegotiation'
            },
            {
                name: 'suppressReplicationOperations'
            },
            {
                name: 'connectionCriteria'
            },
            {
                name: 'requestCriteria'
            },
            {
                name: 'resultCriteria'
            },
            {
                name: 'enabled'
            },
            {
                name: 'loggingErrorBehavior'
            },
            {
                name: 'serverHostName'
            },
            {
                name: 'serverPort'
            },
            {
                name: 'autoFlush'
            },
            {
                name: 'asynchronous'
            },
            {
                name: 'defaultSeverity'
            },
            {
                name: 'overrideSeverity'
            },
            {
                name: 'logFile'
            },
            {
                name: 'logFilePermissions'
            },
            {
                name: 'rotationPolicy'
            },
            {
                name: 'rotationListener'
            },
            {
                name: 'retentionPolicy'
            },
            {
                name: 'compressionMechanism'
            },
            {
                name: 'signLog'
            },
            {
                name: 'encryptLog'
            },
            {
                name: 'encryptionSettingsDefinitionID'
            },
            {
                name: 'append'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
            {
                name: 'bufferSize'
            },
            {
                name: 'timeInterval'
            },
            {
                name: 'logConnects'
            },
            {
                name: 'logDisconnects'
            },
            {
                name: 'logClientCertificates'
            },
            {
                name: 'logRequests'
            },
            {
                name: 'logResults'
            },
            {
                name: 'logSearchEntries'
            },
            {
                name: 'logSearchReferences'
            },
            {
                name: 'logIntermediateResponses'
            },
            {
                name: 'correlateRequestsAndResults'
            },
            {
                name: 'searchEntryCriteria'
            },
            {
                name: 'searchReferenceCriteria'
            },
            {
                name: 'minIncludedOperationProcessingTime'
            },
            {
                name: 'minIncludedPhaseTimeNanos'
            },
            {
                name: 'maxStringLength'
            },
            {
                name: 'includeRequestDetailsInResultMessages'
            },
            {
                name: 'logAssuranceCompleted'
            },
            {
                name: 'includeRequestDetailsInSearchEntryMessages'
            },
            {
                name: 'includeRequestDetailsInSearchReferenceMessages'
            },
            {
                name: 'includeRequestDetailsInIntermediateResponseMessages'
            },
            {
                name: 'includeResultCodeNames'
            },
            {
                name: 'includeExtendedSearchRequestDetails'
            },
            {
                name: 'includeAddAttributeNames'
            },
            {
                name: 'includeModifyAttributeNames'
            },
            {
                name: 'includeSearchEntryAttributeNames'
            },
            {
                name: 'generifyMessageStringsWhenPossible'
            },
            {
                name: 'logFieldBehavior'
            },
            {
                name: 'debugMessageType'
            },
            {
                name: 'httpMessageType'
            },
            {
                name: 'accessTokenValidatorMessageType'
            },
            {
                name: 'idTokenValidatorMessageType'
            },
            {
                name: 'scimMessageType'
            },
            {
                name: 'consentMessageType'
            },
            {
                name: 'directoryRESTAPIMessageType'
            },
            {
                name: 'extensionMessageType'
            },
            {
                name: 'includePathPattern'
            },
            {
                name: 'excludePathPattern'
            },
            {
                name: 'server'
            },
            {
                name: 'logFieldMapping'
            },
            {
                name: 'logTableName'
            },
            {
                name: 'timestampPrecision'
            },
            {
                name: 'defaultDebugLevel'
            },
            {
                name: 'defaultDebugCategory'
            },
            {
                name: 'defaultOmitMethodEntryArguments'
            },
            {
                name: 'defaultOmitMethodReturnValue'
            },
            {
                name: 'defaultIncludeThrowableCause'
            },
            {
                name: 'defaultThrowableStackFrames'
            },
            {
                name: 'logRequestHeaders'
            },
            {
                name: 'suppressedRequestHeaderName'
            },
            {
                name: 'logResponseHeaders'
            },
            {
                name: 'suppressedResponseHeaderName'
            },
            {
                name: 'logRequestAuthorizationType'
            },
            {
                name: 'logRequestCookieNames'
            },
            {
                name: 'logResponseCookieNames'
            },
            {
                name: 'logRequestParameters'
            },
            {
                name: 'logRequestProtocol'
            },
            {
                name: 'suppressedRequestParameterName'
            },
            {
                name: 'logRedirectURI'
            },
            {
                name: 'obscureSensitiveContent'
            },
            {
                name: 'debugACIEnabled'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'outputLocation'
            },
        ]
    },
    '/log-publishers/{log-publisher-name}-DELETE': {
        parameters: [
            {
                name: 'log-publisher-name'
            },
        ]
    },
    '/log-publishers/{log-publisher-name}-GET': {
        parameters: [
            {
                name: 'log-publisher-name'
            },
        ]
    },
    '/log-publishers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/log-publishers/{log-publisher-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'log-publisher-name'
            },
        ]
    },
    '/log-retention-policies-POST': {
        parameters: [
            {
                name: 'policyName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'retainDuration'
            },
            {
                name: 'numberOfFiles'
            },
            {
                name: 'freeDiskSpace'
            },
            {
                name: 'diskSpaceUsed'
            },
        ]
    },
    '/log-retention-policies/{log-retention-policy-name}-DELETE': {
        parameters: [
            {
                name: 'log-retention-policy-name'
            },
        ]
    },
    '/log-retention-policies/{log-retention-policy-name}-GET': {
        parameters: [
            {
                name: 'log-retention-policy-name'
            },
        ]
    },
    '/log-retention-policies-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/log-retention-policies/{log-retention-policy-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'log-retention-policy-name'
            },
        ]
    },
    '/log-rotation-policies-POST': {
        parameters: [
            {
                name: 'policyName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'rotationInterval'
            },
            {
                name: 'timeOfDay'
            },
            {
                name: 'fileSizeLimit'
            },
        ]
    },
    '/log-rotation-policies/{log-rotation-policy-name}-DELETE': {
        parameters: [
            {
                name: 'log-rotation-policy-name'
            },
        ]
    },
    '/log-rotation-policies-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/log-rotation-policies/{log-rotation-policy-name}-GET': {
        parameters: [
            {
                name: 'log-rotation-policy-name'
            },
        ]
    },
    '/log-rotation-policies/{log-rotation-policy-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'log-rotation-policy-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}/mac-secret-keys/{mac-secret-key-name}-GET': {
        parameters: [
            {
                name: 'mac-secret-key-name'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}/mac-secret-keys-GET': {
        parameters: [
            {
                name: 'server-instance-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/server-instances/{server-instance-name}/mac-secret-keys/{mac-secret-key-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'mac-secret-key-name'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/matching-rules/{matching-rule-name}-GET': {
        parameters: [
            {
                name: 'matching-rule-name'
            },
        ]
    },
    '/matching-rules-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/matching-rules/{matching-rule-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'matching-rule-name'
            },
        ]
    },
    '/monitor-providers-POST': {
        parameters: [
            {
                name: 'providerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'checkFrequency'
            },
            {
                name: 'prolongedOutageDuration'
            },
            {
                name: 'prolongedOutageBehavior'
            },
            {
                name: 'enabled'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/monitor-providers/{monitor-provider-name}-DELETE': {
        parameters: [
            {
                name: 'monitor-provider-name'
            },
        ]
    },
    '/monitor-providers/{monitor-provider-name}-GET': {
        parameters: [
            {
                name: 'monitor-provider-name'
            },
        ]
    },
    '/monitor-providers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/monitor-providers/{monitor-provider-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'monitor-provider-name'
            },
        ]
    },
    '/monitoring-endpoints-POST': {
        parameters: [
            {
                name: 'endpointName'
            },
            {
                name: 'schemas'
            },
            {
                name: 'hostname'
            },
            {
                name: 'serverPort'
            },
            {
                name: 'connectionType'
            },
            {
                name: 'trustManagerProvider'
            },
            {
                name: 'additionalTags'
            },
            {
                name: 'enabled'
            },
        ]
    },
    '/monitoring-endpoints/{monitoring-endpoint-name}-DELETE': {
        parameters: [
            {
                name: 'monitoring-endpoint-name'
            },
        ]
    },
    '/monitoring-endpoints/{monitoring-endpoint-name}-GET': {
        parameters: [
            {
                name: 'monitoring-endpoint-name'
            },
        ]
    },
    '/monitoring-endpoints-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/monitoring-endpoints/{monitoring-endpoint-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'monitoring-endpoint-name'
            },
        ]
    },
    '/notification-managers-POST': {
        parameters: [
            {
                name: 'managerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
            {
                name: 'enabled'
            },
            {
                name: 'subscriptionBaseDN'
            },
            {
                name: 'transactionNotification'
            },
            {
                name: 'monitorEntriesEnabled'
            },
        ]
    },
    '/notification-managers/{notification-manager-name}-DELETE': {
        parameters: [
            {
                name: 'notification-manager-name'
            },
        ]
    },
    '/notification-managers/{notification-manager-name}-GET': {
        parameters: [
            {
                name: 'notification-manager-name'
            },
        ]
    },
    '/notification-managers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/notification-managers/{notification-manager-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'notification-manager-name'
            },
        ]
    },
    '/oauth-token-handlers-POST': {
        parameters: [
            {
                name: 'handlerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/oauth-token-handlers/{oauth-token-handler-name}-DELETE': {
        parameters: [
            {
                name: 'oauth-token-handler-name'
            },
        ]
    },
    '/oauth-token-handlers/{oauth-token-handler-name}-GET': {
        parameters: [
            {
                name: 'oauth-token-handler-name'
            },
        ]
    },
    '/oauth-token-handlers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/oauth-token-handlers/{oauth-token-handler-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'oauth-token-handler-name'
            },
        ]
    },
    '/obscured-values-POST': {
        parameters: [
            {
                name: 'valueName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'obscuredValue'
            },
        ]
    },
    '/obscured-values/{obscured-value-name}-DELETE': {
        parameters: [
            {
                name: 'obscured-value-name'
            },
        ]
    },
    '/obscured-values/{obscured-value-name}-GET': {
        parameters: [
            {
                name: 'obscured-value-name'
            },
        ]
    },
    '/obscured-values-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/obscured-values/{obscured-value-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'obscured-value-name'
            },
        ]
    },
    '/otp-delivery-mechanisms-POST': {
        parameters: [
            {
                name: 'mechanismName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'twilioAccountSID'
            },
            {
                name: 'twilioAuthToken'
            },
            {
                name: 'twilioAuthTokenPassphraseProvider'
            },
            {
                name: 'phoneNumberAttributeType'
            },
            {
                name: 'phoneNumberJSONField'
            },
            {
                name: 'phoneNumberJSONObjectFilter'
            },
            {
                name: 'senderPhoneNumber'
            },
            {
                name: 'messageTextBeforeOTP'
            },
            {
                name: 'messageTextAfterOTP'
            },
            {
                name: 'enabled'
            },
            {
                name: 'emailAddressAttributeType'
            },
            {
                name: 'emailAddressJSONField'
            },
            {
                name: 'emailAddressJSONObjectFilter'
            },
            {
                name: 'senderAddress'
            },
            {
                name: 'messageSubject'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/otp-delivery-mechanisms/{otp-delivery-mechanism-name}-DELETE': {
        parameters: [
            {
                name: 'otp-delivery-mechanism-name'
            },
        ]
    },
    '/otp-delivery-mechanisms/{otp-delivery-mechanism-name}-GET': {
        parameters: [
            {
                name: 'otp-delivery-mechanism-name'
            },
        ]
    },
    '/otp-delivery-mechanisms-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/otp-delivery-mechanisms/{otp-delivery-mechanism-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'otp-delivery-mechanism-name'
            },
        ]
    },
    '/pass-through-authentication-handlers-POST': {
        parameters: [
            {
                name: 'handlerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'apiURL'
            },
            {
                name: 'authURL'
            },
            {
                name: 'OAuthClientID'
            },
            {
                name: 'OAuthClientSecret'
            },
            {
                name: 'OAuthClientSecretPassphraseProvider'
            },
            {
                name: 'environmentID'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'userMappingLocalAttribute'
            },
            {
                name: 'userMappingRemoteJSONField'
            },
            {
                name: 'additionalUserMappingSCIMFilter'
            },
            {
                name: 'includedLocalEntryBaseDN'
            },
            {
                name: 'connectionCriteria'
            },
            {
                name: 'requestCriteria'
            },
            {
                name: 'server'
            },
            {
                name: 'serverAccessMode'
            },
            {
                name: 'dnMap'
            },
            {
                name: 'bindDNPattern'
            },
            {
                name: 'searchBaseDN'
            },
            {
                name: 'searchFilterPattern'
            },
            {
                name: 'initialConnections'
            },
            {
                name: 'maxConnections'
            },
            {
                name: 'useLocation'
            },
            {
                name: 'maximumAllowedLocalResponseTime'
            },
            {
                name: 'maximumAllowedNonlocalResponseTime'
            },
            {
                name: 'usePasswordPolicyControl'
            },
            {
                name: 'subordinatePassThroughAuthenticationHandler'
            },
            {
                name: 'continueOnFailureType'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/pass-through-authentication-handlers/{pass-through-authentication-handler-name}-DELETE': {
        parameters: [
            {
                name: 'pass-through-authentication-handler-name'
            },
        ]
    },
    '/pass-through-authentication-handlers/{pass-through-authentication-handler-name}-GET': {
        parameters: [
            {
                name: 'pass-through-authentication-handler-name'
            },
        ]
    },
    '/pass-through-authentication-handlers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/pass-through-authentication-handlers/{pass-through-authentication-handler-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'pass-through-authentication-handler-name'
            },
        ]
    },
    '/passphrase-providers-POST': {
        parameters: [
            {
                name: 'providerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'environmentVariable'
            },
            {
                name: 'enabled'
            },
            {
                name: 'awsExternalServer'
            },
            {
                name: 'secretID'
            },
            {
                name: 'secretFieldName'
            },
            {
                name: 'secretVersionID'
            },
            {
                name: 'secretVersionStage'
            },
            {
                name: 'maxCacheDuration'
            },
            {
                name: 'obscuredValue'
            },
            {
                name: 'keyVaultURI'
            },
            {
                name: 'azureAuthenticationMethod'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'secretName'
            },
            {
                name: 'passwordFile'
            },
            {
                name: 'conjurExternalServer'
            },
            {
                name: 'conjurSecretRelativePath'
            },
            {
                name: 'vaultExternalServer'
            },
            {
                name: 'vaultSecretPath'
            },
            {
                name: 'vaultSecretFieldName'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/passphrase-providers/{passphrase-provider-name}-DELETE': {
        parameters: [
            {
                name: 'passphrase-provider-name'
            },
        ]
    },
    '/passphrase-providers/{passphrase-provider-name}-GET': {
        parameters: [
            {
                name: 'passphrase-provider-name'
            },
        ]
    },
    '/passphrase-providers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/passphrase-providers/{passphrase-provider-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'passphrase-provider-name'
            },
        ]
    },
    '/password-generators-POST': {
        parameters: [
            {
                name: 'generatorName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'passwordCharacterSet'
            },
            {
                name: 'passwordFormat'
            },
            {
                name: 'enabled'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'dictionaryFile'
            },
            {
                name: 'minimumPasswordCharacters'
            },
            {
                name: 'minimumPasswordWords'
            },
            {
                name: 'capitalizeWords'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/password-generators/{password-generator-name}-DELETE': {
        parameters: [
            {
                name: 'password-generator-name'
            },
        ]
    },
    '/password-generators/{password-generator-name}-GET': {
        parameters: [
            {
                name: 'password-generator-name'
            },
        ]
    },
    '/password-generators-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/password-generators/{password-generator-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'password-generator-name'
            },
        ]
    },
    '/password-policies-POST': {
        parameters: [
            {
                name: 'policyName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'requireSecureAuthentication'
            },
            {
                name: 'requireSecurePasswordChanges'
            },
            {
                name: 'accountStatusNotificationHandler'
            },
            {
                name: 'stateUpdateFailurePolicy'
            },
            {
                name: 'enableDebug'
            },
            {
                name: 'passwordAttribute'
            },
            {
                name: 'defaultPasswordStorageScheme'
            },
            {
                name: 'deprecatedPasswordStorageScheme'
            },
            {
                name: 'reEncodePasswordsOnSchemeConfigChange'
            },
            {
                name: 'allowMultiplePasswordValues'
            },
            {
                name: 'allowPreEncodedPasswords'
            },
            {
                name: 'passwordValidator'
            },
            {
                name: 'bindPasswordValidator'
            },
            {
                name: 'minimumBindPasswordValidationFrequency'
            },
            {
                name: 'bindPasswordValidationFailureAction'
            },
            {
                name: 'passwordGenerator'
            },
            {
                name: 'passwordHistoryCount'
            },
            {
                name: 'passwordHistoryDuration'
            },
            {
                name: 'minPasswordAge'
            },
            {
                name: 'maxPasswordAge'
            },
            {
                name: 'passwordExpirationWarningInterval'
            },
            {
                name: 'expirePasswordsWithoutWarning'
            },
            {
                name: 'returnPasswordExpirationControls'
            },
            {
                name: 'allowExpiredPasswordChanges'
            },
            {
                name: 'graceLoginCount'
            },
            {
                name: 'requireChangeByTime'
            },
            {
                name: 'lockoutFailureCount'
            },
            {
                name: 'lockoutDuration'
            },
            {
                name: 'lockoutFailureExpirationInterval'
            },
            {
                name: 'ignoreDuplicatePasswordFailures'
            },
            {
                name: 'failureLockoutAction'
            },
            {
                name: 'idleLockoutInterval'
            },
            {
                name: 'allowUserPasswordChanges'
            },
            {
                name: 'passwordChangeRequiresCurrentPassword'
            },
            {
                name: 'passwordRetirementBehavior'
            },
            {
                name: 'maxRetiredPasswordAge'
            },
            {
                name: 'allowedPasswordResetTokenUseCondition'
            },
            {
                name: 'forceChangeOnAdd'
            },
            {
                name: 'forceChangeOnReset'
            },
            {
                name: 'maxPasswordResetAge'
            },
            {
                name: 'skipValidationForAdministrators'
            },
            {
                name: 'maximumRecentLoginHistorySuccessfulAuthenticationCount'
            },
            {
                name: 'maximumRecentLoginHistorySuccessfulAuthenticationDuration'
            },
            {
                name: 'maximumRecentLoginHistoryFailedAuthenticationCount'
            },
            {
                name: 'maximumRecentLoginHistoryFailedAuthenticationDuration'
            },
            {
                name: 'recentLoginHistorySimilarAttemptBehavior'
            },
            {
                name: 'lastLoginIPAddressAttribute'
            },
            {
                name: 'lastLoginTimeAttribute'
            },
            {
                name: 'lastLoginTimeFormat'
            },
            {
                name: 'previousLastLoginTimeFormat'
            },
        ]
    },
    '/password-policies/{password-policy-name}-DELETE': {
        parameters: [
            {
                name: 'password-policy-name'
            },
        ]
    },
    '/password-policies/{password-policy-name}-GET': {
        parameters: [
            {
                name: 'password-policy-name'
            },
        ]
    },
    '/password-policies-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/password-policies/{password-policy-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'password-policy-name'
            },
        ]
    },
    '/password-storage-schemes-POST': {
        parameters: [
            {
                name: 'schemeName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'iterationCount'
            },
            {
                name: 'parallelismFactor'
            },
            {
                name: 'memoryUsageKb'
            },
            {
                name: 'saltLengthBytes'
            },
            {
                name: 'derivedKeyLengthBytes'
            },
            {
                name: 'enabled'
            },
            {
                name: 'passwordEncodingMechanism'
            },
            {
                name: 'numDigestRounds'
            },
            {
                name: 'maxPasswordLength'
            },
            {
                name: 'vaultExternalServer'
            },
            {
                name: 'defaultField'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
            {
                name: 'digestAlgorithm'
            },
            {
                name: 'encryptionSettingsDefinitionID'
            },
            {
                name: 'bcryptCostFactor'
            },
            {
                name: 'awsExternalServer'
            },
            {
                name: 'keyVaultURI'
            },
            {
                name: 'azureAuthenticationMethod'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'conjurExternalServer'
            },
            {
                name: 'scryptCpuMemoryCostFactorExponent'
            },
            {
                name: 'scryptBlockSize'
            },
            {
                name: 'scryptParallelizationParameter'
            },
        ]
    },
    '/password-storage-schemes/{password-storage-scheme-name}-DELETE': {
        parameters: [
            {
                name: 'password-storage-scheme-name'
            },
        ]
    },
    '/password-storage-schemes/{password-storage-scheme-name}-GET': {
        parameters: [
            {
                name: 'password-storage-scheme-name'
            },
        ]
    },
    '/password-storage-schemes-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/password-storage-schemes/{password-storage-scheme-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'password-storage-scheme-name'
            },
        ]
    },
    '/password-validators-POST': {
        parameters: [
            {
                name: 'validatorName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'characterSet'
            },
            {
                name: 'allowUnclassifiedCharacters'
            },
            {
                name: 'minimumRequiredCharacterSets'
            },
            {
                name: 'enabled'
            },
            {
                name: 'validatorRequirementDescription'
            },
            {
                name: 'validatorFailureMessage'
            },
            {
                name: 'minPasswordDifference'
            },
            {
                name: 'matchAttribute'
            },
            {
                name: 'testPasswordSubstringOfAttributeValue'
            },
            {
                name: 'testAttributeValueSubstringOfPassword'
            },
            {
                name: 'minimumAttributeValueLengthForSubstringMatches'
            },
            {
                name: 'testReversedPassword'
            },
            {
                name: 'maxConsecutiveLength'
            },
            {
                name: 'caseSensitiveValidation'
            },
            {
                name: 'dictionaryFile'
            },
            {
                name: 'ignoreLeadingNonAlphabeticCharacters'
            },
            {
                name: 'ignoreTrailingNonAlphabeticCharacters'
            },
            {
                name: 'stripDiacriticalMarks'
            },
            {
                name: 'alternativePasswordCharacterMapping'
            },
            {
                name: 'maximumAllowedPercentOfPassword'
            },
            {
                name: 'assumedPasswordGuessesPerSecond'
            },
            {
                name: 'minimumAcceptableTimeToExhaustSearchSpace'
            },
            {
                name: 'allowNonAsciiCharacters'
            },
            {
                name: 'allowUnknownCharacters'
            },
            {
                name: 'allowedCharacterType'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'pwnedPasswordsBaseURL'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'httpConnectTimeout'
            },
            {
                name: 'httpResponseTimeout'
            },
            {
                name: 'invokeForAdd'
            },
            {
                name: 'invokeForSelfChange'
            },
            {
                name: 'invokeForAdminReset'
            },
            {
                name: 'acceptPasswordOnServiceError'
            },
            {
                name: 'keyManagerProvider'
            },
            {
                name: 'trustManagerProvider'
            },
            {
                name: 'disallowedCharacters'
            },
            {
                name: 'disallowedLeadingCharacters'
            },
            {
                name: 'disallowedTrailingCharacters'
            },
            {
                name: 'maxPasswordLength'
            },
            {
                name: 'minPasswordLength'
            },
            {
                name: 'matchPattern'
            },
            {
                name: 'matchBehavior'
            },
            {
                name: 'minUniqueCharacters'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/password-validators/{password-validator-name}-DELETE': {
        parameters: [
            {
                name: 'password-validator-name'
            },
        ]
    },
    '/password-validators-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/password-validators/{password-validator-name}-GET': {
        parameters: [
            {
                name: 'password-validator-name'
            },
        ]
    },
    '/password-validators/{password-validator-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'password-validator-name'
            },
        ]
    },
    '/plugin-root/plugins-POST': {
        parameters: [
            {
                name: 'pluginName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'traditionalStaticGroupObjectClass'
            },
            {
                name: 'maximumMembershipUpdatesPerModify'
            },
            {
                name: 'readOperationSupport'
            },
            {
                name: 'enabled'
            },
            {
                name: 'invokeForInternalOperations'
            },
            {
                name: 'pluginType'
            },
            {
                name: 'numThreads'
            },
            {
                name: 'baseDN'
            },
            {
                name: 'lowerBound'
            },
            {
                name: 'upperBound'
            },
            {
                name: 'filterPrefix'
            },
            {
                name: 'filterSuffix'
            },
            {
                name: 'filter'
            },
            {
                name: 'attributeType'
            },
            {
                name: 'pollingInterval'
            },
            {
                name: 'peerServerPriorityIndex'
            },
            {
                name: 'maxUpdatesPerSecond'
            },
            {
                name: 'numDeleteThreads'
            },
            {
                name: 'invokeGCDayOfWeek'
            },
            {
                name: 'invokeGCTimeUtc'
            },
            {
                name: 'delayAfterAlert'
            },
            {
                name: 'delayPostGC'
            },
            {
                name: 'apiURL'
            },
            {
                name: 'authURL'
            },
            {
                name: 'OAuthClientID'
            },
            {
                name: 'OAuthClientSecret'
            },
            {
                name: 'OAuthClientSecretPassphraseProvider'
            },
            {
                name: 'environmentID'
            },
            {
                name: 'httpProxyExternalServer'
            },
            {
                name: 'includedLocalEntryBaseDN'
            },
            {
                name: 'connectionCriteria'
            },
            {
                name: 'requestCriteria'
            },
            {
                name: 'tryLocalBind'
            },
            {
                name: 'overrideLocalPassword'
            },
            {
                name: 'updateLocalPassword'
            },
            {
                name: 'updateLocalPasswordDN'
            },
            {
                name: 'allowLaxPassThroughAuthenticationPasswords'
            },
            {
                name: 'ignoredPasswordPolicyStateErrorCondition'
            },
            {
                name: 'userMappingLocalAttribute'
            },
            {
                name: 'userMappingRemoteJSONField'
            },
            {
                name: 'additionalUserMappingSCIMFilter'
            },
            {
                name: 'scope'
            },
            {
                name: 'includeAttribute'
            },
            {
                name: 'outputFile'
            },
            {
                name: 'previousFileExtension'
            },
            {
                name: 'logInterval'
            },
            {
                name: 'collectionInterval'
            },
            {
                name: 'suppressIfIdle'
            },
            {
                name: 'headerPrefixPerColumn'
            },
            {
                name: 'emptyInsteadOfZero'
            },
            {
                name: 'linesBetweenHeader'
            },
            {
                name: 'includedLDAPStat'
            },
            {
                name: 'includedResourceStat'
            },
            {
                name: 'histogramFormat'
            },
            {
                name: 'histogramOpType'
            },
            {
                name: 'perApplicationLDAPStats'
            },
            {
                name: 'statusSummaryInfo'
            },
            {
                name: 'ldapChangelogInfo'
            },
            {
                name: 'gaugeInfo'
            },
            {
                name: 'logFileFormat'
            },
            {
                name: 'logFile'
            },
            {
                name: 'logFilePermissions'
            },
            {
                name: 'append'
            },
            {
                name: 'rotationPolicy'
            },
            {
                name: 'rotationListener'
            },
            {
                name: 'retentionPolicy'
            },
            {
                name: 'loggingErrorBehavior'
            },
            {
                name: 'localDBBackendInfo'
            },
            {
                name: 'replicationInfo'
            },
            {
                name: 'entryCacheInfo'
            },
            {
                name: 'hostInfo'
            },
            {
                name: 'includedLDAPApplication'
            },
            {
                name: 'datetimeAttribute'
            },
            {
                name: 'datetimeJSONField'
            },
            {
                name: 'datetimeFormat'
            },
            {
                name: 'customDatetimeFormat'
            },
            {
                name: 'customTimezone'
            },
            {
                name: 'expirationOffset'
            },
            {
                name: 'purgeBehavior'
            },
            {
                name: 'numMostExpensivePhasesShown'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
            {
                name: 'server'
            },
            {
                name: 'serverAccessMode'
            },
            {
                name: 'dnMap'
            },
            {
                name: 'bindDNPattern'
            },
            {
                name: 'searchBaseDN'
            },
            {
                name: 'searchFilterPattern'
            },
            {
                name: 'initialConnections'
            },
            {
                name: 'maxConnections'
            },
            {
                name: 'sourceDN'
            },
            {
                name: 'targetDN'
            },
            {
                name: 'enableAttributeMapping'
            },
            {
                name: 'mapAttribute'
            },
            {
                name: 'enableControlMapping'
            },
            {
                name: 'alwaysMapResponses'
            },
            {
                name: 'referralBaseURL'
            },
            {
                name: 'contextName'
            },
            {
                name: 'agentxAddress'
            },
            {
                name: 'agentxPort'
            },
            {
                name: 'numWorkerThreads'
            },
            {
                name: 'sessionTimeout'
            },
            {
                name: 'connectRetryMaxWait'
            },
            {
                name: 'pingInterval'
            },
            {
                name: 'allowedRequestControl'
            },
            {
                name: 'valuePattern'
            },
            {
                name: 'multipleValuePatternBehavior'
            },
            {
                name: 'multiValuedAttributeBehavior'
            },
            {
                name: 'targetAttributeExistsDuringInitialPopulationBehavior'
            },
            {
                name: 'updateSourceAttributeBehavior'
            },
            {
                name: 'sourceAttributeRemovalBehavior'
            },
            {
                name: 'updateTargetAttributeBehavior'
            },
            {
                name: 'includeBaseDN'
            },
            {
                name: 'excludeBaseDN'
            },
            {
                name: 'includeFilter'
            },
            {
                name: 'excludeFilter'
            },
            {
                name: 'updatedEntryNewlyMatchesCriteriaBehavior'
            },
            {
                name: 'updatedEntryNoLongerMatchesCriteriaBehavior'
            },
            {
                name: 'sourceAttribute'
            },
            {
                name: 'targetAttribute'
            },
            {
                name: 'delay'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'passThroughAuthenticationHandler'
            },
            {
                name: 'updateInterval'
            },
            {
                name: 'type'
            },
            {
                name: 'multipleAttributeBehavior'
            },
            {
                name: 'preventConflictsWithSoftDeletedEntries'
            },
            {
                name: 'preventAddingMembersToNonexistentGroups'
            },
            {
                name: 'preventAddingGroupsAsInvertedStaticGroupMembers'
            },
            {
                name: 'preventNestingNonexistentGroups'
            },
        ]
    },
    '/plugin-root/plugins/{plugin-name}-DELETE': {
        parameters: [
            {
                name: 'plugin-name'
            },
        ]
    },
    '/plugin-root/plugins/{plugin-name}-GET': {
        parameters: [
            {
                name: 'plugin-name'
            },
        ]
    },
    '/plugin-root/plugins-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/plugin-root/plugins/{plugin-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'plugin-name'
            },
        ]
    },
    '/plugin-root-GET': {
        parameters: [
        ]
    },
    '/plugin-root-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/post-ldif-export-task-processors-POST': {
        parameters: [
            {
                name: 'processorName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'awsExternalServer'
            },
            {
                name: 's3BucketName'
            },
            {
                name: 'targetThroughputInMegabitsPerSecond'
            },
            {
                name: 'maximumConcurrentTransferConnections'
            },
            {
                name: 'maximumFileCountToRetain'
            },
            {
                name: 'maximumFileAgeToRetain'
            },
            {
                name: 'fileRetentionPattern'
            },
            {
                name: 'enabled'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/post-ldif-export-task-processors/{post-ldif-export-task-processor-name}-DELETE': {
        parameters: [
            {
                name: 'post-ldif-export-task-processor-name'
            },
        ]
    },
    '/post-ldif-export-task-processors/{post-ldif-export-task-processor-name}-GET': {
        parameters: [
            {
                name: 'post-ldif-export-task-processor-name'
            },
        ]
    },
    '/post-ldif-export-task-processors-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/post-ldif-export-task-processors/{post-ldif-export-task-processor-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'post-ldif-export-task-processor-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/prometheus-monitor-attribute-metrics-POST': {
        parameters: [
            {
                name: 'metricName'
            },
            {
                name: 'http-servlet-extension-name'
            },
            {
                name: 'schemas'
            },
            {
                name: 'monitorAttributeName'
            },
            {
                name: 'monitorObjectClassName'
            },
            {
                name: 'metricType'
            },
            {
                name: 'filter'
            },
            {
                name: 'metricDescription'
            },
            {
                name: 'labelNameValuePair'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/prometheus-monitor-attribute-metrics/{prometheus-monitor-attribute-metric-name}-DELETE': {
        parameters: [
            {
                name: 'prometheus-monitor-attribute-metric-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/prometheus-monitor-attribute-metrics/{prometheus-monitor-attribute-metric-name}-GET': {
        parameters: [
            {
                name: 'prometheus-monitor-attribute-metric-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/prometheus-monitor-attribute-metrics-GET': {
        parameters: [
            {
                name: 'http-servlet-extension-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/prometheus-monitor-attribute-metrics/{prometheus-monitor-attribute-metric-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'prometheus-monitor-attribute-metric-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/recurring-tasks-POST': {
        parameters: [
            {
                name: 'taskName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'profileDirectory'
            },
            {
                name: 'includePath'
            },
            {
                name: 'retainPreviousProfileCount'
            },
            {
                name: 'retainPreviousProfileAge'
            },
            {
                name: 'cancelOnTaskDependencyFailure'
            },
            {
                name: 'emailOnStart'
            },
            {
                name: 'emailOnSuccess'
            },
            {
                name: 'emailOnFailure'
            },
            {
                name: 'alertOnStart'
            },
            {
                name: 'alertOnSuccess'
            },
            {
                name: 'alertOnFailure'
            },
            {
                name: 'reason'
            },
            {
                name: 'backupDirectory'
            },
            {
                name: 'includedBackendID'
            },
            {
                name: 'excludedBackendID'
            },
            {
                name: 'compress'
            },
            {
                name: 'encrypt'
            },
            {
                name: 'encryptionSettingsDefinitionID'
            },
            {
                name: 'sign'
            },
            {
                name: 'retainPreviousFullBackupCount'
            },
            {
                name: 'retainPreviousFullBackupAge'
            },
            {
                name: 'maxMegabytesPerSecond'
            },
            {
                name: 'sleepDuration'
            },
            {
                name: 'durationToWaitForWorkQueueIdle'
            },
            {
                name: 'ldapURLForSearchExpectedToReturnEntries'
            },
            {
                name: 'searchInterval'
            },
            {
                name: 'searchTimeLimit'
            },
            {
                name: 'durationToWaitForSearchToReturnEntries'
            },
            {
                name: 'taskReturnStateIfTimeoutIsEncountered'
            },
            {
                name: 'taskJavaClass'
            },
            {
                name: 'taskObjectClass'
            },
            {
                name: 'taskAttributeValue'
            },
            {
                name: 'outputDirectory'
            },
            {
                name: 'encryptionPassphraseFile'
            },
            {
                name: 'includeExpensiveData'
            },
            {
                name: 'includeReplicationStateDump'
            },
            {
                name: 'includeBinaryFiles'
            },
            {
                name: 'includeExtensionSource'
            },
            {
                name: 'useSequentialMode'
            },
            {
                name: 'securityLevel'
            },
            {
                name: 'jstackCount'
            },
            {
                name: 'reportCount'
            },
            {
                name: 'reportIntervalSeconds'
            },
            {
                name: 'logDuration'
            },
            {
                name: 'logFileHeadCollectionSize'
            },
            {
                name: 'logFileTailCollectionSize'
            },
            {
                name: 'comment'
            },
            {
                name: 'retainPreviousSupportDataArchiveCount'
            },
            {
                name: 'retainPreviousSupportDataArchiveAge'
            },
            {
                name: 'ldifDirectory'
            },
            {
                name: 'backendID'
            },
            {
                name: 'excludeBackendID'
            },
            {
                name: 'retainPreviousLDIFExportCount'
            },
            {
                name: 'retainPreviousLDIFExportAge'
            },
            {
                name: 'postLDIFExportTaskProcessor'
            },
            {
                name: 'baseOutputDirectory'
            },
            {
                name: 'dataSecurityAuditor'
            },
            {
                name: 'backend'
            },
            {
                name: 'includeFilter'
            },
            {
                name: 'retainPreviousReportCount'
            },
            {
                name: 'retainPreviousReportAge'
            },
            {
                name: 'commandPath'
            },
            {
                name: 'commandArguments'
            },
            {
                name: 'commandOutputFileBaseName'
            },
            {
                name: 'retainPreviousOutputFileCount'
            },
            {
                name: 'retainPreviousOutputFileAge'
            },
            {
                name: 'logCommandOutput'
            },
            {
                name: 'taskCompletionStateForNonzeroExitCode'
            },
            {
                name: 'workingDirectory'
            },
            {
                name: 'targetDirectory'
            },
            {
                name: 'filenamePattern'
            },
            {
                name: 'timestampFormat'
            },
            {
                name: 'retainFileCount'
            },
            {
                name: 'retainFileAge'
            },
            {
                name: 'retainAggregateFileSize'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/recurring-tasks/{recurring-task-name}-DELETE': {
        parameters: [
            {
                name: 'recurring-task-name'
            },
        ]
    },
    '/recurring-tasks/{recurring-task-name}-GET': {
        parameters: [
            {
                name: 'recurring-task-name'
            },
        ]
    },
    '/recurring-tasks-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/recurring-tasks/{recurring-task-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'recurring-task-name'
            },
        ]
    },
    '/recurring-task-chains-POST': {
        parameters: [
            {
                name: 'chainName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'recurringTask'
            },
            {
                name: 'scheduledMonth'
            },
            {
                name: 'scheduledDateSelectionType'
            },
            {
                name: 'scheduledDayOfTheWeek'
            },
            {
                name: 'scheduledDayOfTheMonth'
            },
            {
                name: 'scheduledTimeOfDay'
            },
            {
                name: 'timeZone'
            },
            {
                name: 'interruptedByShutdownBehavior'
            },
            {
                name: 'serverOfflineAtStartTimeBehavior'
            },
        ]
    },
    '/recurring-task-chains/{recurring-task-chain-name}-DELETE': {
        parameters: [
            {
                name: 'recurring-task-chain-name'
            },
        ]
    },
    '/recurring-task-chains/{recurring-task-chain-name}-GET': {
        parameters: [
            {
                name: 'recurring-task-chain-name'
            },
        ]
    },
    '/recurring-task-chains-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/recurring-task-chains/{recurring-task-chain-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'recurring-task-chain-name'
            },
        ]
    },
    '/replication-assurance-policies-POST': {
        parameters: [
            {
                name: 'policyName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'evaluationOrderIndex'
            },
            {
                name: 'localLevel'
            },
            {
                name: 'remoteLevel'
            },
            {
                name: 'timeout'
            },
            {
                name: 'connectionCriteria'
            },
            {
                name: 'requestCriteria'
            },
        ]
    },
    '/replication-assurance-policies/{replication-assurance-policy-name}-DELETE': {
        parameters: [
            {
                name: 'replication-assurance-policy-name'
            },
        ]
    },
    '/replication-assurance-policies/{replication-assurance-policy-name}-GET': {
        parameters: [
            {
                name: 'replication-assurance-policy-name'
            },
        ]
    },
    '/replication-assurance-policies-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/replication-assurance-policies/{replication-assurance-policy-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'replication-assurance-policy-name'
            },
        ]
    },
    '/synchronization-providers/{synchronization-provider-name}/replication-domains/{replication-domain-name}-GET': {
        parameters: [
            {
                name: 'replication-domain-name'
            },
            {
                name: 'synchronization-provider-name'
            },
        ]
    },
    '/synchronization-providers/{synchronization-provider-name}/replication-domains-GET': {
        parameters: [
            {
                name: 'synchronization-provider-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/synchronization-providers/{synchronization-provider-name}/replication-domains/{replication-domain-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'replication-domain-name'
            },
            {
                name: 'synchronization-provider-name'
            },
        ]
    },
    '/synchronization-providers/{synchronization-provider-name}/replication-server-GET': {
        parameters: [
            {
                name: 'synchronization-provider-name'
            },
        ]
    },
    '/synchronization-providers/{synchronization-provider-name}/replication-server-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'synchronization-provider-name'
            },
        ]
    },
    '/request-criteria-POST': {
        parameters: [
            {
                name: 'criteriaName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'operationType'
            },
            {
                name: 'operationOrigin'
            },
            {
                name: 'connectionCriteria'
            },
            {
                name: 'allIncludedRequestControl'
            },
            {
                name: 'anyIncludedRequestControl'
            },
            {
                name: 'notAllIncludedRequestControl'
            },
            {
                name: 'noneIncludedRequestControl'
            },
            {
                name: 'includedTargetEntryDN'
            },
            {
                name: 'excludedTargetEntryDN'
            },
            {
                name: 'allIncludedTargetEntryFilter'
            },
            {
                name: 'anyIncludedTargetEntryFilter'
            },
            {
                name: 'notAllIncludedTargetEntryFilter'
            },
            {
                name: 'noneIncludedTargetEntryFilter'
            },
            {
                name: 'allIncludedTargetEntryGroupDN'
            },
            {
                name: 'anyIncludedTargetEntryGroupDN'
            },
            {
                name: 'notAllIncludedTargetEntryGroupDN'
            },
            {
                name: 'noneIncludedTargetEntryGroupDN'
            },
            {
                name: 'targetBindType'
            },
            {
                name: 'includedTargetSASLMechanism'
            },
            {
                name: 'excludedTargetSASLMechanism'
            },
            {
                name: 'includedTargetAttribute'
            },
            {
                name: 'excludedTargetAttribute'
            },
            {
                name: 'includedExtendedOperationOID'
            },
            {
                name: 'excludedExtendedOperationOID'
            },
            {
                name: 'includedSearchScope'
            },
            {
                name: 'usingAdministrativeSessionWorkerThread'
            },
            {
                name: 'includedApplicationName'
            },
            {
                name: 'excludedApplicationName'
            },
            {
                name: 'allIncludedRequestCriteria'
            },
            {
                name: 'anyIncludedRequestCriteria'
            },
            {
                name: 'notAllIncludedRequestCriteria'
            },
            {
                name: 'noneIncludedRequestCriteria'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/request-criteria/{request-criteria-name}-DELETE': {
        parameters: [
            {
                name: 'request-criteria-name'
            },
        ]
    },
    '/request-criteria/{request-criteria-name}-GET': {
        parameters: [
            {
                name: 'request-criteria-name'
            },
        ]
    },
    '/request-criteria-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/request-criteria/{request-criteria-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'request-criteria-name'
            },
        ]
    },
    '/rest-resource-types-POST': {
        parameters: [
            {
                name: 'typeName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'passwordAttributeCategory'
            },
            {
                name: 'passwordDisplayOrderIndex'
            },
            {
                name: 'enabled'
            },
            {
                name: 'resourceEndpoint'
            },
            {
                name: 'structuralLDAPObjectclass'
            },
            {
                name: 'auxiliaryLDAPObjectclass'
            },
            {
                name: 'searchBaseDN'
            },
            {
                name: 'includeFilter'
            },
            {
                name: 'parentDN'
            },
            {
                name: 'parentResourceType'
            },
            {
                name: 'relativeDNFromParentResource'
            },
            {
                name: 'createRDNAttributeType'
            },
            {
                name: 'postCreateConstructedAttribute'
            },
            {
                name: 'updateConstructedAttribute'
            },
            {
                name: 'displayName'
            },
            {
                name: 'searchFilterPattern'
            },
            {
                name: 'primaryDisplayAttributeType'
            },
            {
                name: 'delegatedAdminSearchSizeLimit'
            },
            {
                name: 'delegatedAdminReportSizeLimit'
            },
            {
                name: 'membersColumnName'
            },
            {
                name: 'nonmembersColumnName'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}-DELETE': {
        parameters: [
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}-GET': {
        parameters: [
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/rest-resource-types-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/rest-resource-types/{rest-resource-type-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'rest-resource-type-name'
            },
        ]
    },
    '/result-code-maps-POST': {
        parameters: [
            {
                name: 'mapName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'bindAccountLockedResultCode'
            },
            {
                name: 'bindMissingUserResultCode'
            },
            {
                name: 'bindMissingPasswordResultCode'
            },
            {
                name: 'serverErrorResultCode'
            },
        ]
    },
    '/result-code-maps/{result-code-map-name}-DELETE': {
        parameters: [
            {
                name: 'result-code-map-name'
            },
        ]
    },
    '/result-code-maps-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/result-code-maps/{result-code-map-name}-GET': {
        parameters: [
            {
                name: 'result-code-map-name'
            },
        ]
    },
    '/result-code-maps/{result-code-map-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'result-code-map-name'
            },
        ]
    },
    '/result-criteria-POST': {
        parameters: [
            {
                name: 'criteriaName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'requestCriteria'
            },
            {
                name: 'includeAnonymousBinds'
            },
            {
                name: 'includedUserBaseDN'
            },
            {
                name: 'excludedUserBaseDN'
            },
            {
                name: 'includedUserFilter'
            },
            {
                name: 'excludedUserFilter'
            },
            {
                name: 'includedUserGroupDN'
            },
            {
                name: 'excludedUserGroupDN'
            },
            {
                name: 'resultCodeCriteria'
            },
            {
                name: 'resultCodeValue'
            },
            {
                name: 'processingTimeCriteria'
            },
            {
                name: 'processingTimeValue'
            },
            {
                name: 'queueTimeCriteria'
            },
            {
                name: 'queueTimeValue'
            },
            {
                name: 'referralReturned'
            },
            {
                name: 'allIncludedResponseControl'
            },
            {
                name: 'anyIncludedResponseControl'
            },
            {
                name: 'notAllIncludedResponseControl'
            },
            {
                name: 'noneIncludedResponseControl'
            },
            {
                name: 'usedAlternateAuthzid'
            },
            {
                name: 'usedAnyPrivilege'
            },
            {
                name: 'usedPrivilege'
            },
            {
                name: 'missingAnyPrivilege'
            },
            {
                name: 'missingPrivilege'
            },
            {
                name: 'retiredPasswordUsedForBind'
            },
            {
                name: 'searchEntryReturnedCriteria'
            },
            {
                name: 'searchEntryReturnedCount'
            },
            {
                name: 'searchReferenceReturnedCriteria'
            },
            {
                name: 'searchReferenceReturnedCount'
            },
            {
                name: 'searchIndexedCriteria'
            },
            {
                name: 'includedAuthzUserBaseDN'
            },
            {
                name: 'excludedAuthzUserBaseDN'
            },
            {
                name: 'allIncludedAuthzUserGroupDN'
            },
            {
                name: 'anyIncludedAuthzUserGroupDN'
            },
            {
                name: 'notAllIncludedAuthzUserGroupDN'
            },
            {
                name: 'noneIncludedAuthzUserGroupDN'
            },
            {
                name: 'allIncludedResultCriteria'
            },
            {
                name: 'anyIncludedResultCriteria'
            },
            {
                name: 'notAllIncludedResultCriteria'
            },
            {
                name: 'noneIncludedResultCriteria'
            },
            {
                name: 'localAssuranceLevel'
            },
            {
                name: 'remoteAssuranceLevel'
            },
            {
                name: 'assuranceTimeoutCriteria'
            },
            {
                name: 'assuranceTimeoutValue'
            },
            {
                name: 'responseDelayedByAssurance'
            },
            {
                name: 'assuranceBehaviorAlteredByControl'
            },
            {
                name: 'assuranceSatisfied'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/result-criteria/{result-criteria-name}-DELETE': {
        parameters: [
            {
                name: 'result-criteria-name'
            },
        ]
    },
    '/result-criteria/{result-criteria-name}-GET': {
        parameters: [
            {
                name: 'result-criteria-name'
            },
        ]
    },
    '/result-criteria-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/result-criteria/{result-criteria-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'result-criteria-name'
            },
        ]
    },
    '/root-dn-GET': {
        parameters: [
        ]
    },
    '/root-dn-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/root-dn/root-dn-users-POST': {
        parameters: [
            {
                name: 'userName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'alternateBindDN'
            },
            {
                name: 'password'
            },
            {
                name: 'firstName'
            },
            {
                name: 'lastName'
            },
            {
                name: 'userID'
            },
            {
                name: 'emailAddress'
            },
            {
                name: 'workTelephoneNumber'
            },
            {
                name: 'homeTelephoneNumber'
            },
            {
                name: 'mobileTelephoneNumber'
            },
            {
                name: 'pagerTelephoneNumber'
            },
            {
                name: 'inheritDefaultRootPrivileges'
            },
            {
                name: 'privilege'
            },
            {
                name: 'searchResultEntryLimit'
            },
            {
                name: 'timeLimitSeconds'
            },
            {
                name: 'lookThroughEntryLimit'
            },
            {
                name: 'idleTimeLimitSeconds'
            },
            {
                name: 'passwordPolicy'
            },
            {
                name: 'disabled'
            },
            {
                name: 'accountActivationTime'
            },
            {
                name: 'accountExpirationTime'
            },
            {
                name: 'requireSecureAuthentication'
            },
            {
                name: 'requireSecureConnections'
            },
            {
                name: 'allowedAuthenticationType'
            },
            {
                name: 'allowedAuthenticationIPAddress'
            },
            {
                name: 'preferredOTPDeliveryMechanism'
            },
            {
                name: 'isProxyable'
            },
            {
                name: 'isProxyableByDN'
            },
            {
                name: 'isProxyableByGroup'
            },
            {
                name: 'isProxyableByURL'
            },
            {
                name: 'mayProxyAsDN'
            },
            {
                name: 'mayProxyAsGroup'
            },
            {
                name: 'mayProxyAsURL'
            },
        ]
    },
    '/root-dn/root-dn-users/{root-dn-user-name}-DELETE': {
        parameters: [
            {
                name: 'root-dn-user-name'
            },
        ]
    },
    '/root-dn/root-dn-users/{root-dn-user-name}-GET': {
        parameters: [
            {
                name: 'root-dn-user-name'
            },
        ]
    },
    '/root-dn/root-dn-users-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/root-dn/root-dn-users/{root-dn-user-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'root-dn-user-name'
            },
        ]
    },
    '/root-dse-backend-GET': {
        parameters: [
        ]
    },
    '/root-dse-backend-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
    '/sasl-mechanism-handlers-POST': {
        parameters: [
            {
                name: 'handlerName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'identityMapper'
            },
            {
                name: 'enabled'
            },
            {
                name: 'otpValidityDuration'
            },
            {
                name: 'accessTokenValidator'
            },
            {
                name: 'idTokenValidator'
            },
            {
                name: 'requireBothAccessTokenAndIDToken'
            },
            {
                name: 'validateAccessTokenWhenIDTokenIsAlsoProvided'
            },
            {
                name: 'alternateAuthorizationIdentityMapper'
            },
            {
                name: 'allRequiredScope'
            },
            {
                name: 'anyRequiredScope'
            },
            {
                name: 'serverFqdn'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/sasl-mechanism-handlers/{sasl-mechanism-handler-name}-DELETE': {
        parameters: [
            {
                name: 'sasl-mechanism-handler-name'
            },
        ]
    },
    '/sasl-mechanism-handlers/{sasl-mechanism-handler-name}-GET': {
        parameters: [
            {
                name: 'sasl-mechanism-handler-name'
            },
        ]
    },
    '/sasl-mechanism-handlers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/sasl-mechanism-handlers/{sasl-mechanism-handler-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'sasl-mechanism-handler-name'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes-POST': {
        parameters: [
            {
                name: 'attributeName'
            },
            {
                name: 'scim-schema-name'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'name'
            },
            {
                name: 'type'
            },
            {
                name: 'required'
            },
            {
                name: 'caseExact'
            },
            {
                name: 'multiValued'
            },
            {
                name: 'canonicalValue'
            },
            {
                name: 'mutability'
            },
            {
                name: 'returned'
            },
            {
                name: 'referenceType'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes/{scim-attribute-name}-DELETE': {
        parameters: [
            {
                name: 'scim-attribute-name'
            },
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes/{scim-attribute-name}-GET': {
        parameters: [
            {
                name: 'scim-attribute-name'
            },
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes-GET': {
        parameters: [
            {
                name: 'scim-schema-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes/{scim-attribute-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'scim-attribute-name'
            },
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/scim-attribute-mappings-POST': {
        parameters: [
            {
                name: 'mappingName'
            },
            {
                name: 'scim-resource-type-name'
            },
            {
                name: 'schemas'
            },
            {
                name: 'correlatedLDAPDataView'
            },
            {
                name: 'scimResourceTypeAttribute'
            },
            {
                name: 'ldapAttribute'
            },
            {
                name: 'readable'
            },
            {
                name: 'writable'
            },
            {
                name: 'searchable'
            },
            {
                name: 'authoritative'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/scim-attribute-mappings/{scim-attribute-mapping-name}-DELETE': {
        parameters: [
            {
                name: 'scim-attribute-mapping-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/scim-attribute-mappings-GET': {
        parameters: [
            {
                name: 'scim-resource-type-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/scim-attribute-mappings/{scim-attribute-mapping-name}-GET': {
        parameters: [
            {
                name: 'scim-attribute-mapping-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}/scim-attribute-mappings/{scim-attribute-mapping-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'scim-attribute-mapping-name'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types-POST': {
        parameters: [
            {
                name: 'typeName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'endpoint'
            },
            {
                name: 'lookthroughLimit'
            },
            {
                name: 'schemaCheckingOption'
            },
            {
                name: 'structuralLDAPObjectclass'
            },
            {
                name: 'auxiliaryLDAPObjectclass'
            },
            {
                name: 'includeBaseDN'
            },
            {
                name: 'includeFilter'
            },
            {
                name: 'includeOperationalAttribute'
            },
            {
                name: 'createDNPattern'
            },
            {
                name: 'coreSchema'
            },
            {
                name: 'requiredSchemaExtension'
            },
            {
                name: 'optionalSchemaExtension'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}-DELETE': {
        parameters: [
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}-GET': {
        parameters: [
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-resource-types-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/scim-resource-types/{scim-resource-type-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'scim-resource-type-name'
            },
        ]
    },
    '/scim-schemas-POST': {
        parameters: [
            {
                name: 'schemaName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'schemaURN'
            },
            {
                name: 'displayName'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}-DELETE': {
        parameters: [
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}-GET': {
        parameters: [
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/scim-schemas-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes/{scim-attribute-name}/scim-subattributes-POST': {
        parameters: [
            {
                name: 'subattributeName'
            },
            {
                name: 'scim-attribute-name'
            },
            {
                name: 'scim-schema-name'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'type'
            },
            {
                name: 'required'
            },
            {
                name: 'caseExact'
            },
            {
                name: 'multiValued'
            },
            {
                name: 'canonicalValue'
            },
            {
                name: 'mutability'
            },
            {
                name: 'returned'
            },
            {
                name: 'referenceType'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes/{scim-attribute-name}/scim-subattributes/{scim-subattribute-name}-DELETE': {
        parameters: [
            {
                name: 'scim-subattribute-name'
            },
            {
                name: 'scim-attribute-name'
            },
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes/{scim-attribute-name}/scim-subattributes/{scim-subattribute-name}-GET': {
        parameters: [
            {
                name: 'scim-subattribute-name'
            },
            {
                name: 'scim-attribute-name'
            },
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes/{scim-attribute-name}/scim-subattributes-GET': {
        parameters: [
            {
                name: 'scim-attribute-name'
            },
            {
                name: 'scim-schema-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/scim-schemas/{scim-schema-name}/scim-attributes/{scim-attribute-name}/scim-subattributes/{scim-subattribute-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'scim-subattribute-name'
            },
            {
                name: 'scim-attribute-name'
            },
            {
                name: 'scim-schema-name'
            },
        ]
    },
    '/search-entry-criteria-POST': {
        parameters: [
            {
                name: 'criteriaName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'requestCriteria'
            },
            {
                name: 'allIncludedEntryControl'
            },
            {
                name: 'anyIncludedEntryControl'
            },
            {
                name: 'notAllIncludedEntryControl'
            },
            {
                name: 'noneIncludedEntryControl'
            },
            {
                name: 'includedEntryBaseDN'
            },
            {
                name: 'excludedEntryBaseDN'
            },
            {
                name: 'allIncludedEntryFilter'
            },
            {
                name: 'anyIncludedEntryFilter'
            },
            {
                name: 'notAllIncludedEntryFilter'
            },
            {
                name: 'noneIncludedEntryFilter'
            },
            {
                name: 'allIncludedEntryGroupDN'
            },
            {
                name: 'anyIncludedEntryGroupDN'
            },
            {
                name: 'notAllIncludedEntryGroupDN'
            },
            {
                name: 'noneIncludedEntryGroupDN'
            },
            {
                name: 'allIncludedSearchEntryCriteria'
            },
            {
                name: 'anyIncludedSearchEntryCriteria'
            },
            {
                name: 'notAllIncludedSearchEntryCriteria'
            },
            {
                name: 'noneIncludedSearchEntryCriteria'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/search-entry-criteria/{search-entry-criteria-name}-DELETE': {
        parameters: [
            {
                name: 'search-entry-criteria-name'
            },
        ]
    },
    '/search-entry-criteria/{search-entry-criteria-name}-GET': {
        parameters: [
            {
                name: 'search-entry-criteria-name'
            },
        ]
    },
    '/search-entry-criteria-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/search-entry-criteria/{search-entry-criteria-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'search-entry-criteria-name'
            },
        ]
    },
    '/search-reference-criteria-POST': {
        parameters: [
            {
                name: 'criteriaName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'requestCriteria'
            },
            {
                name: 'allIncludedReferenceControl'
            },
            {
                name: 'anyIncludedReferenceControl'
            },
            {
                name: 'notAllIncludedReferenceControl'
            },
            {
                name: 'noneIncludedReferenceControl'
            },
            {
                name: 'allIncludedSearchReferenceCriteria'
            },
            {
                name: 'anyIncludedSearchReferenceCriteria'
            },
            {
                name: 'notAllIncludedSearchReferenceCriteria'
            },
            {
                name: 'noneIncludedSearchReferenceCriteria'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/search-reference-criteria/{search-reference-criteria-name}-DELETE': {
        parameters: [
            {
                name: 'search-reference-criteria-name'
            },
        ]
    },
    '/search-reference-criteria/{search-reference-criteria-name}-GET': {
        parameters: [
            {
                name: 'search-reference-criteria-name'
            },
        ]
    },
    '/search-reference-criteria-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/search-reference-criteria/{search-reference-criteria-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'search-reference-criteria-name'
            },
        ]
    },
    '/sensitive-attributes-POST': {
        parameters: [
            {
                name: 'attributeName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'attributeType'
            },
            {
                name: 'includeDefaultSensitiveOperationalAttributes'
            },
            {
                name: 'allowInReturnedEntries'
            },
            {
                name: 'allowInFilter'
            },
            {
                name: 'allowInAdd'
            },
            {
                name: 'allowInCompare'
            },
            {
                name: 'allowInModify'
            },
        ]
    },
    '/sensitive-attributes/{sensitive-attribute-name}-DELETE': {
        parameters: [
            {
                name: 'sensitive-attribute-name'
            },
        ]
    },
    '/sensitive-attributes-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/sensitive-attributes/{sensitive-attribute-name}-GET': {
        parameters: [
            {
                name: 'sensitive-attribute-name'
            },
        ]
    },
    '/sensitive-attributes/{sensitive-attribute-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'sensitive-attribute-name'
            },
        ]
    },
    '/server-groups-POST': {
        parameters: [
            {
                name: 'groupName'
            },
            {
                name: 'schemas'
            },
            {
                name: 'member'
            },
        ]
    },
    '/server-groups/{server-group-name}-DELETE': {
        parameters: [
            {
                name: 'server-group-name'
            },
        ]
    },
    '/server-groups/{server-group-name}-GET': {
        parameters: [
            {
                name: 'server-group-name'
            },
        ]
    },
    '/server-groups-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/server-groups/{server-group-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'server-group-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}-GET': {
        parameters: [
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/server-instances-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/server-instances/{server-instance-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}/server-instance-listeners/{server-instance-listener-name}-GET': {
        parameters: [
            {
                name: 'server-instance-listener-name'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/server-instances/{server-instance-name}/server-instance-listeners-GET': {
        parameters: [
            {
                name: 'server-instance-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/server-instances/{server-instance-name}/server-instance-listeners/{server-instance-listener-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'server-instance-listener-name'
            },
            {
                name: 'server-instance-name'
            },
        ]
    },
    '/soft-delete-policies-POST': {
        parameters: [
            {
                name: 'policyName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'autoSoftDeleteConnectionCriteria'
            },
            {
                name: 'autoSoftDeleteRequestCriteria'
            },
            {
                name: 'softDeleteRetentionTime'
            },
            {
                name: 'softDeleteRetainNumberOfEntries'
            },
        ]
    },
    '/soft-delete-policies/{soft-delete-policy-name}-DELETE': {
        parameters: [
            {
                name: 'soft-delete-policy-name'
            },
        ]
    },
    '/soft-delete-policies/{soft-delete-policy-name}-GET': {
        parameters: [
            {
                name: 'soft-delete-policy-name'
            },
        ]
    },
    '/soft-delete-policies-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/soft-delete-policies/{soft-delete-policy-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'soft-delete-policy-name'
            },
        ]
    },
    '/synchronization-providers/{synchronization-provider-name}-GET': {
        parameters: [
            {
                name: 'synchronization-provider-name'
            },
        ]
    },
    '/synchronization-providers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/synchronization-providers/{synchronization-provider-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'synchronization-provider-name'
            },
        ]
    },
    '/id-token-validators/{id-token-validator-name}/token-claim-validations-POST': {
        parameters: [
            {
                name: 'id-token-validator-name'
            },
            {
                name: 'validationName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'allRequiredValue'
            },
            {
                name: 'anyRequiredValue'
            },
            {
                name: 'claimName'
            },
            {
                name: 'requiredValue'
            },
        ]
    },
    '/id-token-validators/{id-token-validator-name}/token-claim-validations/{token-claim-validation-name}-DELETE': {
        parameters: [
            {
                name: 'token-claim-validation-name'
            },
            {
                name: 'id-token-validator-name'
            },
        ]
    },
    '/id-token-validators/{id-token-validator-name}/token-claim-validations/{token-claim-validation-name}-GET': {
        parameters: [
            {
                name: 'token-claim-validation-name'
            },
            {
                name: 'id-token-validator-name'
            },
        ]
    },
    '/id-token-validators/{id-token-validator-name}/token-claim-validations-GET': {
        parameters: [
            {
                name: 'id-token-validator-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/id-token-validators/{id-token-validator-name}/token-claim-validations/{token-claim-validation-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'token-claim-validation-name'
            },
            {
                name: 'id-token-validator-name'
            },
        ]
    },
    '/topology-admin-users-POST': {
        parameters: [
            {
                name: 'userName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'alternateBindDN'
            },
            {
                name: 'password'
            },
            {
                name: 'firstName'
            },
            {
                name: 'lastName'
            },
            {
                name: 'userID'
            },
            {
                name: 'emailAddress'
            },
            {
                name: 'workTelephoneNumber'
            },
            {
                name: 'homeTelephoneNumber'
            },
            {
                name: 'mobileTelephoneNumber'
            },
            {
                name: 'pagerTelephoneNumber'
            },
            {
                name: 'inheritDefaultRootPrivileges'
            },
            {
                name: 'privilege'
            },
            {
                name: 'searchResultEntryLimit'
            },
            {
                name: 'timeLimitSeconds'
            },
            {
                name: 'lookThroughEntryLimit'
            },
            {
                name: 'idleTimeLimitSeconds'
            },
            {
                name: 'passwordPolicy'
            },
            {
                name: 'disabled'
            },
            {
                name: 'accountActivationTime'
            },
            {
                name: 'accountExpirationTime'
            },
            {
                name: 'requireSecureAuthentication'
            },
            {
                name: 'requireSecureConnections'
            },
            {
                name: 'allowedAuthenticationType'
            },
            {
                name: 'allowedAuthenticationIPAddress'
            },
            {
                name: 'preferredOTPDeliveryMechanism'
            },
            {
                name: 'isProxyable'
            },
            {
                name: 'isProxyableByDN'
            },
            {
                name: 'isProxyableByGroup'
            },
            {
                name: 'isProxyableByURL'
            },
            {
                name: 'mayProxyAsDN'
            },
            {
                name: 'mayProxyAsGroup'
            },
            {
                name: 'mayProxyAsURL'
            },
        ]
    },
    '/topology-admin-users/{topology-admin-user-name}-DELETE': {
        parameters: [
            {
                name: 'topology-admin-user-name'
            },
        ]
    },
    '/topology-admin-users/{topology-admin-user-name}-GET': {
        parameters: [
            {
                name: 'topology-admin-user-name'
            },
        ]
    },
    '/topology-admin-users-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/topology-admin-users/{topology-admin-user-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'topology-admin-user-name'
            },
        ]
    },
    '/trust-manager-providers-POST': {
        parameters: [
            {
                name: 'providerName'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'includeJVMDefaultIssuers'
            },
            {
                name: 'trustStoreFile'
            },
            {
                name: 'trustStoreType'
            },
            {
                name: 'trustStorePin'
            },
            {
                name: 'trustStorePinFile'
            },
            {
                name: 'trustStorePinPassphraseProvider'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/trust-manager-providers/{trust-manager-provider-name}-DELETE': {
        parameters: [
            {
                name: 'trust-manager-provider-name'
            },
        ]
    },
    '/trust-manager-providers/{trust-manager-provider-name}-GET': {
        parameters: [
            {
                name: 'trust-manager-provider-name'
            },
        ]
    },
    '/trust-manager-providers-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/trust-manager-providers/{trust-manager-provider-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'trust-manager-provider-name'
            },
        ]
    },
    '/trusted-certificates-POST': {
        parameters: [
            {
                name: 'certificateName'
            },
            {
                name: 'schemas'
            },
            {
                name: 'certificate'
            },
        ]
    },
    '/trusted-certificates/{trusted-certificate-name}-DELETE': {
        parameters: [
            {
                name: 'trusted-certificate-name'
            },
        ]
    },
    '/trusted-certificates/{trusted-certificate-name}-GET': {
        parameters: [
            {
                name: 'trusted-certificate-name'
            },
        ]
    },
    '/trusted-certificates-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/trusted-certificates/{trusted-certificate-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'trusted-certificate-name'
            },
        ]
    },
    '/uncached-attribute-criteria-POST': {
        parameters: [
            {
                name: 'criteriaName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'attributeType'
            },
            {
                name: 'minValueCount'
            },
            {
                name: 'minTotalValueSize'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/uncached-attribute-criteria/{uncached-attribute-criteria-name}-DELETE': {
        parameters: [
            {
                name: 'uncached-attribute-criteria-name'
            },
        ]
    },
    '/uncached-attribute-criteria-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/uncached-attribute-criteria/{uncached-attribute-criteria-name}-GET': {
        parameters: [
            {
                name: 'uncached-attribute-criteria-name'
            },
        ]
    },
    '/uncached-attribute-criteria/{uncached-attribute-criteria-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'uncached-attribute-criteria-name'
            },
        ]
    },
    '/uncached-entry-criteria-POST': {
        parameters: [
            {
                name: 'criteriaName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'accessTimeThreshold'
            },
            {
                name: 'filter'
            },
            {
                name: 'filterIdentifiesUncachedEntries'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/uncached-entry-criteria/{uncached-entry-criteria-name}-DELETE': {
        parameters: [
            {
                name: 'uncached-entry-criteria-name'
            },
        ]
    },
    '/uncached-entry-criteria/{uncached-entry-criteria-name}-GET': {
        parameters: [
            {
                name: 'uncached-entry-criteria-name'
            },
        ]
    },
    '/uncached-entry-criteria-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/uncached-entry-criteria/{uncached-entry-criteria-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'uncached-entry-criteria-name'
            },
        ]
    },
    '/vault-authentication-methods-POST': {
        parameters: [
            {
                name: 'methodName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'vaultAccessToken'
            },
            {
                name: 'vaultRoleID'
            },
            {
                name: 'vaultSecretID'
            },
            {
                name: 'loginMechanismName'
            },
            {
                name: 'username'
            },
            {
                name: 'password'
            },
        ]
    },
    '/vault-authentication-methods/{vault-authentication-method-name}-DELETE': {
        parameters: [
            {
                name: 'vault-authentication-method-name'
            },
        ]
    },
    '/vault-authentication-methods-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/vault-authentication-methods/{vault-authentication-method-name}-GET': {
        parameters: [
            {
                name: 'vault-authentication-method-name'
            },
        ]
    },
    '/vault-authentication-methods/{vault-authentication-method-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'vault-authentication-method-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers-POST': {
        parameters: [
            {
                name: 'http-servlet-extension-name'
            },
            {
                name: 'providerName'
            },
            {
                name: 'schemas'
            },
            {
                name: 'requestTool'
            },
            {
                name: 'sessionTool'
            },
            {
                name: 'applicationTool'
            },
            {
                name: 'enabled'
            },
            {
                name: 'objectScope'
            },
            {
                name: 'includedView'
            },
            {
                name: 'excludedView'
            },
            {
                name: 'responseHeader'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
            {
                name: 'httpMethod'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}-DELETE': {
        parameters: [
            {
                name: 'velocity-context-provider-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}-GET': {
        parameters: [
            {
                name: 'velocity-context-provider-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers-GET': {
        parameters: [
            {
                name: 'http-servlet-extension-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-context-providers/{velocity-context-provider-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'velocity-context-provider-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-template-loaders-POST': {
        parameters: [
            {
                name: 'loaderName'
            },
            {
                name: 'http-servlet-extension-name'
            },
            {
                name: 'schemas'
            },
            {
                name: 'enabled'
            },
            {
                name: 'evaluationOrderIndex'
            },
            {
                name: 'mimeTypeMatcher'
            },
            {
                name: 'mimeType'
            },
            {
                name: 'templateSuffix'
            },
            {
                name: 'templateDirectory'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-template-loaders/{velocity-template-loader-name}-DELETE': {
        parameters: [
            {
                name: 'velocity-template-loader-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-template-loaders-GET': {
        parameters: [
            {
                name: 'http-servlet-extension-name'
            },
            {
                name: 'filter'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-template-loaders/{velocity-template-loader-name}-GET': {
        parameters: [
            {
                name: 'velocity-template-loader-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/http-servlet-extensions/{http-servlet-extension-name}/velocity-template-loaders/{velocity-template-loader-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'velocity-template-loader-name'
            },
            {
                name: 'http-servlet-extension-name'
            },
        ]
    },
    '/virtual-attributes-POST': {
        parameters: [
            {
                name: 'name'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'conflictBehavior'
            },
            {
                name: 'sourceAttribute'
            },
            {
                name: 'sourceEntryDNAttribute'
            },
            {
                name: 'sourceEntryDNMap'
            },
            {
                name: 'bypassAccessControlForSearches'
            },
            {
                name: 'enabled'
            },
            {
                name: 'attributeType'
            },
            {
                name: 'baseDN'
            },
            {
                name: 'groupDN'
            },
            {
                name: 'filter'
            },
            {
                name: 'clientConnectionPolicy'
            },
            {
                name: 'requireExplicitRequestByName'
            },
            {
                name: 'multipleVirtualAttributeEvaluationOrderIndex'
            },
            {
                name: 'multipleVirtualAttributeMergeBehavior'
            },
            {
                name: 'allowIndexConflicts'
            },
            {
                name: 'valuePattern'
            },
            {
                name: 'directMembershipsOnly'
            },
            {
                name: 'includedGroupFilter'
            },
            {
                name: 'rewriteSearchFilters'
            },
            {
                name: 'joinDNAttribute'
            },
            {
                name: 'joinBaseDNType'
            },
            {
                name: 'joinCustomBaseDN'
            },
            {
                name: 'joinScope'
            },
            {
                name: 'joinSizeLimit'
            },
            {
                name: 'joinFilter'
            },
            {
                name: 'joinAttribute'
            },
            {
                name: 'referencedByAttribute'
            },
            {
                name: 'referenceSearchBaseDN'
            },
            {
                name: 'value'
            },
            {
                name: 'joinSourceAttribute'
            },
            {
                name: 'joinTargetAttribute'
            },
            {
                name: 'joinMatchAll'
            },
            {
                name: 'scriptClass'
            },
            {
                name: 'scriptArgument'
            },
            {
                name: 'allowRetrievingMembership'
            },
            {
                name: 'extensionClass'
            },
            {
                name: 'extensionArgument'
            },
        ]
    },
    '/virtual-attributes/{virtual-attribute-name}-DELETE': {
        parameters: [
            {
                name: 'virtual-attribute-name'
            },
        ]
    },
    '/virtual-attributes-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/virtual-attributes/{virtual-attribute-name}-GET': {
        parameters: [
            {
                name: 'virtual-attribute-name'
            },
        ]
    },
    '/virtual-attributes/{virtual-attribute-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'virtual-attribute-name'
            },
        ]
    },
    '/web-application-extensions-POST': {
        parameters: [
            {
                name: 'extensionName'
            },
            {
                name: 'description'
            },
            {
                name: 'schemas'
            },
            {
                name: 'baseContextPath'
            },
            {
                name: 'warFile'
            },
            {
                name: 'documentRootDirectory'
            },
            {
                name: 'deploymentDescriptorFile'
            },
            {
                name: 'temporaryDirectory'
            },
            {
                name: 'initParameter'
            },
        ]
    },
    '/web-application-extensions/{web-application-extension-name}-DELETE': {
        parameters: [
            {
                name: 'web-application-extension-name'
            },
        ]
    },
    '/web-application-extensions/{web-application-extension-name}-GET': {
        parameters: [
            {
                name: 'web-application-extension-name'
            },
        ]
    },
    '/web-application-extensions-GET': {
        parameters: [
            {
                name: 'filter'
            },
        ]
    },
    '/web-application-extensions/{web-application-extension-name}-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
            {
                name: 'web-application-extension-name'
            },
        ]
    },
    '/work-queue-GET': {
        parameters: [
        ]
    },
    '/work-queue-PATCH': {
        parameters: [
            {
                name: 'operations'
            },
        ]
    },
}