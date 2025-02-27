/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AdministrativeSessionExtendedOperationHandlerResponse } from './administrative-session-extended-operation-handler-response';
import { BackupCompatibilityExtendedOperationHandlerResponse } from './backup-compatibility-extended-operation-handler-response';
import { BatchedTransactionsExtendedOperationHandlerResponse } from './batched-transactions-extended-operation-handler-response';
import { CancelExtendedOperationHandlerResponse } from './cancel-extended-operation-handler-response';
import { CollectSupportDataExtendedOperationHandlerResponse } from './collect-support-data-extended-operation-handler-response';
import { CustomExtendedOperationHandlerResponse } from './custom-extended-operation-handler-response';
import { DeliverOtpExtendedOperationHandlerResponse } from './deliver-otp-extended-operation-handler-response';
import { DeliverPasswordResetTokenExtendedOperationHandlerResponse } from './deliver-password-reset-token-extended-operation-handler-response';
import { EnumextendedOperationHandlerAllowedOperationProp } from './enumextended-operation-handler-allowed-operation-prop';
import { EnumextendedOperationHandlerRouteToBackendSetBehaviorProp } from './enumextended-operation-handler-route-to-backend-set-behavior-prop';
import { EnumgetConfigurationExtendedOperationHandlerSchemaUrn } from './enumget-configuration-extended-operation-handler-schema-urn';
import { ExportReversiblePasswordsExtendedOperationHandlerResponse } from './export-reversible-passwords-extended-operation-handler-response';
import { GeneratePasswordExtendedOperationHandlerResponse } from './generate-password-extended-operation-handler-response';
import { GetChangelogBatchExtendedOperationHandlerResponse } from './get-changelog-batch-extended-operation-handler-response';
import { GetConfigurationExtendedOperationHandlerResponse } from './get-configuration-extended-operation-handler-response';
import { GetConnectionIdExtendedOperationHandlerResponse } from './get-connection-id-extended-operation-handler-response';
import { GetPasswordQualityRequirementsExtendedOperationHandlerResponse } from './get-password-quality-requirements-extended-operation-handler-response';
import { GetSupportedOtpDeliveryMechanismsExtendedOperationHandlerResponse } from './get-supported-otp-delivery-mechanisms-extended-operation-handler-response';
import { GetSymmetricKeyExtendedOperationHandlerResponse } from './get-symmetric-key-extended-operation-handler-response';
import { InteractiveTransactionsExtendedOperationHandlerResponse } from './interactive-transactions-extended-operation-handler-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { MultiUpdateExtendedOperationHandlerResponse } from './multi-update-extended-operation-handler-response';
import { NotificationSubscriptionExtendedOperationHandlerResponse } from './notification-subscription-extended-operation-handler-response';
import { PasswordModifyExtendedOperationHandlerResponse } from './password-modify-extended-operation-handler-response';
import { PasswordPolicyStateExtendedOperationHandlerResponse } from './password-policy-state-extended-operation-handler-response';
import { ReplaceCertificateExtendedOperationHandlerResponse } from './replace-certificate-extended-operation-handler-response';
import { SingleUseTokensExtendedOperationHandlerResponse } from './single-use-tokens-extended-operation-handler-response';
import { StartTlsExtendedOperationHandlerResponse } from './start-tls-extended-operation-handler-response';
import { StreamDirectoryValuesExtendedOperationHandlerResponse } from './stream-directory-values-extended-operation-handler-response';
import { StreamProxyValuesExtendedOperationHandlerResponse } from './stream-proxy-values-extended-operation-handler-response';
import { SubtreeAccessibilityExtendedOperationHandlerResponse } from './subtree-accessibility-extended-operation-handler-response';
import { SynchronizeEncryptionSettingsExtendedOperationHandlerResponse } from './synchronize-encryption-settings-extended-operation-handler-response';
import { ThirdPartyExtendedOperationHandlerResponse } from './third-party-extended-operation-handler-response';
import { ThirdPartyProxiedExtendedOperationHandlerResponse } from './third-party-proxied-extended-operation-handler-response';
import { ValidateTotpPasswordExtendedOperationHandlerResponse } from './validate-totp-password-extended-operation-handler-response';
import { WhoAmIExtendedOperationHandlerResponse } from './who-am-iextended-operation-handler-response';

/**
 * @type ExtendedOperationHandlerListResponseResourcesInner
 * @export
 */
export type ExtendedOperationHandlerListResponseResourcesInner = AdministrativeSessionExtendedOperationHandlerResponse | BackupCompatibilityExtendedOperationHandlerResponse | BatchedTransactionsExtendedOperationHandlerResponse | CancelExtendedOperationHandlerResponse | CollectSupportDataExtendedOperationHandlerResponse | CustomExtendedOperationHandlerResponse | DeliverOtpExtendedOperationHandlerResponse | DeliverPasswordResetTokenExtendedOperationHandlerResponse | ExportReversiblePasswordsExtendedOperationHandlerResponse | GeneratePasswordExtendedOperationHandlerResponse | GetChangelogBatchExtendedOperationHandlerResponse | GetConfigurationExtendedOperationHandlerResponse | GetConnectionIdExtendedOperationHandlerResponse | GetPasswordQualityRequirementsExtendedOperationHandlerResponse | GetSupportedOtpDeliveryMechanismsExtendedOperationHandlerResponse | GetSymmetricKeyExtendedOperationHandlerResponse | InteractiveTransactionsExtendedOperationHandlerResponse | MultiUpdateExtendedOperationHandlerResponse | NotificationSubscriptionExtendedOperationHandlerResponse | PasswordModifyExtendedOperationHandlerResponse | PasswordPolicyStateExtendedOperationHandlerResponse | ReplaceCertificateExtendedOperationHandlerResponse | SingleUseTokensExtendedOperationHandlerResponse | StartTlsExtendedOperationHandlerResponse | StreamDirectoryValuesExtendedOperationHandlerResponse | StreamProxyValuesExtendedOperationHandlerResponse | SubtreeAccessibilityExtendedOperationHandlerResponse | SynchronizeEncryptionSettingsExtendedOperationHandlerResponse | ThirdPartyExtendedOperationHandlerResponse | ThirdPartyProxiedExtendedOperationHandlerResponse | ValidateTotpPasswordExtendedOperationHandlerResponse | WhoAmIExtendedOperationHandlerResponse;


