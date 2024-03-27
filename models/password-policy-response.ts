/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpasswordPolicyAllowPreEncodedPasswordsProp } from './enumpassword-policy-allow-pre-encoded-passwords-prop';
import { EnumpasswordPolicyAllowedPasswordResetTokenUseConditionProp } from './enumpassword-policy-allowed-password-reset-token-use-condition-prop';
import { EnumpasswordPolicyBindPasswordValidationFailureActionProp } from './enumpassword-policy-bind-password-validation-failure-action-prop';
import { EnumpasswordPolicyPasswordRetirementBehaviorProp } from './enumpassword-policy-password-retirement-behavior-prop';
import { EnumpasswordPolicyRecentLoginHistorySimilarAttemptBehaviorProp } from './enumpassword-policy-recent-login-history-similar-attempt-behavior-prop';
import { EnumpasswordPolicyReturnPasswordExpirationControlsProp } from './enumpassword-policy-return-password-expiration-controls-prop';
import { EnumpasswordPolicySchemaUrn } from './enumpassword-policy-schema-urn';
import { EnumpasswordPolicyStateUpdateFailurePolicyProp } from './enumpassword-policy-state-update-failure-policy-prop';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { PasswordPolicyResponseAllOf } from './password-policy-response-all-of';
import { PasswordPolicyShared } from './password-policy-shared';

/**
 * @type PasswordPolicyResponse
 * @export
 */
export type PasswordPolicyResponse = Meta & PasswordPolicyResponseAllOf & PasswordPolicyShared;


