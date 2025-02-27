/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AddPasswordPolicyRequestAllOf } from './add-password-policy-request-all-of';
import { EnumpasswordPolicyAllowPreEncodedPasswordsProp } from './enumpassword-policy-allow-pre-encoded-passwords-prop';
import { EnumpasswordPolicyAllowedPasswordResetTokenUseConditionProp } from './enumpassword-policy-allowed-password-reset-token-use-condition-prop';
import { EnumpasswordPolicyBindPasswordValidationFailureActionProp } from './enumpassword-policy-bind-password-validation-failure-action-prop';
import { EnumpasswordPolicyPasswordRetirementBehaviorProp } from './enumpassword-policy-password-retirement-behavior-prop';
import { EnumpasswordPolicyRecentLoginHistorySimilarAttemptBehaviorProp } from './enumpassword-policy-recent-login-history-similar-attempt-behavior-prop';
import { EnumpasswordPolicyReturnPasswordExpirationControlsProp } from './enumpassword-policy-return-password-expiration-controls-prop';
import { EnumpasswordPolicySchemaUrn } from './enumpassword-policy-schema-urn';
import { EnumpasswordPolicyStateUpdateFailurePolicyProp } from './enumpassword-policy-state-update-failure-policy-prop';
import { PasswordPolicyShared } from './password-policy-shared';

/**
 * @type AddPasswordPolicyRequest
 * @export
 */
export type AddPasswordPolicyRequest = AddPasswordPolicyRequestAllOf & PasswordPolicyShared;


