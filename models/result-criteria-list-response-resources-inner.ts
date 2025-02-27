/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AggregateResultCriteriaResponse } from './aggregate-result-criteria-response';
import { EnumresultCriteriaAssuranceBehaviorAlteredByControlProp } from './enumresult-criteria-assurance-behavior-altered-by-control-prop';
import { EnumresultCriteriaAssuranceSatisfiedProp } from './enumresult-criteria-assurance-satisfied-prop';
import { EnumresultCriteriaAssuranceTimeoutCriteriaProp } from './enumresult-criteria-assurance-timeout-criteria-prop';
import { EnumresultCriteriaLocalAssuranceLevelProp } from './enumresult-criteria-local-assurance-level-prop';
import { EnumresultCriteriaMissingAnyPrivilegeProp } from './enumresult-criteria-missing-any-privilege-prop';
import { EnumresultCriteriaMissingPrivilegeProp } from './enumresult-criteria-missing-privilege-prop';
import { EnumresultCriteriaProcessingTimeCriteriaProp } from './enumresult-criteria-processing-time-criteria-prop';
import { EnumresultCriteriaQueueTimeCriteriaProp } from './enumresult-criteria-queue-time-criteria-prop';
import { EnumresultCriteriaReferralReturnedProp } from './enumresult-criteria-referral-returned-prop';
import { EnumresultCriteriaRemoteAssuranceLevelProp } from './enumresult-criteria-remote-assurance-level-prop';
import { EnumresultCriteriaResponseDelayedByAssuranceProp } from './enumresult-criteria-response-delayed-by-assurance-prop';
import { EnumresultCriteriaResultCodeCriteriaProp } from './enumresult-criteria-result-code-criteria-prop';
import { EnumresultCriteriaResultCodeValueProp } from './enumresult-criteria-result-code-value-prop';
import { EnumresultCriteriaRetiredPasswordUsedForBindProp } from './enumresult-criteria-retired-password-used-for-bind-prop';
import { EnumresultCriteriaSearchEntryReturnedCriteriaProp } from './enumresult-criteria-search-entry-returned-criteria-prop';
import { EnumresultCriteriaSearchIndexedCriteriaProp } from './enumresult-criteria-search-indexed-criteria-prop';
import { EnumresultCriteriaSearchReferenceReturnedCriteriaProp } from './enumresult-criteria-search-reference-returned-criteria-prop';
import { EnumresultCriteriaUsedAlternateAuthzidProp } from './enumresult-criteria-used-alternate-authzid-prop';
import { EnumresultCriteriaUsedAnyPrivilegeProp } from './enumresult-criteria-used-any-privilege-prop';
import { EnumresultCriteriaUsedPrivilegeProp } from './enumresult-criteria-used-privilege-prop';
import { EnumthirdPartyResultCriteriaSchemaUrn } from './enumthird-party-result-criteria-schema-urn';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { ReplicationAssuranceResultCriteriaResponse } from './replication-assurance-result-criteria-response';
import { SimpleResultCriteriaResponse } from './simple-result-criteria-response';
import { SuccessfulBindResultCriteriaResponse } from './successful-bind-result-criteria-response';
import { ThirdPartyResultCriteriaResponse } from './third-party-result-criteria-response';

/**
 * @type ResultCriteriaListResponseResourcesInner
 * @export
 */
export type ResultCriteriaListResponseResourcesInner = AggregateResultCriteriaResponse | ReplicationAssuranceResultCriteriaResponse | SimpleResultCriteriaResponse | SuccessfulBindResultCriteriaResponse | ThirdPartyResultCriteriaResponse;


