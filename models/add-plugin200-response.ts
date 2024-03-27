/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AttributeMapperPluginResponse } from './attribute-mapper-plugin-response';
import { CleanUpExpiredPingfederatePersistentAccessGrantsPluginResponse } from './clean-up-expired-pingfederate-persistent-access-grants-plugin-response';
import { CleanUpExpiredPingfederatePersistentSessionsPluginResponse } from './clean-up-expired-pingfederate-persistent-sessions-plugin-response';
import { CleanUpInactivePingfederatePersistentSessionsPluginResponse } from './clean-up-inactive-pingfederate-persistent-sessions-plugin-response';
import { CoalesceModificationsPluginResponse } from './coalesce-modifications-plugin-response';
import { ComposedAttributePluginResponse } from './composed-attribute-plugin-response';
import { DelayPluginResponse } from './delay-plugin-response';
import { DnMapperPluginResponse } from './dn-mapper-plugin-response';
import { EnuminvertedStaticGroupReferentialIntegrityPluginSchemaUrn } from './enuminverted-static-group-referential-integrity-plugin-schema-urn';
import { EnumpluginDatetimeFormatProp } from './enumplugin-datetime-format-prop';
import { EnumpluginEntryCacheInfoProp } from './enumplugin-entry-cache-info-prop';
import { EnumpluginGaugeInfoProp } from './enumplugin-gauge-info-prop';
import { EnumpluginHistogramFormatProp } from './enumplugin-histogram-format-prop';
import { EnumpluginHistogramOpTypeProp } from './enumplugin-histogram-op-type-prop';
import { EnumpluginHostInfoProp } from './enumplugin-host-info-prop';
import { EnumpluginIgnoredPasswordPolicyStateErrorConditionProp } from './enumplugin-ignored-password-policy-state-error-condition-prop';
import { EnumpluginIncludedLDAPStatProp } from './enumplugin-included-ldapstat-prop';
import { EnumpluginIncludedResourceStatProp } from './enumplugin-included-resource-stat-prop';
import { EnumpluginInvokeGCDayOfWeekProp } from './enumplugin-invoke-gcday-of-week-prop';
import { EnumpluginLdapChangelogInfoProp } from './enumplugin-ldap-changelog-info-prop';
import { EnumpluginLocalDBBackendInfoProp } from './enumplugin-local-dbbackend-info-prop';
import { EnumpluginLogFileFormatProp } from './enumplugin-log-file-format-prop';
import { EnumpluginLoggingErrorBehaviorProp } from './enumplugin-logging-error-behavior-prop';
import { EnumpluginMultiValuedAttributeBehaviorProp } from './enumplugin-multi-valued-attribute-behavior-prop';
import { EnumpluginMultipleValuePatternBehaviorProp } from './enumplugin-multiple-value-pattern-behavior-prop';
import { EnumpluginPeriodicStatsLoggerPerApplicationLDAPStatsProp } from './enumplugin-periodic-stats-logger-per-application-ldapstats-prop';
import { EnumpluginPluginTypeProp } from './enumplugin-plugin-type-prop';
import { EnumpluginPurgeBehaviorProp } from './enumplugin-purge-behavior-prop';
import { EnumpluginReadOperationSupportProp } from './enumplugin-read-operation-support-prop';
import { EnumpluginReplicationInfoProp } from './enumplugin-replication-info-prop';
import { EnumpluginScopeProp } from './enumplugin-scope-prop';
import { EnumpluginServerAccessModeProp } from './enumplugin-server-access-mode-prop';
import { EnumpluginSourceAttributeRemovalBehaviorProp } from './enumplugin-source-attribute-removal-behavior-prop';
import { EnumpluginStatusSummaryInfoProp } from './enumplugin-status-summary-info-prop';
import { EnumpluginTargetAttributeExistsDuringInitialPopulationBehaviorProp } from './enumplugin-target-attribute-exists-during-initial-population-behavior-prop';
import { EnumpluginTraditionalStaticGroupObjectClassProp } from './enumplugin-traditional-static-group-object-class-prop';
import { EnumpluginUniqueAttributeMultipleAttributeBehaviorProp } from './enumplugin-unique-attribute-multiple-attribute-behavior-prop';
import { EnumpluginUpdateSourceAttributeBehaviorProp } from './enumplugin-update-source-attribute-behavior-prop';
import { EnumpluginUpdateTargetAttributeBehaviorProp } from './enumplugin-update-target-attribute-behavior-prop';
import { EnumpluginUpdatedEntryNewlyMatchesCriteriaBehaviorProp } from './enumplugin-updated-entry-newly-matches-criteria-behavior-prop';
import { EnumpluginUpdatedEntryNoLongerMatchesCriteriaBehaviorProp } from './enumplugin-updated-entry-no-longer-matches-criteria-behavior-prop';
import { GroovyScriptedPluginResponse } from './groovy-scripted-plugin-response';
import { InternalSearchRatePluginResponse } from './internal-search-rate-plugin-response';
import { InvertedStaticGroupReferentialIntegrityPluginResponse } from './inverted-static-group-referential-integrity-plugin-response';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { ModifiablePasswordPolicyStatePluginResponse } from './modifiable-password-policy-state-plugin-response';
import { PassThroughAuthenticationPluginResponse } from './pass-through-authentication-plugin-response';
import { PeriodicGcPluginResponse } from './periodic-gc-plugin-response';
import { PeriodicStatsLoggerPluginResponse } from './periodic-stats-logger-plugin-response';
import { PingOnePassThroughAuthenticationPluginResponse } from './ping-one-pass-through-authentication-plugin-response';
import { PluggablePassThroughAuthenticationPluginResponse } from './pluggable-pass-through-authentication-plugin-response';
import { PurgeExpiredDataPluginResponse } from './purge-expired-data-plugin-response';
import { ReferentialIntegrityPluginResponse } from './referential-integrity-plugin-response';
import { ReferralOnUpdatePluginResponse } from './referral-on-update-plugin-response';
import { SearchShutdownPluginResponse } from './search-shutdown-plugin-response';
import { SevenBitCleanPluginResponse } from './seven-bit-clean-plugin-response';
import { SimpleToExternalBindPluginResponse } from './simple-to-external-bind-plugin-response';
import { SnmpSubagentPluginResponse } from './snmp-subagent-plugin-response';
import { SubOperationTimingPluginResponse } from './sub-operation-timing-plugin-response';
import { ThirdPartyPluginResponse } from './third-party-plugin-response';
import { TraditionalStaticGroupSupportForInvertedStaticGroupsPluginResponse } from './traditional-static-group-support-for-inverted-static-groups-plugin-response';
import { UniqueAttributePluginResponse } from './unique-attribute-plugin-response';

/**
 * @type AddPlugin200Response
 * @export
 */
export type AddPlugin200Response = AttributeMapperPluginResponse | CleanUpExpiredPingfederatePersistentAccessGrantsPluginResponse | CleanUpExpiredPingfederatePersistentSessionsPluginResponse | CleanUpInactivePingfederatePersistentSessionsPluginResponse | CoalesceModificationsPluginResponse | ComposedAttributePluginResponse | DelayPluginResponse | DnMapperPluginResponse | GroovyScriptedPluginResponse | InternalSearchRatePluginResponse | InvertedStaticGroupReferentialIntegrityPluginResponse | ModifiablePasswordPolicyStatePluginResponse | PassThroughAuthenticationPluginResponse | PeriodicGcPluginResponse | PeriodicStatsLoggerPluginResponse | PingOnePassThroughAuthenticationPluginResponse | PluggablePassThroughAuthenticationPluginResponse | PurgeExpiredDataPluginResponse | ReferentialIntegrityPluginResponse | ReferralOnUpdatePluginResponse | SearchShutdownPluginResponse | SevenBitCleanPluginResponse | SimpleToExternalBindPluginResponse | SnmpSubagentPluginResponse | SubOperationTimingPluginResponse | ThirdPartyPluginResponse | TraditionalStaticGroupSupportForInvertedStaticGroupsPluginResponse | UniqueAttributePluginResponse;


