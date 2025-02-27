/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumperiodicStatsLoggerPluginSchemaUrn } from './enumperiodic-stats-logger-plugin-schema-urn';
import { EnumpluginEntryCacheInfoProp } from './enumplugin-entry-cache-info-prop';
import { EnumpluginGaugeInfoProp } from './enumplugin-gauge-info-prop';
import { EnumpluginHistogramFormatProp } from './enumplugin-histogram-format-prop';
import { EnumpluginHistogramOpTypeProp } from './enumplugin-histogram-op-type-prop';
import { EnumpluginHostInfoProp } from './enumplugin-host-info-prop';
import { EnumpluginIncludedLDAPStatProp } from './enumplugin-included-ldapstat-prop';
import { EnumpluginIncludedResourceStatProp } from './enumplugin-included-resource-stat-prop';
import { EnumpluginLdapChangelogInfoProp } from './enumplugin-ldap-changelog-info-prop';
import { EnumpluginLocalDBBackendInfoProp } from './enumplugin-local-dbbackend-info-prop';
import { EnumpluginLogFileFormatProp } from './enumplugin-log-file-format-prop';
import { EnumpluginLoggingErrorBehaviorProp } from './enumplugin-logging-error-behavior-prop';
import { EnumpluginPeriodicStatsLoggerPerApplicationLDAPStatsProp } from './enumplugin-periodic-stats-logger-per-application-ldapstats-prop';
import { EnumpluginReplicationInfoProp } from './enumplugin-replication-info-prop';
import { EnumpluginStatusSummaryInfoProp } from './enumplugin-status-summary-info-prop';

/**
 * 
 * @export
 * @interface PeriodicStatsLoggerPluginShared
 */
export interface PeriodicStatsLoggerPluginShared {
    /**
     * A description for this Plugin
     * @type {string}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumperiodicStatsLoggerPluginSchemaUrn>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'schemas': Array<EnumperiodicStatsLoggerPluginSchemaUrn>;
    /**
     * The duration between statistics collection and logging. A new line is logged to the output for each interval. Setting this value too small can have an impact on performance.
     * @type {string}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'logInterval'?: string;
    /**
     * Some of the calculated statistics, such as the average and maximum queue sizes, can use multiple samples within a log interval. This value controls how often samples are gathered. It should be a multiple of the log-interval.
     * @type {string}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'collectionInterval'?: string;
    /**
     * If the server is idle during the specified interval, then do not log any output if this property is set to true. The server is idle if during the interval, no new connections were established, no operations were processed, and no operations are pending.
     * @type {boolean}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'suppressIfIdle'?: boolean;
    /**
     * This property controls whether the header prefix, which applies to a group of columns, appears at the start of each column header or only the first column in a group.
     * @type {boolean}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'headerPrefixPerColumn'?: boolean;
    /**
     * This property controls whether a value in the output is shown as empty if the value is zero.
     * @type {boolean}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'emptyInsteadOfZero'?: boolean;
    /**
     * The number of lines to log between logging the header line that summarizes the columns in the table.
     * @type {number}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'linesBetweenHeader'?: number;
    /**
     * 
     * @type {Array<EnumpluginIncludedLDAPStatProp>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'includedLDAPStat'?: Array<EnumpluginIncludedLDAPStatProp>;
    /**
     * 
     * @type {Array<EnumpluginIncludedResourceStatProp>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'includedResourceStat'?: Array<EnumpluginIncludedResourceStatProp>;
    /**
     * The format of the data in the processing time histogram.
     * @type {EnumpluginHistogramFormatProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'histogramFormat'?: EnumpluginHistogramFormatProp;
    /**
     * 
     * @type {Array<EnumpluginHistogramOpTypeProp>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'histogramOpType'?: Array<EnumpluginHistogramOpTypeProp>;
    /**
     * Controls whether per application LDAP statistics are included in the output for selected LDAP operation statistics.
     * @type {EnumpluginPeriodicStatsLoggerPerApplicationLDAPStatsProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'perApplicationLDAPStats'?: EnumpluginPeriodicStatsLoggerPerApplicationLDAPStatsProp;
    /**
     * Specifies the level of detail to include about the status summary monitor entry.
     * @type {EnumpluginStatusSummaryInfoProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'statusSummaryInfo'?: EnumpluginStatusSummaryInfoProp;
    /**
     * Specifies the level of detail to include for the LDAP changelog.
     * @type {EnumpluginLdapChangelogInfoProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'ldapChangelogInfo'?: EnumpluginLdapChangelogInfoProp;
    /**
     * Specifies the level of detail to include for Gauges.
     * @type {EnumpluginGaugeInfoProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'gaugeInfo'?: EnumpluginGaugeInfoProp;
    /**
     * Specifies the format to use when logging server statistics.
     * @type {EnumpluginLogFileFormatProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'logFileFormat'?: EnumpluginLogFileFormatProp;
    /**
     * The file name to use for the log files generated by the Periodic Stats Logger Plugin. The path to the file can be specified either as relative to the server root or as an absolute path.
     * @type {string}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'logFile': string;
    /**
     * The UNIX permissions of the log files created by this Periodic Stats Logger Plugin.
     * @type {string}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'logFilePermissions'?: string;
    /**
     * Specifies whether to append to existing log files.
     * @type {boolean}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'append'?: boolean;
    /**
     * The rotation policy to use for the Periodic Stats Logger Plugin .
     * @type {Array<string>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'rotationPolicy'?: Array<string>;
    /**
     * A listener that should be notified whenever a log file is rotated out of service.
     * @type {Array<string>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'rotationListener'?: Array<string>;
    /**
     * The retention policy to use for the Periodic Stats Logger Plugin .
     * @type {Array<string>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'retentionPolicy'?: Array<string>;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumpluginLoggingErrorBehaviorProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'loggingErrorBehavior'?: EnumpluginLoggingErrorBehaviorProp;
    /**
     * Specifies the level of detail to include about the Local DB Backends.
     * @type {EnumpluginLocalDBBackendInfoProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'localDBBackendInfo'?: EnumpluginLocalDBBackendInfoProp;
    /**
     * Specifies the level of detail to include about replication.
     * @type {EnumpluginReplicationInfoProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'replicationInfo'?: EnumpluginReplicationInfoProp;
    /**
     * Specifies the level of detail to include for each entry cache.
     * @type {EnumpluginEntryCacheInfoProp}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'entryCacheInfo'?: EnumpluginEntryCacheInfoProp;
    /**
     * 
     * @type {Array<EnumpluginHostInfoProp>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'hostInfo'?: Array<EnumpluginHostInfoProp>;
    /**
     * If statistics should not be included for all applications, this property names the subset of applications that should be included.
     * @type {Array<string>}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'includedLDAPApplication'?: Array<string>;
    /**
     * Indicates whether the plug-in is enabled for use.
     * @type {boolean}
     * @memberof PeriodicStatsLoggerPluginShared
     */
    'enabled': boolean;
}

