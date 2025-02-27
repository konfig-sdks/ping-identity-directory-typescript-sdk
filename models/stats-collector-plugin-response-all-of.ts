/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumpluginEntryCacheInfoProp } from './enumplugin-entry-cache-info-prop';
import { EnumpluginHostInfoProp } from './enumplugin-host-info-prop';
import { EnumpluginLdapChangelogInfoProp } from './enumplugin-ldap-changelog-info-prop';
import { EnumpluginLdapInfoProp } from './enumplugin-ldap-info-prop';
import { EnumpluginLocalDBBackendInfoProp } from './enumplugin-local-dbbackend-info-prop';
import { EnumpluginReplicationInfoProp } from './enumplugin-replication-info-prop';
import { EnumpluginServerInfoProp } from './enumplugin-server-info-prop';
import { EnumpluginStatsCollectorPerApplicationLDAPStatsProp } from './enumplugin-stats-collector-per-application-ldapstats-prop';
import { EnumpluginStatusSummaryInfoProp } from './enumplugin-status-summary-info-prop';
import { EnumstatsCollectorPluginSchemaUrn } from './enumstats-collector-plugin-schema-urn';

/**
 * 
 * @export
 * @interface StatsCollectorPluginResponseAllOf
 */
export interface StatsCollectorPluginResponseAllOf {
    /**
     * A description for this Plugin
     * @type {string}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumstatsCollectorPluginSchemaUrn>}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'schemas'?: Array<EnumstatsCollectorPluginSchemaUrn>;
    /**
     * Name of the Plugin
     * @type {string}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'id'?: string;
    /**
     * The duration between statistics collections. Setting this value too small can have an impact on performance. This value should be a multiple of collection-interval.
     * @type {string}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'sampleInterval'?: string;
    /**
     * Some of the calculated statistics, such as the average and maximum queue sizes, can use multiple samples within a log interval. This value controls how often samples are gathered, and setting this value too small can have an adverse impact on performance.
     * @type {string}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'collectionInterval'?: string;
    /**
     * Specifies the level of detail to include about the LDAP connection handlers.
     * @type {EnumpluginLdapInfoProp}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'ldapInfo'?: EnumpluginLdapInfoProp;
    /**
     * Specifies whether statistics related to resource utilization such as JVM memory and CPU/Network/Disk utilization.
     * @type {EnumpluginServerInfoProp}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'serverInfo'?: EnumpluginServerInfoProp;
    /**
     * Controls whether per application LDAP statistics are included in the output for selected LDAP operation statistics.
     * @type {EnumpluginStatsCollectorPerApplicationLDAPStatsProp}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'perApplicationLDAPStats'?: EnumpluginStatsCollectorPerApplicationLDAPStatsProp;
    /**
     * Specifies the level of detail to include for the LDAP changelog.
     * @type {EnumpluginLdapChangelogInfoProp}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'ldapChangelogInfo'?: EnumpluginLdapChangelogInfoProp;
    /**
     * Specifies the level of detail to include about the status summary monitor entry.
     * @type {EnumpluginStatusSummaryInfoProp}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'statusSummaryInfo'?: EnumpluginStatusSummaryInfoProp;
    /**
     * Indicates whether this plugin should store metric samples on disk for use by the Data Metrics Server. If the Stats Collector Plugin is only being used to collect metrics for one or more StatsD Monitoring Endpoints, then this can be set to false to prevent unnecessary I/O.
     * @type {boolean}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'generateCollectorFiles'?: boolean;
    /**
     * Specifies the level of detail to include about the Local DB Backends.
     * @type {EnumpluginLocalDBBackendInfoProp}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'localDBBackendInfo'?: EnumpluginLocalDBBackendInfoProp;
    /**
     * Specifies the level of detail to include about replication.
     * @type {EnumpluginReplicationInfoProp}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'replicationInfo'?: EnumpluginReplicationInfoProp;
    /**
     * Specifies the level of detail to include for each entry cache.
     * @type {EnumpluginEntryCacheInfoProp}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'entryCacheInfo'?: EnumpluginEntryCacheInfoProp;
    /**
     * 
     * @type {Array<EnumpluginHostInfoProp>}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'hostInfo'?: Array<EnumpluginHostInfoProp>;
    /**
     * If statistics should not be included for all applications, this property names the subset of applications that should be included.
     * @type {Array<string>}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'includedLDAPApplication'?: Array<string>;
    /**
     * Indicates whether the plug-in is enabled for use.
     * @type {boolean}
     * @memberof StatsCollectorPluginResponseAllOf
     */
    'enabled'?: boolean;
}

