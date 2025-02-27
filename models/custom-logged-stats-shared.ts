/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumcustomLoggedStatsSchemaUrn } from './enumcustom-logged-stats-schema-urn';
import { EnumcustomLoggedStatsStatisticTypeProp } from './enumcustom-logged-stats-statistic-type-prop';

/**
 * 
 * @export
 * @interface CustomLoggedStatsShared
 */
export interface CustomLoggedStatsShared {
    /**
     * A description for this Custom Logged Stats
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumcustomLoggedStatsSchemaUrn>}
     * @memberof CustomLoggedStatsShared
     */
    'schemas': Array<EnumcustomLoggedStatsSchemaUrn>;
    /**
     * Indicates whether the Custom Logged Stats object is enabled.
     * @type {boolean}
     * @memberof CustomLoggedStatsShared
     */
    'enabled'?: boolean;
    /**
     * The objectclass name of the monitor entries to examine for generating these statistics.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'monitorObjectclass': string;
    /**
     * An optional LDAP filter that can be used restrict which monitor entries are used to produce the output.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'includeFilter'?: string;
    /**
     * Specifies the attributes on the monitor entries that should be included in the output.
     * @type {Array<string>}
     * @memberof CustomLoggedStatsShared
     */
    'attributeToLog': Array<string>;
    /**
     * Optionally, specifies an explicit name for each column header instead of having these names automatically generated from the monitored attribute name.
     * @type {Array<string>}
     * @memberof CustomLoggedStatsShared
     */
    'columnName'?: Array<string>;
    /**
     * 
     * @type {Array<EnumcustomLoggedStatsStatisticTypeProp>}
     * @memberof CustomLoggedStatsShared
     */
    'statisticType': Array<EnumcustomLoggedStatsStatisticTypeProp>;
    /**
     * An optional prefix that is included in the header before the column name.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'headerPrefix'?: string;
    /**
     * An optional attribute from the monitor entry that is included as a prefix before the column name in the column header.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'headerPrefixAttribute'?: string;
    /**
     * An optional regular expression pattern, that when used in conjunction with regex-replacement, can alter the value of the attribute being monitored.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'regexPattern'?: string;
    /**
     * An optional regular expression replacement value, that when used in conjunction with regex-pattern, can alter the value of the attribute being monitored.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'regexReplacement'?: string;
    /**
     * An optional floating point value that can be used to scale the resulting value.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'divideValueBy'?: string;
    /**
     * An optional property that can scale the resulting value by another attribute in the monitored entry.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'divideValueByAttribute'?: string;
    /**
     * This provides a way to format the monitored attribute value in the output to control the precision for instance.
     * @type {string}
     * @memberof CustomLoggedStatsShared
     */
    'decimalFormat'?: string;
    /**
     * If this property is set to true, then the value of any of the monitored attributes here can contribute to whether an interval is considered \"idle\" by the Periodic Stats Logger.
     * @type {boolean}
     * @memberof CustomLoggedStatsShared
     */
    'nonZeroImpliesNotIdle'?: boolean;
}

