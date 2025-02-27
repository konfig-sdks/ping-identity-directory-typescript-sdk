/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumgaugeAlertLevelProp } from './enumgauge-alert-level-prop';
import { EnumgaugeOverrideSeverityProp } from './enumgauge-override-severity-prop';
import { EnumgaugeServerDegradedSeverityLevelProp } from './enumgauge-server-degraded-severity-level-prop';
import { EnumgaugeServerUnavailableSeverityLevelProp } from './enumgauge-server-unavailable-severity-level-prop';
import { EnumindicatorGaugeSchemaUrn } from './enumindicator-gauge-schema-urn';

/**
 * 
 * @export
 * @interface IndicatorGaugeShared
 */
export interface IndicatorGaugeShared {
    /**
     * A description for this Gauge
     * @type {string}
     * @memberof IndicatorGaugeShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumindicatorGaugeSchemaUrn>}
     * @memberof IndicatorGaugeShared
     */
    'schemas': Array<EnumindicatorGaugeSchemaUrn>;
    /**
     * Specifies the source of data to use in determining this Indicator Gauge\'s severity and status.
     * @type {string}
     * @memberof IndicatorGaugeShared
     */
    'gaugeDataSource': string;
    /**
     * A regular expression pattern that is used to determine whether the current monitored value indicates this gauge\'s severity should be critical.
     * @type {string}
     * @memberof IndicatorGaugeShared
     */
    'criticalValue'?: string;
    /**
     * A regular expression pattern that is used to determine whether the current monitored value indicates this gauge\'s severity will be \'major\'.
     * @type {string}
     * @memberof IndicatorGaugeShared
     */
    'majorValue'?: string;
    /**
     * A regular expression pattern that is used to determine whether the current monitored value indicates this gauge\'s severity will be \'minor\'.
     * @type {string}
     * @memberof IndicatorGaugeShared
     */
    'minorValue'?: string;
    /**
     * A regular expression pattern that is used to determine whether the current monitored value indicates this gauge\'s severity will be \'warning\'.
     * @type {string}
     * @memberof IndicatorGaugeShared
     */
    'warningValue'?: string;
    /**
     * Indicates whether this Gauge is enabled.
     * @type {boolean}
     * @memberof IndicatorGaugeShared
     */
    'enabled'?: boolean;
    /**
     * When defined, causes this Gauge to assume the specified severity, overriding its computed severity. This is useful for testing alarms generated by Gauges as well as suppressing alarms for known conditions.
     * @type {EnumgaugeOverrideSeverityProp}
     * @memberof IndicatorGaugeShared
     */
    'overrideSeverity'?: EnumgaugeOverrideSeverityProp;
    /**
     * Specifies the level at which alerts are sent for alarms raised by this Gauge.
     * @type {EnumgaugeAlertLevelProp}
     * @memberof IndicatorGaugeShared
     */
    'alertLevel'?: EnumgaugeAlertLevelProp;
    /**
     * The frequency with which this Gauge is updated.
     * @type {string}
     * @memberof IndicatorGaugeShared
     */
    'updateInterval'?: string;
    /**
     * Indicates the number of times the monitor data source value will be collected during the update interval.
     * @type {number}
     * @memberof IndicatorGaugeShared
     */
    'samplesPerUpdateInterval'?: number;
    /**
     * Specifies set of resources to be monitored.
     * @type {Array<string>}
     * @memberof IndicatorGaugeShared
     */
    'includeResource'?: Array<string>;
    /**
     * Specifies resources to exclude from being monitored.
     * @type {Array<string>}
     * @memberof IndicatorGaugeShared
     */
    'excludeResource'?: Array<string>;
    /**
     * Specifies the alarm severity level at or above which the server is considered unavailable.
     * @type {EnumgaugeServerUnavailableSeverityLevelProp}
     * @memberof IndicatorGaugeShared
     */
    'serverUnavailableSeverityLevel'?: EnumgaugeServerUnavailableSeverityLevelProp;
    /**
     * Specifies the alarm severity level at or above which the server is considered degraded.
     * @type {EnumgaugeServerDegradedSeverityLevelProp}
     * @memberof IndicatorGaugeShared
     */
    'serverDegradedSeverityLevel'?: EnumgaugeServerDegradedSeverityLevelProp;
}

