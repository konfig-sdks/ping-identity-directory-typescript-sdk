/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumrecurringTaskChainInterruptedByShutdownBehaviorProp } from './enumrecurring-task-chain-interrupted-by-shutdown-behavior-prop';
import { EnumrecurringTaskChainScheduledDateSelectionTypeProp } from './enumrecurring-task-chain-scheduled-date-selection-type-prop';
import { EnumrecurringTaskChainScheduledDayOfTheMonthProp } from './enumrecurring-task-chain-scheduled-day-of-the-month-prop';
import { EnumrecurringTaskChainScheduledDayOfTheWeekProp } from './enumrecurring-task-chain-scheduled-day-of-the-week-prop';
import { EnumrecurringTaskChainScheduledMonthProp } from './enumrecurring-task-chain-scheduled-month-prop';
import { EnumrecurringTaskChainSchemaUrn } from './enumrecurring-task-chain-schema-urn';
import { EnumrecurringTaskChainServerOfflineAtStartTimeBehaviorProp } from './enumrecurring-task-chain-server-offline-at-start-time-behavior-prop';

/**
 * 
 * @export
 * @interface RecurringTaskChainShared
 */
export interface RecurringTaskChainShared {
    /**
     * A description for this Recurring Task Chain
     * @type {string}
     * @memberof RecurringTaskChainShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumrecurringTaskChainSchemaUrn>}
     * @memberof RecurringTaskChainShared
     */
    'schemas'?: Array<EnumrecurringTaskChainSchemaUrn>;
    /**
     * Indicates whether this Recurring Task Chain is enabled for use. Recurring Task Chains that are disabled will not have any new instances scheduled, but instances that are already scheduled will be preserved. Those instances may be manually canceled if desired.
     * @type {boolean}
     * @memberof RecurringTaskChainShared
     */
    'enabled'?: boolean;
    /**
     * The set of recurring tasks that make up this chain. At least one value must be provided. If multiple values are given, then the task instances will be invoked in the order in which they are listed.
     * @type {Array<string>}
     * @memberof RecurringTaskChainShared
     */
    'recurringTask': Array<string>;
    /**
     * 
     * @type {Array<EnumrecurringTaskChainScheduledMonthProp>}
     * @memberof RecurringTaskChainShared
     */
    'scheduledMonth'?: Array<EnumrecurringTaskChainScheduledMonthProp>;
    /**
     * The mechanism used to determine the dates on which instances of this Recurring Task Chain may be scheduled to start.
     * @type {EnumrecurringTaskChainScheduledDateSelectionTypeProp}
     * @memberof RecurringTaskChainShared
     */
    'scheduledDateSelectionType': EnumrecurringTaskChainScheduledDateSelectionTypeProp;
    /**
     * 
     * @type {Array<EnumrecurringTaskChainScheduledDayOfTheWeekProp>}
     * @memberof RecurringTaskChainShared
     */
    'scheduledDayOfTheWeek'?: Array<EnumrecurringTaskChainScheduledDayOfTheWeekProp>;
    /**
     * 
     * @type {Array<EnumrecurringTaskChainScheduledDayOfTheMonthProp>}
     * @memberof RecurringTaskChainShared
     */
    'scheduledDayOfTheMonth'?: Array<EnumrecurringTaskChainScheduledDayOfTheMonthProp>;
    /**
     * The time of day at which instances of the Recurring Task Chain should be eligible to start running. Values should be in the format HH:MM (where HH is a two-digit representation of the hour of the day, between 00 and 23, inclusive), and MM is a two-digit representation of the minute of the hour (between 00 and 59, inclusive). Alternately, the value can be in the form *:MM, which indicates that the task should be eligible to start at the specified minute of every hour. At least one value must be provided, but multiple values may be given to indicate multiple start times within the same day.
     * @type {Array<string>}
     * @memberof RecurringTaskChainShared
     */
    'scheduledTimeOfDay': Array<string>;
    /**
     * The time zone that will be used to interpret the scheduled-time-of-day values. If no value is provided, then the JVM\'s default time zone will be used.
     * @type {string}
     * @memberof RecurringTaskChainShared
     */
    'timeZone'?: string;
    /**
     * Specifies the behavior that the server should exhibit if it is shut down or abnormally terminated while an instance of this Recurring Task Chain is running.
     * @type {EnumrecurringTaskChainInterruptedByShutdownBehaviorProp}
     * @memberof RecurringTaskChainShared
     */
    'interruptedByShutdownBehavior'?: EnumrecurringTaskChainInterruptedByShutdownBehaviorProp;
    /**
     * Specifies the behavior that the server should exhibit if it is offline when the start time arrives for the tasks in this Recurring Task Chain.
     * @type {EnumrecurringTaskChainServerOfflineAtStartTimeBehaviorProp}
     * @memberof RecurringTaskChainShared
     */
    'serverOfflineAtStartTimeBehavior'?: EnumrecurringTaskChainServerOfflineAtStartTimeBehaviorProp;
}

