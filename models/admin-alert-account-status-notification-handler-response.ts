/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { AdminAlertAccountStatusNotificationHandlerShared } from './admin-alert-account-status-notification-handler-shared';
import { EnumaccountStatusNotificationHandlerAccountStatusNotificationTypeProp } from './enumaccount-status-notification-handler-account-status-notification-type-prop';
import { EnumadminAlertAccountStatusNotificationHandlerSchemaUrn } from './enumadmin-alert-account-status-notification-handler-schema-urn';
import { Meta } from './meta';
import { MetaMeta } from './meta-meta';
import { MetaUrnPingidentitySchemasConfigurationMessages20 } from './meta-urn-pingidentity-schemas-configuration-messages20';
import { SmtpAccountStatusNotificationHandlerResponseAllOf } from './smtp-account-status-notification-handler-response-all-of';

/**
 * @type AdminAlertAccountStatusNotificationHandlerResponse
 * @export
 */
export type AdminAlertAccountStatusNotificationHandlerResponse = AdminAlertAccountStatusNotificationHandlerShared & Meta & SmtpAccountStatusNotificationHandlerResponseAllOf;


