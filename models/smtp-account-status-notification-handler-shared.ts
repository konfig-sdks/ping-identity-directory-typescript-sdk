/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumsmtpAccountStatusNotificationHandlerSchemaUrn } from './enumsmtp-account-status-notification-handler-schema-urn';

/**
 * 
 * @export
 * @interface SmtpAccountStatusNotificationHandlerShared
 */
export interface SmtpAccountStatusNotificationHandlerShared {
    /**
     * A description for this Account Status Notification Handler
     * @type {string}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumsmtpAccountStatusNotificationHandlerSchemaUrn>}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'schemas': Array<EnumsmtpAccountStatusNotificationHandlerSchemaUrn>;
    /**
     * Specifies which attribute in the user\'s entries may be used to obtain the email address when notifying the end user.
     * @type {Array<string>}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'emailAddressAttributeType'?: Array<string>;
    /**
     * The name of the JSON field whose value is the email address to which the message should be sent. The email address must be contained in a top-level field whose value is a single string.
     * @type {string}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'emailAddressJSONField'?: string;
    /**
     * A JSON object filter that may be used to identify which email address value to use when sending the message.
     * @type {string}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'emailAddressJSONObjectFilter'?: string;
    /**
     * Specifies an email address to which notification messages are sent, either instead of or in addition to the end user for whom the notification has been generated.
     * @type {Array<string>}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'recipientAddress'?: Array<string>;
    /**
     * Indicates whether an email notification message should be generated and sent to the set of notification recipients even if the user entry does not contain any values for any of the email address attributes (that is, in cases when it is not possible to notify the end user).
     * @type {boolean}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'sendMessageWithoutEndUserAddress'?: boolean;
    /**
     * Specifies the email address from which the message is sent. Note that this does not necessarily have to be a legitimate email address.
     * @type {string}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'senderAddress': string;
    /**
     * Specifies the subject that should be used for email messages generated by this account status notification handler.
     * @type {Array<string>}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'messageSubject': Array<string>;
    /**
     * Specifies the path to the file containing the message template to generate the email notification messages.
     * @type {Array<string>}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'messageTemplateFile': Array<string>;
    /**
     * Indicates whether the Account Status Notification Handler is enabled. Only enabled handlers are invoked whenever a related event occurs in the server.
     * @type {boolean}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'enabled': boolean;
    /**
     * Indicates whether the server should attempt to invoke this Account Status Notification Handler in a background thread so that any potentially-expensive processing (e.g., performing network communication to deliver a message) will not delay processing for the operation that triggered the notification.
     * @type {boolean}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'asynchronous'?: boolean;
    /**
     * A result criteria object that identifies which successful bind operations should result in account authentication notifications for this handler.
     * @type {string}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'accountAuthenticationNotificationResultCriteria'?: string;
    /**
     * A request criteria object that identifies which add requests should result in account creation notifications for this handler.
     * @type {string}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'accountCreationNotificationRequestCriteria'?: string;
    /**
     * A request criteria object that identifies which delete requests should result in account deletion notifications for this handler.
     * @type {string}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'accountDeletionNotificationRequestCriteria'?: string;
    /**
     * A request criteria object that identifies which modify and modify DN requests should result in account update notifications for this handler.
     * @type {string}
     * @memberof SmtpAccountStatusNotificationHandlerShared
     */
    'accountUpdateNotificationRequestCriteria'?: string;
}

