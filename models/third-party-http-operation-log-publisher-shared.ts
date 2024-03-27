/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumlogPublisherLoggingErrorBehaviorProp } from './enumlog-publisher-logging-error-behavior-prop';
import { EnumthirdPartyHttpOperationLogPublisherSchemaUrn } from './enumthird-party-http-operation-log-publisher-schema-urn';

/**
 * 
 * @export
 * @interface ThirdPartyHttpOperationLogPublisherShared
 */
export interface ThirdPartyHttpOperationLogPublisherShared {
    /**
     * A description for this Log Publisher
     * @type {string}
     * @memberof ThirdPartyHttpOperationLogPublisherShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumthirdPartyHttpOperationLogPublisherSchemaUrn>}
     * @memberof ThirdPartyHttpOperationLogPublisherShared
     */
    'schemas': Array<EnumthirdPartyHttpOperationLogPublisherSchemaUrn>;
    /**
     * The fully-qualified name of the Java class providing the logic for the Third Party HTTP Operation Log Publisher.
     * @type {string}
     * @memberof ThirdPartyHttpOperationLogPublisherShared
     */
    'extensionClass': string;
    /**
     * The set of arguments used to customize the behavior for the Third Party HTTP Operation Log Publisher. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof ThirdPartyHttpOperationLogPublisherShared
     */
    'extensionArgument'?: Array<string>;
    /**
     * Indicates whether the Log Publisher is enabled for use.
     * @type {boolean}
     * @memberof ThirdPartyHttpOperationLogPublisherShared
     */
    'enabled': boolean;
    /**
     * Specifies the behavior that the server should exhibit if an error occurs during logging processing.
     * @type {EnumlogPublisherLoggingErrorBehaviorProp}
     * @memberof ThirdPartyHttpOperationLogPublisherShared
     */
    'loggingErrorBehavior'?: EnumlogPublisherLoggingErrorBehaviorProp;
}

