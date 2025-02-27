/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumthirdPartyPassThroughAuthenticationHandlerSchemaUrn } from './enumthird-party-pass-through-authentication-handler-schema-urn';

/**
 * 
 * @export
 * @interface ThirdPartyPassThroughAuthenticationHandlerShared
 */
export interface ThirdPartyPassThroughAuthenticationHandlerShared {
    /**
     * A description for this Pass Through Authentication Handler
     * @type {string}
     * @memberof ThirdPartyPassThroughAuthenticationHandlerShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumthirdPartyPassThroughAuthenticationHandlerSchemaUrn>}
     * @memberof ThirdPartyPassThroughAuthenticationHandlerShared
     */
    'schemas': Array<EnumthirdPartyPassThroughAuthenticationHandlerSchemaUrn>;
    /**
     * The fully-qualified name of the Java class providing the logic for the Third Party Pass Through Authentication Handler.
     * @type {string}
     * @memberof ThirdPartyPassThroughAuthenticationHandlerShared
     */
    'extensionClass': string;
    /**
     * The set of arguments used to customize the behavior for the Third Party Pass Through Authentication Handler. Each configuration property should be given in the form \'name=value\'.
     * @type {Array<string>}
     * @memberof ThirdPartyPassThroughAuthenticationHandlerShared
     */
    'extensionArgument'?: Array<string>;
    /**
     * The base DNs for the local users whose authentication attempts may be passed through to the external authentication service.
     * @type {Array<string>}
     * @memberof ThirdPartyPassThroughAuthenticationHandlerShared
     */
    'includedLocalEntryBaseDN'?: Array<string>;
    /**
     * A reference to connection criteria that will be used to indicate which bind requests should be passed through to the external authentication service.
     * @type {string}
     * @memberof ThirdPartyPassThroughAuthenticationHandlerShared
     */
    'connectionCriteria'?: string;
    /**
     * A reference to request criteria that will be used to indicate which bind requests should be passed through to the external authentication service.
     * @type {string}
     * @memberof ThirdPartyPassThroughAuthenticationHandlerShared
     */
    'requestCriteria'?: string;
}

