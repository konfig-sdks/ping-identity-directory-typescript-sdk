/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumjsonLogFieldSyntaxSchemaUrn } from './enumjson-log-field-syntax-schema-urn';
import { EnumlogFieldSyntaxDefaultBehaviorProp } from './enumlog-field-syntax-default-behavior-prop';

/**
 * 
 * @export
 * @interface JsonLogFieldSyntaxResponseAllOf
 */
export interface JsonLogFieldSyntaxResponseAllOf {
    /**
     * A description for this Log Field Syntax
     * @type {string}
     * @memberof JsonLogFieldSyntaxResponseAllOf
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumjsonLogFieldSyntaxSchemaUrn>}
     * @memberof JsonLogFieldSyntaxResponseAllOf
     */
    'schemas'?: Array<EnumjsonLogFieldSyntaxSchemaUrn>;
    /**
     * Name of the Log Field Syntax
     * @type {string}
     * @memberof JsonLogFieldSyntaxResponseAllOf
     */
    'id'?: string;
    /**
     * The names of the JSON fields that will be considered sensitive.
     * @type {Array<string>}
     * @memberof JsonLogFieldSyntaxResponseAllOf
     */
    'includedSensitiveField'?: Array<string>;
    /**
     * The names of the JSON fields that will not be considered sensitive.
     * @type {Array<string>}
     * @memberof JsonLogFieldSyntaxResponseAllOf
     */
    'excludedSensitiveField'?: Array<string>;
    /**
     * The default behavior that the server should exhibit when logging fields with this syntax. This may be overridden on a per-field basis.
     * @type {EnumlogFieldSyntaxDefaultBehaviorProp}
     * @memberof JsonLogFieldSyntaxResponseAllOf
     */
    'defaultBehavior'?: EnumlogFieldSyntaxDefaultBehaviorProp;
}

