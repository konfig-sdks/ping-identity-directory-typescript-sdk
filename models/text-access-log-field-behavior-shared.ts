/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumlogFieldBehaviorDefaultBehaviorProp } from './enumlog-field-behavior-default-behavior-prop';
import { EnumlogFieldBehaviorTextAccessOmitFieldProp } from './enumlog-field-behavior-text-access-omit-field-prop';
import { EnumlogFieldBehaviorTextAccessPreserveFieldProp } from './enumlog-field-behavior-text-access-preserve-field-prop';
import { EnumlogFieldBehaviorTextAccessRedactEntireValueFieldProp } from './enumlog-field-behavior-text-access-redact-entire-value-field-prop';
import { EnumlogFieldBehaviorTextAccessRedactValueComponentsFieldProp } from './enumlog-field-behavior-text-access-redact-value-components-field-prop';
import { EnumlogFieldBehaviorTextAccessTokenizeEntireValueFieldProp } from './enumlog-field-behavior-text-access-tokenize-entire-value-field-prop';
import { EnumlogFieldBehaviorTextAccessTokenizeValueComponentsFieldProp } from './enumlog-field-behavior-text-access-tokenize-value-components-field-prop';
import { EnumtextAccessLogFieldBehaviorSchemaUrn } from './enumtext-access-log-field-behavior-schema-urn';

/**
 * 
 * @export
 * @interface TextAccessLogFieldBehaviorShared
 */
export interface TextAccessLogFieldBehaviorShared {
    /**
     * A description for this Log Field Behavior
     * @type {string}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumtextAccessLogFieldBehaviorSchemaUrn>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'schemas': Array<EnumtextAccessLogFieldBehaviorSchemaUrn>;
    /**
     * 
     * @type {Array<EnumlogFieldBehaviorTextAccessPreserveFieldProp>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'preserveField'?: Array<EnumlogFieldBehaviorTextAccessPreserveFieldProp>;
    /**
     * The names of any custom fields whose values should be preserved. This should generally only be used for fields that are not available through the preserve-field property (for example, custom log fields defined in Server SDK extensions).
     * @type {Array<string>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'preserveFieldName'?: Array<string>;
    /**
     * 
     * @type {Array<EnumlogFieldBehaviorTextAccessOmitFieldProp>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'omitField'?: Array<EnumlogFieldBehaviorTextAccessOmitFieldProp>;
    /**
     * The names of any custom fields that should be omitted from log messages. This should generally only be used for fields that are not available through the omit-field property (for example, custom log fields defined in Server SDK extensions).
     * @type {Array<string>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'omitFieldName'?: Array<string>;
    /**
     * 
     * @type {Array<EnumlogFieldBehaviorTextAccessRedactEntireValueFieldProp>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'redactEntireValueField'?: Array<EnumlogFieldBehaviorTextAccessRedactEntireValueFieldProp>;
    /**
     * The names of any custom fields whose values should be completely redacted. This should generally only be used for fields that are not available through the redact-entire-value-field property (for example, custom log fields defined in Server SDK extensions).
     * @type {Array<string>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'redactEntireValueFieldName'?: Array<string>;
    /**
     * 
     * @type {Array<EnumlogFieldBehaviorTextAccessRedactValueComponentsFieldProp>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'redactValueComponentsField'?: Array<EnumlogFieldBehaviorTextAccessRedactValueComponentsFieldProp>;
    /**
     * The names of any custom fields for which to redact components within the value. This should generally only be used for fields that are not available through the redact-value-components-field property (for example, custom log fields defined in Server SDK extensions).
     * @type {Array<string>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'redactValueComponentsFieldName'?: Array<string>;
    /**
     * 
     * @type {Array<EnumlogFieldBehaviorTextAccessTokenizeEntireValueFieldProp>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'tokenizeEntireValueField'?: Array<EnumlogFieldBehaviorTextAccessTokenizeEntireValueFieldProp>;
    /**
     * The names of any custom fields whose values should be completely tokenized. This should generally only be used for fields that are not available through the tokenize-entire-value-field property (for example, custom log fields defined in Server SDK extensions).
     * @type {Array<string>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'tokenizeEntireValueFieldName'?: Array<string>;
    /**
     * 
     * @type {Array<EnumlogFieldBehaviorTextAccessTokenizeValueComponentsFieldProp>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'tokenizeValueComponentsField'?: Array<EnumlogFieldBehaviorTextAccessTokenizeValueComponentsFieldProp>;
    /**
     * The names of any custom fields for which to tokenize components within the value. This should generally only be used for fields that are not available through the tokenize-value-components-field property (for example, custom log fields defined in Server SDK extensions).
     * @type {Array<string>}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'tokenizeValueComponentsFieldName'?: Array<string>;
    /**
     * The default behavior that the server should exhibit for fields for which no explicit behavior is defined. If no default behavior is defined, the server will fall back to using the default behavior configured for the syntax used for each log field.
     * @type {EnumlogFieldBehaviorDefaultBehaviorProp}
     * @memberof TextAccessLogFieldBehaviorShared
     */
    'defaultBehavior'?: EnumlogFieldBehaviorDefaultBehaviorProp;
}

