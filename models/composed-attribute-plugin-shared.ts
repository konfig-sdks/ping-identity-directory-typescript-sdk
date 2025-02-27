/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnumcomposedAttributePluginSchemaUrn } from './enumcomposed-attribute-plugin-schema-urn';
import { EnumpluginMultiValuedAttributeBehaviorProp } from './enumplugin-multi-valued-attribute-behavior-prop';
import { EnumpluginMultipleValuePatternBehaviorProp } from './enumplugin-multiple-value-pattern-behavior-prop';
import { EnumpluginPluginTypeProp } from './enumplugin-plugin-type-prop';
import { EnumpluginSourceAttributeRemovalBehaviorProp } from './enumplugin-source-attribute-removal-behavior-prop';
import { EnumpluginTargetAttributeExistsDuringInitialPopulationBehaviorProp } from './enumplugin-target-attribute-exists-during-initial-population-behavior-prop';
import { EnumpluginUpdateSourceAttributeBehaviorProp } from './enumplugin-update-source-attribute-behavior-prop';
import { EnumpluginUpdateTargetAttributeBehaviorProp } from './enumplugin-update-target-attribute-behavior-prop';
import { EnumpluginUpdatedEntryNewlyMatchesCriteriaBehaviorProp } from './enumplugin-updated-entry-newly-matches-criteria-behavior-prop';
import { EnumpluginUpdatedEntryNoLongerMatchesCriteriaBehaviorProp } from './enumplugin-updated-entry-no-longer-matches-criteria-behavior-prop';

/**
 * 
 * @export
 * @interface ComposedAttributePluginShared
 */
export interface ComposedAttributePluginShared {
    /**
     * A description for this Plugin
     * @type {string}
     * @memberof ComposedAttributePluginShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnumcomposedAttributePluginSchemaUrn>}
     * @memberof ComposedAttributePluginShared
     */
    'schemas': Array<EnumcomposedAttributePluginSchemaUrn>;
    /**
     * 
     * @type {Array<EnumpluginPluginTypeProp>}
     * @memberof ComposedAttributePluginShared
     */
    'pluginType'?: Array<EnumpluginPluginTypeProp>;
    /**
     * The name or OID of the attribute type for which values are to be generated.
     * @type {string}
     * @memberof ComposedAttributePluginShared
     */
    'attributeType': string;
    /**
     * Specifies a pattern for constructing the values to use for the target attribute type.
     * @type {Array<string>}
     * @memberof ComposedAttributePluginShared
     */
    'valuePattern': Array<string>;
    /**
     * The behavior to exhibit if the plugin is configured with multiple value patterns.
     * @type {EnumpluginMultipleValuePatternBehaviorProp}
     * @memberof ComposedAttributePluginShared
     */
    'multipleValuePatternBehavior'?: EnumpluginMultipleValuePatternBehaviorProp;
    /**
     * The behavior to exhibit for source attributes that have multiple values.
     * @type {EnumpluginMultiValuedAttributeBehaviorProp}
     * @memberof ComposedAttributePluginShared
     */
    'multiValuedAttributeBehavior'?: EnumpluginMultiValuedAttributeBehaviorProp;
    /**
     * The behavior to exhibit if the target attribute exists when initially populating the entry with composed values (whether during an LDIF import, an add operation, or an invocation of the populate composed attribute values task).
     * @type {EnumpluginTargetAttributeExistsDuringInitialPopulationBehaviorProp}
     * @memberof ComposedAttributePluginShared
     */
    'targetAttributeExistsDuringInitialPopulationBehavior'?: EnumpluginTargetAttributeExistsDuringInitialPopulationBehaviorProp;
    /**
     * The behavior to exhibit for modify and modify DN operations that update one or more of the source attributes used in any of the value patterns.
     * @type {EnumpluginUpdateSourceAttributeBehaviorProp}
     * @memberof ComposedAttributePluginShared
     */
    'updateSourceAttributeBehavior'?: EnumpluginUpdateSourceAttributeBehaviorProp;
    /**
     * The behavior to exhibit for modify and modify DN operations that update an entry to remove source attributes in such a way that this plugin would no longer generate any composed values for that entry.
     * @type {EnumpluginSourceAttributeRemovalBehaviorProp}
     * @memberof ComposedAttributePluginShared
     */
    'sourceAttributeRemovalBehavior'?: EnumpluginSourceAttributeRemovalBehaviorProp;
    /**
     * The behavior to exhibit for modify and modify DN operations that attempt to update the set of values for the target attribute.
     * @type {EnumpluginUpdateTargetAttributeBehaviorProp}
     * @memberof ComposedAttributePluginShared
     */
    'updateTargetAttributeBehavior'?: EnumpluginUpdateTargetAttributeBehaviorProp;
    /**
     * The set of base DNs below which composed values may be generated.
     * @type {Array<string>}
     * @memberof ComposedAttributePluginShared
     */
    'includeBaseDN'?: Array<string>;
    /**
     * The set of base DNs below which composed values will not be generated.
     * @type {Array<string>}
     * @memberof ComposedAttributePluginShared
     */
    'excludeBaseDN'?: Array<string>;
    /**
     * The set of search filters that identify entries for which composed values may be generated.
     * @type {Array<string>}
     * @memberof ComposedAttributePluginShared
     */
    'includeFilter'?: Array<string>;
    /**
     * The set of search filters that identify entries for which composed values will not be generated.
     * @type {Array<string>}
     * @memberof ComposedAttributePluginShared
     */
    'excludeFilter'?: Array<string>;
    /**
     * The behavior to exhibit for modify or modify DN operations that update an entry that previously did not satisfy either the base DN or filter criteria, but now do satisfy that criteria.
     * @type {EnumpluginUpdatedEntryNewlyMatchesCriteriaBehaviorProp}
     * @memberof ComposedAttributePluginShared
     */
    'updatedEntryNewlyMatchesCriteriaBehavior'?: EnumpluginUpdatedEntryNewlyMatchesCriteriaBehaviorProp;
    /**
     * The behavior to exhibit for modify or modify DN operations that update an entry that previously satisfied the base DN and filter criteria, but now no longer satisfies that criteria.
     * @type {EnumpluginUpdatedEntryNoLongerMatchesCriteriaBehaviorProp}
     * @memberof ComposedAttributePluginShared
     */
    'updatedEntryNoLongerMatchesCriteriaBehavior'?: EnumpluginUpdatedEntryNoLongerMatchesCriteriaBehaviorProp;
    /**
     * Indicates whether the plug-in is enabled for use.
     * @type {boolean}
     * @memberof ComposedAttributePluginShared
     */
    'enabled': boolean;
    /**
     * Indicates whether the plug-in should be invoked for internal operations.
     * @type {boolean}
     * @memberof ComposedAttributePluginShared
     */
    'invokeForInternalOperations'?: boolean;
}

