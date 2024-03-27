/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"

import { EnummirrorVirtualAttributeSchemaUrn } from './enummirror-virtual-attribute-schema-urn';
import { EnumvirtualAttributeConflictBehaviorProp } from './enumvirtual-attribute-conflict-behavior-prop';
import { EnumvirtualAttributeMultipleVirtualAttributeMergeBehaviorProp } from './enumvirtual-attribute-multiple-virtual-attribute-merge-behavior-prop';

/**
 * 
 * @export
 * @interface MirrorVirtualAttributeShared
 */
export interface MirrorVirtualAttributeShared {
    /**
     * A description for this Virtual Attribute
     * @type {string}
     * @memberof MirrorVirtualAttributeShared
     */
    'description'?: string;
    /**
     * 
     * @type {Array<EnummirrorVirtualAttributeSchemaUrn>}
     * @memberof MirrorVirtualAttributeShared
     */
    'schemas': Array<EnummirrorVirtualAttributeSchemaUrn>;
    /**
     * Specifies the behavior that the server is to exhibit for entries that already contain one or more real values for the associated attribute.
     * @type {EnumvirtualAttributeConflictBehaviorProp}
     * @memberof MirrorVirtualAttributeShared
     */
    'conflictBehavior'?: EnumvirtualAttributeConflictBehaviorProp;
    /**
     * Specifies the source attribute containing the values to use for this virtual attribute.
     * @type {string}
     * @memberof MirrorVirtualAttributeShared
     */
    'sourceAttribute': string;
    /**
     * Specifies the attribute containing the DN of another entry from which to obtain the source attribute providing the values for this virtual attribute.
     * @type {string}
     * @memberof MirrorVirtualAttributeShared
     */
    'sourceEntryDNAttribute'?: string;
    /**
     * Specifies a DN map that will be used to identify the entry from which to obtain the source attribute providing the values for this virtual attribute.
     * @type {string}
     * @memberof MirrorVirtualAttributeShared
     */
    'sourceEntryDNMap'?: string;
    /**
     * Indicates whether searches performed by this virtual attribute provider should be exempted from access control restrictions.
     * @type {boolean}
     * @memberof MirrorVirtualAttributeShared
     */
    'bypassAccessControlForSearches'?: boolean;
    /**
     * Indicates whether the Virtual Attribute is enabled for use.
     * @type {boolean}
     * @memberof MirrorVirtualAttributeShared
     */
    'enabled': boolean;
    /**
     * Specifies the attribute type for the attribute whose values are to be dynamically assigned by the virtual attribute.
     * @type {string}
     * @memberof MirrorVirtualAttributeShared
     */
    'attributeType': string;
    /**
     * Specifies the base DNs for the branches containing entries that are eligible to use this virtual attribute.
     * @type {Array<string>}
     * @memberof MirrorVirtualAttributeShared
     */
    'baseDN'?: Array<string>;
    /**
     * Specifies the DNs of the groups whose members can be eligible to use this virtual attribute.
     * @type {Array<string>}
     * @memberof MirrorVirtualAttributeShared
     */
    'groupDN'?: Array<string>;
    /**
     * Specifies the search filters to be applied against entries to determine if the virtual attribute is to be generated for those entries.
     * @type {Array<string>}
     * @memberof MirrorVirtualAttributeShared
     */
    'filter'?: Array<string>;
    /**
     * Specifies a set of client connection policies for which this Virtual Attribute should be generated. If this is undefined, then this Virtual Attribute will always be generated. If it is associated with one or more client connection policies, then this Virtual Attribute will be generated only for operations requested by clients assigned to one of those client connection policies.
     * @type {Array<string>}
     * @memberof MirrorVirtualAttributeShared
     */
    'clientConnectionPolicy'?: Array<string>;
    /**
     * Indicates whether attributes of this type must be explicitly included by name in the list of requested attributes. Note that this will only apply to virtual attributes which are associated with an attribute type that is operational. It will be ignored for virtual attributes associated with a non-operational attribute type.
     * @type {boolean}
     * @memberof MirrorVirtualAttributeShared
     */
    'requireExplicitRequestByName'?: boolean;
    /**
     * Specifies the order in which virtual attribute definitions for the same attribute type will be evaluated when generating values for an entry.
     * @type {number}
     * @memberof MirrorVirtualAttributeShared
     */
    'multipleVirtualAttributeEvaluationOrderIndex'?: number;
    /**
     * Specifies the behavior that will be exhibited for cases in which multiple virtual attribute definitions apply to the same multivalued attribute type. This will be ignored for single-valued attribute types.
     * @type {EnumvirtualAttributeMultipleVirtualAttributeMergeBehaviorProp}
     * @memberof MirrorVirtualAttributeShared
     */
    'multipleVirtualAttributeMergeBehavior'?: EnumvirtualAttributeMultipleVirtualAttributeMergeBehaviorProp;
    /**
     * Indicates whether the server should allow creating or altering this virtual attribute definition even if it conflicts with one or more indexes defined in the server.
     * @type {boolean}
     * @memberof MirrorVirtualAttributeShared
     */
    'allowIndexConflicts'?: boolean;
}

