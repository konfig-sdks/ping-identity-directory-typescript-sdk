/* tslint:disable */
/* eslint-disable */
/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/

import globalAxios, { AxiosPromise, AxiosInstance, AxiosRequestConfig } from 'axios';
import { Configuration } from '../configuration';
// Some imports not used depending on template conditions
// @ts-ignore
import { DUMMY_BASE_URL, assertParamExists, setApiKeyToObject, setBasicAuthToObject, setBearerAuthToObject, setSearchParams, serializeDataIfNeeded, toPathString, createRequestFunction, isBrowser } from '../common';
// @ts-ignore
import { BASE_PATH, COLLECTION_FORMATS, RequestArgs, BaseAPI, RequiredError } from '../base';
// @ts-ignore
import { AddPlugin200Response } from '../models';
// @ts-ignore
import { AddPluginRequest } from '../models';
// @ts-ignore
import { EnuminvertedStaticGroupReferentialIntegrityPluginSchemaUrn } from '../models';
// @ts-ignore
import { EnumpluginDatetimeFormatProp } from '../models';
// @ts-ignore
import { EnumpluginEntryCacheInfoProp } from '../models';
// @ts-ignore
import { EnumpluginGaugeInfoProp } from '../models';
// @ts-ignore
import { EnumpluginHistogramFormatProp } from '../models';
// @ts-ignore
import { EnumpluginHistogramOpTypeProp } from '../models';
// @ts-ignore
import { EnumpluginHostInfoProp } from '../models';
// @ts-ignore
import { EnumpluginIgnoredPasswordPolicyStateErrorConditionProp } from '../models';
// @ts-ignore
import { EnumpluginIncludedLDAPStatProp } from '../models';
// @ts-ignore
import { EnumpluginIncludedResourceStatProp } from '../models';
// @ts-ignore
import { EnumpluginInvokeGCDayOfWeekProp } from '../models';
// @ts-ignore
import { EnumpluginLdapChangelogInfoProp } from '../models';
// @ts-ignore
import { EnumpluginLocalDBBackendInfoProp } from '../models';
// @ts-ignore
import { EnumpluginLogFileFormatProp } from '../models';
// @ts-ignore
import { EnumpluginLoggingErrorBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginMultiValuedAttributeBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginMultipleValuePatternBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginPeriodicStatsLoggerPerApplicationLDAPStatsProp } from '../models';
// @ts-ignore
import { EnumpluginPluginTypeProp } from '../models';
// @ts-ignore
import { EnumpluginPurgeBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginReadOperationSupportProp } from '../models';
// @ts-ignore
import { EnumpluginReplicationInfoProp } from '../models';
// @ts-ignore
import { EnumpluginScopeProp } from '../models';
// @ts-ignore
import { EnumpluginServerAccessModeProp } from '../models';
// @ts-ignore
import { EnumpluginSourceAttributeRemovalBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginStatusSummaryInfoProp } from '../models';
// @ts-ignore
import { EnumpluginTargetAttributeExistsDuringInitialPopulationBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginTraditionalStaticGroupObjectClassProp } from '../models';
// @ts-ignore
import { EnumpluginUniqueAttributeMultipleAttributeBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginUpdateSourceAttributeBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginUpdateTargetAttributeBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginUpdatedEntryNewlyMatchesCriteriaBehaviorProp } from '../models';
// @ts-ignore
import { EnumpluginUpdatedEntryNoLongerMatchesCriteriaBehaviorProp } from '../models';
// @ts-ignore
import { GetPlugin200Response } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { PluginListResponse } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * PluginApi - axios parameter creator
 * @export
 */
export const PluginApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Plugin to the config
         * @param {AddPluginRequest} addPluginRequest Create a new Plugin in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig: async (addPluginRequest: AddPluginRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addPluginRequest' is not null or undefined
            assertParamExists('addNewConfig', 'addPluginRequest', addPluginRequest)
            const localVarPath = `/plugin-root/plugins`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'POST', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)

    
            localVarHeaderParameter['Content-Type'] = 'application/json';


            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                requestBody: addPluginRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/plugin-root/plugins',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addPluginRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Plugin
         * @param {string} pluginName Name of the Plugin
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deletePlugin: async (pluginName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pluginName' is not null or undefined
            assertParamExists('deletePlugin', 'pluginName', pluginName)
            const localVarPath = `/plugin-root/plugins/{plugin-name}`
                .replace(`{${"plugin-name"}}`, encodeURIComponent(String(pluginName !== undefined ? pluginName : `-plugin-name-`)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'DELETE', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)

    
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/plugin-root/plugins/{plugin-name}',
                httpMethod: 'DELETE'
            });

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Returns a single Plugin
         * @param {string} pluginName Name of the Plugin
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle: async (pluginName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pluginName' is not null or undefined
            assertParamExists('getSingle', 'pluginName', pluginName)
            const localVarPath = `/plugin-root/plugins/{plugin-name}`
                .replace(`{${"plugin-name"}}`, encodeURIComponent(String(pluginName !== undefined ? pluginName : `-plugin-name-`)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)

    
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/plugin-root/plugins/{plugin-name}',
                httpMethod: 'GET'
            });

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Returns a list of all Plugin objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/plugin-root/plugins`;
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'GET', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)
            if (filter !== undefined) {
                localVarQueryParameter['filter'] = filter;
            }


    
            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/plugin-root/plugins',
                httpMethod: 'GET'
            });

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Update an existing Plugin by name
         * @param {string} pluginName Name of the Plugin
         * @param {UpdateRequest} updateRequest Update an existing Plugin
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (pluginName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'pluginName' is not null or undefined
            assertParamExists('updateByName', 'pluginName', pluginName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/plugin-root/plugins/{plugin-name}`
                .replace(`{${"plugin-name"}}`, encodeURIComponent(String(pluginName !== undefined ? pluginName : `-plugin-name-`)));
            // use dummy base URL string because the URL constructor only accepts absolute URLs.
            const localVarUrlObj = new URL(localVarPath, DUMMY_BASE_URL);
            let baseOptions;
            if (configuration) {
                baseOptions = configuration.baseOptions;
            }

            const localVarRequestOptions: AxiosRequestConfig = { method: 'PATCH', ...baseOptions, ...options};
            const localVarHeaderParameter = configuration && !isBrowser() ? { "User-Agent": configuration.userAgent } : {} as any;
            const localVarQueryParameter = {} as any;

            // authentication basicAuth required
            // http basic authentication required
            setBasicAuthToObject(localVarRequestOptions, configuration)

    
            localVarHeaderParameter['Content-Type'] = 'application/json';


            let headersFromBaseOptions = baseOptions && baseOptions.headers ? baseOptions.headers : {};
            localVarRequestOptions.headers = {...localVarHeaderParameter, ...headersFromBaseOptions, ...options.headers};
            requestBeforeHook({
                requestBody: updateRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/plugin-root/plugins/{plugin-name}',
                httpMethod: 'PATCH'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(updateRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
    }
};

/**
 * PluginApi - functional programming interface
 * @export
 */
export const PluginApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = PluginApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Plugin to the config
         * @param {PluginApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewConfig(requestParameters: PluginApiAddNewConfigRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddPlugin200Response>> {
            const addPluginRequest: AddPluginRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewConfig(addPluginRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Plugin
         * @param {PluginApiDeletePluginRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deletePlugin(requestParameters: PluginApiDeletePluginRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deletePlugin(requestParameters.pluginName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Plugin
         * @param {PluginApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingle(requestParameters: PluginApiGetSingleRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetPlugin200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingle(requestParameters.pluginName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Plugin objects
         * @param {PluginApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllObjects(requestParameters: PluginApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<PluginListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Plugin by name
         * @param {PluginApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: PluginApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetPlugin200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.pluginName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * PluginApi - factory interface
 * @export
 */
export const PluginApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = PluginApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Plugin to the config
         * @param {PluginApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig(requestParameters: PluginApiAddNewConfigRequest, options?: AxiosRequestConfig): AxiosPromise<AddPlugin200Response> {
            return localVarFp.addNewConfig(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Plugin
         * @param {PluginApiDeletePluginRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deletePlugin(requestParameters: PluginApiDeletePluginRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deletePlugin(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Plugin
         * @param {PluginApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle(requestParameters: PluginApiGetSingleRequest, options?: AxiosRequestConfig): AxiosPromise<GetPlugin200Response> {
            return localVarFp.getSingle(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Plugin objects
         * @param {PluginApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects(requestParameters: PluginApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<PluginListResponse> {
            return localVarFp.listAllObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Plugin by name
         * @param {PluginApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: PluginApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<GetPlugin200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewConfig operation in PluginApi.
 * @export
 * @interface PluginApiAddNewConfigRequest
 */
export type PluginApiAddNewConfigRequest = {
    
} & AddPluginRequest

/**
 * Request parameters for deletePlugin operation in PluginApi.
 * @export
 * @interface PluginApiDeletePluginRequest
 */
export type PluginApiDeletePluginRequest = {
    
    /**
    * Name of the Plugin
    * @type {string}
    * @memberof PluginApiDeletePlugin
    */
    readonly pluginName: string
    
}

/**
 * Request parameters for getSingle operation in PluginApi.
 * @export
 * @interface PluginApiGetSingleRequest
 */
export type PluginApiGetSingleRequest = {
    
    /**
    * Name of the Plugin
    * @type {string}
    * @memberof PluginApiGetSingle
    */
    readonly pluginName: string
    
}

/**
 * Request parameters for listAllObjects operation in PluginApi.
 * @export
 * @interface PluginApiListAllObjectsRequest
 */
export type PluginApiListAllObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof PluginApiListAllObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in PluginApi.
 * @export
 * @interface PluginApiUpdateByNameRequest
 */
export type PluginApiUpdateByNameRequest = {
    
    /**
    * Name of the Plugin
    * @type {string}
    * @memberof PluginApiUpdateByName
    */
    readonly pluginName: string
    
} & UpdateRequest

/**
 * PluginApiGenerated - object-oriented interface
 * @export
 * @class PluginApiGenerated
 * @extends {BaseAPI}
 */
export class PluginApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Plugin to the config
     * @param {PluginApiAddNewConfigRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PluginApiGenerated
     */
    public addNewConfig(requestParameters: PluginApiAddNewConfigRequest, options?: AxiosRequestConfig) {
        return PluginApiFp(this.configuration).addNewConfig(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Plugin
     * @param {PluginApiDeletePluginRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PluginApiGenerated
     */
    public deletePlugin(requestParameters: PluginApiDeletePluginRequest, options?: AxiosRequestConfig) {
        return PluginApiFp(this.configuration).deletePlugin(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Plugin
     * @param {PluginApiGetSingleRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PluginApiGenerated
     */
    public getSingle(requestParameters: PluginApiGetSingleRequest, options?: AxiosRequestConfig) {
        return PluginApiFp(this.configuration).getSingle(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Plugin objects
     * @param {PluginApiListAllObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PluginApiGenerated
     */
    public listAllObjects(requestParameters: PluginApiListAllObjectsRequest = {}, options?: AxiosRequestConfig) {
        return PluginApiFp(this.configuration).listAllObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Plugin by name
     * @param {PluginApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof PluginApiGenerated
     */
    public updateByName(requestParameters: PluginApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return PluginApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
