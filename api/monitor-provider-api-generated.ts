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
import { AddMonitorProvider200Response } from '../models';
// @ts-ignore
import { AddMonitorProviderRequest } from '../models';
// @ts-ignore
import { EnummonitorProviderProlongedOutageBehaviorProp } from '../models';
// @ts-ignore
import { EnumthirdPartyMonitorProviderSchemaUrn } from '../models';
// @ts-ignore
import { GetMonitorProvider200Response } from '../models';
// @ts-ignore
import { MonitorProviderListResponse } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * MonitorProviderApi - axios parameter creator
 * @export
 */
export const MonitorProviderApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Monitor Provider to the config
         * @param {AddMonitorProviderRequest} addMonitorProviderRequest Create a new Monitor Provider in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig: async (addMonitorProviderRequest: AddMonitorProviderRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addMonitorProviderRequest' is not null or undefined
            assertParamExists('addNewConfig', 'addMonitorProviderRequest', addMonitorProviderRequest)
            const localVarPath = `/monitor-providers`;
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
                requestBody: addMonitorProviderRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/monitor-providers',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addMonitorProviderRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Monitor Provider
         * @param {string} monitorProviderName Name of the Monitor Provider
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteProvider: async (monitorProviderName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'monitorProviderName' is not null or undefined
            assertParamExists('deleteProvider', 'monitorProviderName', monitorProviderName)
            const localVarPath = `/monitor-providers/{monitor-provider-name}`
                .replace(`{${"monitor-provider-name"}}`, encodeURIComponent(String(monitorProviderName !== undefined ? monitorProviderName : `-monitor-provider-name-`)));
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
                pathTemplate: '/monitor-providers/{monitor-provider-name}',
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
         * @summary Returns a single Monitor Provider
         * @param {string} monitorProviderName Name of the Monitor Provider
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleProvider: async (monitorProviderName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'monitorProviderName' is not null or undefined
            assertParamExists('getSingleProvider', 'monitorProviderName', monitorProviderName)
            const localVarPath = `/monitor-providers/{monitor-provider-name}`
                .replace(`{${"monitor-provider-name"}}`, encodeURIComponent(String(monitorProviderName !== undefined ? monitorProviderName : `-monitor-provider-name-`)));
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
                pathTemplate: '/monitor-providers/{monitor-provider-name}',
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
         * @summary Returns a list of all Monitor Provider objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/monitor-providers`;
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
                pathTemplate: '/monitor-providers',
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
         * @summary Update an existing Monitor Provider by name
         * @param {string} monitorProviderName Name of the Monitor Provider
         * @param {UpdateRequest} updateRequest Update an existing Monitor Provider
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (monitorProviderName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'monitorProviderName' is not null or undefined
            assertParamExists('updateByName', 'monitorProviderName', monitorProviderName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/monitor-providers/{monitor-provider-name}`
                .replace(`{${"monitor-provider-name"}}`, encodeURIComponent(String(monitorProviderName !== undefined ? monitorProviderName : `-monitor-provider-name-`)));
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
                pathTemplate: '/monitor-providers/{monitor-provider-name}',
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
 * MonitorProviderApi - functional programming interface
 * @export
 */
export const MonitorProviderApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = MonitorProviderApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Monitor Provider to the config
         * @param {MonitorProviderApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewConfig(requestParameters: MonitorProviderApiAddNewConfigRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddMonitorProvider200Response>> {
            const addMonitorProviderRequest: AddMonitorProviderRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewConfig(addMonitorProviderRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Monitor Provider
         * @param {MonitorProviderApiDeleteProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteProvider(requestParameters: MonitorProviderApiDeleteProviderRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteProvider(requestParameters.monitorProviderName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Monitor Provider
         * @param {MonitorProviderApiGetSingleProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingleProvider(requestParameters: MonitorProviderApiGetSingleProviderRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetMonitorProvider200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingleProvider(requestParameters.monitorProviderName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Monitor Provider objects
         * @param {MonitorProviderApiListObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listObjects(requestParameters: MonitorProviderApiListObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<MonitorProviderListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Monitor Provider by name
         * @param {MonitorProviderApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: MonitorProviderApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetMonitorProvider200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.monitorProviderName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * MonitorProviderApi - factory interface
 * @export
 */
export const MonitorProviderApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = MonitorProviderApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Monitor Provider to the config
         * @param {MonitorProviderApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig(requestParameters: MonitorProviderApiAddNewConfigRequest, options?: AxiosRequestConfig): AxiosPromise<AddMonitorProvider200Response> {
            return localVarFp.addNewConfig(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Monitor Provider
         * @param {MonitorProviderApiDeleteProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteProvider(requestParameters: MonitorProviderApiDeleteProviderRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteProvider(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Monitor Provider
         * @param {MonitorProviderApiGetSingleProviderRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleProvider(requestParameters: MonitorProviderApiGetSingleProviderRequest, options?: AxiosRequestConfig): AxiosPromise<GetMonitorProvider200Response> {
            return localVarFp.getSingleProvider(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Monitor Provider objects
         * @param {MonitorProviderApiListObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listObjects(requestParameters: MonitorProviderApiListObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<MonitorProviderListResponse> {
            return localVarFp.listObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Monitor Provider by name
         * @param {MonitorProviderApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: MonitorProviderApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<GetMonitorProvider200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewConfig operation in MonitorProviderApi.
 * @export
 * @interface MonitorProviderApiAddNewConfigRequest
 */
export type MonitorProviderApiAddNewConfigRequest = {
    
} & AddMonitorProviderRequest

/**
 * Request parameters for deleteProvider operation in MonitorProviderApi.
 * @export
 * @interface MonitorProviderApiDeleteProviderRequest
 */
export type MonitorProviderApiDeleteProviderRequest = {
    
    /**
    * Name of the Monitor Provider
    * @type {string}
    * @memberof MonitorProviderApiDeleteProvider
    */
    readonly monitorProviderName: string
    
}

/**
 * Request parameters for getSingleProvider operation in MonitorProviderApi.
 * @export
 * @interface MonitorProviderApiGetSingleProviderRequest
 */
export type MonitorProviderApiGetSingleProviderRequest = {
    
    /**
    * Name of the Monitor Provider
    * @type {string}
    * @memberof MonitorProviderApiGetSingleProvider
    */
    readonly monitorProviderName: string
    
}

/**
 * Request parameters for listObjects operation in MonitorProviderApi.
 * @export
 * @interface MonitorProviderApiListObjectsRequest
 */
export type MonitorProviderApiListObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof MonitorProviderApiListObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in MonitorProviderApi.
 * @export
 * @interface MonitorProviderApiUpdateByNameRequest
 */
export type MonitorProviderApiUpdateByNameRequest = {
    
    /**
    * Name of the Monitor Provider
    * @type {string}
    * @memberof MonitorProviderApiUpdateByName
    */
    readonly monitorProviderName: string
    
} & UpdateRequest

/**
 * MonitorProviderApiGenerated - object-oriented interface
 * @export
 * @class MonitorProviderApiGenerated
 * @extends {BaseAPI}
 */
export class MonitorProviderApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Monitor Provider to the config
     * @param {MonitorProviderApiAddNewConfigRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof MonitorProviderApiGenerated
     */
    public addNewConfig(requestParameters: MonitorProviderApiAddNewConfigRequest, options?: AxiosRequestConfig) {
        return MonitorProviderApiFp(this.configuration).addNewConfig(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Monitor Provider
     * @param {MonitorProviderApiDeleteProviderRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof MonitorProviderApiGenerated
     */
    public deleteProvider(requestParameters: MonitorProviderApiDeleteProviderRequest, options?: AxiosRequestConfig) {
        return MonitorProviderApiFp(this.configuration).deleteProvider(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Monitor Provider
     * @param {MonitorProviderApiGetSingleProviderRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof MonitorProviderApiGenerated
     */
    public getSingleProvider(requestParameters: MonitorProviderApiGetSingleProviderRequest, options?: AxiosRequestConfig) {
        return MonitorProviderApiFp(this.configuration).getSingleProvider(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Monitor Provider objects
     * @param {MonitorProviderApiListObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof MonitorProviderApiGenerated
     */
    public listObjects(requestParameters: MonitorProviderApiListObjectsRequest = {}, options?: AxiosRequestConfig) {
        return MonitorProviderApiFp(this.configuration).listObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Monitor Provider by name
     * @param {MonitorProviderApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof MonitorProviderApiGenerated
     */
    public updateByName(requestParameters: MonitorProviderApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return MonitorProviderApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
