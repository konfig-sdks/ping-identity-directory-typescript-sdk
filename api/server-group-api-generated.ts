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
import { AddServerGroupRequest } from '../models';
// @ts-ignore
import { EnumserverGroupSchemaUrn } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { ServerGroupListResponse } from '../models';
// @ts-ignore
import { ServerGroupResponse } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * ServerGroupApi - axios parameter creator
 * @export
 */
export const ServerGroupApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Server Group to the config
         * @param {AddServerGroupRequest} addServerGroupRequest Create a new Server Group in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewServerGroup: async (addServerGroupRequest: AddServerGroupRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addServerGroupRequest' is not null or undefined
            assertParamExists('addNewServerGroup', 'addServerGroupRequest', addServerGroupRequest)
            const localVarPath = `/server-groups`;
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
                requestBody: addServerGroupRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/server-groups',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addServerGroupRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Server Group
         * @param {string} serverGroupName Name of the Server Group
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteServerGroup: async (serverGroupName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'serverGroupName' is not null or undefined
            assertParamExists('deleteServerGroup', 'serverGroupName', serverGroupName)
            const localVarPath = `/server-groups/{server-group-name}`
                .replace(`{${"server-group-name"}}`, encodeURIComponent(String(serverGroupName !== undefined ? serverGroupName : `-server-group-name-`)));
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
                pathTemplate: '/server-groups/{server-group-name}',
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
         * @summary Returns a single Server Group
         * @param {string} serverGroupName Name of the Server Group
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle: async (serverGroupName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'serverGroupName' is not null or undefined
            assertParamExists('getSingle', 'serverGroupName', serverGroupName)
            const localVarPath = `/server-groups/{server-group-name}`
                .replace(`{${"server-group-name"}}`, encodeURIComponent(String(serverGroupName !== undefined ? serverGroupName : `-server-group-name-`)));
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
                pathTemplate: '/server-groups/{server-group-name}',
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
         * @summary Returns a list of all Server Group objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/server-groups`;
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
                pathTemplate: '/server-groups',
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
         * @summary Update an existing Server Group by name
         * @param {string} serverGroupName Name of the Server Group
         * @param {UpdateRequest} updateRequest Update an existing Server Group
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (serverGroupName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'serverGroupName' is not null or undefined
            assertParamExists('updateByName', 'serverGroupName', serverGroupName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/server-groups/{server-group-name}`
                .replace(`{${"server-group-name"}}`, encodeURIComponent(String(serverGroupName !== undefined ? serverGroupName : `-server-group-name-`)));
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
                pathTemplate: '/server-groups/{server-group-name}',
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
 * ServerGroupApi - functional programming interface
 * @export
 */
export const ServerGroupApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ServerGroupApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Server Group to the config
         * @param {ServerGroupApiAddNewServerGroupRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewServerGroup(requestParameters: ServerGroupApiAddNewServerGroupRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ServerGroupResponse>> {
            const addServerGroupRequest: AddServerGroupRequest = {
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewServerGroup(addServerGroupRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Server Group
         * @param {ServerGroupApiDeleteServerGroupRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteServerGroup(requestParameters: ServerGroupApiDeleteServerGroupRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteServerGroup(requestParameters.serverGroupName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Server Group
         * @param {ServerGroupApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingle(requestParameters: ServerGroupApiGetSingleRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ServerGroupResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingle(requestParameters.serverGroupName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Server Group objects
         * @param {ServerGroupApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllObjects(requestParameters: ServerGroupApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ServerGroupListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Server Group by name
         * @param {ServerGroupApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: ServerGroupApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ServerGroupResponse>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.serverGroupName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ServerGroupApi - factory interface
 * @export
 */
export const ServerGroupApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ServerGroupApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Server Group to the config
         * @param {ServerGroupApiAddNewServerGroupRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewServerGroup(requestParameters: ServerGroupApiAddNewServerGroupRequest, options?: AxiosRequestConfig): AxiosPromise<ServerGroupResponse> {
            return localVarFp.addNewServerGroup(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Server Group
         * @param {ServerGroupApiDeleteServerGroupRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteServerGroup(requestParameters: ServerGroupApiDeleteServerGroupRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteServerGroup(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Server Group
         * @param {ServerGroupApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle(requestParameters: ServerGroupApiGetSingleRequest, options?: AxiosRequestConfig): AxiosPromise<ServerGroupResponse> {
            return localVarFp.getSingle(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Server Group objects
         * @param {ServerGroupApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects(requestParameters: ServerGroupApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<ServerGroupListResponse> {
            return localVarFp.listAllObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Server Group by name
         * @param {ServerGroupApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: ServerGroupApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<ServerGroupResponse> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewServerGroup operation in ServerGroupApi.
 * @export
 * @interface ServerGroupApiAddNewServerGroupRequest
 */
export type ServerGroupApiAddNewServerGroupRequest = {
    
} & AddServerGroupRequest

/**
 * Request parameters for deleteServerGroup operation in ServerGroupApi.
 * @export
 * @interface ServerGroupApiDeleteServerGroupRequest
 */
export type ServerGroupApiDeleteServerGroupRequest = {
    
    /**
    * Name of the Server Group
    * @type {string}
    * @memberof ServerGroupApiDeleteServerGroup
    */
    readonly serverGroupName: string
    
}

/**
 * Request parameters for getSingle operation in ServerGroupApi.
 * @export
 * @interface ServerGroupApiGetSingleRequest
 */
export type ServerGroupApiGetSingleRequest = {
    
    /**
    * Name of the Server Group
    * @type {string}
    * @memberof ServerGroupApiGetSingle
    */
    readonly serverGroupName: string
    
}

/**
 * Request parameters for listAllObjects operation in ServerGroupApi.
 * @export
 * @interface ServerGroupApiListAllObjectsRequest
 */
export type ServerGroupApiListAllObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof ServerGroupApiListAllObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in ServerGroupApi.
 * @export
 * @interface ServerGroupApiUpdateByNameRequest
 */
export type ServerGroupApiUpdateByNameRequest = {
    
    /**
    * Name of the Server Group
    * @type {string}
    * @memberof ServerGroupApiUpdateByName
    */
    readonly serverGroupName: string
    
} & UpdateRequest

/**
 * ServerGroupApiGenerated - object-oriented interface
 * @export
 * @class ServerGroupApiGenerated
 * @extends {BaseAPI}
 */
export class ServerGroupApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Server Group to the config
     * @param {ServerGroupApiAddNewServerGroupRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ServerGroupApiGenerated
     */
    public addNewServerGroup(requestParameters: ServerGroupApiAddNewServerGroupRequest, options?: AxiosRequestConfig) {
        return ServerGroupApiFp(this.configuration).addNewServerGroup(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Server Group
     * @param {ServerGroupApiDeleteServerGroupRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ServerGroupApiGenerated
     */
    public deleteServerGroup(requestParameters: ServerGroupApiDeleteServerGroupRequest, options?: AxiosRequestConfig) {
        return ServerGroupApiFp(this.configuration).deleteServerGroup(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Server Group
     * @param {ServerGroupApiGetSingleRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ServerGroupApiGenerated
     */
    public getSingle(requestParameters: ServerGroupApiGetSingleRequest, options?: AxiosRequestConfig) {
        return ServerGroupApiFp(this.configuration).getSingle(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Server Group objects
     * @param {ServerGroupApiListAllObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ServerGroupApiGenerated
     */
    public listAllObjects(requestParameters: ServerGroupApiListAllObjectsRequest = {}, options?: AxiosRequestConfig) {
        return ServerGroupApiFp(this.configuration).listAllObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Server Group by name
     * @param {ServerGroupApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ServerGroupApiGenerated
     */
    public updateByName(requestParameters: ServerGroupApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return ServerGroupApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
