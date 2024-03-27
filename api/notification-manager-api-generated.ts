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
import { AddThirdPartyNotificationManagerRequest } from '../models';
// @ts-ignore
import { EnumnotificationManagerTransactionNotificationProp } from '../models';
// @ts-ignore
import { EnumthirdPartyNotificationManagerSchemaUrn } from '../models';
// @ts-ignore
import { NotificationManagerListResponse } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { ThirdPartyNotificationManagerResponse } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * NotificationManagerApi - axios parameter creator
 * @export
 */
export const NotificationManagerApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Notification Manager to the config
         * @param {AddThirdPartyNotificationManagerRequest} addThirdPartyNotificationManagerRequest Create a new Notification Manager in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig: async (addThirdPartyNotificationManagerRequest: AddThirdPartyNotificationManagerRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addThirdPartyNotificationManagerRequest' is not null or undefined
            assertParamExists('addNewConfig', 'addThirdPartyNotificationManagerRequest', addThirdPartyNotificationManagerRequest)
            const localVarPath = `/notification-managers`;
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
                requestBody: addThirdPartyNotificationManagerRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/notification-managers',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addThirdPartyNotificationManagerRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Notification Manager
         * @param {string} notificationManagerName Name of the Notification Manager
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteNotificationManager: async (notificationManagerName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'notificationManagerName' is not null or undefined
            assertParamExists('deleteNotificationManager', 'notificationManagerName', notificationManagerName)
            const localVarPath = `/notification-managers/{notification-manager-name}`
                .replace(`{${"notification-manager-name"}}`, encodeURIComponent(String(notificationManagerName !== undefined ? notificationManagerName : `-notification-manager-name-`)));
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
                pathTemplate: '/notification-managers/{notification-manager-name}',
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
         * @summary Returns a single Notification Manager
         * @param {string} notificationManagerName Name of the Notification Manager
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle: async (notificationManagerName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'notificationManagerName' is not null or undefined
            assertParamExists('getSingle', 'notificationManagerName', notificationManagerName)
            const localVarPath = `/notification-managers/{notification-manager-name}`
                .replace(`{${"notification-manager-name"}}`, encodeURIComponent(String(notificationManagerName !== undefined ? notificationManagerName : `-notification-manager-name-`)));
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
                pathTemplate: '/notification-managers/{notification-manager-name}',
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
         * @summary Returns a list of all Notification Manager objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/notification-managers`;
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
                pathTemplate: '/notification-managers',
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
         * @summary Update an existing Notification Manager by name
         * @param {string} notificationManagerName Name of the Notification Manager
         * @param {UpdateRequest} updateRequest Update an existing Notification Manager
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (notificationManagerName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'notificationManagerName' is not null or undefined
            assertParamExists('updateByName', 'notificationManagerName', notificationManagerName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/notification-managers/{notification-manager-name}`
                .replace(`{${"notification-manager-name"}}`, encodeURIComponent(String(notificationManagerName !== undefined ? notificationManagerName : `-notification-manager-name-`)));
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
                pathTemplate: '/notification-managers/{notification-manager-name}',
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
 * NotificationManagerApi - functional programming interface
 * @export
 */
export const NotificationManagerApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = NotificationManagerApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Notification Manager to the config
         * @param {NotificationManagerApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewConfig(requestParameters: NotificationManagerApiAddNewConfigRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ThirdPartyNotificationManagerResponse>> {
            const addThirdPartyNotificationManagerRequest: AddThirdPartyNotificationManagerRequest = {
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewConfig(addThirdPartyNotificationManagerRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Notification Manager
         * @param {NotificationManagerApiDeleteNotificationManagerRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteNotificationManager(requestParameters: NotificationManagerApiDeleteNotificationManagerRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteNotificationManager(requestParameters.notificationManagerName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Notification Manager
         * @param {NotificationManagerApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingle(requestParameters: NotificationManagerApiGetSingleRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ThirdPartyNotificationManagerResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingle(requestParameters.notificationManagerName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Notification Manager objects
         * @param {NotificationManagerApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllObjects(requestParameters: NotificationManagerApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<NotificationManagerListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Notification Manager by name
         * @param {NotificationManagerApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: NotificationManagerApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ThirdPartyNotificationManagerResponse>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.notificationManagerName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * NotificationManagerApi - factory interface
 * @export
 */
export const NotificationManagerApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = NotificationManagerApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Notification Manager to the config
         * @param {NotificationManagerApiAddNewConfigRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewConfig(requestParameters: NotificationManagerApiAddNewConfigRequest, options?: AxiosRequestConfig): AxiosPromise<ThirdPartyNotificationManagerResponse> {
            return localVarFp.addNewConfig(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Notification Manager
         * @param {NotificationManagerApiDeleteNotificationManagerRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteNotificationManager(requestParameters: NotificationManagerApiDeleteNotificationManagerRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteNotificationManager(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Notification Manager
         * @param {NotificationManagerApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle(requestParameters: NotificationManagerApiGetSingleRequest, options?: AxiosRequestConfig): AxiosPromise<ThirdPartyNotificationManagerResponse> {
            return localVarFp.getSingle(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Notification Manager objects
         * @param {NotificationManagerApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects(requestParameters: NotificationManagerApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<NotificationManagerListResponse> {
            return localVarFp.listAllObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Notification Manager by name
         * @param {NotificationManagerApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: NotificationManagerApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<ThirdPartyNotificationManagerResponse> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewConfig operation in NotificationManagerApi.
 * @export
 * @interface NotificationManagerApiAddNewConfigRequest
 */
export type NotificationManagerApiAddNewConfigRequest = {
    
} & AddThirdPartyNotificationManagerRequest

/**
 * Request parameters for deleteNotificationManager operation in NotificationManagerApi.
 * @export
 * @interface NotificationManagerApiDeleteNotificationManagerRequest
 */
export type NotificationManagerApiDeleteNotificationManagerRequest = {
    
    /**
    * Name of the Notification Manager
    * @type {string}
    * @memberof NotificationManagerApiDeleteNotificationManager
    */
    readonly notificationManagerName: string
    
}

/**
 * Request parameters for getSingle operation in NotificationManagerApi.
 * @export
 * @interface NotificationManagerApiGetSingleRequest
 */
export type NotificationManagerApiGetSingleRequest = {
    
    /**
    * Name of the Notification Manager
    * @type {string}
    * @memberof NotificationManagerApiGetSingle
    */
    readonly notificationManagerName: string
    
}

/**
 * Request parameters for listAllObjects operation in NotificationManagerApi.
 * @export
 * @interface NotificationManagerApiListAllObjectsRequest
 */
export type NotificationManagerApiListAllObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof NotificationManagerApiListAllObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in NotificationManagerApi.
 * @export
 * @interface NotificationManagerApiUpdateByNameRequest
 */
export type NotificationManagerApiUpdateByNameRequest = {
    
    /**
    * Name of the Notification Manager
    * @type {string}
    * @memberof NotificationManagerApiUpdateByName
    */
    readonly notificationManagerName: string
    
} & UpdateRequest

/**
 * NotificationManagerApiGenerated - object-oriented interface
 * @export
 * @class NotificationManagerApiGenerated
 * @extends {BaseAPI}
 */
export class NotificationManagerApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Notification Manager to the config
     * @param {NotificationManagerApiAddNewConfigRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof NotificationManagerApiGenerated
     */
    public addNewConfig(requestParameters: NotificationManagerApiAddNewConfigRequest, options?: AxiosRequestConfig) {
        return NotificationManagerApiFp(this.configuration).addNewConfig(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Notification Manager
     * @param {NotificationManagerApiDeleteNotificationManagerRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof NotificationManagerApiGenerated
     */
    public deleteNotificationManager(requestParameters: NotificationManagerApiDeleteNotificationManagerRequest, options?: AxiosRequestConfig) {
        return NotificationManagerApiFp(this.configuration).deleteNotificationManager(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Notification Manager
     * @param {NotificationManagerApiGetSingleRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof NotificationManagerApiGenerated
     */
    public getSingle(requestParameters: NotificationManagerApiGetSingleRequest, options?: AxiosRequestConfig) {
        return NotificationManagerApiFp(this.configuration).getSingle(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Notification Manager objects
     * @param {NotificationManagerApiListAllObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof NotificationManagerApiGenerated
     */
    public listAllObjects(requestParameters: NotificationManagerApiListAllObjectsRequest = {}, options?: AxiosRequestConfig) {
        return NotificationManagerApiFp(this.configuration).listAllObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Notification Manager by name
     * @param {NotificationManagerApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof NotificationManagerApiGenerated
     */
    public updateByName(requestParameters: NotificationManagerApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return NotificationManagerApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
