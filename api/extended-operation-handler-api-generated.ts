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
import { AddExtendedOperationHandler200Response } from '../models';
// @ts-ignore
import { AddExtendedOperationHandlerRequest } from '../models';
// @ts-ignore
import { EnumextendedOperationHandlerAllowedOperationProp } from '../models';
// @ts-ignore
import { EnumthirdPartyExtendedOperationHandlerSchemaUrn } from '../models';
// @ts-ignore
import { ExtendedOperationHandlerListResponse } from '../models';
// @ts-ignore
import { GetExtendedOperationHandler200Response } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * ExtendedOperationHandlerApi - axios parameter creator
 * @export
 */
export const ExtendedOperationHandlerApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Extended Operation Handler to the config
         * @param {AddExtendedOperationHandlerRequest} addExtendedOperationHandlerRequest Create a new Extended Operation Handler in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewHandler: async (addExtendedOperationHandlerRequest: AddExtendedOperationHandlerRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addExtendedOperationHandlerRequest' is not null or undefined
            assertParamExists('addNewHandler', 'addExtendedOperationHandlerRequest', addExtendedOperationHandlerRequest)
            const localVarPath = `/extended-operation-handlers`;
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
                requestBody: addExtendedOperationHandlerRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/extended-operation-handlers',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addExtendedOperationHandlerRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Extended Operation Handler
         * @param {string} extendedOperationHandlerName Name of the Extended Operation Handler
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteHandler: async (extendedOperationHandlerName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'extendedOperationHandlerName' is not null or undefined
            assertParamExists('deleteHandler', 'extendedOperationHandlerName', extendedOperationHandlerName)
            const localVarPath = `/extended-operation-handlers/{extended-operation-handler-name}`
                .replace(`{${"extended-operation-handler-name"}}`, encodeURIComponent(String(extendedOperationHandlerName !== undefined ? extendedOperationHandlerName : `-extended-operation-handler-name-`)));
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
                pathTemplate: '/extended-operation-handlers/{extended-operation-handler-name}',
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
         * @summary Returns a single Extended Operation Handler
         * @param {string} extendedOperationHandlerName Name of the Extended Operation Handler
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getHandlerById: async (extendedOperationHandlerName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'extendedOperationHandlerName' is not null or undefined
            assertParamExists('getHandlerById', 'extendedOperationHandlerName', extendedOperationHandlerName)
            const localVarPath = `/extended-operation-handlers/{extended-operation-handler-name}`
                .replace(`{${"extended-operation-handler-name"}}`, encodeURIComponent(String(extendedOperationHandlerName !== undefined ? extendedOperationHandlerName : `-extended-operation-handler-name-`)));
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
                pathTemplate: '/extended-operation-handlers/{extended-operation-handler-name}',
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
         * @summary Returns a list of all Extended Operation Handler objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/extended-operation-handlers`;
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
                pathTemplate: '/extended-operation-handlers',
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
         * @summary Update an existing Extended Operation Handler by name
         * @param {string} extendedOperationHandlerName Name of the Extended Operation Handler
         * @param {UpdateRequest} updateRequest Update an existing Extended Operation Handler
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (extendedOperationHandlerName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'extendedOperationHandlerName' is not null or undefined
            assertParamExists('updateByName', 'extendedOperationHandlerName', extendedOperationHandlerName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/extended-operation-handlers/{extended-operation-handler-name}`
                .replace(`{${"extended-operation-handler-name"}}`, encodeURIComponent(String(extendedOperationHandlerName !== undefined ? extendedOperationHandlerName : `-extended-operation-handler-name-`)));
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
                pathTemplate: '/extended-operation-handlers/{extended-operation-handler-name}',
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
 * ExtendedOperationHandlerApi - functional programming interface
 * @export
 */
export const ExtendedOperationHandlerApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = ExtendedOperationHandlerApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Extended Operation Handler to the config
         * @param {ExtendedOperationHandlerApiAddNewHandlerRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewHandler(requestParameters: ExtendedOperationHandlerApiAddNewHandlerRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<AddExtendedOperationHandler200Response>> {
            const addExtendedOperationHandlerRequest: AddExtendedOperationHandlerRequest = requestParameters;
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewHandler(addExtendedOperationHandlerRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Extended Operation Handler
         * @param {ExtendedOperationHandlerApiDeleteHandlerRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteHandler(requestParameters: ExtendedOperationHandlerApiDeleteHandlerRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteHandler(requestParameters.extendedOperationHandlerName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Extended Operation Handler
         * @param {ExtendedOperationHandlerApiGetHandlerByIdRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getHandlerById(requestParameters: ExtendedOperationHandlerApiGetHandlerByIdRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetExtendedOperationHandler200Response>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getHandlerById(requestParameters.extendedOperationHandlerName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Extended Operation Handler objects
         * @param {ExtendedOperationHandlerApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllObjects(requestParameters: ExtendedOperationHandlerApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<ExtendedOperationHandlerListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllObjects(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Extended Operation Handler by name
         * @param {ExtendedOperationHandlerApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: ExtendedOperationHandlerApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<GetExtendedOperationHandler200Response>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.extendedOperationHandlerName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * ExtendedOperationHandlerApi - factory interface
 * @export
 */
export const ExtendedOperationHandlerApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = ExtendedOperationHandlerApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Extended Operation Handler to the config
         * @param {ExtendedOperationHandlerApiAddNewHandlerRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewHandler(requestParameters: ExtendedOperationHandlerApiAddNewHandlerRequest, options?: AxiosRequestConfig): AxiosPromise<AddExtendedOperationHandler200Response> {
            return localVarFp.addNewHandler(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Extended Operation Handler
         * @param {ExtendedOperationHandlerApiDeleteHandlerRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteHandler(requestParameters: ExtendedOperationHandlerApiDeleteHandlerRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteHandler(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Extended Operation Handler
         * @param {ExtendedOperationHandlerApiGetHandlerByIdRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getHandlerById(requestParameters: ExtendedOperationHandlerApiGetHandlerByIdRequest, options?: AxiosRequestConfig): AxiosPromise<GetExtendedOperationHandler200Response> {
            return localVarFp.getHandlerById(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Extended Operation Handler objects
         * @param {ExtendedOperationHandlerApiListAllObjectsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllObjects(requestParameters: ExtendedOperationHandlerApiListAllObjectsRequest = {}, options?: AxiosRequestConfig): AxiosPromise<ExtendedOperationHandlerListResponse> {
            return localVarFp.listAllObjects(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Extended Operation Handler by name
         * @param {ExtendedOperationHandlerApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: ExtendedOperationHandlerApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<GetExtendedOperationHandler200Response> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewHandler operation in ExtendedOperationHandlerApi.
 * @export
 * @interface ExtendedOperationHandlerApiAddNewHandlerRequest
 */
export type ExtendedOperationHandlerApiAddNewHandlerRequest = {
    
} & AddExtendedOperationHandlerRequest

/**
 * Request parameters for deleteHandler operation in ExtendedOperationHandlerApi.
 * @export
 * @interface ExtendedOperationHandlerApiDeleteHandlerRequest
 */
export type ExtendedOperationHandlerApiDeleteHandlerRequest = {
    
    /**
    * Name of the Extended Operation Handler
    * @type {string}
    * @memberof ExtendedOperationHandlerApiDeleteHandler
    */
    readonly extendedOperationHandlerName: string
    
}

/**
 * Request parameters for getHandlerById operation in ExtendedOperationHandlerApi.
 * @export
 * @interface ExtendedOperationHandlerApiGetHandlerByIdRequest
 */
export type ExtendedOperationHandlerApiGetHandlerByIdRequest = {
    
    /**
    * Name of the Extended Operation Handler
    * @type {string}
    * @memberof ExtendedOperationHandlerApiGetHandlerById
    */
    readonly extendedOperationHandlerName: string
    
}

/**
 * Request parameters for listAllObjects operation in ExtendedOperationHandlerApi.
 * @export
 * @interface ExtendedOperationHandlerApiListAllObjectsRequest
 */
export type ExtendedOperationHandlerApiListAllObjectsRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof ExtendedOperationHandlerApiListAllObjects
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in ExtendedOperationHandlerApi.
 * @export
 * @interface ExtendedOperationHandlerApiUpdateByNameRequest
 */
export type ExtendedOperationHandlerApiUpdateByNameRequest = {
    
    /**
    * Name of the Extended Operation Handler
    * @type {string}
    * @memberof ExtendedOperationHandlerApiUpdateByName
    */
    readonly extendedOperationHandlerName: string
    
} & UpdateRequest

/**
 * ExtendedOperationHandlerApiGenerated - object-oriented interface
 * @export
 * @class ExtendedOperationHandlerApiGenerated
 * @extends {BaseAPI}
 */
export class ExtendedOperationHandlerApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Extended Operation Handler to the config
     * @param {ExtendedOperationHandlerApiAddNewHandlerRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ExtendedOperationHandlerApiGenerated
     */
    public addNewHandler(requestParameters: ExtendedOperationHandlerApiAddNewHandlerRequest, options?: AxiosRequestConfig) {
        return ExtendedOperationHandlerApiFp(this.configuration).addNewHandler(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Extended Operation Handler
     * @param {ExtendedOperationHandlerApiDeleteHandlerRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ExtendedOperationHandlerApiGenerated
     */
    public deleteHandler(requestParameters: ExtendedOperationHandlerApiDeleteHandlerRequest, options?: AxiosRequestConfig) {
        return ExtendedOperationHandlerApiFp(this.configuration).deleteHandler(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Extended Operation Handler
     * @param {ExtendedOperationHandlerApiGetHandlerByIdRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ExtendedOperationHandlerApiGenerated
     */
    public getHandlerById(requestParameters: ExtendedOperationHandlerApiGetHandlerByIdRequest, options?: AxiosRequestConfig) {
        return ExtendedOperationHandlerApiFp(this.configuration).getHandlerById(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Extended Operation Handler objects
     * @param {ExtendedOperationHandlerApiListAllObjectsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ExtendedOperationHandlerApiGenerated
     */
    public listAllObjects(requestParameters: ExtendedOperationHandlerApiListAllObjectsRequest = {}, options?: AxiosRequestConfig) {
        return ExtendedOperationHandlerApiFp(this.configuration).listAllObjects(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Extended Operation Handler by name
     * @param {ExtendedOperationHandlerApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof ExtendedOperationHandlerApiGenerated
     */
    public updateByName(requestParameters: ExtendedOperationHandlerApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return ExtendedOperationHandlerApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
