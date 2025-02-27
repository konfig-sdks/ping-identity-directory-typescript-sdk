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
import { AddJsonFieldConstraintsRequest } from '../models';
// @ts-ignore
import { EnumjsonFieldConstraintsCacheModeProp } from '../models';
// @ts-ignore
import { EnumjsonFieldConstraintsIsArrayProp } from '../models';
// @ts-ignore
import { EnumjsonFieldConstraintsSchemaUrn } from '../models';
// @ts-ignore
import { EnumjsonFieldConstraintsValueTypeProp } from '../models';
// @ts-ignore
import { JsonFieldConstraintsListResponse } from '../models';
// @ts-ignore
import { JsonFieldConstraintsResponse } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * JsonFieldConstraintsApi - axios parameter creator
 * @export
 */
export const JsonFieldConstraintsApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new JSON Field Constraints to the config
         * @param {string} jsonAttributeConstraintsName Name of the JSON Attribute Constraints
         * @param {AddJsonFieldConstraintsRequest} addJsonFieldConstraintsRequest Create a new JSON Field Constraints in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewField: async (jsonAttributeConstraintsName: string, addJsonFieldConstraintsRequest: AddJsonFieldConstraintsRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'jsonAttributeConstraintsName' is not null or undefined
            assertParamExists('addNewField', 'jsonAttributeConstraintsName', jsonAttributeConstraintsName)
            // verify required parameter 'addJsonFieldConstraintsRequest' is not null or undefined
            assertParamExists('addNewField', 'addJsonFieldConstraintsRequest', addJsonFieldConstraintsRequest)
            const localVarPath = `/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints`
                .replace(`{${"json-attribute-constraints-name"}}`, encodeURIComponent(String(jsonAttributeConstraintsName !== undefined ? jsonAttributeConstraintsName : `-json-attribute-constraints-name-`)));
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
                requestBody: addJsonFieldConstraintsRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addJsonFieldConstraintsRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a JSON Field Constraints
         * @param {string} jsonFieldConstraintsName Name of the JSON Field Constraints
         * @param {string} jsonAttributeConstraintsName Name of the JSON Attribute Constraints
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteFieldConstraints: async (jsonFieldConstraintsName: string, jsonAttributeConstraintsName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'jsonFieldConstraintsName' is not null or undefined
            assertParamExists('deleteFieldConstraints', 'jsonFieldConstraintsName', jsonFieldConstraintsName)
            // verify required parameter 'jsonAttributeConstraintsName' is not null or undefined
            assertParamExists('deleteFieldConstraints', 'jsonAttributeConstraintsName', jsonAttributeConstraintsName)
            const localVarPath = `/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}`
                .replace(`{${"json-field-constraints-name"}}`, encodeURIComponent(String(jsonFieldConstraintsName !== undefined ? jsonFieldConstraintsName : `-json-field-constraints-name-`)))
                .replace(`{${"json-attribute-constraints-name"}}`, encodeURIComponent(String(jsonAttributeConstraintsName !== undefined ? jsonAttributeConstraintsName : `-json-attribute-constraints-name-`)));
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
                pathTemplate: '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}',
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
         * @summary Returns a single JSON Field Constraints
         * @param {string} jsonFieldConstraintsName Name of the JSON Field Constraints
         * @param {string} jsonAttributeConstraintsName Name of the JSON Attribute Constraints
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleFieldConstraints: async (jsonFieldConstraintsName: string, jsonAttributeConstraintsName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'jsonFieldConstraintsName' is not null or undefined
            assertParamExists('getSingleFieldConstraints', 'jsonFieldConstraintsName', jsonFieldConstraintsName)
            // verify required parameter 'jsonAttributeConstraintsName' is not null or undefined
            assertParamExists('getSingleFieldConstraints', 'jsonAttributeConstraintsName', jsonAttributeConstraintsName)
            const localVarPath = `/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}`
                .replace(`{${"json-field-constraints-name"}}`, encodeURIComponent(String(jsonFieldConstraintsName !== undefined ? jsonFieldConstraintsName : `-json-field-constraints-name-`)))
                .replace(`{${"json-attribute-constraints-name"}}`, encodeURIComponent(String(jsonAttributeConstraintsName !== undefined ? jsonAttributeConstraintsName : `-json-attribute-constraints-name-`)));
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
                pathTemplate: '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}',
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
         * @summary Returns a list of all JSON Field Constraints objects
         * @param {string} jsonAttributeConstraintsName Name of the JSON Attribute Constraints
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllJsonFieldConstraints: async (jsonAttributeConstraintsName: string, filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'jsonAttributeConstraintsName' is not null or undefined
            assertParamExists('listAllJsonFieldConstraints', 'jsonAttributeConstraintsName', jsonAttributeConstraintsName)
            const localVarPath = `/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints`
                .replace(`{${"json-attribute-constraints-name"}}`, encodeURIComponent(String(jsonAttributeConstraintsName !== undefined ? jsonAttributeConstraintsName : `-json-attribute-constraints-name-`)));
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
                pathTemplate: '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints',
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
         * @summary Update an existing JSON Field Constraints by name
         * @param {string} jsonFieldConstraintsName Name of the JSON Field Constraints
         * @param {string} jsonAttributeConstraintsName Name of the JSON Attribute Constraints
         * @param {UpdateRequest} updateRequest Update an existing JSON Field Constraints
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (jsonFieldConstraintsName: string, jsonAttributeConstraintsName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'jsonFieldConstraintsName' is not null or undefined
            assertParamExists('updateByName', 'jsonFieldConstraintsName', jsonFieldConstraintsName)
            // verify required parameter 'jsonAttributeConstraintsName' is not null or undefined
            assertParamExists('updateByName', 'jsonAttributeConstraintsName', jsonAttributeConstraintsName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}`
                .replace(`{${"json-field-constraints-name"}}`, encodeURIComponent(String(jsonFieldConstraintsName !== undefined ? jsonFieldConstraintsName : `-json-field-constraints-name-`)))
                .replace(`{${"json-attribute-constraints-name"}}`, encodeURIComponent(String(jsonAttributeConstraintsName !== undefined ? jsonAttributeConstraintsName : `-json-attribute-constraints-name-`)));
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
                pathTemplate: '/json-attribute-constraints/{json-attribute-constraints-name}/json-field-constraints/{json-field-constraints-name}',
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
 * JsonFieldConstraintsApi - functional programming interface
 * @export
 */
export const JsonFieldConstraintsApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = JsonFieldConstraintsApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new JSON Field Constraints to the config
         * @param {JsonFieldConstraintsApiAddNewFieldRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewField(requestParameters: JsonFieldConstraintsApiAddNewFieldRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<JsonFieldConstraintsResponse>> {
            const addJsonFieldConstraintsRequest: AddJsonFieldConstraintsRequest = {
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewField(requestParameters.jsonAttributeConstraintsName, addJsonFieldConstraintsRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a JSON Field Constraints
         * @param {JsonFieldConstraintsApiDeleteFieldConstraintsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteFieldConstraints(requestParameters: JsonFieldConstraintsApiDeleteFieldConstraintsRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteFieldConstraints(requestParameters.jsonFieldConstraintsName, requestParameters.jsonAttributeConstraintsName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single JSON Field Constraints
         * @param {JsonFieldConstraintsApiGetSingleFieldConstraintsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingleFieldConstraints(requestParameters: JsonFieldConstraintsApiGetSingleFieldConstraintsRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<JsonFieldConstraintsResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingleFieldConstraints(requestParameters.jsonFieldConstraintsName, requestParameters.jsonAttributeConstraintsName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all JSON Field Constraints objects
         * @param {JsonFieldConstraintsApiListAllJsonFieldConstraintsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllJsonFieldConstraints(requestParameters: JsonFieldConstraintsApiListAllJsonFieldConstraintsRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<JsonFieldConstraintsListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllJsonFieldConstraints(requestParameters.jsonAttributeConstraintsName, requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing JSON Field Constraints by name
         * @param {JsonFieldConstraintsApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: JsonFieldConstraintsApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<JsonFieldConstraintsResponse>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.jsonFieldConstraintsName, requestParameters.jsonAttributeConstraintsName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * JsonFieldConstraintsApi - factory interface
 * @export
 */
export const JsonFieldConstraintsApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = JsonFieldConstraintsApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new JSON Field Constraints to the config
         * @param {JsonFieldConstraintsApiAddNewFieldRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewField(requestParameters: JsonFieldConstraintsApiAddNewFieldRequest, options?: AxiosRequestConfig): AxiosPromise<JsonFieldConstraintsResponse> {
            return localVarFp.addNewField(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a JSON Field Constraints
         * @param {JsonFieldConstraintsApiDeleteFieldConstraintsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteFieldConstraints(requestParameters: JsonFieldConstraintsApiDeleteFieldConstraintsRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteFieldConstraints(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single JSON Field Constraints
         * @param {JsonFieldConstraintsApiGetSingleFieldConstraintsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingleFieldConstraints(requestParameters: JsonFieldConstraintsApiGetSingleFieldConstraintsRequest, options?: AxiosRequestConfig): AxiosPromise<JsonFieldConstraintsResponse> {
            return localVarFp.getSingleFieldConstraints(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all JSON Field Constraints objects
         * @param {JsonFieldConstraintsApiListAllJsonFieldConstraintsRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllJsonFieldConstraints(requestParameters: JsonFieldConstraintsApiListAllJsonFieldConstraintsRequest, options?: AxiosRequestConfig): AxiosPromise<JsonFieldConstraintsListResponse> {
            return localVarFp.listAllJsonFieldConstraints(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing JSON Field Constraints by name
         * @param {JsonFieldConstraintsApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: JsonFieldConstraintsApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<JsonFieldConstraintsResponse> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewField operation in JsonFieldConstraintsApi.
 * @export
 * @interface JsonFieldConstraintsApiAddNewFieldRequest
 */
export type JsonFieldConstraintsApiAddNewFieldRequest = {
    
    /**
    * Name of the JSON Attribute Constraints
    * @type {string}
    * @memberof JsonFieldConstraintsApiAddNewField
    */
    readonly jsonAttributeConstraintsName: string
    
} & AddJsonFieldConstraintsRequest

/**
 * Request parameters for deleteFieldConstraints operation in JsonFieldConstraintsApi.
 * @export
 * @interface JsonFieldConstraintsApiDeleteFieldConstraintsRequest
 */
export type JsonFieldConstraintsApiDeleteFieldConstraintsRequest = {
    
    /**
    * Name of the JSON Field Constraints
    * @type {string}
    * @memberof JsonFieldConstraintsApiDeleteFieldConstraints
    */
    readonly jsonFieldConstraintsName: string
    
    /**
    * Name of the JSON Attribute Constraints
    * @type {string}
    * @memberof JsonFieldConstraintsApiDeleteFieldConstraints
    */
    readonly jsonAttributeConstraintsName: string
    
}

/**
 * Request parameters for getSingleFieldConstraints operation in JsonFieldConstraintsApi.
 * @export
 * @interface JsonFieldConstraintsApiGetSingleFieldConstraintsRequest
 */
export type JsonFieldConstraintsApiGetSingleFieldConstraintsRequest = {
    
    /**
    * Name of the JSON Field Constraints
    * @type {string}
    * @memberof JsonFieldConstraintsApiGetSingleFieldConstraints
    */
    readonly jsonFieldConstraintsName: string
    
    /**
    * Name of the JSON Attribute Constraints
    * @type {string}
    * @memberof JsonFieldConstraintsApiGetSingleFieldConstraints
    */
    readonly jsonAttributeConstraintsName: string
    
}

/**
 * Request parameters for listAllJsonFieldConstraints operation in JsonFieldConstraintsApi.
 * @export
 * @interface JsonFieldConstraintsApiListAllJsonFieldConstraintsRequest
 */
export type JsonFieldConstraintsApiListAllJsonFieldConstraintsRequest = {
    
    /**
    * Name of the JSON Attribute Constraints
    * @type {string}
    * @memberof JsonFieldConstraintsApiListAllJsonFieldConstraints
    */
    readonly jsonAttributeConstraintsName: string
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof JsonFieldConstraintsApiListAllJsonFieldConstraints
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in JsonFieldConstraintsApi.
 * @export
 * @interface JsonFieldConstraintsApiUpdateByNameRequest
 */
export type JsonFieldConstraintsApiUpdateByNameRequest = {
    
    /**
    * Name of the JSON Field Constraints
    * @type {string}
    * @memberof JsonFieldConstraintsApiUpdateByName
    */
    readonly jsonFieldConstraintsName: string
    
    /**
    * Name of the JSON Attribute Constraints
    * @type {string}
    * @memberof JsonFieldConstraintsApiUpdateByName
    */
    readonly jsonAttributeConstraintsName: string
    
} & UpdateRequest

/**
 * JsonFieldConstraintsApiGenerated - object-oriented interface
 * @export
 * @class JsonFieldConstraintsApiGenerated
 * @extends {BaseAPI}
 */
export class JsonFieldConstraintsApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new JSON Field Constraints to the config
     * @param {JsonFieldConstraintsApiAddNewFieldRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof JsonFieldConstraintsApiGenerated
     */
    public addNewField(requestParameters: JsonFieldConstraintsApiAddNewFieldRequest, options?: AxiosRequestConfig) {
        return JsonFieldConstraintsApiFp(this.configuration).addNewField(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a JSON Field Constraints
     * @param {JsonFieldConstraintsApiDeleteFieldConstraintsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof JsonFieldConstraintsApiGenerated
     */
    public deleteFieldConstraints(requestParameters: JsonFieldConstraintsApiDeleteFieldConstraintsRequest, options?: AxiosRequestConfig) {
        return JsonFieldConstraintsApiFp(this.configuration).deleteFieldConstraints(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single JSON Field Constraints
     * @param {JsonFieldConstraintsApiGetSingleFieldConstraintsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof JsonFieldConstraintsApiGenerated
     */
    public getSingleFieldConstraints(requestParameters: JsonFieldConstraintsApiGetSingleFieldConstraintsRequest, options?: AxiosRequestConfig) {
        return JsonFieldConstraintsApiFp(this.configuration).getSingleFieldConstraints(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all JSON Field Constraints objects
     * @param {JsonFieldConstraintsApiListAllJsonFieldConstraintsRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof JsonFieldConstraintsApiGenerated
     */
    public listAllJsonFieldConstraints(requestParameters: JsonFieldConstraintsApiListAllJsonFieldConstraintsRequest, options?: AxiosRequestConfig) {
        return JsonFieldConstraintsApiFp(this.configuration).listAllJsonFieldConstraints(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing JSON Field Constraints by name
     * @param {JsonFieldConstraintsApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof JsonFieldConstraintsApiGenerated
     */
    public updateByName(requestParameters: JsonFieldConstraintsApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return JsonFieldConstraintsApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
