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
import { AddDelegatedAdminAttributeCategoryRequest } from '../models';
// @ts-ignore
import { DelegatedAdminAttributeCategoryListResponse } from '../models';
// @ts-ignore
import { DelegatedAdminAttributeCategoryResponse } from '../models';
// @ts-ignore
import { EnumdelegatedAdminAttributeCategorySchemaUrn } from '../models';
// @ts-ignore
import { Operation } from '../models';
// @ts-ignore
import { UpdateRequest } from '../models';
import { paginate } from "../pagination/paginate";
import type * as buffer from "buffer"
import { requestBeforeHook } from '../requestBeforeHook';
/**
 * DelegatedAdminAttributeCategoryApi - axios parameter creator
 * @export
 */
export const DelegatedAdminAttributeCategoryApiAxiosParamCreator = function (configuration?: Configuration) {
    return {
        /**
         * 
         * @summary Add a new Delegated Admin Attribute Category to the config
         * @param {AddDelegatedAdminAttributeCategoryRequest} addDelegatedAdminAttributeCategoryRequest Create a new Delegated Admin Attribute Category in the config
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewCategory: async (addDelegatedAdminAttributeCategoryRequest: AddDelegatedAdminAttributeCategoryRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'addDelegatedAdminAttributeCategoryRequest' is not null or undefined
            assertParamExists('addNewCategory', 'addDelegatedAdminAttributeCategoryRequest', addDelegatedAdminAttributeCategoryRequest)
            const localVarPath = `/delegated-admin-attribute-categories`;
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
                requestBody: addDelegatedAdminAttributeCategoryRequest,
                queryParameters: localVarQueryParameter,
                requestConfig: localVarRequestOptions,
                path: localVarPath,
                configuration,
                pathTemplate: '/delegated-admin-attribute-categories',
                httpMethod: 'POST'
            });
            localVarRequestOptions.data = serializeDataIfNeeded(addDelegatedAdminAttributeCategoryRequest, localVarRequestOptions, configuration)

            setSearchParams(localVarUrlObj, localVarQueryParameter);
            return {
                url: toPathString(localVarUrlObj),
                options: localVarRequestOptions,
            };
        },
        /**
         * 
         * @summary Delete a Delegated Admin Attribute Category
         * @param {string} delegatedAdminAttributeCategoryName Name of the Delegated Admin Attribute Category
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteCategory: async (delegatedAdminAttributeCategoryName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'delegatedAdminAttributeCategoryName' is not null or undefined
            assertParamExists('deleteCategory', 'delegatedAdminAttributeCategoryName', delegatedAdminAttributeCategoryName)
            const localVarPath = `/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}`
                .replace(`{${"delegated-admin-attribute-category-name"}}`, encodeURIComponent(String(delegatedAdminAttributeCategoryName !== undefined ? delegatedAdminAttributeCategoryName : `-delegated-admin-attribute-category-name-`)));
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
                pathTemplate: '/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}',
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
         * @summary Returns a single Delegated Admin Attribute Category
         * @param {string} delegatedAdminAttributeCategoryName Name of the Delegated Admin Attribute Category
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle: async (delegatedAdminAttributeCategoryName: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'delegatedAdminAttributeCategoryName' is not null or undefined
            assertParamExists('getSingle', 'delegatedAdminAttributeCategoryName', delegatedAdminAttributeCategoryName)
            const localVarPath = `/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}`
                .replace(`{${"delegated-admin-attribute-category-name"}}`, encodeURIComponent(String(delegatedAdminAttributeCategoryName !== undefined ? delegatedAdminAttributeCategoryName : `-delegated-admin-attribute-category-name-`)));
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
                pathTemplate: '/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}',
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
         * @summary Returns a list of all Delegated Admin Attribute Category objects
         * @param {string} [filter] SCIM filter
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllCategories: async (filter?: string, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            const localVarPath = `/delegated-admin-attribute-categories`;
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
                pathTemplate: '/delegated-admin-attribute-categories',
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
         * @summary Update an existing Delegated Admin Attribute Category by name
         * @param {string} delegatedAdminAttributeCategoryName Name of the Delegated Admin Attribute Category
         * @param {UpdateRequest} updateRequest Update an existing Delegated Admin Attribute Category
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName: async (delegatedAdminAttributeCategoryName: string, updateRequest: UpdateRequest, options: AxiosRequestConfig = {}): Promise<RequestArgs> => {
            // verify required parameter 'delegatedAdminAttributeCategoryName' is not null or undefined
            assertParamExists('updateByName', 'delegatedAdminAttributeCategoryName', delegatedAdminAttributeCategoryName)
            // verify required parameter 'updateRequest' is not null or undefined
            assertParamExists('updateByName', 'updateRequest', updateRequest)
            const localVarPath = `/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}`
                .replace(`{${"delegated-admin-attribute-category-name"}}`, encodeURIComponent(String(delegatedAdminAttributeCategoryName !== undefined ? delegatedAdminAttributeCategoryName : `-delegated-admin-attribute-category-name-`)));
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
                pathTemplate: '/delegated-admin-attribute-categories/{delegated-admin-attribute-category-name}',
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
 * DelegatedAdminAttributeCategoryApi - functional programming interface
 * @export
 */
export const DelegatedAdminAttributeCategoryApiFp = function(configuration?: Configuration) {
    const localVarAxiosParamCreator = DelegatedAdminAttributeCategoryApiAxiosParamCreator(configuration)
    return {
        /**
         * 
         * @summary Add a new Delegated Admin Attribute Category to the config
         * @param {DelegatedAdminAttributeCategoryApiAddNewCategoryRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async addNewCategory(requestParameters: DelegatedAdminAttributeCategoryApiAddNewCategoryRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DelegatedAdminAttributeCategoryResponse>> {
            const addDelegatedAdminAttributeCategoryRequest: AddDelegatedAdminAttributeCategoryRequest = {
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.addNewCategory(addDelegatedAdminAttributeCategoryRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Delete a Delegated Admin Attribute Category
         * @param {DelegatedAdminAttributeCategoryApiDeleteCategoryRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async deleteCategory(requestParameters: DelegatedAdminAttributeCategoryApiDeleteCategoryRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<void>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.deleteCategory(requestParameters.delegatedAdminAttributeCategoryName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a single Delegated Admin Attribute Category
         * @param {DelegatedAdminAttributeCategoryApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async getSingle(requestParameters: DelegatedAdminAttributeCategoryApiGetSingleRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DelegatedAdminAttributeCategoryResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.getSingle(requestParameters.delegatedAdminAttributeCategoryName, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Returns a list of all Delegated Admin Attribute Category objects
         * @param {DelegatedAdminAttributeCategoryApiListAllCategoriesRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async listAllCategories(requestParameters: DelegatedAdminAttributeCategoryApiListAllCategoriesRequest = {}, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DelegatedAdminAttributeCategoryListResponse>> {
            const localVarAxiosArgs = await localVarAxiosParamCreator.listAllCategories(requestParameters.filter, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
        /**
         * 
         * @summary Update an existing Delegated Admin Attribute Category by name
         * @param {DelegatedAdminAttributeCategoryApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        async updateByName(requestParameters: DelegatedAdminAttributeCategoryApiUpdateByNameRequest, options?: AxiosRequestConfig): Promise<(axios?: AxiosInstance, basePath?: string) => AxiosPromise<DelegatedAdminAttributeCategoryResponse>> {
            const updateRequest: UpdateRequest = {
                operations: requestParameters.operations
            };
            const localVarAxiosArgs = await localVarAxiosParamCreator.updateByName(requestParameters.delegatedAdminAttributeCategoryName, updateRequest, options);
            return createRequestFunction(localVarAxiosArgs, globalAxios, BASE_PATH, configuration);
        },
    }
};

/**
 * DelegatedAdminAttributeCategoryApi - factory interface
 * @export
 */
export const DelegatedAdminAttributeCategoryApiFactory = function (configuration?: Configuration, basePath?: string, axios?: AxiosInstance) {
    const localVarFp = DelegatedAdminAttributeCategoryApiFp(configuration)
    return {
        /**
         * 
         * @summary Add a new Delegated Admin Attribute Category to the config
         * @param {DelegatedAdminAttributeCategoryApiAddNewCategoryRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        addNewCategory(requestParameters: DelegatedAdminAttributeCategoryApiAddNewCategoryRequest, options?: AxiosRequestConfig): AxiosPromise<DelegatedAdminAttributeCategoryResponse> {
            return localVarFp.addNewCategory(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Delete a Delegated Admin Attribute Category
         * @param {DelegatedAdminAttributeCategoryApiDeleteCategoryRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        deleteCategory(requestParameters: DelegatedAdminAttributeCategoryApiDeleteCategoryRequest, options?: AxiosRequestConfig): AxiosPromise<void> {
            return localVarFp.deleteCategory(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a single Delegated Admin Attribute Category
         * @param {DelegatedAdminAttributeCategoryApiGetSingleRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        getSingle(requestParameters: DelegatedAdminAttributeCategoryApiGetSingleRequest, options?: AxiosRequestConfig): AxiosPromise<DelegatedAdminAttributeCategoryResponse> {
            return localVarFp.getSingle(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Returns a list of all Delegated Admin Attribute Category objects
         * @param {DelegatedAdminAttributeCategoryApiListAllCategoriesRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        listAllCategories(requestParameters: DelegatedAdminAttributeCategoryApiListAllCategoriesRequest = {}, options?: AxiosRequestConfig): AxiosPromise<DelegatedAdminAttributeCategoryListResponse> {
            return localVarFp.listAllCategories(requestParameters, options).then((request) => request(axios, basePath));
        },
        /**
         * 
         * @summary Update an existing Delegated Admin Attribute Category by name
         * @param {DelegatedAdminAttributeCategoryApiUpdateByNameRequest} requestParameters Request parameters.
         * @param {*} [options] Override http request option.
         * @throws {RequiredError}
         */
        updateByName(requestParameters: DelegatedAdminAttributeCategoryApiUpdateByNameRequest, options?: AxiosRequestConfig): AxiosPromise<DelegatedAdminAttributeCategoryResponse> {
            return localVarFp.updateByName(requestParameters, options).then((request) => request(axios, basePath));
        },
    };
};

/**
 * Request parameters for addNewCategory operation in DelegatedAdminAttributeCategoryApi.
 * @export
 * @interface DelegatedAdminAttributeCategoryApiAddNewCategoryRequest
 */
export type DelegatedAdminAttributeCategoryApiAddNewCategoryRequest = {
    
} & AddDelegatedAdminAttributeCategoryRequest

/**
 * Request parameters for deleteCategory operation in DelegatedAdminAttributeCategoryApi.
 * @export
 * @interface DelegatedAdminAttributeCategoryApiDeleteCategoryRequest
 */
export type DelegatedAdminAttributeCategoryApiDeleteCategoryRequest = {
    
    /**
    * Name of the Delegated Admin Attribute Category
    * @type {string}
    * @memberof DelegatedAdminAttributeCategoryApiDeleteCategory
    */
    readonly delegatedAdminAttributeCategoryName: string
    
}

/**
 * Request parameters for getSingle operation in DelegatedAdminAttributeCategoryApi.
 * @export
 * @interface DelegatedAdminAttributeCategoryApiGetSingleRequest
 */
export type DelegatedAdminAttributeCategoryApiGetSingleRequest = {
    
    /**
    * Name of the Delegated Admin Attribute Category
    * @type {string}
    * @memberof DelegatedAdminAttributeCategoryApiGetSingle
    */
    readonly delegatedAdminAttributeCategoryName: string
    
}

/**
 * Request parameters for listAllCategories operation in DelegatedAdminAttributeCategoryApi.
 * @export
 * @interface DelegatedAdminAttributeCategoryApiListAllCategoriesRequest
 */
export type DelegatedAdminAttributeCategoryApiListAllCategoriesRequest = {
    
    /**
    * SCIM filter
    * @type {string}
    * @memberof DelegatedAdminAttributeCategoryApiListAllCategories
    */
    readonly filter?: string
    
}

/**
 * Request parameters for updateByName operation in DelegatedAdminAttributeCategoryApi.
 * @export
 * @interface DelegatedAdminAttributeCategoryApiUpdateByNameRequest
 */
export type DelegatedAdminAttributeCategoryApiUpdateByNameRequest = {
    
    /**
    * Name of the Delegated Admin Attribute Category
    * @type {string}
    * @memberof DelegatedAdminAttributeCategoryApiUpdateByName
    */
    readonly delegatedAdminAttributeCategoryName: string
    
} & UpdateRequest

/**
 * DelegatedAdminAttributeCategoryApiGenerated - object-oriented interface
 * @export
 * @class DelegatedAdminAttributeCategoryApiGenerated
 * @extends {BaseAPI}
 */
export class DelegatedAdminAttributeCategoryApiGenerated extends BaseAPI {
    /**
     * 
     * @summary Add a new Delegated Admin Attribute Category to the config
     * @param {DelegatedAdminAttributeCategoryApiAddNewCategoryRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof DelegatedAdminAttributeCategoryApiGenerated
     */
    public addNewCategory(requestParameters: DelegatedAdminAttributeCategoryApiAddNewCategoryRequest, options?: AxiosRequestConfig) {
        return DelegatedAdminAttributeCategoryApiFp(this.configuration).addNewCategory(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Delete a Delegated Admin Attribute Category
     * @param {DelegatedAdminAttributeCategoryApiDeleteCategoryRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof DelegatedAdminAttributeCategoryApiGenerated
     */
    public deleteCategory(requestParameters: DelegatedAdminAttributeCategoryApiDeleteCategoryRequest, options?: AxiosRequestConfig) {
        return DelegatedAdminAttributeCategoryApiFp(this.configuration).deleteCategory(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a single Delegated Admin Attribute Category
     * @param {DelegatedAdminAttributeCategoryApiGetSingleRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof DelegatedAdminAttributeCategoryApiGenerated
     */
    public getSingle(requestParameters: DelegatedAdminAttributeCategoryApiGetSingleRequest, options?: AxiosRequestConfig) {
        return DelegatedAdminAttributeCategoryApiFp(this.configuration).getSingle(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Returns a list of all Delegated Admin Attribute Category objects
     * @param {DelegatedAdminAttributeCategoryApiListAllCategoriesRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof DelegatedAdminAttributeCategoryApiGenerated
     */
    public listAllCategories(requestParameters: DelegatedAdminAttributeCategoryApiListAllCategoriesRequest = {}, options?: AxiosRequestConfig) {
        return DelegatedAdminAttributeCategoryApiFp(this.configuration).listAllCategories(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }

    /**
     * 
     * @summary Update an existing Delegated Admin Attribute Category by name
     * @param {DelegatedAdminAttributeCategoryApiUpdateByNameRequest} requestParameters Request parameters.
     * @param {*} [options] Override http request option.
     * @throws {RequiredError}
     * @memberof DelegatedAdminAttributeCategoryApiGenerated
     */
    public updateByName(requestParameters: DelegatedAdminAttributeCategoryApiUpdateByNameRequest, options?: AxiosRequestConfig) {
        return DelegatedAdminAttributeCategoryApiFp(this.configuration).updateByName(requestParameters, options).then((request) => request(this.axios, this.basePath));
    }
}
