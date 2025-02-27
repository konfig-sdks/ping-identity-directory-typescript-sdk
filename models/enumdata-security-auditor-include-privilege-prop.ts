/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * If defined, only entries with the specified privileges will be reported. By default, entries with any privilege assigned will be reported.
 * @export
 * @enum {string}
 */
export type EnumdataSecurityAuditorIncludePrivilegeProp = 'audit-data-security' | 'bypass-acl' | 'bypass-read-acl' | 'modify-acl' | 'config-read' | 'config-write' | 'jmx-read' | 'jmx-write' | 'jmx-notify' | 'ldif-import' | 'ldif-export' | 'backend-backup' | 'backend-restore' | 'server-shutdown' | 'server-restart' | 'proxied-auth' | 'disconnect-client' | 'password-reset' | 'update-schema' | 'privilege-change' | 'unindexed-search' | 'unindexed-search-with-control' | 'bypass-pw-policy' | 'lockdown-mode' | 'stream-values' | 'third-party-task' | 'soft-delete-read' | 'metrics-read' | 'remote-log-read' | 'manage-topology' | 'permit-get-password-policy-state-issues' | 'permit-proxied-mschapv2-details' | 'permit-forwarding-client-connection-policy' | 'exec-task' | 'collect-support-data' | 'file-servlet-access' | 'permit-replace-certificate-request'

