/*
PingData Config - OpenAPI 3.0

This is the PingData Configuration API

The version of the OpenAPI document: 0.1


NOTE: This file is auto generated by Konfig (https://konfigthis.com).
*/
import type * as buffer from "buffer"


/**
 * The log fields whose values should be completely tokenized in log messages. The field name will be included, but the value will be replaced with a token that does not reveal the actual value, but that is generated from the value.
 * @export
 * @enum {string}
 */
export type EnumlogFieldBehaviorTextAccessTokenizeEntireValueFieldProp = 'abandon-message-id' | 'add-attributes' | 'add-entry-dn' | 'add-undelete-from-dn' | 'additional-info' | 'administrative-operation' | 'assurance-timeout-millis' | 'authorization-dn' | 'auto-authenticated-as' | 'bind-access-token-original-authentication-type' | 'bind-authentication-dn' | 'bind-authentication-failure-id' | 'bind-authentication-failure-name' | 'bind-authentication-failure-reason' | 'bind-authentication-type' | 'bind-authorization-dn' | 'bind-dn' | 'bind-protocol-version' | 'bind-retired-password-used' | 'bind-sasl-mechanism' | 'change-to-soft-deleted-entry' | 'cipher' | 'client-connection-policy' | 'collect-support-data-comment' | 'collect-support-data-encrypted' | 'collect-support-data-include-binary-files' | 'collect-support-data-include-expensive-data' | 'collect-support-data-include-extension-source' | 'collect-support-data-include-replication-state-dump' | 'collect-support-data-jstack-count' | 'collect-support-data-log-duration' | 'collect-support-data-log-file-head-collection-size-kb' | 'collect-support-data-log-file-tail-collection-size-kb' | 'collect-support-data-log-time-window' | 'collect-support-data-report-count' | 'collect-support-data-report-interval-seconds' | 'collect-support-data-security-level' | 'collect-support-data-use-sequential-mode' | 'compare-assertion-value' | 'compare-attribute-name' | 'compare-entry-dn' | 'connect-from-address' | 'connect-from-port' | 'connect-to-address' | 'connect-to-port' | 'connection-id' | 'delete-entry-dn' | 'delete-soft-deleted-entry-dn' | 'deliver-otp-authentication-id' | 'deliver-otp-preferred-delivery-mechanisms' | 'deliver-password-reset-token-dn' | 'deliver-password-reset-token-preferred-delivery-mechanisms' | 'deliver-password-reset-token-successful-delivery-mechanism' | 'deliver-password-reset-token-unsuccessful-delivery-mechanisms' | 'diagnostic-message' | 'disconnect-message' | 'disconnect-reason' | 'entry-rebalancing-admin-action-message' | 'entry-rebalancing-base-dn' | 'entry-rebalancing-entries-added-to-target' | 'entry-rebalancing-entries-deleted-from-source' | 'entry-rebalancing-entries-read-from-source' | 'entry-rebalancing-error-message' | 'entry-rebalancing-operation-id' | 'entry-rebalancing-size-limit' | 'entry-rebalancing-source-backend-set' | 'entry-rebalancing-source-server' | 'entry-rebalancing-source-server-altered' | 'entry-rebalancing-target-backend-set' | 'entry-rebalancing-target-server' | 'entry-rebalancing-target-server-altered' | 'export-reversible-passwords-backend-id' | 'export-reversible-passwords-encryption-settings-definition-id' | 'export-reversible-passwords-entries-excluded-not-matching-filter' | 'export-reversible-passwords-entries-excluded-without-passwords' | 'export-reversible-passwords-entries-exported-with-non-reversible-passwords' | 'export-reversible-passwords-entries-exported-with-reversible-passwords' | 'export-reversible-passwords-entries-exported-without-passwords' | 'export-reversible-passwords-export-non-reversible-passwords' | 'export-reversible-passwords-export-only-entries-with-passwords' | 'export-reversible-passwords-filter' | 'export-reversible-passwords-include-virtual-attributes' | 'export-reversible-passwords-output-file' | 'export-reversible-passwords-total-entries-examined' | 'export-reversible-passwords-total-entries-excluded' | 'export-reversible-passwords-total-entries-exported' | 'extended-request-oid' | 'extended-request-type' | 'extended-response-oid' | 'extended-response-type' | 'externally-processed-bind-authentication-id' | 'externally-processed-bind-auth-failure-reason' | 'externally-processed-bind-end-client-ip-address' | 'externally-processed-bind-external-mechanism-name' | 'externally-processed-bind-was-password-based' | 'externally-processed-bind-was-secure' | 'externally-processed-bind-was-successful' | 'generate-password-num-passwords' | 'generate-password-max-validation-attempts' | 'generate-password-password-generator' | 'generate-password-password-policy' | 'get-supported-otp-delivery-mechanisms-dn' | 'gssapi-bind-qop' | 'gssapi-bind-requested-authentication-id' | 'gssapi-bind-requested-authorization-id' | 'indexes-with-keys-accessed-exceeding-entry-limit' | 'indexes-with-keys-accessed-near-entry-limit' | 'instance-name' | 'inter-server-bind-connection-privileges' | 'inter-server-bind-connection-purpose' | 'inter-server-bind-source-certificate-subject' | 'inter-server-component' | 'inter-server-control-forwarded-client-connection-policy' | 'inter-server-properties' | 'inter-server-operation-purpose' | 'intermediate-client-request' | 'intermediate-client-result' | 'intermediate-response-name' | 'intermediate-response-oid' | 'intermediate-response-value' | 'intermediate-responses-returned' | 'issuer-certificate-subject-dn' | 'ldap-client-decode-error-message' | 'local-assurance-level' | 'local-assurance-satisfied' | 'matched-dn' | 'message-id' | 'missing-privileges' | 'moddn-delete-old-rdn' | 'moddn-entry-dn' | 'moddn-new-rdn' | 'moddn-new-superior-dn' | 'modify-attributes' | 'modify-entry-dn' | 'multi-update-connection-id' | 'multi-update-first-failed-operation' | 'multi-update-first-failed-operation-error-message' | 'multi-update-first-failed-operation-result-code' | 'multi-update-operation-id' | 'non-critical-json-formatted-request-control-decode-errors' | 'non-critical-request-controls-ignored-due-to-acl' | 'oauthbearer-bind-access-token-client-id' | 'oauthbearer-bind-access-token-expiration-time' | 'oauthbearer-bind-access-token-identifier' | 'oauthbearer-bind-access-token-identity-mapper' | 'oauthbearer-bind-access-token-is-active' | 'oauthbearer-bind-access-token-issued-at' | 'oauthbearer-bind-access-token-issuer' | 'oauthbearer-bind-access-token-not-before' | 'oauthbearer-bind-access-token-owner' | 'oauthbearer-bind-access-token-scope' | 'oauthbearer-bind-access-token-subject' | 'oauthbearer-bind-access-token-type' | 'oauthbearer-bind-access-token-username' | 'oauthbearer-bind-access-token-validator' | 'oauthbearer-bind-authorization-error-code' | 'oauthbearer-bind-authorization-id' | 'oauthbearer-bind-id-token-client-id' | 'oauthbearer-bind-id-token-expiration-time' | 'oauthbearer-bind-id-token-identifier' | 'oauthbearer-bind-id-token-identity-mapper' | 'oauthbearer-bind-id-token-is-active' | 'oauthbearer-bind-id-token-issued-at' | 'oauthbearer-bind-id-token-issuer' | 'oauthbearer-bind-id-token-not-before' | 'oauthbearer-bind-id-token-owner' | 'oauthbearer-bind-id-token-subject' | 'oauthbearer-bind-id-token-type' | 'oauthbearer-bind-id-token-username' | 'oauthbearer-bind-id-token-validator' | 'operation-id' | 'operation-oauth-scopes' | 'operation-purpose' | 'origin' | 'pass-through-authentication-mapped-dn' | 'pass-through-authentication-succeeded' | 'pass-through-authentication-updated-local-password' | 'password-modify-grace-login-used' | 'password-modify-target-entry' | 'password-modify-used-password-reset-token' | 'password-policy-state-entry-dn' | 'password-update-behavior-allow-pre-encoded-password' | 'password-update-behavior-ignore-minimum-password-age' | 'password-update-behavior-ignore-password-history' | 'password-update-behavior-is-self-change' | 'password-update-behavior-must-change-password' | 'password-update-behavior-password-storage-scheme' | 'password-update-behavior-skip-password-validation' | 'peer-certificate-subject-dn' | 'ping-one-pass-through-authentication-auth-failure-reason' | 'ping-one-pass-through-authentication-mapped-id' | 'ping-one-pass-through-authentication-updated-local-user-password' | 'pluggable-pass-through-authentication-failure-reason' | 'pluggable-pass-through-authentication-mapped-user-identifier' | 'pluggable-pass-through-authentication-result-code' | 'pluggable-pass-through-authentication-updated-local-user-password' | 'pre-authorization-used-privileges' | 'processing-time-millis' | 'product-name' | 'protocol' | 'referral-urls' | 'remote-assurance-level' | 'remote-assurance-satisfied' | 'replace-certificate-certificate-decode-error' | 'replace-certificate-certificate-source' | 'replace-certificate-key-store-error' | 'replace-certificate-key-store-path' | 'replace-certificate-private-key-decode-error' | 'replace-certificate-request-decode-error' | 'replace-certificate-tool-error' | 'replication-change-id' | 'request-control-oids' | 'requester-dn' | 'requester-ip-address' | 'response-control-oids' | 'response-delayed-by-assurance' | 'result-code-name' | 'result-code-value' | 'search-base-dn' | 'search-deref-policy' | 'search-entries-returned' | 'search-filter' | 'search-requested-attributes' | 'search-result-entry-dn' | 'search-result-entry-attributes' | 'search-scope-value' | 'search-size-limit' | 'search-time-limit-seconds' | 'search-types-only' | 'search-unindexed' | 'server-assurance-results' | 'servers-accessed' | 'single-use-token-successful-delivery-mechanism' | 'single-use-token-token-id' | 'single-use-token-unsuccessful-delivery-mechanisms' | 'single-use-token-user-dn' | 'startup-id' | 'target-host' | 'target-port' | 'target-protocol' | 'thread-id' | 'totp-shared-secret-authentication-id' | 'totp-shared-secret-static-password-provided' | 'triggered-by-connection-id' | 'triggered-by-operation-id' | 'uncached-data-accessed' | 'uniqueness-request-control' | 'used-privileges' | 'using-admin-session-worker-thread' | 'work-queue-wait-time-millis' | 'yubikey-otp-bind-authentication-id' | 'yubikey-otp-bind-authorization-id' | 'yubikey-otp-device-authentication-id' | 'yubikey-otp-device-static-password-provided' | 'yubikey-otp-device-yubikey-public-id'

