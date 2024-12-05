# NevisFIDODeployable_client

Enter the ID of the nevisIDM `Client`.

Only 1 client is supported.


# NevisAuthRealmBase_cookieName

Each realm has its own session cookie.
By default, this cookie will be called `Session_<pattern-name>`

Set this optional property to use a different name (e.g. `ProxySession`).

Note that each realm has its own session.
However, if the same cookie name is configured for multiple realms running on the same host
the sessions will be cleaned up together when the first session expires.

# NevisIDMDeployable_port

Port the nevisIDM instance is listening on.

# OAuth2AuthorizationServer_scopes

Enter scopes which may be requested by an `OAuth 2.0 / OpenID Connect Client`.

The scope `openid` must be allowed when `OpenID Connect` is used.

# NevisIDMUserLookup_attributes

Enter user attributes to fetch from nevisIDM.

Important attributes are:

- `extId` - unique ID of the user in nevisIDM
- `loginId` - name which could be used to login (instead of email)
- `firstName` 
- `name` - surname
- `email`
- `mobile`
- `language` - language stored for user (can differ from `Accept-Language` sent by the browser)

For a complete list check the documentation of
[IdmGetPropertiesState](https://docs.nevis.net/nevisidm/Configuration/authentication_plug-ins/nevisIDM-authentication-plug-ins/IdmGetPropertiesState).

Some attributes (e.g. `extId`, `email`, and `mobile`) are always fetched 
as they are required by standard authentication steps.

The attributes will be stored in the user session as `ch.nevis.idm.User.<attribute>`.

Attributes may be used in sub-sequent authentication steps 
or included in application access tokens (e.g. `NEVIS SecToken`, `SAML Token`, or `JWT Token`).

For instance, use them in a `Generic Authentication Step` 
via the expression `${sess:ch.nevis.idm.User.<attribute>}`.

# NevisIDMDeployable_encryptionAlgorithm

Encryption algorithm.


# NevisAdaptAuthenticationConnectorStep_highThreshold

Will be considered only if `Profile` is set to either `balanced`, `strict` or `custom`.

Set the risk score threshold [0...1] for high threat.

# NevisAuthRadiusFacade_responses

Configure additional Radius responses depending on your authentication flow.

For instance, configure `Access-Challenge` responses if your authentication flow is interactive.

Response rules configured here are evaluated first. 
You can therefore overrule the default rules added by this pattern.

No configuration may be required for basic username / password login 
as username and password can be sent by the Radius client in the initial `Access-Request` message.

# UserInput_onSuccess

Configure the step to execute after the user has provided input.
If no step is configured here the process ends with `AUTH_DONE`.

# SamlSpConnector_context

Select `nevis` if the SAML service provider is provided by a `SAML SP Realm`
and you want to use `Authorization Policy` to specify the required
`Authentication Level` for application protected by that realm.

When `nevis` is selected the roles and attained authentication level
are added to the SAML `Response` via an `AuthnContextClassRef` element.

Example:

```xml
<saml2:AuthnStatement AuthnInstant="2021-05-07T06:48:14.967Z">
  <saml2:AuthnContext>
    <saml2:AuthnContextClassRef>...,nevisIdm.Admin,urn:nevis:level:1</saml2:AuthnContextClassRef>
  </saml2:AuthnContext>
</saml2:AuthnStatement>
```

Select `PasswordProtectedTransport` to add the following standard context:

```xml
<saml2:AuthnStatement AuthnInstant="2021-05-07T06:48:14.967Z">
  <saml2:AuthnContext>
    <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
  </saml2:AuthnContext>
</saml2:AuthnStatement>
```

Select `none` to not add any `AuthnContext` element.


# NevisMetaWebApplicationAccess_backendTrustStore

Assign the Trust Store provider for outbound TLS connections.
If no pattern is assigned a trust store will be provided by nevisAdmin 4 automatic key management.

# NevisProxyObservabilitySettings_traceExporterAddress

Enter the target URL (`host:port`) of the backend services to which the exporter is going to send spans.
The `/v1/traces` path is automatically attached to it.


# CustomNevisMetaLogFile_levels

Configure log levels.

See the nevisMeta Technical Documentation, chapter
[Logging](https://docs.nevis.net/nevismeta/Operation-and-Administration/Logging) for details.

Hint: If you only change log levels nevisAdmin 4 does not restart the component in classic VM deployment.
The new log configuration will be reloaded within 60 seconds after deployment.

Examples: 

```
ch.nevis.nevismeta = INFO
ch.nevis.ninja = DEBUG
```


# NevisAdaptDeployable_addons

Assign an add-on pattern to customize the configuration.

# HeaderCustomization_requestHeaders

Adds/overwrites HTTP headers in requests. 

The syntax is: `<header name>:<value>`

Examples:

```
X-Forwarded-For: ${client.ip}
User-ID: ${auth.user.auth.UserId}
```

Note: change the `Filter Phase` to replace headers early / late.

In order to use the `${exec: ...}` syntax of nevisProxy for passwords,
use an inventory secret to skip the validation of the value.

# OAuth2Scope_consentRequired

Select `enabled` if consent shall be requested for this scope.

# ActiveMQClientConfiguration_messageBrokerURL

Set the URL for the ActiveMQ message broker. Example:

`ssl://my-message-broker:61616`


# LogSettingsBase_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.

# DummyLogin_buttons

Assign an `Dispatcher Button` to add a button which points to a different authentication step.

# NevisAdaptPluginPattern_propagateGeolocation

Risk scores to be delivered to the client in the request headers.
This option configures enables geolocation risk score to be propagated.

# HostContext_tls

Choose between:

- `recommended`: for high security, apply the recommended settings for `SSLProtocol` and `SSLCipherSuite`.
  The settings may change in future releases.
  Check the [nevisProxy Technical Documentation](https://docs.nevis.net/nevisproxy/Configuration/Servlet-container---Navajo/Frontend-connectors) for details.
  This works with modern browsers and clients. Current `recommended` values are:
  ```
  sslProtocol = '-all +TLSv1.2 -TLSv1.3'
  sslCipherSuite = 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256'
  ```

- `compatible`: the `SSLProtocol` and `SSLCipherSuite` will be based on [Mozilla's SSL configuration](https://ssl-config.mozilla.org/#server=apache&version=2.4.41&config=old&openssl=1.1.1k&guideline=5.6) for Apache server. These settings provide high compatibility with older browsers and clients. Current `compatible` values are:
  ```
  sslProtocol = '-all +TLSv1.1 +TLSv1.2 -TLSv1.3'
  sslCipherSuite = 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA'
  ```

- `custom`: assign a `TLS Settings` pattern via `Additional Settings` to apply your own configuration. If not provided, `SSLProtocol` and `SSLCipherSuite` follow the `recommended` settings.

# PemTrustStoreProvider_rootDirName

Set to deploy the trust store underneath a _base_ directory.
The trust store will be established at:

`/var/opt/keys/trust/<base>/<name>`

This configuration may be used to prevent trust stores overwriting each other 
and is only required in complex setups with multiple projects or inventories.

# NevisAdaptEvent_minMatch

Specify the minimum number of matching risk events to continue with `Authentication Step`.
Picking a number that exceeds the size of selected `Risk Events` will set `all` during generation.

# NevisIDMClientCertAuthentication_onSuccess

Assign an optional step to execute after successful authentication.

# NevisIDMClient_displayNames

The name of the client in different languages.

The format is:
* two letter language code in lower case
* separator characher: `=` or `:`
* the client name in that language

For example:
```
de:Beispiel-Client
fr:Exemple de client
```


# CustomNevisIDMLogFile_regexFilter

If set, messages for `application.log` which match the given regular expression won't be logged.

The regular expression must match the entire line.
For instance, you may use the following format to match `some text`:

```
.*some text.*
```


# NevisAdaptUserNotification_onSuccess

Set the step to continue with on successful authentication.

# ServiceBase_realm

Optionally assign a realm to protect this application or service.

# NevisIDMDeployable_encryptionKey

Enter an encryption key as Base64. 
This is mandatory because of security.

For existing setups please enter the value of `security.properties.key` 
from your `/var/opt/nevisidm/<instance>/conf/nevisidm-prod.properties` file.

If you don't know which value was used so far you may generate a new key 
and set `Encryption Fallback` to `enabled` to ease migration.

When there are no URL tickets or encrypted properties the fallback can be disabled.

For new setups the key should consist of random bytes.
The following openssl command generates a random key and returns the Base64 value:

```bash
openssl rand -base64 16
```

Note that when `Encryption Algorithm` is set to `AES`, the key length must be 8, 16 or 24 bytes. 8 byte long `AES` keys 
are strongly discouraged for new instances, but supported for legacy instances.

# HeaderCustomization_responsePhase

- `BEFORE_SANITIATION` - manipulate request headers late to also cover any headers set by nevisProxy.
- `AFTER_AUTHENTICATION` - default behaviour which should work in most cases.
- `END` - manipulate response headers early hiding them from other nevisProxy filters which operate on responses.

# HeaderCustomization_condition

Set to do the header customization only if the given condition applies.

The condition is checked for `Add / Overwrite Headers` on requests and on responses.

You can use the expressions mentioned above. 

Syntax:

```
${expression} == value
```

Examples:

```
${request.header.Content-Type} == application/x-www-form-urlencoded
```

# NevisAuthDeployable_classPath

Enter directory paths to be added to the `classPath` of the `AuthEngine`.

The paths will be added as a prefix. Entries added by other patterns
(e.g. `/opt/nevisidmcl/nevisauth/lib` or `/opt/nevisauth/plugin`)
are preserved.

This is an advanced setting which should only be used 
when working with custom `AuthState` classes.

# GoogleLogin_clientId

ClientID is `Client ID` provided by Google when you create a OAUTH 2.0 credential in Google.

# NevisDPLogSettings_maxFileSize

Maximum allowed file size (in bytes) before rolling over.

Suffixes "KB", "MB" and "GB" are allowed. 10KB = 10240 bytes, etc.

This configuration applies to non-Kubernetes deployment only.

Note: not relevant when rotation type is `time`.

# CSRFProtectionSettings_sameSite

Set to `lax` to issue a separate cookie with the `SameSite` flag set to `lax`.
In this configuration, links and redirects from other domains are allowed,
while CSRF-prone requests (e.g. `POST`) should be prevented by the browser.

Set to `off` to not send an additional cookie.
There are several reasons why this feature may be disabled:

- Not all browsers support the `SameSite` flag and behave incorrectly by never sending the cookie. Older versions of IE and Windows may be affected.

- The `SameSite` flag breaks SAML use cases when POST binding is used. 
SP-initiated authentication does work with NEVIS but all other SAML process (e.g. logout) will fail.


# ICAPScanning_contentType

Optional property to restrict scanning to a certain Content-Type (regular expression is supported here). 

Example: `application/.*`

# NevisProxyDatabase_encryption

Enables TLS in a specific mode. The following values are supported:

- `disabled`: Do not use TLS (default)
- `trust`: Only use TLS for encryption. Do not perform certificate or hostname verification. This mode is not recommended
  for production applications but still safer than `disabled`.
- `verify-ca`: Use TLS for encryption and perform certificates verification, but do not perform hostname verification.
- `verify-full`: Use TLS for encryption, certificate verification, and hostname verification.

# LuaPattern_phase

Defines the position of the filter-mapping for this Lua filter.
Which position to choose depends on your use case.

For requests filters will be invoked from `START` to `END`.
For responses filters will be invoked from `END` to `START`. 

Choose from the following filter phases:

- `START`: applied as early as possible for requests and as late as possible for responses.
- `BEFORE_SANITATION`: applied before filters which validate the request (e.g. Mod Security).
- `SANITATION`: used for security. This is the first phase which allows accessing the session for applications protected by a realm.
- `AFTER_SANITATION`: your request has passed security checks.
- `BEFORE_AUTHENTICATION`: applied just before authentication.
- `AUTHENTICATION`: used by the filter which connects to nevisAuth for applications which are protected by an `Authentication Realm`.
- `AFTER_AUTHENTICATION`: the request has level 1 authentication. Used by `Authorization Policy` for `Authentication Level` stepup.
- `BEFORE_AUTHORIZATION`: choose this phase to do preprocessing before authorization.
- `AUTHORIZATION`: used by `Authorization Policy` for `Required Roles` check.
- `AFTER_AUTHORIZATION`: used by patterns assigned as `Application Access Token` to applications.
- `END`: applied as late as possible for requests and as early as possible for responses.

# TANBase_title

Change the Gui title.

We recommend to enter a label here and provide translations for this label in the `Authentication Realm`.


# UserInformation_label

Enter a label or an expression for the text message
that shall be presented to the user.

Translations for the label can be defined in the realm pattern.

If not set the expression `${notes:lasterrorinfo}` is used.


# GenericDeployment_executableFiles

Expression to select files which shall have the _executable_ flag.
Add exact file names or `*.<ending>`.

Example:
* myScript.sh
* *.py

# SOAPServiceAccess_schema

Optional property to upload a schema.

This feature is experimental and may change in future releases.

You must upload all required XSD schema files. 
Each XSD schema file must declare 1 target namespace which will be extracted from the first `targetNamespace` attribute found in the file.

Upload of a WSDL file is optional. 
If provided, the WSDL must contain a `types` declaration containing an XSD schema.
However, this schema definition can be empty. Here is a minimal example:

```asciidoc
   <types>
      <xsd:schema targetNamespace="urn:com.example:echo"
                  elementFormDefault="qualified">
      </xsd:schema>
   </types>
```
 
The actual schemas must still be uploaded as separate files.

# SamlResponseConsumer_idp

Assign a `SAML IDP Connector` for each SAML Identity Provider.

SP-initiated authentication is not supported and thus 
the `Selection Expression` of the connector patterns is ignored.

# HostContext_resources

Upload a ZIP to provide your own resources.

By default, the following resources are provided:

* `/favicon.ico`
* `/index.html`
* `/errorpages/403.html`
* `/errorpages/404.html`
* `/errorpages/500.html`
* `/errorpages/502.html`
* `/resources/logo.png`
* `/resources/bootstrap.min.css`
* `/resources/default.css`

This host has its own error handler (`ErrorHandler_Default`) which is assigned to the root location (`/*`).
The error handler will replace the response body when an HTTP error code occurs and an error page is available.

Error pages for HTML must be added the sub-directory `errorpages` and named `<code>.html`.

The error code is returned to the caller as this may be required by some REST clients.

If you do not want this you can assign a specific `HTTP Error Handling` pattern 
to this `Virtual Host` or to applications via `Additional Settings`.

The servlet hosting the above resources is usually mapped to the root location (`/*`), however if there is already 
another servlet mapped there, the servlet is mapped to individual root files and directories. 

If there is an undesired mapping, it can be deleted by removing the given resource from the zip file.

# NevisProxyObservabilitySettings_traceContextInjection

Choose one of:

- **enabled**: inject the current context (span ID, trace ID, etc) as a HTTP header to the request
- **disabled**: do not inject the current context in the request


# NevisDetectEntrypointDeployable_contentType

Apply restriction based on request header Content-Type

# NevisAdaptAuthenticationConnectorStep_fingerprintJsVersion

This configuration option gives the administrator the ability to ensure backwards compatibility in
case so far V2 fingerprints have been in use.

* `V2` - to ensure backward compatibility, FingerprintJS V2 will be used
* `V3` - default option, uses FingerprintJS V3

# NevisFIDODeployable_customURILink

Custom URI links will open the mobile app directly.

The scheme must be registered for the mobile app.

See [Link Structure for Custom URIs](https://docs.nevis.net/nevisaccessapp/features/channels/link#custom-uri-structure) for details.

If the mobile app is not installed an error will occur.

Example:

```
myaccessapp://x-callback-url/authenticate
```


# NevisMetaServiceAccessBase_token

Assign a `NEVIS SecToken` pattern.

The token informs nevisMeta about the authenticated user.

If you are not using automatic key management then you also have to configure `nevisMeta Instance` / `NEVIS SecToken Trust`
so that the signer certificate is trusted.

# NevisAuthDeployable_backendKeyStore

Assign the Key Store provider for outbound TLS connections.
If no pattern is assigned a key store will be provided by the nevisAdmin 4 PKI.

# HostingService_rewrites

Rewrite rules for serving files. 

This can be useful if a file should be served under a different name,
or to map extensions to file names.

Examples:

| Source            | Destination           |
|-------------------|-----------------------|
| `/static/picture` | `/static/picture.jpg` |


# PemTrustStoreProvider_truststoreFile

Upload trusted certificate(s) in PEM format.

If you set a _variable_, the variable should be a list of secret file references in the inventory.
Example:

```
  my-variable: 
    - inv-res-secret://147cc54a5629fadac761ec01#some-cert.pem
    - inv-res-secret://147cc54a5629fadac761ec01#some-other-cert.pem
```

Upload files for this variable by clicking `Attach files`
in the drop-down on the inventory screen.

If you are deploying to Kubernetes you may store the trust store content in a Kubernetes secret.
You can pick any name for the Kubernetes secret but the keys must be as in the following example:

```
  my-variable: 
    - k8s-secret-file://dummy-truststore:truststore.pem/
    - k8s-secret-file://dummy-truststore:truststore.jks/
    - k8s-secret-file://dummy-truststore:truststore.p12/
    - k8s-secret-file://dummy-truststore:keypass/
```

Note that nevisAdmin 4 does not notice when the content of the Kubernetes secret changes.
Manual interaction (terminating pods) is required in that case.

# NevisIDMUserLookup_unitProperties

Enter unit properties to fetch from nevisIDM and store in the unit session.
 
Properties must be created in the nevisIDM via SQL. 

# HostContext_securityHeaders

Configure security response headers:

- `off` does not set any security headers
- `basic` sets default headers on responses. That is:
  - `Strict-Transport-Security: max-age=63072000`
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- `custom` configure `Security Response Headers` via `Additional Settings`

# OAuth2Client_pkceMode

The following types of PKCE modes are supported:

- `allowed` (default): If the client sends PKCE information in the form of a code challenge in the authorization request, the code challenge will be validated. If the code challenge is not valid, the authorization will fail. But if no code challenge is included in the authorization request, the authorization will not fail.
- `required`: The client must send valid PKCE information. If no code challenge is included in the authorization request, the authorization will fail.
- `s256-required`: The client must send valid PKCE information using the S256 code challenge method. The authorization will fail if no code challenge is included in the authorization request, or if the code challenge does not use the S256 code challenge method.

If the client supports the s256 code challenge method, then `s256-required` is the recommended value.

# NevisAdaptDatabase_password

Provide the DB password here.

# GenericIngressSettings_tlsSettings

If `disabled`, the TLS related settings are removed from the generated Ingress resource, 
which means the default certificate provided by NGINX will be used for the TLS termination. 

It's only recommended to use this option, when an additional loadbalancer is used in front of
NGINX (e.g. Cloudflare), which already provides a valid certificate.

# CustomProxyLogFile_eventLog

Enable event logging capability of nevisProxy. 

Event logs are not forwarded to syslog.

# NevisIDMUserCreate_unitId

Enter the unit ID where the user shall be created.


# FIDO2Onboarding_userVerification

User verification is a crucial step during WebAuthn authentication process as it confirms that the person attempting to authenticate is indeed the legitimate user.

This setting allows to configure the user verification requirements for onboarding.

Allowed values:

- `discouraged`
- `preferred`
- `required`


# NevisFIDOLogSettings_serverLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the default SERVER logs.
This pattern is used for **non**-kubernetes deployments.

Note: not relevant when Log Targets is set to `syslog`.

# NevisAdaptDeployable_observationConfig

Used to assign a `nevisAdapt Observation Cleanup Configuration` pattern to configure
the time interval for cleaning up observation data.

This is an optional setting. Default values if nothing is set:

- Observation Timeframe: `60d`
- Trusted Cleanup Period: `1d`
- Untrusted Cleanup Timeframe: `12d`

# NevisAuthDeployable_startTimeout

Enter a timeout to wait for nevisAuth startup.

Set a higher value if nevisAuth takes longer to start.

This setting applies to classic VM-based deployment only.

# NevisProxyObservabilitySettings_metricsMode

Choose one of:

- **enabled**: enable the metrics feature of OpenTelemetry
- **disabled**: disable the metrics feature of OpenTelemetry


# NevisIDMUserLookup_properties

Enter user properties to fetch from nevisIDM and store in the user session.
 
Properties must be created in the nevisIDM via SQL. 

# SAPLogonTicket_authScheme

Authentication scheme associated with this ticket. See SAP documentation of SAP SSO logon tickets for more information. Default value is SAP's default and should be correct for most cases.

# ProxyPluginPattern_riskScores

Risk scores to be delivered. Please add entries in the following format:

RiskScoreName=#ColorCode

# Button_buttonName

Enter a `name` to use for the `GuiElem`.

Configuration is optional but may be required when the button is rendered differently based on the name.

If missing, the sanitized name of the pattern will be used.


# NevisDetectDatabase_flywayLicenceKey

Please provide a licence key in case you would use the Flyway Teams Edition.

This is recommended only in case you would use an old database version (more than 5 years old).
If you do not provide a licence key, the Flyway Community Edition will be used by default.

For more information about Flyway editions please visit this page [Flyway](https://flywaydb.org/download).


# CustomProxyLogFile_logLevelParameters

Configure log levels.

Overrules the `Log Level` property.

See [nevisProxy Reference Guide `Operation and Administration / Debugging`](https://docs.nevis.net/nevisproxy/Operation-and-Administration/Debugging) 
for possible trace groups.

Enter the **suffix** of the name of the trace group and a log level.

Supported log levels are:

- ERROR
- NOTICE
- INFO
- DEBUG
- DEBUG_HIGH
- TRACE

Do **not** enter numbers for the log level as nevisAdmin4 will calculate them automatically.

The default configuration is:

```
NavajoOp = INFO 
NProxyOp = INFO
```

Debug startup:

```
NavajoStart = INFO
```

Debug `HTTP Header Customization`:

```
IW4HdrDlgFlt = DEBUG
```


# AuthStatePatch_realm

Authentication realm to patch.

# SamlSpRealm_postProcess

Assign a _Generic Authentication Step_ to apply custom post-processing logic 
to an SP-initiated SAML process (e.g. authentication, session upgrade, or logout).

By assigning a step here the last AuthState of the process will be replaced
so that it points to the first AuthState provided by the assigned step.
This AuthState should be marked with the name `${state.entry}`.

Use the expression `${state.done}` to complete with the SAML process.

# SharedStorageSettings_claimName

The name of the PersistentVolumeClaim.

For more information regarding persistent volumes in Kubernetes please visit this [page](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)

# SamlResponseConsumer_host

Assign a `Virtual Host` which shall serve as entry point.

# InBandMobileAuthenticationRealm_nevisfido

Assign a nevisFIDO instance. This instance will be responsible for providing the in-band authentication services.

# AuthServiceBase_realm

Assign an `Authentication Realm`.

# SamlIdpConnector_url

Enter the `Location` of the SAML `SingleSignOnService`.
This may be a URL or a path on the same virtual host.

nevisAuth will send an `AuthnRequest` to this location
to delegate the authentication or session upgrade process 
to the IDP.

By default, the `AuthnRequest` contains a `RequestedAuthnContext` 
which specifies the required authentication level.
You can disable this feature via `Custom Properties`.

# NevisProxyDatabase_params

Add custom `init-param` for the MySQL session store servlet.

Check the nevisProxy technical documentation for supported parameters
of the servlet class `ch::nevis::nevisproxy::servlet::cache::mysql::MySQLSessionStoreServlet`.


# NevisAdaptPluginPattern_propagateDeviceFingerprint

Risk scores to be delivered to the client in the request headers.
This option configures enables device fingerprint risk score to be propagated.


# MicrosoftLogin_claimsRequest

The claims request parameter. This value is expected to be formatted in JSON and does not accept trailing spaces nor tabs.

# GenericDeployment_commandTrigger

Defines when or how often the command is executed.

Possible values are:

* `always`: Execution during each deployment.
* `onFileChange`: Executed if an uploaded file under the specified `Path` has changed. 
* `onFileTriggers`: Executed if a file that is listed under `Command: Execution File Triggers` has changed.
* `onFileChange + onFileTriggers`: Combining both options above. 


# NevisIDMAuthorizationsAddon_roleAssignmentFile

Add properties for `rolesAssignment.properties`. 
If a role not defined in the uploaded file default values will be used for it. 

See [Data room authorization](https://docs.nevis.net/nevisidm/Configuration/Security/Authorization-in-nevisIDM/Data-room-authorization) for details.

You can input the role with or without `nevisIdm` prefix. 
For instance, both `Root` are `nevisIdm.Root` are supported.


# GenericAuthService_pathAddons

Assign add-on patterns to customize the `Frontend Path`.

# NevisAuthRealmBase_logrendKeyStore

Assign a pattern which sets up a key store to use for 2-way HTTPs connections to nevisLogrend.

If no pattern is assigned no key store will be setup and 1-way HTTPs 
or plain HTTP will be used depending on the connection URL of nevisLogrend.

# GenericDeployment_command

Bash shell expression which will be executed from the working directory `Path` as the deployment user (`__connection_user` variable in the inventory).

Example:
* ./my_script.sh

The command will run depending on the `Command: Execution` setting: always or conditional (e.g. `onFileChange`).
Note that with the onFileChange setting, the command is _not_ automatically executed if you change it here. 

Tip: Instead of specifying your shell instruction(s) here, add them as a separate script file into `Files`. For example, if the file name is 
`my_script.sh`, enter `./my_script.sh` as the `Command`. This way, the script _will_ be re-executed each time you upload an updated script file
and deploy the project (if `onFileChange` command execution is configured below).


# NevisLogrendDeployable_trustStore

Used when mutual (2-way) HTTPs is configured.
If no pattern is assigned here automatic key management will provide the trust store.

# RoleCheck_notFound

Assign a step to continue with when the user has **none** of the configured roles.

If no step is assigned, error code `403` will be returned in this case.


# ApplicationProtectionDeployableBase_keyStore

Used when simple or mutual (2-way) HTTPs is configured.
If no pattern is assigned here automatic key management will provide the key store.

# ApplicationProtectionDeployableBase_clientAuth

Setting for 2-way TLS on the nevisAdapt HTTPs endpoint. There are 3 options will
affect the callers (e.g. nevisProxy or technical clients accessing nevisAdapt REST APIs)

* required: Callers **must** present a client certificate.
* requested: Callers **can** present a client certificate.
* disabled: Callers **must not** use a client certificate.

The `Frontend Trust Store` must contain the issuing CA.

# NevisAdaptUserNotification_notificationType

This mandatory property selects the actual communication event and thus the used template text type.


# NevisAdaptDeployable_ipPrivateNetworkCountryCode

When selected 'disabled' on IP Private Network Filter, the country code of the IP address is not in the list of private network country codes.

You can also assign a default Geolocation by country code by [ISO 3166 alpha-2](https://www.iban.com/country-codes).

# GenericAuthWebService_configFile

The file should contain `WebService` elements only.

Uploading a complete `esauth4.xml` is not supported. 


# NevisMetaWebApplicationAccess_meta

Reference the nevisMeta Instance.

# EmailInputField_optional

Input into the field is optional or mandatory.

Choose between:

- `optional` - No input is required to the field.
- `mandatory` - Input is required to the field.

# NevisAdaptObservationCleanupConfig_timeframeDays

This value defines the observation lookup period, the cleanup of trusted observations cannot happen sooner than this.

The default value is `60d`.

# NevisAuthRealm_onDemandFallback

Assign an authentication step which should be invoked when a session upgrade is triggered
and none of the `Session Upgrade Flows` can be applied.


# NevisIDMUserLookup_unitAttributes

Enter unit attributes to fetch from nevisIDM.

Possible attributes are:

- `extId` - unique ID of the unit in nevisIDM
- `state` - state of the unit in nevisIDM
- `name` 
- `displayName`
- `displayAbbreviation`
- `location`
- `description`
- `hname`
- `localizedHname`
- `ctlCreDat`
- `ctlCreUid`
- `ctlModDat`
- `ctlModUid`

For a complete list check the documentation of
[IdmGetPropertiesState](https://docs.nevis.net/nevisidm/Configuration/authentication_plug-ins/nevisIDM-authentication-plug-ins/IdmGetPropertiesState).

The attributes will be stored in the user session as `ch.nevis.idm.Unit.<attribute>`.

Attributes may be used in sub-sequent authentication steps or included in application access tokens.

For instance, use them in a `Generic Authentication Step` 
via the expression `${sess:ch.nevis.idm.Unit.<attribute>}`.


# NevisAuthDeployable_scripts

Upload shared Groovy scripts used in your authentication steps.

You can use the expression `${var.<name>}` inside your scripts to refer to an inventory variable.

How the value of a variable is generated into the script depends on the variable content:

Scalar variables will be generated as-is. This means the variable expression has to be within a Java String (`'`) or a Groovy _GString_ (`"`).

YAML variables of type **sequence** will be generated as a **Groovy list**.

For instance, let's assume you have the following variable in your inventory:

```yaml
my-sequence-var:
  - some-entry
  - another-entry
```

In your script you may use the expression as follows:

```text
def myList = ${var.my-sequence-var}
```

The following will be generated:

```groovy
def myList = ["some-entry", "another-entry"]
```

Inventory variables containing a **YAML mapping** are not supported yet.

Uploaded files will be deployed to the `conf/groovy` folder of the nevisAuth instance.


# GenericModQosConfiguration_serverDirectives

Server level directives can be entered here.

These directives apply to the entire `nevisProxy Instance` 
which means that other `Virtual Host` patterns may be affected.

Examples:

```
QS_ClientEventBlockCount 200 300
QS_SetEnvIf NAVAJO_HTTPSESS_CREATED !QSNOT QS_Block=yes
QS_SrvMaxConnClose 85%
QS_SrvMaxConnPerIP 75
QS_SrvMinDataRate 75 300 250
```

# TransactionConfirmation_nevisfido

Assign a `nevisFIDO UAF Instance`. This instance will provide the transaction confirmation services.


# NevisIDMUserCreate_loginId

Define how the `loginId` is set:

- `auto`: the `loginId` is generated. 
  `loginIdGenerator.enabled=true` must be set in the client policy.
  This can be achieved via the `nevisIDM Administration GUI`.
  
- `email`: use the email for the `loginId`. 
  The `email` must be provided via `Mandatory User Attributes`.
  
- `value`: the `loginId` must be provided via `Mandatory User Attributes`.

# PropertiesTestPattern_keyValueProperty

Enter key=value pair(s).
This property also supports other separators.

# NevisIDMDeployable_frontendTrustStore

Assign the Trust Store provider for the HTTPs endpoint.
If no pattern is assigned the Trust Store will be provided by the nevisAdmin 4 PKI.

# Webhook_url

Enter the URL to call.

# GenericAuthenticationStep_nextSteps

Assign follow-up steps.
 
The order of steps is relevant. 
The first step in this list has index `1`. 
 
You may reference a step in the configuration
via the expression `${state.exit.<index>}`.

# SAPLogonTicket_recipientClient

See SAP documentation of SAP SSO logon tickets for more information. Setting no value for this property should be correct for most cases.

# NevisIDMChangePassword_newPassword2

Mandatory input value to use for confirming the new password if `Show GUI` is disabled and `Show Confirmation Field` is enabled.

# NevisFIDODatabase_type

Choose between `MariaDB` and `PostgresSQL`.

We recommend to use `MariaDB` as it is supported by all Nevis components that have a database.

**Note:** `PostgresSQL` database is only experimental configuration.


# GenericIngressSettings_nodePortService

If `enabled`, the generated services for the Ingresses will be of type NodePort. This allows direct connection to the nevisProxy instance.

# NevisIDMPasswordLogin_buttons

Assign an `Dispatcher Button` to add a button which points to a different authentication step.

# NevisDetectDatabase_database

Enter the name of the database.

This database will be created in the database service.


# TANBase_buttons

Assign a `Dispatcher Button` to add a button which points to a different authentication step.

# NevisAdaptAuthenticationConnectorStep_clientKeyStore

The key store used by this pattern to establish a connection with the nevisAdapt component.
For a client TLS connection, this key store should be trusted by the ```nevisAdapt Instance```. If no pattern is assigned here automatic key management will provide the key store.

# OAuth2Client_address

Set to `allowed` to allow this client to request the scope `address`.

This scope produces various claims.

# AuditChannel_channelClass

Enter the fully qualified name of your Java class.
The class must implement the [AuditChannel interface](https://docs.nevis.net/nevisauth/operation/auditing#auditchannel-interface).

The class must be on the classpath of the `AuthEngine`.
You can upload your JAR file in the `Classloading` tab of the `nevisAuth Instance` under `Custom Dependencies`.


# GenericDeployment_files

Upload the files which will be copied into the `Path`. 

To upload files into subdirectories within `Path`, add a single .zip file with files and directories. Unpacked files will have `Owner` and `Group` applied. Note: If multiple files are uploaded, any .zip file is deployed as is, without being extracted.

It is not supported to overwrite files generated by other patterns. See also `Path` above.

# NevisAuthRadiusFacade_realm

Assign a nevisAuth Realm which shall be exposed via Radius.

# NevisFIDODeployable_noUserVerificationTimeout

Maximum time that a FIDO2 client has to send the response in a ceremony where user-verification is **not** required.

Default value is 2 minutes.


# RequestValidationSettings_scope

Sets the scope of request validation:

- `all`: validation will be applied to all requests. This includes authentication.

- `backend`: validation will be applied to requests which are sent to the backend application. The authentication is excluded.

- `authentication`: validation will be applied to requests which are sent to nevisAuth. 


# TCPSettings_keepAliveInactiveInterval

Inactivity duration allowed before a TCP connection is dropped. By leaving this field empty, you will be using the nevisProxy default value.


# NevisAdaptDatabase_parameters

Enter parameters for the DB connection string.

Enter 1 parameter per line.

Lines will be joined with `&`.

The default is:

```
useMysqlMetadata=true
```

The default value will be used **only** when no parameters are entered.

If you want to keep the default parameters, add them as well.


# NevisAdaptDatabase_hikariValues

Specify custom values for Hikari datasource configuration. Separate keys and values with `=`. The valid keys can be found at [HikariCP - GitHub](https://github.com/brettwooldridge/HikariCP).

Example to set the same as if selecting `recommended`:

```
maxLifetime=300000
idleTimeout=100000
maximumPoolSize=50
```

# JavaObservability_deploymentEnvironment

Select a value for the OpenTelemetry [`deployment.environment`](https://opentelemetry.io/docs/specs/semconv/resource/deployment-environment/) attribute.

Choose between:

- `production`: example value used in OpenTelemetry documentation
- `staging`: example value used in OpenTelemetry documentation
- `testing`
- `development`

If nothing is selected, then this attribute will not be set.

In case the attribute is set in the `Agent Configuration` as well, the configuration provided here wins.

You may use this attribute for filtering, e.g. to separate information from prod and test for metrics and traces.


# NevisIDMProperty_regex

Enter `regex` for the property definition file.

The defined regular expression will restrict the possible values that can be assigned to the property.
If a value is entered, it will be checked against the specified pattern to ensure it meets the criteria.

Some examples of how regular expressions can be used for common data types:

Email address:

`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`

Telephone number in the format `+[country code] (XXX) XXX-XXXX`:

`^\+\d{1,3}\s?\(\d{3}\)\s?\d{3}-\d{4}$`

Social Insurance Number (SIN) in the format `XXX-XX-XXXX`:

`^\d{3}-\d{2}-\d{4}$`

URL in the format:

`(https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/)?[a-zA-Z0-9]{2,}(\.[a-zA-Z0-9]{2,})(\.[a-zA-Z0-9]{2,})?`

The regex will be escaped for JSON if required.

# SecurityResponseHeaders_responseHeaders

Use this property to add security headers to responses. 
The syntax is: `<header name>:<value>`

Example:

```
Strict-Transport-Security: max-age=63072000
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

# CustomNevisMetaLogFile_serverLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the default SERVER logs.

Note: not relevant when Log Targets is set to `syslog`.

# OAuth2Client_offlineAccess

Set to `allowed` to allow this client to request the scope `offline_access`.

When this scope is requested a refresh token will be returned as well.

# CustomProxyLogFile_rotationType

Defines how to handle log retention for the access, apache and navajo log files. Rotation is possible based on:
* file size
* time interval

# URLHandler_forwards

Rewrite the path of HTTP requests.

Rewrites are done using a `forward` which means 
that they are transparent for the caller.

The format is the same as in `Redirect Rules`.


# NevisLogrendDeployable_path

Set a custom path for nevisLogrend resources (e.g. CSS).
The path will be made accessible in nevisProxy.

You must change the path when using multiple nevisLogrend instances 
on the same virtual host.

# TLSSettings_options

The value configured here will be applied as `SSLOptions`.

It should only have value when assigned to a `Virtual Host` pattern.

Check the [Apache Documentation](http://httpd.apache.org/docs/current/mod/mod_ssl.html#ssloptions) for details.

If empty and when this pattern is assigned to a `Virtual Host` the following value is used:

`+OptRenegotiate +StdEnvVars +ExportCertData`

# NevisIDMSecondFactorSelection_notFound

Assign a step to continue with if the user does not have any supported credential.

Configuration is optional but we recommend to assign a step to handle the missing second-factor credential case.
For instance, you may assign the following steps:
 
- `User Information`: to show an error message and terminate the authentication flow.
- `OATH Onboarding`: to register an authenticator app which supports OATH Time-based One-Time Password algorithm (TOTP).
- `FIDO2 Onboarding`: to register a FIDO2 authenticator such as a mobile device or USB security key.


# AppleLogin_issuer

The `issuer` registered claim identifies the principal that issued the client secret. 
Since the client secret belongs to your developer team, use your 10-character Team ID associated with your developer account.
Find out more [here](https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens).

# NevisDetectRiskPluginBase_dashboard

BehavioSec Dashboard URL

# CookieCustomization_sharedCookies

Cookies listed here will be stored in nevisProxy
and shared between all applications which have this pattern assigned.

Note that storing cookies requires a user session.
Thus, we recommend to not use this feature for applications which are supposed to be stateless and public.

Regular expressions are supported.

Note that cookies matching `^Marker_.*$` will never be stored as a
corresponding `allow` rule is generated to support `Session Expiration` features of the `SAML SP Realm`.

**Example**:

- `LANG.*`


# OAuth2AuthorizationServer_preProcess

Assign a step to apply custom pre-processing logic.

This pre-processing logic is executed on the `Authorization Path` and `Token Path`.

You may assign a chain of steps to build a flow.
The dispatching will continue when leaving this flow on the happy path.

For `On Success` exits this works automatically.

However, generic exits (i.e. `Additional Follow-up Steps` in `Generic Authentication Step`)
must be marked a _success exits_ by assigning the `Pre-Processing Done` pattern.


# NevisDetectServiceAccessBase_token

Propagate a token to the backend application. 
The token informs the application about the authenticated user.

Please assign a `NEVIS SecToken`. This is mandatory to have access to the Administration UI.

# NevisFIDODeployable_restrictAuthenticators

By default, all authenticators that fulfill the requirements given by the FIDO2 patterns are allowed.

Here you can restrict which authenticators are allowed based on metadata.

Select `enabled` here and provide the required metadata by configuring `Allowed Authenticators`.


# OAuth2AuthorizationServer_transitions

Add or overwrite `ResultCond` elements in the `AuthorizationServer` state. 

This setting is advanced. Use without proper know-how may lead to incorrect behavior.

If you use this setting, we recommend that you contact Nevis to discuss your use case. 

The position refers to the list of `Additional Follow-up Steps`. The position starts at 1.

Examples:

| `ResultCond`                | Position   |
|-----------------------------|------------|
| valid-token-request         | 1          |
| valid-authorization-request | 2          |

The following `ResultCond` elements cannot be overruled by this setting:

* `authenticate:valid-authorization-request`
* `stepup:valid-authorization-request`
* `server-error`
* `invalid-client` (configure `Invalid Client` instead)
* `invalid-redirect-uri` (configure `invalid Redirect URI` instead)
* `invalid-authorization-request` (configure `Invalid Authorization Request` instead)
* `invalid-token-request` (configure `Invalid Token Request` instead)


# HeaderCustomization_responseHeaders

Adds/overwrites HTTP headers in responses. 

The syntax is: `<header name>:<value>`

Force browser to use HTTPS only (1 day expiration):

```
Strict-Transport-Security: max-age=86400
```

Ensure pages are not cached:

```
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

Headers set by Apache (e.g. `Server`) cannot be overwritten.

Note: change the `Filter Phase` to set headers early / late.

# DeployableBase_instanceRenameDetection

During deployment nevisAdmin 4 checks if the instance has been renamed
by checking the last metadata file deployed on the target host given the pattern ID.

If instance rename is detected the current instance is stopped.

This check should be disabled if multiple environments are simulated on the same server.

This setting is relevant for classic VM deployment only.


# GenericNevisAuthSettings_javaOpts

Add additional entries to the JAVA_OPTS environment variable.

Use the expression `${instance}` for the instance name.

For instance, you may configure nevisAuth to create a heap dump on out of memory as follows:

```
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/opt/nevisauth/${instance}/log/
```

Be aware that this example will not work for Kubernetes
as the pod will be automatically restarted on out of memory
and the created heap dump files will be lost.


# JWTToken_algorithm

The following algorithms of JWT token are supported:

- `HS256` or `HS512`: compatible with `JWS` token type
- `RSA-OAEP-256`: compatible with `JWE` token type

# CustomRiskScoreWeightConfiguration_reputationWeight

Configuration of the risk score weight for the ip reputation analyzer's risk score.

# CustomAuthLogFile_auditSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the AUDIT SYS logs.

Note: not relevant when Log Targets is set to `default`.

# SamlToken_type

- `Assertion`: produces a `SAML Assertion`. 

Use for applications protected by Ninja.

- `Response`: produces a `SAML Response`. 

Use for applications which have their own SAML SP. 
Assign the `SAML SP Binding` pattern to the application and link this pattern there.

# Maintenance_path

Enter the base path under which the maintenance page will be hosted.

You usually don't have to change this configuration, unless the path clashes with any other hosted resources.

By default, `/maintenance/` is used.


# NevisMetaDeployable_authSignerTrustStore

Assign a Trust Store which is used to validate the signature of a received NEVIS SecToken.

There are 2 use cases which require validation:

- when a user accesses the `nevisMeta Web Console` the SecToken is signed using `NEVIS SecToken` / `Key Store`.
- when nevisAuth calls nevisMeta the SecToken is signed using `nevisAuth Instance` / `Internal SecToken Signer`.

If no pattern is assigned the trust store will be provided by nevisAdmin 4 automatic key management. 
However, this requires that automatic key management is used in the `NEVIS SecToken` and `nevisAuth Instance` patterns.

# SamlSpRealm_assertionConsumerService

Enter the path where SAML `Response` messages sent by the IDP shall be consumed.

This path also accepts `LogoutRequest` messages.

The IDP may send messages using POST or redirect binding.


# NevisDetectDatabase_jdbcDriver

Due to licensing, nevisDetect cannot ship the JDBC driver to connect to Oracle databases,
Therefore, those who want to use an Oracle database need to obtain and provide the Oracle JDBC driver on their own.

The `.jar` files can be downloaded from [Oracle](https://www.oracle.com/database/technologies/appdev/jdbc-downloads.html)

Uploading any other `.jar` files containing JDBC drivers is possible as well.


# NevisAuthRealm_logout

The default logout flow works as follows:

- the user accesses a protected application URL with query parameter `logout`, for instance `/myapp/?logout`
- any active session for this realm is terminated
- an HTML page is displayed that informs the user and allows to log in again on the same URL

To replace this behavior, assign a logout step here.

Note: to expose the logout function to the user, the web page(s) of backend applications should to be customized. 
Supported approaches are:

- Adapt the backend application: add a button or link that requests a URL ending with `?logout`.

Note that when this realm is used as a SAML IDP then the logout flow cannot be customized.
The only thing you can do is to assign a `Logout` pattern and configure a custom `Redirect`.
This is the location the user is redirect to after the SAML logout flow is done.


# NevisAuthRealm_labels

Labels are used to show text in the language of the user.

Which labels are used depends on the assigned steps.
Click `Download Default Labels` to retrieve the used labels and their translations.

Here you can overwrite the defaults and add your own translations or even add new labels,
which may be required when using a `Custom Login Template` or `Generic Authentication Step`.

Upload 1 file per language code. The file name should be `labels_<code>.properties`.
Check `Languages` on the `nevisAuth Instance` for enabled language codes.

The uploaded files **must** be UTF-8 encoded or special characters must be HTML encoded.

If you want to reuse existing `text_<code>.properties` and `LitDict_<code>.properties` files, 
you have to merge them first, or set `Translations Mode` to `separate`.

By default, the patterns add several default labels and the labels configured here are added on top. 
This is convenient as you only have to define labels that you want to add or overwrite.
However, this way you cannot remove labels. If you want to do that you have to set `Default Translations` to `disabled` 
and then only the uploaded labels will be used.

The default login template uses the following labels:
- `title` - used as browser page title
- `language.<code>` - used by language switch component

The default logout process of nevisAuth (which will be applied when no step is assigned to `Logout`)
has a confirmation GUI which uses the following labels:

- `logout.label` - header of the logout confirmation GUI
- `logout.text` - text shown to the user
- `continue.button.label` - label on the confirmation button


# HostContext_sessionResourceAccessRestriction

Assign an access restriction patterns to prevent unauthorized access to the REST interface
of the session resource.


# 8.2411.0

Full changelog:

[Patterns 8.2411.0 Release Notes - 2024-11-20](https://docs.nevis.net/nevisadmin4/release-notes#patterns-824110-release-notes---2024-11-20)

##### NevisProxy Observability pattern refactor

The `NevisProxy Observability` pattern was refactored:
- Renamed the `Trace Resource Service Name` parameter and moved to the `Basic Settings` tab. It now controls the `service.name` key-value pair resource attribute for both the Metrics and Trace. If the default value was overwritten, the new parameter needs to be set.
- New configuration options have been added, such as `Sampler`, `Deployment Environment`, etc.
- Removed the experimental label from the pattern.

##### Maintenance Page pattern improvements

- The `Maintenance Page` pattern now includes its sanitized name in the names of the generated `MaintenanceFilter` and `DefaultServlet`.
This prevents naming collisions, and allow linking several `Maintenance Page` patterns to a Virtual Host or an Application.
- The UpdateInterval is now configurable.

Check your configuration if you use a `Generic Application Settings` pattern or a `Generic Virtual Host Settings` pattern to customize your `MaintenanceFilter` or the related `DefaultServlet`.

##### Automatic migration

The `nevisadmin-plugin-nevisadapt` plugin was separated from the `nevisadmin-plugin-nevisdetect` plugin.
As a result, the class names are updated accordingly.

`nevisAdapt Instance` -> `Observation timeframe` was moved to its own pattern (`nevisAdapt Observation Cleanup Configuration`).
As a result (if `Observation timeframe` was not empty), the deprecated property has to be removed and the new pattern has to be generated for each instance to keep the configuration value.


# DatabaseBase_trustStore

Assign a trust store which provides the CA certificate of the DB endpoint.


# NevisIDMClient_clientExtId

External ID of the new client.


# BackendServiceAccessBase_backends

Enter the complete URLs (scheme, host, port and path) of the backend services. 

Note: 

- all URLs must use the same scheme and path.
- automatic path rewriting will be performed when the path differs from the `Frontend Path`.

In case you are setting multiple addresses, use `Load Balancing` to select a request dispatching strategy.

# NevisAdaptRememberMeConnectorStep_originalAuthenticationFlow

Set the first step of the full authentication flow to continue with in case no valid remember-me cookie was found:

- the remember-me cookie is not present in the headers
- the remember-me cookie is present but no longer valid
- the associated user is no longer active
- the browser fingerprint has changed

CAUTION: It will disable the remember-me functionality if you set it to the same step as the `On Success`.

# NevisIDMJmsQueues_truststore

You should add a CA certificate, and then use a `PEM Trust Store` to provide it. 

# CustomRiskScoreWeightConfiguration_deviceWeight

Configuration of the risk score weight for the device cookie analyzer's risk score.

# SamlSpIntegration_parameters

Define custom `init-params` for the nevisProxy `DelegationFilter`
which propagates the SAML Response to the backend.

This setting is experimental and may be adapted in future releases.

Examples:

- `DelegatePostPolicy: override` - create a new POST request and send it to the `Assertion Consumer Service Path`. 
The response is returned to the client which means that the original (GET) request is lost. However, the SP can redirect to the application. This mode should be preferred for proper SP integration.

- `DelegatePostPolicy: sidecall` - send a POST request to the `Assertion Consumer Service Path` but do not return the response to the client. 
Afterwards, the original (GET) request is sent. This mode may be required in case the response of the POST request does not redirect to the application.

# NevisIDMURLTicketConsume_idm

Assign a `nevisIDM Instance` or `nevisIDM Connector`.

# OAuth2AuthorizationServer_properties

Configure properties of the nevisAuth `AuthorizationServer`.

**Add** or **overwrite** properties by entering a value.

**Remove** properties generated by this pattern by leaving the value empty.

Examples:

| Key                           | Value   |
|-------------------------------|---------|
| propagationScope              | session |
| nevismeta.blockClientInterval | 600     |


# NevisFIDODeployable_addons

Assign add-on patterns to customize the configuration of nevisFIDO.


# GenericSocialLogin_redirectURI

The callback URI to go to after a successful login with the social account.

This will create an endpoint in your host config. 

The URL will be a combination of the `Frontend Address` of the `Virtual Host` and the value configured here.
For example, let's assume that you have configured:

- Return Path: `/oidc/app/`
- Frontend Address: `https://nevis.net`

Then the URL will be `https://nevis.net/oidc/app/`.

Use the `exact:` prefix to use the given path as-is.
Without this prefix a normal mapping with `/*` will be generated and thus sub-paths will be accessible as well.


# SamlSpConnector_encryptionCert

Assign a pattern to configure the certificate to encrypt the outgoing message to the service provider.

# NevisIDMChangePassword_lockWarn

Assign an authentication step to execute when the status of the URL ticket or credential is **lockWarn**.


# GenericAuthRealm_authStatesFile

Upload an XML file containing `AuthState` elements.

Upload of a complete `esauth4.xml` is **not** supported.

The `Domain` element is optional.

- If missing the element will be created. The `Entry` methods
  `authenticate` and `stepup` will be set to the first provided `AuthState`.
  The method `logout` is not set and thus the nevisAuth default behaviour applies.

- If provided the `Domain` must come before all `AuthState` elements.
  The attributes `name` and `default` are not supported and should be omitted.
  Attributes are sorted by name. The `Entry` elements are sorted by `method`.

The `AuthState` linked to `stepup` should be able to dispatch the request.
For instance, you may have assigned an `Authorization Policy` to your application(s)
and thus you need a state which decides based on the request variable `requiredRoles`.

The following example dispatches level `2` into an `AuthState` named `TAN`
which provides authentication via mTAN:

```
<AuthState name="EntryDispatcher" class="ch.nevis.esauth.auth.states.standard.ConditionalDispatcherState" final="false">
    <ResultCond name="nomatch" next="Authentication_Done"/>
    <ResultCond name="level2" next="TAN"/> <!-- TAN state is expecetd to set authLevel="2" -->
    <Response value="AUTH_ERROR">
        <Arg name="ch.nevis.isiweb4.response.status" value="403"/>
    </Response>
    <property name="condition:level2" value="${request:requiredRoles:^2.*$:true}"/>
</AuthState>
```

The following expressions are supported:

- `${instance}`: name of the nevisAuth instance
- `${request_url}`: generates a nevisAuth expression which returns the URL of the current request
- `${realm}`: name of the Realm (see below)
- `${keystore}`: name of the `KeyStore` element provided by this pattern. Assign a pattern to `Key Objects` to add a `KeyObject` into this `KeyStore`.

The `name` of `AuthState` elements is prefixed
with the sanitized name of the Realm (referred to as `${realm}`).

The realm prefix must be added when using `propertyRef` to reference AuthStates
generated by other patterns (e.g. `<propertyRef name="${realm}_SomeState"/>`).

An exception is the AuthState which defines the nevisIDM connection
(as generated by `nevisIdm Password Login` or `nevisIDM Connector for Generic Authentication`).
Here the `propertyRef` must be defined as follows:

`<propertyRef name="nevisIDM_Connector"/>`

This pattern does not validate that labels are translated.
Translations can be provided on the `Authentication Realm` pattern.

# OAuth2AuthorizationServer_realm

Assign a realm which shall be exposed as an OAuth2 Authorization Server or OpenID Connect Provider.

# TCPSettings_connectTimeout

Timeout for establishing the TCP connection.

# NevisProxyObservabilitySettings_resourceServiceName

Configure the `service.name` key-value pair resource attribute.

# SamlSpConnector_sessionIndex

Set current session ID to SAML Response in `SessionIndex` element.
This element is required for IDP-initiated logout and SP-initiated logout when Logout Type is set to `SOAP`.

The element will be included in SAML Response like:
```
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response Destination=... >
	...
	<saml2:Assertion ID=...>
		...
		<saml2:AuthnStatement SessionIndex="JeBKZSJah-0m2QjC4LJ8u74LUOY2ayAeenlPgBOx1N8" ... >
            ...
		</saml2:AuthnStatement>
	</saml2:Assertion>
</saml2p:Response>
```

And in SAML LogoutRequest, the SessionIndex element will be included like:
```
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:LogoutRequest Destination=...>
    ...
	<saml2p:SessionIndex>JeBKZSJah-0m2QjC4LJ8u74LUOY2ayAeenlPgBOx1N8</saml2p:SessionIndex>
</saml2p:LogoutRequest>
```

# GenericNevisLogrendSettings_javaOpts

Add additional entries to the JAVA_OPTS environment variable.

Use the expression `${instance}` for the instance name.

For instance, you may configure nevisLogrend to create a heap dump on out of memory as follows:

```
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/opt/nevislogrend/${instance}/log/
```

Be aware that this example will not work for Kubernetes
as the pod will be automatically restarted on out of memory
and the created heap dump files will be lost.


# LdapLogin_properties

Set custom properties for the 
[UseridPasswordAuthenticateState](https://docs.nevis.net/nevisauth/setup-and-configuration/authentication-plugins-and-authstates/ldap-authentication-authstates/useridpasswordauthenticatestate). 

Examples:

```
searchSizeLimit = 512
```

# LogSettingsBase_logLevel

Change the level of the root logger.
This impacts all logging apart from `Log Levels`.

Note that Syslog appenders have a threshold which ensures 
that only `INFO`, `WARN`, or `ERROR` messages are forwarded.


# NevisAuthDeployable_sessionIndexingAttribute

Enter the name of a session variable for the session index.


# FIDO2Onboarding_failedScreenButton

Configure to add a dispatcher button to the failed screen.

The button may have a special `Button Name` to render in a nice way by a customized `Login Template`.

For instance, Identity Cloud uses this mechanism to add a button which looks like a back arrow.
This button takes the user to a previous step.

This is an advanced setting. Use only when you understand the concept.


# GenericIngressSettings_caSecret

Enter the name of the Kubernetes secret which contains the CA certificate in the key `ca.crt`. If the secret does not exist it will result in `403 (Forbidden)`, and with a missing `ca.crt` key
the feature will not be enabled.

Can be created with:
`kubectl create secret generic ca-secret --from-file=ca.crt=ca.crt`

The `ca.crt` file can contain multiple certificates.

# NevisIDMDeployable_encryptionFallback

Initialization vector ("iv") fallback mechanism

This must be set to true for customers who previously had no value set for
`security.properties.key` / `propertiesKey` (old name) in the properties file
*and* had encrypted values already stored in the database. Otherwise, the old
values encrypted by default value will not be readable. If the database does not
contain encrypted properties or unused URL tickets, it is safe to leave this
turned off, and it is adviced to be turned off for stronger security.

# NevisFIDODeployable_deepLinkAppHost

If you have uploaded any `Deep Link App Files`, then assign a `Virtual Host`.

The files will be hosted with a base path of `/.well-known/`.

The domain of the `Deep Link` must point to this `Virtual Host`.

If the user does not have the mobile app installed,
the `Deep Link` will be opened in the browser instead.


# NevisIDMCheckUserCredentials_credentialTypesToCheck

Credential types which existence for the user should be checked.

Possible values:

* `PASSWORD`
* `CERTIFICATE`
* `SECURID`
* `TICKET`
* `SAFEWORDUSER`
* `OTP`
* `TEMPSTRONGPASSWORD`
* `GENERIC`
* `KERBEROS`
* `MTAN`
* `VASCO`
* `PUK`
* `URLTICKET`
* `DEVICEPASSWORD`
* `MOBILESIGNATURE`
* `SAMLFEDERATION`
* `SECURITYQUESTIONS`
* `CONTEXTPASSWORD`
* `OATH`
* `FIDO_UAF`
* `RECOVERY_CODE`
* `FIDO2`

# NevisMetaRESTServiceAccess_backendTrustStore

Assign the Trust Store provider for outbound TLS connections.
If no pattern is assigned a trust store will be provided by the nevisAdmin 4 PKI.

# LdapLogin_subtreeSearch

If `disabled` all the users to authenticate must be in the same directory node, 
specified in the properties `Base DN` and `User Attribute`. 
In this case nevisAuth uses the user's account to authenticate against the LDAP directory.

If `enabled` a search query for the user is performed, with the specified `Base DN`.

# NevisFIDODeployable_username

Configure what is expected as `username` in incoming API calls.

Choose between `extId` and `loginId`.


# NevisAuthConnector_url

Enter `hostname:port` of the nevisAuth instance.

# UserInput_greeting

Enter a text or _litdict key_ to be displayed in a line below the title.

The text should inform the user what has to be entered in this form.


# NevisIDMChangePassword_clientNotFound

Assign an authentication step to execute when the status of the URL ticket or credential is **clientNotFound**.


# NevisMetaConnector_url

Enter `hostname:port` of the nevisMeta instance.

# NevisFIDODeployable_signerTrustStore

Assign the Trust Store provider for SecToken verification.

# NevisDetectDatabase_user

Enter the user for the DB connection.


# NevisAdaptFeedbackConfig_tokenLifetime

Set the maximum lifetime for the feedback token.

# CustomProxyLogFile_serverLog

Select if only log file should be used or if statements should also be forwarded to syslog.

This property is relevant for classic VM deployments only. In Kubernetes the main logs are written to system out so that log messages appear in the docker logs.

Choose between:

- `default` - log to a file
- `default + syslog` - log to a file and forward to syslog
- `syslog` - forward to syslog only. The syslog facility is `localhost3` and the threshold is `INFO`.

# SwissPhoneChannel_sender

The sender phone number to use to transmit the SMS.


# SamlResponseConsumer_postProcess

Assign a step to apply custom post-processing logic,
e.g. to enrich the authenticated user.

# NevisIDMUserCreate_optionalAttributes

Define which attributes are optional and how to provide them.

Example:

```
firstName: ${sess:given_name}
name: ${sess:family_name}
country: ${sess:country}
```

# NevisDetectDeployableBase_logging

Assign `nevisDetect Log Settings` to change the log configuration.


# SamlSpConnector_outEncrypt

Select a part of the outgoing message going to be encrypted from the service provider.

# AutomaticTrustStoreProvider_keystore

Assign one or multiple `Automatic Key Store` patterns to establish a trust relation.

# GenericThirdPartyRealm_rolesFilter

Define the filter that shall be application to applications
to enforce the presence of certain roles.

The following expressions may be used:

- `${realm.id}` - unique ID of this realm pattern
- `${realm.name}` - name of this realm pattern
- `${auth.servlet}` - name of the servlet of the `Authentication Application`. May be used to perform a side-call.
- `${filter.name}` - a proposed filter name calculated from the required roles
- `*{roles}` - duplicates the entire line once for each role

# NevisIDMUserUpdate_allowOverwrite

If `enabled`, the attribute or property will be stored even when there already is a stored value.

If `disabled`, the stored value remains unchanged in this case.


# CustomRiskScoreWeightConfiguration_countryWeight

Configuration of the risk score weight for the suspicious country analyzer's risk score.

# OAuth2AuthorizationServer_host

Assign a `Virtual Host` which shall serve as entry point.

# NevisProxyObservabilitySettings_sampler

Configures the available head sampling methods. Possible values are:

- **AlwaysOn**: Samples every trace. With high traffic in a production application it may cause significant overhead.
- **AlwaysOff**: Samples no traces. NevisProxy still generates the spanID for internal trace ID.
- **TraceIdRatio:<ratio>**: Samples a given fraction of traces based on the configured `ratio`.
- **ParentBased:<delegate_sampler>**: Makes the decision based on the parent of the span. If the span has a parent, the sampler flag of the parent span will decide.
  If there is no parent span, the delegate sampler is used, that can be any of the samplers above.

# SamlSpRealm_labels

Labels are used to provide human-readable text in the language of the user.
Here you can overwrite the defaults and add your own translations.

The name of uploaded files must end with the language code.
As the format is compatible you may upload existing `text_<code>.properties` files of nevisLogrend 
or `LitDict_<code>.properties` of nevisAuth.

The encoding of uploaded files does not matter as long as all translations are HTML encoded.

So far this property is relevant only if the `Logout Reminder` feature is enabled
because then a page will be rendered. The following labels are used:

- `title` - used as browser page title
- `logout.text`
- `language.<code>` - used by language switch component
- `info.logout.reminder`
- `continue.button.label`

# NevisProxyDatabase_path

Enter the path where the local session store shall be exposed and accessed by the nevisProxy peer.


# GenericServiceSettings_removeFilterMappings

Remove `<filter-mapping>` elements generated by other patterns.

The syntax is a map of `<filter-name>:<url-pattern>`, according to elements from the `web.xml`.

In the `<filter-name>` the expressions `${service.name}` and `${realm.name}` may be used.

For applications which have only 1 frontend path you may use `${service.mapping}` instead of `<url-pattern>`.

Examples:

```
ModSecurity_${service.name}:${service.mapping}
Authentication_${realm.name}:${service.mapping}
```

# NevisDetectDeployableBase_addons

Assign an add-on pattern to customize the configuration.

# WebApplicationAccess_csrf

_Cross-Site Request Forgery_ (_CSRF_) is an attack to force an authenticated user to send unwanted requests.

- `off (default)` - no CSRF protection. Recommended for applications which may be called from other sites.
- `header-based` - `GET` and `HEAD` requests are allowed (assumption: these methods must not manipulate server-side state). 
For other requests the `Referer` and `Origin` headers must match the `Host` header.

# GenericSocialLogin_clientId

The identifier provided by the social account when you register with it as the IdP service.

# AuthCloudBase_accessKeysJson

Upload the `access-keys.json` of your Authentication Cloud instance.

The file contains the instance name and an access key.

You can download this file from the [NEVIS Authentication Cloud Console](https://docs.nevis.net/authcloud/access-app/management-console).

Check [Integrate Authentication Cloud with nevisAdmin 4](https://docs.nevis.net/authcloud/integrations/identity-suite-integration/integrate-with-nevisadmin-4) for setup instructions.


# NevisProxyDeployable_passwordGetter

Choose between:

- `recommended`: uses `nevisadmin` for Kubernetes and classic deployments.
The recommended value may change in future releases.

- `nevisadmin`: uses a script deployed by nevisAdmin. Does not work for PKCS11.

- `nevisproxy`: uses `/opt/nevisproxy/bin/keystorepwget` to lookup passwords for encrypted key material. 
Requires nevisProxy version `4.4` or later. 
Does not support lookup of the password for the `key.pem` of `PEM Key Store`.

- `neviskeybox`: uses `/opt/neviskeybox/bin/keystorepwget` to lookup passwords for encrypted key material. 
nevisKeybox must be installed on the target system. 
Does not work in Kubernetes deployments.

# NevisAdaptDeployable_database

Add a database connection reference pattern.

Required properties to be set in the connector pattern are as follows:
- JDBC Driver (Oracle or MariaDB)
- JDBC URL
- DB user/password


# NevisIDMPasswordLogin_policyName

Enter the name of a nevisIDM URL Ticket policy to use for the URL Ticket 
that is created at the beginning of the password reset process.

If nothing is configured here the default URL Ticket policy will be used.

Among others, the policy defines how the link is communicated to the user 
(e.g. by sending an email) and sets the expiration.

You can create additional policies via the nevisIDM Admin GUI or via SOAP / REST API.

# NevisIDMChangePassword_showGUI

Sets if the authState's GUI should be rendered, default is `enabled`.

If not set or set to `disabled`, the GUI will not be rendered, making `New Password` setting mandatory. 
`Current Password` and `New Password Confirmation` settings may also be required, depending on other settings.

# PropertiesTestPattern_patternReferenceProperty

Reference one of the allowed patterns.

# NevisFIDODeployable_port

Enter the port for the HTTPS endpoint.


# NevisAdaptAuthenticationConnectorStep_profile

The profile used during processing the results of the analysis done by the nevisAdapt service.

There are 2 ways to react on the returned values:
* React on the returned events directly
* React based on the calculated weighted sum of the risk scores

Supported values are:
* `balanced` - balanced risk profile
* `strict` - strict risk profile with higher weights
* `custom` - to define own weights for the risk profile
* `events` - react on the returned events instead of the risk scores

You can find more information about the [Risk profiles](https://docs.nevis.net/nevisadapt/Integration-with-other-Nevis-components/nevisAuth-direct-integration/NevisAdaptAuthState/Profiles/Risk-weight-profiles) in the documentation.


# GenericAuthenticationStep_entryState

Define the `name` of the first `AuthState`.

If not set the sanitized name of the pattern will be used.

The XML must contain an `AuthState` which has this name set,
or one that uses the expression `${state.entry}` for the name.

# CustomRiskScoreWeightConfiguration_velocityWeight

Configuration of the risk score weight for the ip velocity analyzer's risk score.

# UserInformation_buttonType

Adds a button to the GUI:

- `none` - no button is added
- `submit` - adds a submit button. To continue with `On Submit` the `Message Type` must be `warning` or `info`.
- `cancel` - adds a cancel button. The button restarts the authentication flow from the beginning. The flow must be reentrant.

# GenericServiceSettings_servlets

Configure `servlet` and/or `servlet-mapping` elements
using the XML constructs described in the nevisProxy Technical Documentation.

You may **add** new elements or **customize** elements provided by other patterns.

- Reference a `servlet` by setting `servlet-name`. Use `Connector_${service.name}`for the servlet which connects to the backend application.
- Reference a `servlet-mapping` by setting `url-pattern`.

In Kubernetes side-by-side deployment a postfix is added to service names. 
Use the expression `${service.postfix}` connecting to a service deployed against the same inventory.

Example 1: Add or overwrite an `init-param`:

Enable load-balancing when there are multiple backend servers.

```xml
<servlet>
  <servlet-name>Connector_${service.name}</servlet-name>
  <init-param>
    <param-name>LoadBalancing</param-name>
    <param-value>true</param-value>
  </init-param>
</servlet>
```

Instruct nevisProxy to a add `Content-Type` header when missing.

```xml
<servlet>
  <servlet-name>Connector_${service.name}</servlet-name>
  <init-param>
    <param-name>ProxyPolicy</param-name>
    <param-value>mime-completion</param-value>
  </init-param>
</servlet>
```

Example 2: Remove an `init-param` (no `param-value` provided):

```xml
<servlet>
  <servlet-name>Connector_${service.name}</servlet-name>
  <init-param>
    <param-name>CookieManager</param-name>
  </init-param>
</servlet>
```

Example 3: Change the `servlet-mapping` for an application to use a different servlet 
by changing `servlet-name`.

```xml
<servlet>
   <servlet-name>Connector_Conditional_${service.name}</servlet-name>
   <servlet-class>ch::nevis::isiweb4::servlet::mapping::ServletMappingServlet</servlet-class>
   ...
</servlet>
<servlet-mapping>
   <servlet-name>Connector_Conditional_${service.name}</servlet-name>
   <url-pattern>${service.path}/*</url-pattern>
</servlet-mapping>
```

Removing `servlet` or `servlet-mapping` elements is not supported.

# GenericAuthRealm_parameters

Define _Template Parameters_.

Examples:

```yaml
smtp: smtp.siven.ch
sender: noreply@siven.ch
```

These parameters can be used in your `Configuration`.

The expression formats are:

`${param.<name>}`:

- `name` found: parameter value is used.
- `name` missing: expression is **not** replaced.

`${param.<name>:<default value>}`:

- `name` found: parameter value is used.
- `name` missing: default value will be used.

In `<default value>` the character `}` must be escaped as `\}`.

# NevisProxyObservabilitySettings_metricsExporterAddress

Enter the target URL (`host:port`) of the backend services to which the exporter is going to send metrics.
The `/v1/metrics` path is automatically attached to it.


# NevisDPLogSettings_serverSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# SamlSpConnector_roles

Check for required roles.

Roles provided by nevisIDM have the following format: `<applicationName>.<roleName>`.
Roles provided by other systems (e.g. LDAP) may have a different format.

Examples:

```
myApp.Admin
```

Required roles are always checked at the end of authentication, 
after enforcing the `Minimum Required Authentication Level` (optional).

The user must have any of the enter roles to continue.

If the user does not have any of these roles,
the authentication will fail and a SAML `Response`
with status `AuthnFailed` message will be returned to the SP.

If you want to do custom error handling (e.g. show a GUI to the user), 
assign a step to `On Forbidden`.


# GroovyScriptStep_customSteps

Assign follow-up steps.

For each step a _transition_ (called `ResultCond` in `esauth4.xml`) is added.
The name of the transition depends on the position in the list.

For instance, if 2 steps are assigned the following _transitions_ will be added:

- `exit.1`
- `exit.2` 

The Groovy script may trigger a certain transition by calling the method `response.setResult` 
handing over the name of the transition.

Example:

```
response.setResult('exit.1')
```

# SamlSpRealm_authParams

Add custom `init-param` elements to **each** `IdentityCreationFilter`
generated by this pattern.

This pattern generates 2 `IdentityCreationFilter` elements:

1. `Authentication_<name>`: enforces authentication for applications.
2. `SAML_<name>`: provides the `Assertion Consumer Service` and `Session Upgrade Path`

If you want to patch only one of these filters 
consider using `Generic Application Settings` instead.

Note that the parameter `InterceptionRedirect` of the `SAML_<name>` filter
is forced to `never`. If you configure `InterceptionRedirect` here
it will be ignored for this filter as leads to message loss in SAML POST binding.

Examples:

- `BodyReadSize = 64000`

# NevisIDMProperty_propertyName

Enter `name` for the property definition file.

Technical name of the property. The name has to be unique among the properties of the same scope and within the same
client.

# NevisFIDODeployable_link

Choose between:

- `Deep Link`: configures nevisFIDO to use a _deep link_ (recommended).
- `Custom URI`: configures nevisFIDO to use a _custom URI link_.
- `undefined`: this pattern won't generate any link dispatcher configuration.

Deep links are harder to set up but more recommended as they offer a better user experience.

Nevis recommends using Custom URI links in mobile only scenarios only.
The end-user is always expected to click a link on the same phone as the Access App is running on.

Note: the selected type here and the corresponding URI/URL must be communicated 
when [Ordering an Access App](https://docs.nevis.net/nevisaccessapp/ordering-an-access-app#2-deep-link-domain--customer-uri-scheme-with-x-callback-url-support).

Further information about deep links and custom URI links can be found in the related settings.


# NevisAdaptAuthenticationConnectorStep_customRiskScoreWeightConfiguration

Custom risk score weight configuration for the calculation. Set the weights to be considered for each risk score analyzer.

Analyzer list:
- Suspicious country
- Device cookie
- Fingerprint
- IP
- IP location
- IP velocity
- IP reputation

# ServiceMappingReport

<p>This report lists the applications of this project, how they are protected by a realm, and which filters are applied.</p>
<table>
    <thead>
    <tr>
        <th>Frontend Address</th>
        <th>Backend Address</th>
        <th>Virtual Host</th>
        <th>Application</th>
        <th>Realm</th>
        <th>Filter Chain</th>
        <th>nevisProxy Instance</th>
        <th>Deployment Target</th>
    </tr>
    </thead>
    <tbody>
{{#.}}
{{#addressMappings}}
        <tr>
            <td><a href="{{frontendAddress}}">{{frontendAddress}}</a></td>
            {{#backendAddress}}
            <td><a href="{{backendAddress}}">{{backendAddress}}</a></td>
            {{/backendAddress}}
            {{^backendAddress}}
            <td>n/a</td>
            {{/backendAddress}}
            <td><a href="pattern://{{hostContextId}}">{{hostContextName}}</a></td>
            <td><a href="pattern://{{serviceId}}">{{serviceName}}</a></td>
            <td><a href="pattern://{{realmId}}">{{realmName}}</a></td>
            <td>{{{filters}}}</td>
            <td><a href="pattern://{{deployableId}}">{{deployableName}}</a></td>
            <td>{{targetHost}}</td>
        </tr>
{{/addressMappings}}
{{/.}}
    </tbody>
</table>


# JSONResponse_onContinue

This exit will be taken when `Response Type` is set to `AUTH_CONTINUE` and the next request is received.


# NevisDetectAuthenticationConnectorStep_jmsClientKeyStore

Used when simple or mutual (2-way) HTTPs is configured.
If no pattern is assigned here automatic key management will provide the key store.

# CustomProxyLogFile_logLevel

Sets the base log level of nevisProxy.

The level will be applied to `BC.Tracer.ThresholdBase` as follows:

- `ERROR`: `3`
- `NOTICE`: `5`
- `INFO`: `6`
- `DEBUG`: `7`
- `DEBUG_HIGH`: `9`
- `TRACE`: `10`

Note that if you only change log levels nevisProxy won't be restarted during deployment.
The new configuration will be activated within 60 seconds.

# SamlSpRealm_spLogoutTarget

Enter a path or URL to redirect to when an SP-initiated SAML logout completes on this SP.

The redirect is performed only when `Logout Mode` is set to `redirect-target`.

# AuthorizationPolicy_forbiddenRolesMode

The `Forbidden Roles Mode` defines which `Forbidden Roles` are set for the current paths.

When combining several `Authorization Policy` patterns for an application, this setting allow inheriting the `Forbidden Roles` from a more general pattern.

Choose one of:
- `self-contained`: The `Forbidden Roles` defined in this pattern are applied to the current paths. They override any `Forbidden Roles` set on parent paths. If no `Forbidden Roles` are set in the current pattern, no forbidden roles will be enforced for the current paths.
- `inherited`: The `Forbidden Roles` in this pattern is not used. Use this setting if you have another `Authorization Policy` pattern applied to a parent path to inherit the configuration from. For the `Forbidden Roles` to be inherited from a particular parent, this setting has to be set to `default (self-contained)` in the parent pattern (otherwise you may inherit a value from a grandparent).


# JSONResponse_code

Enter an appropriate status code for the HTTP response.
If not set the code will be set based on the selected `Response Type`:

- `AUTH_ERROR`: `401`
- `AUTH_DONE`: `200`

# OutOfBandMobileAuthStepBase_level

Set an authentication level to apply when authentication is successful. 

The level is relevant only if there are is an `Authorization Policy` assigned to applications.


# NevisIDMUserLookup_clientInput

Enable this to allow the user to enter the name of the _Client_ (tenant) when logging in to nevisIDM.

If `disabled`, the input field is not shown and the Client `Default` is used.

# NevisFIDODeployable_deviceServiceTimeout

Defines the maximum time difference that is accepted between the time in the `creationTime` attribute 
in device service requests and the time when the server processes the request. 

This value is close to the time drift that is accepted between the mobile device clock and the server clock. 
If the time drift is bigger than this value, the operation will fail.

The default value is 5 minutes. If no time unit is provided, seconds will be used.


# NevisIDMChangePassword_tmpLocked

Assign an authentication step to execute when the status of the URL ticket or credential is **tmpLocked**.


# JWTToken_kid

The `kid` (key ID) Header Parameter is a hint indicating which key
was used to secure the JWS. This parameter allows originators to
explicitly signal a change of key to recipients.

When used with a JWK, the `kid` value is used to match a JWK `kid`
parameter value.

For reference, please consult [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515).

# SamlIdp_metadataServicePath

Enter a path where the _SAML Metadata Service_ shall be exposed
on the assigned `Virtual Host`.

# FIDO2StepBase_fido

Assign a `nevisFIDO FIDO2 Instance`.


# NevisIDMPasswordLogin_unitAttributes

Enter unit attributes to fetch from nevisIDM.
Enter 1 attribute per line.

The following unit attributes are supported:

- extId, state, name
- displayName, displayAbbreviation, location, description, hname, localizedHname
- ctlCreDat, ctlCreUid, ctlModDat, ctlModUid


# LdapLogin_onPasswordExpired

Assign a pattern which defines the step that is executed
when the user must change his password.

If no pattern is assigned the next AuthState is `Authentication_Failed`
which terminates the authentication process.

# NevisAdaptDeployable_ipToLocationUpload

Provide a file attachment for the IP-to-Location service to use.

**Please consider uploading the file manually if its size exceeds 20MB, then adjust the path
`ipToLocationMappingFile` in *nevisadapt.properties* after deployment if needed.**

With file upload, only the IP-Country database is supported, with fields listed as follows (CC is the 
2-letter country code, no header row):

`"IP range min (decimal)","IP range max (decimal)","CC","COUNTRY"`

The file must adhere to the following formatting rules: all fields must be separated by 
commas and surrounded by double-quotes. The IP ranges should not intersect each other.
File name must end with either .csv or .CSV.

If IP velocity analysis is required, it is handled through IP2LOCATION updates. No other provider is supported at this point. Please switch to either `DB5BIN` or `DB5LITEBIN`.

The IP-mapping file has to be updated regularly for the service to stay relevant.

Uploaded files are *not* updated by default.

We recommend [setting up periodic update of IP geolocation and reputation mappings](https://docs.nevis.net/nevisadapt/Installation-of-nevisAdapt/Setting-up-periodic-update-of-IP-geolocation-and-reputation-mappings).


# CSRFProtectionSettings_headerBased

CSRF protection can be obstructive for some cross-domain use cases 
(e.g. federation or providing a public REST API).

# OAuth2Client_email

Set to `allowed` to allow this client to request the scope `email`.

This scope produces a claim `email`.

# ErrorHandler_keepHeaderStatusCodes

By default, HTTP headers are dropped when an error code is handled.

This avoids _information leakage_ but can lead to _session loss_ in some cases.

For instance, the nevisProxy session will be lost when all of the following holds:

- this pattern is configured to handle code `502`.
- the application is unreachable (`502` is produced).
- the nevisProxy session cookie is _renegotiated_ (`Set-Cookie` header is set).
- user refreshes the page after the error page is shown.

To overcome this limitation you may enter `502` here.

Note that we are investigating additional measures 
and may adapt this property in future releases.

# NevisIDMPasswordLogin_finalRedirect

Where to redirect to once the password reset is successfully completed.

See the "Email Sent Redirect" property for more information about the possible values.

Note that in this case, `referrer` can be very useful as it will redirect the client straight
to the page he initially wanted to access before he started the password forgotten process.


# FrontendKerberosLogin_keyTabFilePath

Enter the path of the Kerberos keytab file.

The path must exist on the target host(s) of the `nevisAuth Instance`.

This configuration is ignored when keytab file(s) are uploaded via `Keytab File`.

In complex setups with multiple `Kerberos Realms` and/or `Frontend Addresses` 
you may want to enter multiple keytab file paths.

# Dispatcher_defaultStep

Assign the step to continue with if no transition matches.

# HostContext_additionalStatusCodes

Allow non-standard HTTP status codes. 

The configuration of additional status codes is required, for example, when using WebDav 
(HTTP status code `207` is used by WebDav).

# ServiceAccessBase_truststore

Optional setting for enabling trust to HTTPS backends.

For securing production environments:
- set `Backend Addresses` starting with `https://`
- assign a `Trust Store` pattern containing the certificates required for verifying the backend certificate
- set `Hostname Validation` to `enabled`


# NevisAdaptRememberMeConnectorStep_onSuccess

Decides what to do if the remember-me token is present and valid. Leave empty for skipping to the end of the authentication flow immediately.

CAUTION: It will disable the remember-me functionality if you set it to the same step as the `Original Authentication Flow`.

# GenericHostContextSettings_mimeMappings

Set or replace `mime-mapping` elements.

Examples:

```
<mime-mapping>
    <extension>svg</extension>
    <mime-type>image/svg+xml</mime-type>
</mime-mapping>
```

The `mime-mapping` elements affect the entire `Virtual Host`
and are used use to determine the `Content-Type` for responses.

nevisProxy always sets a `Content-Type` header 
for static resources served by the `Virtual Host`.

Further, nevisProxy can add a `Content-Type` header for resources served by applications.
To enable this advanced feature assign `Generic Application Settings` to the application
and set the parameter `ProxyPolicy` to `mime-completion`.

# ResponseRewritingSettings_responseBodyContentTypes

Enter regular expressions to match the `Content-Type`
of responses. If the expression matches, the response body is rewritten.

# CustomRiskScoreWeightConfiguration_ipWeight

Configuration of the risk score weight for the ip analyzer's risk score.

# RESTServiceAccess_jsonValidation

Choose between:

- `enabled` - **all** requests which have a request body must be valid JSON.
- `log only` - similar to `enabled` but violations are not blocked, only logged.  
- `content-type` - validation is performed only when the `Content-Type` header matches `application/json`.
- `disabled`



# NevisAuthDeployable_clientAuth

Enable to enforce 2-way TLS on the nevisAuth HTTPs endpoint. 

This means that callers (e.g. nevisProxy or technical clients accessing nevisAuth REST APIs) must present a client certificate.

The `Frontend Trust Store` must contain the issuing CA.

# CustomAuthLogFile_maxFileSize

Maximum allowed file size (in bytes) before rolling over. 

Suffixes "KB", "MB" and "GB" are allowed. 10KB = 10240 bytes, etc.

Note: not relevant when rotation type is `time`.

# NevisIDMPasswordCreate_showPolicyViolations

If set to `enabled` then after failed credential creation displays violated policies.

# NevisAdaptDeployableBase_keyStore

Used when simple or mutual (2-way) HTTPs is configured.
If no pattern is assigned here automatic key management will provide the key store.

# NevisMetaDeployable_port

Port the nevisMeta instance is listening on.

# TLSSettings_ciphers

The value configured here will be applied as `SSLCipherSuite`.

Check the [Apache Documentation](http://httpd.apache.org/docs/current/mod/mod_ssl.html#sslciphersuite) for details.

If empty and when this pattern is assigned to a `Virtual Host` the following value is used:

`ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256`

If empty and when this pattern is assigned to an application, default `SSLCipherSuites` from nevisProxy are applied.
Check the [nevisProxy Technical Documentation](https://docs.nevis.net/nevisproxy/Configuration/Servlets/HttpsConnectorServlet) for details.


# NevisIDMConnectorAddon_genericAuthPatterns

Any generic Auth pattern that should have access to the generated `AuthState`.


# 7.2402.0

Full changelog:

[Patterns 7.2402.0 Release Notes - 2024-02-21](https://docs.nevis.net/nevisadmin4/release-notes#patterns-724020-release-notes---2024-02-21)

##### Changes to init-params in nevisProxy

The latest nevisProxy release has breaking changes which affect several init-params.

Examples:

- `AutoRewrite` of `Http(s)ConnectorServlet`
- `RenewIdentification` of `IdentityCreationFilter`

You may have to adapt your configuration if you are using `Generic Virtual Host Settings`
or `Generic Application Settings` to add or patch servlets or filters.

Check the release notes of nevisProxy for further information.

##### Removed Virtual Host Observability Settings pattern

The `Virtual Host Observability Settings` has been removed. 
Due to the refactoring of the OpenTelemetry integration in nevisProxy, the configuration now applies to the whole instance.

##### Modified TLS Encryption setting in NevisIDM pattern
Possible value `enabled` is removed and new more fine graded value of 'trust', 'verify-ca' and 'verify-full' are added.

# NevisAdaptDeployable_ipToLocationFileSelector

**Set a file code only if the provider is IP2LOCATION or MaxMind and also set the access token in that case.**

Provide a file code that identifies the database file to be downloaded.

The supported values are:
* `upload` - no update mechanism will be in place for custom uploads by default. Must be *.csv/*.CSV, up to 20MB.
* `DB1BIN` - commercial version, IP-Country
* `DB1BINLITE` - free version, IP-Country
* `DB5BIN` - commercial version, IP-Country-City-GPS
* `DB5BINLITE` - free version, IP-Country-City-GPS
* `Geo2-City` - MaxMind GeoIP2 City Database
* `GeoLite2-City` - free version of the MaxMind GeoIP2 City Database

nevisAdapt doesn't provide any access token by default. They have to be generated after registration (in case of the commercial version, purchase).

You can find more information about the supported geolocation databases at the [IP2LOCATION](https://www.ip2location.com/database/ip2location) and [MaxMind](https://www.maxmind.com/en/geoip2-services-and-databases) websites.


# HostContext_qosConfiguration

nevisProxy uses the [mod_qos](http://mod-qos.sourceforge.net/) module 
to ensure quality of service (QoS). Choose between:

- `off`: the module is disabled on this virtual host.
- `standard`: provides a default configuration which protects against common denial of service (DoS) attacks.
- `custom`: configure `Generic mod_qos Configuration` via `Additional Settings`.

# NevisIDMPasswordLogin_unitProperties

Enter unit properties to fetch from nevisIDM.
Enter 1 property per line.

The properties must have scope onUnitGlobal.
The property name must be exactly as defined in nevisIDM. 
Otherwise, the property value will never be written into the session.


# CustomInputField_label

Enter a text or _litdict key_ to be displayed as _label_ in front of the input field.

# MicrosoftLogin_clientExtId

The ExtId of the client in nevisIDM that will be used to store the user 

# NevisFIDODeployable_authenticationTimeout

Defines the maximum time duration between the generation of the `AuthenticationRequest` by nevisFIDO and the `AuthenticationResponse` by the FIDO UAF client. 

If the client has not sent the response after this time, a client timeout occurs. 

The default value is 2 minutes. If no time unit is provided, seconds will be used.

This timeout is relevant in the authentication use-cases, such as:

- [In-Band Authentication](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/in-band-authentication)
- [Out-of-Band Authentication](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/out-of-band-authentication)


# NevisAdaptDatabase_hikariType

Select which method of generation should be applied when configuring the Hikari datasource for the database connection.

Possible options:

- `recommended`: the default option, this sets up three explicit values:
    - Maximum session lifetime: 300s
    - Session idle timeout: 100s
    - Maximum pool size: 50
- `custom`: specify values in the next text area, separate keys and values with `=`. 
    - The valid keys can be found at [HikariCP - GitHub](https://github.com/brettwooldridge/HikariCP).
- `unmodified`: this configuration doesn't generate anything, leaving all default configurations coming from the library in effect.


# NevisAdaptRememberMeConnectorStep_adapt

Reference for the nevisAdapt service to check for the presence of the provided remember-me token.

# SamlIdpConnector_assertionLifetime

SAML assertions have an issue timestamp.
nevisAuth validates the timestamps of SAML assertions received from the IDP.

Some identity providers create the SAML assertion on login and return the same
assertion as long as the session is active on the identity provider.

In this case enter a duration which is at least as long as the maximum session lifetime
on the identity provider.

For identity providers which always return a new assertion (e.g. nevisAuth)
the value can be very low (e.g. `30s`)

Enter ```unlimited``` to disable the maximum lifetime check for received SAML ```Responses```.
This sets ```in.max_age``` to ```-1``` in the generated ```ServiceProviderState```.

# OAuth2AuthorizationServer_clientExtId

The `extId` of the client in nevisIDM where the user is stored.

# FacebookLogin_redirectURI

The callback URI to go to after a successful login with Facebook.

This will create an endpoint in your host config.

The URL will be a combination of the `Frontend Address` of the `Virtual Host` and the value configured here.
For example, let's assume that you have configured:

- Return Path: `/oidc/facebook/`
- Frontend Address: `https://nevis.net`

Then the URL will be `https://nevis.net/oidc/facebook/`.

Use the `exact:` prefix to use the given path as-is.
Without this prefix a normal mapping with `/*` will be generated and thus sub-paths will be accessible as well.


# NevisIDMStepBase_nevisIDM

Assign a `nevisIDM Instance` or `nevisIDM Connector`.


# NevisFIDODeployable_userVerificationTimeout

Maximum time that a FIDO2 client has to send the response in a ceremony where user-verification is required. 

Default value is 5 minutes.


# NevisDetectDatabase_encryption

Enables TLS in a specific mode. The following values are supported:

- `disabled`: Do not use TLS (default)
- `trust`: Only use TLS for encryption. Do not perform certificate or hostname verification. This mode is not recommended
  for production applications but still safer than `disabled`.
- `verify-ca`: Use TLS for encryption and perform certificates verification, but do not perform hostname verification.
- `verify-full`: Use TLS for encryption, certificate verification, and hostname verification.

# AppleLogin_claimsRequest

The claims request parameter. This value is expected to be formatted in JSON and does not accept trailing spaces nor tabs.

# StaticContentCache_maxLifetime

The maximum duration to cache a document.

# NevisAdaptDeployable_ipToLocationHostnameVerifier

Enabling this option will set an Apache hostname verifier (which also handles certificate checks) instead of the default one.

Default: `disabled` (backwards compatibility)

# NevisProxyDeployable_logging

Add logging configuration for nevisProxy.

# GroovyScriptStep_validation

Choose between:

- `enabled` - parse the Groovy script and run against mock objects.
- `parse-only` - only parse the Groovy script.
- `disabled` - the script is not validated.

The validation is not feature complete and thus there may false negatives.

For instance, `import` statements can make the validation fail as the corresponding classes
are usually not on the nevisAdmin 4 classpath. This case is quite common and thus
failed imports will be reported as info issues to not block deployment.

If your Groovy script produces warning or error issues
but is working inside nevisAuth please select `disabled` 
and provide the script to Nevis Security so that we can improve the validation.

When set to `enabled` the following mock objects will be used for validation:

```
Map<String, String> parameters
Map<String, Object> inctx
Properties inargs
Map<String, Object> session
Properties outargs
Properties notes
Request request
Response response
Tracer LOG
```

# SamlIdpConnector_logoutType

Setting for SP-initiated logout, logout methods can be chosen
* **IMPLIED**: the logout method will be used by getting configuration of `Binding: Outbound`
* **POST**: force logout method to POST
* **SOAP**: force logout method to SOAP. This only work when IdP SAML Response contain `SessionIndex`.

# InitRuntimeConfiguration_realm

Authentication realm to create the init runtime configuration.

# CustomNevisIDMLogFile_auditSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# NevisIDMSecondFactorSelection_fido2

Assign a step which may be selected when the user has a FIDO2 Authenticator credential.

Assign a `FIDO2 Authentication` pattern here.


# SAPLogonTicket_includeCertificate

When `enabled`, the signer's certificate is inserted into the issued SAP ticket.

# NevisAdaptUserNotification_async

This property defines whether the communication should happen immediately (disabled) or via the EventQueue (enabled).


# DatabaseBase_database

Here you can change the name of the database.

The database name **only** needs to be changed when the database service
contains multiple databases.


# AuthCloudOnboard_deepLinkLabel

Label to display on the element which allows the user to use the deep link to onboard.

The element is usually a button.


# NevisFIDOServiceAccessBase_nevisfido

Assign a `nevisFIDO Instance` or `nevisFIDO Connector`.


# GroovyScriptStep_scriptFile

Upload the Groovy script as a file.

Further information can be found in the nevisAuth Technical Documentation:

- [ScriptState](https://docs.nevis.net/nevisauth/setup-and-configuration/authentication-plugins-and-authstates/standard-authentication-authstates-and-plugins/scriptstate)
- [Writing scripts in Groovy](https://docs.nevis.net/nevisauth/setup-and-configuration/authentication-plugins-and-authstates/standard-authentication-authstates-and-plugins/scriptstate/writing-scripts-in-groovy)

Use the expression `${service.postfix}` to refer to Kubernetes services
deployed by this nevisAdmin 4 project.

The expression can always be used as it produces an empty String 
when the deployment is not a Kubernetes side-by-side deployment.

For instance, the following snippet declares a URL which points to the REST API
of a `nevisIDM Instance` that has been deployed as a Kubernetes service called `idm`:

```groovy
def url = "https://idm${service.postfix}:8989/nevisidm/api"
```

You may use `var` expressions to insert values from inventory variables at generation time.
For instance, use `${var.<name>}` to insert a variable called `<name>`.

If the variable is a scalar, the value will be returned as-is.
If the variable is a sequence, a Groovy list will be returned (start: `[`, end: `]`, separator: `,`, String quote: `"`).
 
If your Groovy script fails to validate, see `Script Validation`.


# OATHAuthentication_level

Authentication level that is set on success.

# NevisIDMSecondFactorSelection_otp

Assign a step which may be selected when the user has an OTP card credential.

Note that OTP card credentials may be used for various authentication methods 
(e.g. a one-time password list or VASCO Digipass devices).


# NevisFIDODeployable_authenticationTokenTimeout

Defines the maximum time a client has to redeem an authentication token after the generation of the token by nevisFIDO.

Once the token is redeemed, the `Authentication Response Timeout` applies: the client has a maximum time to send an `AuthenticationResponse` to nevisFIDO.

This timeout is relevant in [Out-of-Band Authentication](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/out-of-band-authentication).


# NevisMetaDatabase_schemaPassword

The password of the user on behalf of the schema will be created in the database.

# NevisIDMChangePassword_reenterOldPassword

If `enabled`, the user has to re-enter the old password before changing it. 

If `disabled`, the user can change the password without re-entering the old password.

# SamlIdpConnector_attributes

Configure to extract attributes from SAML assertions 
and store them in a session variable. 

Examples:

| Session Variable  | Attribute |
|-------------------|-----------|
| sess:user.email   | email     |
| sess:user.mobile  | mobile    |


# ServiceAccessBase_keystore

Optional setting to use a client certificate for connecting to HTTPS backends.

# FIDO2Authentication_authStateClass

Select one of the available implementations.

When `ScriptState` is selected, all requests sent by JavaScript are directed towards nevisAuth.
The script takes care of the communication with the nevisFIDO component, and thus you can restrict access to nevisFIDO. 
There is no need to expose any nevisFIDO APIs on the nevisProxy `Virtual Host`.

When `Fido2AuthState` is selected, configuration for `Fido2AuthState` is generated.
FIDO2 related requests are sent to nevisFIDO instead. This requires that the following nevisFIDO APIs 
are exposed on the nevisProxy `Virtual Host`:

- `/nevisfido/fido2/attestation/options`
- `/nevisfido/fido2/assertion/result`
- `/nevisfido/fido2/status`

The easiest way to ensure this is to add a `nevisFIDO FIDO2 REST Service` pattern to your project.

It is recommended to select the `Fido2AuthState` implementation as it is a more pragmatic solution whereas
the `ScriptState` is likely to be decommissioned.

This pattern is experimental and likely to change in future releases.


# NevisLogrendDeployable_bindHost

The host name that this nevisLogrend instance will bind to. nevisProxy will connect to the same host name.

# SamlSpRealm_issuer

Set the `Issuer` used by this SAML Service Provider.

The issuer can be an arbitrary string but it is recommended to use the complete URL that the 
_Assertion Consumer Service_ is exposed on.

Example: `https://sp.siven.ch/SAML2/ACS/`

# NevisIDMPasswordLogin_passwordResetEnabled

Enables the password reset process. 

The password reset process works as follows:

- The user has to enter his login ID or email.
- An email with a link be sent to the user.
- The user has to click the link in the mail to set a new password.

A link will be added to the login page. 
Users may click this link if they have forgotten their password to request a new password.

The link text can be changed on the Realm pattern by setting translations for the label `pwreset.info.linktext`. 

# NevisFIDO2Database_maxConnectionLifetime

Defines the maximum time that a session database connection remains in the connection pool.

# NevisIDMChangePassword_displayPasswordPolicy

If `enabled`, the active password policy is displayed on the GUI.


# NevisFIDODeployable_policy

A FIDO UAF [Policy](https://fidoalliance.org/specs/fido-uaf-v1.1-ps-20170202/fido-uaf-protocol-v1.1-ps-20170202.html#policy-dictionary) 
defines which authenticators can be used during registration or authentication.

Each configuration file has to contain exactly 1 policy, as a JSON object.

A policy contains a list of allowed and/or disallowed [AAIDs](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-protocol-v1.1-id-20170202.html#authenticator-attestation-id-aaid-typedef),
pointing to specific authenticator implementations.

The policy for a certain operation can be specified in the `context` of the [GetUafRequest](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-client-api-transport-v1.1-id-20170202.html#getuafrequest-dictionary) object.

Example Javascript snippet for a registration operation with `pin_only` policy:

```
const getUafRequest = {
    op: "Reg",
    context: JSON.stringify({username: userExtId, policy: "pin_only"})
}
```

Given a policy in the `GetUafRequest` context, nevisFIDO looks for a `.json` file with the same name.

There must be at least one file named `default.json` which serves as default policy.
This policy will be used when no policy is specified in the `GetUafRequest` context.

The following policies are included by default:

* `default`: allows to execute registration or authentication with all authenticators supported by Nevis.
* `pin_only`: allows only the PIN authenticators.
* `biometrics_only`: allows only biometric authenticators.
* `password_only`: allows only (alphanumeric) password authenticators.


:::info supported authenticators
Note that two authenticators supplied by the policy files are currently only supported by the Nevis Mobile Authentication SDK but not the Nevis Access App, these authenticators are:

* The Device Passcode authenticator
* The Password authenticator
:::


# NevisMetaRESTServiceAccess_meta

Reference the nevisMeta Instance.

# Webhook_headers

Configure headers to send along with the call.

# NevisIDMChangePassword_onSuccess

Assign an authentication step to execute when the status of the URL ticket or credential is **onSuccess**. Required field.


# 4.13.0

Full changelog: 

[Patterns 4.13.0 Release Notes - 2021-11-17](https://docs.nevis.net/nevisadmin4/release-notes#patterns-4130-release-notes---2021-11-17)

##### ModSecurity Core Rule Set Upgrade

The _OWASP ModSecurity Core Rule Set_ (CRS) version has been upgraded from `3.0.2` to `3.3.2`. 

To choose between the CRS versions, a new setting `OWASP ModSecurity CRS Version`
has been added to the `Virtual Host` pattern under the `Security` tab.

Please note that Nevis cannot ensure that the new rules are compatible.
If you cannot affort testing your applications you can select the previous version.

If you have uploaded a custom rule set (`ModSecurity Rule Set` in the `Virtual Host` pattern),
you have to select `custom`.

##### Changes to TLS Settings

Updated the `compatible` configuration for the `Frontend TLS Settings` of Virtual Hosts. 
Please refer to the Help for the new values.

Blank fields in `TLS Settings` patterns assigned to a Virtual Host will be now be replaced by the corresponding `recommended` value. 
The `compatible` value was previously applied.

Fixed an issue where a Virtual Host could have `Frontend TLS Settings` set to `recommended` or `compatible`, 
and have a `TLS Settings` pattern assigned at the same time.
Now assigning a `TLS Settings` pattern requires setting `Frontend TLS Settings` to `custom`.

# JWTAccessRestriction_publicKey

The public key corresponding to the private key which was used to sign the JWT.

# SamlSpConnector_keyInfo

The `KeyInfo` embedded into the signature informs the service provider about the signer credential used. 

Enter one or several of the following elements:

- SKI 
- Certificate 
- CertificateChain
- Subject
- IssuerSerial
- CRLs
- SubjectDNAsKeyName
- SubjectCNAsKeyName
- KeyNames
- EntityID
- PublicKey

Note that only configured fields defined in the signer certificate are actually added to the `KeyInfo` structure.

# RequestValidationSettings_parameters

Define _parameters_ which may be used within rules.

Enter a map of key-value pairs. 

For instance, a parameter `my_param` could be defined as follows:

```yaml
my_param: 900200
```

These parameters can be used in:

- `Additional Rules`
- `Whitelist Modifications`
- `Exception Modifications`

The expression formats are:

`${param.<name>}`:

- `name` found: parameter value is used.
- `name` missing: expression is **not** replaced.

`${param.<name>:<default value>}`:

- `name` found: parameter value is used.
- `name` missing: default value will be used.

In `<default value>` the character `}` must be escaped as `\}`.

In case a variable `my-variable` is used this is the format you need to use in the inventory:

```yaml
my-variable: |
  my_param: 900200
```


# GenericSocialLogin_firstNameClaim

The claim that contains the first name of the logged-in user in the social account.
The default value is `given_name`.

# PropertiesTestPattern_pathProperty

Enter a path starting with `/`.
Usually this is then used to create a mapping in nevisProxy ending with `/*`.
Supports the special prefix `exact:` to declare that an exact mapping is desired instead of a nested on in nevisProxy.

# GenericAuthXmlServiceBase_parameters

Define _Template Parameters_.

Examples:

```yaml
smtp: smtp.siven.ch
sender: noreply@siven.ch
```

These parameters can be used in your `Configuration`.

The expression formats are:

`${param.<name>}`:

- `name` found: parameter value is used.
- `name` missing: expression is **not** replaced.

`${param.<name>:<default value>}`:

- `name` found: parameter value is used.
- `name` missing: default value will be used.

In `<default value>` the character `}` must be escaped as `\}`.

# SamlSpRealm_idp

Assign a `SAML IDP Connector` for each SAML Identity Provider.

SP-initiated authentication with multiple IDPs requires 
a `Selection Expression` to be configured for each connector.

# NevisAdaptFeedbackConfig_feedbackRedirectURL

Provide a URL to redirect to after sending a report by pressing the feedback link in the notification.
This can either be a base homepage or a more security-oriented one (for example page for password reset).

If it remains unset, a basic informative text is displayed about the report instead of a redirect.

# SamlIdp_preProcess

An an authentication step to execute before dispatching according to the issuer.


# NevisAuthDatabase_synchronizeSessions

Defines when sessions are stored to the remote session store.

- `after-successful-authentication`

A session is stored to the remote session store
once authentication has been completed successfully.

Use this mode when performance is critical,
when the authentication flow is stateless (e.g. no GUI is shown),
when there is only 1 nevisAuth instance, or in classic VM-based deployment scenarios.

- `always`

Session are always stored to the remote session store.

This mode requires nevisAuth version 4.28.0.216 or newer.

We recommend this mode when you want to restart nevisAuth without user impact
and for deployments to Kubernetes.

Typically, while a user is logging in, multiple requests are sent to nevisAuth.

If you configure multiple replicas of nevisAuth, the Kubernetes service may forward these requests to any of the replicas.
By selecting `always`, you ensure that all replicas can access the user's session during the authentication process.

- `recommended (default)`

Uses `always` when deploying to Kubernetes and `after-successful-authentication` for classic, VM-based deployments.


# ErrorHandler_contentTypeMode

The **Content-Type Mode** allows enabling or disabling the error handling depending on the `Content-Type` header of the backend response.
Use this setting in combination with the **Content-Types** setting.

Choose one of:
- `None`: The error handling settings are applied to all backend responses.
- `Enabled`: The error handling settings are enabled only for the backend responses with a `Content-Type` header included in the **Content-Types** setting.
Backend responses with other Content-Types are propagated to the client.
- `Disabled`: The error handling settings are disabled for the backend responses with a `Content-Type` header included in the **Content-Types** setting. 
These responses are propagated to the client.
The error handling settings are applied to backend responses with other `Content-Type` headers.



# GenericAuthenticationStep_onFailure

Use `${state.failed}` to continue with the assigned step.

If no step is assigned and `${state.failed}` is used an `AuthState` named `<Realm>_Authentication_Failed` is generated.

# AccessRestriction_subPaths

Set to apply this pattern on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table provides examples to illustrate the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |

# EmailTAN_recipient

Enter a nevisAuth or EL expression for the recipient.

You have to ensure that this expression always resolves.
There will be a system error if the expression does not produce an email address.

Examples:

```
${sess:ch.nevis.idm.User.email}
```


# NevisAdaptAnalyzerConfig_geoAnalyzer

Used to disable GeoLocation analysis. If you wish to disable this setting
also consider disabling the IP Geolocation settings as well in the `nevisAdapt Instance / IP Geolocation` configuration 
and the `nevisAdapt Instance / IP Reputation` configuration.

# NevisConnectorPattern_kubernetes

This setting is used when deploying to Kubernetes only.

Choose between:

- `disabled`: instance running on a VM.

- `same_namespace`: service running in the same cluster and namespace.
  
- `other_namespace`: service running in the same cluster but in another namespace.
  
- `other_cluster`: service running in another cluster.


# NevisAuthRealmBase_logrendTrustStore

If nevisLogrend is used and the connection to nevisLogrend uses HTTPs then a trust store should be configured here.
  
If no pattern is assigned the nevisAdmin 4 automatic key management will set up a trust store.

# Maintenance_end

Enter the end date and time of the maintenance window.

- format: `yyyy-mm-dd HH:mm` (24 hours)
- timezone: UTC (not your local time)
- example: `2020-05-20 15:00`

# NevisFIDODeployable_basicFullAttestation

Android Key Attestation relies on FIDO UAF Full Basic Attestation in the backend.

Whether Android Key Attestation is applied is controlled by the FIDO UAF policy.

Here you can choose between 2 levels for the FIDO UAF Full Basic Attestation:

`default` - does FIDO UAF Basic Full attestation solely based on the UAF protocol specification. 
In practice, this means it’s limited to verifying the certificate chain.

`strict` - is doing additional checks on the attestation extension of the `TBSCertificate`,
ensuring that all key material is kept in certified secure hardware and the phone bootloader was not manipulated.

Additional information can be found in the [nevisFIDO UAF configuration documentation](http://docs.nevis.net/nevisfido/reference-guide/nevisfido-component/configuration#fido-uaf-configuration) including the specifics of the additional checks done in `strict` mode

Refer to the following sections for additional information of how to create the necessary policy files:

* [nevisFIDO policy configuration](http://docs.nevis.net/nevisfido/reference-guide/nevisfido-component/configuration#policy-configuration)
* [support of basic full and basic surrogate attestations](http://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/technical-architecture/functional-adaptions-of-the-fido-uaf-specification#support-of-basic-full-and-basic-surrogate-attestations) 


# BackendServiceAccessBase_sessionTermination

Use this feature to terminate sessions on the backend application.

nevisProxy will send a `GET` request to this path when the nevisProxy session is terminated (due to logout or session timeout).

# JSONResponse_type

Use `AUTH_CONTINUE` to keep the current session and stay in state.
When the next request comes in, the `On Continue` exit will be taken.

Use `AUTH_DONE` to complete the current flow and establish an authenticated session.
The request will continue in the filter chain in nevisProxy, towards a backend application.

Use `AUTH_ERROR` to terminate the flow, removing the session.
Note that this type may also be used for successful execution, to remove the session.


# SecurosysKeyStoreProvider_keyObjectLabel

The key objects label on the HSM.

# LdapLogin_connectionPassword

Password of the connection user. 
The user is part of the LDAP connection url.

Example:
* secret://Ll41Zsw54rmeNi2ZeoZD
* verySecretPassword

See the nevisAuth Reference Guide `UseridPasswordAuthenticateState` for more details on how to use obfuscated password.

# NevisAdaptDeployable_sharedStorageSettings

Configure this to override the default configurations used for the shared storage in Kubernetes deployments. 
If you would use an existing shared volume please only set the claim name.
This storage should support the ReadWriteMany access mode.

For more information regarding persistent volumes in Kubernetes please visit this [page](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)

# EmailTAN_onFailure

Assign the step to execute in case no TAN code can be sent or all attempts had been exhausted.
 
The step will be executed in the following cases:

- the `Recipient` could not be determined
- all attempts had been exhausted and the user has failed to authenticate

If no step is assigned then the authentication flow will be terminated 
and an error GUI with label `error_99` (`System Problems`) will be shown.


# SamlIdpConnector_authRequestLifetime

SAML authentication requests have a maximum lifetime
which may be validated by the identity provider.

The lifetime should be low but high enough 
so that the authentication works on slow network connections.

# SAPLogonTicket_keystore

Assign a pattern which sets the key material used for signing the token.

If no pattern is assigned automatic key management is used
and the signer key will be created automatically.

# AuthorizationPolicy_levelMode

The `Authentication Level Mode` defines which `Authentication Level` is set for the current paths.

When combining several `Authorization Policy` patterns for an application, this setting allow inheriting the `Authorization Level` from a more general pattern.

Choose one of:
- `self-contained`: The `Authentication Level` defined in this pattern is applied to the current paths. They override any `Authentication Level` set on parent paths. If no `Authentication Level` is set in the current pattern, no authentication level will be enforced for the current paths.
- `inherited`: The `Authentication Level` in this pattern is not used. Use this setting if you have another `Authorization Policy` pattern applied to a parent path to inherit the configuration from. For the `Authentication Level` to be inherited from a particular parent, this setting has to be set to `default (self-contained)` in the parent pattern (otherwise you may inherit a value from a grandparent).


# FIDO2Onboarding_displayName

Enter a 1 line Groovy statement to determine the `displayName`
included in the call to the [Registration Options Service](https://docs.nevis.net/nevisfido/reference-guide/fido2-http-api/registration-services/registration-options-service).

The statement must produce a String.

The `displayName` is required by nevisFIDO
and may be shown to the user by some devices.

Examples:

```groovy
"${session['ch.nevis.idm.User.firstName']}_${session['ch.nevis.idm.User.name']}"
```


# DatabaseBase_rootCredential

Enter the name of a Kubernetes secret which contains the user and password of a database root account.

Required in Kubernetes deployment when `Advanced Settings` / `Database Management` is to `complete` or `schema`.

This is the default behaviour in Kubernetes.

With `complete` the secret should contain the following:
```
username: <root-user
password: <root-password>
```

If the `Database Management` is set to `schema` the root user can be omitted, but the application and schema user has to be specified:
```
ownerUsername: <some-username>
ownerPassword: <some-password>
appUsername: <some-username>
appPassword: <some-password>
```

If used with `complete` the app and owner users will be created with the credentials specified in the secret.

Due to the usage of schemas, it is recommended to create a separate Kubernetes secret for each database pattern with the app and owner credentials when using Oracle or PostgreSQL.

# NevisDetectRiskPluginBase_url

Service URL used to connect to the plugin

# OutOfBandMobileAuthentication_username

The `username` is used by nevisFIDO to look up the user in nevisIDM.

Depending on how the `nevisFIDO FIDO UAF Instance` is configured, either the `extId` or the `loginId` have to be used.


# NevisDetectMessageQueueDeployable_messageBrokerName

The name for the broker to configure ActiveMQ with.

# GoogleLogin_buttonLabel

Enter the text that should be displayed for the end-user on the social login button, and provide translations for this label on the Authentication Realms.

# InBandMobileAuthenticationRealm_trustStore

Defines the trust store that nevisProxy uses to validate the nevisAuth HTTPs endpoint.

# NevisMetaDeployable_addons

Assign add-on patterns to customize the behaviour of this nevisMeta instance.

# OutOfBandMobileStepBase_onCancel

Assign an authentication step to continue with when the user clicks cancel.

Use to provide a fallback authentication option.

You can change the text on the cancel button by translating the label `mobile_auth.cancel.button.label`.


# SamlIdpConnector_properties

Enter custom properties for the nevisAuth `ServiceProviderState`.

Example: overwrite `authnContextClassRef` in the `AuthnRequest`

```
out.authnContextClassRef = urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified
```

Example: remove `authnContextClassRef` from `AuthnRequest`

```
out.authnContextClassRef =
```

# OAuth2AuthorizationServer_propagationScope

Define propagation scope to store information for following AuthStates. Following are propagated data:
* Authorization request:
  * oauth2.authorization_request.[requestParameter]
* Client configuration:
  * oauth2.client.id
  * oauth2.client.metadata.[field]
* Scope configuration:
  * oauth2.scope.policy.clientCredentialsFlow
  * oauth2.scope.policy.authorizationCodeFlow
  * oauth2.scope.policy.implicitFlow
  * oauth2.scope.policy.refreshTokenRequest
  * oauth2.scope.policy.authenticationRequired
  * oauth2.scope.metadata.[field]

You can find out more information in the output session of [AuthorizationServer](https://docs.nevis.net/nevisauth/setup-and-configuration/authentication-plugins-and-authstates/oauth-2.0-and-openid-connect-plugins/authorization-server-and-open-id-connect-provider-plugins/authorizationserver)

The propagated data is intended for logging purposes only, no standard AuthState will use it. But you can access and use with `Groovy Script Step`.

**Note**: If your flow has multiple user interactions, use the scope `session` to ensure that the information is available throughout the flow.

# LdapLogin_type

Configure the type of LDAP directory.

# SamlIdp_samlSigner

Configure the key used by this Identity Provider
to sign outgoing SAML Assertions.

# ErrorHandler_subPaths

Set to apply the error handling on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table provides examples to illustrate the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |

# ObservabilityBase_parameters

Provide parameters for your configuration file.

Examples:

```properties
connectionString = InstrumentationKey=00000000-0000-0000-0000-000000000000
```

```properties
tracesEndpoint = https://otel-collector:4318/v1/traces
metricsEndpoint = https://otel-collector:4318/v1/metrics
logsEndpoint = https://otel-collector:4318/v1/logs
```

# ErrorHandler_blockedStatusCodes

Hide certain HTTP status code(s) by returning 200 OK
instead (by using the reset-status-code action).

By default, the status code is not changed 
as it can be useful for technical clients. 

The response body will still be replaced.

You may also enter:

- ranges of status codes (e.g. `500-599`),
- lists (e.g. `403,500`)
- combination thereof (e.g. `403,500-599`).


# GenericAuthRealm_dependencies

In case your `AuthState` elements use custom classes upload the required JAR file(s) here.

Files uploaded here will be deployed into the `lib` directory of the nevisAuth instance.

# OAuth2UserInfo_realm

Assign a realm which shall be exposed to get user information of an OAuth2 Authorization Server or OpenID Connect Provider.

# NevisIDMClient_clientName

The name of the client.


# DummyTAN_onSuccess

Set the next step on successful entry of the TAN code.
If no step is assigned, the process ends and the user will be authenticated.

# NevisIDMUserUpdate_mandatoryAttributes

Define which attributes are required and how to provide them.

Example:

```
clientExtId: 100
email: ${sess:email}
remarks:
mobile:
```


# NevisAuthDeployable_port

Port the nevisAuth instance is listening on.

# HostContext_sessionResource

Exposes the REST interface of the session store servlet on the given path.
For security reasons, only DELETE requests are allowed and assigning an access restriction 
pattern is recommended.

Before setting this parameter, make sure that there will be an actual session store servlet.  

# KerberosLogin_limitSessionLifetime

If set to `true` then the lifetime of the underlying Kerberos service ticket used by the client during the SPNEGO negotiation 
will be considered when determining the lifetime of Nevis session. In this case the expiration time of Nevis session cannot 
be longer than the expiration time of the Kerberos service ticket.

Default is `false`.

# GenericAuthenticationStep_onSuccess

Use `${state.done}` to continue with the assigned step.

If no step is assigned and `${state.done}` is found an `AuthState` named `<Realm>_Prepare_Done` will be used instead.

# StaticContentCache_subPaths

Set to apply the cache handling on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table provides examples to illustrate the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |

# GenericIngressSettings_clientCertAuth

Enables client certificate validation in the NGINX Ingress.

Please note that client cert validation cannot be used 
when the TLS connection is terminated in front of the NGINX Ingress.

Choose between:

- `enabled`: Request a client certificate that must be signed by a certificate that is included in the `CA Secret`. 
Failed certificate verification will result in a status code `400 (Bad Request)` (unless `Error Page` is configured`).

- `optional`: Do optional client certificate validation against the CAs. 
Requests will fail with status code `400 (Bad Request)` when a certificate is provided that is not signed by the CA
(unless `Error Page` is configured`). When no or an otherwise invalid certificate is provided, 
the request does not fail, but instead the request is allowed to pass through.

- `optional_no_ca`: Do optional client certificate validation, but do not fail the request when the client certificate 
is not signed by the CAs from `CA Secret`. The secret still has to exist with a valid certificate.

- `disabled` (default): Don't request client certificates and don't do client certificate verification.

This setting is used to generate the following annotation for the NGINX Ingress:

`nginx.ingress.kubernetes.io/auth-tls-verify-client`

# GenericHostContextSettings_filterMappings

Choose between:

- `manual` (default): only the `filter-mapping` elements which have been configured via `Filters and Mappings` will be added.
- `automatic`: filters configured via `Filters and Mappings` will be mapped to `/*`.
- `both`: like `automatic` but additional `filter-mapping` elements are allowed as well.

# SamlSpRealm_timeoutPage

Renders a timeout page when the user session has expired.

This is different from the `Logout Reminder Page` feature 
which also show a page when the user comes back after closing the browser.

The page contains a heading, an info message and a continue button.
You can customize them via `Custom Translations` by setting the following labels:

- `title.timeout.page`
- `info.timeout.page`
- `continue.button.label`

For this feature an additional cookie `Marker_<name>` will be issued.
The value will be set to `login` or `logout` depending on the last user action.

The following requirements must be fulfilled:
 
- Usage of HTTPs to access the application and for the entire SAML process.
- No other session expiration feature must be used.

# AppleLogin_scope

Select the requested scopes for getting user information from Apple. 

The default is `email` and thus minimal information will be returned.

The scope `openid` will always be added as Apple uses OpenID Connect.


# RuleBundle_exceptionRules

Configure _exception modifications_.

As explained in the [ModSecurity documentation](https://www.modsecurity.org/CRS/Documentation/exceptions.html#exceptions-versus-whitelist)
_exception modifications_ are applied **after** including the core rules.

If both the `Request Validation Settings` and the `Rule Bundle` pattern have _exception modifications_ configured, first
the `Request Validation Settings`, then the `Rule Bundle` modifications will be applied.

Note that new rule may require a rule ID which has to be unique for this pattern.
Use the range 1-99,999 as it is reserved for local (internal) use. 

* Remove rule with ID `900200`:

`SecRuleRemoveById 900200`

* Whitelist body parameter `upload` for all rules:

`SecRuleUpdateTargetByTag ".*" "!ARGS:upload"`

* Whitelist body parameter `upload` for rule ID `123`:

`SecRuleUpdateTargetById 123 !ARGS:upload`

* Add a new rule which allows the HTTP methods used for WebDAV:

```
SecAction \
 "id:1,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE CHECKOUT COPY DELETE LOCK MERGE MKACTIVITY MKCOL MOVE PROPFIND PROPPATCH PUT UNLOCK'"
```

# FacebookLogin_clientSecret

Client Secret is `App Secret` provided by Facebook when you register Facebook as IdP service.

# OAuth2AuthorizationServer_cacheTimeout

Caching of responses from a nevisMeta instance. After this time (in seconds), a response is considered outdated and attempts are made to update it.

# GenericDeployment_commandPhase

Defines when the command is executed. The files are always copied during the CONFIGURE phase.

Phases:

* CONFIGURE: Command runs after files have been uploaded, but before NEVIS instances are (re)started. Use e.g. when patching a NEVIS instance configuration file.
* ACTIVATE: Command runs when instances are (re)started. Use when deploying files or commands that are independent of NEVIS instances.


# UserInput_label

Enter a text or _litdict key_ to be displayed as _label_ in front of the input field.

# NevisIDMUserLookup_clientId

The source of the client’s external ID. 

Used only when `Show Client Input Field` is set to `disabled`.

Set either this or `Client Name`.

# NevisAuthConnector_languages

Enter the language codes which are enabled in nevisAuth.

This property is considered only if nevisLogrend is generated by nevisAdmin
to ensure that nevisLogrend provides support for the same languages.

# GenericWebBase_filters

Configure filters and their mappings using the XML syntax described in the nevisProxy Technical Documentation. 

Filters that have the same name as other filters (even those defined by other patterns) 
will be combined: the `init-param` sets will be merged where possible.
Direct contradictions are interpreted as validation failures.

**Example 1**: Create (or patch) a filter with a fixed name

```xml
<filter>
   <filter-name>SomeName</filter-name>
   <filter-class>ch::nevis::isiweb4::filter::SomeClass</filter-class>
   <init-param>
      <param-name>...</param-name>
      <param-value>...</param-value>
   </init-param>
</filter>
```

**Example 2**: Create (or patch) a filter using an application-specific name

```xml
<filter>
   <filter-name>SomeName_${service.name}</filter-name>
   <filter-class>ch::nevis::isiweb4::filter::SomeClass</filter-class>
   ...
</filter>
```

**Example 3**: Map a filter to a sub-path of the assigned application(s).
This example works for applications which have 1 frontend path only.

```xml
<filter-mapping>
   <filter-name>SomeFilter</filter-name>
   <url-pattern>${service.path}/custom/*</url-pattern>
</filter-mapping>
```

**Example 4**: Use multi-value expressions

Multi-value expressions replicate an entire line for each associated value.

Use the expressions `*{service.path}` and `*{service.mapping}` to generate filters 
which must contain the frontend paths of all assigned applications.

The following snippet is not complete but should illustrate the concept:

```xml
<filter>
    <filter-name>FormSigning</filter-name> 
    <filter-class>ch::nevis::isiweb4::filter::validation::EncryptionFilter</filter-class>
    <init-param>
        <param-name>EntryURL</param-name>
        <param-value>
            *{service.path}/
        </param-value>
    </init-param>
    ...
</filter>
```

# NevisMetaDeployable_frontendTrustStore

Assign the Trust Store for the HTTPs endpoint.

If no pattern is assigned a Trust Store will be provided by nevisAdmin 4 automatic key management.

# CustomNevisMetaLogFile_syslogHost

Defines where to send logs to via syslog.
 
This configuration is used only when syslog forwarding is enabled (see `Log Targets`).

The syslog facility is `localhost3` and the threshold is `INFO`.

# AuthenticationFlow_flow

Assign a step to execute for incoming requests.

If not present already, the step will be added to the `Authentication Realm`.

If no step is assigned the default flow of the `Authentication Realm` will be executed.

# NevisAdaptServiceAccessBase_realm

Mandatory setting to enforce authentication.

# NevisDetectCoreDeployable_port

Enter the port on which nevisDetect Core will listen.

# GenericIngressSettings_caSecretNamespace

Enter the namespace of the `CA Secret`.

# GenericAuthRealm_resources

In case your `AuthState` elements require additional configuration files or scripts upload them here.

Files uploaded here will be deployed into the `conf` directory of the nevisAuth instance.

# KerberosLogin_kerberosRealms

Enter the allowed `Kerberos realms` (`AD domains`).

Example:

- `SIVEN.CH`

In case multiple values have to be configured you can define which `Keytab File` or `Keytab File Path`  
to use by referencing its file name.

Example:

- `SIVEN.CH -> kerberos_ch.keytab`
- `SIVEN.DE -> kerberos_de.keytab`

# GenericThirdPartyRealm_authServiceAddons

Assign add-on patterns to customize the behaviour of the `Authentication Application`.

Assigning these add-ons here may be more appropriate to have the complete authentication 
logic concentrated here.

# FrontendKerberosLogin_proxyHostNames

Enter the `Frontend Addresses` of the nevisProxy `Virtual Host` patterns 
for which this pattern provides authentication.

Example:

- `www.siven.ch`

In case multiple values are configured you can define which `Keytab File` or `Keytab File Path` 
to use by referencing its file name.

Example:

- `www.siven.ch -> kerberos_ch.keytab`
- `www.siven.de -> kerberos_de.keytab`


# HostingService_path

The path at which the resources shall be accessible at the frontend.
You may use `/` to deploy root content.

# LdapLogin_level

Set an authentication level if authentication of this step is successful.

# NevisAdaptAnalyzerConfig_browserFingerprintAnalyzer

Used to disable Browser Finger creation and 
analysis.


# StaticContentCache_maxEntries

The maximum number of documents to be cached.


# LdapLogin_onSuccess

Configure the step to execute after successful authentication.
If no step is assigned, the process ends and the user will be authenticated.

# NevisFIDODeployable_frontendTrustStore

Assign the trust store for validating 
incoming connections on the HTTPS endpoint.

If no pattern is assigned an automatic trust store will be generated.
This requires automatic key management to be enabled in the inventory.

In that case clients, such as nevisProxy and nevisAuth, should use an automatic key store 
for the connection to nevisFIDO so that the trust can be established.


# GenericSocialLogin_authorizationEndpoint

The authorization endpoint of the OAuth2 provider.

Required when `Provider Type` is set to `OAuth2`.


# GenericThirdPartyRealm_timestampInterval

Sets the minimum time interval between two updates of the session timestamp.

If the parameter is set to "0", the system will update the session timestamp each time a request accesses a session.

The `Initial Session Timeout` is used as `Update Session Timestamp Interval` if it is shorter than the duration configured here.

# HostContext_keystore

A key store is required when HTTPS is used for any of the `Frontend Addresses`.

If not set a key store will be set up automatically. 
This requires automatic key management to be enabled.

The key store should provide a certificate which is valid for all frontend addresses, 
e.g. because SANs (subject alternative names) are set or because it is a wildcard certificate.

In a Kubernetes deployment the TLS connection 
is terminated by an NGINX Ingress in front of nevisProxy and this configuration does not apply. 
The required key material will be generated automatically.

You can configure the NGINX Ingress to use key material from a Kubernetes secret as follows:

1. assign a `NGINX Ingress Settings` pattern to your `nevisProxy Instance` via `Additional Settings`
2. in the `NGINX Ingress Settings` pattern configure `TLS Secrets`.


# AuthCloudBase_onAbort

Assign a step to continue with when the user has aborted in the mobile app or a timeout occurred.


# CustomAuthLogFile_auditChannels

Assign `nevisAuth Audit Channel` patterns to use your own channel implementations.


# FIDO2Onboarding_onCancel

If assigned a skip button will be added.

Use to provide an alternative to the user.

The button is defined by the label `info.signup.passwordless.skip` and looks like a link.

Translations for this label must include a button with name `cancel-bottom`. Example:

```html
<button name="cancel-bottom" type="submit" value="true" class="btn btn-link link-primary">Skip for now</button>
```


# OutOfBandMobileDeviceRegistration_realm

Assign an `Authentication Realm` to protect the APIs for out-of-band registration.

When the APIs are called by a protected application which is exposed / running on nevisProxy,
then you should assign the same realm here.


# AuthCloudBase_accessKey

Instead of uploading an `access-key.json`,
you can enter the access key of your Authentication Cloud instance here.

# CustomNevisIDMLogFile_levels

Configure log levels.

See the nevisIDM Technical Documentation, chapter
[nevisIDM log levels (file: logging.yml)](https://docs.nevis.net/nevisidm/Operation-and-Administration/Configuration-Files) for details.

Hint: If you only change log levels nevisAdmin 4 does not restart the component in classic VM deployment.
The new log configuration will be reloaded within 60 seconds after deployment.

The default configuration is:

```
ch.nevis.idm.batch.jobs = INFO
ch.nevis.idm.standalone = INFO
```

Examples: 

```
ch.adnovum.nevisidm.service.properties = INFO
ch.nevis.ninja = DEBUG
```


# NevisIDMUserUpdate_writeEmptyValues

If `enabled`, it is possible to clear user attributes or properties.
The value will be overwritten with an empty value.

This is supported only if the corresponding attribute or property is optional. 

If `disabled`, empty values are ignored, i.e., the stored value remains unchanged.


# NevisIDMURLTicketConsume_onSuccess

Assign an authentication step which shall be executed when the URL ticket is valid.

Note: this pattern does not provide any content on the exposed `Frontend Path(s)` and does not ensure
that the caller is redirected when the authentication flow terminates. 

Thus, please take appropriate measures at the end of the flow to avoid a `404` error.
For instance, you may trigger a redirect at the end of your flow, or
assign an `URL Handler` to `Additional Settings`.

# StaticContentCache_maxAgeMode

Choose one of:

- **override** : The cache entry lifetime is set to **Max Lifetime**.
- **backend** : The cache entry lifetime is copied from the `Cache-Control: max-age` directive sent by the backend. The **Max Lifetime** is used as a fallback.



# SamlSpConnector_type

Reserved for ID Cloud use.

# NevisIDMUserLookup_buttons

Assign a `Dispatcher Button` to add button(s) which points to a different authentication step.

# OAuth2AuthorizationServer_idTokenJWKSetTrust

Assign a trust store for the outbound TLS connection to JWK Set endpoint for ID Token encryption.

Import the CA certificate of the `JWK Set endpoint` into this trust store.

Since version 4.38 nevisAuth trusts CA certificates included in the JDK.

Thus, it is not required to configure this.

However, you can still configure a trust store here to be as strict as possible.


# AuthorizationPolicy_requiredRolesMode

The `Required Roles Mode` defines which `Required Roles` are set for the current paths.

When combining several `Authorization Policy` patterns for an application, this setting allow inheriting the `Required Roles` from a more general pattern.

Choose one of:
- `self-contained`: The `Required Roles` defined in this pattern are applied to the current paths. They override any `Required Roles` set on parents paths. If no `Required Roles` are set in the current pattern, no required roles will be enforced for the current paths.
- `inherited`: The `Required Roles` in this pattern is not used. Use this setting if you have another `Authorization Policy` pattern applied to a parent path to inherit the configuration from. For the `Required Roles` to be inherited from a particular parent, this setting has to be set to `default (self-contained)` in the parent pattern (otherwise you may inherit a value from a grandparent).


# PemKeyStoreProvider_rootDirName

Set to deploy the key store underneath a _base_ directory.
The key store will be established at:

`/var/opt/keys/own/<base>/<name>`

This configuration may be used to prevent key stores overwriting each other 
and is only required in complex setups with multiple projects or inventories.

# NevisIDMUserCreate_mandatoryAttributes

Define which attributes will always be set for the user.

The value can be constant or determined by a nevisAuth or EL expression.
User creation will fail when the value is empty.

Which attributes must be provided depends on policy configuration in nevisIDM.

How to best determine the value depends on preceeding authentication states and the (session)
variables they produce.

For instance, let's assume that the email is stored in a session variable called `email`,
the first name in `firstname`, and the last name in `name`. You can then use:

```
email: ${sess:email}
loginId: ${sess:email}
name: ${sess:name}
firstName: ${sess:firstname}
```


# InBandMobileAuthenticationRealm_tokens

Tokens assigned here may be created after successful authentication.

To produce and forward a token to an application backend,
reference the same token from the application's `Additional Settings` property.

# SAPLogonTicket_recipientSID

See SAP documentation of SAP SSO logon tickets for more information. Setting no value for this property should be correct for most cases.

# NevisDPDeployable_idmKeystore

Assign a key store which shall be used for outbound (2-way) TLS connections to nevisIDM.
If no pattern is assigned no key store will be generated.

For nevisDataPorter to use the key store, 
the following expressions should be used inside the `dataporter.xml` file:

```
${idm.keystore}
${idm.keystore.password}
```

Example configuration:

```xml
<object type="NevisIDMConnectionPool" name="adminService">
    <dp:paraVal name="endpoint" value="${cfg.idmEndpoint}"/>
    <dp:paraVal name="loginMode" value="proxyCert"/>
    <dp:paraMap name="sslSettings">
        <value name="javax.net.ssl.keyStore" value="${idm.keystore}"/>
        <value name="javax.net.ssl.keyStorePassword" value="${idm.keystore.password}"/>
        ...
    </dp:paraMap>
</object>
```


# DeployableBase_memoryLimit

This setting defines the maximum amount of RAM than can be used by this instance.

### VM Deployment

By default, the Java process will use 1/4 of the available RAM.

Depending on how many instances are deployed to the same target host
this may be either **too much** or **too little**.

The value configured here will be used for
the maximum heap size of the Java process (`-Xmx`).

### Kubernetes Deployment

In Kubernetes deployment the value configured here will be ignored 
 and the Java process will be configured to use a percentage of the available RAM. 
 
Note that `-Xmx` is not set to avoid file changes when adapting the limit.
 
As the docker container runs only 1 process the JVM flags 
`-XX:+UseContainerSupport` and `-XX:MaxRAMPercentage=80.0` will be applied
so that Java process can use up to 80% of the configured limit.

# JWTToken_attributes

Add custom claims to the JWT token.

Values can be static, nevisAuth expressions (`${...}`) or EL expressions (`#{...}`).

Examples:

| Claim | Expression           | 
|-------|----------------------|
| email | `${sess:user.email}` |


# FacebookLogin_clientExtId

The ExtId of the client in nevisIDM that will be used to store the user 

# ErrorHandler_contentTypes

The **Content-Types** configures the `Content-Type` headers for which the **Content-Type Mode** setting is applied.
Enter one value per line.

Use this setting in combination with the **Content-Type Mode** setting.


# NevisLogrendLogSettings_serverLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the default SERVER logs.

Note: not relevant when Log Targets is set to `syslog`.

# MultipleFieldUserInput_onSuccess

Configure the step to execute after the user has provided input.
If no step is configured here the process ends with `AUTH_DONE`.

# NevisIDMSecondFactorSelection_oath

Assign a step which may be selected when the user has an OATH (TOTP) credential.

OATH (TOTP) credentials may be used for second factor authentication using an authentication app, 
e.g. Google Authenticator.


# InBandMobileAuthenticationRealm_auth

The ```nevisAuth Instance``` where the authentication flow will be configured.

# PemKeyStoreProvider_keystorePass

Enter a passphrase.

The passphrase will be used to protect sensitive keystore files
(`key.pem`, `keystore.pem`, `keystore.jks`, and `keystore.p12`) on the target hosts.

If you do not enter any passphrase a passphrase will be generated.

As the passphrase is considered sensitive information it should not be published with the project.
It is therefore required to use a variable and set the value in the inventory (as a secret).

# NevisAdaptLogSettings_serverLogFormat

[Logback log format](https://logback.qos.ch/manual/layouts.html#conversionWord) for the default SERVER logs.
This pattern is used for **non**-kubernetes deployments.

Note: not relevant when Log Targets is set to `syslog`.

# MicrosoftLogin_redirectURI

The callback URI to go to after a successful login with Microsoft.

This will create an endpoint in your host config.

The URL will be a combination of the `Frontend Address` of the `Virtual Host` and the value configured here.
For example, let's assume that you have configured:

- Return Path: `/oidc/microsoft/`
- Frontend Address: `https://nevis.net`

Then the URL will be `https://nevis.net/oidc/microsoft/`.

Use the `exact:` prefix to use the given path as-is.
Without this prefix a normal mapping with `/*` will be generated and thus sub-paths will be accessible as well.


# 8.2505.0

Full changelog:

[Patterns 8.2505.0 Release Notes - 2025-05-21](https://docs.nevis.net/nevisadmin4/release-notes#patterns-825050-release-notes---2025-05-21)

##### TODO

Describe the most important changes here.

##### Automatic migration

Describe automatic migrations


# NevisIDMDeployable_host

Enter a custom host name to listen on.

# NevisFIDODeployable_connectionType

Define which APIs nevisFIDO uses when talking to nevisIDM.

Choose between:

- `default`: use the API recommended by Nevis.
- `both`: uses the SOAP API for most use cases and REST for updating login counters.
- `rest`: uses only the REST API. 

As of November 2024 our `default` is `both`.
The `rest` mode is still experimental, but is expected to become the `default` in the future.


# NevisAuthDeployable_startupDelay

Time to wait before checking Kubernetes readiness on startup.

You may have to increase this value if start of the nevisAuth service fails because of a failing readiness check.

Sets `initialDelaySeconds` of the Kubernetes startup probe.


# AuthCloudOnboard_onUserExists

Assign an authentication step to continue with when the user exists and has an active authenticator.

If no step is assigned here the authentication flow will fail for such users.


# SamlSpConnector_binding

The `Outbound Binding` controls how SAML messages are returned to the service provider.

Choose a binding which is supported by the service provider.

Use `http-redirect` when the SAML `Response` has to be returned using a `302 Redirect`.

Use `http-post` to generate a self-submitting form which produces a `POST` request.
This binding is recommended as SAML `Response` messages will include a signature.

When `http-post` is selected, HTML encoding will be applied to the `RelayState` parameter to include
it in the self-submitting form. This ensures that the parameter can be returned to the service provider,
even when it contains special characters.


# GenericDeployment_groupPermission

Read-write permissions for specified group of the directory. All files and subdirectories (including unpacked from single .zip) will have the same permissions. 
The executable bit will be set automatically for readable directories and for readable `Executable Files`.

# OAuth2Scope_label

Enter a label which shall be show when requesting consent for this scope.

You have to provide `Translations` for this label in the `Authentication Realm`
associated with the `OAuth 2.0 Authorization Server / OpenID Provider`.

# HostContext_encodedSlashes

Choose from:

- `allowed`: URLs containing encoded slashes are allowed and will not be decoded (`AllowEncodedSlashes NoDecode`).
Also `URLEncoding` will be set to `false` for each `HttpsConnectorServlet`.

- `forbidden`: URLs containing encoded slashes will be denied and a 404 will be returned. 
This is the default behaviour of Apache.

# OutOfBandMobileStepBase_clientKeyStore

Assign a key store for the TLS connection to nevisFIDO.

If no pattern is assigned, a key store will be provided
by automatic key management.

The client certificate in the key store must be trusted by nevisFIDO.

In case both sides use automatic key management, trust can be established automatically and there is nothing to configure.

However, if you are using a different kind of key store,
then you **must** configure `Frontend Trust Store` in the associated `nevisFIDO UAF Instance`.


# NevisAdaptAuthenticationConnectorStep_onLogoutDone

Optional. Reference for the next step in the logout authentication flow. If missing, this is the last step and the result will be `AUTH_DONE`.

# LdapLogin_userFilter

Enter an LDAP Filter. 

Use when the user has to be determined with custom criteria.
When configured this is used instead of `User Attribute`. 
 
Example:

```
(|(${notes:userid}=cn)(${notes:userid}=mail))
```

For debugging the authentication set the log level of `JNDI` to `DEBUG`.

# NevisIDMTermsAcceptance_nevisIDM

Reference a `nevisIDM Instance` to be used for checking terms and conditions.

# NevisIDMDeployable_frontendKeyStore

Assign the Key Store provider for the HTTPs endpoint.
If no pattern is assigned a Key Store will be provided by the nevisAdmin 4 PKI.

# NevisFIDODeployable_serverTrustStore

Assign the trust store for validating the nevisIDM endpoint.

The trust store should contain the certificate of the CA that
has issued the server certificate.

If no pattern is assigned an automatic trust store will be generated.
This requires automatic key management to be enabled in the inventory.

In that case the pattern assigned to `nevisIDM` must be a `nevisIDM Instance` pattern
which uses an automatic key store for the `Frontend Key Store`.


# TransformVariablesStep_properties

Set property elements for the `TransformAttributes` state.

# SwissPhoneChannel_defaultCountryCode

The default country code to add to the mobile number if the number found in the session does not have a country code. 

This value must **not** contain a `+`.

For instance, assuming that numbers without country code information are Swiss, enter `0041` in this field.


# NevisDetectLogSettings_levels

Configure log levels.

See nevisDetect Reference Guide, chapter `Logging Configuration` for details.

Hint: If you only change log levels nevisAdmin 4 does not restart the component in classic VM deployment.
The new log configuration will be reloaded within 60 seconds after deployment.

The default configuration is:

```
ch.nevis.nevisadapt = INFO
ch.nevis.nevisdetect.util.logging.OpTracer = DEBUG
```

Examples:

```
org.springframework.web.filter.CommonsRequestLoggingFilter=DEBUG
ch.nevis.nevisdetect.entrypoint.icap.RequestProcessingHelper=INFO
```


# MicrosoftLogin_type

The application type that you choose when you create your application in Microsoft. We are supporting 3 types

* common
* organizations
* consumers

Please follow this [document](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc#fetch-the-openid-connect-metadata-document) 
to select your application type correctly 

# LdapLogin_onFailure

Assign an authentication step that is processed if LDAP authentication fails with an technical error, 
or if the user is not unique. 

If no step is assigned an AuthState `Authentication_Failed`
will be created automatically.

# EmailInputField_label

Enter a text or _litdict key_ to be displayed as _label_ in front of the input field.

# OutOfBandManagementApp_addons

Assign add-on patterns to customize the behaviour of this pattern.

# NevisIDMPasswordLogin_loginType

Define how to look up the user.

Choose between:

- `LOGINID` - lookup user by `loginId` attribute.
- `EMAIL` - lookup user by `email` attribute.
- `AUTO` - depending on what has been entered, nevisIDM tries to look up the user by `email` or `loginId` attribute.

We recommend to use `LOGINID` as it is the most efficient way to look up users and has no side effects.
This can even work when users enter their email as you can store the email in the `loginId` attribute as well.

For `AUTO` and `EMAIL` to work nevisIDM has to be configured accordingly. You either have to:

- Set `authentication.loginWithEmail.enabled=true` in the Client policy. Policies cannot be configured using patterns. You can change them on the nevisIDM Admin GUI.
- Set `application.feature.emaillogin.enabled=true` in `nevisidm-prod.properties`. Use the `Generic nevisIDM Instance Settings` pattern for this.


# NevisIDMPasswordLogin_onSuccess

Configure the step to execute after successful authentication.

If no step is configured here the process ends and the user will be authenticated.

# 4.18.0

Full changelog: 

[Patterns 4.18.0 Release Notes - 2023-02-15](https://docs.nevis.net/nevisadmin4/release-notes#patterns-4180-release-notes---2023-02-15)

##### Mobile Authentication Pattern Improvements

The mobile authentication patterns have been improved. The help texts have been completely rewritten to give more details
about the use case. New patterns have been added to make the solution more flexible.
The existing `Mobile Device Registration` pattern has been marked as deprecated and will be removed in the May 23 release.
If you are using mobile authentication, see release notes for more details.

##### New Database Patterns

Introducing new database patterns for all components which use a database.

The new patterns can be used in classic and Kubernetes setups. 

Depending on the deployment type, different settings will be used.

Migration to the new patterns is **mandatory**. 

There will be error issues guiding you through the process.

##### nevisAuth Session Store Changes

There are breaking changes in the local and remote session store configuration in nevisAuth 4.38.
See nevisAuth release notes for details. You must upgrade nevisAuth to 4.38 when using patterns 4.18 and vice versa.

##### nevisAuth Outbound HTTP Changes

There are breaking changes in the in nevisAuth 4.38 affecting the behaviour of outbound HTTP connections.
See nevisAuth release notes for details. You must upgrade nevisAuth to 4.38 when using patterns 4.18 and vice versa.


# NevisIDMUserLookup_clientName

The source of the client’s name.

Used only when `Show Client Input Field` is set to `disabled`.

Set either this or `Client ID`. 
When neither is set then `Default` is used.

# NevisDetectLogSettings_serverSyslogFormat

[Logback log format](https://logback.qos.ch/manual/layouts.html#conversionWord) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# AuthCloudBase_skipLabel

Label to display on the element which allows the user to skip.

The element is usually a button but this can be changed by setting `Skip Type`.


# NevisAdaptAuthenticationConnectorStep_adapt

Reference for the nevisAdapt service to calculate risk scores during authentication.

# Logout_logoutBehaviour

- `gui` - shows a logout GUI. On submit the user is redirected to the same URL with the query parameter `logout` removed.
- `redirect` - does not show a GUI. The user is immediately redirected to the given URL or path.

# AutomaticTrustStoreProvider_truststoreFile

Upload additional trusted certificates in PEM format.

The content of all files will be concatenated and added to the `truststore.*` files generated by this pattern.

You can make this a variable and upload the files in the inventory using the `Attach files` function.

# SamlSpIntegration_token

Assign a SAML Token pattern.

The referred pattern must:

- have `Token Type` set to `Response` 
- be assigned to the correct Realm pattern(s)


# AuthCloudLogin_onSuccess

Assign a step to execute after successful authentication.

If no step is configured, the flow ends and an authenticated session will be established.

This requires that the session contains an authenticated user.

A simple way to ensure that is to include `nevisIDM User Lookup` or `nevisIDM Password Login` steps in your flow.


# LdapLogin_onUserNotFound

Assign an authentication step to be invoked if the user could not be found.

For instance, you may use this setting to chain multiple `LDAP Login` patterns,
e.g. to lookup users based on a different `User Attribute` or in separate `LDAP Endpoints`. 

The following `notes` will also be set and may be shown if the next state renders a GUI:

```
lasterror                 = 1
lasterrorinfo             = authentication failed, invalid input
lastresult                = usernotfound
```

# NevisFIDODatabase_schemaPassword

The password of the user on behalf of the schema will be created in the database.

# WebhookCalls_authMode

Configure the `authMode` property.

# InBandMobileAuthenticationRealm_fidoTrustStore

Assign a pattern which provides the trust store for nevisAuth to connect to nevisFIDO.

# HeaderCustomization_basicAuthUser

Enter the basic auth user or an expression of the format `<source>:<parameter>`.

For the `<source>` you may use:

- `AUTH`: outargs returned by nevisAuth.
- `CONST`: constant strings.
- `ENV`: Apache environment variables.
- `PARAM`: values from a request body as provided by a `ParameterFilter`.
- `HEADER`: request headers.

# NevisAdaptPluginPattern_propagateDeviceRecognition

Risk scores to be delivered to the client in the request headers.
This option configures enables device cookie risk score to be propagated.

# MicrosoftLogin_tenantId

Enter the `Tenant ID` of your Azure Active Directory.

This setting is used when `Application Type` is set to `organizations`.

Check Microsoft documentation on [How to find your Azure Active Directory tenant ID](https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/active-directory-how-to-find-tenant).


# JWTToken_properties

Set low-level properties for the 
[JWTToken](https://docs.nevis.net/nevisauth/setup-and-configuration/authentication-plugins-and-authstates/standard-authentication-authstates-and-plugins/jwt-plugin-jwttoken-authstate) AuthState.

# SOAPServiceAccess_schemaValidation

Choose between:

- `strict` - **all** requests must be valid SOAP, requests without a body are blocked.
- `enabled` - **all** requests which have a request body must be valid SOAP, requests without a body are allowed.
- `log only` - similar to `strict` but violations are not blocked, only logged.
- `content-type` - validation is performed only when the `Content-Type` header matches `application/soap+xml`.
- `disabled`



# ErrorHandler_keepSecurityHeaders

Configure the name of special response headers which should be kept,
regardless of the header action of the matching rule.
Useful for keeping the security response headers for the error pages.

Default:

```
Strict-Transport-Security
X-Content-Type-Options
Referrer-Policy
```


# GroovyScriptStep_errorStatusCode

Set the status code for responses when the `Response Type` is set to `AUTH_ERROR`.

The default of `403` is backward compatible. 

Note that we generally use `403` for unhandled error cases in authentication step patterns.
This is to avoid exposing the information that a certain case is not properly handled.

Depending on your case, a `500` or `400` may be a more appropriate choice.


# SamlResponseConsumer_issuer

Configure the `Issuer` used by this SAML Service Provider (SP).

This setting is used only when Artifact Binding is used.

Example: `https://sp.example.org/SAML2`

# GenericDeployment_templateFiles

Expressions matching files in which to replace parameters.

If a single .zip file is unpacked, it is scanned for matching files as well.

Possible values are exact file names or file endings.

Example:
* my_script.sh
* *.txt
* *.properties


# TokenHeaderPropagation_header

Enter the HTTP header to set for requests to backend applications.
The value of this header will be the base64 encoded token.

# NevisAuthRealmBase_timestampInterval

Sets the minimum time interval between two updates of the session timestamp.

If the parameter is set to "0", the system will update the session timestamp each time a request accesses a session.

The `Initial Session Timeout` is used as `Update Session Timestamp Interval` if it is shorter than the duration configured here.

# NevisProxyDeployable_addons

Assign add-on patterns to customize the behaviour of this nevisProxy instance.


# NevisDetectPersistencyWebApplicationAccess_persistency

Reference for the pattern with the details of the web application.

Supported patterns:
- nevisDetect Persistency Instance

# ICAPScanning_subPaths

Set to apply the ICAP scanning on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table provides examples to illustrate the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |

# NevisIDMUserUpdate_optionalAttributes

Define which attributes are optional and how to provide them.

Example:

```
firstName: ${sess:given_name}
name: ${sess:family_name}
country: ${sess:country}
```

# NevisProxyDatabase_accessRestriction

This optional configuration is available when `Mode` is set to `hybrid`.

Assign an `Access Restriction` pattern to define the source IPs that are allowed to access the `Session Store Path`.


# 7.2311.0

Full changelog:

[Patterns 7.2311.0 Release Notes - 2023-11-15](https://docs.nevis.net/nevisadmin4/release-notes#patterns-723110-release-notes---2023-11-15)

##### Kubernetes Deployments

We have added the `Crash Recovery Strategy` `kill` in the `nevisProxy Instance` pattern. For Kubernetes deployments this is the new default.

##### SAML Signing and Signature Validation

We have refactored the `Signature Validation` in `SAML IDP Connector` and `Signed Element` in `SAML SP Connector` to provide more options.
The new drop-downs are multi-select and thus you can choose multiple options.

The option `both` has been removed as more than 2 signed elements can be configured.
The default in the `SAML IDP Connector` has changed.


# OAuth2AuthorizationServer_authCodeLifetime

How long an authorization code issued by the authorization server should be valid.

# DeployableBase_startInactive

In a classic VM deployment the instance is restarted when a configuration file changes that requires a restart.
The instance is not restarted when a configuration file changes that does not require a restart.

This setting defines if the instance should also be started when it is down.

This setting applies to classic VM deployment only. 
In Kubernetes deployment the container pods are always recreated when any configuration file changes.


# NevisIDMDatabase_jdbcDriver

Due to licensing restrictions, we cannot ship any Oracle dependencies.
If you want to use an Oracle database, upload a JDBC driver here.

The driver can be downloaded from [Oracle](https://www.oracle.com/database/technologies/appdev/jdbc-downloads.html).

Note that both the component (`nevisidm`) and the database migration tool (`nevisidmdb`) need a JDBC driver to access the database. 
In a classic deployment, the driver will therefore be added to 2 different instance directories.

In Kubernetes setups, and when `Database Management` is enabled, you have to configure `Volume Claim` **instead** of uploading the JDBC driver here. 
This is to avoid committing binary files to Git during the deployment process.


# NevisAdaptFeedbackConfig_proxy

Reference for the nevisProxy instance to set up frontend addresses.

# SocialLoginBase_nevisIDM

Choose which nevisIDM instance you want to store the user's information after logged in with social login provider.

# NevisLogrendLogSettings_serverSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# NevisIDMPruneHistoryJob_cronExpression

Enter a cron expression which defines when this job will be executed.

Cron expressions consist of 6 required fields and one optional field separated by white space.

The field order is:

1. Seconds
2. Minutes
3. Hours
4. Day-of-Month
5. Month
6. Day-of-Week
7. Year (optional)

Cron expression can be complex and this pattern only validates the length.
The most important wildcards are:

- `*` is used to specify all values. For example, `*` in the minute field means _every minute_.
- `?` is allowed for the day-of-month and day-of-week fields. It is used to specify _no specific value_.
- `-` is used to specify ranges.

Further information about the supported syntax can be found in the javadoc of
[org.quartz.CronExpression](https://www.javadoc.io/doc/org.quartz-scheduler/quartz/latest/org/quartz/CronExpression.html).

Examples:

- `0 0 0 * * ?`: fires every midnight.
- `0 0/30 8-9 5,20 * ?`: fires every half hour between the hours of 8 am and 10 am on the 5th and 20th of every month.
- `0 30 10-13 ? * WED,FRI`: fires at 10:30, 11:30, 12:30, and 13:30, on every Wednesday and Friday.

# SecurosysKeyStoreProvider_securosysPin

The PIN for accessing the materials on the HSM.

You must set it as a variable for security reasons.

# TCPSettings_keepAliveByClient

Forces TCP connections to only be reused for the same client. A call from a different client will use another TCP connection from the connection pool. If set to `default`, the nevisProxy default will be used.


# OAuth2UserInfo_path

Enter the path where the endpoint shall be exposed on nevisProxy.

Use the `exact:` prefix to expose only the given path.
Without this prefix sub-paths will be accessible as well.
This is because a normal mapping with `/*` at the end will be created in nevisProxy.


# OutOfBandManagementApp_realm

Configure an authentication realm, which will protect the device management application.

# GenericSocialLogin_providerType

The provider type of the social account: either `OpenID Connect` or `OAuth2`.


# AuthServiceBase_host

Assign a `Virtual Host`.

# NevisAdaptDeployable_deviceCookieName

Provide a name for the cookie that will be used as the volatile identification for a browser.

Leave this configuration empty if you want to keep the default value of `DEVICE_COOKIE`.

# LogSettingsBase_rotationType

Select log rotation type.

Choose between:

- `size` - defines the maximum file size before the log files are rolled over
- `time` - defines the time span after which logs are rolled over

If you rotate by time we recommend you monitor the disk usage as log files can be huge.

Note: a combination of size and time based log rotation is not supported.


# OnDemandEntry_level

Define the authentication level that this flow produces on successful execution.

The step assigned to `On Entry` (or a subsequent step) must achieve at least this level.

# NevisAdaptDeployable_feedbackConfig

Provide additional settings for defining the details of the distrust session mechanism:

- JWE key to generate new tokens with
- nevisAuth reference to distrust and terminate sessions there as well
- nevisProxy reference to build the distrust feedback URI
- action to take on received token
- token lifetime
- redirect URL after sending the token

# OAuth2Client_clientId

Enter the Client ID.

# HostContext_listen

The physical address(es) to bind on, with scheme HTTP or HTTPS and ports. 

Must be set when multiple virtual hosts should listen on the same endpoint
(name-based virtual hosts).

If not set the `Frontend Addresses` will be used to bind.

The host name must resolve to an IP which is bound to a network interface.

You can also use `0.0.0.0` for the host name to listen on all network interfaces.

Examples:
```yaml
https://www.siven.ch:8443
http://localhost:8080
https://192.168.1.1:443
http://0.0.0.0:80
```

# ServiceAccessBase_backends

Enter the complete URLs (scheme, host, port and path) of the backend services. 

Note: 

- all URLs must use the same scheme and path.
- automatic path rewriting will be performed when the path differs from the `Frontend Path`.

In case you are setting multiple addresses, the first one will be chosen as the primary resource.

* When the primary resource cannot be accessed, nevisProxy will attempt to use the next resource.
* Even when the primary resource is reachable again, the request will still go to the current resource until the end of the session. 
However, for new sessions the primary resource is used.

# NevisIDMPasswordLogin_reenterExpiredPassword

When the password is expired or has been reset by an administrator, 
the user is forced to set a new password.

Set this drop-down to `enabled` to force the user to enter the old password again
when this happens.

# JWTToken_issuer

The issuer (`iss`) is an optional claim
which may be checked by applications receiving this token.

# GenericSMTPChannel_smtpUser

If a username is required at the SMTP server enter it here.

# NevisIDMUserUpdate_onSuccess

Define how to continue after user update.

# RoleCheck_found

Assign a step to continue with when the user has **any** of the configured roles.

If no step is assigned, the authentication flow will be done and the user is authenticated.


# DatabaseBase_rootCredentialNamespace

Set if the `Root Credential` is in a different Kubernetes namespace.


# OAuth2AuthorizationServer_tokenEndpoint

The endpoint to exchange the authorization code for tokens.

Use the `exact:` prefix to expose only the given path.
Without this prefix sub-paths will be accessible as well.
This is because a normal mapping with `/*` at the end will be created in nevisProxy.


# NevisIDMServiceAccessBase_backendTrustStore

Assign a trust store if you want to validate the server certificate used by nevisIDM.
If this not set, the connection is 1-way TLS.

# OutOfBandManagementApp_path

The path at which the management app shall be accessible at the frontend.

# NevisDetectCoreDeployable_persistency

Add reference for a nevisDetect Persistency Instance pattern.

# NevisIDMDeployable_smtpTLSMode

Choose between:

- `disabled` - SSL/TLS is disabled. The `SMTP Trust Store` is not used.
- `STARTTLS` - uses the `STARTTLS` command (see RFC 2487) to switch to SSL/TLS if supported by the SMTP server.

# NevisIDMServiceAccessBase_nevisIDM

References a nevisIDM Instance.

# OAuth2AuthorizationServer_invalidRedirectUri

Configure the step to execute when the `redirect_uri` request parameter value is not registered for the client sending the request.

If no step is configured here the flow ends and an error will be displayed.


# NevisAuthDatabase_passwordType

Choose between:

- `automatic`: behaves like `command` when the password starts with `/opt/`.
- `command`: use when the input is a command. In `esauth4.xml` the prefix `pipe://` will be added.
- `plain`: take the password as-is.


# SamlIdpConnector_audienceCheck

Define how to validate the optional `Audience` element of received SAML assertions.

- `disabled` - `Audience` is not checked
- `lax` - if present the `Audience` has to match the `Allowed Audience`
- `strict` - the `Audience` element must be present and must match the `Allowed Audience`

# SharedStorageSettings_storageClassName

The name of the StorageClass. The selected storage should support ReadWriteMany access.

For example: `azurefile`

For more information regarding persistent volume types in Kubernetes please visit this [page](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#types-of-persistent-volumes)

# HostingService_resources

Upload your resources here. 

All files will be deployed in the same directory.
Please use standard extensions (e.g. .css, .png, .html, .htm) only.

If you want to use subdirectories please upload a .zip file instead. 
The content of the .zip file will be unpacked.

# KeyObject_properties

Add `property` child elements to the `KeyObject` element.


# NevisFIDODeployable_logging

Assign a pattern to customize the log configuration.


# LdapLogin_delegateMap

Defines mappings from LDAP attributes to delegate names.
The specified LDAP attributes are queried and set as output arguments with the specified output argument name.


* `<attribute-name-in-directory>:<output-argument-name>`
* `<attribute-name-in-directory>`

Examples: 
* `givenName` 
* `mail:email`
* `telephoneNumber:user.mobile`


# NevisDetectRiskPluginBase_keyStore

Used when simple or mutual (2-way) HTTPs is configured.
If no pattern is assigned here automatic key management will provide the key store.

# NevisIDMChangePassword_nowLocked

Assign an authentication step to execute when the status of the URL ticket or credential is **nowLocked**.


# NevisAdaptDeployable_ipReputationUpload

Provide a file attachment for the IP reputation service to use.

**Please consider uploading the file manually if its size exceeds 20MB, then adjust the path `ipReputationMappingFile`
in *nevisadapt.properties* after deployment if needed.**

Every line should contain a single blacklisted IPv4 range in [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) format: 

`A.B.C.D/E` or `A.B.C.D` (A/B/C/D: [0-255]; E: [0-32])

The IP ranges should not intersect each other.

The IP-mapping file has to be updated regularly for the service to stay relevant.
We recommend [setting up periodic update of IP geolocation and reputation mappings](https://docs.nevis.net/nevisadapt/Installation-of-nevisAdapt/Setting-up-periodic-update-of-IP-geolocation-and-reputation-mappings).


# NevisIDMAuthorizationsAddon_rolePermissionsFile

Add properties for `rolesMapping.properties`. 
If a role not defined in the uploaded file default values will be used for it.

See [Functional authorization - nevisIDM roles](https://docs.nevis.net/nevisidm/Configuration/Security/Authorization-in-nevisIDM/Functional-authorization---nevisIDM-roles) for details.

The following permissions are allowed:

- ApplicationCreate, ApplicationDelete, ApplicationModify, ApplicationSearch, ApplicationView
- AuthorizationApplCreate, AuthorizationApplDelete, AuthorizationApplSearch, AuthorizationApplView,
- AuthorizationClientCreate, AuthorizationClientDelete, AuthorizationClientSearch, AuthorizationClientView
- AuthorizationCreate, AuthorizationDelete, AuthorizationModify, AuthorizationSearch
- AuthorizationEnterpriseRoleCreate, AuthorizationEnterpriseRoleDelete, AuthorizationEnterpriseRoleSearch, AuthorizationEnterpriseRoleView
- AuthorizationUnitCreate, AuthorizationUnitDelete, AuthorizationUnitSearch, AuthorizationUnitView
- AuthorizationView, 
- BatchJobExecute, BatchJobView
- ClientApplAssign, ClientApplDelete, ClientApplView
- ClientCreate, ClientDelete, ClientModify, ClientSearch, ClientView
- CollectionCreate, CollectionDelete, CollectionModify, CollectionView
- ConsentView
- CredentialChangeState, CredentialCreate, CredentialDelete, CredentialModify, CredentialPdfView, CredentialSearch, CredentialView, CredentialViewPlainValue
- EnterpriseAuthorizationCreate, EnterpriseAuthorizationDelete, EnterpriseAuthorizationModify, EnterpriseAuthorizationSearch, EnterpriseAuthorizationView
- EnterpriseRoleCreate, EnterpriseRoleDelete, EnterpriseRoleModify, EnterpriseRoleSearch, EnterpriseRoleView
- EnterpriseRoleMemberCreate, EnterpriseRoleMemberDelete, EnterpriseRoleMemberSearch
- EntityAttributeAccessOverride
- GenerateReport
- HistoryView
- LoginIdOverride, LoginIdModify
- PersistentQueueView, PersistentQueueDelete
- PersonalQuestionCreate, PersonalQuestionDelete, PersonalQuestionModify, PersonalQuestionView, PersonalQuestionSearch
- PolicyConfigurationCreate, PolicyConfigurationDelete, PolicyConfigurationModify, PolicyConfigurationSearch, PolicyConfigurationView
- ProfileArchive, ProfileCreate, ProfileDelete, ProfileModify, ProfileSearch, ProfileView
- DeputyCreate, DeputyDelete
- PropertyAllowedValueCreate, PropertyAllowedValueDelete, PropertyAllowedValueModify, PropertyAllowedValueSearch, PropertyAllowedValueView, PropertyAttributeAccessOverride
- PropertyView, PropertyCreate, PropertyDelete, PropertyModify, PropertySearch
- PropertyValueCreate, PropertyValueDelete, PropertyValueModify, PropertyValueSearch, PropertyValueView
- RoleCreate, RoleDelete, RoleModify, RoleSearch, RoleView
- SearchResultsExport
- SelfAdmin
- TemplateView, TemplateCreate, TemplateDelete, TemplateModify, TemplateStore
- TemplateTextCreate, TemplateTextDelete, TemplateTextModify, TemplateTextView 
- TermsCreate, TermsDelete, TermsModify, TermsView
- UnitCreate, UnitCreateTopUnit, UnitDelete, UnitModify, UnitSearch, UnitView
- UnitCredPolicyCreate, UnitCredPolicyDelete, UnitCredPolicyView
- UserArchive, UserCreate, UserDelete, UserModify, UserSearch, UserView
- UserCreateTechUser, UserModifyTechUser, UserDeleteTechUser, UserArchiveTechUser

#### User related fine-grained permissions

For permissions `UserModify` and `UserView` a more fine-grained permission can be used.

See [Configuration of fine-grained permissions](https://docs.nevis.net/nevisidm/Configuration/Security/Authorization-in-nevisIDM/Functional-authorization---nevisIDM-roles#configuration-of-fine-grained-permissions) for details.

#### Credential-type specific permissions
For permissions related to credentials (such as CredentialChangeState, CredentialCreate, CredentialDelete, CredentialModify, CredentialPdfView, CredentialSearch, CredentialView, and CredentialViewPlainValue), it's permissible to reduce the elementary permission to specific credential type(s).

See [Credential-type specific permissions of nevisIDM roles](https://docs.nevis.net/nevisidm/Configuration/Security/Authorization-in-nevisIDM/Functional-authorization---nevisIDM-roles#credential-type-specific-permissions-of-nevisidm-roles) for details

# BehavioSecPluginPattern_flagDescMappings

List of BehavioSec report flag names with their description name in the following format: `<flagName>=<descriptionName>`. Please add each entry line-by-line.

If any of these flags contain true value in the report, it will be added to the respective header 
field along with the mapped description value.

To delete a default mapping, omit the description field's name: `<flagName>=`.
If the flag is part of the default mapping, it will be overwritten, otherwise added.

Default combined values (flag name/description name):
- advancedUser/advancedUserScore
- deviceChanged/deviceDesc
- deviceIntegrity/deviceIntegrityDesc
- diError/diDesc
- finalized/finalizeTimestamp
- isBot/botDesc
- isDuplicate/duplicateDesc
- isRemoteAccess/raDesc
- isReplay/replayDesc
- isSessionCorrupted/isSessionCorruptedDesc
- locationMismatch/locationMismatchDesc
- newCountry/ipCountry
- numpadUsed/numpadRatio
- otjsError/otjsDesc
- pdError/pdDesc
- pocUsed/pocRatio
- tabUsed/tabRatio
- travelTooFast/travelTooFastDesc
- uiConfidenceFlag/uiConfidence
- uiScoreFlag/uiScore


# UserInformation_title

Enter a label for the title. No expressions are supported.

By default, the label `title.login` is used. 
This label is which is translated as `Login` in all languages.

We recommend to use a different label depending on your use case.

Translations for the label can be defined in the realm pattern.


# GoogleLogin_claimsRequest

The claims request parameter. This value is expected to be formatted in JSON and does not accept trailing spaces nor tabs.

# DummyLogin_level

Set an authentication level.

# NevisFIDODeployable_frontendKeyStore

Assign the key store to be used for the HTTPS endpoint.

If no pattern is assigned a key store will be generated.
This requires automatic key management to be enabled in the inventory.


# NevisProxyDeployable_crashRecoveryStrategy

Defines how to handle process crashes.

Choose between:

- `recommended`: uses `recover` for classic and `kill` for Kubernetes deployments;
- `recover`: the child process is recovered by the parent process;
- `block`: every request will be blocked by `503 Service Unavailable` status code;
- `kill`: the whole nevisproxy process (including the parent process) is killed.
This works only if the owner of the child process has the permissions to kill the parent process (for example in some Kubernetes setups).
Otherwise, this option works like `block`.

Note for `block` and `kill`: these actions take place if at least one request was being processed when the crash occurred.
These features can be useful for liveness test in Kubernetes setups, so the given pod can be terminated normally in case of a crash.
Using one of these options in a classic setup requires to restart nevisProxy with an external tool after a crash.


# GenericAuthenticationStep_level

Optionally define an authentication level which will be set
if the user has passed this step successfully.

# GoogleLogin_scope

Select the request scope(s) for getting user information from Google. Default scopes is `email`.

Scope `openid` will be added automatically because Google is implement based on OpenID protocol.

Scope `offline_access` for generate refresh token. This scope will transfer to `access_type=offline` request parameter for matching with Google spec

# HostContext_truststore

Set a trust store to validate client certificates
for incoming TLS connections.

The trust store may contain an arbitrary number of CA certificates.
Client certificates must be signed by those CAs.

**Caution**: client certificate authentication is not enabled automatically. 
As of release 4.3.1 there are no dedicated patterns but client cert authentication 
can be enforced for the entire host (e.g. using `Generic nevisProxy Settings`) 
or in the authentication process (`X509State` and `IdentityCreationFilter` init-param `ClientCert`).

# JWTToken_subject

Enter a nevisAuth expression for the claim `sub`.
The default refers to the ID of the authenticated user.

# NevisIDMUpdateUserLoginInfo_onFailure

Assign a step to execute if the nevisIDM is not able to update a User's login info.

For instance, you may assign the following steps:

- `User Information`: show an error message and terminate the authentication flow.


# GenericSocialLogin_clientSecretMethod

The method used for authenticating the client. It can be either `Basic Authentication` or `POST`.
The default value is `Basic Authentication`.

# NevisIDMServiceAccessBase_backendKeyStore

Assign a key store if you want to use 2-way TLS for the connection between nevisProxy and nevisIDM.

# SecretTestAddon_secretFiles

Set a variable and upload secret file(s) in the inventory.

The file `/var/opt/nevisproxy/<instanceName>/run/secret_files.txt` should then contain:

- classic: resolved value(s)
- Kubernetes: `inv-res-secret://` reference(s)

# OAuth2Client_secret

Enter the Client Secret. 

Configuration is required for certain flows only.

# GenericDeployment_ownerPermission

Read-write permissions for specified owner of the directory. All files and subdirectories (including unpacked from single .zip) will have the same permissions. 
The executable bit will be set automatically for readable directories and for readable `Executable Files`.

# GenericHostContextSettings_removeFilterMappings

Remove `<filter-mapping>` elements generated by other patterns.

This is an advanced configuration. 
Use only when you want to remove a `<filter-mapping>` but keep the `<filter>` element,
e.g. to map it on a sub-location.

The syntax is a map of `<filter-name>:<url-pattern>`, according to values from the `web.xml`.

For instance, the following would remove the `ErrorHandler_Default` from `/*`:

```
ErrorHandler_Default:/*
```

# OAuth2AuthorizationServer_oidc

If enabled the scope openid is allowed for this client.

# NevisAdaptDeployable_suspiciousCountryCodeList

Provide a list of two-letter ISO country codes of considerable risk.

Input method 1: Single line - comma-delimited

Input method 2: One country code entry per line

ISO code description can be found at: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2

# GenericSMTPChannel_smtp

Enter host:port of the SMTP server.

# NevisIDMPasswordLogin_separateScreens

Set to `enabled` to ask for the username and password in two separate screens.

# InBandMobileAuthenticationRealm_fidoKeyStore

Assign a pattern which provides the key store for nevisAuth to connect to nevisFIDO with client TLS.

# OATHOnboarding_onSuccess

Assign a step to execute **after** onboarding the authenticator app.

We recommended to assign `OATH Authentication` to validate that the onboarding was successful.

Also note that the `nevisIDM Second-Factor Selection` pattern only considers OATH credentials 
which have passed the `OATH Authentication` once.

If no step is assigned the process ends and the user will be authenticated.


# NevisIDMDatabase_oracleVolumeClaimName

Due to licensing restrictions, we cannot ship any Oracle dependencies.

If you are using an Oracle database, are deploying to Kubernetes, and `Database Management` is _enabled_ (`complete` or `schema`), 
then you have to provide a Kubernetes volume containing an Oracle driver and client.

For more information, see [Preparing Oracle Volume](http://docs.nevis.net/nevisadmin4/Installation/Software-Installation/Kubernetes-Based-Installation/Prepare-Oracle-Volume).

Enter the name of that volume here.

The volume will be mounted in the `nevisidm-dbschema` image to set up and patch the database schema.

The volume will be mounted in the `nevisidm` image to connect to the database.
Because of that, there is no need to upload a `JDBC Driver`.


# Maintenance_start

Enter the start date and time of the maintenance window.

- format: `yyyy-mm-dd HH:mm` (24 hours)
- timezone: UTC (not your local time)
- example: `2020-05-20 15:00`

# OAuth2Client_profile

Set to `allowed` to allow this client to request the scope `profile`.

This scope produces various claims.

# OATHOnboarding_nevisIDM

Reference the nevisIDM Instance which has been used for first factor authentication.

# HeaderCustomization_requestPhase

- `BEFORE_SANITIATION` - manipulate request headers early to hide them from validation and authentication.
- `AFTER_AUTHENTICATION` - the original values are subject to validation and can be accessed in the authentication flow.
The header manipulation is applied afterwards to affect the application only.
- `END` - manipulate request headers late, just before the request is forwarded to the application.

# NevisIDMProperty_propertyScope

Select the type of property:

- `USER_GLOBAL`: all users have this property
- `CREDENTIAL_GENERIC_GLOBAL`: all `Generic` credentials have this property
- `UNIT_GLOBAL`: all units have this property


# GenericWebBase_parameters

Define _Template Parameters_.

Examples:

```yaml
backend-host: backend.siven.ch
```

These parameters can be used in:

* `Servlets and Mappings`
* `Filters and Mappings`

The expression formats are:

`${param.<name>}`:

- `name` found: parameter value is used.
- `name` missing: expression is **not** replaced.

`${param.<name>:<default value>}`:

- `name` found: parameter value is used.
- `name` missing: default value will be used.

In `<default value>` the character `}` must be escaped as `\}`.

# TestingService_onPlanning

Use for testing only.

# NevisAdaptRememberMeConnectorStep_clientTrustStore

The trust store used by this pattern to establish a connection with the nevisAdapt component.
This trust store must trust the `nevisAdapt Instance`'s key store. Please reference a trust store provider pattern or leave empty to manage the trust store with nevisAdmin automatic key management.

# NevisAuthRealmBase_sessionTracking

Choose between:

- `COOKIE`: issue a session cookie.
- `AUTHORIZATION_HEADER`: track the session based on the value of the Authorization header.
- `CUSTOM`: track the session based on custom configuration. It generates an empty session filter which has to be replaced (see below).
- `disabled`: disable session tracking.

### CUSTOM session tracking

Given a pattern name of SSO, the following empty filter will be generated:
```xml
    <filter>
        <filter-name>SessionHandler_SSO</filter-name>
        <filter-class>__REPLACE_USING_GENERIC__</filter-class>
    </filter>
```
For the filter-class, a placeholder (__REPLACE_USING_GENERIC__) will be used and that placeholder has to be overwritten.

Another pattern must complete the session filter. For example, use `Generic Virtual Host Context` pattern with the following Filters and Mappings configuration:

```xml
<filter>
	<filter-name>SessionHandler_SSO_RealmName</filter-name>
	<filter-class>ch::nevis::nevisproxy::filter::session::SessionManagementFilter</filter-class>
	<init-param>
		<param-name>Identification</param-name>
		<param-value>CUSTOM</param-value>
	</init-param>
	<init-param>
		<param-name>Custom.RequiredIdentifiers</param-name>
		<param-value>HEADER:Authorization</param-value>
	</init-param>		
	<init-param>
		<param-name>Servlet</param-name>
		<param-value>LocalSessionStoreServlet</param-value>
	</init-param>
</filter>
```

# RequestValidationSettings_ruleBundle

Add a Rule Bundle pattern for global or group ModSecurity rule configuration.


# NevisLogrendDeployable_logrendProperties

Add or overwrite properties in `logrend.properties`.

You can use the following expressions (format: `${...}`):

- `${protocol}` - depends on `HTTPs` setting
- `${host}` - depends on `Bind Host` setting
- `${port}` - will be replaced with `TCP Service Port`
- `${instance}` - contains the instance name

This is an advanced setting which should be used in complex setups only.
If you have to configure anything here we are looking forward for your use case.


# SocialLoginExtender_socialLogin

Quick win solution for ID Cloud to short-cut the 
automatic lookup logic.


# CustomNevisIDMLogFile_maxFileSize

Maximum allowed file size (in bytes) before rolling over. 

Suffixes "KB", "MB" and "GB" are allowed. 10KB = 10240 bytes, etc.

Note: This parameter only applies to ``application.log`` and ``batch.log`` (as ``audit.log`` is configured with ``DailyRollingFileAppender``).

# NevisDPDeployable_configuration

The `dataporter.xml` must be uploaded here.

Click `Download Configuration Template` to get started.

# 4.14.0

Full changelog: 

[Patterns 4.14.0 Release Notes - 2022-02-16](https://docs.nevis.net/nevisadmin4/release-notes#patterns-4140-release-notes---2022-02-16))

##### Log Settings

The configuration options for `Log Targets` have been adapted to fit Kubernetes deployment.
If you get an error please select one of the available options.

Support for Syslog forwarding has been deprecated. If you need Syslog forwarding
please get in touch to discuss your requirements before May 2022 when Syslog forwarding support will be removed.

The Generic Log Settings patterns have been deprecated. If you are using them
please get in touch to discuss your requirements before May 2022 when these patterns will be removed.

##### nevisIDM Encryption

Since this release the security settings used by NevisIDM to store encrypted properties and URL tickets are exposed.
Setting the `Encryption Key` is mandatory to enforce the proper handling of these settings.
For setups with existing encrypted data in the database you can enable a fallback mechanism.
However, it is recommended to disable the fallback as soon as possible for stronger security.

##### nevisAuth Client Authentication

Since this release we don't generate `Frontend Trust Store` any more when `Client Authentication`
is `disabled` in `nevisAuth Instance` patterns.

This requires nevisAuth version `4.34` or later. 
You must upgrade nevisAuth before deploying to avoid connection issues.

##### Realm Translations Encoding

Up to (and including) pattern version 4.13.0 `Translations` in realm patterns supported ASCII encoded files only.
By accident ISO-8859-1 encoded files were also working in some scenarios.

Since release 4.13.1 the encoding is fixed to `UTF-8` and thus invalid characters were displayed in some setups.

This release fixes the remaining encoding issues. Only the following encodings are supported:

- ASCII with HTML escaped special characters
- UTF-8

If a character is detected in the uploaded files that cannot be represented in UTF-8 a warning message will be shown.

Further, trying to set `-Dch.nevis.esauth.litdict.charset.encoding` using `Generic nevisAuth Instance Settings` will raise an error.

If you get a warning or error message adapt your pattern configuration accordingly.


# AccessRestriction_listingType

Indicates if `Source IPs` should be used as blacklist or whitelist.

- `blacklist`: Access from all configured `Source IPs` is denied. All other IPs are allowed.
- `whitelist`: Access is allowed only for IPs in the `Source IPs` list. All other IPs are blocked.

# AuthorizationPolicy_subPaths

Set to apply this pattern on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table provides examples to illustrate the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |

# MobileDeviceDeregistration_realm

To provide the best possible security, the nevisFIDO APIs required for mobile device deregistration may be protected by [In-Band Authentication](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/in-band-authentication).

Assign an `In-band Mobile Authentication Realm` here.


# NevisIDMAccountRecovery_nevisIDM

Reference a nevisIDM Instance to be used for checking terms and conditions.

# RealmBase_sessionTimeout

Defines the idle timeout of a nevisProxy session.

A nevisProxy session will be created only if required (e.g. to store application cookies).

Please set the timeout as low as possible to not increase the risk of session exhaustion attacks.

# DummyLogin_label

Set to show a different message.

# Maintenance_updateInterval

Enter the time interval between checks of the maintenance page.

- In normal mode, the system checks the maintenance page for updates when a request comes in, if the configured interval has passed since the last check.
- In maintenance mode, the system ignores the `UpdateInterval` and fetches the maintenance page on each request.


# NevisDPLogSettings_regexFilter

If set, messages for `dataporter.log` which match the given regular expression won't be logged.

The regular expression must match the entire line.
For instance, you may use the following format to match `some text`:

```
.*some text.*
```


# RequestValidationSettings_level

Sets the `paranoia level` of the ModSecurity OWASP Core Rule Set (CRS).
Please see https://coreruleset.org/faq/ for more details.

- Paranoia level `1` (PL1) is recommended for beginners and setups with standard security requirements. If you encounter false positives at PL1 OWASP recommends to raise an issue at their Github site.

- Paranoia level `2` (PL2) includes SQL, XSS and code injection rules. PL2 is recommended for setups with elevated security requirements and advanced users. 

- Paranoia level `3` (PL3) enables additional rules and keyword lists to cover less common attacks. Consider PL3 if you are experienced at handling false-positives and for sites with high security requirements. 

- Paranoia level `4` (PL4) also restricts special characters. PL4 may produce a lot of false positives so please do extensive testing before going into production.

# LogSettingsBase_maxFileSize

Maximum allowed file size (in bytes) before rolling over. 

Suffixes "KB", "MB" and "GB" are allowed. 10KB = 10240 bytes, etc.

Note: not relevant when rotation type is `time`.

# RealmBase_timestampInterval

Sets the minimum time interval between two updates of the session timestamp.

If the parameter is set to "0", the system will update the session timestamp each time a request accesses a session.

The `Initial Session Timeout` is used as `Update Session Timestamp Interval` if it is shorter than the duration configured here.

# NevisDPLogSettings_levels

Configure log levels.

See nevisDataPorter Technical Documentation, chapter
[Logging, tracing, debugging, and profiling](https://docs.nevis.net/nevisdataporter/Operation-and-Administration/logging-tracing_debuging_profiling) for details.

Hint: If you only change log levels nevisAdmin 4 does not restart the component in classic VM deployment.
The new log configuration will be reloaded within 60 seconds after deployment.

The default configuration is:

```
dataporter = INFO
```

Examples:

```
dataporter.config=INFO
dataporter.statistics=INFO
```


# MicrosoftLogin_clientSecret

Client Secret is `Client Secret` provided by Microsoft when you create an Application `Credentials & Secrets` in Microsoft.

# NevisAdaptAnalyzerConfig_ipAnalyzer

Used to disable IpAddress analysis. If you wish to disable filtering for private address,
the configuration can be found at `nevisAdapt Instance / IP Geolocation`.


If you wish to disable this setting
also consider disabling the IP Geolocation settings as well in the `nevisAdapt Instance / IP Geolocation` configuration
and the `nevisAdapt Instance / IP Reputation` configuration.

# SamlIdp_authenticationType

Select which authentication types are allowed:

- `SP-initiated`: recommended
- `IDP-initiated`: less secure as no `AuthnRequest` is sent.


# NevisAdaptLogSettings_serverSyslogFormat

[Logback log format](https://logback.qos.ch/manual/layouts.html#conversionWord) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# CustomAuthLogFile_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.

# NevisIDMUpdateUserLoginInfo_onSuccess

Configure the step to execute after the user's login info is updated.
If no step is configured here the process ends with `AUTH_DONE`.

# NevisAuthDeployable_threads

Number of threads to process incoming requests.



# CustomAuthLogFile_eventLog

Enable event logging capability of nevisAuth. 

# JWTToken_header

When this pattern is assigned to an application, 
the JWT token will be added to all requests which are forwarded to that application.

Here you can define the name of the HTTP header which should contain the token.

# CustomProxyLogFile_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.

# SamlIdpConnector_signerTrust

Assign a pattern to configure the signer certificate of the identity provider.

# NevisMetaDatabase_schemaUser

The user which will be used to connect to the database and create the schema (tables).

The database must have been created already (`CREATE DATABASE`)
and the user must have `CREATE` privileges for this database.

Example: `umet01`


# TANBase_level

Set an authentication level if authentication of this step is successful. 
The level is relevant only if there are is an Authorization Policy assigned to applications.


# NevisAuthDeployable_differingResourceStartover

Define the value of the `AuthEngine` attribute `differingResourceStartover`.

- `enabled`: `true` is set.
- `disabled`: `false` is set.

Do not change this unless you know what you are doing.


# NevisAdaptAuthenticationConnectorStep_onUntrained

Set the step to continue with in case the user is untrained.

Risk Profile configuration: Setting this step is optional, but the highest available from High and Medium step will replace it.

Risk Event configuration: Setting this step is mandatory.

# NevisAdaptAnalyzerConfig_geoIpAnalyzer

Geo/IP Analyzer is a global setting, disabling this
means that the device analyzer will not be used to
calculate risk scores. This will result in a lower
risk score for all users.

If you wish to disable, consider disabling all other submodules as well.



# SamlIdpConnector_nextSteps

Assign follow-up steps.
 
The order of steps is relevant. 
The first step in this list has index `1`. 
 
You may reference a step in the configuration
via the `Custom Transitions`.

# NevisIDMPruneHistoryJob_retention

Define how long history data shall be kept in days.

Example: `30d`

The minimum value is `1d`. The maximum value is `1024d`.

# ApplicationProtectionDeployableBase_trustStore

Reference a trust store provider pattern or leave empty to manage the trust store with nevisAdmin.

# SamlSpConnector_multiValue

This setting defines how multi-value attributes are added to the SAML Assertion.

Example for `enabled`:

```xml
<saml2:Attribute Name="example">
  <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">value 1</saml2:AttributeValue>
  <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">value 2</saml2:AttributeValue>
</saml2:Attribute>
```

Example for `disabled`:

```xml
<saml2:Attribute Name="example">
  <saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">value 1,value 2</saml2:AttributeValue>
</saml2:Attribute>
```

# GenericDeployment_deleteUnknownFiles

If enabled, all files in the directory (`Path` property) that are not specified under `Files` are deleted.

If you enable this property your files must be in one of the following directories or subdirectories:
* `/var/opt`
* `/tmp`
* `/home`

# GenericSMTPChannel_smtpPass

If a password is required at the SMTP server enter it here.

# SamlSpConnector_subjectConfirmation

Many SAML service providers require a subject confirmation element to be present in the SAML assertion.

Select `bearer` to add a bearer subject confirmation.

Further options may be provided in future releases.

It may be required to set additional properties. Consult the documentation
of the nevisAuth `IdentityProviderState` and apply them via `Custom Properties`.

# NevisAdaptAuthenticationConnectorStep_onTimeout

Set the step to continue with in case the authentication attempt runs into a timeout.

Risk Profile configuration: Setting this step is optional, but the highest available from High and Medium step will replace it.

Risk Event configuration: Setting this step is mandatory.

# NevisMetaServiceAccessBase_backendKeyStore

Assign a key store if you want to use 2-way TLS for the connection between nevisProxy and nevisMeta.

# ServiceAccessBase_path

The (base) path of the application.

Examples:

- `/app/` - defines a base path. 
Any requests which have a path component starting with `/app/` will be sent to this application.
- `/` - forward all requests to this application. 
Use this only when there are no other applications or hosted resources.
- `exact:/app.html` - matches requests to `/app.html` only (query parameters are allowed). 
Use this for single-page applications which don't require any additional resources.

Note that if the frontend path is different from the path used within `Backend Addresses` 
then URL rewriting will be configured to correctly route
requests and responses between clients and backends.

# AuthCloudLogin_onUserNotExists

Assign an authentication step to continue with when the user does not exist or has no active authenticator.

If no step is assigned here the authentication flow will fail for such users.


# NevisAdaptDeployable_port

Enter the port on which nevisAdapt will listen.

# NevisFIDODeployable_authorizationDeregistration

TODO

# NevisFIDODatabase_encryption

Enables SSL/TLS in a specific mode. The following values are supported:

- `disabled`: Do not use SSL/TLS (default)
- `trust`: Only use SSL/TLS for encryption. Do not perform certificate or hostname verification. This mode is not safe
  for production applications but still safer than `disabled`.
- `verify-ca`: Use SSL/TLS for encryption and perform certificates verification, but do not perform hostname verification.
- `verify-full`: Use SSL/TLS for encryption, certificate verification, and hostname verification.


# SamlIdp_metadataService

When `enabled` a _SAML Metadata Service_ will be generated
which can be accessed on the `Metadata Service Path`.

The SAML Metadata Service is not protected by authentication.

# NevisDetectCoreDeployable_riskPlugins

List of Risk Plugins that are loaded by this nevisDetect Core component

# Button_label

Enter the label which shall be used for this button.

The label should be added to the `Translations` of the realm.


# TransactionConfirmation_host

Assign a `Virtual Host` to expose the transaction confirmation services.

The following public endpoints can be invoked:

- `/nevisfido/token/dispatch/authentication`
- `/nevisfido/status`
- `/nevisfido/token/redeem/authentication`
- `/nevisfido/uaf/1.1/facets`
- `/nevisfido/uaf/1.1/authentication`


# 4.15.0

Full changelog: 

[Patterns 4.15.0 Release Notes - 2022-05-18](https://docs.nevis.net/nevisadmin4/release-notes#patterns-4150-release-notes---2022-05-18)

##### nevisProxy Session Store

The nevisProxy `Virtual Host` now generates only 1 `servlet` for storing sessions. 
The servlets have fixed names:

- remote session store: `MySQLSessionStoreServlet`
- local session store: `LocalSessionStoreServlet`

If you are using `Generic Virtual Host Settings` to patch a session store servlet
you will have to adapt the pattern configuration to use the new names.

##### Authorization Policy Pattern

Several new features have been added to the `Authorization Policy` pattern.
The generated filters have been renamed. 

If you are using `Generic Virtual Host Settings` to patch any of these filters,
you will have to adapt the pattern configuration to use the new names.

##### Changes related to Log Settings

Several Nevis components have migrated from Log4J v1 to Log4J v2.
The relevant Log Settings pattern have been adapted and aligned.
Generic Log Settings patterns have been removed. 
Further, log settings for nevisFIDO have been moved into a separate pattern.
If you have configured log settings you may have to adapt your pattern configuration.
The issues generated during background validation will guide you through this process.


# SamlSpConnector_issuer

Configure the _issuer_ used by the SAML service provider.

# NevisProxyObservabilitySettings_captureRespHeaders

HTTP client instrumentation will capture HTTP response header values for all configured header names.

Default in nevisProxy:
```
Content-Type, Content-Length, Content-Encoding, Location, Server, Connection, Keep-Alive, X-Forwarded-For
```

# DeployableBase_openTelemetry

OpenTelemetry is used for several use cases:

- cross-component tracing in logs
- exposing metrics

By default, OpenTelemetry is `enabled` and a Java agent is loaded.

If that Java agent is not present on the machines you are deploying to,
then you have to provide it at `/opt/agent/opentelemetry-javaagent.jar` or select `disabled`.


# PropertiesTestPattern_bytesProperty

Enter a value in bytes, kilobytes, megabytes, gigabites.
The unit should be entered with "k", "m", "gb".
Ideally, we should have a widget which helps with the unit.

# NevisMetaDeployable_clientAuth

Setting for 2-way TLS on the nevisMeta HTTPs endpoint. There are 3 options will
affect the callers (e.g. nevisProxy or technical clients accessing nevisAuth REST APIs)

* required: Callers **must** present a client certificate.
* requested: Callers **can** present a client certificate.
* disabled: Callers **must not** use a client certificate.

The `Frontend Trust Store` must contain the issuing CA.

# NevisIDMPasswordCreate_onSuccess

Assign a step to continue with after successfully creating the password credential.


# RealmBase_cookieName

By default, the session cookie will be called `Session_<pattern-name>`

Set this optional property to use a different name (e.g. `ProxySession`).

If the same name is configured for multiple realms on the same host
then the sessions will be cleaned up together when the first session expires.

# OAuth2RegistrationEndpoint_path

Enter the URL of the registration endpoint.

Note that this pattern does **not** set up a registration endpoint,
it just provides information about that endpoint.

The information is then used by the `OAuth 2.0 / OpenID Connect Metadata Endpoint` to provide metadata.

The prefix `exact:` is not supported here, enter the path as-is.


# NevisDetectPersistencyDeployable_jms

Add reference for the pattern providing Java Messaging Service.

Two different options are allowed at this time:
- `nevisDetect Message Queue Instance` - deployment pattern for a dedicated MQ component
- `ActiveMQ Client Configuration` - connect to an external ActiveMQ service via SSL

**WARNING: In case of Kubernetes deployment, only `ActiveMQ Client Configuration` is supported.**

# LdapLogin_connectionUsername

User to connect with. This user is part of the LDAP connection url.

Example:
* CN=admin,O=company,C=ch

# NevisLogrendLogSettings_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.

# GroovyScriptStep_parameters

Set parameters for your Groovy script.

Enter the **name** of the parameter as `Key`.

The `Value` can be either:

1. constant String value
2. nevisAuth expression (`${...:...}`)
3. an EL expression (`#{...}`)
4. a reference to an inventory variable (`${var.<name>}`). Such expressions are resolved during generation.

Parameters can then be used inside the Groovy script via the `parameters` map. 

Example usage: 

```groovy
parameters.get('backend-url')
```


# AuthCloudBase_instance

Instead of uploading an `access-key.json`, 
you can enter the name of your Authentication Cloud instance here.


# NevisAuthDeployable_sessionLimit

Defines the maximum number of user sessions than may be created in this nevisAuth instance.

A nevisAuth session requires at least 10kb but the session can be much bigger 
when a user has many roles or multiple tokens are used.

# SecToken_header

Set a custom header instead of the default `Authorization` header.

# SAPLogonTicket_applicationMappings

A list of user ID mappings of the form `<application>:<ID>` to be inserted in the ticket. This will be used by SAP services to retrieve local user IDs.
SAP NetWeaver Portal CRM plays a special role here as its user management is based on UME and, typically, has distinct IDs.

# GenericModQosConfiguration_hostDirectives

Host level directives can be entered here.

# BackendServiceAccessBase_hostHeader

Defines the `Host` header for requests forwarded to the application.

When `backend` is selected then nevisProxy uses the host part of the backend address that has been selected.
This is the default behaviour and similar to what a browser would do.
Therefore, this configuration should work in most cases.

When `client` is selected then nevisProxy will keep the `Host` header as received from the client.
The following `init-param` will be generated:
              
```
<init-param>
  <param-name>HostName</param-name>
  <param-value>ENV:HTTP_Host;</param-value>
</init-param>
```

The configuration is dynamic to support virtual hosts with multiple frontend addresses.
Note that this may be less secure. 
Even though browsers do not allow this clients may sent an arbitrary value for the `Host` header.
It is therefore recommended to test how your application behaves in this case.

# InBandMobileDeviceRegistration_authenticationService

Convenience feature.

If `enabled`, an endpoint will be provided at the `Authentication Service Path`.

The mobile app may use this endpoint to authenticate and obtain a cookie.

With this cookie the registration operation can be initiated.

The flow is described [here](https://docs.nevis.net/mobilesdk/integration-scenarios#in-app-registration-1).

There are several alternatives:

- use `Standalone Authentication Flow` to provide an authentication endpoint for this realm using authentication steps.
- authenticate the registration operation using the `Initial Authentication Flow` of the assigned `Authentication Realm`.


# AccessRestriction_ips

List of client source IPs which shall be allowed. You may include entire range of IPs by separating two IPs with `-`.
If there is load-balancer in front of nevisProxy please configure it to preserve the client source IP. IPv6 is not supported here.

Examples: 
- `10.0.0.1`: specific IP address
- `192.168.0.0-192.168.0.255`: range of IP addresses
- `0.0.0.0-255.255.255.255`: all IP addresses


# NevisFIDODeployable_firebaseServiceAccount

For sending push notifications, nevisFIDO needs to access Firebase, which is a push messaging service. For that, it requires an account and its corresponding credential.

Please visit the [Firebase Console](https://console.firebase.google.com/project/_/settings/serviceaccounts/adminsdk), create a project and download the ```service-account.json``` file. Please upload this file here.

Note that this file contains a private key, that gives access to your project's Firebase services. Keep it confidential at all times, and never store it in a public repository. 
Be aware that anybody who has access to this property, also has access to the file itself.


# NevisAuthRadiusResponse_condition

An expression which defines when this response is generated.

For instance, use `${response:status:0}` to return this Radius response for all `AUTH_CONTINUE` responses.
Likewise, you can use `1` for `AUTH_DONE` and `2` for `AUTH_ERROR` responses.

In complex authentication flows consisting of multiple steps 
it can be tricky to find a good expression which matches for one step only.
Please contact your integration partner if you need support.

# NevisAdaptUserNotification_sendingMethod

This mandatory property defines the communication method. For the configuration and usage of these methods, refer to the nevisIDM reference guide.


# NevisFIDODeployable_registrationTokenTimeout

Defines the maximum time a client has to redeem a registration token after the generation of the token by nevisFIDO. 

Once the token is redeemed, the `Registration Response Timeout` applies: the client has a maximum time to send a `RegistrationResponse` to nevisFIDO.

The default value is 5 minutes. If no time unit is provided, seconds will be used.

This timeout is relevant in the [Out-of-Band Registration](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/out-of-band-registration) use-case.


# OAuth2RestEndpointBase_path

If you enter a **path** the REST service will be generated and exposed on the nevisProxy `Virtual Host`
assigned to the `OAuth 2.0 Authorization Server / OpenID Provider`.

The prefix `exact:` is not supported here, enter the path as-is.

If you enter a **URL** no REST service will be generated.
Use this variant if you want to use an external service.

Either way, the information will be used by the `OAuth 2.0 / OpenID Connect Metadata Endpoint` to provide metadata.


# NevisAuthRealmBase_initialSessionTimeout

Define the idle timeout of the initial session.
The user must complete the authentication within this time.


# NevisAdaptDatabase_oracleApplicationRoleName

Name of the application role for the oracle database used for the Kubernetes migration. It's recommended to keep the default value unless the pattern is used with an existing database that has a different one.

# MobileDeviceDeregistration_host

A virtual host assigned will be used to expose the protected services.

# NevisAuthDatabase_schemaUser

The user which will be used to connect to the database and create the schema (tables).

The database must have been created already (`CREATE DATABASE`)
and the user must have `CREATE` privileges for this database.

If not set, the database connection user will be used.

Example: `schema-user`


# NevisIDMJmsQueues_expiry

NevisIDM JMS Queue to which Expiry messages should be sent.

Only accepts URIs starting with `amqp`, `amqps` or `Endpoint=sb`.
Validates only URIs with `amqp` or `amqps` schemes.

Messages in Expiry Queue are those messages which validTo time has passed without successful receive action and without failing for other reason.
For further reference check `NevisIdm Technical documentation > Configuration > Components > Provisioning module > Provisioning providers`.

# NevisAdaptAnalyzerConfig_suspiciousCountryAnalyzer

Used to disable suspicious country analysis. Use with caution.

# OutOfBandMobileAuthentication_numberMatching

Enable/disable number matching in case of push notifications.
If `enabled`, a 4-digit number will be displayed on the screen that you have to enter on your mobile device.

By default, it is `disabled`.

For more information, see [Number Matching](https://docs.nevis.net/nevisaccessapp/features/number-matching).

# NevisAuthRealm_resetAuthenticationCondition

In some setups it is required to adapt the `resetAuthenticationCondition` of the `Domain`.
You can configure a nevisAuth or EL expression here.

If the expression evaluates to `true` then the authentication flow is reset
and the request is dispatched from the beginning.

# StaticContentCache_requestHeaderMode

Request headers can force an intermediate server to override its cache and answer with the response from the original server.

Choose one of:

- **comply** : Follow the `Cache-Control: no-cache` directives sent by the client.
- **ignore** : Answer with the stored response even if the client sent a `Cache-Control: no-cache` directive.


# NevisProxyObservabilitySettings_captureReqHeaders

HTTP client instrumentation will capture HTTP request header values for all configured header names.

Default in nevisProxy:
```
Content-Type, Content-Length, User-Agent, Referer, Host, X-Forwarded-For
```

# TransformVariablesStep_emptyValue

Defines how to set the variable when null or an empty String shall be stored.

Choose between:

- `skip-variable`: do not set the variable. The current value is preserved.
- `clear-variable`: sets an empty String.
- `remove-variable`: removes the variable.


# NevisDetectEntrypointDeployable_persistency

Add reference for a nevisDetect Persistency Instance pattern.

# NevisAdaptAuthenticationConnectorStep_mediumThreshold

Will be considered only if `Profile` is set to either `balanced`, `strict` or `custom`.

Set the risk score threshold [0...1] for medium threat.

# NevisAuthRealm_langCookieName

Enter a name of the cookie that nevisLogrend issues 
to remember the language of the user.

The same name will also be used in nevisAuth to determine the language.

Note that the language cookie name is an instance global configuration in nevisAuth.
Enter the same value for all realms associated with the same nevisAuth instance.


# ObservabilityBase_type

Choose agent type:
* `OpenTelemetry` to integrate with self-hosted observability stack or with an OpenTelemetry compatible cloud provider.
* `Application Insights` to integrate with Azure Application Insights.

# OutOfBandMobileRegistration_profileId

Enter a variable expression for the profile ID.

The default works when this step is a follow-up of
`nevisIDM Password Login` or `nevisIDM User Lookup`.


# ErrorHandler_overwriteStatusCodes

Overwrite certain HTTP status code(s) by returning 
with the defined status code instead.

If for an error code both **Blocked Status Code** 
and **Overwrite Status Code** is configured, the **Blocked Status Code**
will take precedent.

Examples:
```
404,406-499 -> 401
405 -> 200
```



# NevisAuthDatabase_attributes

Add or overwrite attributes of the `RemoteSessionStore` and `RemoteOutOfContextDataStore` XML elements.

Supported attributes are described in the Nevis documentation:

- [RemoteSessionStore](https://docs.nevis.net/nevisauth/setup-and-configuration/components/session-management#configuration)
- [RemoteOutOfContextDataStore](https://docs.nevis.net/nevisauth/setup-and-configuration/components/shared-out-of-context-data#configuring-nevisauth)

If you want to set an attribute only on one of the 2 elements use the prefix `session:` or `oocd:` as illustrated below.

Examples:

| Attribute                              | Value   |
|----------------------------------------|---------|
| `syncPullInitial`                      | `true`  |
| `session:reaperThreads`                | `5`     |
| `session:storeUnauthenticatedSessions` | `false` |
| `oocd:reaperPeriod`                    | `120`   |


# NevisIDMUserLookup_onSuccess

For security reasons `nevisIDM User Lookup` alone is not sufficient to authenticate the user.

The authentication flow should contain another step which checks credentials of the user 
and sets an `Authentication Level`.

Thus, it is required to assign a step here which will be executed 
after the user has been looked up from nevisIDM.

Examples:

- `Authentication Cloud`
- `Mobile TAN (mTAN)`
- `Generic Authentication Step`

# NevisAdaptAuthenticationConnectorStep_events

Will be considered only if `Profile` is set to `events`.

Select which events to react on. The events are identified and returned by the nevisAdapt service 
and the first event combination that they match successfully will determine the next 
step in the authentication flow. No further entries of this list will be considered.

One event combination entry consists of the following properties:
- `Risk Events`: set of suspicious event(s) to match against 
- `Minimum Match Count`: minimum number of events to consider the matching valid (`all` by default). They have to be present in the service response to classify the entire combination as matching. 
- `Authentication Step`: next authentication step if the matching is valid

Complete example with full ruleset:

Combination 1:
- Risk Events: [ 'ip-reputation-blacklisted', 'suspicious-country' ]
- Minimum Match Count: 1
- Authentication Step: Authentication Fails

This combination will match successfully if any of the two selected events are being reported by the nevisAdapt service.
If this is the case, neither Combination 2 or 3 will be checked as the authentication fails immediately.

Combination 2:
- Risk Events: [ 'unknown-device', 'unknown-country', 'unknown-fingerprint' ]
- Minimum Match Count: 2
- Authentication Step: mTAN

This combination will match successfully if any 2 of the three selected events are being reported by the nevisAdapt service.
If this is the case, Combination 3 will not be checked and the next authentication step will be mTAN.

Combination 3:
- Risk Events: [ 'unknown-country', 'high-ip-velocity' ]
- Minimum Match Count: all
- Authentication Step: email

This combination will match successfully only if both events were reported by the nevisAdapt service.
If this is the case, a notification email will be sent to the user.

Otherwise, authentication succeeds without any further complication.

# NevisMetaServiceAccessBase_backendTrustStore

Assign a trust store if you want to validate the server certificate used by nevisMeta.
If this not set, the connection is 1-way TLS

# GenericAuthRestService_configFile

As an alternative to direct configuration you can upload a file 
which contains the XML. 

The file should contain `RESTService` elements only.

Uploading a complete `esauth4.xml` is not supported. 

# NevisAdaptObservationCleanupConfig_untrustedTimeframeDays

nevisAdapt stores session data that was not marked as trusted (e.g.: failed 2FA authentication)
for a certain amount of time. This is done to allow staff to investigate the issue and to provide
the user with a better experience. However, storing untrusted session data for too long can lead
to privacy issues. This pattern describes how to configure the cleanup of untrusted session data.

The default value is `12d`.

# NevisDetectCoreDeployable_jms

Add reference for the pattern providing Java Messaging Service.

Two different options are allowed at this time:
- `nevisDetect Message Queue Instance` - deployment pattern for a dedicated MQ component
- `ActiveMQ Client Configuration` - connect to an external ActiveMQ service via SSL

**WARNING: In case of Kubernetes deployment, only `ActiveMQ Client Configuration` is supported.**

# RealmBase_sessionValidation

A newline separated list of rules declaring attributes that must not change in the same session.
A rule has the following syntax:

```
ENV|CONST|PARAM|HEADER:<name of the attribute>:block|invalidate
```

- `block`: the request will be blocked and `403 (Forbidden)` will be returned
- `invalidate`: the session will be invalidated and a new one will be created

nevisProxy Conditions are supported. See nevisProxy reference guide for details.

For instance, use the following configuration to terminate the session if the source IP changes:

```
ENV:REMOTE_ADDR:invalidate
```

# DefaultService_path

The path(s) which shall be accessible on the assigned `Virtual Host(s)`.

# UserInput_title

Enter a text or _litdict key_ for the form title (`<h1>`).

# AuthCloudLogin_deepLinkLabel

Label to display on the element which allows the user to use the deep link to log in.

The element is usually a button.


# NevisAdaptFeedbackConfig_auth

Add nevisAuth Instance reference pattern(s) to enable session termination in connected components. 
If the session store is shared, it is enough to add one instance per database.

Please make sure that all involved nevisAuth Instances have ManagementService enabled.
Add or extend a `Generic nevisAuth REST Service` for each with the following configuration:

```
<RESTService name="ManagementService" class="ch.nevis.esauth.rest.service.session.ManagementService" />
```

# NevisAuthDeployable_backendTrustStore

Assign the Trust Store provider for outbound TLS connections.
If no pattern is assigned a trust store will be provided by nevisAdmin 4 automatic key management.

# URLHandler_subPaths

Set to apply this pattern on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table provides examples to illustrate the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |

# GenericDeployment_owner

Owner of the directory at specified path. All files and subdirectories will have the same owner.

# SocialLoginDone_status

Choose how to complete the flow:

* `AUTH_DONE`: user is authenticated
* `AUTH_ERROR`: session is terminated

In both cases the caller is redirect back to the path before jumping of 
to the social login provider.

When social login is behind federation (e.g. `SAML IDP`), `AUTH_ERROR` will be handled
by sending the caller back to the origin (e.g. the `SAML SP`) with a technical error message.


# NevisAuthDeployable_propagateSession

Define the value of the `AuthEngine` attribute `propagateSession`.

- `enabled`: `true` is set which makes nevisAuth return the user's session to nevisProxy on `AUTH_DONE`.
- `disabled`: `false` is set - nevisAuth does not return the session.

It is generally recommended to disable this feature and thus we
plan to change the default to `disabled` in a future release.

# DatabaseBase_parameters

Enter parameters for the DB connection string.

The default value will be used only when no parameters are entered.

If you want to keep the default parameters, add them as well.

Enter 1 parameter per line.

Lines will be joined with `&`.

Examples (from various Nevis components):

```
pinGlobalTxToPhysicalConnection=1
useMysqlMetadata=true
autocommit=0
```


# CustomProxyLogFile_rotationTime

Interval on which a logfile will be rotated.

# NevisIDMSecondFactorSelection_recovery

Assign a step which may be selected when the user has a recovery codes credential.

For instance, assign a `Generic Authentication Step` pattern.


# RealmBase_maxSessionLifetime

Define the maximum lifetime of a nevisProxy session.
The session will be removed after that time even if active.

# CustomNevisIDMLogFile_applicationLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the default SERVER logs.

Note: not relevant when Log Targets is set to `syslog`.

# TCPSettings_dnsCacheTTL

If `DNS Caching` is set to `true`, `DNS Caching Timeout` specifies how long the DNS info should be cached (in seconds) before
 getting
 again the IP address.

# NevisIDMPasswordLogin_encryption

Set to enable form encryption.

This feature is still experimental in nevisAdmin 4 and has been added to this pattern as a preview.

The default template includes the required JavaScript (e2eenc.js) to perform client-side encryption
of the form values.

# OAuth2AuthorizationServer_removeEmptyClaimsInToken

Defines if the empty claim(s) will appear in the Access Token and ID Token.

* enabled: the ID Token and Access Token will not include empty claim(s).
* disabled (default): the ID Token and Access Token may include empty claim(s).

# WebApplicationAccess_requestValidation

- `off` - no request validation
- `standard` - uses ModSecurity OWASP Core Rule Set (CRS) with default paranoia level 1 - Basic security
- `custom` - configure `Request Validation Settings` via `Additional Settings`
- `log only` - uses `standard` in log only mode


# SamlSpConnector_attributes

Add attributes to SAML assertions.

Values may be static, produced by a nevisAuth expression (`${...}`), or an EL expressions (`#{...}`).
This table shows how to enter the configuration:

| Attribute      | Value        |
|----------------|--------------|
| some_attribute | `${...}`     |
| some_attribute | `#{...}`     |
| some_attribute | `some_value` |

Set the log level `Vars = DEBUG` and check the nevisAuth `esauth4sv.log`
to find out which variables may are available.

For instance, if you have a `nevisIDM Second-Factor Selection` pattern in your authentication flow,
you can use the expression `${sess:user.mobile}` to add a `mobile` attribute.


# FIDO2Onboarding_authenticatorType

Describes the authenticators' attachment modalities.

Allowed values:

- `any` - does not set a specific value accepting the standard's default
- `platform` - indicates a platform authenticator, such as Windows Hello
- `cross-platform` - indicates a roaming authenticator, such as a security key

# NevisIDMUserCreate_onSuccess

Define how to continue after user creation.

# PropertiesTestPattern_urlProperty

Enter a URL. By default, only allows HTTP and HTTPS but this can be changed in patterns.

# GenericAuthService_host

Assign a `Virtual Host` which shall serve
as entry point for this authentication service.

# SamlSpConnector_signerTrust

Configure the trust store used to validate incoming SAML messages
(e.g. `AuthnRequest`, `LogoutRequest`) which are sent by this SP.

# NevisAuthRealm_authenticate

The initial authentication flow starts with the authentication step assigned here.
To create a multi-step flow, you can reference further steps from within the first assigned step.

The initial authentication flow is applied on first access, 
when the client does not have an authenticated session.

Every time a step within the flow executes successfully,
the authentication level defined in that step is added to the authenticated session.

# NevisAuthRealm_tokens

Tokens assigned here may be created after successful completion of the `Initial Authentication Flow`.

To produce and forward a token to an application backend,
reference the same token from the application's `Additional Settings` property.

# GenericAuthRealm_keyObjects

Assign patterns to add `KeyObject` elements to the `KeyStore` provided by this pattern.


# NevisIDMPasswordLogin_properties

Enter user properties to fetch from nevisIDM and store in the user session.
 
Properties must be created in the nevisIDM via SQL. 

# GenericSocialLogin_userInfoEndpoint

The user information endpoint of the OAuth2 server.
It's required when `providerType` has the value `OAuth2`.


# DatabaseBase_databaseManagement

The pattern can set up the database, and it's schema when deploying to Kubernetes.

The `complete` option, on top of handling the schema migration, will do the initial database preparation like creating the actual database or tablespace in case of oracle, as well as creating the required database users.

The `schema` option will skip the initial preparation and will only take care of the actual schema migration. 
This requires the schema owner and the application user credentials to be present in the root credential secret. 
The root user information can be omitted with this option.

You can select `disabled` here to opt out.
In this case you have to create and migrate the database schema yourself.

This feature is set to `recommended` by default which aims for the most convenient solution based on the deployment type. 
In case of Kubernetes deployments, it uses `complete`. In a classical VM deployment, it will use `schema` if the pattern allows setting `Schema User` and `Schema Password`, otherwise it's `disabled`.


# OAuth2AuthorizationServer_idTokenLifetime

How long the ID token should be valid per default (can be overwritten by the setting of individual client).
At most a few minutes are recommended.


# SamlIdp_path

Define paths for the following cases.

- **SP-initiated authentication**

Service providers may send a parameter `SAMLRequest` containing an `AuthnRequest` (using POST or redirect binding) 
to request authentication. On successful authentication the IDP returns a SAML `Response`.

On entry an initial session will be created.
The session may expire during authentication due to timeout. 

When this happens an error page (name: `saml_dispatcher`) with title `title.saml.failed` 
and error message `error.saml.failed `will be rendered.

- **SP-initiated logout**

Service providers may send a `LogoutRequest` (POST or redirect binding)
to logout from this IDP and other service providers.

- **IDP-initiated logout**

Applications may have a link pointing to the IDP to trigger a global logout. 

This link may point to:

- `<path>/logout`: to show a logout confirmation page (GUI name: `saml_logout_confirm`, label: `info.logout.confirmation`)
- `<path>/?logout`: to skip the logout confirmation page.

If a `Referer` header has been sent by the browser, the logout confirmation page will have a `cancel` button which redirects to the referer.
Note that if the SP is NEVIS you may have to adapt the `Security Response Headers` of the `Virtual Host`.
By default, the header `Referrer-Policy: strict-origin-when-cross-origin` is set and this will prevent the path being sent so the `cancel` button will redirect to `/`.

During SAML logout the IDP renders a GUI named `saml_logout`
with the following hidden fields:

- `saml.logoutURLs`: the URL of the SPs including `LogoutRequest` message as query parameter
- `saml.logoutURL`: the URL to redirect to after successful logout

The default nevisLogrend template contains Javascript to invoke all `saml.logoutURLs`
and redirect to `saml.logoutURL` after all requests have been sent. This is a best effort operation 
which means that the JavaScript does not check if the logout was successful.

- **IDP-initiated authentication**

Requests to the base path without `SAMLRequest` will trigger IDP-initiated authentication.

In this case the following parameters must be sent: 

- `Issuer`: as entered for a `SAML SP Connector`
- `RelayState`: this parameter is returned to the SAML SP together with the `Response`


# StaticContentCache_maxEntrySize

The maximum size of a document to be cached. Larger documents are never cached.


# ProxyPluginPattern_description

Add description(s) for this proxy plugin

# CustomInputField_variable

Enter `<scope>:<name>` of the variable which shall be set.

The following scopes are supported:

- `inargs`
- `notes`
- `sess` or `session`

For instance, enter `notes:loginid` to prefill the login form
which is produced by the `nevisIDM Password Login` pattern.

# BehavioSecPluginPattern_url

Service URL used to connect to the BehavioSec service from the plugin.
For example: `https://mycompany.behaviosec.com/BehavioSenseAPI/`

# FIDO2Onboarding_onUnsupported

Assign a step to continue with when the browser does not support FIDO2 WebAuthn.


# FIDO2Authentication_userVerification

User verification is a crucial step during WebAuthn authentication process as it confirms that the person attempting to authenticate is indeed the legitimate user.

This setting allows to configure the user verification requirements for authentication.

Allowed values:

- `discouraged`
- `preferred`
- `required`


# RequestValidationSettings_whitelistRules

Configure _whitelist modifications_.

As explained in the [ModSecurity documentation](https://www.modsecurity.org/CRS/Documentation/exceptions.html#exceptions-versus-whitelist)
_whitelist modifications_ are applied **before** including the core rules.

Note that new rule may require a rule ID which has to be unique for this pattern.
Use the range 1-99,999 as it is reserved for local (internal) use. 

* Remove rule with ID `900200` for the path `/app/some.html`:

`SecRule REQUEST_URI "@streq /app/some.html" "pass,nolog,id:1000,ctl:ruleRemoveById=200002"`

# AuthenticationConnectorStepBase_onFailure

Set the step to continue with in case of error. If nothing is set, the authentication fails.

# OAuth2AuthorizationServer_refreshTokenRotation

Defines if a new Refresh Token is issued together with the Access Token on the Token Endpoint while exchanging a 
refresh token for a new access token (`grant_type=refresh_token`).

* enabled, a new Refresh Token is issued, the existing Refresh token is deleted.
* disabled, the existing Refresh token is returned and remains valid.

# NevisFIDOConnector_frontendAddress

Enter the address of the `Virtual Host` where the services of this instance are exposed.

Enter the address without any path component.

Example:

```
https://example.com
```

The entered value is used to calculate:
* [AppID](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-appid-and-facets-v1.1-id-20170202.html#the-appid-and-facetid-assertions)
* _Dispatch payload_

The _dispatch payload_ informs the mobile device where to access nevisFIDO for the following use cases:
- [Out-of-band Registration](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/out-of-band-registration)
- [Out-of-band Authentication](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/out-of-band-authentication)


# AuthenticationConnectorStepBase_cookieDomain

If unset, the cookie will not be scoped to subdomains.
Set this value to a specific domain to include more than one hostname.

Example: The user wants to login through example.com

If `no value` is given, the cookie will be effective for requests with the following addresses:
- https://example.com/one/two/three...

If the value is actually set as `example.com`, the cookie will be effective for requests against subdomains as well:
- https://shopping.example.com/one...
- https://account.example.com/two...
- https://example.com/three...

# CustomAuthLogFile_regexFilter

If set, messages for `esauth4sv.log` which match the given regular expression won't be logged.

The regular expression must match the entire line.
For instance, you may use the following format to match `some text`: 

```
.*some text.*
```


# NevisAdaptLogSettings_levels

Configure log levels.

See nevisAdapt Reference Guide, chapter `Logging Configuration` for details.

Comprehensive logging guide is found [here](https://docs.nevis.net/nevisadapt/Administration-of-nevisAdapt#logging-groups-of-nevisadapt).

Hint: If you only change log levels nevisAdmin 4 does not restart the component in classic VM deployment.
The new log configuration will be reloaded within 60 seconds after deployment.

The default configuration is:

```
AdaptModules-Generic = INFO
ch.nevis.nevisadapt.util.logging.OpTracer = DEBUG
```

Examples:

```
org.springframework.web.filter.CommonsRequestLoggingFilter=DEBUG
```


# CustomRiskScoreWeightConfiguration_fingerprintWeight

Configuration of the risk score weight for the fingerprint analyzer's risk score.

# SecurityConfigReport

<p>
    <b>EXPERIMENTAL FEATURE - REPORT CONTENT WILL CHANGE IN FUTURE RELEASES</b>
</p>
<p>
    This report provides a detailed overview of the security configuration for virtual hosts 
    and the backend applications on these virtual hosts.
</p>
{{#hosts}}
{{#.}}
<h1>Virtual Host: <a href="pattern://{{host_id}}">{{host_name}}</a></h1>
<p>
    The following table shows the settings at the virtual host level. 
    These settings apply to all applications.
</p>
<table id="{{host_id}}">
    <thead>
    <tr>
        <th>Topic</th>
        <th>Pattern Setting</th>
        <th>Configuration</th>
        <th>Scope</th>
    </tr>
    </thead>
    <tbody>
        <tr>
            <td><b><a href="pattern://{{host_id}}#qosConfiguration">QoS Configuration (mod_qos)</a></b></td>
            <td>{{qos}}</td>
            <td>
                {{#qos_element}}<div><pre class='code' tabindex='0'><code>navajo.xml: <br/>{{qos_element}}</code></pre></div>{{/qos_element}}
                {{#qos_server}}<div><pre class='code' tabindex='0'><code>web.xml (server directives): <br/>{{qos_server}}</code></pre></div>{{/qos_server}}
                {{#qos_host}}<div><pre class='code' tabindex='0'><code>web.xml (host directives): <br/>{{qos_host}}</code></pre></div>{{/qos_host}}
            </td>
            <td>
                <i>server directives</i>: <br/>all applications on nevisProxy instance.<br/><br/>
                <i>host directives</i>: <br/>all applications on virtual host.
            </td>
        </tr>
        <tr>
            <td><b><a href="pattern://{{host_id}}#unsecureConnection">Unsecure Connection</a></b></td>
            <td>{{unsecure_connection}}</td>
            <td><div><pre class='code' tabindex='0'><code>navajo.xml: <br/>{{context_element}}</code></pre></div></td>
            <td>All applications on virtual host.</td>
        </tr>
        <tr>
            <td><b><a href="pattern://{{host_id}}#requireClientCert">Require Client Certificate</a></b></td>
            <td>{{client_cert}}</td>
            <td>{{#ssl_element}}<pre class='code' tabindex='0'><code>navajo.xml: <br/>{{ssl_element}}</code></pre>{{/ssl_element}}</td>
            <td>All applications on virtual host.</td>
        </tr>
        <tr>
            <td><b><a href="pattern://{{host_id}}#rules">Security Configuration (ModSecurity)</a></b></td>
            <td>{{rules}}</td>
            <td>{{rules_version}}</td>
            <td>Applications on virtual host which have enabled <i>Request Validation (ModSecurity)</i>.</td>
        </tr> 
        <tr>
            <td><b><a href="pattern://{{host_id}}#allowedMethods">Allowed HTTP Methods</a></b></td>
            <td>{{allowed_methods}}</td>
            <td><pre class='code' tabindex='0'><code>navajo.xml: <br/>{{context_element}}</code></pre></td>
            <td>All applications on virtual host.</td>
        </tr>        
        <tr>
            <td><b><a href="pattern://{{host_id}}#securityHeaders">Security Response Headers</a></b></td>
            <td>{{{response_headers}}}</td>
            <td>{{#response_headers_filter}}<pre class='code' tabindex='0'><code>web.xml: <br/>{{response_headers_filter}}</code></pre>{{/response_headers_filter}}</td>
            <td>All applications on virtual host (unless replaced on application-level).</td>
        </tr>
        {{#tls_settings}}
        <tr>
            <td><b>TLS Settings</b></td>
            <td>{{{tls_settings}}}</td>
            <td>{{{tls_settings_details}}}</td>
            <td>All applications on virtual host.</td>
        </tr>
        {{/tls_settings}}                 
    </tbody>
</table>

{{#services}}
{{#.}}
<h2>{{service_type}}: <a href="pattern://{{service_id}}">{{service_name}}</a></h2>
<p>
Settings at the application level can override or complement the virtual host settings. 
The <b>Effective Configuration</b> shows the final settings for each application.  
</p>
<table id="{{service_id}}">
    <thead>
    <tr>
        <th>Topic</th>
        <th>Pattern Setting</th>
        <th>Effective Configuration</th>
    </tr>
    </thead>
    <tbody>
        <tr>
            <td><b><a href="pattern://{{host_id}}#qosConfiguration">QoS Configuration (mod_qos)</a></b></td>
            <td>-</td>
            <td>
                {{#qos_element}}<div><pre class='code' tabindex='0'><code>navajo.xml: <br/>{{qos_element}}</code></pre></div>{{/qos_element}}
                {{#qos_server}}<div><pre class='code' tabindex='0'><code>web.xml (server directives): <br/>{{qos_server}}</code></pre></div>{{/qos_server}}
                {{#qos_host}}<div><pre class='code' tabindex='0'><code>web.xml (host directives): <br/>{{qos_host}}</code></pre></div>{{/qos_host}}
            </td>
        </tr>
        <tr>
            <td><b><a href="pattern://{{host_id}}#unsecureConnection">Unsecure Connection</a></b></td>
            <td>-</td>
            <td><pre class='code' tabindex='0'><code>navajo.xml: <br/>{{context_element}}</code></pre></td>
        </tr>
        <tr>
            <td><b><a href="pattern://{{host_id}}#requireClientCert">Require Client Certificate</a></b></td>
            <td>-</td>
            <td>{{client_cert}}</td>
        </tr>
        {{#request_validation}} {{! rendered only for Web Application pattern }}        
        <tr>
            <td><b><a href="pattern://{{service_id}}#requestValidation">Request Validation (ModSecurity)</a></b></td>
            <td>{{{request_validation}}}</td>
            <td>{{{request_validation_details}}}</td>
        </tr>
        {{/request_validation}}
        <tr>
            <td><b><a href="pattern://{{service_id}}#allowedMethods">Allowed HTTP Methods</a></b></td>
            <td>{{#allowed_methods}}{{.}}<br/>{{/allowed_methods}}</td>
            <td><pre class='code' tabindex='0'><code>{{#allowed_methods_resolved}}{{.}} {{/allowed_methods_resolved}}</code></pre></td>
        </tr>
        {{#csrf}} {{! only Web Application and REST Service have CSRF Protection property }}    
        <tr>
            <td><b><a href="pattern://{{service_id}}#csrf">CSRF Protection</a></b></td>
            <td>{{{csrf}}}</td>
            <td>{{{csrf_details}}}</td>
        </tr>
        {{/csrf}}
        {{#json}} {{! only REST Service has JSON Validation property }}    
        <tr>
            <td><b><a href="pattern://{{service_id}}#jsonValidation">JSON Validation</a></b></td>
            <td>{{json}}</td>
            <td>{{{json_details}}}</td>
        </tr>
        {{/json}}
        {{#soap_schema_files}} {{! only SOAP Service has SOAP Schema Validation property }}    
        <tr>
            <td><b><a href="pattern://{{service_id}}#schema">SOAP Schema Validation</a></b></td>
            <td>{{#soap_schema_files}}{{.}} <br/>{{/soap_schema_files}}</td>
            <td>{{{soap_schema_files_details}}}</td>
        </tr>
        {{/soap_schema_files}}
        <tr>
            <td><b><a href="pattern://{{host_id}}#securityHeaders">Security Response Headers</a></b></td>
            <td>{{{response_headers}}}</td>
            <td>{{#response_headers_filter}}<pre class='code' tabindex='0'><code>web.xml: <br/>{{response_headers_filter}}</code></pre>{{/response_headers_filter}}</td>
        </tr>
        {{#tls_settings}}
        <tr>
            <td><b>TLS Settings</b></td>
            <td>{{{tls_settings}}}</td>
            <td>{{{tls_settings_details}}}</td>
        </tr>
        {{/tls_settings}}        
    </tbody>
</table>  
{{/.}}
{{/services}}
{{/.}}
{{/hosts}}

# OnDemandEntry_condition

Enter a custom nevisAuth or EL expression.

If set the `Authentication Level` will not be used.

The step assigned to `On Entry` will be executed when the expression evaluates to `true`.

# NevisProxyObservabilitySettings_metricsInterval

Interval of the metrics reader to initiate metrics collection.

# AuthCloudBase_proxy

If you have to go through a forward proxy for the outbound connection to firebase
enter the hostname:port here.

At the moment only HTTP proxy is supported.

# OAuth2Client_accessTokenLifetime

Enter a custom lifetime for the access token.

If not set the value of the `OAuth 2.0 Authorization Server / OpenID Provider` is used.

# TestingService_onValidation

Use for testing only.

# NevisFIDODatabase_schemaUser

The user which will be used to connect to the database and create the schema (tables).

The database must have been created already (`CREATE DATABASE`)
and the user must have `CREATE` privileges for this database.

Example: `schema-user`


# NevisAuthRealmBase_signerTrustStore

Defines the trust store nevisProxy uses 
for validating the signature of the NEVIS SecToken issued by nevisAuth. 

If no pattern is assigned automatic key management is asked to provide the trust store.
This requires that the `nevisAuth Instance` is part of this project and also uses automatic key management. 

Automatic key management should be used for test setups only.

# CustomAuthLogFile_syslogHost

Defines where to send logs to via syslog.
 
This configuration is used only when syslog forwarding is enabled (see `Log Targets`).

The syslog facility is `localhost3` and the threshold is `INFO`.

# 4.19.0

Full changelog: 

[Patterns 4.19.0 Release Notes - 2023-05-17](https://docs.nevis.net/nevisadmin4/release-notes#patterns-4190-release-notes---2023-05-17)

##### SAML Signature Validation

The SAML IDP now signs the entire SAML `Response` to protect against _XML Signature Wrapping_ (XSW) attacks.

This is a breaking change as you have to adapt the configuration of your SAML service providers (SPs) 
to validate the signature of the `Response` instead of, or in addition to, the `Assertion`.

If this is not possible, you can opt out of this change by selecting `Assertion` 
in the `Signed Element` drop-down of the `SAML SP Connector`.

If only the `Assertion` is signed, then your setup may be vulnerable to attacks.
In this case we recommend to check if your SP applies appropriate mitigations.

If you are using a Nevis SP, then we recommend to upgrade to the latest applicable version of nevisAuth
to benefit from additional checks of the `ServiceProviderState`. Check the release notes of nevisAuth for details.

To easily configure which signatures are validated on the SP side,
we have added a drop-down `Signature Validation` to the `SAML IDP Connector` pattern.

The default of this drop-down is `both`, which means that the signature of the `Response` and `Assertion` is checked.
This in line with the change of the default on the IDP side.

If you can not enable response signing on the IDP site, you can opt out of this change 
by setting the drop-down to `Assertion`. 

##### OAuth 2.0 Authorization Server / OpenID Provider REST Endpoints

The `REST Endpoints` tab in the `OAuth 2.0 Authorization Server / OpenID Provider` pattern and corresponding settings have been replaced with separate patterns.

You have to adapt your configuration. Add the patterns you need to your project and assign them via the new `REST Endpoints` setting.

##### nevisProxy upgrade to OpenSSL 3.0

OpenSSL version 3.0 has a more strict default for security level than OpenSSL version 1.1.1. The default security level 1 now forbids signatures using SHA1 and MD5.

In consequence, the following issues may occur:

1. Connections using TLSv1.1 will fail with the following message in the `navajo.log`:
   ```
   3-ERROR : OpenSSL-failure: 00777CC0137F0000:error:0A00014D:SSL routines:tls_process_key_exchange:legacy sigalg disallowed or unsupported:ssl/statem/statem_clnt.c:2255:0x0a [OSSL-0005]
   ```
   We recommend upgrading your configuration to use TLSv1.2 or TLSv1.3. If it is not possible, you can add the suffix `:@SECLEVEL=0` to your TLSv1.1 cipher suites to allow their signature algorithms.

2. Connections using a certificate with a deprecated signature algorithm will fail with the following message in the `navajo.log`:
   ```
   3-ERROR :  [...] error:0A00018E:SSL routines::ca md too weak (must be pem encoded)) [NVCT-0054]
   ```
   We recommend renewing your certificates with a stronger signature algorithm. In the meanwhile, you can add the suffix `:@SECLEVEL=0` to the cipher suites of the affected filter or servlet.
   If the issue occurs at several places, or if it affects your EsAuth4ConnectorServlets, you can also modify the default cipher suites to include this suffix. Proceed as follows:

   * Add a `Generic nevisProxy Instance Settings` pattern to you configuration.
   * Add a `bc.property` for each cipher suite you want to modify. The keys are:
     - `ch.nevis.isiweb4.servlet.connector.http.SSLCipherSuites` for the HttpsConnectorServlets
     - `ch.nevis.isiweb4.servlet.connector.websocket.SSLCipherSuites` for the WebSocketServlets
     - `ch.nevis.isiweb4.servlet.connector.soap.esauth4.Transport.SSLCipherSuites` for the EsAuth4ConnectorServlets
     - `ch.nevis.nevisproxy.servlet.connector.http.BackendConnectorServlet.Secure.CipherSuites` for the BackendConnectorServlets
     - `ch.nevis.isiweb4.filter.icap.ICAPFilter.SSLCipherSuites` for the ICAPFilters
   * The modified default values should be `ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0`
   * Attach this pattern to your `nevisProxy Instance`, under `Advanced Settings` > `Additional Settings`.


# CustomNevisIDMLogFile_auditLog

Configure audit logging capability of nevisIDM.

- When `JSON` (default) is selected, nevisIDM will write audit entries in JSON format.
- When `plain` is selected, nevisIDM will write audit entries as plain log lines. This setting is deprecated and may be removed in a future release.
- When `disabled` is selected, nevisIDM will not log audit entries at all.

In classic VM deployments the log target is `/var/opt/nevisidm/<instance>/logs/audit.log`.
In Kubernetes and when `JSON` is selected the log messages are written to the pod log with the prefix `[audit.log]`.

If you deploy nevisIDM to multiple hosts (multi-instance setup), the audit logging will only be enabled on the first host.


# NevisIDMUserCreate_clientId

Enter the client ID where the user shall be created.


# SamlIdpConnector_audience

Enter a regular expression to validate the `Audience` of a received SAML `Assertion`.


# NevisIDMDatabase_encryption

Enables TLS in a specific mode. The following values are supported:

- `disabled`: Do not use TLS (default)
- `trust`: Only use TLS for encryption. Do not perform certificate or hostname verification. This mode is not recommended
  for production applications but still safer than `disabled`.
- `verify-ca`: Use TLS for encryption and perform certificates verification, but do not perform hostname verification.
- `verify-full`: Use TLS for encryption, certificate verification, and hostname verification.

# NevisIDMWebApplicationAccess_selfAdmin

Choose between:

- `enabled` - the nevisIDM self admin GUI will be exposed on the path `/nevisidm/selfadmin/`.
- `disabled` - access to the path `/nevisidm/selfadmin/` will be blocked.

If you want to provide a self admin interface for end users we recommend to implement your
own application and call the nevisIDM REST API instead. 
This way you can decide which settings to expose to your users and achieve the desired user experience.


# Maintenance_statusCode

The status code of the response with the maintenance page.

By default, the response is sent with status code `503` for `Service Unavailable`.


# NevisAdaptDeployable_analyzerConfig

Allows you to customize nevisAdapt Analyzer configuration.

# FIDO2Authentication_onCancel

If assigned a button with label 'fido2.cancel.button.label' will be added.

Use to provide an alternative to the user when the user decides to cancel the authentication
or the authentication fails and the error cannot be handled.


# NevisAdaptAnalyzerConfig_deviceAnalyzer

Device Analyzer is a global setting, disabling this
means that the device analyzer will not be used to
calculate risk scores. This will result in a lower
risk score for all users.

If you wish to disable, consider disabling all other submodules as well.



# OAuth2AuthorizationServer_accessTokenFormat

Choose between:

- `JWE`: the access token will be encrypted. This is the default. 
The token is considered opaque and thus resource servers need to call the token introspection endpoint to validate the token.

- `JWS`: the access token will not be encrypted. Choose this mode to get a signed token
which can be validated without calling the token introspection endpoint. 
A JWKS endpoint will be added to this pattern in 2022.

# NevisIDMProperty_accessCreate

Possible settings:

* `READ_WRITE`: Input is possible for the if no previous value was stored.
* `READ_ONLY`: Field is read only.
* `OFF`: Field is not updatable and property is not displayed GUI.

Users with `AccessControl.PropertyAttributeAccessOverride` can edit these field regardless of this settings.

# NevisFIDODeployable_clientKeyStore

Assign a key store to be used for the 2-way TLS connection to nevisIDM.

If no pattern is assigned an automatic key store will be generated. 
This requires automatic key management to be enabled in the inventory.
Further, the pattern assigned to `nevisIDM` must be a `nevisIDM Instance`
which uses an automatic trust store for the `Frontend Trust Store`.

Note that it is required that the certificate used by nevisFIDO to connect to nevisIDM
is uploaded as a certificate credential for the `nevisfido` technical user.
This is done automatically when deploying to Kubernetes and using automatic key management 
on both sides. In any other case, this step has to be done manually.


# ErrorHandler_errorPages

Upload HTML error pages, JSON error pages and associated resources here.

Pages must be named like the error code they are used for (e.g. `500.html`).
You can use the same page for multiple status code (e.g. `401,403,500-599.html`).

By default, the error pages are deployed to `/errorpages/<name>` but
you can set a different location via the property `Base Path` (see `Advanced Settings`).

In your error pages we recommend to use relative links to include resources.
You may also include resources deployed on the virtual host via `Hosted Resources`.

The following placeholders are supported:

- `TRANSFER_ID` for the unique ID of the request (e.g. `c0a80e52-5d04-11ac0500-16906714eee-00000003`)
- `TIMESTAMP` to show a timestamp (e.g. `Tue, 19 Feb 2019 15:48:02 GMT`)


# NevisAuthDeployable_linePreference

This setting (together with the inventory) defines the order of nevisAuth endpoints in the connection string from nevisProxy.

nevisAuth stores unauthenticated sessions in memory.
In a classic deployment to VMs, even when a `nevisAuth MariaDB Remote Session Store` is configured, 
sessions are synced to the DB only after successful authentication.
Thus, multi-step login flows require that requests for the same session are routed to the same nevisAuth endpoint.

nevisProxy uses a simple fail-over strategy. The first URL in the connection string for nevisAuth is always used,
unless this instance is not available. This strategy works well when:

* there is only 1 nevisProxy instance
* there are 2 lines of nevisProxy but line 1 is active and line 2 is standby
* there is a session-sticky load-balancer in front of nevisProxy is session-sticky

The order of the connection string depends on the inventory. See also:
[Defining Lines and Fail-over Association](https://docs.nevis.net/nevisadmin4/User-Guide/Infrastructure-Inventories/Working-with-Inventory-Files/Defining-Lines-and-Failover-Association)

This strategy may fail in active / active setups when line groups are defined in the inventory.
In such setups you can set this drop-down to `disabled` to ensure that the order in the connection string is the same on all nevisProxy lines.


# NevisDetectEntrypointDeployable_subPaths

Set to apply this pattern on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table provides examples to illustrate the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |

# NevisIDMDeployable_authSignerTrustStore

Assign a Trust Store provider pattern to use for setting up trust between nevisIDM and nevisAuth. If no pattern is assigned the signer key will be provided by the nevisAdmin 4 PKI.

# GenericSocialLogin_emailClaim

The claim that contains the e-mail of the logged-in user in the social account.
The default value is `email`.

# AppleLogin_buttonLabel

Enter the text that should be displayed for the end-user on the social login button, and provide translations for this label on the Authentication Realms.

# HostContext_addresses

Define addresses (HTTPS or HTTP) at which this host will be reachable from a client perspective.

The basic syntax is:

- `<scheme>://<hostname>`
- `<scheme>://<hostname>:<port>`

A variable may be used to define different addresses for different stages (e.g. DEV, TEST, PROD).

The expression `${deployment_host}` may be used when the name of the target host is required.

Examples:

- `http://www.siven.ch`
- `https://www.siven.ch`
- `http://${deployment_host}:8080`

The `port` will, if omitted, default to `443` for HTTPS and to `80` for HTTP.

You also have to set `Bind Addresses` if:

- the addresses cannot be resolved on the target host(s)
- the port should be opened on different addresses / IPs, or ports.
- multiple virtual hosts should listen on the same endpoint (name-based virtual hosts).

# NevisIDMGenericBatchJob_resources

Upload JAR file(s) for custom batch jobs.

Note that batch jobs which call the nevisIDM business layer are not supported by Nevis.
Please call the nevisIDM REST API only.

# NevisAdaptEvent_events

Select at least one event for the combination to react on:
- `unknown-device` : this is the first time for this device cookie
- `unknown-country` : this is the first time for this geolocation (country)
- `unknown-fingerprint` : this is the first time for this browser fingerprint
- `suspicious-country` : the login request came from a prohibited country
- `high-ip-velocity` : the current geolocation is physically too far to be reachable since the last login
- `ip-reputation-blacklisted` : the login request came from an IP address with low reputation

For technical details check [Event-based configuration](https://docs.nevis.net/nevisadapt/Integration-with-other-Nevis-components/nevisAuth-direct-integration/NevisAdaptAuthState/).

# AuthenticationConnectorStepBase_onSuccess

Set the step to continue with on successful authentication.

# AccessRestriction_override

By default, access restriction rules apply to all sub-locations.

For instance, when you assign an `Access Restriction` pattern to a `Virtual Host` 
all applications on this virtual host will be affected. 

To **replace** the rules defined on a parent location 
select `enabled` on all `Access Restriction` patterns in the hierarchy.

If `disabled` is selected anywhere in the hierarchy the rules are 
considered **additional**.

Technical Details:

This feature is implemented using a nevisProxy `LuaFilter`.
Mapped filters are inherited to sub-locations unless an `exclude-url-regex` is defined.

By selecting `enabled` the generator is informed that the mapped filter has the purpose
`access restriction`. The generator then ensures that an `exclude-url-regex` entry
 is generated when a filter with the same purpose is mapped to a sub-location.

# NevisIDMProperty_description

The `description` field in the property definition file allows you to provide a clear and informative description of the custom property. This description will be valuable for understanding the purpose, expected values, or any other relevant information about the property.

The description will be escaped for JSON if required.

# GenericNevisProxySettings_parameters

Define _Template Parameters_.

Examples:

```yaml
backend-host: backend.siven.ch
```

These parameters can be used in:

* `Configuration: navajo.xml`
* `Configuration: bc.properties`

The expression formats are:

`${param.<name>}`:

- `name` found: parameter value is used.
- `name` missing: expression is **not** replaced.

`${param.<name>:<default value>}`:

- `name` found: parameter value is used.
- `name` missing: default value will be used.

In `<default value>` the character `}` must be escaped as `\}`.

# SamlResponseConsumer_logoutProcess

Assign a step to apply custom post-processing logic
which is executed when a `LogoutRequest` or `LogoutResponse` message is received.

# OAuth2AuthorizationServer_nextSteps

Assign follow-up steps.
 
The order of steps is relevant. 
The first step in this list has index `1`. 
 
You may reference a step in the configuration
via the `Custom Transitions`.

# GenericSocialLogin_providerEndpoint

The provider endpoint that contains the configuration of the OpenID Connect server.
It's required when `providerType` has the value `OpenID Connect`.

# SamlSpRealm_tokens

SAML Responses returned by the IDP are consumed in nevisAuth
and **not** forwarded to applications.

If your application requires a token then you have assign a pattern which can produce that token here.
For instance, assign a `NEVIS SecToken` or `SAML Token`.

To forward the token to applications you also have to assign the token pattern
to these applications via `Application Access Token`.

The token will be created on first access (missing token role triggers a stepup).
In case of a session upgrade via SAML the token (role) is revoked 
and thus the token is recreated on the next access. 

In your application you may use the Ninja authentication filter provided by NEVIS 
to extract user id, roles, and custom attributes.

# SamlSpConnector_properties

Configure properties of the nevisAuth `IdentityProviderState`.

**Add** or **overwrite** properties by entering a value.

**Remove** properties generated by this pattern by leaving the value empty.

Examples:

| Key                   | Value       |
|-----------------------|-------------|
| out.extension.Bearer  | ch.nevis.esauth.auth.states.saml.extensions.SubjectConfirmationExtender |
| Bearer.inResponseTo   | ${notes:saml.request.id} |
| out.signatureKeyInfo  | Certificate |


# NevisAuthDeployable_host

Enter a custom host name to listen on.

This setting is relevant in classic VM deployment,
when working with multi-homed target hosts.

In Kubernetes nevisAuth listens on `0.0.0.0`
and thus this setting is discouraged.

# HeaderCustomization_basicAuthPass

Enter the basic auth password or an expression of the format `<source>:<parameter>`.

For the `<source>` you may use:

- `AUTH`: outargs returned by nevisAuth.
- `CONST`: constant strings. 
- `ENV`: Apache environment variables.
- `PARAM`: values from a request body as provided by a `ParameterFilter`. 
- `HEADER`: request headers.

# LuaPattern_parameters

Parameters defined here can be used inside the Lua script.

The name of each parameter must start with `param_`. This limitation may be lifted in a future release.

The value will be trimmed.

Set this property if you need a **different** value depending on the inventory. 

1. click `var` to use a nevisAdmin 4 variable for the **entire** setting:
   - Enter a good name for the variable as the default may be quite verbose.
   - Enter some sample values to document the variable in the project. 
2. add the nevisAdmin 4 variable to your inventories:
   - See below for an example which illustrates the syntax.

**Example inventory variable**:

```
vars:
  example-variable:
    param_example_string: "on"
    param_example_numeric: 60
```

It is sometimes required to quote values.
In the example above, the value `on` would be converted to a boolean value if it weren't for the double quotes `"`.
When unsure, always put double quotes around the value.


# OAuth2AuthorizationServer_accessTokenClaims

Configure additional claims for the OAuth2.0 Access Token.

Claims are added if they have a value.

For instance, claims may be added when a certain scope is requested which includes them.

OpenID Connect defines the following `scope` values which may be requested to get `claims`:

- `profile`. claims: `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at`.
- `email`. claims: `email`, `email_verified`
- `address`. claims: `address`
- `phone`. claims: `phone_number`, `phone_number_verified`

Examples:

```
given_name=${sess:ch.nevis.idm.User.firstName}
family_name=${sess:ch.nevis.idm.User.name}
email=${sess:ch.nevis.idm.User.email}
mobile=${sess:ch.nevis.idm.User.mobile}
```

# NevisIDMPasswordLogin_attributes

Enter user attributes to fetch from nevisIDM.

Important attributes are:

- `extId` - unique ID of the user in nevisIDM
- `loginId` - name which could be used to login (instead of email)
- `firstName` 
- `name` - surname
- `email`
- `mobile`
- `language` - language stored for user (can differ from `Accept-Language` sent by the browser)

For a complete list please check the documentation of
[IdmGetPropertiesState](https://docs.nevis.net/nevisidm/Configuration/authentication_plug-ins/nevisIDM-authentication-plug-ins/IdmGetPropertiesState).

Some attributes (e.g. `extId`, `email`, and `mobile`) are always fetched 
as they are required by standard authentication steps.

The attributes will be stored in the user session as `ch.nevis.idm.User.<attribute>`.

Attributes may be used in sub-sequent authentication steps 
or included in application access tokens (e.g. `NEVIS SecToken`, `SAML Token`, or `JWT Token`).

For instance, use them in a `Generic Authentication Step` 
via the expression `${sess:ch.nevis.idm.User.<attribute>}`.


# NevisIDMUserCreate_onFailure

Define how to continue after user creation, if it was unsuccessful.

# ResponseRewritingSettings_responseRewrite

- `off` disables automatic response rewriting
- `header` enables auto rewrite of response headers (includes cookies)
- `complete` enables auto rewrite for response headers and body

# GenericSocialLogin_clientExtId

The ExtId of the client in nevisIDM that will be used to store the user.

# NevisDetectRiskPluginBase_trustStore

Reference a trust store provider pattern or leave empty to manage the trust store with nevisAdmin.

# RealmBase_cookieSameSiteRelaxation

Some older browsers treat cookies with `SameSite=None` as Strict.

See this example bug report for Safari:

[Bug 198181 - Cookies with SameSite=None or SameSite=invalid treated as Strict](https://bugs.webkit.org/show_bug.cgi?id=198181)

Enable this feature to map a filter to the root location `/*` which evaluates the `User-Agent` request header
to remove `SameSite=None` for browsers which are known to be affected.


# LogSettingsBase_rotationInterval

Rotation interval after which log files are rolled over.

This configuration is *not* used when `Rotation Type` is set to `size`.

Choose between:

- `daily` - the postfix of rotated files will be `.%d{yyyy-MM-dd}`
- `hourly` - the postfix of rotated files will be `.%d{yyyy-MM-dd-HH}`


# NevisProxyDatabase_mode

Select one of:

- `classic` - sessions are stored in the remote database only.
  Recommended setting for production setups.

- `hybrid` - adds a local cache to improve the performance of the session store.
  This value is experimental and should **only** be used for test setups.
  This mode requires a session-sticky load balancer in front of nevisProxy.
  The generated configuration may change in future versions.


# NevisProxyDatabase_peer

The hybrid session store requires that the `nevisProxy Instance` is deployed on 2 lines.
For illustration purposes let's call the hosts where the instances are deployed `p1` and `p2`.

Enter the URL where the other nevisProxy `Virtual Host` exposes its local session store.
The URL must be reachable and should not go via a load-balancer to ensure that the request reaches the peer proxy directly.

You can use variables to ensure that the correct host name is used for the configuration on each line.
For instance, the variable may be a host variable and have the following values:

- for server `p1` use: `https://p2:443`
- for server `p2` use: `https://p1:443`

Alternatively, you can use a semantic host name and and define this name in `/etc/hosts` on both `p1` and `p2`.

Example: `https://proxy-peer:443`


# OutOfBandMobileRegistration_username

The `username` is used by nevisFIDO to look up the user in nevisIDM.

Depending on how the `nevisFIDO FIDO UAF Instance` is configured, either the `extId` or the `loginId` have to be used.


# NevisIDMAdvancedSettings_javaOpts

Add additional entries to the JAVA_OPTS environment variable.

Use the expression `${instance}` for the instance name.

For instance, you may configure nevisIDM to create a heap dump on out of memory as follows:

```
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/opt/nevisidm/${instance}/log/
```

Be aware that this example will not work for Kubernetes
as the pod will be automatically restarted on out of memory
and the created heap dump files will be lost.


# NevisAuthDeployable_connectionHost

Enter the host:port pair(s) which nevisProxy should use
to connect to this nevisAuth instance.

This setting is required when the primary names of the nevisAuth hosts 
are not accessible by nevisProxy, which is sometimes the case
in classic VM deployment, when working with multi-homed target hosts.

The server certificate provided by the `Frontend Key Store` must be valid 
for all provided hosts names.

# OAuth2Scope_description

Used by the ID Cloud management console to store a description for this scope provided by the user.

# NevisIDMPasswordLogin_entryPath

The path prefix of the links for the password forgotten process.

Example: given a domain `www.adnovum.ch` and the value `/pwreset/`, all password forgotten steps will
use the base path `www.adnovum.ch/pwreset/`.


# NevisAuthRealm_langCookieDomain

Enter a domain for the cookie that nevisLogrend issues 
to remember the language of the user.

This setting should only be used when you want to issue a _wildcard cookie_
to share the language with other sub-domains (e.g. across multiple `Virtual Host`).

For instance, if you enter `.example.com` then 
the cookie will also be sent to `subdomain.example.com`.


# NevisAuthRealmBase_sessionValidation

A newline separated list of rules declaring attributes that must not change in the same session.
A rule has the following syntax:

```
AUTH|ENV|CONST|PARAM|HEADER:<name of the attribute>:block|invalidate
```

- `block`: the request will be blocked and `403 (Forbidden)` will be returned
- `invalidate`: the session will be invalidated and a new one will be created

nevisProxy Conditions are supported. See nevisProxy reference guide for details.

For instance, use the following configuration to terminate the session if the source IP changes:

```
ENV:REMOTE_ADDR:invalidate
```

# SamlToken_subject

Configure the subject of the generated SAML assertion.

- `User ID`: sets the internal user ID
- `Login ID`: sets the ID as entered by the user during login

# DatabaseBase_connectionUrl

Set **only** if you have to use a JDBC connection string which the pattern cannot generate.

If the prefix of the connection string works for you 
and you **only** have to add or overwrite query parameters, set `Connection Parameters` instead.

If you have to use this setting, please consult your setup with your integration partner.

In Kubernetes deployments the connection string configured here is used by the component **only**.
It is **not** used to set up and migrate the database schema. 

Thus, this setting should **only** be used in classic deployments,
or when `Database Management` is `disabled`.


# CustomNevisIDMLogFile_auditLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the default SERVER logs.

Note: not relevant when Log Targets is set to `syslog`.

# NevisIDMPasswordLogin_legacyLitDictMode

In legacy mode policy violations are displayed using 1 GUI element.

You can use `enabled` here until November 2021 when this mode will be removed.

# Logout_redirect

Enter a URL or path to redirect to after logout.

# CustomNevisIDMLogFile_applicationSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# SamlIdp_errorRedirect

URL to redirect to when the IDP is unable to handle the request.

There are 3 cases:

- a session is required for the current operation (e.g. logout, session upgrade) but no session was found.
- the authentication type (SP-initiated or IDP-initiated) is not allowed.
- not enough information for IDP-initiated authentication (e.g. missing query parameters).

If no URL is configured, the IDP will redirect back to the `Referer`, or `/` if no `Referer` header has been sent.


# EmailTAN_sender

Sender email address.

# TCPSettings_keepAliveConnectionPoolSize

Number of pooled TCP connections. A TCP connection is only put in the pool if the size of the pool does not exceed the configured size. By leaving this field empty, you will be using the nevisProxy default value.


# PropertiesTestPattern_dateTimePickerProperty

Not sure why we don't have a date time picker yet.

# NevisLogrendLogSettings_levels

Configure log levels.

See nevisLogrend Technical Documentation, chapter
[Logging configuration](https://docs.nevis.net/nevislogrend/setup-and-configuration/configuration-files/logging-configuration) for details.

Hint: If you only change log levels nevisAdmin 4 does not restart the component in classic VM deployment.
The new log configuration will be reloaded within 60 seconds after deployment.

Examples:

```
ch.nevis.logrend.beans.LoginBean = DEBUG
```


# NevisAuthDatabase_encryption

Enables SSL/TLS in a specific mode. The following modes are supported:

- `disabled`: Do not use SSL/TLS (default)
- `trust`: Use SSL/TLS for encrypted transfer. Do not perform certificate or hostname verification. This mode is not safe
  for production applications but still safer than `disabled`.
- `verify-ca`: Use SSL/TLS for encryption and perform certificate verification, but do not perform hostname verification.
- `verify-full`: Use SSL/TLS for encryption, certificate verification, and hostname verification.


# SamlSpConnector_preProcess

Assign a step to apply custom pre-processing logic
before validating the incoming request for this SP.

You may assign a chain of steps to build a flow.

The flow will be executed for all incoming requests,
no matter if the user has a session already.

If you need to apply different logic for these 3 cases you can use `Dispatcher Step`
and dispatch based on the following expressions:

```
${request:method:^authenticate$:true}
${request:method:^stepup$:true}
${request:method:^logout$:true}
```

The dispatching will continue after leaving this flow on the happy path.

For `On Success` exits this works automatically.

However, generic exits (i.e. `Additional Follow-up Steps` in `Generic Authentication Step`)
must be marked as success exits by assigning the `Pre-Processing Done` pattern.


# SamlSpRealm_spLogoutMode

Defines how this SP should react when an SP-initiated logout completes on this SP.

- `redirect-target`: redirects to a defined path or URL. 
When this option is selected a `Logout Target` must be entered.

- `redirect-state`: redirects according to the `RelayState` query parameter
received in combination with the `LogoutResponse`.
The IDP is expected to return this parameter as-is
and thus the `RelayState` should contain the URL where the logout was initiated. 
As this is a protected application URL authentication will be enforced
and the user will be sent to the IDP again to perform a login.

# KerberosLogin_keyTabFile

Upload the Kerberos keytab file. 

nevisAuth uses this file to validate Kerberos tokens sent by browsers.

Please check the nevisAuth Technical Documentation on how to create the keytab file.

The keytab file will be deployed to the `conf` directory of the nevisAuth instance.

For a more secure and environment-specific configuration you have the following alternatives:
 
- create a variable and upload the keytab file in the inventory
- set `Keytab File Path` instead of uploading the file and deploy the file by other means

In complex setups with multiple `Kerberos Realms` and/or `Frontend Addresses` 
you may have to upload multiple keytab files.

# SamlIdpConnector_binding

Configure the outgoing binding.
This affects how the SAML `AuthnRequest` is sent to the IDP.

# NevisDPDeployable_customJars

Upload custom JAR files to handle specialized logic.

# SamlSpRealm_logoutReminderPage

Enable this feature to show a logout reminder page.

The page will be shown on next access in the following cases:

- the user has closed the browser
- user session has expired due to idle timeout

The page contains a heading, an info message and a continue button.
You can customize them via `Custom Translations` by setting the following labels:

- `title.logout.reminder`
- `info.logout.reminder`
- `continue.button.label`

For this feature to work an additional cookie `Marker_<name>` will be issued.
The value will be set to `login` or `logout` depending on the last action of the user.

The following requirements must be fulfilled:
 
- Usage of HTTPs to access the application and for the entire SAML process.
- No other session expiration feature must be used.

# OAuth2Client_responseTypes

Enter the allowed response types.

# InitRuntimeConfiguration_configurations

Add key/value pairs to initialize runtime configurations in a session variable.

- Key: name of a nevisAuth session variable
- Value: name of a nevisAdmin4 inventory/project variable.

The inventory/project variable is replaced by its groovy-escaped String value and will be set to the session in a generated groovy script.

```yaml
- ch.nevis.idc.config.authentication.accessAppEnabled: "accessAppEnabled"
- ch.nevis.idc.config.authentication.passkeyEnabled: "passkeyEnabled"
```  


# NevisFIDODeployable_firebaseProxyAddress

The URL of the HTTP/HTTPS proxy used by nevisFIDO to access the Firebase Cloud Messaging service.

Note: The FCM dispatcher requires outbound access to the Google API service, specifically https://oauth2.googleapis.com for authentication and https://fcm.googleapis.com for accessing the FCM HTTP API.
In case proxies and/or company firewalls are in place the connectivity to these Google services must be ensured.

# TLSSettings_protocols

The value configured here will be applied as `SSLProtocol`. 

Check the [Apache Documentation](http://httpd.apache.org/docs/current/mod/mod_ssl.html#sslprotocol) for details.

If empty and when this pattern is assigned to a `Virtual Host` the following value is used:

`-all +TLSv1.2 -TLSv1.3`

If empty and when this pattern is assigned to an application, default `SSLProtocol` from nevisProxy are applied.
Check the [nevisProxy Technical Documentation](https://docs.nevis.net/nevisproxy/Configuration/Servlets/HttpsConnectorServlet) for details.


# NevisIDMPasswordLogin_resetLockedPassword

Defines whether it is possible to reset locked passwords or not. 
* If enabled, it is possible to reset locked passwords as well. In this case, only disabled passwords cannot be reset. 
* If disabled, it is only possible to reset active passwords.

# GenericDeployment_deploymentHosts

The host group to deploy the `Files` to and execute the `Command` on. 
For testing purposes you can also enter a host **name** instead of a group.

The host name / group must exist in the selected inventory.


# KeyObject_type

Select `key store` when a private key is needed.
Select `trust store` for providing trusted certificate (e.g. for signature validation).

# GenericSocialLogin_scope

The request scope(s) for getting the user information from the social account. The default value is `email`.

The scope `openid` will be added automatically if `providerType` is set to `OpenID Connect`.

Scope `offline_access` for generate refresh token.

# NevisProxyObservabilitySettings_deploymentEnv

Allows the configuration of the `deployment.environment` key-value pair resource attribute.

# NevisIDMDeployable_logging

Add logging configuration for nevisIDM.

# README

nevisAdmin 4 Plugins
====================

Plugins to use and configure NEVIS from nevisAdmin 4.

![](plugin.png)

## Setup

Use Java 17 JDK (openjdk). 

To resolve dependencies from private repositories (nevisAdmin 4 BE)
you have to create a personal access token for your github account. 

Don't forget to "Enable SSO" for this token!

Now you can configure the user and token once and for all in your global gradle.properties.

```
cat ~/.gradle/gradle.properties
GITHUB_USER=benjamin-koenig
GITHUB_TOKEN=...
```

Commit signing is enforced in this repository for all branches. 
Configure your GIT client according to our [best practises](https://nevissecurity.atlassian.net/wiki/spaces/Nevisweb/pages/17158546/GitHub+Best+Practices).

You can validate the signature of a commit using:

```
git verify-commit <commit>
```

## Build

* Build all sub projects

  `./gradlew assemble`
  
* Build using a certain version
 
  `GITHUB_RUN_NUMBER=1 ./gradlew assemble -Dorg.gradle.project.BUILD_VERSION_BASE=4.9.1`
  `GITHUB_REF=refs/tags/release/4.9.1.2 ./gradlew assemble`

* Clean and builds projects

  `./gradlew clean build`

* Run the unit and architecture tests

  `./gradlew unitTest`
  
* Run integration tests (nevisadmin-test-system)

  `./gradlew systemTest`

  These tests rely on the `nevis-dev-systemd` docker image.
  If you have problems with this image check with the team.
  
* Start nevisAdmin 4:

  in the `nevisadmin4` repository run `./gradlew devRun` and keep the task running  

* Deploy to local nevisAdmin 4:

  `./gradlew deploy`
  
* Copy plugins into a folder for easy upload

  `find . -name nevisadmin-plugin*4.9.1.1.jar -exec cp {} /tmp/ \;`

## IDEA

  * File / Open / Select the build.gradle
  * In general delegate all build actions to the gradle wrapper.
  
## Maintenance

### Upgrade Gradle Wrapper

```
./gradlew wrapper --gradle-version=6.2 --distribution-type=bin
```

### Backport

``git cherry-pick`` seems to be the most robust way to backport changes to the ``release/*`` branches.

### Github Packages Housekeeping

There is a cleanup workflow: `.github/workflows/cleanup.yml`

You can also use the tools provided by the `housekeeping` repository 
to delete old versions which are not required anymore.

```
./gradlew delete_packages -Dgithub_repo=nevisadmin4-plugins -Dmaven_version=<version>
```

Have a look at the plugin-base to find out which versions exist:

https://github.com/nevissecurity/nevisadmin4-plugins/packages/142340/versions

You can remove all versions which:

- are not referenced by any release branch of `nevisadmin4` repository (`release/4.5` and `master`)
- have not been handed out to customers for testing purposes

#### Release Process Details

Create a new pre-release in Github: https://github.com/nevissecurity/nevisadmin4-plugins/releases/new

For the tag version enter: `release/<version>`

Check `This is a pre-release`.

The `.github/workflow/release.yml` will now be executed. 
When the workflow completes the JARs are published in Github packages.

#### Download Github Packages

You can use the following steps to download JARs of a certain released version 
from Github packages into `target/download`:

```bash
rm target/download/*
```

Now use either:

```bash
GITHUB_REF=refs/tags/release/4.9.1.2 ./gradlew download
```

or:

```bash
GITHUB_RUN_NUMBER=1 ./gradlew download -Dorg.gradle.project.BUILD_VERSION_BASE=4.9.1
```

#### Cloudsmith Publish Tasks

Cloudsmith publishing is done as part of the release process 
when the checkbox `This is a pre-release` is **not** selected.

You can also do these steps manually.

For instance, you can use the `helper/cloudsmith-push.sh` script to push all JARs to the `delivery` repository.
This is the highest repository at Nevis which is **not** customer visible.

In order for customers to download these JARs they have to be tagged with a quarterly label (e.g. `2023R2`).
The tag is defined in `gradle.properties` and must be incremented after each quarterly releases on the `main` branch. 

Use the following task to apply the current tag to artefacts in delivery:

```
CLOUDSMITH_TOKEN=... GITHUB_REF=refs/tags/release/4.20.0.1 ./gradlew tagDelivery
```

Then the JARs in Cloudsmith `delivery` then need to be copied to `rolling`.
Because of costs it is better to move them instead.

There is no Gradle task for that as this copy is usually done by a workflow in `neviscluster`,
or manually for intermediate releases.

### Check Documentation Links

The help of a pattern often contains links to docs.nevis.net which break easily. New URLs won’t be available on the productive 
docs.nevis.net as they become available on release day when the integration branch is merged into main and docs is redeployed.
Hence, we have to check manually (for now) whether the links still point to an existing page.

There is a Python script that can be simply run in a terminal as `helper/check-docs-urls.py` and it will generate warnings
about which URLs in which files are broken.


# RequestValidationSettings_customRules

Configure _exception modifications_.

As explained in the [ModSecurity documentation](https://www.modsecurity.org/CRS/Documentation/exceptions.html#exceptions-versus-whitelist)
_exception modifications_ are applied **after** including the core rules.

Note that new rule may require a rule ID which has to be unique for this pattern.
Use the range 1-99,999 as it is reserved for local (internal) use. 

* Remove rule with ID `900200`:

`SecRuleRemoveById 900200`

* Whitelist body parameter `upload` for all rules:

`SecRuleUpdateTargetByTag ".*" "!ARGS:upload"`

* Whitelist body parameter `upload` for rule ID `123`:

`SecRuleUpdateTargetById 123 !ARGS:upload`

* Add a new rule which allows the HTTP methods used for WebDAV:

```
SecAction \
 "id:1,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE CHECKOUT COPY DELETE LOCK MERGE MKACTIVITY MKCOL MOVE PROPFIND PROPPATCH PUT UNLOCK'"
```

# NevisAdaptPluginPattern_properties

Set the value for the following optional parameters if the default ones do not match the requirements:

- cacheDisabled = (default 'false')
- ignoreHttpRequest = (default 'false')
- ignoreTlsObservation = (default 'true')



# GenericIngressSettings_path

Define a custom path for the generated ingress resource.

Example:

```properties
/nevis/
```

This is an ingress specific setting, the endpoints have to be configured separately to be available under the defined path.
When using side-by-side deployment, the path must be the same between the primary and secondary deployment.

# OnDemandEntry_onEntry

Point to the first step of the authentication process.

# NevisDetectDatabase_hikariType

Select which method of generation should be applied when configuring the Hikari datasource for the database connection.

Possible options:

- `recommended`: the default option, this sets up three explicit values:
    - Maximum session lifetime: 300s
    - Session idle timeout: 100s
    - Maximum pool size: 50
- `custom`: specify values in the next text area, separate keys and values with `=`. The valid keys can be found at [HikariCP - GitHub](https://github.com/brettwooldridge/HikariCP).
- `unmodified`: this configuration doesn't generate anything, leaving all default configurations coming from the library in effect.


# NevisFIDO2Database_type

Choose between `MariaDB` and `PostgresSQL`.

We recommend to use `MariaDB` as it is supported by all Nevis components that have a database.

**Note:** `PostgresSQL` database is only experimental configuration.


# NevisAdaptDatabase_encryption

Enables TLS in a specific mode. The following values are supported:

- `disabled`: Do not use TLS (default)
- `trust`: Only use TLS for encryption. Do not perform certificate or hostname verification. This mode is not recommended
  for production applications but still safer than `disabled`.
- `verify-ca`: Use TLS for encryption and perform certificates verification, but do not perform hostname verification.
- `verify-full`: Use TLS for encryption, certificate verification, and hostname verification.

# NevisDPDeployable_logging

Add logging configuration for nevisDataPorter.

# NevisAdaptDatabase_oracleVolumeClaimName

Due to licensing restrictions, we cannot ship any Oracle dependencies.

If you are using an Oracle database, are deploying to Kubernetes, and `Database Management` is _enabled_ (`complete` or `schema`), 
then you have to provide a Kubernetes volume containing an Oracle driver and client.

For more information, see [Preparing Oracle Volume](http://docs.nevis.net/nevisadmin4/Installation/Software-Installation/Kubernetes-Based-Installation/Prepare-Oracle-Volume).

Enter the name of that volume here.

The volume will be mounted in the `nevisadapt-dbschema` image to set up and patch the database schema.

The volume will be mounted in the `nevisadapt` image to connect to the database.
Because of that, there is no need to upload a `JDBC Driver`.


# LogSettingsBase_syslogHost

Defines where to send logs to via syslog.

This configuration is used only when syslog forwarding is enabled (see `Log Targets`).

The syslog facility is `localhost3` and the threshold is `INFO`.

# NevisIDMSecondFactorSelection_fido

Assign a step which may be selected when the user has an FIDO UAF Authenticator credential.

For instance, assign the `Out-of-band Mobile Authentication` pattern.


# CustomAuthLogFile_serverLog

Select the type of log4j appender.

This property is relevant for classic VM deployments only.

In Kubernetes the main logs are written to system out so
that log messages appear in the docker logs.
 
Choose between:

- `default` - log to a file
- `default + syslog` - log to a file and forward to a Syslog server
- `syslog` - forward to a Syslog server only

# KeyObject_keyStore

Reference a key store provider pattern or leave empty to let nevisAdmin establish a key store.
This reference property is considered when type `key store` is selected.

# EmailTAN_testingMode

When testing mode is enabled the TAN code is always `AAAAA`.

Thus, you can test the flow more easily during integration.

No email will be sent and thus no `SMTP Server` needs to be assigned.


# NevisFIDODeployable_backendTrustStore

The trust store nevisFIDO uses to connect to ```nevisIDM Instance```.

# TANBase_testingMode

Enables "Testing Mode". The TAN challenge is `AAAAA`.

When testing mode is enabled, the TAN challenge is constant and might not be sent over the linked connection. 

Each connection pattern decides individually how it behaves with respect to "Testing Mode". 

For instance, the `SwissPhone Connection` does not sent a message to the gateway when "Testing Mode" is enabled.


# WebhookCalls_login

Configure Webhook calls for login flows.

# NevisIDMPasswordLogin_emailSentRedirect

Where to redirect to once the password reset ticket has been generated.

- `root`: to the domain root (`/`) on this `Virtual Host`
- `referrer`: to the initial URL requested by the client
- `custom`: to a custom path or URL as configured by `Custom Email Sent Redirect`

Note that the `referrer` will always be a page requiring authentication, hence
it will basically redirect to the login page.


# OAuth2Client_tokenEndpointAuthMethod

Set authentication method for Token Endpoint. 

* None: for public client without secret
* Client_secret_basic: for confident OAuth 2.0/OpenId Connect Client.
Client need to send combination between OAuth 2.0/OpenId Connect Client and Secret in base64 using Authorization Header when call to Token Endpoint.
* Client_secret_post: for confident OAuth 2.0/OpenId Connect Client. 
Client need to send OAuth 2.0/OpenId Connect Client and Secret in request body when call to Token Endpoint.

# NevisIDMAuthorizationsAddon_roleManagementFile

Add properties for `authorizationConfig.properties`. 
If a role not defined in the uploaded file default values will be used for it.

See [Assigning IDM roles](https://docs.nevis.net/nevisidm/Configuration/Security/Authorization-internals/Assigning-IDM-roles) for details.

You can input the role with or without `nevisIdm` prefix.
For instance, both `Root` are `nevisIdm.Root` are supported.


# NevisIDMChangePassword_encryption

Set to enable form encryption.

This feature is still experimental in nevisAdmin 4 and has been added to this pattern as a preview.

The default template includes the required JavaScript (e2eenc.js) to perform client-side encryption
of the form values.

# WebApplicationAccess_responseRewrite

Enable to replace backend host names in responses
or set to `custom` for complex rewriting use cases.

- `off` - disables automatic response rewriting
- `header` - enables auto rewrite for response headers (including `Set-Cookie` header)
- `complete` - enables auto rewrite for the entire response (including body)
- `custom` - requires assignment of `Response Rewriting Settings` via `Additional Settings`

# NevisFIDOServiceAccess_fido

Assign a `nevisFIDO FIDO2 Instance`.

# OATHAuthentication_onSuccess

Configure the step to execute after successful authentication.

If no step is configured here the process ends and the user will be authenticated.

# OutOfBandMobileStepBase_host

To complete the authentication, the mobile app will send a request
to `/nevisfido/token/redeem/authentication`.

The domain is coded into the mobile app and has to be communicated
when ordering the app.

We recommend to assign the `Virtual Host` which serves that domain here
so that this pattern can generate the required configuration.

The `Virtual Host` assigned here will also be considered when calculating
the `Frontend Address` in the `nevisFIDO UAF Instance`.


# NevisDetectDeployableBase_jmsClientTrustStore

Reference a trust store provider pattern or leave empty to manage the trust store with nevisAdmin.

# AuthCloudOnboard_onboardingScreenButton

Adds another button to the onboarding screen.

The button may have a special `Button Name` set
to render it in a nice way using a customized `Login Template`.

For instance, Identity Cloud uses this mechanism to add
a button which looks like a back arrow. This button takes the user to a previous step.

This is an advanced setting.
Use only when you understand the concept.


# NevisAdaptDeployableBase_trustStore

Reference a trust store provider pattern or leave empty to manage the trust store with nevisAdmin.

# MultipleFieldUserInput_greeting

Enter a text or _litdict key_ to be displayed in a line below the title.

The text should inform the user what has to be entered in this form.


# GroovyScriptStep_guis

Add `Gui` elements to the `Response`.

For each line 1 `Gui` element will be generated.

Most authentication states have only 1 `Gui` element.

The format is key-value pairs. The key is used as `name`. The value is optional and used as `label`.

For instance, the line `auth:title.login` will produce the following `Gui` element:

```xml
<Gui name="auth" label="title.login"/>
```

Configuration of `GuiElem` elements is not supported.
You have to create them dynamically in your script.

Here is an example how to render a certain `Gui` and add `GuiElem` elements:

```groovy
response.setGuiName('login')
response.addInfoGuiField('info', 'info.login', null)
```


# RequestValidationSettings_logOnlyMode

Allows to use the request validation settings in log only mode.


# AccessRestriction_countryRules

Defines what action should be taken for a specified country.

Possible actions are:
* **allow**: Requests are let through
* **log**: A log entry is made for each request from the specified country
* **block**: Blocks requests from a country

# NevisFIDODeployable_relyingPartyId

Enter a base domain for all `Relying Party Origins`.

Example: `example.com`


# PropertiesTestPattern_modSecurityRuleProperty

Used in 1 place only.

# OATHAuthentication_loginType

Sets the type of login identifier which will be used to look up the user.

In nevisIDM any client whose users should be able to log in with their email address must have the following entry in the Client policy:
`authentication.loginWithEmail.enabled=true`

# OutOfBandMobileStepBase_nevisfido

Assign a `nevisFIDO UAF Instance` pattern.
nevisFIDO provides required services for out-of-band authentication.


# NevisAuthDeployable_dependencies

In case `AuthStates` uses custom AuthState classes upload the required JAR file(s) here.
Files will be deployed into the `plugin` directory of the nevisAuth instance.

# AzureServiceBus_provisioning

Remote Azure Service Bus Queue to which provisioning messages should be sent.

# SocialLoginCreateUser_idGeneration

Define how the user extId and profileExtId are generated. Choose between:
* undefined: the extId and profileExtId will be generated by nevisIDM, and 
it depends on nevisIDM config that the id will be uuid or in any sequence
* uuid: the extId and profileExtId will be generated in UUID format 
by nevisAuth and send to nevisIDM. 
The newly created user extId and profileExtId will be in UUID format

# NevisIDMDatabase_oracleApplicationRoleName

Name of the application role for the oracle database. It's recommended to keep the default value unless the pattern is used with an existing database that has a different one.

# NevisAdaptDatabase_flywayLicenceKey

Please provide a licence key in case you would use the Flyway Teams Edition.

This is recommended only in case you would use an old database version (more than 5 years old).
If you do not provide a licence key, the Flyway Community Edition will be used by default.

For more information about Flyway editions please visit this page [Flyway](https://flywaydb.org/download).


# NevisFIDOLogSettings_levels

Configure log levels.

In classic deployment nevisAdmin 4 does **not** restart nevisFIDO if you only change log levels.
The log configuration will be reloaded within 60 seconds after deployment.

The category `ch.nevis.auth.fido.application.Application` will **always** be generated.
If you don't set its level, `INFO` will be used.

This gives you:

- log messages during startup and when the startup is done
- 1 line per incoming request
- 1 line for each API call towards nevisIDM

Debug incoming requests:

```
org.springframework.web.filter.CommonsRequestLoggingFilter = DEBUG
```

Debug the entire component:

```
ch.nevis.auth.fido = DEBUG
```


# AuthCloudBase_allowedOperations

You can customize the pattern behavior by choosing one of the allowed operations.

The pattern supports two operations:

- enrollment: registers the user and their mobile device in the Authentication Cloud Instance.
- login confirmation: authenticates the user by sending a confirmation request to their mobile device via push notification.

Available options:

- enrollment: Choosing this will *disable login confirmation*.
- login confirmation: Choosing this will *disable enrollment*.
  Make sure the user and their mobile device are *already registered* in the Authentication Cloud Instance.
- both (default): Allows both operations.


# NevisAuthRealmBase_template

Customize the rendering of login pages.

Download the default template to get started.

### nevisLogrend: Simple Mode

Point your browser to a protected application to have a look at the login page.
Download any resources (e.g. images, CSS) that you want to adapt. 
Then upload the changed files here.

To change the outer HTML upload a file named `template.html`. Here is a simple example:

```html
<!DOCTYPE html>
<html lang="${lang.code}">
  <head>
    <title>${label.title}</title>
    <link href="${resources}/bootstrap.min.css" rel="stylesheet" type="text/css">
    <link href="${resources}/default.css" rel="stylesheet" type="text/css" media="all">
  </head>
  <body>
    <header id="header" class="container-fluid">
      <img class="logo center-block" src="${resources}/example.svg" alt="NEVIS Security Suite">
    </header>
    <main id="content" class="container">
      ${form}
    </main>
  </body>
</html>
```

Please also upload file resources referenced by your template (e.g. images, CSS, Javascript). 
Use this when you reference additional files, or if you want to override the default files provided. 

The template must contain `${form}` and may contain additional expressions.

| Expression | Description | 
|---|---|
| `${form}` | generated login form (required) |
| `${lang.switch}` | language switcher component |
| `${lang.code}` | current language code (i.e. EN, DE) |
| `${label.title}` | a human-readable title |
| `${label.myLabel}` | a custom text which must be defined via `Custom Translations` |
| `${resources}` | path to static resources (e.g. CSS, images, Javascript) |

Some resources (i.e. bootstrap.min.css, default.css) are provided out of the box
because they are required by the default template. Feel free to use them.

### nevisLogrend: Expert Mode

Expert users may upload Velocity templates and resources to nevisLogrend.

Zip files will be extracted into the nevisLogrend *application*:

`/var/opt/nevislogrend/<instance>/data/applications/<realm>`

Flat files will be added to the following subdirectories:

-  `webdata/template`: Velocity templates (`*.vm`)
-  `webdata/resources`: additional resources (e.g. images, CSS)

### nevisProxy: Simple Template

nevisProxy provides a simple login page renderer which can be used instead of nevisLogrend.
See `Login Renderer` for details.

For each enabled language (e.g. `en`) upload a file named `<lang>_template.html`.
The template must contain the placeholder `NEVIS_AUTH_FORM`. 

If your templates require additional resources (e.g. CSS, images)
upload them as `Hosted Resources` on the nevisProxy virtual host.


# NevisIDMSecondFactorSelection_mTAN

Assign a step which may be selected when the user has an mTAN credential.

You can assign any step here but we recommend to use the `Mobile TAN` pattern.

The session variable `user.mobile` will contain the mobile number from the mTAN credential.


# BehavioSecPluginPattern_fraudulentFlags

List of BehavioSec report flag names. Please add each entry line-by-line.

If any of these flags contains true value in the report, the request is marked as fraudulent and the request fails.

If the field remains empty, the items marked with (*) will be part of the default configuration.

Potential flag names (as of 5.4):

- advancedUser (*)
- autoModel
- coached (*)
- deviceChanged (*)
- deviceIdShared (*)
- deviceIntegrity (*)
- diError (*)
- drFlag (*)
- finalized
- ipChanged (*)
- ipShared (*)
- isDataCorrupted (*)
- isBot (*)
- isDuplicate (*)
- isOneHand
- isRemoteAccess (*)
- isReplay (*)
- isSessionCorrupted (*)
- isWhitelisted
- locationMismatch (*)
- newCountry (*)
- newsubprofile
- numpadAnomaly (*)
- numpadUsed
- numrowUsed
- ohFlag (*)
- otjsError (*)
- pdError (*)
- pnFlag (*)
- pocAnomaly (*)
- pocUsed
- tabAnomaly (*)
- tabUsed
- travelTooFast (*)
- uiConfidenceFlag (*)
- uiScoreFlag (*)


# WebhookCalls_signup

Configure Webhook calls for signup flows.

# Logout_label

Enter a label for the message that shall be presented to the user.
This is used when `Logout Behaviour` is set to `gui`.

# PropertiesTestPattern_durationProperty

Enter a time duration with unit.

# DatabaseBase_keyStore

Define the key store to use for 2-way HTTPs connections for DB endpoint.

This configuration only accept PEM Key Store pattern configuration.

**Noted**: This is an experimental configuration

# NevisAdaptAnalyzerConfig_fingerprintAnalyzer

Fingerprint Analyzer is a global setting, disabling this
means that the device analyzer will not be used to
calculate risk scores. This will result in a lower
risk score for all users.

If you wish to disable, consider disabling all other submodules as well.



# NevisDetectLogSettings_serverLogFormat

[Logback log format](https://logback.qos.ch/manual/layouts.html#conversionWord) for the default SERVER logs.
This pattern is used for **non**-kubernetes deployments.

Note: not relevant when Log Targets is set to `syslog`.

# AuthCloudBase_onSkip

Assign a step to continue with when the user clicks the skip button.

A skip button will be added to the authentication screen.


# AuthenticationFlow_stepup

Assign a step to execute for incoming requests when there already is an authenticated session.

If not present already, the step will be added to the `Authentication Realm`.

If no step is assigned the same step as for `Authentication Flow` will be executed.

# CookieCustomization_sessionCookies

Cookies listed here will be stored in nevisProxy.

However, cookies marked as `Client Cookies` in any `Cookie Customization` pattern
assigned to the same application will still be allowed to pass through!

Storing cookies requires a user session.
Thus, we recommend to not use this feature for stateless or public applications!

Incoming cookies with the same name will be blocked.

Regular expressions are supported.

**Example**:

- `.*SESSION.*`


# NevisFIDO2Database_schemaUser

The user which will be used to connect to the database and create the schema (tables).

The database must have been created already (`CREATE DATABASE`)
and the user must have `CREATE` privileges for this database.

Example: `schema-user`


# NevisProxyDatabase_type

Choose between `MariaDB` and `PostgresSQL`.

We recommend to use `MariaDB` as it is supported by all Nevis components that have a database.


# OAuth2AuthorizationServer_clients

Assign `OAuth 2.0 Client` patterns.

Configuration is ignored if `nevisMeta` is used.

# PropertiesTestPattern_portProperty

Enter a port number.

# SwissPhoneChannel_password

The password to use to connect to the SwissPhone SMS Gateway.

# TANBase_maxRegenerate

The maximum number of times a **new** code can be generated.

If the value is `1` or greater, a _resend_ button will be added to the screen.
The button is shown only when there are still resends left.

When you configure `0` there will only be `1` code and thus there will be no resend button.
Note that when `Max Retries` is reached, a new code will be generated and sent automatically.


# NevisKeyboxProvider_label

Setting the `Label` is required if this pattern is used as a key store provider.

This pattern relies on the standard nevisKeybox mechanism for retrieving the passphrase of the private key.

Run the following commands on all target server(s) to ensure the passphrase can be retrieved:

`neviskeybox passwd -slot <slot> -label <label> -keep`

`neviskeybox access -slot <slot> -label <label> -group nvbgroup`

The last command will generate a shell script `/var/opt/neviskeybox/default/<slot>/<label>_keypass`
which can be invoked by NEVIS components to retrieve the passphrase.

Due to a limitation in some NEVIS components keypass files which contain base64 encoded passphrases are not supported yet.
Replace any of the following content with a simple echo returning the passphrase directly.

`echo "cGFzc3dvcmQ=" | openssl base64 -d`

nevisKeybox may also be integrated with nevisCred to store the passphrase in a secure place.
In this case the shell script will not contain the passphrase but a call of nevisCred.


# NevisIDMDeployable_mailSMTPPass

Set if a password is required to connect to the SMTP server.

# OAuth2Client_phone

Set to `allowed` to allow this client to request the scope `phone`.

# CustomRiskScoreWeightConfiguration_locationWeight

Configuration of the risk score weight for the geolocation analyzer's risk score.

# 4.20.0

Full changelog:

[Patterns 4.20.0 Release Notes - 2023-08-16](https://docs.nevis.net/nevisadmin4/release-notes#patterns-4200-release-notes---2023-08-16)

##### Automatic Key Management (Classic)

In a _classic_ (VM) deployment, the automatic key management now generates most of the key material at generation time.

Only JKS and PKCS12 format files are still assembled on the target hosts by running a command.
JKS and PKCS12 files are therefore **not** shown in the deployment preview.

Generated key material is stored in the nevisAdmin 4 database until expiration.

The new implementation is simpler and more reliable, but leads to changes in the deployment preview.
You can ignore any differences to the `/var/opt/keys` folder.

The automatic key management for classic deployment is still **only** supposed to speed up integration work, 
but **not** intended to be used in production.

##### ModSecurity Core Rule Set Upgrade

The default _OWASP ModSecurity Core Rule Set_ (CRS) version has been upgraded from `3.3.4` to `3.3.5`.

If you have explicitly selected the `3.3.4` version rule set (`ModSecurity Rule Set` in the `Virtual Host` pattern),
you need to change to the new default version `3.3.5`.

##### nevisAdapt Feedback Configuration change

Feedback-related configuration values from `nevisAdapt Deployable` and `nevisAdapt Authentication Connector` were grouped together in the new `nevisAdapt Feedback Configuration` pattern.
Please add one under `nevisAdapt Deployable`/`Advanced Settings` and fill it out with the values from the earlier configuration.


# GenericIngressSettings_propagateClientCert

Indicates if the received certificates should be passed on to nevisProxy in the header `ssl-client-cert`.

# NevisDetectDatabase_password

Enter the password of the DB connection user.


# NevisAuthRealmBase_authConnectorParams

Add custom `init-param` elements to the `Esauth4ConnectorServlet` generated by this pattern.

That servlet is called `Connector_<name>`.

Multi-line values, as required for conditional configuration,
can be entered by replacing the line-breaks with `\n`. 

Examples:

| Key                  | Value                                                          |
|----------------------|----------------------------------------------------------------|
| EnablePollTerminatedCalls | true                                                      |


# NevisIDMJmsQueues_provisioning

NevisIDM JMS Queue to which Provisioning messages should be sent.

Only accepts URIs starting with `amqp`, `amqps` or `Endpoint=sb`.
Validates only URIs with `amqp` or `amqps` schemes.

# GenericAuthenticationStep_parameters

Define _Template Parameters_.

The syntax is a multi-line String containing a YAML map (key-value pairs). Example:

```yaml
smtp: smtp.siven.ch
sender: noreply@siven.ch
doctype: "&lt;!DOCTYPE html&gt;"
counter: 1
```

As shown in the example above,
double quotes `"` need to be put around the value if the value contains special characters.

Parameters can be used in:

- `AuthState(s): direct input`
- `AuthState(s): as file`

The expression formats are:

`${param.<name>}`:

- `name` found: parameter value is used.
- `name` missing: expression is **not** replaced.

`${param.<name>:<default value>}`:

- `name` found: parameter value is used.
- `name` missing: default value will be used.

In `<default value>` the character `}` must be escaped as `\}`.

# CustomNevisMetaLogFile_serverSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# GroovyScriptStep_onSuccess

Assign an authentication step which shall be executed 
when the Groovy script sets the result `ok`.

```
response.setResult('ok')
```

If no step is assigned a default state will be added.

# LdapLogin_urls

Configure the LDAP endpoint.
The URL must start with `ldap://` or `ldaps://`

In case of `ldaps://` you may have to import the certificate of the CA which has issued the certificate
 of the LDAP server into the `Backend Trust Store` on the `nevisAuth Instance`.

# GenericDeployment_path

Absolute path of a directory on the target host(s) where the files will be deployed to. The command 
will run from the same path. 

nevisAppliance targets only: if the files must be persisted across reboots, use a file name
or path listed in the `/etc/rwdisk.conf` file on the nevisAppliance target host.

The path must not point into a directory (potentially) managed by a nevisAdmin 4 Instance Pattern.
Thus, it is not possible to directly overwrite files generated by other patterns. See `Command` 
and `Command: Execution File Triggers` for an alternative solution to overcome this limitation.

Allowed Paths:
* `/tmp/generic-deployment`
* `/var/opt/<directory>`

Example:
* `/tmp/generic-deployment/patch01/`


# GenericNevisFIDOSettings_nevisFidoYml

This setting provides a low-level way to
add or overwrite configuration in `nevisfido.yml`.

Enter the configuration as it would appear in the `nevisfido.yml` using correct indentation.

Example:

```yaml
fido-uaf:  
  dispatchers:
  - type: png-qr-code
    registration-redeem-url: http://localhost:9080/nevisfido/token/redeem/registration
    authentication-redeem-url: http://localhost:9080/nevisfido/token/redeem/authentication
    deregistration-redeem-url: http://localhost:9080/nevisfido/token/redeem/deregistration
```


# OutOfBandMobileDeviceRegistration_nevisfido

Assign a nevisFIDO instance. 

This instance will be responsible for providing the device registration services.


# PropertiesTestPattern_textProperty

Enter a text block.

# OAuth2AuthorizationServer_consentScreen

Select `enabled` if you want to ask the user to grant consents for scopes.

Which scopes require consent can be configured in nevisMeta.

Select `disabled` if you don't have any scopes that require consents,
or if you have to do custom consent handling.


# AppleLogin_clientExtId

The ExtId of the client in nevisIDM that will be used to store the user 

# NevisLogrendConnector_url

Enter `hostname:port` of the nevisLogrend instance.

# NevisFIDOLogSettings_serverSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# NevisAdaptDeployable_proxyHost

Enter the host for the forward proxy if available.

# NevisAuthRealmBase_authParams

Add custom `init-param` elements to **each** `IdentityCreationFilter` generated by this pattern.

Most realms generate only 1 `IdentityCreationFilter` named `Authentication_<name>`, 
which is used to protect the application.

Multi-line values, as required for conditional configuration,
can be entered by replacing the line-breaks with `\n`. 

Examples:

| Key                  | Value                                 |
|----------------------|---------------------------------------|
| BodyReadSize         | 64000                                 |
| InterceptionRedirect | Condition:ENV:HTTP_USER_AGENT:mozilla\|Mozilla\ninitial\nnever |
| ClientCert           | want                                  |


# NevisProxyDatabase_parameters

Enter parameters for the DB connection string.

Enter 1 parameter per line.

Lines will be joined with `&`.

The default for MariaDB:

```
ping_timeout=2
connect_timeout=10
```

and for PostgreSQl:

```
connect_timeout=10
```

The default value will be used **only** when no parameters are entered.

If you want to keep the default parameters, add them as well.


# SwissPhoneChannel_serverAddress

The address of the server hosting the SwissPhone SMS Gateway.


# NevisDetectAdminDeployable_port

Enter the port on which nevisDetect Admin service will listen.

# SendgridChannel_key

API key to connect to Sendgrid.

# MultipleFieldUserInput_title

Enter a text or _litdict key_ for the form title (`<h1>`).

# FIDO2Onboarding_onSuccess

Assign an authentication step to continue with after successful FIDO2 onboarding.


# GenericSocialLogin_responseMode

The mode used for the responses of the server. It can be either `Query` or `Form POST`.
The default value is `Query`.

# NevisAdaptDeployable_ipReputationCron

Pick the update frequency of the IP reputation database.

Valid values:

* `disabled` - no update mechanism will be triggered. Not recommended for productive environment.
* `hourly`
* `daily`  
* `weekly`  
* `monthly`

When selecting 'disabled', it's highly recommended having a custom mechanism in place for keeping the database file up-to-date. 
We recommend [setting up periodic update of IP geolocation and reputation mappings](https://docs.nevis.net/nevisadapt/Installation-of-nevisAdapt/Setting-up-periodic-update-of-IP-geolocation-and-reputation-mappings).


# SamlIdp_issuer

Configure the `Issuer` used by this IDP.

The issuer can be an arbitrary String but it is a common practise 
to use the URL of the IDP. 

Example: `https://idp.example.org/SAML2/`

# OutOfBandMobileStepBase_trustStore

The trust store used to establish a connection with the nevisFIDO component.

The trust store must contain the certificate of the CA that has issued
the certificated contained in the `Key Store` of the `nevisFIDO UAF Instance`.

In case both sides use automatic key management, 
trust can be established automatically and there is nothing to configure.


# NevisAuthDeployable_frontendTrustStore

Assign the Trust Store provider for the HTTPs endpoint.
If no pattern is assigned the Trust Store will be provided by the nevisAdmin 4 PKI.

# GenericHostContextSettings_servlets

Configure `servlet` and/or `servlet-mapping` elements
using the XML constructs described in the nevisProxy Technical Documentation.

You can also customize elements which have been generated by other patterns.
Elements can be referenced as follows:

- `servlet`: `servlet-name`
- `servlet-mapping`: `url-pattern`

In Kubernetes side-by-side deployment a postfix is added to service names. 
Use the expression `${service.postfix}` connecting to a service deployed against the same inventory.

Example 1: Add or overwrite an `init-param` for an existing `servlet`:

```xml
<servlet>
  <servlet-name>Hosting_Default</servlet-name>
  <init-param>
    <param-name>NoMatchFile</param-name>
    <param-value>/index.html</param-value>
  </init-param>
</servlet>
```

Example 2: Remove a `servlet-mapping`:

```xml
<servlet-mapping>
    <url-pattern>/app/*</url-pattern>
</servlet-mapping>
```

Here we left out the `servlet-name` to tell the pattern to remove the `servlet-mapping` for the given `url-pattern`.

Note that the mapping of the hosted resources is an exception and cannot be removed this way 
(see the property `Hosted resources` of the Virtual Host pattern for more information).

Removing a `servlet` element is not supported.

# CustomAuthLogFile_hide

Enter variables that should be hidden in logs. 

The special option `auto` hides the following variables:

- variables used for GUI elements of type `pw-text`
- `dyncert.key`
- `connection.HttpHeader.Authorization` 
- `client_secret`

The wildcard `*` may be appended (but not prepended).
This way, every variable that starts with a certain string will be hidden from the log. 
For instance, `passw*` will hide `password` and `passwd`.


# OAuth2UserInfo_signer

Configure the key material which is used to validate tokens. This signer must be the same signer that use to sign the tokens.

# SamlSpConnector_subjectFormat

Set the `format` of the `NameID` element.

Examples:

```
urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
```

# AppleLogin_clientId

ClientID is `Identifier` provided by Apple when you register Apple as IdP service.

# NevisAdaptDatabase_oracleOwnerRoleName

Name of the owner role for the oracle database used for the Kubernetes migration. It's recommended to keep the default value unless the pattern is used with an existing database that has a different one.

# AuthStatePatch_patchFile

Upload an XML file containing `AuthState` patch elements.

Example to illustrate the syntax:

```xml
<AuthState name="Check_FIDO2_Credential" class="ch.nevis.idc.auth.EventLoggingAuthState">
    <property name="eventLogger.wrappedState" value="ch.nevis.admin.v4.plugin.fido2.patterns.FIDO2Authentication"/>
    <property name="eventLogger.eventName" value="user.password.verified"/>
    <property name="eventLogger.failed.results" value="failed,noCredential,tmpLocked,locked"/>
    <property name="eventLogger.userDto" value="${sess:ch.adnovum.nevisidm.userDto}"/>
</AuthState>
```  


# NevisProxyObservabilitySettings_metricsTimeout

Configures a timeout for the metrics observable callback.



# AuthCloudBase_authenticationType

Choose between:

- `QR code / deep link`: renders a QR code which should be scanned or shows a deep link
- `push / deep link`: sends a push notification to the user which tells them to check the access app or shows a deep link.

The first option is used for non-mobile browsers. 
The `deep link` is shown when using a browser on a mobile.


# NevisIDMWebApplicationAccess_apiAccess

Enables REST API access for the NevisIDM web application. As of 2022 May it is only needed by the Terms & Conditions
functionality. If Terms & Conditions is not used, then this can be disabled safely.

- `enabled` - the REST API will be exposed on the path `/nevisidm/api/*`.
- `disabled` - access to the path `/nevisidm/api/*` will be blocked.

If the REST API is enabled here, then the use of the `nevisIDM REST Service` pattern is not needed.

**WARNING: if the `nevisIDM REST Service` pattern is also used, and has different realms or SecToken patterns assigned, then the
configuration may lead to a requirement clash or a similar issue**


# NevisAuthRealmBase_authHostCheck

Enable to verify that the hostname on the certificate presented by nevisAuth matches the configured hostname in the `nevisAuth Instance` or `nevisAuth Connector` pattern.


# GenericThirdPartyRealm_initialSessionTimeout

Define the idle timeout of the initial session.
The user must complete the authentication within this time.


# NevisIDMUserLookup_onUserNotFound

Assign a step to execute in the following error cases:

- User not found (`1`)
- User archived or disabled (`98`)

The variable `lasterror` is **not** cleared from the `notes`
and thus an error message may be displayed in the next GUI which is rendered by nevisAuth.

This setting does **not** apply to technical errors. 
In case the call to nevisIDM fails the GUI will be shown (again) and the
the message `error_99` will be displayed.

# 4.16.0

Full changelog: 

[Patterns 4.16.0 Release Notes - 2022-08-17](https://docs.nevis.net/nevisadmin4/release-notes#patterns-4160-release-notes---2022-08-17)

##### GUI Naming

The name of several `Gui` elements has been adapted.
If you have a `Login Template` that expects certain names, you may have to adapt your `*.vm` and `*.js` files:

- `ConsentDialog` -> `oauth_consent`
- `cloud_mobile_auth` -> `authcloud`
- `oobloginform` -> `mauth`

##### Out-of-band Mobile Authentication

How this authentication step determines the userid has been changed.
Check the release notes for details.

##### SAML IDP Dispatching

In previous versions the `SAML IDP` did not use the `Fallback Session Upgrade Flow` of `Authentication Realm`.

This has been changed so that a flow can be executed when there already is an authenticated session.
Further, the `Fallback Session Upgrade Flow` has been renamed to `Default Session Upgrade Flow`.

The `SAML IDP` will now always dispatch into the `Default Session Upgrade Flow` when
an authenticated session is found and none of the `Session Upgrade Flows` are applicable.

Note that `Session Upgrade Flows` will only be applied when their `Authentication Level` is required.
This can be achieved by either:

- assigning an `Authorization Policy` requesting an `Authentication Level` to applications protected by `SAML SP Realm`,
- declaring a `Minimum Required Authentication Level` in `SAML SP Connector` patterns.

##### SAML Issuer and Audience Restriction

Commas and whitespaces are not allowed for SAML `Issuer` and `Audience Restriction`.
If you need multiple `Audience` elements, enter multiple lines.


# OAuth2Client_oidc

If enabled the scope openid is allowed for this client.

# NevisDetectAdminWebApplicationAccess_admin

Reference for the pattern with the details of the web application.

Supported patterns:
- nevisDetect Admin Instance

# FrontendKerberosLogin_onFailure

Assign authentication step that is processed if Kerberos authentication fails.

If no step is assigned an AuthState `Authentication_Failed`
will be created automatically.

# GenericSocialLogin_buttonLabel

The text that should be displayed for the end-user on the social login button, and provide translations for this label on the Authentication Realms.

# SamlToken_keystore

Assign a pattern which sets the key material used for signing the token.

If no pattern is assigned automatic key management is used
and the signer key will be created automatically.

# NevisDetectRiskPluginBase_proxy

Outbound proxy, optional

# Dispatcher_steps

Assign the steps to be used for `Transition(s)`.

# SamlSpRealm_preProcess

Assign a step to apply custom pre-processing logic 
before executing SP-initiated SAML authentication.
This pre-processing logic is executed for methods: `authenticate`, `stepup`, `unlock`, and `logout`.

You may assign a chain of steps to build a flow.
The dispatching will continue when leaving this flow on the happy path.

For `On Success` exits this works automatically. 

However, generic exits (i.e. `Additional Follow-up Steps` in `Generic Authentication Step`) 
must be marked a _success exits_ by assigning the `Pre-Processing Done` pattern.


# MobileTAN_onFailure

Assign the step to execute in case no mTAN can be sent or all attempts had been exhausted.
 
The step will be executed in the following cases:

- there is no session variable (`user.mobile` or `sess:ch.nevis.idm.User.mobile`) which contains the mobile number of the user
- the mobile number cannot be converted into a format supported by the `Connection Provider`
- all attempts had been exhausted and the user has failed to authenticate

If no step is assigned then the authentication flow will be terminated 
and an error GUI with label `error_99` (`System Problems`) will be shown.


# TCPSettings_keepAlive

Pool TCP connections to backends for later reuse. 

- `default`: does not generate any configuration so the default nevisProxy behaviour will apply.
- `disabled`: the TCP connection is closed after use, and a new connection will be established for the next request. 
- `enabled`: the TCP connection is put in a pool so that it can be reused by future requests. 
Limiting factors are `Connection Pool Size`, `By Client`, `Inactive Interval`, and `Lifetime`.


# AuthenticationFailed_code

Enter a status code for error page produced by nevisAuth.
If not set the status code will be `200`.

Note that the error page from nevisAuth will not be shown, 
when error handling is applied by nevisProxy.

nevisProxy replaces the body of the HTTP response, when there is a page for this status code, 
uploaded to `Hosted Resources` of the `Virtual Host`, or to a `HTTP Error Handling` pattern.

# SocialLoginBase_onSuccess

The step executed after a successful authentication.
If no step is configured here the process ends with `AUTH_DONE`.

In case you change this to your custom step(s),
you can assign pattern `Social Login Final Step` as the last step of the Authentication process 
to redirect back to original URL.

# HostContext_cache

Add a Static Content Cache pattern to the Virtual Host.

Use it to cache the early hint resources as static content in nevisProxy to further increase the performance.
Map the Static Content Cache pattern to the same paths as the Early Hints parameter.

# RequestValidationSettings_rules

Use to **add**, **modify**, or **remove** ModSecurity rules. 

Use the _Rule recommender_ to white-list requests. 
Click the link to open the dialog, 
then paste log snippets from the nevisProxy `navajo.log` 
for requests which have been blocked by ModSecurity.

The log statement must contain the trace group `IW4ModsecF`
and at least the `id` of the ModSecurity rule which has blocked the request. 
Example:

```
2020-07-21 13:00... IW4ModsecF ... Matched "Operator `Rx' with parameter ... against variable `REQUEST_BODY' ... [id "930100"] ... [uri "/nevisidm/admin/"]
```

The recommender will propose _ModSecurity modifications_ 
to prevent these requests from being blocked in the future. 
The modifications will be as specific as possible, including the path, 
as well as parameters from the request. 
Please review the recommended modifications and adapt as required.

You may also enter your own rules or modifications directly, skipping the recommender dialog.
Check the [ModSecurity documentation](https://www.modsecurity.org/CRS/Documentation/exceptions.html) 
for further information on how to modify rules.
 
Both _exception modifications_ or _whitelist modifications_ are allowed in this box. 
The pattern ensures that the statements are included into the correct place 
in the generated ModSecurity configuration.

New ModSecurity rules require a _rule ID_ which has to be unique within this pattern 
and must not used in the rule set. 
According to [ModSecurity documentation](https://www.modsecurity.org/CRS/Documentation/ruleid.html)
the range `1-99999` is reserved for local (internal) use.
The rule recommender will use the range `10001-10999`.

# MultipleFieldUserInput_fields

List to contain `Custom Input Field`s and `Email Input Field`s, to retrieve information from the user.

# CustomAuthLogFile_eventsLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the EVENTS logs.

Note: not relevant when Log Targets is set to `syslog`.

# NevisIDMPasswordLogin_level

Set an authentication level if authentication of this step is successful.
The level is relevant only if there are is an `Authorization Policy`
assigned to applications.

# NevisAdaptRestServiceAccess_backendHostnameCheck

Enable to verify that the hostname on the certificate presented by the backend matches the hostname of `nevisAdapt Instance`

# GenericThirdPartyRealm_addons

Assign add-on patterns to customize the behaviour of applications protected by this realm.

A common case for redirect-based authentication is to assign a `Cookie Customization` here and to `Authentication Application Settings`
to share cookies between applications and the authentication application.

# AzureServiceBus_truststore

Assign a trust store which provides the `Microsoft Azure TLS Issuing CA 01` certificate.

You can access the `Host name` with your browser by adding `https://` in front, 
download the CA certificate, and then use a `PEM Trust Store` to provide it. 

# NevisAdaptServiceAccessBase_csrf

_Cross-Site Request Forgery_ (_CSRF_) is an attack to force an authenticated user to send unwanted requests.

- `off (default)` - no CSRF protection. Recommended for applications which may be called from other sites.
- `header-based` - `GET` and `HEAD` requests are allowed (assumption: these methods must not manipulate server-side state). 
For other requests the `Referer` and `Origin` headers must match the `Host` header.

# DatabaseBase_type

Choose between `MariaDB` and `Oracle` and `PostgresSQL`.

We recommend to use `MariaDB` as it is supported by all Nevis components that have a database.

**Note:** `PostgresSQL` database is only experimental configuration.


# LdapLogin_loginidField

Specifies the attribute in the LDAP directory that should match the users login-ID input. 

Examples:

* `uid`
* `cn`

# HostContext_http2

Enables the support of HTTP/2 for incoming connections on this nevisProxy virtual host.

Note that mod_qos has limited support for HTTP/2, therefore only request level directives are supported if enabled.

# LuaPattern_libraries

Upload addtional Lua libraries to be used within the `Lua Script`.

Uploaded files will be deployed to the following directory:

```
/var/opt/nevisproxy/${instance}/${host}/WEB-INF/lib/${name}/"
```

The Lua script **must** patch `package.path` so that the Lua libraries can be used.

For instance, add the following line at the beginning of the script:

```
package.path = package.path .. ";/var/opt/nevisproxy/${instance}/${host}/WEB-INF/lib/${name}/?.lua"
```

# SamlSpIntegration_acsPath

Enter a sub-path of the application to sent the POST request to.

The POST request is sent by a DelegationFilter mapped in phase `AFTER_AUTHORIZATION`.

# ErrorHandler_path

By default, the error pages are deployed to `/errorpages/<name>` but you can set a different location here.

# GenericNevisProxySettings_instanceSettings

Customize the Navajo servlet container configuration (`navajo.xml`)
using XML constructs described in the [nevisProxy Technical Documentation](https://docs.nevis.net/nevisproxy).

The root element `<Service>` must be provided.

Examples:

Increase number of parallel requests (worker threads):

```xml
<Service>
    <Server MaxClients="1000"/>
</Service>
```

Increase the maximum allowed request body size:

```xml
<Service>
    <Server LimitRequestBody="10485760"/>
</Service>
```

Set a `Context` attribute for `some.domain.com`:

```xml
<Service>
    <Engine>
        <Host name="some.domain.com">
            <Context additionalStatusCodes="207,210,242,422,423,424,449,456,540,541,543,544,545,456,549,552,560" />
        </Host>
    </Engine>
</Service>
```

Overrule the allowed HTTP methods for `some.domain.com`:

```xml
<Service>
    <Engine>
        <Host name="some.domain.com">
            <Context allowedMethods="ALL-HTTP" />
        </Host>
    </Engine>
</Service>
```

Overrule the server aliases for `some.domain.com`:

```xml
<Service>
    <Connector name="some.domain.com" port="*" serverAlias="*.domain.com">
    </Connector>
</Service>
```

It is possible to use the following placeholders:

- `${instance.id}`: unique ID of the `nevisProxy Instance` pattern
- `${instance.name}`: name of the nevisProxy instance. For instance, use `/var/opt/nevisproxy/${instance.name}` to refer to the instance directory.

Limitations:

- customizing `Navajo` elements is not supported
- customizing `Host` (or its child elements) requires `name`


# SamlSpConnector_sls

Enter the _Single Logout Service URL_ of the SP.

If omitted the Assertion Consumer Service URL is used.

# PermissionFilter_onSuccess

Assign the next authentication step (optional).

# NevisFIDO2Database_encryption

Enables SSL/TLS in a specific mode. The following values are supported:

- `disabled`: Do not use SSL/TLS (default)
- `trust`: Only use SSL/TLS for encryption. Do not perform certificate or hostname verification. This mode is not safe
  for production applications but still safer than `disabled`.
- `verify-ca`: Use SSL/TLS for encryption and perform certificates verification, but do not perform hostname verification.
- `verify-full`: Use SSL/TLS for encryption, certificate verification, and hostname verification.


# OAuth2PAREndpoint_requestTimeout

Configure how the PAR request shall be valid.

For security reasons, we suggest to keep this duration as low as possible.

If not set, the default in the nevisAuth component (90s) applies.


# NevisFIDODeployable_displayNameSource

Defines the attribute of the user that will be populated into the `user.name` property in the [PublicKeyCredentialCreationOptions](https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions) object that nevisFIDO sends to the FIDO2 client during the Registration ceremony.
Some browsers choose this `user.name` property to display to the user when they prompt for user interaction (as opposed to `user.displayName`). 
Supported values are `loginId`, `displayName`, `email` and `username` - this latter does not correspond strictly to a nevisIDM user property, but instead is the same `username` what nevisFIDO received in the `ServerPublicKeyCredentialCreationOptionsRequest` object.

The default is `loginId`.

# HostContext_rules

Upload a `.zip` file containing configuration for ModSecurity.
The `.zip` must contain a configuration file called `modsecurity.conf`.

The `modsecurity.conf` file will be included for all `Web Application` patterns
which have `Request Validation` set to `standard`, `custom`, or `log only`.

Click `Download Default Configuration` to download the default configuration
which is applied when no `.zip` is uploaded.
There is one link per provided `OWASP ModSecurity CRS Version`.


# NevisAdaptAuthenticationConnectorStep_onHighRisk

Will be considered only if `Profile` is set to either `balanced`, `strict` or `custom`.

Set the step to continue with if the calculated risk score exceeds the High threshold.

In case it remains unset:
1. `On Medium Risk` becomes mandatory
2. Applies the same next step as `On Medium Risk`

# NevisIDMDeployable_addons

Assign add-on patterns to customize the configuration of nevisIDM.

# NevisAuthRealmBase_logrend

Assign a pattern which defines the login renderer.

In case no pattern is assigned a nevisLogrend instance named `default` will be created 
and deployed on the same host as nevisProxy.


# GroovyScriptStep_onFailure

Assign an authentication step which shall be executed 
when the Groovy script sets the result `error`.

```
response.setResult('error')
```

If no step is assigned a default state will be added.

# NevisAdaptObservationCleanupConfig_cleanupPeriodDays

This value indicates the buffer time beyond the base observation timeframe for removing trusted observations.

The default value is `1d`.

# JWTToken_audience

The audience (`aud`) is an optional claim 
which may be checked by applications receiving this token.

# OutOfBandMobileStepBase_policy

Enter the name of a policy provided by the assigned `nevisFIDO` instance.

Read the help of the `Policies` settings in the `nevisFIDO UAF Instance` pattern for details.

By default, no policy name is set here and thus the policy `default` will be used.

You can also enter a nevisAuth or EL expression to determine the policy based on the request or the user session.


# Button_buttonValue

Enter a `value` to use for the `GuiElem`.

Configure only when you need a different value.


# DummyLogin_onSuccess

Set the step to continue with on successful authentication.
If no step is assigned, the process ends and the user will be authenticated.

# JSONResponse_parameters

Define _Parameters_ to be used in the `JSON Response`.

Examples:

```yaml
backend-host: backend.siven.ch
```

The expression formats are:

`${param.<name>}`:

- `name` found: parameter value is used.
- `name` missing: expression is **not** replaced.

`${param.<name>:<default value>}`:

- `name` found: parameter value is used.
- `name` missing: default value will be used.

In `<default value>` the character `}` must be escaped as `\}`.


# CustomNevisIDMLogFile_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.

This setting applies to `application.log` and `batch.log` only.
The `audit.log` is rotated on a daily basis.


# NevisAuthRadiusResponse_type

The Radius message type. 

For instance, use `Access-Challenge` to prompt the user for input.

# GenericNevisFIDOSettings_javaOpts

Add additional entries to the `JAVA_OPTS` environment variable.

Use the expression `${instance}` for the instance name.

For instance, you may configure nevisFIDO to create a heap dump on out of memory as follows:

```
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/opt/nevisfido/${instance}/log/
```

Be aware that this example will not work for Kubernetes
as the pod will be automatically restarted on out of memory
and the created heap dump files will be lost.


# NevisIDMDatabase_oracleIndexTablespaceName

Name of the index tablespace for the oracle database. It's recommended to keep the default value unless the pattern is used with an existing database that has a different one.

# SamlSpConnector_logoutMode

Configure the logout mode when a logout is initiated by or for this SP. Choose between:

* **ConcurrentLogout-Redirect**: IdP will send logout to all SP(s) at once.
* **SingleLogout**: IdP will send logout to 1 SP at a time.
* **SingleLogout-SOAP**: IdP will send SOAP logout to SP(s) one by one using SOAP method.

# Maintenance_page

The page must contain two meta-tags which define the maintenance interval 
and will be patched during generation.

Example:

```html
<head>
  <meta name="maintenance-start" content="${maintenance-start-value}">
  <meta name="maintenance-end" content="${maintenance-end-value}">
</head>
```

If the date and time on the target host are within this interval, the maintenance page will be shown. 
See also the introduction help text above.


# NevisIDMDeployable_managementPort

This port is used in Kubernetes deployment to check if the instance is up after deployment.

# NevisIDMUserLookup_rememberInput

Select `enabled` to add a `Remember Input` checkbox.

By ticking the checkbox the whatever has been entered by the user
will be stored in a long-living cookie (named like this pattern).

Using this cookie, the login ID will be prefilled on subsequent authentications.

If no GUI is shown (e.g. to look up the user based on `Login ID Source`) you **must** select `disabled`.


# NevisAuthRealmBase_maxSessionLifetime

Define the maximum lifetime of an authenticated session.
The session will be removed after that time even if active.

# NevisAdaptAnalyzerConfig_sharedDeviceAnalyzer

Used to disable the shared device analyzer. This means that the shared device analyzer will not be used to calculate risk scores.

# SocialLoginBase_onFailure

The step that will be executed if the authentication fails.
If no step is configured here the process ends with `AUTH_ERROR`.

In case you change this to your custom step(s),
you can assign pattern `Social Login Final Failure Step` as the last step of the Authentication process
to redirect back to original URL.

# FIDO2Onboarding_welcomeScreenButton

Configure to add a dispatcher button to the welcome screen.

The button may have a special `Button Name` to render in a nice way by a customized `Login Template`.

For instance, Identity Cloud uses this mechanism to add a button which looks like a back arrow. 
This button takes the user to a previous step.

This is an advanced setting. Use only when you understand the concept.


# NevisAuthDeployable_addons

Assign an add-on pattern to customize the configuration of nevisAuth.

# NevisIDMAdvancedSettings_properties

Add properties for `nevisidm-prod.properties`.
See nevisIDM Reference Guide (chapter Configuration files) for details.

# AuthCloudOnboard_onSuccess

Assign a step to execute after successful onboarding.

If no step is configured, the flow ends and an authenticated session will be established.

This requires that the session contains an authenticated user. 

A simple way to ensure that is to include `nevisIDM User Lookup` or `nevisIDM Password Login` steps in your flow.


# NevisIDMChangePassword_currentPassword

Mandatory input value to use for old password if `Show GUI` is `disabled` and `Re-enter old Password` is `enabled`.

# SamlSpIntegration_relayState

Enter a static value, or a nevisProxy expression, 
which defines the value of the POST parameter `RelayState` that shall be sent to the SP 
together with the SAML `Response`.

Whether a `RelayState` is required depends on the SP.
Many SPs expect a URL and will redirect to this URL
once the SAML `Response` has been successfully validated.

# RealmBase_sessionTracking

Choose between:

- `COOKIE`: issue a session cookie.
- `AUTHORIZATION_HEADER`: track the session based on the value of the Authorization header.
- `CUSTOM`: track the session based on custom configuration. It generates an empty session filter which has to be replaced (see below).
- `disabled`: disable session tracking.

### CUSTOM session tracking

Given a pattern name of SSO, the following empty filter will be generated:
```xml
    <filter>
        <filter-name>SessionHandler_SSO</filter-name>
        <filter-class>__REPLACE_USING_GENERIC__</filter-class>
    </filter>
```
For the filter-class, a placeholder (__REPLACE_USING_GENERIC__) will be used and that placeholder has to be overwritten.

Another pattern must complete the session filter. For example, use `Generic Virtual Host Context` pattern with the following Filters and Mappings configuration:

```xml
<filter>
    <filter-name>SessionHandler_SSO_RealmName</filter-name>
    <filter-class>ch::nevis::nevisproxy::filter::session::SessionManagementFilter</filter-class>
    <init-param>
        <param-name>Identification</param-name>
        <param-value>CUSTOM</param-value>
    </init-param>
    <init-param>
        <param-name>Custom.RequiredIdentifiers</param-name>
        <param-value>HEADER:Authorization</param-value>
    </init-param>
    <init-param>
        <param-name>Servlet</param-name>
        <param-value>LocalSessionStoreServlet</param-value>
    </init-param>
</filter>
```

# OATHAuthentication_nevisIDM

Reference the nevisIDM Instance which has been used for first factor authentication.

# ServiceBase_host

Assign a `Virtual Host` which shall serve as entry point.

# CustomProxyLogFile_rotationCompression

Define rotated files will be compress or not

# SamlIdpConnector_selector

The expression configured here will be used by nevisAuth 
to determine the IDP for SP-initiated SAML flows. 

Configuration is required there are multiple `SAML IDP Connector` patterns
assigned to the same `SAML SP Realm`.

For IDP-initiated flows the expression is not relevant
as the IDP can usually be determined based on the `Issuer`
contained in received SAML messages.

You may enter nevisAuth or EL expressions.

You must ensure that there is always exactly 1 expression
which evaluates to `true`

If there is no match or multiple IDPs are applicable 
then `403 Forbidden` is returned.

Examples:

- IP of the user starts with `10.0.106`: `${request:clientAddress:^10.0.106}`
- Request path starts with `/myapp`: `${request:currentResource:(http.?.//[^/]+)/myapp.*}`

# SamlSpRealm_samlSigner

Use a pattern to configure the signer certificate used by this Service Provider.
If no pattern is assigned a key store will be provided automatically.

# MicrosoftLogin_clientId

ClientID is `Application (client) ID` provided by Microsoft when you create an Application Microsoft.

# Maintenance_enabled

Allows to easily enable / disable the maintenance with being forced to set a time window.

# SharedStorageSettings_storageMountPath

The path where the volume will be mounted and used by the service.

For example: `/var/opt/shared`

For more information regarding persistent volumes in Kubernetes please visit this [page](https://kubernetes.io/docs/concepts/storage/persistent-volumes/)

# FrontendKerberosLogin_onSuccess

Configure the step to execute after successful authentication.
If no step is configured here the process ends
and the user will be authenticated.

# TestingService_onGeneration

Use for testing only.

# NevisAdaptEvent_followUpStep

Select which authentication step to continue with in case at least `Minimum Match Count` out of the selection provided in `Risk Events` are present in the report coming from the nevisAdapt service.

# RESTServiceAccess_csrf

_Cross-Site Request Forgery_ (_CSRF_) is an attack that forces an authenticated user to send unwanted requests.

- `off (default)` - no CSRF protection. Recommended for APIs which may be called from other sites.
- `header-based` - `GET` and `HEAD` requests are allowed. 
For other requests `Referer` and `Origin` headers must match the `Host` header.

# SocialLoginCreateUser_unitExtId

The ExtId of the unit in nevisIDM that will be used to store the user 

# NevisIDMDeployable_smtpTruststore

Assign a Trust Store provider pattern to use for setting up trust between nevisIDM and the SMTP server.

# OAuth2AuthorizationServer_restEndpoints

Add extension services for OAuth 2.0 Authorization Server / OpenID Provider

# TCPSettings_dnsCache

Cache DNS lookup results.

- `default`: does not generate any configuration so the default nevisProxy behaviour will apply.
- `disabled`: the configured backend host names are resolved for each request. Use when IP addresses may change.
- `enabled`: host names are resolved only once. Use when the IP addresses are stable.


# SamlSpConnector_assertionLifetime

On successful authentication this IDP will issue a SAML assertion.

The SAML assertion is re-created on each session upgrade
to avoid replay attacks.

The lifetime of the assertion should be low but high enough 
so that the authentication works on slow network connections.

The SAML assertion will be consumed by the service provider.
The service provider should then use a different mechanism 
to track the user session (e.g. a session cookie).

# NevisAdaptServiceAccessBase_token

Propagate a token to the backend application. 
The token informs the application about the authenticated user.

Please assign a `NEVIS SecToken`. This is mandatory to have access to the Administration UI.

# SamlSpConnector_authRequestLifetime

SAML authentication requests have a maximum lifetime
which may be validated by this identity provider.

Enter ```unlimited``` to disable the maximum lifetime check for received SAML ```AuthnRequests```.
This sets ```in.max_age``` to ```-1``` in the generated ```IdentityProviderState```.

# CustomNevisIDMLogFile_batchSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the BATCH SYS logs.

Note: not relevant when Log Targets is set to `default`.

# GenericSMTPChannel_protocol

Select the protocol of the SMTP server.

SMTPS is usually mentioned as the TLS secured SMTP protocol.

# JSONResponse_json

Enter the JSON response.

# NevisIDMServiceAccessBase_realm

Mandatory setting to enforce authentication.

# NevisIDMCheckUserCredentials_allCredentialFound

Configure the step to execute if the user has at least one credential from all type selected in `Credential Types`.
If no step is configured here the process ends with `AUTH_DONE`.

# GenericSocialLogin_clientSecret

The secret of the client ID that has been set in the OAuth/OpenID Connect configuration of the social account.


# SecurosysKeyStoreProvider_configFiles

The two necessary configuration files for accessing the HSM.

'primus.cfg' must contain the configuration settings for connecting to the HSM,
and '.secrets.cfg' must contain the credentials to access the materials on HSM.

Keep in mind that the files are not validated, first set up a working configuration,
and use the already validated files here. 

# KeyObject_trustStore

Reference a trust store provider pattern or leave empty to let nevisAdmin establish a trust store.
This reference property is considered when type `trust store` is selected.

# HeaderCustomization_subPaths

Set to apply the header customization on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table illustrates the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |


# SamlIdpConnector_artifactResolutionService

Configure to enable HTTP Artifact Binding.

Enter the `Location` of the `ArtifactResolutionService`. 
This information can usually be found in the SAML metadata provided by the IDP.

The location must be a valid URL. In case of `https://` import the CA certificate of the endpoint 
into the backend truststore of nevisAuth.
 
When a SAML artifact is returned by the IDP
the service provider will send a request to the artifact resolution service
to retrieve the SAML assertion.


# JWTAccessRestriction_header

By default, the JWT will be extracted from the `Bearer` type `Authorization` request header:
```
Authorization: Bearer <token>
```

Optionally, this behavior can be overwritten by this property by specifying a request 
header from where the token should be extracted, for example if the token is sent like:
```
CustomAuthHeader: <token>
```
Then configure `CustomAuthHeader` for this property.

# NevisIDMChangePassword_fail

Assign an authentication step to execute when the status of the URL ticket or credential is **failed**.


# OAuth2AuthorizationServer_meta

Assign a `nevisMeta Instance` or `nevisMeta Connector`.
 
nevisMeta is used to lookup metadata for the given
OAuth2 / OpenID Connect Setup (see `Setup ID`).

# NevisFIDODeployable_relyingPartyOrigins

Enter all URLs from where FIDO 2 registration and authentication is invoked.

Example: `https://www.example.com`

nevisFIDO will use this information to check the `Origin` header of incoming REST calls.

URLs must be entered without a path.

URLs must have a common base domain which will be used as the ID for the relying party.

For Android Applications using the non-WebauthN standard compliant Origins enter the origin in the format `android:apk-key-hash:<your-apk-key-hash>`.


# CustomAuthLogFile_serverLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the default SERVER logs.

Note: not relevant when Log Targets is set to `syslog`.

# FacebookLogin_clientId

ClientID is `App ID` provided by Facebook when you register Facebook as IdP service.

# NevisIDMUserLookup_userNotFoundError

When no user is found error code `1` is set.

If you flow shows another GUI after taking the `On User Not Found` exit, 
an error text may be displayed. 

The default translation for English is: `Please check your input.`

In some flows (e.g. self-registration) this is not desired. 
Thus, you can select `disabled` here to remove the error code.


# NevisProxyDeployable_apacheSSLCache

Configures the Apache storage type of the global/inter-process SSL Session Cache.

Uses the default high-performance cyclic buffer inside a shared memory segment in RAM.

This is the recommended and default SSL Cache for nevisProxy, which is required to enable SSL session resumption.

For more information, see the official Apache documentation about the [SLLSessionCache directive](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslsessioncache).


# NevisAdaptDeployable_ipReputationHostnameVerifier

Enabling this option will set an Apache hostname verifier (which also handles certificate checks) instead of the default one.

Default: `disabled` (backwards compatibility)

# HeaderCustomization_responseHeadersRemove

Removes HTTP headers from responses.

The syntax is: `<header name>`

Examples:

```
X-Content-Type-Options
```

Headers set by Apache cannot be removed:

- `Server`

Note: change the `Filter Phase` to remove headers early / late.

# NevisIDMAccountRecovery_onSuccess

Configure the step to execute after the user was successfully authenticated.

# NevisAuthRealmBase_logrendHostCheck

Enable to verify that the hostname on the certificate presented by nevisLogRend matches the configured hostname in the `nevisLogrend Instance` or `nevisLogrend Connector` pattern.

This setting only applies if nevisLogrend is used in the `Login Renderer` setting and the connection to nevisLogrend uses HTTPs.


# AutomaticKeyStoreProvider_owner

Select an instance pattern which defines the target hosts of this `Automatic Key Store`.
This setting is required only when this pattern is assigned to an `Automatic Trust Store`.

# NevisConnectorPattern_kubernetesNamespace

Enter the Kubernetes namespace.

Configuration is required when `Kubernetes` is set to `other_namespace`.


# NevisAuthDeployable_languages

Configure the language codes that shall be supported.

Each language code must be entered on a new line.
By default, translations are provided for the following codes:

- `en`: English
- `de`: German
- `fr`: French
- `it`: Italian

nevisAuth uses the `Accept-Language` header sent by the browser to determine the user language.
In case this header is not available the first configured language code will be used as a default.

# NevisLogrendDeployable_logging

Add logging configuration for nevisLogrend.

# NevisFIDODeployable_nevisidm

For user and credential management, nevisFIDO needs nevisIDM.

Assign a `nevisIDM Instance` or `nevisIDM Connector` here.

This connection uses _Client TLS_ and the trust is **not** built up automatically.


# NevisLogrendLogSettings_maxFileSize

Maximum allowed file size (in bytes) before rolling over.

Suffixes "KB", "MB" and "GB" are allowed. 10KB = 10240 bytes, etc.

Note: not relevant when rotation type is `time`.

# NevisIDMJmsQueues_dlq

NevisIDM JMS Queue to which Dead Letter messages should be sent.

Only accepts URIs starting with `amqp`, `amqps` or `Endpoint=sb`.
Validates only URIs with `amqp` or `amqps` schemes.

Dead letter messages are those messages which are not in the expiryQueue and their delivery was unsuccessful.
For further reference check `NevisIdm Technical documentation > Configuration > Components > Provisioning module > Provisioning providers`.

# NevisAdaptDeployableBase_secTokenTrustStore

Assign the Trust Store provider for verifying the NEVIS SecToken. If no pattern is assigned the signer key will be provided by the nevisAdmin 4 PKI.

# GenericDeployment_group

Owner of the directory at path. All files and subdirectories will have the same owner.

# NevisIDMPasswordLogin_customEmailSentRedirect

Enter a URL, path, or nevisAuth expression which defines where to redirect to
after the ticket has been created (and sent to the user via email). 

# NevisIDMCheckUserLoginInfo_userPreviouslyLoggedIn

Configure the step to execute if the user has previously logged in.
If no step is configured here the process ends with `AUTH_DONE`.

# CookieCustomization_clientCookies

Cookies listed here will be allowed to pass through.

Use for cookies which should be returned to the caller (e.g. browser).

Regular expressions are supported.

**Example**:

- `LANG.*`


# NevisIDMProperty_uniquenessScope

If set then values stored in the property must be unique within the configured scope.

- `ABSOLUTE`: The property's values have to be unique overall. Two property values with the same content must not exist.

# NevisFIDODeployable_deepLinkAppFiles

Upload resources required for deep links.

### Installation Page

You can upload the HTML page that your `Deep Link` points to.

This page is shown only when the mobile app is not installed and should provide installation instructions.

You can also upload static resources (e.g. CSS and images) used by this page.

Uploaded files will be hosted at the root location (`/`) of the `Deep Link Host`.

If you want to host them on a sub-path, use the `Hosting Service` pattern instead.

### App Link Files

App link files are JSON files which provide information about the mobile app.
Apple and Google use different terms, and expect different filenames and contents.

Visit our [official documentation](https://docs.nevis.net/nevisaccessapp/appendixes/app-link-best-practices) for more information.

#### iOS

The file must be named `apple-app-site-assocation` **without** any extension and will be hosted at `/.well-known/apple-app-site-association`.

The file must be created manually and match the following structure:

```json
{
  "applinks": {
    "details": [
      {
        "appIDs": [
          "<team id>.<bundle id>"
        ],
        "components": [
          {
            "/": "open",
            "?": {
              "dispatchTokenResponse": "*"
            },
            "caseSensitive": false
          }
        ]
      }
    ]
  }
}
```

_appID_: refers to the app. It consists of two components as follows: `<TeamID>.<bundleID>`,
for details or about how to obtain it, see Apple documentation about [app links](https://developer.apple.com/documentation/bundleresources/applinks).

_deep-link-base-path_: The path configured here is the one supported in the deep links. 
Make sure the path used in the `Deep Link` corresponds to this value.

When the mobile app is installed or updated, iOS fetches this file from the server and stores it for later, 
to verify the paths in deep links the user clicks on.

For more information, visit [app links](https://developer.apple.com/documentation/bundleresources/applinks).

### Android

The file must be named `assetlinks.json` **with** the extension and will be hosted at `/.well-known/assetlinks.json`.

The file can be generated with the [Statement List Generator](https://developers.google.com/digital-asset-links/tools/generator)
using the following information:

* _Hosting site domain_: enter the domain used in the `Deep Link`. It should point to the assigned `Deep Link Host`.
* _App package name_: enter the package name of your app. If you are using a NEVIS branded Access App, that would be `ch.nevis.security.accessapp`.
* _App package fingerprint (SHA256)_: enter the fingerprint of the certificate your app has been signed with.

For more information, visit [Android App Links](https://developer.android.com/training/app-links).

Note that certain Chinese browsers do not support _Android App Links_: 360, QQ, UC.

The file must be created manually and match the following structure:

```json
[
  {
    "relation": [
      "delegate_permission/common.handle_all_urls"
    ],
    "target": {
      "namespace": "android_app",
      "package_name": "<bundle id>",
      "sha256_cert_fingerprints": [
        "<certificate fingerprint>"
      ]
    }
  }
]
```


# GenericAuthService_authStatesFile

Enter `AuthState` elements as XML.

The `Domain` element is optional.

- If missing the element will be created. The `Entry` methods 
`authenticate` and `stepup` will be set to the first provided `AuthState`. 
The method `logout` is not set and thus the nevisAuth default behaviour applies.

- If provided the `Domain` must come before all `AuthState` elements. 
The attributes `name` and `default` are not supported and should be omitted.
Attributes are sorted by name. The `Entry` elements are sorted by `method`.

The `AuthState` linked to `stepup` should be able to dispatch the request.
For instance, you may have assigned an `Authorization Policy` to your application(s)
and thus you need a state which decides based on the request variable `requiredRoles`.

The following example dispatches level `2` into an `AuthState` named `TAN`
which provides authentication via mTAN:

```
<AuthState name="EntryDispatcher" class="ch.nevis.esauth.auth.states.standard.ConditionalDispatcherState" final="false">
    <ResultCond name="nomatch" next="Authentication_Done"/>
    <ResultCond name="level2" next="TAN"/> <!-- TAN state is expected to set authLevel="2" -->
    <Response value="AUTH_ERROR">
        <Arg name="ch.nevis.isiweb4.response.status" value="403"/>
    </Response>
    <property name="condition:level2" value="${request:requiredRoles:^2.*$:true}"/>
</AuthState>
```

The following expressions are supported:

- `${instance}`: name of the nevisAuth instance
- `${request_url}`: generates a nevisAuth expression which returns the URL of the current request
- `${realm}`: name of the Realm (see below)
- `${service_url}`: generates a nevisAuth expression which evaluates to true for requests received on the configured `Frontend Path`
- `${service.postfix}`: in Kubernetes side-by-side deployment a postfix is added to service names. Use this expression when connecting to a service deployed against the same inventory.
- `${keystore}`: name of the `KeyStore` element provided by this pattern. Assign a pattern to `Key Objects` to add a `KeyObject` into this `KeyStore`. 

The `name` of `AuthState` elements is prefixed 
with the sanitized name of the Realm (referred to as `${realm}`).

The realm prefix must be added when using `propertyRef` to reference AuthStates
generated by other patterns (e.g. `<propertyRef name="${realm}_SomeState"/>`).

An exception is the AuthState which defines the nevisIDM connection 
(as generated by `nevisIdm Password Login` or `nevisIDM Connector for Generic Authentication`).
Here the `propertyRef` must be defined as follows: 

`<propertyRef name="nevisIDM_Connector"/>`

This pattern does not validate that labels are translated.
Translations can be provided on the `Authentication Realm` pattern.

# FacebookLogin_claimsRequest

The claims request parameter. This value is expected to be formatted in JSON and does not accept trailing spaces nor tabs.

# NevisIDMDeployable_encryptionCipher

Encryption cipher.

# NevisAdaptFeedbackConfig_feedbackKey

Enter a 256-bit encryption key represented in Base64.

To generate a new random key, you may run the following console command:

```bash
openssl rand -base64 32
```

Regular expression for valid values: `[a-zA-Z0-9+/]{43}=`

Example: `fq7J7E1xVFNHcEJ2MSQojLibKOQOMIlp2qXVqvv5y9w=`


# NevisAdaptLogSettings_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.
When `Rotation Type` is `time`, this property is used as Logback's [maxHistory](https://logback.qos.ch/manual/appenders.html#tbrpMaxHistory) property.
This means that logs will be archived for this number of time units where time unit is as defined in `Rotation Interval`.

# NevisIDMClient_remarks

Any other additional information about the client.


# EmailInputField_variable

Enter `<scope>:<name>` of the variable which shall be set.

The following scopes are supported:

- `inargs`
- `notes`
- `sess` or `session`

For instance, enter `notes:loginid` to prefill the login form
which is produced by the `nevisIDM Password Login` pattern.

# NevisAdaptDeployable_logging

Assign `nevisAdapt Log Settings` to change the log configuration.


# NevisIDMPasswordLogin_useDefaultProfile

Should in the Authentication flow assume default profile is selected if the user has multiple profiles, or should it display a selection dialog for the user.

# 4.17.0

Full changelog: 

[Patterns 4.17.0 Release Notes - 2022-11-16](https://docs.nevis.net/nevisadmin4/release-notes#patterns-4170-release-notes---2022-11-16)

##### Improved key-value settings

Improved handling and display of key-value settings.
Keys and values are now displayed in separate boxes.

So far, a multi-line text box was used with the following separators: `->`, `:`, `=`.

The new widget uses a structured format to store its configuration.
The widget is able to import legacy configuration, but requires you to confirm the migration.

Check your project for issues and follow the instructions given in the patterns.

Some separators (usually `->`) were used the "wrong way round" in previous releases.
Therefore, you may have to switch the content of the left and right boxes after you have clicked the "Migrate" button.
Check the help of the setting for what is expected there.

##### Refactored Social Login patterns

Social login patterns had to be refactored to address a security vulnerability.

It was possible to take over another nevisIDM user by changing the email at the social login provider.

To address this issue, the social login patterns don't automatically link the user anymore.

Some exits in the patterns have to be re-configured.

The exit `On User Found` will be taken when a user was found in nevisIDM but the user is not linked yet.
We recommend to assign a step to validate that possession of the nevisIDM user, e.g. by asking for the password, 
and then end the flow with the `Social Login Link User` pattern.

The exit `On User Not Found` will be taken when the email provided by the social login provider
was not found in nevisIDM. In this case you should validate that the user has access to the email,
e.g. by sending a TAN code, and then complete the flow with the `Social Login Create User` pattern.


# NevisIDMCheckUserCredentials_noCredentialFound

Configure the step to execute if the user has no credential from credential types defined in `Credential Types`.
If no step is configured here the process ends with `AUTH_DONE`.

# OAuth2AuthorizationServer_idTokenJWKSetProxy

Forward proxy for the connection to the JWK Set endpoint for ID token encryption.
Enter the hostname:port here

Example: `proxy.your-internal-domain:3128`


# InBandMobileDeviceRegistration_authenticationServicePath

Configure the path of the authentication service.


# AuthCloudBase_userNamePrefix

Optional prefix which will be added to the Authentication Cloud username.

**WARNING: Changing this option means that all existing users will have to register their Access Apps again.**

The Authentication Cloud _username_ consists of the _user ID_ and the optional `Username Prefix`.

The _user ID_ is looked up from the following sources:

- session variable `ch.adnovum.nevisidm.user.extId`
- request field `userId`

# NevisIDMDeployable_mailSMTPPort

Port of the SMTP server.

# GroovyScriptStep_scriptTraceGroup

Use a different category for logging in your Groovy script.


# PemKeyStoreProvider_dirName

Enter a name for the key store directory
which is used instead of the pattern name.

This configuration may be used to prevent key stores overwriting each other 
and is only required in complex setups with multiple projects or inventories.

# NevisLogrendDeployable_addons

Assign an add-on pattern to customize the configuration of nevisLogrend.

# SamlResponseConsumer_path

Enter a path where SAML `Response` messages sent by an external IDP shall be consumed.

The external IDP may send messages using POST or redirect binding.


# NevisIDMAccountRecovery_onFailure

Configure the step to execute after the authentication failed.

If no step is configured here the process ends.

# FIDO2Authentication_onSuccess

Assign an authentication step to continue with after successful authentication.


# FacebookLogin_scope

Select the request scopes for getting user information from Facebook. 

The default is `email` and thus minimal information will be returned.

Select `public_profile` to return additional user information.

Scope `offline_access` is not supported as Facebook has [removed this scope](https://developers.facebook.com/docs/roadmap/completed-changes/offline-access-removal/).


# BackendServiceAccessBase_sendCertificateChain

Choose which certificates are sent to the backend during mutual authentication:

- `disabled`: Send the client certificate from the **Key Store**;
- `enabled`: Send the certificate chain from a **PEM Key Store** or a **nevisKeybox Store**.
The certificate chain file must contain the client certificate and the intermediate CA certificates.

# FacebookLogin_buttonLabel

Enter the text that should be displayed for the end-user on the social login button, and provide translations for this label on the Authentication Realms.

# SamlIdpConnector_issuer

Enter the `Issuer` of the IDP.

Example: `https://idp.example.org/SAML2`

The `Issuer` is used to look up the trust store 
containing the signer certificate of the IDP.

For this purpose a `KeyObject` element will be configured
in the nevisAuth `esauth4.xml` using the `Issuer` 
for the attribute `id`.

# AzureServiceBusRemoteQueue_policy

Enter the `Policy` that shall be used to connect.

Also known as: `SAS Policy`, `Shared access policy`

# GenericSocialLogin_subjectClaim

The claim that contains the subject of the logged-in user in the social account.
The default value is `sub`.

# NevisDetectAuthenticationConnectorStep_jmsClientTrustStore

Reference a trust store provider pattern or leave empty to manage the trust store with nevisAdmin.

# PropertiesTestPattern_attachmentProperty

Upload 1 or multiple files.
No support for subdirectories but some patterns unpack uploaded zip files.
Should have support for in-place file edit for known file extensions.

# ErrorHandler_redirectStatusCodes

Redirect to a given location **instead** of rewriting the response body. 

Locations can be entered as:

- URLs (starting with `http://` or `https://`)
- paths (starting with `/`)

Internal and external locations are supported.

Examples:
```
404,500-599 -> /some/super/redirect/
403 -> https://www.google.com
```


# ObservabilityBase_configuration

Configuration file of the selected agent.

Use `${...}` expressions to refer parameter values.
Default parameters:
* `${name}`: component name
* `${instance}`: instance name
* `${version}`: version
* `${service.name}`: service name (kubernetes deployment)

Sample configuration for OpenTelemetry:
```properties
otel.service.name = ${service.name}
otel.resource.attributes = service.version=${version}
otel.exporter.otlp.protocol = http/protobuf
otel.exporter.otlp.traces.protocol = http/protobuf
otel.exporter.otlp.traces.endpoint = ${tracesEndpoint}
otel.exporter.otlp.metrics.protocol = http/protobuf
otel.exporter.otlp.metrics.endpoint = ${metricsEndpoint}
otel.exporter.otlp.metrics.temporality.preference = cumulative
otel.exporter.otlp.logs.protocol = http/protobuf
otel.exporter.otlp.logs.endpoint = ${logsEndpoint}
```

Sample configuration for Application Insights:
```json
{
  "connectionString": "${connectionString}",
  "role": {
    "name": "${service.name}"
  },
  "customDimensions": {
    "service.version": "${version}"
  },
  "sampling": {
    "percentage": 100
  },
  "instrumentation": {
    "logging": {
      "level": "OFF"
    }
  }
}
```

# KerberosLogin_proxyHostNames

Enter the `Frontend Addresses` of the nevisProxy `Virtual Host` patterns 
for which this pattern provides authentication.

Example:

- `www.siven.ch`

In case multiple values are configured you can define which `Keytab File` or `Keytab File Path` 
to use by referencing its file name.

Example:

- `www.siven.ch -> kerberos_ch.keytab`
- `www.siven.de -> kerberos_de.keytab`


# AuthServiceBase_addons

Assign add-on patterns to customize the behaviour of this authentication service.

Example use cases:

- `URL Handling` with phase `AFTER_AUTHENTICATION` to redirect after the authentication flow completes.
- `Access Restriction` to restrict access based on source IPs.
- `HTTP Header Customization` to add, replace, or remove HTTP headers in requests or responses.

# FrontendKerberosLogin_kerberosRealms

Enter the allowed `Kerberos realms` (`AD domains`).

Example:

- `SIVEN.CH`

In case multiple values have to be configured you can define which `Keytab File` or `Keytab File Path`  
to use by referencing its file name.

Example:

- `SIVEN.CH -> kerberos_ch.keytab`
- `SIVEN.DE -> kerberos_de.keytab`

# GenericNevisMetaSettings_javaOpts

Add additional entries to the JAVA_OPTS environment variable.

Use the expression `${instance}` for the instance name.

For instance, you may configure nevisMeta to create a heap dump on out of memory as follows:

```
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/opt/nevismeta/${instance}/log/
```

Be aware that this example will not work for Kubernetes
as the pod will be automatically restarted on out of memory
and the created heap dump files will be lost.


# OAuth2UserInfo_idm

Assign a `nevisIDM Instance` or `nevisIDM Connector` to get user information.

# GenericNevisAdaptSettings_javaOpts

Add additional entries to the JAVA_OPTS environment variable.

For instance, you may configure nevisAdapt to create a heap dump on out of memory as follows:

```
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/opt/nevisadapt/log/
```

Be aware that this example will not work for Kubernetes
as the pod will be automatically restarted on out of memory
and the created heap dump files will be lost.


# CustomNevisMetaLogFile_maxFileSize

Maximum allowed file size (in bytes) before rolling over. 

Suffixes "KB", "MB" and "GB" are allowed. 10KB = 10240 bytes, etc.

Note: not relevant when rotation type is `time`.

# OutOfBandMobileDeviceRegistration_host

Assign the `Virtual Host` which serves the domain where the nevisFIDO services shall be exposed
so that this pattern can generate the required configuration.

The domain is coded into the mobile app and has to be communicated
when ordering the app.

The `Virtual Host` assigned here will also be considered when calculating
the `Frontend Address` in the `nevisFIDO UAF Instance`.


# NevisIDMDeployable_jobStore

Select `db` to track job execution in the database.
This ensures that a given batch job can only run once at the same time. 
Use this configuration when you have multiple lines / replicas.

Select `ram` to store track job execution in memory. 
You may use this value when you have only 1 line / replica.

# NevisAuthDeployable_sessionIndexing

Enables session indexing.

**WARNING**: Other patterns, such as `nevisAdapt Instance` may overrule this configuration.

This is required by [ThrottleSessionsState](https://docs.nevis.net/nevisauth/setup-and-configuration/authentication-plugins-and-authstates/standard-authentication-authstates-and-plugins/throttlesessionsstate).

Set `Session Index Attribute` if you need to index a non-default attribute.


# AuthCloudBase_hashUserName

Enable to use a hash (MD5) for the Authentication Cloud username.

**WARNING: Changing this option means that all existing users will have to register their Access Apps again.**

There are 2 motivations for enabling this feature:

- the Authentication Cloud username is limited to 50 characters. Hashing makes it shorter.
- you avoid storing sensitive user information in the Authentication Cloud instance.

# DatabaseBase_password

Password for the database connection user.

This setting is used in the following cases:

- Classic deployments (VM)
- In Kubernetes when 'Database Management' (Advanced Settings) is set to 'disabled'.


# LdapLogin_baseDN

Specifies the directory subtree where all users are located.

Example:
* ou=people,o=company,c=ch

# NevisAdaptDeployable_ipToLocationCron

Pick the update frequency of the IP-to-location database.

Valid values:

* `disabled` - no update mechanism will be triggered. Not recommended for productive environment.
* `hourly`
* `daily`
* `weekly`
* `monthly`

When selecting `disabled`, it's highly recommended having a mechanism in place for keeping the database file up-to-date.
We recommend [setting up periodic update of IP geolocation and reputation mappings](https://docs.nevis.net/nevisadapt/Installation-of-nevisAdapt/Setting-up-periodic-update-of-IP-geolocation-and-reputation-mappings).


# NevisIDMURLTicketConsume_onExpired

Assign an authentication step to execute when the URL ticket is **expired**.

If not set a screen with `title.url_ticket` and `error.url_ticket.expired` will be shown in that case.

# LuaPattern_subPaths

Set to apply this pattern on some sub-paths only.

Sub-paths must be relative (e.g. not starting with `/`)
and will be appended to the frontend path(s) of the virtual host (`/`) 
or applications this pattern is assigned to.

Sub-paths ending with `/` are treated as a prefix,
otherwise an exact filter-mapping will be created.

The following table provides examples to illustrate the behaviour:

| Frontend Path | Sub-Path | Effective Filter Mapping |
|---|---|---|
| `/` | `secure/` | `/secure/*` |
| `/` | `accounts` | `/accounts` |
| `/` | `api/secure/` | `/api/secure/*` |
| `/` | `api/accounts` | `/api/accounts` |
| `/app/` | `secure/` | `/app/secure/*` |
| `/app/` | `accounts` | `/app/accounts` |
| `/app/` | `api/secure/` | `/app/api/secure/*` |
| `/app/` | `api/accounts` | `/app/api/accounts` |

# NevisFIDODeployable_facets

[Facets](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/concept-description/fido-uaf-universal-authentication-framework#application-and-facets) are required configuration for mobile authentication scenarios.
The [FIDO AppID and Facet Specification](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-appid-and-facets-v1.1-id-20170202.html) defines facets as _identities of a single logical application across various platforms_.


The following [wildcard facet IDs](https://docs.nevis.net/mobilesdk/guide/configuration#wildcard-facet-ids) are included for ease of use, to speed up integration of the Nevis Access App or Nevis Mobile Authentication SDK:

``` 
android:apk-key-hash:*,
ios:bundle-id:*
```

The wildcard facet ID entries are compatible with _integration_ flavor Access Apps or _debug_ flavor mobile SDKs. 
_Production_ Access Apps or _release_ mobile SDKs do not accept wildcard facet ID entries.
If you want to use one of the Nevis Mobile Authentication SDK example applications with the _release_ SDK, you will need to add one or multiple of the following facetID entries: 

- `android:apk-key-hash:ch.nevis.mobile.authentication.sdk.android.example`
- `android:apk-key-hash:ch.nevis.mobile.authentication.sdk.flutter.example`
- `android:apk-key-hash:ch.nevis.mobile.authentication.sdk.react.example`
- `ios:bundle-id:ch.nevis.mobile.authentication.sdk.ios.example`
- `ios:bundle-id:ch.nevis.mobile.authentication.sdk.flutter.example`
- `ios:bundle-id:ch.nevis.mobile.authentication.sdk.objc.proxy.example`
- `ios:bundle-id:ch.nevis.mobile.authentication.sdk.react.example`

For **production deployment** you have to replace the default and add your own facets for your iOS or Android applications. The following documentation provides additional information:

* For **Access Apps**, refer to the [FacetID Calculation documentation](https://docs.nevis.net/nevisaccessapp/appendixes/facetid-calculation).
* For the **mobile SDK**, refer to the [FacetID chapter in the configuration section](https://docs.nevis.net/mobilesdk/guide/configuration#facet-id).

# OAuth2AuthorizationServer_idTokenClaims

Define claims for the OpenID Connect ID token.

For the value you can use a constant, a nevisAuth expression, an EL expression,
or refer to an inventory variable by using the `${var.<name>}` syntax.

Note that you also have to do this for standard OpenID Connect claims.
The only exception are `sub`, `iss` which will always be added.

Here are some examples:

| Claim         | Value                                 |
|---------------|---------------------------------------|
| `given_name`  | `${sess:ch.nevis.idm.User.firstName}` |
| `family_name` | `${sess:ch.nevis.idm.User.name}`      |
| `email`       | `${sess:ch.nevis.idm.User.email}`     |
| `mobile`      | `${sess:ch.nevis.idm.User.mobile}`    |
| `customer`    | `${var.customer-number}`              |

Which claims will be added to the ID token depends on the incoming request.
Non-standard claims have to be requested using the claims request parameter.
Standard claims are added when a certain OpenID Connect `scope` is requested:

| Requested Scope | Added Claims                                                                                                                                                                     |
|-----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `profile`       | `name`, `family_name`, `given_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email`         | `email`, `email_verified`                                                                                                                                                        |
| `address`       | `address`                                                                                                                                                                        |
| `phone`         | `phone_number`, `phone_number_verified`                                                                                                                                          |


# OAuth2AuthorizationServer_idm

Assign a `nevisIDM Instance` or `nevisIDM Connector`.
Required if nevisMeta is not used to store user consent.

# GenericNevisProxySettings_bcProperties

Customize the low-level configuration (`bc.properties`)
using properties described in the [nevisProxy Technical Documentation](https://docs.nevis.net/nevisproxy).

For instance, when request validation is enabled this requires a buffer
and this buffer has to be big enough to store the entire request.

The following example increases the maximum size of the request buffer to 10 MB:

```
ch.nevis.navajo.request.BufferSize=10485760
```

You also may have to increase the maximum allowed request size. 
See `Configuration: navajo.xml` for an example.

Note that increased buffer sizes may lead to increased demand of RAM and disk space. 

When the required buffer exceeds `ch.nevis.navajo.request.MemBufferSize` 
then nevisProxy will buffer to disk instead.

The demand caused by request buffers can be estimated as follows:

- RAM: `MaxClients` * `ch.nevis.navajo.request.MemBufferSize` 
- disk: `MaxClients` * `ch.nevis.navajo.request.BufferSize` 

See `Configuration: navajo.xml` for a description of `MaxClients`.


# NevisFIDODeployable_allowedAuthenticators

Here you can configure which authenticators are allowed.

This configuration is used and required **only** when `Allowed Authenticators` is `enabled`.

Proceed as follows:

1. Download the official FIDO Alliance Metadata file (JWT) from the [FIDO Alliance Metadata Service](https://fidoalliance.org/metadata/).
2. Decode the downloaded JWT.
3. Copy out the complete metadata statements of the desired authenticators into a new JSON file.
4. (optional) Remove the optional entries to “slim down” the metadata entry, only required entries are `aaguid` and `attestationRootCertificates`.
5. Safe the JSON file and upload it here.

You can find more information in our [FIDO2 Concept and Integration Guide](https://docs.nevis.net/configurationguide/fido2-concept-and-integration-guide/use-cases/allow-list).

# NevisLogrendDeployable_https

Choose between plain HTTP, normal HTTPs and mutual (2-way) HTTPs.
If `enabled` a `Key Store` is required.
If set to `mutual`, a `Trust Store` is required as well.

# OAuth2Client_refreshTokenLifetime

Enter a custom lifetime for the refresh token.

If not set the value of the `OAuth 2.0 Authorization Server / OpenID Provider` is used.

# HostContext_defaultEntry

Set to redirect requests for the root path (/) to an absolute path or a full URL.


# FIDO2StepBase_username

The `username` is used by nevisFIDO to look up the user in nevisIDM.

Depending on how the `nevisFIDO FIDO2 Instance` is configured, either the `extId` or the `loginId` have to be used.


# NevisMetaServiceAccessBase_backendHostnameCheck

Enable to verify that the hostname on the certificate presented by the backend matches the hostname of `nevisMeta`

# NevisDetectPersistencyDeployable_database

Add a database connection reference pattern.

Required properties to be set in the connector pattern are as follows:
- JDBC Driver (Oracle or MariaDB)
- JDBC URL
- DB user/password


# BackendServiceAccessBase_hostnameCheck

Enable to verify that the hostname on the certificate presented by the backend matches the hostname configured in `Backend Addresses`

# NevisAuthDatabase_schemaPassword

The password of the user on behalf of the schema will be created in the database.

# NevisDetectAuthenticationConnectorStep_core

Pattern reference for the nevisDetect Core Instance to connect to.

# CustomProxyLogFile_maxFileSize

Maximum allowed file size (in bytes) before rolling over. 

Suffixes "KB", "MB" and "GB" are allowed. 10KB = 10240 bytes, etc.

If not set the following defaults will be used:

- `apache.log`: 1MB
- other logs: 10MB

# SocialLoginBase_arbitraryAuthRequestParam

Arbitrary additional request parameters used in the authentication request.
The property supports variable substitution.

Example:
```properties
[paramName]=[paramValue]
```

# InBandMobileDeviceRegistration_realm

Assign an `In-band Mobile Authentication Realm` or `Authentication Realm` here.

Assignment is required.

The assigned realm will be used to protect the path `/nevisfido/uaf/1.1/request/registration/`.

If `Authentication Service` is `enabled`, a simple authentication flow will be added to this realm.


# GroovyScriptStep_classPath

Set the `classPath` attribute of the `AuthState` element.

Lines will be joined with `:`. Enter 1 path per line.

When set, the `classLoadStrategy` attribute will be set to `PARENT_LAST`.


# NevisIDMDeployable_smtp

Host:port of the SMTP server used for sending emails.

Configure if you prefer to provide the SMTP server with a single configuration,
instead of configuring both `SMTP Host` and `SMTP Port`.


# NevisFIDODeployable_relyingPartyName

Enter a name for the relying party.

This name is displayed by the user agent when performing a FIDO 2 registration or authentication.


# GenericThirdPartyRealm_authenticationFilter

Define the filter that shall be application to applications
to enforce authentication.

The following variables may be used:

- `${realm.id}` - unique ID of this realm pattern
- `${realm.name}` - name of this realm pattern
- `${auth.servlet}` - name of the servlet of the `Authentication Application`. May be used to perform a side-call.

# NevisDetectPersistencyWebApplicationAccess_backendHostnameCheck

Enable to verify that the hostname on the certificate presented by the backend matches the hostname of `nevisDetect Persistency`

# ServiceAccessBase_responseRewrite

Use this feature to replace backend hostnames in responses
or set to `custom` to configure complex rewriting use cases.

- `off` disables automatic response rewriting
- `header` enables auto rewrite for response headers (including Set-Cookie header)
- `complete` enables auto rewrite for the entire response (including body)
- `custom` configure `Response Rewriting Settings` via `Additional Settings`

# NevisAdaptDeployable_ipToLocationToken

Provide a secret download token for authentication.


# DeployableBase_initialMemory

Use the given percentage of `Memory Limit` for the initial memory usage (`-Xms`).

This setting applies to classic VM deployments only.

# PemKeyStoreProvider_keyPass

Enter the passphrase of the private key.

The passphrase will be used 
to decrypt the uploaded private key, if it is encrypted.

As the passphrase is considered sensitive information it should not be published with the project.
It is therefore required to use a variable and define the value in the inventory (as a secret).

The default value of the variable is not relevant 
as the key is not loaded during background validation.

# AuthCloudLookup_onUserNotExists

Assign an authentication step to continue with when the user does not exist or has no active authenticator.


# AzureServiceBusRemoteQueue_key

Enter the `Primary Key` of the `Policy` as shown in the Azure portal.

# PropertiesTestPattern_numberProperty

Enter a number.

# GenericSocialLogin_secondNameClaim

The claim that contains the second name of the logged-in user in the social account.
The default value is `family_name`.

# HostContext_proxy

Assign the `nevisProxy Instance` this virtual host should be assigned to.


# GoogleLogin_redirectURI

The callback URI to go to after a successful login with Google.

This will create an endpoint in your host config.

The URL will be a combination of the `Frontend Address` of the `Virtual Host` and the value configured here.
For example, let's assume that you have configured:

- Return Path: `/oidc/google/`
- Frontend Address: `https://nevis.net`

Then the URL will be `https://nevis.net/oidc/google/`.

Use the `exact:` prefix to use the given path as-is.
Without this prefix a normal mapping with `/*` will be generated and thus sub-paths will be accessible as well.


# GenericSocialLogin_tokenEndpoint

The token endpoint of the OAuth2 server.
It's required when `providerType` has the value `OAuth2`.


# NevisAuthDeployable_frontendKeyStore

Assign the Key Store provider for the HTTPs endpoint.
If no pattern is assigned a Key Store will be provided by the nevisAdmin 4 PKI.

# FrontendKerberosLogin_level

Authentication level that is set on success.

# TestingService_onDeployment

Use for testing only.

# OAuth2RestEndpointBase_secure

Set Basic authentication for REST Service of OAuth 2.0 Authorization Server / OpenID Provider.

When this property is `enabled`, the request must include Authentication Header.
The header is a combination of clientID and clientSecret with base64 encoded

# NevisDetectDatabase_parameters

Enter parameters for the DB connection string.

Enter 1 parameter per line.

Lines will be joined with `&`.

The default is:

```
useMysqlMetadata=true
```

The default value will be used **only** when no parameters are entered.

If you want to keep the default parameters, add them as well.


# NevisDetectServiceAccessBase_csrf

_Cross-Site Request Forgery_ (_CSRF_) is an attack to force an authenticated user to send unwanted requests.

- `off (default)` - no CSRF protection. Recommended for applications which may be called from other sites.
- `header-based` - `GET` and `HEAD` requests are allowed (assumption: these methods must not manipulate server-side state). 
For other requests the `Referer` and `Origin` headers must match the `Host` header.

# SamlSpRealm_template

By default, the Service Provider does not need any rendering template.

However, a GUI will be shown when `Logout Reminder` is `enabled`
and may be shown when `Custom Pre-Processing` is used.

### nevisLogrend: Simple Mode

Point your browser to a protected application to have a look at the login page.
Download any resources (e.g. images, CSS) that you want to adapt. 
Then upload the changed files here.

To change the outer HTML upload a file named `template.html`. Here is a simple example:

```html
<!DOCTYPE html>
<html lang="${lang.code}">
  <head>
    <title>${label.title}</title>
    <link href="${resources}/bootstrap.min.css" rel="stylesheet" type="text/css">
    <link href="${resources}/default.css" rel="stylesheet" type="text/css" media="all">
  </head>
  <body>
    <header id="header" class="container-fluid">
      <img class="logo center-block" src="${resources}/example.svg" alt="NEVIS Security Suite">
    </header>
    <main id="content" class="container">
      ${form}
    </main>
  </body>
</html>
```

Please also upload file resources referenced by your template (e.g. images, CSS, Javascript). 
Use this when you reference additional files, or if you want to override the default files provided. 

The template must contain `${form}` and may contain additional expressions.

| Expression | Description | 
|---|---|
| `${form}` | generated login form (required) |
| `${lang.switch}` | language switcher component |
| `${lang.code}` | current language code (i.e. EN, DE) |
| `${label.title}` | a human-readable title |
| `${label.myLabel}` | a custom text which must be defined via `Custom Translations` |
| `${resources}` | path to static resources (e.g. CSS, images, Javascript) |

Some resources (i.e. bootstrap.min.css, default.css) are provided out of the box
because they are required by the default template. Feel free to use them.

### nevisLogrend: Expert Mode

Expert users may upload Velocity templates and resources to nevisLogrend.

Zip files will be extracted into the nevisLogrend *application*:

`/var/opt/nevislogrend/<instance>/data/applications/<realm>`

Flat files will be added to the following subdirectories:

-  `webdata/template`: Velocity templates (`*.vm`)
-  `webdata/resources`: additional resources (e.g. images, CSS)

### nevisProxy: Simple Template

nevisProxy provides a simple login page renderer which can be used instead of nevisLogrend.
See `Login Renderer` for details.

For each enabled language (e.g. `en`) upload a file named `<lang>_template.html`.
The template must contain the placeholder `NEVIS_AUTH_FORM`. 

If your templates require additional resources (e.g. CSS, images)
upload them as `Hosted Resources` on the nevisProxy virtual host.


# MobileDeviceDeregistration_token

Assign a `NEVIS SecToken` pattern.

This pattern must also be assigned to `Application Access Tokens` in the `Authentication Realm`.


# NevisMetaDeployable_frontendKeyStore

Assign the Key Store for the HTTPs endpoint.

If no pattern is assigned a Key Store will be provided by nevisAdmin 4 automatic key management.

# HostContext_sessionStore

Assign a `nevisProxy Remote / Hybrid Session Store` pattern here if you want to store sessions
in a remote session store.

A remote session store must be used when the nevisProxy instance is deployed with redundancy
and there is no sticky load balancer in front.

# ProxyPluginPattern_serviceMapping

Mapping entries between RESTful addressees and services. One line per mapping, for example:
```yaml
requestData=/processRequestData
terminateSession=/processSessionTermination
getVersion=/getVersion
```


# GenericNevisAuthSettings_envVariables

Add additional environment variables to the nevisAuth `env.conf`.

The standard environment variables `RTENV_SECURITY_CHECK` and `JAVA_OPTS`
will always be present in `env.conf` and can't be overwritten using this setting.


# NevisFIDODeployable_metadata

The [FIDO UAF specification](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-uaf-protocol-v1.1-id-20170202.html#authenticator-metadata) describes metadata as follows:

```
It is assumed that FIDO Server has access to a list of all supported authenticators and their corresponding Metadata. Authenticator metadata contains information such as:

* Supported Registration and Authentication Schemes
* Authentication Factor, Installation type, supported content-types and other supplementary information, etc.

To make a decision about which authenticators are appropriate for a specific transaction, FIDO Server looks up the list of authenticator metadata by AAID and retrieves the required information from it.
```

The nevisFIDO server ignores any authenticators and halts all operations in relation to them, which do not have metadata data entries
accessible for the server.

Note that the default value of this field represents the metadata required for nevisFIDO to be
able to work with the ```NEVIS Access App```. If you're using a custom app based on the NEVIS Mobile Authentication SDK
or a customized Whitelabel Access App, these values will need to be updated.

The _Android_ metadata statements contain the [Google root certificates](https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate) to support _Android Key Attestation_ / _FIDO UAF Basic Full Attestation_. These entries must be kept up-to-date.  

# NevisAdaptDatabase_user

Provide the DB user name here.

# NevisMetaWebApplicationAccess_token

A `NEVIS SecToken` pattern must be assigned here.

The token will be issued after authentication 
and propagated to nevisMeta.

The user must have the role `nevisMeta.admin`.

# OAuth2AuthorizationServer_jwkSetKeyId

When set to `enabled` a `kid` header value will be added to issued access and ID tokens.

The value allows the authorization server to explicitly signal a change of key material to recipients.

The meaning of the `kid` header is slightly different for signed and encrypted tokens.

# ServiceAccessBase_backendTrustStore

Assign the trust store for outbound TLS connections.

If no pattern is assigned a trust store will be provided by nevisAdmin 4 automatic key management.

# GenericSocialLogin_buttonCss

The css class that apply for the social login button.
Ensure that the Login Template used in your realm pattern includes a CSS file which defines the CSS class. 

# NevisAdaptDatabase_jdbcDriver

Due to licensing, nevisAdapt cannot ship the JDBC driver to connect to Oracle databases,
Therefore, those who want to use an Oracle database need to obtain and provide the Oracle JDBC driver on their own.

The `.jar` files can be downloaded from [Oracle](https://www.oracle.com/database/technologies/appdev/jdbc-downloads.html)

Uploading any other `.jar` files containing JDBC drivers is possible as well.


# SocialLoginBase_onUserFound

Configure the Authentication Flow in case no user with Subject/ID from social account was found
but email does exist in nevisIDM.
The Authentication Flow must contain:
* `Social Login Link User` pattern to link an existing user in IDM with Subject/ID of social account.
* `Social Login Done` to end the social login flow after some other action(s).

**Note**: Please select scope `email` and `profile` for getting user's information from social account.

# LogSettingsBase_serverLog

Select the type of appender.

In Kubernetes the `default` appender writes to system out so
that log messages appear in the docker logs.

Choose between:

- `default` - log to default target
- `default + syslog` - log to default target and forward to a Syslog server
- `syslog` - forward to a Syslog server only


# CustomAuthLogFile_auditLog

Configure audit logging of nevisAuth.

Select `enabled` to use the default audit channel implementation provided by the [NevisAuditChannel](https://docs.nevis.net/nevisauth/operation/auditing#nevisauditchannel) class.

If you want to use your own channel, you have to assign `Audit Channels` and select one of the following options here:

- `enabled`: use you own channel **in addition** to the `NevisAuditChannel`.
- `custom`: use only own channel.


# UserInput_rememberInput

Enable this feature to show a `Remember Input` checkbox.

If selected the user input is stored in a cookie (named like this step)
so that the value can be prefilled on subsequent authentications.

# UserInformation_onSubmit

Define a follow-up step.

The `Button Type` should be set to `submit`, 
but the form can also be submitted by other means (e.g. refreshing the browser).


# BackendServiceAccessBase_params

Add custom `init-param(s)` for the Http(s)ConnectorServlet. For example: ConnectionRetries=10

Please check the nevisProxy technical documentation for supported `init-params` of the servlet classes `ch::nevis::isiweb4::servlet::connector::http::HttpConnectorServlet` and `ch::nevis::isiweb4::servlet::connector::http::HttpsConnectorServlet`.

# GenericNevisDetectSettings_javaOpts

Add additional entries to the JAVA_OPTS environment variable.

Use the expression `${instance}` for the instance name.

For instance, you may configure nevisDetect to create a heap dump on out of memory as follows:

```
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/opt/nevisdetect/${instance}/log/
```

Be aware that this example will not work for Kubernetes
as the pod will be automatically restarted on out of memory
and the created heap dump files will be lost.


# NevisIDMDeployable_mailSMTPUser

Set if a user is required to connect to the SMTP server.

# NevisDetectEntrypointDeployable_jms

Add reference for the pattern providing Java Messaging Service.

Two different options are allowed at this time:
- `nevisDetect Message Queue Instance` - deployment pattern for a dedicated MQ component
- `ActiveMQ Client Configuration` - connect to an external ActiveMQ service via SSL

**WARNING: In case of Kubernetes deployment, only `ActiveMQ Client Configuration` is supported.**

# ICAPScanning_url

URL(s) of the ICAP server(s). Each URL must have the same path.

Example: `icap://my-clamav-server1/avscan`

# TCPSettings_requestTimeout

Timeout waiting for the response.

# NevisProxyObservabilitySettings_traceContextExtraction

Choose one of:

- **enabled**: if present, extract the trace context from the HTTP request header and set it as parent for the current span
- **disabled**: ignore the trace context from the HTTP request header


# CustomAuthLogFile_auditLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the AUDIT logs.

Note: not relevant when Log Targets is set to `syslog`.

# OAuth2Client_redirectUri

Enter allowed URIs to return the code / token to.

Single-page and classic Web applications should use URLs, mobile applications sometimes use custom scheme URIs.

Regular expressions are not supported.


# CustomAuthLogFile_levels

Set log levels.

The default is:

| Category                                     | Level  |
|----------------------------------------------|--------|
| `EsAuthStart`                                  | `INFO`   |
| `org.apache.catalina.loader.WebappClassLoader` | `FATAL`  |
| `org.apache.catalina.startup.HostConfig`       | `ERROR`  |

The default gives you log messages during startup but is rather silent during runtime.

A good setting for troubleshooting is:

| Category   | Level |
|------------|-------|
| `AuthEngine` | `INFO`  |
| `Vars`       | `INFO`  |

When using `nevisAuth Database` with MariaDB the category `org.mariadb.jdbc` can be set. The levels behave as follows:

- `ERROR`: log connection errors
- `WARNING`: log query errors
- `DEBUG`: log queries
- `TRACE`: log all exchanges with server

Check the documentation for other [important trace groups](https://docs.nevis.net/nevisauth/setup-and-configuration/configuration-files/logging-configuration#important-trace-groups).

In classic deployment nevisAdmin 4 does **not** restart nevisAuth if you only change log levels.
The log configuration will be reloaded within 60 seconds after deployment.


# HostContext_allowedMethods

Define the HTTP methods which are allowed on this virtual host.

The setting `default (complete)` is quite relaxed as it enables most methods. 
Only two are excluded:

- `CONNECT`: no use case of nevisProxy.
- `TRACE`: may be useful for debugging but can be a security vulnerability.

If you do not have any applications using WebDav select `basic`.

The allowed HTTP methods can be restricted further in application patterns.

For more fine-grained control you may use `Generic nevisProxy Instance Settings` 
to overwrite the `allowedMethods` (see pattern help for details).

# CustomAuthLogFile_eventsSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the EVENTS SYS logs.

Note: not relevant when Log Targets is set to `default`.

# NevisAuthDeployable_logging

Add logging configuration for nevisAuth.

# NevisAdaptUserNotification_idm

Reference for the nevisIDM service. The `nevisAdapt Authentication Connector` uses nevisIDM's REST API to send notification emails to the user if the calculated weighted risk score exceeds the configured threshold.


# NevisIDMPasswordCreate_onExists

If the user already has a password credential and error will occur.

You can assign a step here to handle this case.


# TANBase_maxRetry

The maximum attempts for **each** code.

When this threshold is reached, the behaviour depends on `Max Regenerations`.

As long as `Max Regenerations` is not exhausted, a new code will be generated and sent to the user.

Once `Max Regenerations` is reached as well, the `On Failure` exit will be taken.


# NevisAdaptAnalyzerConfig_deviceCookieAnalyzer

Used to disable Device Cookie creation.


# AuthCloudLookup_onUserExists

Assign an authentication step to continue with when the user exists and has an active authenticator.


# NevisDetectAuthenticationConnectorStep_adapt

Optional pattern reference for the nevisAdapt Instance to help configure the device cookie name.

# SecretTestAddon_secretValues

Set a variable and insert secret value(s) in the inventory.

The file `/var/opt/nevisproxy/<instanceName>/run/secret_values.txt` should then contain:

- classic: resolved value(s)
- Kubernetes: `secret://` reference(s)

# OutOfBandManagementApp_resources

Upload a ZIP to provide your own resources.

By default, the following resources are provided:
* `index.html`
* `logo.png`


# SamlSpConnector_audienceRestrictionMode

Configure **if** an `<AudienceRestriction>` element shall be added to generated SAML assertions
and **what** the element shall contain.

Choose between:

- `automatic`: use `Custom Audience`, if configured, and `SP Issuer` otherwise.
- `issuer`: use `SP Issuer`.
- `custom`: use `Custom Audience`.
- `none`: no `<AudienceRestriction>` element is added.


# GenericAuthenticationStep_keyObjects

This pattern adds a XML element `KeyStore` to `esauth4.xml`.

Each pattern referenced here creates an additional `KeyObject`
which will be added to this `KeyStore` as a child element.

# AzureServiceBus_dlq

Remote Azure Service Bus Queue to which Dead Letter messages should be sent.

Dead letter messages are those messages which are not in the expiryQueue and their delivery was unsuccessful.
For further reference check `NevisIdm Technical documentation > Configuration > Components > Provisioning module > Provisioning providers`.

# NevisDPLogSettings_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.

This configuration applies to non-Kubernetes deployment only.

# NevisIDMCheckUserLoginInfo_neverLoggedIn

Configure the step to execute if the user never logged in.
If no step is configured here the process ends with `AUTH_DONE`.

# NevisFIDODeployable_frontendAddress

Enter the address of the `Virtual Host` where the services of this instance are exposed.

Enter the address without any path component.

Example:

```
https://example.com
```

If no address is provided, the pattern tries to automatically determine a value based on the `Virtual Host` patterns,
that are associated with this instance through patterns for out-of-band use-cases.

The entered value is used to calculate:
* [AppID](https://fidoalliance.org/specs/fido-uaf-v1.1-id-20170202/fido-appid-and-facets-v1.1-id-20170202.html#the-appid-and-facetid-assertions)
* _Dispatch payload_

The _dispatch payload_ informs the mobile device where to access nevisFIDO for the following use cases:
- [Out-of-band Registration](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/out-of-band-registration)
- [Out-of-band Authentication](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/out-of-band-authentication)


# NevisProxyDatabase_peerStrategy

Controls the used strategy of the Peer Servlet:

 * `FAILOVER`: The loadbalancer sends all requests to the same instance (instance A). If instance A goes down, the loadbalancer will send now all requests to instance B. The loadbalancer should only switch back to instance A if it has been restarted.
 * `DISTRIBUTED`: The loadbalancer assure at least 90% session stickiness to both instances, for example by using the client IP address. Once the request for a session goes to the other instance, this one will get the session information from the first instance and copy into its local session store.

# MicrosoftLogin_buttonLabel

Enter a label for the social login button.

Translations for this label can be configured in the `Authentication Realm` pattern.


# ObservabilityBase_agentLibrary

Path to the selected agent's library that is available locally to the deployed application. 

# NevisIDMDeployable_messagingPort

Port of the messaging service.

Enter a different port to deploy multiple nevisIDM instances on the same target host in classic VM deployment.

# SecToken_keystore

Assign a pattern which sets the key material used for signing the token.

If no pattern is assigned automatic key management is used
and the signer key will be created automatically.

# StaticContentCache_responseHeaderMode

Response headers can indicate whether clients and intermediate servers should cache the response. 

Choose one of:

- **comply** : Follow the `Cache-Control` directives sent by the backend.
- **ignore** : Store the response even if the backend sent a `Cache-Control` directive to prevent caching. 
Be aware that ignoring `Cache-Control` directives can lead to sharing sensitive data between clients.

Some clients or content providers try to switch off caching even for mostly static content like images or style sheets.
You can limit the load on your content providers as follows:

- Add a **Static Content Cache** pattern and link it to your application via **Additional Settings**;
- Configure **Apply only to sub-paths** to store responses on paths that only emit static content, for instance images;
- Set **Response Header Mode** to **ignore**;
- Configure the **Max Lifetime** of stored responses.


# KerberosLogin_level

Authentication level that is set on success.

# SAPLogonTicket_userIdSource

Source of the user ID to set for the issued SAP ticket.

The default is `${request:userId}`.

# NevisProxyDatabase_databaseSchemaCheck

Select one of:

- `enabled` - the database schema and integrity constraints are checked on startup to ensure they match the requirements of the `Remote Session Store`.

- `disabled` - the database schema and integrity constraints are not checked on startup.

Note: On certain MariaDB versions, the check produces fake errors due to a MariaDB bug.
By setting this parameter to `disabled`, you can skip the check.


# DummyTAN_level

Set an authentication level.

# NevisDetectDatabase_hikariValues

Specify custom values for Hikari datasource configuration. 
Separate keys and values with `=`. 
The valid keys can be found at [HikariCP - GitHub](https://github.com/brettwooldridge/HikariCP).

Example to set the same as if selecting `recommended`:

```
maxLifetime=300000
idleTimeout=100000
maximumPoolSize=50
```

# GenericIngressSettings_ingressClassName

Defines the `ingressClassName` of the generated ingress. It can be used instead of the `kubernetes.io/ingress.class` annotation to select which
ingress controller should handle the generated ingress.
For more information see [Multiple Ingress controllers](https://kubernetes.github.io/ingress-nginx/user-guide/multiple-ingress/#multiple-ingress-controllers).

# OAuth2AuthorizationServer_invalidClient

Configure the step to execute after error when the client sending the request is not registered.

If no step is configured here the process ends and the error will display on UI.

# NevisFIDODeployable_database

Configure a database to store nevisFIDO sessions. 

If no pattern is assigned, sessions will be stored in memory.
We recommend to use a database in production.


# Webhook_key

Set a unique key for the property name.

# AuthCloudBase_title

Enter a label to use for the title.

You can use a different standard label (e.g. `title.login`) or invent your own.

Translations for custom labels can be defined in the `Authentication Realm` / `GUI Rendering` / `Translations`.

The default label `title.authcloud` has the following translations:

- `en`: Authenticate with Access App
- `de`: Mit Access-App anmelden
- `fr`: S'authentifier avec l'application Access
- `it`: Autenticazione con l'app Access


# ManagementDemo_path

Enter the path where this example shall be exposed on the nevisProxy `Virtual Host`.


# NevisIDMChangePassword_addConfirmationField

If `enabled`, a confirmation field is also rendered on GUI.

# NevisIDMPruneHistoryJob_skipList

Comma-separated list of versioned tables (which are used to provide history data) to be ignored by the prune history job and left with their original content.

Possible values (Any combination of the following):

* `tidma_application_v`
* `tidma_authorization_appl_v`
* `tidma_authorization_client_v`
* `tidma_authorization_erole_v`
* `tidma_authorization_unit_v`
* `tidma_authorization_v`
* `tidma_cert_info_v`
* `tidma_client_application_v`
* `tidma_client_v`
* `tidma_consent_v`
* `tidma_cred_login_info_v`
* `tidma_credential_v`
* `tidma_dict_entry_v`
* `tidma_dict_entry_value_v`
* `tidma_enterprise_auth_v`
* `tidma_enterprise_role_v`
* `tidma_erole_member_v`
* `tidma_fido2_v`
* `tidma_fido_uaf_v`
* `tidma_mobile_signature_v`
* `tidma_oath_v`
* `tidma_personal_answer_v`
* `tidma_personal_question_v`
* `tidma_policy_configuration_v`
* `tidma_policy_parameter_v`
* `tidma_profile_v`
* `tidma_property_allowed_val_v`
* `tidma_property_v`
* `tidma_property_value_v`
* `tidma_role_v`
* `tidma_saml_federation_v`
* `tidma_template_collection_v`
* `tidma_template_text_v`
* `tidma_template_v`
* `tidma_terms_application_v`
* `tidma_terms_url_v`
* `tidma_terms_v`
* `tidma_unit_cred_policy_v`
* `tidma_unit_v`
* `tidma_user_login_info_v`
* `tidma_user_v`

For further information about historical tables visit [Versioned DB tables
](https://docs.nevis.net/nevisidm/Configuration/Data-Model/Database-tables-and-the-nevisIDM-data-model/Versioned-DB-tables).

# Dispatcher_transitions

Define how to dispatch based on _conditions_.

In the first column enter the _transition_. A _transition_ may be:
 
- a condition `name`
- a comma-separated list of conditions

All conditions in the transition **must** match in order for the transition to be applicable. 
The most specific transition is chosen.

In the second column enter the _position_.
Position refers to the list of `Conditional Step(s)`. The first step has position `1`.

Examples:

| Transition  | Position |
|-------------|----------|
| pwreset     | 1        |
| pwreset,mfa | 2        |


# UserInformation_messageType

- `error` - terminates the session (`AUTH_ERROR`) and shows an error message.
- `warn` - does not terminate the session (`AUTH_CONTINUE`) but the message is shown as an error.
- `info` - renders as a message of type `info` and does not terminate the session (`AUTH_CONTINUE`).

Terminating the session needs careful testing 
as state loss can lead to follow-up errors.

# NevisAdaptDatabase_oracleDataTablespaceName

Name of the data tablespace for the oracle database used for the Kubernetes migration. It's recommended to keep the default value unless the pattern is used with an existing database that has a different one.

# NevisAuthRealmBase_auth

Assign a `nevisAuth Instance` pattern.

# JWTToken_keystore

A Key Store is required when an asymmetric algorithm is used.

This is required for `JWE` because of the `RSA-OAEP-256` algorithm.

# NevisFIDODeployable_registrationTimeout

Defines the maximum time duration between the generation of the `RegistrationRequest` by nevisFIDO and the `RegistrationResponse` by the FIDO UAF client. 

If the client has not sent the response after this time, a client timeout occurs. 

The default value is 5 minutes. If no time unit is provided, seconds will be used.

This timeout is relevant in registration use-cases, such as:

- [In-Band Registration](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/in-band-registration)
- [Out-of-Band Registration](https://docs.nevis.net/configurationguide/mobile-auth-concept-and-integration-guide/use-cases-and-best-practices/out-of-band-registration)


# AccessRestriction_ipHeader

Optional setting used to specify HTTP header that contains the users IP.
Otherwise, a default environment variable from nevisProxy is used.

Examples:
* `X-Forwarded-For`


# NevisAuthDeployable_server

Set _Server Configuration_ properties (`nevisauth.yml`).

Examples:

```properties
server.max-http-header-size: 16384
```


# SamlIdpConnector_signatureValidation

Configure for which SAML elements signature validation shall be performed.

It is recommended that the IDP signs the entire `Response` as this is the most secure mode.

If only the `Assertion` is signed nevisAuth will perform additional checks to prevent attack scenarios.


# NevisMetaDeployable_logging

Configure the nevisMeta log files.

# GenericThirdPartyRealm_authService

Optionally assign an application which provides the authentication service
and shall be exposed on the same virtual host as the applications.

Not required for federation-based authentication 
where the authentication service is hosted on another domain.

# KeyObject_keyStoreName

Define the `name` of the parent `KeyStore` element.

You can enter the `name` of a `KeyStore` element generated by another pattern, or enter a new name.

If **not** configured, the `name` of the `KeyStore` depends on **where** this `nevisAuth KeyObject` pattern is assigned:

- `Generic Authentication Realm`: sanitized name of the realm pattern.
- `Generic Authentication Step`: sanitized name of the step pattern.
- `nevisAuth Instance`: the name `AddonKeyStore`.

Note that the nevisAuth configuration always contains a `KeyStore` element with name `DefaultKeyStore`.
This `KeyStore` is typically used as a container for signer key material.


# NevisDPDeployable_resources

Upload additional resources here.

For instance, you may upload files used by your data sources in the `Configuration`.

nevisAdmin generation time expressions (e.g. `${var.name}`) are not supported here.


# SamlToken_audience

Configure the `AudienceRestriction`.

Enter 1 line for each `Audience`.

# AppleLogin_clientSecret

The Client Secret is a JWT token generated by using a private key provided by Apple.
Please follow the instructions [here](https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens).

You can generate the client secret by yourself and configure it here, or upload the Private Key to generate the client secret automatically.
Only private key or client secret can be use at the time

# NevisIDMCheckUserCredentials_anyCredentialFound

Configure the step to execute if the user has at least one credential from credential type selected in `Credential Types`, but nit from all credential type.
If no step is configured here the process ends with `AUTH_DONE`.

# NevisAuthDeployable_signerKeyStore

Assign a key store for signing the **internal** NEVIS SecToken.

This token is returned to nevisProxy and validated there. It should **not** be added to calls to applications.
If your applications need a NEVIS SecToken, assign a `NEVIS SecToken` pattern to your applications.

If no pattern is assigned, the signer key material will be provided by automatic key management.


# NevisIDMDeployable_clientAuth

Setting for 2-way TLS on the nevisIDM HTTPs endpoint. There are 3 options will
affect the callers (e.g. nevisProxy or technical clients accessing nevisIDM REST APIs)

* required: Callers **must** present a client certificate.
* requested: Callers **can** present a client certificate.
* disabled: Callers **must not** use a client certificate.

The `Frontend Trust Store` must contain the issuing CA.

# NevisAdaptPluginPattern_nevisAdapt

Pattern reference for the nevisAdapt Instance to connect to.

# SharedStorageSettings_storageSize

The size of the persistent volume. The minimum size is 1 gigabyte, we recommend to use at least 4 gigabytes.

For example: `4GB`

# GroovyScriptStep_responseType

Choose between:

- `AUTH_ERROR`: terminates the session.
- `AUTH_CONTINUE`: use to produce a response and continue with this state on next request.


# SamlSpConnector_onForbidden

Configure a step that shall be executed
when the `Required Roles` check fails.


# NevisFIDOConnector_url

Enter URL(s) to connect to your nevisFIDO instance.

The path must be omitted.

Only scheme `https://` is allowed.

The scheme is optional which means
that you can enter simple `host:port` pairs (1 per line).


# CSRFProtectionSettings_allowedDomains

CSRF protection can be obstructive for cross-domain use cases 
(e.g. federation or providing a public REST API).

Enter domains which should be excluded from `header-based` CSRF protection. 
There is no support for wildcards, pre- or postfix notations (sub-domains must be listed individually).

Example: 
```
www.adnovum.ch 
adnovum.ch
```

# UserInput_variable

Enter `<scope>:<name>` of the variable which shall be set.

The following scopes are supported:

- `inargs`
- `notes`
- `sess` or `session`

For instance, enter `notes:loginid` to prefill the login form
which is produced by the `nevisIDM Password Login` pattern.

# SAPLogonTicket_setCookie

If set, this property must specify the value of the HTTP header "Set-Cookie". The cookie will be issued to the client by nevisAuth such that a cookie-based SSO federation with SAP applications is possible. 
This property is evaluated after the ticket has been issued, so the variables `sap.ticket`, `sap.ticket.maxAge` and `sap.ticket.expires` can be used. 

Example value for this property that sets the cookie as expected by SAP products:

   ```
   MYSAPSSO2=${outarg:sap.ticket}; Version=1; Path=/; Secure; HttpOnly; Max-Age=${notes:sap.ticket.maxAge}; Expires=${notes:sap.ticket.expires};
   ```

To use this example value by default, set this property to `true`.

# NevisDetectAdminDeployable_jms

Add references (at least one) for the patterns configuring Java Messaging Service.
In case of Kubernetes deployment, only one configuration is allowed.

Two different options are allowed at this time:
- `nevisDetect Message Queue Instance` - deployment pattern for a dedicated MQ component
- `ActiveMQ Client Configuration` - connect to an external ActiveMQ service via SSL

**WARNING: In case of Kubernetes deployment, only `ActiveMQ Client Configuration` is supported.**

# DatabaseBase_hosts

Enter the host name of the database service.

The database service must be up when you deploy.

In a classic deployment the `Database User` and `Database Password` is used to connect.

In Kubernetes deployment a connection user and password will be generated
and the `Root Credential` will be used to set up the database schema.


# SecToken_attributes

Set the content of the `NEVIS SecToken`.

Example:

| Attribute | Variable                              |
|-----------|---------------------------------------|
| userid    | request:UserId                        |
| loginId   | session:ch.nevis.session.loginid      |
| profileId | session:ch.adnovum.nevisidm.profileId |
| clientId  | session:ch.adnovum.nevisidm.clientId  |
| roles     | request:ActualRoles                   |

Supported variable _scopes_ are:

- `session` - a session variable.
- `request` - a variable from the request.
- `const` - a fixed value.

This configuration should work for most backend applications,
including NEVIS components.

The `userid` is required by Ninja and **must** always be set.
You can use `ch.nevis.session.loginid` when this pattern is **not** part of the `Initial Authentication Flow`.

The `loginId`, `profileId`, `clientId` are required by nevisIDM.

The attribute `roles` is required by nevisWF and nevisMeta.

For some attributes there are multiple variables to choose from.
Check the nevisAuth log with log levels of `Vars` set to `INFO`
to find out which variables are available in your case.


# NevisFIDODeployable_managementPort

This port is used to check if the instance is up after deployment.

# OAuth2Client_scopes

Enter scopes which may be requested by this client.
The scope `openid` must be allowed when OpenID Connect is used.

# FrontendKerberosLogin_keyTabFile

Upload the Kerberos keytab file. 

nevisAuth uses this file to validate Kerberos tokens sent by browsers.

Please check the nevisAuth Technical Documentation on how to create the keytab file.

The keytab file will be deployed to the `conf` directory of the nevisAuth instance.

For a more secure and environment-specific configuration you have the following alternatives:
 
- create a variable and upload the keytab file in the inventory
- set `Keytab File Path` instead of uploading the file and deploy the file by other means

In complex setups with multiple `Kerberos Realms` and/or `Frontend Addresses` 
you may have to upload multiple keytab files.

# DummyTAN_label

Set to show a different message.

# InBandMobileAuthenticationRealm_keyStore

Define the key store to use for 2-way HTTPs connections from nevisProxy to nevisAuth.

# HostContext_addons

Assign add-on patterns to customize the behaviour of this virtual host.


# NevisFIDODatabase_maxConnectionLifetime

Defines the maximum time that a session database connection remains in the connection pool.

# GenericIngressSettings_tlsSecrets

Use your own Kubernetes secrets to provide the frontend key store for a `Virtual Host`.

Syntax is a map of (primary) frontend address of the host to secret name.

```properties
www.siven.ch: customsecretname
```

Secrets must be of `type: kubernetes.io/tls`. Secrets must be prepared before deployment.
They must contain a private key (`tls.key`), a matching certificate (`tls.crt`) and should contain the CA chain (`ca.crt`).

If not set the Nevis operator request certificates from the cluster issuer
and generates a secret for each `Virtual Host` to store the required key material.


# NevisIDMDatabase_oracleOwnerRoleName

Name of the owner role for the oracle database. It's recommended to keep the default value unless the pattern is used with an existing database that has a different one.

# NevisFIDODeployable_deepLink

Deep links use the standard `https://` scheme. 

Enter a complete URL here. 

We recommend to add a **path** component as otherwise `/` will be used
and there often is no appropriate content on the root location.

Note that **Apple requires the link to point to another domain**.
You can use any web server or Nevis as the target.

When the user clicks the link, the OS of the mobile device
will first try to download an _app link_ file from a `/.well-known/` path on that domain.

You can configure `Deep Link Host` and `Deep Link App Files` to host these files.

The app link file is used by the OS to determine if a mobile app shall be opened, 
handing over the current URL.

If no mobile app can be determined, the deep link will be opened in the browser instead.
Examples:

- user does not have the app installed
- no rule in the `/.well-known/apple-app-site-association` file applies to the path

Because of these error cases, there should be content on the deep link URL.

We recommend to create a page that informs the user how to install the mobile app.
You can use the `Hosting Service` pattern to host this page on the `Deep Link Host`.


# NevisIDMUserLookup_useDefaultProfile

Should in the Authentication flow assume default profile is selected if the user has multiple profiles, or should it display a selection dialog for the user.

# DeployableBase_enforceVersion

Select `enabled` to perform basic version checks.

In classic VM deployment we run a command on each target host,
to check which version of the component is installed.

In Kubernetes deployment we check the version of the docker image instead.

This check can be disabled for testing purposes.


# GenericIngressSettings_clientCertVerifyDepth

The maximum validation depth between the provided client certificate and the CA chain. (default: 1).

You only need to increase this if you only have a parent CA in the CA Secret
but want to accept client certificates which have been issued by a child CA.

# WebApplicationAccess_path

Enter the path(s) where this application shall be accessible on the assigned `Virtual Host`.

It is recommended to set only 1 path. Examples:

- `/app/` - defines a base path. 
Requests which have a path component starting with `/app/` will be sent to this application. This is the most common scenario.

- `/` - may be used when there are no other applications. 
The `Hosted Resources` of the `Virtual Host` are still accessible but all other requests will be sent to the backend application.

- `exact:/app.html` - matches requests to `/app.html` only (query parameters may also be added). 
Use for single-page applications which don't require any additional resources.
  
- `prefix:/app` - matches requests which have a path component starting with `/app`. 
Examples: `/application`, `/app/index.html`, `/app2/secure/`

In case the frontend path is different from the path used within `Backend Addresses` 
then the path will be rewritten in incoming requests. 

Note that for response by default only the headers are rewritten. See `Response Rewriting` for further options.

Note that when you enter multiple paths there are some limitations:

- Filters created by a `Realm` or `Additional Settings` will be mapped to all paths.
- The paths have to be the same on the backend server.


# EmailTAN_channel

The connection provider for the sending the email code. 

Choose between `Sendgrid SMTP` and a `Generic SMTP` patterns.


# NevisIDMURLTicketConsume_onDisabled

Assign an authentication step to execute when the URL ticket or user is **disabled**.

If not set a screen with `title.url_ticket` and `error.user_or_url_ticket.disabled` will be shown in that case.

# ServiceBase_addons

Assign add-on patterns to customize the behaviour of this service.

Example use cases:

- `Authorization Policy` to enforce roles or an authentication level.
- `URL Handling` to redirect or forward requests.
- `HTTP Header Customization` to add, replace, or remove HTTP headers in requests or responses.


# AppleLogin_privateKeyFile

Private key provided by Apple. Find out more [here](https://help.apple.com/developer-account/#/dev77c875b7e).

If you upload your private key here and set the `Issuer`, the pattern will automatically generate the `Client Secret`. 

If you do not want to configure your private key, you have to set the `Client Secret` instead.


# AccessRestriction_defaultAction

Defines the action taken either when no country rules were matched or the IP of a request
does not have an associated country in the database.

Possible actions are:
* **allow**: Requests are let through
* **log**: A log entry is made for each request
* **block**: Blocks requests

# NevisIDMConnector_url

Enter URL(s) to connect to your nevisIDM instance.

The path must be omitted.

Only scheme `https://` is allowed.

The scheme is optional which means
that you can enter simple `host:port` pairs (1 per line).


# NevisIDMDeployable_resources

Files uploaded here will be added to the `conf` folder of the nevisIDM Instance.

# NevisAuthRealmBase_sessionTimeout

Define the idle timeout of an authenticated session.

# NevisIDMPasswordLogin_clientInput

Enable this to allow the user to enter the name of the _Client_ (tenant) when logging in to nevisIDM.

If `disabled`, the input field is not shown and the Client `Default` is used.

# OutOfBandMobileAuthentication_channel

Select how to transfer information to the mobile application.

`Link / QR-Code`: 
User can click a link if they are navigating on the same mobile device as the app resides on.
A QR-code is shown as well which can be scanned if the user uses a browser separate from the mobile device the app resides on.
The QR-code can also be scanned with the camera app of the mobile device.
This option uses `mauth_link_qr.js`.

`Push / QR-Code (in-app)`: 
The user receives a push notification on their mobile device. 
In addition to that, a QR-code is shown which can be scanned instead in case the user does not receive the push notification.
This QR-code can be scanned in the mobile app **only**, scanning the QR-Code using the camera app of the mobile device is not supported.
This option uses `mauth_push_qr.js`.

If you are using a custom login template, add the correct
Javascript file and some Velocity template snippets.

Download the default template in your `Authentication Realm`,
unpack the zip, and search for `mauth` to get started.


# NevisIDMPasswordLogin_redirectionValidationFallback

If `Allowed` then after checking regexes set in `Custom Redirection Path Validation Regexes` it also a check if the path starts with any declared `Web Application`'s path. (To see which paths would be find you can check Application Reports). If yes, those requests are also allowed

# CustomNevisIDMLogFile_batchLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the default SERVER logs.

Note: not relevant when Log Targets is set to `syslog`.

# NevisAdaptAuthenticationConnectorStep_passthroughMode

The passthrough mode disables the nevisAdapt validation. All analysers are still executed and results (risks/active sessions) are persisted.

When enabled, all risks follow the `On Success` step. High and Medium risk actions are ignored.

This mode is useful for data gathering and troubleshooting.

# PropertiesTestPattern_hostPortProperty

Enter `host:port` pair(s).

# BackendServiceAccessBase_host

Assign `Virtual Host` patterns which shall serve as entry point for this application.

# NevisIDMPasswordLogin_passwordConfirmation

Select the behaviour of password reset and the form of the password reset screen. If

* `enabled`: displays password confirmation field on password reset screen which is required to be filled in for password to be reset.
* `disabled`: leaves out field on password reset screen and password can be reset with filling out password field only.

# CustomProxyLogFile_rotationCompressionApplication

You may specify a program or script which shall be used to compress rotated files.
 
 Example: 
 
 ```/usr/bin/gzip```

# AzureServiceBusRemoteQueue_host

Enter the complete `Host name` of the Service Bus as shown in the Azure portal.

Example: `my-service-bus-name.servicebus.windows.net`

# GenericIngressSettings_clientCertErrorPage

An error page which will be presented in case of certificate validation error.

If you enter a path (e.g. `/errorpages/403.html`) then that path will be fetched from nevisProxy.

If you enter a URL then the caller is redirected to that URL.

# NevisAuthRealmBase_keyStore

Define the key store to use for 2-way HTTPs connections from nevisProxy to nevisAuth.

If no pattern is assigned automatic key management will provide the required key material.
This requires that the `nevisAuth Instance` is part of this project and also uses automatic key management. 

Automatic key management should be used for test setups only.

# GoogleLogin_clientExtId

The ExtId of the client in nevisIDM that will be used to store the user 

# NevisAuthRealmBase_trustStore

Defines the trust store that nevisProxy uses to validate the nevisAuth HTTPs endpoint.

If no pattern is assigned automatic key management is used to provide the trust store.
This requires that the `nevisAuth Instance` is part of this project and also uses automatic key management. 

Automatic key management should be used for test setups only.

# NevisAuthRadiusResponse_attributes

Adds additional attributes to this Radius response.

Which attributes are required depends on the `Radius Response Type`.

For instance, in an `Access-Challenge` it is often required to add a `Reply-Message` which can be shown to the user.
Also a `State` must be added some that the authentication can continue.

You may use expressions for the attribute value. For instance, use a `${litdict:` expression to return a translated text.

Examples:

```
Prompt: No-Echo
Reply-Message: ${litdict:mtan.prompt}
State: ${sess:Id}
```

# OutOfBandMobileStepBase_onSuccess

On a successful authentication, the flow will continue with the assigned step.


# GenericDeployment_commandTriggerFiles

Files deployed by other nevisAdmin 4 patterns that, when changed, trigger the script to be executed, even if the script and files itself do not change.

Example:
* /var/opt/nevisproxy/my_proxy/conf/navajo.xml

Hint:
This is useful for patching e.g. `navajo.xml` after generation. Note that during the next deployment, it will be reverted (if the `nevisProxy Instance` pattern is deployed as well) 
and then patching will happen again.

# NevisIDMDeployable_database

Assign a `nevisIDM Database`.


# SwissPhoneChannel_username

The username to use to connect to the SwissPhone SMS Gateway.


# NevisIDMDeployable_queryService

Enable the Query Service to allow full-text searches on the Admin GUI and REST API.
Please note that using the Query Service requires the nevisIDM REST API to be exposed with the _nevisIDM REST Service_ pattern. 

# NevisFIDOLogSettings_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.
When `Rotation Type` is `time`, this property is used as Logback's [maxHistory](https://logback.qos.ch/manual/appenders.html#tbrpMaxHistory) property.
This means that logs will be archived for this number of time units where time unit is as defined in `Rotation Interval`.

# AuthCloudBase_onSuccess

Assign a step to execute after successful authentication.

If no step is configured here the process ends and the user will be authenticated.

# NevisProxyDeployable_startupDelay

Time to wait before checking Kubernetes readiness on startup.

You may have to increase this value if start of the nevisProxy service fails because of a failing readiness check.

Sets `initialDelaySeconds` of the Kubernetes startup probe.


# AuthorizationPolicy_requiredRoles

Optional setting to enforce authorization.

Callers need any of the specified roles to access.

Required roles defined for an application can be overridden for a sub-path by combining several `Authorization Policy` patterns for this application.
Required roles can also be inherited between patterns. See `Required Roles Mode` for details.

This setting requires assigning an `Authentication Realm` on the application pattern.

Usage examples:
- Enforce required roles for an application:
  use an `Authorization Policy` pattern with the `Required Roles` to enforce and link it to the application via `Additional Settings`;
- Enforce required roles for some sub-paths of an application:
  use an `Authorization Policy` pattern with the `Required Roles` to enforce and `Apply only to sub-paths` set to the paths to protect. Link the pattern to the application via `Additional Settings`;
- Enforce some main required roles for an application and some specific required roles for some sub-paths:
  use two `Authorization Policy` patterns, one with the main `Required Roles` and no sub-path, and one with the specific `Required Roles` and `Apply only to sub-paths` set to the paths where the specific required roles should apply. Link both patterns to the application via `Additional Settings`.
- Enforce some main required roles for an application and disable them for some sub-paths:
  use two `Authorization Policy` patterns, one with the main `Required Roles` and no sub-path, and one with no `Required Roles` and `Apply only to sub-paths` set to the paths where no required roles should be enforced. Link both patterns to the application via `Additional Settings`.
- Enforce some required roles for an application and add some forbidden roles for some sub-paths:
  use two `Authorization Policy` patterns, one with the `Required Roles` for the application, `Required Roles Mode` set to `self-contained`, and no sub-path, and the other pattern with no `Required Roles`, `Required Roles Mode` set to `inherited`, the `Forbidden Roles` for the subpaths, `Forbidden Roles Mode` set to `self-contained`, and `Apply only to sub-paths` set to the paths where the forbidden roles should be enforced. Link both patterns to the application via `Additional Settings`.


# GenericDeployment_otherPermission

Read-write permissions for all users of the directory. All files and subdirectories (including unpacked from single .zip) will have the same permissions. 
The executable bit will be set automatically for readable directories and for readable `Executable Files`.

# NevisIDMPasswordLogin_emailRedirRegexes

Enter regexes for Deny/Allow-list to validate redirection URL query parameter sent with the Password reset-email

Default defined for Deny-list regexes and filters out all paths containing `line feed` and `carriage return` characters.

# GoogleLogin_clientSecret

Client Secret is `Client Secret` provided by Google when you create a OAUTH 2.0 credential in Google.

# SocialLoginExtender_onSuccess

The step executed after a successful authentication.
If no step is configured here the process ends with `AUTH_DONE`.

**Note**: In order to have profile selection in case account have multiple profiles, you need to use the User Lookup pattern.

# GenericServiceSettings_filterMappings

Choose between:

- `manual` (default): only the `filter-mapping` elements which have been configured via `Filters and Mappings` will be added.
- `automatic`: filters configured via `Filters and Mappings` will be mapped to all `Frontend Paths` of the application.
- `both`: like `automatic` but additional `filter-mapping` elements are allowed as well.


# CustomInputField_optional

Input into the field is optional or mandatory.

Choose between:

- `optional` - No input is required to the field.
- `mandatory` - Input is required to the field.

# OAuth2Scope_scopeName

Enter the technical name of the scope.

If not set the name entered for the pattern will be used.

# SamlIdp_host

Assign a `Virtual Host` which shall serve as entry point.

# HostContext_unsecureConnection

This property defines how to handle requests received via plain HTTP. Choose between:

* `redirect` If a request is received via plain HTTP the client is redirect to the HTTPS endpoint (requires a `Frontend Address`
 with scheme `https://`).
* `allow` the request is processed.


# NevisIDMDeployable_multiClientMode

If IDM should support multiple Clients.

# BackendServiceAccessBase_loadBalancing

Select a request dispatching strategy when several `Backend Addresses` are configured.

- `disabled` - all requests will be sent to the first address. If this address is not available the next address is chosen;
- `round-robin` - one of the addresses will be picked up for each request using a round-robin rotation;
- `session-sticky` - one of the addresses will be picked up for each new session using a round-robin rotation, then subsequent requests for the session will be sent to the same address.


Failover strategy:
* When the selected backend cannot be accessed, nevisProxy will attempt to use another one.
* Once the said backend can be accessed again, it can be picked up for new requests if the load balancing is `round-robin`, or for new sessions if the load balancing is `disabled` or `session-sticky`. 
The requests linked to an existing session will still go to the current backend until the end of the session if the load balancing is `disabled` or `session-sticky`.



# NevisAdaptAuthenticationConnectorStep_clientTrustStore

The trust store used by this pattern to establish a connection with the nevisAdapt component.
This trust store must trust the `nevisAdapt Instance`'s key store. Please reference a trust store provider pattern or leave empty to manage the trust store with nevisAdmin automatic key management.

# NevisIDMChangePassword_locked

Assign an authentication step to execute when the status of the URL ticket or credential is **locked**.


# CustomAuthLogFile_eventLogFields

Set to add additional fields to the nevisAuth events log.

Enter field names (with optional format `JSON`) to nevisAuth expressions.

Examples:

| Field              | Expression                                                                        |
|--------------------|-----------------------------------------------------------------------------------|
| unitDisplayName    | `${sess:ch.nevis.idm.User.unit.displayName}`                                      |
| unitHierarchy:JSON | `${StringUtils.strip(sess['ch.nevis.idm.User.unit.hname'].replace('/',','),',')}` |

Based on this `CustomField` elements with `name`, `value`,
and optional attribute `format`, are created in `esauth4.xml`.


# NevisFIDOServiceAccess_backendKeyStore

Assign a key store for 2-way TLS connection to nevisFIDO.


# SwissPhoneChannel_proxy

Forward proxy for the connection to the SwissPhone SMS Gateway. 

Example: `proxy.your-internal-domain:3128`


# NevisIDMTermsAcceptance_onSuccess

Configure the step to execute after the user has accepted all terms and conditions.

If no step is configured here the process ends and the user will be authenticated.

# KerberosLogin_keyTabFilePath

Enter the path of the Kerberos keytab file.

The path must exist on the target host(s) of the `nevisAuth Instance`.

This configuration is ignored when keytab file(s) are uploaded via `Keytab File`.

In complex setups with multiple `Kerberos Realms` and/or `Frontend Addresses` 
you may want to enter multiple keytab file paths.

# NevisIDMServiceAccessBase_backendHostnameCheck

Enable to verify that the hostname on the certificate presented by the backend matches the hostname of `nevisIDM`

# NevisAuthRealmBase_addons

Assign `Session Settings` to set advanced settings, 
such as session timeout and session validation requirements.

# GenericAuthRealm_labels

Labels are used to provide human-readable text in the language of the user.

The language is extracted from the `Accept-Language` header
and the default login page template has a language selection.

Which labels are used depends on the assigned steps.
Click `Download Default Labels` to retrieve the labels used and their translations.

Here you can overwrite the defaults and add your own translations or even introduce new labels
which may be required when using a `Custom Login Template` or `Generic Authentication Step` patterns.

The name of uploaded files must end with the language code.
As the format is compatible you may upload existing `text_<code>.properties` files of nevisLogrend
or `LitDict_<code>.properties` of nevisAuth.

The encoding of uploaded files does not matter as long as all translations are HTML encoded.

The default login template uses the following labels:
- `title` - used as browser page title
- `language.<code>` - used by language switch component

The default logout process of nevisAuth (which will be applied when no step is assigned to `Logout`)
produces a confirmation GUI which requires the following labels:

- `logout.label` - header of the logout confirmation GUI
- `logout.text` - text shown to the user
- `continue.button.label` - label on the confirmation button

# NevisDetectAdminWebApplicationAccess_backendHostnameCheck

Enable to verify that the hostname on the certificate presented by the backend matches the hostname of `nevisDetect Admin`

# NevisAdaptRememberMeConnectorStep_clientKeyStore

The key store used by this pattern to establish a connection with the nevisAdapt component.
For a client TLS connection, this key store should be trusted by the ```nevisAdapt Instance```. If no pattern is assigned here automatic key management will provide the key store.

# PropertiesTestPattern_simpleTextProperty

Enter text.
Each line is one value.

# HostContext_requireClientCert

Choose from:

- `disabled (default)`: No client certificate is required to connect to this virtual host.

- `enabled`: Clients must present a client certificate signed by a CA.
The CA which has issued the client certificate must be part of the `Frontend Truststore`.
When no client certificate is presented or the certificate is not valid the connection will be aborted. 
As no error page is rendered this feature is not recommended when there are browser-based clients.
Use for technical clients only.

# NevisAdaptDeployable_proxyPort

Enter the port of the forward proxy if available.

```
3182
```

# AccessTokenConsumer_onSuccess

Assign a step to continue with after successfully validating the token.


# NevisIDMUserLookup_mode

Select `interactive` to prompt the user to enter a Login ID.

An input form will be shown when the query or POST parameter `isiwebuserid` is missing
or the user is not found in nevisIDM (and `On User Not Found` is not set).

Select `pass-through` to look up the user based on `Login ID Source`.

In this mode no input form will be shown. Instead, a `403` response will be generated 
if the user is not found (and `On User Not Found` is not set).

# GenericAuthService_path

Define a path to be mapped on the assigned virtual host.

Requests sent to this path will be forwarded to nevisAuth
so that they can be handled by this authentication service.

# SamlSpConnector_authenticationLevel

Enforce a minimum required authentication level for this Service Provider.

If not set, the minimum required authentication level will depend on the incoming `AuthnRequest`.
An SP may specify the level by including a `RequestedAuthnContext`, such as:

```xml
<samlp:RequestedAuthnContext Comparison="minimum">
  <saml:AuthnContextClassRef>urn:nevis:level:2</saml:AuthnContextClassRef>
</samlp:RequestedAuthnContext>
```

If there is any requirement for a minimum authentication level, 
the `Authentication Realm` must provide a `Session Upgrade Flow` for that level.
See the help of the `Authentication Realm` pattern for details.

Note that when there is no authenticated session,
the `Initial Authentication Flow` of the `Authentication Realm` will be executed first.

After successfully completing the `Initial Authentication Flow` the attained authentication level 
is compared against the minimum level and, if required, a `Session Upgrade Flow` is executed.


# AzureServiceBusRemoteQueue_queue

Enter the name of a queue.

# OAuth2AuthorizationServer_signer

Configure the key material which is used to sign issued codes and tokens.

# NevisAdaptFeedbackConfig_feedbackAction

The authentication step is able to generate a short-term feedback token if there are suspicious circumstances around the authentication attempt. 

The registered user receives a URL in a notification email (in a notification step if configured), following that link within the token's lifetime would perform the configured task:

* `disabled` - no token will be generated
* `session` - following the link distrusts the suspicious session (even retroactively)
* `device` - following the link distrusts the suspicious session and all other sessions associated with the same device
* `all` - following the link removes all sessions and observations for the user

All options apart from `disabled` require access to SessionManagement API in all involved `nevisAuth Instance`.

In case of `all`, please set `Enable Indexing` value to `on` for all involved `nevisAuth Instance`.


# AuthCloudBase_onFailure

Assign a step to continue with when the operation has failed due to unknown reasons.

For instance, you may assign the following steps:

- `User Information`: show an error message and terminate the authentication flow.
- `nevisIDM Second Factor Selection`: select an alternative second factor for authentication.


# CustomNevisMetaLogFile_serverLog

Select type of log4j appender.
 
`RollingFileAppender` and `SyslogAppender` are possible options. 

# NevisProxyObservabilitySettings_traceMode

Choose one of:

- **enabled**: enable the trace feature of OpenTelemetry
- **disabled**: disable the trace feature of OpenTelemetry


# NevisMetaDeployable_managementPort

This port is used to check if the instance is up after deployment.

# OutOfBandMobileAuthentication_onDispatchFailure

When a failure occurs during _dispatching_, the authentication flow will continue with the assigned step.

There are several error cases:

- nevisFIDO is unable to hand out a link or render a QR-code
- the `dispatchTargetId` sent by the JavaScript does not exist. For instance, the credential may have been deleted in nevisIDM.


# NevisDPDeployable_idmTruststore

Assign a trust store which shall be used for outbound TLS connections to nevisIDM.
If no pattern is assigned no trust store will be generated.

For nevisDataPorter to use the trust store,
the following expressions should be used inside the `dataporter.xml` file:

```
${idm.truststore}
${idm.truststore.password}
```

Example configuration:

```xml
<object type="NevisIDMConnectionPool" name="adminService">
    <dp:paraVal name="endpoint" value="${cfg.idmEndpoint}"/>
    <dp:paraVal name="loginMode" value="proxyCert"/>
    <dp:paraMap name="sslSettings">
        <value name="javax.net.ssl.trustStore" value="${idm.truststore}"/>
        <value name="javax.net.ssl.trustStorePassword" value="${idm.truststore.password}"/>
        ...
    </dp:paraMap>
</object>
```


# NevisAuthDeployable_database

By default, nevisAuth stores sessions and out of context data in memory.

In most setups you should use a database instead, and you should assign a `nevisAuth Database` pattern here.

In memory should be used only when there is only 1 line / pod of nevisAuth,
or in a classic deployment where nevisProxy can ensure session-sticky load balancing towards nevisAuth.


# OAuth2AuthorizationServer_setupId

ID of the nevisMeta _setup_.

Create your setup via the `nevisMeta Web Console`.

Then the ID of the setup can be determined. There are several ways to do that:
 
- hover over the icon which links to the REST API 
- export the setup and check the exported files
- Configure a `nevisMeta REST Service`, login and send a `GET` to `/nevismeta/rest/v2/modules/oauthv2/setups/`

# NevisIDMDeployable_managementHost

Enter a custom host name to open the `Status Port` on.

If not set `0.0.0.0` will be used in case of Kubernetes deployment
and `localhost` for deployment to VMs.

# CustomNevisMetaLogFile_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.

This setting applies to `nevismeta.log` only.

# OAuth2AuthorizationServer_oidcIssuer

Enter the _issuer_ for OpenID Connect.

The value must be a case-sensitive URL using the https scheme that contains at least scheme and host.
The port number and path component are optional. No query or fragment components are allowed.

If not set the issuer will be calculated based on:

- the first `Frontend Address` with scheme `https` of the assigned `Virtual Host`
- the first `Frontend Path`

# NevisIDMPasswordLogin_nevisIDM

Reference a `nevisIDM Instance` to be used for the username / password authentication.

# WebSocket_params

Add custom `init-param` for the WebSocket servlet. 

Please check the nevisProxy technical documentation for supported `init-params` 
of the servlet class `ch::nevis::isiweb4::servlet::connector::websocket::WebSocketServlet`.

# SamlSpConnector_subject

Set to use a different subject for the SAML `Assertion`.

Examples:

- `${sess:ch.nevis.session.loginid}` - what the user has entered to login


# TokenHeaderPropagation_token

Assign a Token pattern.

The referred pattern must be assigned to the correct Realm pattern(s).


# AuthServiceBase_allowedMethods

Define the allowed HTTP methods. 

If not configured, all HTTP methods are allowed.


# 8.2405.0

Full changelog:

[Patterns 8.2405.0 Release Notes - 2024-05-15](https://docs.nevis.net/nevisadmin4/release-notes#patterns-824050-release-notes---2024-05-15)

##### Removed FIDO Facets

The following 2 values have been removed from the default facets in nevisFIDO UAF Instance:
- `android:apk-key-hash:z7Xkw62dAn/BsckOQ9a3OMhmlwhzdr2VkcswIIyJgJE`
- `ios:bundle-id:ch.nevis.accessapp.presales.k8s`

If your app uses any of these facets you have to configure them.


# TransformVariablesStep_onSuccess

Set the step to continue with after successful execution.

# HostContext_crsVersion

Allows to select the OWASP ModSecurity CRS version.

Available options are:

- `4.7.0`: newest version of CRS, uses Anomaly Scoring Mode, minimal CRS setup
- `3.3.5`: default and recommended setup, uses Anomaly Scoring Mode
- `3.3.2`: previous version of CRS, uses Anomaly Scoring Mode, kept for easier migration
- `custom`: allows to upload a custom rule set. See the `ModSecurity Rule Set` option for more information.

The following HTTP methods are allowed by default when selecting any of the included versions:
```
CHECKOUT, COPY, DELETE, GET, HEAD,
LOCK, MERGE, MKACTIVITY, MKCOL, MOVE, OPTIONS,
POST, PROPFIND, PROPPATCH, PATCH, POST, PUT, TRACE, UNLOCK
```

# SamlIdpConnector_decryptionKey

Assign a pattern to configure the private key to decrypt the incoming message of the identity provider.

# RealmBase_cookieSameSite

In February 2020 Chrome 80 has been released which treats cookies without SameSite flag as `Lax`.

This change can break cross-domain use cases (e.g. SAML).

Thus, it is recommended to select `None` here. 

If `None` is selected, and you have to support older browsers also check `Cookie Same Site Relaxation`.

If you do not expect any requests from other domains, you may also go for `Lax` or `Strict` as this increases security.


# NevisIDMDeployable_mailSenderAddress

The default sender address for e-mails.

# NevisAuthRealm_auth

Assign a `nevisAuth Instance` pattern.

# ApplicationProtectionDeployableBase_bindHost

Enter a custom host name to listen on.

This setting is relevant in classic VM deployment,
when working with multi-homed target hosts.

In Kubernetes the component listens on `0.0.0.0`
and thus this setting is discouraged.

# URLHandler_redirects

Terminate requests by returning a _HTTP Redirect_ (status code `302`).

In the first column (_source_) enter the current location.
In the second column enter the destination to redirect to.

The following formats are supported:

- `URL`
- `absolute path` (starting with `/`)
- `relative path`

Regular expressions are supported in the source, 
and group extractions may be used in the destination.

Absolute paths always point to the host,
while relative paths are appended to the path of the assigned host (`/`) or application.

The order of the rules matters. 
Only the first matching rule is applied. 

Examples: 

| Source         | Destination            | Description                                                    |
|----------------|------------------------|----------------------------------------------------------------|
| `http://(.*)`  | `https://$1`           | redirects plain HTTP to HTTPs, preserving the request path     |
| `(.*)?lang=de` | `de/$1`                | put query parameter into request path                          |
| `/nevis.html`  | `https://www.nevis.ch` | redirect requests to a certain HTML page to a different domain |


# NevisMetaDatabase_type

Choose between `MariaDB` and `PostgresSQL`.

We recommend to use `MariaDB` as it is supported by all Nevis components that have a database.

**Note:** `PostgresSQL` database is only experimental configuration.


# NevisAuthDatabase_type

Choose between `MariaDB` and `PostgresSQL`.

We recommend to use `MariaDB` as it is supported by all Nevis components that have a database.

**Note:** `PostgresSQL` database is only experimental configuration.


# SamlIdpConnector_transitions

Add or overwrite `ResultCond` elements in the `ServiceProviderState` state.

This setting is advanced. Use without proper know-how may lead to incorrect behavior.

If you use this setting, we recommend that you contact Nevis to discuss your use case.

The position refers to the list of `Additional Follow-up Steps`. The position starts at 1.

Examples:

| `ResultCond`                 | Position |
|------------------------------|----------|
| status-Responder             | 1        |
| status-Responder-AuthnFailed | 2        |

The following `ResultCond` elements cannot be overruled by this setting:

* `ok`
* `logout`
* `logoutCompleted`
* `logoutFailed` 


# NevisKeyboxProvider_validation

Allows to the validation in case the nevisKeybox is deployed by this project (e.g. using `Generic Deployment`).

# SocialLoginExtender_onFailure

The step that will be executed if the authentication fails.
If no step is configured here the process ends with `AUTH_ERROR`.

# NevisProxyDeployable_cacheSize

Configures the approximate size of the Apache SSL Cache.

The minimum allowed value is `1 KB`. The maximum is `100 MB`.

If not, the default from Apache is used.


# NevisAdaptAuthenticationConnectorStep_onMediumRisk

Will be considered only if `Profile` is set to either `balanced`, `strict` or `custom`.

Set the step to continue with if the calculated risk score exceeds the Medium threshold.

In case it remains unset:
1. `On High Risk` becomes mandatory
2. Applies the same next step as `On Success`

# LdapLogin_onInvalidPassword

Assign an authentication step to be processed if the user is found but the password is incorrect.

Use for custom reporting or error handling.

If no step is assigned the GUI is displayed again and an error message will be shown.

This setting is experimental and may be adapted in future releases.

# GenericAuthXmlServiceBase_auth

Assign a `nevisAuth Instance`.

# WebhookCalls_onFailure

Assign the next authentication step (optional).

# SamlToken_attributes

Define which nevisAuth `session variables` to include as `attributes` in the SAML assertion.

If not set the following default will be used:

| Attribute  | Session Variable              |
|------------|-------------------------------|
| userid     | ch.nevis.session.userid       |
| loginId    | ch.nevis.session.loginid      |
| profileId  | ch.adnovum.nevisidm.profileId |
| clientId   | ch.adnovum.nevisidm.clientId  |

Which session variables are available depends on your authentication flow.
For instance, if you use `nevisIDM Password Login` there will be a session variable
`user.email` so you can easily add an attribute `email`.

Set the log level of `Vars` to `INFO` and check the `esauth4sv.log` 
to find out which session variables are available after authentication.

In case a session variable is not found the attribute will be omitted.


# NevisProxyDeployable_defaultHostContext

The default virtual host of this nevisProxy instance. 

The default will be used for requests without a `Host` header
or if there is no host with a corresponding frontend address.

# MultipleFieldUserInput_buttons

Assign an `Dispatcher Button` to add a button which points to a different authentication step.

# NevisAdaptRestServiceAccess_adapt

Reference to the nevisAdapt Instance pattern.


# PemTrustStoreProvider_dirName

Enter a name for the trust store directory 
which is used instead of the pattern name.

This configuration may be used to prevent trust stores overwriting each other 
and is only required in complex setups with multiple projects or inventories.

# ServiceBase_token

Propagate a token to the backend application. 
The token informs the application about the authenticated user.

For instance, assign `NEVIS SecToken` if the application uses Ninja or
`SAML Token` for applications which are able to consume SAML Responses.

# NevisIDMDatabase_parameters

Enter parameters for the DB connection string.

Enter 1 parameter per line.

Lines will be joined with `&`.

When connecting to a MariaDB database some query parameters will be added when not present.
The following parameters will be enforced then:

```
pinGlobalTxToPhysicalConnection=1
useMysqlMetadata=true
cachePrepStmts=true
prepStmtCacheSize=1000
```


# KeyObject_revocation

Define the `revocation` attribute of the `KeyObject`.

You can enter a path or URL of the certificate revocation list or the URL to the OCSP service.

See [Generic key material configuration attributes](https://docs.nevis.net/nevisauth/setup-and-configuration/components/authentication-engine/certificates-keys-and-public-key-infrastructure/certificate-validation#generic-key-material-configuration-attributes) for examples.


# ApplicationProtectionDeployableBase_secTokenTrustStore

Assign the Trust Store provider for verifying the NEVIS SecToken. If no pattern is assigned the signer key will be provided by the nevisAdmin 4 PKI.

# GenericAuthenticationStep_resources

Upload additional configuration files or scripts required by your `AuthState` configuration.
Uploaded files will be deployed into the `conf` directory of the nevisAuth instance.

# CustomProxyLogFile_conditionalLogLevels

Can be used to configure log levels based on conditions.

Example:
```
Condition:REMOTE_ADDR:CIDR/10.4.12.0/24/
Pragma: block-begin
BC.Tracer.DebugProfile.NavajoOp=4
BC.Tracer.DebugProfile.IsiwebOp=4
BC.Tracer.DebugProfile.IW4IdentCreaFlt=4
Pragma: block-end
```



# NevisProxyDeployable_restartPolicy

Determines the instance behaviour when a configuration change triggers an optional restart.

Select one of:

- `eager` - the instance will restart when deploying the new configuration;

- `lazy` - the instance will skip optional restarts.

# OAuth2AuthorizationServer_authorizationEndpoint

This is the path where relying parties redirect the browser to.

Example use cases:

- **OAuth**: acquire an access and refresh tokens
- **OpenID Connect**: acquire access, refresh and ID tokens

Use the `exact:` prefix to expose only the given path.
Without this prefix sub-paths will be accessible as well.
This is because a normal mapping with `/*` at the end will be created in nevisProxy.


# HeaderCustomization_requestHeadersRemove

Removes HTTP headers from requests.

The syntax is: `<header name>`

Examples:

```
User-Agent
```

Note: change the `Filter Phase` to remove headers early / late.

# SocialLoginBase_onUserNotFound

Configure the authentication flow to be executed when no user was found and the email provided by social account does not exist.
The authentication flow must contain the `Social Login Create User` pattern if a new user shall be created.

**Note**: Please select scope `email` and `profile` for getting user's information from social account.

# FIDO2Onboarding_attestation

Define the preference for [attestation conveyance](https://www.w3.org/TR/webauthn-2/#attestation-conveyance).

You can configure if you want an [attestation statement](https://www.w3.org/TR/webauthn-2/#attestation-statement).

- `none` - no attestation statement required.
- `direct` - receive an attestation statement as produced by the authenticator.
- `indirect` - requests an attestation statement but allows the client to modify what has been received from the authenticator (e.g. for anonymization).


# GenericDeployment_parameters

Define _Template Parameters_.

Examples:

```yaml
smtp: smtp.siven.ch
sender: noreply@siven.ch
```

These parameters can be used in:

* uploaded files matching an expression specified in the `Template Files` property
* the value of the `Path` property
* the value of the `Command` property

The expression formats are:

`${param.<name>}`:

- `name` found: parameter value is used.
- `name` missing: expression is **not** replaced.

`${param.<name>:<default value>}`:

- `name` found: parameter value is used.
- `name` missing: default value will be used.

In `<default value>` the character `}` must be escaped as `\}`.

# UnauthenticatedRealm_timestampInterval

Sets the minimum time interval between two updates of the session timestamp.

If the parameter is set to "0", the system will update the session timestamp each time a request accesses a session.

The `Initial Session Timeout` is used as `Update Session Timestamp Interval` if it is shorter than the duration configured here.

# NevisFIDODeployable_idm

Assign a `nevisIDM Instance` or `nevisIDM Connector` pattern.

Use `nevisIDM Connector` only when the nevisIDM instance is not setup by the same nevisAdmin 4 project.

When using `nevisIDM Connector` you have to use non-automatic key management.


# DeployableBase_deploymentHosts

The host group or Kubernetes service that this instance will be deployed to.
For testing purposes you can also enter a host name instead of a group.

For classic deployment, the host name / group must exist in the selected inventory.
For Kubernetes deployment, defining the service is optional in the inventory.


# NevisAuthRealmBase_defaultLabels

Choose between:

- `enabled` - add default translations for labels which are commonly used
(e.g. `title` or language labels in nevisLogrend, error labels in nevisAuth)
and which are required by the realm patterns (e.g. assigned authentication steps).

- `disabled` - select to only add what has been uploaded via `Translations`.
Note that if `Translations` are incomplete users may encounter untranslated labels.


# NevisAdaptDeployableBase_clientAuth

Setting for 2-way TLS on the nevisAdapt HTTPs endpoint. There are 3 options will
affect the callers (e.g. nevisProxy or technical clients accessing nevisAdapt REST APIs)

* required: Callers **must** present a client certificate.
* requested: Callers **can** present a client certificate.
* disabled: Callers **must not** use a client certificate.

The `Frontend Trust Store` must contain the issuing CA.

# NevisDetectPersistencyDeployable_port

Enter the port on which nevisDetect Persistency will listen.

# NevisIDMUserLookup_loginIdSource

Enter a _nevisAuth expression_ for the login ID 
which is used to look up the user.

Supported and required in authentication mode `pass-through` only.

Examples

- `${inargs:isiwebuserid}`

# NevisIDMGenericBatchJob_trigger

Add configuration of a bean which acts as a trigger for job execution. 

Execute every 24 hours:

```xml
<bean id="someTriggerId" class="org.springframework.scheduling.quartz.SimpleTriggerFactoryBean">
    <property name="description" value="Some description shown in nevisIDM Admin GUI"/>
    <property name="jobDetail" ref="someJobId"/> <!-- must be provided via Job(s) -->
    <property name="repeatInterval" value="86400000"/> <!-- 1 day in ms -->
    <property name="misfireInstructionName" value="MISFIRE_INSTRUCTION_RESCHEDULE_NEXT_WITH_EXISTING_COUNT"/>
</bean>
```

Execute once a day at midnight (cron expression):

```xml
<bean id="someTriggerId" class="org.springframework.scheduling.quartz.CronTriggerFactoryBean">
    <property name="description" value="Some description shown in nevisIDM Admin GUI"/>
    <property name="jobDetail" ref="someJobId"/> <!-- must be provided via Job(s) -->
    <property name="cronExpression" value="0 0 0 * * ?"/>
</bean>
```

# InBandMobileDeviceRegistration_nevisfido

Assign a nevisFIDO instance. 

This instance will be responsible for providing the device registration services.


# NevisIDMConnectorAddon_nevisIDM

The nevisIDM instance that the generated `AuthState` should connect to.


# NevisIDMURLTicketConsume_onNotFound

Assign an authentication step to execute when the URL ticket is **not found**.

If not set a screen with `title.url_ticket` and `error.url_ticket.not_found` will be shown in that case.

# TANBase_guiName

Change the `name` of the `Gui` element.

Change this only if you need the Gui name your login template to render the screen differently.


# MobileDeviceDeregistration_nevisfido

Assign a `nevisFIDO UAF Instance`. This instance will be responsible for providing the mobile device deregistration services.

# NevisLogrendDeployable_keyStore

Used when simple or mutual (2-way) HTTPs is configured.
If no pattern is assigned here automatic key management will provide the key store.

# NevisAuthRealmBase_labelsMode

Choose between:

- `combined` - upload 1 file per language code named `labels_<code>.properties`. 
The labels will be added to both nevisAuth and nevisLogrend. 
Alternatively, you can upload a zip file called `labels.zip` containing these properties files.

- `separate` - select *only* when you need different labels in nevisAuth and nevisLogrend.
The files must be called `LitDict_<code>.properties` for nevisAuth and `text_<code>.properties` for nevisLogrend.
Alternatively, you may upload zip file called `LitDict.zip` and `text.zip` containing these properties files.


# SamlIdp_sp

Define the SAML Service Providers which can use this IDP.

For each SP an own `AuthState` of class `IdentityProviderState` will be generated.

# NevisProxyDeployable_restartCondition

Enter an expression to prevent nevisProxy from being restarted even if the configuration changes.

nevisProxy will only be restarted if the exit status is `0`.

The expression must always terminate.

In Kubernetes deployment this setting is ignored.

A use case where this is required is when nevisProxy is deployed to multiple hosts
and listens on a shared IP which is bound on 1 host only.

```
ip address show dev eth1 | grep -q "172.29.0.5"
```

Example for multiple shared IPs:

```
ip address show dev eth1 | egrep -q "172.29.0.5|172.29.0.6"
```

Recommendations:

- Run the command manually on the target host to be sure that it works for you.
- You can check the exit status of the last command by running `echo $?`





# NevisMetaServiceAccessBase_realm

Assign a realm pattern which authenticates access to nevisMeta.

# KerberosLogin_onFailure

Assign authentication step that is processed if Kerberos authentication fails.

If no step is assigned an AuthState `Authentication_Failed`
will be created automatically.

# HostingService_defaultFile

Defines a default file which will be returned when there is no other matching file.

# SwissPhoneChannel_backendTrustStore

Assign a trust store for the outbound TLS connection to SwissPhone.

Import the CA certificate of the `Portal Server` into this trust store.

Since version 4.38 nevisAuth trusts CA certificates included in the JDK.

Thus, it is not required to configure this. 

However, you can still configure a trust store here to be as strict as possible.


# AuthCloudBase_skipType

The type of element which allows the user to skip this step.

The element is usually a button but may also be changed to an `info` text.
As info elements may contain HTML you can display a link that behaves like a button.


# NevisDetectLogSettings_maxBackupIndex

Maximum number of backup files to keep in addition to the current log file.
When `Rotation Type` is `time`, this property is used as Logback's [maxHistory](https://logback.qos.ch/manual/appenders.html#tbrpMaxHistory) property.
This means that logs will be archived for this number of time units where time unit is as defined in `Rotation Interval`.

# OAuth2UserInfo_host

Assign a `Virtual Host` which shall serve as entry point.

# SamlIdp_logoutConfirmation

Choose between:

- `enabled` - shows a logout confirmation screen when the path ends with `/logout`
- `disabled` - never shows a logout confirmation screen

Please be aware that we plan further changes which affect SAML logout 
and thus this setting may change or even disappear in a future release.


# Dispatcher_conditions

Configure _conditions_.

The first column gives your condition a name.
The name must be unique and must be used in `Transition(s)`.

In the second column enter an _expression_.
This may be a nevisAuth expression (`${...}`) or EL expression (`#{...}`).
See nevisAuth Technical Documentation for information about the expression syntax.

In EL expressions it is possible to reference variables from the inventory,
an example can be found below.

All conditions will be evaluated and thus multiple conditions may apply.
In this case the combination of conditions in must be configured in `Transition(s)`.

Examples:

| Key     | Value                                                 |
|---------|-------------------------------------------------------|
| pwreset | `${request:currentResource:/pwreset:true}`            |
| sp      | `${sess:ch.nevis.auth.saml.request.issuer:^SP$:true}` |
| mfa     | `#{${var.mtanEnabled} or ${var.oathEnabled}}`         |


# OAuth2Client_type

Reserved for ID Cloud use.

# CustomNevisMetaLogFile_regexFilter

If set, messages for `nevismeta.log` which match the given regular expression won't be logged.

The regular expression must match the entire line.
For instance, you may use the following format to match `some text`:

```
.*some text.*
```


# NevisIDMPasswordCreate_credentialState

The state which the credential is in when created. Options:

* INITIAL
* ACTIVE
* DISABLED


# NevisIDMWebApplicationAccess_requestValidation

- `off` - no request validation
- `standard` - uses ModSecurity OWASP Core Rule Set (CRS) with default paranoia level 1 - Basic security
- `custom` - configure `Request Validation Settings` via `Additional Settings`
- `log only` - uses `standard` in log only mode


# NevisDetectEntrypointDeployable_port

Enter the port on which nevisDetect Feature Correlator will listen.

# CustomProxyLogFile_logFormat

Allows the configuration of the `LogFormat` Apache directive in the navajo.xml file.

For more information, check the [official Apache documentation](http://httpd.apache.org/docs/current/mod/mod_log_config.html#logformat) of the directive.

# NevisAuthDeployable_idPregenerate

Define the value of the `idPregenerate` attribute.

- `enabled`: `true` is set.
- `disabled`: `false` is set.

Do not change this unless you know what you are doing.


# WebhookCalls_onSuccess

Assign the next authentication step (optional).

# ServiceAccessBase_allowedMethods

Define the HTTP methods allowed for this application. 

Methods which are listed here must also be allowed on the `Virtual Host`.

You may also use the following method groups:

* `ALL-HTTP` includes common HTTP methods.

  These are: `GET, POST, HEAD, DELETE, TRACE, CONNECT, OPTIONS, PUT, PATCH`

* `ALL-WEBDAV` includes all methods required for WebDAV.
  
  These are: `MERGE, UNCHECKOUT, MKACTIVITY, PROPPATCH, LOCK, CHECKOUT, SEARCH, COPY, MKCOL, MKWORKSPACE, PROPFIND, UPDATE, REBIND, BASELINE-CONTROL, UNBIND, CHECKIN, VERSION-CONTROL, UNLOCK, LABEL, MOVE, ACL, BIND, REPORT` 

To remove methods from `ALL-HTTP` and `ALL-WEBDAV` simply add the method with a `-` sign in front of it.

# NevisIDMDeployable_defaultLanguage

Sets default language for nevisIDM.

It is the same as using `web.gui.languages.default` in `properties`.
If given by both way, the value in `properties` will be used.

See nevisIDM Reference Guide (chapter Configuration files) for details.

# AuditChannel_properties

Provide configuration for the audit channel.

For each key-value pair 1 `property` element will be generated.


# Button_onClick

Assign an authentication step to continue with when the button is clicked.

# NevisIDMDeployable_mailSMTPHost

The name of the host on which the SMTP server is running.

# TCPSettings_keepAliveLifetime

The absolute lifetime of a TCP connection. This should be configured to less than the connection lifetime allowed by the firewall between nevisProxy and the content providers. By leaving this field empty, you will be using the nevisProxy default value.


# SamlToken_properties

Enter custom properties for the nevisAuth `IdentityProviderState`
which issues the SAML `Response` (or `Assertion`).

Please check the technical documentation for details.

Common use cases are:

- `out.issuer`: sets the `Issuer` element (By default, the sanitized name of the pattern is used)
- `out.audienceRestriction`: some recipients require this to be set to decide if they accept the token
- `out.signatureKeyInfo`: add information about the signer certificate

Examples:

```
out.authnContextClassRef = urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
out.sessionIndex = ${notes:saml.assertionId}
out.signatureKeyInfo = Certificate
out.subject.format = urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
out.ttl = 10
relayState = ${request:currentResource}
```

# InBandMobileAuthenticationRealm_signerTrustStore

Defines the trust store nevisProxy uses for validating the signature of the NEVIS SecToken issued by nevisAuth.

# NevisDetectDeployableBase_jmsClientKeyStore

Used when simple or mutual (2-way) HTTPs is configured.
If no pattern is assigned here automatic key management will provide the key store.

# NevisMetaDeployable_database

Assign a `nevisMeta Database`.


# NevisIDMDatabase_oracleDataTablespaceName

Name of the data tablespace for the oracle database. It's recommended to keep the default value unless the pattern is used with an existing database that has a different one.

# SamlSpConnector_sign

Configure what to sign.

The setting `none` is not recommended for productive setups as it is vulnerable to attacks.

The setting `Assertion` may require additional checks on service provider side to close the attack vector.
For instance, count the number of `Assertion` elements in the message.

When `recommended` is selected the signed element depends on the `Outbound Binding`:

- `http-redirect`: nothing will be signed as signing is not supported.
- `http-post`: the `Response` is signed as this is most secure.


# NevisAuthRadiusFacade_inputs

Define how attributes from Radius requests 
are mapped to input arguments (`inargs`) for nevisAuth.

There are some well-known input arguments which you may have to provide:

- `isiwebuserid` - entered user name
- `isiwebpasswd` - entered password
- `mtanresponse` - used in mobile TAN patterns

Examples:

| Radius Attribute | Input                          |
|------------------|--------------------------------|
| User-Name        | `isiwebuserid`                 |
| User-Password    | `isiwebpasswd`, `mtanresponse` |
| State            | `sessionid`                    |

Depending on your authentication flow it may be required to provide additional input arguments.


# GenericWebBase_phase

When adding `filter-mapping` elements, a phase must be defined.

The phase defines where the `filter-mapping` is placed in the `web.xml` and ensures that filters
are applied in the right order, relative to other phases.

The order within a certain phase is undefined as it must **not** matter.

The order for requests is `START` to `END` and `END` to `START` for responses.

This setting applies to all `filter-mapping` elements. 

The `filter-mapping` elements may be provided via _Filters and Servlets_,
or created automatically (see `Filter Mappings` for details).

Choose from the following filter phases:

- `START`: applied as early as possible for requests and as late as possible for responses.
- `BEFORE_SANITATION`: applied before filters which validate the request (e.g. Mod Security).
- `SANITATION`: used for security. This is the first phase which allows accessing the session for applications protected by a realm.
- `AFTER_SANITATION`: your request has passed security checks.
- `BEFORE_AUTHENTICATION`: applied just before authentication. 
- `AUTHENTICATION`: used by the filter which connects to nevisAuth for applications which are protected by an `Authentication Realm`.
- `AFTER_AUTHENTICATION`: the request has level 1 authentication. Used by `Authorization Policy` for `Authentication Level` stepup.
- `BEFORE_AUTHORIZATION`: choose this phase to do preprocessing before authorization.
- `AUTHORIZATION`: used by `Authorization Policy` for `Required Roles` check.
- `AFTER_AUTHORIZATION`: used by patterns assigned as `Application Access Token` to applications.
- `END`: applied as late as possible for requests and as early as possible for responses.

This setting is ignored when you patch a `filter` generated by another pattern 
(e.g. by adding, overwriting, or removing an `init-param` element) but don't create any `filter-mapping` element.

# KerberosLogin_onSuccess

Configure the step to execute after successful authentication.
If no step is configured here the process ends
and the user will be authenticated.

# HostContext_earlyHints

Enables the HTTP/2 feature of early hints.

Configures early hints with the Apache directive [H2PushResource](https://httpd.apache.org/docs/2.4/howto/http2.html#earlyhints)

It will send out a "103 Early Hints" response to a client as soon as the server starts processing the request.

# UnauthenticatedRealm_sessionTimeout

Defines the idle timeout of a nevisProxy session.

A nevisProxy session will be created only if required (e.g. to store application cookies).

Please set the timeout as low as possible to not increase the risk of session exhaustion attacks.

Nevis recommends not to exceed the default. **A high session timeout in Unauthenticated Realm is strongly discouraged as it opens the door to DoS attacks: nevisProxy can be brought down by creating millions of sessions with simple GET requests.**

# FIDO2Onboarding_residentKey

WebAuthn enables high assurance multi-factor authentication with a passwordless login experience. 
One of the things that enables this is what is called Discoverable Credentials, also referred to as resident keys.
This property specifies the extent to which the Relying Party desires to create a client-side discoverable credential.

Allowed values:

- `unspecified`
- `discouraged`
- `preferred`
- `required`


# NevisAuthRadiusFacade_secret

Enter a secret to be used for this facade and all Radius clients.

# NevisAuthRealm_onDemand

Applications may be configured to trigger a session upgrade flow.

Here you assign the authentication steps which provide these session upgrade flows.
This mechanism also works when the realm is accessed via a `SAML IDP`.

The process of selecting and executing a flow is as follows:

An application's `Authorization Policy` specifies the required authentication level (`2`-`9`) which is needed to access the application.
(Level `1` is not allowed here, as the session has at least level `1` after the user successfully completes the initial authentication flow.)

Every time the user accesses the application, the policy is enforced as follows:

- If the authentication level of the current session is lower than the level required by the policy, 
nevisAuth is invoked to execute a session upgrade flow - the one which provides the required level.
 
- Only if the flow runs through successfully, the level reached is stored in the session and access is granted.

- If the level of the session equals, or is higher than the required level, access is granted immediately.

- Authentication steps assigned here are executed only if the required level (by policy) 
  exactly matches the provided value in its `Authentication Level` property. 
  For example, if level `3` is required, the authentication step directly providing that level is started.
  
It is possible, in a multi-step flow, that the required authentication is reached only after the second step or later.
In this case, assign `Advanced Session Upgrade` as the first step. 
In this step, you declare the level that should ultimately be reached by the flow.
The engine can then match the required level to the one provided by the flow, 
even if it is not provided by the first authentication step in the flow.

When no flow can be determined the `Default Session Upgrade Flow` will be used instead.


# MicrosoftLogin_scope

Select the request scope(s) for getting user information from Microsoft. Default scopes is `email`.

Scope `openid` will be added automatically because Microsoft is implement based on OpenID protocol.

Scope `offline_access` for generate refresh token.

# SamlSpConnector_acsUrlWhitelist

By default, the whitelist is calculated based on `SP URL - Assertion Consumer Service(s)`.
But in some special cases, you can use wildcards to allow a wide range of whitelisted urls. Examples:
* *.mydomain.com
* mydomain.com*

# TANBase_tanFormat

The format of the TAN sent to the user. 
For instance, with `5 digits`, the generated TAN will always consist of 5 numerical digits (e.g. `12345`).


# SAPLogonTicket_systemClient

Identifier of client. See SAP documentation of SAP SSO logon tickets for more information. Default value is SAP's default and should be correct for most cases.

# NevisIDMChangePassword_newPassword1

Mandatory input value to use for new password if `Show GUI` is disabled.

# OAuth2AuthorizationServer_allowedOrigin

List of URL from where that allow to access the `authorization` endpoint and `token` endpoint.
If this field does not set, `authorization` endpoint and `token` endpoint can be access from everywhere.  

# URLHandler_phase

The phase when this filter should be applied depends on your use case.

- use `START` when the redirect / rewrite should be done as early as possible.
- use `AFTER_SANITATION` to redirect / rewrite after validating the request.
- use `AFTER_AUTHENTICATION` to redirect / rewrite after authentication.

# NevisDPDeployable_resourceBase

Configure the base directory for uploaded `Custom Resources`.

Enter a path relative to the instance directory, such as `conf` or `import`.

Absolute paths and nested paths are not supported.


# SamlResponseConsumer_samlSigner

Configure the key material for signing outbound SAML messages.

The following messages will be signed: `ArtifactResolve, LogoutRequest, LogoutResponse`

##### SAML Artifact Binding

To use SAML Artifact Binding with a certain IDP,
the `Artifact Resolution Service` must be configured in the `SAML IDP Connector`.

The flow begins with the IDP sending an `ArtifactResponse` message to any of the configured frontend paths.

Now an `ArtifactResolve` message will be created and signed using this certificate.
The message will then be sent to the IDP via a server-to-server call.

# SamlSpRealm_logoutReminderRedirect

Enter a URL or path to redirect to when a user accesses, and the session has expired.

The redirect is executed on next access in the following cases:

- the user has closed the browser
- user session has expired due to idle timeout

The following requirements must be fulfilled:
 
- Usage of HTTPs to access the application and for the entire SAML process.
- No other session expiration feature must be used.

# SecurosysKeyStoreProvider_certObjectLabel

The certificate objects label on the HSM.

# AuthorizationPolicy_level

The `Authentication Level` defines the strength of authentication.
Enter a number between `2` and `9` (including).

If the session is not yet at the configured level
a session upgrade will be performed.

Level `1` is the weakest possible authentication.
By definition this level is reached by the initial authentication flow,
e.g. set by a username / password authentication step (e.g. `LDAP Login`).

Level `2` is the default level set by steps
which do second factor authentication (e.g. `Test TAN`).

Levels `3` to `9` are not used by default. These levels
may be used for additional session upgrade processes.

For the session upgrade to succeed there must be a step which set at least this level.
This step must be assigned to `Session Upgrade Flow(s)` in the `Authentication Realm` pattern.

In case the upgrade flow consists of multiple steps 
and the level should be reached by a subsequent step
assign the `Advanced Session Upgrade` pattern instead.

The authentication level defined for an application can be overridden for a sub-path by combining several `Authorization Policy` patterns for this application.
The authentication level can also be inherited between patterns. See `Authentication Level Mode` for details.

This setting requires assigning an `Authentication Realm` on the application pattern.

Usage examples:
- Enforce an authentication level for an application:
  use an `Authorization Policy` pattern with the `Authentication Level` to enforce and link it to the application via `Additional Settings`;
- Enforce an authentication level for some sub-paths of an application:
  use an `Authorization Policy` pattern with the `Authentication Level` to enforce and `Apply only to sub-paths` set to the paths to protect. Link the pattern to the application via `Additional Settings`;
- Enforce some main authentication level for an application and some specific authentication level for some sub-paths:
  use two `Authorization Policy` patterns, one with the main `Authentication Level` and no sub-path, and one with the specific `Authentication Level` and `Apply only to sub-paths` set to the paths where the specific authentication level should apply. Link both patterns to the application via `Additional Settings`.
- Enforce some main authentication level for an application and disable them for some sub-paths:
  use two `Authorization Policy` patterns, one with the main `Authentication Level` and no sub-path, and one with no `Authentication Level` and `Apply only to sub-paths` set to the paths where no authentication level should be enforced. Link both patterns to the application via `Additional Settings`.
- Enforce an authentication level for an application and add some required roles for some sub-paths:
  use two `Authorization Policy` patterns, one with the `Authentication Level` for the application, `Authentication Level Mode` set to `self-contained`, and no sub-path, and the other pattern with no `Authentication Level`, `Authentication Level Mode` set to `inherited`, the `Required Roles` for the subpaths, `Required Roles Mode` set to `self-contained`, and `Apply only to sub-paths` set to the paths where the required roles should be enforced. Link both patterns to the application via `Additional Settings`.


# LuaPattern_script

Upload a Lua script which should be invoked for requests and / or responses.
The script has to contain one or multiple of the following Lua functions:

- `function inputHeader(request, response)` - called once per request
- `function input(request, response, chunk)` - called once per request body _chunk_
- `function outputHeader(request, response)` - called once per response
- `function output(request, response, chunk)` - called once per response body _chunk_

The uploaded script will be deployed to the nevisProxy host in sub-directory `WEB-INF` using
the name of this pattern for the file name to ensure that the file name is unique.

Here is an example Lua script which replaces sensitive information in response bodies:

```
local buf = {}
function output(request, response, chunk)
  if chunk ~= nil then
    table.insert(buf, chunk)
    return nil
  else
    return string.gsub(table.concat(buf), "some-sensitive-data", "*****");
  end
end  
```

The following expressions can be used anywhere within the script:

- `${name}` - sanitized name of this pattern
- `${host}` - name of the `Virtual Host` directory
- `${instance}` - name of the `nevisProxy Instance` directory



# JWTToken_secret

Enter a shared secret to be used for symmetric algorithms.

This is required for `JWS` because of the `HS256` algorithm.

# SamlToken_issuer

Enter the `Issuer` which will be used to create the token.

If nothing is configured the name of the pattern is taken.

# OAuth2AuthorizationServer_invalidTokenRequest

Configure the step to execute after error when token request is invalid and token error response is about to be issued.

If no step is configured here the process ends and the error response issued and return to the client.

# NevisLogrendDeployable_port

Enter the port the nevisLogrend shall listen on.

# NevisFIDO2Database_schemaPassword

The password of the user on behalf of the schema will be created in the database.

# NevisIDMProperty_maxLength

Enter `maxLength` for the property definition file.

Defines the maximum length of the property value.

# NevisDetectServiceAccessBase_realm

Mandatory setting to enforce authentication.

# NevisAuthRealmBase_templateMode

Choose between two options:

- `additive`: files uploaded as `Login Template` will be added on top of the default.
Use this option when you want to **add** or **replace** files, but don't want to upload an entire template.
There will be less work when you upgrade.

- `complete`: **only** the files uploaded as `Login Template` will be deployed.
Use this option when you want to provide the entire template.


# NevisDetectMessageQueueDeployable_port

Enter the port on which nevisDetect MQ will listen.

# RoleCheck_roles

Enter 1 or multiple roles, 1 role per line.

If the user has **any** of these roles, the flow will continue with `Found`.

If the user has **none** of these roles, the flow continues with `Not Found` instead.

Roles managed in nevisIDM have the format `<application>.<name>`.

Examples: 

- `MyApp.Admin`
- `nevisIDM.Root`


# NevisAdaptAnalyzerConfig_deviceFingerprintAnalyzer

Used to disable Device Finger creation and
analysis.


# CookieCustomization_conflictResolution

When multiple `Cookie Customization` patterns are used it happen that 
a certain cookie is defined as both a `Client Cookie` and as a `Shared Protected Cookie` 
for the same application.

By default, this conflict is resolved by allowing the cookie to `pass-through`, treating it as a `Client Cookie`.

This behaviour is usually more robust but less secure as the cookie will be accessible in the browser.

Select `protect` to threat the cookie as a `Shared Protected Cookie` instead.

# NevisIDMProperty_accessModify

Possible settings:

* `READ_WRITE`: Input is possible for the if previous value was stored.
* `READ_ONLY`: Field is read only.
* `OFF`: Field is not updatable and property is not displayed GUI.

Users with `AccessControl.PropertyAttributeAccessOverride` can edit these field regardless of this settings.

# SocialLoginBase_userId

Logged userId will automatically get from social account. But you can change the userId by using this field.

# NevisIDMPasswordLogin_customFinalRedirect

Enter a URL, path, or nevisAuth expression which defines where to redirect to
after the new password has been set. 

# NevisKeyboxProvider_slot

A `Slot` is a directory of a nevisKeybox instance.

By default, nevisKeybox is located at `/var/opt/neviskeybox/default/`.
If missing please run the following command on the affected target server(s):

`neviskeybox handover`

A `Slot` may contain:

- an arbitrary number of key stores (identified by label)
- up to 1 trust store.

# AccessRestriction_dbFile

IP geolocation database file for country filtering. 

Currently only the `mmdb` format (MaxMind Database) is supported. This is a binary file format.


# SamlSpRealm_timeoutRedirect

Enter a URL or path to redirect to after session timeout.

The redirect is executed on next access when the session has expired.

This is different from the `Logout Reminder Redirect` feature 
which also performs the redirect when the user comes back after closing the browser.

For this feature an additional cookie `Marker_<name>` will be issued.
The value will be set to `login` or `logout` depending on the last user action.

The following requirements must be fulfilled:
 
- Usage of HTTPs to access the application and for the entire SAML process.
- No other session expiration feature must be used.

# AzureServiceBus_expiry

Remote Azure Service Bus Queue to which Expiry messages should be sent.

Messages in Expiry Queue are those messages which validTo time has passed without successful receive action and without failing for other reason.
For further reference check `NevisIdm Technical documentation > Configuration > Components > Provisioning module > Provisioning providers`.

# OutOfBandManagementApp_host

A virtual host assigned will be used to expose services required for ```Out-of-band Management Application```.

# AuthorizationPolicy_forbiddenRoles

Optional setting to enforce authorization.

Callers must not have any of the specified roles to access.

Forbidden roles defined for an application can be overridden for a sub-path by combining several `Authorization Policy` patterns for this application.
Forbidden roles can also be inherited between patterns. See `Forbidden Roles Mode` for details.

This setting requires assigning an `Authentication Realm` on the application pattern.

Usage examples:
- Enforce forbidden roles for an application:
  use an `Authorization Policy` pattern with the `Forbidden Roles` to enforce and link it to the application via `Additional Settings`;
- Enforce forbidden roles for some sub-paths of an application:
  use an `Authorization Policy` pattern with the `Forbidden Roles` to enforce and `Apply only to sub-paths` set to the paths to protect. Link the pattern to the application via `Additional Settings`;
- Enforce some main forbidden roles for an application and some specific forbidden roles for some sub-paths:
  use two `Authorization Policy` patterns, one with the main `Forbidden Roles` and no sub-path, and one with the specific `Forbidden Roles` and `Apply only to sub-paths` set to the paths where the specific forbidden roles should apply. Link both patterns to the application via `Additional Settings`.
- Enforce some main forbidden roles for an application and disable them for some sub-paths:
  use two `Authorization Policy` patterns, one with the main `Forbidden Roles` and no sub-path, and one with no `Forbidden Roles` and `Apply only to sub-paths` set to the paths where no forbidden roles should be enforced. Link both patterns to the application via `Additional Settings`.
- Enforce some forbidden roles for an application and add an authentication level for some sub-paths:
  use two `Authorization Policy` patterns, one with the `Forbidden Roles` for the application, `Forbidden Roles Mode` set to `self-contained`, and no sub-path, and the other pattern with no `Forbidden Roles`, `Forbidden Roles Mode` set to `inherited`, the `Authentication Level` for the subpaths, `Authentication Level Mode` set to `self-contained`, and `Apply only to sub-paths` set to the paths where the authentication level should be enforced. Link both patterns to the application via `Additional Settings`.


# JWTToken_type

The following types of JWT token are supported:

- `JWS`: JSON Web Signature - using `HS256` or `HS512` algorithm
- `JWE`: JSON Web Encryption - using `RSA-OAEP-256` and `A256GCM` algorithm

Note: in case asymmetric encryption is used, the `x5t#S256` Certificate thumbprint header parameter will automatically be added
according to [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.8).

# PemKeyStoreProvider_keystoreFiles

Upload your key material in PEM format.

| File name      | Description     | Required                        |
|----------------|-----------------|---------------------------------|
| `key.pem`      | private key     | yes                             |
| `cert.pem`     | own certificate | yes                             |
| `ca-chain.pem` | CA chain        | when providing a HTTPS endpoint |

### Examples

How to produce the required files depends on your setup. 
The following examples use `openssl`.

Generate a private key:

```
openssl genrsa -des3 -out key.pem 2048
```

Generate a certificate signing request (CSR):

```
openssl req -new -key key.pem -out example.csr -subj "/C=CH/O=Example Company/CN=example.com"
```

If this key store is used to provide a HTTPs endpoint, 
the common name (CN) should contain the domain.

You can now use the CSR to request a certificate from your CA.
For testing a self-signed certificate is often sufficient:

```
openssl x509 -signkey key.pem -in example.csr -req -days 365 -out cert.pem
```

### Hardening

We recommend to use a _variable_ so that you can use **secrets** to protect the content.
This example references 2 _nevisAdmin 4 secrets_ storing private key and own certificate:

```
  my-variable: 
    - inv-res-secret://f370a14a36db9f29763e8dc1#key.pem
    - inv-res-secret://147cc54a5629fadac761ec01#cert.pem
```

When deploying to Kubernetes, the key material may be stored in a _Kubernetes secret_ instead.
nevisAdmin 4 does not retrieve Kubernetes secrets during generation and thus all key store files **must** be provided. 
This example uses a Kubernetes secret `my-secret`:

```
  my-variable: 
    - k8s-secret-file://my-secret:key.pem/
    - k8s-secret-file://my-secret:cert.pem/
    - k8s-secret-file://my-secret:ca-chain.pem/
    - k8s-secret-file://my-secret:keystore.pem/
    - k8s-secret-file://my-secret:keystore.jks/
    - k8s-secret-file://my-secret:keystore.p12/
    - k8s-secret-file://my-secret:keypass/
```

The additional `keystore.*` files contain private key, own certificate, and the CA chain.
You can use the Java `keytool` and `openssl` to produce these files.

The `keypass` file must be a script which is executable by `nvbgroup` 
and prints the passphrase for `keystore.*` and `key.pem` to stdout.

nevisAdmin 4 does not notice when the content of the Kubernetes secret changes.
Manual interaction (terminating pods) is required in that case.


# FIDO2Authentication_level

Authentication level that is set on success.


# DeployableBase_instanceName

Enter the instance name.

If not set, the pattern name will be used as the instance name.

When deploying to Kubernetes, this setting will be ignored and the instance name will be `default`.


# GenericSocialLogin_claimsRequest

The claims request parameter. This value is expected to be formatted in JSON and does not accept trailing spaces nor tabs.

# AuthCloudBase_loginMessage

You can set an optional custom message for the login confirmation step.

Only one language is supported here.

For example, `New login request for siven.ch`.


# AccessTokenConsumer_onMissingToken

Assign a step to continue with when no token was sent.

If nothing is assigned then authentication will fail with an error.


# OAuth2Client_idTokenLifetime

Enter a custom lifetime for the ID token.

If not set the value of the `OAuth 2.0 Authorization Server / OpenID Provider` is used.

# NevisAuthDeployable_signerTrustStore

Assign a trust store to validate the signature of the **internal** NEVIS SecToken.

This is an advanced setting and it is usually not required to configure this.

If no pattern, an `Automatic Key Store` pattern, or a `PEM Key Store`, 
is assigned to `Internal SecToken Signer Key Store`, then you **do not** have to configure this. 
The configuration of nevisAuth will be generated correctly, based on the deployment type and scaling.

Configuration is required in **classic VM deployment**, when this instance is deployed to multiple hosts,
**and** the hosts have **different** key material in the `Internal SecToken Signer Key Store`.


# SamlSpConnector_url

Enter the _Assertion Consumer Service URL_ of the SP.

Enter multiple values if the same SP can be accessed via multiple URLs.

If the SP is provided by a `SAML SP Realm` the URLs are structured as follows:

- scheme, host and port: `Frontend Addresses` of each `Virtual Host` where the `SAML SP Realm` is used.
- path component: `Assertion Consumer Service` of the `SAML SP Realm`.

The URLs are used during SP-initiated SAML authentication to validate incoming SAML requests.
The `assertionConsumerServiceURL` attribute of received SAML `AuthnRequest` messages must match one of these URLs.

The first URL is also used for IDP-initiated authentication (property `spURL` of the `IdentityProviderState`).

IDP-initiated authentication may be triggered by sending a request 
to any of the `Frontend Path(s)` of the `SAML IDP`.
The following parameters must be provided either in the query or as `POST` parameters:

- `Issuer` - the unique name used by the SP (also called `entityID` in the SAML metadata).
- `RelayState` - will be sent back to the SP together with the SAML `Response` when authentication is done. 
In case the SP is setup by a `SAML SP Realm` this should a URL of an application protected by this realm.


# SamlSpConnector_audienceRestriction

Set custom audience(s).

If you need multiple `<Audience>` elements in the generated `<AudienceRestriction>`, enter multiple lines.

This configuration is ignored when `Audience Restriction` is set to `issuer` or `none`.

Check the documentation of the service provider on what is expected.


# AuthServiceBase_path

Enter frontend path(s) which should be handled.

# MobileTAN_channel

The connection provider for the TAN transmission. 
Currently the only supported connection provider is a SwissPhone SMS Gateway.


# NevisDPLogSettings_serverLogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the default SERVER logs.

Note: not relevant when Log Targets is set to `syslog`.

# SAPLogonTicket_caching

If set to `enabled`, this property enables the `CachingAllowed` flag in the issued ticket. See SAP documentation of SAP SSO logon tickets for more information.

# NevisAdaptRememberMeConnectorStep_fingerprintJsVersion

This configuration option gives the administrator the ability to ensure backwards compatibility in
case so far V2 fingerprints have been in use.

* `V2` - to ensure backward compatibility, FingerprintJS V2 will be used
* `V3` - default option, uses FingerprintJS V3

# AccessTokenConsumer_authorizationServer

Assign the `OAuth 2.0 Authorization Server / OpenID Provider`
which has issued the access token.

Note that this step works in combination with Nevis `OAuth 2.0 Authorization Server / OpenID Provider`
only and the other pattern has to be in the same project.


# NevisMetaDeployable_properties

Configure properties of the nevisMeta.

**Add** or **overwrite** properties by entering a value.

**Remove** properties generated by this pattern by leaving the value empty.

Examples:

| Key                           | Value |
|-------------------------------|-------|
| database.migration.automatic  | false |


# SamlSpRealm_stepupPath

Applications may redirect to this location
to force the SP to invoke the IDP again by sending an `AuthnRequest`.

This mechanism allows applications to enforce a _session upgrade_.

The URL must contain the following query parameters:

- `relayState`: the path to redirect to after successful session upgrade.
- `level`: the required authentication level (`2-9`). The level will be sent to the IDP within the `RequestedAuthnContext`.

Tokens produced by `Application Access Token` patterns assigned to applications
will be re-created on next access to reflect updated user data.

Example for `RequestedAuthnContext` with `level=2`:

```xml
<saml2p:RequestedAuthnContext>
  <saml2:AuthnContextClassRef xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">urn:nevis:level:2</saml2:AuthnContextClassRef>
</saml2p:RequestedAuthnContext>
```


# NevisIDMPasswordLogin_emailRedirPathValidationMode

Defines how to validate the redirection path which sent in the password reset e-mail. The following modes are available:

* `Allow-list regexes`: Only paths that match the regexes are allowed. Only paths needs to be defined (For example in case of `https://your-domain.com/your-path`, only /your-path needs to be defined). Regexes can be defined in `Custom Redirection Path Validation Regexes`.
* `Deny-list Regexes`: All paths are allowed except those that match the regexes. Only paths needs to be defined (For example in case of `https://your-domain.com/your-path`, only /your-path needs to be defined).  Regexes can be defined in `Custom Redirection Path Validation Regexes`.

# TransformVariablesStep_variables

Set variables.

To find out which variables are available when a request comes in 
set the log level of `Vars` to `DEBUG` and check the nevisAuth log.

The following syntax variants are supported:

```
<scope>:<name> = 
<scope>:<name> = some value
<scope>:<name> = ${some-auth-expression}
<scope>:<name> = #{some-EL-expression}
```

The setting `On Empty Value` defines how null values and empty Strings shall be handled.

**Example**: store the query parameter `RelayState` in the session:

```
sess:RelayState = ${inargs:RelayState}
```

**Example**: clear _finishers_ registered in the session:

```
sess:ch.nevis.session.finishers = 
```

If you want to use advanced features of the `TransformAttributes` state,
provide the required configuration via `Custom Properties`.


# DatabaseBase_encryption

If `enabled` the query parameter `useSSL=true` will be added to enable 1-way TLS.

If no `Trust Store` is assigned then `trustServerCertificate=true` will be added to the connection string.

Assignment of a `Trust Store` is recommended for production use.

**Note:** `PostgresSQL` database connection configuration doesn't support TLS connection yet.


# ErrorHandler_mode

Enable or disable the error handling.

When set to `disabled`, all settings except `Apply only to sub-paths` are ignored.
Use this setting in combination with `Apply only to sub-paths` to disable the error handling for some sub-paths only.

Usage examples (valid for `Virtual Host`s and backend applications):
- Disable the error handling: 
use an `Error Handler` pattern with `Mode` set to `disabled` and link it to the target pattern via `Additional Settings`;
- Disable the error handling for some sub-paths:
use an `Error Handler` pattern with `Mode` set to `disabled` and `Apply only to sub-paths` set to the paths where no error handling should occur, and link it to the target pattern via `Additional Settings`;
- Define a customised error handling and disable it for some sub-paths: 
use two `Error Handler` patterns, one with the custom settings, and one with `Mode` set to `disabled` and `Apply only to sub-paths` set to the paths where no error handling should occur. Link both of them to the target pattern via `Additional Settings`.

# DatabaseBase_user

Database connection user.

This setting is used in the following cases:

- Classic deployments (VM)
- In Kubernetes when 'Database Management' (Advanced Settings) is set to 'disabled'.


# GenericSocialLogin_buttonLogo

The path to logo file of the social login provider.
This path is the path of logo file which you which uploaded at Login template in Realm pattern. E.g:

In the zip file the icon with path `/webdata/resources/icons/icon.csv`, the input is `/icons/icon.csv`

# NevisAdaptDeployable_ipReputationUpdateURL

Provide a download URL for the database file. The file is downloaded then moved over to the path defined above.

# OAuth2Client_grantTypes

Enter the allowed grant types.

# AppleLogin_redirectURI

The callback URI to go to after a successful login with Apple.

This will create an endpoint in your host config.

The URL will be a combination of the `Frontend Address` of the `Virtual Host` and the value configured here.
For example, let's assume that you have configured:

- Return Path: `/oidc/apple/`
- Frontend Address: `https://nevis.net`

Then the URL will be `https://nevis.net/oidc/apple/`.

Use the `exact:` prefix to use the given path as-is.
Without this prefix a normal mapping with `/*` will be generated and thus sub-paths will be accessible as well.


# CustomAuthLogFile_serverSyslogFormat

[Log4j 2 log format](https://logging.apache.org/log4j/2.x/manual/layouts.html#Format) for the SERVER SYS logs.

Note: not relevant when Log Targets is set to `default`.

# NevisAdaptDeployable_ipPrivateNetworkFilter

If your network you are connecting from only contains private network addresses
nevisAdapt will filter these addresses out thus not assigning riskscore
to GeoIP data from these addresses.


If you wish to disable this feature, you can do so by setting the following.
```properties
nevisAdapt.database.ipPrivateNetworkFilter.enabled=false
```

The default value is `true`.

# GenericIngressSettings_annotations

Add Kubernetes annotations to customize the behaviour of the NGINX ingress.

Restrict access based on source IP:

```properties
nginx.ingress.kubernetes.io/whitelist-source-range: 213.189.148.0/24,173.245.48.0/20,103.21.244.0/22
```

Increase the maximum allowed request size:

```properties
nginx.ingress.kubernetes.io/proxy-body-size: 10m
```

Please read [Annotations - NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/) for details.

# SocialLoginBase_host

Assign a `Virtual Host` which shall serve as entry point for the callback from social login provider.

In case your host has
* 1 address, that address will be used
* many addresses with
  * 1 https, and many http, the https will be used without warning
  * mix between http and https, the 1st https will be used with warning
  * single scheme (http or https only) the 1st address will be used with warning

E.g.
```
http://nevis.net
http://nevis-security.net
https://nevis.net
https://nevis-security.net
```
The `https://nevis.net` will be used as the host for Apple callback

# SAPLogonTicket_encoding

Encoding to use for the SAP token. Note that some SAP applications (in particular those running as native processes) do not support all encodings. In such cases, error messages may be misleading. 
Usage of the encoding "ISO8859-1 (ISO-LATIN-1)" is encouraged as this seems to be supported by all SAP products.

The default is `ISO8859-1`.

# ResponseRewritingSettings_responseBody

Configure response body rewrite rules.

In the first column enter a regular expression.
In the second column enter the replacement.

Rules will be applied to each line of the response body.

Response body rewriting can be a complex task and should only be done if there is no other way. 
Use the browser's network tracing to have a look at the responses to find out what needs to be rewritten.

Examples:

| Regex                              | Replacement            | Description                                                                       |
|------------------------------------|------------------------|-----------------------------------------------------------------------------------|
| `http://my-backend.intra.siven.ch` | `https://www.siven.ch` | replace an internal host name with the external one                               |
| `https?://[^/]+(/.*)`              | `$1`                   | make links relative                                                               |
| `<base href="/">`                  | `<base href="/app/">`  | apps which have a context root of `/` may require a rewrite of the `base` element |

For further information see documentation of `RewriteFilter` in nevisProxy Technical Documentation.


# RuleBundle_whitelistRules

Configure _whitelist modifications_.

As explained in the [ModSecurity documentation](https://www.modsecurity.org/CRS/Documentation/exceptions.html#exceptions-versus-whitelist)
_whitelist modifications_ are applied **before** including the core rules.

If both the `Request Validation Settings` and the `Rule Bundle` pattern have _whitelist modifications_ configured, first
the `Rule Bundle`, then the `Request Validation Settings` whitelists will be applied.

Note that new rule may require a rule ID which has to be unique for this pattern.
Use the range 1-99,999 as it is reserved for local (internal) use. 

* Remove rule with ID `900200` for the path `/app/some.html`:

`SecRule REQUEST_URI "@streq /app/some.html" "pass,nolog,id:1000,ctl:ruleRemoveById=200002"`

# OAuth2AuthorizationServer_invalidAuthorizationRequest

Configure the step to execute after error when the authorization request is invalid. Example:
* Cannot parse Authorization Request
* Request `response-type` mismatch with client configuration
* Invalid scope
* Policy not allow
* PKCE method not support
* Missing code challenge
* Plain code challenge

If no step is configured here the process ends and the error will display on UI.

# NevisAuthDeployable_resources

Upload additional resources required by your configuration.

Uploaded files will be deployed into the `conf` folder of the nevisAuth instance.


# GenericAuthenticationStep_authStatesFile

Upload an XML file containing `AuthState` elements.

Example to illustrate the syntax:

```xml
<AuthState 
  name="${state.entry}"
  class="ch.nevis.esauth.auth.states.standard.ThrottleSessionsState"
  final="false">
  <ResultCond name="ok" next="${state.done}" />
  <Response value="AUTH_ERROR">
    <Gui name="AuthErrorDialog"/>
  </Response>
  <property name="queryValue" value="${request:userId}" />
</AuthState>
```  

See [Standard authentication AuthStates and plug-ins](https://docs.nevis.net/nevisauth/setup-and-configuration/authentication-plugins-and-authstates/standard-authentication-authstates-and-plugins/authdone) for further examples.

The following expressions may be used:

- `${instance}`: name of the nevisAuth instance.
- `${request_url}`: generates a nevisAuth expression which returns the URL of the current request
- `${realm}`: name of the Realm (see below)
- `${state.entry}`: use as `name` to mark the first `AuthState`.
- `${state.done}`: use as `next` in `ResultCond` elements to exit this step and continue with `On Success`.
- `${state.failed}`: use as `next` in `ResultCond` elements to exit this step and continue with `On Failure`.
- `${state.exit.<index>}`: use as `next` in `ResultCond` elements to exit this step and continue with an `Additional Follow-up Step(s)`. The index starts with `1`.
- `${state.level}`: must be used if an `Authentication Level` has been defined. Use as `authLevel` on `ResultCond` elements which point to `${state.done}`.
- `${keystore}`: name of the `KeyStore` element provided by this pattern. Assign a pattern to `Key Objects` to add a `KeyObject` into this `KeyStore`.
- `${service.postfix}`: in Kubernetes side-by-side deployment a postfix is added to service names. Use this expression when connecting to a service deployed against the same inventory.
- `${var.<name>}`: insert the scalar variable `<name>`. This is an alternative to using `Template Parameters`.

The `name` of `AuthState` elements is prefixed
with the sanitized name of the Realm (referred to as `${realm}`).

The realm prefix must be added when using `propertyRef` to reference AuthStates
generated by other patterns (e.g. `<propertyRef name="${realm}_SomeState"/>`).

An exception is the add-on pattern `nevisIDM Connector for Generic Authentication` which does not set a prefix.
Here the `propertyRef` must be defined as follows:

`<propertyRef name="nevisIDM_Connector"/>`

This pattern does not validate that labels are translated.
Translations can be provided on the `Authentication Realm` pattern.

# TANBase_onSuccess

Configure the step to execute after successful authentication. 
If no step is configured here the process ends and the user will be authenticated.


# OutOfBandMobileAuthentication_onFailure

When authentication fails due to user behaviour, the authentication flow may continue with assigned step.

The authentication may fail due to the following reasons (non-exhaustive list):

* A timeout has occurred
* The authentication itself has failed (for example wrong biometric credential was provided)
* Client errors (e.g. the authenticator chosen did not comply with the policy)

To handle a failure upon sending a push notification, configure `On Push Failure` instead.


# NevisIDMProperty_clientExtId

Enter `clientExtId` for the property definition file.

If set, the property becomes specific to the referred client. Otherwise, the property is client-independent.

# NevisProxyDeployable_cacheTimeout

Configures the number of seconds before an SSL session expires in the SSL Session Cache.

For more information, see the documentation of the [SSLSessionCacheTimeout directive](https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslsessioncachetimeout).

# NevisAuthRealmBase_secRoleParams

Add custom `init-param` elements to the `SecurityRoleFilter` generated by this pattern.

Multi-line values, as required for conditional configuration,
can be entered by replacing the line-breaks with `\n`. 


# NevisLogrendLogSettings_regexFilter

If set, messages for `nevislogrend.log` which match the given regular expression won't be logged.

The regular expression must match the entire line.
For instance, you may use the following format to match `some text`:

```
.*some text.*
```

Example: drop messages caused by the Kubernetes liveness checks

```
.*GET /nevislogrend/health.*
```


# KeyObject_keyObjectId

Set the attribute `id` of the `KeyObject` element.

The `id` must be unique within the nevisAuth instance.
If not set the sanitized name of this pattern will be used.


# NevisAdaptDeployableBase_bindHost

Enter a custom host name to listen on.

This setting is relevant in classic VM deployment,
when working with multi-homed target hosts.

In Kubernetes the component listens on `0.0.0.0`
and thus this setting is discouraged.

# JWTAccessRestriction_algorithm

The algorithm used to sign and verify the JWT.

Supported algorithms are:
- RS256
- RS384
- RS512 (default)

# NevisFIDODeployable_backendKeyStore

The key nevisFIDO uses to connect to ```nevisIDM Instance```.
Important to note that the certificate that belongs to this key must exist in nevisIDM as the certificate credential of the nevisfido technical user.

# NevisIDMGenericBatchJob_job

Add configuration of a bean which configures your batch job. 

The basic syntax is as follows:

```
<bean id="someJobId" class="org.springframework.scheduling.quartz.JobDetailFactoryBean">
    <property name="description" value="Some job description"/>
    <property name="durability" value="true"/>
    <property name="jobClass" value="some.job.Class"/>
    <property name="jobDataMap">
        <bean class="org.quartz.JobDataMap">
            <constructor-arg>
                <map>
                    <entry key="someJobParam" value="some value"/>
                </map>
            </constructor-arg>
        </bean>
    </property>
</bean>
```

# NevisAuthRealmBase_defaultProperties

Add or overwrite properties in the `default.properties` of the nevisLogrend application.

Use only when there is no high-level setting.
We recommend to **not** overwrite any language related properties, as the languages should be in sync with nevisAuth.
You can configure the languages on the `nevisAuth Instance`.

Requires that nevisLogrend is used for GUI rendering. Check the help of `Login Renderer` for details.


# SAPLogonTicket_systemId

Identifier of issuing system (or issuer). This must match the key under which the issuer certificate was configured in the consuming service.

