# Introduction

The following explains the most important features of [Hashicorp Vault](https://www.vaultproject.io/).
For more in depth information, visit the [general documentation site](https://www.vaultproject.io/docs) or the 
[REST API description](https://www.vaultproject.io/api-docs)

# Overview

Vault is a pure REST API base application that (among other) implements various mechanisms
for distributing _credentials_ ("secrets"). For _authenticating_ users to retrieve
these secrets, multiple _authentication mechanisms_ are implemented into the 
system. A possible scenario for the application of Vault would be to store database
credentials in vault, authenticate to Vault via OIDC by integrating an 
external Authprovider, e.g. RedHat keycloak, and _inject_ the secrets into an
arbitrary application. 
For a thorough introduction to Vault, please see the excellent 
[introduction tutorial](https://learn.hashicorp.com/tutorials/vault/getting-started-intro?in=vault/getting-started).
The tutorial also explains the powerful feature of _dynamic secrets_ which is 
however not applied in the KubeEdge context.

# Integration with KubeEdge

For the integration with KubeEdge the following features of Vault are utilized:

* Setup of an public key infrastructure (PKI) to generate cryptographic X.509 certificates.
* Authentication of the cloud hub via the kubernetes authentication plugin and kubernetes service accounts.
* Generation and rotation of TLS server certificates.
* Authentication of the edge nodes directly via a Vault token.
* Generation and rotation of TLS client certificates.

# Concepts of Vault


The following concepts of Vault are relevant for the understanding of the integration.
Note that these explanations have been condensed to relevant parts. For more in-depth
information see the associated links

![](http://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/edgefarm/vault-integration/vault/docs/images/vault-concepts.puml)


# [Policies](https://www.vaultproject.io/docs/concepts/policies)

Vault is implemented as a pure REST API, i.e. every functionality of Vault is 
invoked by issuing a suitable HTTP-request to the server. The used HTTP method
(GET, POST, PUT, DELETE and the non-standard verb LIST) and the URL path determine the 
function to execute. A policy defines an _Access Control List_ (ACL) for the access to the API.
A simple example would be: 

    path "secret/foo" {
      capabilities = ["read"]
    }

This allows the invoking (authenticated) client to read the secret defined at path _secret/foo_. Vault allows it, to integrated multiple _secret engines_, e.g. JWT, X.509 etc., at different paths. This allows for a customized setup.
During authentication Vault determines, which policies are applicable for the user and will filter all following requests by these ACLs.
Policies may be defined using wildcard patterns.

# [Entities](https://www.vaultproject.io/docs/concepts/identity)

Although Vault is not intended for user management, Vault has to differentiate the _identity_ of a client. For this, the _entity_ abstraction is used. During authentication, an appropriate entity is determined for the requesting client. Important: If no entity can be found, but the authentication was successful, a _new_ entity is automatically created. Therefore, it is important that for every used authentication mechanism the corresponding entity must be defined (see below for details).

# [Tokens](https://www.vaultproject.io/docs/concepts/tokens)

The authorization of clients is defined using _Tokens_. These tokens are _session identifiers_ (optionally with a limited lifetime), that identify the requesting entity and it's associated policy. The tokens are generated during authentication and used as [Bearer Token](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication). The Tokens are basic authorization mechanism in Vault: The result of every authentication is always a token which is used afterwards to identify the successful authenticated session.
Tokens may be revoked automatically or manually, which results in an instant logout of the user. 

# [Secrets](https://www.vaultproject.io/docs/secrets#secrets-engines)

A secret in Vault is an abstract representation of _credentials_. Some example are

* Database credentials
* Vault identities
* SSH Keys
* X.509 cryptographic certificates
* Username/Password tuples
* ...

Vault stores these secrets securely and provides them to an authenticated application using various approaches.

# [Authentication](https://www.vaultproject.io/docs/auth#auth-methods)

Vault provides multiple authentication _engines_ that are made available in the REST API. It is even valid to add the same engine with different settings multiple times. 
During authentication the following steps are performed:

* Authenticating the actual user using the appropriate mechanism (OIDC, username & password, JWT token from a k8s service account etc.). This results in
    * an _entity_ ("who is authenticated")
    * A set of applicable policies ("what may the entity do?")
    * A token (the "session identifier")


# Roles

A _role_ in Vault is very different concept compared to other systems. In Vault, a role defines additional attributes for an authentication mechanism. When authenticating a client, additional attributes of the session (apart from the identity) have to be defined. For example, it has to be determined, which _policies_ are applicable to the session or how long the resulting token will be valid. These additionally attributes are defined by the Vault operator and are associated via a role specific to the authentication mechanism. During authentication a user has to define in which _role_ it authenticates. Depending on the used authentication mechanism, various restrictions on the available roles may be defined, e.g. requesting IP address range etc.

# [Entity Aliases](https://www.vaultproject.io/docs/concepts/identity)

When authenticating the Vault entity has to be determined. This is highly specific to the used mechanism. For example:

* For a x.509 client certificate the subject name may be used
* For a k8s service account the name may be used
* For a username/password tuple the username is used.

So a _bridge_ from the authentication mechanism to the entity identifying the requesting client is required. This bridge is defined by the _entity alias_: For every tuple (entity, auth mechanism) exactly _one_ alias may be defined that represents the identifying characteristics extracted from the specific authentication mechanism.
