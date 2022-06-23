# Vault Integration
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fedgefarm%2Fvault-integration.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fedgefarm%2Fvault-integration?ref=badge_shield)


This repository provides the elements for the integration of edgefarm with [Hashicorp Vault](https://www.vaultproject.io/).

## Component certretrieval

This component implements automatic login to Vault and retrieval of X.509 certificates. The component requires an 
initial _vault token_ that allows authenticating against vault. The token must be associated with a suitable role that
allows creating certificates for a configured common name. The token can be deployed using a flat file or the app
may use a k8s service account to retrieve it itself.

The process retrieves the new certificate from Vault and stores it into local files. Existing files are overwritten,
however this is done atomically by renaming a temporary file. This assures that no partial certificates are visible to
using processes. 

### Configuration via commandline
The process may be configured using command line parameters, text file (for use with k8s config maps) and environment variables. Commandline parameters take precedence over environment variabels.

Commandline Arg | Environment Variable | Description
--|--|--
tokenfile | VAULT_TOKEN_FILE | The Vault token that authenticates the request to Vault. Is used as bearer token.
vault | VAULT_ADDR | The URL of the Vault server.
serverca | VAULT_CACERT | A ca certificate for validating the Vault server certificate, if self-signed certificates are  used.
role | ROLE | The Vault role name for generating a new certificate. The rolename will be passed to Vault and defines the parameters for the new certificate. The role must already be configured within Vault.
authrole | AUTH_ROLE | Only when using the kubernetes authentication to retrieve the Vault token. Defines the role to be used when authenticating. The role must already have been defined in Vault.
name | COMMON_NAME | The common name to be used for the new certificate.
ca | CA_FILE | Target filename for the issuing CA certificate, stored in PEM format.
cert | CERT_FILE | Target filename for the new certificate, stored in PEM format.
key | KEY_FILE | Target filename for the private key associated with the new certificate, stored in PEM format.
checktolerance | n/a | If defined, the validity of the current certificate is checked. If the certificate is not stale, the retrieval of a new certificate is skipped. The tolerance defines how close to the end of the validity period the certificate has to be: e.g. 80 means that the certificate is considered stale, if only 20% of the validity period remain.
ttl | TTL | The time to live of the newly created  certificate. The server may impose a shorter limit.
config | n/a | A text file containing the configuration (see below).
loopdelay | n/a | If defined, the process will not terminate after retrieval, but sleep for the given delay before the next retrieval in a endless loop. Note that the configfile is not re-read between loops
### Configuration via configfile

To facilitate the usage within kubernetes, the component may also read a config file containing _key=value_ pairs.

Example:

    authrole=cloudcore
    force=false
    name=cloudcore.ci4rail.com
    ca=/etc/kubeedge/certs/rootCA.crt
    cert=/etc/kubeedge/certs/edge.crt
    key=/etc/kubeedge/certs/edge.key
    role=server
    serverca=/opt/certretrieval/cert/ca.crt
    ttl=24h
    vault=https://vault.ci4rail.com

The file is passed using _-config_ parameter and is intended for usage within kubernetes, where configuration may be passed as configmap.

# Technical documentation

More in-depth documentation for concepts, setup and configuration is found [here](./docs/index.md)

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fedgefarm%2Fvault-integration.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fedgefarm%2Fvault-integration?ref=badge_large)