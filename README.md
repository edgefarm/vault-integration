# Vault Integration

This repository provides the elements for the integration of edgefarm with [Hashicorp Vault](https://www.vaultproject.io/).

## Component certretrieval

This component implements automatic login to Vault and retrieval of X.509 certificates. The component requires an 
initial _vault token_ that allows authenticating against vault. The token must be associated with a suitable role that
allows creating certificates for a configured common name.

The process retrieves the new certificate from Vault and stores it into local files. Existing files are overwritten,
however this is done atomically by renaming a temporary file. This assures that no partial certificates are visible to
using processes. 


The process may be configured using command line parameters and environment variables. Commandline parameters take precedence over environment variabels.

| Commandline Arg | Environment Variable | Description
|--|--|--|
| tokenfile | VAULT_TOKEN_FILE | The Vault token that authenticates the request to Vault. Is used as bearer token | 
| vault | VAULT_ADDR | The URL of the Vault server | 
| serverca | VAULT_CACERT | A ca certificate for validating the Vault server certificate, if self-signed certificates are  used | 
| role | ROLE | The Vault role name for generating a new certificate | 
| name | COMMON_NAME | The common name to be used for the new certificate | 
| ca | CA_FILE | Target filename for the issuing CA certificate, stored in PEM format | 
| cert | CERT_FILE | Target filename for the new certificate, stored in PEM format | 
| key | KEY_FILE | Target filename for the private key associated with the new certificate, stored in PEM format | 
| checktolerance | n/a | If defined, the validity of the current certificate is checked. If the certificate is not stale, the retrieval of a new certificate is skipped. The tolerance defines how close to the end of the validity period the certificate has to be: e.g. 80 means that the certificate is considered stale, if only 20% of the validity period remain. |
| ttl | TTL | The time to live of the newly created  certificate. The server may impose a shorter limit. |


# Technical documentation

More in-depth documentation for concepts, setup and configuration is found [here](./docs/index.md)