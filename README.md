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



# Technical notes

## Direct login via identity token
Create Token role


    vault write auth/token/roles/pki-client allowed_policies=pki-client renewable=true token_explicit_max_ttl=24h token_no_default_policy=true allowed_entity_aliases=*.token

Create alias

    vault write identity/entity-alias name=edge0.token canonical_id=4e537ff7-ebc4-32a3-cf3a-77db8c1e0fb3 mount_accessor=auth_token_945fa6db

Create token

    vault write auth/token/create/pki-client entity_alias=edge0.token


## Setup Cloudcore Cert Generation

### PKI Preparation
Define a policy that allows to create root certificates

    vault policy write pki-server - << EOF
    path "/pki/issue/server" {
        capabilities = [ "create","update" ]
    }
    EOF

Define a PKI role that allows to create certificte for the target domain (this role will be assigned via the login):

    vault write pki/roles/server ext_key_usage=ServerAuth allowed_domains=ci4rail.com allow_subdomains=true

### Kubernetes Auth Preparation

Enable kubernetes auth method

    vault auth enable kubernetes

Configure the auth method to allow access to the cluster. For minikube:

    vault write auth/kubernetes/config kubernetes_host=https://$(minikube ip):8443 kubernetes_ca_crt=$HOME/.minikube/ca.crt

(adapt the port as needed)

The cloudcore deployment has already created a service account:

    kubectl -n kubeedge get serviceaccount cloudcore -o yaml


Create a role that binds the serviceaccount, resp. it's secret, to a Vault role. This role defines, which in turn defines the policies available to the serviceaccount user
    
    vault write auth/kubernetes/role/cloudcore bound_service_account_names=cloudcore bound_service_account_namespaces=kubeedge token_policies=pki-server alias_name_source=serviceaccount_name token_no_default_policy=true

### Entity Preparation
Create a new entity representing the cloudcore server

    vault write identity/entity name=cloudcore.rivendell.home

Create an alias that associates the entity with the kubernetes login mechanism, i.e. when logging in using kubernetes the alias creates the brige to the entity


    # Determine the entity id
    export ID=$(vault read -format=json identity/entity/name/cloudcore.rivendell.home|jq -r .data.id)

    # Determine the internal accessor id of the kubernetes auth method
    export ACCESSOR=$(vault auth list -format=json|jq -r '.["kubernetes/"].accessor')

    # Link the entity to the kubernetes auth method
    vault write identity/entity-alias canonical_id=$ID mount_accessor=$ACCESSOR name=kubeedge/cloudcore