# OUTDATED INTERNAL NOTES #

# Bootstrapping prototype

## Setup, done as administrator

### Setup a PKI


    # Enable the pki module
    vault secrets enable pki

    # Tune some values
    vault secrets tune -max-lease-ttl $((24*365*10))h pki
    vault write pki/config/urls issuing_certificates=https://vault.rivendell.home/cert crl_distribution_points=https://vault.rivendell.home/v1/pki/crl ocsp_servers=https://vault.rivendell.home/ocsp

    # Create a self signed root certificate
    vault write -field=certificate pki/root/generate/internal common_name=ca.rivendell.home ttl=$((24*365*10))h

    # Define a role for creating server certificates
    vault write pki/roles/server ext_key_usage=ServerAuth allowed_domains=rivendell.home allow_subdomains=true

    # Define a policy that allows to retrieve certificates
    cat <<EOF|vault policy write pki-client -
    # Allow clients to issue PKI client certs
    path "/pki/issue/client" {
        capabilities = [ "create", "update" ]
    }
    EOF

 

### Get the approle mount point in Vault

The edge nodes will authenticate themselves using the [Approle](https://www.vaultproject.io/api-docs/auth/approle) mechanism of vault. For this, we need the internal of approle within vault

    export APPROLE=$(vault auth list -format=json|jq -r '."approle/".accessor')
    export KUBERNETES=$(vault auth list -format=json|jq -r '."kubernetes/".accessor')


### Define a policy for the entity bootstrap
To perform the bootstrap process, a simple policy is required that allows to create secret-ids for a new edge node

    cat <<EOF|vault policy write edge0-bootstrap -
    path "auth/approle/role/edge0/secret-id" {
        capabilities = ["update"]
    }

    path "sys/wrapping/unwrap" {
        capabilities = ["update"]
    }
    EOF



### Create a new entity for the edge node

The edgenode is represented by a manually created entity. In Vault, every entity has auth-system specific aliases that may contain additional metadata specific for this auth system. So, we
create a user for the edge node and attach the common name as metadata attribute to the metadata of the associated entity alias (specific to the approle).

    vault write identity/entity name=edge0.rivendell.home metadata=common_name=edge0.rivendell.home
    
    # Get the ID of the created entity
    ID=$(vault read -format=json identity/entity/name/edge0.rivendell.home|jq -r .data.id)

### Create an alias

When logging in into Vault via the approle authentication mechanism, an _entity alias_ is used. This alias is the bridge between the authentication mechanism and the entity. Therefore an alias has to be created that contains both the approle _role-id_ (the _name_ attribute) and the _approle accessor_ (the _mount_accessor_ attribute)

    # Associate the common name with the entity alias for approle
    vault write identity/entity-alias canonical_id=$ID mount_accessor=$APPROLE name=edge0



### Define a PKI role for creating certificates.
This  role defines parameters for the certificates that should be issued. We define that the common_name of the issued certificate must conform to a template. This template is based on the metadata of the used entity.

    vault write pki/roles/client ext_key_usage=ClientAuth allowed_domains_template=true allowed_domains={{identity.entity.metadata.common_name}} allow_bare_domains=true ttl="720d"

The allowed common name is read from the requesting entity. By using the template it is sufficient to only create a single PKI role.

### Define Approle role

For every physical node that should be registered, an approle _role_ has to be defined. This role is a _user_ representing the physical node and defines the _common name_ of the certificates that will be created. The creation adds metadata that is associated in the entity created by the approle. The token may only be used _once_.

For example to create a role _edge0_, valid for 7 days: 

    vault write auth/approle/role/edge0 token_policies=pki-client token_no_default_policy=true role_id=edge0 secret_id_ttl=7d token_ttl=60m



### Create a bootstrap entity

This entity is exclusively used to create the approle secret id for the new edge node.

    vault write identity/entity name=edge0-bootstrap policies=edge0-bootstrap

### Create an initial token

This token is used by the bootstrap entity to initially access the system and has a limited lifetime

    export BOOTSTRAP=$(vault token create -format=json -policy edge0-bootstrap -no-default-policy -renewable=false -ttl=168h -use-limit=1 -no-default-policy|jq -r .auth.client_token)

> For the remaining steps, logout as vault admin
> This may be done by removing $HOME/.vault-token and unsetting the env variable VAULT_TOKEN

### Alternative: Login of the edgenode directly via a kubernetes service account

* Enable kubernetes auth

        vault auth enable kubernetes

* Configure the auth method to interact with the cluster

        vault write auth/kubernetes/config kubernetes_host=https://192.168.39.119:8443 kubernetes_ca_crt=$HOME/.minikube/ca.crt

    Important is the address of the cluster API and the public key. Depending on the kubernetes provider the values differ

* Create a role for the bootstrap login

        vault write auth/kubernetes/role/edge0 bound_service_account_names=edge0 bound_service_account_namespaces=edge0 token_policies=edge0 alias_name_source=serviceaccount_name token_no_default_policy=true

    This will assign the edge0 policy to the logged in entity
* create a service account in kubernetes

        kubectl -n edge0 create serviceaccount edge0

    This creates a service account _and_ a secret containing a signed JWT token


* To select the correct entity, an appropriate alias has to be defined for the entity. This alias associates the qualified serviceaccount name read by the kubernetes auth method with the entity

         vault write identity/entity-alias canonical_id=$ID mount_accessor=$KUBERNETES name=edge0/edge0
    (the name is defined as _namespace_/_serviceaccount_)

When this setup is complete, the login may be done without existing Vault token using the service account secret:

* Find the secret associated with the service account

        export SECRET=$(kubectl -n edge0 get serviceaccounts edge0 -o jsonpath='{.secrets[0].name}')

* Retrieve the JWT from the secret

        export JWT=$(kubectl -n edge0 get secrets $SECRET -o jsonpath='{.data.token}'|base64 -d)

* Login via kubernetes

        export VAULT_TOKEN=$(vault write -format=json auth/kubernetes/login role=edge0 jwt=$JWT|jq -r .auth.client_token)

* The token now allows to create certificates

        vault write -format=json pki/issue/client common_name=edge0.rivendell.home|tee private/client.json
    Note that here only the correct common_name can be used as well!

## On the edgenode using the limited token generated above

### Create a secret id

With the role defined, a _wrapped_ secret id can be generated:

    export WRAPPED_ID=$(vault write -wrap-ttl=60s -f -format=json auth/approle/role/edge0/secret-id|jq -r .wrap_info.token)

Wrapped means, that the actual secret id is itself encrypted, so that the bootstrapping entity cannot use the secret id itself


### Login with the application

Using role and secret ID the actual application may login. To acquire the actual secret_id, the wrapped ID must be unwrapped first:

    export SECRET_ID=$(vault unwrap -format=json $WRAPPED_ID|jq -r .data.secret_id)

    # Finally, the real login
    export VAULT_TOKEN=$(vault write -format=json  auth/approle/login role_id=edge0 secret_id=$SECRET_ID|jq -r .auth.client_token) 

This secret ID will be valid to 7days to create an access token. The generated token will be valid for 60 minutes and can be used only once. 

### Issue certificates

After the successful login, certificates may be created:

    vault write -format=json pki/issue/client common_name=edge0.rivendell.home 

Note that due to the template policy defined above, it is not possible to define any other common name!

