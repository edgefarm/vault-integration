# Introduction

High level receipt of the necessary steps to enroll a new device.

# Overview


![](http://www.plantuml.com/plantuml/proxy?src=https://raw.githubusercontent.com/edgefarm/vault-integration/main/docs/images/pki-enrollment.puml)

# Vault configuration for new device

## Creating an entity

The entity represents the new device in the Vault configuration. See [./setup-pki.md]() for details how to setup a new entity. When following the documentation in [./setup-pki.md](), for every entity exactly _one_ fullly qualified domain name (FQDN) is allowed as subject in the generated certificates. 
> Hint: The restriction to a single fqdn is an arbitrary restriction and may be changed with a more complex setup of Vault. 

## Definining the common name

Every client certificate must contain the common name as subject. The common name is attached to the entity as a metadata entry called _"common_name"_. The rules defined for the PKI prevent the client from requesting a certificate with a different client name.

## Defining an alias

An entity alias has to be defined that ties the _token authentication_ mechanism to the entity defined above. Basically, the identity of the used login token is linked to the entity using an alias

# Token generation

When the entity has been defined, a login token may be created. The lifetime of this token has to be chosen according to the requirements:

* A token with an unlimited TTL will never expire and continuously allow the new client to request new client certificates _until explicitly deleted_. To lock out an device, the token has to be retrieved from the Vault datastore and deleted.
* A token with a limited TTL provides further protection against abuse, but will require periodic renewal of the token. It may be discussed if this is actually necessary, as the generated client certificates already have a limited validity period and must be continuously renewed.

With this information, an token for the entity may be generated and distributed.


# Device Enrollment

For the actual enrollment of the device, two steps have to be completed:

* Provisioning of the generated token to the device. This can be done either via
    * a simple textfile containing the token (recommended)
    * the environment variable "VAULT_TOKEN"
* Setup of the edge node configuration as describerd in [./configuration.md]()
