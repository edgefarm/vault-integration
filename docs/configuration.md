# Introduction

Description of the enhanced configuration of Cloud Hub and Edge Nodes to
integrate vault.

# Cloud Hub

## General concept
The original implementation of the cloud hub alternatively reads the following elements from either a k8s secret
or the file system:

* The server certificate
* The private key for the server certificate
* The CA certificate (signing certificate)
* The private key (!) of the signing certificate

The fact that the cloud hub _creates signs client certificates_ is the reason for the surprising requirement 
to provide the private key of the signing certificate. The intention of the vault integration is, that the certificates 
are now generated and signed by the Vault CA and not the cloud hub server itself. 
With Vault integrated, some minor changes to the cloud hub server have been done:

* The requirement for the signing private key has been lifted (it remains securely within Vault)
* The certificates are not moved to k8s secrets anymore when in Vault mode, as they are exclusively read from the file system

To keep the changes to the server small, an external tool has been provided that

* Authenticates to Vault using the kubernetes authentication method based on a service account
* Retrieves fresh certificates in periodic intervals and writes them to a shared (non-persistent) k8s volume.



## Adaptions to deployment

## Configuration settings
# Edge Node

## General concept

