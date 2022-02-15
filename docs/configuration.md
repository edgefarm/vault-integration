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
Conceptually, the following changes must be made to the deployment of cloudhub:

* Define an init container, that will retrieve a valid certificate from Vault, _before_ cloud hub starts
* Define a sidecar container that will periodically retrieve fresh certificates from Vault.
* Define the service account to be used
* Provide configurations for the certificate retrieval, e.g. the signing certificate for communicating with Vault, the Vault address etc.
* Make some slight adaptions to the shared volumes to allow file based communication between the cloud hub and the certificate retrieving sidecar

This changes have been preconfigured in a kustomize layer that has been checked in to the kubeedge fork.

To apply the patched configuration use

    kubectl apply -k build/overlays/vault

After this, the server will deploy, retrieve an certificate and open the websocket server using the newly generated certificate

## Test Setup

Connecting to the websocket server should return a certificate signed by the CA and a limited lifetime:

    openssl s_client -connect dns-name-of-cloud-hub:10000|openssl x509 -text
# Edge Node

## General concept

The Vault integration on the edge node side is a bit more complicated, as in this setup no sidecar container may be used. Therefore the certificate retrieval has been integrated into the edge hub. However, the implementation is the same as used in the sidecar container on the cloud hub side.

## Configuration settings
Integrating the retrieval into edge node itself consequently requires the configuration to be extended. The following commented example shows the new configuration settings:

    apiVersion: edgecore.config.kubeedge.io/v1alpha1
    database:
    dataSource: /home/rschmitz/devel/kubeedge/_tmp/edgecore.db
    kind: EdgeCore
    modules:
        edgeHub:
            enable: true
            heartbeat: 2
            httpServer: https://cloudcore.rivendell.home:10002
            tlsCaFile: /home/rschmitz/devel/kubeedge/_tmp/rootCA.crt
            tlsCertFile: /home/rschmitz/devel/kubeedge/_tmp/server.crt
            tlsPrivateKeyFile: /home/rschmitz/devel/kubeedge/_tmp/server.key
            token: "" 
            extCertificateRetrieval: true
            tokenFile: /home/rschmitz/devel/kubeedge/_tmp/token.txt
            # the new vault configuration block
            vault:
                # enable vault integration
                enable: true
                # path to the file containing the Vault auth token
                tokenFile: /home/rschmitz/devel/kubeedge/_tmp/token.txt
                # the vault role to use when authenticating
                role: client
                # the subject name to requset
                commonName: edge0.rivendell.home
                # the requested validity period of the certificate
                ttl: 1h
                # The address of the vault server
                # (the tlsCaFile is used to validate the server certificate )
                vault: "https://vault.rivendell.home"
            websocket:
                enable: true
                handshakeTimeout: 30
                readDeadline: 15
                server: cloudcore.rivendell.home:10000
                writeDeadline: 15
        edged:
            enable: true
            cgroupDriver: systemd
            cgroupRoot: ""
            cgroupsPerQOS: false
            clusterDNS: ""
            clusterDomain: ""
            devicePluginEnabled: false
            dockerAddress: unix:///var/run/docker.sock
            gpuPluginEnabled: false
            hostnameOverride: vtux
            nodeIP: 192.168.10.108
            podSandboxImage: kubeedge/pause:3.1
            remoteImageEndpoint: unix:///var/run/dockershim.sock
            remoteRuntimeEndpoint: unix:///var/run/dockershim.sock
            runtimeType: docker
        eventBus:
            enable: false
            mqttMode: 2
            mqttQOS: 0
            mqttRetain: false
            mqttServerExternal: tcp://127.0.0.1:1883
            mqttServerInternal: tcp://127.0.0.1:1884


If the vault block is disabled (or not present), the original handling for certificates
is used.