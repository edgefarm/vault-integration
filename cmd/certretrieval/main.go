package main

import (
	"flag"
	"log"
	"os"
	"time"

	certretrival "github.com/edgefarm/vault-integration/pkg/certretrieval"
)

// setFallbackByEnv sets the string to the value of the given env variable, if it is unset
func setFallbackByEnv(target *string, envName string) {
	if *target == "" {
		*target = os.Getenv(envName)
	}
}

func main() {
	println("Certretrieval for edgefarm")

	config := certretrival.Config{}
	flags := flag.NewFlagSet("certretrieval", flag.ExitOnError)
	flags.StringVar(&config.Tokenfile, "tokenfile", "", "The vault tokenfile (env: VAULT_TOKEN)")
	flags.StringVar(&config.Name, "name", "", "The common name of the certificate (env: COMMON_NAME)")
	flags.StringVar(&config.OutCAfile, "ca", "", "The targetfile for the issuing CA (env: CA_FILE)")
	flags.StringVar(&config.OutCertfile, "cert", "", "The targetfile for the PEM encoded certificate(env: CERT_FILE)")
	flags.StringVar(&config.OutKeyfile, "key", "", "The targetfile for the PEM encoded private key(env: KEY_FILE)")
	flags.StringVar(&config.Role, "role", "", "The Vault role when requesting the certificate (env: ROLE)")
	flags.StringVar(&config.ServerCA, "serverca", "", "The signing CA of the vault server certificate when requesting the certificate(env: VAULT_CACERT)")
	flags.StringVar(&config.Vault, "vault", "", "The vault address (env: VAULT_ADDR)")
	flags.DurationVar(&config.TTL, "ttl", 0, "The validity period of the certificate (env : TTL")
	flags.BoolVar(&config.Force, "force", false, "Force retrieval of new certificate")
	flags.Int64Var(&config.ValidityCheckTolerance, "checktolerance", 0, "The tolerance in %% when checking the validity of the existing certificate. Must be between 0 and 100 (env: n/a)")

	if len(os.Args) == 1 {
		flags.Usage()
		return
	}

	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Printf("Failed to parse commandline args: %v", err)
		return
	}

	setFallbackByEnv(&config.Tokenfile, "VAULT_TOKEN_FILE")
	setFallbackByEnv(&config.Token, "VAULT_TOKEN")
	setFallbackByEnv(&config.Name, "COMMON_NAME")
	setFallbackByEnv(&config.OutCAfile, "CA_FILE")
	setFallbackByEnv(&config.OutCertfile, "CERT_FILE")
	setFallbackByEnv(&config.OutKeyfile, "KEY_FILE")
	setFallbackByEnv(&config.Role, "ROLE")
	setFallbackByEnv(&config.ServerCA, "VAULT_CACERT")
	setFallbackByEnv(&config.Vault, "VAULT_ADDR")

	if val := os.Getenv("TTL"); config.TTL == 0 && val != "" {
		duration, err := time.ParseDuration(val)
		if err != nil {
			log.Fatalf("Invalid ttl %q: %v", val, err)
		}
		config.TTL = duration
	}

	cr, err := certretrival.New(config)
	if err != nil {
		log.Fatalf("Failed to create cert retrieval: %v", err)
	}

	if err := cr.Retrieve(); err != nil {
		log.Fatalf("Failed to retrieve cert: %v", err)
	}
}
