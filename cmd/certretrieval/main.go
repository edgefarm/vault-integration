package main

import (
	"flag"
	"os"
	"time"

	"github.com/edgefarm/vault-integration/pkg/certretrieval"
	"github.com/magiconair/properties"
	"k8s.io/klog/v2"
)

// setFallbackByEnv sets the string to the value of the given env variable, if it is unset
func setFallbackByEnv(target *string, envName string) {
	if *target == "" {
		*target = os.Getenv(envName)
	}
}

func main() {
	println("Certretrieval for edgefarm")

	config := certretrieval.Config{}
	flags := flag.NewFlagSet("certretrieval", flag.ExitOnError)
	flags.StringVar(&config.Tokenfile, "tokenfile", "", "The vault tokenfile (env: VAULT_TOKEN)")
	flags.StringVar(&config.Name, "name", "", "The common name of the certificate (env: COMMON_NAME)")
	flags.StringVar(&config.AltNames, "altnames", "", "The requested Subject Alternative Names as comma seperated list e.g. \"a,b,c\" (env: ALT_NAMES)")
	flags.StringVar(&config.OutCAfile, "ca", "", "The targetfile for the issuing CA (env: CA_FILE)")
	flags.StringVar(&config.OutCertfile, "cert", "", "The targetfile for the PEM encoded certificate(env: CERT_FILE)")
	flags.StringVar(&config.OutKeyfile, "key", "", "The targetfile for the PEM encoded private key(env: KEY_FILE)")
	flags.StringVar(&config.Role, "role", "", "The Vault role when requesting the certificate (env: ROLE)")
	flags.StringVar(&config.ServerCA, "serverca", "", "The signing CA of the vault server certificate when requesting the certificate(env: VAULT_CACERT)")
	flags.StringVar(&config.PKI, "pki", "pki", "The path to the PKI engine in Vault (env: VAULT_PKI)")
	flags.StringVar(&config.Address, "address", "", "The vault address (env: VAULT_ADDR)")
	flags.StringVar(&config.AuthRole, "authrole", "", "The Vault role to use, when authenticating via the k8s api. Not needed, when a token is used. (env: AUTH_ROLE)")
	flags.DurationVar(&config.TTL, "ttl", 0, "The validity period of the certificate (env : TTL")
	flags.BoolVar(&config.Force, "force", false, "Force retrieval of new certificate")
	flags.Int64Var(&config.ValidityCheckTolerance, "checktolerance", 0, "The tolerance in %% when checking the validity of the existing certificate. Must be between 0 and 100 (env: n/a)")
	configFile := flags.String("config", "", "Load settings from a config file")
	loopDelay := flags.Duration("loopdelay", 0, "If set, the process stays in a loop and wakes in _loopdelay_ intervals to update the certificate")
	klog.InitFlags(flags)

	if err := flags.Parse(os.Args[1:]); err != nil {
		klog.Fatalf("Failed to parse commandline args: %v", err)
	}
	setFallbackByEnv(&config.Tokenfile, "VAULT_TOKEN_FILE")
	setFallbackByEnv(&config.Token, "VAULT_TOKEN")
	setFallbackByEnv(&config.Name, "COMMON_NAME")
	setFallbackByEnv(&config.AltNames, "ALT_NAMES")
	setFallbackByEnv(&config.OutCAfile, "CA_FILE")
	setFallbackByEnv(&config.OutCertfile, "CERT_FILE")
	setFallbackByEnv(&config.OutKeyfile, "KEY_FILE")
	setFallbackByEnv(&config.Role, "ROLE")
	setFallbackByEnv(&config.ServerCA, "VAULT_CACERT")
	setFallbackByEnv(&config.PKI, "VAULT_PKI")
	setFallbackByEnv(&config.Address, "VAULT_ADDR")
	setFallbackByEnv(&config.AuthRole, "AUTH_ROLE")

	if *configFile != "" {
		props, err := properties.LoadFile(*configFile, properties.UTF8)
		if err != nil {
			klog.Fatalf("Failed to load settingsfile: %v", err)
		}
		config.AuthRole = props.GetString("authrole", config.AuthRole)
		config.Force = props.GetBool("force", config.Force)
		config.Name = props.GetString("name", config.Name)
		config.AltNames = props.GetString("altnames", config.AltNames)
		config.OutCAfile = props.GetString("ca", config.OutCAfile)
		config.OutCertfile = props.GetString("cert", config.OutCertfile)
		config.OutKeyfile = props.GetString("key", config.OutKeyfile)
		config.Role = props.GetString("role", config.OutCertfile)
		config.ServerCA = props.GetString("serverca", config.ServerCA)
		config.PKI = props.GetString("pki", config.PKI)
		if val, ok := props.Get("ttl"); ok {
			ttl, err := time.ParseDuration(val)
			if err != nil {
				klog.Exitf("Failed to parse TTL %q: %v", val, err)
			}
			config.TTL = ttl
		}
		config.Token = props.GetString("token", config.Token)
		config.Tokenfile = props.GetString("tokenfile", config.Tokenfile)
		config.ValidityCheckTolerance = props.GetInt64("checktolerance", config.ValidityCheckTolerance)
		config.Address = props.GetString("address", config.Address)
	}

	if val := os.Getenv("TTL"); config.TTL == 0 && val != "" {
		duration, err := time.ParseDuration(val)
		if err != nil {
			klog.Exitf("Invalid ttl %q: %v", val, err)
		}
		config.TTL = duration
	}

	cr, err := certretrieval.New(config)
	if err != nil {
		klog.Exitf("Failed to create cert retrieval: %v", err)
	}

	for {
		if err := cr.Retrieve(); err != nil {
			klog.Exitf("Failed to retrieve cert: %v", err)
		}

		if *loopDelay == 0*time.Second {
			// no loop delay defined, so break
			break
		}
		klog.Infof("Sleeping for %v", *loopDelay)
		time.Sleep(*loopDelay)
	}
}
