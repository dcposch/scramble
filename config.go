package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"path/filepath"
)

// All configuration for a Scramble server+notary.
// The config object is read from ~/.scramble/config.json
type Config struct {
	DbServer   string
	DbUser     string
	DbPassword string
	DbCatalog  string

	SMTPMxHost   string
	SMTPPort     int // internal, nginx handles TLS and forwards
	MaxEmailSize int

	HTTPPort int // internal, nginx handles SSL and forwards

	Notaries map[string]string // for seeding new accounts, and clients to query

	ReservedNames       []string // reserved usernames
	AncestorIDsMaxBytes int      // should match the VARCHAR() limit of email > ancestor_ids
	AdminEmails         []string // alerted for server issues
}

// Gets the cotents of the Scramble config file, ~/.scramble/config.json
// The file is read only once at startup.
func GetConfig() *Config {
	return &config
}

var defaultConfig = Config{
	"127.0.0.1",
	"scramble",
	"scramble",
	"scramble",

	"local.scramble.io",
	8825,
	15728640, // 15 MB max email size

	8888,
	map[string]string{
		"local.scramble.io": "notaries/local.scramble.io",
	},
	[]string{"admin", "administrator", "root", "support", "help", "spam",
		"info", "contact", "webmaster", "abuse", "security", "mailer-daemon",
		"mailer", "daemon", "postmaster"},
	10240,
	[]string{},
}

var config = defaultConfig

func init() {
	configFile := os.Getenv("HOME") + "/.scramble/config.json"
	log.Printf("Reading " + configFile)

	// try to read configuration. if missing, write default
	configBytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		writeDefaultConfig(configFile)
		fmt.Println("Config file written to ~/.scramble/config.json. Please edit & run again")
		os.Exit(1)
		return
	}

	// try to parse configuration. on error, die
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		log.Panicf("Invalid configuration file %s: %v", configFile, err)
	}
}

func writeDefaultConfig(configFile string) {
	log.Printf("Creating default configration file %s", configFile)
	configBytes, err := json.MarshalIndent(defaultConfig, "", "    ")
	if err != nil {
		panic(err)
	}
	err = os.MkdirAll(filepath.Dir(configFile), 0700)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(configFile, configBytes, 0600)
	if err != nil {
		panic(err)
	}
}

// Checks whether a given name (such as "admin" or "root")
// is reserved, to prevent outside users from registering those user names
func (cfg *Config) IsReservedName(name string) bool {
	for _, n := range cfg.ReservedNames {
		if strings.ToLower(n) == strings.ToLower(name) {
			return true
		}
	}
	return false
}
