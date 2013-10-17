package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type Config struct {
	DbServer   string
	DbUser     string
	DbPassword string
	DbCatalog  string

	SmtpMxHost string
	SmtpPort   int // internal, nginx handles TLS and forwards

	HttpPort int // internal, nginx handles SSL and forwards

	SeedNotaries []string // for seeding new accounts

	ReservedNames []string // reserved usernames
}

func GetConfig() *Config {
	return &config
}

var defaultConfig = Config{
	"127.0.0.1",
	"scramble",
	"scramble",
	"scramble",

	"dev.scramble.io",
	8825,

	8888,

	[]string{"hashed.im", "dev.hashed.im"},

	[]string{"admin", "administrator", "root", "support", "help", "spam",
		"info", "contact", "webmaster", "abuse", "security", "mailer-daemon",
		"mailer", "daemon", "postmaster"},
}

var config Config

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
	config = defaultConfig
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
	err = ioutil.WriteFile(configFile, configBytes, 0600)
	if err != nil {
		panic(err)
	}
}

func (cfg *Config) IsReservedName(name string) bool {
	for _, n := range cfg.ReservedNames {
		if strings.ToLower(n) == strings.ToLower(name) {
			return true
		}
	}
	return false
}
