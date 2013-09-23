package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"fmt"
)

type Config struct {
	DbServer   string
	DbUser     string
	DbPassword string
	DbCatalog  string

	SmtpMxHost string
	SmtpPort   int // internal, nginx handles TLS and forwards

	HttpPort int // internal, nginx handles SSL and forwards
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
}

var config Config

func init() {
	configFile := os.Getenv("HOME") + "/.scramble/config.json"

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
	err = ioutil.WriteFile(configFile, configBytes, 0600)
	if err != nil {
		panic(err)
	}
}
