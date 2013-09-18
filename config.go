package main

import (
	"os"
	"io/ioutil"
	"log"
	"strings"
)

type Config struct {
	MySQLHost  string

	ThisMxHost string
	SMTPPort   string // internal, which nginx forwards to
}

var config Config

func init() {
	// read configuration
	configFile := os.Getenv("HOME") + "/.scramble/scramble.config"
	configBytes, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Panicf("Please create config file %s with the following lines.\n"+
			"<db user>:<db pass>@<db host, empty if local>/scramble\n"+
			"<this mx host>",
			configFile)
	}
	configStr := strings.TrimSpace(string(configBytes))
	configLines := strings.Split(configStr, "\n")
	if len(configLines) != 2 {
		log.Panicf("Invalid number of lines in config file.\n"+
			"Please create config file %s with the following lines.\n"+
			"<db user>:<db pass>@<db host, empty if local>/scramble\n"+
			"<this mx host>",
			configFile)
	}
	config.MySQLHost = strings.TrimSpace(configLines[0])
	config.ThisMxHost = strings.TrimSpace(configLines[1])
	config.SMTPPort = "8825"
}

func GetConfig() *Config {
	return &config
}
