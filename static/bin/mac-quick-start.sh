#!/bin/bash

# Exit on failure
set -e

# Install dependencies
echo "Installing MySQL and Nginx. You must have Homebrew installed!"
brew update
brew install mysql nginx 

# Set up MySQL locally
echo "Creating MySQL user 'scramble', password 'scramble' and database 'scramble'..."
echo "(By default, MySQL only accepts connections from localhost."
echo " Do NOT allow outside connections unless you've locked it down first.)"
(
    echo "create database if not exists scramble;"
    echo "grant all on scramble.* to scramble@localhost identified by 'scramble';"
    echo "flush privileges;"
) | mysql -u root

# Configure the Scramble app server
# Point it to your database server
echo "Writing app server configuration to ~/.scramble/db.config"
mkdir -p ~/.scramble
echo "scramble:scramble@/scramble" > ~/.scramble/db.config

# Download the latest release
echo "Downloading Scramble binary..."
curl https://scramble.io/bin/scramble > scramble
chmod +x scramble-mac-64bit

# Run it
./scramble-mac-64bit

