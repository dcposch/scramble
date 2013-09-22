#!/bin/bash

# Exit on failure
set -e

# Install dependencies
echo "Installing MySQL and Nginx. You must have Homebrew installed!"
brew update
brew install mysql nginx 

# Set up MySQL locally
# (By default, MySQL only accepts connections from localhost. 
#  Do NOT allow outside connections unless you've locked it down first.)
# Make a user `scramble` and corresponding DB. No password.
echo "Creating MySQL user 'scramble' and database 'scramble'..."
read -s -p "Enter MySQL root password: " pass
echo ""
read -s -p "Enter MySQL password for new user 'scramble': " spass
echo ""
(
    echo "create database if not exists scramble;"
    echo "grant all on scramble.* to scramble@localhost identified by '$spass';"
    echo "flush privileges;"
) | mysql -u root -p$pass

# Configure the Scramble app server
# Point it to your database server
echo "Writing app server configuration to ~/.scramble/scramble.config"
read -s -p "Enter MX host name: " host
echo ""
mkdir -p ~/.scramble
echo "scramble:$spass@/scramble\n$host" > ~/.scramble/scramble.config

# Download the latest release
echo "Downloading Scramble binary..."
curl https://scramble.io/bin/scramble-mac-64bit > scramble-mac-64bit
chmod +x scramble-mac-64bit

# Run it
./scramble-mac-64bit
