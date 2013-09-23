#!/bin/bash

# Exit on failure
set -e

# Install dependencies
echo "Installing MySQL and Nginx..."
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install mysql-server nginx 

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


# Download the latest release
echo "Downloading Scramble binary..."
wget https://scramble.io/bin/scramble -O scramble
chmod +x scramble

# Run it
./scramble

# Configure the Scramble app server at ~/.scramble/config.json
# Point it to your database server & run ./scramble again
