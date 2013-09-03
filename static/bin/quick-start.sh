#!/bin/bash

# Install dependencies
echo "Installing MySQL and Nginx..."
sudo apt-get install mysql-server nginx

# Set up MySQL locally
# (By default, MySQL only accepts connections from localhost. 
#  Do NOT allow outside connections unless you've locked it down first.)
# Make a user `scramble` and corresponding DB. No password.
echo "Creating MySQL user 'scramble' and database 'scramble'..."
read -s -p "Enter MySQL root password: " pass
read -s -p "Enter MySQL password for new user 'scramble': " spass
(
    echo "create database if not exists scramble;"
    echo "grant all on scramble.* to scramble@localhost identified by '$spass';"
    echo "flush privileges;"
) | mysql -u root -p$pass


# Configure the Scramble app server
# Point it to your database server
echo "Writing app server configuration to ~/.scramble/db.config"
mkdir -p ~/.scramble
echo "scramble:$spass@/scramble" > ~/.scramble/db.config

# Download the latest release
echo "Downloading Scramble binary..."
wget https://scramble.io/bin/scramble -O scramble
chmod +x scramble

# Run it
./scramble

