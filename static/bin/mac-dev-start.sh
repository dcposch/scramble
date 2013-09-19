#!/bin/bash
set -e

# Install and configure Markdown and Go
brew install markdown go
echo "export GOPATH=$HOME/go" >> ~/.bashrc
source ~/.bashrc

# Clone the repo
mkdir -p ~/go/src
cd ~/go/src
git clone git@github.com:dcposch/scramble
cd scramble

# Compile and run
go get github.com/go-sql-driver/mysql
make

