run: build
	~/go/bin/gpgmail.io

build: static/doc/why.html
	go install gpgmail.io

static/doc/why.html: doc/why.md
	mkdir -p static/doc
	echo '<!DOCTYPE html><head><link rel="stylesheet" href="/style.css" /><head><body>' > static/doc/why.html
	markdown doc/why.md >> static/doc/why.html
