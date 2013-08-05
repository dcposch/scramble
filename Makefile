run: build
	~/go/bin/scramble

build: static/doc/why.html
	go install scramble

static/doc/why.html: doc/why.md
	mkdir -p static/doc
	echo '<!DOCTYPE html><head><link rel="stylesheet" href="/style.css" /><head><body>' > static/doc/why.html
	markdown doc/why.md >> static/doc/why.html
