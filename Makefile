GOPATH := $(shell pwd)

run: build
	./static/bin/scramble

build: doc $(shell find . -name '*.go') $(shell find . -name '*.js')
	go get scramble
	mkdir -p bin
	go build -o bin/scramble src/cmd/scramble/*.go
	go build -o bin/scramble-notify src/cmd/scramble-notify/*.go
	cp bin/* static/bin/

test: $(shell find . -name '*.go') $(shell find . -name '*.js')
	go test scramble
	cd static/js && cat stubs.js lib/sugar.min.js lib/openpgp.js lib/scrypt.js app.js test.js | node

lint: 
	go get github.com/golang/lint/golint
	$(GOPATH)/bin/golint *.go

chrome:
	rm -rf build/chrome_extension
	mkdir -p build/chrome_extension
	cp static/chrome_extension/* build/chrome_extension/
	cp static/index.html build/chrome_extension/
	cp static/favicon.ico build/chrome_extension/
	cp -r static/js build/chrome_extension/js
	cp -r static/css build/chrome_extension/css
	echo "\nChrome extension built to ./build/chrome_extension!\n"

MARKDOWN := $(shell ls doc/*.md)
HTML := $(MARKDOWN:%.md=static/%.html)
doc: $(HTML) static/doc/index.html

static/doc/never-forget.html: doc/never-forget.md
	mkdir -p static/doc
	markdown doc/never-forget.md > $@

static/doc/slideshow.html: doc/slideshow.html
	mkdir -p static/doc
	cp doc/slideshow.html static/doc/slideshow.html

static/doc/%.html: doc/%.md doc/head.html
	mkdir -p static/doc
	cat doc/head.html > $@
	markdown doc/$*.md >> $@

static/doc/index.html: static/doc/why.html static/doc/quick-start.html
	cp static/doc/why.html static/doc/index.html

