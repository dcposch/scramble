
run: build
	./static/bin/scramble

build: build-go build-js
	echo "Build done"



#
# BUILD
#

GOPATH := $(shell pwd)
SRCS_GO := $(wildcard src/scramble/*.go)
SRCS_JS := $(wildcard static/js/lib/*.js static/js/*.js)
SRCS_MD := $(wildcard doc/*.md)
OUTPUT_HTML := $(SRCS_MD:%.md=static/%.html)

build-go: $(SRCS_GO)
	go get scramble
	mkdir -p bin
	go build -o bin/scramble src/cmd/scramble/*.go
	go build -o bin/scramble-notify src/cmd/scramble-notify/*.go
	cp bin/* static/bin/

build-js: $(SRCS_JS)
	npm install
	mkdir -p build/js
	jsx components/ build/js/
	browserify build/js/* > static/js/app.js


#
# UNIT TESTS
#

test: lint $(SRCS_GO) $(SRCS_JS)
	go test scramble
	cd static/js && cat stubs.js lib/sugar.min.js lib/openpgp.js lib/scrypt.js app.js test.js | node

lint: $(SRCS_GO)
	go get github.com/golang/lint/golint
	$(GOPATH)/bin/golint *.go



#
# DOCUMENTATION
#

doc: $(OUTPUT_HTML) static/doc/index.html

$(OUTPUT_HTML): $(SRCS_MD) doc/head.html
	mkdir -p static/doc
	cat doc/head.html > $@
	markdown doc/$*.md >> $@

static/doc/index.html: static/doc/why.html static/doc/quick-start.html
	cp static/doc/why.html static/doc/index.html

