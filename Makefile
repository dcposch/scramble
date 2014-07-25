#
# RUN
#

run: build
	./static/bin/scramble


#
# BUILD
#

GOPATH := $(shell pwd)
SRCS_GO := $(wildcard src/scramble/*.go)
SRCS_JS := $(wildcard src/js/lib/*.js src/js/*.js)
SRCS_JSX := $(wildcard src/jsx/*.jsx)
SRCS_GEN_JS := $(SRCS_JSX:.jsx=.js)

OUTPUT_HTML := $(SRCS_MD:%.md=static/%.html)

build: build-go build-js
	echo "Build done"

build-go: $(SRCS_GO)
	go get scramble
	mkdir -p bin
	go build -o bin/scramble src/cmd/scramble/*.go
	go build -o bin/scramble-notify src/cmd/scramble-notify/*.go
	cp bin/* static/bin/

src/jsx/%.js: src/jsx/%.jsx
	jsx $^ > $@

build-js: $(SRCS_JS) $(SRCS_GEN_JS)
	npm install
	browserify $(SRCS_JS) $(SRCS_GEN_JS) > static/js/app.js

clean:
	rm static/js/app.js
	rm src/jsx/*.js
	rm static/doc/*.html


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

