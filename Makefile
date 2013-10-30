run: build
	$(GOPATH)/bin/scramble

build: doc
	go get .
	go install .
	cp $(GOPATH)/bin/scramble static/bin/scramble

test:
	go test
	cat static/js/stubs.js static/js/sugar.js static/js/openpgp.js static/js/scrypt.js static/js/app.js static/js/test.js | node

lint:
	go get github.com/golang/lint/golint
	../../bin/golint *.go

MARKDOWN := $(shell ls doc/*.md)
HTML := $(MARKDOWN:%.md=static/%.html)
doc: $(HTML) static/doc/index.html

static/doc/never-forget.html: doc/never-forget.md
	mkdir -p static/doc
	markdown doc/never-forget.md > $@

static/doc/slideshow.html: doc/slideshow.html
	mkdir -p static/doc
	cp doc/slideshow.html static/doc/slideshow.html

static/doc/%.html: doc/%.md
	mkdir -p static/doc
	cat doc/head.html > $@
	markdown doc/$*.md >> $@

static/doc/index.html: static/doc/why.html static/doc/quick-start.html
	cp static/doc/why.html static/doc/index.html
