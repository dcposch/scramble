run: build
	$(GOPATH)/bin/scramble

build: doc
	go install scramble
	cp $(GOPATH)/bin/scramble static/bin/scramble

MARKDOWN := $(shell ls doc/*.md)
HTML := $(MARKDOWN:%.md=static/%.html)
doc: $(HTML) static/doc/index.html

static/doc/never-forget.html: doc/never-forget.md
	mkdir -p static/doc
	markdown doc/never-forget.md > $@

static/doc/%.html: doc/%.md
	mkdir -p static/doc
	cat doc/head.html > $@
	markdown doc/$*.md >> $@

static/doc/index.html: static/doc/why.html static/doc/quick-start.html
	cp static/doc/why.html static/doc/index.html
