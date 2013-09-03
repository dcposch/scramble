run: build
	~/go/bin/scramble

build: doc
	go install scramble

doc: static/doc/index.html static/doc/how.html

static/doc/%.html: doc/%.md
	mkdir -p static/doc
	cat doc/head.html > $@
	markdown doc/$*.md >> $@

static/doc/index.html: static/doc/why.html static/doc/quick-start.html
	cp static/doc/why.html static/doc/index.html
