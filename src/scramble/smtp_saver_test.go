package scramble

import "testing"

func TestPlainTextFromHTML(t *testing.T) {
	pairs := [...][2]string{
		{
			`
<!DOCTYPE html>
<!-- doctypes and comments are stripped -->
<div>Hello World</div>
`,
			`Hello World`,
		},
		{
			`
<!-- style tags are stripped -->
<style>
body { font-size:10em }
</style>
<!-- divs and paragraphs get a newline, spans don't -->
<div>This Is Just To Say</div>
<br />
<p>I have <span>eaten</span></p>
<p>the plums</p>
<p>that were in</p>
<p>the icebox</p>
`,
			`This Is Just To Say

I have eaten
the plums
that were in
the icebox`,
		},
		{`
<div>Hello World</div>
<div>Click here: <a href="https://google.com">Google</a></div>
`,
			`Hello World
Click here: ( link to https://google.com ) Google`,
		}}
	for _, pair := range pairs {
		in, out := pair[0], pair[1]
		if x, err := extractTextFromHTML(in); err != nil || x != out {
			t.Errorf("extractTextFromHTML on input:\n'%s'\nproduced output:\n'%s'\nshould be:\n'%s'", in, x, out)
		}
	}
}
