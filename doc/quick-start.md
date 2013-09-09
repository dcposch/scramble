<style>
body { width:650px }
iframe { width:650px; height: 650px; }
</style>


SCRAMBLE.io Quick Start
======

Run a Scramble server, the easy way
----
This script interactively installs MySQL and configures Scramble. You can start from zero, with a freshly installed Ubuntu server.

Follow the instructions, then go to `http://localhost:8888` to see results.

Here's the script, <a href="/bin/quick-start.sh">quick-start.sh</a>:

<iframe src="/bin/quick-start.sh" style="border:none"></iframe>

Go produces statically linked binaries with no dependencies. It's awesome.

You can run the database server and application server on different machines. <br />
Just edit `~/.scramble/db.config` on the app server.

We'll add a mechanism to sign the `scramble` binary soon. More on that under "Sign Scramble Releases", below.


Run a real Scrable server
----
For actual use, you'll need to serve a domain with HTTPS, not `http://localhost:8888/`.

### Hosting
Linode and AWS both work well. 
I recommend Linode, since they have a free real-time monitoring tool.

Install Scramble as described above.

I recommend [locking down your server](http://feross.org/how-to-setup-your-linode/) to avoid being compromised.

### Domain name
I've had a good experience with Gandi, which also provides DNS and SSL certificates.

### SSL Certificate
You'll have to buy an SSL certificate for your domain. Install it on your server. [Here's how.](http://www.digicert.com/ssl-certificate-installation-nginx.htm)

### Nginx
Configure Nginx. Here's the configuration for `scramble.io`. Fill in your own details.

    # Serve scramble.io
    # The application server (Go)
    upstream app_scramble {
        server 127.0.0.1:8888;
    }
    # Handle SSL connections. Forward to the Scramble application server.
    # Old should be expired and securely deleted regularly.
    server {
        server_name scramble.io;
        access_log /var/log/nginx/scramble.log;

        listen 443;
        ssl on; 
        ssl_certificate /etc/ssl/scramble.io/scramble.gandi.crt;
        ssl_certificate_key /etc/ssl/scramble.io/scramble.key;


        location / { 
            proxy_pass http://app_scramble/;
            proxy_redirect off;
            proxy_set_header Host $host;
        }   
    }
    # Redirect HTTP to HTTPS
    server {
        server_name scramble.io;
        listen 80; 
        return 301 https://$host$request_uri;
    }

### Cron
Back up the database. Rotate the logs. Both should be copied to a different disk, ideally in a different location. Here's my basic configuration.

    > crontab -e

    0 3 * * * ~/backup.sh

Here's backup.sh

    # Back up the Scramble.io DB
    FNAME=~/dumps/`date +%Y%m%d`.sql.gz
    echo "`date '+%Y-%m-%d %H:%M'` Backup up Scramble.io DB to $FNAME"
    mysqldump -u<YOUR DB USER> -p<YOUR DB PASSWORD> scramble | gzip -c > $FNAME
    echo "`date '+%Y-%m-%d %H:%M'` `du -sh $FNAME`"

If you've made it this far, you have a usable mail server. Thanks for helping defending people's rights!


Sign Scramble releases
----
As mentioned above, I need a mechanism to sign Scramble releases.

That way, people who run Scramble servers will be protected even if this website is compromised or someone compels me to serve a bad version of Scramble, as long as they check the signature.

I would like each release to be signed not just by myself, but by a group of volunteers in different countries.

I propose the following process:

* We develop, test and code review in public.
* We announce a new release candidate, specifying the git commit hash.
* You, the volunteer, check out the specified commit. 
  Git verifies hashes, so you have confidence that all volunteers are looking at the same code.
* You compile the binary.
  Scramble will have a repeatable build process, so each volunteer produces an identical binary from source.
* You sign the binary.
* We publish the new release, displaying all the signatures on this page.
* People who run Scramble servers are invited to upgrade, checking the signatures.


Develop Scramble
----

Prerequisites: Git, Go, and Screen

To install this on Ubuntu:

    sudo apt-get install git golang screen

Then, set up Go. For example:

    cd ~
    mkdir -p go/src
    echo "export GOPATH=/home/dc/go" >> ~/.bashrc
    echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
    source ~/.bashrc

Then, run Scramble:

    cd ~/go/src
    git clone git@github.com:dcposch/scramble
    cd scramble
    make

Navigate to `http://localhost:8888`.

### Coding style

* Go
  * Standard formatting. Using `gofmt` before committing. 
  * Write godoc. 
  * Write tests.
* Javascript
  * No semicolons at the end of the line.
  * Always use braces. 
  * Write comments before each function. 
  * We'll add jslint or something soon.
* Both languages
  * No lines over 80 characters. Unix line endings. Tabs, not spaces. 
  * Use consisent prefixes and suffixes in variable names to avoid confusion. 
    For example, `plainSubject`, `cipherSubject`, `plainBody`, `cipherBody`.

And to steal from the Zen of Python...

* Explicit is better than implicit
* Flat is better than nested
* Beautiful is better than ugly

### First pull request
You can make your first pull request in an hour or so!

* Fix a bug: https://github.com/dcposch/scramble/issues
* Write a unit test
* Pull requests that only add comments or documentation are still cool

