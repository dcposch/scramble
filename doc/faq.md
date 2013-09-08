<style>
body { width:600px; font-size:12px; }
p { margin-left:10px; }
</style>

Scramble FAQ
=======
<div>Frequently asked questions. If you have questions that aren't answered here, feel free to email me:</div>

    nqkgpx6bqscslher@scramble.io

Basics
----
### When I want to email someone through Scramble, do I give them my user name or the 'scrambled' email address? 
**Give them your email address.**

Your user name is just a easier way to log in, since it's memorable. Nobody except you needs to know your user name.

### Is it safe to give out my Scramble email via other channels (eg Gchat)?
**Yes, this is fine, and does not compromise your security.**

**There is one important caveat: you should not do it if you want *anonymity* in addition to security.**

Anonymity means never publically associating your name with your email address. When people have strong security requirements---they want to protect not only Subject and Body, but also *who* they talk to and *when*---they can achieve this by maintaining anonymity. 

That means only giving your email address out to people you trust. Don't communicate your Scramble address over channels which are likely wiretapped, such as conventional email or Gchat. Communicating in person (eg via a post-it note) is best. After the initial exchange, you can use Scramble to communicate freely, securely, and anonymously. The fewer people who know an anonymous address, the better the chance it will stay anonymous. Remember that it's always easy to generate a new Scramble account. Use Scramble through Tor, so as not to associate your email address with an IP address.

Most users won't require this level of protection, but it's possible in case you need it!

Security
-----
### Won't this be shut down, like Lavabit and Silent Circle?
**Having many Scramble servers in many places makes the system more robust.**

Our plan is for Scramble to be federated. That means that it's easy for organizations and even individuals to run their own Scramble server.

Many users will simply use scramble.io. A volunteer could run, say, scramble.fr with everything translated into French. An organization could run a Scramble server for its members. For example, you'd have addresses like <hash>@pirateparty.org.uk

We also plan to have volunteers run *mirrors*, or backup servers, around the world---so if your server ever goes down, your email should survive.

Finally, our goal is to keep users secure *even if an adversary took control of the server*, via the upcoming Chrome App. More on that below.

### Is Scramble owned by one organization?
**No. Scramble is open source.**

The goal is to have the code developed and vetted by people around the world.

As explained above, servers and backups will also be run by volunteers around the world.

### If the server I'm using (eg `scramble.io`) is wiretapped, can the adversary read my email?
**Fortunately not!**

Scamble uses end-to-end encryption. That means your messages are encrypted in your browser and decrypted in your recipient's browser, using Javascript. The server never knows the contents of your messages, nor the subjects, not even your address book.

### If a server is compromised, can the adversary add a backdoor to the Javascript?
**Only if you're using the web app.** 

Note that this is an extreme case that no other webmail we know of even tries to address.

We're working on a Chrome App, and possibly also a Firefox extension. These will be the same Scramble app you know and love---the same HTML, CSS, and Javascript---but installed locally on your computer. Once installed, you no longer rely on the server to give you valid code. 

At that point, an adversary could have full control of the server and you'd still be safe.

### Once the Chrome App is available, how can I install it securely?
**We're working on something called Deterministic Builds and we will sign the browser extensions we release.**

Together, these technologies will give you confidence that what you're installing comes from public, open source code that was vetted by security experts.

Features
-----
### Can we have Markdown instead of plain text?
**I've definitely thought about Markdown! That may be coming soon.**

Link highlighting is also in the pipeline.

### Can we have HTML email? Attachments?
**I'm not planning to support HTML. We may support attachments in the future, but not now.** 

The main reason is that typical rich media email is much (100x? 1000x?) bigger than typical plain text email. This has the following repercussions:

* It requires serious resources. Gmail, for example, gives users ~10GB inboxes, and the average user probably uses a gig or so. They have enormous server farms. I want Scramble to be federated, so I want it to be possible to run Scramble servers on a modest budget.

* It's slow. Even Google, with their massive resources and expertise, has to show people a loading bar when they log into Gmail. I don't prefer that. I want instant email.

* For Scramble, it would be really slow. You have to decrypt each email on the client, in Javascript.

To reiterate, my main reason for avoiding rich media is size, and all that it entails. There are a few additional reasons.

First, it lets us avoid the tricky and error-prone problem of sanitizing HTML. 

Second, the opponents of free, private, encrypted communication can't use the "think of the children" argument against us. It ensures that Scramble servers are never hosting porn.

Lastly, at least in my experience, most HTML email is advertisements and flyers, so I won't miss it :)

### What if I really need attachments?
**We're working on a solution.**

As described above, Scramble servers won't host attachments for you. But what happens when you need to share private documents? 

You can use one of the many existing services for hosting binaries, upload an encrypted copy, and then use Scramble to tell a trusted recipient the URL and passphrase. 

We'd like to give people an easy way to do that. We'll see if Mega, or a similar service, has an API we could use. For now, you'll have to do it manually.

