<style>
body { width:600px }
td.sec { background:#090 }
td.ins { background:#a00 }
table { layout:fixed }
th,td { font-size:11px; width:100px; height:30px; border:1px solid transparent; cursor:pointer; }
th.label,td.label { width:180px }
div#explanation { font-size:11px; width: 600px; height:60px; margin:20px 6px; }
</style>

<a href="https://github.com/dcposch/scramble"><img style="position: absolute; top: 0; right: 0; border: 0;" src="https://s3.amazonaws.com/github/ribbons/forkme_right_gray_6d6d6d.png" alt="Fork me on GitHub"></a>

SCRAMBLE.io
===========
Secure email for everyone.

Motivation
------
Big brother is here. Mass surveillance with breadth, depth, and immediacy.

[With a few keystrokes](http://www.theguardian.com/world/2013/jul/31/nsa-top-secret-program-online-data), bureaucrats can read the emails you got this morning.

[You should care](http://www.thoughtcrime.org/blog/we-should-all-have-something-to-hide/), even if you have nothing to hide.


Technology
-------

This is a work in progress. 

- Do check it out! 
- Don't use it for anything sensitive yet

Ideas, bug reports, and code reviews are much appreciated.

### Encryption

Scramble is end-to-end encrypted webmail. For conversations between Scramble addresses, the servers never have access to the plaintext message or body of your mail--only From and To. 

It uses public-key encryption. That leads to the tricky problem of key exchange. Our solution is make your email the hash of your public key. For example,

    a9f8173fa98237fa92bce89e1642a01a8a10ca0a@scramble.io

The bad news is that you can't memorize it. The good news is that you can look up someone's public key from an untrusted server, and easily verify its correctness.
This is the same tradeoff that Tor Hidden Services make.

### Address book

Your address book is now very important: since your contacts' email addresses are just a jumble of letters and numbers, you need the address book in order to send mail or know who a received message is from.

To preserve your anonymity, the server stores your address book encrypted with your own public key. When you log in, you download the encrypted address book, and decrypt it in your browser. If you add new entries, the client encrypts the modified address book, again in the browser, and sends it back to the server. Thus, not only are the Subject and Body of each email unknown to the server, but the real names associated with From and To can also be anonymous.


### Compatibility

Some users will opt for less security and more convenience.

For compatibility, you can exchange email with addresses outside of Scramble. Those messages are sent in plaintext. Incoming plaintext messages are encrypted with your public key for storage, so nobody can obtain the records from Scramble after the fact. 

Be careful about doing this, especially if you want to keep your address anonymous. The security guarantees here are, of course, weaker than for conversations between Scramble users.


The Old Threat Model
------------
The old threat model was simple. Hackers from faraway countries, scammers, or just the troll sharing an open cafe WiFi network with you.
Those people shouldn't be able to read your email.

Existing webmail services, such as Gmail, address this threat adequately. They use HTTPS, they use secure SMTP, they support two-factor authentication, and so on.

A Brave New World
-------
The new threat is more complex. Centralized adversaries, such as the Chinese government or the NSA, compromise the privacy of entire populations. Existing services have proven to be insecure.

A few months ago, for example, a Chinese root CA issued a false certificate for mail.google.com. This allowed the government to run a MITM attack against certain activists. With the green lock logo still there, the victims had no easy way to know anything was amiss. This is not Google's fault--it's an inherent limitation of HTTPS. Centralized adversaries, unlike typical hackers, control root CAs.

Then, a few weeks ago, we learned that American government takes an even more direct approach. Using a secret judgement, rendered by a secret court and based on secret laws, they go to the places where data already resides--such as Google's servers--and compel the owners to provide secret access. That is, Google is not allowed to tell its users that they're being spied on. 

The new threat model is harsh: all data not stored by yourself or your recipient is available to the adversary. Hence, Scramble servers store only ciphertext. 


Down the Rabbit Hole
---------
Another possibility goes further than demanding email records: centralized adversaries could simply commandeer our servers.
For now, that threat is just theoretical, but given recent events it's never too early to start planning.

Users of webmail are inherently not secure against such an attack. The adversary can simply serve them modifed Javascript, designed to reveal their passpharse, private key, or plaintext emails.

To protect against this, we plan to offer a browser extension soon. Once installed, you'll have the same UI you know and love---but the HTML, CSS, and Javascript will be served from local disk. An adversary cannot serve you tainted code, and they cannot access any of your plaintext, even if they control the server. The server is fully untrusted, and everything you send to or receive from it is already encrypted!


Why Not PGP?
---------
PGP has been around for a very long time, yet almost nobody uses it.
This is a shame.

We see three problems with PGP:

- It's hard to use
- It's only useful if your friends use PGP: the network effect problem
- In typical use, it encrypts only the body of your messages. This means that a central adversary still knows who you're talking to, when, and what the subject lines say.

Scramble is our attempt to fix these shortcomings.

Opt-In Security
--------
Scramble is for everyone. Hence, we want to accomodate a lot of choices.

Users who care most about convenience can use the webmail client. They can check their email anywhere, even on a library computer. They can exchange mail with regular, unencrypted addresses. Even then, they get better protection than current webmail offers: because the server encrypts all mail with the recipient's public key before storing it, nobody can retroactively ask us for the contents of your inbox. We don't know what's there.

Users who want even stronger security can keep their address secret except from people they trust. To spies, the address is anonymous. They can also use the browser extension intead of webmail.

Here's the full set of options and the threat models they protect against.

<table>
<tr>    <th class="label"></th>
        <th class="ev">Eavesdrop</th>     <th class="dc">Demand Records</th> <th class="wt">SSL Wiretap</th>       <th class="fc">Full compromise</th>
</tr>
<tr>    <td class="label gmail">Gmail</td>
        <td class="ev gmail sec"></td>    <td class="dc gmail ins"></td>     <td class="wt gmail ins"></td>    <td class="fc gmail ins"></td>
</tr>
<tr>    <td class="label scrwb">Scramble Webmail</td>
        <td class="ev scrwb sec"></td>    <td class="dc scrwb sec"></td>     <td class="wt scrwb ins"></td>    <td class="fc scrwb ins"></td>
</tr>
<tr>    <td class="label screx">Scramble Extension</td>
        <td class="ev screx sec"></td>    <td class="dc screx sec"></td>     <td class="wt screx sec"></td>    <td class="fc screx sec"></td>
</tr>
</table>
<div id="explanation"></div>

<script type="text/javascript" src="/js/jquery.min.js"></script>
<script type="text/javascript">
var defaultText = "Mouse over for explanation...";
$("#explanation").text(defaultText);
$("table").mouseleave(function(){
    $("#explanation").text(defaultText);
});

function show(sel, text) {
    $(sel).mouseover(function(){$("#explanation").html(text)})
}

show("td.label.gmail", "GMail and other webmail programs.")
show("td.label.scrwb", "Scramble.io website. You share your email only with people you trust.")
show("td.label.screx", "Scramble.io Chrome extension. You share your email only with people you trust.")

show("th.ev", "Someone is capturing your packets, for example on open WiFi or at your ISP.");
show("th.dc", "A central adversary compels the host to hand over email records.");
show("th.wt", "A central adversary with the power to issue a fake certificate and execute a MITM attack. <br/>"+
              "Also beware of SSL stripping. Scramble.io is HTTPS only, if you ever see http://scramble.io, don't log in!");
show("th.fc", "A central adversary compels the host to serve broken Javascript. <br/>"+
              "Alternatively, the host is owned by hackers.");

show("td.ev.gmail", "Programs like Gmail use HTTP and secure SMTP to defend against eavesdroppers.");
show("td.ev.scrwb", "Scramble uses HTTPS to defend against eavesdroppers. They can't even see the encrypted private key to attempt passphrase cracking.");
show("td.ev.screx", "Scramble uses HTTPS to defend against eavesdroppers. They can't even see the encrypted private key to attempt passphrase cracking.");

show("td.dc.gmail", "With National Security Letters and other tools, central adversaries can spy on traditional webmail.");
show("td.dc.scrwb", "Scramble servers never see the plaintext of message bodies, subjects, or address books.<br/>" +
                    "The servers only know the From and To addresses.<br/>" +
                    "If you share your address only with people you trust, spies might not even know which public key is yours.");
show("td.dc.screx", "Scramble servers never see the plaintext of message bodies, subjects, or address books.<br/>" +
                    "The servers only know the From and To addresses.<br/>" +
                    "If you share your address only with people you trust, spies might not even know which public key is yours.");

show("td.wt.gmail", "With a man-in-the-middle attack, adversaries can passively read webmail contents.");
show("td.wt.scrwb", "With a man-in-the-middle attack, adversaries can actively insert malicious Javascript to break Scramble's security.");
show("td.wt.screx", "The browser extension does not download any code from the server. <br/>"+
                    "It treats the server as fully untrusted, so even with an SSL wiretap, your mail should be secure.");

show("td.fc.gmail", "If they control the server, adversaries can do anything.");
show("td.fc.scrwb", "If they control the server, adversaries can actively insert malicious Javascript to break Scramble's security.");
show("td.fc.screx", "The browser extension does not download any code from the server. <br/>"+
                    "It treats the server as fully untrusted, so even if the server is compromised, your mail should be secure.<br/>" +
                    "(The service might stop working, but it won't reveal your plaintexts.)");
</script>

Revenue
------
You'll notice that since the server never sees the contents of an email, it knows nothing about its users. So targeted advertising isn't possible... and even if were, we don't like it.

Scramble is free and ad-free. Its our gift to you. We want you to exercise your Fourth Amendent freedoms, to communicate without fear of "unreasonable search and seizure".

If you'd like to help, check out the [Github repo](http://github.com/dcposch/scramble)


