SCRAMBLE.IO
===========
Secure email for everyone.

Motivation
------
Big brother is here. Mass surveillance with breadth, depth, and immediacy. 

[With a few keystrokes](http://www.theguardian.com/world/2013/jul/31/nsa-top-secret-program-online-data), bureaucrats can read the emails you got this morning.

[You should care](http://www.thoughtcrime.org/blog/we-should-all-have-something-to-hide/), even if you think you have "nothing to hide". 


Technology
-------
Scramble is end-to-end encrypted webmail. That means the servers never have access to the plaintext message or body of your mail--only From and To. 

It uses public-key encryption. That leads to the tricky problem of key exchange. Our solution is make your email the hash of your public key. For example,

    a9f8173fa98237fa92bce89e1642a01a8a10ca0a@scramble.io

The bad news is that you can't memorize it. The good news is that you can look up someone's public key from an untrusted server, and easily verify it's correctness.
This is the same tradeoff that Tor Hidden Services make.

### Address book

You'll notice that your address book is now very important: since your contact's email addresses are just a jumble of letters and numbers, you need the address book in order to send mail or know who a received message is from.

To preserve your anonymity, the server stores your address book encrypted with your public key. When you log in, you download the encrypted address book, and decrypt it in your browser. Thus, not only are the Subject and Body unknown to the server, but the real names associated with From and To can also be anonymous.


New Threat Model
------------
The old threat model was simple. Hackers from faraway countries, scammers, or just the "grey hat" guy on the same cafe WiFi network as you.
Those people shouldn't be able to read your email.

Existing webmail services, such as Gmail, address this threat adequately. They use HTTPS, they use secure SMTP, they support two-factor authentication, and so on.

The new threat is more complex. Centralized adversaries, such as the Chinese government or the NSA, compromise the privacy of entire countries. Existing services offer no protection against them.

A few months ago, for example, a Chinese root CA issued a false certificate for mail.google.com. This allowed the government to run a MITM attack against certain activists. With the green lock logo still there, the victims had no way to know anything was amiss. This is not Google's fault--it's an inherent limitation of HTTPS. Centralized adversaries, unlike typical hackers, control root CAs.

A few weeks ago, we learned that American government takes an even more direct approach. Using a secret judgement, rendered by a secret court and based on secret laws, they go directly to places where data already resides--such as Google's servers--and compel the owners to provide a secret backdoor. That is, Google is not allowed to tell its users that they're being spied on.

The new threat model is harsh: all data not stored by yourself or your recipient is available to the adversary. Hence, scramble.io ensures that the server never stores (or even sees) your plaintext.


Down the Rabbit Hole
---------
Another possibility goes further than a backdoor: centralized aversaries could simply commandeer our servers.
For now, that threat is just theoretical, but experience shows it's never too early to start planning.

Users of webmail are inherently not secure against such an attack. The adversary can simply serve them modifed Javascript, designed to reveal their passpharse, private key, or plaintext emails.

To protect against this, we plan to offer a browser extension soon. Once installed, you'll have the same UI you know and love---but the HTML, CSS, and Javascript are now being served from local disk. An adversary cannot serve you tainted code, and they cannot access any of your data, even if they control the server. Remember, everything you send the server is already encrypted!


Why Not PGP?
---------
PGP has been around for a very long time, yet almost nobody uses it.
This is a shame.

I see three problems with PGP:
* It's hard to use
* It's only useful if your friends already use PGP: the network effect problem
* It encrypts only the body of your messages. This means that a central adversary still knows who you're talking to, when, and what the subject lines say.

Scramble is my attempt to address all of these shortcomings.


Opt-In Security
--------
Scramble is for everyone. Hence, we want to accomodate a lot of choices.

Users who care most about convenience can use the webmail client. They can check their email anywhere, even on a library computer. They can exchange mail with regular, unencrypted addresses. Even then, they get better protection than current webmail offers: because the server encrypts all mail with the recipient's public key before storing it, nobody can retroactively ask us for the contents of your inbox. We don't know what's there.

Users who want even stronger security can keep their address secret except from people they trust. To spies, the address is anonymous. They can also use the browser extension intead of webmail.

Here's the full set of options and the threat models they protect against.

<table>
<th>	<td></td>				<td>Normal Hackers</td>	<td>Content</td>	<td>Metadata</td>	<td>Wiretap</td>	<td>Full compromise</td></th>
<tr>	<td>Gmail</td>				<td class="sec"></td>	<td class="insec"></td>	<td class="insec"></td>	<td class="insec"></td>	<td class="insec"></td></tr>
<tr>	<td>Scramble Web</td>			<td class="sec"></td>	<td class="sec"></td>	<td class="insec"></td>	<td class="sec"></td>	<td class="insec"></td></tr>
<tr>	<td>Scramble Web, Anon</td>		<td class="sec"></td>	<td class="sec"></td>	<td class="sec"></td>	<td class="sec"></td>	<td class="insec"></td></tr>
<tr>	<td>Scramble Extension</td>		<td class="sec"></td>	<td class="sec"></td>	<td class="insec"></td>	<td class="sec"></td>	<td class="sec"></td></tr>
<tr>	<td>Scramble Extension, Anon</td>	<td class="sec"></td>	<td class="sec"></td>	<td class="sec"></td>	<td class="sec"></td>	<td class="sec"></td></tr>
</table>


Revenue
------
You'll notice that since the server never sees the contents of an email, it knows nothing about its users. That's the point! So targetted advertising isn't possible... and even if were, I don't like it.

Scramble is free and ad-free. Its our gift to you. We want you to exercise your Fourth Amendent freedoms, to communicate without fear of "unreasonable search".

If you'd like to help, check out the [Github repo](http://github.com/dcposch/scrable), or maybe send us a few Bitcoin :)

