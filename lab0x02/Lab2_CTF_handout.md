# Lab 2 - Software Security CTF

## What is a CTF?

A CTF is a security competition that simulates the role of an attacker trying to
exploit various services. Nowadays it is used by many security students and
professionals to improve their skills in various domains (binary exploitation,
reverse engineering, web hacking, ...) and compete against each other. In this
course it will be used to present you the practical side of the attacks and
mitigations shown in the lectures.

## Rules

There aren't many rules but those have to be absolutely respected:

- It is forbidden to hack the infrastructure, if you find a bug in it privately
  disclose it to use and we will be happy to reward you points. On the other
  hand if you use it for your advantage and we catch you, we might disqualify
  you.
- No bruteforcing: no challenge requires you to bruteforce anything on our
  server, so there is no need to send hundreds of requests. Students doing this
  will be penalized.
- Sharing flags or exploits is clearly forbidden as it is equivalent to sharing
  the solution of a classical homework. CTFs are fun to be played together and
  we encourage you to do so but as every other individual assignment in this
  school, the solution that you provide can be generated from a peer discussion
  but cannot be completely created together and be identical to another student.
- You can use every tool or technique you want (that doesn't violates any of the
  rules above), no limitations.

## Grading

The grade is represented by the number of points that you score over the total
of points. The grading is set up in a reversed way compared to a standard CTF:
easier challenges are worth more points than harder ones. This is because the
aim of this CTF is not to make you an advanced CTF player (but if you want to,
at Polygl0ts we are more than happy to welcome you) but to show in a fun way how
practical security is, and make you learn tools and techniques that you will
maybe use in your career.

For this reason, solving only easy challenges will still grant you most of the
points for this lab.

You will see that there are challenges that are worth only 5 points and
therefore have almost no influence on your grading, those challenges are for the
people that want to dig deeper in the techniques, prove they are the best in the
class or see what actual CTF challenges look like.  Beware that those challenges
are generally time sinkholes, and clearly they don't benefit your grade very
much.

Only 5 point challenges might be released after the start of the CTF and for a
total of maximum 20 additional points. This means that from the beginning you
could calculate exactly which challenges are needed for your desired grade. We
might reserve the right of modifying certain challenges if it is absolutely
needed for the good unfolding of the CTF.

At the end of the lab you will have to submit a writeup of the hardest challenge
you solved, meaning the challenge with the lower number of points. If you have
multiple challenges with equal points you can choose the challenge that you will
write the writeup for. A writeup is a document that explains how you solved the
challenge and includes your exploit (if any). You don't need to be super
detailed, a short explanation will suffice, it is enough to show that you
understood the challenge. You can submit your writeup in Markdown, Pdf or plain
text.

## Suggested tools

- [Ghidra](https://ghidra-sre.org/)(complete reverse engineering tool,
  opensource, created by the NSA)
- [Ida Free](https://hex-rays.com/ida-free/)(complete reverse engineering tool,
  free version of the famous and extremely costly Ida Pro)
- [GEF](https://gef.readthedocs.io/en/master/)(GDB plugin)
- [pwntools](https://docs.pwntools.com/en/stable/)(Python library for working
  with binaries)
- [Radare2](https://www.radare.org/n/)

## How to play

The platform is available only from the EPFL network therefore only while
connected to the EPFL wifi or while using the VPN.

Browse to
[http://hexhive005.iccluster.epfl.ch](http://hexhive005.iccluster.epfl.ch) and
register using your EPFL email address. After registration you can update your
profile if you want to or simply start solving challenges click on the
`Challenges` tab and all the challenges, divided by category, will be displayed
to you. If you want to see how you compare against your fellow colleagues you
can click on `Scoreboard`.

The flag format is: `SoftSec{[\x20-\x7E]*}`. An example flag is
`SoftSec{Hell0_World}`.

Certain challenges have hidden hints, revealing them doesn't cost you points
therefore you are free to look at them directly before starting the challenge or
try it without them and use them only when you are stuck.

## Additional resources

We are here to help, come to the exercise sessions or post on Moodle and we will
happily answer all your questions (as long as we are allowed to). Other than
that there are multiple resources online related to CTFs, techniques for solving
challenges, tools and more and we encourage you to look for them. Here we
present a selection that we think you might find useful.

General:
- [LiveOverflow Binary Exploitation/Rev/CTF playlist on
  YT](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN).
  This playlist starts from the basics and goes deeper than what you probably
  needs for this lab but you might interested in some videos of it.

Reverse engineering:
- [RE Intro](https://www.gh0s1.com/RE_0x00) focusing on assembly.

Ghidra:
- [Ghidra cheat
  sheet](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/stable/GhidraDocs/CheatSheet.html)
- [Basic Ghidra tutorial on YT](https://www.youtube.com/watch?v=fTGTnrgjuGA)
- [Ghidra and RE playlist on
  YT](https://www.youtube.com/playlist?list=PL_tws4AXg7auglkFo6ZRoWGXnWL0FHAEi)(I
  haven't actually seen it but it looks good)
- Here Be Dragons: Reverse Engineering with Ghidra ([part
  0](https://www.shogunlab.com/blog/2019/04/12/here-be-dragons-ghidra-0.html))([part
  1](https://www.shogunlab.com/blog/2019/12/22/here-be-dragons-ghidra-1.html)).
  Blog posts introducing Ghidra usage on real CTF challenges.
- [The Ghidra
  Book](https://slsp-epfl.primo.exlibrisgroup.com/discovery/fulldisplay?docid=cdi_askewsholts_vlebooks_9781718501034&context=PC&vid=41SLSP_EPF:prod&lang=en&search_scope=DN_and_CI&adaptor=Primo%20Central&tab=41SLSP_EPF_DN_CI&query=any,contains,ghidra)
  (Very good book on Ghidra and reverse engineering, available for reading
  online on the EPFL library via VPN)
- [Ghidra Reverse Engineering for beginners
  book](https://ebookcentral.proquest.com/lib/epflch/reader.action?docID=6449017&ppg=8)
  (Not really recommended but if you want another book it can be an option,
  accessible only via EPFL VPN)

Ida:
- [Ida tutorial on
  YT](https://www.youtube.com/watch?v=N_3AGB9Vf9E&list=PLKwUZp9HwWoDDBPvoapdbJ1rdofowT67z)
- [Ida pro
  book](https://slsp-epfl.primo.exlibrisgroup.com/discovery/fulldisplay?docid=alma991170402995105501&context=L&vid=41SLSP_EPF:prod&lang=fr&search_scope=DN_and_CI&adaptor=Local%20Search%20Engine&tab=41SLSP_EPF_DN_CI&query=any,contains,ida%20pro&offset=0)
  (Old but very complete resource available on the EPFL library via VPN)

Binary exploitation:
- [Pwn.college (Master level course on binary exploitation)](pwn.college)
