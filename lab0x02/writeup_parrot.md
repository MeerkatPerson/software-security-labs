
# CTF Writeup: Parrot (20 points)

## by Theresa Tratzmüller, 344665

For this challenge (probably the one that shows the most creativity on the creator's part!), we are given a Telegram bot to interact with. 

It offers the following commands to interact with the environment it is embedded in:

```
/pun - tell me a really, really funny joke
/say <text> - let me speak to you
/source - hear the source of this program
```

The initial hope that the solution is hidden somewhere in the puns soon dissipates. It seems required to dig into the source, i.e., spend some unpleasant minutes listening to the source code. At shortly over 2 minutes, we hear an interesting fact: when we use the `/say` command, what we tell the parrot to say will end up in a call to `system`!

Naturally, the first thing to try is `/say ;cat flag`. The response is: `SoftSec ... some ... characters ... are ... non ... pronouncable`. At first glance, it seems that the flag is composed of non-pronouncable characters and the bot merely informs us of this fact, but listening to the source code of the `say`-function once more reveals that there is no instruction telling the bot to give us such information. Instead, the message `some characters are non-pronouncable` seems to be a part of the flag. 

Firstly, we notice that the bot has not mentioned any curly braces, but we know that all of the flags are of the form `SoftSec{Hell0_W0rld}`.
What else can not be pronounced? One could bruteforce this, by having the bot say all kinds of things including special symbols, but that would be too tedious. There has to be some other way!

Digging around in obscure corners of the internet delivers the final clue: we need to get the bot to tell us the hex-representation of the flag, whereupon we can then convert the hex symbols to unicode. The relevant command is this:

```
/say ; cat flag | od -v -t x1 -A n | tr -d '\n'
```

After some unpleasant transcription, we arrive at this hex representation of the symbols the flag is composed of:

```
53 6f 66 74 53 65 63 7b 73 6f 6d 65 5f 27 63 68 61 72 61 63 74 65 72 73 27 5f 69 6e 5f 66 6c 61 67 5f 27 61 72 65 27 5f 27 6e 6f 6e 27 5f 70 72 6f 6e 6f 75 6e 63 65 61 62 6c 65 7d 0a
```

Which in UniCode corresponds to:

```
SoftSec{some_'characters'_in_flag_'are'_'non'_pronounceable}
```