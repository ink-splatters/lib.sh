## Origins

_`lib.sh`_ intially emerged as sanity - preserving kit, aimed to make the unforgiving, barely recoverable experience of Apple _RecoveryOS_ - less punishing.

Later on it became the author's daily driver.

## Hurt

The Following paragraph is generously sponsored by Trent:

[![NIN - Hurt](http://img.youtube.com/vi/PbHz9p7Z4OU/1.jpg)](http://www.youtube.com/watch?v=PbHz9p7Z4OU "NIN - Hurt")

_Recovery_ has been always half-baked environment. Apple hardly could care less, however, and let it rot in every aspect but related to Platform Security.

More, when it comes to improving Platform Security across the products, Apple assumes a user must pay for it with damn degrade in their experience.
Well, _because they always pay no matter what_.

Take _Sonoma_: why the hell manipulating `~/Library/Containers` is so slow, even under root?

And even more interesting: why does

```sh
mv ~/Library/C{ontainers,}
do_hacky_stuff
mv ~/Library/C{,ontainers}
```

make `hucky_stuff` **FAST AGAIN** as it had been with pre-Sonoma releases?

_Apple, do you count on a poor malicious actor suddenly having succumbed to Comprehending the Essense of the Slowness?_

### Hope not found

Again, _Sonoma_:

```sh
bash: rsync: command not found

bash-3.2 #
```

That's due to `rsync` now suddenly living at `/Volumes/Macintosh HD/usr/libexec/rsync/rsync.samba`. Nothing to worry about though
as this is exactly how caring even less looks like. In the end, consistency is half of the success!

_"All is going according to the plan"_ (C)

### Deliberate assault

Sometimes, however, it gets worse on purpose which makes me imagine that _Apple rockstar 10x engineers_ are pushed to their limits in terms of
building Security via Emasculation.

Figurally speaking, penile shaft of `gpt` utility bundled with RecoveryOS, was left without its _satellites_ if say so, for good or not:

```sh
bash-3.2 # gpt add
gpt: add: operation not permitted: add
```

This is:

```c
if (true) { fuck_you(); }
```

that was planted to `gpt.c` to sit like a stuck fishbone in the throat, _in order for thou, user, to know your place!_

Annoying? Of course! But only a little bit: it takes up next to no time to download `gdisk`
which is _allowed_ to make GPT modifications:

```sh
bash-3.2 # curl -LO https://sourceforge.net/projects/gptfdisk/files/gdisk-1.0.10.pkg
   % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   408    0   408    0     0    955      0 --:--:-- --:--:-- --:--:--   955
100   649    0   649    0     0    545      0 --:--:--  0:00:01 --:--:--   545
100   387  100   387    0     0    199      0  0:00:01  0:00:01 --:--:--   675
100  472k  100  472k    0     0   194k      0  0:00:02  0:00:02 --:--:-- 2954k

bash-3.2 # pkgutil --expand-all gdisk-* gdisk
```

and `./gdisk/Payload/usr/local/bin/gdisk` is now your Jedi GPT force!

Loks like the art of eunuchizing fails to deliver.

______________________________________________________________________

But what I can't underestimate Apple for, is how they disable the fuck out of User Input

That _Failed to create activation request_ screen which can be done nothing about (most of times),
even appeals to somewhat masochistic statisfaction.

Somtimes. (if you made a backup)

### tmp1

Finishing it with absolutely hilarious stuff:

some _Monterey_ release once had _forbidden creating a user named `tmp`_ in Setup Assistant.

In a couple of _incremental_ updates **THIS CHANGE WAS REVERTED**

![image](https://github.com/ink-splatters/lib.sh/assets/2706884/03a29a17-c840-4391-9e7f-d9a2798715bd)

Please feel free to post issues with only wrong stories about what was taking place at Apple's Setup Assistant team, back then between those releases :)
