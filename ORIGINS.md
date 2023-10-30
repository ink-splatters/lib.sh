## Origins

_`lib.sh`_ intially emerged as sanity - preserving kit, aimed to make the unforgiving, barely recoverable experience of Apple _RecoveryOS_ - less punishing.

Later on it became the author's daily driver.

## Hurt

The Following paragraph is generously sponsored by Trent:

[![NIN - Hurt](http://img.youtube.com/vi/PbHz9p7Z4OU/1.jpg)](http://www.youtube.com/watch?v=PbHz9p7Z4OU "NIN - Hurt")

_Recovery_ has been always half-baked environment. Apple has been continously disabling it, arming against user's mental health. If one needs more than changing Security Policy via menu (1TR needs to be correctly booted!), it's all pain and dispair. It's taken over by bitrot. E.g., at some point in the past, more dylibs were moved to `dyldcache` which broke tons of CLI tools. This has become persistent, only to get even worse with each major release.

Apple hardly could care less, however: Recovery is stub OS, meaning they have a freedom to put absolute nonsense as far as it fulfills the minimum viable requirements.

### Hope not found

```
bash: rsync: command not found

bash-3.2 #
```

Nice move, Apple! It's because `rsync` now lives at `/Volumes/Macintosh HD/usr/libexec/rsync/rsync.samba`, as of _Sonoma_.

### Deliberate assault

Sometimes, however, it gets worse on purpose. That is: rockstar engineering workforce hired from all over the world is being wasted for pushing the limits of noncense. Indeed, why not enmasculate `gpt`:

```
bash-3.2 # gpt add
gpt: add: operation not permitted: add
```

Srsly, Apple, what did it do to you? Or is it perverted approach to security?

Good that [`gdisk`](https://sourceforge.net/projects/gptfdisk) just works fine.

### tmp1

Finishing my rant with a really funny stuff: some _Monterey_ release frorbade creating a user named `tmp`. In a couple of incremental updates it has been reverted :)

![image](https://github.com/ink-splatters/lib.sh/assets/2706884/03a29a17-c840-4391-9e7f-d9a2798715bd)
