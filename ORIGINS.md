## Origins

While used in `macOS` on daily basis by author, it initially emerged as
improvised survival kit, borne to make miserable, irrecoverable experience of Apple
`RecoveryOS` less punishing. There is zero proud about it and this tool should probably
have never existed, thus all the benefits of using it are just supprising side effect
of struggling to preserve some sanity.

### Hope not found

```shell
bash: rsync: command not found

bash-3.2 #
```

Apple has been continously arming `RecoveryOS` against operator's mental health.

For the luckiest ones, who just need to switch `SIP` on/off or enable 3rd-party KEXTs, it may not pose an issue, but otherwise it's advised to prepare for the worst. Or if the reader already got sadly aquainted to it, they may want to stop reading.

### The Fall

```shell
bash-3.2 # top
bash: top: command not found # of course there is no top, neither is there a bottom

bash-3.2 #
```

Initially eunuchized, prostrate environment, it has been degrading over time. And while the _top of it_ was left behind long time ago,
the bottom is also yet to be seen, so this abyssic fall seems neverending.

It's taken over by bitrot. E.g. Apple's moving more dylibs to `dyldcache` just broke tons of tools in Recovery. Well, of course, Apple hardly could
care less about it.

### Perverted stance on security

```shell
bash-3.2 # gpt add
gpt: add: operation not permitted: add
```

But it's unthinkable that some disimprovements are being made on purpuse. That is, rockstars Apple engineers hired from all over the world, keep on working hard, probing the limit of "breaking things and getting away with it".

So, one of their latest targeted assaults emasculated `gpt` utility, which has lost ability to make any modifications to partition tables.

Srsly, Apple, **why**? Especially, given [`gdisk`](https://sourceforge.net/projects/gptfdisk) continues to work like a charm and requires no special entitlements or stuff.

While the question stays open for a reader, I can't come up with better answer for myself, than

Tim's _because fuck you submissive cash cows, that's why_.

### Script Kiddie's woe

As survival kit, anxiously crafted from bunch of oneliners, it probably may look even more ugly than I anticipate, so don't expect it to be more nice than the beast it was supposed to fight. Generally it needs good refactoring, but I really don't feel like investing into it :)
