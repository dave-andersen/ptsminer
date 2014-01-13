Protoshares Pool Miner (PTS Miner)
==================================

This is a protoshares pool mining version
based on xolokrams's [primecoin miner](https://github.com/thbaumbach/primecoin).
and Invictus Innovations [protoshares client](https://github.com/InvictusInnovations/ProtoShares).
and jh00's & testix' [jhProtominer](https://github.com/jh000/jhProtominer).

This is the start of keeping an open source, high-performance version
available.  It's about 2x faster than the normal ptsminer.

It has some build issues with windows that I'll fix soon.

Features:
- pool mining client
- custom getworx-protocol
- light-weight code
- portable

Build notes:
you'll need libboost & yasm

Running:
ptsminer <payment-addr> <#threads> [mode]

If you want AVX2, you'll have to specificy it explicitly in the mode string.

Known bugs:
- Will not do AVX2 on MacOS
- It yells if you haven't enabled hugepages on Linux, but runs properly.

To silence that, run hugepages:
```
  echo 2048 > /proc/sys/vm/nr_hugepages
```

It will give you a moderate speed boost.

Donations appreciated:
 - PTS: Pr8cnhz5eDsUegBZD4VZmGDARcKaozWbBc
 - BTC: 17sb5mcCnnt4xH3eEkVi6kHvhzQRjPRBtS
