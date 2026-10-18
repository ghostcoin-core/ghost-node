# Linkage test

The linkage test checks that the chain itself does not tie the hops of one
coin together: the commit that creates it, a partial reveal of it, and the
reveal of the remainder that partial reveal left. The code is in
`core/ghostpriv/linkage`, and it is tests only.

## What it runs on

The test builds a real `core.BlockChain` in-process on the internal network's
genesis and seals its blocks with the RandomX engine (gas limit 30,000,000).
A commit transaction, a partial reveal and, in a later fee window, a reveal
of the whole remainder are built by the commit and reveal code of
`core/ghostpriv` with stub proofs (`core/ghostpriv/ghostprivtest`), each mined
in a block of its own and checked by the chain's block processing on import.

Each hop is then read back from the chain: the transaction's binary encoding
as stored in the block body (`rawdb.ReadBodyRLP`), checked against the hash
the block commits to, and the topics and data of its receipt's logs.

## What it compares

Every pair of hops is compared, in four ways:

1. **Fields, decoded.** Every field and sub-field, at the width of its layout:
   the commit transaction's RLP fields with the commit data split into
   version, F and note; the reveal payload's fixed layout down to the proof's
   first word and the note's 32-byte words; the receipt data of a commit
   (tree, position, leaf, amount, note) and of a reveal (tree, position,
   remainder, note, recipient, out); every log topic. Two fields of the same
   width with the same bytes are a link. Integers of more than four
   significant bytes are also compared by value across widths, so a 32-byte
   amount word and a minimal RLP integer meet.
2. **Bytes.** Any run of 16 or more contiguous bytes that two hops share
   anywhere in their raw data, outside the whitelist, is a link. The report
   names the field at the start of the run in each hop.
3. **One tagged hash, both ways.** For every field of one hop and every hash
   tag written in `core/ghosttree`, `core/ghostpriv` and the packages below it
   (read from the source, so a new tag is covered without a change), the
   value `K(tag, field)` is searched among the fields and in the raw bytes of
   the other hop. An integer is hashed as laid out, in its minimal form and
   as a 32-byte word.
4. **The whitelist is exact.** Only these values may be shared, each with its
   reason in the code: coin tree roots that a block header also carries (the
   shared tree state), the chain id, version 1 of the commit data and reveal
   payload, the private transaction type byte, the commit entry address, the
   receipt topic constants, and zero padding (an all-zero field, or a run of
   four or more zero bytes). A short constant (type byte, version, chain id)
   is admitted only where both layouts put it. Anything the test cannot
   positively place on the list is a link; a hop it cannot decode fails the
   test.

The test passes on the real design, and each of these deliberately linked
variants, built at the byte level, makes it fail with a message naming the
two hops and the fields:

- a reveal that carries the commit's leaf, as its marker or inside its proof;
- a reveal of the remainder that reuses the first reveal's blinding, so its
  marker or its remainder equals the first reveal's;
- a field equal to one tagged hash of a field of another hop, in either
  direction;
- 16 bytes of one hop's note copied into another hop, off any field boundary;
- values shared outside the whitelist: a root no header carries, another
  reveal's proof, the chain id in a field that is not a chain id.

## What it does not cover

- **destinations:** the test does not ask whether the recipient addresses of
  the reveals, or what is later done with them, identify the owner; it only
  rejects a recipient that literally repeats a value of another hop.
- **amounts:** the test does not look for relations between amounts, such as
  a commit's value equal to the sum of the outs, fees and remainder that
  follow it; it only rejects an amount that literally repeats one of another
  hop.
- **timing:** the test does not consider when the hops are made or how close
  together they fall in blocks or fee windows, which can link them on its
  own.
- **network data:** the test does not consider how transactions reach the
  network, such as the peer, address or connection that first sends them,
  which lies outside the chain.
