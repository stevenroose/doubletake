




## segwit sighash structure

Prepare first:
 - `<prevouts>`: sha256d of all prevouts
 - `<sequences>`: sha256d of all sequences
 - `<outputs>`: sha256d of all outputs

```
<version> (4 bytes)
<prevouts> (32 byte hash)
<sequences> (32 byte hash)
<prevout> (36-byte prevout, txid + vout)
<script-code> (n-bytes encoded witnessScript)
<value> (8-bytes)
<sequence> (4 bytes)
<outputs> (32 byte hash)
<locktime> (4 bytes)
<sighashtype> (4 bytes>
```

Then do sha256d on all this.

## Strategy

The 2 fields we care about in the sighash are the `<prevout>` and `<outputs>`.
Any 2 valid signatures of a sighash that encodes a different `<outputs>` but identical `<prevout>`
is technically a double spend.

So a strategy would be to take two times 5 pushes as inputs:

//TODO(stevenroose) maybe fix scriptcode 

We do basic checking on the input length to make it harder to
use any random signature to burn the bond.

- `<version><prevouts><sequences>` (exact 68 bytes)
- `<prevout>` (exact 36 bytes)
- `<script-code><value><sequence>` (free form, minimum 16 bytes I guess)
- `<outputs>` (exact 32 bytes)
- `<locktime><sighashtype>` (exact 8 bytes)
- `<signature>`

Procedure:

- somehow cat the sighash together but extract the prevout and outputs to the altstack
  - the fact that the scriptcode is arbitrary length is a bit annoying, because if not
    we could do strong length checks to make sure it was an actual sighash and not any
    random message that just happens to contain the same prevout.
    I have a suspicion that the scriptCode can actually be fixed which makes the 
    protocol more robust because then we know the exact lengths of all pushes.
    For now, we can enforce the length of the first and last push, only the middle push will have
    to be freeform.
- validate the signature for our hardcoded pubkey
- repeat above for second sighash
- then take `<prevout1><outputs1><prevout2><outputs2>` from altstack, reorg and check
  - equality of prevout
  - inequality of outputs

Then a covenant that checks there is actually a burn.
To do this using CHECKSIGFROMSTACK, we need another sighash,
this time the one for the current tx.
The only check we need to do is that there is one fixed output
with `OP_RETURN` script and a hardcoded value.

Because this is a Liquid covenant ofc, the output will have to be serialized as follows:
`<6d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f><01><u64::swap_bytes(value)><00><01><6a>`

from stack:
- <version><prevouts><sequences><prevout><script-code><value><sequence> (4 + 32 + 32 + 36 + scriptcode + 8 + 4 = 116 + scriptcode)
- <other-outputs> so we can add the burn output and calculate <outputs> (32 bytes)
- <locktime><sighashtype> (8 bytes)

extract: value to calculate the burn output

TODO(stevenroose) add a covenant that enforces 90% of the funds get burned


## Test

sk: d79fc34caae4473e2c6c5e99021ddad4009e626ff69a75ed6fbc76e5a7c86c13
pk: 023dcde4c823bc457e1fdbe73365ca1ffa3995a0ace704826e32882038abfa793e

double spend prevout:

sighash1: 
- 1691f3295e3edd9f4c628215a2f73b9cfe05edb2d9158111685d1dcd2450452ca5be4ca7e3df0a2eebc972f6224bdb983c92bcd72c7c1937e4c76aaa88f75db24bac72c0
- 092d108e1c6acb097059ddbfb245947bfc7a66c0cafea968b42286cb00c9dd4a4152c8f2
- 82b4277a224cf78cc096ac6e95ec8b36f5c1e1
- efb6b9105af08b235f75f5864747a7a239711e0b57538c02e11e4f6600aa543d
- ab92956c4ca89f12

sha256d: 20d318e04e8c3fb85d2a14e7b83da10ad3e58ee6962adbdd8c442f22b771417b
(NB: need to be cautious with hex byte order for double sha)
sig: 30440220737ea0c88ceb413783e5490c3cd3a4b8f4656fc708d0f2437d6d4c09c069c3e9022033b82aac8eef2fbb5d855fc8e437e6329da89b336d835d8692b9100f3487de29",


sighash2:
- fa53d9210837fe247b256d0aac9da0b9bbbaf039a91b9febdbebc360072a79b1438db08f7de6b12c1337a38a9ed990568f637f829f427bb71491c230b3b154d080a538d9
- 092d108e1c6acb097059ddbfb245947bfc7a66c0cafea968b42286cb00c9dd4a4152c8f2
- 3cf5a4bfb111f01eb7ba86a8dc68bfc7b06863
- a8e30639a60de000008b1099a5dad6dc792c4a19b215e86e9f4c48cdca3999e3
- d3b55cf0f8f1a84d

sha256d: 243b6bde35c1eb25ea077f46ce6a2934e2946b67a9d9d5032551ddfb14dc2517
sig: 304402207f1d82fc527a2f64f6ebdc249736a2f94f35a31bf7da68aedd5f0aab1394f7a302205d36b398dc5791edf219cc8778da4fcf854db8e10980e0fae8ddcc9badac1dc1


covenant:
prevout: c1f0a621c7a3be44a7082db09d4a0191e420ce0f93e06864ecd65437f274a337
sequence: ffffffff
prevout spk: 76a9144156e4a2cee8d695fc84ed6ab2f070955bc0bba688ac
(sk cab05a6e71a4b1616b5a050971cb9f65c45da4070dde2645c36ce14ff7482cd0)
(pk 02b967977f305d71f547a5e543e18e0be10972aeeadd19b78f2f25ba025e8d673d)
sig :304402207dce62aa9ba6c559a320672493ed6b5fb8f084864bdf61747ec6c1a00a4b1c0c0220350e53aca9e1a3c5fbef533c6185ff4447618fc478903574bb87196a9f836e33


// <version><prevouts><sequences><issuances><prevout><script-code><value><sequence>
 01000000ba12a5da25cb0c1708b3a73631d999acb25342d9953da11ecf0e57c6b29e1543ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d37a374f23754d6ec6468e0930fce20e491014a9db02d08a744bea3c721a6f0c10000000076a9144156e4a2cee8d695fc84ed6ab2f070955bc0bba688ace803000000000000

other out:
016d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f01000000000000003200160014bccfbd62315d782f3908f2628a7c6538ffd6a3c2
burn:
016d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f0100000000000001a400016a

// <locktime><sighashtype>
0000000001000000

### ide

input:

```

//
// Script Wizard makes it easy to design and compile
// custom Liquid scripts. You can see stack execution line by line.
//
// Feel free to create issues on GitHub if you encounter bugs.
//


<0x3045022100fbfa8bf3f9ea6cf069ac4a9ebf260bcc0373fea03fbc4877df4819d54490d0fc02202f533cf53ec67d936e925538c13158ecf5195024738186bfab023c654ff76e5f>
<0x02b967977f305d71f547a5e543e18e0be10972aeeadd19b78f2f25ba025e8d673d>


// locktime sighashtype
<0x0000000001000000>
// first part of cov sighash
// <version><prevouts><sequences><prevout><script-code><value><sequence>
<0x01000000ba12a5da25cb0c1708b3a73631d999acb25342d9953da11ecf0e57c6b29e1543ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d37a374f23754d6ec6468e0930fce20e491014a9db02d08a744bea3c721a6f0c10000000076a9144156e4a2cee8d695fc84ed6ab2f070955bc0bba688ace803000000000000>
// other output
<0x016d521c38ec1ea15734ae22b7c46064412829c0d0579f0a713d1c04ede979026f01000000000000003200160014bccfbd62315d782f3908f2628a7c6538ffd6a3c2>


// sig2
<0x304402207f1d82fc527a2f64f6ebdc249736a2f94f35a31bf7da68aedd5f0aab1394f7a302205d36b398dc5791edf219cc8778da4fcf854db8e10980e0fae8ddcc9badac1dc1>

// sighash2
<0xd3b55cf0f8f1a84d>
<0xa8e30639a60de000008b1099a5dad6dc792c4a19b215e86e9f4c48cdca3999e3>
<0x3cf5a4bfb111f01eb7ba86a8dc68bfc7b06863>
<0x092d108e1c6acb097059ddbfb245947bfc7a66c0cafea968b42286cb00c9dd4a4152c8f2>
<0xfa53d9210837fe247b256d0aac9da0b9bbbaf039a91b9febdbebc360072a79b1438db08f7de6b12c1337a38a9ed990568f637f829f427bb71491c230b3b154d080a538d9>

// sig1
<0x30440220737ea0c88ceb413783e5490c3cd3a4b8f4656fc708d0f2437d6d4c09c069c3e9022033b82aac8eef2fbb5d855fc8e437e6329da89b336d835d8692b9100f3487de29>

// sighash1
<0xab92956c4ca89f12>
<0xefb6b9105af08b235f75f5864747a7a239711e0b57538c02e11e4f6600aa543d>
<0x82b4277a224cf78cc096ac6e95ec8b36f5c1e1>
<0x092d108e1c6acb097059ddbfb245947bfc7a66c0cafea968b42286cb00c9dd4a4152c8f2>
<0x1691f3295e3edd9f4c628215a2f73b9cfe05edb2d9158111685d1dcd2450452ca5be4ca7e3df0a2eebc972f6224bdb983c92bcd72c7c1937e4c76aaa88f75db24bac72c0>
```

script:

```

// check size of <ver><prevs><seqs>
OP_SIZE
<68>
OP_EQUALVERIFY

// copy prevout to front
OP_OVER

// check size of <prev>
OP_SIZE
<36>
OP_EQUALVERIFY

// put <prev> to alt stack
OP_TOALTSTACK

// cat: <ver><prevs><seqs><prev>
OP_SWAP
OP_CAT

// because the next element is flexible in size, just cat it too
// cat: <ver><prev><seqs><prev><sc><val><seq>
OP_SWAP
OP_CAT

// copy outputs to front
OP_OVER

// check size of outputs
OP_SIZE
<32>
OP_EQUALVERIFY

// put outputs on altstack
// alt: <prev1><outs1>
OP_TOALTSTACK

// cat: <ver><prev><seqs><prev><sc><val><seq><outs>
OP_SWAP
OP_CAT

// copy <lt><sht> to the front
OP_OVER

// check size
OP_SIZE
<8>
OP_EQUALVERIFY

// cat: <ver><prev><seqs><prev><sc><val><seq><outs><lt><sht>
OP_DROP
OP_SWAP
OP_CAT

// now we have the entire sighash data, hash it
OP_SHA256

// then check signature
<0x023dcde4c823bc457e1fdbe73365ca1ffa3995a0ace704826e32882038abfa793e>
OP_CHECKSIGFROMSTACKVERIFY


// all the same for sighash2



// check size of <ver><prevs><seqs>
OP_SIZE
<68>
OP_EQUALVERIFY

// copy prevout to front
OP_OVER

// check size of <prev>
OP_SIZE
<36>
OP_EQUALVERIFY

// put <prev> to alt stack
OP_TOALTSTACK

// cat: <ver><prevs><seqs><prev>
OP_SWAP
OP_CAT

// because the next element is flexible in size, just cat it too
// cat: <ver><prev><seqs><prev><sc><val><seq>
OP_SWAP
OP_CAT

// copy outputs to front
OP_OVER

// check size of outputs
OP_SIZE
<32>
OP_EQUALVERIFY

// put outputs on altstack
// alt: <prev1><outs1>
OP_TOALTSTACK

// cat: <ver><prev><seqs><prev><sc><val><seq><outs>
OP_SWAP
OP_CAT

// copy <lt><sht> to the front
OP_OVER

// check size
OP_SIZE
<8>
OP_EQUALVERIFY

// cat: <ver><prev><seqs><prev><sc><val><seq><outs><lt><sht>
OP_DROP
OP_SWAP
OP_CAT

// now we have the entire sighash data, hash it
OP_SHA256

// then check signature
<0x023dcde4c823bc457e1fdbe73365ca1ffa3995a0ace704826e32882038abfa793e>
OP_CHECKSIGFROMSTACKVERIFY


// so now we checked that our pubkey signed two sighashes
// altstack: <prev1><outs1><prev2><outs2>

OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK
OP_FROMALTSTACK

OP_2
OP_ROLL
// check that prevouts are identical
OP_EQUALVERIFY
// check that outputs are not identical
OP_EQUAL
OP_0
OP_EQUALVERIFY


// now build a covenant that forces a certain burn amount











```



















