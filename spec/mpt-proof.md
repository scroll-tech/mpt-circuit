# Storage Tree Proof

The storage tree proof helps to check updating on accounts and their storage (via SSTORE and SSLOAD op) are correctly integrated into the storage tree, so the change of state root of EVM has represented and only represented the effects from transactions being executed in EVM. The `Account` and `Storage` records in state proof, which would finally take effect on storage tree, need to be picked into storage tree proof. The storage tree circuit provide EVM's state root are updated sequentially and the final root after being updated by the records sequence from state proof coincided with which being purposed in the new block.

## The architecture of state trie

An alternative implement of BMPT (Binary Patricia Merkle Tree) has been applied for the zk-evm as the state trie. The BMPT has replaced the original MPT for world state trie and account storage trie, and a stepwise hashing scheme instead of rlp encoding-hashing has been used for mapping data structures into hashes. For the BMPT implement we have:

+ Replacing all hashing calculations from kecca256 to poseidon hash

+ In BMPT there are only branch and leaf nodes, and their hashes are calculated as following schemes:

    * Branch node is an 2 item node and `NodeHash = H(NodeHashLeft, NodeHashRight)`
    * Leaf node is an 2 item node and `NodeHash = H(1, encodedPath, value)`

+ In world state trie, the value of leaf node is obtained from account state and the hashing scheme is: `AccountHash = H(H(nonce, balance), H(H(CodeHash_first16, CodeHash_last16), storageRoot))`, in which `CodeHash_first16` and `CodeHash_last16` represent the first and last 16 bytes of the 32-byte codeHash item

+ In account storage trie, the value of leaf node is obtained from hashing the first and last 16 bytes of the storaged 32-byte value, i.e: `ValueHash = H(value_first16, value_last16)`

## Layouts of the circuit

To provide there is value `v` and key `k` existed for account `addr` we need 4 proofs:

1. Proof the stored key and value has been correctly encoded and hashed into the secured key and value in one of the leaf node of account storage trie
2. Proof the BMPT path for the leaf node in proof `1` against the current root `Rs` of storage trie, is correct
3. Proof the account `addr` with stateRoot is `Rs` can be encoded and hashed into one of the leaf node of state trie
4. Proof the BMPT path for the leaf node in proof `3` against the current root `R` of state trie, is correct

To provide the root of state trie change from `R0` to `R1` is contributed by updating key `k` for account `addr` from value `v0` to `v1`, we used 4 proofs as described before for providing `(v0, k, addr) -> R0` and another 4 proofs for providing `(v1, k, addr) -> R1`. Then another updating on storage can be applied on the new state trie with root `R1` and transit it to root `R2`. For a series of *n* updates on storage of EVM which transit state trie from root `R0` to `Rn`, our proofs provide the transition via *n* intermediate roots `R1, R2 ... Rn-1`, and provide *n* transitions `R0 -> R1`, `R1 -> R2`, ... `Rn-1 -> Rn` caused by the *n* updates are all correct.

For the proof of each transition `Ri -> Ri+1` on the trie. Every of the 4 proofs for the start state `Ri` is paired with the 4 proofs for the end state `Ri+1` and the 4 proof pairs are stacked from bottom to top, so the layout would look like:

| state | proof of start | proof of end | trie root |
| ----- | -------------- | ------------ | --------- |
|  ...  |                |              |           |
|   i   |  <proof 4>     |   <proof 4>  |  Ri, Ri+1 |
|       |  <proof 3>     |   <proof 3>  |           |
|       |  <proof 2>     |   <proof 2>  |           |
|       |  <proof 1>     |   <proof 1>  |           |
|  i+1  |  <proof 4>     |   <proof 4>  | Ri+1, Ri+2|

So there are 5 kinds of proof (4 proof 'pair' mentioned before and a 'padding' proof) which need to be layout to the circuit. Columns in circuit are grouped for 3 parts:

+ Controlling part enable different proofs being activated in specified row and constraint how adjacent rows for different proofs can transit:

>    * `series` indicate one row is dedicated for the i*th* transition for state trie. The cell of `series` on next row must be the same or only 1 more than the current one.
>    * `selector 0~5` each enable the row for one of the 5 proofs. With constraint `sigma(selector_i) = 1` there would be one and only one selector is enabled for each row.
>    * `op_type` can be 0 to 5 and specified the row currently works for proof N. And constraint `sigma(selector_i * i) = op_type` bind the value of `op_type` to the enabled `selector_i`.
>    * `op_delta_aux` reflects whether there is a different between the value of current `op_type` cell and the one above it.
>    * `ctrl_type` is used by different proofs to mark one row for its roles. When the value of `op_type` changed in adjacent rows, only the constrained pairs of `(op_type, ctrl_type)` are allowed so the sequence of proofs stacking is controlled. More specific, we just: 
>        + look up current `(op_type, ctrl_type)` pair from 'external rules' collection when value of current `op_type` cell different from which in above row (the difference must be one)
>        + look up current `(op_type, ctrl_type)` pair from 'internal rules' collection when value of current `op_delta_aux` is one

+ Data part currently has 3 cols `data_0` ~ `data_2` which dedicate to values whose relations should be provided to be correct by a proof. Different proof assign specified data on that columns: For proof 1 and 3 (the BMPT proof), the hashes of nodes for the BMPT before and after updating are recorded in `data_0` and `data_1` respectively; for proof 2 `data_0` and `data_1` are used for account hash before and after being updated. proofs can also refer cells in data columns which belong to the rows adjacent to it, i.e. the data which has been provided by another proof.

Since the transition is provided in a series of adjacent rows (a "block") in our layout, and the proof of state trie being stacked first. The beginning row of the proof block always contain the start and end trie root in the transition. So a `root_aux` col is used to 'carry' the end trie root to the last row of the proof block, to ensure the start trie root of next transition must equal to the end trie root of previous proof block. The layout look like follows:

| series| data_0 *for old_root* | data_1 *for new_root* | root_aux |
| ----- | -------- | -------- | -------- |
|  ...  |          |          |          |
|   i   |    Ri    |   Ri+1   |  Ri+1    |
|       |          |          |  Ri+1    |
|       |          |          |  Ri+1    |
|       |          |          |  Ri+1    |
|  i+1  |  Ri+1    |   Ri+2   |  Ri+2    |

The constraint for `root_aux` is:

> `root_aux(cur) = new_root(cur)` if `series` has changed, else `root_aux(cur) = root_aux(prev)`

+ Gadget part has columns dedicated by different proof. Each kind of proof (BMPT, account hash, value hash or padding) use these columns and custom gates for a proof has to be enabled by the `selector_i` col inside controlling part.

### BMPT transition proof

This provide an updating on the key `k` of BMPT has made its root to change from `Ri` to `Ri+1` under one of the following three possible transitions:

1. A new leaf node with value `v1` is created
2. The leaf node with value `v0` is removed
3. The leaf node with value `v0` is being updated to value `v1`

It is needed to provide the path in BMPT, from root to the leaf node of key `k`, is valid. Both the BMPT path before and after leaf node `k` being updated has to be provided and the two BMPT path shared the same siblings. It take one row to put the data of one layer in the BMPT path, including the type of node (branch or leaf), the hash of node, the prefix bit for the corresponding layer etc. The two BMPT path for providing should has the same depth. In the case of transitions 1 and 2, an un-existing proof, i.e. an BMPT path from root to an empty node should be provided.

For the nature of patricia tree, if there is no leaf with key `k` in the trie and leaf node `k1` which has longest common prefix with `k` in all leafs of the trie. Suppose the length of the common prefix is `l` and currently the length of prefix of leaf node `k1` is still less than `l`, depth of BMPT path would be changed after being updated. In this case, in the (un-existing) proof for the empty node of key `k` the BMPT path has to be re-organized for reflecting the trie state right before leaf node of key `k` being updated to an empty node, or right after the leaf node being removed and the empty node left. Take following example:

![a Merkle tree storing example](https://i.imgur.com/SaLpIn3.png)

+ While only leaf node A and B is inserted, the prefix path for node B (key 1000) is 1, and the root of current trie is `Rb`;
+ Now node C (key 1010) will be inserted. For providing, we use the re-organized trie state which leaf node C just updated a corresponding empty node with key 1010, and the prefix path of this empty node is 101.
+ For such a situation, the prefix path for node B has become 100 instead of 1.
+ Notice this is a 'virtual' state for the trie, for the root of trie doesn't change from `Rb`. To provide this virtual BMPT path, we induce new node types for the reorganized branch node (whose prefix path is 1 and 10 in our case). The node hash for these node types is just equal to its child.

The BMPT transition proof use following columns:

> `Old/NewHashType`: Record the type of a node in current row, the two column `Old-` and `New-` is dedicated to the state of trie before and after updating respectively. There are 6 types would be used:
>  + `START`: indicate the node is dedicated for the root hash of trie, both in old- and new- state the rows for BMPT path should start with this node
>  + `MID`: indicate a branch node
>  + `LEAF`: indicate a leaf node
>  + `LEAFEXT`: 

> `Old/NewVal`:

> `sibling`:

> `path`:

> `depth`:

> `accKey`

## Hash table

Proved by poseidon hash circuit. Inputs and output for each hash calculation are put in the same row. For a hash circuit which calculate the hash of at most N items we have N+2 cols: 

>  - **Items** the number of items in the calculation
>  - **1..N (Fields)** N cols for at most N items
>  - **Hash** then the col for the hash.

Currently the least N we need is 3:

| 0 Items| 1  | 2  | 3  | Hash       |
| ---    |--- |--- |--- | ---        |
|   1    | FQ1|    |    | FQ         |
|   3    | FQ1| FQ2| FQ3| FQ         |
|   3    | FQ1| FQ2| FQ3| FQ         |

