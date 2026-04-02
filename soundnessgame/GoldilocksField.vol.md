# GoldilocksField.sol — Soundness Report

After careful line-by-line analysis, here are the findings:

---

~~## 1. `modExp` Clobbers the Solidity Heap Without Updating the Free Memory Pointer~~
> Fixed in round 1

**Description**

`modExp` reads the Solidity free memory pointer (`mload(0x40)`) and writes 192 bytes of input data starting at `ptr`, then instructs the precompile to write its 32-byte output back to the same `ptr` address. The function never advances the free memory pointer (`mstore(0x40, add(ptr, 192))`). After `modExp` returns, the Solidity runtime still believes the heap ends at `ptr`.

**Affected code** — lines 51–63:

```solidity
assembly {
    let ptr := mload(0x40)
    mstore(ptr, 32)
    ...
    if iszero(staticcall(gas(), 0x05, ptr, 192, ptr, 32)) { revert(0, 0) }
    result := mload(ptr)
    // ← free memory pointer is never updated
}
```

**Why this is a soundness concern**

Any Solidity `memory` allocation that occurs after this function returns — in the same call frame — will reuse `ptr` and overwrite the 192-byte region. If the Solidity compiler ever emits a memory allocation between this call and the use of a derived value (e.g., when constructing an `Ext2` struct in `GoldilocksExt2.inv` or `evalL0`), intermediate data written by earlier `modExp` calls could be silently corrupted. The result of the *current* call is safe (captured in the stack variable `result`) but callers that chain multiple `modExp`-derived values on the heap (as happens in `inv → evalL0`) are operating on a heap that the compiler believes is still empty at `ptr`. This does not currently produce a wrong result because the return value is always on the stack, but it violates the Solidity memory ABI and is fragile under compiler optimisation changes.

**Suggested fix**

Advance the free memory pointer after the call:

```solidity
mstore(0x40, add(ptr, 224)) // align to next 32-byte boundary past the 192-byte input region
```

---

~~## 2. `GoldilocksExt2.expPowerOf2` Does Not Canonicalise Its Input When `powerLog = 0`~~
> Fixed in round 1

**Description**

The base-field version (`GoldilocksField.expPowerOf2`, line 69) explicitly reduces the input before the loop:

```solidity
uint256 result = base % P;   // canonical reduction applied unconditionally
```

The extension-field version (`GoldilocksExt2.expPowerOf2`, line 160) copies the struct directly:

```solidity
Ext2 memory result = Ext2(a.c0, a.c1);  // no reduction
```

When `powerLog = 0` the loop body never executes, so the input is returned verbatim. Any `c0 ≥ P` or `c1 ≥ P` in the input propagates unchanged to the output.

**Affected code** — lines 159–165 (specifically the `powerLog = 0` path):

```solidity
function expPowerOf2(Ext2 memory a, uint256 powerLog) internal pure returns (Ext2 memory) {
    Ext2 memory result = Ext2(a.c0, a.c1); // non-canonical if a.c0 or a.c1 >= P
    for (uint256 i = 0; i < powerLog; i++) {
        result = mul(result, result);       // mul would canonicalise, but never runs for powerLog=0
    }
    return result;
}
```

**Why this is a soundness concern**

`GoldilocksExt2.evalL0` calls `expPowerOf2(x, degreeBits)` (line 178) and then passes the result to `sub` (line 179). When `degreeBits = 0`, `xn` is `x` unmodified. The subsequent `sub`, `mulScalar`, and `mul` calls all use `addmod`/`mulmod` internally and will produce the mathematically correct reduced result, so the final arithmetic outcome is currently correct. However:

- The function's return type is an `Ext2` representing a field element, with the implicit contract that `c0, c1 < P`. Returning a non-canonical element breaks this contract.
- Any caller that pattern-matches on the raw `c0`/`c1` values (e.g. via `a.c0 == b.c0` instead of `isEqual`) will silently get the wrong answer when `degreeBits = 0`.
- The inconsistency with the base-field sibling is a latent defect: future callers or refactors that rely on canonical outputs will be surprised.

**Suggested fix**

Mirror the base-field version by reducing the initial value:

```solidity
Ext2 memory result = Ext2(a.c0 % P, a.c1 % P);
```

---

~~## 3. `GoldilocksField.inv` Passes an Unreduced Base to `modExp`~~
> Fixed in round 1

**Description**

`GoldilocksField.inv` validates the input with `a % P != 0` but then forwards the original, potentially unreduced `a` to `modExp`:

```solidity
function inv(uint256 a) internal view returns (uint256) {
    require(a % P != 0, "GL: inv(0)");
    return modExp(a, P - 2);   // a may be >= P here
}
```

**Affected code** — lines 41–44.

**Why this is a soundness concern**

The EVM `MODEXP` precompile computes `a^(P−2) mod P` correctly even for `a ≥ P` (modular arithmetic is closed), so the return value is always the correct field inverse. The concern is defensive: the pattern makes it easy to introduce a future bug if `modExp` is ever changed to assume a reduced base (e.g. for a hand-rolled square-and-multiply), or if the precompile's behaviour for oversized inputs is ever relied upon differently. More concretely, `modExp` is also called from `evalL0` indirectly via `inv(denominator)`, where `denominator` is the output of field operations and is always reduced — but the divergence in `inv` means the contract "inputs to `modExp` are already reduced" is not uniformly maintained, making auditing harder.

**Suggested fix**

Reduce the base before the Fermat exponentiation:

```solidity
function inv(uint256 a) internal view returns (uint256) {
    uint256 r = a % P;
    require(r != 0, "GL: inv(0)");
    return modExp(r, P - 2);
}
```

---

**Summary**

None of the three issues as currently written permits an invalid proof to pass verification — the mathematical results of all operations are correct. Issues 1 and 2 are latent defects that violate the library's internal invariants (free-pointer discipline; canonical representation contract) and create fragile code paths. Issue 3 is a defensive-coding gap. In cryptographic verifier code, all three warrant fixing before production use.
