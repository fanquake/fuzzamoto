# Fuzzamoto

Fuzzamoto provides a framework and fuzzing engine for coverage-guided fuzzing
of Bitcoin full node implementations.

* **Implementation Agnostic**: The same tests can target different protocol
  implementations and compare their behavior (e.g. [Bitcoin
  Core](https://github.com/bitcoin/bitcoin),
  [btcd](https://github.com/btcsuite/btcd),
  [libbitcoin](https://github.com/libbitcoin/libbitcoin), ...)
* **Holistic**: Tests are performed on the full system, not just isolated
  components, enabling the discovery of bugs that arise from the composition of
  different components
* **Coverage-Guided**: Fuzzing is guided by coverage feedback

*It is not meant to be a replacement for traditional fuzzing of isolated
components, but rather a complement to it.*

## Trophies 

| Project                                                                | Bug                                                                   | Scenario           |
| :--------------------------------------------------------------------- | :-------------------------------------------------------------------- | :----------------- |
| [Bitcoin Core](https://github.com/bitcoin/bitcoin) | [`migratewallet` RPC assertion failure](https://github.com/bitcoin/bitcoin/issues/32111) | `wallet-migration` |
| [Bitcoin Core](https://github.com/bitcoin/bitcoin) | [`migratewallet` RPC assertion failure](https://github.com/bitcoin/bitcoin/issues/32112) | `wallet-migration` |
| [Bitcoin Core](https://github.com/bitcoin/bitcoin) | [assertion failure in `CheckBlockIndex`](https://github.com/bitcoin/bitcoin/issues/32173) | `rpc-generic` |
| [Bitcoin Core PR#30277](https://github.com/bitcoin/bitcoin/pull/30277) | [Remotely reachable assertion failure in `Miniketch::Deserialize`](https://github.com/bitcoin/bitcoin/pull/30277#issuecomment-2992101654) | `ir` |
| [Bitcoin Core PR#28676](https://github.com/bitcoin/bitcoin/pull/28676) | [Assertion failure in `CTxMemPool::check()`](https://github.com/bitcoin/bitcoin/pull/28676#issuecomment-3016809091) | `ir` |
| [Bitcoin Core](https://github.com/bitcoin/bitcoin) | [uncaught exception in IPC interface](https://github.com/bitcoin/bitcoin/issues/33341) | `ipc-mining` ([*](https://github.com/marcofleon/fuzzamoto/tree/ipc-mining)) |
| [btcd](https://github.com/btcsuite/btcd) | [bloom filters; panic: integer divide by zero](https://gist.github.com/dergoegge/b123d7feb183f7c19754da2ff87dc1f6) | `ir` |
| [btcd](https://github.com/btcsuite/btcd) | [addrv2; panic: invalid memory address or nil pointer dereference](https://gist.github.com/dergoegge/b1e75e07e4525b8a1ce7c11a7cd6b585) | `ir` |
| [btcd](https://github.com/btcsuite/btcd) | [infinite wait in getdata handling](https://gist.github.com/dergoegge/2f19a438f69f0f9b5cb64986c8239b16) | `ir` |
