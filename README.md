# SimplePortScannerDetector
A simple tool to analyze network trace data to detect `SYN` port scanning. This tool outputs a set of IP addresses (one per line) that sent at least 'scaler' times more `SYN` packets than than the number of `SYN+ACK` packets they received.
- A good scaler value to start with is 3, more optimizations could be done on this value depending on the complexity of the port scan.

## Dependences
- You need to install the following python package:
  - [dpkt](https://github.com/kbandla/dpkt)

## How to use
`detector.py scaler network-capture-file`
