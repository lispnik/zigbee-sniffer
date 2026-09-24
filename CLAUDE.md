# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A sniffer for the TI CC2531 USB dongle running TI's packet-sniffer firmware
(`0451:16AE`). It is a Common Lisp library plus a clingon command-line tool
(`bin/zigbee-sniffer`: `list`, `info`, `capture`, `survey`). SBCL only. It depends on
`libusb` from github.com/lispnik/libusb, which must be checked out as a sibling of this
tree. The dongle is attached to `pi@rpi4`.

## Commands

```sh
make            # bin/zigbee-sniffer (program-op; embeds the core -- build where it runs)
make test       # zigbee-sniffer/tests: core only, no dongle, no libusb
make deploy     # rsync this tree + ocicl/ + ../libusb to pi@rpi4, clear stale fasls there
make pi-test    # core suite on the Pi
make pi-build   # build the binary on the Pi
```

On the Pi, run it with `ssh pi@rpi4 'cd ~/zigbee-sniffer && sudo -n bin/zigbee-sniffer ...'`.
The device node is root-only there. Do not install the udev rule on the Pi without
asking, because it is a permanent change to that machine.

To run one test: `(fiveam:run! 'zigbee-sniffer/tests::the-documented-beacon-message-parses)`.

The Makefile's `BOOT` sets up a hermetic source registry: this tree as a `:tree`, and
`LIBUSB_DIR` as a single `:directory`. A `:tree` over libusb would also pick up
libusb's own vendored `ocicl/`, and with it a second copy of cffi. At a REPL, copy that
`initialize-source-registry` form rather than widening it.

Always use `make deploy`, never a bare rsync. rsync keeps mtimes, so the Pi's ASDF can
decide that stale fasls are current. `deploy` clears the `pi` fasl cache and root's
(the binary is usually run under sudo), then checks that both are gone.

## Architecture

- `zigbee-sniffer/core` (`src/stream.lisp`, `ieee802154.lisp`, `pcap.lisp`) is pure
  Lisp. It parses the dongle's messages, decodes 802.15.4 MAC headers, runs the dongle
  clock and writes pcap. The tests depend only on this system.
- `zigbee-sniffer` (`src/dongle.lisp`) covers the vendor requests, `WITH-SNIFFER` and
  `WITH-CAPTURE`. It exports its own names, so loading only the core advertises only
  the core.
- `zigbee-sniffer/cli` has one file per subcommand. Each file registers itself with
  `REGISTER-SUBCOMMAND`.

Threads: bulk transfers complete on libusb's event-pump thread. The callback
(`TRANSFER-COMPLETED`) only queues the bytes into an `sb-concurrency` mailbox and
resubmits the transfer. All parsing and writing happens on the main thread through
`RECEIVE-MESSAGE`, so each output stream has exactly one writer. Keep it that way.

## Things that are easy to get wrong here

- **clingon catches every error inside `CLINGON:RUN`** and prints it bare. Error hints
  therefore live in `REPORTING-ERRORS`, which wraps each subcommand's handler, not in
  `MAIN`.
- **SIGINT and SIGTERM during `capture` and `survey` only set a flag**
  (`WITH-STOP-SIGNALS`), and the receive loop polls it. Do not unwind from the signal
  handler. It can run on libusb's thread, and unwinding halfway through a pcap record
  corrupts the file. A second signal exits immediately.
- **Stopping a capture:** `CLOSE-CAPTURE` stops the radio, sets the flag, then cancels
  in rounds until nothing is `:submitted`. A callback already past the flag check can
  resubmit once, and freeing a submitted transfer is a use-after-free.
- **RSSI is the raw byte minus `+RSSI-OFFSET+` (73).** The original libusb example
  omitted the offset and reported about -17 dBm for signals near sensitivity.
- **The dongle clock must see every frame, including ones that are not written.**
  Skipping one can hide a counter wrap.
- **Frames that fail CRC are excluded by default and never feed the PAN or source
  counts.** Corrupt frames decode as devices that do not exist. This has been observed
  on channel 12.
- `SET_CHAN` is two requests (low byte at wIndex 0, high byte at wIndex 1), and it is
  ignored if it arrives before `GET_POWER` confirms the radio is on.
- A beacon on channel 25 (and 12) sets a reserved frame-control bit. Wireshark marks it
  malformed, but it passed the radio's CRC. It is a test fixture.
