# zigbee-sniffer

An IEEE 802.15.4 / Zigbee / Thread sniffer for the **TI CC2531** USB dongle running TI's
packet-sniffer firmware, as a Common Lisp library and a command-line tool. It prints
frames as they arrive, writes pcap files for Wireshark, and surveys channels. Built on
[lispnik/libusb](https://github.com/lispnik/libusb).

```
$ sudo zigbee-sniffer capture -c 25
Capturing on channel 25 (2475 MHz). C-c to stop.
17:25:56.336752  ch25  -96 dBm lqi  96  Beacon   seq  83  pan 0x6ed2  src 00:d0:2d:ff:fe:12:e3:cb  62 B
17:25:56.660585  ch25  -85 dBm lqi 105  Data     seq  46  pan 0xaaee  0a:81:fe:47:ff:75:c7:d4 -> 0xffff  72 B
17:25:58.302964  ch25  -95 dBm lqi  86  Beacon   seq  91  pan 0x6ed2  src 00:d0:2d:ff:fe:12:e3:cb  62 B
17:26:01.918985  ch25  -96 dBm lqi  86  Data     seq 130  pan 0x026d  5e:f3:ff:53:41:f2:61:0f -> 0xffff  67 B
...
^C
Channel 25: 30 frames, 17 shown, 13 failed CRC (excluded; --bad-crc keeps them)
  9 heartbeats, RSSI mean -85.8 dBm, peak -7 dBm
```

These results come from a Raspberry Pi 4. Channel 25 there carries a Resideo device's
beacons (PAN `0x6ed2`) and two Thread networks' MLE advertisements.

## Commands

| | |
|---|---|
| `zigbee-sniffer list` | Every CC2531 attached, with its location and firmware. A dongle flashed with zigbee2mqtt's Z-Stack firmware (`0451:16a8`) is listed, with a note that it cannot sniff. |
| `zigbee-sniffer info` | One dongle's descriptors, the firmware's `GET_IDENT` bytes and the radio's power state. |
| `zigbee-sniffer capture` | Capture one channel. Frames go to the terminal, or with `-w FILE` to a pcap file. |
| `zigbee-sniffer survey` | Listen on each channel in turn and report frames, RSSI, sources and PANs for each. |
| `zigbee-sniffer read FILE.pcap...` | Decode saved captures, with the same output options as `capture`. Reads this tool's pcaps and the plain 802.15.4 link types (195, 230) other sniffers write. |
| `zigbee-sniffer inventory FILE.pcap...` | Every network and device in saved captures (see [Inventory](#inventory)). `capture -i` prints the same report when a capture ends. |

`capture` options:

```
  -c, --channel <INT>   802.15.4 channel, 11-26 [default: 25]
  -w, --write <FILE>    write a pcap file (IEEE 802.15.4 TAP); - for stdout
  -t, --seconds <INT>   stop after this many seconds (default: run until C-c)
  -n, --count <INT>     stop after this many frames
      --bad-crc         keep frames that failed CRC
      --implausible     keep frames that passed CRC but cannot be real
  -V, --decode          decode every layer under each frame's line
      --format <FMT>    text, or jsonl: one JSON object per frame, every decoded field
  -x, --hex             hex dump each frame's MAC bytes under its summary
  -v, --verbose         with --write, also print each frame on stderr
  -i, --inventory       report every network and device when the capture ends
      --oui-file <F>    vendor registry (IEEE oui.csv or Wireshark manuf)
  -d, --device <B:A>    the dongle to use, as BUS:ADDRESS from `list`
```

## Decoding

Every frame is decoded as far as its bytes allow, and the decoder says where it had to
stop and why: ciphertext, a subsequent fragment, or a header that runs off the end.

| Layer | What is reported |
|---|---|
| MAC | Frame type, version, sequence, PANs, flags, and the 2015 header IEs. Addresses: short addresses with their meaning (broadcast, unassigned); extended addresses with the vendor from the OUI registry or *local (random)*, and the IPv6 link-local address each implies. The auxiliary security header: level, key ID mode, frame counter, key source and index. |
| Beacon | Superframe (beacon and superframe order, final CAP slot, PAN coordinator, association permit), GTS, pending addresses. Zigbee beacon payloads (stack profile, depth, router and end-device capacity, extended PAN ID). Thread beacon payloads (network name, extended PAN ID, joining permitted). Anything else as hex. |
| MAC command | The command, including a secured command's identifier, which is sent in the clear. Association request capabilities; association response address and status; disassociation reason. |
| 6LoWPAN | Mesh, first and subsequent fragment headers; IPHC. |
| IPv6 | Source and destination rebuilt from IPHC, including addresses elided because the MAC addresses imply them; hop limit; next header. |
| UDP, ICMPv6 | Ports (from the compressed UDP header too) and service; ICMPv6 type. |
| MLE | Encrypted: its security header, the Thread key sequence, the frame counter, and whether the key index matches the key sequence. Unencrypted (discovery, for example): the command and every TLV, including MeshCoP network names and extended PAN IDs. |
| Zigbee NWK and APS | NWK addresses, radius, sequence, IEEE addresses, source route, and the security header (key, frame counter, source). APS endpoints, cluster and profile, when the NWK layer is not encrypted. |

`-V` prints this as a tree under each frame's line. `--format jsonl` writes one JSON
object per frame with every field, plus time, channel, RSSI, LQI, verdict and the raw
bytes:

```
10:28:07.185577  ch25  -83 dBm lqi  94  Data seq 68 pan 0xaaee  0a:81:fe:47:ff:75:c7:d4 (random) -> 0xffff (broadcast)  | fe80::881:fe47:ff75:c7d4 -> ff02::1 | UDP 19788 MLE | MLE encrypted key-seq 23 fc 4366  72 B
```

How it was checked: every field that tshark 4.4.6 also reports was compared on the
13,488 plausible frames of two hour-long channel-25 captures, and they agreed on all of
them. The fields were MAC addresses and PANs, IPv6 addresses, UDP ports, MLE security
suite, frame counters and command identifiers. The Zigbee, Thread-beacon,
unencrypted-MLE and MAC-command paths, which those captures never exercised, were
checked the same way on synthetic frames, and the unit tests fix both sets.

**Vendor names** come from the system's IEEE registry when it has one
(`/usr/share/ieee-data/oui.csv`, from Debian's `ieee-data` package), or from `--oui-file`
/ `ZIGBEE_SNIFFER_OUI`. Otherwise they come from a built-in table of 802.15.4 chip and
device vendors (`data/oui-802154.tsv`, regenerated by `tools/make-oui-table.sh`).
Thread gives every device a random extended address, so Thread devices show as
*random* and no vendor is looked up: a lookup on random bits would name a company that
had nothing to do with the device.

## Inventory

`inventory` (or `capture -i`) groups the frames that passed every check by PAN.

For each PAN it infers the protocol from what the frames carry: Thread (MLE), Zigbee,
6LoWPAN, or proprietary beacons.

For each device it reports:
- its vendor, or that its address is random
- for Thread short addresses, the router or child the RLOC16 names
- its IPv6 link-local address
- frames sent and frames addressed to it
- median RSSI and the 5–95% range
- how often it transmits, measured between bursts
- what it sent
- its unicast peers
- the Thread key sequences it used
- any beacon payload

Devices that are only ever addressed are listed separately: they exist but are out of
range or asleep. Addresses and PANs seen fewer than `--min-frames` times (default 3) are
counted rather than listed. That is what a real address with a corrupt byte looks
like.

```
PAN 0xaaee: Thread, 1627 frames
  0a:81:fe:47:ff:75:c7:d4  random
      878 sent in 344 bursts, 9 addressed to it, RSSI median -83 dBm (5-95%: -85 to -81), every 21.7 s (median)
      sent: MLE (encrypted) 865, MAC-encrypted data 13
      unicast to: ba:2a:3c:3d:6f:e1:fe:65 (15), 9a:43:ec:d4:88:30:28:58 (13), 0e:c5:ec:37:7a:f5:d2:c0 (9), ...
      Thread key sequences 22, 23
  0xb000  router 44
      46 sent in 6 bursts, RSSI median -84 dBm, ...
      unicast to: 0xd800 (20), 0xc800 (8), 0x9800 (5), 0xa400 (3), 0x4400 (2)
  addressed but never heard:
      0x9800  router 38  (addressed 5 times)
      ba:2a:3c:3d:6f:e1:fe:65  random  (addressed 17 times)
```

`--format json` writes the same report as one JSON object.

To watch live in Wireshark, send the pcap to stdout. Each frame is flushed as it
arrives:

```sh
sudo zigbee-sniffer capture -c 25 -w - | wireshark -k -i -
ssh pi@rpi4 sudo zigbee-sniffer capture -c 25 -w - | wireshark -k -i -
```

C-c, SIGTERM (so `timeout 60 zigbee-sniffer capture ...` works), `-t`, `-n` and a closed
pipe all stop a capture the same way. The transfers are cancelled, the radio is powered
down and the summary is printed. A second C-c exits immediately.

```
$ sudo zigbee-sniffer survey --dwell 3
CH   MHz  FRAMES   BAD   MEAN dBm  PEAK dBm  SOURCES  PANS
11  2405       0     0          -         -        0
12  2410       3     1      -84.3       -82        1  0x6ed2
...
24  2470       2     2      -80.0       -64        0
25  2475       5     4      -92.0       -88        1  0x6ed2
26  2480       0     0          -         -        0
```

## What goes in the pcap

Frames are written with link type 283, `LINKTYPE_IEEE802_15_4_TAP`. Wireshark shows
each frame's RSSI, channel and link quality beside the decode. The FCS type is
declared as *none*, because the radio overwrites the FCS with RSSI and a status byte.
Recomputing the CRC would put a made-up checksum on exactly the frames that are
corrupt.

Frames that fail CRC are counted but not written or shown unless you pass `--bad-crc`.
A corrupt frame can decode as a device that does not exist. On channel 12, two corrupt
beacons from `00:d0:2d:ff:fe:12:e3:cb` decoded with source addresses
`c0:d5:2d:ff:9e:12:e3:cd` and `2d:ff:fe:f2:e3:cb:6e:d2`. TAP has no field for CRC
validity, so a bad frame in a pcap file looks the same as a good one.

**Passing CRC is not enough on its own.** Over an hour on channel 25, about 3% of the
frames the radio marked CRC-OK were plainly corrupt. They were real MLE advertisements
and beacons with bits flipped throughout, and frames of random bytes, with RSSI
readings from −200 to +53 dBm, which the radio cannot measure. Many carried the same
trailing −34 dBm / LQI 63 under different "sources", so even their status bytes were
not the radio's. A frame is therefore also rejected as *implausible* if any of these
hold:
- its RSSI is outside −100 to +10 dBm
- its frame type is one that nothing on 2.4 GHz sends (reserved, multipurpose,
  fragment or extended)
- its frame version is the reserved 3
- it is a 2003/2006 acknowledgement that is not exactly three octets
- it is too short for its own header

Implausible frames are counted and excluded like failed-CRC frames; `--implausible`
keeps them. Some corrupt frames still pass every check, typically a real address with
one byte wrong, so `survey` counts a source only once it has been heard twice.

**RSSI** is the radio's RSSI byte minus 73 dB, the CC2530-family datasheet's typical
offset. Without the offset, a neighbour's thermostat reads about -17 dBm, a level you
would expect from a transmitter a few centimetres away, yet a third of its frames fail
CRC. With the offset it reads about -90 dBm, near the radio's sensitivity, which is
consistent with that failure rate. **LQI** is the radio's 7-bit correlation value
(0-127). The CC2531 has no true 802.15.4 LQI.

## The firmware

TI's sniffer firmware provides six vendor control requests and one bulk IN endpoint
(`0x83`). All of them are in `src/dongle.lisp`: `GET_IDENT` (`0xC0`), `SET_POWER`/`GET_POWER`
(`0xC5`/`0xC6`), `SET_START`/`SET_END` (`0xD0`/`0xD1`) and `SET_CHAN` (`0xD2`, sent
as two requests: the low byte, then the high byte). The meaning of the `GET_IDENT` bytes is
undocumented, so they are shown as hex.

The bulk endpoint delivers a byte stream of messages: a type byte, a 16-bit length and
a body. Most reads hold exactly one message, but about one in a hundred arrives split
across two reads at an arbitrary offset. So reads are joined in order and cut on the
messages' own length fields, and a header that cannot be right is skipped a byte at a
time until one that can is found. The summary reports the bytes skipped. Type 0 is a
captured frame: a 32-bit timestamp counting 1/32 µs, a length byte, and the frame with
its last two bytes replaced by RSSI and a status byte. The top bit of the status byte is
CRC-OK and the low seven bits are the correlation value. Type 1 is a timer heartbeat.
The layout was read off live hexdumps. `src/stream.lisp` shows an annotated example.
The counter wraps every 134 s. Timestamps are anchored to the host clock at the first
frame, and after that they follow the dongle's counter, so the gaps between frames are
the radio's own measurements.

## Building

```sh
git clone git@github.com:lispnik/libusb.git          # a sibling of this tree
git clone git@github.com:lispnik/zigbee-sniffer.git
cd zigbee-sniffer
ocicl install        # restore ocicl/ from ocicl.csv
make                 # bin/zigbee-sniffer; build it on the machine that runs it
make test            # the core suite; needs no dongle and no libusb
```

`LIBUSB_DIR` points at the libusb checkout (default `../libusb`). Only `#:libusb` is
loaded, not `libusb/closures`, so you do not need libffi or a C compiler.

On the Pi, `make deploy` copies this tree, its `ocicl/` and the libusb checkout, and
clears stale fasls on the Pi. `make pi-build` and `make pi-test` then build and test
there. Opening the dongle needs write access to its device node. Either run as root, or
install `contrib/99-cc2531-sniffer.rules`, which gives the `plugdev` group access.

## Systems

| System | Depends on | What it is |
|---|---|---|
| `zigbee-sniffer/core` | — | The stream parser and reassembler, the plausibility checks, the layered decoder, vendor lookup, the inventory, the dongle clock, and pcap reading and writing. |
| `zigbee-sniffer` | core, `libusb`, `sb-concurrency` | The dongle: finding it, its vendor requests and streaming capture. |
| `zigbee-sniffer/cli` | `zigbee-sniffer`, `clingon` | The `bin/zigbee-sniffer` binary. |
| `zigbee-sniffer/tests` | core, `fiveam` | Uses real frames from a channel-25 capture as fixtures. |

SBCL only.

## License

MIT.
