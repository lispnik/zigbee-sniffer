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

`capture` options:

```
  -c, --channel <INT>   802.15.4 channel, 11-26 [default: 25]
  -w, --write <FILE>    write a pcap file (IEEE 802.15.4 TAP); - for stdout
  -t, --seconds <INT>   stop after this many seconds (default: run until C-c)
  -n, --count <INT>     stop after this many frames
      --bad-crc         keep frames that failed CRC
  -x, --hex             hex dump each frame's MAC bytes under its summary
  -v, --verbose         with --write, also print each frame on stderr
  -d, --device <B:A>    the dongle to use, as BUS:ADDRESS from `list`
```

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

Each bulk read returns one message: a type byte, a 16-bit length and a body. Type 0 is a
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
| `zigbee-sniffer/core` | — | The stream parser, 802.15.4 MAC header decoding, the dongle clock and the pcap/TAP writer. |
| `zigbee-sniffer` | core, `libusb`, `sb-concurrency` | The dongle: finding it, its vendor requests and streaming capture. |
| `zigbee-sniffer/cli` | `zigbee-sniffer`, `clingon` | The `bin/zigbee-sniffer` binary. |
| `zigbee-sniffer/tests` | core, `fiveam` | Uses real frames from a channel-25 capture as fixtures. |

SBCL only.

## License

MIT.
