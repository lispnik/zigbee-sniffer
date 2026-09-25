# Build and test zigbee-sniffer.
#
#   make          -- build bin/zigbee-sniffer (embeds the SBCL core)
#   make test     -- run the core suite (no dongle, no libusb needed)
#   make deploy   -- copy this tree and the libusb checkout to the Pi
#   make pi-build -- build bin/zigbee-sniffer on the Pi
#   make pi-test  -- run the core suite on the Pi
#   make clean    -- remove bin/ and this tree's fasl cache
#
# The binary embeds the SBCL core, so build it on the machine it will run on --
# which for a sniffer is usually the Pi with the dongle in it.

SBCL       ?= sbcl
SBCL_FLAGS := --noinform --non-interactive --no-userinit --no-sysinit

# Where `libusb' lives: github.com/lispnik/libusb, a sibling checkout rather than
# an ocicl dependency because ocicl has nothing to fetch -- it is ours.
LIBUSB_DIR ?= ../libusb

# Hermetic source registry: this tree, its vendored ocicl/ deps, and exactly one
# directory of the libusb checkout -- :directory, not :tree, so we pick up
# libusb.asd without also inheriting libusb's own vendored ocicl/ and ending up with
# two copies of cffi on the registry. Nothing else the machine has lying around gets
# in; a missing dependency should fail loudly rather than resolve to a neighbour's.
BOOT := --eval "(require :asdf)" \
        --eval "(asdf:initialize-source-registry \`(:source-registry (:tree ,(truename \"./\")) (:directory ,(truename \"$(LIBUSB_DIR)/\")) :ignore-inherited-configuration))"

# Where the dongle is. Overridable: make deploy HOST=pi@other
HOST        ?= pi@rpi4
DEST        ?= ~/zigbee-sniffer/
LIBUSB_DEST ?= ~/libusb/

# Plain `make', not $(MAKE): that expands to this machine's path, which on macOS is
# inside Xcode and does not exist on the Pi.
REMOTE_MAKE ?= make

SRC := zigbee-sniffer.asd $(wildcard src/*.lisp) $(wildcard cli/*.lisp) \
       $(LIBUSB_DIR)/libusb.asd $(wildcard $(LIBUSB_DIR)/src/*.lisp)
BIN := bin/zigbee-sniffer

.PHONY: all test deploy pi-build pi-test clean help
.DEFAULT_GOAL := all

all: $(BIN)

$(BIN): $(SRC)
	@mkdir -p bin
	$(SBCL) $(SBCL_FLAGS) $(BOOT) --eval "(asdf:make :zigbee-sniffer/cli)" --eval "(sb-ext:exit)"
	@ls -lh $(BIN)

test:
	$(SBCL) $(SBCL_FLAGS) $(BOOT) \
	  --eval "(asdf:test-system :zigbee-sniffer/core)" --eval "(sb-ext:exit)"

# Copy both trees, then DROP THE REMOTE FASL CACHE.
#
# rsync -a preserves this machine's mtimes, and against the Pi's cached build times
# they can look older -- so ASDF sees no reason to recompile and silently keeps the
# previous build. The source on the Pi is right, the fasls are not, and the only clue
# is behaviour that matches code you have already changed. Root's cache too: the
# binary is often run under sudo, and `sudo -E make' builds into root's.
#
# The libusb checkout is shipped as well, because it is in no ocicl registry and the
# Pi cannot fetch it. Its own ocicl/ is not: libusb resolves cffi and
# bordeaux-threads from OUR ocicl/, which is the point of :directory above.
deploy:
	rsync -a --delete --exclude .git --exclude ocicl --exclude bin --exclude captures --exclude '*.pcap' \
	      --exclude '*.fasl' ./ $(HOST):$(DEST)
	rsync -a --exclude .git ./ocicl/ $(HOST):$(DEST)ocicl/
	rsync -a --delete --exclude .git --exclude ocicl --exclude vendor --exclude '*.fasl' \
	      $(LIBUSB_DIR)/ $(HOST):$(LIBUSB_DEST)
	ssh $(HOST) 'sudo -n find ~/.cache/common-lisp /root/.cache/common-lisp \
	               \( -path "*/zigbee-sniffer/src/*" -o -path "*/zigbee-sniffer/cli/*" \
	                  -o -path "*/zigbee-sniffer/tests/*" -o -path "*/libusb/src/*" \) \
	               -delete 2>/dev/null; exit 0'
	@# Verified, not assumed: a cache that silently survives is the whole failure
	@# this target exists to prevent.
	ssh $(HOST) 'test -z "$$(find ~/.cache/common-lisp /root/.cache/common-lisp \
	               \( -path "*/zigbee-sniffer/src/*" -o -path "*/zigbee-sniffer/cli/*" \
	                  -o -path "*/libusb/src/*" \) -name "*.fasl" 2>/dev/null | head -1)"' \
	  && echo "==> deployed to $(HOST):$(DEST), stale fasls cleared" \
	  || (echo "deploy: remote fasl cache NOT cleared" >&2; exit 1)

pi-build:
	ssh $(HOST) 'cd $(DEST) && $(REMOTE_MAKE) LIBUSB_DIR=$(LIBUSB_DEST)'

pi-test:
	ssh $(HOST) 'cd $(DEST) && $(REMOTE_MAKE) test LIBUSB_DIR=$(LIBUSB_DEST)'

clean:
	rm -rf bin
	rm -rf $(HOME)/.cache/common-lisp/*/$(subst /,_,$(CURDIR))

help:
	@grep -E '^#   ' Makefile | sed 's/^#   //'
