# Build all rux user programs for both architectures.
# Requires: clang, rust-lld (via rustup)

PROGS = hello count ls cat uname uptime echo mkfile rm wc shell

# Base addresses (each program gets a unique VA to avoid conflicts)
BASE_hello   = 0x2000000
BASE_count   = 0x3000000
BASE_ls      = 0x4000000
BASE_cat     = 0x5000000
BASE_uname   = 0x6000000
BASE_uptime  = 0x6000000
BASE_echo    = 0x6000000
BASE_mkfile  = 0x7000000
BASE_rm      = 0x7000000
BASE_wc      = 0xA000000
BASE_shell   = 0x1000000

LLD = rustup run nightly rust-lld -flavor gnu

all: $(foreach p,$(PROGS),$(p)_x86_64.elf $(p)_aarch64.elf)

%_x86_64.elf: %_x86_64.S
	clang -target x86_64-elf -c -o /tmp/$*_x86_64.o $<
	$(LLD) -o $@ /tmp/$*_x86_64.o --image-base=$(BASE_$*) -z noexecstack

%_aarch64.elf: %_aarch64.S
	clang -target aarch64-elf -c -o /tmp/$*_aarch64.o $<
	$(LLD) -o $@ /tmp/$*_aarch64.o --image-base=$(BASE_$*) -z noexecstack

clean:
	rm -f *.elf /tmp/*_x86_64.o /tmp/*_aarch64.o

.PHONY: all clean
