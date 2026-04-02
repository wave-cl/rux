/* Minimal dynamically-linked test program for rux kernel.
 * Uses raw write() syscall to avoid stdio buffering complexity.
 * Build: x86_64-linux-musl-gcc -o dynhello_x86_64.elf dynhello.c
 *        aarch64-linux-musl-gcc -o dynhello_aarch64.elf dynhello.c
 */
#include <unistd.h>

int main(void) {
    write(1, "dynlink_ok\n", 11);
    return 0;
}
