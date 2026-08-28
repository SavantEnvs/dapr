/* mayhem/lsan_off.c — fleet policy: LeakSanitizer off at BUILD time for every
 * ASan-linked binary (fuzz_expr and the expr_kat oracle), ASan itself stays on.
 * Leaks are not a bug class this fleet fuzzes for. Linked by mayhem/build.sh.
 * Runtime toggles and the ASan default-options override are forbidden. */
int __lsan_is_turned_off(void) { return 1; }
