extern void clock_gettime(void);
extern void pidfd_spawnp(void) __attribute__((weak));

/* Linker fixture only: never executed. */
void _start(void) {
    clock_gettime();
    if (pidfd_spawnp)
        pidfd_spawnp();
}
