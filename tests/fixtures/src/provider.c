/* Linker-only ABI stubs. These are not libc implementations and are never run. */
void malloc(void) {}
void free(void) {}
void clock_gettime(void) {}
void pthread_create(void) {}
void pidfd_spawnp(void) {}
void pidfd_spawn(void) {}
