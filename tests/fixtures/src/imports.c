extern void malloc(void), free(void), clock_gettime(void);
extern void pthread_create(void), pidfd_spawnp(void), pidfd_spawn(void);
#ifdef NAMESPACES
extern void cpp_api(void), cxx_api(void), gcc_api(void), ssl_api(void), misleading(void);
#endif
/* A decoy string must never become a version requirement. */
const char decoy[] = "GLIBC_99.99";
void _start(void) {
    malloc(); free(); clock_gettime();
#ifdef NEW_GLIBC
    pthread_create(); pidfd_spawnp(); pidfd_spawn();
#endif
#ifdef NAMESPACES
    cpp_api(); cxx_api(); gcc_api(); ssl_api(); misleading();
#endif
}
