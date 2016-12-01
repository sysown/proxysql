static unsigned int g_seed;


inline void fast_srand( int seed ) {
g_seed = seed;
}
inline int fastrand() {
    g_seed = (214013*g_seed+2531011);
    return (g_seed>>16)&0x7FFF;
}

static char _s[128];

void gen_random_stdstring(string *s, const int len) {
  //char *_s=(char *)alloca(len+1);
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    for (int i = 0; i < len; ++i) {
        _s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
    }
    _s[len] = '\0';
  *s=string(_s);
    //return s;
}



char * gen_random_string(const int len) {
    char *s=(char *)malloc(len+1);
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
    return s;
}
