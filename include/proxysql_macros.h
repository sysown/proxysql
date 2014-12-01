


// fast memory copy forward . Use this instead of memcpy for small buffers
#define MEM_COPY_FWD(dst_p, src_p, bytes)  \
    do { \
        void *__a=dst_p; \
        void *__b=src_p; \
        size_t __nbytes = (bytes); \
        while (__nbytes > 0) { \
        char __x = ((char *) __b)[0]; \
            __b += 1; \
            __nbytes -= 1; \
            ((char *) __a)[0] = __x; \
            __a += 1; \
        } \
    } while (0)


// copy 1 byte
#define CPY1(x)	*((uint8_t *)x)

// copy 2 bytes
#define CPY2(x)	*((uint16_t *)x)



/*
#define CPY3(x) \
	do { \
		uchar _cpy3buf[4]; \
		memcpy(_cpy3buf, x, 3); \
		_cpy3buf[3]=0; \
		return *((uint32_t *)cy3buf); \
	} while(0)
*/

// copy 4 bytes
#define CPY4(x) *((uint32_t *)x)

// copy 8 bytes
#define CPY8(x) *((uint64_t *)x)

// (un)set blocking mode on a file descriptor
#define ioctl_FIONBIO(fd, mode) \
{ \
  int ioctl_mode=mode; \
  ioctl(fd, FIONBIO, (char *)&ioctl_mode); \
}

// copy 4 bytes
#define Copy4B(x,y) \
	do { \
		uint32_t *a=(uint32_t *)x; \
		*a=*((uint32_t *)y); \
	} while(0)
