
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

#define CPY4(x) *((uint32_t *)x)
#define CPY8(x) *((uint64_t *)x)

#define ioctl_FIONBIO(fd, mode) \
{ \
  int ioctl_mode=mode; \
  ioctl(fd, FIONBIO, (char *)&ioctl_mode); \
}
