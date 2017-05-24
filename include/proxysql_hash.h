/*
Use of generic memory structure
set/get function defined by the user

Ex:
*/

typedef _hte_ext_t hte_ext_t;

union _hte_ext_t {
  void *ptr;
  int i;
  uint32_t u32;
  uint64_t u64;
};

struct __leo_hash_entry_t {
  unsigned char *key;
  void *self;
  hte_ext_t ext0;
  hte_ext_t ext1;
  hte_ext_t ext2;
  hte_ext_t ext3;
  hte_ext_t ext4;
  hte_ext_t ext5;
  hte_ext_t ext6;
  hte_ext_t ext7;
  hte_ext_t ext8;
  hte_ext_t ext9;
};
