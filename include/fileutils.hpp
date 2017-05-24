#include <unistd.h>

#ifndef __CLASS_FILEUTILS_H
#define __CLASS_FILEUTILS_H
class FileUtils {
public:
  static bool isReadable(const char *pathname) {
    if (access(pathname, R_OK) == 0)
      return true;
    return false;
  };
  static bool isWritable(const char *pathname) {
    if (access(pathname, W_OK) == 0)
      return true;
    return false;
  };
};
#endif /* __CLASS_FILEUTILS_H */
