#include "autograph/core/init.h"

#include "sodium.h"

int autograph_core_init() {
  if (sodium_init() == 0) {
    return 0;
  } else {
    return -1;
  }
}
