#include "safety_number.h"

#include "private.h"
#include "sizes.h"

namespace Autograph {

SafetyNumberFunction createSafetyNumber(const Bytes ourIdentityKey) {
  auto safetyNumberFunction = [ourIdentityKey](const Bytes theirIdentityKey) {
    Bytes safetyNumber(SAFETY_NUMBER_SIZE);
    bool success =
        autograph_safety_number(safetyNumber.data(), ourIdentityKey.data(),
                                theirIdentityKey.data()) == 0;
    SafetyNumberResult result = {success, safetyNumber};
    return result;
  };
  return safetyNumberFunction;
}

}  // namespace Autograph
