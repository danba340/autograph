#include "sizes.h"

namespace Autograph {

unsigned int getCiphertextSize(unsigned int plaintextSize) {
  return autograph_ciphertext_size(plaintextSize);
}

unsigned int getPlaintextSize(unsigned int ciphertextSize) {
  return autograph_plaintext_size(ciphertextSize);
}

unsigned int getSubjectSize(unsigned int size) {
  return autograph_subject_size(size);
}

}  // namespace Autograph
