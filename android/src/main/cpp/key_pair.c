#include <jni.h>

#include "autograph.h"

JNIEXPORT jint JNICALL
Java_sh_autograph_KeyPair_00024Companion_autographKeyPairSize(JNIEnv* env,
                                                              jclass class) {
  return (jint)autograph_key_pair_size();
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_KeyPair_00024Companion_autographIdentityKeyPair(
    JNIEnv* env, jclass class, jbyteArray key_pair) {
  jbyte* elements = (*env)->GetByteArrayElements(env, key_pair, NULL);
  bool result = autograph_identity_key_pair((uint8_t*)elements);
  if (result) {
    (*env)->ReleaseByteArrayElements(env, key_pair, elements, 0);
  } else {
    (*env)->ReleaseByteArrayElements(env, key_pair, elements, JNI_ABORT);
  }
  return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_KeyPair_00024Companion_autographEphemeralKeyPair(
    JNIEnv* env, jclass class, jbyteArray key_pair) {
  jbyte* elements = (*env)->GetByteArrayElements(env, key_pair, NULL);
  bool success = autograph_ephemeral_key_pair((uint8_t*)elements);
  if (success) {
    (*env)->ReleaseByteArrayElements(env, key_pair, elements, 0);
  } else {
    (*env)->ReleaseByteArrayElements(env, key_pair, elements, JNI_ABORT);
  }
  return success ? JNI_TRUE : JNI_FALSE;
}
