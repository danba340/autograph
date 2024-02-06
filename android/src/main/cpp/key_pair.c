#include <jni.h>

#include "autograph.h"

JNIEXPORT jboolean JNICALL Java_sh_autograph_KeyPair_autographIdentityKeyPair(
    JNIEnv* env, jobject obj, jbyteArray key_pair) {
  jbyte* elements = (*env)->GetByteArrayElements(env, key_pair, NULL);
  bool result = autograph_identity_key_pair((uint8_t*)elements);
  if (result) {
    (*env)->ReleaseByteArrayElements(env, key_pair, elements, 0);
  } else {
    (*env)->ReleaseByteArrayElements(env, key_pair, elements, JNI_ABORT);
  }
  return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_sh_autograph_KeyPair_autographEphemeralKeyPair(
    JNIEnv* env, jobject obj, jbyteArray key_pair) {
  jbyte* elements = (*env)->GetByteArrayElements(env, key_pair, NULL);
  bool success = autograph_ephemeral_key_pair((uint8_t*)elements);
  if (success) {
    (*env)->ReleaseByteArrayElements(env, key_pair, elements, 0);
  } else {
    (*env)->ReleaseByteArrayElements(env, key_pair, elements, JNI_ABORT);
  }
  return success ? JNI_TRUE : JNI_FALSE;
}
