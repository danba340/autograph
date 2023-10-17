add_executable(${AUTOGRAPH_TARGET} ${AUTOGRAPH_SOURCES})

target_compile_options(${AUTOGRAPH_TARGET} PRIVATE -Os)

set(AUTOGRAPH_EXPORTED_FUNCTIONS
    autograph_ciphertext_size
    autograph_decrypt
    autograph_encrypt
    autograph_handshake_size
    autograph_index_size
    autograph_init
    autograph_key_exchange
    autograph_key_exchange_signature
    autograph_key_exchange_transcript
    autograph_key_exchange_verify
    autograph_key_pair_ephemeral
    autograph_key_pair_identity
    autograph_plaintext_size
    autograph_private_key_size
    autograph_public_key_size
    autograph_read_uint32
    autograph_read_uint64
    autograph_safety_number
    autograph_safety_number_size
    autograph_secret_key_size
    autograph_signature_size
    autograph_sign_data
    autograph_sign_identity
    autograph_sign_subject
    autograph_size_size
    autograph_skipped_keys_size
    autograph_subject
    autograph_subject_size
    autograph_transcript_size
    autograph_verify_data
    autograph_verify_identity
    calloc
    free)

string(JOIN "\'\,\'_" AUTOGRAPH_EXPORTED_FUNCTIONS
       ${AUTOGRAPH_EXPORTED_FUNCTIONS})
set(AUTOGRAPH_EXPORTED_FUNCTIONS "[\'_${AUTOGRAPH_EXPORTED_FUNCTIONS}\']")

target_link_options(
  ${AUTOGRAPH_TARGET}
  PRIVATE
  -Os
  -sEXPORT_ES6=1
  -sEXPORTED_FUNCTIONS=${AUTOGRAPH_EXPORTED_FUNCTIONS}
  -sEXPORTED_RUNTIME_METHODS=ccall
  -sMODULARIZE=1
  -sSAFE_HEAP
  -sWASM_BIGINT)
