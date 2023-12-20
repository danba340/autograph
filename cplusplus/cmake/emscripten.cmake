add_executable(${AUTOGRAPH_TARGET} ${AUTOGRAPH_SOURCES})

target_compile_options(${AUTOGRAPH_TARGET} PRIVATE -Os)

set(AUTOGRAPH_EXPORTED_FUNCTIONS
    autograph_certify_data
    autograph_certify_identity
    autograph_ciphertext_size
    autograph_close_session
    autograph_decrypt_message
    autograph_encrypt_message
    autograph_ephemeral_key_pair
    autograph_identity_key_pair
    autograph_key_exchange
    autograph_open_session
    autograph_plaintext_size
    autograph_read_index
    autograph_read_size
    autograph_safety_number
    autograph_session_size
    autograph_verify_data
    autograph_verify_identity
    autograph_verify_key_exchange
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
