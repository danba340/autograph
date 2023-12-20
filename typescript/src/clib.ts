import wasmModule from '../wasm/autograph.js'

type EmscriptenModule = {
  _calloc: (size: number, elementSize: number) => number
  _free: (ptr: number) => void
  ccall: (
    name: string,
    returnType: string,
    types: string[],
    values: (number | bigint)[]
  ) => number | bigint
  HEAPU8: Uint8Array
}

type EmscriptenValue = number | bigint | Uint8Array

type EmscriptenAddressPool = Map<number, Uint8Array>

let Module: EmscriptenModule = null

const allocate = (
  addresses: EmscriptenAddressPool,
  args: EmscriptenValue[]
) => {
  const types: string[] = []
  const values = args.map((value) => {
    if (value instanceof Uint8Array) {
      types.push('number')
      const address = Module._calloc(value.byteLength, 1)
      addresses.set(address, value)
      Module.HEAPU8.set(value, address)
      return address
    }
    types.push(typeof value)
    return value
  })
  return { types, values }
}

const deallocate = (addresses: EmscriptenAddressPool) => {
  addresses.forEach((value, address) => {
    value.set(Module.HEAPU8.subarray(address, address + value.byteLength))
    Module._free(address)
  })
}

const call = (name: string, returnType: string, ...args: EmscriptenValue[]) => {
  const addresses: EmscriptenAddressPool = new Map()
  const { types, values } = allocate(addresses, args)
  const result = Module.ccall(name, returnType, types, values)
  deallocate(addresses)
  return result
}

export const ready = async () => {
  if (!Module) {
    Module = (await wasmModule()) as EmscriptenModule
  }
}

export const certify_data = (
  signature: Uint8Array,
  state: Uint8Array,
  data: Uint8Array,
  data_size: number
) => call('autograph_certify_data', 'number', signature, state, data, data_size)

export const certify_identity = (signature: Uint8Array, state: Uint8Array) =>
  call('autograph_certify_identity', 'number', signature, state)

export const ciphertext_size = (plaintext_size: number) =>
  call('autograph_ciphertext_size', 'number', plaintext_size) as number

export const close_session = (
  secret_key: Uint8Array,
  ciphertext: Uint8Array,
  state: Uint8Array
) =>
  call(
    'autograph_close_session',
    'number',
    secret_key,
    ciphertext,
    state
  ) as number

export const decrypt_message = (
  plaintext: Uint8Array,
  plaintext_size: Uint8Array,
  index: Uint8Array,
  state: Uint8Array,
  ciphertext: Uint8Array,
  ciphertext_size: number
) =>
  call(
    'autograph_decrypt_message',
    'number',
    plaintext,
    plaintext_size,
    index,
    state,
    ciphertext,
    ciphertext_size
  )

export const encrypt_message = (
  ciphertext: Uint8Array,
  index: Uint8Array,
  state: Uint8Array,
  plaintext: Uint8Array,
  plaintext_size: number
) =>
  call(
    'autograph_encrypt_message',
    'number',
    ciphertext,
    index,
    state,
    plaintext,
    plaintext_size
  )

export const ephemeral_key_pair = (
  private_key: Uint8Array,
  public_key: Uint8Array
) => call('autograph_ephemeral_key_pair', 'number', private_key, public_key)

export const identity_key_pair = (
  private_key: Uint8Array,
  public_key: Uint8Array
) => call('autograph_identity_key_pair', 'number', private_key, public_key)

export const key_exchange = (
  our_handshake: Uint8Array,
  state: Uint8Array,
  is_initiator: number,
  our_identity_private_key: Uint8Array,
  our_identity_public_key: Uint8Array,
  our_ephemeral_private_key: Uint8Array,
  our_ephemeral_public_key: Uint8Array,
  their_identity_public_key: Uint8Array,
  their_ephemeral_public_key: Uint8Array
) =>
  call(
    'autograph_key_exchange',
    'number',
    our_handshake,
    state,
    is_initiator,
    our_identity_private_key,
    our_identity_public_key,
    our_ephemeral_private_key,
    our_ephemeral_public_key,
    their_identity_public_key,
    their_ephemeral_public_key
  ) as number

export const open_session = (
  state: Uint8Array,
  secret_key: Uint8Array,
  ciphertext: Uint8Array,
  ciphertext_size: number
) =>
  call(
    'autograph_open_session',
    'number',
    state,
    secret_key,
    ciphertext,
    ciphertext_size
  )

export const plaintext_size = (ciphertext_size: number) =>
  call('autograph_plaintext_size', 'number', ciphertext_size) as number

export const read_index = (bytes: Uint8Array) =>
  call('autograph_read_index', 'number', bytes) as number

export const read_size = (bytes: Uint8Array) =>
  call('autograph_read_size', 'number', bytes) as number

export const safety_number = (safety_number: Uint8Array, state: Uint8Array) =>
  call('autograph_safety_number', 'number', safety_number, state) as number

export const session_size = (state: Uint8Array) =>
  call('autograph_session_size', 'number', state) as number

export const verify_data = (
  state: Uint8Array,
  data: Uint8Array,
  data_size: number,
  public_key: Uint8Array,
  signature: Uint8Array
) =>
  call(
    'autograph_verify_data',
    'number',
    state,
    data,
    data_size,
    public_key,
    signature
  ) as number

export const verify_identity = (
  state: Uint8Array,
  public_key: Uint8Array,
  signature: Uint8Array
) =>
  call(
    'autograph_verify_identity',
    'number',
    state,
    public_key,
    signature
  ) as number

export const verify_key_exchange = (
  state: Uint8Array,
  our_ephemeral_public_key: Uint8Array,
  their_handshake: Uint8Array
) =>
  call(
    'autograph_verify_key_exchange',
    'number',
    state,
    our_ephemeral_public_key,
    their_handshake
  ) as number
