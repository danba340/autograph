import wasmModule from '../wasm/autograph.js'

type EmscriptenModule = {
  _calloc: (size: number, elementSize: number) => number
  _free: (ptr: number) => void
  ccall: (
    name: string,
    returnType: string,
    types: string[],
    values: (number | boolean)[]
  ) => number | boolean
  HEAPU8: Uint8Array
}

type EmscriptenValue = number | boolean | Uint8Array

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

const call = (
  name: string,
  returnType: string | null,
  ...args: EmscriptenValue[]
) => {
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

export const autograph_identity_key_pair = (key_pair: Uint8Array) =>
  call('autograph_identity_key_pair', 'boolean', key_pair) as boolean

export const autograph_ephemeral_key_pair = (key_pair: Uint8Array) =>
  call('autograph_ephemeral_key_pair', 'boolean', key_pair) as boolean

export const autograph_use_key_pairs = (
  public_keys: Uint8Array,
  state: Uint8Array,
  identity_key_pair: Uint8Array,
  ephemeral_key_pair: Uint8Array
) =>
  call(
    'autograph_use_key_pairs',
    'boolean',
    public_keys,
    state,
    identity_key_pair,
    ephemeral_key_pair
  ) as boolean

export const autograph_use_public_keys = (
  state: Uint8Array,
  public_keys: Uint8Array
) => call('autograph_use_public_keys', null, state, public_keys)

export const autograph_authenticate = (
  safety_number: Uint8Array,
  state: Uint8Array
) => call('autograph_authenticate', 'boolean', safety_number, state) as boolean

export const autograph_key_exchange = (
  our_signature: Uint8Array,
  state: Uint8Array,
  is_initiator: boolean
) =>
  call(
    'autograph_key_exchange',
    'boolean',
    our_signature,
    state,
    is_initiator
  ) as boolean

export const autograph_verify_key_exchange = (
  state: Uint8Array,
  their_signature: Uint8Array
) =>
  call(
    'autograph_verify_key_exchange',
    'boolean',
    state,
    their_signature
  ) as boolean

export const autograph_encrypt_message = (
  ciphertext: Uint8Array,
  index: Uint8Array,
  state: Uint8Array,
  plaintext: Uint8Array,
  plaintext_size: number
) =>
  call(
    'autograph_encrypt_message',
    'boolean',
    ciphertext,
    index,
    state,
    plaintext,
    plaintext_size
  ) as boolean

export const autograph_decrypt_message = (
  plaintext: Uint8Array,
  plaintext_size: Uint8Array,
  index: Uint8Array,
  state: Uint8Array,
  ciphertext: Uint8Array,
  ciphertext_size: number
) =>
  call(
    'autograph_decrypt_message',
    'boolean',
    plaintext,
    plaintext_size,
    index,
    state,
    ciphertext,
    ciphertext_size
  ) as boolean

export const autograph_certify_data = (
  signature: Uint8Array,
  state: Uint8Array,
  data: Uint8Array,
  data_size: number
) =>
  call(
    'autograph_certify_data',
    'boolean',
    signature,
    state,
    data,
    data_size
  ) as boolean

export const autograph_certify_identity = (
  signature: Uint8Array,
  state: Uint8Array
) => call('autograph_certify_identity', 'boolean', signature, state) as boolean

export const autograph_verify_data = (
  state: Uint8Array,
  data: Uint8Array,
  data_size: number,
  public_key: Uint8Array,
  signature: Uint8Array
) =>
  call(
    'autograph_verify_data',
    'boolean',
    state,
    data,
    data_size,
    public_key,
    signature
  ) as boolean

export const autograph_verify_identity = (
  state: Uint8Array,
  public_key: Uint8Array,
  signature: Uint8Array
) =>
  call(
    'autograph_verify_identity',
    'boolean',
    state,
    public_key,
    signature
  ) as boolean

export const autograph_close_session = (
  key: Uint8Array,
  ciphertext: Uint8Array,
  state: Uint8Array
) =>
  call('autograph_close_session', 'boolean', key, ciphertext, state) as boolean

export const autograph_open_session = (
  state: Uint8Array,
  key: Uint8Array,
  ciphertext: Uint8Array,
  ciphertext_size: number
) =>
  call(
    'autograph_open_session',
    'boolean',
    state,
    key,
    ciphertext,
    ciphertext_size
  ) as boolean

export const autograph_hello_size = () =>
  call('autograph_hello_size', 'number') as number

export const autograph_key_pair_size = () =>
  call('autograph_key_pair_size', 'number') as number

export const autograph_safety_number_size = () =>
  call('autograph_safety_number_size', 'number') as number

export const autograph_secret_key_size = () =>
  call('autograph_secret_key_size', 'number') as number

export const autograph_signature_size = () =>
  call('autograph_signature_size', 'number') as number

export const autograph_state_size = () =>
  call('autograph_state_size', 'number') as number

export const autograph_index_size = () =>
  call('autograph_index_size', 'number') as number

export const autograph_size_size = () =>
  call('autograph_size_size', 'number') as number

export const autograph_session_size = (state: Uint8Array) =>
  call('autograph_session_size', 'number', state) as number

export const autograph_ciphertext_size = (plaintext_size: number) =>
  call('autograph_ciphertext_size', 'number', plaintext_size) as number

export const autograph_plaintext_size = (ciphertext_size: number) =>
  call('autograph_plaintext_size', 'number', ciphertext_size) as number

export const autograph_read_index = (bytes: Uint8Array) =>
  call('autograph_read_index', 'number', bytes) as number

export const autograph_read_size = (bytes: Uint8Array) =>
  call('autograph_read_size', 'number', bytes) as number
