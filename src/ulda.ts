// Licensed under ULDA-NC-1.0 — see LICENSE
// © 2025 Mark Shaposhnik / ZeroAM

import { Socket } from 'socket.io-client'
import { SocketApi } from './socket'

type PasswordConfig = {
  password: string
  iv?: string
  salt?: string
  passwordConfig?: {
    PBKDF2Salt: string
    PBKDF2itter: number
  }
}

type DisassembleConfig = {
  content: Uint8Array
  password: PasswordConfig
  signatures: Uint8Array
}

type Signatures = {
  [key: number]: Uint8Array
}

type DisassembleResponse = {
  gap: number
  password: PasswordConfig
  jsonOrigin: any
  signatures?: Signatures
  backUp: Uint8Array | null
  iteration: number
  size: number
}

type Structure = {
  size: number
  iteration: number
  line: Signatures | null
  signature: Uint8Array | null
  backupNormal: Uint8Array | null
  backupToUpdate: Uint8Array | null
  backupToUpdateNumber: number | null
  backup: Uint8Array | null
}

type SignatureTypeCheckResponse = {
  status: boolean
  backupStatus: boolean
  structure: Structure | null
}

type SuperAssemblerConfig = {
  gap: number
  password: PasswordConfig
  jsonOrigin: Record<string, unknown>
  signatures: Signatures
  backUp: Uint8Array
}

type LocalPackage = {
  backUp: Uint8Array
  signatures: Signatures
  gap: number
}

type GlobalPackage = {
  signPack: Uint8Array
  textBlock: Uint8Array
}

type PackageToSend = {
  local: LocalPackage
  global: GlobalPackage
}

type ContentFile = {
  id: number
  signPack: Uint8Array
  textBlock: Uint8Array
  masterFileId: number
  createdAt: Date
}

export interface ContentFileResponse {
  name: string
  id: number
  content: string | Record<string, any>
}

interface ContentFileData extends DisassembleResponse {
  id: number
  name: string
}

export const ulda0 = {
  /**
   * Generates a specified number of random signatures using the Web Crypto API.
   *
   * @param {number} [signatureCount=5] - The number of signatures to generate, defaults to 5.
   * @returns {Promise<{ [key: number]: Uint8Array }>} An object with numeric keys mapping to 24-byte random Uint8Arrays.
   *
   * This function creates cryptographically secure random byte arrays, which serve as the initial signatures for the system.
   * It is used to initialize the signature line, a critical component for cryptographic operations like linking hashes and assembling packages.
   * The randomness ensures uniqueness and security in the signature generation process.
   */
  generateSignatures: async (signatureCount = 5) => {
    // generates origins for signatures
    const signatures: { [key: number]: Uint8Array } = {}

    for (let i = 0; i < signatureCount; i++) {
      const array = new Uint8Array(24)
      signatures[i] = window.crypto.getRandomValues(array)
    }

    return signatures
  },

  /**
   * Updates the signature array by removing the oldest entry and adding a new random signature.
   *
   * @param {{ [key: number]: Uint8Array }} array - The current signature array to update.
   * @returns {Promise<{ [key: number]: Uint8Array }>} The updated signature array.
   *
   * This function implements a sliding window mechanism for signatures, ensuring they evolve over time.
   * It removes the signature with the smallest key and appends a new one with a key one greater than the current maximum.
   * This is vital for maintaining a dynamic and secure signature line, used in assembling packages for server communication.
   */
  stepUpSignaturesUpdate: async (array: {
    [key: number]: Uint8Array
  }): Promise<{ [key: number]: Uint8Array }> => {
    // Takes signature line and makes +1 to the stack
    delete array[Math.min(...Object.keys(array).map(Number))]
    array[Math.max(...Object.keys(array).map(Number)) + 1] =
      window.crypto.getRandomValues(new Uint8Array(24))
    return array
  },

  /**
   * Creates a chain of linked hashes from a signature line, enhancing security through interdependence.
   *
   * @param {Signatures} line - The signature line to process.
   * @returns {Promise<{ [key: number]: Uint8Array }>} An object containing the linked hash chain.
   *
   * This function is the core cryptographic engine for signing signatures. It iteratively hashes each signature,
   * combining it with CRC32 checksums to link them, ensuring that altering one signature affects subsequent ones.
   * It’s essential for verifying data integrity and authenticity in the package sent to the server.
   */
  generateLinkedHashes: async (line: Signatures) => {
    // Main engine part to sign all the signatures in proper way
    const start = Math.min(...Object.keys(line).map(Number))
    const end = Math.max(...Object.keys(line).map(Number))
    const chain: { [key: number]: Signatures } = {}
    const finishedChain = { [start]: line[start] }

    for (let i = start + 1; i <= end; i++) {
      chain[i] = { 0: line[i] }
      for (let k = 1; k <= i - start; k++) {
        const current = await ulda0.sha256(chain[i][k - 1])
        const crcCurrent = ulda0.calculateCRC32(current)
        const crcOld = ulda0.calculateCRC32(chain[i][k - 1])
        const ready = current.slice(0, 16)
        chain[i][k] = new Uint8Array([...ready, ...crcCurrent, ...crcOld])
      }
      finishedChain[i] =
        chain[i][Math.max(...Object.keys(chain[i]).map(Number))]
    }

    return finishedChain
  },

  /**
   * Computes the SHA-256 hash of a byte array using the Web Crypto API.
   *
   * @param {Uint8Array} data - The byte array to hash.
   * @returns {Promise<Uint8Array>} The 32-byte SHA-256 hash.
   *
   * This utility function provides a secure hashing mechanism used across the codebase for integrity checks and signature generation.
   * It’s a fundamental building block for cryptographic operations, ensuring data consistency and security.
   */
  sha256: async (data: Uint8Array): Promise<Uint8Array> => {
    // sha256 that works with byte arrays
    const buffer = new Uint8Array(data).buffer
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
    return new Uint8Array(hashBuffer)
  },

  /**
   * Calculates the CRC32 checksum of a byte array.
   *
   * @param {Uint8Array} bytes - The byte array to compute the checksum for.
   * @returns {Uint8Array} A 4-byte array representing the CRC32 checksum.
   *
   * This function implements the CRC32 algorithm to provide an additional layer of integrity checking.
   * It’s used in conjunction with SHA-256 hashing to create linked hashes, enhancing the security of signature chains.
   */
  calculateCRC32: (bytes: Uint8Array): Uint8Array => {
    // crc32 for bytes
    const table = Array(256)
      .fill(0)
      .map((_, i) => {
        let crc = i
        for (let j = 0; j < 8; j++) {
          crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1
        }
        return crc
      })

    let crc = 0xffffffff
    for (let i = 0; i < bytes.length; i++) {
      crc = (crc >>> 8) ^ table[(crc ^ bytes[i]) & 0xff]
    }
    crc = (crc ^ 0xffffffff) >>> 0

    const result = new Uint8Array(4)
    for (let i = 0; i < 4; i++) {
      result[3 - i] = (crc >>> (i * 8)) & 0xff
    }
    return result
  },

  /**
   * Serializes a signature line into a byte array for transport or storage.
   *
   * @param {{ [key: number]: Uint8Array }} line - The signature line to serialize.
   * @returns {Promise<Uint8Array>} The serialized byte array.
   *
   * This function compacts the signature line into a contiguous byte array, prefixed with metadata (size and iteration).
   * It’s necessary for preparing signatures for transmission to the server or storage, ensuring efficient and secure data handling.
   */
  normalPackImporter: async (line: {
    [key: number]: Uint8Array
  }): Promise<Uint8Array> => {
    // takes the line of signatures and prepares it for transport things, compressing a bit
    const signatureIteration = Math.min(...Object.keys(line).map(Number)) // smallest key
    const lineEnd = Math.max(...Object.keys(line).map(Number)) // largest key
    const lineSize = lineEnd - signatureIteration + 1 // calculate the size as the difference between the maximum and minimum keys + 1
    const startByteArray = ulda0.first5Bytes(signatureIteration, lineSize)
    let totalSize = 5

    for (let i = signatureIteration; i <= lineEnd; i++) {
      totalSize += line[i].byteLength // assuming line[i] is a Uint8Array
    }

    const bodyBuffer = new Uint8Array(totalSize)
    let offset = 0

    bodyBuffer.set(startByteArray, offset)
    offset += startByteArray.length

    for (let i = signatureIteration; i <= lineEnd; i++) {
      bodyBuffer.set(line[i], offset)
      offset += line[i].length
    }

    return bodyBuffer // Return the ArrayBuffer for further use
  },

  /**
   * Encodes signature iteration and line size into a 5-byte array.
   *
   * @param {number} signatureIteration - The starting iteration of the signature line.
   * @param {number} lineSize - The number of signatures in the line.
   * @returns {Uint8Array} A 5-byte array with encoded metadata.
   *
   * This utility function creates a compact representation of signature metadata, used as a header in serialized signature packages.
   * It ensures that the receiver can reconstruct the signature line’s structure accurately.
   */
  first5Bytes: (signatureIteration: number, lineSize: number): Uint8Array => {
    // takes line length and iteration and makes them to 5 bytes of data
    const buffer = new ArrayBuffer(5) // Create an ArrayBuffer of size 5 bytes
    const view = new DataView(buffer)

    view.setUint8(0, lineSize & 0xff) // Write only the lower byte of lineSize
    view.setUint32(1, signatureIteration, false) // Write signatureIteration using big-endian order

    return new Uint8Array(buffer) // Return Uint8Array representing the buffer
  },

  /**
   * Generates a random byte array as a backup origin.
   *
   * @param {number} [size=32] - The size of the byte array, defaults to 32 bytes.
   * @returns {Uint8Array} A random byte array.
   *
   * This function provides a secure random value used as the foundation for backup signatures.
   * It’s critical for initializing backup data, ensuring that each backup operation starts with a unique base.
   */
  backUpBaseGenerator: (size: number = 32): Uint8Array => {
    return crypto.getRandomValues(new Uint8Array(size))
  },

  /**
   * Merges two 32-byte arrays using XOR operations and appends an extra byte.
   *
   * @param {Uint8Array} array1 - The first 32-byte array.
   * @param {Uint8Array} array2 - The second 32-byte array.
   * @param {number} extraByte - The byte to append, typically representing iteration height.
   * @returns {Uint8Array} A 16-byte merged array.
   *
   * This function combines backup data securely by XORing halves of the input arrays and incorporating an extra byte.
   * It’s used in backup signature assembly to produce a final signature, ensuring integrity and uniqueness.
   */
  mergeSignatures: (
    array1: Uint8Array,
    array2: Uint8Array,
    extraByte: number
  ): Uint8Array => {
    // merging backups to backup signed final variant
    if (array1.length !== 32 || array2.length !== 32) {
      throw new Error('Both arrays must be exactly 32 bytes long.')
    }

    const xorHalf1 = new Uint8Array(16)
    const xorHalf2 = new Uint8Array(16)

    for (let i = 0; i < 16; i++) {
      xorHalf1[i] = array1[i] ^ array2[i] // Первые половины
      xorHalf2[i] = array1[i + 16] ^ array2[i + 16] // Вторые половины
    }

    const finalResult = new Uint8Array(16)

    for (let i = 0; i < 16; i++) {
      finalResult[i] = xorHalf1[i] ^ xorHalf2[i]
    }

    finalResult[15] = extraByte

    return finalResult
  },

  /**
   * Assembles a backup signature by repeatedly hashing the base and merging results.
   *
   * @param {Uint8Array | null} [line=null] - The base byte array, or null for an empty result.
   * @param {number} [height=254] - The number of hash iterations, defaults to 254.
   * @returns {Promise<Uint8Array>} The assembled backup signature.
   *
   * This function generates a secure signature from a backup base, used in the superAssembler for package creation.
   * It ensures that backup data is cryptographically transformed, enhancing security for server transmission.
   */
  backUpSignatureAssembler: async (
    line: Uint8Array | null = null,
    height: number = 254
  ): Promise<Uint8Array> => {
    // generates the origin from the signature
    //    let base = (line) ? line : BackUpBaseGenerator();
    let base = line

    if (base !== null) {
      for (let i = 0; i < height; i++) {
        base = await ulda0.sha256(base)
      }
    }

    const newBase = base ? await ulda0.sha256(base) : new Uint8Array()

    return base
      ? ulda0.mergeSignatures(newBase, base, height)
      : new Uint8Array()
  },

  /**
   * Prepares a backup base for transmission by hashing it multiple times.
   *
   * @param {Uint8Array} base - The base byte array to hash.
   * @param {number} iter - The number of hash iterations.
   * @returns {Promise<Uint8Array>} The hashed byte array.
   *
   * This function transforms backup data into a form suitable for server packages, adding an extra layer of security through hashing.
   * It’s used in the superAssembler to finalize backup signatures.
   */
  backupOutPorter: async (
    base: Uint8Array,
    iter: number
  ): Promise<Uint8Array> => {
    // provides option where it makes signature ready to send
    for (let i = 0; i < iter; i++) {
      base = await ulda0.sha256(base)
    }
    return base
  },

  /**
   * Assembles a complete data package for server transmission, including signatures, backup, and encrypted content.
   *
   * @param {SuperAssemblerConfig} config - Configuration with gap, password, jsonOrigin, signatures, and backUp.
   * @returns {Promise<PackageToSend>} An object with local and global package components.
   *
   * This central function orchestrates the creation of a secure package by updating signatures, handling backups,
   * and encrypting content. It’s the primary mechanism for preparing data to be sent to the server securely.
   */
  superAssembler: async (
    config: SuperAssemblerConfig
  ): Promise<PackageToSend> => {
    //Prepares all the parts to be signed and transported to the server
    // creating signature
    const newLine = await ulda0.stepUpSignaturesUpdate(config.signatures)
    const newLinePorter = await ulda0.normalPackImporter(newLine)
    const newSignatureProof = await ulda0.generateLinkedHashes(config.signatures)
    const preparedLine = await ulda0.normalPackImporter(newSignatureProof)

    // backup part
    let backup, newBackup

    if (config.gap < 5) {
      // this number 5 is number of signatures. It is scalable !
      backup = await ulda0.backUpSignatureAssembler(config.backUp)
      newBackup = config.backUp
    } else {
      newBackup = ulda0.backUpBaseGenerator()
      const newBackupToGo = await ulda0.backUpSignatureAssembler(newBackup)
      const iteration = 259 - config.gap // should be checked and validated

      // Validate iteration value
      if (iteration < 0 || iteration > 255) {
        throw new Error(`Invalid iteration value: ${iteration}`)
      }

      const newSignatureForBackup = await ulda0.backupOutPorter(
        config.backUp,
        iteration
      )

      const iterationByteArray = new Uint8Array([iteration]) // getting BackupValidationNumber as byte
      backup = new Uint8Array([
        ...newBackupToGo,
        ...newSignatureForBackup,
        ...iterationByteArray,
      ])
    }

    //Assembler part
    const SignatureForPackage = new Uint8Array([...preparedLine, ...backup]) // this is a full ready signature for the server

    //encryption part
    const newLinePorterWithBackup = new Uint8Array([...newLinePorter, ...newBackup])
    const newFile = await ulda0.newEncContentFile(
      config.jsonOrigin,
      config.password,
      newLinePorterWithBackup
    )

    // return part we say
    return {
      local: {
        // what stays here
        backUp: newBackup, // new backup
        signatures: newLine,
        gap: 1, // not sure that it should be here or we can upcount it from the side of status holder
      },
      global: {
        // what does to server
        signPack: SignatureForPackage, // we need to change the name in order to make sure we do not show that it works via signatures
        textBlock: newFile,
      },
    }
  },

  /**
   * Verifies and parses the structure of a signature byte array.
   *
   * @param {Uint8Array} signature - The signature byte array to check.
   * @returns {Promise<SignatureTypeCheckResponse>} An object with status and parsed structure.
   *
   * This function ensures that a signature conforms to the expected format, extracting its components for validation.
   * It’s used to verify signatures received from the server or during file disassembly.
   */
  signatureTypeCheck: async (
    signature: Uint8Array
  ): Promise<SignatureTypeCheckResponse> => {
    // checker if the signature is correct
    // Check that the minimum required bytes are provided
    if (signature.length < 45) {
      // 1 + 4 + 24 * 1 + 16 minimum required bytes
      return {
        status: false,
        backupStatus: false,
        structure: null,
      }
    }

    // Parsing the signature structure
    const signatureBuffer =
      signature instanceof Uint8Array
        ? signature.buffer
        : new Uint8Array(signature).buffer
    const view = new DataView(signatureBuffer)

    // Reading the size (first byte)
    const size = view.getUint8(0)
    const requiredSignatureBytes = 24 * size

    // Reading 4 bytes (skip them as indicated)
    const iteration = view.getUint32(1) //, true); // true for little-endian

    // Check if there are enough bytes for signatures and backup
    if (signature.length < 1 + 4 + requiredSignatureBytes + 16) {
      return {
        status: false,
        backupStatus: false,
        structure: null,
      }
    }

    // Extracting signatures
    const signatures = signature.slice(5, 5 + requiredSignatureBytes)

    // Extracting 16 bytes of backup
    const backupNormal = signature.slice(
      5 + requiredSignatureBytes,
      5 + requiredSignatureBytes + 16
    )

    // Check for optional 33 bytes
    let backupToUpdate: Uint8Array | null = null
    let backupToUpdateNumber: number | null = null
    const backupStatus =
      signature.length === 5 + requiredSignatureBytes + 16 + 33

    if (backupStatus) {
      backupToUpdate = signature.slice(
        5 + requiredSignatureBytes + 16,
        5 + requiredSignatureBytes + 16 + 32
      )
      backupToUpdateNumber = view.getUint8(5 + requiredSignatureBytes + 16 + 32)
    }

    // Forming the report
    return {
      status: true,
      backupStatus: backupStatus,
      structure: {
        size: size,
        iteration: iteration,
        signature: signatures,
        backupNormal: backupNormal,
        backupToUpdate: backupToUpdate,
        backupToUpdateNumber: backupToUpdateNumber,
        backup: null,
        line: null,
      },
    }
  },

  /**
   * Disassembles a signature byte array into its components, providing metadata and signature line.
   *
   * @param {Uint8Array} signature - The signature byte array to disassemble.
   * @returns {Promise<{ status: boolean; backupStatus: boolean; structure: Structure | null }>} An object with disassembled data.
   *
   * This function extracts the signature line and backup from a byte array, used for verification and reconstruction.
   * It’s critical for processing received signatures and ensuring their integrity.
   */
  decSignatureTypeCheck: async (
    signature: Uint8Array
  ): Promise<{
    status: boolean
    backupStatus: boolean
    structure: Structure | null
  }> => {
    // disassables the line and provides metadata
    // Minimum possible: 1 byte (size) + 4 bytes (itter) + 24 * 1 (one signature) + 32 (backup) = 37
    if (signature.length < 37) {
      return {
        status: false,
        backupStatus: false,
        structure: null,
      }
    }

    const signatureBuffer =
      signature instanceof Uint8Array
        ? signature.buffer
        : new Uint8Array(signature).buffer
    const view = new DataView(signatureBuffer)

    // 1st byte: number of signatures
    const size = view.getUint8(0)
    // Calculation of the number of bytes for signatures
    const requiredSignatureBytes = 24 * size

    // Reading 4 bytes (iteration)
    // By default, it reads in big-endian. If little-endian is needed, set to true
    const iteration = view.getUint32(1, false)

    // Check if there are enough bytes (5 = 1 byte for size + 4 bytes for iteration)
    // + signatures themselves (requiredSignatureBytes)
    // + 32 bytes of backup
    if (signature.length < 5 + requiredSignatureBytes + 32) {
      return {
        status: false,
        backupStatus: false,
        structure: null,
      }
    }

    // Extract signatures as a numbered object
    const line: { [key: number]: Uint8Array } = {}
    const offset = 5 // skip 1 + 4 bytes

    for (let i = 0; i < size; i++) {
      const start = offset + i * 24
      line[iteration + i] = signature.slice(start, start + 24)
    }

    // Extracting 32 bytes of backup
    const backupOffset = offset + requiredSignatureBytes
    const backup = signature.slice(backupOffset, backupOffset + 32)

    // Returning the structure
    return {
      status: true,
      backupStatus: false,
      structure: {
        size,
        iteration,
        line,
        backup,
        signature: null,
        backupNormal: null,
        backupToUpdate: null,
        backupToUpdateNumber: null,
      },
    }
  },

  /**
   * Extracts signature line and backup data from a serialized signature byte array.
   *
   * @param {Uint8Array} signature - The serialized signature byte array.
   * @returns {Promise<{ line: { [key: number]: Uint8Array }; itter: number; backupNormal: Uint8Array; backupToUpdate: Uint8Array | null; backupToUpdateNumber: number | null }>} An object with extracted data.
   *
   * This function deserializes a signature package, reconstructing the signature line and backup components.
   * It’s used to process data received from the server or storage, enabling further operations like verification.
   */
  normalPackExporter: async (
    signature: Uint8Array
  ): Promise<{
    line: { [key: number]: Uint8Array }
    itter: number
    backupNormal: Uint8Array
    backupToUpdate: Uint8Array | null
    backupToUpdateNumber: number | null
  }> => {
    // disassembles the line to ready to use signatures and data
    if (signature.length < 21) {
      // Minimum length: 1 + 4 + 24 * 0 + 16
      throw new Error('Insufficient buffer length for analysis.')
    }

    const signatureBuffer =
      signature instanceof Uint8Array
        ? signature.buffer
        : new Uint8Array(signature).buffer
    const view = new DataView(signatureBuffer)
    const numSignatures = view.getUint8(0)
    const signatureIteration = view.getUint32(1, false) // big-endian
    const expectedLength =
      1 +
      4 +
      numSignatures * 24 +
      16 +
      (signatureBuffer.byteLength >= 1 + 4 + numSignatures * 24 + 16 + 33
        ? 33
        : 0)

    if (signatureBuffer.byteLength !== expectedLength) {
      throw new Error(
        'Incorrect buffer length, does not match the expected number of signatures and backup.'
      )
    }

    const offset = 5 // Skip the first byte and the next 4 bytes
    const line: { [key: number]: Uint8Array } = {}

    for (let i = 0; i < numSignatures; i++) {
      const start = offset + i * 24
      line[signatureIteration + i] = new Uint8Array(
        signatureBuffer.slice(start, start + 24)
      )
    }

    const backupOffset = 5 + numSignatures * 24
    const backupNormal = new Uint8Array(
      signatureBuffer.slice(backupOffset, backupOffset + 16)
    )
    let backupToUpdate: Uint8Array | null = null
    let backupToUpdateNumber: number | null = null

    if (signatureBuffer.byteLength > backupOffset + 16) {
      const backupToUpdateStart = backupOffset + 16
      backupToUpdate = new Uint8Array(
        signatureBuffer.slice(backupToUpdateStart, backupToUpdateStart + 32)
      )
      backupToUpdateNumber = view.getUint8(backupToUpdateStart + 32)
    }

    return {
      line, // Returning the line object with numbered signatures
      itter: signatureIteration,
      backupNormal,
      backupToUpdate,
      backupToUpdateNumber,
    }
  },

  /**
   * Disassembles and decrypts a content file, verifying its integrity with signatures.
   *
   * @param {DisassembleConfig} config - Configuration with content, password, and signatures.
   * @returns {Promise<{ data?: DisassembleResponse; error?: string }>} An object with decrypted data or an error.
   *
   * This function decrypts a content file and verifies its signatures, ensuring authorized access and data integrity.
   * It’s a key component for retrieving and validating stored files, exported for standalone use.
   */
  fileDisassembler: async (
    config: DisassembleConfig
  ): Promise<{ data?: DisassembleResponse; error?: string }> => {
    // gets file and provides json with passwords and metadata
    // som tests here probably
    const testSignature = await ulda0.signatureTypeCheck(config.signatures)
    if (
      !testSignature.status ||
      !testSignature.structure ||
      !testSignature.structure.signature ||
      !config.password?.iv
    ) {
      return { error: 'PASSWORD IS INCORRECT' }
    }

    const signatureLength = testSignature.structure.signature.byteLength + 5 + 32
    const context = await ulda0.decContentFile(
      config.content,
      config.password,
      signatureLength
    )

    // voter part
    const a = await ulda0.normalPackExporter(config.signatures)
    const b = await ulda0.decSignatureTypeCheck(context.signatureBytes)

    if (!b.structure?.line) {
      return { error: 'PASSWORD IS INCORRECT' }
    }

    const pb = await ulda0.generateLinkedHashes(b.structure.line)

    if (!ulda0.objectsEqual(a.line, pb)) {
      return { error: 'PASSWORD IS INCORRECT' }
    }

    //voter is done here

    return {
      data: {
        gap: 1, // Probably needed to be changed
        password: config.password,
        jsonOrigin: context.file,
        signatures: b.structure?.line,
        backUp: b.structure.backup,
        iteration: b.structure.iteration,
        size: b.structure.size,
      },
    }
  },

  /**
   * Compares two objects for equality, specifically designed for signature lines.
   *
   * @param {any} obj1 - The first object to compare.
   * @param {any} obj2 - The second object to compare.
   * @returns {boolean} True if objects are equal, false otherwise.
   *
   * This utility function checks if two signature lines match, used in verification processes to ensure data consistency.
   * It’s crucial for validating decrypted signatures against expected values.
   */
  objectsEqual: (obj1: Record<string, any>, obj2: Record<string, any>) =>
    Object.keys(obj1).length === Object.keys(obj2).length &&
    Object.keys(obj1).every(
      (key) =>
        obj2[key] &&
        obj1[key].length === obj2[key].length &&
        obj1[key].every((v: any, i: string | number) => v === obj2[key][i])
    ),

  /**
   * Generates a new password configuration with random password, IV, and salt.
   *
   * @returns {Promise<{ password: string; iv: string; salt: string }>} An object with generated cryptographic parameters.
   *
   * This function creates secure random values for encrypting content files, ensuring each file has unique parameters.
   * It’s necessary for initializing encryption settings for new content files.
   */
  generateNewPassForContentFile: async () => {
    // generates new password for Content file
    const arrayBufferToBase64 = (buffer: Uint8Array): string => {
      return btoa(
        String.fromCharCode.apply(null, Array.from(new Uint8Array(buffer)))
      )
    }

    const arrayBufferToHex = (buffer: Uint8Array) => {
      return Array.from(new Uint8Array(buffer))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
    }

    // Password generation
    const passwordBuffer = crypto.getRandomValues(new Uint8Array(32)) // 24 байта = 32 символа в base64
    const password = arrayBufferToBase64(passwordBuffer)

    // Generate IV
    const ivBuffer = crypto.getRandomValues(new Uint8Array(16)) // 12 байт для IV
    const iv = arrayBufferToHex(ivBuffer)

    // Generate salt
    const saltBuffer = crypto.getRandomValues(new Uint8Array(32)) // 24 байта = 32 символа в base64
    const salt = arrayBufferToBase64(saltBuffer)

    return {
      password,
      iv,
      salt,
    }
  },

  /**
   * Encrypts a content file using AES-CBC, incorporating signature bytes and a salt.
   *
   * @param {any} file - The file object to encrypt.
   * @param {PasswordConfig} passwordSettings - Configuration with password, IV, and salt.
   * @param {Uint8Array} signatureBytes - The signature bytes to include.
   * @returns {Promise<Uint8Array>} The encrypted byte array.
   *
   * This function secures content files by encrypting them with AES-CBC, adding signature bytes for verification.
   * It’s essential for protecting data sent to the server, ensuring confidentiality and integrity.
   */
  newEncContentFile: async (
    file: any,
    passwordSettings: PasswordConfig,
    signatureBytes: Uint8Array
  ): Promise<Uint8Array> => {
    // encrypts file
    const { password, iv, salt } = passwordSettings

    // Encode the file object to JSON (string) and then to UTF-8 bytes.
    const encoder = new TextEncoder()
    const data = encoder.encode(JSON.stringify(file))

    // Instead of 32 random bytes, now we take your signature (signatureBytes) and
    // assemble new data: [signature + JSON]
    // (If necessary, you can additionally validate/format signatureBytes:
    //  for example, add 1 byte of length or other structure.)
    const newData = new Uint8Array(signatureBytes.length + data.length)
    newData.set(signatureBytes, 0)
    newData.set(data, signatureBytes.length)

    // Create an array to store the result of XOR with the "salt".
    const saltedData = new Uint8Array(newData.length)

    // Prepare the salt in bytes.
    const saltBytes = encoder.encode(salt)

    // Apply XOR between each byte of newData and the salt (modulo the length of the salt).
    for (let i = 0; i < newData.length; i++) {
      saltedData[i] = newData[i] ^ saltBytes[i % saltBytes.length]
    }

    // Convert the password to bytes and trim/pad it to 32 bytes (256 bits).
    const passwordBytes = encoder.encode(password).slice(0, 32)

    // Import the key for AES-CBC.
    const key = await crypto.subtle.importKey(
      'raw',
      passwordBytes, // 256 бит
      { name: 'AES-CBC' },
      false,
      ['encrypt']
    )

    // Convert `iv` (string in hex) to Uint8Array.
    // If you already have `iv` as Uint8Array, use it directly.
    const ivArray = new Uint8Array(
      (iv?.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
    )

    // Encrypt saltedData using AES-CBC
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: 'AES-CBC',
        iv: ivArray,
      },
      key,
      saltedData
    )

    // Returning the encrypted bytes (as Uint8Array).
    return new Uint8Array(encryptedData)
  },

  /**
   * Decrypts a content file using AES-CBC and extracts the file object and signature bytes.
   *
   * @param {Uint8Array} encryptedData - The encrypted byte array.
   * @param {PasswordConfig} passwordSettings - Configuration with password, IV, and salt.
   * @param {number} signatureLength - The length of the signature bytes.
   * @returns {Promise<{ file: any; signatureBytes: Uint8Array }>} An object with decrypted file and signature bytes.
   *
   * This function reverses encryption to access content file data, verifying its integrity with embedded signatures.
   * It’s critical for retrieving and validating stored files.
   */
  decContentFile: async (
    encryptedData: Uint8Array,
    passwordSettings: PasswordConfig,
    signatureLength: number
  ): Promise<{ file: any; signatureBytes: Uint8Array }> => {
    //decrypt any files
    const { password, iv, salt } = passwordSettings

    // Prepare TextEncoder/Decoder for working with text data.
    const encoder = new TextEncoder()
    const decoder = new TextDecoder()

    // Import the password as a key for decryption (AES-CBC).
    const passwordBytes = encoder.encode(password).slice(0, 32)
    const key = await crypto.subtle.importKey(
      'raw',
      passwordBytes,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    )

    // Convert IV (string in hex) to Uint8Array.
    const ivArray = new Uint8Array(
      (iv?.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
    )

    // Perform decryption using AES-CBC.
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: ivArray,
      },
      key,
      encryptedData
    )

    // Convert to Uint8Array for further operations.
    const saltedData = new Uint8Array(decryptedBuffer)

    // Apply reverse XOR with the salt to return the original `[signature + JSON]`.
    const saltBytes = encoder.encode(salt)
    const newData = new Uint8Array(saltedData.length)
    for (let i = 0; i < saltedData.length; i++) {
      newData[i] = saltedData[i] ^ saltBytes[i % saltBytes.length]
    }

    // Now newData = [signature + JSON].
    // Separate the signature and JSON data:
    const signatureBytes = newData.slice(0, signatureLength)
    const fileData = newData.slice(signatureLength)

    // Decode the JSON and parse it back into an object.
    const fileString = decoder.decode(fileData)
    const file = JSON.parse(fileString)

    // Returning the result in a convenient format.
    return {
      file, // the object we passed to newEncContentFile
      signatureBytes, // the same signature that we originally wrote at the beginning
    }
  },

  /**
   * Optimizes a password configuration by deriving a key with PBKDF2 and ensuring IV and salt are present.
   *
   * @param {PasswordConfig} passwordObject - The initial password configuration.
   * @returns {Promise<PasswordConfig>} An optimized configuration with derived key, IV, and salt.
   *
   * This function enhances password security by generating a key using PBKDF2, adding IV and salt if missing.
   * It’s used to prepare passwords for master file encryption, ensuring robust cryptographic protection.
   */
  optimizePassword: async (passwordObject: PasswordConfig) => {
    // makes string password usable for master file
    // Generate or use existing IV in HEX format
    if (!passwordObject.iv) {
      const ivArray = crypto.getRandomValues(new Uint8Array(16))
      passwordObject.iv = Array.from(ivArray, (byte) =>
        byte.toString(16).padStart(2, '0')
      ).join('')
    }

    // Generate or use existing salt in Base64 format
    if (!passwordObject.salt) {
      const saltArray = crypto.getRandomValues(new Uint8Array(16))
      passwordObject.salt = btoa(
        String.fromCharCode.apply(null, Array.from(saltArray))
      )
    }

    // Set default PBKDF2 parameters or use provided ones
    const iterations = passwordObject.passwordConfig
      ? passwordObject.passwordConfig.PBKDF2itter
      : 1000000
    const hash = 'SHA-256' // Can be made configurable if needed

    // Creating a key from the password
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passwordObject.password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits', 'deriveKey']
    )

    // Getting PBKDF2 key
    const key = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: new TextEncoder().encode(atob(passwordObject.salt)),
        iterations: iterations,
        hash: hash,
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    )

    // Export the key to Base64
    const exportedKey = await crypto.subtle.exportKey('raw', key)
    const base64Key = btoa(
      String.fromCharCode.apply(null, Array.from(new Uint8Array(exportedKey)))
    )

    // Return the settings object
    return {
      password: base64Key,
      iv: passwordObject.iv,
      salt: passwordObject.salt,
      passwordConfig: {
        PBKDF2itter: iterations,
        PBKDF2Salt: passwordObject.salt,
      },
    }
  },
}

type MasterFile = {
  id: number
  key: string
  name: string
  signPack: Uint8Array
  textBlock: Uint8Array
  passwordSettings: PasswordConfig
}

type MasterfileServerResponse = {
  data?: MasterFile
  error?: string
}

type CreateMasterFileResponse = {
  status: boolean
  data?: MasterFile
  error?: string
}

export type MasterContent = {
  value: Record<string, any>
  id: number
  name: string
  key: string
}

type ContentFileFunctionality = {
  update: <T extends Object>(updateFileDto: string | T) => Promise<boolean | T>
  delete: () => Promise<{ status: boolean }>
}

export class Ulda {
  private apiKey: string
  data: {
    [key: string | symbol]: ContentFileResponse &
      ContentFileFunctionality & { name: string }
  } = {}
  private masterFile: MasterFile | undefined
  private masterFileData: MasterContent | undefined
  private masterFileFullInfo: (DisassembleResponse & MasterContent) | undefined
  private masterPassword: string | undefined
  private storage: {
    master: Record<number, any>
    content: Record<number, any>
  } = { master: {}, content: {} }
  private contentFiles: ContentFile[] = [] // crypted content File
  private contentFileData: ContentFileResponse[] = [] // encrypted content File
  private contentFileFullInfo: ContentFileData[] = [] // encrypted ContentData white full info

  private socket: Socket

  constructor(apiKey: string, apiUrl: string = "https://api.0am.ch", dev?: boolean) {
    this.apiKey = apiKey
    this.socket = SocketApi.createConnection(apiKey, apiUrl, dev)
  }

  async connect(
    masterFileIdOrName: string | number,
    password: string
  ): Promise<MasterContent | undefined> {
    const { data, error } = await this.getMasterFile(
      typeof masterFileIdOrName === 'string'
        ? { name: masterFileIdOrName, password }
        : { id: masterFileIdOrName, password }
    )
    if (error) {
      throw new Error(error)
    }
    this.masterFileData = data
    this.masterPassword = password
    return data
  }

  getUser() {
    if (this.masterFileData) {
      return this.masterFileData
    }
  }

  async createMasterFile(
    name: string,
    masterPassword: string
  ): Promise<CreateMasterFileResponse> {
    const apiKey = this.apiKey
    let passwordSettings = { password: masterPassword }
    passwordSettings = await ulda0.optimizePassword(passwordSettings)

    const originSignatures = await ulda0.generateSignatures()
    const backupOrigin = ulda0.backUpBaseGenerator()
    const packageConfig = {
      gap: 1,
      password: passwordSettings,
      jsonOrigin: {},
      signatures: originSignatures,
      backUp: backupOrigin,
    }
    const packageToSend = await ulda0.superAssembler(packageConfig)

    return new Promise<CreateMasterFileResponse>((resolve) => {
      const { password, ...passwordConfig } = passwordSettings
      const request = {
        key: `${apiKey}_${name}`,
        name,
        apiKey,
        signPack: packageToSend.global.signPack,
        textBlock: packageToSend.global.textBlock,
        passwordSettings: passwordConfig,
      }
      this.socket.emit(
        'master:init',
        {data: request, apiKey},
        (response: CreateMasterFileResponse) => {
          this.connect(name, masterPassword)
          resolve(response)
        }
      )
    })
  }

  async createContentFile(
    jsonOrigin: Record<string, any>,
    fileName: string
  ): Promise<{
    status: boolean
    error?: string
  }> {
    if (
      this.contentFileData?.find(
        (f) => typeof f.content !== 'string' && f.content.name === fileName
      )
    )
      return { status: false }
    return new Promise(async (resolve, reject) => {
      try {
        const password = await ulda0.generateNewPassForContentFile()
        const signatures = await ulda0.generateSignatures()
        const backUp = ulda0.backUpBaseGenerator()
        const packageConfig = {
          gap: 1,
          password,
          jsonOrigin: { ...jsonOrigin, name: fileName },
          signatures,
          backUp,
        }
        const packageToSend = await ulda0.superAssembler(packageConfig)
        const response = {
          signPack: packageToSend.global.signPack,
          textBlock: packageToSend.global.textBlock,
          createdAt: new Date(),
        }
        this.socket.emit(
          'content:create',
          {
            data: response,
            apiKey: this.apiKey,
          },
          async (id: number) => {
            const master = this.masterFileFullInfo
            if (master) {
              master.jsonOrigin[id] = {
                name: fileName,
                passwordSettings: password,
              }
              if (
                master.password.password &&
                master.signatures &&
                master.backUp &&
                this.masterFileData
              ) {
                await this.updateMasterFile(master.jsonOrigin)
                this.contentFiles.push({
                  ...response,
                  id,
                  masterFileId: this.masterFileData.id,
                })
                this.contentFileData.push({
                  name: fileName,
                  id,
                  content: { ...jsonOrigin, name: fileName },
                })
                this.contentFileFullInfo.push({
                  name: fileName,
                  size: 0,
                  ...packageConfig,
                  jsonOrigin: {
                    ...jsonOrigin,
                    name: fileName,
                  },
                  id,
                  iteration: 1,
                })
                Object.assign(this.storage.content, {
                  [fileName]: {
                    iterationClient: 1,
                    iterationServer: 1,
                    backUp: packageConfig.backUp,
                  },
                })
                this.data[fileName] = {
                  id,
                  name: fileName,
                  content: { ...jsonOrigin, name: fileName },
                  update: async <T extends Object>(
                    updateFile: Record<string, any> | T
                  ) => {
                    Object.assign(updateFile, {
                      name: fileName,
                    })
                    const updateFileDto = mergeObjects(
                      jsonOrigin.content,
                      updateFile
                    )
                    const result = await this.saveContentFile(id, updateFileDto)
                    if (result?.data) {
                      this.data[fileName] = {
                        ...this.data[fileName],
                        name: fileName,
                        content: {
                          ...updateFileDto,
                          name: fileName,
                        },
                      }
                      return true
                    }
                    return false
                  },
                  delete: async () => {
                    const result = await this.deleteContentFile(id)
                    if (result?.status) {
                      delete this.data[fileName]
                      this.contentFiles = this.contentFiles.filter(
                        (file) => file.id === file.id
                      )
                      this.contentFileData = this.contentFileData.filter(
                        (file) => file.id === file.id
                      )
                      this.contentFileFullInfo =
                        this.contentFileFullInfo.filter(
                          (file) => file.id === file.id
                        )
                      return { status: true }
                    }
                    return { status: false }
                  },
                }
                resolve({ status: true })
              }
            }
            reject({ error: 'TODO Error', status: false })
          }
        )
      } catch (error) {
        console.error('[createContentFile] error: ', error)
        reject({ error: 'Error creation content file', status: false })
      }
    })
  }

  async getMasterFile({
                        id,
                        password,
                        name,
                      }: {
    id?: number
    password: string
    name?: string
  }): Promise<{
    data?: MasterContent
    error?: string
  }> {
    return new Promise((resolve, reject) => {
      this.socket.emit(
        'master:getOne',
        { apiKey: this.apiKey, id, name },
        async (masterfileData: MasterfileServerResponse) => {
          if (masterfileData.error) {
            reject({ error: masterfileData.error })
            return
          }

          this.masterFile = masterfileData.data
          if (masterfileData.data) {
            try {
              const masterfile = masterfileData.data
              const passwordSettingsOptimized = await ulda0.optimizePassword({
                ...masterfile.passwordSettings,
                password,
              })
              const config = {
                content: new Uint8Array(masterfile.textBlock),
                password: passwordSettingsOptimized,
                signatures: new Uint8Array(masterfile.signPack),
              }
              const result = await ulda0.fileDisassembler(config)
              if (!result.data) return false
              this.masterFileFullInfo = {
                value: result.data.jsonOrigin,
                id: masterfile.id,
                name: masterfile.name,
                key: masterfile.key,
                ...result.data,
              }

              const contentFiles = (await this.getContentFiles()).data
              if (!contentFiles) return false
              this.data = contentFiles.reduce((acc, file) => {
                Object.assign(acc, {
                  [file.content.name]: {
                    ...file,
                    update: async (
                      updateFile: string | Record<string, any>
                    ) => {
                      let updateFileWithoutName = {}
                      if (
                        typeof updateFile === 'object' &&
                        updateFile !== null
                      ) {
                        const { name, ...rest } = updateFile
                        updateFileWithoutName = rest
                      }
                      const updateFileDto = mergeObjects(
                        file.content,
                        updateFileWithoutName
                      )
                      const result = await this.saveContentFile(
                        file.id,
                        updateFileDto
                      )

                      if (result?.data) {
                        this.data[file.content.name] = {
                          ...this.data[file.content.name],
                          content: updateFileDto,
                        }
                      }
                    },
                    delete: async () => {
                      const result = await this.deleteContentFile(file.id)
                      if (result?.status) {
                        delete this.data[file.content.name]
                        this.contentFiles = this.contentFiles.filter(
                          (file) => file.id === file.id
                        )
                        this.contentFileData = this.contentFileData.filter(
                          (file) => file.id === file.id
                        )
                        this.contentFileFullInfo =
                          this.contentFileFullInfo.filter(
                            (file) => file.id === file.id
                          )
                      }
                    },
                  },
                })
                return acc
              }, {})
              const data = {
                value: this.masterFileFullInfo.jsonOrigin,
                id: this.masterFileFullInfo.id,
                name: this.masterFileFullInfo.name,
                key: this.masterFileFullInfo.key,
              }

              Object.assign(this.storage.master, {
                [masterfile.id]: {
                  iterationClient: result.data?.iteration,
                  iterationServer: result.data?.iteration,
                  backUp: result.data?.backUp,
                },
              })
              resolve({ data })
            } catch (error) {
              console.error('[getMasterFile] fileDisassembler error: ', error)
              reject({ error: 'Error decrypting file' })
            }
          } else {
            resolve({ data: undefined })
          }
        }
      )
    })
  }

  async updateMasterFile(jsonOrigin: Record<string, any>): Promise<{
    data?: DisassembleResponse
    error?: string
  }> {
    if (!this.masterFileFullInfo) return { error: 'Master file not found' }
    if (!this.masterFile?.id) return { error: 'Master file not found' }
    const packageConfig = {
      gap:
        this.storage.master[this.masterFile.id].iterationClient -
        this.storage.master[this.masterFile.id].iterationServer,
      password: this.masterFileFullInfo.password,
      jsonOrigin,
      signatures: this.masterFileFullInfo.signatures!,
      backUp: this.storage.master[this.masterFile.id].backUp,
    }
    const { password, ...passwordToSend } = packageConfig.password
    const packageToSend = await ulda0.superAssembler(packageConfig)
    return new Promise((resolve, reject) => {
      this.socket.emit(
        'master:update',
        {
          masterFile: {
            id: this.masterFileFullInfo?.id,
            name: this.masterFileFullInfo?.name,
            key: this.masterFileFullInfo?.key,
            signPack: packageToSend.global.signPack,
            textBlock: packageToSend.global.textBlock,
            passwordSettings: passwordToSend,
          },
          apiKey: this.apiKey,
        },
        async (props: MasterfileServerResponse) => {
          const { data, error } = props
          if (data) {
            try {
              const config = {
                content: data.textBlock,
                password: {
                  ...data.passwordSettings,
                  password,
                },
                signatures: data.signPack,
              }
              const decryptedData = await ulda0.fileDisassembler(config)
              if (this.masterFileFullInfo) {
                this.storage.master[this.masterFileFullInfo.id] = {
                  iterationClient: decryptedData.data?.iteration,
                  iterationServer: decryptedData.data?.iteration,
                  backUp: decryptedData.data?.backUp,
                }
                resolve(decryptedData)
              }
            } catch (error) {
              reject({ error: 'Error decrypting file' })
            }
          }
          reject({ error: error || 'Unknown Error' })
        }
      )
    })
  }

  async getContentFiles(): Promise<{
    data?: Array<{ id: number; name: string; content: ContentFileResponse }>
    error?: string
  }> {
    if (!this.masterFileFullInfo) {
      console.log('please connect to master file')
      return { data: [] }
    }

    const contentFiles = this.masterFileFullInfo.jsonOrigin
    if (contentFiles) {
      return new Promise((resolve, reject) => {
        this.socket.emit(
          'content:get',
          {
            apiKey: this.apiKey,
            ids: Object.keys(contentFiles),
          },
          async (result: ContentFile[]) => {
            this.contentFiles = result

            const promises = result.map(async (file) => {
              const config = {
                content: file.textBlock,
                password: contentFiles[file.id].passwordSettings,
                signatures: file.signPack,
              }
              const encrypted = await ulda0.fileDisassembler(config)
              Object.assign(this.storage.content, {
                [encrypted.data?.jsonOrigin.name]: {
                  iterationClient: encrypted.data?.iteration,
                  backUp: encrypted.data?.backUp,
                  iterationServer: encrypted.data?.iteration,
                },
              })
              return {
                data: {
                  ...encrypted.data!,
                  id: file.id,
                  name: encrypted.data?.jsonOrigin.name as string,
                },
                error: encrypted.error,
              }
            })

            const allContentFiles = await Promise.all(promises)
            this.contentFileFullInfo = allContentFiles.map((f) => f.data)

            const data = allContentFiles.map((file) => ({
              id: file.data.id,
              content: file.data?.jsonOrigin,
              name: file.data.name,
            }))

            this.contentFileData = data

            if (data) resolve({ data })
            else reject({ error: 'Error' })
          }
        )
      })
    }

    return { data: [] }
  }

  async changeMasterFilePassword(newPassword: string){
    let passwordSettings = { password: newPassword }
    passwordSettings = await ulda0.optimizePassword(passwordSettings)
    if (!this.masterFileFullInfo) return { error: 'Master file not found' }
    if (!this.masterFile?.id) return { error: 'Master file not found' }
    const packageConfig = {
      gap:
        this.storage.master[this.masterFile.id].iterationClient -
        this.storage.master[this.masterFile.id].iterationServer,
      password: passwordSettings,
      jsonOrigin: this.masterFileFullInfo.jsonOrigin,
      signatures: this.masterFileFullInfo.signatures!,
      backUp: this.storage.master[this.masterFile.id].backUp,
    }
    const { password, ...passwordToSend } = packageConfig.password
    const packageToSend = await ulda0.superAssembler(packageConfig)
    return new Promise((resolve, reject) => {
      this.socket.emit(
        'master:update',
        {
          masterFile: {
            id: this.masterFileFullInfo?.id,
            name: this.masterFileFullInfo?.name,
            key: this.masterFileFullInfo?.key,
            signPack: packageToSend.global.signPack,
            textBlock: packageToSend.global.textBlock,
            passwordSettings: passwordToSend,
          },
          apiKey: this.apiKey,
        },
        async (props: MasterfileServerResponse) => {
          const { data, error } = props
          if (data) {
            try {
              const config = {
                content: data.textBlock,
                password: {
                  ...data.passwordSettings,
                  password,
                },
                signatures: data.signPack,
              }
              const decryptedData = await ulda0.fileDisassembler(config)
              if (this.masterFileFullInfo) {
                this.storage.master[this.masterFileFullInfo.id] = {
                  iterationClient: decryptedData.data?.iteration,
                  iterationServer: decryptedData.data?.iteration,
                  backUp: decryptedData.data?.backUp,
                }
                resolve(decryptedData)
              }
            } catch (error) {
              reject({ error: 'Error decrypting file' })
            }
          }
          reject({ error: error || 'Unknown Error' })
        }
      )
    })
  }

  async saveContentFile(
    id: number,
    content: Record<string, any>
  ): Promise<{
    data?: Record<string, unknown>
    error?: string
  }> {
    const fileToUpdate = this.contentFileFullInfo?.find((f) => f.id === id)
    if (
      fileToUpdate &&
      this.masterFile &&
      fileToUpdate.signatures &&
      fileToUpdate.backUp
    ) {
      this.storage.content[fileToUpdate.jsonOrigin.name].iterationClient++
      const packageConfig = {
        gap:
          this.storage.content[fileToUpdate.jsonOrigin.name].iterationClient -
          this.storage.content[fileToUpdate.jsonOrigin.name].iterationServer +
          1,
        password: fileToUpdate.password,
        jsonOrigin: content,
        signatures: fileToUpdate.signatures,
        backUp: fileToUpdate.backUp,
      }
      const packageToSend = await ulda0.superAssembler(packageConfig)
      // const test = await this.simulateBackUp(packageToSend, content, fileToUpdate.password, id);
      return new Promise((resolve, reject) => {
        try {
          this.socket.emit(
            'content:update',
            {
              data: {
                id,
                signPack: packageToSend.global.signPack,
                textBlock: packageToSend.global.textBlock,
              },
              apiKey: this.apiKey,
              masterFileId: this.masterFile?.id,
            },
            async ({ error, data }: { data: ContentFile; error: string }) => {
              if (error) reject({ error })
              resolve({ data: data })
            }
          )
        } catch (error) {
          reject({ error: error || 'Unknown Error' })
        }
      })
    } else {
      return { error: 'File not found, please check name' }
    }
  }

  async simulateBackUp(
    packageToSend: PackageToSend,
    content: Record<string, any>,
    password: PasswordConfig,
    id: number
  ) {
    let data = { ...packageToSend }

    for (let i = 0; i < 100; i++) {
      this.storage.content[id].iterationClient++
      const test = await ulda0.fileDisassembler({
        signatures: data.global.signPack,
        password: password,
        content: data.global.textBlock,
      })
      data = await ulda0.superAssembler({
        gap:
          this.storage.content[id].iterationClient -
          this.storage.content[id].iterationServer +
          1,
        password: test.data?.password!,
        jsonOrigin: content,
        signatures: test.data?.signatures!,
        backUp: this.storage.content[id].backUp,
      })
    }
    return data
  }

  async deleteContentFile(
    id: number
  ): Promise<Promise<{ status: boolean; error?: string }> | undefined> {
    const fileToUpdate = this.contentFileFullInfo?.find((f) => f.id === id)

    if (
      fileToUpdate &&
      this.masterFile &&
      fileToUpdate.signatures &&
      fileToUpdate.backUp
    ) {
      this.storage.content[fileToUpdate.jsonOrigin.name].iterationClient++
      const packageConfig = {
        gap:
          this.storage.content[fileToUpdate.jsonOrigin.name].iterationClient -
          this.storage.content[fileToUpdate.jsonOrigin.name].iterationServer +
          1,
        password: fileToUpdate.password,
        jsonOrigin: {},
        signatures: fileToUpdate.signatures,
        backUp: fileToUpdate.backUp,
      }
      const packageToSend = await ulda0.superAssembler(packageConfig)
      return new Promise((resolve, reject) => {
        this.socket.emit(
          'content:delete',
          {
            contentFile: {
              id,
              signPack: packageToSend.global.signPack,
              textBlock: packageToSend.global.textBlock,
            },
            apiKey: this.apiKey,
            masterFileId: this.masterFile?.id,
          },
          async ({ status, error }: { status: boolean; error: string }) => {
            const master = this.masterFileFullInfo
            if (master) {
              delete master.jsonOrigin[id]
              if (
                master.password.password &&
                master.signatures &&
                master.backUp
              ) {
                await this.updateMasterFile(master.jsonOrigin)
                resolve({ status: true })
              }
              resolve({ status: false })
            }
            if (status) resolve({ status })
            else reject({ error: error || 'Error deleting file' })
          }
        )
      })
    }
  }

  async deleteMasterFile(): Promise<{ status?: boolean; error?: string }> {
    if (!this.masterFileFullInfo) return { error: 'Master file not found' }
    if (!this.masterFile) return { error: 'Master file not found' }
    await Promise.all(
      this.contentFiles.map((file) => this.deleteContentFile(file.id))
    )
    const packageConfig = {
      gap:
        this.storage.master[this.masterFile.id].iterationClient -
        this.storage.master[this.masterFile.id].iterationServer,
      password: this.masterFileFullInfo.password,
      jsonOrigin: {},
      signatures: this.masterFileFullInfo.signatures!,
      backUp: this.storage.master[this.masterFile.id].backUp,
    }
    const { password, ...passwordToSend } = packageConfig.password
    const packageToSend = await ulda0.superAssembler(packageConfig)
    return new Promise((resolve, reject) => {
      this.socket.emit(
        'master:delete',
        {
          masterFile: {
            id: this.masterFileFullInfo?.id,
            name: this.masterFileFullInfo?.name,
            key: this.masterFileFullInfo?.key,
            signPack: packageToSend.global.signPack,
            textBlock: packageToSend.global.textBlock,
            passwordSettings: passwordToSend,
          },
          apiKey: this.apiKey,
        },
        ({ status, error }: { status: boolean; error: string }) => {
          if (status) {
            this.contentFiles = []
            this.contentFileData = []
            this.contentFileFullInfo = []
            this.masterPassword = undefined
            this.masterFile = undefined
            this.masterFileData = undefined
            this.masterFileFullInfo = undefined
            this.data = {}
            this.storage = { master: {}, content: {} }
            resolve({ status })
          } else reject({ error: error || 'Error deleting file' })
        }
      )
    })
  }

  async connectToUpdateContentFile(
    updateFileByWebsocket?: (
      res:
        | ContentFileResponse
        | {
        status: true
      }
    ) => void
  ) {
    const handleActionFunction = async (
      res: ContentFile | { status: boolean }
    ) => {
      if ('status' in res && res.status) {
        return res
      }
      if (!('id' in res)) return {}
      const selectedMasterFile = this.masterFileFullInfo

      if (
        selectedMasterFile &&
        selectedMasterFile.value[res?.id].passwordSettings
      ) {
        const result = await ulda0.fileDisassembler({
          content: res.textBlock,
          password: selectedMasterFile.value[res.id].passwordSettings,
          signatures: res.signPack,
        })

        const data = {
          id: res.id,
          content: result.data?.jsonOrigin,
        }
        this.contentFiles = this.contentFiles.map((file) =>
          file.id === res.id ? res : file
        )
        this.contentFileData = this.contentFileData.map((file) =>
          file.id === res.id
            ? {
              ...data,
              name: data.content.name,
            }
            : file
        )
        this.contentFileFullInfo = this.contentFileFullInfo.map((file) =>
          file.id === res.id ? { ...file, ...result.data } : file
        )
        this.storage.content[result.data?.jsonOrigin.name] = {
          iterationClient: result.data?.iteration,
          iterationServer: result.data?.iteration,
          backUp: result.data?.backUp,
        }
        this.data[result.data?.jsonOrigin.name] = {
          ...this.data[result.data?.jsonOrigin.name],
          content: data.content,
        }
        if (updateFileByWebsocket) {
          return updateFileByWebsocket({
            ...data,
            name: data.content.name,
          })
        }
      }
    }
    this.socket.on('content:update', handleActionFunction)
  }

  async connectToDeleteContentFile(
    updateFileByWebsocket?: (
      res:
        | ContentFileResponse
        | {
        status: true
      }
    ) => void
  ) {
    const handleActionFunction = async (
      res: ContentFile | { status: boolean }
    ) => {
      if ('status' in res && res.status) {
        return res
      }

      if (!('id' in res)) return { status: false }

      const selectedMasterFile = this.masterFileFullInfo
      if (
        selectedMasterFile &&
        selectedMasterFile.value[res.id].passwordSettings &&
        this.masterFile &&
        this.masterPassword
      ) {
        const result = await ulda0.fileDisassembler({
          content: res.textBlock,
          password: selectedMasterFile.value[res.id].passwordSettings,
          signatures: res.signPack,
        })

        this.contentFiles = this.contentFiles.filter(
          (file) => file.id !== res.id
        )
        this.contentFileData = this.contentFileData.filter(
          (file) => file.id !== res.id
        )
        this.contentFileFullInfo = this.contentFileFullInfo.filter(
          (file) => file.id !== res.id
        )
        delete this.storage.content[result.data?.jsonOrigin.name]
        delete this.data[result.data?.jsonOrigin.name]
        await this.connect(this.masterFile.name, this.masterPassword)

        if (updateFileByWebsocket)
          return updateFileByWebsocket({
            id: res.id,
            content: result.data?.jsonOrigin,
            name: result.data?.jsonOrigin.name,
          })
      }
    }
    this.socket?.on('content:delete', handleActionFunction)
  }

  async connectToUpdateMasterFile(
    updateFileByWebsocket?: (
      res:
        | {
        data?: MasterContent | undefined
        error?: string
      }
        | {
        status: boolean
      }
    ) => Promise<void> | void
  ) {
    const handleActionFunction = async (
      res: MasterFile | { status: boolean }
    ) => {
      if ('status' in res && res.status) {
        return res
      }

      if (!('id' in res)) return { status: false }
      if (!this.masterPassword && !this.masterFileFullInfo)
        return { status: false }
      const selectedMasterFile = this.masterFileFullInfo!
      const masterFilePassword = this.masterPassword!
      const masterFile = await this.getMasterFile({
        id: selectedMasterFile?.id,
        password: masterFilePassword,
      })

      await this.connect(selectedMasterFile.id, masterFilePassword)

      if (updateFileByWebsocket) return updateFileByWebsocket(masterFile)
    }
    this.socket?.on('master:update', handleActionFunction)
  }

  async disconnectSocket(event: string, handler: (...args: any[]) => void) {
    SocketApi.instance?.off(event, handler)
  }
}

export function mergeObjects(
  prevObj: Record<string, any>,
  newObj: Record<string, any>
): Record<string, any> {
  const result = { ...prevObj }

  Object.keys(newObj).forEach((key) => {
    if (newObj[key] === null) {
      delete result[key]
    } else if (
      typeof newObj[key] === 'object' &&
      !Array.isArray(newObj[key]) &&
      typeof result[key] === 'object' &&
      !Array.isArray(result[key])
    ) {
      result[key] = mergeObjects(result[key], newObj[key])
    } else {
      result[key] = newObj[key]
    }
  })

  return result
}

