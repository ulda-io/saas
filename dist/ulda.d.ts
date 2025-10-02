type PasswordConfig = {
    password: string;
    iv?: string;
    salt?: string;
    passwordConfig?: {
        PBKDF2Salt: string;
        PBKDF2itter: number;
    };
};
type DisassembleConfig = {
    content: Uint8Array;
    password: PasswordConfig;
    signatures: Uint8Array;
};
type Signatures = {
    [key: number]: Uint8Array;
};
type DisassembleResponse = {
    gap: number;
    password: PasswordConfig;
    jsonOrigin: any;
    signatures?: Signatures;
    backUp: Uint8Array | null;
    iteration: number;
    size: number;
};
type Structure = {
    size: number;
    iteration: number;
    line: Signatures | null;
    signature: Uint8Array | null;
    backupNormal: Uint8Array | null;
    backupToUpdate: Uint8Array | null;
    backupToUpdateNumber: number | null;
    backup: Uint8Array | null;
};
type SignatureTypeCheckResponse = {
    status: boolean;
    backupStatus: boolean;
    structure: Structure | null;
};
type SuperAssemblerConfig = {
    gap: number;
    password: PasswordConfig;
    jsonOrigin: Record<string, unknown>;
    signatures: Signatures;
    backUp: Uint8Array;
};
type LocalPackage = {
    backUp: Uint8Array;
    signatures: Signatures;
    gap: number;
};
type GlobalPackage = {
    signPack: Uint8Array;
    textBlock: Uint8Array;
};
type PackageToSend = {
    local: LocalPackage;
    global: GlobalPackage;
};
export interface ContentFileResponse {
    name: string;
    id: number;
    content: string | Record<string, any>;
}
export declare const ulda0: {
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
    generateSignatures: (signatureCount?: number) => Promise<{
        [key: number]: Uint8Array;
    }>;
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
    stepUpSignaturesUpdate: (array: {
        [key: number]: Uint8Array;
    }) => Promise<{
        [key: number]: Uint8Array;
    }>;
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
    generateLinkedHashes: (line: Signatures) => Promise<{
        [x: number]: Uint8Array;
    }>;
    /**
     * Computes the SHA-256 hash of a byte array using the Web Crypto API.
     *
     * @param {Uint8Array} data - The byte array to hash.
     * @returns {Promise<Uint8Array>} The 32-byte SHA-256 hash.
     *
     * This utility function provides a secure hashing mechanism used across the codebase for integrity checks and signature generation.
     * It’s a fundamental building block for cryptographic operations, ensuring data consistency and security.
     */
    sha256: (data: Uint8Array) => Promise<Uint8Array>;
    /**
     * Calculates the CRC32 checksum of a byte array.
     *
     * @param {Uint8Array} bytes - The byte array to compute the checksum for.
     * @returns {Uint8Array} A 4-byte array representing the CRC32 checksum.
     *
     * This function implements the CRC32 algorithm to provide an additional layer of integrity checking.
     * It’s used in conjunction with SHA-256 hashing to create linked hashes, enhancing the security of signature chains.
     */
    calculateCRC32: (bytes: Uint8Array) => Uint8Array;
    /**
     * Serializes a signature line into a byte array for transport or storage.
     *
     * @param {{ [key: number]: Uint8Array }} line - The signature line to serialize.
     * @returns {Promise<Uint8Array>} The serialized byte array.
     *
     * This function compacts the signature line into a contiguous byte array, prefixed with metadata (size and iteration).
     * It’s necessary for preparing signatures for transmission to the server or storage, ensuring efficient and secure data handling.
     */
    normalPackImporter: (line: {
        [key: number]: Uint8Array;
    }) => Promise<Uint8Array>;
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
    first5Bytes: (signatureIteration: number, lineSize: number) => Uint8Array;
    /**
     * Generates a random byte array as a backup origin.
     *
     * @param {number} [size=32] - The size of the byte array, defaults to 32 bytes.
     * @returns {Uint8Array} A random byte array.
     *
     * This function provides a secure random value used as the foundation for backup signatures.
     * It’s critical for initializing backup data, ensuring that each backup operation starts with a unique base.
     */
    backUpBaseGenerator: (size?: number) => Uint8Array;
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
    mergeSignatures: (array1: Uint8Array, array2: Uint8Array, extraByte: number) => Uint8Array;
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
    backUpSignatureAssembler: (line?: Uint8Array | null, height?: number) => Promise<Uint8Array>;
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
    backupOutPorter: (base: Uint8Array, iter: number) => Promise<Uint8Array>;
    /**
     * Assembles a complete data package for server transmission, including signatures, backup, and encrypted content.
     *
     * @param {SuperAssemblerConfig} config - Configuration with gap, password, jsonOrigin, signatures, and backUp.
     * @returns {Promise<PackageToSend>} An object with local and global package components.
     *
     * This central function orchestrates the creation of a secure package by updating signatures, handling backups,
     * and encrypting content. It’s the primary mechanism for preparing data to be sent to the server securely.
     */
    superAssembler: (config: SuperAssemblerConfig) => Promise<PackageToSend>;
    /**
     * Verifies and parses the structure of a signature byte array.
     *
     * @param {Uint8Array} signature - The signature byte array to check.
     * @returns {Promise<SignatureTypeCheckResponse>} An object with status and parsed structure.
     *
     * This function ensures that a signature conforms to the expected format, extracting its components for validation.
     * It’s used to verify signatures received from the server or during file disassembly.
     */
    signatureTypeCheck: (signature: Uint8Array) => Promise<SignatureTypeCheckResponse>;
    /**
     * Disassembles a signature byte array into its components, providing metadata and signature line.
     *
     * @param {Uint8Array} signature - The signature byte array to disassemble.
     * @returns {Promise<{ status: boolean; backupStatus: boolean; structure: Structure | null }>} An object with disassembled data.
     *
     * This function extracts the signature line and backup from a byte array, used for verification and reconstruction.
     * It’s critical for processing received signatures and ensuring their integrity.
     */
    decSignatureTypeCheck: (signature: Uint8Array) => Promise<{
        status: boolean;
        backupStatus: boolean;
        structure: Structure | null;
    }>;
    /**
     * Extracts signature line and backup data from a serialized signature byte array.
     *
     * @param {Uint8Array} signature - The serialized signature byte array.
     * @returns {Promise<{ line: { [key: number]: Uint8Array }; itter: number; backupNormal: Uint8Array; backupToUpdate: Uint8Array | null; backupToUpdateNumber: number | null }>} An object with extracted data.
     *
     * This function deserializes a signature package, reconstructing the signature line and backup components.
     * It’s used to process data received from the server or storage, enabling further operations like verification.
     */
    normalPackExporter: (signature: Uint8Array) => Promise<{
        line: {
            [key: number]: Uint8Array;
        };
        itter: number;
        backupNormal: Uint8Array;
        backupToUpdate: Uint8Array | null;
        backupToUpdateNumber: number | null;
    }>;
    /**
     * Disassembles and decrypts a content file, verifying its integrity with signatures.
     *
     * @param {DisassembleConfig} config - Configuration with content, password, and signatures.
     * @returns {Promise<{ data?: DisassembleResponse; error?: string }>} An object with decrypted data or an error.
     *
     * This function decrypts a content file and verifies its signatures, ensuring authorized access and data integrity.
     * It’s a key component for retrieving and validating stored files, exported for standalone use.
     */
    fileDisassembler: (config: DisassembleConfig) => Promise<{
        data?: DisassembleResponse;
        error?: string;
    }>;
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
    objectsEqual: (obj1: Record<string, any>, obj2: Record<string, any>) => boolean;
    /**
     * Generates a new password configuration with random password, IV, and salt.
     *
     * @returns {Promise<{ password: string; iv: string; salt: string }>} An object with generated cryptographic parameters.
     *
     * This function creates secure random values for encrypting content files, ensuring each file has unique parameters.
     * It’s necessary for initializing encryption settings for new content files.
     */
    generateNewPassForContentFile: () => Promise<{
        password: string;
        iv: string;
        salt: string;
    }>;
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
    newEncContentFile: (file: any, passwordSettings: PasswordConfig, signatureBytes: Uint8Array) => Promise<Uint8Array>;
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
    decContentFile: (encryptedData: Uint8Array, passwordSettings: PasswordConfig, signatureLength: number) => Promise<{
        file: any;
        signatureBytes: Uint8Array;
    }>;
    /**
     * Optimizes a password configuration by deriving a key with PBKDF2 and ensuring IV and salt are present.
     *
     * @param {PasswordConfig} passwordObject - The initial password configuration.
     * @returns {Promise<PasswordConfig>} An optimized configuration with derived key, IV, and salt.
     *
     * This function enhances password security by generating a key using PBKDF2, adding IV and salt if missing.
     * It’s used to prepare passwords for master file encryption, ensuring robust cryptographic protection.
     */
    optimizePassword: (passwordObject: PasswordConfig) => Promise<{
        password: string;
        iv: string;
        salt: string;
        passwordConfig: {
            PBKDF2itter: number;
            PBKDF2Salt: string;
        };
    }>;
};
type MasterFile = {
    id: number;
    key: string;
    name: string;
    signPack: Uint8Array;
    textBlock: Uint8Array;
    passwordSettings: PasswordConfig;
};
type CreateMasterFileResponse = {
    status: boolean;
    data?: MasterFile;
    error?: string;
};
export type MasterContent = {
    value: Record<string, any>;
    id: number;
    name: string;
    key: string;
};
type ContentFileFunctionality = {
    update: <T extends Object>(updateFileDto: string | T) => Promise<boolean | T>;
    delete: () => Promise<{
        status: boolean;
    }>;
};
export declare class Ulda {
    private apiKey;
    data: {
        [key: string | symbol]: ContentFileResponse & ContentFileFunctionality & {
            name: string;
        };
    };
    private masterFile;
    private masterFileData;
    private masterFileFullInfo;
    private masterPassword;
    private storage;
    private contentFiles;
    private contentFileData;
    private contentFileFullInfo;
    private socket;
    constructor(apiKey: string, apiUrl?: string, dev?: boolean);
    connect(masterFileIdOrName: string | number, password: string): Promise<MasterContent | undefined>;
    getUser(): MasterContent | undefined;
    createMasterFile(name: string, masterPassword: string): Promise<CreateMasterFileResponse>;
    createContentFile(jsonOrigin: Record<string, any>, fileName: string): Promise<{
        status: boolean;
        error?: string;
    }>;
    getMasterFile({ id, password, name, }: {
        id?: number;
        password: string;
        name?: string;
    }): Promise<{
        data?: MasterContent;
        error?: string;
    }>;
    updateMasterFile(jsonOrigin: Record<string, any>): Promise<{
        data?: DisassembleResponse;
        error?: string;
    }>;
    getContentFiles(): Promise<{
        data?: Array<{
            id: number;
            name: string;
            content: ContentFileResponse;
        }>;
        error?: string;
    }>;
    changeMasterFilePassword(newPassword: string): Promise<unknown>;
    saveContentFile(id: number, content: Record<string, any>): Promise<{
        data?: Record<string, unknown>;
        error?: string;
    }>;
    simulateBackUp(packageToSend: PackageToSend, content: Record<string, any>, password: PasswordConfig, id: number): Promise<{
        local: LocalPackage;
        global: GlobalPackage;
    }>;
    deleteContentFile(id: number): Promise<Promise<{
        status: boolean;
        error?: string;
    }> | undefined>;
    deleteMasterFile(): Promise<{
        status?: boolean;
        error?: string;
    }>;
    connectToUpdateContentFile(updateFileByWebsocket?: (res: ContentFileResponse | {
        status: true;
    }) => void): Promise<void>;
    connectToDeleteContentFile(updateFileByWebsocket?: (res: ContentFileResponse | {
        status: true;
    }) => void): Promise<void>;
    connectToUpdateMasterFile(updateFileByWebsocket?: (res: {
        data?: MasterContent | undefined;
        error?: string;
    } | {
        status: boolean;
    }) => Promise<void> | void): Promise<void>;
    disconnectSocket(event: string, handler: (...args: any[]) => void): Promise<void>;
}
export declare function mergeObjects(prevObj: Record<string, any>, newObj: Record<string, any>): Record<string, any>;
export {};
