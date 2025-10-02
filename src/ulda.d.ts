import {Socket} from 'socket.io-client';

interface PasswordConfig {
  password: string;
  iv?: string;
  salt?: string;
  passwordConfig?: {
    PBKDF2Salt: string;
    PBKDF2itter: number;
  };
}

interface DisassembleConfig {
  content: Uint8Array;
  password: PasswordConfig;
  signatures: Uint8Array;
}

interface Signatures {
  [key: number]: Uint8Array;
}

interface DisassembleResponse {
  gap: number;
  password: PasswordConfig;
  jsonOrigin: any;
  signatures?: Signatures;
  backUp: Uint8Array | null;
  iteration: number;
  size: number;
}

interface Structure {
  size: number;
  iteration: number;
  line: Signatures | null;
  signature: Uint8Array | null;
  backupNormal: Uint8Array | null;
  backupToUpdate: Uint8Array | null;
  backupToUpdateNumber: number | null;
  backup: Uint8Array | null;
}

interface SignatureTypeCheckResponse {
  status: boolean;
  backupStatus: boolean;
  structure: Structure | null;
}

interface SuperAssemblerConfig {
  gap: number;
  password: PasswordConfig;
  jsonOrigin: Record<string, unknown>;
  signatures: Signatures;
  backUp: Uint8Array;
}

interface LocalPackage {
  backUp: Uint8Array;
  signatures: Signatures;
  gap: number;
}

interface GlobalPackage {
  signPack: Uint8Array;
  textBlock: Uint8Array;
}

interface PackageToSend {
  local: LocalPackage;
  global: GlobalPackage;
}

interface ContentFile {
  id: number;
  signPack: Uint8Array;
  textBlock: Uint8Array;
  masterFileId: number;
  createdAt: Date;
}

interface ContentFileResponse {
  name: string;
  id: number;
  content: string | Record<string, any>;
}

interface ContentFileData extends DisassembleResponse {
  id: number;
  name: string;
}

interface MasterFile {
  id: number;
  key: string;
  name: string;
  signPack: Uint8Array;
  textBlock: Uint8Array;
  passwordSettings: PasswordConfig;
}

interface MasterfileServerResponse {
  data?: MasterFile;
  error?: string;
}

interface CreateMasterFileResponse {
  status: boolean;
  data?: MasterFile;
  error?: string;
}

interface MasterContent {
  value: Record<string, any>;
  id: number;
  name: string;
  key: string;
}

interface ContentFileFunctionality {
  update: <T extends Object>(updateFileDto: string | T) => Promise<boolean | T>;
  delete: () => Promise<{ status: boolean }>;
}

export declare const ulda0: {
  generateSignatures: (signatureCount?: number) => Promise<{ [key: number]: Uint8Array }>;
  stepUpSignaturesUpdate: (array: { [key: number]: Uint8Array }) => Promise<{ [key: number]: Uint8Array }>;
  generateLinkedHashes: (line: Signatures) => Promise<{ [key: number]: Uint8Array }>;
  sha256: (data: Uint8Array) => Promise<Uint8Array>;
  calculateCRC32: (bytes: Uint8Array) => Uint8Array;
  normalPackImporter: (line: { [key: number]: Uint8Array }) => Promise<Uint8Array>;
  first5Bytes: (signatureIteration: number, lineSize: number) => Uint8Array;
  backUpBaseGenerator: (size?: number) => Uint8Array;
  mergeSignatures: (array1: Uint8Array, array2: Uint8Array, extraByte: number) => Uint8Array;
  backUpSignatureAssembler: (line?: Uint8Array | null, height?: number) => Promise<Uint8Array>;
  backupOutPorter: (base: Uint8Array, iter: number) => Promise<Uint8Array>;
  superAssembler: (config: SuperAssemblerConfig) => Promise<PackageToSend>;
  signatureTypeCheck: (signature: Uint8Array) => Promise<SignatureTypeCheckResponse>;
  decSignatureTypeCheck: (signature: Uint8Array) => Promise<{
    status: boolean;
    backupStatus: boolean;
    structure: Structure | null;
  }>;
  normalPackExporter: (signature: Uint8Array) => Promise<{
    line: { [key: number]: Uint8Array };
    itter: number;
    backupNormal: Uint8Array;
    backupToUpdate: Uint8Array | null;
    backupToUpdateNumber: number | null;
  }>;
  fileDisassembler: (config: DisassembleConfig) => Promise<{
    data?: DisassembleResponse;
    error?: string;
  }>;
  objectsEqual: (obj1: Record<string, any>, obj2: Record<string, any>) => boolean;
  generateNewPassForContentFile: () => Promise<{
    password: string;
    iv: string;
    salt: string;
  }>;
  newEncContentFile: (file: any, passwordSettings: PasswordConfig, signatureBytes: Uint8Array) => Promise<Uint8Array>;
  decContentFile: (encryptedData: Uint8Array, passwordSettings: PasswordConfig, signatureLength: number) => Promise<{
    file: any;
    signatureBytes: Uint8Array;
  }>;
  optimizePassword: (passwordObject: PasswordConfig) => Promise<PasswordConfig>;
};

export declare class Ulda {
  private apiKey: string;
  data: {
    [key: string | symbol]: ContentFileResponse & ContentFileFunctionality & { name: string };
  };
  private masterFile: MasterFile | undefined;
  private masterFileData: MasterContent | undefined;
  private masterFileFullInfo: (DisassembleResponse & MasterContent) | undefined;
  private masterPassword: string | undefined;
  private storage: {
    master: Record<number, any>;
    content: Record<number, any>;
  };
  private contentFiles: ContentFile[];
  private contentFileData: ContentFileResponse[];
  private contentFileFullInfo: ContentFileData[];
  private socket: Socket;

  constructor(apiKey: string, apiUrl: string = "https://api.0am.ch", dev?: boolean);

  connect(masterFileIdOrName: string | number, password: string): Promise<MasterContent | undefined>;

  getUser(): MasterContent | undefined;

  createMasterFile(name: string, masterPassword: string): Promise<CreateMasterFileResponse>;

  createContentFile(jsonOrigin: Record<string, any>, fileName: string): Promise<{
    status: boolean;
    error?: string;
  }>;

  getMasterFile({id, password, name}: { id?: number; password: string; name?: string }): Promise<{
    data?: MasterContent;
    error?: string;
  }>;

  updateMasterFile(jsonOrigin: Record<string, any>): Promise<{
    data?: DisassembleResponse;
    error?: string;
  }>;

  getContentFiles(): Promise<{
    data?: Array<{ id: number; name: string; content: ContentFileResponse }>;
    error?: string;
  }>;

  saveContentFile(id: number, content: Record<string, any>): Promise<{
    data?: Record<string, unknown>;
    error?: string;
  }>;

  simulateBackUp(packageToSend: PackageToSend, content: Record<string, any>, password: PasswordConfig, id: number): Promise<PackageToSend>;

  deleteContentFile(id: number): Promise<{ status: boolean; error?: string } | undefined>;

  deleteMasterFile(): Promise<{ status?: boolean; error?: string }>;

  connectToUpdateContentFile(updateFileByWebsocket?: (res: ContentFileResponse | {
    status: true
  }) => void): Promise<void>;

  connectToDeleteContentFile(updateFileByWebsocket?: (res: ContentFileResponse | {
    status: true
  }) => void): Promise<void>;

  connectToUpdateMasterFile(updateFileByWebsocket?: (res: { data?: MasterContent; error?: string } | {
    status: boolean
  }) => Promise<void> | void): Promise<void>;

  disconnectSocket(event: string, handler: (...args: any[]) => void): Promise<void>;
}

export declare function mergeObjects(prevObj: Record<string, any>, newObj: Record<string, any>): Record<string, any>;
