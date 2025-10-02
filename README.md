# ULDA Library Documentation

## Overview

The ulda library is a JavaScript/TypeScript tool for secure data management, focusing on encrypted file handling and cryptographic signatures. It leverages WebSockets for real-time server communication, ensuring synchronized data across clients. The library supports TypeScript for type safety and includes socket.io-client as a dependency for seamless WebSocket integration. Key features include:

- Secure master and content file management with encryption (AES-CBC) and PBKDF2 key derivation.
- Cryptographic signature generation and verification for data integrity.
- Real-time updates via WebSocket listeners.
- The ulda.data object for intuitive content file access and manipulation.

This documentation provides detailed instructions on installation, usage, and methods, with extensive examples to demonstrate practical applications.

## Installation

Install the ulda library via npm:

```bash
npm install @zeroam/ulda
```

The socket.io-client dependency is automatically included, enabling WebSocket communication without additional setup (Socket.IO Client).

## Getting Started

Initialize the Ulda class with an API key to authenticate server operations:

```javascript
import { Ulda } from '@zeroam/ulda';

const apiKey = 'your-api-key';
const ulda = new Ulda(apiKey);
```

Connect to a master file using its name or ID and a password:

```javascript
const masterFileName = 'myMasterFile';
const password = 'mySecurePassword';
await ulda.connect(masterFileName, password);
```

After connecting, use the ulda.data object to manage content files, create new files, and set up real-time event listeners.

## Working with ulda.data

The ulda.data object is a dynamic map where keys are content file names, and values are objects containing file details and methods for manipulation. It simplifies accessing, updating, and deleting content files.

### Structure of ulda.data

Each entry in ulda.data has:

- **id**: Unique file identifier (number).
- **name**: File name (string).
- **content**: File data (string or Record<string, any>).
- **update(newData: Record<string, any>)**: Async method to update file content.
- **delete()**: Async method to delete the file.

### Example: Accessing a File

```javascript
console.log(ulda.data['myFile'].id); // Outputs: 123
console.log(ulda.data['myFile'].content); // Outputs: { key: 'value', name: 'myFile' }
```

### Updating Content Files

The update method merges new data with existing content, adding new fields, updating existing ones, or removing fields set to null. It ensures atomic updates and maintains data integrity.

**Syntax:**

```
await ulda.data[name].update(newData: Record<string, any>): Promise<boolean>
```

**Behavior:**

- Adds new fields from newData.
- Updates existing fields with new values.
- Removes fields if their value is null.
- Returns true on success, false on failure.

**Example: Updating a File**

```javascript
// Initial content: { user: 'Alice', role: 'admin' }
await ulda.data['userProfile'].update({ role: 'editor', email: 'alice@example.com' });
// New content: { user: 'Alice', role: 'editor', email: 'alice@example.com' }

await ulda.data['userProfile'].update({ email: null });
// New content: { user: 'Alice', role: 'editor' }
```

### Deleting Content Files

The delete method removes a content file from the server and ulda.data, ensuring it's no longer accessible.

**Syntax:**

```
await ulda.data[name].delete(): Promise<{ status: boolean }>
```

**Behavior:**

- Sends a deletion request to the server.
- Removes the file from ulda.data on success.
- Returns { status: true } on success, { status: false } on failure.

**Example: Deleting a File**

```javascript
const result = await ulda.data['userProfile'].delete();
if (result.status) {
  console.log('File deleted successfully');
} else {
  console.log('Failed to delete file');
}
```

### Iterating Over Content Files

Use Object.entries, Object.keys, or Object.values to iterate over ulda.data for batch operations or listing files.

**Example: Listing All Files**

```javascript
for (const [name, file] of Object.entries(ulda.data)) {
  console.log(`File: ${name}, ID: ${file.id}, Content:`, file.content);
}
```

### Error Handling

Always verify a file exists before operations and handle errors with try-catch blocks to manage network issues, invalid data, or server errors.

**Example: Safe Update**

```javascript
try {
  if (ulda.data['myFile']) {
    const result = await ulda.data['myFile'].update({ key: 'newValue' });
    console.log(result ? 'Update successful' : 'Update failed');
  } else {
    console.log('File not found');
  }
} catch (error) {
  console.error('Error updating file:', error.message);
}
```

## Methods

### Ulda Class Methods

These methods manage master and content files, providing core functionality:

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| connect(masterFileIdOrName: string \| number, password: string) | Connects to a master file. | masterFileIdOrName: ID or name<br>password: Password | Promise<MasterContent \| undefined> |
| createMasterFile(name: string, masterPassword: string) | Creates a new master file. | name: File name<br>masterPassword: Password | Promise<CreateMasterFileResponse> |
| createContentFile(jsonOrigin: Record<string, any>, fileName: string) | Creates a content file. | jsonOrigin: Data<br>fileName: Name | Promise<{ status: boolean; error?: string }> |
| getMasterFile({ id?: number; password: string; name?: string }) | Retrieves master file data. | id: ID (optional)<br>password: Password<br>name: Name (optional) | Promise<{ data?: MasterContent; error?: string }> |
| updateMasterFile(jsonOrigin: Record<string, any>) | Updates master file data. | jsonOrigin: New data | Promise<{ data?: DisassembleResponse; error?: string }> |
| getContentFiles() | Retrieves all content files. | None | Promise<{ data?: Array<{ id: number; name: string; content: ContentFileResponse }>; error?: string }> |
| saveContentFile(id: number, content: Record<string, any>) | Updates a content file by ID. | id: File ID<br>content: New data | Promise<{ data?: Record<string, unknown>; error?: string }> |
| deleteContentFile(id: number) | Deletes a content file by ID. | id: File ID | Promise<{ status: boolean; error?: string }> |
| deleteMasterFile() | Deletes the master file and all content files. | None | Promise<{ status?: boolean; error?: string }> |

### Real-time Update Methods

These methods configure WebSocket listeners for real-time updates:

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| connectToUpdateContentFile(updateFileByWebsocket?: (res: ContentFileResponse \| { status: true }) => void) | Listens for content file updates. | updateFileByWebsocket: Callback (optional) | Promise<void> |
| connectToDeleteContentFile(updateFileByWebsocket?: (res: ContentFileResponse \| { status: true }) => void) | Listens for content file deletions. | updateFileByWebsocket: Callback (optional) | Promise<void> |
| connectToUpdateMasterFile(updateFileByWebsocket?: (res: { data?: MasterContent \| undefined; error?: string } \| { status: boolean }) => Promise<void> \| void) | Listens for master file updates. | updateFileByWebsocket: Callback (optional) | Promise<void> |
| disconnectSocket(event: string, handler: (...args: any[]) => void) | Removes a WebSocket listener. | event: Event name<br>handler: Callback function | Promise<void> |

### ulda0 Methods

The ulda0 object provides cryptographic utilities for advanced use cases, used internally by Ulda. These methods handle signature generation, hashing, encryption, and more:

| Method | Description | Parameters | Returns |
|--------|-------------|------------|---------|
| generateSignatures(signatureCount?: number) | Generates random signatures (Web Crypto API). | signatureCount: Number of signatures (default: 5) | Promise<{ [key: number]: Uint8Array }> |
| stepUpSignaturesUpdate(array: { [key: number]: Uint8Array }) | Updates signature array by removing oldest and adding new. | array: Signatures | Promise<{ [key: number]: Uint8Array }> |
| generateLinkedHashes(line: Signatures) | Creates linked hash chain. | line: Signature line | Promise<{ [key: number]: Uint8Array }> |
| sha256(data: Uint8Array) | Computes SHA-256 hash (SHA-256). | data: Byte array | Promise<Uint8Array> |
| calculateCRC32(bytes: Uint8Array) | Calculates CRC32 checksum. | bytes: Byte array | Uint8Array |
| normalPackImporter(line: { [key: number]: Uint8Array }) | Serializes signature line. | line: Signature line | Promise<Uint8Array> |
| first5Bytes(signatureIteration: number, lineSize: number) | Encodes metadata into 5 bytes. | signatureIteration: Iteration<br>lineSize: Signature count | Uint8Array |
| backUpBaseGenerator(size?: number) | Generates random backup bytes. | size: Byte size (default: 32) | Uint8Array |
| mergeSignatures(array1: Uint8Array, array2: Uint8Array, extraByte: number) | Merges arrays with XOR. | array1, array2: 32-byte arrays<br>extraByte: Byte | Uint8Array |
| backUpSignatureAssembler(line?: Uint8Array \| null, height?: number) | Assembles backup signature. | line: Base bytes (optional)<br>height: Iterations (default: 254) | Promise<Uint8Array> |
| backupOutPorter(base: Uint8Array, iter: number) | Hashes backup for transmission. | base: Byte array<br>iter: Iterations | Promise<Uint8Array> |
| superAssembler(config: SuperAssemblerConfig) | Assembles data package. | config: Configuration | Promise<PackageToSend> |
| signatureTypeCheck(signature: Uint8Array) | Verifies signature structure. | signature: Byte array | Promise<SignatureTypeCheckResponse> |
| decSignatureTypeCheck(signature: Uint8Array) | Disassembles signature. | signature: Byte array | Promise<{ status: boolean; backupStatus: boolean; structure: Structure \| null }> |
| normalPackExporter(signature: Uint8Array) | Deserializes signature. | signature: Byte array | Promise<{ line: { [key: number]: Uint8Array }; itter: number; backupNormal: Uint8Array; backupToUpdate: Uint8Array \| null; backupToUpdateNumber: number \| null }> |
| fileDisassembler(config: DisassembleConfig) | Decrypts and verifies file. | config: Content, password, signatures | Promise<{ data?: DisassembleResponse; error?: string }> |
| objectsEqual(obj1: Record<string, any>, obj2: Record<string, any>) | Compares objects for equality. | obj1, obj2: Objects | boolean |
| generateNewPassForContentFile() | Generates password config. | None | Promise<{ password: string; iv: string; salt: string }> |
| newEncContentFile(file: any, passwordSettings: PasswordConfig, signatureBytes: Uint8Array) | Encrypts file with AES-CBC. | file: Data<br>passwordSettings: Config<br>signatureBytes: Signatures | Promise<Uint8Array> |
| decContentFile(encryptedData: Uint8Array, passwordSettings: PasswordConfig, signatureLength: number) | Decrypts file. | encryptedData: Bytes<br>passwordSettings: Config<br>signatureLength: Length | Promise<{ file: any; signatureBytes: Uint8Array }> |
| optimizePassword(passwordObject: PasswordConfig) | Derives key with PBKDF2 (PBKDF2). | passwordObject: Config | Promise<PasswordConfig> |

## Socket Communication

The ulda library uses WebSockets for real-time updates, ensuring immediate synchronization with server changes. Listeners can be set up for events like content file updates or deletions, enhancing responsiveness. A stable internet connection is recommended for reliable operation.

**Example: Setting Up a Listener**

```javascript
await ulda.connectToUpdateContentFile((response) => {
  console.log('Content file updated:', response);
});
```

## Example Usage

### Example 1: Managing a User Profile

This example creates a master file, adds a user profile as a content file, updates it, and sets up real-time updates.

```javascript
import { Ulda } from 'ulda';

async function manageUserProfile() {
  const ulda = new Ulda('api-key-123');

  // Create a master file
  const masterFileName = 'userVault';
  const password = 'securePass123';
  await ulda.createMasterFile(masterFileName, password);
  await ulda.connect(masterFileName, password);

  // Create a content file for user profile
  const profileData = { username: 'Bob', email: 'bob@example.com' };
  await ulda.createContentFile(profileData, 'bobProfile');
  console.log('Profile created:', ulda.data['bobProfile'].content);

  // Update user profile
  await ulda.data['bobProfile'].update({ email: 'bob.new@example.com', role: 'user' });
  console.log('Updated profile:', ulda.data['bobProfile'].content);

  // Set up real-time updates
  await ulda.connectToUpdateContentFile((response) => {
    console.log('Profile updated in real-time:', response);
  });
}

manageUserProfile().catch(console.error);
```

### Example 2: Batch Operations on Content Files

This example demonstrates creating multiple content files, iterating over them, and performing batch updates.

```javascript
import { Ulda } from 'ulda';

async function batchOperations() {
  const ulda = new Ulda('api-key-456');
  await ulda.connect('dataStore', 'pass456');

  // Create multiple content files
  const files = [
    { name: 'file1', data: { value: 10 } },
    { name: 'file2', data: { value: 20 } },
  ];
  for (const { name, data } of files) {
    await ulda.createContentFile(data, name);
  }

  // List all files
  console.log('All files:');
  for (const [name, file] of Object.entries(ulda.data)) {
    console.log(`File: ${name}, Content:`, file.content);
  }

  // Batch update: increment all values
  for (const name of Object.keys(ulda.data)) {
    const currentValue = ulda.data[name].content.value;
    await ulda.data[name].update({ value: currentValue + 5 });
  }

  console.log('After batch update:');
  for (const [name, file] of Object.entries(ulda.data)) {
    console.log(`File: ${name}, Content:`, file.content);
  }
}

batchOperations().catch(console.error);
```

### Example 3: Advanced Cryptographic Operations

This example uses ulda0 methods to generate and verify signatures for custom cryptographic tasks.

```javascript
import { ulda0 } from 'ulda';

async function customCrypto() {
  // Generate signatures
  const signatures = await ulda0.generateSignatures(3);
  console.log('Generated signatures:', signatures);

  // Update signatures
  const updatedSignatures = await ulda0.stepUpSignaturesUpdate(signatures);
  console.log('Updated signatures:', updatedSignatures);

  // Create linked hashes
  const linkedHashes = await ulda0.generateLinkedHashes(updatedSignatures);
  console.log('Linked hashes:', linkedHashes);

  // Serialize for transport
  const serialized = await ulda0.normalPackImporter(linkedHashes);
  console.log('Serialized package:', serialized);

  // Verify signature structure
  const check = await ulda0.signatureTypeCheck(serialized);
  console.log('Signature check:', check);
}

customCrypto().catch(console.error);
```

### Example 4: Full Lifecycle with Deletion

This example covers creating, updating, and deleting both master and content files, with error handling.

```javascript
import { Ulda } from 'ulda';

async function fullLifecycle() {
  const ulda = new Ulda('api-key-789');
  const masterFileName = 'tempVault';
  const password = 'tempPass789';

  try {
    // Create and connect to master file
    await ulda.createMasterFile(masterFileName, password);
    await ulda.connect(masterFileName, password);

    // Create content file
    const data = { note: 'Temporary note' };
    await ulda.createContentFile(data, 'tempNote');
    console.log('Created note:', ulda.data['tempNote'].content);

    // Update content file
    await ulda.data['tempNote'].update({ note: 'Updated note', priority: 'high' });
    console.log('Updated note:', ulda.data['tempNote'].content);

    // Delete content file
    const deleteResult = await ulda.data['tempNote'].delete();
    console.log('Delete note:', deleteResult.status ? 'Success' : 'Failed');

    // Delete master file
    const masterDeleteResult = await ulda.deleteMasterFile();
    console.log('Delete master:', masterDeleteResult.status ? 'Success' : 'Failed');
  } catch (error) {
    console.error('Error:', error.message);
  }
}

fullLifecycle().catch(console.error);
```

## Security Considerations

- **Key Management**: Store API keys and passwords in environment variables or secure vaults, never in source code.
- **Authentication**: Ensure robust authentication mechanisms to prevent unauthorized access.
- **Encryption**: The library uses AES-CBC and PBKDF2 for secure encryption, but proper key handling is critical (Web Crypto API Security).
- **Network**: Use HTTPS for server communication to protect data in transit.
- **Error Handling**: Implement comprehensive error handling to manage server or network failures gracefully.
