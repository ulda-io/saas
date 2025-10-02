import { Socket } from 'socket.io-client';
export declare class SocketApi {
    static instance?: Socket;
    static createConnection(key: string, serverUrl: string, dev?: boolean): Socket;
}
