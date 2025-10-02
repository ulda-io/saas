import io, { Socket } from 'socket.io-client'

export class SocketApi {
  static instance?: Socket

  static createConnection(key: string, serverUrl: string, dev?: boolean): Socket {
    const socket = io(serverUrl, {
      query: {
        key,
      },
    })

    socket.on('connect', () => {
      this.instance = socket
    })

    socket.on('disconnect', () => {
      this.instance = undefined
    })

    if (dev) {
      socket.onAny((event, ...args) => {
        console.log('ANY: ', {
          socket: socket.id,
          event,
          args,
          instance: SocketApi.instance,
        })
      })
    }

    return socket
  }
}
