// PCAP file format writer
// Implements the PCAP file format specification for packet capture files

export class PcapWriter {
  constructor() {
    this.packets = []
    this.snaplen = 65535 // Maximum bytes per packet
    this.network = 1 // Ethernet
  }

  // Write PCAP global header
  writeGlobalHeader() {
    const buffer = Buffer.alloc(24)
    buffer.writeUInt32LE(0xa1b2c3d4, 0)  // Magic number
    buffer.writeUInt16LE(2, 4)           // Major version
    buffer.writeUInt16LE(4, 6)           // Minor version
    buffer.writeInt32LE(0, 8)            // Timezone (GMT)
    buffer.writeUInt32LE(0, 12)          // Timestamp accuracy
    buffer.writeUInt32LE(this.snaplen, 16) // Snapshot length
    buffer.writeUInt32LE(this.network, 20) // Network type
    return buffer
  }

  // Write PCAP packet header
  writePacketHeader(timestamp, packetLength) {
    const buffer = Buffer.alloc(16)
    const seconds = Math.floor(timestamp / 1000)
    const microseconds = (timestamp % 1000) * 1000
    
    buffer.writeUInt32LE(seconds, 0)           // Timestamp seconds
    buffer.writeUInt32LE(microseconds, 4)      // Timestamp microseconds
    buffer.writeUInt32LE(packetLength, 8)      // Captured length
    buffer.writeUInt32LE(packetLength, 12)     // Original length
    return buffer
  }

  addPacket(timestamp, packetData) {
    this.packets.push({ timestamp, data: packetData })
  }

  build() {
    const buffers = [this.writeGlobalHeader()]
    
    for (const packet of this.packets) {
      buffers.push(this.writePacketHeader(packet.timestamp, packet.data.length))
      buffers.push(packet.data)
    }
    
    return Buffer.concat(buffers)
  }
}

// Ethernet frame builder
export class EthernetFrame {
  static build(srcMac, dstMac, etherType, payload) {
    const frame = Buffer.alloc(14 + payload.length)
    
    // Destination MAC (6 bytes)
    const dstMacBytes = dstMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) frame[i] = dstMacBytes[i]
    
    // Source MAC (6 bytes)
    const srcMacBytes = srcMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) frame[6 + i] = srcMacBytes[i]
    
    // EtherType (2 bytes)
    frame.writeUInt16BE(etherType, 12)
    
    // Payload
    payload.copy(frame, 14)
    
    return frame
  }
}

// IPv4 packet builder
export class IPv4Packet {
  static build(srcIp, dstIp, protocol, payload, ttl = 64) {
    const headerLength = 20
    const totalLength = headerLength + payload.length
    const packet = Buffer.alloc(totalLength)
    
    // Version (4 bits) + IHL (4 bits)
    packet[0] = (4 << 4) | 5
    
    // DSCP + ECN
    packet[1] = 0
    
    // Total length
    packet.writeUInt16BE(totalLength, 2)
    
    // Identification
    packet.writeUInt16BE(Math.floor(Math.random() * 65535), 4)
    
    // Flags + Fragment offset
    packet.writeUInt16BE(0x4000, 6) // Don't fragment
    
    // TTL
    packet[8] = ttl
    
    // Protocol
    packet[9] = protocol
    
    // Header checksum (calculated later)
    packet.writeUInt16BE(0, 10)
    
    // Source IP
    const srcIpBytes = srcIp.split('.').map(b => parseInt(b))
    for (let i = 0; i < 4; i++) packet[12 + i] = srcIpBytes[i]
    
    // Destination IP
    const dstIpBytes = dstIp.split('.').map(b => parseInt(b))
    for (let i = 0; i < 4; i++) packet[16 + i] = dstIpBytes[i]
    
    const checksum = this.calculateChecksum(packet.subarray(0, headerLength))
    packet.writeUInt16BE(checksum, 10)
    
    // Payload
    payload.copy(packet, headerLength)
    
    return packet
  }

  static calculateChecksum(buffer) {
    let sum = 0
    for (let i = 0; i < buffer.length - 1; i += 2) {
      sum += buffer.readUInt16BE(i)
    }
    if (buffer.length % 2 !== 0) {
      sum += buffer[buffer.length - 1] << 8
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16)
    }
    return ~sum & 0xFFFF
  }
}

// TCP packet builder
export class TcpPacket {
  static build(srcPort, dstPort, seq, ack, flags, payload = Buffer.alloc(0), window = 65535) {
    const headerLength = 20
    const totalLength = headerLength + payload.length
    const packet = Buffer.alloc(totalLength)
    
    // Source port
    packet.writeUInt16BE(srcPort, 0)
    
    // Destination port
    packet.writeUInt16BE(dstPort, 2)
    
    // Sequence number
    packet.writeUInt32BE(seq, 4)
    
    // Acknowledgment number
    packet.writeUInt32BE(ack, 8)
    
    // Data offset (4 bits) + Reserved (3 bits) + NS (1 bit)
    packet[12] = (5 << 4)
    
    // Flags
    packet[13] = flags
    
    // Window size
    packet.writeUInt16BE(window, 14)
    
    // Checksum (0 for now)
    packet.writeUInt16BE(0, 16)
    
    // Urgent pointer
    packet.writeUInt16BE(0, 18)
    
    // Payload
    if (payload.length > 0) {
      payload.copy(packet, headerLength)
    }
    
    return packet
  }
}

// UDP packet builder
export class UdpPacket {
  static build(srcPort, dstPort, payload = Buffer.alloc(0)) {
    const headerLength = 8
    const totalLength = headerLength + payload.length
    const packet = Buffer.alloc(totalLength)
    
    // Source port
    packet.writeUInt16BE(srcPort, 0)
    
    // Destination port
    packet.writeUInt16BE(dstPort, 2)
    
    // Length
    packet.writeUInt16BE(totalLength, 4)
    
    // Checksum (0 for now - optional in IPv4)
    packet.writeUInt16BE(0, 6)
    
    // Payload
    if (payload.length > 0) {
      payload.copy(packet, headerLength)
    }
    
    return packet
  }
}

// ICMP packet builder
export class IcmpPacket {
  static build(type, code, payload = Buffer.alloc(0)) {
    const headerLength = 8
    const totalLength = headerLength + payload.length
    const packet = Buffer.alloc(totalLength)
    
    // Type
    packet[0] = type
    
    // Code
    packet[1] = code
    
    // Checksum (calculated later)
    packet.writeUInt16BE(0, 2)
    
    // Identifier
    packet.writeUInt16BE(Math.floor(Math.random() * 65535), 4)
    
    // Sequence number
    packet.writeUInt16BE(Math.floor(Math.random() * 65535), 6)
    
    // Payload
    if (payload.length > 0) {
      payload.copy(packet, headerLength)
    }
    
    // Calculate checksum
    const checksum = IPv4Packet.calculateChecksum(packet)
    packet.writeUInt16BE(checksum, 2)
    
    return packet
  }
}

// DNS packet builder
export class DnsPacket {
  static build(transactionId, flags, questions = [], answers = []) {
    let packet = Buffer.alloc(12) // Header only
    
    // Transaction ID
    packet.writeUInt16BE(transactionId, 0)
    
    // Flags
    packet.writeUInt16BE(flags, 2)
    
    // Question count
    packet.writeUInt16BE(questions.length, 4)
    
    // Answer count
    packet.writeUInt16BE(answers.length, 6)
    
    // Authority RRs
    packet.writeUInt16BE(0, 8)
    
    // Additional RRs
    packet.writeUInt16BE(0, 10)
    
    // Add questions
    for (const q of questions) {
      const qBuffer = this.encodeDnsName(q.name)
      packet = Buffer.concat([packet, qBuffer])
      const typeClass = Buffer.alloc(4)
      typeClass.writeUInt16BE(q.type, 0)
      typeClass.writeUInt16BE(q.class, 2)
      packet = Buffer.concat([packet, typeClass])
    }
    
    // Add answers
    for (const a of answers) {
      const aBuffer = this.encodeDnsName(a.name)
      packet = Buffer.concat([packet, aBuffer])
      const answerHeader = Buffer.alloc(10 + a.data.length)
      answerHeader.writeUInt16BE(a.type, 0)
      answerHeader.writeUInt16BE(a.class, 2)
      answerHeader.writeUInt32BE(a.ttl, 4)
      answerHeader.writeUInt16BE(a.data.length, 8)
      a.data.copy(answerHeader, 10)
      packet = Buffer.concat([packet, answerHeader])
    }
    
    return packet
  }

  static encodeDnsName(name) {
    const parts = name.split('.')
    const buffers = []
    
    for (const part of parts) {
      const len = Buffer.alloc(1)
      len[0] = part.length
      buffers.push(len)
      buffers.push(Buffer.from(part, 'ascii'))
    }
    
    buffers.push(Buffer.alloc(1)) // Null terminator
    return Buffer.concat(buffers)
  }
}

// HTTP packet builder
export class HttpPacket {
  static buildRequest(method, path, host, headers = {}, body = '') {
    let request = `${method} ${path} HTTP/1.1\r\n`
    request += `Host: ${host}\r\n`
    
    for (const [key, value] of Object.entries(headers)) {
      request += `${key}: ${value}\r\n`
    }
    
    // Only add Content-Length if not already provided in headers
    if (body && !headers['Content-Length']) {
      request += `Content-Length: ${Buffer.byteLength(body, 'utf-8')}\r\n`
    }
    
    request += '\r\n'
    
    if (body) {
      request += body
    }
    
    return Buffer.from(request, 'utf-8')
  }

  static buildResponse(statusCode, statusText, headers = {}, body = '') {
    let response = `HTTP/1.1 ${statusCode} ${statusText}\r\n`
    
    for (const [key, value] of Object.entries(headers)) {
      response += `${key}: ${value}\r\n`
    }
    
    if (body) {
      response += `Content-Length: ${Buffer.byteLength(body, 'utf-8')}\r\n`
    }
    
    response += '\r\n'
    
    if (body) {
      response += body
    }
    
    return Buffer.from(response, 'utf-8')
  }
}
