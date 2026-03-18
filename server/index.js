import express from 'express'
import cors from 'cors'
import path from 'path'
import { fileURLToPath } from 'url'
import { generatePcap } from './pcap-generator.js'
import { generateScenarioPcap } from './pcap-generator.js'
import { generateCtfPcap } from './pcap-generator.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const distPath = path.resolve(__dirname, '../dist')

const app = express()

app.use(cors())
app.use(express.json({ limit: '1mb' }))
app.use(express.static(distPath)) // serve built frontend

// --- Validation helpers ---
const VALID_ATTACK_TYPES = ['dos', 'ddos', 'dns_spoofing', 'arp_spoofing', 'port_scan', 'mitm', 'sql_injection', 'xss', 'malware_download']

function isValidIpv4(ip) {
  if (typeof ip !== 'string') return false
  const parts = ip.split('.')
  if (parts.length !== 4) return false
  return parts.every(p => /^\d{1,3}$/.test(p) && parseInt(p, 10) >= 0 && parseInt(p, 10) <= 255)
}

function sanitizeFilename(name) {
  if (typeof name !== 'string') return 'file'
  return name.replace(/[^a-zA-Z0-9_\-]/g, '_').substring(0, 100) || 'file'
}

function validatePcapConfig(config) {
  const errors = []
  if (!config || typeof config !== 'object') return ['Missing config']
  if (config.sourceIp && !isValidIpv4(config.sourceIp)) errors.push('Invalid source IP')
  if (config.targetIp && !isValidIpv4(config.targetIp)) errors.push('Invalid target IP')
  if (config.port != null && (typeof config.port !== 'number' || config.port < 1 || config.port > 65535)) errors.push('Port must be 1-65535')
  if (config.duration != null && (typeof config.duration !== 'number' || config.duration < 1 || config.duration > 300)) errors.push('Duration must be 1-300 seconds')
  return errors
}

// Generate PCAP endpoint
app.post('/api/generate-pcap', async (req, res) => {
  try {
    const { attackType, config } = req.body
    
    if (!VALID_ATTACK_TYPES.includes(attackType)) {
      return res.status(400).json({ error: 'Invalid attack type' })
    }
    const configErrors = validatePcapConfig(config)
    if (configErrors.length > 0) {
      return res.status(400).json({ error: configErrors.join(', ') })
    }
    
    console.log(`Generating PCAP for attack type: ${attackType}`)
    console.log('Config:', config)
    
    const pcapBuffer = await generatePcap(attackType, config)
    
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap')
    res.setHeader('Content-Disposition', `attachment; filename="${sanitizeFilename(attackType)}_${Date.now()}.pcap"`)
    res.send(pcapBuffer)
  } catch (error) {
    console.error('Error generating PCAP:', error)
    res.status(500).json({ error: error.message })
  }
})

// Generate Scenario PCAP endpoint
app.post('/api/generate-scenario', async (req, res) => {
  try {
    const { name, timelineMinutes, attacks } = req.body
    if (!Array.isArray(attacks) || attacks.length === 0) {
      return res.status(400).json({ error: 'Scenario must include at least one attack' })
    }
    if (attacks.length > 20) {
      return res.status(400).json({ error: 'Maximum 20 attacks per scenario' })
    }
    for (const atk of attacks) {
      if (!VALID_ATTACK_TYPES.includes(atk.attackType)) {
        return res.status(400).json({ error: `Invalid attack type: ${atk.attackType}` })
      }
      const errs = validatePcapConfig(atk.config)
      if (errs.length > 0) {
        return res.status(400).json({ error: errs.join(', ') })
      }
    }
    console.log(`Generating Scenario: ${name} (${timelineMinutes} min) with ${attacks.length} attacks`)
    const pcapBuffer = await generateScenarioPcap({ name, timelineMinutes, attacks })
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap')
    res.setHeader('Content-Disposition', `attachment; filename="${sanitizeFilename(name)}_${Date.now()}.pcap"`)
    res.send(pcapBuffer)
  } catch (error) {
    console.error('Error generating Scenario PCAP:', error)
    res.status(500).json({ error: error.message })
  }
})

// Generate CTF PCAP endpoint
app.post('/api/generate-ctf', async (req, res) => {
  try {
    const { name, difficulty, flags, background } = req.body
    if (!Array.isArray(flags) || flags.length === 0) {
      return res.status(400).json({ error: 'CTF must include at least one flag' })
    }
    if (flags.length > 50) {
      return res.status(400).json({ error: 'Maximum 50 flags per CTF' })
    }
    const validDifficulties = ['Easy', 'Medium', 'Hard', 'Expert']
    if (difficulty && !validDifficulties.includes(difficulty)) {
      return res.status(400).json({ error: 'Invalid difficulty' })
    }
    console.log(`Generating CTF: ${name} (${difficulty}) with ${flags.length} flags`)
    const pcapBuffer = await generateCtfPcap({ name, difficulty, flags, background })
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap')
    res.setHeader('Content-Disposition', `attachment; filename="${sanitizeFilename(name)}_${Date.now()}.pcap"`)
    res.send(pcapBuffer)
  } catch (error) {
    console.error('Error generating CTF PCAP:', error)
    res.status(500).json({ error: error.message })
  }
})

// Get available attack types
app.get('/api/attack-types', (req, res) => {
  res.json({
    dos: ['SYN Flood', 'UDP Flood', 'ICMP Flood', 'HTTP Flood'],
    ddos: ['Botnet SYN Flood', 'DNS Amplification', 'NTP Amplification'],
    dns_spoofing: ['Basic Spoofing', 'Cache Poisoning'],
    arp_spoofing: ['Gateway Poisoning', 'Bilateral Poisoning'],
    port_scan: ['TCP Connect', 'SYN Scan', 'UDP Scan', 'Stealth Scan'],
    mitm: ['SSL Strip', 'Session Hijacking'],
    sql_injection: ['Classic SQLi', 'Blind SQLi', 'Union-based'],
    xss: ['Reflected XSS', 'Stored XSS', 'DOM-based XSS'],
    malware_download: ['HTTP Download', 'FTP Download', 'Email Attachment']
  })
})

// SPA fallback to index.html for non-API routes
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' })
  }
  res.sendFile(path.join(distPath, 'index.html'))
})

const PORT = process.env.PORT || 3001
app.listen(PORT, () => {
  console.log(`🚀 PCAP Generator Server running on http://localhost:${PORT}`)
  console.log(`📦 Ready to generate cybersecurity training PCAPs`)
})
