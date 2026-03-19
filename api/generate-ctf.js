import { generateCtfPcap } from '../server/pcap-generator.js'
import {
  sanitizeFilename,
  parseJsonBody,
  sendMethodNotAllowed
} from './_shared.js'

export default async function handler(req, res) {
  if (sendMethodNotAllowed(req, res, 'POST')) return

  try {
    const body = await parseJsonBody(req)
    const { name, difficulty, flags, background } = body

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

    const pcapBuffer = await generateCtfPcap({ name, difficulty, flags, background })
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap')
    res.setHeader('Content-Disposition', `attachment; filename="${sanitizeFilename(name || 'ctf')}_${Date.now()}.pcap"`)
    res.status(200).send(pcapBuffer)
  } catch (error) {
    res.status(500).json({ error: error.message || 'Failed to generate CTF PCAP' })
  }
}
