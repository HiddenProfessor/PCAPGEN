import { generatePcap } from '../server/pcap-generator.js'
import {
  VALID_ATTACK_TYPES,
  sanitizeFilename,
  validatePcapConfig,
  parseJsonBody,
  sendMethodNotAllowed
} from './_shared.js'

export default async function handler(req, res) {
  if (sendMethodNotAllowed(req, res, 'POST')) return

  try {
    const body = await parseJsonBody(req)
    const { attackType, config } = body

    if (!VALID_ATTACK_TYPES.includes(attackType)) {
      return res.status(400).json({ error: 'Invalid attack type' })
    }

    const configErrors = validatePcapConfig(config)
    if (configErrors.length > 0) {
      return res.status(400).json({ error: configErrors.join(', ') })
    }

    const pcapBuffer = await generatePcap(attackType, config)
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap')
    res.setHeader('Content-Disposition', `attachment; filename="${sanitizeFilename(attackType)}_${Date.now()}.pcap"`)
    res.status(200).send(pcapBuffer)
  } catch (error) {
    res.status(500).json({ error: error.message || 'Failed to generate PCAP' })
  }
}
