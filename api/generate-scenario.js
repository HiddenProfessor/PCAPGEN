import { generateScenarioPcap } from '../server/pcap-generator.js'
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
    const { name, timelineMinutes, attacks } = body

    if (!Array.isArray(attacks) || attacks.length === 0) {
      return res.status(400).json({ error: 'Scenario must include at least one attack' })
    }

    if (attacks.length > 20) {
      return res.status(400).json({ error: 'Maximum 20 attacks per scenario' })
    }

    for (const attack of attacks) {
      if (!VALID_ATTACK_TYPES.includes(attack.attackType)) {
        return res.status(400).json({ error: `Invalid attack type: ${attack.attackType}` })
      }

      const configErrors = validatePcapConfig(attack.config)
      if (configErrors.length > 0) {
        return res.status(400).json({ error: configErrors.join(', ') })
      }
    }

    const pcapBuffer = await generateScenarioPcap({ name, timelineMinutes, attacks })
    res.setHeader('Content-Type', 'application/vnd.tcpdump.pcap')
    res.setHeader('Content-Disposition', `attachment; filename="${sanitizeFilename(name || 'scenario')}_${Date.now()}.pcap"`)
    res.status(200).send(pcapBuffer)
  } catch (error) {
    res.status(500).json({ error: error.message || 'Failed to generate scenario PCAP' })
  }
}
