export const VALID_ATTACK_TYPES = ['dos', 'ddos', 'dns_spoofing', 'arp_spoofing', 'port_scan', 'mitm', 'sql_injection', 'xss', 'malware_download']

export function isValidIpv4(ip) {
  if (typeof ip !== 'string') return false
  const parts = ip.split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => /^\d{1,3}$/.test(part) && parseInt(part, 10) >= 0 && parseInt(part, 10) <= 255)
}

export function sanitizeFilename(name) {
  if (typeof name !== 'string') return 'file'
  return name.replace(/[^a-zA-Z0-9_\-]/g, '_').substring(0, 100) || 'file'
}

export function validatePcapConfig(config) {
  const errors = []
  if (!config || typeof config !== 'object') return ['Missing config']
  if (config.sourceIp && !isValidIpv4(config.sourceIp)) errors.push('Invalid source IP')
  if (config.targetIp && !isValidIpv4(config.targetIp)) errors.push('Invalid target IP')
  if (config.port != null && (typeof config.port !== 'number' || config.port < 1 || config.port > 65535)) {
    errors.push('Port must be 1-65535')
  }
  if (config.duration != null && (typeof config.duration !== 'number' || config.duration < 1 || config.duration > 300)) {
    errors.push('Duration must be 1-300 seconds')
  }
  return errors
}

export async function parseJsonBody(req) {
  if (req.body && typeof req.body === 'object') {
    return req.body
  }

  const chunks = []
  for await (const chunk of req) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk)
  }

  if (chunks.length === 0) return {}
  const raw = Buffer.concat(chunks).toString('utf-8')
  if (!raw.trim()) return {}
  return JSON.parse(raw)
}

export function sendMethodNotAllowed(req, res, allowedMethod) {
  if (req.method !== allowedMethod) {
    res.setHeader('Allow', allowedMethod)
    res.status(405).json({ error: 'Method not allowed' })
    return true
  }
  return false
}
