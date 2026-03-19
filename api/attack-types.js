import { sendMethodNotAllowed } from './_shared.js'

export default function handler(req, res) {
  if (sendMethodNotAllowed(req, res, 'GET')) return

  res.status(200).json({
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
}
