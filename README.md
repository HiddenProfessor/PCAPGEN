# PCAP Generator - Cybersecurity Training Tool

A Windows XP-styled web application for generating realistic PCAP files with various cyberattack simulations for cybersecurity training and AI model development.

## Features

- **Multiple Attack Types**:
  - DoS/DDoS (SYN Flood, UDP Flood, ICMP Flood, HTTP Flood, Botnet, DNS/NTP Amplification)
  - DNS Spoofing & Cache Poisoning
  - ARP Spoofing & MITM (SSL Strip, Session Hijacking)
  - Port Scanning (TCP Connect, SYN, UDP, Stealth/FIN)
  - SQL Injection (Classic, Blind, Union-based)
  - Cross-Site Scripting (Reflected, Stored, DOM-based)
  - Malware Download Simulation (HTTP, FTP, Email Attachment + C2 callback)

- **Scenario Builder** — Combine multiple attacks into a single timeline
- **CTF Challenge Creator** — Embed flags in HTTP headers, DNS, ICMP, TCP, or multi-packet encoding
- **Configurable Parameters** — IPs, ports, duration, intensity, legitimate background traffic
- **Nostalgic Windows XP UI**

## Quick Start (Development)

```bash
npm install
npm run dev
```

This starts the frontend on http://localhost:3000 and the API on http://localhost:3001.

## Production Build & Deploy

```bash
npm install
npm run build
npm start
```

The server serves the built React app and the API from a single process on `PORT` (default 3001). Set the `PORT` environment variable to match your hosting provider.

### Hosting Requirements

- **Node.js 18+**
- No native dependencies — pure JavaScript
- Single-process: Express serves both the static frontend and the API
- Stateless: no database, no file system writes, no sessions

### Deploying to common platforms

**Railway / Render / Fly.io:**
Set build command to `npm install && npm run build`, start command to `npm start`. The `PORT` env var is set automatically.

**VPS / Docker:**
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
RUN npm run build
EXPOSE 3001
CMD ["npm", "start"]
```

## Tech Stack

- **Frontend**: React 18 + Vite 5
- **Backend**: Node.js + Express
- **PCAP Generation**: Custom binary packet crafting (Ethernet/IPv4/TCP/UDP/ICMP/DNS/HTTP/ARP)

## Development

- `npm run dev` - Start both frontend and backend in development mode
- `npm run dev:client` - Start only the frontend
- `npm run dev:server` - Start only the backend
- `npm run build` - Build for production

## License

MIT
