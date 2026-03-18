# PCAPGEN

PCAPGEN is a small efficient web application for generating realistic PCAP files with various cyberattack simulations for cybersecurity training and AI model development.
It is made to look like an old Windows XP program with the only reason being that it looks so beautifully ugly!

## What's inside

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

**As of right now - the attacks work, but the other parts need som work. However these will be fixed at a later date.**
  
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

## How I use it (and how you might)

- Open the UI in your browser, pick an attack or assemble a scenario, tweak source/target IPs and durations, then download the resulting PCAP.
- Use `POST /api/generate-pcap` for single attacks, `POST /api/generate-scenario` for timelines, and `POST /api/generate-ctf` for CTF-style PCAPs.
- The server also exposes `GET /api/attack-types` to discover available templates.

## Contributing and ideas

If you have templates, more realistic background traffic, or nicer scenario-editing UX, send a PR. Small, focused changes are easiest to review — adding a single new attack type or improving validation is a great start.

Want this to support a classroom workflow? Open an issue and describe your ideal features — I try to keep the surface area small and practical.

Thanks for trying PCAPGEN — I hope it saves you time.

— Hidden Professor
