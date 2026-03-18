import React, { useState } from 'react'
import './App.css'

// Attack types configuration
const ATTACK_TYPES = {
  dos: {
    name: 'DoS Attack',
    description: 'Denial of Service attack',
    variants: ['SYN Flood', 'UDP Flood', 'ICMP Flood', 'HTTP Flood']
  },
  ddos: {
    name: 'DDoS Attack',
    description: 'Distributed Denial of Service from multiple sources',
    variants: ['Botnet SYN Flood', 'DNS Amplification', 'NTP Amplification']
  },
  dns_spoofing: {
    name: 'DNS Spoofing',
    description: 'Fake DNS responses to redirect traffic',
    variants: ['Basic Spoofing', 'Cache Poisoning']
  },
  arp_spoofing: {
    name: 'ARP Poisoning',
    description: 'Man-in-the-Middle via ARP poisoning',
    variants: ['Gateway Poisoning', 'Bilateral Poisoning']
  },
  port_scan: {
    name: 'Port Scanning',
    description: 'Network reconnaissance',
    variants: ['TCP Connect', 'SYN Scan', 'UDP Scan', 'Stealth Scan']
  },
  mitm: {
    name: 'On-Path Attack',
    description: 'Intercept and modify network traffic - previously called man-in-the-middle',
    variants: ['SSL Strip', 'Session Hijacking']
  },
  sql_injection: {
    name: 'SQL Injection',
    description: 'Database attack',
    variants: ['Classic SQLi', 'Blind SQLi', 'Union-based']
  },
  xss: {
    name: 'Cross-Site Scripting',
    description: 'XSS attack in HTTP traffic',
    variants: ['Reflected XSS', 'Stored XSS', 'DOM-based XSS']
  },
  malware_download: {
    name: 'Malware Download',
    description: 'Simulate malicious file downloads',
    variants: ['HTTP Download', 'FTP Download', 'Email Attachment']
  }
}

function App() {
  const [activeTab, setActiveTab] = useState('attacks')
  const [selectedAttack, setSelectedAttack] = useState('')
  const [attackConfig, setAttackConfig] = useState({
    variant: '',
    sourceIp: '192.168.1.100',
    targetIp: '192.168.1.1',
    duration: 60,
    intensity: 'medium',
    port: 80,
    includeLegitimate: true
  })
  const [generatingPcap, setGeneratingPcap] = useState(false)
  const [statusMessage, setStatusMessage] = useState('Ready')
  // Scenario builder state
  const [scenarioName, setScenarioName] = useState('My Scenario')
  const [timelineMinutes, setTimelineMinutes] = useState(30)
  const [scenarioAttacks, setScenarioAttacks] = useState([])
  const [scenarioStartMinute, setScenarioStartMinute] = useState(0)
  // CTF builder state
  const [ctfName, setCtfName] = useState('Find the Hidden Flag')
  const [ctfDifficulty, setCtfDifficulty] = useState('Medium')
  const [ctfFlags, setCtfFlags] = useState([])
  const [ctfFlagText, setCtfFlagText] = useState('FLAG{example_flag}')
  const [ctfHideIn, setCtfHideIn] = useState('HTTP Headers')
  const [ctfPayloadText, setCtfPayloadText] = useState('')
  const [ctfIncludeBackground, setCtfIncludeBackground] = useState(true)
  const [ctfBackgroundLevel, setCtfBackgroundLevel] = useState('Medium')
  const [ctfBackgroundWindowSec, setCtfBackgroundWindowSec] = useState(30)

  const handleGeneratePcap = async () => {
    if (!selectedAttack) {
      alert('Please select an attack type!')
      return
    }

    setGeneratingPcap(true)
    setStatusMessage('Generating PCAP file...')

    try {
      const response = await fetch('/api/generate-pcap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attackType: selectedAttack,
          config: attackConfig
        })
      })

      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${selectedAttack}_${Date.now()}.pcap`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)
        setStatusMessage('PCAP file generated successfully!')
      } else {
        throw new Error('Generation failed')
      }
    } catch (error) {
      setStatusMessage('Error: ' + error.message)
      alert('Failed to generate PCAP file')
    } finally {
      setGeneratingPcap(false)
      setTimeout(() => setStatusMessage('Ready'), 3000)
    }
  }

  return (
    <div className="xp-window" style={{ margin: '20px', maxWidth: '1200px', height: 'calc(100vh - 40px)', marginLeft: 'auto', marginRight: 'auto' }}>
      {/* Title Bar */}
      <div className="xp-titlebar">
        <div className="xp-titlebar-text">
          <div className="icon icon-app"></div>
          <span>PCAP Generator - Cybersecurity Training Tool</span>
        </div>
        <div className="xp-titlebar-buttons">
          <div className="xp-button-chrome">_</div>
          <div className="xp-button-chrome">□</div>
          <div className="xp-button-chrome close">✕</div>
        </div>
      </div>

      {/* Tabs for navigation */}
      <div className="xp-tabs">
        <div className={`xp-tab ${activeTab === 'attacks' ? 'active' : ''}`} onClick={() => setActiveTab('attacks')}>
          Attack Configuration
        </div>
        <div className={`xp-tab ${activeTab === 'scenarios' ? 'active' : ''}`} onClick={() => setActiveTab('scenarios')}>
          Scenario Builder
        </div>
        <div className={`xp-tab ${activeTab === 'ctf' ? 'active' : ''}`} onClick={() => setActiveTab('ctf')}>
          CTF Challenge Creator
        </div>
        <div style={{ flex: 1 }}></div>
        <button className="xp-button primary" style={{ marginRight: '5px' }} disabled={!selectedAttack || generatingPcap} onClick={handleGeneratePcap}>
          {generatingPcap ? 'Generating...' : 'Generate PCAP'}
        </button>
      </div>

      {/* Content Area */}
      <div className="xp-content">
        {activeTab === 'attacks' && (
          <div>
            <fieldset className="xp-fieldset">
              <legend className="xp-legend">Select Attack Type</legend>
              <div className="attack-list">
                {Object.entries(ATTACK_TYPES).map(([key, attack]) => (
                  <div
                    key={key}
                    className={`attack-item ${selectedAttack === key ? 'selected' : ''}`}
                    onClick={() => {
                      setSelectedAttack(key)
                      setAttackConfig({ ...attackConfig, variant: attack.variants[0] })
                    }}
                    style={{
                      background: selectedAttack === key 
                        ? 'linear-gradient(180deg, #D1E8FF 0%, #8FC7FF 100%)'
                        : undefined,
                      border: selectedAttack === key ? '2px solid #0054E3' : undefined
                    }}
                  >
                    <div>
                      <strong>{attack.name}</strong>
                      <div style={{ fontSize: '10px', color: '#666' }}>{attack.description}</div>
                    </div>
                    <div style={{ fontSize: '20px' }}>
                      {selectedAttack === key ? '✓' : '○'}
                    </div>
                  </div>
                ))}
              </div>
            </fieldset>

            {selectedAttack && (
              <fieldset className="xp-fieldset">
                <legend className="xp-legend">Attack Configuration</legend>
                <div className="xp-grid">
                  <div className="xp-form-group">
                    <label className="xp-label">Attack Variant:</label>
                    <select 
                      className="xp-select" 
                      value={attackConfig.variant}
                      onChange={(e) => setAttackConfig({ ...attackConfig, variant: e.target.value })}
                    >
                      {ATTACK_TYPES[selectedAttack].variants.map(variant => (
                        <option key={variant} value={variant}>{variant}</option>
                      ))}
                    </select>
                  </div>

                  <div className="xp-form-group">
                    <label className="xp-label">Intensity:</label>
                    <select 
                      className="xp-select"
                      value={attackConfig.intensity}
                      onChange={(e) => setAttackConfig({ ...attackConfig, intensity: e.target.value })}
                    >
                      <option value="low">Low (100 packets/sec)</option>
                      <option value="medium">Medium (1000 packets/sec)</option>
                      <option value="high">High (10000 packets/sec)</option>
                    </select>
                  </div>

                  <div className="xp-form-group">
                    <label className="xp-label">Source IP:</label>
                    <input 
                      type="text" 
                      className="xp-input" 
                      value={attackConfig.sourceIp}
                      onChange={(e) => setAttackConfig({ ...attackConfig, sourceIp: e.target.value })}
                      placeholder="192.168.1.100"
                    />
                  </div>

                  <div className="xp-form-group">
                    <label className="xp-label">Target IP:</label>
                    <input 
                      type="text" 
                      className="xp-input"
                      value={attackConfig.targetIp}
                      onChange={(e) => setAttackConfig({ ...attackConfig, targetIp: e.target.value })}
                      placeholder="192.168.1.1"
                    />
                  </div>

                  <div className="xp-form-group">
                    <label className="xp-label">Target Port:</label>
                    <input 
                      type="number" 
                      className="xp-input"
                      value={attackConfig.port}
                      onChange={(e) => setAttackConfig({ ...attackConfig, port: parseInt(e.target.value) })}
                      placeholder="80"
                    />
                  </div>

                  <div className="xp-form-group">
                    <label className="xp-label">Duration (seconds):</label>
                    <input 
                      type="number" 
                      className="xp-input"
                      value={attackConfig.duration}
                      onChange={(e) => setAttackConfig({ ...attackConfig, duration: parseInt(e.target.value) })}
                      placeholder="60"
                    />
                  </div>
                </div>

                <div className="xp-form-group" style={{ marginTop: '15px' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
                    <input 
                      type="checkbox" 
                      className="xp-checkbox"
                      checked={attackConfig.includeLegitimate}
                      onChange={(e) => setAttackConfig({ ...attackConfig, includeLegitimate: e.target.checked })}
                    />
                    <span className="xp-label">Include legitimate traffic (more realistic)</span>
                  </label>
                </div>

                <div style={{ marginTop: '20px', display: 'flex', gap: '10px', justifyContent: 'center' }}>
                  <button className="xp-button primary" onClick={handleGeneratePcap} disabled={generatingPcap}>
                    {generatingPcap ? 'Generating...' : 'Generate PCAP File'}
                  </button>
                  <button className="xp-button" onClick={() => setSelectedAttack('')}>
                    Clear Selection
                  </button>
                </div>
              </fieldset>
            )}
          </div>
        )}

        {activeTab === 'scenarios' && (
          <div>
            <fieldset className="xp-fieldset">
              <legend className="xp-legend">Multi-Attack Scenarios</legend>
              <p style={{ marginBottom: '15px' }}>
                Create complex scenarios combining multiple attack types for realistic training simulations.
              </p>
              <div className="xp-grid">
                <div className="xp-form-group">
                  <label className="xp-label">Scenario Name:</label>
                  <input 
                    type="text" 
                    className="xp-input" 
                    value={scenarioName}
                    onChange={(e) => setScenarioName(e.target.value)}
                    placeholder="e.g., Advanced Persistent Threat" 
                  />
                </div>
                <div className="xp-form-group">
                  <label className="xp-label">Timeline (minutes):</label>
                  <input 
                    type="number" 
                    className="xp-input" 
                    value={timelineMinutes}
                    onChange={(e) => setTimelineMinutes(parseInt(e.target.value) || 0)}
                    placeholder="30" 
                  />
                </div>
              </div>

              <div className="xp-fieldset" style={{ marginTop: '10px' }}>
                <legend className="xp-legend">Add Attack To Timeline</legend>
                <div className="xp-grid">
                  <div className="xp-form-group">
                    <label className="xp-label">Attack Type:</label>
                    <select 
                      className="xp-select" 
                      value={selectedAttack}
                      onChange={(e) => {
                        const key = e.target.value
                        setSelectedAttack(key)
                        if (key) {
                          setAttackConfig({
                            ...attackConfig,
                            variant: ATTACK_TYPES[key].variants[0]
                          })
                        }
                      }}
                    >
                      <option value="">Select Attack</option>
                      {Object.entries(ATTACK_TYPES).map(([key, attack]) => (
                        <option key={key} value={key}>{attack.name}</option>
                      ))}
                    </select>
                  </div>
                  <div className="xp-form-group">
                    <label className="xp-label">Start at minute:</label>
                    <input 
                      type="number" 
                      className="xp-input"
                      value={scenarioStartMinute}
                      min={0}
                      max={timelineMinutes}
                      onChange={(e) => setScenarioStartMinute(parseInt(e.target.value) || 0)}
                    />
                  </div>
                </div>

                {/* Reuse attack configuration controls */}
                {selectedAttack && (
                  <div className="xp-grid" style={{ marginTop: '10px' }}>
                    <div className="xp-form-group">
                      <label className="xp-label">Variant:</label>
                      <select 
                        className="xp-select" 
                        value={attackConfig.variant}
                        onChange={(e) => setAttackConfig({ ...attackConfig, variant: e.target.value })}
                      >
                        {ATTACK_TYPES[selectedAttack].variants.map(variant => (
                          <option key={variant} value={variant}>{variant}</option>
                        ))}
                      </select>
                    </div>
                    <div className="xp-form-group">
                      <label className="xp-label">Intensity:</label>
                      <select 
                        className="xp-select"
                        value={attackConfig.intensity}
                        onChange={(e) => setAttackConfig({ ...attackConfig, intensity: e.target.value })}
                      >
                        <option value="low">Low</option>
                        <option value="medium">Medium</option>
                        <option value="high">High</option>
                      </select>
                    </div>
                    <div className="xp-form-group">
                      <label className="xp-label">Source IP:</label>
                      <input 
                        type="text" 
                        className="xp-input" 
                        value={attackConfig.sourceIp}
                        onChange={(e) => setAttackConfig({ ...attackConfig, sourceIp: e.target.value })}
                      />
                    </div>
                    <div className="xp-form-group">
                      <label className="xp-label">Target IP:</label>
                      <input 
                        type="text" 
                        className="xp-input" 
                        value={attackConfig.targetIp}
                        onChange={(e) => setAttackConfig({ ...attackConfig, targetIp: e.target.value })}
                      />
                    </div>
                    <div className="xp-form-group">
                      <label className="xp-label">Port:</label>
                      <input 
                        type="number" 
                        className="xp-input" 
                        value={attackConfig.port}
                        onChange={(e) => setAttackConfig({ ...attackConfig, port: parseInt(e.target.value) || 0 })}
                      />
                    </div>
                    <div className="xp-form-group">
                      <label className="xp-label">Duration (sec):</label>
                      <input 
                        type="number" 
                        className="xp-input" 
                        value={attackConfig.duration}
                        onChange={(e) => setAttackConfig({ ...attackConfig, duration: parseInt(e.target.value) || 0 })}
                      />
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
                  <button 
                    className="xp-button" 
                    onClick={() => {
                      if (!selectedAttack) {
                        alert('Select an attack to add')
                        return
                      }
                      if (scenarioStartMinute < 0 || scenarioStartMinute > timelineMinutes) {
                        alert('Start minute must be within timeline')
                        return
                      }
                      setScenarioAttacks(prev => ([
                        ...prev,
                        {
                          id: Date.now(),
                          attackType: selectedAttack,
                          startMinute: scenarioStartMinute,
                          config: { ...attackConfig }
                        }
                      ]))
                      setStatusMessage('Attack added to scenario')
                    }}
                  >
                    Add Attack to Scenario
                  </button>
                  <button 
                    className="xp-button" 
                    onClick={() => setScenarioAttacks([])}
                  >
                    Clear Scenario
                  </button>
                </div>
              </div>

              {/* Scenario timeline list */}
              <div className="xp-fieldset" style={{ marginTop: '10px' }}>
                <legend className="xp-legend">Timeline</legend>
                {scenarioAttacks.length === 0 ? (
                  <div style={{ fontSize: '11px', color: '#666' }}>No attacks added yet.</div>
                ) : (
                  <div className="attack-list">
                    {scenarioAttacks
                      .sort((a, b) => a.startMinute - b.startMinute)
                      .map(item => (
                        <div key={item.id} className="attack-item">
                          <div>
                            <strong>{ATTACK_TYPES[item.attackType].name}</strong>
                            <div style={{ fontSize: '10px', color: '#666' }}>
                              Variant: {item.config.variant} • Start: {item.startMinute}m • Duration: {item.config.duration}s
                            </div>
                          </div>
                          <div style={{ display: 'flex', gap: '8px' }}>
                            <button 
                              className="xp-button"
                              onClick={() => setScenarioAttacks(prev => prev.filter(a => a.id !== item.id))}
                            >Remove</button>
                          </div>
                        </div>
                      ))}
                  </div>
                )}
              </div>

              {/* Generate Scenario PCAP */}
              <div style={{ marginTop: '15px', display: 'flex', gap: '10px' }}>
                <button 
                  className="xp-button primary"
                  disabled={generatingPcap || scenarioAttacks.length === 0}
                  onClick={async () => {
                    setGeneratingPcap(true)
                    setStatusMessage('Generating scenario PCAP...')
                    try {
                      const response = await fetch('/api/generate-scenario', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                          name: scenarioName,
                          timelineMinutes,
                          attacks: scenarioAttacks
                        })
                      })
                      if (response.ok) {
                        const blob = await response.blob()
                        const url = window.URL.createObjectURL(blob)
                        const a = document.createElement('a')
                        a.href = url
                        a.download = `${scenarioName.replace(/\s+/g, '_')}_${Date.now()}.pcap`
                        document.body.appendChild(a)
                        a.click()
                        window.URL.revokeObjectURL(url)
                        document.body.removeChild(a)
                        setStatusMessage('Scenario PCAP generated!')
                      } else {
                        throw new Error('Scenario generation failed')
                      }
                    } catch (err) {
                      setStatusMessage('Error: ' + err.message)
                      alert('Failed to generate scenario PCAP')
                    } finally {
                      setGeneratingPcap(false)
                      setTimeout(() => setStatusMessage('Ready'), 3000)
                    }
                  }}
                >
                  Generate Scenario PCAP
                </button>
              </div>
            </fieldset>
          </div>
        )}

        {activeTab === 'ctf' && (
          <div>
            <fieldset className="xp-fieldset">
              <legend className="xp-legend">CTF Challenge Creator</legend>
              <p style={{ marginBottom: '15px' }}>
                Create Capture The Flag challenges with embedded flags in network traffic.
              </p>
              <div className="xp-grid">
                <div className="xp-form-group">
                  <label className="xp-label">Challenge Name:</label>
                  <input 
                    type="text" 
                    className="xp-input" 
                    value={ctfName}
                    onChange={(e) => setCtfName(e.target.value)}
                    placeholder="e.g., Find the Hidden Flag" 
                  />
                </div>
                <div className="xp-form-group">
                  <label className="xp-label">Difficulty, influences obfuscation / spread:</label>
                  <select 
                    className="xp-select"
                    value={ctfDifficulty}
                    onChange={(e) => setCtfDifficulty(e.target.value)}
                  >
                    <option>Easy</option>
                    <option>Medium</option>
                    <option>Hard</option>
                    <option>Expert</option>
                  </select>
                </div>
                <div className="xp-form-group">
                  <label className="xp-label">Include Normal Traffic:</label>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <input 
                      type="checkbox" 
                      className="xp-checkbox" 
                      checked={ctfIncludeBackground}
                      onChange={(e) => setCtfIncludeBackground(e.target.checked)}
                    />
                    <span>Generate normal browsing/noise around flags</span>
                  </label>
                </div>
                <div className="xp-form-group">
                  <label className="xp-label">Amount of normal traffic:</label>
                  <select 
                    className="xp-select"
                    value={ctfBackgroundLevel}
                    onChange={(e) => setCtfBackgroundLevel(e.target.value)}
                    disabled={!ctfIncludeBackground}
                  >
                    <option>Low</option>
                    <option>Medium</option>
                    <option>High</option>
                  </select>
                </div>
                <div className="xp-form-group">
                  <label className="xp-label">Noise Window Around Flag (sec):</label>
                  <input 
                    type="number" 
                    className="xp-input"
                    value={ctfBackgroundWindowSec}
                    onChange={(e) => setCtfBackgroundWindowSec(Math.max(0, parseInt(e.target.value) || 0))}
                    disabled={!ctfIncludeBackground}
                  />
                </div>
              </div>

              <div className="xp-fieldset" style={{ marginTop: '10px' }}>
                <legend className="xp-legend">Add Flag</legend>
                <div className="xp-grid">
                  <div className="xp-form-group">
                    <label className="xp-label">Flag Text:</label>
                    <input 
                      type="text" 
                      className="xp-input" 
                      value={ctfFlagText}
                      onChange={(e) => setCtfFlagText(e.target.value)}
                      placeholder="FLAG{...}" 
                    />
                  </div>
                  <div className="xp-form-group">
                    <label className="xp-label">Hide Flag In:</label>
                    <select 
                      className="xp-select"
                      value={ctfHideIn}
                      onChange={(e) => setCtfHideIn(e.target.value)}
                    >
                      <option>HTTP Headers</option>
                      <option>DNS Query</option>
                      <option>ICMP Data</option>
                      <option>TCP Payload</option>
                      <option>Encoded in Multiple Packets</option>
                    </select>
                  </div>
                  <div className="xp-form-group">
                    <label className="xp-label">Additional Payload (optional):</label>
                    <input 
                      type="text" 
                      className="xp-input" 
                      value={ctfPayloadText}
                      onChange={(e) => setCtfPayloadText(e.target.value)}
                      placeholder="Context or decoy data" 
                    />
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '10px' }}>
                  <button 
                    className="xp-button"
                    onClick={() => {
                      if (!ctfFlagText.trim()) {
                        alert('Enter a flag text')
                        return
                      }
                      setCtfFlags(prev => ([
                        ...prev,
                        {
                          id: Date.now(),
                          flag: ctfFlagText.trim(),
                          hideIn: ctfHideIn,
                          payload: ctfPayloadText
                        }
                      ]))
                      setStatusMessage('Flag added to CTF')
                    }}
                  >Add Flag</button>
                  <button className="xp-button" onClick={() => setCtfFlags([])}>Clear Flags</button>
                </div>
              </div>

              {/* Flags list */}
              <div className="xp-fieldset" style={{ marginTop: '10px' }}>
                <legend className="xp-legend">Flags</legend>
                {ctfFlags.length === 0 ? (
                  <div style={{ fontSize: '11px', color: '#666' }}>No flags added yet.</div>
                ) : (
                  <div className="attack-list">
                    {ctfFlags.map(item => (
                      <div key={item.id} className="attack-item">
                        <div>
                          <strong>{item.flag}</strong>
                          <div style={{ fontSize: '10px', color: '#666' }}>Hidden in: {item.hideIn}</div>
                          {item.payload && (
                            <div style={{ fontSize: '10px', color: '#666' }}>Payload: {item.payload}</div>
                          )}
                        </div>
                        <div>
                          <button 
                            className="xp-button"
                            onClick={() => setCtfFlags(prev => prev.filter(f => f.id !== item.id))}
                          >Remove</button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Generate CTF PCAP */}
              <div style={{ marginTop: '15px', display: 'flex', gap: '10px' }}>
                <button 
                  className="xp-button primary"
                  disabled={generatingPcap || ctfFlags.length === 0}
                  onClick={async () => {
                    setGeneratingPcap(true)
                    setStatusMessage('Generating CTF PCAP...')
                    try {
                      const response = await fetch('/api/generate-ctf', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                          name: ctfName,
                          difficulty: ctfDifficulty,
                          flags: ctfFlags,
                          background: {
                            include: ctfIncludeBackground,
                            level: ctfBackgroundLevel,
                            windowSec: ctfBackgroundWindowSec
                          }
                        })
                      })
                      if (response.ok) {
                        const blob = await response.blob()
                        const url = window.URL.createObjectURL(blob)
                        const a = document.createElement('a')
                        a.href = url
                        a.download = `${ctfName.replace(/\s+/g, '_')}_${Date.now()}.pcap`
                        document.body.appendChild(a)
                        a.click()
                        window.URL.revokeObjectURL(url)
                        document.body.removeChild(a)
                        setStatusMessage('CTF PCAP generated!')
                      } else {
                        throw new Error('CTF generation failed')
                      }
                    } catch (err) {
                      setStatusMessage('Error: ' + err.message)
                      alert('Failed to generate CTF PCAP')
                    } finally {
                      setGeneratingPcap(false)
                      setTimeout(() => setStatusMessage('Ready'), 3000)
                    }
                  }}
                >
                  Generate CTF PCAP
                </button>
              </div>
            </fieldset>
          </div>
        )}
      </div>

      {/* Status Bar */}
      <div className="xp-statusbar">
        <div className="xp-status-panel" style={{ flex: 1 }}>
          <span>📊</span> {statusMessage}
        </div>
        <div className="xp-status-panel">
          <span>🖥️</span> Ready
        </div>
      </div>
    </div>
  )
}

export default App
