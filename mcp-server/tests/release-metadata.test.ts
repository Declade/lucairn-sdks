import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

type PackageManifest = {
  version: string
}

type ServerManifest = {
  version: string
  packages: Array<{ version: string }>
}

const packageManifest = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
) as PackageManifest
const serverManifest = JSON.parse(
  readFileSync(new URL('../server.json', import.meta.url), 'utf8'),
) as ServerManifest

describe('MCP release metadata', () => {
  it('keeps both registry manifest versions aligned with package.json', () => {
    expect(serverManifest.version).toBe(packageManifest.version)
    expect(serverManifest.packages[0]?.version).toBe(packageManifest.version)
  })
})
