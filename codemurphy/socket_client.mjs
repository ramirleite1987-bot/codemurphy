// Run only in an isolated tool directory. The only input is verified release tuples.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import version from '@vltpkg/security-archive/package.json' with { type: 'json' };

if (version.version !== '1.7.0') throw Error('Unexpected security archive client version');
const { SecurityArchive } = await import('@vltpkg/security-archive');
const { joinDepIDTuple } = await import('@vltpkg/dep-id');
const rows = JSON.parse(readFileSync(0, 'utf8'));
const namePattern = /^(?:@[a-z0-9][a-z0-9_.-]*\/)?[a-z0-9][a-z0-9_.-]*$/u;
const versionPattern = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u;
if (!Array.isArray(rows) || rows.length === 0 || rows.length > 128 || rows.some(row =>
  !Array.isArray(row) || row.length !== 2 || typeof row[0] !== 'string' || typeof row[1] !== 'string' ||
  row[0].length > 214 || row[1].length > 128 || !namePattern.test(row[0]) || !versionPattern.test(row[1]))) {
  throw Error('Invalid release list');
}

const options = { registries: { npm: 'https://registry.npmjs.org/' } };
const nodes = rows.map(([name, version]) => ({ name, version, options,
  id: joinDepIDTuple(['registry', 'npm', `${name}@${version}`]),
}));
const archive = await SecurityArchive.start({ nodes, path: join(process.env.TMPDIR, 'socket-cache.db'),
  retries: 0, timeout: 25000 });

const bounded = value => typeof value === 'string' && value.length <= 192 ? value : null;
const slim = alert => ({ type: bounded(alert?.type), severity: bounded(alert?.severity), ids: [
  alert?.key, alert?.props?.cveId, alert?.props?.ghsaId, alert?.props?.advisoryId,
  ...(Array.isArray(alert?.props?.aliases) ? alert.props.aliases.slice(0, 12) : []),
].map(bounded).filter(Boolean) });

process.stdout.write(JSON.stringify(nodes.map(node => {
  const alerts = archive.get(node.id)?.alerts;
  return { package: node.name, version: node.version,
    alerts: Array.isArray(alerts) && alerts.length <= 512 ? alerts.map(slim) : null };
})));
