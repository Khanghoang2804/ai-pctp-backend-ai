import { executeQuery, withLbugDb } from '/usr/lib/node_modules/gitnexus/dist/core/lbug/lbug-adapter.js';
import { resolve } from 'path';

async function main() {
    const repoPath = process.argv[2];
    const dbPath = resolve(repoPath, '.gitnexus', 'lbug');
    try {
        await withLbugDb(dbPath, async () => {
            const res = await executeQuery(`MATCH (a)-[r]->(b) RETURN a.id as sourceId, b.id as targetId, type(r) as type, r.confidence as confidence, r.reason as reason, r.step as step LIMIT 1`);
            console.log(JSON.stringify(res, null, 2));
        });
    } catch (e) {
        console.error(e.message);
        process.exit(1);
    }
}
main();
