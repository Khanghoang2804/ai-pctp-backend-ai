import { executeQuery, withLbugDb } from '/usr/lib/node_modules/gitnexus/dist/core/lbug/lbug-adapter.js';
import { resolve } from 'path';

async function main() {
    const repoPath = process.argv[2];
    if (!repoPath) {
        console.error("Missing repoPath");
        process.exit(1);
    }
    
    const dbPath = resolve(repoPath, '.gitnexus', 'lbug');
    const includeContent = process.argv[3] === 'true';

    try {
        await withLbugDb(dbPath, async () => {
            const nodes = [];
            const relationships = [];
            
            const labels = ['File', 'Folder', 'Function', 'Method', 'Class', 'Variable', 'Struct', 'Macro', 'Namespace', 'Process', 'Community'];
            
            for (const label of labels) {
                try {
                    const q = (label === 'File' && includeContent)
                        ? `MATCH (n:File) RETURN n, n.content as content`
                        : `MATCH (n:${label}) RETURN n`;
                    const res = await executeQuery(q);
                    for (const row of res) {
                        const props = { ...row.n };
                        delete props._id;
                        delete props._label;
                        if (label === 'File' && includeContent && row.content) props.content = row.content;
                        nodes.push({ id: row.n.id || `${label}:${row.n.name}`, label: label, properties: props });
                    }
                } catch (e) {}
            }

            // Get relationships
            try {
                const res = await executeQuery(`MATCH (a)-[r]->(b) RETURN a.id as sourceId, b.id as targetId, r.type as type, r.confidence as confidence, r.reason as reason, r.step as step`);
                for (const row of res) {
                    if (row.sourceId && row.targetId) {
                        relationships.push({
                            sourceId: row.sourceId,
                            targetId: row.targetId,
                            type: row.type,
                            confidence: row.confidence,
                            reason: row.reason,
                            step: row.step
                        });
                    }
                }
            } catch (e) {
                console.error("Relationships query failed:", e.message);
            }

            console.log(JSON.stringify({ nodes, relationships }));
        });
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

main();
