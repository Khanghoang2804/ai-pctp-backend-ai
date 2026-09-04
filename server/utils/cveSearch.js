// file: server/utils/cveSearch.js
require('dotenv').config();
const { Pool } = require('pg');

const isLocal = process.env.NEON_DB_URL && (process.env.NEON_DB_URL.includes('localhost') || process.env.NEON_DB_URL.includes('127.0.0.1'));

const pool = new Pool({
    connectionString: process.env.NEON_DB_URL,
    ssl: isLocal ? false : { rejectUnauthorized: false }
});

pool.query("SELECT 1")
    .then(() => console.log("[Neon PostgreSQL] Kết nối Database thành công, sẵn sàng truy vấn!"))
    .catch(err => console.error("[Neon] LỖI KẾT NỐI DATABASE:", err.message));

async function extractSearchIntentJSON(vietnameseQuery) {
    console.log("   -> [AI] Đang nhờ GPT trích xuất ý định tìm kiếm...");
    try {
        const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${process.env.OPENROUTER_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                model: "openai/gpt-oss-120b", 
                messages: [
                    {
                        role: "system",
                        content: `Bạn là một cỗ máy phân tích ngôn ngữ tự nhiên thành định dạng JSON chuyên dùng cho hệ thống tìm kiếm lỗ hổng an ninh mạng (CVE). Năm hiện tại đang là 2026
Nhiệm vụ: Đọc câu hỏi và CHỈ TRẢ VỀ JSON HỢP LỆ. KHÔNG BAO GỒM VĂN BẢN NÀO KHÁC.

CẤU TRÚC JSON BẮT BUỘC:
{
  "action": "SEARCH" hoặc "SKIP",
  "cve_id": "Mã CVE nếu có (vd: CVE-2021-44228). Nếu không, để rỗng ''",
  "vendor_product": "Tên công cụ, hãng, framework. Nếu không có, để rỗng ''",
  "version": "Phiên bản. Nếu không có, để rỗng ''",
  "year": YYYY (dạng số nguyên) hoặc null,
  "english_query": "Câu truy vấn tiếng Anh tối ưu cho Semantic Vector Search"
}

QUY TẮC PHÂN LOẠI (action):
- "SKIP": Dùng cho lời chào, hỏi thăm, hoặc CÁC CÂU HỎI KIẾN THỨC CHUNG (VD: "Phishing là gì?", "Cách chống DDoS").
- "SEARCH": Dùng khi người dùng muốn tra cứu lỗ hổng, lỗi bảo mật, hoặc thông tin về một CVE cụ thể.

QUY TẮC TRÍCH XUẤT (Nếu action là SEARCH):
- "vendor_product": Gom tất cả công nghệ được nhắc đến (VD: "React Next.js", "Windows Exchange").
- "english_query": Dịch từ khóa quan trọng sang tiếng Anh và MỞ RỘNG bằng các từ khóa kỹ thuật đồng nghĩa. (Ví dụ: Nếu người dùng hỏi "React Server Components", hãy thêm các từ khóa gói nội bộ như "react-server-dom"). BẮT BUỘC phải bao gồm Tên công nghệ + Loại tấn công.
- "year": Nếu người dùng hỏi năm cụ thể, trích xuất năm đó (VD: 2024). Nếu người dùng dùng các từ khóa như "gần đây", "mới nhất", "hiện nay", "năm nay", HÃY TRẢ VỀ NĂM HIỆN TẠI VÀ NĂM TRƯỚC ĐÓ DƯỚI DẠNG MẢNG (VD: [2025, 2026]). Nếu không có bối cảnh thời gian nào, trả về null.

VÍ DỤ 1: "có lỗ hổng nào của windows 10 năm 2024 không"
{"action": "SEARCH", "cve_id": "", "vendor_product": "windows", "version": "10", "year": 2024, "english_query": "windows 10 security vulnerabilities"}

VÍ DỤ 2: "Gần đây có lỗi RCE nào nghiêm trọng liên quan đến React Server Components ảnh hưởng tới Next.js không?"
{"action": "SEARCH", "cve_id": "", "vendor_product": "React Next.js", "version": "", "year": null, "english_query": "React Server Components Next.js RCE remote code execution vulnerabilities"}

VÍ DỤ 3: "Cho tôi thông tin về CVE-2024-1234"
{"action": "SEARCH", "cve_id": "CVE-2024-1234", "vendor_product": "", "version": "", "year": 2024, "english_query": "CVE-2024-1234 details and vulnerabilities"}

VÍ DỤ 4: "SQL Injection là gì?"
{"action": "SKIP", "cve_id": "", "vendor_product": "", "version": "", "year": null, "english_query": ""}`
                    },
                    {
                        role: "user",
                        content: vietnameseQuery
                    }
                ],
                temperature: 0.1
            })
        });

        if (!response.ok) {
            throw new Error(`Lỗi API OpenRouter: ${response.status}`);
        }

        const data = await response.json();
        let content = data.choices[0]?.message?.content || "{}";

        content = content.replace(/```json/g, '').replace(/```/g, '').trim();

        const jsonResponse = JSON.parse(content);
        return jsonResponse;
        
    } catch (error) {
        console.error("❌ Lỗi khi trích xuất JSON bằng AI:", error);
        return { action: "SEARCH", english_query: vietnameseQuery }; 
    }
}

function sliceAndNormalizeMRL(vector, dimensions = 1024) {
    const sliced = vector.slice(0, dimensions);
    let sumSq = 0;
    for (let i = 0; i < dimensions; i++) sumSq += sliced[i] * sliced[i];
    const norm = Math.sqrt(sumSq);
    if (norm === 0) return sliced;
    for (let i = 0; i < dimensions; i++) sliced[i] = sliced[i] / norm;
    return sliced;
}

async function getEmbeddingFromOpenRouter(text) {
    const url = "https://openrouter.ai/api/v1/embeddings";
    console.log("   -> [OpenRouter] Bắt đầu gọi API lấy Vector...");

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${process.env.OPENROUTER_API_KEY}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                model: "qwen/qwen3-embedding-8b",
                input: text,
                encoding_format: "float"
            }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        
        console.log("   -> [OpenRouter] Lấy Vector thành công siêu tốc!");
        return sliceAndNormalizeMRL(data.data[0].embedding, 1024);
        
    } catch (error) {
        clearTimeout(timeoutId);
        console.error("   -> [OpenRouter] QUÁ THỜI GIAN HOẶC LỖI MẠNG! Ép ngắt kết nối.");
        return null;
    }
}

function reciprocalRankFusion(vectorRows, ftsRows, topK = 3) {
    const fusionScores = {};
    const k = 60; 

    vectorRows.forEach((row, rank) => {
        fusionScores[row.id] = { score: (1 / (k + rank + 1)), data: row };
    });

    ftsRows.forEach((row, rank) => {
        if (fusionScores[row.id]) {
            fusionScores[row.id].score += (1 / (k + rank + 1));
        } else {
            fusionScores[row.id] = { score: (1 / (k + rank + 1)), data: row };
        }
    });

    return Object.values(fusionScores)
        .sort((a, b) => b.score - a.score)
        .slice(0, topK)
        .map(item => item.data);
}

const queryWithTimeout = async (sql, params, timeoutMs = 20000) => {
    const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error("POSTGRES_TIMEOUT")), timeoutMs));
    return Promise.race([pool.query(sql, params), timeout]);
};

async function searchCVEs(query) {
    console.log(`\n[RAG] Bắt đầu xử lý cho: "${query}"`);
    
    const cveRegex = /cve-\d{4}-\d{4,7}/gi;
    const cveMatches = query.match(cveRegex);

    if (cveMatches && cveMatches.length > 0) {
        const cveIds = [...new Set(cveMatches.map(id => id.toUpperCase()))];
        console.log(`[RAG] Kích hoạt Fast Track cho: ${cveIds.join(', ')}`);
        
        const placeholders = cveIds.map((_, i) => `$${i + 1}`).join(',');
        const exactMatchSql = `SELECT id, title, description, vendor_product, cvss_score, published_date FROM cves WHERE id IN (${placeholders})`;
        
        try {
            const exactResult = await pool.query(exactMatchSql, cveIds);
            if (exactResult.rows.length > 0) {
                return exactResult.rows.map(row => ({...row, description: row.description.substring(0, 300) + "..."}));
            }
        } catch (e) {
            console.error("[RAG] Lỗi SQL ở Fast Track:", e.message);
        }
    }

    // Trích xuất ý định người dùng
    const intent = await extractSearchIntentJSON(query);
    if (intent.action === "SKIP") {
        console.log("[RAG] AI xác định câu hỏi ngoài lề. Bỏ qua RAG.");
        return [];
    }

    console.log(`[RAG] Ý định trích xuất: Vendor: "${intent.vendor_product || 'N/A'}", Version: "${intent.version || 'N/A'}", Year: ${intent.year || 'N/A'}`);

    const vectorPromise = getEmbeddingFromOpenRouter(intent.english_query || query);
    
    let vectorRows = [];
    let ftsRows = [];

    let ftsSearchString = intent.english_query || "";
    if (!ftsSearchString) {
        if (intent.vendor_product) ftsSearchString += `${intent.vendor_product} `;
        if (intent.version) ftsSearchString += `${intent.version} `;
        if (intent.year) ftsSearchString += `${intent.year}`; 
    }
    ftsSearchString = ftsSearchString.trim();

    try {
        let yearFilter = "";
        if (intent.year) {
            if (Array.isArray(intent.year)) {
                yearFilter = `AND year IN (${intent.year.join(',')})`;
            } else {
                yearFilter = `AND year = ${parseInt(intent.year)}`;
            }
        }

        let ftsQueryPromise = Promise.resolve({ rows: [] });
        if (ftsSearchString !== "") {
            console.log(`   -> [Neon] Đang truy vấn FTS (Từ khóa: [${ftsSearchString}])...`);
            
            const ftsKeywords = ftsSearchString.split(' ').filter(w => w.length > 0).join(' | ');

            const ftsSql = `
                SELECT id, title, description, vendor_product, cvss_score, published_date
                FROM cves
                WHERE (
                    setweight(to_tsvector('english', coalesce(title, '')), 'A') || 
                    setweight(to_tsvector('english', coalesce(description, '')), 'B')
                ) @@ to_tsquery('english', $1)
                ${yearFilter}
                ORDER BY ts_rank_cd(
                    (setweight(to_tsvector('english', coalesce(title, '')), 'A') || 
                    setweight(to_tsvector('english', coalesce(description, '')), 'B')), 
                    to_tsquery('english', $1)
                ) DESC
                LIMIT 50;
            `;
            ftsQueryPromise = queryWithTimeout(ftsSql, [ftsKeywords]).catch(err => {
                console.error("   -> [Neon] Lỗi quét FTS:", err.message);
                return { rows: [] };
            });
        }

        // HNSW Index
        const vector = await vectorPromise;
        let vectorQueryPromise = Promise.resolve({ rows: [] });

        if (vector) {
            console.log("   -> [Neon] Đang truy vấn Vector Semantic...");
            
            // PostgreSQL Vector Syntax: <=> (Cosine Distance)
            const vectorSql = `
                WITH vector_matches AS (
                    SELECT id, title, description, vendor_product, cvss_score, published_date,
                        (embedding <=> $1::vector) AS vector_distance
                    FROM cves
                    WHERE description IS NOT NULL ${yearFilter} -- Lọc đúng năm ở đây
                    ORDER BY embedding <=> $1::vector
                    LIMIT 200
                )
                SELECT id, title, description, vendor_product, cvss_score, published_date
                FROM vector_matches
                ORDER BY vector_distance 
                LIMIT 50;
            `;
            vectorQueryPromise = queryWithTimeout(vectorSql, [JSON.stringify(vector)]).catch(err => {
                console.error("   -> [Neon] Lỗi quét Vector:", err.message);
                return { rows: [] };
            });
        }

        const [vRes, fRes] = await Promise.all([vectorQueryPromise, ftsQueryPromise]);
        
        vectorRows = vRes.rows || [];
        ftsRows = fRes.rows || [];
        
        if (vectorRows.length > 0) console.log(`   -> [Neon] Xong Vector Search (${vectorRows.length} kết quả).`);
        if (ftsRows.length > 0) console.log(`   -> [Neon] Xong FTS Search (${ftsRows.length} kết quả).`);

        // RRF
        let finalRows = reciprocalRankFusion(vectorRows, ftsRows, 10);
        console.log(`[RAG] Hoàn thành! Pass qua RRF được ${finalRows.length} kết quả.`);
        
        return finalRows.map(row => ({
            id: row.id,
            title: row.title,
            description: row.description,
            vendor_product: row.vendor_product,
            cvss_score: row.cvss_score,
            published_date: row.published_date
        }));

    } catch (error) {
        console.error("❌ Lỗi cấu trúc truy vấn DB:", error);
        return [];
    }
}

module.exports = { searchCVEs };