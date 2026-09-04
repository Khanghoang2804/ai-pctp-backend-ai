// file: server/controllers/scanController.js
const fs = require('fs');
const path = require('path');
const AdmZip = require('adm-zip');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const PYTHON_API_URL = process.env.PYTHON_API_URL || 'http://localhost:8000';
const SCAN_LAYER3_LIMIT = Number(process.env.SCAN_LAYER3_LIMIT || '999');
const PYTHON_HTTP_TIMEOUT_MS = Number(process.env.PYTHON_HTTP_TIMEOUT_MS || String(90 * 60 * 1000));

// ==========================================
// 1. QUẢN LÝ TIẾN TRÌNH & KẾT QUẢ QUÉT
// ==========================================
global.scanProgress = {};
global.scanResults = {};
const cpgHashCache = {};

function computeRepoHash(dirPath) {
    try {
        const files = [];
        function readDirRecursive(d) {
            const items = fs.readdirSync(d);
            for (const item of items) {
                if (item.startsWith('.')) continue;
                const full = path.join(d, item);
                const stat = fs.statSync(full);
                if (stat.isDirectory()) {
                    readDirRecursive(full);
                } else {
                    files.push(full);
                }
            }
        }
        readDirRecursive(dirPath);
        files.sort();
        const hash = crypto.createHash('sha256');
        for (const file of files.slice(0, 100)) {
            try {
                hash.update(fs.readFileSync(file));
            } catch(e) {}
        }
        return hash.digest('hex');
    } catch(e) {
        return null;
    }
}

function setScanProgress(scanId, percent, stage, status = 'processing') {
    global.scanProgress[scanId] = { 
        ...(global.scanProgress[scanId] || {}),
        percent, 
        stage, 
        status 
    };
}

exports.getScanProgress = (req, res) => {
    const { scanId } = req.params;
    const progress = global.scanProgress[scanId] || {
        percent: 0,
        stage: 'Không tìm thấy tiến trình quét',
        status: 'unknown',
    };
    const result = global.scanResults[scanId];
    const payload = { success: true, scanId, ...progress };

    if (progress.status === 'done' && result) {
        payload.graph = result.graph;
        payload.vulns = result.vulns;
    }
    if (progress.status === 'error') {
        payload.message = progress.message || progress.stage;
    }

    // Đọc live logs từ file .agent_logs.txt (nếu có)
    if (progress.actualRepoPath) {
        const logPath = path.join(progress.actualRepoPath, '.agent_logs.txt');
        if (fs.existsSync(logPath)) {
            try {
                payload.live_logs = fs.readFileSync(logPath, 'utf8');
            } catch (e) {
                console.error("Lỗi đọc live logs:", e);
            }
        }
    }

    res.json(payload);
};

// ==========================================
// 2. PIPELINE QUÉT (CHẠY NỀN SAU KHI TRẢ scanId)
// ==========================================
async function runScanPipeline(scanId, input) {
    const { githubUrl, githubToken, branch, uploadedFilePath } = input;
    let zipFilePath = '';
    const targetDir = path.resolve(__dirname, '..', 'temp_uploads', scanId);
    fs.mkdirSync(targetDir, { recursive: true });

    const axiosConfig = {
        headers: { 'Content-Type': 'application/json' },
        timeout: PYTHON_HTTP_TIMEOUT_MS,
    };

    // A. TẢI FILE ZIP TỪ GITHUB
    if (githubUrl) {
        setScanProgress(scanId, 5, 'Đang tải mã nguồn từ GitHub...');
        const repoPath = githubUrl.replace('https://github.com/', '').replace(/\/$/, '');
        const targetBranch = branch || 'main';
        const downloadUrl = `https://api.github.com/repos/${repoPath}/zipball/${targetBranch}`;
        zipFilePath = path.join(targetDir, 'repo.zip');

        const dlConfig = { method: 'get', url: downloadUrl, responseType: 'stream' };
        if (githubToken && githubToken !== 'null') {
            dlConfig.headers = {
                Authorization: `token ${githubToken}`,
                Accept: 'application/vnd.github.v3+json',
            };
        }

        const response = await axios(dlConfig);
        const writer = fs.createWriteStream(zipFilePath);
        response.data.pipe(writer);
        await new Promise((resolve, reject) => {
            writer.on('finish', resolve);
            writer.on('error', reject);
        });
    } else if (uploadedFilePath) {
        setScanProgress(scanId, 5, 'Đang tiếp nhận tệp ZIP...');
        zipFilePath = uploadedFilePath;
    } else {
        throw new Error('Thiếu file ZIP hoặc link GitHub.');
    }

    // B. GIẢI NÉN
    setScanProgress(scanId, 12, 'Đang giải nén mã nguồn...');
    const zip = new AdmZip(zipFilePath);
    zip.extractAllTo(targetDir, true);
    if (fs.existsSync(zipFilePath)) fs.rmSync(zipFilePath, { force: true });

    let actualRepoPath = targetDir;
    const extractedItems = fs.readdirSync(targetDir);
    if (extractedItems.length === 1) {
        const firstItemPath = path.join(targetDir, extractedItems[0]);
        if (fs.statSync(firstItemPath).isDirectory()) {
            actualRepoPath = firstItemPath;
        }
    }

    // B.1. CPG HASH CACHE CHECK
    const repoHash = computeRepoHash(actualRepoPath);
    if (repoHash && cpgHashCache[repoHash]) {
        console.log(`[CPG Cache HIT] Returning cached graph for SHA-256: ${repoHash.substring(0, 12)}`);
        global.scanResults[scanId] = cpgHashCache[repoHash];
        setScanProgress(scanId, 100, 'Fast-served from CPG Hash Cache (0ms)!', 'done');
        return;
    }

    const serverTempUploadsDir = path.resolve(__dirname, '..', 'temp_uploads');
    const containerRepoPath = actualRepoPath.replace(serverTempUploadsDir, '/app/temp_uploads').replace(/\\/g, '/');
    console.log(`[Node.js] Path gửi cho Docker: ${containerRepoPath}`);

    // C. ANALYZE & SYNC
    setScanProgress(scanId, 30, 'Engine đang phân tích AST và tạo Graph...');
    const analyzeRes = await axios.post(
        `${PYTHON_API_URL}/ast/analyze`,
        {
            repo_path: containerRepoPath,
            force: false,
            include_content: true,
            replace_repo: true,
        },
        axiosConfig
    );

    const repoName = analyzeRes.data.repo_name;
    if (!repoName) throw new Error('Không lấy được repo_name từ Python API.');

    // Save targetDir and repoName to progress state for live logs reading
    if (global.scanProgress[scanId]) {
        global.scanProgress[scanId].targetDir = targetDir;
        global.scanProgress[scanId].repoName = repoName;
        global.scanProgress[scanId].actualRepoPath = actualRepoPath;
    }

    // D. FULL GRAPH
    setScanProgress(scanId, 52, 'Đang trích xuất cấu trúc Đồ thị Tri thức...');
    const graphRes = await axios.post(
        `${PYTHON_API_URL}/ast/parse-full-graph`,
        {
            repo_name: repoName,
            excluded_labels: ["Community", "Process"],
            excluded_rel_types: [],
            limit_nodes: 5000,
            offset_nodes: 0,
        },
        axiosConfig
    );

    const graphData = {
        nodes: graphRes.data.nodes || [],
        edges: graphRes.data.edges || [],
    };

    // E. SCAN LAYERS (L1 + L2 + L3)
    setScanProgress(scanId, 72, 'Hệ thống đang phân tích lỗ hổng...');
    const scanRes = await axios.post(
        `${PYTHON_API_URL}/scan/layers`,
        {
            repo_name: repoName,
            repo_root: containerRepoPath,
            prompt_dump_dir: null,
            layer3_limit: SCAN_LAYER3_LIMIT,
            depth: 2,
            debug_prompt: false,
        },
        axiosConfig
    );

    const scanOutput = {
        graph: graphData,
        vulns: scanRes.data.layer3_results || [],
    };

    if (repoHash) {
        cpgHashCache[repoHash] = scanOutput;
    }

    global.scanResults[scanId] = scanOutput;
    setScanProgress(scanId, 100, 'Hoàn tất phân tích!', 'done');
}

exports.uploadAndExtract = async (req, res) => {
    const scanId = `scan_${crypto.randomUUID()}`;

    try {
        const githubUrl = req.body?.githubUrl;
        const githubToken = req.body?.githubToken;
        const branch = req.body?.branch;
        const uploadedFile = req.file;

        if (!githubUrl && !uploadedFile) {
            return res.status(400).json({ success: false, message: 'Thiếu file ZIP hoặc link GitHub.' });
        }

        setScanProgress(scanId, 0, 'Đã nhận yêu cầu, đang chuẩn bị...', 'processing');

        const jobInput = {
            githubUrl,
            githubToken,
            branch,
            uploadedFilePath: uploadedFile?.path,
        };

        // Trả scanId ngay để FE poll progress
        res.status(202).json({ success: true, scanId, status: 'processing' });

        runScanPipeline(scanId, jobInput).catch((error) => {
            console.error('Lỗi Real Scan:', error.response?.data || error.message);
            const message = error.response?.data?.detail || error.message || 'Lỗi hệ thống';
            global.scanProgress[scanId] = {
                percent: 0,
                stage: message,
                status: 'error',
                message,
            };
        });
    } catch (error) {
        console.error('Lỗi khởi tạo scan:', error.message);
        res.status(500).json({ success: false, message: error.message });
    }
};

// ==========================================
// 3. DUMMY CÁC ENDPOINT ĐÃ BỎ
// ==========================================
exports.analyzeAstAndLlm = (req, res) => {
    res.json({ success: true, message: 'Đã gộp vào uploadAndExtract khi dùng Python.' });
};
exports.getFullGraph = (req, res) => {
    res.json({ success: true, nodes: [], edges: [] });
};

exports.loadMoreGraph = async (req, res) => {
    try {
        const { repo_name, offset } = req.body;
        if (!repo_name) {
            return res.status(400).json({ success: false, message: 'Thiếu repo_name' });
        }
        
        const axiosConfig = {
            timeout: 600000,
            maxContentLength: Infinity,
            maxBodyLength: Infinity,
        };
        
        const graphRes = await axios.post(
            `${PYTHON_API_URL}/ast/parse-full-graph`,
            {
                repo_name: repo_name,
                excluded_labels: ["Community", "Process"],
                excluded_rel_types: [],
                limit_nodes: 500,
                offset_nodes: offset || 0,
            },
            axiosConfig
        );
        
        res.json({ success: true, graph: { nodes: graphRes.data.nodes || [], edges: graphRes.data.edges || [] } });
    } catch (error) {
        console.error('Lỗi loadMoreGraph:', error.message);
        res.status(500).json({ success: false, message: error.message });
    }
};

// ==========================================
// 4. AI FIX & EXPLAIN
// ==========================================
exports.generatePatch = async (req, res) => {
    const { issue, snippet, language } = req.body;
    if (!snippet) return res.status(400).json({ success: false, message: 'Thiếu đoạn code cần vá.' });
    try {
        const prompt = `Bạn là một chuyên gia bảo mật. Dưới đây là đoạn code bị lỗ hổng:\nLỗi: ${issue}\nCode:\n${snippet}\nHãy viết lại đoạn code này sao cho an toàn nhất (Vá lỗ hổng). CHỈ TRẢ VỀ ĐOẠN CODE ĐÃ ĐƯỢC VÁ.`;
        const openRouterResponse = await axios.post(
            'https://openrouter.ai/api/v1/chat/completions',
            {
                model: 'minimax/minimax-m2.5',
                messages: [{ role: 'user', content: prompt }],
                temperature: 0.1,
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );
        let patchedCode = openRouterResponse.data.choices[0].message.content.trim();
        patchedCode = patchedCode.replace(/^```[a-z]*\n/gi, '').replace(/```$/g, '').trim();
        res.status(200).json({ success: true, patchedCode });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Không thể tạo bản vá lúc này.' });
    }
};

exports.explainVulnerability = async (req, res) => {
    const { issue, snippet } = req.body;
    if (!snippet || !issue) return res.status(400).json({ success: false, message: 'Thiếu thông tin lỗ hổng.' });
    try {
        const prompt = `Bạn là chuyên gia AppSec. Có đoạn code lỗi:\nTên lỗi: ${issue}\nCode:\n${snippet}\nHãy giải thích ngắn gọn (3-4 câu tiếng Việt): 1. Đoạn code này đang làm gì? 2. Hacker có thể lợi dụng như thế nào?`;
        const openRouterResponse = await axios.post(
            'https://openrouter.ai/api/v1/chat/completions',
            {
                model: 'minimax/minimax-m2.5',
                messages: [{ role: 'user', content: prompt }],
                temperature: 0.3,
            },
            {
                headers: {
                    Authorization: `Bearer ${process.env.OPENROUTER_API_KEY}`,
                    'Content-Type': 'application/json',
                },
            }
        );
        const explanation = openRouterResponse.data.choices[0].message.content.trim();
        res.status(200).json({ success: true, explanation });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Không thể giải thích lúc này.' });
    }
};

// ==========================================
// 5. GITHUB OAUTH
// ==========================================
exports.getGithubAccessToken = async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ message: 'Thiếu mã xác thực GitHub' });

    try {
        const response = await axios.post(
            'https://github.com/login/oauth/access_token',
            {
                client_id: process.env.GITHUB_CLIENT_ID,
                client_secret: process.env.GITHUB_CLIENT_SECRET,
                code: code,
            },
            { headers: { Accept: 'application/json' } }
        );

        if (response.data.error) return res.status(400).json({ message: response.data.error_description });
        res.json({ accessToken: response.data.access_token });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi kết nối máy chủ GitHub' });
    }
};

exports.getGithubRepos = async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Không tìm thấy token' });

    try {
        const response = await axios.get('https://api.github.com/user/repos?sort=updated&per_page=100', {
            headers: { Authorization: `token ${token}`, Accept: 'application/vnd.github.v3+json' },
        });

        const repos = response.data.map((repo) => ({
            id: repo.id,
            name: repo.name,
            fullName: repo.full_name,
            private: repo.private,
            branch: repo.default_branch,
        }));
        res.json({ repos });
    } catch (error) {
        res.status(500).json({ message: 'Lỗi khi lấy danh sách Repositories' });
    }
};
