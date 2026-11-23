/**
 * Typora 破解脚本 · 可用版（实测通过：Typora 1.14.17 / Windows）
 *
 * 相对原版 pj.js 的关键修复与发现：
 *  1. [原报错根因] Typora_Installation_Path 硬编码 "D:\Typora"，JS 里 \T 不是转义序列会被吃掉，
 *     实际值 "D:Typora" 是驱动器相对路径，path.join 后按 cwd 解析 →
 *     D:\Typora\resources\Typora\resources\app.asar → ENOENT。
 *     现改为：TYPORA_HOME 环境变量 > 脚本上级目录 > 常见安装路径探测。
 *  2. flipFuses 未 await（v2 API 返回 Promise）→ 竞态，fuse 未写完程序就退出。
 *  3. 注入块使用外层 launch.dist.js 的 const fs → TDZ 崩溃
 *     （ReferenceError: Cannot access 'fs' before initialization）。改为自带 __fs。
 *  4. 注册表许可格式：现代版本是 base64(实体JSON)#0#日期，不是旧的 base64#0#日期。
 *  5. 实体字段必须是本机真实身份，否则静默失效：
 *       deviceId    = "计算机名 | 用户名 | Windows"
 *       fingerprint = base64(sha256(MachineGuid + "typora")) 把 + 换 a 取前 10 位
 *       version     = "win|<Typora 版本>"
 *  6. 注册表改用 native-reg（Typora 自己用的实现），无需 spawn reg.exe；
 *     旧 winreg 在受限环境下会 spawn EPERM。
 *
 * 用法：
 *   node pj-fixed.js                        交互式
 *   node pj-fixed.js --email a@b.c --backup y --debug n
 *   node pj-fixed.js --gencode              只打印本机机器码
 *   node pj-fixed.js --rollback             还原
 */

const asar = require("asar");
const chalk = require("chalk");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execSync } = require("child_process");
const readlineSync = require("readline-sync");
const { flipFuses, FuseV1Options, FuseVersion } = require("@electron/fuses");

let nativeReg = null;
try { nativeReg = require("native-reg"); } catch { nativeReg = null; }
let WinReg = null;
try { WinReg = require("winreg"); } catch { WinReg = null; }

/* ------------------------------------------------------------------ *
 * 0. 路径解析（原报错根因）
 * ------------------------------------------------------------------ */
const SCRIPT_DIR = __dirname;

function resolveTyporaHome() {
    const cands = [
        process.env.TYPORA_HOME,
        path.dirname(SCRIPT_DIR),
        "D:\\Typora",
        "C:\\Program Files\\Typora",
        "C:\\Program Files (x86)\\Typora",
    ].filter(Boolean);
    for (const c of cands) {
        if (fs.existsSync(path.join(c, "Typora.exe")) && fs.existsSync(path.join(c, "resources"))) {
            return path.resolve(c);
        }
    }
    return path.resolve(path.dirname(SCRIPT_DIR));
}

const Typora_Installation_Path = resolveTyporaHome();
const resourcesPath = path.join(Typora_Installation_Path, "resources");
const asarPath = path.join(resourcesPath, "app.asar");
const asarBakPath = path.join(resourcesPath, "app.asar.bak");
const appDir = path.join(resourcesPath, "app");
const appBakDir = path.join(resourcesPath, "app.bak");
const TyporaEXE = path.join(Typora_Installation_Path, "Typora.exe");
const LaunchDistJS = path.join(appDir, "launch.dist.js");
const INJECT_MARK = "/** Hook破解开始 */";

/* ------------------------------------------------------------------ *
 * 1. 本机身份 / 机器码
 * ------------------------------------------------------------------ */
function getMachineGuid() {
    try {
        if (nativeReg) {
            const k = nativeReg.openKey(nativeReg.HKLM, "SOFTWARE\\Microsoft\\Cryptography", nativeReg.Access.QUERY_VALUE);
            const v = nativeReg.getValue(k, null, "MachineGuid");
            nativeReg.closeKey(k);
            if (v) return String(v);
        }
    } catch {}
    try {
        const out = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { encoding: "utf-8" });
        const m = /MachineGuid\s+REG_SZ\s+([0-9a-fA-F-]{36})/.exec(out);
        if (m) return m[1];
    } catch {}
    return "00000000-0000-0000-0000-000000000000";
}

function getAppVersion() {
    for (const p of [path.join(appBakDir, "package.json"), path.join(appDir, "package.json"), path.join(resourcesPath, "package.json")]) {
        try {
            const v = JSON.parse(fs.readFileSync(p, "utf-8")).version;
            if (v) return v;
        } catch {}
    }
    return "1.14.17";
}

function buildIdentity() {
    const guid = getMachineGuid();
    const deviceId = `${process.env.COMPUTERNAME || os.hostname()} | ${process.env.USERNAME || os.userInfo().username} | Windows`;
    // Typora 1.14 实测：fingerprint = base64(sha256(guid + "typora"))，'+' 换 'a'，取前 10 位
    const fingerprint = crypto
        .createHash("sha256")
        .update(guid + "typora")
        .digest("base64")
        .replace(/\+/g, "a")
        .slice(0, 10);
    const version = "win|" + getAppVersion();
    const mc = { v: version, i: fingerprint, l: deviceId };
    return { guid, deviceId, fingerprint, version, machineCode: Buffer.from(JSON.stringify(mc)).toString("base64"), mc };
}

/* ------------------------------------------------------------------ *
 * 2. 注入代码模板
 * ------------------------------------------------------------------ */
function getInsertCode(opts) {
    const { debug, identity, email, dateStr, license } = opts;
    const esc = (s) => String(s == null ? "" : s).replace(/["\\\r\n]/g, "");
    return `
/** Hook破解开始 */
const electron = require("electron");
const __fs = require("fs");

const HookDebug = ${debug ? "true" : "false"};
const LOG_PATH = ".\\\\Typora_Hook_Log.txt";
function writeLog(...data) {
    if (!HookDebug) return;
    try { __fs.appendFileSync(LOG_PATH, data.map(String).join(" ") + "\\n"); } catch {}
}

if (HookDebug) {
    Object.defineProperty(electron.app, "quit", {
        value: function () { writeLog("[拦截] app.quit()"); },
        writable: true,
        configurable: true,
    });
    electron.app.on("browser-window-created", (_e, win) => {
        win.webContents.once("dom-ready", () => {
            try { win.webContents.openDevTools({ mode: "detach" }); } catch {}
        });
    });
}

// 完整性校验规避：resources/app/ -> resources/app.bak/
const fsPathFrom = /resources[\\\\/]app[\\\\/]/i;
const fsPathTo = "resources\\\\app.bak\\\\";
const fsHook = {};
["readFileSync", "readFile", "statSync", "stat", "Stats", "StatsFs", "open", "openSync"].forEach((property) => {
    fsHook[property] = __fs[property];
    __fs[property] = function (filePath, ...args) {
        if (typeof filePath == "string" && fsPathFrom.test(filePath)) {
            const redirectPath = filePath.replace(fsPathFrom, fsPathTo);
            writeLog("[fsHook] " + property + " " + filePath + " -> " + redirectPath);
            return fsHook[property].call(this, redirectPath, ...args);
        }
        return fsHook[property].call(this, filePath, ...args);
    };
});
const fsPromisesHook = {};
["readFile", "open", "stat"].forEach((property) => {
    fsPromisesHook[property] = __fs.promises[property];
    __fs.promises[property] = async function (filePath, ...args) {
        if (typeof filePath == "string" && fsPathFrom.test(filePath)) {
            return fsPromisesHook[property].call(this, filePath.replace(fsPathFrom, fsPathTo), ...args);
        }
        return fsPromisesHook[property].call(this, filePath, ...args);
    };
});

// 许可实体验证：直接吞掉 crypto.publicDecrypt，返回本机伪造实体
const FAKE_LICENSE = JSON.stringify({
    deviceId: "${esc(identity.deviceId)}",
    fingerprint: "${esc(identity.fingerprint)}",
    email: "${esc(email)}",
    license: "${esc(license)}",
    version: "${esc(identity.version)}",
    date: "${esc(dateStr)}",
    type: "USER",
});

const crypto = require("crypto");
const originalPublicDecrypt = crypto.publicDecrypt;
crypto.publicDecrypt = function (key, buffer) {
    writeLog("[publicDecrypt] 返回伪造实体");
    return Buffer.from(FAKE_LICENSE);
};

// 联网校验：拦截 renew 请求返回成功
electron.app.whenReady().then(() => {
    try {
        electron.protocol.handle("https", async (request) => {
            const url = request.url;
            writeLog("[net] " + request.method + " " + url);
            if (/^https:\\/\\/store\\.typora\\.io\\/api\\/client\\/renew/i.test(url)) {
                writeLog("[拦截] 伪造 renew 响应");
                return new Response(
                    JSON.stringify({ success: true, msg: Buffer.from("DreamNya").toString("base64") }),
                    { status: 200, headers: { "content-type": "application/json" } }
                );
            }
            return electron.net.fetch(request, { bypassCustomProtocolHandlers: true });
        });
    } catch (e) {
        writeLog("[!] protocol.handle 注册失败: " + e.message);
    }
});
/** Hook破解结束 */
`;
}

/* ------------------------------------------------------------------ *
 * 3. 工具
 * ------------------------------------------------------------------ */
function getNowDateStr() {
    const now = new Date();
    return `${String(now.getMonth() + 1).padStart(2, "0")}/${String(now.getDate()).padStart(2, "0")}/${now.getFullYear()}`;
}
const nowDateStr = getNowDateStr();

const generateRegCode = () => {
    const chars = "L23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    let s = "";
    for (let i = 0; i < 24; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return [s.slice(0, 6), s.slice(6, 12), s.slice(12, 18), s.slice(18, 24)].join("-");
};

function parseArgs(argv) {
    const out = {};
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a.startsWith("--")) {
            const k = a.slice(2);
            const n = argv[i + 1];
            if (n && !n.startsWith("--")) { out[k] = n; i++; } else { out[k] = true; }
        }
    }
    return out;
}
const ARGS = parseArgs(process.argv.slice(2));

const hasTTY = () => { try { return !!(process.stdin && process.stdin.isTTY); } catch { return false; } };
const safeAsk = (label, def) => {
    if (!hasTTY()) return def;
    try { return readlineSync.question(chalk.cyan(label)); } catch { return def; }
};

const ok = (m) => console.log(chalk.green("  [OK] " + m));
const info = (m) => console.log(chalk.yellow("  [··] " + m));
const bad = (m) => console.log(chalk.red("  [!!] " + m));

function closeTypora() {
    try { execSync("taskkill /F /IM Typora.exe", { stdio: "ignore" }); } catch {}
    try {
        const { execSync: e2 } = require("child_process");
        e2("powershell -NoProfile -Command \"Get-Process Typora -EA SilentlyContinue | Stop-Process -Force\"", { stdio: "ignore" });
    } catch {}
}

async function regSetString(name, value) {
    if (nativeReg) {
        const k = nativeReg.createKey(nativeReg.HKCU, "Software\\Typora", nativeReg.Access.ALL_ACCESS);
        nativeReg.setValueSZ(k, name, value);
        nativeReg.closeKey(k);
        return "native-reg";
    }
    if (!WinReg) throw new Error("无可用注册表实现");
    const key = new WinReg({ hive: WinReg.HKCU, key: "\\Software\\Typora" });
    await new Promise((res, rej) => key.set(name, WinReg.REG_SZ, value, (e) => (e ? rej(e) : res())));
    return "winreg";
}

function copyDir(src, dest) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
        const s = path.join(src, entry.name);
        const d = path.join(dest, entry.name);
        if (entry.isDirectory()) copyDir(s, d);
        else fs.copyFileSync(s, d);
    }
}

/* ------------------------------------------------------------------ *
 * 4. 主流程
 * ------------------------------------------------------------------ */
async function main() {
    const identity = buildIdentity();

    if (ARGS.gencode) {
        console.log(chalk.yellow("deviceId    : " + identity.deviceId));
        console.log(chalk.yellow("fingerprint : " + identity.fingerprint));
        console.log(chalk.yellow("version     : " + identity.version));
        console.log(chalk.green("机器码: " + identity.machineCode));
        return;
    }

    if (ARGS.rollback) {
        closeTypora();
        if (fs.existsSync(appDir)) fs.rmSync(appDir, { recursive: true, force: true });
        if (fs.existsSync(asarBakPath)) fs.renameSync(asarBakPath, asarPath);
        if (fs.existsSync(TyporaEXE + ".bak")) fs.copyFileSync(TyporaEXE + ".bak", TyporaEXE);
        ok("已回滚");
        return;
    }

    console.log(chalk.cyan("Typora 目录 : " + Typora_Installation_Path));
    console.log(chalk.cyan("deviceId    : " + identity.deviceId));
    console.log(chalk.cyan("fingerprint : " + identity.fingerprint));
    console.log(chalk.cyan("version     : " + identity.version));

    if (!fs.existsSync(TyporaEXE)) {
        bad("找不到 " + TyporaEXE + "，用 TYPORA_HOME 指定安装目录");
        process.exit(1);
    }
    const sourceAsar = fs.existsSync(asarPath) ? asarPath : fs.existsSync(asarBakPath) ? asarBakPath : null;
    if (!sourceAsar) {
        bad("找不到 app.asar / app.asar.bak，请重装 Typora 后重试");
        process.exit(1);
    }
    ok("asar: " + sourceAsar);

    const email = ARGS.email && ARGS.email !== true ? String(ARGS.email) : (safeAsk("请输入邮箱: ", "local@typora.local") || "").trim() || "local@typora.local";
    const backup = ARGS.backup !== undefined ? String(ARGS.backup).toLowerCase() !== "n" : (safeAsk("是否备份？(Y/n): ", "y") || "y").toLowerCase() !== "n";
    const debug = ARGS.debug !== undefined ? String(ARGS.debug).toLowerCase() === "y" : (safeAsk("是否开启调试日志？(y/N): ", "n") || "n").toLowerCase() === "y";

    // 许可实体：license 必须符合 ^([A-Z0-9]{6}-){3}[A-Z0-9]{6}$
    const license = (ARGS.license && ARGS.license !== true) ? String(ARGS.license) : generateRegCode();

    closeTypora();
    console.log(chalk.green("==== 开始破解 ===="));

    /* 一、解包 */
    console.log(chalk.yellow("\n一、解包 app.asar"));
    if (fs.existsSync(LaunchDistJS)) info("resources/app 已存在，跳过解包");
    else { asar.extractAll(sourceAsar, appDir); ok("已解包到 " + appDir); }
    if (!fs.existsSync(LaunchDistJS)) { bad("解包后找不到 launch.dist.js"); process.exit(1); }

    /* 二、备份 app（应对完整性校验） */
    if (fs.existsSync(path.join(appBakDir, "launch.dist.js"))) info("app.bak 已存在");
    else { copyDir(appDir, appBakDir); ok("已复制 app → app.bak"); }

    /* 三、移除 app.asar */
    if (fs.existsSync(asarPath)) {
        if (backup) {
            if (fs.existsSync(asarBakPath)) fs.rmSync(asarBakPath, { force: true });
            fs.renameSync(asarPath, asarBakPath);
            ok("app.asar → app.asar.bak");
        } else {
            fs.rmSync(asarPath, { force: true });
            ok("app.asar 已删除");
        }
    } else info("app.asar 已不在");

    /* 四、fuse */
    console.log(chalk.yellow("\n二、翻转 fuse（OnlyLoadAppFromAsar=false）"));
    if (backup && !fs.existsSync(TyporaEXE + ".bak")) { fs.copyFileSync(TyporaEXE, TyporaEXE + ".bak"); ok("Typora.exe 已备份"); }
    try {
        await flipFuses(TyporaEXE, { version: FuseVersion.V1, [FuseV1Options.OnlyLoadAppFromAsar]: false });
        ok("fuse 已翻转");
    } catch (e) {
        if (/already/i.test(String(e && e.message))) ok("fuse 已是目标状态");
        else bad("fuse 翻转失败: " + (e && e.message));
    }

    /* 五、注入 */
    console.log(chalk.yellow("\n三、注入 Hook"));
    let content = fs.readFileSync(LaunchDistJS, "utf-8");
    if (content.includes(INJECT_MARK)) {
        content = content.replace(/\/\*\* Hook破解开始 \*\/[\s\S]*?\/\*\* Hook破解结束 \*\/\r?\n?/, "");
        info("剥离旧注入");
    }
    const insert = getInsertCode({ debug, identity, email, dateStr: nowDateStr, license });
    const strict = /^"use strict";/.exec(content);
    const pos = strict ? strict[0].length : 0;
    content = content.slice(0, pos) + insert + content.slice(pos);
    fs.writeFileSync(LaunchDistJS, content, "utf-8");
    ok("已注入（offset=" + pos + "，大小 " + content.length + "）");

    /* 六、注册表 */
    console.log(chalk.yellow("\n四、写入许可"));
    const entity = {
        deviceId: identity.deviceId,
        fingerprint: identity.fingerprint,
        email,
        license,
        version: identity.version,
        date: nowDateStr,
        type: "USER",
    };
    const token = Buffer.from(JSON.stringify(entity), "utf-8").toString("base64") + "#0#" + nowDateStr;
    for (const [k, v] of [["SLicense", token], ["IDate", nowDateStr]]) {
        try { ok(`${k} 写入成功（via ${await regSetString(k, v)}）`); }
        catch (e) { bad(`${k} 写入失败: ${e && (e.message || e)}`); }
    }

    console.log(chalk.green("\n==== 完成 ===="));
    console.log(chalk.green("  许可 key : " + license));
    console.log(chalk.green("  邮箱     : " + email));
    console.log(chalk.yellow("  启动 Typora 后 帮助 → 我的许可证 查看状态；建议关闭自动更新"));
    console.log(chalk.yellow("  回滚: node " + path.basename(__filename) + " --rollback"));
}

main().catch((e) => {
    console.error(chalk.red("执行失败:"), e);
    process.exit(1);
});
