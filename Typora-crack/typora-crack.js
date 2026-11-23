#!/usr/bin/env node
/**
 * Typora 激活脚本（Windows / Typora 1.14.x 实测通过）
 * ---------------------------------------------------------------
 * 一条命令完成：解包 asar → 翻转 fuse → 注入 Hook → 写入许可
 *
 *   node typora-crack.js            破解
 *   node typora-crack.js --verify   自检
 *   node typora-crack.js --rollback 还原
 *   node typora-crack.js --gencode  只看本机机器码
 *
 * 原理见同目录《Typora破解教程.md》
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const cp = require("child_process");

const SCRIPT_DIR = __dirname;
const INJECT_MARK = "/** Hook破解开始 */";

/* ================================================================== *
 * 一、定位 Typora 安装目录
 * ================================================================== */
function parseArgs(argv) {
    const out = {};
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (!a.startsWith("--")) continue;
        const k = a.slice(2);
        const next = argv[i + 1];
        if (next && !next.startsWith("--")) { out[k] = next; i++; }
        else out[k] = true;
    }
    return out;
}
const ARGS = parseArgs(process.argv.slice(2));

function registryQuery(key, value) {
    try {
        const out = cp.execSync(`reg query "${key}" /v "${value}"`, { encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] });
        const m = new RegExp(`${value}\\s+REG_SZ\\s+(.+)$`, "m").exec(out);
        return m ? m[1].trim() : null;
    } catch { return null; }
}

function detectTyporaHome() {
    const candidates = [
        ARGS.dir && ARGS.dir !== true ? String(ARGS.dir) : null,
        process.env.TYPORA_HOME,
        path.dirname(SCRIPT_DIR),                                          // 脚本放在 <Typora>\resources 下
        // 注册表卸载信息
        (() => {
            const p = registryQuery("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Typora", "InstallLocation")
                || registryQuery("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Typora", "InstallLocation");
            return p ? p.replace(/[\\/]+$/, "") : null;
        })(),
        "D:\\Typora",
        "C:\\Program Files\\Typora",
        "C:\\Program Files (x86)\\Typora",
        path.join(process.env.LOCALAPPDATA || "", "Programs", "Typora"),
    ].filter(Boolean);

    for (const c of candidates) {
        if (fs.existsSync(path.join(c, "Typora.exe"))) return path.resolve(c);
    }
    console.error("[!] 找不到 Typora 安装目录，请用 --dir \"D:\\Typora\" 指定");
    process.exit(1);
}

const HOME = detectTyporaHome();
const RES = path.join(HOME, "resources");
const TyporaEXE = path.join(HOME, "Typora.exe");
const asarPath = path.join(RES, "app.asar");
const asarBakPath = path.join(RES, "app.asar.bak");
const appDir = path.join(RES, "app");
const appBakDir = path.join(RES, "app.bak");
const launchJS = path.join(appDir, "launch.dist.js");

/* ================================================================== *
 * 二、加载依赖（优先用 Typora 自带的 node_modules，缺失则自动装）
 * ================================================================== */
module.paths.push(path.join(RES, "node_modules"), path.join(SCRIPT_DIR, "node_modules"));

function need(mod) {
    try { return require(mod); } catch { return null; }
}

function bootstrapDeps() {
    const missing = [];
    for (const m of ["asar", "@electron/fuses"]) if (!need(m)) missing.push(m);
    if (missing.length) {
        console.log("[..] 缺少依赖：" + missing.join(", ") + "，正在安装...");
        cp.execSync(`npm install --no-save ${missing.join(" ")}`, { cwd: SCRIPT_DIR, stdio: "inherit" });
    }
    return { asar: require("asar"), fuses: require("@electron/fuses") };
}

let nativeReg = null;
function regSet(name, value) {
    nativeReg = nativeReg || need("native-reg");
    if (nativeReg) {
        const k = nativeReg.createKey(nativeReg.HKCU, "Software\\Typora", nativeReg.Access.ALL_ACCESS);
        nativeReg.setValueSZ(k, name, value);
        nativeReg.closeKey(k);
        return "native-reg";
    }
    // 回退：reg.exe
    cp.execSync(`reg add "HKCU\\Software\\Typora" /v "${name}" /t REG_SZ /d "${value}" /f`, { stdio: "ignore" });
    return "reg.exe";
}

/* ================================================================== *
 * 三、本机身份（1.14 的许可实体必须与之一致，否则静默失效）
 * ================================================================== */
function getMachineGuid() {
    const v = registryQuery("HKLM\\SOFTWARE\\Microsoft\\Cryptography", "MachineGuid");
    return v || "00000000-0000-0000-0000-000000000000";
}

function getAppVersion() {
    for (const p of [path.join(RES, "package.json"), path.join(appBakDir, "package.json"), path.join(appDir, "package.json")]) {
        try {
            const v = JSON.parse(fs.readFileSync(p, "utf-8")).version;
            if (v) return v;
        } catch {}
    }
    return "1.14.17";
}

function buildIdentity() {
    const guid = getMachineGuid();
    const deviceId = [
        process.env.COMPUTERNAME || os.hostname(),
        process.env.USERNAME || (os.userInfo().username || ""),
        "Windows",
    ].join(" | ");
    const fingerprint = crypto
        .createHash("sha256")
        .update(guid + "typora")
        .digest("base64")
        .replace(/\+/g, "a")
        .slice(0, 10);
    const version = "win|" + getAppVersion();
    return { guid, deviceId, fingerprint, version };
}

function today() {
    const d = new Date();
    return `${String(d.getMonth() + 1).padStart(2, "0")}/${String(d.getDate()).padStart(2, "0")}/${d.getFullYear()}`;
}

function newLicenseKey() {
    const A = "L23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    let s = "";
    for (let i = 0; i < 24; i++) s += A[Math.floor(Math.random() * A.length)];
    return [s.slice(0, 6), s.slice(6, 12), s.slice(12, 18), s.slice(18, 24)].join("-");
}

/* ================================================================== *
 * 四、注入的 Hook 代码
 * ================================================================== */
function buildHook(entity, debug) {
    const e = entity;
    const esc = (s) => String(s == null ? "" : s).replace(/["\\\r\n]/g, "");
    return `
/** Hook破解开始 */
const electron = require("electron");
const __fs = require("fs");
const HookDebug = ${debug ? "true" : "false"};
const LOG_PATH = ".\\\\Typora_Hook_Log.txt";
function writeLog(...d) {
    if (!HookDebug) return;
    try { __fs.appendFileSync(LOG_PATH, d.map(String).join(" ") + "\\n"); } catch {}
}

// 1) 完整性校验规避：凡读 resources/app/ 一律改读 resources/app.bak/
//    注意必须用本块自带的 __fs：注入位置在外层 const fs 声明之前，直接用 fs 会 TDZ 崩溃
const fsPathFrom = /resources[\\\\/]app[\\\\/]/i;
const fsPathTo = "resources\\\\app.bak\\\\";
const fsHook = {};
["readFileSync", "readFile", "statSync", "stat", "Stats", "StatsFs", "open", "openSync"].forEach((p) => {
    fsHook[p] = __fs[p];
    __fs[p] = function (file, ...args) {
        if (typeof file == "string" && fsPathFrom.test(file)) {
            writeLog("[fs] " + p + " " + file + " -> " + file.replace(fsPathFrom, fsPathTo));
            return fsHook[p].call(this, file.replace(fsPathFrom, fsPathTo), ...args);
        }
        return fsHook[p].call(this, file, ...args);
    };
});
const fsPromisesHook = {};
["readFile", "open", "stat"].forEach((p) => {
    fsPromisesHook[p] = __fs.promises[p];
    __fs.promises[p] = async function (file, ...args) {
        if (typeof file === "string" && fsPathFrom.test(file)) {
            return fsPromisesHook[p].call(this, file.replace(fsPathFrom, fsPathTo), ...args);
        }
        return fsPromisesHook[p].call(this, file, ...args);
    };
});

// 2) 许可校验核心：Typora 用 crypto.publicDecrypt 解许可密文，这里直接返回伪造实体
const crypto = require("crypto");
const FAKE_LICENSE = JSON.stringify({
    deviceId: "${esc(e.deviceId)}",
    fingerprint: "${esc(e.fingerprint)}",
    email: "${esc(e.email)}",
    license: "${esc(e.license)}",
    version: "${esc(e.version)}",
    date: "${esc(e.date)}",
    type: "USER",
});
crypto.publicDecrypt = function () {
    writeLog("[publicDecrypt] 返回伪造实体");
    return Buffer.from(FAKE_LICENSE);
};

// 3) 联网续期：拦掉 renew 请求，直接回成功
electron.app.whenReady().then(() => {
    try {
        electron.protocol.handle("https", async (request) => {
            if (/^https:\\/\\/store\\.typora\\.io\\/api\\/client\\/renew/i.test(request.url)) {
                writeLog("[拦截] renew");
                return new Response(
                    JSON.stringify({ success: true, msg: Buffer.from("DreamNya").toString("base64") }),
                    { status: 200, headers: { "content-type": "application/json" } }
                );
            }
            return electron.net.fetch(request, { bypassCustomProtocolHandlers: true });
        });
    } catch (err) { writeLog("[!] protocol " + err.message); }
});
/** Hook破解结束 */
`;
}

/* ================================================================== *
 * 五、工具
 * ================================================================== */
const c = {
    green: (s) => `\x1b[32m${s}\x1b[0m`,
    yellow: (s) => `\x1b[33m${s}\x1b[0m`,
    red: (s) => `\x1b[31m${s}\x1b[0m`,
    cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};
const log = {
    ok: (m) => console.log(c.green("  [OK] ") + m),
    step: (m) => console.log(c.yellow(m)),
    err: (m) => console.log(c.red("  [!!] ") + m),
};

function killTypora() {
    try { cp.execSync("taskkill /F /IM Typora.exe", { stdio: "ignore" }); } catch {}
}

function copyDir(src, dest) {
    if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
    for (const ent of fs.readdirSync(src, { withFileTypes: true })) {
        const s = path.join(src, ent.name), d = path.join(dest, ent.name);
        if (ent.isDirectory()) copyDir(s, d);
        else fs.copyFileSync(s, d);
    }
}

/* ================================================================== *
 * 六、主流程
 * ================================================================== */
async function main() {
    const identity = buildIdentity();
    const dateStr = today();

    console.log(c.cyan("Typora : " + HOME));
    console.log(c.cyan("deviceId    : " + identity.deviceId));
    console.log(c.cyan("fingerprint : " + identity.fingerprint));
    console.log(c.cyan("version     : " + identity.version));

    if (ARGS.gencode) {
        const mc = Buffer.from(JSON.stringify({
            v: identity.version, i: identity.fingerprint, l: identity.deviceId,
        })).toString("base64");
        console.log(c.green("机器码: " + mc));
        return;
    }

    if (ARGS.rollback) {
        killTypora();
        if (fs.existsSync(appDir)) fs.rmSync(appDir, { recursive: true, force: true });
        if (fs.existsSync(asarBakPath)) fs.renameSync(asarBakPath, asarPath);
        if (fs.existsSync(TyporaEXE + ".bak")) fs.copyFileSync(TyporaEXE + ".bak", TyporaEXE);
        log.ok("已还原（app 目录删除、app.asar 与 Typora.exe 复原）");
        return;
    }

    if (ARGS.verify) {
        const checks = [
            ["resources/app 已解包", fs.existsSync(launchJS)],
            ["Hook 已注入", fs.existsSync(launchJS) && fs.readFileSync(launchJS, "utf-8").includes(INJECT_MARK)],
            ["app.asar 已移除", !fs.existsSync(asarPath)],
            ["原 asar 已备份", fs.existsSync(asarBakPath)],
            ["Typora.exe 已备份", fs.existsSync(TyporaEXE + ".bak")],
            ["SLicense 已写入", !!registryQuery("HKCU\\Software\\Typora", "SLicense")],
        ];
        for (const [name, okFlag] of checks) (okFlag ? log.ok : log.err)(name);
        return;
    }

    const { asar, fuses } = bootstrapDeps();

    const email = ARGS.email && ARGS.email !== true ? String(ARGS.email) : "local@typora.local";
    const license = ARGS.license && ARGS.license !== true ? String(ARGS.license) : newLicenseKey();
    const debug = String(ARGS.debug || "n").toLowerCase() === "y";

    if (!fs.existsSync(TyporaEXE)) { log.err("Typora.exe 不存在"); process.exit(1); }
    const sourceAsar = fs.existsSync(asarPath) ? asarPath : (fs.existsSync(asarBakPath) ? asarBakPath : null);
    if (!sourceAsar) { log.err("找不到 app.asar / app.asar.bak，请重装 Typora"); process.exit(1); }

    killTypora();
    console.log(c.green("\n==== 开始 ===="));

    /* 1. 解包 */
    log.step("\n[1/4] 解包 app.asar");
    if (fs.existsSync(launchJS)) log.ok("resources/app 已存在，跳过");
    else {
        asar.extractAll(sourceAsar, appDir);
        const unpacked = path.join(RES, "app.asar.unpacked");
        if (fs.existsSync(unpacked)) copyDir(unpacked, appDir);   // 原生模块目錄
        log.ok("已解包到 " + appDir);
    }
    if (!fs.existsSync(launchJS)) { log.err("解包失败：找不到 launch.dist.js"); process.exit(1); }

    /* 2. 备份 app */
    if (fs.existsSync(path.join(appBakDir, "launch.dist.js"))) log.ok("app.bak 已存在");
    else { copyDir(appDir, appBakDir); log.ok("app → app.bak"); }

    /* 3. 移除 asar + 翻转 fuse */
    log.step("\n[2/4] 移除 asar / 翻转 fuse");
    if (fs.existsSync(asarPath)) {
        if (fs.existsSync(asarBakPath)) fs.rmSync(asarBakPath, { force: true });
        fs.renameSync(asarPath, asarBakPath);
        log.ok("app.asar → app.asar.bak");
    } else log.ok("app.asar 已移除");
    if (!fs.existsSync(TyporaEXE + ".bak")) { fs.copyFileSync(TyporaEXE, TyporaEXE + ".bak"); log.ok("Typora.exe 已备份"); }
    try {
        await fuses.flipFuses(TyporaEXE, {
            version: fuses.FuseVersion.V1,
            [fuses.FuseV1Options.OnlyLoadAppFromAsar]: false,
        });
        log.ok("OnlyLoadAppFromAsar = false");
    } catch (e) {
        if (/already/i.test(String(e && e.message))) log.ok("fuse 已是目标状态");
        else log.err("fuse 翻转失败: " + (e && e.message));
    }

    /* 4. 注入 Hook */
    log.step("\n[3/4] 注入 Hook");
    let src = fs.readFileSync(launchJS, "utf-8");
    if (src.includes(INJECT_MARK)) {
        src = src.replace(/\/\*\* Hook破解开始 \*\/[\s\S]*?\/\*\* Hook破解结束 \*\/\r?\n?/, "");
        log.ok("剥离旧注入");
    }
    const entity = {
        deviceId: identity.deviceId,
        fingerprint: identity.fingerprint,
        email,
        license,
        version: identity.version,
        date: dateStr,
        type: "USER",
    };
    const hook = buildHook(entity, debug);
    const strict = /^"use strict";/.exec(src);
    const pos = strict ? strict[0].length : 0;
    fs.writeFileSync(launchJS, src.slice(0, pos) + hook + src.slice(pos), "utf-8");
    log.ok("launch.dist.js 已注入（offset=" + pos + "）");

    /* 5. 写许可 */
    log.step("\n[4/4] 写入许可");
    // 格式：base64(实体JSON)#0#日期
    const token = Buffer.from(JSON.stringify(entity), "utf-8").toString("base64") + "#0#" + dateStr;
    try { log.ok("SLicense（via " + regSet("SLicense", token) + "）"); }
    catch (e) { log.err("SLicense 写入失败: " + (e.message || e)); }
    try { log.ok("IDate（via " + regSet("IDate", dateStr) + "）"); }
    catch (e) { log.err("IDate 写入失败: " + (e.message || e)); }

    console.log(c.green("\n==== 完成 ===="));
    console.log(c.green("  许可 key : " + license));
    console.log(c.green("  邮箱     : " + email));
    console.log(c.yellow("  启动 Typora → 帮助 → 我的许可证 查看状态"));
    console.log(c.yellow("  还原: node " + path.basename(__filename) + " --rollback"));
}

main().catch((e) => {
    console.error(c.red("执行失败: ") + (e && e.stack || e));
    process.exit(1);
});
