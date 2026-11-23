# Typora 激活破解教程（Windows）

> 环境：Typora 1.14.17 / Windows 11 / Node.js 18+
> 成品：`typora-crack.js` + `一键激活.bat`
> 目标：**双击一个 bat，破解完成**

---

## 一、效果

```
=== 一键激活 ===
[1/4] 解包 app.asar
  [OK] 已解包到 D:\Typora\resources\app
[2/4] 移除 asar / 翻转 fuse
  [OK] app.asar → app.asar.bak
  [OK] OnlyLoadAppFromAsar = false
[3/4] 注入 Hook
  [OK] launch.dist.js 已注入（offset=13）
[4/4] 写入许可
  [OK] SLicense（via native-reg）
  [OK] IDate（via native-reg）

==== 完成 ====
  许可 key : W8L9VR-FWC38A-SFU8P3-KDVBUA
```

启动 Typora，日志里就是这两行：

```
[L] pass
[watch L] hasL: true
```

界面右上角的「未激活」按钮消失，`帮助 → 我的许可证` 显示已激活。

---

## 二、原理：Typora 有三道关卡

Typora 是 Electron 应用，整个程序就是一个 `.asar` 压缩包 + 一个 Chromium 外壳。想让它认为你已购买，要过三关。

### 第 1 关：让 Electron 加载我们的代码

正常情况下 Electron 只认 `resources/app.asar`。想改成加载解包后的 `resources/app/` 目录，就得把 exe 里的 fuse 开关关掉：

```js
await flipFuses("Typora.exe", {
    version: FuseVersion.V1,
    [FuseV1Options.OnlyLoadAppFromAsar]: false,
});
```

改完 exe 的哈希会变，所以**必须先备份 exe**。

> ⚠️ 这里有个经典坑：`flipFuses` 是 **async 函数**，原版脚本没写 `await`，进程抢在写盘前就退出了，fuse 压根没改成功，Typora 照样去读 asar。

### 第 2 关：让 RSA 校验吐出我们想要的内容

1.14 的许可校验在 **V8 字节码**里（`atom.compiled.dist.jsc`），没法改源码，只能挂钩子。好在它验证时调用了标准 API：

```js
crypto.publicDecrypt(pubKey, 密文)
```

把 `publicDecrypt` 换成我们的实现，直接返回伪造的许可实体：

```js
crypto.publicDecrypt = function () {
    return Buffer.from(FAKE_LICENSE);
};
```

同时拦掉联网续期：

```js
electron.protocol.handle("https", async (request) => {
    if (/store\.typora\.io\/api\/client\/renew/i.test(request.url)) {
        return new Response(JSON.stringify({ success: true, msg: "..." }), { status: 200 });
    }
    return electron.net.fetch(request, { bypassCustomProtocolHandlers: true });
});
```

### 第 3 关：伪造的许可实体必须"长得像真的"

这是最关键、也最容易翻车的一关。许可实体是这么一串 JSON：

```json
{
  "deviceId":    "DESKTOP-QE1U6MG | 20718 | Windows",
  "fingerprint": "NP8Jab6a9q",
  "email":       "local@typora.local",
  "license":     "W8L9VR-FWC38A-SFU8P3-KDVBUA",
  "version":     "win|1.14.17",
  "date":        "11/23/2026",
  "type":        "USER"
}
```

**这三个字段必须和本机真实值一模一样**，否则校验静默失败（不报错，只是把注册表清空）：

| 字段 | 含义 | 怎么算 |
|---|---|---|
| `deviceId` | 设备标识 | `计算机名 \| 用户名 \| Windows` |
| `fingerprint` | 设备指纹 | `base64(sha256(MachineGuid + "typora"))`，把 `+` 换成 `a`，取前 10 位 |
| `version` | 版本标识 | `win\|` + Typora 版本号 |

`license` 字段必须符合正则 `^([A-Z0-9]{6}-){3}[A-Z0-9]{6}$`（4 组 6 位，共 24 位）。

最终写进注册表：

```
HKCU\Software\Typora\SLicense = base64(实体JSON)#0#日期
HKCU\Software\Typora\IDate    = 日期
```

---

## 三、怎么拿到本机真实身份

不用猜。Typora 的许可页面是通过 IPC 向主进程要机器码的：

```js
window.Setting.invokeWithCallback("license.machineCode")
```

在注入的 Hook 里挂一下 IPC，让它自己吐出来：

```js
const handlers = {};
const origHandle = electron.ipcMain.handle;
electron.ipcMain.handle = function (channel, listener) {
    handlers[channel] = listener;
    return origHandle.call(this, channel, listener);
};

// app ready 之后主动调用
setTimeout(async () => {
    const res = await handlers["license.machineCode"]({ sender: null });
    console.log(Buffer.from(res, "base64").toString());   // 机器码明文
}, 3000);
```

解出来就是：

```json
{"v":"win|1.14.17","i":"NP8Jab6a9q","l":"DESKTOP-QE1U6MG | 20718 | Windows"}
```

拿到之后反推出公式，正式脚本里就能自己算了，不用每次问程序。

---

## 四、开始破解

### 1. 准备

- 安装 [Node.js](https://nodejs.org/)（18 以上）
- 确认 Typora 装在哪，比如 `D:\Typora`

### 2. 放文件

把两个文件放到 Typora 的 `resources` 目录下（那里已经有现成的 `node_modules`，省得自己装依赖）：

```
D:\Typora\resources\
    ├─ app.asar
    ├─ node_modules\        ← 已有 asar / @electron/fuses / native-reg
    ├─ typora-crack.js
    └─ 一键激活.bat
```

> 脚本也能放别处：它会自己从 `%TYPORA_HOME%`、注册表、常见路径里找 Typora，依赖缺失时会自动 `npm install`。

### 3. 双击运行

直接双击 `一键激活.bat`。或者命令行：

```powershell
node typora-crack.js              # 破解
node typora-crack.js --verify     # 自检
node typora-crack.js --gencode    # 只看本机机器码
node typora-crack.js --rollback   # 还原
```

想自定义邮箱和 license：

```powershell
node typora-crack.js --email me@example.com --license ABCDEF-123456-GHJKLM-NPQRST
```

### 4. 验证

启动 Typora → `帮助` → `我的许可证`。

想看内部日志（排查用）：

```powershell
node typora-crack.js --debug y
```

带 `--debug y` 会在 `resources\Typora_Hook_Log.txt` 里记录每一次 `publicDecrypt`、每一次 fs 重定向、每一个联网请求。

---

## 五、还原

```powershell
node typora-crack.js --rollback
```

它会删掉 `resources\app`、把 `app.asar.bak` 改回 `app.asar`、用 `Typora.exe.bak` 覆盖 exe。

手动还原也是这三步。**升级 Typora 前一定要还原**，否则新版本会覆盖掉破解。

---

## 六、代码骨架（4 段核心）

### 1. 定位安装目录

```js
function detectTyporaHome() {
    const candidates = [
        process.env.TYPORA_HOME,
        path.dirname(__dirname),        // 脚本在 <Typora>\resources 下
        registryQuery("HKLM\\...\\Uninstall\\Typora", "InstallLocation"),
        "D:\\Typora",
        "C:\\Program Files\\Typora",
    ].filter(Boolean);

    for (const c of candidates) {
        if (fs.existsSync(path.join(c, "Typora.exe"))) return c;
    }
}
```

### 2. 翻转 fuse（必须 await）

```js
await flipFuses(TyporaEXE, {
    version: FuseVersion.V1,
    [FuseV1Options.OnlyLoadAppFromAsar]: false,
});
```

### 3. 注入 Hook

`launch.dist.js` 的第一行是 `"use strict";`，紧跟着就是一大串 `const fs = require("fs")`。注入位置要卡在 `"use strict";` 之后：

```js
const strict = /^"use strict";/.exec(src);
const pos = strict ? strict[0].length : 0;
fs.writeFileSync(launchJS, src.slice(0, pos) + hook + src.slice(pos), "utf-8");
```

**注入块里绝对不能用外层的 `fs`**，因为此时 `const fs` 还没执行，会触发暂时性死区。必须自带别名：

```js
const __fs = require("fs");       // ✅ 正确
// fs.readFileSync(...)           // ❌ ReferenceError: Cannot access 'fs' before initialization
```

### 4. 写许可实体

```js
const entity = {
    deviceId: identity.deviceId,
    fingerprint: identity.fingerprint,
    email,
    license,
    version: identity.version,
    date: dateStr,
    type: "USER",
};
const token = Buffer.from(JSON.stringify(entity)).toString("base64") + "#0#" + dateStr;
regSet("SLicense", token);
regSet("IDate", dateStr);
```

---

## 七、踩坑对照表

这些都是实际调试中真撞过的，遇到先查这张表：

| 报错 / 现象 | 原因 | 解决 |
|---|---|---|
| `ENOENT ...\Typora\resources\Typora\resources\app.asar` | 路径写成 `"D:\Typora"`，`\T` 不是转义，反斜杠被吞成 `D:Typora`（驱动器相对路径） | 用 `"D:\\Typora"` 或 `path.join` / 从 `__dirname` 推导 |
| `A JavaScript error occurred: Cannot access 'fs' before initialization` | 注入块引用了外层还没初始化的 `const fs` | 注入块自带 `__fs` |
| fuse 显示成功但 Typora 仍读 asar | `flipFuses` 没 `await`，进程提前退出 | `await flipFuses(...)` |
| `spawn EPERM`（写注册表时） | `winreg` 内部 spawn `reg.exe`，受限环境被拦 | 换 `native-reg`（Typora 自己用的实现，纯 Win32 API） |
| 注册表写进去了但重启就没了 | 实体字段和本机身份不一致，校验失败后程序主动清空 | 用真实 `deviceId` / `fingerprint` / `version` |
| `pure = undefined` + `no info` | 同上，许可实体被判定无效 | 同上 |
| 日志里 `Unexpected token '锘'` | JSON 文件带了 UTF-8 BOM | 写入时用 `new UTF8Encoding($false)` |
| 打开 `license` 页面看到 `SAMPLE_MACHINE_CODE` | 渲染层没拿到主进程的机器码 | 检查 IPC `license.machineCode` 是否注册 |

---

## 八、适配其它 Typora 版本

版本升级后最可能变的是 `fingerprint` 算法。三步确认：

1. 打开 Typora → `帮助` → `我的许可证`，找到页面上显示的机器码
2. 跑 `node typora-crack.js --gencode`，对比两边是否一致
3. 不一致就开 `--debug y` 重新注入，看 `Typora_Hook_Log.txt` 里 `hash.update` 的入参，反推新的拼接方式

由于 hook 挂在标准 API（`crypto.publicDecrypt`）而不是具体函数地址上，版本小升级通常无需改动。

---

## 九、文件清单

| 文件 | 作用 |
|---|---|
| `typora-crack.js` | 主程序：解包 / fuse / 注入 / 写许可 / 自检 / 还原 |
| `一键激活.bat` | 双击入口 |
| `Typora破解教程.md` | 本文 |
| `app.bak\` | 注入前的原始 app 目录（完整性校验靠它） |
| `app.asar.bak` | 原始 asar |
| `Typora.exe.bak` | 原始 exe |

## 十、
