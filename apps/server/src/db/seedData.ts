/**
 * 演示数据目录：规则库 / 项目 / 文件路径 / 代码片段。
 * 集中放在这里，seed 脚本与「模型检测」页的示例数据共用，避免两处漂移。
 */

export interface RuleTemplate {
  ruleId: string;
  ruleName: string;
  category: string;
  cwe: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  language: string;
  title: string;
  description: string;
  suggestion: string;
  /** 命中片段模板；{N} 会替换为行内随机量，保证同一规则在不同项目下片段不同 */
  snippet: string;
  filePath: string;
}

export const RULE_CATALOG: RuleTemplate[] = [
  {
    ruleId: 'sql-injection-java',
    ruleName: 'SQL注入',
    category: 'injection',
    cwe: 'CWE-89',
    severity: 'high',
    language: 'java',
    title: '用户输入未过滤直接拼接进 SQL 语句',
    description: 'name 参数来源于 HTTP 请求且未做校验，攻击者可构造恶意输入执行任意 SQL。',
    suggestion: '使用 PreparedStatement 参数化查询，禁止字符串拼接构造 SQL。',
    snippet:
      'public List<User> find(String name) {\n  String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";\n  return jdbc.query(sql);\n}',
    filePath: 'src/main/java/com/demo/dao/UserDao.java',
  },
  {
    ruleId: 'xss-reflected',
    ruleName: '反射型XSS',
    category: 'xss',
    cwe: 'CWE-79',
    severity: 'medium',
    language: 'javascript',
    title: '未转义的用户输入直接写入 HTML',
    description: 'query 参数未经转义即拼接到 DOM，可注入脚本在受害者浏览器执行。',
    suggestion: '使用 textContent 或框架内置转义；如需输出 HTML 请接入 DOMPurify 白名单过滤。',
    snippet:
      'const q = new URLSearchParams(location.search).get("q");\ndocument.getElementById("result").innerHTML = "搜索结果: " + q;',
    filePath: 'src/web/pages/search.js',
  },
  {
    ruleId: 'command-injection-python',
    ruleName: '命令注入',
    category: 'injection',
    cwe: 'CWE-78',
    severity: 'critical',
    language: 'python',
    title: '用户可控参数拼接进系统命令',
    description: 'host 参数来自请求体，直接拼接进 shell 命令，可执行任意系统命令。',
    suggestion: '改用 subprocess.run([...], shell=False) 传参数列表，并对输入做白名单校验。',
    snippet:
      'def ping(host):\n    cmd = "ping -c 1 " + host\n    return os.popen(cmd).read()',
    filePath: 'scripts/net_tools.py',
  },
  {
    ruleId: 'path-traversal-node',
    ruleName: '路径遍历',
    category: 'path_traversal',
    cwe: 'CWE-22',
    severity: 'high',
    language: 'javascript',
    title: '文件下载接口未校验路径，可读取任意文件',
    description: 'name 参数未做规范化与白名单校验，攻击者可用 ../ 跳出上传目录。',
    suggestion: '使用 path.resolve 后校验前缀必须落在允许目录内，并拒绝包含 .. 的输入。',
    snippet:
      'app.get("/download", (req, res) => {\n  res.sendFile(path.join(UPLOAD_DIR, req.query.name));\n});',
    filePath: 'src/server/routes/file.js',
  },
  {
    ruleId: 'buffer-overflow-c',
    ruleName: '缓冲区溢出',
    category: 'memory',
    cwe: 'CWE-787',
    severity: 'critical',
    language: 'c',
    title: 'strcpy 拷贝未校验长度导致缓冲区溢出',
    description: 'dst 为固定长度栈缓冲区，src 长度不受控，可覆盖返回地址。',
    suggestion: '改用 strncpy/snprintf 并显式校验长度，或换用带边界检查的安全函数。',
    snippet:
      'void copy_name(char *src) {\n  char dst[32];\n  strcpy(dst, src);\n  printf("%s\\n", dst);\n}',
    filePath: 'src/core/string_util.c',
  },
  {
    ruleId: 'deserialization-java',
    ruleName: '不安全反序列化',
    category: 'deserialization',
    cwe: 'CWE-502',
    severity: 'critical',
    language: 'java',
    title: '对不可信数据执行 Java 反序列化',
    description: '请求体直接交给 ObjectInputStream，可被构造 gadget 链触发远程代码执行。',
    suggestion: '避免反序列化不可信数据；必须使用时启用 ObjectInputFilter 白名单类。',
    snippet:
      'public Object parse(byte[] body) throws Exception {\n  try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body))) {\n    return in.readObject();\n  }\n}',
    filePath: 'src/main/java/com/demo/util/Serializer.java',
  },
  {
    ruleId: 'hardcoded-credential',
    ruleName: '硬编码凭证',
    category: 'secrets',
    cwe: 'CWE-798',
    severity: 'high',
    language: 'javascript',
    title: '源码中硬编码数据库密码',
    description: '数据库口令硬编码在源码中，随仓库泄露即失效。',
    suggestion: '改为从环境变量或密钥管理服务读取，并立即轮换已泄露口令。',
    snippet:
      'const pool = mysql.createPool({\n  host: "10.0.0.12",\n  user: "root",\n  password: "Passw0rd!2024",\n  database: "orders",\n});',
    filePath: 'src/config/database.js',
  },
  {
    ruleId: 'csrf-missing-token',
    ruleName: 'CSRF 防护缺失',
    category: 'csrf',
    cwe: 'CWE-352',
    severity: 'medium',
    language: 'java',
    title: '转账接口缺少 CSRF Token 校验',
    description: '状态变更接口未校验 CSRF Token，可被第三方站点诱导发起请求。',
    suggestion: '接入框架的 CSRF 防护，或改用 SameSite=Strict 的会话 Cookie + 自定义校验头。',
    snippet:
      '@PostMapping("/transfer")\npublic Result transfer(@RequestBody TransferReq req) {\n  return service.transfer(req);\n}',
    filePath: 'src/main/java/com/demo/web/AccountController.java',
  },
  {
    ruleId: 'weak-hash-md5',
    ruleName: '弱哈希算法',
    category: 'crypto',
    cwe: 'CWE-327',
    severity: 'medium',
    language: 'python',
    title: '使用 MD5 存储口令',
    description: 'MD5 已被证明可快速碰撞与彩虹表破解，不适合口令存储。',
    suggestion: '改用 bcrypt / argon2 等带盐慢哈希。',
    snippet:
      'def hash_password(pwd):\n    return hashlib.md5(pwd.encode()).hexdigest()',
    filePath: 'app/auth/password.py',
  },
  {
    ruleId: 'ssrf-http-client',
    ruleName: 'SSRF',
    category: 'ssrf',
    cwe: 'CWE-918',
    severity: 'high',
    language: 'python',
    title: '服务端请求 URL 完全由用户控制',
    description: 'url 参数未做内网地址拦截，可用于探测内网服务与云元数据接口。',
    suggestion: '解析并校验目标主机，拒绝私有网段与元数据地址，必要时走正向代理白名单。',
    snippet:
      'def fetch(url):\n    return requests.get(url, timeout=5).text',
    filePath: 'app/api/proxy.py',
  },
  {
    ruleId: 'file-upload-unrestricted',
    ruleName: '任意文件上传',
    category: 'file_upload',
    cwe: 'CWE-434',
    severity: 'critical',
    language: 'javascript',
    title: '上传接口未校验文件类型与后缀',
    description: '仅依赖客户端提交的文件名，攻击者可上传可执行脚本并访问触发。',
    suggestion: '服务端校验 MIME 与白名单后缀，重命名文件，上传目录禁止脚本执行权限。',
    snippet:
      'router.post("/upload", upload.single("file"), (req, res) => {\n  fs.writeFileSync(path.join(UPLOAD_DIR, req.file.originalname), req.file.buffer);\n  res.json({ ok: true, url: "/files/" + req.file.originalname });\n});',
    filePath: 'src/server/routes/upload.js',
  },
  {
    ruleId: 'xxe-xml-parser',
    ruleName: 'XXE 外部实体注入',
    category: 'xxe',
    cwe: 'CWE-611',
    severity: 'high',
    language: 'java',
    title: 'XML 解析未禁用外部实体',
    description: 'DocumentBuilderFactory 默认允许外部实体，可读取本地文件或发起 SSRF。',
    suggestion: '设置 disallow-doctype-decl 为 true 并关闭外部通用实体。',
    snippet:
      'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nDocument doc = f.newDocumentBuilder().parse(new ByteArrayInputStream(body));',
    filePath: 'src/main/java/com/demo/xml/FeedParser.java',
  },
  {
    ruleId: 'log-injection',
    ruleName: '日志注入',
    category: 'injection',
    cwe: 'CWE-117',
    severity: 'low',
    language: 'javascript',
    title: '未过滤换行符直接写日志',
    description: '用户输入含换行时可伪造日志行，干扰审计与告警。',
    suggestion: '写入日志前过滤 \\r\\n 并限制长度，或使用结构化日志字段。',
    snippet:
      'logger.info("user login: " + req.body.username);',
    filePath: 'src/server/middlewares/logger.js',
  },
  {
    ruleId: 'debug-enabled-prod',
    ruleName: '生产开启调试模式',
    category: 'misconfig',
    cwe: 'CWE-489',
    severity: 'medium',
    language: 'python',
    title: '生产配置开启 DEBUG 与热重载',
    description: '调试模式会暴露堆栈与源码，并可被用于执行任意代码。',
    suggestion: '生产环境关闭 DEBUG 与自动重载，异常统一由错误处理器返回。',
    snippet:
      'if __name__ == "__main__":\n    app.run(host="0.0.0.0", port=5000, debug=True)',
    filePath: 'app/main.py',
  },
  {
    ruleId: 'insecure-random-token',
    ruleName: '弱随机数生成令牌',
    category: 'crypto',
    cwe: 'CWE-338',
    severity: 'medium',
    language: 'php',
    title: '使用 rand() 生成会话令牌',
    description: 'rand() 不是密码学安全随机源，令牌可被预测。',
    suggestion: '改用 random_bytes / random_int 等 CSPRNG。',
    snippet:
      '$token = md5(rand());\nsetcookie("session", $token);',
    filePath: 'web/auth/session.php',
  },
  {
    ruleId: 'idor-order-api',
    ruleName: '越权访问',
    category: 'authorization',
    cwe: 'CWE-639',
    severity: 'high',
    language: 'go',
    title: '订单查询未校验归属，可越权读取他人订单',
    description: '仅按 orderId 查询，未校验当前用户是否为订单所有者。',
    suggestion: '查询条件强制带上当前用户 ID，或查询后校验归属再返回。',
    snippet:
      'func GetOrder(c *gin.Context) {\n    id := c.Param("id")\n    order, _ := db.FindOrder(id)\n    c.JSON(200, order)\n}',
    filePath: 'internal/handler/order.go',
  },
  {
    ruleId: 'open-redirect',
    ruleName: '开放重定向',
    category: 'redirect',
    cwe: 'CWE-601',
    severity: 'low',
    language: 'javascript',
    title: '跳转目标从查询参数直接取用',
    description: 'next 参数未校验域名，可被用于钓鱼跳转。',
    suggestion: '仅允许站内相对路径或校验目标域名白名单。',
    snippet:
      'app.get("/login/callback", (req, res) => {\n  res.redirect(req.query.next || "/");\n});',
    filePath: 'src/server/routes/auth.js',
  },
  {
    ruleId: 'unsafe-reflection',
    ruleName: '不安全的反射调用',
    category: 'injection',
    cwe: 'CWE-470',
    severity: 'high',
    language: 'java',
    title: '按用户输入反射加载类',
    description: 'className 完全由请求控制，可加载任意类并触发静态初始化。',
    suggestion: '改为按枚举/映射表白名单分派，禁止直接使用用户输入做类名。',
    snippet:
      'public Object handle(String className) throws Exception {\n  return Class.forName(className).getDeclaredConstructor().newInstance();\n}',
    filePath: 'src/main/java/com/demo/plugin/Loader.java',
  },
];

export interface ProjectTemplate {
  name: string;
  repoType: 'github' | 'gitlab' | 'gitee' | 'bitbucket' | 'other';
  repoUrl: string;
  repoFullName: string;
  defaultBranch: string;
  owner: string;
  description: string;
}

export const PROJECT_CATALOG: ProjectTemplate[] = [
  {
    name: 'order-service',
    repoType: 'github',
    repoUrl: 'https://github.com/acme/order-service',
    repoFullName: 'acme/order-service',
    defaultBranch: 'main',
    owner: '张三',
    description: '订单核心服务，Spring Boot + MySQL',
  },
  {
    name: 'user-center',
    repoType: 'github',
    repoUrl: 'https://github.com/acme/user-center',
    repoFullName: 'acme/user-center',
    defaultBranch: 'main',
    owner: '李四',
    description: '统一用户中心与认证服务',
  },
  {
    name: 'web-portal',
    repoType: 'gitlab',
    repoUrl: 'https://gitlab.acme.com/frontend/web-portal',
    repoFullName: 'frontend/web-portal',
    defaultBranch: 'master',
    owner: '王五',
    description: '对客门户前端，React + Vite',
  },
  {
    name: 'payment-gateway',
    repoType: 'gitlab',
    repoUrl: 'https://gitlab.acme.com/pay/payment-gateway',
    repoFullName: 'pay/payment-gateway',
    defaultBranch: 'main',
    owner: '赵六',
    description: '支付网关，Go 实现',
  },
  {
    name: 'data-pipeline',
    repoType: 'gitee',
    repoUrl: 'https://gitee.com/acme/data-pipeline',
    repoFullName: 'acme/data-pipeline',
    defaultBranch: 'main',
    owner: '孙七',
    description: '离线数据管道与调度脚本',
  },
  {
    name: 'admin-console',
    repoType: 'gitlab',
    repoUrl: 'https://gitlab.acme.com/backend/admin-console',
    repoFullName: 'backend/admin-console',
    defaultBranch: 'develop',
    owner: '周八',
    description: '运营后台，Java + Vue',
  },
  {
    name: 'mobile-api',
    repoType: 'github',
    repoUrl: 'https://github.com/acme/mobile-api',
    repoFullName: 'acme/mobile-api',
    defaultBranch: 'main',
    owner: '吴九',
    description: '移动端 BFF 接口层',
  },
  {
    name: 'legacy-cms',
    repoType: 'other',
    repoUrl: 'https://git.acme.com/legacy/cms',
    repoFullName: 'legacy/cms',
    defaultBranch: 'master',
    owner: '郑十',
    description: '存量内容管理系统，PHP，计划下线',
  },
];

export const DEMO_USERS = [
  { username: 'auditor', displayName: '安全审计员', email: 'auditor@example.com', role: 'auditor' as const },
  { username: 'viewer', displayName: '只读用户', email: 'viewer@example.com', role: 'viewer' as const },
  { username: 'lisi', displayName: '李四', email: 'lisi@example.com', role: 'auditor' as const },
  { username: 'wangwu', displayName: '王五', email: 'wangwu@example.com', role: 'auditor' as const },
];

export const DEFAULT_USER_PASSWORD = 'Admin@12345';
