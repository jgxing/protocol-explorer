/* ============================================================
   data.js — 协议课程、分层报文字节与字段定义
   所有报文均由真实的「层 → 字节 → 字段偏移」结构拼装，
   报文详情中的十六进制视图直接由这些字节生成。
   ============================================================ */
(function (global) {
  'use strict';

  /* ---------- 字节工具 ---------- */
  const enc = new TextEncoder();
  const U = {
    mac: s => s.split(':').map(h => parseInt(h, 16)),
    ip: s => s.split('.').map(Number),
    u16: n => [(n >>> 8) & 255, n & 255],
    u24: n => [(n >>> 16) & 255, (n >>> 8) & 255, n & 255],
    u32: n => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255],
    z: n => new Array(n).fill(0),
    s: str => Array.from(enc.encode(str)),
    seq: (n, start, step) => Array.from({ length: n }, (_, i) => (start + i * (step || 1)) & 255),
    qname: name => name.split('.').reduce((a, p) => a.concat([p.length], U.s(p)), []).concat(0),
    hx: (bytes, from, len) => bytes.slice(from, from + len).map(b => b.toString(16).padStart(2, '0')).join(' ')
  };

  const C = {
    eth: '#2749c9', ip: '#3f6fe0', tcp: '#0f9c9c', udp: '#12a08f',
    dns: '#7c4dd6', http: '#dd9a12', tls: '#d24b6a', data: '#6b7aa5',
    arp: '#8a5cd6', icmp: '#0f9c9c', dhcp: '#7c4dd6', ws: '#dd9a12',
    quic: '#c04a8e', payload: '#7b89ad', smtp: '#dd9a12', ftp: '#dd9a12'
  };

  const MAC_CLIENT = '08:00:5e:5d:52:81';
  const MAC_GW = '00:1b:21:9c:4e:0a';
  const IP_CLIENT = '192.168.1.10';
  const IP_GW = '192.168.1.1';
  const IP_DNS = '8.8.8.8';
  const IP_WEB = '203.0.113.10';
  const IP_MAIL = '198.51.100.25';
  const IP_FTP = '198.51.100.40';

  /* ---------- 层构造器 ---------- */
  const L = (key, name, short, color, bytes, fields) => ({ key, name, short, color, bytes, fields });
  const F = (n, v, o, l, d) => ({ n, v, o, l, d });

  function ETH(dst, src, type, typeLabel) {
    const t = type || 0x0800;
    return L('eth', 'Ethernet II', 'ETH', C.eth,
      [...U.mac(dst), ...U.mac(src), ...U.u16(t)],
      [
        F('目的地址', dst, 0, 6, '下一跳设备的 MAC 地址。数据链路层靠它把帧送到局域网内正确的网卡。'),
        F('源地址', src, 6, 6, '发送方网卡的物理地址；交换机据此学习「端口 ↔ MAC」映射表。'),
        F('类型 EtherType', typeLabel || '0x0800 (IPv4)', 12, 2, '指明上层协议：0x0800 = IPv4，0x0806 = ARP，0x86DD = IPv6。')
      ]);
  }

  function IPV4(src, dst, protoNum, protoLabel, payloadLen, opt) {
    const o = opt || {};
    const total = 20 + payloadLen;
    const id = o.id || 0x1c46;
    const ttl = o.ttl || 64;
    const flags = o.flags || 0x4000;
    return L('ip', 'IPv4', 'IPv4', C.ip,
      [0x45, 0x00, ...U.u16(total), ...U.u16(id), ...U.u16(flags), ttl, protoNum,
        0x8a, 0x3f, ...U.ip(src), ...U.ip(dst)],
      [
        F('版本 / 首部长度', '4 / 5 (20 字节)', 0, 2, '高 4 位为版本号 4；低 4 位为首部长度（单位 4 字节），5 × 4 = 20 字节。'),
        F('DSCP / ECN', '0x00', 1, 1, '差分服务代码点与显式拥塞通知，全 0 表示尽力而为（Best Effort）。'),
        F('总长度', total + ' 字节', 2, 2, '首部 + 载荷的总字节数，最大 65535。超过链路 MTU 时需要分片。'),
        F('标识', '0x' + id.toString(16), 4, 2, '同一数据报的所有分片共享该标识，接收端据此重组。'),
        F('标志 / 片偏移', o.frag ? 'MF=1, offset=' + o.frag : 'DF=1, offset=0', 6, 2, 'DF 禁止分片，MF 表示后面还有分片；片偏移以 8 字节为单位。'),
        F('生存时间 TTL', String(ttl), 8, 1, '每经过一台路由器减 1，归零则丢弃并回送 ICMP 超时，防止环路。'),
        F('上层协议', protoLabel || String(protoNum), 9, 1, '6 = TCP，17 = UDP，1 = ICMP；决定把载荷交给哪个传输层模块。'),
        F('首部校验和', '0x8a3f', 10, 2, '仅校验 IP 首部；每跳 TTL 变化都要重新计算。'),
        F('源地址', src, 12, 4, '发送主机的逻辑地址，网络层据此做路由寻址。'),
        F('目的地址', dst, 16, 4, '目标主机的逻辑地址，路由器按最长前缀匹配选择下一跳。')
      ]);
  }

  function TCP(sport, dport, seq, ack, flags, flagLabel, payloadLen, opt) {
    const o = opt || {};
    return L('tcp', 'TCP', 'TCP', C.tcp,
      [...U.u16(sport), ...U.u16(dport), ...U.u32(seq), ...U.u32(ack),
        0x50, flags, ...U.u16(o.win || 64240), 0xf0, 0x2a, 0x00, 0x00],
      [
        F('源端口', String(sport), 0, 2, '客户端随机选择的临时端口（Ephemeral Port），用于区分本机不同连接。'),
        F('目的端口', String(dport) + ' (' + (o.service || 'http') + ')', 2, 2, '熟知端口标识服务：80 = HTTP，443 = HTTPS，25 = SMTP，21 = FTP。'),
        F('序号 Seq', String(seq), 4, 4, '本报文段第一个数据字节的编号；SYN 会占用一个序号。'),
        F('确认号 Ack', String(ack), 8, 4, '期望收到的下一个字节编号，表示此前所有字节均已正确收到。'),
        F('数据偏移 / 保留', '5 (20 字节)', 12, 2, 'TCP 首部长度，单位 4 字节；无选项时为 20 字节。'),
        F('标志位 Flags', flagLabel, 13, 1, 'SYN 建连、ACK 确认、PSH 立即交付、FIN 断开、RST 复位。'),
        F('窗口大小', String(o.win || 64240), 14, 2, '接收方通告的可用缓冲区大小，实现流量控制。'),
        F('校验和', '0xf02a', 16, 2, '覆盖伪首部 + TCP 首部 + 数据，检测传输中的比特差错。'),
        F('紧急指针', '0', 18, 2, '仅 URG 置位时有效，本报文未使用。'),
        ...(payloadLen ? [F('数据载荷', payloadLen + ' 字节' + (o.truncated ? '（此处展开前 ' + (o.shown || payloadLen) + ' 字节）' : ''), 20, payloadLen, '上层应用数据；TCP 把它当作无结构的字节流。')] : [])
      ]);
  }

  function UDP(sport, dport, payloadLen) {
    return L('udp', 'UDP', 'UDP', C.udp,
      [...U.u16(sport), ...U.u16(dport), ...U.u16(8 + payloadLen), 0x3c, 0x91],
      [
        F('源端口', String(sport), 0, 2, '发送端临时端口，响应报文会把该值作为目的端口。'),
        F('目的端口', String(dport), 2, 2, '53 = DNS，67/68 = DHCP，443 = QUIC。'),
        F('长度', (8 + payloadLen) + ' 字节', 4, 2, 'UDP 首部 8 字节加上载荷长度。'),
        F('校验和', '0x3c91', 6, 2, '覆盖伪首部与整个数据报；IPv4 中可为 0 表示不校验。')
      ]);
  }

  /* 文本行层：每行即一个可高亮的字段 */
  function LINES(key, name, short, color, lines, note) {
    let bytes = [];
    const fields = [];
    lines.forEach(ln => {
      const b = U.s(ln.v);
      fields.push(F(ln.n, ln.v.replace(/\r\n/g, '↵').replace(/\n/g, '↵'), bytes.length, b.length, ln.d));
      bytes = bytes.concat(b);
    });
    const layer = L(key, name, short, color, bytes, fields);
    layer.note = note || '';
    return layer;
  }

  function DNS_QUERY(name, id, qtype) {
    const qt = qtype || 1;
    return L('dns', 'DNS', 'DNS', C.dns,
      [...U.u16(id), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ...U.qname(name), 0x00, qt, 0x00, 0x01],
      [
        F('事务 ID', '0x' + id.toString(16), 0, 2, '客户端生成的随机标识，响应必须带回相同 ID 才能匹配请求。'),
        F('标志 Flags', '0x0100 · 标准查询 + 期望递归', 2, 2, 'QR=0 表示查询；RD=1 请求服务器代为递归查询。'),
        F('问题数 QDCOUNT', '1', 4, 2, '本报文携带 1 个查询问题。'),
        F('回答数 ANCOUNT', '0', 6, 2, '查询报文不含回答记录。'),
        F('授权数 NSCOUNT', '0', 8, 2, '权威名称服务器记录数。'),
        F('附加数 ARCOUNT', '0', 10, 2, '附加记录数（如 OPT 伪资源记录）。'),
        F('查询名称 QNAME', name, 12, U.qname(name).length, '长度前缀编码：每段前 1 字节表示长度，最后以 0x00 结束。'),
        F('查询类型 QTYPE', qt === 1 ? '1 (A 记录)' : String(qt), 12 + U.qname(name).length, 2, 'A = IPv4 地址，AAAA = IPv6，MX = 邮件交换，CNAME = 别名。'),
        F('查询类别 QCLASS', '1 (IN / Internet)', 14 + U.qname(name).length, 2, '几乎总是 1，表示互联网类别。')
      ]);
  }

  function DNS_RESPONSE(name, id, answerIp) {
    const q = U.qname(name);
    const qEnd = 12 + q.length;
    const ansOff = qEnd + 4;
    return L('dns', 'DNS', 'DNS', C.dns,
      [...U.u16(id), 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ...q, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, ...U.ip(answerIp)],
      [
        F('事务 ID', '0x' + id.toString(16), 0, 2, '与请求一致，客户端据此把响应关联到之前的查询。'),
        F('标志 Flags', '0x8180 · 响应 + 递归可用', 2, 2, 'QR=1 为响应，RA=1 表示服务器支持递归，rcode=0 表示无差错。'),
        F('问题数 / 回答数', '1 / 1', 4, 4, '原样带回问题，并追加 1 条回答记录。'),
        F('查询名称 QNAME', name, 12, q.length, '与请求完全相同，便于校验。'),
        F('查询类型 / 类别', 'A / IN', qEnd, 4, 'A 记录、互联网类别。'),
        F('回答 · 名称指针', '0xC00C → 偏移 12', ansOff, 2, 'DNS 压缩：前两位 11 表示指针，指向问题区中的域名，避免重复存储。'),
        F('回答 · 类型 / 类别', 'A / IN', ansOff + 2, 4, '该资源记录是一条 IPv4 地址记录。'),
        F('生存时间 TTL', '300 秒', ansOff + 6, 4, '本地解析器可缓存该结果 5 分钟，过期后需重新查询。'),
        F('数据长度 RDLENGTH', '4 字节', ansOff + 10, 2, 'IPv4 地址恰好 4 字节。'),
        F('回答 · 地址 RDATA', answerIp, ansOff + 12, 4, '域名解析结果，浏览器随后向该 IP 发起 TCP 连接。')
      ]);
  }

  function ICMP(type, code, label, id, seq, payload) {
    const data = payload || U.seq(48, 0x61);
    return L('icmp', 'ICMP', 'ICMP', C.icmp,
      [type, code, 0x4d, 0x2a, ...U.u16(id), ...U.u16(seq), ...data],
      [
        F('类型 Type', type + ' (' + label + ')', 0, 1, '8 = 回显请求，0 = 回显应答，3 = 目的不可达，11 = 超时。'),
        F('代码 Code', String(code), 1, 1, '对类型的进一步细分，Echo 报文固定为 0。'),
        F('校验和', '0x4d2a', 2, 2, '覆盖整个 ICMP 报文。'),
        F('标识符', String(id), 4, 2, '区分不同 ping 进程，响应原样返回。'),
        F('序列号', String(seq), 6, 2, '每发一个请求加 1，用于计算丢包与往返时延。'),
        F('数据', data.length + ' 字节', 8, data.length, '任意填充数据，响应必须逐字节回显；常含时间戳以测量 RTT。')
      ]);
  }

  function ARP(op, senderMac, senderIp, targetMac, targetIp) {
    return L('arp', 'ARP', 'ARP', C.arp,
      [0x00, 0x01, 0x08, 0x00, 0x06, 0x04, ...U.u16(op), ...U.mac(senderMac), ...U.ip(senderIp),
        ...U.mac(targetMac), ...U.ip(targetIp)],
      [
        F('硬件类型', '1 (Ethernet)', 0, 2, '链路层地址类型。'),
        F('协议类型', '0x0800 (IPv4)', 2, 2, '要映射的网络层地址类型。'),
        F('硬件/协议地址长度', '6 / 4', 4, 2, 'MAC 地址 6 字节，IPv4 地址 4 字节。'),
        F('操作码 Opcode', op === 1 ? '1 (request)' : '2 (reply)', 6, 2, '1 为广播请求，2 为单播应答。'),
        F('发送方 MAC', senderMac, 8, 6, '应答中即被查询的目标网卡地址。'),
        F('发送方 IP', senderIp, 14, 4, '与 MAC 配对写入本地 ARP 缓存。'),
        F('目标 MAC', targetMac, 18, 6, '请求时为全 0（未知）或广播地址。'),
        F('目标 IP', targetIp, 24, 4, '希望解析的 IPv4 地址。')
      ]);
  }

  function DHCP(op, type, xid, yiaddr, options) {
    const optBytes = options || [0x35, 0x01, type, 0xff];
    const body = [
      op, 0x01, 0x06, 0x00, ...U.u32(xid), 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, ...U.ip(yiaddr), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      ...U.mac(MAC_CLIENT), ...U.z(10), ...U.z(64), ...U.z(128), 0x63, 0x82, 0x53, 0x63,
      ...optBytes
    ];
    return L('dhcp', 'DHCP', 'DHCP', C.dhcp, body,
      [
        F('操作码 op', op === 1 ? '1 (Boot Request)' : '2 (Boot Reply)', 0, 1, '客户端请求为 1，服务器应答为 2。'),
        F('硬件类型 / 长度', 'Ethernet / 6', 1, 2, '以太网 MAC 地址。'),
        F('事务 ID xid', '0x' + xid.toString(16), 4, 4, '随机事务号，用于匹配同一轮 DORA 交互。'),
        F('客户端地址 ciaddr', '0.0.0.0', 12, 4, '尚未获得地址时填 0。'),
        F('分配地址 yiaddr', yiaddr, 16, 4, '服务器准备分配给客户端的 IP 地址。'),
        F('客户端 MAC chaddr', MAC_CLIENT, 28, 16, '服务器据此为特定主机保留租约。'),
        F('魔术Cookie', '0x63825363', 236, 4, '标识后续为 DHCP Options（区别于 BOOTP）。'),
        F('Option 53 · 消息类型', type + ' (' + ({ 1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 5: 'ACK' })[type] + ')', 240, 3, 'DORA 四步：Discover → Offer → Request → Ack。'),
        F('Option 255 · 结束', '0xFF', 240 + optBytes.length - 1, 1, '选项区结束标记。')
      ]);
  }

  function TLS(label, bytes, fields) {
    return L('tls', label, 'TLS', C.tls, bytes, fields);
  }

  function TLS_CLIENTHELLO(sni) {
    const name = sni || 'www.example.com';
    const host = U.s(name);
    const random = U.seq(32, 0x9a, 7);
    const sid = U.z(32);
    const suites = [0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f, 0x00, 0xff]; // TLS 1.3 + 兼容套件
    // Server Name Indication 扩展（真实编码）
    const sniList = [0x00, ...U.u16(host.length), ...host];
    const sniData = [...U.u16(sniList.length), ...sniList];
    const ext = [0x00, 0x00, ...U.u16(sniData.length), ...sniData];
    const hsBody = [0x03, 0x03, ...random, 32, ...sid, ...U.u16(suites.length), ...suites,
      0x01, 0x00, ...U.u16(ext.length), ...ext];
    const hs = [0x01, ...U.u24(hsBody.length), ...hsBody];
    const rec = [0x16, 0x03, 0x01, ...U.u16(hs.length), ...hs];
    const R = 9; // rec 中 handshake body 的起始偏移：3 + 2(record len) + 1(type) + 3(len)
    return TLS('TLS 1.3 · ClientHello', rec,
      [
        F('记录类型', '0x16 (Handshake)', 0, 1, 'TLS 记录层内容类型：22 表示握手协议。'),
        F('记录版本', '0x0301 (TLS 1.0 兼容值)', 1, 2, '为兼容中间设备，记录层仍写 0x0301，真实版本在扩展中协商。'),
        F('记录长度', hs.length + ' 字节', 3, 2, '本条 TLS 记录承载的握手数据长度。'),
        F('握手类型', '0x01 (ClientHello)', 5, 1, '客户端发起握手，声明自己支持的算法。'),
        F('握手长度', hsBody.length + ' 字节', 6, 3, '24 位大端整数，表示后续握手消息长度。'),
        F('客户端版本', '0x0303 (TLS 1.2)', R, 2, 'legacy_version，TLS 1.3 依旧填 0x0303。'),
        F('随机数 Random', U.hx(rec, R + 2, 8) + ' … (32 字节)', R + 2, 32, '客户端随机数，与服务端随机数一起派生会话密钥。'),
        F('会话 ID', '32 字节', R + 35, 32, '兼容 TLS 1.2 会话恢复字段。'),
        F('密码套件列表', 'TLS_AES_128_GCM_SHA256 等 4 项', R + 67, 10, '客户端按优先级列出支持的加密套件，服务端从中选择。'),
        F('扩展 · SNI', name, R + hsBody.length - host.length, host.length, 'Server Name Indication：明文告知要访问的域名，使一台服务器能托管多个证书。')
      ]);
  }

  const HTTP_GET_LINES = [
    { n: '请求行', v: 'GET / HTTP/1.1\r\n', d: '方法 GET 表示获取资源；/ 为请求路径；HTTP/1.1 为协议版本。' },
    { n: 'Host', v: 'Host: www.example.com\r\n', d: 'HTTP/1.1 唯一必填首部，虚拟主机靠它区分站点。' },
    { n: 'User-Agent', v: 'User-Agent: ProtocolExplorer/1.0 (Windows NT 10.0; Win64; x64)\r\n', d: '客户端标识，服务端可据此做内容适配或统计。' },
    { n: 'Accept', v: 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n', d: '声明可接受的媒体类型与优先级权重 q。' },
    { n: 'Accept-Language', v: 'Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n', d: '期望的自然语言，用于内容协商。' },
    { n: 'Accept-Encoding', v: 'Accept-Encoding: gzip, deflate, br\r\n', d: '声明支持的压缩算法，可显著降低传输体积。' },
    { n: 'Connection', v: 'Connection: keep-alive\r\n', d: '复用同一条 TCP 连接发送后续请求，避免重复三次握手。' },
    { n: 'Cache-Control', v: 'Cache-Control: max-age=0\r\n', d: '要求回源校验缓存是否新鲜。' },
    { n: '首部结束', v: '\r\n', d: '空行（CRLF CRLF）标志首部结束，其后才是可选的请求体。' }
  ];

  const HTTP_200_LINES = [
    { n: '状态行', v: 'HTTP/1.1 200 OK\r\n', d: '版本 + 状态码 + 原因短语；200 表示请求成功。' },
    { n: 'Date', v: 'Date: Sat, 07 Nov 2026 01:02:03 GMT\r\n', d: '报文生成时间，用于缓存新鲜度计算。' },
    { n: 'Server', v: 'Server: nginx/1.25.3\r\n', d: '服务端软件标识。' },
    { n: 'Content-Type', v: 'Content-Type: text/html; charset=UTF-8\r\n', d: '实体类型与字符编码，决定浏览器如何解析响应体。' },
    { n: 'Content-Length', v: 'Content-Length: 12480\r\n', d: '响应体字节数；TCP 流式传输时靠它界定报文边界。' },
    { n: 'Connection', v: 'Connection: keep-alive\r\n', d: '保持连接，供后续资源请求复用。' },
    { n: 'ETag', v: 'ETag: "67b3-5f9a1c2d4e8"\r\n', d: '资源指纹，用于条件请求 304 协商缓存。' },
    { n: 'Cache-Control', v: 'Cache-Control: max-age=3600\r\n', d: '允许本地缓存 1 小时。' },
    { n: '首部结束', v: '\r\n', d: '空行之后是 HTML 响应体，浏览器开始解析渲染。' },
    { n: '响应体片段', v: '<!DOCTYPE html>\n<html lang="zh-CN">\n<head><title>Example Domain</title></head>\n<body>\n  <h1>Example Domain</h1>\n  <p>这个页面用于说明协议交互过程。</p>\n</body>\n</html>\n', d: 'HTML 文档；整页共 12480 字节，被拆成 9 个 TCP 报文段传输。' }
  ];

  /* ---------- 报文组装 ---------- */
  function P(cfg) {
    let base = 0;
    const layers = cfg.layers.map(l => {
      const item = Object.assign({}, l, {
        base: base,
        bytes: l.bytes.slice(),
        fields: l.fields.map(f => Object.assign({}, f, { g: base + f.o, layer: l.key }))
      });
      base += item.bytes.length;
      return item;
    });
    return Object.assign({}, cfg, { layers: layers, size: base, bytes: layers.reduce((a, l) => a.concat(l.bytes), []) });
  }

  const ethC = () => ETH(MAC_GW, MAC_CLIENT);
  const ethR = () => ETH(MAC_CLIENT, MAC_GW);

  /* 常用层组合 */
  const frame = (src, dst, protoNum, protoLabel, transport, app, opts) => {
    const o = opts || {};
    const payloadLen = app ? app.bytes.length : 0;
    const tport = transport(payloadLen);
    const ip = IPV4(src, dst, protoNum, protoLabel, tport.bytes.length + payloadLen, o);
    return [o.eth || (o.inbound ? ethR() : ethC()), ip, tport, ...(app ? [app] : [])];
  };
  const udpTo = (sp, dp) => len => UDP(sp, dp, len);
  const tcpTo = (sp, dp, seq, ack, flags, label, opts) => len => {
    const l = TCP(sp, dp, seq, ack, flags, label, len, Object.assign({}, opts, { shown: len }));
    return l;
  };

  /* ---------- 场景数据 ---------- */
  const S = {};
  const def = (id, cfg) => { S[id] = Object.assign({ id, packets: [], nodes: ['client', 'gateway', 'web'] }, cfg); };

  /* 01 · HTTP —— 完整 Web 通信 */
  (function () {
    const get = LINES('http', 'HTTP 请求', 'HTTP', C.http, HTTP_GET_LINES,
      'HTTP 是文本协议：请求行、首部、空行、实体体，全部以 CRLF 分隔，可直接阅读。');
    const res = LINES('http', 'HTTP 响应', 'HTTP', C.http, HTTP_200_LINES,
      '状态码分 5 类：1xx 信息、2xx 成功、3xx 重定向、4xx 客户端错误、5xx 服务端错误。');
    const seg = (n, text) => LINES('data', 'TCP 段 #' + n + ' · HTML', 'DATA', C.payload,
      [{ n: 'HTML 片段', v: text, d: '响应体被 TCP 按 MSS（通常 1460 字节）切分，每段独立编号，接收端按 Seq 重组。' }],
      '该段实际承载 1460 字节，抓包视图仅展开开头片段。');

    const ps = [
      P({ t: 0.000, src: IP_CLIENT, dst: IP_DNS, proto: 'DNS', kind: 'dns', phase: 'DNS 查询', from: 'client', to: 'dns',
        title: 'DNS 查询', info: 'Standard query 0x5a1b A www.example.com', osi: [7, 4, 3, 2], layer: 7,
        note: '浏览器先查本地缓存，未命中才向递归解析器发出 UDP 查询。',
        layers: frame(IP_CLIENT, IP_DNS, 17, '17 (UDP)', udpTo(52344, 53), DNS_QUERY('www.example.com', 0x5a1b)) }),

      P({ t: 0.012, src: IP_DNS, dst: IP_CLIENT, proto: 'DNS', kind: 'dns', phase: 'DNS 响应', from: 'dns', to: 'client',
        title: 'DNS 响应', info: 'Standard query response 0x5a1b A 203.0.113.10', osi: [7, 4, 3, 2], layer: 7,
        note: '响应带回 A 记录与 300 秒 TTL，浏览器把域名映射写入本地缓存。',
        layers: frame(IP_DNS, IP_CLIENT, 17, '17 (UDP)', udpTo(53, 52344), DNS_RESPONSE('www.example.com', 0x5a1b, IP_WEB), { inbound: true }) }),

      P({ t: 0.024, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'tcp', phase: 'TCP 握手', from: 'client', to: 'web',
        title: 'TCP 第一次握手', info: '52344 → 80 [SYN] Seq=0 Win=64240 Len=0', osi: [4, 3, 2], layer: 4,
        note: 'SYN 不携带数据，但要占用一个序号；客户端进入 SYN-SENT 状态。',
        layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 0, 0, 0x02, '0x02 SYN')) }),

      P({ t: 0.041, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'tcp', phase: 'TCP 握手', from: 'web', to: 'client',
        title: 'TCP 第二次握手', info: '80 → 52344 [SYN, ACK] Seq=0 Ack=1 Win=65535', osi: [4, 3, 2], layer: 4,
        note: '服务端同时确认客户端的 SYN 并发出自己的 SYN，进入 SYN-RECEIVED。',
        layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 0, 1, 0x12, '0x12 SYN,ACK'), null, { inbound: true }) }),

      P({ t: 0.058, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'ack', phase: 'TCP 握手', from: 'client', to: 'web',
        title: 'TCP 第三次握手', info: '52344 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0', osi: [4, 3, 2], layer: 4,
        note: '三次握手完成，双方进入 ESTABLISHED，全双工字节流通道建立。',
        layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 1, 1, 0x10, '0x10 ACK')) }),

      P({ t: 0.058, src: IP_CLIENT, dst: IP_WEB, proto: 'HTTP', kind: 'request', phase: 'HTTP 请求', from: 'client', to: 'web',
        title: 'HTTP GET 请求', info: 'GET / HTTP/1.1  ·  Host: www.example.com', osi: [7, 4, 3, 2], layer: 7,
        note: '应用层报文被交给 TCP，加上 20 字节首部，再逐层封装成 IP 数据报与以太网帧。',
        layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 1, 1, 0x18, '0x18 PSH,ACK'), get) }),

      P({ t: 0.062, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'ack', phase: '纯 ACK', from: 'web', to: 'client',
        title: 'TCP 确认', info: '80 → 52344 [ACK] Seq=1 Ack=431 Win=65535 Len=0', osi: [4, 3, 2], layer: 4,
        note: '不携带应用数据的纯 ACK：只确认已收到的字节，不占用序号空间。',
        layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 1, 431, 0x10, '0x10 ACK'), null, { inbound: true }) }),

      P({ t: 0.214, src: IP_WEB, dst: IP_CLIENT, proto: 'HTTP', kind: 'response', phase: 'HTTP 响应', from: 'web', to: 'client',
        title: 'HTTP 200 OK', info: 'HTTP/1.1 200 OK (text/html)  ·  Content-Length: 12480', osi: [7, 4, 3, 2], layer: 7,
        displaySize: '12.8 kB', truncated: true,
        note: '页面共 12480 字节，被拆成 9 个 TCP 报文段；抓包工具重组后展示为一条完整响应。',
        layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 1, 431, 0x18, '0x18 PSH,ACK', { truncated: true }), res, { inbound: true }) }),

      P({ t: 0.216, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'ack', phase: '纯 ACK', from: 'client', to: 'web',
        title: 'TCP 累计确认', info: '52344 → 80 [ACK] Seq=431 Ack=1461 Len=0', osi: [4, 3, 2], layer: 4,
        note: '累计确认：Ack=N 表示 N 之前的全部字节都已收到，允许中间个别 ACK 丢失。',
        layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 431, 1461, 0x10, '0x10 ACK')) }),

      P({ t: 0.398, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'response', phase: '响应报文段', from: 'web', to: 'client',
        title: 'TCP 数据段 #2', info: '[PSH, ACK] Seq=1461  ·  TCP 段续传 (1460 B)', osi: [4, 3, 2], layer: 4,
        displaySize: '1460 B', truncated: true,
        note: '拥塞窗口允许时，服务端连续发送多个段，无需逐个等待确认。',
        layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 1461, 431, 0x18, '0x18 PSH,ACK', { truncated: true }), seg(2, '<div class="hero">\n  <h2>协议是如何发送的？</h2>\n  <p>每一层都添加自己的首部。</p>\n</div>\n'), { inbound: true }) }),

      P({ t: 0.581, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'response', phase: '响应报文段', from: 'web', to: 'client',
        title: 'TCP 数据段 #5', info: '[PSH, ACK] Seq=5841  ·  TCP 段续传 (1460 B)', osi: [4, 3, 2], layer: 4,
        displaySize: '1460 B', truncated: true,
        note: '接收端按序号把乱序到达的段重新排序，再按字节流顺序交给 HTTP 层。',
        layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 5841, 431, 0x18, '0x18 PSH,ACK', { truncated: true }), seg(5, '<section id="formats">\n  <table><tr><th>层</th><th>首部</th></tr></table>\n</section>\n'), { inbound: true }) }),

      P({ t: 0.876, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'response', phase: '响应报文段', from: 'web', to: 'client',
        title: 'TCP 数据段 #9', info: '[PSH, ACK] Seq=11681  ·  响应体结束 (1460 B)', osi: [4, 3, 2], layer: 4,
        displaySize: '1460 B', truncated: true,
        note: '最后一个段携带 </html>，浏览器边接收边解析，逐步构建 DOM 树。',
        layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 11681, 431, 0x18, '0x18 PSH,ACK', { truncated: true }), seg(9, '  <footer>Page delivered.</footer>\n</body>\n</html>\n'), { inbound: true }) }),

      P({ t: 0.879, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'ack', phase: '纯 ACK', from: 'client', to: 'web',
        title: 'TCP 最终确认', info: '52344 → 80 [ACK] Seq=431 Ack=12481 Len=0', osi: [4, 3, 2], layer: 4,
        note: '全部 12480 字节接收完毕，页面渲染完成；连接保持 keep-alive 以备复用。',
        layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 431, 12481, 0x10, '0x10 ACK')) })
    ];

    def('http', {
      name: 'HTTP', title: 'WEB 通信', cat: 'app', sub: '超文本传输协议', url: 'www.example.com',
      osi: 7, layer: 7,
      nodes: ['url', 'client', 'gateway', 'dns', 'web'],
      labels: { web: { name: 'Web 服务器', ip: IP_WEB } },
      steps: [
        { t: '客户端请求', d: '在地址栏输入域名并发起请求', at: 1 },
        { t: 'DNS 解析', d: '查询域名对应的 IP 地址', at: 2 },
        { t: 'TCP 连接', d: '三次握手建立可靠通道', at: 5 },
        { t: 'HTTP 交换', d: '发送请求并接收响应', at: 8 },
        { t: '页面渲染', d: '重组报文段并绘制页面', at: 13 }
      ],
      desc: '不到一秒之内：笔记把域名查到了地址，打开了 TCP 连接，并交换了一次 HTTP 请求和响应，再逐段把页面送达。',
      tip: '一次「打开网页」其实跨越了 DNS（UDP/53）、TCP 三次握手与 HTTP 三层协议。每一层只在自己的首部里添加必要信息，接收端自下而上逐层剥离。',
      stats: [
        { k: '往返次数', v: '3  (DNS, TCP, HTTP)' },
        { k: '总时间', v: '0.894 s' },
        { k: '页面大小', v: '12.8 kB' },
        { k: '响应', v: '分成 9 个 TCP 报文段发送' }
      ],
      packets: ps
    });
  })();

  /* 02 · DNS */
  (function () {
    const q = DNS_QUERY('www.example.com', 0x2f1a);
    const r = DNS_RESPONSE('www.example.com', 0x2f1a, IP_WEB);
    const q6 = DNS_QUERY('www.example.com', 0x2f1b, 28);
    def('dns', {
      name: 'DNS', title: '域名解析', cat: 'base', sub: '域名系统', url: 'www.example.com',
      osi: 7, layer: 7, nodes: ['url', 'client', 'gateway', 'dns'],
      steps: [
        { t: '输入域名', d: '浏览器检查本地与系统缓存', at: 1 },
        { t: '发出查询', d: '向递归解析器发送 UDP 报文', at: 2 },
        { t: '递归查询', d: '根 → 顶级域 → 权威服务器', at: 3 },
        { t: '返回应答', d: 'A 记录与 TTL 写回缓存', at: 4 }
      ],
      desc: 'DNS 把人类可读的域名翻译成 IP 地址。它跑在 UDP/53 上，一次查询 + 一次应答即可完成，几乎没有握手开销。',
      tip: 'DNS 报文用「长度前缀」编码域名，并用 0xC00C 指针压缩重复出现的名称。TTL 决定结果能被缓存多久。',
      stats: [{ k: '传输协议', v: 'UDP / 53' }, { k: '查询往返', v: '1 RTT' }, { k: '报文大小', v: '75 B → 91 B' }, { k: '缓存 TTL', v: '300 s' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: IP_DNS, proto: 'DNS', kind: 'dns', phase: '标准查询', from: 'client', to: 'dns', title: 'DNS 标准查询 (A)',
          info: 'Standard query 0x2f1a A www.example.com', osi: [7, 4, 3, 2], layer: 7, note: 'UDP 无连接：不握手，直接把问题塞进一个数据报。',
          layers: frame(IP_CLIENT, IP_DNS, 17, '17 (UDP)', udpTo(53120, 53), q) }),
        P({ t: 0.014, src: IP_DNS, dst: IP_CLIENT, proto: 'DNS', kind: 'dns', phase: '标准响应', from: 'dns', to: 'client', title: 'DNS 标准查询响应 (A)',
          info: 'Standard query response 0x2f1a A 203.0.113.10', osi: [7, 4, 3, 2], layer: 7, note: '事务 ID 必须与请求一致，否则客户端会丢弃该响应。',
          layers: frame(IP_DNS, IP_CLIENT, 17, '17 (UDP)', udpTo(53, 53120), r, { inbound: true }) }),
        P({ t: 0.016, src: IP_CLIENT, dst: IP_DNS, proto: 'DNS', kind: 'dns', phase: 'AAAA 查询', from: 'client', to: 'dns', title: 'DNS 标准查询 (AAAA)',
          info: 'Standard query 0x2f1b AAAA www.example.com', osi: [7, 4, 3, 2], layer: 7, note: '现代浏览器会并行查询 A 与 AAAA 记录，优先尝试 IPv6。',
          layers: frame(IP_CLIENT, IP_DNS, 17, '17 (UDP)', udpTo(53121, 53), q6) }),
        P({ t: 0.029, src: IP_DNS, dst: IP_CLIENT, proto: 'DNS', kind: 'dns', phase: 'AAAA 响应', from: 'dns', to: 'client', title: 'DNS 响应 (无 AAAA 记录)',
          info: 'Standard query response 0x2f1b · NOERROR, 0 answers', osi: [7, 4, 3, 2], layer: 7, note: '没有 IPv6 记录时返回空回答，客户端回退到 IPv4。',
          layers: frame(IP_DNS, IP_CLIENT, 17, '17 (UDP)', udpTo(53, 53121), DNS_RESPONSE('www.example.com', 0x2f1b, IP_WEB), { inbound: true }) })
      ]
    });
  })();

  /* 03 · TCP */
  (function () {
    const hello = LINES('data', '应用数据', 'DATA', C.payload,
      [{ n: '数据', v: 'hello over tcp\n', d: 'TCP 不保留消息边界，只保证字节按序、不重、不丢。' }]);
    const bye = LINES('data', '应用数据', 'DATA', C.payload,
      [{ n: '数据', v: 'bye\n', d: 'FIN 同样占用一个序号，四次挥手各自独立关闭一个方向。' }]);
    def('tcp', {
      name: 'TCP', title: '三次握手与可靠传输', cat: 'base', sub: '传输控制协议', osi: 4, layer: 4,
      nodes: ['client', 'gateway', 'web'], labels: { web: { name: '服务端', ip: IP_WEB } },
      steps: [
        { t: 'SYN', d: '客户端发起连接并声明初始序号', at: 1 },
        { t: 'SYN + ACK', d: '服务端确认并声明自己的序号', at: 2 },
        { t: 'ACK', d: '连接建立，进入 ESTABLISHED', at: 3 },
        { t: '数据传输', d: '按序发送并累计确认', at: 5 },
        { t: '四次挥手', d: '双向独立关闭连接', at: 8 }
      ],
      desc: 'TCP 用序号、确认、重传与滑动窗口，在不可靠的 IP 之上提供可靠的字节流服务；连接建立需要 1 个 RTT。',
      tip: 'SYN 与 FIN 虽然不带数据，也要占用一个序号。纯 ACK 不占用序号。握手第三次报文已经可以携带数据（TCP Fast Open）。',
      stats: [{ k: '建连往返', v: '1 RTT (3 报文)' }, { k: '首部长度', v: '20 字节' }, { k: '可靠性', v: '序号 + 累计确认 + 重传' }, { k: '流量控制', v: '滑动窗口 64240 B' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'tcp', phase: '第一次握手', from: 'client', to: 'web', title: '[SYN] 连接请求',
          info: '52344 → 80 [SYN] Seq=0 Win=64240 MSS=1460', osi: [4, 3, 2], layer: 4, note: 'MSS 在 TCP 选项中通告，决定每个段最多装多少应用数据。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 0, 0, 0x02, '0x02 SYN')) }),
        P({ t: 0.018, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'tcp', phase: '第二次握手', from: 'web', to: 'client', title: '[SYN, ACK] 同意建连',
          info: '80 → 52344 [SYN, ACK] Seq=0 Ack=1', osi: [4, 3, 2], layer: 4, note: '服务端把两个动作合并成一个报文，减少一次往返。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 0, 1, 0x12, '0x12 SYN,ACK'), null, { inbound: true }) }),
        P({ t: 0.035, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'ack', phase: '第三次握手', from: 'client', to: 'web', title: '[ACK] 连接建立',
          info: '52344 → 80 [ACK] Seq=1 Ack=1', osi: [4, 3, 2], layer: 4, note: '此刻起双方都可以随时发送数据，是全双工连接。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 1, 1, 0x10, '0x10 ACK')) }),
        P({ t: 0.041, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'request', phase: '数据传输', from: 'client', to: 'web', title: '[PSH, ACK] 发送数据',
          info: '52344 → 80 [PSH, ACK] Seq=1 Len=15', osi: [4, 3, 2], layer: 4, note: 'PSH 提示接收端立即把缓冲数据交给应用，不要等待填满。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 1, 1, 0x18, '0x18 PSH,ACK'), hello) }),
        P({ t: 0.058, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'ack', phase: '累计确认', from: 'web', to: 'client', title: '[ACK] 确认数据',
          info: '80 → 52344 [ACK] Seq=1 Ack=16', osi: [4, 3, 2], layer: 4, note: 'Ack = 收到的最后字节序号 + 1。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 1, 16, 0x10, '0x10 ACK'), null, { inbound: true }) }),
        P({ t: 0.090, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'tcp', phase: '四次挥手', from: 'client', to: 'web', title: '[FIN, ACK] 主动关闭',
          info: '52344 → 80 [FIN, ACK] Seq=16 Ack=1', osi: [4, 3, 2], layer: 4, note: '客户端关闭自己到服务端的方向，进入 FIN-WAIT-1。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(52344, 80, 16, 1, 0x11, '0x11 FIN,ACK')) }),
        P({ t: 0.107, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'ack', phase: '四次挥手', from: 'web', to: 'client', title: '[ACK] 确认关闭',
          info: '80 → 52344 [ACK] Seq=1 Ack=17', osi: [4, 3, 2], layer: 4, note: '半关闭状态：服务端仍可继续发送剩余数据。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 1, 17, 0x10, '0x10 ACK'), null, { inbound: true }) }),
        P({ t: 0.120, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'tcp', phase: '四次挥手', from: 'web', to: 'client', title: '[FIN, ACK] 服务端关闭',
          info: '80 → 52344 [FIN, ACK] Seq=1 Ack=17', osi: [4, 3, 2], layer: 4, note: '服务端发完数据后关闭另一方向；客户端回 ACK 后进入 TIME-WAIT。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 52344, 1, 17, 0x11, '0x11 FIN,ACK'), bye, { inbound: true }) })
      ]
    });
  })();

  /* 04 · UDP */
  (function () {
    const d1 = LINES('data', '应用数据', 'DATA', C.payload, [{ n: '语音帧 #1', v: '\x80\x01\x02\x03audio-frame-001', d: '实时媒体允许少量丢包，但不能容忍重传带来的延迟。' }]);
    const d2 = LINES('data', '应用数据', 'DATA', C.payload, [{ n: '语音帧 #2', v: '\x80\x01\x02\x04audio-frame-002', d: '每个数据报独立寻址，可能乱序或重复到达。' }]);
    def('udp', {
      name: 'UDP', title: '无连接数据报', cat: 'base', sub: '用户数据报协议', osi: 4, layer: 4,
      nodes: ['client', 'gateway', 'web'], labels: { web: { name: '流媒体服务器', ip: IP_WEB } },
      steps: [{ t: '构造数据报', d: '加上 8 字节 UDP 首部', at: 1 }, { t: '直接发送', d: '无需握手与连接状态', at: 2 }, { t: '独立到达', d: '每个报文独立路由', at: 3 }, { t: '应用兜底', d: '乱序/丢包交给上层处理', at: 4 }],
      desc: 'UDP 只有 8 字节首部：源端口、目的端口、长度、校验和。没有序号、没有确认、没有重传，换来的是极低的时延。',
      tip: 'DNS、DHCP、NTP、实时音视频与 QUIC 都选择 UDP。QUIC 在 UDP 之上自己实现了可靠传输与拥塞控制。',
      stats: [{ k: '首部长度', v: '8 字节 (固定)' }, { k: '建连开销', v: '0 RTT' }, { k: '可靠性', v: '不保证，由应用层负责' }, { k: '典型应用', v: 'DNS / 音视频 / QUIC' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: IP_WEB, proto: 'UDP', kind: 'request', phase: '数据报 1', from: 'client', to: 'web', title: 'UDP 数据报 #1',
          info: '53120 → 5004  Len=28', osi: [4, 3, 2], layer: 4, note: 'UDP 保留消息边界：一次 write 对应一个数据报。',
          layers: frame(IP_CLIENT, IP_WEB, 17, '17 (UDP)', udpTo(53120, 5004), d1) }),
        P({ t: 0.020, src: IP_WEB, dst: IP_CLIENT, proto: 'UDP', kind: 'response', phase: '数据报 2', from: 'web', to: 'client', title: 'UDP 数据报 #2',
          info: '5004 → 53120  Len=28', osi: [4, 3, 2], layer: 4, note: '没有 ACK：服务端不知道客户端是否收到。',
          layers: frame(IP_WEB, IP_CLIENT, 17, '17 (UDP)', udpTo(5004, 53120), d2, { inbound: true }) }),
        P({ t: 0.040, src: IP_CLIENT, dst: IP_WEB, proto: 'UDP', kind: 'request', phase: '数据报 3', from: 'client', to: 'web', title: 'UDP 数据报 #3',
          info: '53120 → 5004  Len=28', osi: [4, 3, 2], layer: 4, note: '即使前一帧丢失，后续帧也照常发送，不会被阻塞。',
          layers: frame(IP_CLIENT, IP_WEB, 17, '17 (UDP)', udpTo(53120, 5004), d1) }),
        P({ t: 0.061, src: IP_WEB, dst: IP_CLIENT, proto: 'UDP', kind: 'response', phase: '数据报 4', from: 'web', to: 'client', title: 'UDP 数据报 #4',
          info: '5004 → 53120  Len=28', osi: [4, 3, 2], layer: 4, note: '应用层用序列号与抖动缓冲处理乱序和丢包。',
          layers: frame(IP_WEB, IP_CLIENT, 17, '17 (UDP)', udpTo(5004, 53120), d2, { inbound: true }) })
      ]
    });
  })();

  /* 05 · IP 与分片 */
  (function () {
    const payload = n => LINES('data', '原始载荷', 'DATA', C.payload, [{ n: '载荷片段 ' + n, v: U.seq(120, 0x41).map(c => String.fromCharCode(c)).join(''), d: '超过链路 MTU (1500 B) 的 IP 数据报会被切成多个分片。' }]);
    def('ip', {
      name: 'IP', title: '分组、路由与分片', cat: 'base', sub: '互联网协议', osi: 3, layer: 3,
      nodes: ['client', 'gateway', 'web'], labels: { web: { name: '远端主机', ip: IP_WEB } },
      steps: [{ t: '封装数据报', d: '添加 20 字节 IP 首部', at: 1 }, { t: '查路由表', d: '最长前缀匹配选下一跳', at: 2 }, { t: 'TTL 递减', d: '每跳减 1 防止环路', at: 3 }, { t: '分片与重组', d: '超过 MTU 时切分', at: 5 }],
      desc: 'IP 提供「尽力而为」的逐跳投递：不保证送达、不保证顺序。路由器只依据目的 IP 查表转发，每跳重写二层帧首部而 IP 首部基本不变。',
      tip: '分片由标识 + 标志 + 片偏移三个字段协同完成；重组只在最终目的主机进行。IPv6 已把分片移到源端的扩展首部。',
      stats: [{ k: '首部长度', v: '20 字节 (无选项)' }, { k: '地址长度', v: '32 bit / IPv4' }, { k: '初始 TTL', v: '64 跳' }, { k: '分片单位', v: '8 字节' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: IP_WEB, proto: 'IP', kind: 'request', phase: '数据报', from: 'client', to: 'gateway', title: 'IP 数据报 · 发往默认网关',
          info: '192.168.1.10 → 203.0.113.10  TTL=64  proto=6', osi: [3, 2], layer: 3, note: '目的地址不在本地网段，帧的目的 MAC 写成网关的 MAC。',
          layers: [ETH(MAC_GW, MAC_CLIENT), IPV4(IP_CLIENT, IP_WEB, 6, '6 (TCP)', 20, { ttl: 64 }), TCP(52344, 80, 1, 1, 0x10, '0x10 ACK', 0)] }),
        P({ t: 0.003, src: IP_CLIENT, dst: IP_WEB, proto: 'IP', kind: 'request', phase: '转发', from: 'gateway', to: 'web', title: '路由器转发 · TTL-1',
          info: 'TTL 64 → 63 · 重写二层帧首部', osi: [3, 2], layer: 3, note: '路由器剥离以太网帧、TTL 减 1、重算校验和，再用新 MAC 封装发出。',
          layers: [ETH('aa:bb:cc:dd:ee:01', MAC_GW), IPV4(IP_CLIENT, IP_WEB, 6, '6 (TCP)', 20, { ttl: 63 }), TCP(52344, 80, 1, 1, 0x10, '0x10 ACK', 0)] }),
        P({ t: 0.021, src: IP_WEB, dst: IP_CLIENT, proto: 'ICMP', kind: 'response', phase: 'ICMP 差错', from: 'web', to: 'client', title: 'ICMP · 需要分片',
          info: 'Type=3 Code=4  Fragmentation needed, MTU=1500', osi: [3, 2], layer: 3, note: 'DF 置位却超过 MTU 时，路由器丢弃并回送 ICMP 差错，用于路径 MTU 发现。',
          layers: [ethR(), IPV4(IP_WEB, IP_CLIENT, 1, '1 (ICMP)', 56, { ttl: 52 }), ICMP(3, 4, 'Destination Unreachable', 1, 1)] }),
        P({ t: 0.025, src: IP_CLIENT, dst: IP_WEB, proto: 'IP', kind: 'request', phase: '分片 1/2', from: 'client', to: 'web', title: 'IP 分片 #1 (MF=1, offset=0)',
          info: 'id=0x1c46  MF=1  offset=0  1480 B', osi: [3, 2], layer: 3, displaySize: '1500 B', truncated: true,
          note: '第一片携带原数据报的前 1480 字节，MF=1 表示后面还有分片。',
          layers: [ethC(), IPV4(IP_CLIENT, IP_WEB, 6, '6 (TCP)', 120, { flags: 0x2000, frag: 0, id: 0x1c46 }), payload(1)] }),
        P({ t: 0.026, src: IP_CLIENT, dst: IP_WEB, proto: 'IP', kind: 'request', phase: '分片 2/2', from: 'client', to: 'web', title: 'IP 分片 #2 (MF=0, offset=185)',
          info: 'id=0x1c46  MF=0  offset=185  1480 B', osi: [3, 2], layer: 3, displaySize: '1500 B', truncated: true,
          note: '片偏移以 8 字节为单位：185 × 8 = 1480，恰好接在第一片之后。',
          layers: [ethC(), IPV4(IP_CLIENT, IP_WEB, 6, '6 (TCP)', 120, { flags: 0x0000, frag: 185, id: 0x1c46 }), payload(2)] })
      ]
    });
  })();

  /* 06 · ARP */
  (function () {
    const bcast = ETH('ff:ff:ff:ff:ff:ff', MAC_CLIENT, 0x0806, '0x0806 (ARP)');
    const uni = ETH(MAC_CLIENT, MAC_GW, 0x0806, '0x0806 (ARP)');
    def('arp', {
      name: 'ARP', title: '地址解析协议', cat: 'base', sub: 'IP → MAC 映射', osi: 2, layer: 2,
      nodes: ['client', 'gateway', 'web'], labels: { web: { name: '网段内主机', ip: IP_WEB } },
      steps: [{ t: '查 ARP 缓存', d: '未找到网关的 MAC 地址', at: 1 }, { t: '广播请求', d: '目的 MAC 为全 FF', at: 2 }, { t: '单播应答', d: '网关回复自己的 MAC', at: 3 }, { t: '写入缓存', d: '封装以太网帧正式发送', at: 4 }],
      desc: 'IP 报文最终要装进以太网帧才能发出。ARP 用一次广播 + 一次单播，把「下一跳 IP」解析成「下一跳 MAC」。',
      tip: 'ARP 工作在链路层，EtherType 为 0x0806，报文不经过 IP 层。缓存条目有老化时间，这也是 ARP 欺骗攻击的切入点。',
      stats: [{ k: '报文长度', v: '28 字节' }, { k: '请求方式', v: '广播 FF:FF:FF:FF:FF:FF' }, { k: '应答方式', v: '单播' }, { k: 'EtherType', v: '0x0806' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: 'Broadcast', proto: 'ARP', kind: 'request', phase: '广播请求', from: 'client', to: 'gateway', title: 'ARP 请求 · 谁有 192.168.1.1？',
          info: 'Who has 192.168.1.1? Tell 192.168.1.10', osi: [2], layer: 2, note: '交换机把广播帧复制到同 VLAN 的所有端口。',
          layers: [bcast, ARP(1, MAC_CLIENT, IP_CLIENT, '00:00:00:00:00:00', IP_GW)] }),
        P({ t: 0.002, src: IP_GW, dst: IP_CLIENT, proto: 'ARP', kind: 'response', phase: '单播应答', from: 'gateway', to: 'client', title: 'ARP 应答 · 192.168.1.1 在 00:1b:21:9c:4e:0a',
          info: '192.168.1.1 is at 00:1b:21:9c:4e:0a', osi: [2], layer: 2, note: '只有请求方会收到该单播帧，同时旁听主机也可据此更新缓存。',
          layers: [uni, ARP(2, MAC_GW, IP_GW, MAC_CLIENT, IP_CLIENT)] }),
        P({ t: 0.004, src: IP_CLIENT, dst: IP_WEB, proto: 'IP', kind: 'request', phase: '正式发送', from: 'client', to: 'web', title: '封装完成 · 以太网帧发出',
          info: 'Ether II → IPv4 → ICMP Echo Request', osi: [3, 2], layer: 3, note: '拿到网关 MAC 后，真正的 IP 报文才被封装成帧发出。',
          layers: [ethC(), IPV4(IP_CLIENT, IP_WEB, 1, '1 (ICMP)', 56), ICMP(8, 0, 'Echo Request', 0x0a3d, 1)] })
      ]
    });
  })();

  /* 07 · ICMP */
  def('icmp', {
    name: 'ICMP', title: 'Ping 与差错报告', cat: 'base', sub: '互联网控制报文协议', osi: 3, layer: 3,
    nodes: ['client', 'gateway', 'target'], labels: { target: { name: '目标主机', ip: IP_WEB } },
    steps: [{ t: '构造 Echo', d: 'Type=8, 附带序列号', at: 1 }, { t: '逐跳转发', d: 'TTL 每跳递减', at: 2 }, { t: '回显应答', d: 'Type=0, 数据原样返回', at: 3 }, { t: '计算 RTT', d: '用时间戳得到往返时延', at: 4 }],
    desc: 'ICMP 是 IP 的「控制平面」：报告差错、探测可达性。ping 用 Echo Request / Reply 测量往返时延，traceroute 则利用 TTL 超时报文逐跳定位路径。',
    tip: 'ICMP 直接封装在 IP 数据报里（协议号 1），没有传输层端口。Type 8/0 是查询报文，Type 3/11 是差错报文。',
    stats: [{ k: '协议号', v: '1 (承载于 IP)' }, { k: '请求类型', v: 'Type 8 / Code 0' }, { k: '应答类型', v: 'Type 0 / Code 0' }, { k: '往返时延', v: '≈ 17.4 ms' }],
    packets: [
      P({ t: 0.000, src: IP_CLIENT, dst: IP_WEB, proto: 'ICMP', kind: 'request', phase: 'Echo 请求', from: 'client', to: 'target', title: 'ICMP Echo Request · seq=1',
        info: 'Echo (ping) request  id=0x0a3d  seq=1  ttl=64', osi: [3, 2], layer: 3, note: '数据字段常写入发送时间戳，收到应答后即可算出 RTT。',
        layers: [ethC(), IPV4(IP_CLIENT, IP_WEB, 1, '1 (ICMP)', 56), ICMP(8, 0, 'Echo Request', 0x0a3d, 1)] }),
      P({ t: 0.001, src: IP_GW, dst: IP_CLIENT, proto: 'ICMP', kind: 'response', phase: 'TTL 超时', from: 'gateway', to: 'client', title: 'ICMP Time Exceeded · traceroute 第 1 跳',
        info: 'Type=11 Code=0  Time-to-live exceeded', osi: [3, 2], layer: 3, note: 'TTL 归零的路由器回送该报文，traceroute 由此得知第一跳地址。',
        layers: [ethR(), IPV4(IP_GW, IP_CLIENT, 1, '1 (ICMP)', 56, { ttl: 63 }), ICMP(11, 0, 'Time Exceeded', 1, 1)] }),
      P({ t: 0.017, src: IP_WEB, dst: IP_CLIENT, proto: 'ICMP', kind: 'response', phase: 'Echo 应答', from: 'target', to: 'client', title: 'ICMP Echo Reply · seq=1',
        info: 'Echo (ping) reply  id=0x0a3d  seq=1  ttl=52', osi: [3, 2], layer: 3, note: '目标主机把请求的数据字段逐字节回显。',
        layers: [ethR(), IPV4(IP_WEB, IP_CLIENT, 1, '1 (ICMP)', 56, { ttl: 52 }), ICMP(0, 0, 'Echo Reply', 0x0a3d, 1)] }),
      P({ t: 0.031, src: IP_CLIENT, dst: IP_WEB, proto: 'ICMP', kind: 'request', phase: 'Echo 请求', from: 'client', to: 'target', title: 'ICMP Echo Request · seq=2',
        info: 'Echo (ping) request  id=0x0a3d  seq=2  ttl=64', osi: [3, 2], layer: 3, note: '连续发送多个请求可统计丢包率与抖动。',
        layers: [ethC(), IPV4(IP_CLIENT, IP_WEB, 1, '1 (ICMP)', 56), ICMP(8, 0, 'Echo Request', 0x0a3d, 2)] })
    ]
  });

  /* 08 · DHCP */
  (function () {
    const mk = (op, type, xid, yi, from, to, t, title, info, note) => P({
      t, src: from === 'client' ? '0.0.0.0' : IP_GW, dst: to === 'client' ? '255.255.255.255' : '255.255.255.255',
      proto: 'DHCP', kind: from === 'client' ? 'request' : 'response', phase: title.split(' · ')[1] || 'DHCP', from, to, title, info,
      osi: [7, 4, 3, 2], layer: 7, note,
      layers: frame(from === 'client' ? '0.0.0.0' : IP_GW, '255.255.255.255', 17, '17 (UDP)',
        udpTo(from === 'client' ? 68 : 67, from === 'client' ? 67 : 68), DHCP(op, type, xid, yi),
        { eth: from === 'client' ? ETH('ff:ff:ff:ff:ff:ff', MAC_CLIENT) : ETH(MAC_CLIENT, MAC_GW) })
    });
    def('dhcp', {
      name: 'DHCP', title: '自动获取 IP 地址', cat: 'base', sub: '动态主机配置协议', osi: 7, layer: 7,
      nodes: ['client', 'gateway', 'dhcp'], labels: { dhcp: { name: 'DHCP 服务器', ip: '192.168.1.1' } },
      steps: [{ t: 'DISCOVER', d: '广播寻找可用服务器', at: 1 }, { t: 'OFFER', d: '服务器提供候选地址', at: 2 }, { t: 'REQUEST', d: '客户端选择并请求租约', at: 3 }, { t: 'ACK', d: '确认租约与网络参数', at: 4 }],
      desc: '新主机没有 IP 也能通信：DHCP 用广播完成 DORA 四步，一次性下发 IP、掩码、网关与 DNS 服务器地址。',
      tip: '客户端用 0.0.0.0:68 → 255.255.255.255:67 广播；因为还没有 IP，UDP 与 IP 首部都填特殊地址，靠 MAC 地址识别客户端。',
      stats: [{ k: '交互步骤', v: 'DORA 4 报文' }, { k: '客户端端口', v: 'UDP 68' }, { k: '服务端端口', v: 'UDP 67' }, { k: '典型租约', v: '86400 s (24 h)' }],
      packets: [
        mk(1, 1, 0x3a91f0b2, '0.0.0.0', 'client', 'dhcp', 0.000, 'DHCP Discover · 发现', 'DHCP Discover  ·  Transaction ID 0x3a91f0b2', '主机刚接入网络，还没有 IP，只能用广播寻找 DHCP 服务器。'),
        mk(2, 2, 0x3a91f0b2, IP_CLIENT, 'dhcp', 'client', 0.013, 'DHCP Offer · 提供', 'DHCP Offer  ·  yiaddr 192.168.1.10', '服务器从地址池挑一个地址，附上掩码、网关、DNS 等 Option。'),
        mk(1, 3, 0x3a91f0b2, '0.0.0.0', 'client', 'dhcp', 0.015, 'DHCP Request · 请求', 'DHCP Request  ·  Requested IP 192.168.1.10', '客户端广播告知「我选用了这台服务器提供的地址」，让其他服务器收回 Offer。'),
        mk(2, 5, 0x3a91f0b2, IP_CLIENT, 'dhcp', 'client', 0.028, 'DHCP ACK · 确认', 'DHCP ACK  ·  Lease time 86400 s', '租约生效，主机配置网卡并可以开始正常通信。')
      ]
    });
  })();

  /* 09 · HTTPS */
  (function () {
    const encGet = LINES('tls', '加密的应用数据', 'TLS', C.tls, [
      { n: 'TLS 记录头', v: '\x17\x03\x03\x02\x1a', d: '0x17 表示应用数据记录；之后的内容全部被 AEAD 加密。' },
      { n: '密文片段', v: U.seq(64, 0x5c).map(c => String.fromCharCode(c)).join(''), d: '抓包者只能看到密文与随机填充，无法读出 GET 路径或 Cookie。' }
    ], 'HTTPS = HTTP over TLS：HTTP 报文格式不变，只是被装进加密的 TLS 记录里。');
    const hello = TLS_CLIENTHELLO('www.example.com');
    const srvRandom = U.seq(32, 0x4b, 3);
    const keyShare = U.seq(32, 0x71, 13);
    const shBody = [0x03, 0x03, ...srvRandom, 0x13, 0x01, 0x00,
      ...U.u16(36), 0x00, 0x33, ...U.u16(32), ...keyShare];
    const sh = [0x02, ...U.u24(shBody.length), ...shBody];
    const shRec = [0x16, 0x03, 0x01, ...U.u16(sh.length), ...sh];
    const serverHello = TLS('TLS 1.3 · ServerHello', shRec, [
      F('记录类型 / 版本', '0x16 Handshake · 0x0301', 0, 3, '仍是握手记录，记录层版本保持兼容值。'),
      F('记录长度', sh.length + ' 字节', 3, 2, '本条记录承载的握手消息长度。'),
      F('握手类型', '0x02 (ServerHello)', 5, 1, '服务端回应选定的参数。'),
      F('服务端版本', '0x0303', 9, 2, 'legacy_version。'),
      F('服务端随机数', U.hx(srvRandom, 0, 8) + ' … (32 字节)', 11, 32, '与客户端随机数共同参与密钥派生。'),
      F('选定密码套件', '0x1301 TLS_AES_128_GCM_SHA256', 43, 2, '双方后续用该对称算法加密应用数据。'),
      F('扩展 · Key Share', 'X25519 临时公钥 (32 字节)', 48, 36, 'ECDHE 临时公钥；双方据此算出相同的共享密钥，实现前向保密。')
    ]);
    def('https', {
      name: 'HTTPS', title: '加密的 Web 通信', cat: 'sec', sub: 'HTTP over TLS', url: 'https://www.example.com',
      osi: 7, layer: 7, nodes: ['url', 'client', 'gateway', 'dns', 'web'],
      labels: { web: { name: 'Web 服务器 :443', ip: IP_WEB } },
      steps: [{ t: 'DNS 解析', d: '先拿到服务器 IP', at: 1 }, { t: 'TCP 握手', d: '连接 443 端口', at: 3 }, { t: 'TLS 握手', d: '协商套件并验证证书', at: 5 }, { t: '密钥派生', d: 'ECDHE 生成会话密钥', at: 6 }, { t: '加密传输', d: 'HTTP 报文被封装为密文', at: 8 }],
      desc: 'HTTPS 在 TCP 与 HTTP 之间插入 TLS：先握手验证身份并协商密钥，随后所有应用数据都以密文传输，中间人只能看到 IP、端口与大致长度。',
      tip: 'SNI 与证书在握手中仍以明文出现；TLS 1.3 把握手压缩到 1-RTT，并对已访问过的站点支持 0-RTT 早期数据。',
      stats: [{ k: '默认端口', v: '443' }, { k: 'TLS 版本', v: '1.3 / 0x0303' }, { k: '握手开销', v: '1 RTT' }, { k: '加密套件', v: 'TLS_AES_128_GCM_SHA256' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: IP_DNS, proto: 'DNS', kind: 'dns', phase: 'DNS 查询', from: 'client', to: 'dns', title: 'DNS 查询',
          info: 'Standard query A www.example.com', osi: [7, 4, 3, 2], layer: 7, note: 'HTTPS 并不加密 DNS 查询（除非使用 DoH / DoT）。',
          layers: frame(IP_CLIENT, IP_DNS, 17, '17 (UDP)', udpTo(53411, 53), DNS_QUERY('www.example.com', 0x7b21)) }),
        P({ t: 0.011, src: IP_DNS, dst: IP_CLIENT, proto: 'DNS', kind: 'dns', phase: 'DNS 响应', from: 'dns', to: 'client', title: 'DNS 响应',
          info: 'Standard query response A 203.0.113.10', osi: [7, 4, 3, 2], layer: 7, note: '拿到 IP 后才能向 443 端口发起连接。',
          layers: frame(IP_DNS, IP_CLIENT, 17, '17 (UDP)', udpTo(53, 53411), DNS_RESPONSE('www.example.com', 0x7b21, IP_WEB), { inbound: true }) }),
        P({ t: 0.024, src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'tcp', phase: 'TCP 握手', from: 'client', to: 'web', title: 'TCP SYN → 443',
          info: '53412 → 443 [SYN] Seq=0', osi: [4, 3, 2], layer: 4, note: 'TLS 依赖 TCP 提供的可靠字节流。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(53412, 443, 0, 0, 0x02, '0x02 SYN')) }),
        P({ t: 0.041, src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'tcp', phase: 'TCP 握手', from: 'web', to: 'client', title: 'TCP SYN, ACK',
          info: '443 → 53412 [SYN, ACK] Seq=0 Ack=1', osi: [4, 3, 2], layer: 4, note: '三次握手的第二步。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(443, 53412, 0, 1, 0x12, '0x12 SYN,ACK'), null, { inbound: true }) }),
        P({ t: 0.058, src: IP_CLIENT, dst: IP_WEB, proto: 'TLS', kind: 'tls', phase: 'TLS 握手', from: 'client', to: 'web', title: 'TLS ClientHello',
          info: 'ClientHello  ·  SNI=www.example.com  ·  TLS 1.3', osi: [7, 4, 3, 2], layer: 7, note: '客户端列出支持的版本、套件与扩展，并给出密钥共享公钥。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(53412, 443, 1, 1, 0x18, '0x18 PSH,ACK'), hello) }),
        P({ t: 0.102, src: IP_WEB, dst: IP_CLIENT, proto: 'TLS', kind: 'tls', phase: 'TLS 握手', from: 'web', to: 'client', title: 'TLS ServerHello + 证书',
          info: 'ServerHello  ·  Certificate  ·  Finished', osi: [7, 4, 3, 2], layer: 7, note: '服务端选定套件、发送证书链证明身份，并用证书私钥签名握手摘要。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(443, 53412, 1, 1, 0x18, '0x18 PSH,ACK'), serverHello, { inbound: true }) }),
        P({ t: 0.118, src: IP_CLIENT, dst: IP_WEB, proto: 'TLS', kind: 'tls', phase: '密钥派生', from: 'client', to: 'web', title: 'TLS Finished',
          info: 'Change Cipher Spec  ·  Finished (verify_data)', osi: [7, 4, 3, 2], layer: 7, note: '双方用 HKDF 从共享密钥派生出会话密钥，握手摘要校验通过后切换加密。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(53412, 443, 2, 2, 0x18, '0x18 PSH,ACK'), encGet) }),
        P({ t: 0.163, src: IP_WEB, dst: IP_CLIENT, proto: 'TLS', kind: 'tls', phase: '加密传输', from: 'web', to: 'client', title: 'Application Data',
          info: 'TLSv1.3 Application Data  ·  加密的 HTTP 200 OK', osi: [7, 4, 3, 2], layer: 7, note: '此后 HTTP 请求与响应都变成 0x17 类型的加密记录。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(443, 53412, 2, 2, 0x18, '0x18 PSH,ACK'), encGet, { inbound: true }) })
      ]
    });
  })();

  /* 10 · TLS 证书与密钥交换 */
  (function () {
    const cert = TLS('TLS 1.3 · Certificate', [0x16, 0x03, 0x03, 0x03, 0x20, 0x0b, 0x00, 0x03, 0x1c,
      0x00, 0x03, 0x19, 0x00, 0x03, 0x16, 0x30, 0x82, 0x03, 0x12, ...U.seq(96, 0x30, 5)], [
      F('记录类型', '0x16 (Handshake)', 0, 1, '证书属于握手阶段。'),
      F('握手类型', '0x0b (Certificate)', 5, 1, '服务端发送证书链。'),
      F('证书链长度', '0x031c (796 字节)', 6, 3, '站点证书 + 中间 CA 证书。'),
      F('证书条目长度', '0x0316', 9, 3, '单张 DER 编码的 X.509 证书。'),
      F('ASN.1 SEQUENCE', '0x30 0x82 …', 12, 4, 'X.509 证书以 ASN.1 DER 序列开头。'),
      F('主体 Common Name', 'CN=www.example.com', 16, 22, '证书绑定的域名，浏览器校验它与地址栏是否一致。'),
      F('签发者', 'CN=Example Intermediate CA', 38, 30, '沿证书链向上验证，直到本地信任的根证书。'),
      F('公钥算法', 'ECDSA P-256', 68, 20, '用于验证服务端对握手消息的签名。'),
      F('有效期', '2026-01-01 → 2027-01-01', 88, 20, '过期或尚未生效的证书会被浏览器拒绝。')
    ]);
    const finished = TLS('TLS 1.3 · Finished', [0x16, 0x03, 0x03, 0x00, 0x35, 0x14, 0x00, 0x00, 0x31, ...U.seq(49, 0xa7, 11)], [
      F('握手类型', '0x14 (Finished)', 5, 1, '握手完整性校验的最后一步。'),
      F('verify_data', U.hx(U.seq(49, 0xa7, 11), 0, 8) + ' … (48 字节)', 9, 48, '对整个握手记录做 HMAC，证明双方持有相同密钥且消息未被篡改。')
    ]);
    def('tls', {
      name: 'TLS', title: '证书与密钥交换', cat: 'sec', sub: '传输层安全协议', osi: 6, layer: 6,
      nodes: ['client', 'gateway', 'web'], labels: { web: { name: 'TLS 服务端', ip: IP_WEB } },
      steps: [{ t: '协商参数', d: 'ClientHello 给出算法列表', at: 1 }, { t: '验证身份', d: '校验证书链与域名', at: 2 }, { t: '密钥交换', d: 'ECDHE 生成共享秘密', at: 3 }, { t: '握手完成', d: 'Finished 校验完整性', at: 4 }],
      desc: 'TLS 把「身份可信」「密钥安全」「内容保密」三件事分开解决：证书链解决身份，ECDHE 解决密钥，AEAD 对称加密解决机密性与完整性。',
      tip: '前向保密（PFS）：每次握手生成临时密钥对，即使长期私钥日后泄露，历史会话也无法被解密。',
      stats: [{ k: '密钥交换', v: 'ECDHE / X25519' }, { k: '身份认证', v: 'X.509 证书链' }, { k: '对称加密', v: 'AES-128-GCM' }, { k: '密钥派生', v: 'HKDF-SHA256' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: IP_WEB, proto: 'TLS', kind: 'tls', phase: '协商参数', from: 'client', to: 'web', title: 'ClientHello',
          info: 'TLS 1.3  ·  cipher_suites=4  ·  key_share=X25519', osi: [6, 4, 3, 2], layer: 6, note: '客户端一次性把密钥共享材料发出，省去 TLS 1.2 的额外往返。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(53412, 443, 1, 1, 0x18, '0x18 PSH,ACK'), TLS_CLIENTHELLO('www.example.com')) }),
        P({ t: 0.044, src: IP_WEB, dst: IP_CLIENT, proto: 'TLS', kind: 'tls', phase: '验证身份', from: 'web', to: 'client', title: 'Certificate',
          info: 'Certificate  ·  CN=www.example.com  ·  796 B', osi: [6, 4, 3, 2], layer: 6, note: '浏览器用本地根证书库逐级验证签名，并核对域名与有效期。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(443, 53412, 1, 1, 0x18, '0x18 PSH,ACK'), cert, { inbound: true }) }),
        P({ t: 0.061, src: IP_WEB, dst: IP_CLIENT, proto: 'TLS', kind: 'tls', phase: '密钥交换', from: 'web', to: 'client', title: 'ServerKeyExchange / CertificateVerify',
          info: 'key_share  ·  signature=ECDSA-SHA256', osi: [6, 4, 3, 2], layer: 6, note: '服务端用证书私钥对握手摘要签名，证明自己确实持有该证书。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(443, 53412, 2, 1, 0x18, '0x18 PSH,ACK'), finished, { inbound: true }) }),
        P({ t: 0.078, src: IP_CLIENT, dst: IP_WEB, proto: 'TLS', kind: 'tls', phase: '握手完成', from: 'client', to: 'web', title: 'Finished',
          info: 'Finished  ·  verify_data (HMAC over transcript)', osi: [6, 4, 3, 2], layer: 6, note: '校验通过后派生应用流量密钥，后续记录全部加密。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpTo(53412, 443, 2, 2, 0x18, '0x18 PSH,ACK'), finished) })
      ]
    });
  })();

  /* 11 · WebSocket */
  (function () {
    const up = LINES('http', 'HTTP 升级请求', 'HTTP', C.http, [
      { n: '请求行', v: 'GET /chat HTTP/1.1\r\n', d: 'WebSocket 借用一个普通 HTTP 请求完成协议升级。' },
      { n: 'Host', v: 'Host: www.example.com\r\n', d: '目标主机。' },
      { n: 'Upgrade', v: 'Upgrade: websocket\r\n', d: '请求把连接从 HTTP 切换到 WebSocket。' },
      { n: 'Connection', v: 'Connection: Upgrade\r\n', d: '与 Upgrade 成对出现。' },
      { n: 'Sec-WebSocket-Key', v: 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n', d: '随机 Base64 值，服务端用它派生 Accept，防止缓存代理误判。' },
      { n: 'Sec-WebSocket-Version', v: 'Sec-WebSocket-Version: 13\r\n', d: 'RFC 6455 定义的版本 13。' },
      { n: '首部结束', v: '\r\n', d: '此后不再使用 HTTP 语法，改传二进制帧。' }
    ], '101 之后，同一条 TCP 连接被「接管」，双方改为交换 WebSocket 帧。');
    const ok = LINES('http', 'HTTP 升级响应', 'HTTP', C.http, [
      { n: '状态行', v: 'HTTP/1.1 101 Switching Protocols\r\n', d: '101 表示协议切换成功，连接不会关闭。' },
      { n: 'Upgrade', v: 'Upgrade: websocket\r\n', d: '确认切换目标协议。' },
      { n: 'Connection', v: 'Connection: Upgrade\r\n', d: '确认连接语义。' },
      { n: 'Sec-WebSocket-Accept', v: 'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n', d: 'Key 拼接固定 GUID 后取 SHA-1 再 Base64。' },
      { n: '首部结束', v: '\r\n', d: '握手结束，进入全双工帧传输。' }
    ]);
    const frameWs = (opcode, text) => {
      const p = U.s(text);
      const bytes = [0x81, 0x80 | p.length, 0x12, 0x34, 0x56, 0x78,
        ...p.map((b, i) => b ^ [0x12, 0x34, 0x56, 0x78][i % 4])];
      return L('ws', 'WebSocket 帧', 'WS', C.ws, bytes, [
        F('FIN / RSV / Opcode', '0x81 (FIN=1, Text)', 0, 1, '最高位 FIN 表示这是完整消息；低 4 位 0x1 表示文本帧。'),
        F('MASK / 长度', (0x80 | p.length) + ' (masked, ' + p.length + ' B)', 1, 1, '客户端发出的帧必须掩码；长度 <126 时直接用 7 位表示。'),
        F('掩码密钥', '0x12345678', 2, 4, '每帧随机生成，防止中间设备把载荷误认成 HTTP 请求。'),
        F('掩码后载荷', text, 6, p.length, '载荷与掩码密钥逐字节异或；服务端用同样的密钥还原原文：' + text)
      ]);
    };
    const tcpUp = (seq, ack) => tcpTo(53420, 80, seq, ack, 0x18, '0x18 PSH,ACK');
    def('websocket', {
      name: 'WebSocket', title: '全双工实时通道', cat: 'app', sub: 'HTTP 升级 + 帧协议', url: 'ws://www.example.com/chat',
      osi: 7, layer: 7, nodes: ['url', 'client', 'gateway', 'web'], labels: { web: { name: 'WebSocket 服务', ip: IP_WEB } },
      steps: [{ t: 'HTTP 握手', d: '发送 Upgrade 请求', at: 1 }, { t: '101 切换', d: '服务端同意切换协议', at: 2 }, { t: '客户端帧', d: '带掩码的文本帧', at: 3 }, { t: '服务端帧', d: '无需掩码，可主动推送', at: 4 }],
      desc: 'WebSocket 只借用一次 HTTP 请求完成升级，之后在同一条 TCP 连接上以极小的帧头做真正的双向通信，服务端可以主动推送。',
      tip: '客户端 → 服务端的帧必须掩码（MASK=1），服务端 → 客户端的帧不能掩码。帧头最小仅 2 字节，远小于 HTTP 首部。',
      stats: [{ k: '升级状态码', v: '101 Switching Protocols' }, { k: '帧头开销', v: '2 ~ 14 字节' }, { k: '客户端掩码', v: '强制 (RFC 6455)' }, { k: '连接方向', v: '全双工' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: IP_WEB, proto: 'HTTP', kind: 'request', phase: '升级请求', from: 'client', to: 'web', title: 'HTTP Upgrade 请求',
          info: 'GET /chat HTTP/1.1  ·  Upgrade: websocket', osi: [7, 4, 3, 2], layer: 7, note: '握手阶段仍是标准 HTTP 报文，可穿过常规代理与防火墙。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpUp(1, 1), up) }),
        P({ t: 0.026, src: IP_WEB, dst: IP_CLIENT, proto: 'HTTP', kind: 'response', phase: '101 切换', from: 'web', to: 'client', title: '101 Switching Protocols',
          info: 'HTTP/1.1 101  ·  Upgrade: websocket', osi: [7, 4, 3, 2], layer: 7, note: '响应后 TCP 连接保持打开，但语义已从「请求-响应」变为「帧流」。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 53420, 1, 260, 0x18, '0x18 PSH,ACK'), ok, { inbound: true }) }),
        P({ t: 0.041, src: IP_CLIENT, dst: IP_WEB, proto: 'WS', kind: 'request', phase: '客户端帧', from: 'client', to: 'web', title: 'WebSocket Text Frame (masked)',
          info: 'FIN=1 Opcode=0x1  ·  "hello"', osi: [7, 4, 3, 2], layer: 7, note: '2 字节帧头 + 4 字节掩码 + 载荷，开销极小。',
          layers: frame(IP_CLIENT, IP_WEB, 6, '6 (TCP)', tcpUp(260, 1), frameWs(1, 'hello')) }),
        P({ t: 0.088, src: IP_WEB, dst: IP_CLIENT, proto: 'WS', kind: 'response', phase: '服务端帧', from: 'web', to: 'client', title: 'WebSocket Text Frame (server push)',
          info: 'FIN=1 Opcode=0x1  ·  "pong:hello"', osi: [7, 4, 3, 2], layer: 7, note: '服务端无需等待请求即可主动推送，这是实时应用的关键。',
          layers: frame(IP_WEB, IP_CLIENT, 6, '6 (TCP)', tcpTo(80, 53420, 1, 271, 0x18, '0x18 PSH,ACK'), frameWs(1, 'pong:hello'), { inbound: true }) })
      ]
    });
  })();

  /* 12 · SMTP */
  (function () {
    const cmd = (n, v, d) => LINES('smtp', 'SMTP 命令', 'SMTP', C.smtp, [{ n, v, d }]);
    const reply = (n, v, d) => LINES('smtp', 'SMTP 应答', 'SMTP', C.smtp, [{ n, v, d }]);
    const t = (seq, ack) => tcpTo(53430, 25, seq, ack, 0x18, '0x18 PSH,ACK', { service: 'smtp' });
    const tr = (seq, ack) => tcpTo(25, 53430, seq, ack, 0x18, '0x18 PSH,ACK', { service: 'smtp' });
    def('smtp', {
      name: 'SMTP', title: '邮件投递', cat: 'app', sub: '简单邮件传输协议', osi: 7, layer: 7,
      nodes: ['client', 'gateway', 'mail'], labels: { mail: { name: '邮件服务器', ip: IP_MAIL } },
      steps: [{ t: '建立连接', d: 'TCP 连接到 25 端口', at: 1 }, { t: '身份协商', d: 'EHLO 交换扩展能力', at: 2 }, { t: '指定收发方', d: 'MAIL FROM / RCPT TO', at: 4 }, { t: '传输内容', d: 'DATA 到 CRLF.CRLF 结束', at: 6 }],
      desc: 'SMTP 是纯文本的行协议：客户端发命令，服务端回三位数字状态码。邮件正文以单独一行「.」结束，之后连接可复用或退出。',
      tip: 'SMTP 只负责「投递」，收件人读取邮件用 IMAP / POP3。现代部署在 587 端口配合 STARTTLS 升级加密。',
      stats: [{ k: '默认端口', v: '25 / 587' }, { k: '传输层', v: 'TCP' }, { k: '应答格式', v: '3 位状态码 + 文本' }, { k: '结束标记', v: 'CRLF . CRLF' }],
      packets: [
        P({ t: 0.000, src: IP_MAIL, dst: IP_CLIENT, proto: 'SMTP', kind: 'response', phase: '服务就绪', from: 'mail', to: 'client', title: '220 服务就绪',
          info: '220 mail.example.com ESMTP ready', osi: [7, 4, 3, 2], layer: 7, note: '连接建立后服务端先说话，客户端等待 220 再发命令。',
          layers: frame(IP_MAIL, IP_CLIENT, 6, '6 (TCP)', tr(1, 1), reply('状态行', '220 mail.example.com ESMTP ready\r\n', '2xx 表示成功；220 为服务就绪。'), { inbound: true }) }),
        P({ t: 0.018, src: IP_CLIENT, dst: IP_MAIL, proto: 'SMTP', kind: 'request', phase: 'EHLO', from: 'client', to: 'mail', title: 'EHLO 客户端问候',
          info: 'EHLO client.local', osi: [7, 4, 3, 2], layer: 7, note: 'EHLO 请求服务端列出支持的 ESMTP 扩展。',
          layers: frame(IP_CLIENT, IP_MAIL, 6, '6 (TCP)', t(1, 1), cmd('命令', 'EHLO client.local\r\n', '扩展版 HELO，支持 STARTTLS、SIZE、AUTH 等能力通告。')) }),
        P({ t: 0.036, src: IP_MAIL, dst: IP_CLIENT, proto: 'SMTP', kind: 'response', phase: '能力列表', from: 'mail', to: 'client', title: '250 扩展能力',
          info: '250-mail.example.com  ·  250-STARTTLS  ·  250 SIZE 35882577', osi: [7, 4, 3, 2], layer: 7, note: '多行应答：最后一行用「250 空格」，前面用「250- 连字符」。',
          layers: frame(IP_MAIL, IP_CLIENT, 6, '6 (TCP)', tr(1, 20), reply('多行应答', '250-mail.example.com\r\n250-STARTTLS\r\n250 SIZE 35882577\r\n', '倒数第二行以连字符表示还有后续行。'), { inbound: true }) }),
        P({ t: 0.052, src: IP_CLIENT, dst: IP_MAIL, proto: 'SMTP', kind: 'request', phase: '指定发件人', from: 'client', to: 'mail', title: 'MAIL FROM',
          info: 'MAIL FROM:<alice@example.com>', osi: [7, 4, 3, 2], layer: 7, note: '信封发件人，与邮件头里的 From 可以不同。',
          layers: frame(IP_CLIENT, IP_MAIL, 6, '6 (TCP)', t(20, 70), cmd('命令', 'MAIL FROM:<alice@example.com>\r\n', '开启一次邮件事务，指定退回地址。')) }),
        P({ t: 0.071, src: IP_CLIENT, dst: IP_MAIL, proto: 'SMTP', kind: 'request', phase: '指定收件人', from: 'client', to: 'mail', title: 'RCPT TO',
          info: 'RCPT TO:<bob@example.net>', osi: [7, 4, 3, 2], layer: 7, note: '可重复多次，实现一封邮件多个收件人。',
          layers: frame(IP_CLIENT, IP_MAIL, 6, '6 (TCP)', t(48, 70), cmd('命令', 'RCPT TO:<bob@example.net>\r\n', '每个收件人单独确认，失败不影响其他收件人。')) }),
        P({ t: 0.093, src: IP_CLIENT, dst: IP_MAIL, proto: 'SMTP', kind: 'request', phase: '邮件内容', from: 'client', to: 'mail', title: 'DATA 邮件正文',
          info: 'DATA  ·  Subject: Hello  ·  CRLF.CRLF', osi: [7, 4, 3, 2], layer: 7, note: '服务端回 354 后开始接收，遇到单独一行「.」表示结束。',
          layers: frame(IP_CLIENT, IP_MAIL, 6, '6 (TCP)', t(75, 70), LINES('smtp', 'SMTP 邮件实体', 'SMTP', C.smtp, [
            { n: 'DATA 命令', v: 'DATA\r\n', d: '请求开始传输邮件内容。' },
            { n: '邮件头 Subject', v: 'Subject: Protocol Explorer 测试邮件\r\n', d: '邮件头使用与 HTTP 类似的「名称: 值」格式。' },
            { n: '空行', v: '\r\n', d: '头部与正文的分隔。' },
            { n: '正文', v: '这是一封用于说明协议交互的邮件。\r\n', d: '正文可用 7bit / quoted-printable / base64 编码。' },
            { n: '结束标记', v: '.\r\n', d: '单独一行句点，标志邮件实体结束。' }
          ])) })
      ]
    });
  })();

  /* 13 · FTP */
  (function () {
    const c = (n, v, d) => LINES('ftp', 'FTP 命令', 'FTP', C.ftp, [{ n, v, d }]);
    const r = (n, v, d) => LINES('ftp', 'FTP 应答', 'FTP', C.ftp, [{ n, v, d }]);
    const ctl = (seq, ack) => tcpTo(53440, 21, seq, ack, 0x18, '0x18 PSH,ACK', { service: 'ftp' });
    const ctlr = (seq, ack) => tcpTo(21, 53440, seq, ack, 0x18, '0x18 PSH,ACK', { service: 'ftp' });
    const data = LINES('data', '文件内容', 'DATA', C.payload, [{ n: '目录列表', v: '-rw-r--r--  1  owner  group  12480  index.html\r\n-rw-r--r--  1  owner  group   2048  readme.txt\r\n', d: '数据连接上传输的是纯文件内容，不夹杂 FTP 命令。' }]);
    def('ftp', {
      name: 'FTP', title: '双连接文件传输', cat: 'app', sub: '文件传输协议', osi: 7, layer: 7,
      nodes: ['client', 'gateway', 'ftp'], labels: { ftp: { name: 'FTP 服务器', ip: IP_FTP } },
      steps: [{ t: '控制连接', d: '登录到 21 端口', at: 1 }, { t: '身份认证', d: 'USER / PASS', at: 3 }, { t: '协商数据端口', d: 'PASV 进入被动模式', at: 4 }, { t: '数据连接', d: '另开一条 TCP 连接传文件', at: 6 }],
      desc: 'FTP 的特别之处是使用两条 TCP 连接：21 端口的控制连接长期存活只传命令，数据连接按需建立、传完即关。',
      tip: '被动模式 PASV 由服务端给出端口，客户端主动连过去，便于穿越 NAT；主动模式 PORT 则相反。明文传输账号密码是 FTP 的主要缺陷。',
      stats: [{ k: '控制端口', v: '21' }, { k: '数据端口', v: '动态 / PASV' }, { k: '连接数量', v: '2 条 TCP 连接' }, { k: '传输模式', v: '明文（建议 FTPS/SFTP）' }],
      packets: [
        P({ t: 0.000, src: IP_FTP, dst: IP_CLIENT, proto: 'FTP', kind: 'response', phase: '服务就绪', from: 'ftp', to: 'client', title: '220 FTP 服务就绪',
          info: '220 (vsFTPd 3.0.5)', osi: [7, 4, 3, 2], layer: 7, note: '控制连接建立后服务端主动问候。',
          layers: frame(IP_FTP, IP_CLIENT, 6, '6 (TCP)', ctlr(1, 1), r('应答', '220 (vsFTPd 3.0.5)\r\n', '220 表示服务已准备好接收命令。'), { inbound: true }) }),
        P({ t: 0.021, src: IP_CLIENT, dst: IP_FTP, proto: 'FTP', kind: 'request', phase: '用户名', from: 'client', to: 'ftp', title: 'USER 用户名',
          info: 'USER anonymous', osi: [7, 4, 3, 2], layer: 7, note: '命令以明文传输，抓包即可看到用户名。',
          layers: frame(IP_CLIENT, IP_FTP, 6, '6 (TCP)', ctl(1, 1), c('命令', 'USER anonymous\r\n', '匿名登录常用 anonymous 作为用户名。')) }),
        P({ t: 0.038, src: IP_CLIENT, dst: IP_FTP, proto: 'FTP', kind: 'request', phase: '密码', from: 'client', to: 'ftp', title: 'PASS 密码',
          info: 'PASS guest@example.com', osi: [7, 4, 3, 2], layer: 7, note: '密码同样明文，生产环境应改用 FTPS 或 SFTP。',
          layers: frame(IP_CLIENT, IP_FTP, 6, '6 (TCP)', ctl(19, 26), c('命令', 'PASS guest@example.com\r\n', 'FTP 明文口令的主要安全风险。')) }),
        P({ t: 0.055, src: IP_CLIENT, dst: IP_FTP, proto: 'FTP', kind: 'request', phase: '被动模式', from: 'client', to: 'ftp', title: 'PASV 进入被动模式',
          info: 'PASV', osi: [7, 4, 3, 2], layer: 7, note: '要求服务端开放一个临时端口等待客户端连接。',
          layers: frame(IP_CLIENT, IP_FTP, 6, '6 (TCP)', ctl(45, 50), c('命令', 'PASV\r\n', '被动模式适合客户端位于 NAT 之后的场景。')) }),
        P({ t: 0.072, src: IP_FTP, dst: IP_CLIENT, proto: 'FTP', kind: 'response', phase: '数据端口', from: 'ftp', to: 'client', title: '227 Entering Passive Mode',
          info: '227 Entering Passive Mode (198,51,100,40,195,80)', osi: [7, 4, 3, 2], layer: 7, note: '端口号 = 195×256 + 80 = 50000。前四个数是服务器 IP。',
          layers: frame(IP_FTP, IP_CLIENT, 6, '6 (TCP)', ctlr(50, 50), r('应答', '227 Entering Passive Mode (198,51,100,40,195,80)\r\n', '地址与端口被拆成 6 个十进制数写入文本。'), { inbound: true }) }),
        P({ t: 0.104, src: IP_FTP, dst: IP_CLIENT, proto: 'FTP', kind: 'response', phase: '数据连接', from: 'ftp', to: 'client', title: 'LIST 目录列表 · 数据连接',
          info: '150 Opening data connection  ·  2 files', osi: [7, 4, 3, 2], layer: 7, note: '这条报文走的是另一条 TCP 连接（源端口 20 / 或 PASV 端口）。',
          layers: frame(IP_FTP, IP_CLIENT, 6, '6 (TCP)', tcpTo(50000, 53441, 1, 1, 0x18, '0x18 PSH,ACK'), data, { inbound: true }) })
      ]
    });
  })();

  /* 14 · QUIC */
  (function () {
    const initial = (label, dcid, payloadText) => {
      const p = U.s(payloadText);
      const bytes = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, ...dcid, 0x08, 0xa1, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x82,
        ...U.u16(4 + p.length), ...U.seq(4, 0x31), ...p];
      return L('quic', label, 'QUIC', C.quic, bytes, [
        F('长首部 / 固定位', '0xC0 (Long Header)', 0, 1, '首比特 1 表示长首部，用于建连阶段；建连后改用 1 字节短首部。'),
        F('版本号', '0x00000001 (QUIC v1)', 1, 4, 'RFC 9000 定义的 QUIC 版本 1。'),
        F('目标连接 ID 长度 / DCID', '8 字节', 5, 9, '连接 ID 独立于 IP+端口，网络切换（Wi-Fi → 4G）时连接不中断。'),
        F('源连接 ID 长度 / SCID', '8 字节', 14, 9, '双方各自选择连接 ID 用于路由与加密标识。'),
        F('令牌长度 / 长度', (48 + p.length) + ' 字节', 23, 2, '变长整数编码的剩余报文长度。'),
        F('包号 PN', '0 / 1', 25, 4, '严格递增且永不重用，用于丢包检测与重传。'),
        F('加密载荷', payloadText.slice(0, 24), 29, p.length, 'Initial 之后的载荷整体加密，包含 TLS 1.3 ClientHello / ServerHello。')
      ]);
    };
    const tlsPayload = 'ClientHello(TLS1.3, SNI=www.example.com, ALPN=h3)';
    const srvPayload = 'ServerHello + Certificate + Finished (h3)';
    def('quic', {
      name: 'QUIC', title: '基于 UDP 的下一代传输', cat: 'sec', sub: 'HTTP/3 底层协议', url: 'https://www.example.com',
      osi: 4, layer: 4, nodes: ['url', 'client', 'gateway', 'web'], labels: { web: { name: 'HTTP/3 服务', ip: IP_WEB } },
      steps: [{ t: 'Initial', d: 'UDP 上直接发起加密握手', at: 1 }, { t: '合并握手', d: '传输 + 加密一次完成', at: 2 }, { t: '0-RTT / 1-RTT', d: '最快 1 个 RTT 即可发数据', at: 3 }, { t: '多路复用', d: '流之间互不阻塞', at: 4 }],
      desc: 'QUIC 把 TLS 1.3 握手、可靠传输、拥塞控制与多路复用全部放进 UDP 之上的用户态协议，解决了 TCP 的队头阻塞，并支持连接迁移。',
      tip: 'TCP + TLS 1.2 建连需要 2~3 个 RTT，QUIC 首次 1-RTT、复访可 0-RTT。连接 ID 让 IP 变化时连接依旧存活。',
      stats: [{ k: '承载协议', v: 'UDP / 443' }, { k: '首次建连', v: '1 RTT' }, { k: '加密', v: '强制 TLS 1.3' }, { k: '队头阻塞', v: '仅流内，跨流无阻塞' }],
      packets: [
        P({ t: 0.000, src: IP_CLIENT, dst: IP_WEB, proto: 'QUIC', kind: 'tls', phase: 'Initial', from: 'client', to: 'web', title: 'QUIC Initial · ClientHello',
          info: 'Initial, DCID=0x8394c8f03e515708, PKN: 0', osi: [4, 3, 2], layer: 4, note: '无需 TCP 握手：第一个 UDP 数据报就带上 TLS ClientHello。',
          layers: frame(IP_CLIENT, IP_WEB, 17, '17 (UDP)', udpTo(53450, 443), initial('QUIC Initial (Client)', [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08], tlsPayload)) }),
        P({ t: 0.043, src: IP_WEB, dst: IP_CLIENT, proto: 'QUIC', kind: 'tls', phase: 'Initial', from: 'web', to: 'client', title: 'QUIC Initial · ServerHello',
          info: 'Initial, SCID=0xa12b3c4d5e6f7081, PKN: 0', osi: [4, 3, 2], layer: 4, note: '服务端一个往返内完成密钥协商，后续即可发送应用数据。',
          layers: frame(IP_WEB, IP_CLIENT, 17, '17 (UDP)', udpTo(443, 53450), initial('QUIC Initial (Server)', [0xa1, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81], srvPayload), { inbound: true }) }),
        P({ t: 0.061, src: IP_CLIENT, dst: IP_WEB, proto: 'QUIC', kind: 'request', phase: '1-RTT', from: 'client', to: 'web', title: 'QUIC 1-RTT · HTTP/3 请求',
          info: 'Short Header  ·  Stream 0: HEADERS GET /', osi: [4, 3, 2], layer: 4, note: '握手完成后的短首部仅 1 字节；HTTP/3 用 QPACK 压缩首部。',
          layers: frame(IP_CLIENT, IP_WEB, 17, '17 (UDP)', udpTo(53450, 443), LINES('quic', 'HTTP/3 帧', 'H3', C.quic, [
            { n: '短首部', v: '\x40\xa1\x2b\x3c\x4d', d: '首比特 0 为短首部，只带目标连接 ID 与包号。' },
            { n: 'HEADERS 帧', v: 'Type=0x01  ·  :method=GET  ·  :path=/', d: 'HTTP/3 把请求头编码成二进制帧，不再是文本行。' }
          ])) }),
        P({ t: 0.098, src: IP_WEB, dst: IP_CLIENT, proto: 'QUIC', kind: 'response', phase: '1-RTT', from: 'web', to: 'client', title: 'QUIC 1-RTT · HTTP/3 响应',
          info: 'Short Header  ·  Stream 0: HEADERS 200 + DATA', osi: [4, 3, 2], layer: 4, note: '每条流独立按序，某个流丢包不会阻塞其他流 —— 解决了 TCP 队头阻塞。',
          layers: frame(IP_WEB, IP_CLIENT, 17, '17 (UDP)', udpTo(443, 53450), LINES('quic', 'HTTP/3 帧', 'H3', C.quic, [
            { n: '短首部', v: '\x40\x83\x94\xc8\xf0', d: '加密后首部之外的信息极少，中间设备无法追踪流状态。' },
            { n: 'HEADERS + DATA 帧', v: ':status=200  ·  content-type=text/html  ·  <html>…', d: '响应头与响应体在同一条 QUIC 流上按帧交错发送。' }
          ]), { inbound: true }) })
      ]
    });
  })();

  /* ---------- 元信息 ---------- */
  const ORDER = ['http', 'https', 'dns', 'tcp', 'udp', 'ip', 'arp', 'icmp', 'dhcp', 'tls', 'websocket', 'smtp', 'ftp', 'quic'];
  const CATEGORIES = [
    { id: 'all', zh: '全部', en: 'All' },
    { id: 'base', zh: '基础', en: 'Core' },
    { id: 'app', zh: '应用', en: 'App' },
    { id: 'sec', zh: '安全', en: 'Secure' }
  ];
  const KIND_COLORS = {
    dns: '#2f6fd0', tcp: '#0f9c9c', request: '#e8a317', response: '#7c4dd6',
    ack: '#a5b0c7', tls: '#d24b6a'
  };
  const KIND_ZH = { dns: 'DNS', tcp: 'TCP', request: '请求', response: '响应', ack: '纯 ACK', tls: 'TLS' };
  const KIND_EN = { dns: 'DNS', tcp: 'TCP', request: 'Request', response: 'Response', ack: 'Bare ACK', tls: 'TLS' };
  const OSI_NAMES = ['物理层', '数据链路层', '网络层', '传输层', '会话层', '表示层', '应用层'];

  global.ProtocolData = {
    scenarios: S, order: ORDER, categories: CATEGORIES,
    kindColors: KIND_COLORS, kindZh: KIND_ZH, kindEn: KIND_EN,
    osiNames: OSI_NAMES, colors: C, util: U,
    ipClient: IP_CLIENT, ipDns: IP_DNS, ipWeb: IP_WEB
  };
})(window);
