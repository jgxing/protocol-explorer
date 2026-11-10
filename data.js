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
    quic: '#c04a8e', payload: '#7b89ad', smtp: '#dd9a12', ftp: '#dd9a12',
    rip: '#e07b1f', ospf: '#2f9c6a', bgp: '#a83f8f',
    llc: '#5b6bb5', stp: '#1f8a9c',
    phy: '#8a93ad', pad: '#aab4c8', fcs: '#0f9c9c', jam: '#d0483f',
    wlan: '#7c4dd6', wlanctl: '#12a08f', snap: '#5b6bb5', eapol: '#d24b6a'
  };

  const MAC_CLIENT = '08:00:5e:5d:52:81';
  const MAC_GW = '00:1b:21:9c:4e:0a';
  const IP_CLIENT = '192.168.1.10';
  const IP_GW = '192.168.1.1';
  const IP_DNS = '8.8.8.8';
  const IP_WEB = '203.0.113.10';
  const IP_MAIL = '198.51.100.25';
  const IP_FTP = '198.51.100.40';

  /* 二层实验：主机 / 交换机地址 */
  const MAC_BCAST = 'ff:ff:ff:ff:ff:ff';
  const MAC_STP_MCAST = '01:80:c2:00:00:00';
  const MAC_A = '00:1a:2b:3c:4d:01', MAC_B = '00:1a:2b:3c:4d:02';
  const MAC_C = '00:1a:2b:3c:4d:03', MAC_D = '00:1a:2b:3c:4d:04';
  const IP_A = '192.168.1.11', IP_B = '192.168.1.12', IP_C = '192.168.1.13', IP_D = '192.168.1.14';
  const MAC_SW1 = '00:1c:0e:11:11:11', MAC_SW2 = '00:1c:0e:22:22:22', MAC_SW3 = '00:1c:0e:33:33:33';

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
        F('上层协议', protoLabel || String(protoNum), 9, 1, '6 = TCP，17 = UDP，1 = ICMP，89 = OSPF；决定把载荷交给哪个上层模块。'),
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
        F('目的端口', String(dport) + ' (' + (o.service || 'http') + ')', 2, 2, '熟知端口标识服务：80 = HTTP，443 = HTTPS，25 = SMTP，21 = FTP，179 = BGP。'),
        F('序号 Seq', String(seq), 4, 4, '本报文段第一个数据字节的编号；SYN 会占用一个序号。'),
        F('确认号 Ack', String(ack), 8, 4, '期望收到的下一个字节编号，表示此前所有字节均已正确收到。'),
        F('数据偏移 / 保留', '5 (20 字节)', 12, 2, 'TCP 首部长度，单位 4 字节；无选项时为 20 字节。'),
        F('标志位 Flags', flagLabel, 13, 1, 'SYN 建连、ACK 确认、PSH 立即交付、FIN 断开、RST 复位。'),
        F('窗口大小', String(o.win || 64240), 14, 2, o.windowDesc || '接收方通告的可用缓冲区大小，实现流量控制。'),
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
        F('目的端口', String(dport), 2, 2, '53 = DNS，67/68 = DHCP，443 = QUIC，520 = RIP (RIPv2)。'),
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

  /* ---------- 路由协议层构造器 ---------- */
  // RIPv2 (RFC 2453)：4 字节首部 + N × 20 字节路由表项，承载在 UDP/520 之上
  function RIP(command, entries) {
    const bytes = [command, 0x02, 0x00, 0x00];
    const fields = [
      F('命令 Command', command === 1 ? '1 (Request)' : '2 (Response)', 0, 1, '1 = 向邻居请求路由表；2 = 发送自己的路由更新（周期性或触发式）。'),
      F('版本 Version', '2 (RIPv2)', 1, 1, 'RIPv2 相比 v1 增加了子网掩码、下一跳与路由标记，并改用组播 224.0.0.9。'),
      F('保留字段', '0x0000', 2, 2, '必须为 0，接收端忽略；RIPv1 同样保留这两字节。')
    ];
    let off = 4;
    entries.forEach((e, i) => {
      const afi = e.afi === undefined ? 2 : e.afi;
      const tag = e.tag || 0;
      const net = e.net || '0.0.0.0';
      const mask = e.mask || '0.0.0.0';
      const hop = e.hop || '0.0.0.0';
      const metric = e.metric;
      bytes.push(...U.u16(afi), ...U.u16(tag), ...U.ip(net), ...U.ip(mask), ...U.ip(hop), ...U.u32(metric));
      const p = '表项 #' + (i + 1) + ' · ';
      fields.push(
        F(p + '地址族 AFI', afi === 0 ? '0x0000 (请求整表)' : '0x0002 (IPv4)', off, 2, '0x0002 表示后面是 IPv4 路由；0xFFFF 时这 20 字节用于认证数据。'),
        F(p + '路由标记 Tag', String(tag), off + 2, 2, '区分内部路由与从其他路由协议重分发进来的外部路由。'),
        F(p + '网络地址', net, off + 4, 4, '目的网段的网络号；请求整张路由表时填 0.0.0.0。'),
        F(p + '子网掩码', mask, off + 8, 4, 'RIPv2 随路由携带掩码，支持 VLSM / CIDR；RIPv1 只能按自然类网络判断。'),
        F(p + '下一跳', hop, off + 12, 4, '0.0.0.0 表示通告者自己就是下一跳；否则指定同网段内更优的路由器。'),
        F(p + '度量 Metric', metric + (metric === 16 ? ' (不可达)' : ' 跳'), off + 16, 4, '跳数 1~15，16 表示不可达（路由毒化）。这正是 RIP 限制网络规模、收敛较慢的根源。')
      );
      off += 20;
    });
    return L('rip', 'RIPv2', 'RIP', C.rip, bytes, fields);
  }

  // OSPFv2 (RFC 2328)：24 字节公共首部 + 报文体，直接封装在 IP 数据报中（协议号 89）
  function OSPF(type, typeLabel, routerId, areaId, body, bodyFields) {
    const total = 24 + body.length;
    const bytes = [0x02, type, ...U.u16(total), ...U.ip(routerId), ...U.ip(areaId),
      0x7a, 0x4c, ...U.u16(0), ...U.z(8), ...body];
    const fields = [
      F('版本 Version', '2 (OSPFv2)', 0, 1, 'OSPFv2 面向 IPv4；支持 IPv6 的是 OSPFv3。'),
      F('报文类型 Type', type + ' (' + typeLabel + ')', 1, 1, '1 Hello 发现邻居，2 DD 描述数据库，3 LSR 请求，4 LSU 更新，5 LSAck 确认。'),
      F('报文长度', total + ' 字节', 2, 2, '包含 24 字节公共首部在内的整个 OSPF 报文长度。'),
      F('Router ID', routerId, 4, 4, '区域内唯一标识一台路由器，通常手工指定为最大的环回接口地址。'),
      F('Area ID', areaId, 8, 4, '0.0.0.0 即骨干区域 Area 0；其它区域都必须与骨干相连。'),
      F('校验和', '0x7a4c', 12, 2, '覆盖整个 OSPF 报文（不含认证数据），由接收端校验完整性。'),
      F('认证类型 AuType', '0 (Null)', 14, 2, '0 不认证、1 明文口令、2 MD5；教学场景用空认证。'),
      F('认证数据', '8 字节全 0', 16, 8, 'AuType=0 时全 0；MD5 认证时携带密钥 ID、序列号与摘要。'),
      ...bodyFields.map(f => F(f.n, f.v, 24 + f.o, f.l, f.d))
    ];
    return L('ospf', 'OSPFv2', 'OSPF', C.ospf, bytes, fields);
  }

  // LSA 首部（20 字节），被 DD / LSU / LSAck 复用
  function LSA_HEADER(age, type, id, adv, seq, length) {
    return [...U.u16(age), 0x02, type, ...U.ip(id), ...U.ip(adv), ...U.u32(seq), 0x9f, 0x2a, ...U.u16(length)];
  }
  function ROUTER_LSA(adv, links) {
    const tail = [0x00, 0x00, ...U.u16(links.length)];
    links.forEach(l => tail.push(...U.ip(l.id), ...U.ip(l.data), l.type, 0x00, ...U.u16(l.metric)));
    return [...LSA_HEADER(60, 1, adv, adv, 0x80000003, 20 + tail.length), ...tail];
  }
  function OSPF_HELLO(mask, dr, bdr, neighbors) {
    const body = [...U.ip(mask), ...U.u16(10), 0x02, 0x01, ...U.u32(40), ...U.ip(dr), ...U.ip(bdr)];
    const fields = [
      { n: '网络掩码', v: mask, o: 0, l: 4, d: '发送接口的子网掩码；掩码不一致的两台路由器无法建立邻居关系。' },
      { n: 'Hello 间隔', v: '10 s', o: 4, l: 2, d: '每 10 秒发一次 Hello；两端取值必须一致。' },
      { n: '可选项 Options', v: '0x02 (E-bit)', o: 6, l: 1, d: 'E 位表示本区域允许注入外部路由（非 Stub 区域）。' },
      { n: '路由器优先级', v: '1', o: 7, l: 1, d: '用于 DR / BDR 选举；置 0 表示不参与选举。' },
      { n: '死亡间隔', v: '40 s', o: 8, l: 4, d: '通常为 Hello 间隔的 4 倍；超时未收到 Hello 即判定邻居失效。' },
      { n: '指定路由器 DR', v: dr, o: 12, l: 4, d: '广播网段由 DR 统一泛洪 LSA，把邻接关系数量从 O(n²) 降到 O(n)。' },
      { n: '备份指定路由器 BDR', v: bdr, o: 16, l: 4, d: 'DR 失效时立即接管，避免重新选举造成收敛中断。' }
    ];
    let off = 20;
    neighbors.forEach((nb, i) => {
      body.push(...U.ip(nb));
      fields.push({ n: '已发现邻居 #' + (i + 1), v: nb, o: off, l: 4, d: '列出已在 Hello 中看到自己的邻居；双方互相看到对方后才进入 2-Way 状态。' });
      off += 4;
    });
    return { body: body, fields: fields };
  }
  function OSPF_DBD(seq, headers) {
    const body = [...U.u16(1500), 0x02, 0x07, ...U.u32(seq)];
    const fields = [
      { n: '接口 MTU', v: '1500 B', o: 0, l: 2, d: '发送接口可承载的最大 IP 报文；两端不一致会卡在 ExStart 状态。' },
      { n: '可选项 Options', v: '0x02', o: 2, l: 1, d: '声明本路由器支持的区域能力。' },
      { n: '标志位 Flags', v: '0x07 (I / M / MS)', o: 3, l: 1, d: 'I = 初始报文，M = 后面还有，MS = 本端为主；主从由 Router ID 大小决定。' },
      { n: 'DD 序列号', v: '0x' + seq.toString(16), o: 4, l: 4, d: '由主方递增，保证数据库描述按序、可靠地交换。' }
    ];
    let off = 8;
    headers.forEach((h, i) => {
      body.push(...h);
      fields.push({ n: 'LSA 摘要 #' + (i + 1), v: 'Type 1 Router-LSA · 20 字节', o: off, l: 20, d: '只发送 LSA 首部（摘要）而非完整内容；对方据此比对 LSDB 并列出缺失项。' });
      off += 20;
    });
    return { body: body, fields: fields };
  }
  function OSPF_LSR(items) {
    const body = [], fields = [];
    let off = 0;
    items.forEach((it, i) => {
      body.push(...U.u32(it.type), ...U.ip(it.id), ...U.ip(it.adv));
      fields.push(
        { n: '请求 #' + (i + 1) + ' · LS 类型', v: String(it.type), o: off, l: 4, d: '1 = Router-LSA，2 = Network-LSA，3/4/5 用于区域间与外部路由。' },
        { n: '请求 #' + (i + 1) + ' · LS ID', v: it.id, o: off + 4, l: 4, d: '与通告路由器一起唯一确定一条 LSA。' },
        { n: '请求 #' + (i + 1) + ' · 通告路由器', v: it.adv, o: off + 8, l: 4, d: '产生该 LSA 的路由器 Router ID。' }
      );
      off += 12;
    });
    return { body: body, fields: fields };
  }
  function OSPF_LSU(lsas) {
    const body = [...U.u32(lsas.length)];
    const fields = [{ n: 'LSA 数量', v: String(lsas.length), o: 0, l: 4, d: '本条 LSU 携带的链路状态通告条数；一次可以泛洪多条。' }];
    let off = 4;
    lsas.forEach((lsa, i) => {
      body.push(...lsa);
      fields.push({ n: 'LSA #' + (i + 1) + ' · 首部', v: '20 字节（LS 序号 / 校验和 / 长度）', o: off, l: 20, d: 'LS 序列号越大越新；校验和用于判断 LSA 是否损坏，老化时间到 3600 秒会被清除。' });
      fields.push({ n: 'LSA #' + (i + 1) + ' · Router-LSA 内容', v: (lsa.length - 20) + ' 字节', o: off + 20, l: lsa.length - 20, d: '逐条列出本路由器的链路（类型、链路 ID、链路数据、开销）；全区域的 LSA 集合即链路状态数据库 LSDB。' });
      off += lsa.length;
    });
    return { body: body, fields: fields };
  }
  function OSPF_LSACK(headers) {
    const body = [], fields = [];
    let off = 0;
    headers.forEach((h, i) => {
      body.push(...h);
      fields.push({ n: '确认的 LSA 摘要 #' + (i + 1), v: '20 字节', o: off, l: 20, d: '显式确认已收到的 LSA；未收到确认会重传，保证泛洪可靠。' });
      off += 20;
    });
    return { body: body, fields: fields };
  }

  // BGP-4 (RFC 4271)：19 字节公共首部 + 报文体，承载在 TCP/179 之上
  function BGP(type, typeLabel, body, bodyFields) {
    const total = 19 + body.length;
    const bytes = [...new Array(16).fill(0xff), ...U.u16(total), type, ...body];
    return L('bgp', 'BGP-4', 'BGP', C.bgp, bytes, [
      F('Marker 标记', '16 × 0xFF', 0, 16, 'BGP 报文的固定同步标记，16 字节全 1；早期用于认证，如今保持兼容，接收端据此确认报文边界。'),
      F('长度 Length', total + ' 字节', 16, 2, '包含 19 字节公共首部在内的整个报文长度，取值 19~4096。TCP 是字节流，BGP 靠这个字段把一条条报文切分出来。'),
      F('类型 Type', type + ' (' + typeLabel + ')', 18, 1, '1 OPEN 建立对等体，2 UPDATE 通告或撤销路由，3 NOTIFICATION 报错，4 KEEPALIVE 保活，5 ROUTE_REFRESH 请求重发。'),
      ...bodyFields.map(f => F(f.n, f.v, 19 + f.o, f.l, f.d))
    ]);
  }

  // OPEN 携带的可选参数：类型 2 = Capability，内部再套一层「能力码 + 长度 + 值」TLV
  const BGP_CAPS = as => [
    { code: 1, name: 'Multiprotocol Extensions', value: [0x00, 0x01, 0x00, 0x01],
      valueText: 'AFI 1 (IPv4) · SAFI 1 (Unicast)',
      desc: 'MP-BGP：声明可承载的地址族，使同一会话能同时通告 IPv4 / IPv6 / VPNv4 路由。',
      valueDesc: 'AFI=1 表示 IPv4，中间 1 字节保留，SAFI=1 表示单播路由。' },
    { code: 2, name: 'Route Refresh', value: [], valueText: '（无参数）',
      desc: '允许在不中断 TCP 会话的前提下请求对端重发全部路由，策略变更后无需重置对等体。',
      valueDesc: '' },
    { code: 65, name: '4-Octet AS Number', value: U.u32(as), valueText: 'AS ' + as,
      desc: '声明本端支持 4 字节 AS 号（超过 65535 的 AS）；能力不匹配时 OPEN 会被拒绝。',
      valueDesc: '本端真实的 4 字节自治系统号，避免旧式 2 字节 AS 的 65535 上限。' }
  ];

  function BGP_OPEN(as, hold, routerId, caps) {
    const capBytes = [], capFields = [];
    let off = 0;
    caps.forEach((c, i) => {
      const tlv = [c.code, c.value.length, ...c.value];
      const param = [0x02, tlv.length, ...tlv];
      const p = '能力 #' + (i + 1) + ' · ';
      capBytes.push(...param);
      capFields.push(
        { n: p + '参数类型', v: '2 (Capability)', o: off, l: 1, d: '可选参数类型 2 = 能力通告；OPEN 用它协商双方都支持的扩展。' },
        { n: p + '参数长度', v: tlv.length + ' 字节', o: off + 1, l: 1, d: '这段能力 TLV 的字节数。' },
        { n: p + '能力码', v: c.code + ' (' + c.name + ')', o: off + 2, l: 1, d: c.desc },
        { n: p + '能力长度', v: c.value.length + ' 字节', o: off + 3, l: 1, d: '能力值的长度；Route Refresh 这类无参数能力为 0。' }
      );
      if (c.value.length) capFields.push({ n: p + '能力值', v: c.valueText, o: off + 4, l: c.value.length, d: c.valueDesc });
      off += param.length;
    });
    const body = [4, ...U.u16(as), ...U.u16(hold), ...U.ip(routerId), capBytes.length, ...capBytes];
    const fields = [
      { n: '版本 Version', v: '4 (BGP-4)', o: 0, l: 1, d: 'BGP-4 支持 CIDR 无类域间路由与路由聚合，是当前互联网域间路由的唯一版本。' },
      { n: '我的 AS 号 My AS', v: 'AS ' + as, o: 1, l: 2, d: '发送方所属自治系统号；对端据此判断这是 eBGP（AS 不同）还是 iBGP（AS 相同）。' },
      { n: '保持时间 Hold Time', v: hold + ' s', o: 3, l: 2, d: '连续这么久收不到 KEEPALIVE / UPDATE 就判定对等体失效；双方协商取较小值，0 表示不启用保活。' },
      { n: 'BGP 标识符 Router ID', v: routerId, o: 5, l: 4, d: '发送方在 AS 内的唯一标识，通常取最大的环回接口地址；两端不能相同。' },
      { n: '可选参数长度', v: capBytes.length + ' 字节', o: 9, l: 1, d: '本 OPEN 携带的全部可选参数字节数；不支持的能力可忽略，不影响会话建立。' },
      ...capFields.map(f => ({ n: f.n, v: f.v, o: 10 + f.o, l: f.l, d: f.d }))
    ];
    return { body: body, fields: fields };
  }

  // UPDATE：撤销路由长度 / 撤销前缀 / 路径属性总长 / 属性 TLV / NLRI
  const BGP_PREFIX = pfx => {
    const bits = Number(pfx.split('/')[1]);
    return [bits, ...U.ip(pfx.split('/')[0]).slice(0, Math.ceil(bits / 8))];
  };
  function BGP_ATTR(name, flags, flagText, type, value, valueText, typeDesc, valueDesc) {
    return { name: name, bytes: [flags, type, value.length, ...value],
      flagText: flagText, valueText: valueText, desc: typeDesc, valueDesc: valueDesc };
  }
  function BGP_UPDATE(attrs, nlri, withdrawn) {
    const w = [], wFields = [];
    (withdrawn || []).forEach((p, i) => {
      const b = BGP_PREFIX(p);
      wFields.push({ n: '撤销前缀 #' + (i + 1), v: p, o: w.length, l: b.length,
        d: 'Withdrawn Routes：用「前缀长度 + 网络号」声明该路由已不可达，接收方立即从路由表中删除。' });
      w.push(...b);
    });
    const a = [], aFields = [];
    attrs.forEach(at => {
      const start = a.length;
      a.push(...at.bytes);
      aFields.push(
        { n: at.name + ' · 标志', v: '0x' + at.bytes[0].toString(16) + ' (' + at.flagText + ')', o: start, l: 1,
          d: '属性标志：0x80 Optional、0x40 Transitive、0x20 Partial、0x10 扩展长度。公认必遵属性固定为 0x40。' },
        { n: at.name + ' · 类型', v: at.bytes[1] + ' (' + at.name + ')', o: start + 1, l: 1, d: at.desc },
        { n: at.name + ' · 长度', v: (at.bytes.length - 3) + ' 字节', o: start + 2, l: 1,
          d: '属性值的字节数；超过 255 字节时改用 2 字节扩展长度（置 0x10 标志位）。' }
      );
      if (at.bytes.length > 3) aFields.push({ n: at.name + ' · 值', v: at.valueText, o: start + 3,
        l: at.bytes.length - 3, d: at.valueDesc });
    });
    const body = [...U.u16(w.length), ...w, ...U.u16(a.length), ...a];
    const fields = [
      { n: '撤销路由长度', v: w.length + ' 字节', o: 0, l: 2, d: 'Withdrawn Routes 区间的字节数；为 0 表示本报文只通告新路由。' },
      ...wFields.map(f => ({ n: f.n, v: f.v, o: 2 + f.o, l: f.l, d: f.d })),
      { n: '路径属性总长度', v: a.length + ' 字节', o: 2 + w.length, l: 2, d: '后面所有路径属性 TLV 的总字节数；为 0 表示本报文只撤销路由。' },
      ...aFields.map(f => ({ n: f.n, v: f.v, o: 4 + w.length + f.o, l: f.l, d: f.d }))
    ];
    let nOff = body.length;
    nlri.forEach((p, i) => {
      const b = BGP_PREFIX(p);
      fields.push({ n: 'NLRI #' + (i + 1) + ' · 网络层可达信息', v: p, o: nOff, l: b.length,
        d: 'Network Layer Reachability Information：本报文新通告的前缀，与上面的路径属性一一对应。' });
      body.push(...b);
      nOff += b.length;
    });
    return { body: body, fields: fields };
  }
  function BGP_NOTIFICATION(code, codeText, sub, subText, data) {
    const b = U.s(data);
    return { body: [code, sub, ...b], fields: [
      { n: '错误码 Error Code', v: code + ' (' + codeText + ')', o: 0, l: 1,
        d: '1 首部错、2 OPEN 错、3 UPDATE 错、4 Hold Timer 超时、5 状态机错、6 Cease（主动关闭）。' },
      { n: '错误子码 Error Subcode', v: sub + ' (' + subText + ')', o: 1, l: 1,
        d: '对错误码的进一步说明；Cease/2 表示管理员主动关闭对等体，属于正常下线而非故障。' },
      { n: '附加数据 Data', v: data, o: 2, l: b.length, d: '可选诊断信息；这里是一段可读文本，实际报文中常携带出错的属性或前缀。' }
    ] };
  }

  const IP_R1 = '10.0.12.1', IP_R2 = '10.0.12.2', IP_R2B = '10.0.23.2', IP_R3 = '10.0.23.3';
  const IP_RIP_MCAST = '224.0.0.9', IP_OSPF_MCAST = '224.0.0.5';
  const BGP_PORT = 179;
  const ospfFrame = (src, dst, ospfLayer) =>
    [ethC(), IPV4(src, dst, 89, '89 (OSPF)', ospfLayer.bytes.length, { ttl: 1 }), ospfLayer];
  // BGP 报文一律封装在 TCP/179；app 为 null 时表示纯 TCP 建连报文
  const bgpFrame = (src, dst, sp, dp, seq, ack, flags, flagLabel, app, opts) =>
    frame(src, dst, 6, '6 (TCP)',
      tcpTo(sp, dp, seq, ack, flags, flagLabel, Object.assign({ service: 'bgp' }, opts)), app, opts);

  /* ---------- 二层实验层构造器：802.3 / LLC / STP BPDU ---------- */
  // 802.1D 的 BPDU 封装在 802.3 帧里：Length 字段（≤1500）而非 EtherType，
  // 后面接 3 字节 LLC 首部 DSAP=SSAP=0x42、Control=0x03。
  function ETH8023(dst, src, len) {
    const l = L('eth', 'Ethernet 802.3', 'ETH', C.eth,
      [...U.mac(dst), ...U.mac(src), ...U.u16(len)],
      [
        F('目的地址', dst, 0, 6,
          '01:80:C2:00:00:00 是 IEEE 802.1D 保留的桥组播地址：只有启用了生成树的交换机端口才会接收并处理，普通主机网卡直接丢弃。'),
        F('源地址', src, 6, 6,
          '发送该 BPDU 的交换机端口 MAC。网桥据此比较 Bridge ID，并与「根桥 ID」区分开来。'),
        F('长度 Length', len + ' 字节 (0x' + len.toString(16) + ')', 12, 2,
          '802.3 帧该字段 ≤ 1500 时表示后续数据长度，不是 EtherType；此处长度 = LLC 3 字节 + BPDU ' + (len - 3) + ' 字节。')
      ]);
    l.note = 'BPDU 不走 IP：它封装在 802.3 + LLC 帧里，只在同一个二层广播域内逐跳传递，因此 STP 是纯粹的链路层协议。';
    return l;
  }
  function LLC_STP() {
    return L('llc', 'LLC 首部', 'LLC', C.llc, [0x42, 0x42, 0x03], [
      F('DSAP', '0x42 (STP)', 0, 1, '目的服务访问点：0x42 是 IEEE 802.1 为生成树协议保留的值。'),
      F('SSAP', '0x42 (STP)', 1, 1, '源服务访问点，同为 0x42。'),
      F('控制字段', '0x03 (UI 无编号信息)', 2, 1, '无连接、无确认的 UI 帧；BPDU 紧跟其后，不需要建立 LLC 会话。')
    ]);
  }
  // 802.1D 配置 BPDU：35 字节。Root ID / Bridge ID 各 8 字节 = 2 字节优先级 + 6 字节 MAC。
  function STP_CONFIG(o) {
    const rootPri = o.rootPri, rootMac = o.rootMac, cost = o.cost;
    const brPri = o.brPri, brMac = o.brMac;
    const port = o.port, flags = o.flags || 0;
    const msgAge = o.msgAge == null ? 0 : o.msgAge;
    const maxAge = o.maxAge == null ? 20 : o.maxAge;
    const hello = o.hello == null ? 2 : o.hello;
    const fwd = o.fwd == null ? 15 : o.fwd;
    const bytes = [0x00, 0x00, 0x00, 0x00, flags,
      ...U.u16(rootPri), ...U.mac(rootMac), ...U.u32(cost),
      ...U.u16(brPri), ...U.mac(brMac), ...U.u16(port),
      ...U.u16(msgAge), ...U.u16(maxAge), ...U.u16(hello), ...U.u16(fwd)];
    const l = L('stp', 'STP 配置 BPDU', 'BPDU', C.stp, bytes, [
      F('协议标识 Protocol ID', '0x0000 (Spanning Tree)', 0, 2, '固定为 0，表示 IEEE 802.1D 生成树协议。'),
      F('协议版本 Version', '0 (802.1D STP)', 2, 1, '0 = 经典 STP；2 = RSTP (802.1w)；3 = MSTP (802.1s)。'),
      F('BPDU 类型 Type', '0x00 (Configuration BPDU)', 3, 1, '0x00 为配置 BPDU；0x80 为拓扑变化通知 TCN BPDU。'),
      F('标志 Flags', '0x' + flags.toString(16) + (flags & 1 ? ' · TC 置位' : ' · 无 TC'), 4, 1,
        '最低位 TC（Topology Change）由根桥置位，通知全网把 MAC 表老化时间从 300 s 缩短为 Forward Delay（15 s）；最高位 TCA 用于确认 TCN。'),
      F('根桥 ID Root ID', rootPri + ':' + rootMac, 5, 8,
        '2 字节优先级 + 6 字节 MAC。比较时先比优先级（默认 32768，必须为 4096 的倍数），相同再比 MAC，越小越优先。'),
      F('根路径开销 Root Path Cost', String(cost), 13, 4,
        '从本端口到根桥的累计链路开销。802.1D 经典值：10 Mbps=100、100 Mbps=19、1 Gbps=4、10 Gbps=2；根桥发出的 BPDU 该值为 0。'),
      F('发送桥 ID Bridge ID', brPri + ':' + brMac, 17, 8,
        '发出这条 BPDU 的交换机 ID，用于同一网段上指定端口选举的平局判定。'),
      F('端口 ID Port ID', '0x' + port.toString(16) + ' (优先级 ' + (port >> 12) + ' / 端口 ' + (port & 0xfff) + ')', 25, 2,
        '高 4 位端口优先级、低 12 位端口号；当根路径开销与 Bridge ID 都相同时，用端口 ID 打破平局。'),
      F('Message Age', msgAge + ' s', 27, 2,
        'BPDU 从根桥发出后每经过一台交换机加 1；达到 Max Age 即认为该信息过期。这里是' +
        (msgAge >= 20 ? ' 20 s，已达 Max Age，SW2 判定根桥失联。' : ' 0 s，刚由根桥或上游网桥刷新。')),
      F('Max Age', maxAge + ' s', 29, 2, 'BPDU 最大存活时间，默认 20 s；超时未收到根桥 BPDU 就判定拓扑变化。'),
      F('Hello Time', hello + ' s', 31, 2, '根桥发送配置 BPDU 的周期，默认 2 s；非根桥只是在根端口收到后转发。'),
      F('Forward Delay', fwd + ' s', 33, 2,
        'Listening 与 Learning 各停留 15 s，共 30 s，确保新拓扑的 BPDU 有时间传遍全网，避免临时环路。')
    ]);
    l.note = '配置 BPDU 固定 35 字节。交换机只在「指定端口」上发送它，根端口只接收；被阻塞的端口仍要监听 BPDU，以便故障时及时接管。';
    return l;
  }
  // 拓扑变化通知 BPDU：只有 4 字节，由检测到变化的交换机从根端口向上游逐跳送到根桥。
  function STP_TCN() {
    const l = L('stp', 'STP TCN BPDU', 'TCN', C.stp, [0x00, 0x00, 0x00, 0x80], [
      F('协议标识 Protocol ID', '0x0000 (Spanning Tree)', 0, 2, '与配置 BPDU 一致。'),
      F('协议版本 Version', '0 (802.1D STP)', 2, 1, '经典 STP 版本号。'),
      F('BPDU 类型 Type', '0x80 (Topology Change Notification)', 3, 1,
        'TCN 不含任何拓扑细节，只是「我这里变了」的通告；上游用 TCA 确认，根桥再用 TC 标志通知全网。')
    ]);
    l.note = 'TCN BPDU 只有 4 字节；802.3 帧不足 64 字节最小长度时会由网卡补 0 填充，抓包里常见的 Padding 即来源于此。';
    return l;
  }
  const stpFrame = (src, bpdu) =>
    [ETH8023(MAC_STP_MCAST, src, 3 + bpdu.bytes.length), LLC_STP(), bpdu];

  /* ============================================================
     共享介质 CSMA/CD 与 IEEE 802.11 无线局域网层构造器
     —— CSMA/CD 关注「一个冲突域里真实出现在线上的字节」；
     —— 802.11 按 MAC 首部 / 帧体 / FCS 逐字段生成三类帧。
     ============================================================ */
  const CD_SLOT_BITS = 512;   // 争用期 / 时隙长度 = 512 bit
  const CD_SLOT_US = 51.2;    // 10 Mbps 下发送 512 bit 的时间
  const CD_TAU_US = 25.6;     // 单程最大传播时延
  const CD_IFG_BITS = 96;     // 帧间隙 96 bit
  const CD_JAM_BITS = 32;     // 强化冲突 Jam 长度

  const MAC_AP = '00:1b:21:9c:4e:0a';   // AP 的无线 MAC，同时用作 BSSID
  const MAC_STA = MAC_CLIENT;
  const MAC_STA2 = MAC_B;
  const MAC_DS = '00:1b:21:9c:4e:0b';
  const WLAN_BCAST = MAC_BCAST;
  const WLAN_SSID = 'ZJGSU-Lab';
  const WLAN_CH = 6;

  /* ---------- 以太网共享介质：物理层信号与 MAC 帧 ---------- */
  function CD_PREAMBLE() {
    const l = L('phy', '前导码 + SFD', 'PRE', C.phy,
      [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xab],
      [
        F('前导码 Preamble', '7 × 0xAA (10101010)', 0, 7,
          '让接收端锁相环与发送端时钟同步。共享介质上所有站点都靠这段交替的 1010 波形判断「信道上有载波」。'),
        F('SFD 帧起始定界符', '0xAB (10101011)', 7, 1,
          '最后两个 bit 由 10 变 11，标志后面紧接着就是 MAC 帧的第一个字节（目的地址）。')
      ]);
    l.note = '前导码 + SFD 共 8 字节由物理层添加，不属于 MAC 帧，也不计入 64~1518 字节的帧长；常规抓包工具看不到它们。';
    return l;
  }
  function CD_ETH(dst, src) {
    const l = L('eth', 'Ethernet II 帧首部', 'ETH', C.eth,
      [...U.mac(dst), ...U.mac(src), 0x08, 0x00],
      [
        F('目的地址', dst, 0, 6, '同一冲突域内所有网卡都能收到这个帧，只有目的 MAC 匹配的网卡才把内容上交。'),
        F('源地址', src, 6, 6, '发送站点的 MAC。冲突后重传时源地址不变，也不携带任何「第几次重传」标记。'),
        F('类型 EtherType', '0x0800 (IPv4)', 12, 2, '指示上层协议。注意 IEEE 802.3 帧这里可能是长度字段，与本课程的 Ethernet II 不同。')
      ]);
    l.note = 'MAC 帧从「目的地址」算到 FCS：首部 14 B + 数据 46~1500 B + FCS 4 B = 64~1518 B。数据不足 46 B 时必须由 MAC 子层补 PAD，否则无法满足最短帧长。';
    return l;
  }
  function CD_PAD(n) {
    const l = L('pad', '填充 PAD', 'PAD', C.pad, U.z(n), [
      F('填充字节', n + ' × 0x00', 0, n,
        '上层只交了较短的数据。为满足「数据字段至少 46 字节」，MAC 子层在 FCS 之前补 0；接收端靠 IP 首部的总长度字段区分有效数据与填充。')
    ]);
    l.note = 'PAD 不是应用层数据：它只是在发送前补进去、保证帧发送时间 ≥ 争用期 51.2 μs 的占位字节。';
    return l;
  }
  function CD_FCS(bad) {
    const bytes = bad ? [0xde, 0xad, 0xbe, 0xef] : [0x1b, 0x4a, 0x9c, 0x72];
    const l = L('fcs', '帧校验序列 FCS', 'FCS', C.fcs, bytes, [
      F('CRC-32', bad ? '0xdeadbeef（校验错误）' : '0x1b4a9c72', 0, 4,
        bad ? '冲突叠加破坏了比特，接收端算出的 CRC 与帧尾不符，直接丢弃这个碎片（runt / FCS error）。'
          : '覆盖目的地址到数据字段末尾的 CRC-32。校验失败的帧被网卡静默丢弃，以太网不负责重传。')
    ]);
    l.note = '以太网没有 ACK，也没有链路层重传：FCS 出错的帧直接丢弃，「是否送达」由上层（如 TCP）自己判断。';
    return l;
  }
  function CD_IDLE() {
    const l = L('phy', '帧间隙 IFG（空闲）', 'IFG', C.phy, U.z(12), [
      F('96 bit 空闲', '12 字节时间 · 无信号', 0, 12,
        '发送完一帧后必须安静 96 bit time（10 Mbps 下 9.6 μs），让所有站点恢复并公平竞争下一个时隙。这 12 个 0 仅表示「线上没有信号」，不是真实字节。')
    ]);
    l.note = 'IFG、前导码与 Jam 都是物理层信号，不属于 MAC 帧；这里用占位字节把它们画进十六进制视图，便于对照争用期。';
    return l;
  }
  function CD_JAM() {
    const l = L('jam', '强化冲突 Jam 信号', 'JAM', C.jam, [0x55, 0x55, 0x55, 0x55], [
      F('Jam 32 bit', '4 × 0x55', 0, 4,
        '检测到冲突的站点立即停止发帧，改发 32 bit 的强化冲突信号，确保网段上所有站点都能察觉这次冲突，避免有人误以为帧已发完。')
    ]);
    l.note = 'Jam 之后线路恢复空闲，各站点启动二进制指数退避；冲突中产生的残缺帧（< 64 B）会被接收端判为 runt 丢弃。';
    return l;
  }
  function CD_FRAGMENT() {
    const l = L('jam', '冲突碎片（残缺帧）', 'FRAG', C.jam,
      [0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xab,
        ...U.mac(MAC_B).slice(0, 6), ...U.mac(MAC_A).slice(0, 4), 0x08, 0x00, 0x45, 0x00],
      [
        F('前导码 + SFD', '8 B', 0, 8, '两站几乎同时发出的前导码在介质上叠加，仍能识别起始位置。'),
        F('叠加的 MAC 字段', '6 B 目的 + 4 B 源 + 3 B 类型/版本', 8, 13,
          'A 与 B 的信号在电缆上电压叠加，比特已被破坏，抓到的是长度不足 64 B 的碎片（runt / collision fragment）。')
      ]);
    l.note = '冲突碎片没有有效 FCS，长度通常远小于 64 B，接收网卡按「runt frame」直接丢弃；发送方则靠自己的冲突检测决定是否重传。';
    return l;
  }
  // 上层数据：IPv4 + ICMP Echo，长度可调，用于演示 PAD 与最短帧长
  const CD_BODY = (seq, n) => [IPV4(IP_A, IP_B, 1, '1 (ICMP)', 8 + n),
    ICMP(8, 0, 'Echo Request', 0x0c51, seq, U.z(n))];
  const cdFrame = o => {
    const dst = o.dst || MAC_B, src = o.src || MAC_A;
    const body = o.body || CD_BODY(o.seq || 1, o.len == null ? 14 : o.len);
    const dataLen = body.reduce((a, l) => a + l.bytes.length, 0);
    const padN = o.noPad ? 0 : Math.max(0, 46 - dataLen);
    const ls = [CD_PREAMBLE(), CD_ETH(dst, src), ...body];
    if (padN) ls.push(CD_PAD(padN));
    if (!o.noFcs) ls.push(CD_FCS(o.badFcs));
    return ls;
  };

  /* ---------- IEEE 802.11 MAC 层 ---------- */
  // Frame Control 第 0 字节 = 版本(2) + 类型(2) + 子类型(4)，第 1 字节 = 8 个标志位
  const WLAN_FC = {
    beacon: [0x80, 0x00], probeReq: [0x40, 0x00], probeResp: [0x50, 0x00],
    auth: [0xb0, 0x00], assocReq: [0x00, 0x00], assocResp: [0x10, 0x00],
    rts: [0xb4, 0x00], cts: [0xc4, 0x00], ack: [0xd4, 0x00],
    data: [0x08, 0x01], dataRetry: [0x08, 0x09], dataFrom: [0x08, 0x02]
  };
  const WLAN_TYPE = {
    beacon: '管理帧 · Beacon (subtype 8)', probeReq: '管理帧 · Probe Request (4)',
    probeResp: '管理帧 · Probe Response (5)', auth: '管理帧 · Authentication (11)',
    assocReq: '管理帧 · Association Request (0)', assocResp: '管理帧 · Association Response (1)',
    data: '数据帧 · Data (0)', dataRetry: '数据帧 · Data (0) · Retry=1',
    dataFrom: '数据帧 · Data (0) · From DS'
  };
  function WLAN_HDR(o) {
    const fc = WLAN_FC[o.fc] || WLAN_FC.data;
    const f1 = o.fl == null ? fc[1] : o.fl;
    const sc = ((o.seq || 0) << 4) | (o.frag || 0);
    const bytes = [fc[0], f1, ...U.u16(o.dur || 0), ...U.mac(o.a1), ...U.mac(o.a2), ...U.mac(o.a3), ...U.u16(sc)];
    const l = L('wlan', '802.11 MAC 首部', '802.11', C.wlan, bytes, [
      F('帧控制 · 版本/类型/子类型', '0x' + fc[0].toString(16) + ' · ' + (WLAN_TYPE[o.fc] || WLAN_TYPE.data), 0, 1,
        '低 2 位协议版本恒为 0；bit2~3 类型：00 管理帧、01 控制帧、10 数据帧；高 4 位子类型区分 Beacon / Probe / Auth / Data 等。'),
      F('帧控制 · 标志位', '0x' + f1.toString(16) + (o.fc === 'data' ? ' · To DS=1' : '') +
        (o.fc === 'dataRetry' ? ' · To DS=1, Retry=1' : ''), 1, 1,
        'bit0 To DS、bit1 From DS 决定三个地址字段的含义；bit3 Retry 表示这是重传帧；bit6 Protected 表示帧体已加密；bit7 Order 要求严格按序。'),
      F('Duration / ID', (o.dur || 0) + ' μs · NAV', 2, 2,
        '发送方预留信道的时间。其它站点把这个值写入网络分配矢量 NAV，做「虚拟载波侦听」：即使物理上听不到，也会在 NAV 归零前保持沉默。'),
      F('地址 1 · ' + (o.a1n || 'RA'), o.a1, 4, 6,
        '地址 1 永远是接收端无线地址（RA）：To DS=1 时为 AP 的 BSSID，From DS=1 时为最终站点。'),
      F('地址 2 · ' + (o.a2n || 'TA'), o.a2, 10, 6,
        '地址 2 永远是发送端无线地址（TA）：数据帧里是源站点 MAC，控制帧/ACK 里含义随帧类型变化。'),
      F('地址 3 · ' + (o.a3n || 'BSSID'), o.a3, 16, 6,
        '地址 3 在有 AP 的基础设施网络中通常放 BSSID；To DS=1 时它是真正的目的地址（SA/DA 需要靠三个地址共同还原）。'),
      F('序列控制 · 分片 / 序号', 'Seq ' + (o.seq || 0) + ' · Frag ' + (o.frag || 0), 22, 2,
        '高 12 位是每帧递增的序列号，低 4 位是分片号。重传帧序号不变但 Retry 置 1，接收端据此去重。')
    ]);
    l.note = '802.11 MAC 首部固定 24 字节（QoS 数据帧再多 2 字节 QoS Control）。管理帧和数据帧用三个地址，控制帧只用 1~2 个地址，因此长度更短。';
    return l;
  }
  function WLAN_CTRL(o) {
    const fc = WLAN_FC[o.fc];
    const bytes = [fc[0], fc[1], ...U.u16(o.dur || 0), ...U.mac(o.ra), ...(o.ta ? U.mac(o.ta) : [])];
    const l = L('wlanctl', '802.11 控制帧 · ' + (o.fc === 'rts' ? 'RTS' : o.fc === 'cts' ? 'CTS' : 'ACK'),
      'CTRL', C.wlanctl, bytes, [
        F('帧控制 FC', '0x' + fc[0].toString(16) + ' · ' +
          (o.fc === 'rts' ? 'RTS (subtype 11)' : o.fc === 'cts' ? 'CTS (12)' : 'ACK (13)'), 0, 2,
          o.fc === 'rts' ? '请求发送：发送方先问 AP「我要占用信道这么久，可以吗」。'
            : o.fc === 'cts' ? '允许发送：AP 广播式应答，覆盖范围内的所有站点都会据此设置 NAV。'
              : '确认：接收端在 SIFS（10 μs）后回一个 14 字节的 ACK，这是 802.11 判断「发送成功」的唯一依据。'),
        F('Duration / NAV', (o.dur || 0) + ' μs', 2, 2,
          'RTS/CTS 里的 Duration 覆盖「后续 CTS + DATA + ACK + 3×SIFS」整段交换，让隐藏节点提前静默。'),
        F('接收地址 RA', o.ra, 4, 6,
          o.fc === 'ack' ? 'ACK 只填原发送方地址：它是对刚才那一帧的确认，不需要再带源地址。' : '该控制帧的接收端无线地址。'),
        ...(o.ta ? [F('发送地址 TA', o.ta, 10, 6, 'RTS 必须带上发送方地址，AP 才知道该给谁回 CTS。')] : [])
      ]);
    l.note = '控制帧不含帧体与序列号：RTS 20 B、CTS / ACK 14 B（均已含 4 B FCS）。它们用短帧换时间，把「长数据帧可能撞车」的风险压缩到一次短握手上。';
    return l;
  }
  function WLAN_FCS() {
    const l = L('fcs', '帧校验序列 FCS', 'FCS', C.fcs, [0xa7, 0x3c, 0x19, 0xd0], [
      F('CRC-32', '0xa73c19d0', 0, 4,
        '覆盖 MAC 首部与帧体。FCS 出错的帧不回 ACK，发送方在 ACK 超时后按 CSMA/CA 规则重新争用并重传。')
    ]);
    return l;
  }
  function WLAN_BEACON_BODY() {
    const ssid = U.s(WLAN_SSID), ieSsid = 2 + ssid.length;
    const bytes = [
      0x00, 0x00, 0x00, 0x00, 0x1a, 0x2b, 0x3c, 0x4d,
      ...U.u16(100), 0x11, 0x04,
      0x00, ssid.length, ...ssid,
      0x01, 0x04, 0x82, 0x84, 0x8b, 0x96,
      0x03, 0x01, WLAN_CH,
      0x30, 0x0c, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04
    ];
    const oRates = 12 + ieSsid, oDs = oRates + 6, oRsn = oDs + 3;
    const l = L('wlanbody', 'Beacon 帧体 · 信息元素', 'BEACON', C.wlan, bytes, [
      F('Timestamp', '0x000000001a2b3c4d', 0, 8, 'AP 的 64 位微秒计时器，站点据此同步 TSF 时钟，也用于省电唤醒。'),
      F('Beacon Interval', '100 TU ≈ 102.4 ms', 8, 2, 'AP 每 100 个时间单元（1 TU = 1024 μs）广播一次 Beacon，宣告自己的存在。'),
      F('Capability Info', '0x0411 · ESS + Privacy', 10, 2, 'ESS=1 表示这是基础设施模式 AP；Privacy=1 表示启用加密（WPA2/WPA3）。'),
      F('IE 0 · SSID', WLAN_SSID, 12, ieSsid, '信息元素采用 TLV 编码：1 B 类型 + 1 B 长度 + 内容。被动扫描时站点就是靠它发现网络。'),
      F('IE 1 · Supported Rates', '1 / 2 / 5.5 / 11 Mbps', oRates, 6, 'AP 支持的速率集合；每个值的最高位表示是否为基本速率（必须支持才能关联）。'),
      F('IE 3 · DS Parameter', 'Channel ' + WLAN_CH, oDs, 3, '当前工作信道。2.4 GHz 频段只有 1/6/11 三个互不重叠信道。'),
      F('IE 48 · RSN', 'WPA2 · CCMP / PSK', oRsn, 14, 'RSN（Robust Security Network）信息元素声明认证与加密套件，决定后续四次握手的算法。')
    ]);
    l.note = 'Beacon 是广播管理帧：目的地址为 ff:ff:ff:ff:ff:ff，不需要 ACK。站点既可以被动听 Beacon，也可以主动发 Probe Request 索要应答。';
    return l;
  }
  function WLAN_PROBE_REQ_BODY() {
    const l = L('wlanbody', 'Probe Request 帧体', 'PROBE', C.wlan,
      [0x00, 0x00, 0x01, 0x04, 0x82, 0x84, 0x8b, 0x96], [
        F('IE 0 · SSID（通配）', '长度 0 · 探测所有网络', 0, 2, '长度为 0 表示「不指定 SSID」，范围内所有 AP 都会回应；填具体名称则只有匹配的 AP 应答。'),
        F('IE 1 · Supported Rates', '1 / 2 / 5.5 / 11 Mbps', 2, 6, '客户端声明自己支持的速率，AP 据此判断能否建立连接。')
      ]);
    l.note = '主动扫描会暴露客户端曾连接过的 SSID；被动扫描只听 Beacon，更省电也更隐蔽。';
    return l;
  }
  function WLAN_AUTH_BODY(seq, status) {
    const l = L('wlanbody', 'Authentication 帧体', 'AUTH', C.wlan,
      [...U.u16(0), ...U.u16(seq), ...U.u16(status)], [
        F('认证算法', '0 (Open System)', 0, 2, '开放系统认证：实际上不校验身份，只是走完 802.11 状态机的两步交换；真正的安全由 WPA2 四次握手完成。'),
        F('事务序号', String(seq), 2, 2, '1 = 站点发起，2 = AP 应答；共享密钥认证还会有第 3、4 步。'),
        F('状态码', status === 0 ? '0 (Success)' : String(status), 4, 2, '0 表示成功；非 0 表示拒绝，关联流程就此终止。')
      ]);
    return l;
  }
  function WLAN_ASSOC_BODY(resp, aid) {
    const ssid = U.s(WLAN_SSID);
    if (!resp) {
      const bytes = [0x11, 0x04, ...U.u16(10), 0x00, ssid.length, ...ssid, 0x01, 0x04, 0x82, 0x84, 0x8b, 0x96];
      return L('wlanbody', 'Association Request 帧体', 'ASSOC', C.wlan, bytes, [
        F('Capability Info', '0x0411', 0, 2, '站点声明自己支持的能力（ESS、加密、短时隙等），必须与 AP 兼容。'),
        F('Listen Interval', '10 BI', 2, 2, '省电模式下站点每隔多少个 Beacon 周期醒来收一次缓存帧。'),
        F('IE 0 · SSID', WLAN_SSID, 4, 2 + ssid.length, '要加入的网络名称，必须与 AP 的 Beacon 一致。'),
        F('IE 1 · Supported Rates', '1 / 2 / 5.5 / 11 Mbps', 4 + 2 + ssid.length, 6, '站点支持的速率集；AP 从中挑一个作为后续通信速率。')
      ]);
    }
    return L('wlanbody', 'Association Response 帧体', 'ASSOC', C.wlan,
      [0x11, 0x04, 0x00, 0x00, ...U.u16(aid), 0x01, 0x04, 0x82, 0x84, 0x8b, 0x96], [
        F('Capability Info', '0x0411', 0, 2, 'AP 最终确认的能力集合。'),
        F('状态码', '0 (Success)', 2, 2, '0 表示关联成功，站点从「已认证」进入「已关联」状态。'),
        F('关联 ID AID', String(aid), 4, 2, 'AP 分配给站点的短标识，用于省电轮询与 TIM 位图索引。'),
        F('IE 1 · Supported Rates', '1 / 2 / 5.5 / 11 Mbps', 6, 6, '协商后的速率集合。')
      ]);
  }
  function WLAN_EAPOL_BODY(step) {
    const names = { 1: 'ANonce', 2: 'SNonce + MIC', 3: 'GTK + MIC + Install', 4: '确认 ACK' }[step];
    const info = [0x00, 0x8a, 0x00, 0xca, 0x01, 0x0a, 0x00, 0x8a][step - 1];
    const bytes = [
      0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,   // LLC/SNAP → EAPOL
      0x02, 0x03, 0x00, 0x5f,                             // EAPOL: version / type=Key / length
      0x02, info, 0x00, 0x00, 0x10,                       // descriptor / key info / key length
      ...U.z(8), ...U.seq(8, 0x30 + step, 7)
    ];
    const l = L('eapol', 'EAPOL-Key · 四次握手 第 ' + step + '/4', 'EAPOL', C.eapol, bytes, [
      F('LLC / SNAP', 'AA:AA:03 + OUI 00:00:00 + 0x888E', 0, 8, '0x888E 是 EAPOL 的 EtherType：802.11 数据帧里承载认证报文时先套一层 LLC/SNAP。'),
      F('EAPOL 首部', 'v2 · Type 3 (Key) · Len 95', 8, 4, '版本 2 = 802.1X-2004；Type 3 表示密钥协商报文。'),
      F('Key Descriptor / Info', '0x' + info.toString(16) + ' · ' + names, 12, 5,
        'Key Info 里的 ACK / MIC / Install / Key Type 位组合区分四次握手的每一条消息。'),
      F('Replay Counter', '8 字节单调递增', 17, 8, '防止重放攻击：每发一条 EAPOL-Key 加 1，收到旧计数器的报文直接丢弃。'),
      F('Nonce / MIC（节选）', '8 B · ' + names, 25, 8,
        step === 1 ? 'AP 发出 ANonce。' : step === 2 ? '站点生成 SNonce，用 PMK 派生 PTK 并带上 MIC 供 AP 校验。' :
          step === 3 ? 'AP 验证 MIC 后下发组密钥 GTK，并置 Install 位。' : '站点回最后一条确认，双方安装 PTK/GTK，此后数据帧的 Protected 位置 1。')
    ]);
    l.note = 'WPA2-PSK 四次握手用 ANonce / SNonce / 双方 MAC / PMK 派生 PTK，并逐条用 MIC 校验。真实报文还含 32 B Nonce、16 B MIC 与密钥数据字段，此处按教学需要节选。';
    return l;
  }
  function WLAN_SNAP() {
    const l = L('snap', 'LLC / SNAP', 'SNAP', C.snap,
      [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00], [
        F('DSAP / SSAP / Control', '0xAA / 0xAA / 0x03', 0, 3, 'SNAP 封装的固定前缀：0xAA 表示后续是 SNAP 扩展，0x03 为无编号信息帧。'),
        F('OUI + EtherType', '00:00:00 + 0x0800 (IPv4)', 3, 5, '3 字节组织唯一标识 + 2 字节上层协议类型，等价于以太网里的 EtherType。')
      ]);
    l.note = '802.11 数据帧没有 EtherType 字段，必须靠 8 字节 LLC/SNAP 告诉接收端「帧体是 IPv4 报文」。';
    return l;
  }
  const WLAN_DATA_BODY = (seq) => [WLAN_SNAP(), IPV4(IP_A, IP_B, 1, '1 (ICMP)', 22),
    ICMP(8, 0, 'Echo Request', 0x0c61, seq, U.z(14))];
  const wlanFrame = (hdr, body) => [hdr, ...(body || []), WLAN_FCS()];

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

  /* 15 · RIP —— 距离向量路由 */
  (function () {
    const request = RIP(1, [{ afi: 0, net: '0.0.0.0', mask: '0.0.0.0', hop: '0.0.0.0', metric: 16 }]);
    const r2Routes = RIP(2, [
      { net: '10.0.23.0', mask: '255.255.255.0', metric: 1 },
      { net: '192.168.2.0', mask: '255.255.255.0', hop: IP_R3, metric: 2 }
    ]);
    const r1Routes = RIP(2, [
      { net: '192.168.1.0', mask: '255.255.255.0', metric: 1 },
      { net: '10.0.12.0', mask: '255.255.255.0', metric: 1 }
    ]);
    const periodic = RIP(2, [
      { net: '10.0.12.0', mask: '255.255.255.0', metric: 1 },
      { net: '192.168.1.0', mask: '255.255.255.0', hop: IP_R1, metric: 2 }
    ]);
    const poison = RIP(2, [{ net: '192.168.2.0', mask: '255.255.255.0', metric: 16 }]);

    def('rip', {
      name: 'RIP', title: 'RIPv2 路由更新', cat: 'base', sub: '路由信息协议 · 距离向量',
      osi: 7, layer: 7, nodes: ['r1', 'gateway', 'r3'], seqNodes: ['r1', 'gateway', 'r3'],
      labels: {
        r1: { name: '路由器 R1', en: 'Router R1', ip: IP_R1 },
        gateway: { name: '路由器 R2', en: 'Router R2', ip: IP_R2 },
        r3: { name: '路由器 R3', en: 'Router R3', ip: IP_R3 }
      },
      steps: [
        { t: '启动请求', d: '新上线的 R1 向 224.0.0.9 请求整张路由表', at: 1 },
        { t: '邻居应答', d: 'R2 用 Response 通告自己知道的网段与跳数', at: 2 },
        { t: '距离向量计算', d: '收到路由后跳数 +1，选度量最小的下一跳', at: 3 },
        { t: '周期更新', d: '每 30 秒把整张路由表重发一次', at: 4 },
        { t: '故障与毒化', d: '链路断开时把度量置 16，触发更新抑制环路', at: 5 }
      ],
      desc: 'RIP 用「跳数」衡量距离：每台路由器每 30 秒把整张路由表发给邻居，邻居把跳数加 1 后挑最小的那条写入路由表。最大 15 跳，16 跳即视为不可达。',
      tip: 'RIPv2 承载在 UDP/520，用组播 224.0.0.9，路由项里带子网掩码与下一跳，因此支持 VLSM。距离向量算法「只听邻居说」，收敛慢；要靠水平分割、毒性逆转、抑制计时器来避免路由环路。',
      stats: [
        { k: '承载协议', v: 'UDP / 520' },
        { k: '组播地址', v: '224.0.0.9' },
        { k: '度量标准', v: '跳数 (1~15)' },
        { k: '更新周期', v: '30 s' },
        { k: '最大跳数', v: '15（16 不可达）' }
      ],
      packets: [
        P({ t: 0.000, src: IP_R1, dst: IP_RIP_MCAST, proto: 'RIP', kind: 'routing', phase: '请求路由表',
          from: 'r1', to: 'gateway', title: 'RIPv2 Request',
          info: 'Request · 请求完整路由表 (metric=16)', osi: [7, 4, 3, 2], layer: 7,
          note: '路由器刚启动时不必等 30 秒：先发一个 Request，邻居会立即用 Response 回送整张路由表。',
          layers: frame(IP_R1, IP_RIP_MCAST, 17, '17 (UDP)', udpTo(520, 520), request) }),
        P({ t: 0.018, src: IP_R2, dst: IP_RIP_MCAST, proto: 'RIP', kind: 'update', phase: '邻居应答',
          from: 'gateway', to: 'r1', title: 'RIPv2 Response (R2)',
          info: 'Response · 2 routes · 10.0.23.0/24, 192.168.2.0/24', osi: [7, 4, 3, 2], layer: 7,
          note: 'R2 通告自己知道的网段：直连的 10.0.23.0/24 度量 1，经 R3 可达的 192.168.2.0/24 度量 2 并给出下一跳。',
          layers: frame(IP_R2, IP_RIP_MCAST, 17, '17 (UDP)', udpTo(520, 520), r2Routes, { inbound: true }) }),
        P({ t: 0.032, src: IP_R1, dst: IP_RIP_MCAST, proto: 'RIP', kind: 'update', phase: '距离向量计算',
          from: 'r1', to: 'gateway', title: 'RIPv2 Response (R1)',
          info: 'Response · 2 routes · 192.168.1.0/24, 10.0.12.0/24', osi: [7, 4, 3, 2], layer: 7,
          note: 'R1 也通告自己的直连网段。收到 R2 的路由后把跳数加 1，取度量最小者写入路由表 —— 这就是 Bellman-Ford 式距离向量。',
          layers: frame(IP_R1, IP_RIP_MCAST, 17, '17 (UDP)', udpTo(520, 520), r1Routes) }),
        P({ t: 30.000, src: IP_R2B, dst: IP_RIP_MCAST, proto: 'RIP', kind: 'update', phase: '周期更新',
          from: 'gateway', to: 'r3', title: 'RIPv2 Periodic Update',
          info: 'Response · 周期更新 (30 s) · 2 routes', osi: [7, 4, 3, 2], layer: 7,
          note: '即使拓扑没有变化，RIP 每 30 秒也要把整张路由表重发一遍；这是它带宽开销大、收敛慢的主要原因。',
          layers: frame(IP_R2B, IP_RIP_MCAST, 17, '17 (UDP)', udpTo(520, 520), periodic) }),
        P({ t: 45.120, src: IP_R2, dst: IP_RIP_MCAST, proto: 'RIP', kind: 'update', phase: '故障与毒化',
          from: 'gateway', to: 'r1', title: 'RIPv2 Triggered Update',
          info: 'Response · 192.168.2.0/24 metric=16 (不可达)', osi: [7, 4, 3, 2], layer: 7,
          note: 'R3 侧链路断开，R2 立即触发更新，把该网段度量置为 16（不可达），配合抑制计时器避免计数到无穷与路由环路。',
          layers: frame(IP_R2, IP_RIP_MCAST, 17, '17 (UDP)', udpTo(520, 520), poison, { inbound: true }) })
      ]
    });
  })();

  /* 16 · OSPF —— 链路状态路由 */
  (function () {
    const h1 = OSPF_HELLO('255.255.255.0', '0.0.0.0', '0.0.0.0', []);
    const hello1 = OSPF(1, 'Hello', IP_R1, '0.0.0.0', h1.body, h1.fields);
    const h2 = OSPF_HELLO('255.255.255.0', IP_R2, IP_R1, [IP_R1]);
    const hello2 = OSPF(1, 'Hello', IP_R2, '0.0.0.0', h2.body, h2.fields);
    const lsa = ROUTER_LSA(IP_R1, [
      { id: '10.0.12.0', data: IP_R1, type: 2, metric: 10 },
      { id: '192.168.1.0', data: '255.255.255.0', type: 3, metric: 10 }
    ]);
    const lsaHead = lsa.slice(0, 20);
    const dbd = OSPF_DBD(0x00000a1b, [lsaHead]);
    const dd = OSPF(2, 'Database Description', IP_R1, '0.0.0.0', dbd.body, dbd.fields);
    const lsr = OSPF_LSR([{ type: 1, id: IP_R1, adv: IP_R1 }]);
    const req = OSPF(3, 'Link State Request', IP_R2, '0.0.0.0', lsr.body, lsr.fields);
    const lsu = OSPF_LSU([lsa]);
    const upd = OSPF(4, 'Link State Update', IP_R1, '0.0.0.0', lsu.body, lsu.fields);
    const flood = OSPF(4, 'Link State Update', IP_R2B, '0.0.0.0', lsu.body, lsu.fields);
    const ackBody = OSPF_LSACK([lsaHead]);
    const ack = OSPF(5, 'Link State Ack', IP_R2, '0.0.0.0', ackBody.body, ackBody.fields);

    def('ospf', {
      name: 'OSPF', title: 'OSPFv2 链路状态同步', cat: 'base', sub: '开放式最短路径优先 · 链路状态',
      osi: 3, layer: 3, nodes: ['r1', 'gateway', 'r3'], seqNodes: ['r1', 'gateway', 'r3'],
      labels: {
        r1: { name: '路由器 R1', en: 'Router R1', ip: IP_R1 },
        gateway: { name: '路由器 R2', en: 'Router R2', ip: IP_R2 },
        r3: { name: '路由器 R3', en: 'Router R3', ip: IP_R3 }
      },
      steps: [
        { t: 'Hello 发现邻居', d: '组播 224.0.0.5，双向确认后建立邻接', at: 2 },
        { t: '交换数据库摘要', d: 'DD 只发 LSA 首部，比对 LSDB 差异', at: 3 },
        { t: '请求缺失 LSA', d: 'LSR 列出本机缺少或过期的条目', at: 4 },
        { t: '泛洪并确认', d: 'LSU 携带完整 LSA，逐跳用 LSAck 确认', at: 6 },
        { t: 'SPF 计算路由', d: '以自己为根跑 Dijkstra，生成最短路径树', at: 7 }
      ],
      desc: 'OSPF 不走 TCP 或 UDP，而是直接封装在 IP 数据报里（协议号 89）。每台路由器把自己周边的链路状态（LSA）泛洪给整个区域，所有路由器因此拥有一致的 LSDB，再各自以自己为根运行 SPF 算法算出最短路径。',
      tip: '链路状态算法收敛快、天然无环路，但要求区域内 LSDB 严格一致。Hello 维持邻居关系，DR / BDR 减少广播网段的邻接数量，Area 0 是骨干区域；LSA 靠序列号与老化时间区分新旧。',
      stats: [
        { k: 'IP 协议号', v: '89 (直接封装)' },
        { k: '组播地址', v: '224.0.0.5 / 224.0.0.6' },
        { k: '路由算法', v: 'Dijkstra SPF' },
        { k: '度量标准', v: '开销 Cost（基于带宽）' },
        { k: '报文类型', v: '5 种：Hello / DD / LSR / LSU / LSAck' }
      ],
      packets: [
        P({ t: 0.000, src: IP_R1, dst: IP_OSPF_MCAST, proto: 'OSPF', kind: 'routing', phase: '邻居发现',
          from: 'r1', to: 'gateway', title: 'OSPF Hello (R1)',
          info: 'Hello · Router-ID 10.0.12.1 · DR 未知', osi: [3, 2], layer: 3,
          note: 'R1 在接口上向 AllSPFRouters 组播 224.0.0.5 发 Hello，此时还没有发现任何邻居，DR / BDR 均为 0。',
          layers: ospfFrame(IP_R1, IP_OSPF_MCAST, hello1) }),
        P({ t: 0.012, src: IP_R2, dst: IP_OSPF_MCAST, proto: 'OSPF', kind: 'routing', phase: '邻居发现',
          from: 'gateway', to: 'r1', title: 'OSPF Hello (R2)',
          info: 'Hello · 已发现邻居 10.0.12.1 · DR=10.0.12.2', osi: [3, 2], layer: 3,
          note: 'R2 的 Hello 里列出了 R1；双方都在对方的邻居列表中看到自己后进入 2-Way，随后选举 DR / BDR 并开始同步数据库。',
          layers: ospfFrame(IP_R2, IP_OSPF_MCAST, hello2) }),
        P({ t: 0.035, src: IP_R1, dst: IP_R2, proto: 'OSPF', kind: 'routing', phase: '数据库同步',
          from: 'r1', to: 'gateway', title: 'OSPF Database Description',
          info: 'DD · I/M/MS=0x07 · 1 条 LSA 摘要', osi: [3, 2], layer: 3,
          note: '邻接建立后先交换 DD 报文：只发 LSA 首部（摘要），接收方比对自己的 LSDB，找出缺失或更旧的条目。',
          layers: ospfFrame(IP_R1, IP_R2, dd) }),
        P({ t: 0.049, src: IP_R2, dst: IP_R1, proto: 'OSPF', kind: 'routing', phase: '请求缺失 LSA',
          from: 'gateway', to: 'r1', title: 'OSPF Link State Request',
          info: 'LSR · 请求 Type 1 Router-LSA 10.0.12.1', osi: [3, 2], layer: 3,
          note: 'R2 用「LS 类型 + LS ID + 通告路由器」三元组精确请求自己缺少的那条 LSA 的完整内容。',
          layers: ospfFrame(IP_R2, IP_R1, req) }),
        P({ t: 0.061, src: IP_R1, dst: IP_R2, proto: 'OSPF', kind: 'update', phase: '泛洪链路状态',
          from: 'r1', to: 'gateway', title: 'OSPF Link State Update',
          info: 'LSU · 1 条 Router-LSA · 2 条链路', osi: [3, 2], layer: 3,
          note: 'LSU 携带完整 LSA：链路类型、链路 ID、掩码与开销。收到后写入 LSDB，并向其它接口继续泛洪。',
          layers: ospfFrame(IP_R1, IP_R2, upd) }),
        P({ t: 0.074, src: IP_R2, dst: IP_R1, proto: 'OSPF', kind: 'routing', phase: '泛洪链路状态',
          from: 'gateway', to: 'r1', title: 'OSPF Link State Ack',
          info: 'LSAck · 确认收到 LSA 摘要', osi: [3, 2], layer: 3,
          note: 'LSAck 显式确认收到的 LSA；未在重传间隔内收到确认就重发，保证泛洪在不可靠的 IP 之上仍然可靠。',
          layers: ospfFrame(IP_R2, IP_R1, ack) }),
        P({ t: 0.092, src: IP_R2B, dst: IP_R3, proto: 'OSPF', kind: 'update', phase: '泛洪链路状态',
          from: 'gateway', to: 'r3', title: 'OSPF LSU 泛洪到 R3',
          info: 'LSU · 向另一接口泛洪同一条 LSA', osi: [3, 2], layer: 3,
          note: 'R2 把学到的 LSA 从其它接口继续泛洪出去，直到区域内所有路由器的 LSDB 完全一致，此时每台路由器都能独立跑出最短路径树。',
          layers: ospfFrame(IP_R2B, IP_R3, flood) })
      ]
    });
  })();

  /* 17 · BGP-4 —— 自治系统间的路径向量路由 */
  (function () {
    const origin = BGP_ATTR('ORIGIN', 0x40, 'Well-known / Transitive', 1, [0x00], '0 (IGP)',
      '路由来源：0 IGP（network 语句引入）、1 EGP、2 Incomplete（重分发引入）；BGP 选路时 IGP 优先。',
      '0 表示这条前缀由 AS 内部的 IGP 产生，可信度最高。');
    const asPath = BGP_ATTR('AS_PATH', 0x40, 'Well-known / Transitive', 2,
      [0x02, 0x01, ...U.u16(65001)], 'AS_SEQUENCE: 65001',
      '记录路由经过的 AS 列表：既用于选路（越短越优），也是 eBGP 防环的核心 —— 看到自己的 AS 号就丢弃。',
      '段类型 2 = AS_SEQUENCE，段内 1 个 AS 号 65001。');
    const nextHop = BGP_ATTR('NEXT_HOP', 0x40, 'Well-known / Transitive', 3, U.ip(IP_R1), IP_R1,
      '到达 NLRI 前缀的下一跳 IP；eBGP 通告时会改写为自己，iBGP 转发时默认保持不变。',
      'R1 的 eBGP 接口地址；R3 必须能通过 IGP 到达它，否则要配置 next-hop-self。');
    const med = BGP_ATTR('MULTI_EXIT_DISC', 0x80, 'Optional / Non-transitive', 4, U.u32(50), '50',
      'MED 向相邻 AS 建议「从哪个入口进来」，值小者优先；只在两个直连 AS 之间比较，不跨 AS 传递。',
      '本例取 50，仅影响 AS 65002 的入站选路。');
    const localPref = BGP_ATTR('LOCAL_PREF', 0x40, 'Well-known / Discretionary', 5, U.u32(100), '100',
      '本地优先级：只在 AS 内部的 iBGP 之间传播，值大者优先，且优先级高于 AS_PATH 长度。',
      '默认 100；AS 65002 内部所有路由器据此统一选出出口。');
    const community = BGP_ATTR('COMMUNITY', 0xc0, 'Optional / Transitive', 8,
      [0xfd, 0xe9, 0x00, 0x64], '65001:100',
      '团体属性给路由打标签，供对端按策略批量处理（限制传播范围、调整 LOCAL_PREF 等）。',
      '前 2 字节为 AS 号 65001，后 2 字节为自定义值 100。');

    const o1 = BGP_OPEN(65001, 180, IP_R1, BGP_CAPS(65001));
    const o2 = BGP_OPEN(65002, 180, IP_R2, BGP_CAPS(65002));
    const open1 = BGP(1, 'OPEN', o1.body, o1.fields);
    const open2 = BGP(1, 'OPEN', o2.body, o2.fields);
    const keepalive = BGP(4, 'KEEPALIVE', [], []);
    const adv = BGP_UPDATE([origin, asPath, nextHop, med, community], ['192.168.1.0/24']);
    const ibgp = BGP_UPDATE([origin, asPath, nextHop, med, localPref], ['192.168.1.0/24']);
    const withdraw = BGP_UPDATE([], [], ['192.168.1.0/24']);
    const notif = BGP_NOTIFICATION(6, 'Cease', 2, 'Administrative Shutdown', 'admin shutdown');

    const S1 = 0x1a2b3c4d, S2 = 0x5e6f7a8b, A1 = S1 + 1, A2 = S2 + 1;
    const EP = 41238, EP3 = 41240;
    const up = BGP(2, 'UPDATE', adv.body, adv.fields);
    const ui = BGP(2, 'UPDATE', ibgp.body, ibgp.fields);
    const uw = BGP(2, 'UPDATE', withdraw.body, withdraw.fields);
    const nf = BGP(3, 'NOTIFICATION', notif.body, notif.fields);

    def('bgp', {
      name: 'BGP', title: 'BGP-4 域间路由', cat: 'base', sub: '边界网关协议 · 路径向量',
      osi: 7, layer: 7, nodes: ['r1', 'gateway', 'r3'], seqNodes: ['r1', 'gateway', 'r3'],
      labels: {
        r1: { name: 'AS65001 · R1', en: 'AS 65001 · R1', ip: IP_R1 },
        gateway: { name: 'AS65002 · R2', en: 'AS 65002 · R2', ip: IP_R2 },
        r3: { name: 'AS65002 · R3', en: 'AS 65002 · R3', ip: IP_R3 }
      },
      steps: [
        { t: 'TCP 三次握手', d: '先与对端 179 端口建立可靠连接', at: 3 },
        { t: 'OPEN 协商参数', d: '交换 AS 号、Router ID、Hold Time 与能力', at: 5 },
        { t: 'KEEPALIVE 确认', d: '双方确认 OPEN 后进入 Established 状态', at: 7 },
        { t: 'UPDATE 通告路由', d: '携带 NLRI 前缀与 ORIGIN / AS_PATH / NEXT_HOP', at: 8 },
        { t: 'iBGP 内部转发', d: 'AS_PATH 与 NEXT_HOP 不变，追加 LOCAL_PREF', at: 9 },
        { t: '撤销与会话终止', d: 'Withdrawn Routes 撤路由，NOTIFICATION 关闭对等体', at: 11 }
      ],
      desc: 'BGP-4 是互联网的核心路由协议：它不靠跳数或带宽，而是用「路径向量」在每个自治系统（AS）之间交换可达前缀。对等体先建立 TCP/179 连接，再用 OPEN 协商参数、KEEPALIVE 维持会话，之后所有路由的通告与撤销都由 UPDATE 完成。',
      tip: 'BGP 是增量触发更新：会话建立时通告全表，之后只在拓扑变化时发送变化部分。eBGP（不同 AS）通告时改写 NEXT_HOP、追加自己的 AS 号；iBGP（同一 AS）转发时不改写这两项，改用 LOCAL_PREF 统一选出口，并要求全互联或路由反射器来避免环路。选路顺序大致为 LOCAL_PREF → AS_PATH 长度 → ORIGIN → MED。',
      stats: [
        { k: '承载协议', v: 'TCP / 179' },
        { k: '协议版本', v: 'BGP-4 (RFC 4271)' },
        { k: '会话类型', v: 'eBGP + iBGP' },
        { k: '保活周期', v: 'Keepalive 60s / Hold 180s' },
        { k: '报文类型', v: 'OPEN / UPDATE / KEEPALIVE / NOTIFICATION' },
        { k: '路径属性', v: 'ORIGIN · AS_PATH · NEXT_HOP · LOCAL_PREF' }
      ],
      packets: [
        P({ t: 0.000, src: IP_R1, dst: IP_R2, proto: 'TCP', kind: 'tcp', phase: 'TCP 建连',
          from: 'r1', to: 'gateway', title: 'TCP SYN · 连接 179 端口',
          info: '41238 → 179 · SYN · 发起 BGP 会话', osi: [4, 3, 2], layer: 4,
          note: 'BGP 自己不做可靠传输和分片，而是复用 TCP。R1 用临时端口向 R2 的 179 端口发起三次握手；端口固定为 179 的那一端通常被视为服务端。',
          layers: bgpFrame(IP_R1, IP_R2, EP, BGP_PORT, S1, 0, 0x02, 'SYN', null) }),
        P({ t: 0.012, src: IP_R2, dst: IP_R1, proto: 'TCP', kind: 'tcp', phase: 'TCP 建连',
          from: 'gateway', to: 'r1', title: 'TCP SYN + ACK',
          info: '179 → 41238 · SYN, ACK · 同意建连', osi: [4, 3, 2], layer: 4,
          note: 'R2 同意建立连接。TCP 提供按序、可靠、有流量控制的字节流，BGP 因此不必自己处理重传与乱序。',
          layers: bgpFrame(IP_R2, IP_R1, BGP_PORT, EP, S2, A1, 0x12, 'SYN, ACK', null, { inbound: true }) }),
        P({ t: 0.024, src: IP_R1, dst: IP_R2, proto: 'TCP', kind: 'tcp', phase: 'TCP 建连',
          from: 'r1', to: 'gateway', title: 'TCP ACK · 连接建立',
          info: '41238 → 179 · ACK · 进入 OpenSent', osi: [4, 3, 2], layer: 4,
          note: '三次握手完成，BGP 状态机从 Active 进入 OpenSent，接下来由 TCP 载荷承载第一条 BGP OPEN 报文。',
          layers: bgpFrame(IP_R1, IP_R2, EP, BGP_PORT, A1, A2, 0x10, 'ACK', null) }),
        P({ t: 0.031, src: IP_R1, dst: IP_R2, proto: 'BGP', kind: 'open', phase: 'OPEN 协商',
          from: 'r1', to: 'gateway', title: 'BGP OPEN (AS 65001)',
          info: 'OPEN · AS 65001 · Hold 180s · 3 capabilities', osi: [7, 4, 3, 2], layer: 7,
          note: 'R1 声明自己的 AS 号、BGP Router ID 与 180 秒 Hold Time，并通告 MP-BGP、Route Refresh、4 字节 AS 三项能力。AS 号不同，说明这是一条 eBGP 会话。',
          layers: bgpFrame(IP_R1, IP_R2, EP, BGP_PORT, A1, A2, 0x18, 'PSH, ACK', open1) }),
        P({ t: 0.043, src: IP_R2, dst: IP_R1, proto: 'BGP', kind: 'open', phase: 'OPEN 协商',
          from: 'gateway', to: 'r1', title: 'BGP OPEN (AS 65002)',
          info: 'OPEN · AS 65002 · Hold 180s · 能力匹配', osi: [7, 4, 3, 2], layer: 7,
          note: 'R2 回送自己的 OPEN。双方校验版本、AS 号、Router ID 与 Hold Time；参数不匹配则用 NOTIFICATION 报错并退回 Idle 状态。',
          layers: bgpFrame(IP_R2, IP_R1, BGP_PORT, EP, A2, A1, 0x18, 'PSH, ACK', open2, { inbound: true }) }),
        P({ t: 0.052, src: IP_R1, dst: IP_R2, proto: 'BGP', kind: 'keepalive', phase: 'KEEPALIVE 确认',
          from: 'r1', to: 'gateway', title: 'BGP KEEPALIVE (R1)',
          info: 'KEEPALIVE · 19 B · 确认收到 OPEN', osi: [7, 4, 3, 2], layer: 7,
          note: 'KEEPALIVE 只有 19 字节公共首部、没有报文体。收到对端 OPEN 后用它表示接受，状态机进入 OpenConfirm。',
          layers: bgpFrame(IP_R1, IP_R2, EP, BGP_PORT, A1, A2, 0x18, 'PSH, ACK', keepalive) }),
        P({ t: 0.061, src: IP_R2, dst: IP_R1, proto: 'BGP', kind: 'keepalive', phase: 'KEEPALIVE 确认',
          from: 'gateway', to: 'r1', title: 'BGP KEEPALIVE (R2) · Established',
          info: 'KEEPALIVE · 19 B · 会话建立完成', osi: [7, 4, 3, 2], layer: 7,
          note: '双方互发 KEEPALIVE 后进入 Established —— 这时才可以交换 UPDATE。此后每 60 秒发一次保活，180 秒收不到就断开会话。',
          layers: bgpFrame(IP_R2, IP_R1, BGP_PORT, EP, A2, A1, 0x18, 'PSH, ACK', keepalive, { inbound: true }) }),
        P({ t: 0.078, src: IP_R1, dst: IP_R2, proto: 'BGP', kind: 'update', phase: '路由通告',
          from: 'r1', to: 'gateway', title: 'BGP UPDATE · 通告 192.168.1.0/24',
          info: 'UPDATE · NLRI 192.168.1.0/24 · AS_PATH 65001', osi: [7, 4, 3, 2], layer: 7,
          note: 'R1 把自己的客户网段通告给 R2。UPDATE 同时携带路径属性：ORIGIN=IGP、AS_PATH=65001、NEXT_HOP=10.0.12.1、MED=50、COMMUNITY=65001:100，末尾的 NLRI 就是被通告的前缀。',
          layers: bgpFrame(IP_R1, IP_R2, EP, BGP_PORT, A1, A2, 0x18, 'PSH, ACK', up) }),
        P({ t: 0.096, src: IP_R2B, dst: IP_R3, proto: 'BGP', kind: 'update', phase: 'iBGP 内部转发',
          from: 'gateway', to: 'r3', title: 'BGP UPDATE · iBGP 转发到 R3',
          info: 'UPDATE · LOCAL_PREF 100 · NEXT_HOP 保持不变', osi: [7, 4, 3, 2], layer: 7,
          note: 'R2 用 iBGP 把路由转发给同属 AS 65002 的 R3：AS_PATH 仍是 65001（不追加自己的 AS），NEXT_HOP 仍是 10.0.12.1，但新增只在本 AS 内传播的 LOCAL_PREF=100。R3 需靠 IGP 或 next-hop-self 到达该下一跳。',
          layers: bgpFrame(IP_R2B, IP_R3, EP3, BGP_PORT, 0x74a1b2c3, 0x2b3c4d5e, 0x18, 'PSH, ACK', ui, { inbound: true }) }),
        P({ t: 45.120, src: IP_R1, dst: IP_R2, proto: 'BGP', kind: 'update', phase: '路由撤销',
          from: 'r1', to: 'gateway', title: 'BGP UPDATE · 撤销 192.168.1.0/24',
          info: 'UPDATE · Withdrawn Routes 192.168.1.0/24', osi: [7, 4, 3, 2], layer: 7,
          note: '链路故障后 R1 立刻发一条只含 Withdrawn Routes 的 UPDATE：路径属性与 NLRI 都为空。BGP 是增量更新，不必重发整张路由表，这正是它能承载全球数十万条前缀的关键。',
          layers: bgpFrame(IP_R1, IP_R2, EP, BGP_PORT, A1, A2, 0x18, 'PSH, ACK', uw) }),
        P({ t: 45.230, src: IP_R2, dst: IP_R1, proto: 'BGP', kind: 'notify', phase: '会话终止',
          from: 'gateway', to: 'r1', title: 'BGP NOTIFICATION · Cease',
          info: 'NOTIFICATION · Error 6/2 Administrative Shutdown', osi: [7, 4, 3, 2], layer: 7,
          note: '管理员下线对等体时发送 NOTIFICATION（错误码 6 Cease / 子码 2 主动关闭），随后断开 TCP 连接，双方状态机退回 Idle；撤销的路由也会沿 AS 逐跳传播出去。',
          layers: bgpFrame(IP_R2, IP_R1, BGP_PORT, EP, A2, A1, 0x18, 'PSH, ACK', nf, { inbound: true }) })
      ]
    });
  })();

  /* 18 · TCP 拥塞控制实验 —— 共享仿真内核
     每个 RTT 推进一步：慢启动 cwnd 每轮翻倍（不超过 ssthresh），
     拥塞避免每轮 +1 MSS；丢包时按 Reno / Tahoe 与 dup ACK / RTO 分派恢复动作。
     data.js 用它生成默认参数下的抓包时序，app.js 用它实时画可交互的 cwnd 曲线。 */
  const LAB_DEFAULT = { algo: 'reno', ssthresh: 8, lossMode: 'dupack', lossRound: 8, rounds: 14 };

  function simulateCC(cfg) {
    const o = Object.assign({}, LAB_DEFAULT, cfg || {});
    const out = [];
    let cwnd = 1, ssthresh = o.ssthresh, total = 0;
    for (let r = 1; r <= o.rounds; r++) {
      const startCwnd = cwnd, startSsth = ssthresh;
      const phase = startCwnd < startSsth ? 'ss' : 'ca';
      const sent = Math.floor(startCwnd);
      total += sent;
      let event = null, infl = null, half = 0, endCwnd, endSsth = startSsth;
      if (r === o.lossRound) {
        half = Math.max(2, Math.floor(startCwnd / 2));
        endSsth = half;
        event = o.lossMode;
        if (o.lossMode === 'dupack' && o.algo === 'reno') { infl = half + 3; endCwnd = half; }
        else endCwnd = 1;
      } else {
        endCwnd = phase === 'ss' ? Math.min(startCwnd * 2, startSsth) : startCwnd + 1;
      }

      let zh, en;
      if (event === 'dupack' && o.algo === 'reno') {
        zh = 'RTT ' + r + '：收到第 3 个重复 ACK，判定只是单个段丢失 → 立即快重传。ssthresh = ' + startCwnd + '/2 = ' + half +
          '；快恢复期间 cwnd 临时膨胀到 ' + half + '+3 = ' + infl + '，待新数据 ACK 到达后收缩回 ' + half +
          '，直接进入拥塞避免，不回退到慢启动。';
        en = 'RTT ' + r + ': the 3rd duplicate ACK signals a single lost segment, so fast retransmit fires at once. ssthresh = ' +
          startCwnd + '/2 = ' + half + '. Fast recovery temporarily inflates cwnd to ' + half + '+3 = ' + infl +
          '; a new ACK deflates it back to ' + half + ' and congestion avoidance resumes without slow start.';
      } else if (event === 'dupack') {
        zh = 'RTT ' + r + '：3 个重复 ACK 触发快重传，但 Tahoe 没有快恢复机制：ssthresh = ' + startCwnd + '/2 = ' + half +
          '，cwnd 直接降为 1，重新慢启动。同样的丢包，Reno 只降到 ' + half + '，差别就在快恢复。';
        en = 'RTT ' + r + ': 3 duplicate ACKs trigger fast retransmit, but Tahoe has no fast recovery: ssthresh = ' +
          startCwnd + '/2 = ' + half + ' and cwnd drops all the way to 1, restarting slow start. Reno would only fall back to ' + half + '.';
      } else if (event === 'timeout') {
        zh = 'RTT ' + r + '：重传计时器 RTO 超时，说明网络拥塞严重、连 ACK 都回不来。ssthresh = ' + startCwnd + '/2 = ' + half +
          '，cwnd 归 1 重新慢启动，这是最保守也最伤吞吐的恢复方式（Reno / Tahoe 一致）。';
        en = 'RTT ' + r + ': the retransmission timer (RTO) expires — congestion is severe enough that ACKs stop coming back. ssthresh = ' +
          startCwnd + '/2 = ' + half + ', cwnd resets to 1 and slow start begins again. This is the most conservative, most costly recovery (same in Reno and Tahoe).';
      } else if (phase === 'ss') {
        zh = 'RTT ' + r + '：慢启动 cwnd = ' + startCwnd + ' → ' + endCwnd + '。每收到 1 个 ACK 就把 cwnd 加 1 MSS，一个 RTT 内近似翻倍，快速试探可用带宽。';
        en = 'RTT ' + r + ': slow start, cwnd = ' + startCwnd + ' → ' + endCwnd +
          '. Each ACK adds 1 MSS, so cwnd roughly doubles every RTT to probe available bandwidth quickly.';
      } else {
        zh = 'RTT ' + r + '：拥塞避免 cwnd = ' + startCwnd + ' → ' + endCwnd + '。cwnd 已越过 ssthresh = ' + startSsth +
          '，改为每个 RTT 只增加 1 MSS，线性逼近网络容量（AIMD 的「加性增」）。';
        en = 'RTT ' + r + ': congestion avoidance, cwnd = ' + startCwnd + ' → ' + endCwnd +
          '. cwnd has passed ssthresh = ' + startSsth + ', so it grows by only 1 MSS per RTT, approaching capacity linearly (the additive increase in AIMD).';
      }

      out.push({ r: r, cwnd: startCwnd, ssthresh: startSsth, phase: phase, sent: sent, total: total,
        event: event, infl: infl, half: half, endCwnd: endCwnd, endSsth: endSsth,
        algo: o.algo, lossMode: o.lossMode, zh: zh, en: en });
      cwnd = endCwnd;
      ssthresh = endSsth;
    }
    return out;
  }

  (function () {
    const MSS = 1460, SPORT = 52344, DPORT = 80, GAP = 0.008;
    const WIN_DESC = '这是接收方通告的接收窗口 rwnd（流量控制），不是拥塞窗口 cwnd。cwnd 只存在于发送端内核，TCP 首部里没有这个字段；实际可发送量 = min(cwnd, rwnd)。';
    const RD = simulateCC(LAB_DEFAULT);
    const ps = [];
    let seq = 1;

    const seg = (n, label) => LINES('data', label, 'DATA', C.payload,
      [{ n: 'MSS 载荷片段', v: '[SEG ' + n + '] ' + 'A'.repeat(28) + '\r\n',
        d: '应用字节流被按 MSS = 1460 字节切段；接收端按 Seq 重组。一次允许在途多少段，由拥塞窗口 cwnd 决定。' }],
      '实际段长 1460 字节，此处只展开开头片段。注意 cwnd 是发送端内核状态变量，任何首部字段里都找不到它。');

    const mk = (fromWeb, s, a, flags, label, app) =>
      frame(fromWeb ? IP_WEB : IP_CLIENT, fromWeb ? IP_CLIENT : IP_WEB, 6, '6 (TCP)',
        tcpTo(fromWeb ? DPORT : SPORT, fromWeb ? SPORT : DPORT, s, a, flags, label,
          { service: 'http', windowDesc: WIN_DESC }),
        app, { inbound: fromWeb });

    RD.forEach(rd => {
      const base = (rd.r - 1) * 0.040;
      let k = 0;
      const push = o => {
        o.t = Math.round((base + k++ * GAP) * 1000) / 1000;
        o.rtt = rd.r;
        o.osi = [4, 3, 2]; o.layer = 4;
        ps.push(P(o));
      };
      const phase = rd.phase === 'ss' ? '慢启动' : '拥塞避免';

      push({ src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'ccdata',
        phase: 'RTT ' + rd.r + ' · ' + phase, from: 'client', to: 'web',
        title: 'RTT ' + rd.r + ' · 发送 ' + rd.sent + ' 个段',
        info: '[PSH, ACK] Seq=' + seq + ' Len=1460 · cwnd=' + rd.cwnd + ' (' + rd.sent + ' seg/RTT)',
        displaySize: '1460 B', truncated: true, note: rd.zh,
        layers: mk(false, seq, 1, 0x18, '0x18 PSH,ACK', seg(rd.r, 'TCP 段 · RTT ' + rd.r)) });

      if (rd.event === 'dupack') {
        const lostSeq = seq + 2 * MSS;
        for (let j = 1; j <= 3; j++) {
          push({ src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'dupack',
            phase: 'RTT ' + rd.r + ' · 丢包检测', from: 'web', to: 'client',
            title: '重复 ACK #' + j, info: '[DUP ACK ' + j + '] Ack=' + lostSeq + ' · 仍缺 Seq=' + lostSeq,
            note: '接收端收到乱序段，立即重发对同一字节的 ACK。第 3 个重复 ACK 是「段已丢失而非网络瘫痪」的强信号，发送端据此触发快重传。',
            layers: mk(true, 1, lostSeq, 0x10, '0x10 ACK', null) });
        }
        push({ src: IP_CLIENT, dst: IP_WEB, proto: 'TCP', kind: 'retrans',
          phase: 'RTT ' + rd.r + ' · 快重传', from: 'client', to: 'web',
          title: '快重传丢失段', info: '[RETRANSMISSION] Seq=' + lostSeq + ' Len=1460 · cwnd→' + (rd.infl || 1),
          displaySize: '1460 B', truncated: true,
          note: '不等 RTO 超时，收到第 3 个重复 ACK 就立即重传缺失段；Reno 同时把 ssthresh 设为 cwnd/2 = ' + rd.half +
            '，并把 cwnd 临时膨胀到 ssthresh+3 = ' + rd.infl + ' 进入快恢复。',
          layers: mk(false, lostSeq, 1, 0x18, '0x18 PSH,ACK', seg(rd.r, '重传段 · RTT ' + rd.r)) });
      }

      const nextAck = seq + rd.sent * MSS;
      push({ src: IP_WEB, dst: IP_CLIENT, proto: 'TCP', kind: 'ack',
        phase: 'RTT ' + rd.r + ' · 累计确认', from: 'web', to: 'client',
        title: rd.event === 'dupack' ? '新数据 ACK · 退出快恢复' : '累计 ACK',
        info: '[ACK] Ack=' + nextAck + ' · 确认本轮 ' + rd.sent + ' 段 · cwnd→' + rd.endCwnd,
        note: rd.event === 'dupack'
          ? '确认了包括重传段在内的所有在途数据（新数据 ACK），Reno 把膨胀的窗口收缩回 ssthresh = ' + rd.half + '，跳过慢启动，直接继续拥塞避免。'
          : '累计确认：Ack=N 表示 N 之前的字节全部收到。收到 ACK 才推进 cwnd，因此拥塞控制天然是「自时钟」(self-clocking) 的。',
        layers: mk(true, 1, nextAck, 0x10, '0x10 ACK', null) });

      seq = nextAck;
    });

    def('tcpcc', {
      name: 'TCP 拥塞控制', title: '拥塞控制实验', cat: 'base', sub: '慢启动 · 拥塞避免 · 快恢复',
      osi: 4, layer: 4, nodes: ['client', 'gateway', 'web'], seqNodes: ['client', 'gateway', 'web'],
      labels: {
        client: { name: '发送端', en: 'Sender', ip: IP_CLIENT },
        gateway: { name: '瓶颈链路', en: 'Bottleneck', ip: 'RTT 40 ms · 队列' },
        web: { name: '接收端', en: 'Receiver', ip: IP_WEB }
      },
      steps: [
        { t: '慢启动', d: 'cwnd 从 1 MSS 起步，每个 RTT 翻倍', at: 2 },
        { t: '越过阈值', d: 'cwnd 达到 ssthresh，切换增长方式', at: 8 },
        { t: '拥塞避免', d: '每 RTT 只加 1 MSS，线性探测带宽', at: 14 },
        { t: '丢包与快重传', d: '3 个重复 ACK 触发重传与减半', at: 20 },
        { t: '快恢复', d: '窗口收缩回 ssthresh，不回慢启动', at: 32 }
      ],
      desc: 'TCP 不靠路由器发信号，而是用丢包当拥塞信号：慢启动指数试探、拥塞避免线性逼近，一旦丢包就乘法减小（AIMD）。Reno 用 3 个重复 ACK 区分「偶发丢包」与「网络瘫痪」，靠快重传 + 快恢复避免吞吐崩塌。',
      tip: 'cwnd 不在 TCP 首部里！首部中 16 位的 Window 字段是接收方的 rwnd（流量控制），cwnd 是发送端内核自己维护的状态；实际发送窗口 = min(cwnd, rwnd)。点开任意数据段，展开「窗口大小」字段即可看到这条说明。切换到「拥塞实验」视图还能改算法与参数，实时观察 cwnd 曲线。',
      stats: [
        { k: '拥塞算法', v: 'Reno / Tahoe 可切换' },
        { k: '初始阈值', v: 'ssthresh = 8 MSS' },
        { k: '默认丢包', v: 'RTT 8 · 3 个重复 ACK' },
        { k: '发送窗口', v: 'min(cwnd, rwnd)' },
        { k: 'MSS / RTT', v: '1460 B / 40 ms' }
      ],
      packets: ps,
      lab: Object.assign({}, LAB_DEFAULT)
    });
  })();

  /* ============================================================
     19 · 交换机 / 网桥自学习算法
     共享仿真内核：按「源地址学习 → 目的地址查表 → 泛洪/转发/过滤」推进，
     每一帧都会生成当时的转发表快照，课程抓包与实验台共用同一套帧序列。
     ============================================================ */
  const SW_HOSTS = ['A', 'B', 'C', 'D'];
  const SW_MAC = { A: MAC_A, B: MAC_B, C: MAC_C, D: MAC_D, FF: MAC_BCAST };
  const SW_IP = { A: IP_A, B: IP_B, C: IP_C, D: IP_D };
  const SW_PORT = { A: 1, B: 2, C: 3, D: 4 };
  const SW_HOST_NODE = { A: 'ha', B: 'hb', C: 'hc', D: 'hd' };
  const SW_PORT_NODE = ['', 'ha', 'hb', 'hc', 'hd'];
  const SW_LAB_DEFAULT = { script: 'learn', aging: 'off' };

  const SW_SCRIPTS = {
    learn: [
      { src: 'A', dst: 'B' },
      { src: 'B', dst: 'A' },
      { src: 'A', dst: 'C' },
      { src: 'C', dst: 'A' },
      { src: 'A', dst: 'B', in: 1, dstPort: 1 },
      { src: 'A', dst: 'FF' },
      { src: 'B', dst: 'A', arp: true },
      { src: 'A', dst: 'B', in: 3, move: true },
      { src: 'B', dst: 'A' }
    ],
    aging: [
      { src: 'A', dst: 'B' },
      { src: 'B', dst: 'A' },
      { src: 'C', dst: 'D' },
      { src: 'D', dst: 'C' },
      { src: 'A', dst: 'B', idle: true },
      { src: 'B', dst: 'A' },
      { src: 'A', dst: 'C' },
      { src: 'C', dst: 'A' },
      { src: 'B', dst: 'A' }
    ],
    move: [
      { src: 'A', dst: 'B' },
      { src: 'B', dst: 'A' },
      { src: 'C', dst: 'A' },
      { src: 'A', dst: 'B', in: 3, move: true },
      { src: 'B', dst: 'A' },
      { src: 'C', dst: 'A' },
      { src: 'A', dst: 'D', in: 3 },
      { src: 'D', dst: 'A' },
      { src: 'B', dst: 'A' }
    ]
  };

  function simulateSwitch(cfg) {
    const o = Object.assign({}, SW_LAB_DEFAULT, cfg || {});
    const frames = (o.frames || SW_SCRIPTS[o.script] || SW_SCRIPTS.learn).slice();
    const agingOn = o.aging === 'short' || o.script === 'aging';
    const table = {};                       // mac -> { port, at }
    const out = [];
    let floods = 0, forwards = 0, filters = 0, learns = 0;

    frames.forEach((f, i) => {
      const inPort = f.in || SW_PORT[f.src];
      const r = i + 1;
      const srcMac = SW_MAC[f.src];
      const dstMac = f.dst === 'FF' ? MAC_BCAST : SW_MAC[f.dst];

      // 表项老化：默认 300 s；实验里用「隔 2 帧未刷新即过期」模拟长空闲
      if (agingOn) Object.keys(table).forEach(m => { if (r - 1 - table[m].at >= 2) delete table[m]; });

      // ① 源地址学习（永远只看源 MAC 与入端口，与目的地址无关）
      let learn = 'refresh';
      if (!table[srcMac]) { table[srcMac] = { port: inPort, at: i }; learn = 'add'; learns++; }
      else if (table[srcMac].port !== inPort) { table[srcMac] = { port: inPort, at: i }; learn = 'move'; learns++; }
      else table[srcMac].at = i;

      // ② 目的地址查表，决定泛洪 / 单播转发 / 过滤
      let action, egress = [], hitPort = null;
      if (f.dst === 'FF') {
        action = 'bcast';
        egress = [1, 2, 3, 4].filter(p => p !== inPort); floods++;
      } else if (f.dstPort != null) {
        hitPort = f.dstPort;
        if (hitPort === inPort) { action = 'filter'; filters++; }
        else { action = 'forward'; egress = [hitPort]; forwards++; }
      } else {
        const e = table[dstMac];
        if (!e) { action = 'flood'; egress = [1, 2, 3, 4].filter(p => p !== inPort); floods++; }
        else if (e.port === inPort) { action = 'filter'; hitPort = e.port; filters++; }
        else { action = 'forward'; hitPort = e.port; egress = [hitPort]; forwards++; }
      }

      const snap = Object.keys(table).map(m => {
        const host = SW_HOSTS.find(h => SW_MAC[h] === m) || m.slice(-2);
        return { mac: m, host: host, port: table[m].port, age: i - table[m].at };
      }).sort((a, b) => a.port - b.port);

      const plist = egress.length ? 'P' + egress.join(' / P') : '无';
      const lz = learn === 'add' ? '转发表里没有这个源地址 → 学习并记录 ' + srcMac + ' ↔ P' + inPort + '。' :
        learn === 'move' ? '同一源地址却从新端口出现（主机迁移）→ 覆盖旧表项为 P' + inPort + '。' :
          '源地址已在表中且端口未变 → 只刷新老化计时器。';
      const le = learn === 'add' ? 'The source MAC is unknown, so the switch learns ' + srcMac + ' ↔ P' + inPort + '. ' :
        learn === 'move' ? 'A known source MAC now appears on a new port (host moved), so the entry is overwritten to P' + inPort + '. ' :
          'The source MAC already exists on the same port; only its aging timer is refreshed. ';
      const az = {
        flood: '目的 ' + dstMac + ' 不在表中（未知单播），只能向除入端口外的所有端口泛洪：' + plist + '。',
        forward: '目的 ' + dstMac + ' 命中表项 P' + hitPort + '，只从该端口单播转发，其它端口收不到这个帧。',
        filter: '目的端口与入端口同为 P' + inPort + '（同一共享网段），交换机直接过滤丢弃，不再转发。',
        bcast: '目的为广播地址 ' + MAC_BCAST + '，向除入端口外的所有端口泛洪：' + plist + '。'
      }[action];
      const ae = {
        flood: 'The destination ' + dstMac + ' is unknown (unknown unicast), so the frame is flooded to every port except the ingress port: ' + plist + '.',
        forward: 'The destination ' + dstMac + ' matches entry P' + hitPort + ', so the frame is forwarded out that single port only. Other ports never see it.',
        filter: 'Destination port equals the ingress port P' + inPort + ' (same shared segment), so the bridge filters and drops the frame.',
        bcast: 'A broadcast destination ' + MAC_BCAST + ' is always flooded to every port except the ingress port: ' + plist + '.'
      }[action];

      // 与课程抓包表对应：默认脚本按序号一一对应；自定义帧按「源/目的/入端口」找最相近的抓包行
      let p = -1;
      const list = S.switch && S.switch.packets;
      if (list) {
        if (!o.frames) p = i < list.length ? i : -1;
        else p = list.findIndex(q => q.f && q.f.src === f.src && q.f.dst === f.dst &&
          (q.f.in || SW_PORT[q.f.src]) === inPort && !!q.f.arp === !!f.arp);
        if (p < 0 && list.length) p = Math.min(i, list.length - 1);
      }

      out.push({
        r: r, frame: f, inPort: inPort, egress: egress, action: action, learn: learn,
        table: snap, srcMac: srcMac, dstMac: dstMac, floods: floods, forwards: forwards,
        filters: filters, learns: learns, agingOn: agingOn,
        p: p >= 0 ? p : undefined,
        zh: '帧 ' + r + '：端口 P' + inPort + ' 收到 ' + srcMac + ' → ' + dstMac + '。' + lz + az +
          (agingOn ? ' 本实验开启了短老化：超过 2 帧未刷新的表项已被删除，因此可能出现本可命中却再次泛洪的情况。' : ''),
        en: 'Frame ' + r + ': port P' + inPort + ' receives ' + srcMac + ' → ' + dstMac + '. ' + le + ae +
          (agingOn ? ' Short aging is enabled: entries not refreshed for 2 frames expire, so a previously known destination may be flooded again.' : '')
      });
    });
    return out;
  }

  (function () {
    const swLayers = f => {
      let ls;
      if (f.dst === 'FF') {
        ls = [ETH(MAC_BCAST, SW_MAC[f.src], 0x0806, '0x0806 (ARP)'),
          ARP(1, SW_MAC[f.src], SW_IP[f.src], '00:00:00:00:00:00', IP_B)];
      } else if (f.arp) {
        ls = [ETH(SW_MAC[f.dst], SW_MAC[f.src], 0x0806, '0x0806 (ARP)'),
          ARP(2, SW_MAC[f.src], SW_IP[f.src], SW_MAC[f.dst], SW_IP[f.dst])];
      } else {
        const ic = ICMP(8, 0, 'Echo Request', 0x0b21, 1);
        ls = [ETH(SW_MAC[f.dst], SW_MAC[f.src], 0x0800, '0x0800 (IPv4)'),
          IPV4(SW_IP[f.src], SW_IP[f.dst], 1, '1 (ICMP)', ic.bytes.length), ic];
      }
      ls[0].note = '以太网帧只有源 / 目的 MAC，没有任何「端口号」字段：交换机把帧从哪个端口收到，是硬件在入队列时记下的，学习算法据此建立「MAC ↔ 端口」映射。';
      return ls;
    };
    const META = [
      { t: 0.000, kind: 'flood', phase: '未知单播泛洪', title: 'A → B · 首帧',
        info: 'A → B · 表空 → 学习 A@P1，泛洪 P2/P3/P4', proto: 'ETH',
        note: '交换机刚上电，转发表为空。收到帧先学习源地址 A 在端口 P1，再查目的 B 未命中，于是向除 P1 外的所有端口泛洪；B 会收到，C/D 也会收到但由网卡丢弃。' },
      { t: 0.004, kind: 'forward', phase: '已知单播转发', title: 'B → A · 精准转发',
        info: 'B → A · A@P1 命中 → 只从 P1 转发', proto: 'ETH',
        note: 'B 的应答帧从 P2 进入：先学习 B@P2，再查到 A 在 P1，于是只向 P1 转发。这一刻起交换机从「集线器」变成了「按目的地址定向转发」的网桥。' },
      { t: 0.011, kind: 'flood', phase: '未知单播泛洪', title: 'A → C · 再次泛洪',
        info: 'A → C · C 未学习 → 泛洪 P2/P3/P4', proto: 'ETH',
        note: '自学习是「被动」的：只有主机主动发过帧，交换机才知道它在哪个端口。C 一直沉默，因此去往 C 的帧仍要泛洪。' },
      { t: 0.018, kind: 'forward', phase: '已知单播转发', title: 'C → A · 学习 C 并转发',
        info: 'C → A · 学习 C@P3，A@P1 命中 → 单播 P1', proto: 'ETH',
        note: 'C 一开口，交换机立刻学到 C@P3。此后 A ↔ C 的通信不再泛洪，冲突域被隔离，端口带宽得以独享。' },
      { t: 0.027, kind: 'filter', phase: '同端口过滤', title: 'A → B · 同网段过滤',
        info: 'A / B 同在 P1 共享网段 → 过滤，不转发', proto: 'ETH',
        note: '如果 A 与 B 接在同一个集线器上（都从 P1 进入），目的端口与入端口相同，交换机不会把帧再送回原端口 —— 这就是过滤，也是网桥隔离冲突域的关键。' },
      { t: 0.036, kind: 'bcast', phase: '广播帧泛洪', title: 'ARP Request · 广播',
        info: 'A → FF:FF:FF:FF:FF:FF · 广播必须泛洪', proto: 'ARP',
        note: '广播 / 组播地址永远不会出现在转发表里（它们不可能作为源地址被学习），因此广播帧总是向除入端口外的所有端口复制一份。' },
      { t: 0.041, kind: 'forward', phase: '已知单播转发', title: 'ARP Reply · 单播应答',
        info: 'B → A · A@P1 命中 → 只从 P1 转发', proto: 'ARP',
        note: 'ARP 应答是单播：目的 MAC 是 A，转发表命中 P1，其它端口完全看不到这个应答，也不会打扰 C / D。' },
      { t: 0.092, kind: 'learn', phase: '主机迁移 / 表项更新', title: 'A 迁移到 P3 · 表项覆盖',
        info: '源 A 出现在 P3 → 覆盖 A@P1 为 A@P3', proto: 'ETH',
        note: '把 A 的网线从 P1 拔到 P3 后，同一个源 MAC 出现在新端口。交换机无条件用「最新的入端口」覆盖旧表项，避免把帧继续发错端口。这正是自学习能自适应拓扑变化的原因。' },
      { t: 0.099, kind: 'forward', phase: '已知单播转发', title: 'B → A · 改走新端口',
        info: 'B → A · A@P3 命中 → 改从 P3 转发', proto: 'ETH',
        note: '表项更新立即生效：后续发往 A 的帧改从 P3 出去。注意交换机不会主动广播「A 搬家了」，靠的就是这条「源地址学习 + 覆盖」规则。' }
    ];

    const packets = SW_SCRIPTS.learn.map((f, i) => {
      const m = META[i], inPort = f.in || SW_PORT[f.src];
      return P({
        t: m.t, src: SW_MAC[f.src], dst: f.dst === 'FF' ? 'Broadcast' : SW_MAC[f.dst],
        proto: m.proto, kind: m.kind, phase: m.phase, title: m.title, info: m.info, note: m.note,
        osi: [2], layer: 2, f: f, from: SW_PORT_NODE[inPort], to: 'sw',
        layers: swLayers(f)
      });
    });

    def('switch', {
      name: '交换机自学习', title: '网桥转发表实验', cat: 'base', sub: 'MAC 学习 · 泛洪 · 转发 · 过滤',
      osi: 2, layer: 2,
      nodes: ['ha', 'hb', 'hc', 'hd', 'sw'], seqNodes: ['ha', 'sw', 'hb', 'hc', 'hd'],
      links: [['ha', 'sw'], ['hb', 'sw'], ['hc', 'sw'], ['hd', 'sw']],
      labels: {
        ha: { name: '主机 A · P1', en: 'Host A · P1', ip: MAC_A },
        hb: { name: '主机 B · P2', en: 'Host B · P2', ip: MAC_B },
        hc: { name: '主机 C · P3', en: 'Host C · P3', ip: MAC_C },
        hd: { name: '主机 D · P4', en: 'Host D · P4', ip: MAC_D },
        sw: { name: '交换机 / 网桥 SW1', en: 'Switch / Bridge SW1', ip: 'MAC 转发表 · 4 端口' }
      },
      steps: [
        { t: '源地址学习', d: '从入端口记下「源 MAC ↔ 端口」', at: 1 },
        { t: '未知单播泛洪', d: '目的未命中就复制到其它端口', at: 1 },
        { t: '已知单播转发', d: '命中表项后只发一个端口', at: 2 },
        { t: '同端口过滤', d: '目的与入端口相同则丢弃', at: 5 },
        { t: '广播与老化', d: '广播必泛洪，表项会过期', at: 6 },
        { t: '主机迁移', d: '源地址换端口时覆盖旧表项', at: 8 }
      ],
      desc: '交换机不读取 IP，也不修改帧：它只看以太网帧的源 MAC 和目的 MAC。收到任何一帧，先把「源 MAC ↔ 入端口」写入转发表（学习、覆盖、刷新老化）；再查目的 MAC，命中就单播转发，未命中就泛洪，目的与入端口相同则过滤。表项默认 300 秒老化，主机换端口时由新的源地址帧自动覆盖。',
      tip: '自学习算法本身不会防环：一旦二层存在冗余链路，广播帧与未知单播帧会沿环路无限复制，形成广播风暴，MAC 表也会在两个端口间反复漂移。这就是必须再叠加生成树协议（STP）把冗余链路逻辑阻塞的原因 —— 请接着看下一门课程。',
      stats: [
        { k: '工作层次', v: '数据链路层 (L2)' },
        { k: '学习依据', v: '源 MAC + 入端口' },
        { k: '转发依据', v: '目的 MAC 查表' },
        { k: '三种动作', v: '泛洪 / 转发 / 过滤' },
        { k: '默认老化', v: '300 s' },
        { k: '表项容量', v: '本实验 4 端口' }
      ],
      packets: packets,
      lab: { tab: 'swLabView' }
    });
  })();

  /* ============================================================
     20 · 生成树协议 STP / RSTP
     共享仿真内核：由根桥、链路开销与 Bridge ID 计算端口角色，
     再按「故障 → Max Age 超时 → TCN → TC → 重新收敛」推演拓扑变化。
     ============================================================ */
  const STP_SW = {
    s1: { id: 's1', name: 'SW1', mac: MAC_SW1, ports: { 1: '主机 A', 2: 'SW1—SW2', 3: 'SW1—SW3' } },
    s2: { id: 's2', name: 'SW2', mac: MAC_SW2, ports: { 1: 'SW2—SW1', 2: 'SW2—SW3' } },
    s3: { id: 's3', name: 'SW3', mac: MAC_SW3, ports: { 1: 'SW3—SW1', 2: 'SW3—SW2', 3: '主机 B' } }
  };
  const STP_LINKS = [
    { id: 'l12', a: 's1', b: 's2', pa: 2, pb: 1, cost: 19, label: 'SW1 — SW2' },
    { id: 'l23', a: 's2', b: 's3', pa: 2, pb: 2, cost: 19, label: 'SW2 — SW3' },
    { id: 'l31', a: 's3', b: 's1', pa: 1, pb: 3, cost: 19, label: 'SW3 — SW1' }
  ];
  const STP_LAB_DEFAULT = { root: 's1', fail: 'l12', proto: 'stp' };

  // 依据 (根路径开销, 上游 Bridge ID, 端口 ID) 选出每个非根桥的根端口，
  // 再为每条链路选出指定端口，剩下的端口置为 Alternate / Blocking。
  function stpRoles(root, fail) {
    const pri = {};
    Object.keys(STP_SW).forEach(k => { pri[k] = k === root ? 4096 : 32768; });
    const links = STP_LINKS.filter(l => l.id !== fail);
    const dist = { s1: Infinity, s2: Infinity, s3: Infinity };
    dist[root] = 0;
    for (let k = 0; k < 3; k++) links.forEach(l => {
      if (dist[l.a] + l.cost < dist[l.b]) dist[l.b] = dist[l.a] + l.cost;
      if (dist[l.b] + l.cost < dist[l.a]) dist[l.a] = dist[l.b] + l.cost;
    });

    const parent = {};
    Object.keys(STP_SW).forEach(s => {
      if (s === root) { parent[s] = null; return; }
      const cand = links.filter(l => l.a === s || l.b === s).map(l => {
        const nb = l.a === s ? l.b : l.a;
        return { id: l.id, key: [dist[nb] + l.cost, pri[nb], STP_SW[nb].mac] };
      }).sort((x, y) => x.key[0] - y.key[0] || x.key[1] - y.key[1] || x.key[2].localeCompare(y.key[2]))[0];
      parent[s] = cand ? cand.id : null;
    });

    const roles = { 's1:1': 'DP', 's3:3': 'DP' };   // 接主机的边缘端口恒为指定端口
    links.forEach(l => {
      const A = { s: l.a, d: dist[l.a], p: pri[l.a], m: STP_SW[l.a].mac, port: l.pa };
      const B = { s: l.b, d: dist[l.b], p: pri[l.b], m: STP_SW[l.b].mac, port: l.pb };
      const cmp = (B.d - A.d) || (B.p - A.p) || B.m.localeCompare(A.m);
      const w = cmp >= 0 ? A : B, lo = cmp >= 0 ? B : A;
      roles[w.s + ':' + w.port] = 'DP';
      roles[lo.s + ':' + lo.port] = parent[lo.s] === l.id ? 'RP' : 'ALT';
    });
    if (fail && fail !== 'none') {
      const fl = STP_LINKS.filter(l => l.id === fail)[0];
      if (fl) { roles[fl.a + ':' + fl.pa] = 'DOWN'; roles[fl.b + ':' + fl.pb] = 'DOWN'; }
    }
    const blocked = Object.keys(roles).filter(k => roles[k] === 'ALT');
    return { root: root, pri: pri, dist: dist, parent: parent, roles: roles, blocked: blocked, fail: fail };
  }

  function simulateSTP(cfg) {
    const o = Object.assign({}, STP_LAB_DEFAULT, cfg || {});
    const before = stpRoles(o.root, 'none');
    const after = stpRoles(o.root, o.fail === 'none' ? 'none' : o.fail);
    const rootName = STP_SW[o.root].name;
    const failLink = STP_LINKS.filter(l => l.id === o.fail)[0];
    const failText = failLink ? failLink.label : '无故障';
    const convZh = o.proto === 'rstp' ? 'RSTP 用提案/同意（Proposal / Agreement）握手，毫秒级完成' :
      'STP 需 Max Age 20 s + Listening 15 s + Learning 15 s，约 30~50 s';
    const convEn = o.proto === 'rstp' ? 'RSTP completes in milliseconds via Proposal/Agreement handshakes' :
      'classic STP needs Max Age 20 s + Listening 15 s + Learning 15 s, about 30–50 s';
    const convTime = o.proto === 'rstp' ? '< 1 s' : '30 ~ 50 s';
    const blkBefore = before.blocked.length ? before.blocked.map(k => STP_SW[k.split(':')[0]].name + ':P' + k.split(':')[1]).join('、') : '无';
    const blkAfter = after.blocked.length ? after.blocked.map(k => STP_SW[k.split(':')[0]].name + ':P' + k.split(':')[1]).join('、') : '无';
    const portListEn = rs => rs.blocked.length ? rs.blocked.map(k => STP_SW[k.split(':')[0]].name + ':P' + k.split(':')[1]).join(', ') : 'none';
    const blkBeforeEn = portListEn(before), blkAfterEn = portListEn(after);

    const S11 = [
      { phase: 'boot', p: 0, focus: 's1', arrows: true,
        zh: '阶段 1 · 启动：三台交换机刚上电，都自认为是根桥，从每个活动端口每 2 秒发出配置 BPDU，其中的「根桥 ID」填自己的 Bridge ID（优先级 + MAC），根路径开销为 0。',
        en: 'Stage 1 · Boot: all three switches assume they are the root and emit Configuration BPDUs every 2 s on every active port, each claiming its own Bridge ID (priority + MAC) with a root path cost of 0.' },
      { phase: 'elect', p: 1, focus: 's1',
        zh: '阶段 2 · 根桥选举：逐字段比较 BPDU 里的根桥 ID，先比优先级（默认 32768，需为 4096 倍数），再比 MAC，数值最小者胜出。本实验把 ' + rootName + ' 的优先级设为 4096，因此它成为根桥，其余交换机停止自称根桥，只转发它的 BPDU。',
        en: 'Stage 2 · Root election: BPDUs are compared by root Bridge ID — first priority (default 32768, in steps of 4096), then MAC; the smallest wins. Here ' + rootName + ' has priority 4096, so it becomes the root bridge and the others stop claiming root and only relay its BPDUs.' },
      { phase: 'rootport', p: 2, focus: 's2', arrows: true,
        zh: '阶段 3 · 选根端口：每台非根桥比较所有能到达根桥的端口，取「累计根路径开销」最小者作为根端口 RP；开销相同则依次比较上游 Bridge ID、上游端口 ID。100 Mbps 链路开销为 19，直连根桥的端口开销 19 优于绕行 38。',
        en: 'Stage 3 · Root ports: every non-root bridge picks the port with the smallest cumulative root path cost as its RP; ties are broken by upstream Bridge ID then upstream Port ID. A direct 100 Mbps link costs 19, beating a two-hop detour of 38.' },
      { phase: 'designated', p: 3, focus: 's3', arrows: true,
        zh: '阶段 4 · 选指定端口：每条链路（每个网段）必须且只能有一个指定端口 DP，由该链路上到根桥开销最小的交换机担任；根桥的所有活动端口天然都是 DP。DP 负责在该网段上发送 BPDU 与转发用户帧。',
        en: 'Stage 4 · Designated ports: each segment elects exactly one DP — the endpoint with the lowest root path cost (ties broken by Bridge ID). All active ports on the root bridge are DPs. A DP sends BPDUs onto its segment and forwards user frames.' },
      { phase: 'block', p: 4, focus: 'l23',
        zh: '阶段 5 · 阻塞冗余端口：既不是 RP 也不是 DP 的端口进入 Blocking（Alternate），只收 BPDU、不转发用户帧、也不学习 MAC。三角形环路被剪成一棵无环的树，当前阻塞端口：' + blkBefore + '。',
        en: 'Stage 5 · Blocking: ports that are neither RP nor DP enter Blocking (Alternate) — they listen to BPDUs but do not forward frames or learn MACs. The triangle is pruned into a loop-free tree. Blocked port: ' + blkBeforeEn + '.' },
      { phase: 'stable', p: 5, focus: 's1', arrows: true,
        zh: '阶段 6 · 稳定转发：根桥每 Hello Time (2 s) 发一次配置 BPDU，下游从根端口收到后刷新 Message Age 并从指定端口继续转发。用户帧 A → B 只沿 RP / DP 这条唯一路径通过，被阻塞的链路保持静默。',
        en: 'Stage 6 · Steady state: the root emits a Configuration BPDU every Hello Time (2 s); downstream bridges receive it on root ports, refresh Message Age and relay it out designated ports. User frames A → B follow the single RP/DP path; the blocked link stays silent.' },
      { phase: 'fail', p: 6, focus: o.fail === 'none' ? 's1' : o.fail,
        zh: '阶段 7 · 链路故障：' + failText + (failLink ? ' 断开，下游交换机收不到根桥的 BPDU' : '（本轮未设置故障，活动树保持不变，可对比有故障时的收敛过程）') +
          '。STP 要等 Message Age 累加到 Max Age (20 s) 才判定失效；RSTP 只需连续 3 个 Hello (6 s) 未收到即可，而且备用端口早已准备好。',
        en: 'Stage 7 · Link failure: ' + failText + (failLink ? ' goes down, so downstream bridges stop receiving root BPDUs' : ' — no failure configured this run, so the active tree stays unchanged') +
          '. Classic STP waits until Message Age reaches Max Age (20 s); RSTP detects it after 3 missed Hellos (6 s) and already has an alternate port ready.' },
      { phase: 'detect', p: 7, focus: 's2',
        zh: '阶段 8 · 感知变化并上报：检测到端口状态变化的交换机从根端口向上游发送 TCN BPDU（只有 4 字节），上游用 TCA 确认并继续向根桥转发，直到根桥收到为止。注意 TCN 不含任何拓扑细节，只是「我这里有变化」。',
        en: 'Stage 8 · Detection and notification: the switch that detects the change sends a 4-byte TCN BPDU upstream via its root port; each upstream bridge acknowledges with TCA and relays it until the root hears it. A TCN carries no topology details — just "something changed here".' },
      { phase: 'tcn', p: 8, focus: 's1',
        zh: '阶段 9 · 根桥通告全网：根桥在后续配置 BPDU 中把 TC (Topology Change) 标志置 1 并持续转发 Forward Delay + Max Age 时间。所有交换机把 MAC 转发表的老化时间从默认 300 s 临时缩短为 15 s，快速冲掉可能已经失效的表项。',
        en: 'Stage 9 · Root floods the change: the root sets the TC flag in its Configuration BPDUs for Forward Delay + Max Age. Every bridge temporarily shortens MAC table aging from 300 s to 15 s, flushing entries that may now point out the wrong port.' },
      { phase: 'converge', p: 9, focus: o.fail === 'none' ? 's1' : 'l23',
        zh: '阶段 10 · 重新收敛：' + convZh + '。原阻塞端口若在新拓扑中成为 RP / DP，就由 Blocking → Listening → Learning → Forwarding 逐步放开，同时不学习 MAC 以防临时环路。新阻塞端口：' + blkAfter + '。',
        en: 'Stage 10 · Reconvergence: ' + convEn + '. A formerly blocked port that is now an RP/DP moves Blocking → Listening → Learning → Forwarding without learning MACs, preventing transient loops. New blocked port: ' + blkAfterEn + '.' },
      { phase: 'final', p: 10, focus: 's3',
        zh: '阶段 11 · 新树稳定：冗余链路被激活，A → B 的帧改走新的活动路径，网络恢复连通但不再有环。STP 用「逻辑阻塞」而非物理断开来保留冗余：平时只有一棵树在工作，故障时自动把备份链路纳进来。',
        en: 'Stage 11 · New tree stable: the redundant link is activated and A → B frames take the new active path — connectivity restored without any loop. STP blocks links logically, not physically: one tree forwards at a time, and the backup is absorbed automatically on failure.' }
    ];

    return S11.map((x, i) => Object.assign({}, x, {
      r: i + 1, root: o.root, proto: o.proto, convTime: convTime,
      fail: o.fail === 'none' ? null : o.fail,
      roles: i === 0 ? null : (i <= 8 ? before : after),
      showFail: i >= 6 && o.fail !== 'none',
      blockedCount: (i >= 9 ? after.blocked.length : before.blocked.length),
      blockedPorts: (i >= 9 ? blkAfter : blkBefore),
      rootCost: Math.max.apply(null, Object.keys((i >= 9 ? after : before).dist).map(k => (i >= 9 ? after : before).dist[k]).filter(v => isFinite(v))) || 0
    }));
  }

  (function () {
    const pri = { s1: 4096, s2: 32768, s3: 32768 };
    const B = (rm, cost, br, port, flags, msgAge) => STP_CONFIG({
      rootPri: pri[rm], rootMac: STP_SW[rm].mac, cost: cost,
      brPri: pri[br], brMac: STP_SW[br].mac,
      port: 0x1000 | port, flags: flags || 0, msgAge: msgAge || 0
    });
    const ic = ICMP(8, 0, 'Echo Request', 0x0c31, 1);
    const userFrame = [ETH(MAC_B, MAC_A, 0x0800, '0x0800 (IPv4)'),
      IPV4(IP_A, IP_B, 1, '1 (ICMP)', ic.bytes.length), ic];
    userFrame[0].note = '这是普通用户帧（EtherType 0x0800），与 BPDU 不同：它只在 RP / DP 端口上转发，永远不会从 Blocking 端口出去。';

    const M = [
      { t: 0.000, from: 's1', to: 's2', proto: 'STP', kind: 'bpdu', phase: '启动 · 各自称根',
        title: '配置 BPDU · SW1 自称根桥',
        info: 'Root ID 4096:SW1 · Cost 0 · SW1 从 P2 发出',
        note: '交换机刚启动时所有端口都在发送 BPDU，且都把自己填成根桥（Root ID = 自己的 Bridge ID，Cost = 0）。SW2 / SW3 也在做同样的事。',
        layers: stpFrame(MAC_SW1, B('s1', 0, 's1', 2)) },
      { t: 2.000, from: 's1', to: 's2', proto: 'STP', kind: 'bpdu', phase: '根桥选举',
        title: '配置 BPDU · SW1 胜出成为根桥',
        info: 'Root ID 4096:SW1 · Cost 0 · 向 SW2 通告',
        note: '比较根桥 ID：优先级 4096 < 32768，SW1 的 BPDU 最优。SW2 收到后承认 SW1 是根桥，不再发送自己那套 BPDU，改成从指定端口转发 SW1 的信息。',
        layers: stpFrame(MAC_SW1, B('s1', 0, 's1', 2)) },
      { t: 2.006, from: 's2', to: 's3', proto: 'STP', kind: 'bpdu', phase: '根端口 / 指定端口',
        title: '配置 BPDU · SW2 转发 (Cost 19)',
        info: 'Root ID 4096:SW1 · Cost 19 · Bridge 32768:SW2 · P2',
        note: 'SW2 把根桥 BPDU 的根路径开销加上本链路开销 19 后从 P2 转发出去。P1（直连根桥、开销 19）被选为根端口；P2 在 SW2—SW3 网段上开销最小，成为该网段指定端口。',
        layers: stpFrame(MAC_SW2, B('s1', 19, 's2', 2)) },
      { t: 2.011, from: 's1', to: 's3', proto: 'STP', kind: 'bpdu', phase: '根端口 / 指定端口',
        title: '配置 BPDU · SW1 → SW3 (Cost 0)',
        info: 'Root ID 4096:SW1 · Cost 0 · 从 P3 发出',
        note: '根桥的所有活动端口都是指定端口。SW3 从 P1 收到 Cost=0 的 BPDU，加上链路开销 19，判定 P1 是到根桥最优的根端口。',
        layers: stpFrame(MAC_SW1, B('s1', 0, 's1', 3)) },
      { t: 2.017, from: 's2', to: 's3', proto: 'STP', kind: 'bpdu', phase: '阻塞冗余端口',
        title: '配置 BPDU · SW3 的 P2 被阻塞',
        info: 'Root ID 4096:SW1 · Cost 19 · SW3:P2 → Blocking',
        note: 'SW2—SW3 这条链路上，SW2 与 SW3 到根桥的开销都是 19，平局比较 Bridge ID：SW2 更小，所以 SW2:P2 是指定端口，SW3:P2 既非根端口也非指定端口，被置为 Blocking。环路就此被剪断。',
        layers: stpFrame(MAC_SW2, B('s1', 19, 's2', 2)) },
      { t: 4.000, from: 's1', to: 's3', proto: 'STP', kind: 'bpdu', phase: '稳定转发',
        title: 'Hello BPDU · 根桥周期通告',
        info: 'Root ID 4096:SW1 · Message Age 0 · 每 2 s',
        note: '稳定后只有根桥产生配置 BPDU，其它交换机在根端口收到、刷新 Message Age 后从指定端口继续转发。只要 Hello 不断，端口角色就保持不变。',
        layers: stpFrame(MAC_SW1, B('s1', 0, 's1', 3)) },
      { t: 24.000, from: 's2', to: 's3', proto: 'STP', kind: 'topo', phase: '链路故障',
        title: 'BPDU 老化 · Message Age = Max Age 20 s',
        info: 'SW1—SW2 中断 · 20 s 未收到根 BPDU',
        note: 'SW1—SW2 链路断开后，SW2 再也收不到根桥的 BPDU，缓存的 BPDU 中 Message Age 累加到 20 s（Max Age）后被丢弃。STP 由此判定拓扑发生变化；RSTP 只需 3 个 Hello (6 s)。',
        layers: stpFrame(MAC_SW2, B('s1', 19, 's2', 1, 0, 20)) },
      { t: 24.004, from: 's2', to: 's3', proto: 'STP', kind: 'tcn', phase: '拓扑变化通知',
        title: 'TCN BPDU · 向上游报告变化',
        info: 'TCN · 4 字节 · 从根端口向上游逐跳转发',
        note: 'SW2 通过新的根端口向上游发 TCN BPDU。它只有 4 字节，不带任何拓扑信息；上游用配置 BPDU 中的 TCA 位确认，并继续转发直到根桥。',
        layers: stpFrame(MAC_SW2, STP_TCN()) },
      { t: 24.012, from: 's1', to: 's3', proto: 'STP', kind: 'tc', phase: '根桥通告 TC',
        title: '配置 BPDU · TC 标志置位',
        info: 'Flags 0x01 (TC) · 全网缩短 MAC 表老化',
        note: '根桥收到 TCN 后，在后续配置 BPDU 里把最低位 TC 置 1 并泛洪全网。各交换机把 MAC 转发表老化时间临时从 300 s 改为 Forward Delay (15 s)，尽快清掉可能走错端口的表项。',
        layers: stpFrame(MAC_SW1, B('s1', 0, 's1', 3, 1, 0)) },
      { t: 54.020, from: 's3', to: 's2', proto: 'STP', kind: 'bpdu', phase: '重新收敛',
        title: '配置 BPDU · SW3:P2 成为指定端口',
        info: 'Root ID 4096:SW1 · Cost 19 · SW3:P2 解除阻塞',
        note: '新拓扑里 SW2 只能经 SW3 到达根桥（开销 38）。SW3:P2 由 Blocking 经 Listening / Learning 依次进入 Forwarding 并成为该网段指定端口，SW2:P2 则变成新的根端口；STP 这段收敛约需 30 s。',
        layers: stpFrame(MAC_SW3, B('s1', 19, 's3', 2)) },
      { t: 54.031, from: 'ha', to: 's1', proto: 'ETH', kind: 'swdata', phase: '新树稳定',
        title: '用户帧 · A → B 改走备用路径',
        info: 'A → B · 沿新的 RP / DP 树转发',
        note: '收敛完成后，A 与 B 之间的帧改走 SW1 → SW3 → SW2 这条新路径。冗余链路仍在，但同一时刻只有一棵无环树在转发用户数据。',
        layers: userFrame }
    ];

    def('stp', {
      name: '生成树协议', title: 'STP / RSTP 实验', cat: 'base', sub: '根桥选举 · 端口角色 · 收敛',
      osi: 2, layer: 2,
      nodes: ['ha', 's1', 's2', 's3', 'hd'], seqNodes: ['ha', 's1', 's2', 's3', 'hd'],
      links: [['ha', 's1'], ['s1', 's2'], ['s2', 's3'], ['s3', 's1'], ['s3', 'hd']],
      pos: {
        ha: { x: 120, y: 300 }, s1: { x: 270, y: 130 }, s2: { x: 730, y: 130 },
        s3: { x: 500, y: 330 }, hd: { x: 880, y: 330 }
      },
      labels: {
        ha: { name: '主机 A', en: 'Host A', ip: MAC_A },
        hd: { name: '主机 B', en: 'Host B', ip: MAC_B },
        s1: { name: '交换机 SW1', en: 'Switch SW1', ip: MAC_SW1 },
        s2: { name: '交换机 SW2', en: 'Switch SW2', ip: MAC_SW2 },
        s3: { name: '交换机 SW3', en: 'Switch SW3', ip: MAC_SW3 }
      },
      steps: [
        { t: '各自称根', d: '所有交换机发出自己的配置 BPDU', at: 1 },
        { t: '根桥选举', d: 'Bridge ID 最小者成为根桥', at: 2 },
        { t: '选根端口', d: '非根桥挑到根开销最小的端口', at: 3 },
        { t: '选指定端口', d: '每条链路只保留一个 DP', at: 4 },
        { t: '阻塞冗余端口', d: '剪断环路形成无环树', at: 5 },
        { t: '故障与收敛', d: 'TCN / TC 通告后启用备用链路', at: 9 },
        { t: '新树稳定', d: '用户帧沿新路径转发', at: 11 }
      ],
      desc: '二层冗余链路能提升可靠性，却会让广播帧沿环路无限复制。STP（IEEE 802.1D）用配置 BPDU 交换 Bridge ID 与根路径开销，选出唯一根桥，再为每台交换机定根端口、为每条链路定指定端口，把剩下的端口逻辑阻塞，从而把任意拓扑剪成一棵无环树；链路故障时通过 TCN / TC 机制重新收敛，RSTP（802.1w）把这一过程从 30~50 秒缩短到毫秒级。',
      tip: 'BPDU 直接封装在 802.3 + LLC（DSAP/SSAP = 0x42）帧里，目的 MAC 为组播 01:80:C2:00:00:00，不经过 IP 层。Bridge ID = 2 字节优先级 + 6 字节 MAC，先比优先级再比 MAC，越小越优；端口角色裁决顺序是「根路径开销 → 发送桥 ID → 端口 ID」。被阻塞的端口依然监听 BPDU，这正是故障后能快速接管的原因。',
      stats: [
        { k: '协议标准', v: 'IEEE 802.1D / 802.1w' },
        { k: 'BPDU 组播', v: '01:80:C2:00:00:00' },
        { k: 'LLC 地址', v: 'DSAP/SSAP = 0x42' },
        { k: 'Bridge ID', v: '优先级 + MAC' },
        { k: '链路开销', v: '100 Mbps = 19' },
        { k: 'STP 定时器', v: 'Hello 2 / MaxAge 20 / Fwd 15 s' },
        { k: '收敛时间', v: 'STP 30~50 s · RSTP < 1 s' }
      ],
      packets: M.map((m, i) => P({
        t: m.t, src: m.from === 'ha' ? MAC_A : STP_SW[m.from].mac,
        dst: m.from === 'ha' ? MAC_B : MAC_STP_MCAST,
        proto: m.proto, kind: m.kind, phase: m.phase,
        from: m.from, to: m.to, title: m.title, info: m.info, note: m.note,
        osi: [2], layer: 2, f: { step: i },
        layers: m.layers
      })),
      lab: { tab: 'stpLabView' }
    });
  })();

  /* ============================================================
     21 · 以太网 CSMA/CD 共享介质
     共享仿真内核：按「载波侦听 → 同时发送 → 冲突 → Jam →
     二进制指数退避 → 重发成功」逐时隙推演介质上的事件。
     ============================================================ */
  const CD_LAB_DEFAULT = { hosts: 2, frame: 'min', backoff: 'beb' };
  const CD_FRAME_INFO = {
    min: { bytes: 64, txUs: 51.2, zh: '64 B 最短帧', en: '64 B minimum frame' },
    short: { bytes: 40, txUs: 32, zh: '40 B 过短帧', en: '40 B runt frame' },
    long: { bytes: 1518, txUs: 1214.4, zh: '1518 B 长帧', en: '1518 B long frame' }
  };
  const CD_BACKOFF_ZH = { beb: '二进制指数退避 BEB', fixed: '固定窗口退避 (0~3)', none: '不退避（立即重发）' };
  const CD_BACKOFF_EN = { beb: 'Binary exponential backoff', fixed: 'Fixed window (0–3)', none: 'No backoff (immediate retry)' };

  function simulateCSMA(cfg) {
    const o = Object.assign({}, CD_LAB_DEFAULT, cfg || {});
    const names = ['A', 'B', 'C', 'D'].slice(0, o.hosts);
    const FI = CD_FRAME_INFO[o.frame] || CD_FRAME_INFO.min;
    const minOk = o.frame !== 'short';
    const slotUs = CD_SLOT_US, tau = CD_TAU_US, jamUs = 3.2;
    const out = [], st = {};
    names.forEach(n => { st[n] = { s: 'sense', attempt: 0, k: 0, pick: 0, remain: 0, frozen: false, done: false }; });
    const active = names.slice(0, o.hosts >= 3 ? 3 : 2);
    let t = 0, collisions = 0, successes = 0, attempts = 0;

    const snap = () => { const q = {}; names.forEach(n => { q[n] = Object.assign({}, st[n]); }); return q; };
    const push = (phase, bus, extra) => out.push(Object.assign({
      r: out.length + 1, t: +t.toFixed(1), phase: phase, bus: bus, st: snap(),
      names: names.slice(), active: active.slice(), collisions: collisions, successes: successes,
      attempts: attempts, frameBytes: FI.bytes, txUs: FI.txUs, slotUs: slotUs,
      minOk: minOk, backoff: o.backoff, hosts: o.hosts, frame: o.frame, p: 0
    }, extra || {}));
    const pickOf = (n, attempt) => {
      const max = o.backoff === 'beb' ? Math.pow(2, Math.min(attempt, 10)) : (o.backoff === 'fixed' ? 4 : 1);
      const seed = (attempt * 7 + names.indexOf(n) * 3 + 1) * 13 + o.hosts * 5 + collisions * 17;
      return seed % max;
    };
    const rList = list => list.map(n => n + ' → r=' + st[n].pick).join('，');
    const rListEn = list => list.map(n => n + ' → r=' + st[n].pick).join(', ');

    // ① 载波侦听：IFG 结束，多个站点同时有帧要发
    push('sense', 'idle', { p: 0,
      zh: '时隙 0 · 载波侦听：' + names.join(' / ') + ' 都挂在同一条共享总线上，属于同一个冲突域。上一帧结束后的 96 bit 帧间隙（9.6 μs）已满，' + active.join(' 与 ') + ' 同时侦听到介质空闲并准备发送 ' + FI.zh + '。',
      en: 'Slot 0 · Carrier sense: ' + names.join(' / ') + ' share one bus and one collision domain. After the 96-bit interframe gap (9.6 μs), ' + active.join(' and ') + ' all sense an idle medium and prepare to send a ' + FI.en + '.' });

    // ② 传播时延内的「几乎同时」发送 → 冲突
    active.forEach(n => { st[n].s = 'tx'; st[n].attempt = 1; attempts++; });
    push('tx', 'busy', { p: 1,
      zh: 't = 0 μs · ' + active.join(' 与 ') + ' 开始发送。信号以约 2×10⁸ m/s 传播，最远两端单程需要 ' + tau + ' μs：B 在 A 的载波尚未抵达时也开始发帧，两个信号在电缆上叠加。',
      en: 't = 0 μs · ' + active.join(' and ') + ' start transmitting. A signal needs up to ' + tau + ' μs to cross the cable, so B starts before A’s carrier arrives and the two signals overlap.' });

    if (!minOk) {
      t = FI.txUs;
      active.forEach(n => { st[n].s = 'done'; st[n].done = true; });
      push('late', 'collision', { p: 8,
        zh: 't = ' + FI.txUs + ' μs · 过短帧已发完：' + FI.bytes + ' B 只需 ' + FI.txUs + ' μs，小于往返传播时延 51.2 μs。冲突信号传回时发送方早已发完，误以为发送成功，不会重传；接收端只看到一个 FCS 错误的残帧并丢弃 —— 这就是「迟到冲突」，也是最短帧长必须 ≥ 64 B 的根本原因。',
        en: 't = ' + FI.txUs + ' μs · The runt is already finished: ' + FI.bytes + ' B takes only ' + FI.txUs + ' μs, less than the 51.2 μs round-trip delay. The collision returns after the sender stopped, so it assumes success and never retries; the receiver just drops a bad-FCS fragment. This late collision is exactly why a frame must be at least 64 B.' });
      push('done', 'idle', { p: 9,
        zh: '结论：10 Mbps 以太网把争用期定为 512 bit = 51.2 μs，对应 64 字节。数据不足 46 字节时由 MAC 补 PAD，确保「最晚的冲突一定在帧发完之前被检测到」。可把帧长切回 64 B 再跑一次对比。',
        en: 'Conclusion: 10 Mbps Ethernet fixes the contention period at 512 bit = 51.2 μs, i.e. 64 bytes. Frames shorter than 46 B of payload are padded so that even the latest collision is detected before transmission ends. Switch back to 64 B and compare.' });
      return out;
    }

    t = tau;
    active.forEach(n => { st[n].s = 'collision'; });
    collisions++;
    push('collision', 'collision', { p: 3,
      zh: 't = ' + tau + ' μs · 边发边听：' + active.join(' 与 ') + ' 检测到电压异常（信号叠加），判定第 ' + collisions + ' 次冲突。由于 ' + FI.zh + ' 的发送时间 ' + FI.txUs + ' μs ≥ 争用期 51.2 μs，冲突在帧发完之前被及时发现。',
      en: 't = ' + tau + ' μs · Listen while talking: ' + active.join(' and ') + ' detect the voltage rise and register collision #' + collisions + '. A ' + FI.en + ' takes ' + FI.txUs + ' μs ≥ the 51.2 μs contention period, so the collision is caught before the frame ends.' });

    t += jamUs;
    active.forEach(n => { st[n].s = 'jam'; });
    push('jam', 'jam', { p: 4,
      zh: 't = ' + t.toFixed(1) + ' μs · 强化冲突：各站立即停发数据，改发 32 bit Jam 信号，保证网段上所有站点都意识到本次发送失败；残缺帧（< 64 B）被判为 runt 丢弃。',
      en: 't = ' + t.toFixed(1) + ' μs · Jam: every sender stops the frame and emits a 32-bit jam so all stations notice the failure; the truncated (< 64 B) fragment is dropped as a runt.' });

    // ③ 二进制指数退避：k = min(重传次数, 10)，r ∈ [0, 2^k − 1]
    active.forEach(n => {
      st[n].k = Math.min(st[n].attempt, 10);
      st[n].pick = pickOf(n, st[n].attempt);
      st[n].remain = st[n].pick;
      st[n].s = 'backoff';
    });
    const win = o.backoff === 'beb' ? 'k = min(n, 10)，窗口 0 ~ 2ᵏ−1' :
      (o.backoff === 'fixed' ? '固定窗口 0 ~ 3' : '窗口恒为 0');
    push('backoff', 'idle', { p: 5,
      zh: '退避 · ' + CD_BACKOFF_ZH[o.backoff] + '：' + win + '。本次 ' + rList(active) + '（单位：51.2 μs 时隙）。退避计时器只在介质空闲时递减，侦听到别人在发帧就冻结。',
      en: 'Backoff · ' + CD_BACKOFF_EN[o.backoff] + ': ' + (o.backoff === 'beb' ? 'k = min(n, 10), window 0 … 2^k−1' : o.backoff === 'fixed' ? 'fixed window 0 … 3' : 'window always 0') + '. This time ' + rListEn(active) + ' (unit: one 51.2 μs slot). A backoff timer only decrements while the medium is idle and freezes when another station transmits.' });

    let guard = 0;
    while (active.some(n => !st[n].done) && guard++ < 18) {
      // 先检查「退避已归零」的站点：r = 0 的站应立刻发送，不能等别人一起倒数
      const ready = active.filter(n => !st[n].done && st[n].s === 'backoff' && st[n].remain <= 0);
      if (ready.length >= 2) {
        collisions++; attempts += ready.length;
        ready.forEach(n => { st[n].s = 'collision'; });
        t += tau;
        push('collision', 'collision', { p: 3,
          zh: '第 ' + collisions + ' 次冲突：' + ready.join(' 与 ') + ' 选到了同一个退避时隙，重发再次相撞。' +
            (o.backoff === 'beb' ? 'BEB 把 k 增大，下一次窗口翻倍，冲突概率随之下降。' :
              o.backoff === 'none' ? '没有退避时所有站点永远同时重发，冲突会一直重复，直到第 16 次失败被丢弃。' :
                '固定窗口不随冲突次数扩大，高负载下更容易反复相撞。'),
          en: 'Collision #' + collisions + ': ' + ready.join(' and ') + ' picked the same slot and collided again. ' +
            (o.backoff === 'beb' ? 'BEB doubles the window (k grows), so the collision probability drops.' :
              o.backoff === 'none' ? 'With no backoff every station retries at once, so collisions repeat until the 16th attempt is abandoned.' :
                'A fixed window never grows, so repeated collisions are more likely under load.') });
        if (collisions >= 4) {
          t += jamUs;
          push('giveup', 'idle', { p: 9,
            zh: '重传失败：802.3 规定最多重传 16 次，k 在 n > 10 后封顶为 10（窗口最大 0~1023），仍失败就丢弃该帧并向高层报错。本实验只演示前 ' + collisions + ' 次冲突，避免时间轴无限延长；可切回 BEB 观察它如何快速化解冲突。',
            en: 'Retransmission failure: 802.3 allows at most 16 attempts; k is capped at 10 (window 0…1023) and the frame is dropped with an error to the upper layer. Only the first ' + collisions + ' collisions are shown here; switch back to BEB to see how quickly it resolves them.' });
          return out;
        }
        ready.forEach(n => { st[n].s = 'jam'; });
        t += jamUs;
        push('jam', 'jam', { p: 4, zh: '再次发 32 bit Jam，然后重新计算退避。', en: 'Another 32-bit jam, then backoff is recomputed.' });
        ready.forEach(n => {
          st[n].attempt++;
          st[n].k = Math.min(st[n].attempt, 10);
          st[n].pick = pickOf(n, st[n].attempt);
          st[n].remain = st[n].pick;
          st[n].s = 'backoff';
        });
        push('backoff', 'idle', { p: 5,
          zh: '重新退避（第 ' + collisions + ' 次冲突后）：' + rList(ready) + '，窗口 ' +
            (o.backoff === 'beb' ? '2^' + st[ready[0]].k + ' = ' + Math.pow(2, st[ready[0]].k) + ' 个时隙' : '不变') + '。',
          en: 'Backoff recomputed (after collision #' + collisions + '): ' + rListEn(ready) + ', window ' +
            (o.backoff === 'beb' ? '2^' + st[ready[0]].k + ' = ' + Math.pow(2, st[ready[0]].k) + ' slots' : 'unchanged') + '.' });
        continue;
      }
      if (ready.length === 1) {
        const w = ready[0];
        st[w].s = 'tx';
        active.forEach(n => { if (n !== w && !st[n].done && st[n].remain > 0) { st[n].frozen = true; st[n].s = 'frozen'; } });
        push('tx', 'busy', { p: 6,
          zh: w + ' 退避结束，重新载波侦听到空闲后发送 ' + FI.zh + '；其余站点侦听到载波，退避计时器冻结（不是清零），等介质空闲再继续倒数。',
          en: w + ' finishes backoff, senses an idle medium and sends its ' + FI.en + '; the others hear the carrier and freeze (do not reset) their backoff timers until the medium is idle again.' });
        t += FI.txUs;
        st[w].s = 'success'; st[w].done = true; successes++;
        active.forEach(n => { st[n].frozen = false; if (!st[n].done && st[n].s === 'frozen') st[n].s = 'backoff'; });
        push('success', 'idle', { p: 6,
          zh: 't = ' + t.toFixed(1) + ' μs · ' + w + ' 的 ' + FI.zh + ' 完整发出，发送期间没有检测到冲突 → 判定成功。以太网不回 ACK、不重传，可靠性交给上层；帧发完后所有站点再等 96 bit IFG 才能竞争下一次发送。',
          en: 't = ' + t.toFixed(1) + ' μs · ' + w + ' completes its ' + FI.en + ' with no collision detected → success. Ethernet sends no ACK and never retransmits at layer 2; reliability is left to upper layers. All stations then wait one 96-bit IFG before contending again.' });
        continue;
      }
      // 没有站点可以发送 → 介质空闲一个时隙，未冻结的计数器减 1
      const waiting = active.filter(n => !st[n].done && !st[n].frozen && st[n].remain > 0);
      if (!waiting.length) break;
      waiting.forEach(n => { st[n].remain--; });
      t += slotUs;
      push('slot', 'idle', { p: 5,
        zh: '时隙 +1（t = ' + t.toFixed(1) + ' μs）· 介质空闲，等待中的站点把退避计数器减 1：' +
          active.filter(n => !st[n].done).map(n => n + ' 剩 ' + st[n].remain).join('，') + '。',
        en: 'Slot +1 (t = ' + t.toFixed(1) + ' μs) · idle medium, waiting stations decrement their counters: ' +
          active.filter(n => !st[n].done).map(n => n + ' left ' + st[n].remain).join(', ') + '.' });
    }
    push('done', 'idle', { p: 9,
      zh: '本轮结束：' + successes + ' 帧成功、' + collisions + ' 次冲突、' + attempts + ' 次发送尝试。CSMA/CD 用「先听后发、边发边听、冲突停发、随机重发」把一条共享电缆变成可用的多路信道；交换式全双工以太网已不再有冲突域，但最短帧长与 BEB 的规则仍保留在标准里。',
      en: 'Run complete: ' + successes + ' frame(s) delivered, ' + collisions + ' collision(s), ' + attempts + ' attempts. CSMA/CD turns one shared cable into a usable multi-access channel by "sense before sending, listen while sending, stop on collision, retry randomly". Switched full-duplex Ethernet no longer has collision domains, but the 64 B minimum and BEB rules remain in the standard.' });
    return out;
  }

  (function () {
    const cdA = () => cdFrame({ src: MAC_A, dst: MAC_B, seq: 1 });
    const cdB = () => cdFrame({ src: MAC_B, dst: MAC_A, seq: 2 });
    const cdRunt = () => cdFrame({ src: MAC_C, dst: MAC_D, seq: 3, noPad: true,
      body: [IPV4(IP_C, IP_D, 1, '1 (ICMP)', 2),
        L('data', '仅 2 字节的 IP 载荷（未填充）', 'DATA', C.payload, [0x00, 0x00],
          [F('载荷', '2 字节', 0, 2, '上层只交了这么点数据；若网卡不补 PAD，整帧就只有 40 B，发送时间短于争用期。')])]
    });
    const M = [
      { t: 0.000, from: 'ha', to: 'bus', proto: 'IFG', kind: 'sense', phase: '载波侦听',
        title: '帧间隙 · 介质空闲', info: '96 bit IFG (9.6 μs) · 所有站点载波侦听',
        note: '共享介质上一次只能有一个信号。发帧前必须先听 96 bit 帧间隙；空闲才能发，这就是 CSMA 的「载波侦听多路访问」。',
        layers: [CD_IDLE()] },
      { t: 0.010, from: 'ha', to: 'bus', proto: 'ETH', kind: 'tx', phase: '发送与冲突',
        title: 'A 发送 64 B 最短帧', info: 'A → B · 64 B · 数据 42 B + PAD 4 B + FCS 4 B',
        note: '上层只交了 42 字节（IPv4 20 B + ICMP 22 B），MAC 子层补 4 字节 PAD，使数据字段达到 46 B，整帧恰好 64 B = 512 bit，发送时间 51.2 μs 正好等于争用期。',
        layers: cdA(), displaySize: '64 B' },
      { t: 0.010, from: 'hb', to: 'bus', proto: 'ETH', kind: 'tx', phase: '发送与冲突',
        title: 'B 在传播时延内也开始发送', info: 'B → A · 64 B · 与 A 的信号在总线上叠加',
        note: 'A 的载波需要最多 25.6 μs 才能传到最远端。B 在这段时间内也听到「空闲」并开始发帧，两个信号叠加 —— 冲突不可避免，这就是「传播时延」带来的争用窗口。',
        layers: cdB(), displaySize: '64 B' },
      { t: 0.036, from: 'ha', to: 'bus', proto: 'JAM', kind: 'collision', phase: '发送与冲突',
        title: '冲突 · 残缺帧碎片', info: 'Collision fragment · 21 B · FCS 错误',
        note: '冲突叠加破坏了比特，抓到的是长度远小于 64 B 的碎片。接收网卡按 runt frame 丢弃；发送方靠「边发边听」检测到电压异常，立即停止发送。',
        layers: [CD_FRAGMENT(), CD_FCS(true)] },
      { t: 0.039, from: 'hb', to: 'bus', proto: 'JAM', kind: 'jam', phase: '强化冲突',
        title: 'Jam 强化冲突信号', info: '32 bit Jam · 通知全网本次发送作废',
        note: '检测到冲突的站点改发 32 bit 强化冲突信号，确保网段上所有站点都察觉失败。随后线路恢复空闲，各站启动二进制指数退避。',
        layers: [CD_JAM()] },
      { t: 0.091, from: 'ha', to: 'bus', proto: 'ETH', kind: 'backoff', phase: '指数退避与重发',
        title: 'A 退避 r=0 · 立即重发', info: '第 1 次重传 · k=1 · r∈{0,1} 取 0',
        note: '第 1 次冲突后 k = min(1, 10) = 1，从 {0, 1} 中等概率取 r。A 取到 0，等 0 个 51.2 μs 时隙即可重发；重传帧与首发的字节完全相同，以太网帧里没有「重传次数」字段。',
        layers: cdA(), displaySize: '64 B' },
      { t: 0.142, from: 'hb', to: 'bus', proto: 'ETH', kind: 'success', phase: '指数退避与重发',
        title: 'B 退避 1 时隙后重发成功', info: '第 1 次重传 · k=1 · r=1 → 等 51.2 μs',
        note: 'B 取到 r=1，先等一个时隙。听到 A 正在发送时退避计时器冻结（不清零），A 发完并再等 96 bit IFG 后才继续倒数，最终独立发出，全程无冲突。',
        layers: cdB(), displaySize: '64 B' },
      { t: 0.420, from: 'hc', to: 'bus', proto: 'ETH', kind: 'runt', phase: '最短帧长反例',
        title: 'C 发送 40 B 过短帧（反例）', info: '14 B 首部 + 22 B 数据 + 4 B FCS = 40 B',
        note: '故意不补 PAD：整帧只有 40 B，发送时间 32 μs，短于 51.2 μs 争用期。若冲突在最远端发生，冲突信号传回时 C 已经发完，会误判为成功。',
        layers: cdRunt(), displaySize: '40 B (runt)' },
      { t: 0.452, from: 'hc', to: 'bus', proto: 'JAM', kind: 'late', phase: '最短帧长反例',
        title: '迟到冲突 · FCS 校验失败', info: 'Late collision · 接收端丢弃，发送方不重传',
        note: '这就是「迟到冲突」：过短帧让发送方在检测到冲突之前就结束了发送，网卡不会重传，帧静默丢失。802.3 因此规定最小帧长 64 B，且冲突只可能在帧的前 512 bit 内被检测到。',
        layers: [CD_FRAGMENT(), CD_FCS(true)] },
      { t: 0.900, from: 'hd', to: 'bus', proto: 'ETH', kind: 'long', phase: '长帧对照',
        title: 'D 发送 1518 B 长帧', info: 'D → A · 1518 B（最大帧长）· 占用介质 1214.4 μs',
        note: '最大帧长 1518 B（含 FCS）的发送时间约 1.21 ms，是争用期的 23.7 倍。长帧一旦冲突代价很高，但也绝不会漏检；这里只展开首段字节，其余数据按 MTU 规则截断。',
        layers: cdFrame({ src: MAC_D, dst: MAC_A, seq: 4 }), displaySize: '1518 B', truncated: true }
    ];

    def('csma', {
      name: 'CSMA/CD', title: '共享介质 · 最短帧长 · 指数退避', cat: 'base',
      sub: '载波侦听 / 冲突检测 / 二进制指数退避', osi: 2, layer: 2,
      nodes: ['ha', 'hb', 'hc', 'hd', 'bus'], seqNodes: ['ha', 'hb', 'hc', 'hd', 'bus'],
      links: [['ha', 'bus'], ['hb', 'bus'], ['hc', 'bus'], ['hd', 'bus']],
      pos: {
        ha: { x: 165, y: 120 }, hb: { x: 165, y: 348 }, hc: { x: 835, y: 120 },
        hd: { x: 835, y: 348 }, bus: { x: 500, y: 234 }
      },
      labels: {
        ha: { name: '站点 A', en: 'Station A', ip: MAC_A },
        hb: { name: '站点 B', en: 'Station B', ip: MAC_B },
        hc: { name: '站点 C', en: 'Station C', ip: MAC_C },
        hd: { name: '站点 D', en: 'Station D', ip: MAC_D },
        bus: { name: '共享同轴总线 / 集线器', en: 'Shared bus / Hub', ip: '10 Mbps · 一个冲突域' }
      },
      steps: [
        { t: '载波侦听', d: '先听后发，等 96 bit 帧间隙', at: 1 },
        { t: '发送与冲突', d: '传播时延内两站同时发帧', at: 2 },
        { t: '强化冲突', d: '发 32 bit Jam 让全网知晓', at: 5 },
        { t: '二进制指数退避', d: 'k=min(n,10)，r∈[0,2ᵏ−1]', at: 6 },
        { t: '重发与冻结', d: '忙期冻结计时器，空闲再递减', at: 7 },
        { t: '最短帧长', d: '64 B 保证冲突在发完前被检出', at: 8 },
        { t: '长帧与放弃', d: '1518 B 上限、16 次失败丢弃', at: 10 }
      ],
      desc: '早期以太网用一条同轴电缆（或集线器）把所有站点连在同一个冲突域里。CSMA/CD 的规则是：先听后发、边发边听、冲突停发、随机重发。为保证最远端的冲突能在帧发完之前传回发送方，10 Mbps 以太网把争用期定为 512 bit = 51.2 μs，对应最小帧长 64 字节（数据不足 46 字节由 MAC 补 PAD）；冲突后按二进制指数退避 k = min(重传次数, 10)、r 从 [0, 2ᵏ−1] 个时隙中随机选取，最多重传 16 次。',
      tip: '最短帧长不是拍脑袋定的：它等于「往返传播时延 × 发送速率」，即 512 bit = 64 B。帧太短会出现迟到冲突（late collision），发送方误判成功而不重传。BEB 让冲突越频繁、退避窗口越大，从而自适应负载。今天的交换式全双工以太网每条链路只有两个设备、收发分开，已不再需要 CSMA/CD，但 64~1518 B 帧长、96 bit IFG 等规则被完整保留下来。',
      stats: [
        { k: '介质访问', v: 'CSMA/CD · 半双工' },
        { k: '争用期', v: '512 bit = 51.2 μs' },
        { k: '最短帧长', v: '64 B（数据 ≥ 46 B）' },
        { k: '强化冲突', v: '32 bit Jam' },
        { k: '退避窗口', v: 'r ∈ [0, 2ᵏ−1] · k ≤ 10' },
        { k: '最大重传', v: '16 次后丢弃' },
        { k: '帧间隙', v: '96 bit = 9.6 μs' }
      ],
      packets: M.map((m, i) => P({
        t: m.t, src: i === 0 ? '—' : ({ ha: MAC_A, hb: MAC_B, hc: MAC_C, hd: MAC_D }[m.from] || MAC_A),
        dst: ({ ha: MAC_B, hb: MAC_A, hc: MAC_D, hd: MAC_A }[m.from] || MAC_BCAST),
        proto: m.proto, kind: m.kind, phase: m.phase, from: m.from, to: m.to,
        title: m.title, info: m.info, note: m.note, osi: [2], layer: 2,
        displaySize: m.displaySize, truncated: m.truncated, layers: m.layers
      })),
      lab: { tab: 'cdLabView' }
    });
  })();

  /* ============================================================
     22 · IEEE 802.11 无线局域网（CSMA/CA 实验）
     共享仿真内核：DIFS → 竞争窗口退避 → (RTS/CTS + NAV) →
     DATA → SIFS → ACK；隐藏节点场景演示为什么需要 RTS/CTS。
     ============================================================ */
  const WF_LAB_DEFAULT = { stations: 2, rts: 'off', hidden: 'off', cw: 'cw15' };
  const WF_DIFS = 50, WF_SIFS = 10, WF_SLOT = 9, WF_ACK = 32, WF_NAV = 300;

  function simulateWifi(cfg) {
    const o = Object.assign({}, WF_LAB_DEFAULT, cfg || {});
    const rtsOn = o.rts === 'on', hiddenOn = o.hidden === 'on';
    const cwMax = o.cw === 'cw63' ? 63 : 15;
    const slots = o.cw === 'cw63' ? 8 : 4;   // 图中按 4 / 8 槽示意真实 CW 0~15 / 0~63
    const names = o.stations === 3 ? ['STA1', 'STA2', 'STA3'] : ['STA1', 'STA2'];
    const out = [], st = {};
    names.forEach(n => { st[n] = { s: 'difs', remain: 0, pick: 0, nav: 0, frozen: false, attempt: 0, done: false }; });
    st.AP = { s: 'idle', remain: 0, pick: 0, nav: 0, frozen: false, attempt: 0, done: false };
    let t = 0, collisions = 0, successes = 0, cw = cwMax;

    const r1 = o.cw === 'cw63' ? 2 : 1;
    const rOf = i => i === 0 ? r1 : r1 + 1 + i;
    const snap = () => { const q = {}; Object.keys(st).forEach(k => { q[k] = Object.assign({}, st[k]); }); return q; };
    const push = (phase, medium, extra) => out.push(Object.assign({
      r: out.length + 1, t: +t.toFixed(1), phase: phase, medium: medium, st: snap(),
      names: names.slice(), rtsOn: rtsOn, hiddenOn: hiddenOn, cw: cw, cwMax: cwMax, slots: slots,
      difs: WF_DIFS, sifs: WF_SIFS, slotUs: WF_SLOT, navUs: WF_NAV,
      collisions: collisions, successes: successes, p: 13
    }, extra || {}));

    // ① DIFS：介质空闲后所有站点先等一个分布式帧间间隔
    push('difs', 'idle', { p: 11,
      zh: 't = 0 μs · 介质空闲，' + names.join(' / ') + ' 都有数据帧要发。802.11 用 CSMA/CA：先等 DIFS = 50 μs（比 SIFS 长），再进入竞争窗口。无线网卡无法边发边听（自身发射功率会淹没接收机），所以只能「发之前避开冲突」，不能像以太网那样「边发边检测」。',
      en: 't = 0 μs · The medium is idle and ' + names.join(' / ') + ' all have frames. 802.11 uses CSMA/CA: wait DIFS = 50 μs (longer than SIFS), then enter a contention window. A radio cannot transmit and listen at the same time, so it must avoid collisions before sending instead of detecting them during transmission.' });

    // ② 随机退避：从 [0, CW] 里取一个时隙数
    t = WF_DIFS;
    names.forEach((n, i) => { st[n].pick = rOf(i); st[n].remain = st[n].pick; st[n].s = 'backoff'; });
    push('backoff', 'idle', { p: 11,
      zh: '退避开始 · CW = 0~' + cwMax + '（图中等比缩为 ' + slots + ' 个时隙，1 槽 = ' + WF_SLOT + ' μs）：' +
        names.map(n => n + ' 取 r=' + st[n].pick).join('，') + '。每过一个空闲时隙计数器减 1，先归零者获得信道；这正是 CA（冲突避免）与 CD（冲突检测）的根本差别。',
      en: 'Backoff starts · CW = 0–' + cwMax + ' (shown as ' + slots + ' slots of ' + WF_SLOT + ' μs each): ' +
        names.map(n => n + ' picks r=' + st[n].pick).join(', ') + '. Each idle slot decrements the counter; the first to reach zero wins the medium — the core difference between CA and CD.' });

    for (let k = 0; k < r1; k++) {
      names.forEach(n => { if (!st[n].done && st[n].remain > 0) st[n].remain--; });
      t += WF_SLOT;
      push('slot', 'idle', { p: 11,
        zh: '空闲时隙 ' + (k + 1) + '（t = ' + t.toFixed(1) + ' μs）· ' +
          names.map(n => n + ' 剩 ' + st[n].remain).join('，') + '。若此时听到别人开始发送，计数器会冻结，等下次 DIFS 后接着倒数。',
        en: 'Idle slot ' + (k + 1) + ' (t = ' + t.toFixed(1) + ' μs) · ' +
          names.map(n => n + ' left ' + st[n].remain).join(', ') + '. If a station hears another transmission it freezes its counter and resumes after the next DIFS.' });
    }

    const emitSuccess = (w, useRts) => {
      st[w].s = useRts ? 'rts' : 'tx';
      names.forEach(n => { if (n !== w && !st[n].done) st[n].s = 'frozen'; });
      if (useRts) {
        push('rts', 'busy', { p: 11,
          zh: w + ' 先发 20 B 的 RTS，Duration = ' + WF_NAV + ' μs，预约「CTS + DATA + SIFS + ACK」整段交换。RTS 很短，即使撞车代价也远小于撞掉一个长数据帧。',
          en: w + ' sends a 20 B RTS with Duration = ' + WF_NAV + ' μs, reserving the whole CTS + DATA + SIFS + ACK exchange. An RTS is short, so a collision costs far less than losing a long data frame.' });
        t += 20;
        st.AP.s = 'cts';
        names.forEach(n => { if (n !== w && !st[n].done) { st[n].s = 'nav'; st[n].nav = WF_NAV - 20; } });
        push('cts', 'nav', { p: 12,
          zh: 'AP 回 14 B 的 CTS（SIFS 后）。' +
            (hiddenOn ? '关键点：隐藏节点听不到 ' + w + '，但一定能听到 AP，于是也把 CTS 里的 Duration 写进 NAV 并保持静默 —— 虚拟载波侦听解决了隐藏节点问题。'
              : '范围内所有站点把 Duration 写入 NAV，即使物理上没听到数据帧也会静默，这就是「虚拟载波侦听」。'),
          en: 'The AP replies with a 14 B CTS after SIFS. ' +
            (hiddenOn ? 'Crucially, the hidden station cannot hear ' + w + ' but can hear the AP, so it copies the CTS Duration into its NAV and stays quiet — virtual carrier sensing solves the hidden-node problem.'
              : 'Every station in range copies Duration into its NAV and stays quiet even if it cannot physically hear the data frame — this is virtual carrier sensing.') });
        t += 10;
      }
      st[w].s = 'data'; st.AP.s = 'rx';
      push('data', 'busy', { p: 13,
        zh: w + ' 发送 DATA 帧（To DS=1，三个地址分别是 BSSID / SA / DA）。' +
          (useRts ? '其它站点的 NAV 尚未归零，全程不发帧。' : '其它站点侦听到载波，冻结退避计数器。'),
        en: w + ' sends the DATA frame (To DS = 1: the three addresses are BSSID / SA / DA). ' +
          (useRts ? 'Other stations keep silent because their NAV has not expired.' : 'Other stations hear the carrier and freeze their backoff counters.') });
      t += 150;
      st[w].s = 'wait'; st.AP.s = 'ack';
      t += WF_SIFS;
      push('sifs', 'busy', { p: 14,
        zh: 't + SIFS = 10 μs · 接收端只等最短的 SIFS 就回 ACK，其它帧必须等更长的 DIFS，因此 ACK 天然拥有最高优先级，不会被第三方插队。',
        en: 't + SIFS = 10 μs · The receiver waits only the shortest interframe space before ACKing. Every other frame must wait the longer DIFS, so ACKs always win the medium.' });
      t += WF_ACK;
      st[w].s = 'success'; st[w].done = true; successes++; st.AP.s = 'idle';
      names.forEach(n => {
        if (!st[n].done && (st[n].s === 'nav' || st[n].s === 'frozen')) { st[n].nav = 0; st[n].s = 'backoff'; }
      });
      push('success', 'idle', { p: 14,
        zh: 'AP 在 SIFS 后回 14 B ACK，' + w + ' 收到才算发送成功。收到 ACK 后 CW 重置为 CWmin；若 ACK 超时未到，就认为帧丢失，把 CW 翻倍（' + cw + ' → ' + (2 * cw + 1) + '）后重新争用。',
        en: 'The AP returns a 14 B ACK after SIFS; ' + w + ' counts the frame as delivered only when the ACK arrives. CW resets to CWmin; a missing ACK means loss, so CW doubles (' + cw + ' → ' + (2 * cw + 1) + ') before retrying.' });
    };

    // ③ 无 RTS/CTS 且存在隐藏节点 → AP 处冲突
    if (hiddenOn && !rtsOn) {
      st[names[0]].s = 'tx'; st[names[1]].s = 'tx';
      push('tx', 'busy', { p: 13,
        zh: names[0] + ' 的退避先归零并开始发 DATA。' + names[1] + ' 是隐藏节点：它听不到 ' + names[0] + ' 的载波，误以为信道空闲，也在此时开始发送。',
        en: names[0] + ' wins the backoff and starts DATA. ' + names[1] + ' is a hidden node: it cannot hear ' + names[0] + '’s carrier, assumes the channel is idle and also starts transmitting.' });
      t += WF_SIFS;
      collisions++;
      push('collision', 'collision', { p: 15,
        zh: 'AP 同时收到两个叠加的信号，两个帧的 FCS 都错，一个 ACK 也发不出来。注意：两个发送方自己都「听不到」这次冲突 —— 这正是无线网必须靠 ACK 间接判断成败的原因。',
        en: 'The AP receives two overlapping signals; both FCS checks fail and no ACK can be sent. Neither sender can hear the collision — this is exactly why Wi-Fi must infer success from an ACK.' });
      t += 150;
      push('timeout', 'idle', { p: 15,
        zh: 'ACK 超时：双方都没等到 ACK，判定发送失败，把 CW 翻倍后重新随机退避、重传（帧首部 Retry 位置 1、序列号不变）。隐藏节点场景下重复退避仍可能再次相撞，信道利用率显著下降。',
        en: 'ACK timeout: neither station receives an ACK, so both double CW, back off again and retransmit (Retry = 1, same sequence number). With a hidden node, repeated retries may collide again and throughput drops sharply.' });
      cw = 2 * cw + 1;
      push('retry', 'idle', { p: 15,
        zh: 'CW 由 ' + cwMax + ' 增大到 ' + cw + '（真实 802.11 按 15 → 31 → 63 → … → 1023 翻倍）。但重传只能缓解拥塞，无法消除「互相听不见」这个物理事实。',
        en: 'CW grows from ' + cwMax + ' to ' + cw + ' (real 802.11 doubles 15 → 31 → 63 → … → 1023). Retransmission helps with congestion but cannot fix the fact that the two stations cannot hear each other.' });
      push('done', 'idle', { p: 15,
        zh: '结论：把「RTS/CTS」切到开启再看一次 —— 短 RTS 由 AP 的 CTS 应答，隐藏节点虽听不到发送方，却能听到 AP，根据 CTS 的 NAV 主动静默，冲突因此被避免。这就是 CSMA/CA 用「预约 + 确认」替代 CSMA/CD「边发边听」的完整逻辑。',
        en: 'Conclusion: switch RTS/CTS on and replay — the AP answers the short RTS with a CTS, and the hidden node (which hears the AP even though it cannot hear the sender) sets its NAV from the CTS and stays quiet. This is how CSMA/CA replaces "listen while sending" with reservation plus acknowledgement.' });
      return out;
    }

    emitSuccess(names[0], rtsOn);

    // ④ 第二站：NAV / 冻结结束后继续争用
    t += WF_DIFS;
    st[names[1]].s = 'backoff';
    push('difs', 'idle', { p: 13,
      zh: '介质再次空闲，' + names[1] + (o.stations === 3 ? ' / ' + names[2] : '') +
        ' 等 DIFS 后从冻结的计数器继续倒数（不清零），准备发送自己的帧。',
      en: 'The medium is idle again; ' + names[1] + (o.stations === 3 ? ' / ' + names[2] : '') +
        ' waits DIFS and resumes its frozen backoff counter (not reset) before sending.' });
    t += WF_SLOT;
    push('slot', 'idle', { p: 13,
      zh: '空闲时隙（t = ' + t.toFixed(1) + ' μs）· ' + names[1] + ' 退避归零，获得发送权。',
      en: 'Idle slot (t = ' + t.toFixed(1) + ' μs) · ' + names[1] + ' reaches zero and wins the medium.' });
    emitSuccess(names[1], rtsOn);

    push('done', 'idle', { p: 14,
      zh: '本轮结束：' + successes + ' 帧成功、' + collisions + ' 次冲突。802.11 DCF 的顺序是 DIFS → 随机退避 → (可选 RTS/CTS + NAV) → DATA → SIFS → ACK；与以太网的「先听后发、边发边听、冲突停发、指数退避」形成对照：无线网靠「发前避让 + 收后确认」保证可靠。',
      en: 'Run complete: ' + successes + ' frame(s) delivered, ' + collisions + ' collision(s). The 802.11 DCF order is DIFS → random backoff → (optional RTS/CTS + NAV) → DATA → SIFS → ACK. Compare with Ethernet: Wi-Fi relies on avoiding collisions before sending and acknowledging afterwards.' });
    return out;
  }

  (function () {
    const B = MAC_AP;
    const mgmt = (fc, seq, a1, a2, a3, a1n, a2n, a3n, body, extra) => P(Object.assign({
      t: 0, src: a2, dst: a1, proto: '802.11', osi: [2], layer: 2,
      from: a2 === MAC_STA || a2 === MAC_STA2 ? 'sta' : 'ap',
      to: a1 === WLAN_BCAST ? 'sta2' : (a1 === MAC_STA || a1 === MAC_STA2 ? 'sta' : 'ap'),
      layers: wlanFrame(WLAN_HDR({ fc: fc, seq: seq, a1: a1, a2: a2, a3: a3, a1n: a1n, a2n: a2n, a3n: a3n }), body)
    }, extra || {}));
    const ctrl = (fc, dur, ra, ta, extra) => P(Object.assign({
      t: 0, src: ta || MAC_AP, dst: ra, proto: '802.11', osi: [2], layer: 2,
      from: ta ? 'sta' : 'ap', to: ta ? 'ap' : 'sta',
      layers: wlanFrame(WLAN_CTRL({ fc: fc, dur: dur, ra: ra, ta: ta }))
    }, extra || {}));
    const eapolHdr = (fromAp, step, seq) => WLAN_HDR({
      fc: 'data', fl: 0x00, seq: seq, dur: 44,
      a1: fromAp ? MAC_STA : MAC_AP, a2: fromAp ? MAC_AP : MAC_STA, a3: MAC_AP,
      a1n: fromAp ? 'RA = STA' : 'RA = BSSID', a2n: fromAp ? 'TA = BSSID' : 'TA = SA',
      a3n: 'BSSID'
    });
    const eapol = (fromAp, step, seq, extra) => P(Object.assign({
      t: 0, src: fromAp ? MAC_AP : MAC_STA, dst: fromAp ? MAC_STA : MAC_AP,
      proto: 'EAPOL', osi: [2], layer: 2, from: fromAp ? 'ap' : 'sta', to: fromAp ? 'sta' : 'ap',
      layers: wlanFrame(eapolHdr(fromAp, step, seq), [WLAN_EAPOL_BODY(step)])
    }, extra || {}));
    const dataHdr = retry => WLAN_HDR({
      fc: retry ? 'dataRetry' : 'data', seq: 42, dur: 44,
      a1: MAC_AP, a2: MAC_STA, a3: MAC_DS,
      a1n: 'RA = BSSID (To DS)', a2n: 'TA = SA', a3n: 'DA (有线侧)'
    });

    const M = [
      mgmt('beacon', 10, WLAN_BCAST, B, B, 'RA (广播)', 'TA = BSSID', 'BSSID', [WLAN_BEACON_BODY()], {
        t: 0.000, proto: '802.11', kind: 'beacon', phase: '扫描与发现', title: 'Beacon · AP 周期广播',
        info: 'SSID=ZJGSU-Lab · CH 6 · 100 TU · WPA2/CCMP',
        note: 'AP 每 102.4 ms 广播一次 Beacon，携带 SSID、信道、速率集与 RSN 安全套件。它是广播管理帧，不需要 ACK；站点靠它被动发现网络并完成时钟同步。'
      }),
      mgmt('probeReq', 11, WLAN_BCAST, MAC_STA, WLAN_BCAST, 'RA (广播)', 'TA = SA', 'BSSID', [WLAN_PROBE_REQ_BODY()], {
        t: 0.014, proto: '802.11', kind: 'probe', phase: '扫描与发现', title: 'Probe Request · 主动扫描',
        info: 'Wildcard SSID · 请求范围内所有 AP 应答',
        note: '客户端不想等 Beacon 时主动发 Probe Request。SSID 长度为 0 表示通配，范围内所有 AP 都会回 Probe Response；这也意味着终端会暴露曾经连接过的网络名。'
      }),
      mgmt('probeResp', 12, MAC_STA, B, B, 'RA = STA', 'TA = BSSID', 'BSSID', [WLAN_BEACON_BODY()], {
        t: 0.016, proto: '802.11', kind: 'probe', phase: '扫描与发现', title: 'Probe Response · AP 应答',
        info: 'SSID=ZJGSU-Lab · CH 6 · RSSI -48 dBm',
        note: 'Probe Response 的帧体与 Beacon 基本一致，只是单播发给提问的站点，并且必须等 ACK。站点据此比较信号强度，决定要加入哪个 BSS。'
      }),
      mgmt('auth', 13, B, MAC_STA, B, 'RA = BSSID', 'TA = SA', 'BSSID', [WLAN_AUTH_BODY(1, 0)], {
        t: 0.021, proto: '802.11', kind: 'auth', phase: '认证与关联', title: 'Authentication · 第 1 步',
        info: 'Open System · Transaction Seq 1',
        note: '802.11 状态机的第一步：开放系统认证实际上不做身份校验，只是走完「请求 → 应答」两步。真正的安全由后面的 WPA2 四次握手完成。'
      }),
      mgmt('auth', 14, MAC_STA, B, B, 'RA = STA', 'TA = BSSID', 'BSSID', [WLAN_AUTH_BODY(2, 0)], {
        t: 0.023, proto: '802.11', kind: 'auth', phase: '认证与关联', title: 'Authentication · 第 2 步成功',
        info: 'Open System · Seq 2 · Status 0 (Success)',
        note: '状态码 0 表示认证通过，站点进入「已认证、未关联」状态，接下来才能发 Association Request。'
      }),
      mgmt('assocReq', 15, B, MAC_STA, B, 'RA = BSSID', 'TA = SA', 'BSSID', [WLAN_ASSOC_BODY(false)], {
        t: 0.027, proto: '802.11', kind: 'assoc', phase: '认证与关联', title: 'Association Request',
        info: 'SSID=ZJGSU-Lab · Listen Interval 10 · 支持速率',
        note: '站点声明自己的能力、SSID 与省电唤醒周期，请求加入 BSS。AP 会检查速率集、能力位与鉴权状态是否匹配。'
      }),
      mgmt('assocResp', 16, MAC_STA, B, B, 'RA = STA', 'TA = BSSID', 'BSSID', [WLAN_ASSOC_BODY(true, 1)], {
        t: 0.029, proto: '802.11', kind: 'assoc', phase: '认证与关联', title: 'Association Response · AID=1',
        info: 'Status 0 (Success) · AID 1 · 已关联',
        note: 'AP 分配关联 ID（AID）并确认能力集合，站点进入「已关联」状态。AID 用于后面省电模式的 TIM 位图索引。'
      }),
      eapol(true, 1, 17, { t: 0.034, kind: 'eapol', phase: 'WPA2 四次握手', title: 'EAPOL-Key 1/4 · AP → STA',
        info: 'ANonce · PMK 已知，等待 STA 生成 SNonce',
        note: 'AP 先发一个随机数 ANonce。双方各自持有预共享密钥派生的 PMK，但此时还没有会话密钥 PTK。' }),
      eapol(false, 2, 18, { t: 0.036, kind: 'eapol', phase: 'WPA2 四次握手', title: 'EAPOL-Key 2/4 · STA → AP',
        info: 'SNonce + MIC · 双方据 ANonce/SNonce/MAC 派生 PTK',
        note: '站点生成 SNonce，用 PMK + 两个 Nonce + 双方 MAC 派生 PTK，并附上 MIC 让 AP 验证自己确实持有 PMK。' }),
      eapol(true, 3, 19, { t: 0.038, kind: 'eapol', phase: 'WPA2 四次握手', title: 'EAPOL-Key 3/4 · AP → STA',
        info: 'GTK + MIC + Install · 下发组播密钥',
        note: 'AP 校验 MIC 通过后下发组密钥 GTK，并置 Install 位，通知站点安装 PTK / GTK。' }),
      eapol(false, 4, 20, { t: 0.040, kind: 'eapol', phase: 'WPA2 四次握手', title: 'EAPOL-Key 4/4 · STA → AP',
        info: 'Final ACK · 双方安装密钥，后续数据加密',
        note: '站点回最后一条确认，握手完成。此后所有单播数据帧的 Protected 位置 1，帧体用 CCMP 加密。' }),
      ctrl('rts', 300, B, MAC_STA, { t: 0.052, kind: 'rts', phase: '信道争用与确认', title: 'RTS · 请求发送',
        info: 'RA=BSSID · TA=STA · Duration 300 μs (NAV)',
        note: '可选的 RTS/CTS 握手：发送方先用一个 20 B 短帧预约信道，Duration 覆盖 CTS + DATA + ACK 整段。隐藏节点听不到发送方，但能听到 AP 回的 CTS，因此会按 NAV 静默。' }),
      ctrl('cts', 260, MAC_STA, null, { t: 0.054, kind: 'cts', phase: '信道争用与确认', title: 'CTS · 允许发送',
        info: 'RA=STA · Duration 260 μs · 周围站点设置 NAV',
        note: 'AP 在 SIFS 后回 14 B 的 CTS，广播式地告诉覆盖范围内所有站点「接下来 260 μs 别发」。这就是虚拟载波侦听（NAV）。' }),
      P({ t: 0.058, src: MAC_STA, dst: MAC_AP, proto: '802.11', kind: 'wdata', phase: '信道争用与确认',
        title: 'DATA · STA → AP (To DS=1)', info: 'Seq 42 · To DS=1 · LLC/SNAP + IPv4 + ICMP',
        note: 'To DS=1 时三个地址的语义是：Addr1 = BSSID（AP 的无线口）、Addr2 = 源站点 SA、Addr3 = 真正的目的地址 DA。802.11 没有 EtherType，靠 8 字节 LLC/SNAP 指明帧体是 IPv4。',
        osi: [2], layer: 2, from: 'sta', to: 'ap',
        layers: wlanFrame(dataHdr(false), WLAN_DATA_BODY(1)) }),
      ctrl('ack', 0, MAC_STA, null, { t: 0.059, kind: 'wack', phase: '信道争用与确认', title: 'ACK · 确认收到',
        info: 'RA=STA · SIFS 10 μs 后回复 · Duration 0',
        note: '接收端只在 SIFS（10 μs）后回一个 14 B 的 ACK。收到 ACK 才算发送成功；没有 ACK 就按 CW 翻倍规则重传。这是无线网与以太网最本质的差别。' }),
      P({ t: 0.065, src: MAC_STA, dst: MAC_AP, proto: '802.11', kind: 'wretry', phase: '重传机制',
        title: 'DATA 重传 · Retry=1', info: 'Seq 42（不变）· Retry=1 · CW 翻倍后重发',
        note: '若上一条 ACK 丢失，发送方超时后把竞争窗口翻倍再争用并重发：序列号保持 42 不变、Retry 置 1，接收端据此去重。重传次数与分片/聚合机制共同决定无线链路的吞吐。',
        osi: [2], layer: 2, from: 'sta', to: 'ap',
        layers: wlanFrame(dataHdr(true), WLAN_DATA_BODY(1)) })
    ];

    def('wifi', {
      name: '802.11 Wi-Fi', title: '无线接入 · CSMA/CA · 四次握手', cat: 'base',
      sub: 'Beacon / 认证关联 / RTS-CTS / ACK', osi: 2, layer: 2,
      nodes: ['sta', 'sta2', 'ap', 'ds'],
      seqNodes: ['sta', 'sta2', 'ap', 'ds'],
      links: [['sta', 'ap'], ['sta2', 'ap'], ['ap', 'ds']],
      wirelessLinks: [['sta', 'ap'], ['sta2', 'ap']],
      pos: { sta: { x: 200, y: 355 }, sta2: { x: 200, y: 120 }, ap: { x: 500, y: 235 }, ds: { x: 840, y: 235 } },
      labels: {
        sta: { name: '无线站点 STA1', en: 'Station STA1', ip: MAC_STA },
        sta2: { name: '站点 STA2（隐藏节点）', en: 'Station STA2 (hidden)', ip: MAC_STA2 },
        ap: { name: '无线接入点 AP', en: 'Access Point', ip: 'BSSID ' + MAC_AP },
        ds: { name: '有线网络 / DS', en: 'Wired network / DS', ip: 'SSID ' + WLAN_SSID + ' · CH ' + WLAN_CH }
      },
      steps: [
        { t: '扫描发现', d: 'Beacon 广播或 Probe 主动探测', at: 1 },
        { t: '认证与关联', d: 'Open System 两步 + Association', at: 4 },
        { t: '四次握手', d: 'WPA2 派生 PTK / GTK', at: 8 },
        { t: '信道争用', d: 'DIFS + 随机退避避免冲突', at: 12 },
        { t: 'RTS / CTS', d: 'NAV 虚拟载波侦听解决隐藏节点', at: 12 },
        { t: 'DATA / ACK', d: 'SIFS 后回 ACK 才算成功', at: 14 },
        { t: '重传', d: 'ACK 超时则 CW 翻倍再争用', at: 16 }
      ],
      desc: '802.11 把有线以太网换成共享的无线电信道：网卡无法一边发射一边监听，因此用 CSMA/CA（载波侦听多路访问 / 冲突避免）代替 CSMA/CD。站点先听 DIFS，再从竞争窗口 [0, CW] 里随机挑时隙倒数；发送后用 SIFS 优先回 ACK 来确认成功，收不到 ACK 就把 CW 翻倍重传。可选的 RTS/CTS 用 Duration 字段设置 NAV，让听不见发送方、却听得见 AP 的隐藏节点也保持静默。接入流程则是扫描 → 认证 → 关联 → WPA2 四次握手 → 加密数据。',
      tip: '与以太网对照着看：以太网「边发边听」，冲突后靠 64 B 最短帧保证及时检出并用 BEB 退避；802.11 只能「发前避让」，靠随机退避 + ACK + NAV 间接判断成败。802.11 MAC 首部 24 B 用三个地址（RA / TA / BSSID）配合 To DS / From DS 位表达源与目的，控制帧（RTS 20 B、CTS / ACK 14 B）更短，以缩短争用开销。',
      stats: [
        { k: '协议标准', v: 'IEEE 802.11 · DCF' },
        { k: '介质访问', v: 'CSMA/CA · 半双工' },
        { k: '帧间隔', v: 'DIFS 50 / SIFS 10 / Slot 9 μs' },
        { k: '竞争窗口', v: 'CW 15 → 31 → … → 1023' },
        { k: '确认机制', v: '逐帧 ACK（以太网无链路层重传）' },
        { k: '地址字段', v: '3 × MAC + To/From DS' },
        { k: '安全机制', v: 'WPA2 四次握手 + CCMP' },
        { k: '隐藏节点', v: 'RTS/CTS + NAV 虚拟载波侦听' }
      ],
      packets: M,
      lab: { tab: 'wfLabView' }
    });
  })();

  /* ---------- 元信息 ---------- */
  const ORDER = ['http', 'https', 'dns', 'tcp', 'udp', 'ip', 'arp', 'icmp', 'dhcp', 'tls', 'websocket', 'smtp', 'ftp', 'quic', 'rip', 'ospf', 'bgp', 'tcpcc', 'switch', 'stp', 'csma', 'wifi'];
  const CATEGORIES = [
    { id: 'all', zh: '全部', en: 'All' },
    { id: 'base', zh: '基础', en: 'Core' },
    { id: 'app', zh: '应用', en: 'App' },
    { id: 'sec', zh: '安全', en: 'Secure' }
  ];
  const KIND_COLORS = {
    dns: '#2f6fd0', tcp: '#0f9c9c', request: '#e8a317', response: '#7c4dd6',
    ack: '#a5b0c7', tls: '#d24b6a', routing: '#2f8fd0', update: '#8a5cd6',
    open: '#e08a2e', keepalive: '#3aa87a', notify: '#d0483f',
    ccdata: '#2f6fd0', dupack: '#e8a317', retrans: '#d0483f',
    flood: '#e8a317', forward: '#2f6fd0', filter: '#9aa6c0', bcast: '#7c4dd6', learn: '#0f9c9c',
    bpdu: '#1f8a9c', tcn: '#d0483f', tc: '#e08a2e', topo: '#8a93ad', swdata: '#2f9c6a',
    sense: '#8a93ad', tx: '#2f6fd0', collision: '#d0483f', jam: '#e08a2e',
    backoff: '#7c4dd6', success: '#2f9c6a', runt: '#e8a317', late: '#d24b6a', long: '#0f9c9c',
    beacon: '#2f8fd0', probe: '#7c4dd6', auth: '#e08a2e', assoc: '#12a08f', eapol: '#d24b6a',
    rts: '#8a5cd6', cts: '#0f9c9c', wdata: '#2f6fd0', wack: '#2f9c6a', wretry: '#d0483f'
  };
  const KIND_ZH = { dns: 'DNS', tcp: 'TCP', request: '请求', response: '响应', ack: '纯 ACK', tls: 'TLS',
    routing: '路由报文', update: '路由更新', open: 'OPEN 协商', keepalive: '保活', notify: '会话通知',
    ccdata: '数据段', dupack: '重复 ACK', retrans: '快重传',
    flood: '未知单播泛洪', forward: '已知单播转发', filter: '同端口过滤', bcast: '广播帧', learn: '表项更新',
    bpdu: '配置 BPDU', tcn: 'TCN BPDU', tc: 'TC 置位', topo: '拓扑事件', swdata: '用户数据帧',
    sense: '载波侦听', tx: '发送帧', collision: '冲突碎片', jam: 'Jam 信号', backoff: '退避后重发',
    success: '发送成功', runt: '过短帧', late: '迟到冲突', long: '长帧对照',
    beacon: 'Beacon', probe: 'Probe', auth: 'Authentication', assoc: 'Association',
    eapol: 'EAPOL-Key', rts: 'RTS', cts: 'CTS', wdata: 'DATA', wack: 'ACK', wretry: 'DATA 重传' };
  const KIND_EN = { dns: 'DNS', tcp: 'TCP', request: 'Request', response: 'Response', ack: 'Bare ACK', tls: 'TLS',
    routing: 'Routing', update: 'Route update', open: 'BGP OPEN', keepalive: 'Keepalive', notify: 'Notification',
    ccdata: 'Data segment', dupack: 'Dup ACK', retrans: 'Retransmit',
    flood: 'Unknown-unicast flood', forward: 'Known unicast', filter: 'Filtered', bcast: 'Broadcast', learn: 'MAC move',
    bpdu: 'Config BPDU', tcn: 'TCN BPDU', tc: 'TC flag', topo: 'Topology event', swdata: 'User frame',
    sense: 'Carrier sense', tx: 'Frame sent', collision: 'Collision fragment', jam: 'Jam signal',
    backoff: 'Backoff retry', success: 'Delivered', runt: 'Runt frame', late: 'Late collision', long: 'Long frame',
    beacon: 'Beacon', probe: 'Probe', auth: 'Authentication', assoc: 'Association',
    eapol: 'EAPOL-Key', rts: 'RTS', cts: 'CTS', wdata: 'DATA', wack: 'ACK', wretry: 'DATA retry' };
  const OSI_NAMES = ['物理层', '数据链路层', '网络层', '传输层', '会话层', '表示层', '应用层'];

  global.ProtocolData = {
    scenarios: S, order: ORDER, categories: CATEGORIES,
    kindColors: KIND_COLORS, kindZh: KIND_ZH, kindEn: KIND_EN,
    osiNames: OSI_NAMES, colors: C, util: U,
    labSimulate: simulateCC, labDefault: LAB_DEFAULT,
    swSimulate: simulateSwitch, swDefault: SW_LAB_DEFAULT, swScripts: SW_SCRIPTS,
    swHosts: SW_HOSTS, swMac: SW_MAC, swPort: SW_PORT,
    stpSimulate: simulateSTP, stpDefault: STP_LAB_DEFAULT,
    stpSwitches: STP_SW, stpLinks: STP_LINKS,
    cdSimulate: simulateCSMA, cdDefault: CD_LAB_DEFAULT, cdFrameInfo: CD_FRAME_INFO,
    wfSimulate: simulateWifi, wfDefault: WF_LAB_DEFAULT,
    wlanSsid: WLAN_SSID, wlanChannel: WLAN_CH,
    ipClient: IP_CLIENT, ipDns: IP_DNS, ipWeb: IP_WEB
  };
})(window);
