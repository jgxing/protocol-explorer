/* ============================================================
   app.js — Protocol Explorer 交互逻辑
   拓扑动画 / 时序图 / 抓包列表 / 分层报文解析器
   ============================================================ */
(function () {
  'use strict';

  const D = window.ProtocolData;
  const $ = id => document.getElementById(id);
  const esc = s => String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const rgba = (hex, a) => {
    const n = parseInt(hex.slice(1), 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  };
  const fmtTime = t => t.toFixed(3) + 's';
  const sizeOf = p => p.displaySize || (p.size + ' B');
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  const state = {
    scenario: 'http', category: 'all', view: 'network',
    index: -1, playing: false, speed: 1, timer: null, raf: null,
    lang: 'zh', theme: 'light', finished: new Set(),
    selectedField: null, lockedField: null, dlgIndex: 0
  };

  /* ---------------- i18n ---------------- */
  const I18N = {
    zh: {
      tagline: '了解互联网如何运作', learning: '正在学习', layer: '应用层', progress: '学习进度',
      inProgress: '进行中', protocols: '互联网协议', sideTip: '点击协议切换课程，展开可查看学习步骤',
      networkView: '网络', timingView: '时序', visualHint: '点击「播放」可重新演示完整交互过程',
      packets: '数据包', play: '播放', pause: '暂停', reset: '重置',
      colNo: '序号', colTime: '时间', colSrc: '源地址', colDst: '目的地址', colProto: '协议',
      colInfo: '信息', colSize: '大小', summary: '课程总结', courseDone: '课程完成',
      tipTitle: '知识点', fieldPane: '协议字段', fieldHint: '悬停字段可高亮右侧字节',
      hexPane: '原始字节流', hexTip: '点击或悬停字节，可反查所属字段',
      hexNote: '灰显部分为无法打印的二进制字节',
      dlgFoot: '每次高亮的字节范围都不相同；该视图不显示加密载荷、校验和与填充内容的展开细节。',
      waiting: '等待开始', running: '进行中', statusDone: '课程完成',
      currentPacket: '当前报文', packetsTotal: '报文总数', elapsed: '已用时间',
      doneHint: '全部报文已送达，点击「播放」可重新演示',
      legend: '点击任意一行，展开该报文的分层结构',
      nodeClient: '客户端', nodeGateway: '网关 / 路由器', nodeDns: 'DNS 服务器',
      nodeDhcp: 'DHCP 服务器', nodeWeb: 'Web 服务器', nodeTarget: '目标主机',
      nodeMail: '邮件服务器', nodeFtp: 'FTP 服务器',
      nodeR1: '路由器 R1', nodeR3: '路由器 R3',
      seqTitle: '协议时序 · 纵向为时间', detailTitle: '展开报文',
      statAll: '全部', statBase: '基础', statApp: '应用', statSec: '安全',
      schoolShort: '浙江工商大学', authorShort: '邢建国',
      labView: '拥塞实验', labTitle: '拥塞窗口实验台',
      labNote: '下方抓包表记录默认参数（Reno / ssthresh=8 / 3 个重复 ACK）下的一次过程；此处改参数会重算曲线，抓包表保持默认记录。',
      labAlgo: '拥塞算法', labSsthresh: '初始阈值', labLoss: '丢包信号', labLossRound: '丢包发生在',
      algoReno: 'Reno · 快恢复', algoTahoe: 'Tahoe · 回慢启动',
      lossDup: '3 个重复 ACK', lossTimeout: 'RTO 超时',
      labPlay: '播放', labPause: '暂停', labStep: '单步', labBack: '后退', labReset: '重置',
      labRound: '当前 RTT', labCwnd: '拥塞窗口 cwnd', labSsthNow: '慢启动阈值', labPhase: '所处阶段',
      labSent: '本轮发送', labTotal: '累计发送', labRate: '估算吞吐',
      phaseSS: '慢启动', phaseCA: '拥塞避免', phaseFR: '快恢复 / 重传',
      phaseTO: 'RTO 超时 · 重回慢启动', phaseRT: '快重传 · 回慢启动',
      labLog: '实验记录', labEmpty: '点击「播放」或「单步」开始实验',
      labChartTitle: '拥塞窗口 cwnd（单位：MSS = 1460 字节）', labAxisRTT: 'RTT 轮次',
      labCwndLegend: 'cwnd', labSsthLegend: 'ssthresh',
      labEventDup: '3 dup ACK', labEventTimeout: 'RTO 超时', labInfl: '快恢复膨胀',
      labReady: '尚未开始', labDone: '本轮实验结束，可重置后换参数再跑'
    },
    en: {
      tagline: 'Learn how the Internet works', learning: 'Studying', layer: 'App layer', progress: 'Progress',
      inProgress: 'In progress', protocols: 'Internet Protocols', sideTip: 'Pick a protocol to switch lesson; expand to see the steps',
      networkView: 'Network', timingView: 'Sequence', visualHint: 'Press Play to replay the whole exchange',
      packets: 'Packets', play: 'Play', pause: 'Pause', reset: 'Reset',
      colNo: 'No.', colTime: 'Time', colSrc: 'Source', colDst: 'Destination', colProto: 'Protocol',
      colInfo: 'Info', colSize: 'Size', summary: 'Lesson Summary', courseDone: 'Completed',
      tipTitle: 'Key insight', fieldPane: 'Protocol Fields', fieldHint: 'Hover a field to highlight its bytes',
      hexPane: 'Raw Byte Stream', hexTip: 'Hover or click a byte to locate its field',
      hexNote: 'Dimmed characters are non-printable bytes',
      dlgFoot: 'Highlighted ranges differ per field; encrypted payloads, checksums and padding are not expanded here.',
      waiting: 'Ready', running: 'In progress', statusDone: 'Completed',
      currentPacket: 'Current packet', packetsTotal: 'Packets', elapsed: 'Elapsed',
      doneHint: 'All packets delivered — press Play to replay',
      legend: 'Click any row to expand the layered structure',
      nodeClient: 'Client', nodeGateway: 'Gateway / Router', nodeDns: 'DNS Server',
      nodeDhcp: 'DHCP Server', nodeWeb: 'Web Server', nodeTarget: 'Remote Host',
      nodeMail: 'Mail Server', nodeFtp: 'FTP Server',
      nodeR1: 'Router R1', nodeR3: 'Router R3',
      seqTitle: 'Sequence diagram · vertical = time', detailTitle: 'Inspect packet',
      statAll: 'All', statBase: 'Core', statApp: 'App', statSec: 'Secure',
      schoolShort: 'Zhejiang Gongshang Univ.', authorShort: 'Jianguo Xing',
      labView: 'Congestion Lab', labTitle: 'Congestion Window Lab',
      labNote: 'The capture table below shows one run with default settings (Reno / ssthresh=8 / 3 dup ACKs). Changing parameters here recomputes the curve only.',
      labAlgo: 'Algorithm', labSsthresh: 'Initial ssthresh', labLoss: 'Loss signal', labLossRound: 'Loss at',
      algoReno: 'Reno · fast recovery', algoTahoe: 'Tahoe · slow start',
      lossDup: '3 duplicate ACKs', lossTimeout: 'RTO timeout',
      labPlay: 'Play', labPause: 'Pause', labStep: 'Step', labBack: 'Back', labReset: 'Reset',
      labRound: 'Current RTT', labCwnd: 'Congestion window', labSsthNow: 'ssthresh', labPhase: 'Phase',
      labSent: 'Sent this RTT', labTotal: 'Total segments', labRate: 'Est. throughput',
      phaseSS: 'Slow start', phaseCA: 'Congestion avoidance', phaseFR: 'Fast recovery',
      phaseTO: 'RTO timeout · slow start', phaseRT: 'Fast retransmit · slow start',
      labLog: 'Experiment log', labEmpty: 'Press Play or Step to start the experiment',
      labChartTitle: 'Congestion window cwnd (unit: MSS = 1460 bytes)', labAxisRTT: 'RTT round',
      labCwndLegend: 'cwnd', labSsthLegend: 'ssthresh',
      labEventDup: '3 dup ACKs', labEventTimeout: 'RTO timeout', labInfl: 'Fast recovery inflation',
      labReady: 'Not started', labDone: 'Run complete — reset and try another configuration'
    }
  };
  const STAT_EN = {
    '往返次数': 'Round trips', '总时间': 'Total time', '页面大小': 'Page size', '响应': 'Response',
    '传输协议': 'Transport', '查询往返': 'Query RTT', '报文大小': 'Packet size', '缓存 TTL': 'Cache TTL',
    '建连往返': 'Handshake RTT', '首部长度': 'Header size', '可靠性': 'Reliability', '流量控制': 'Flow control',
    '典型应用': 'Used by', '地址长度': 'Address size', '初始 TTL': 'Initial TTL', '分片单位': 'Fragment unit',
    '报文长度': 'Message size', '请求方式': 'Request mode', '应答方式': 'Reply mode', 'EtherType': 'EtherType',
    '协议号': 'IP protocol', '请求类型': 'Request type', '应答类型': 'Reply type', '往返时延': 'Round-trip time',
    '交互步骤': 'Exchange steps', '客户端端口': 'Client port', '服务端端口': 'Server port', '典型租约': 'Typical lease',
    '默认端口': 'Default port', 'TLS 版本': 'TLS version', '握手开销': 'Handshake cost', '加密套件': 'Cipher suite',
    '密钥交换': 'Key exchange', '身份认证': 'Authentication', '对称加密': 'Symmetric cipher', '密钥派生': 'Key derivation',
    '升级状态码': 'Upgrade status', '帧头开销': 'Frame overhead', '客户端掩码': 'Client mask', '连接方向': 'Direction',
    '应答格式': 'Reply format', '结束标记': 'End marker', '控制端口': 'Control port', '数据端口': 'Data port',
    '连接数量': 'TCP connections', '传输模式': 'Transfer mode', '承载协议': 'Runs over', '首次建连': 'First handshake',
    '加密': 'Encryption', '队头阻塞': 'Head-of-line blocking', '当前报文': 'Current packet',
    '报文总数': 'Packets', '已用时间': 'Elapsed',
    '组播地址': 'Multicast', '度量标准': 'Metric', '更新周期': 'Update interval',
    '最大跳数': 'Max hops', 'IP 协议号': 'IP protocol', '路由算法': 'Algorithm',
    '报文类型': 'Packet types', '建连开销': 'Setup cost', '传输层': 'Transport',
    '协议版本': 'Version', '会话类型': 'Session type', '保活周期': 'Keepalive',
    '路径属性': 'Path attributes',
    '拥塞算法': 'Algorithms', '初始阈值': 'Initial ssthresh', '默认丢包': 'Default loss',
    '发送窗口': 'Send window', 'MSS / RTT': 'MSS / RTT'
  };
  const T = k => (I18N[state.lang] || I18N.zh)[k] || k;
  const trStat = k => state.lang === 'en' ? (STAT_EN[k] || k) : k;
  const trCat = id => ({ all: T('statAll'), base: T('statBase'), app: T('statApp'), sec: T('statSec') })[id];
  const DONE_TITLE = {
    http: '页面已送达', https: '加密页面已送达', dns: '域名已解析', tcp: '连接已建立',
    udp: '数据报已送达', ip: '分组已投递', arp: '地址已解析', icmp: '目标可达',
    dhcp: 'IP 地址已分配', tls: '安全通道已建立', websocket: '实时通道已建立',
    smtp: '邮件已投递', ftp: '文件列表已送达', quic: 'HTTP/3 响应已送达',
    rip: '路由表已收敛', ospf: '链路状态已同步', bgp: '域间路由已收敛',
    tcpcc: '拥塞窗口已收敛'
  };
  const sc = () => D.scenarios[state.scenario];
  const pk = () => sc().packets[state.index] || null;

  /* ---------------- 节点坐标与 SVG 图形 ---------------- */
  const POS = {
    url: { x: 218, y: 92 }, client: { x: 245, y: 352 }, gateway: { x: 522, y: 182 },
    dns: { x: 838, y: 96 }, dhcp: { x: 838, y: 96 }, web: { x: 838, y: 350 },
    target: { x: 838, y: 350 }, mail: { x: 838, y: 350 }, ftp: { x: 838, y: 350 },
    r1: { x: 220, y: 300 }, r3: { x: 820, y: 300 }
  };
  const ROUTER_NODES = ['gateway', 'r1', 'r3'];
  const NODE_NAMES = {
    client: 'nodeClient', gateway: 'nodeGateway', dns: 'nodeDns', dhcp: 'nodeDhcp',
    web: 'nodeWeb', target: 'nodeTarget', mail: 'nodeMail', ftp: 'nodeFtp',
    r1: 'nodeR1', r3: 'nodeR3'
  };
  const NODE_IPS = {
    client: D.ipClient, gateway: '192.168.1.1', dns: D.ipDns, dhcp: '192.168.1.1',
    web: D.ipWeb, target: D.ipWeb, mail: '198.51.100.25', ftp: '198.51.100.40',
    r1: '10.0.12.1', r3: '10.0.23.3'
  };

  function isoFaces(w, h, d) {
    const x = -w / 2, y = -h / 2, dy = d * 0.58;
    return {
      front: 'M' + x + ',' + y + ' h' + w + ' v' + h + ' h' + (-w) + ' Z',
      top: 'M' + x + ',' + y + ' l' + d + ',-' + dy + ' h' + w + ' l' + (-d) + ',' + dy + ' Z',
      side: 'M' + (x + w) + ',' + y + ' l' + d + ',-' + dy + ' v' + h + ' l' + (-d) + ',' + dy + ' Z'
    };
  }

  function laptopSvg() {
    return '' +
      '<path class="node-shape" d="M-62,-72 h124 a4,4 0 0 1 4,4 v58 a4,4 0 0 1 -4,4 h-124 a4,4 0 0 1 -4,-4 v-58 a4,4 0 0 1 4,-4 Z"/>' +
      '<rect class="node-detail" x="-54" y="-64" width="108" height="64" rx="2"/>' +
      '<path class="node-faint" d="M-46,-52 h52 M-46,-42 h70 M-46,-32 h38 M-46,-22 h62 M-46,-12 h46"/>' +
      '<path class="node-shape" d="M-78,10 h156 l16,20 h-188 Z"/>' +
      '<path class="node-detail" d="M-60,16 h120 M-66,22 h132"/>' +
      '<rect class="node-detail" x="-16" y="23" width="32" height="4" rx="1"/>';
  }
  function serverSvg(kind) {
    const f = isoFaces(84, 92, 26);
    const ports = kind === 'gateway'
      ? '<path class="node-detail" d="M-28,12 h56 M-28,24 h56"/>' +
        '<rect class="node-detail" x="-28" y="-4" width="12" height="8" rx="1"/>' +
        '<rect class="node-detail" x="-8" y="-4" width="12" height="8" rx="1"/>' +
        '<rect class="node-detail" x="12" y="-4" width="12" height="8" rx="1"/>'
      : '<rect class="node-detail" x="-28" y="-28" width="56" height="15" rx="2"/>' +
        '<rect class="node-detail" x="-28" y="-6" width="56" height="15" rx="2"/>' +
        '<rect class="node-detail" x="-28" y="16" width="56" height="15" rx="2"/>' +
        '<circle class="node-glow" cx="-18" cy="-20" r="2.5"/><circle class="node-glow" cx="-18" cy="2" r="2.5"/><circle class="node-glow" cx="-18" cy="24" r="2.5"/>';
    return '<path class="node-shape" d="' + f.top + '"/>' +
      '<path class="node-shape" d="' + f.side + '"/>' +
      '<path class="node-shape" d="' + f.front + '"/>' + ports +
      (kind === 'gateway'
        ? '<path class="node-detail" d="M-34,-46 l16,-16 M-18,-62 h28 M10,-62 l16,16"/>'
        : '<path class="node-faint" d="M-42,-46 l26,-15 h84"/>');
  }
  function urlSvg(scene) {
    const text = scene.url || '';
    return '' +
      '<rect class="node-box" x="-115" y="-21" width="230" height="42" rx="6"/>' +
      '<circle class="node-detail" cx="-92" cy="0" r="8"/>' +
      '<path class="node-detail" d="M-100,0 h16 M-92,-8 c3,3 3,13 0,16 M-92,-8 c-3,3 -3,13 0,16"/>' +
      '<text class="node-box-text" x="-74" y="4">' + esc(text.length > 24 ? text.slice(0, 23) + '…' : text) + '</text>' +
      '<path class="node-detail" style="stroke:#16a34a" d="M92,-4 l5,5 l9,-11"/>' +
      '<text class="url-caption" x="0" y="42" text-anchor="middle">' + (state.lang === 'en' ? 'Destination address' : '目标地址') + '</text>';
  }

  function nodeLabel(key, scene) {
    const custom = (scene.labels || {})[key] || {};
    const name = (state.lang === 'en' && custom.en) || custom.name || T(NODE_NAMES[key] || 'nodeWeb');
    const ip = custom.ip || NODE_IPS[key] || '';
    return '<rect class="node-label-bg" x="-76" y="55" width="152" height="40" rx="5"/>' +
      '<text class="node-label" x="0" y="72" text-anchor="middle">' + esc(name) + '</text>' +
      '<text class="node-ip" x="0" y="90" text-anchor="middle">' + esc(ip) + '</text>';
  }

  function linkPath(a, b) {
    const p1 = POS[a], p2 = POS[b], g = POS.gateway;
    if (!p1 || !p2) return '';
    if (a === 'gateway' || b === 'gateway') {
      return 'M' + p1.x + ',' + p1.y + ' Q ' + ((p1.x + p2.x) / 2) + ',' + ((p1.y + p2.y) / 2 - 48) + ' ' + p2.x + ',' + p2.y;
    }
    return 'M' + p1.x + ',' + p1.y + ' Q ' + g.x + ',' + (g.y - 44) + ' ' + p2.x + ',' + p2.y;
  }

  /* ---------------- 渲染：顶部 ---------------- */
  function renderHeader() {
    const s = sc(), p = pk(), ps = s.packets;
    $('lessonName').innerHTML = esc(s.name) + ' <em>→</em> ' + esc(s.title);
    const done = state.index >= ps.length - 1;
    const pct = Math.round(((state.index + 1) / ps.length) * 100);
    $('lessonDots').innerHTML = s.steps.map(st =>
      '<i class="' + (state.index + 1 >= st.at ? 'on' : '') + '"></i>'
    ).join('');
    $('lessonPct').textContent = done ? T('courseDone') : pct + '%';

    const layer = p ? p.layer : s.layer;
    const related = p ? p.osi : [s.layer];
    $('osiCells').innerHTML = [1, 2, 3, 4, 5, 6, 7].map(n =>
      '<b class="' + (n === layer ? 'active' : (related.indexOf(n) >= 0 ? 'related' : '')) + '">' + n + '</b>'
    ).join('');
    $('osiCaption').textContent = D.osiNames[layer - 1] || '';
    $('layerBadge').textContent = layer;

    const overall = Math.round((state.finished.size / D.order.length) * 100);
    $('progressPct').textContent = overall + '%';
    $('progressCount').textContent = state.finished.size + ' / ' + D.order.length +
      (state.lang === 'en' ? ' done' : ' 已完成');
    $('progressBar').style.width = overall + '%';
  }

  /* ---------------- 渲染：左侧 ---------------- */
  function renderSidebar() {
    const counts = { all: D.order.length, base: 0, app: 0, sec: 0 };
    D.order.forEach(id => counts[D.scenarios[id].cat]++);
    $('catTabs').innerHTML = D.categories.map(c =>
      '<button data-cat="' + c.id + '" class="' + (state.category === c.id ? 'active' : '') + '">' +
      trCat(c.id) + '<b>' + counts[c.id] + '</b></button>'
    ).join('');

    const s = sc();
    const html = D.order.filter(id => state.category === 'all' || D.scenarios[id].cat === state.category)
      .map(id => {
        const x = D.scenarios[id], open = id === state.scenario;
        let steps = '';
        if (open) {
          steps = '<div class="steps">' + x.steps.map((st, i) => {
            const prev = i === 0 ? 0 : x.steps[i - 1].at;
            const done = state.index + 1 >= st.at;
            const cur = !done && state.index + 1 >= prev;
            return '<div class="step ' + (done ? 'done' : (cur ? 'current' : '')) + '">' +
              '<span class="step-mark"><svg><use href="#i-check"/></svg></span>' +
              '<div><div class="step-title">' + esc(st.t) + '</div>' +
              '<div class="step-desc">' + esc(st.d) + '</div></div></div>';
          }).join('') + '</div>';
        }
        return '<div class="proto-card ' + (open ? 'open' : '') + '">' +
          '<div class="proto-row" data-id="' + id + '" role="button" tabindex="0">' +
          '<span class="proto-dot"></span>' +
          '<div style="min-width:0"><div class="proto-name">' + esc(x.name) + '</div>' +
          '<div class="proto-sub">' + esc(x.sub) + '</div></div>' +
          '<svg class="proto-chev"><use href="#i-chev"/></svg></div>' + steps + '</div>';
      }).join('');
    $('protocolList').innerHTML = html;
  }

  /* ---------------- 渲染：抓包表格 ---------------- */
  function renderTable() {
    const s = sc();
    const kinds = state.lang === 'en' ? D.kindEn : D.kindZh;
    const legendKeys = Array.from(new Set(s.packets.map(p => p.kind)));
    $('captureLegend').innerHTML = legendKeys.map(k =>
      '<span class="lg"><i style="background:' + D.kindColors[k] + '"></i>' + esc(kinds[k] || k) + '</span>'
    ).join('');
    $('canvasLegend').innerHTML = legendKeys.slice(0, 5).map(k =>
      '<span class="cl-item"><i style="background:' + D.kindColors[k] + '"></i>' + esc(kinds[k] || k) + '</span>'
    ).join('') + '<span class="cl-item" style="color:var(--muted)">· ' + esc(T('legend')) + '</span>';

    $('packetBody').innerHTML = s.packets.map((p, i) => {
      const cls = state.index < 0 ? 'future' : (i === state.index ? 'current' : (i < state.index ? 'past' : 'future'));
      return '<tr class="' + cls + ' k-' + p.kind + '" data-i="' + i + '" title="' + esc(T('detailTitle')) + '">' +
        '<td class="c-no"><span class="pk-no">' + (i + 1) + '</span></td>' +
        '<td class="c-time">' + fmtTime(p.t) + '</td>' +
        '<td class="c-src">' + esc(p.src) + '</td>' +
        '<td class="c-dst">' + esc(p.dst) + '</td>' +
        '<td class="c-proto"><span>' + esc(p.proto) + '</span></td>' +
        '<td class="c-info"><span class="pk-row-dot" style="background:' + D.kindColors[p.kind] + '"></span>' + esc(p.info) + '</td>' +
        '<td class="c-size">' + esc(sizeOf(p)) + '</td></tr>';
    }).join('');
    $('stepCount').textContent = (state.index + 1) + ' / ' + s.packets.length;
    const cur = $('packetBody').querySelector('tr.current');
    if (cur && (state.playing || (state.index >= 0 && state.index < s.packets.length - 1)))
      cur.scrollIntoView({ block: 'nearest' });
  }

  /* ---------------- 渲染：课程总结 ---------------- */
  function renderSummary() {
    const s = sc(), p = pk(), done = state.index >= s.packets.length - 1;
    const st = $('sumStatus');
    st.className = 'sum-status ' + (done ? '' : 'running');
    st.querySelector('span:last-child').textContent = done ? T('statusDone') : T('running');
    $('sumTitle').textContent = done ? (DONE_TITLE[s.id] || (s.name + ' 完成')) :
      (state.index < 0 ? T('waiting') : (p.phase || p.title));
    $('sumDesc').textContent = done ? s.desc : (state.index < 0 ? T('visualHint') : (p.note || p.info));

    const stats = s.stats.map(x => ({ k: trStat(x.k), v: x.v }));
    if (!done) {
      stats.unshift({ k: trStat(T('currentPacket')), v: (state.index + 1) + ' / ' + s.packets.length });
      stats.push({ k: trStat(T('elapsed')), v: state.index >= 0 ? fmtTime(p.t) : '0.000s' });
    }
    $('sumStats').innerHTML = stats.map(x =>
      '<div class="sum-stat"><span class="k">' + esc(x.k) + '</span><span class="v">' + esc(x.v) + '</span></div>'
    ).join('');
    $('sumTip').textContent = s.tip;

    const phases = [];
    s.packets.forEach((q, i) => {
      const last = phases[phases.length - 1];
      if (last && last.name === q.phase) last.count++;
      else phases.push({ name: q.phase, color: D.kindColors[q.kind], count: 1, at: i });
    });
    $('sumFlow').innerHTML = '<div class="sum-flow-title">' + (state.lang === 'en' ? 'EXCHANGE PHASES' : '交互阶段') + '</div>' +
      phases.map(ph =>
        '<div class="flow-item ' + (state.index >= ph.at ? 'done' : (state.index + 1 >= ph.at ? 'active' : '')) + '">' +
        '<i style="background:' + ph.color + '"></i><span>' + esc(ph.name) + '</span>' +
        '<span class="ft">' + ph.count + ' pkt</span></div>'
      ).join('');
  }

  /* ---------------- 渲染：网络拓扑 ---------------- */
  function renderNetwork() {
    const s = sc();
    // links
    const pairs = [];
    s.packets.forEach(p => {
      const key = [p.from, p.to].sort().join('|');
      if (p.from !== p.to && !pairs.some(x => x.key === key)) pairs.push({ key, a: p.from, b: p.to });
    });
    $('linkLayer').innerHTML = pairs.map(x =>
      '<path class="link-line" id="link_' + x.key.replace('|', '_') + '" data-a="' + x.a + '" data-b="' + x.b +
      '" d="' + linkPath(x.a, x.b) + '" marker-end="url(#arrowHeadDim)"/>'
    ).join('');

    // nodes
    $('nodeLayer').innerHTML = s.nodes.map(key => {
      const pos = POS[key];
      if (!pos) return '';
      const inner = key === 'url' ? urlSvg(s) :
        (key === 'client' ? laptopSvg() : serverSvg(ROUTER_NODES.indexOf(key) >= 0 ? 'gateway' : key));
      const label = key === 'url' ? '' : nodeLabel(key, s);
      return '<g class="node" id="node_' + key + '" transform="translate(' + pos.x + ',' + pos.y + ')">' +
        inner + label + '</g>';
    }).join('');
    const fallback = s.packets[0] ? s.packets[0].src : D.ipClient;
    $('canvasCorner').textContent = state.index >= 0 ? (pk().src + '  →  ' + pk().dst) : fallback;
  }

  function renderNetworkState() {
    const p = pk();
    document.querySelectorAll('#nodeLayer .node').forEach(g => {
      g.classList.remove('node-active', 'node-idle');
      if (p) g.classList.add(p.from === g.id.replace('node_', '') || p.to === g.id.replace('node_', '') ? 'node-active' : 'node-idle');
    });
    document.querySelectorAll('#linkLayer .link-line').forEach(pa => pa.classList.remove('active'));
    if (p) {
      const key = [p.from, p.to].sort().join('_');
      const el = $('link_' + key);
      if (el) el.classList.add('active');
    }
    const s = sc();
    $('canvasCorner').textContent = p ? (p.src + '  →  ' + p.dst) : (s.packets[0] ? s.packets[0].src : D.ipClient);
  }

  /* ---------------- 渲染：时序图 ---------------- */
  function renderSequence() {
    const s = sc(), svg = $('sequenceSvg');
    const life = s.nodes.filter(n => n !== 'url' && n !== 'gateway' && n !== 'client');
    const cols = s.seqNodes || ['client'].concat(life.slice(0, 3));
    const x0 = 170, x1 = 870;
    const X = {};
    cols.forEach((c, i) => { X[c] = cols.length === 1 ? 520 : x0 + (x1 - x0) * i / (cols.length - 1); });
    const n = s.packets.length;
    const y0 = 104, y1 = 486;
    const Y = i => n <= 1 ? y0 : y0 + (y1 - y0) * i / (n - 1);
    let out = '<defs><marker id="seqArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">' +
      '<path d="M0 1L9 5L0 9" fill="none" stroke="var(--blue)" stroke-width="1.6"/></marker></defs>';
    for (let gy = 90; gy < 510; gy += 42) {
      out += '<path d="M20,' + gy + ' H980" stroke="var(--line-2)" stroke-width="1" fill="none"/>';
    }
    out += '<text x="24" y="30" style="font:600 11px var(--sans);fill:var(--muted);stroke:none">' + esc(T('seqTitle')) + '</text>';

    cols.forEach(c => {
      const custom = (s.labels || {})[c] || {};
      const name = (state.lang === 'en' && custom.en) || custom.name || T(NODE_NAMES[c] || 'nodeWeb');
      const ip = custom.ip || NODE_IPS[c] || '';
      out += '<path class="seq-line" d="M' + X[c] + ',70 V500"/>';
      out += '<rect class="seq-head-box" x="' + (X[c] - 82) + '" y="36" width="164" height="38" rx="5"/>';
      out += '<text class="seq-head-text" x="' + X[c] + '" y="53">' + esc(name) + '</text>';
      out += '<text class="seq-head-ip" x="' + X[c] + '" y="67">' + esc(ip) + '</text>';
      out += '<text class="seq-head-ip" x="' + X[c] + '" y="515">' + esc(ip) + '</text>';
    });

    s.packets.forEach((p, i) => {
      const y = Y(i), a = X[p.from] != null ? X[p.from] : X.client, b = X[p.to] != null ? X[p.to] : X[cols[cols.length - 1]];
      const cls = state.index < 0 ? '' : (i === state.index ? 'active' : (i < state.index ? 'done' : ''));
      const dir = b >= a ? 1 : -1;
      const tipX = b - dir * 8;
      out += '<text class="seq-time" x="24" y="' + (y + 4) + '">' + fmtTime(p.t) + '</text>';
      out += '<path class="seq-arrow ' + cls + '" d="M' + a + ',' + y + ' L' + tipX + ',' + y + '" marker-end="url(#seqArrow)"/>';
      const mx = (a + b) / 2;
      out += '<rect x="' + (mx - 105) + '" y="' + (y - 24) + '" width="210" height="17" rx="4" fill="var(--panel)" stroke="none"/>';
      out += '<text class="seq-msg ' + cls + '" x="' + mx + '" y="' + (y - 11) + '">' + esc(p.info.length > 34 ? p.info.slice(0, 33) + '…' : p.info) + '</text>';
      out += '<circle class="seq-num" cx="' + (a + (b - a) * 0.14) + '" cy="' + y + '" r="9"/>';
      out += '<text class="seq-num-text" x="' + (a + (b - a) * 0.14) + '" y="' + y + '">' + (i + 1) + '</text>';
    });
    svg.innerHTML = out;
  }

  /* ---------------- TCP 拥塞控制实验台 ---------------- */
  const lab = {
    cfg: Object.assign({}, D.labDefault),
    rounds: D.labSimulate(D.labDefault),
    at: 0, playing: false, timer: null
  };

  function labStop() {
    lab.playing = false;
    if (lab.timer) clearTimeout(lab.timer);
    lab.timer = null;
  }
  /* 把实验进度同步到抓包表 / 总结 / 拓扑（不重绘实验面板，避免递归） */
  function labSyncTable(r) {
    const s = sc();
    if (!s || s.id !== 'tcpcc') return;
    let idx = -1;
    s.packets.forEach((p, i) => { if (p.rtt === r) idx = i; });
    if (idx < 0) return;
    state.index = idx;
    renderHeader(); renderSidebar(); renderTable(); renderSummary(); renderNetworkState();
    $('visualHint').textContent = pk().title + '  ·  ' + pk().info;
  }
  function labRebuild() {
    labStop(); lab.at = 0;
    lab.rounds = D.labSimulate(lab.cfg);
    renderLab();
  }
  function labPlay() {
    if (lab.playing) { labStop(); renderLab(); return; }
    if (lab.at >= lab.rounds.length) lab.at = 0;
    lab.playing = true;
    renderLab();
    const tick = () => {
      if (!lab.playing) return;
      if (lab.at >= lab.rounds.length) { labStop(); renderLab(); return; }
      lab.at++;
      labSyncTable(lab.at);
      renderLab();
      if (lab.at >= lab.rounds.length) { labStop(); renderLab(); return; }
      lab.timer = setTimeout(tick, 680 / state.speed);
    };
    lab.timer = setTimeout(tick, 240);
  }
  function labStep(dir) {
    labStop();
    lab.at = clamp(lab.at + (dir || 1), 0, lab.rounds.length);
    if (lab.at > 0) labSyncTable(lab.at);
    renderLab();
  }
  function labReset() {
    labStop(); lab.at = 0;
    lab.rounds = D.labSimulate(lab.cfg);
    state.index = 0;
    renderHeader(); renderSidebar(); renderTable(); renderSummary(); renderNetworkState();
    $('visualHint').textContent = T('labEmpty');
    renderLab();
  }
  function syncLabTab() {
    const show = state.scenario === 'tcpcc';
    $('labTab').hidden = !show;
    if (!show && state.view === 'lab') setView('network');
  }

  function labChartHTML(rs) {
    const L = 54, R = 700, TOP = 40, BOT = 322, N = rs.length;
    const peak = Math.max.apply(null, [14].concat(rs.map(x => Math.max(x.cwnd, x.ssthresh, x.infl || 0))));
    const maxY = Math.ceil(peak * 1.16 / 2) * 2;
    const X = r => L + (R - L) * (r - 1) / (N - 1);
    const Y = v => BOT - (BOT - TOP) * v / maxY;
    let o = '';

    for (let i = 0; i <= 4; i++) {
      const v = maxY * i / 4, y = Y(v);
      o += '<path class="lab-grid" d="M' + L + ',' + y + ' H' + R + '"/>';
      o += '<text class="lab-tick" x="' + (L - 9) + '" y="' + (y + 3.5) + '" text-anchor="end">' +
        (Number.isInteger(v) ? v : v.toFixed(1)) + '</text>';
    }
    o += '<path class="lab-axis" d="M' + L + ',' + TOP + ' V' + BOT + ' H' + R + '"/>';
    rs.forEach(x => {
      if (x.r % 2 === 1 || x.r === N)
        o += '<text class="lab-tick" x="' + X(x.r) + '" y="' + (BOT + 15) + '" text-anchor="middle">' + x.r + '</text>';
    });

    o += '<polyline class="lab-ssth" points="' + rs.map(x => X(x.r) + ',' + Y(x.ssthresh)).join(' ') + '"/>';
    o += '<polyline class="lab-line-dim" points="' + rs.map(x => X(x.r) + ',' + Y(x.cwnd)).join(' ') + '"/>';

    if (lab.at >= 2) {
      const pts = rs.slice(0, lab.at).map(x => [X(x.r), Y(x.cwnd)]);
      o += '<path class="lab-area" d="M' + pts[0][0] + ',' + BOT + ' L' +
        pts.map(p => p[0] + ',' + p[1]).join(' L') + ' L' + pts[pts.length - 1][0] + ',' + BOT + ' Z"/>';
      o += '<polyline class="lab-line" points="' + pts.map(p => p[0] + ',' + p[1]).join(' ') + '"/>';
    }

    rs.forEach(x => {
      if (!x.event) return;
      const px = X(x.r);
      o += '<path class="lab-evt-line" d="M' + px + ',' + TOP + ' V' + BOT + '"/>';
      o += '<circle class="lab-evt-dot" cx="' + px + '" cy="' + Y(x.cwnd) + '" r="5"/>';
      o += '<text class="lab-evt-lbl" x="' + px + '" y="' + (TOP - 8) + '" text-anchor="middle">' +
        esc(x.event === 'timeout' ? T('labEventTimeout') : T('labEventDup')) + '</text>';
      if (x.infl) {
        const ix = px + 30, iy = Y(x.infl);
        o += '<path class="lab-infl" d="M' + px + ',' + Y(x.cwnd) + ' L' + ix + ',' + iy + '"/>';
        o += '<rect x="' + (ix - 4) + '" y="' + (iy - 4) + '" width="8" height="8" transform="rotate(45 ' + ix + ' ' + iy + ')" ' +
          'style="fill:var(--amber);stroke:var(--panel);stroke-width:1.5"/>';
        o += '<text class="lab-tick" x="' + (ix + 10) + '" y="' + (iy + 3) + '">cwnd→' + x.infl + '</text>';
      }
    });

    rs.forEach(x => {
      o += '<circle class="lab-dot ' + (x.r <= lab.at ? 'on' : '') + '" cx="' + X(x.r) + '" cy="' + Y(x.cwnd) + '" r="3.6"/>';
    });

    if (lab.at >= 1) {
      const c = rs[lab.at - 1], px = X(c.r), py = Y(c.cwnd);
      o += '<circle class="lab-cur-ring" cx="' + px + '" cy="' + py + '" r="11"/>';
      o += '<circle class="lab-cur" cx="' + px + '" cy="' + py + '" r="6"/>';
      o += '<text class="lab-cur-lbl" x="' + px + '" y="' + (py - 15) + '" text-anchor="middle">cwnd=' + c.cwnd + '</text>';
    }

    const half = (R - L) / (N - 1) / 2;
    rs.forEach(x => {
      o += '<rect class="lab-hit" x="' + (X(x.r) - half) + '" y="' + TOP + '" width="' + (half * 2) +
        '" height="' + (BOT - TOP) + '" data-lab-r="' + x.r + '"><title>RTT ' + x.r + '</title></rect>';
    });

    o += '<text class="lab-chart-title" x="' + L + '" y="18">' + esc(T('labChartTitle')) + '</text>';
    const lx = R - 196;
    o += '<rect x="' + lx + '" y="9" width="14" height="3" style="fill:var(--blue)"/>' +
      '<text class="lab-legend-text" x="' + (lx + 19) + '" y="15">' + esc(T('labCwndLegend')) + '</text>' +
      '<rect x="' + (lx + 84) + '" y="9" width="14" height="3" style="fill:var(--purple)"/>' +
      '<text class="lab-legend-text" x="' + (lx + 103) + '" y="15">' + esc(T('labSsthLegend')) + '</text>';
    o += '<text class="lab-tick" x="' + R + '" y="' + (BOT + 31) + '" text-anchor="end">' + esc(T('labAxisRTT')) + '</text>';
    return o;
  }

  function labSideHTML(rs) {
    const en = state.lang === 'en';
    const cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const phaseName = !cur ? T('labReady') :
      (cur.event === 'timeout' ? T('phaseTO') :
        (cur.event === 'dupack' ? (cur.infl ? T('phaseFR') : T('phaseRT')) :
          (cur.phase === 'ss' ? T('phaseSS') : T('phaseCA'))));
    const rate = cur ? (cur.cwnd * 1460 * 8 / 0.04 / 1e6).toFixed(2) + ' Mbps' : '—';
    const opts = (key, list) => list.map(x =>
      '<option value="' + x.v + '"' + (String(lab.cfg[key]) === String(x.v) ? ' selected' : '') + '>' + esc(x.t) + '</option>'
    ).join('');

    const metric = (k, v, wide) =>
      '<div class="lab-metric' + (wide ? ' wide' : '') + '"><span class="k">' + esc(k) + '</span><span class="v">' + esc(v) + '</span></div>';
    const logs = rs.slice(0, lab.at).slice(-7).reverse().map(x => {
      const tag = x.event
        ? (x.event === 'timeout' ? (en ? 'RTO timeout' : 'RTO 超时') : (en ? '3 dup ACKs' : '3 个重复 ACK'))
        : (x.phase === 'ss' ? T('phaseSS') : T('phaseCA'));
      return '<div class="lab-log-item ' + (x.event ? 'evt ' : '') + (x.r === lab.at ? 'cur' : '') + '">' +
        '<b>R' + x.r + '</b><span>' + esc(tag) + ' · cwnd ' + x.cwnd + '→' + x.endCwnd + '</span></div>';
    }).join('');

    return '<div class="lab-panel-title">' + esc(T('labTitle')) + '</div>' +
      '<div class="lab-note">' + esc(T('labNote')) + '</div>' +
      '<div class="lab-ctrl">' +
        '<label>' + esc(T('labAlgo')) + '<select data-lab="algo">' +
          opts('algo', [{ v: 'reno', t: T('algoReno') }, { v: 'tahoe', t: T('algoTahoe') }]) + '</select></label>' +
        '<label>' + esc(T('labSsthresh')) + '<select data-lab="ssthresh">' +
          opts('ssthresh', [8, 16, 32].map(v => ({ v: v, t: v + ' MSS' }))) + '</select></label>' +
        '<label>' + esc(T('labLoss')) + '<select data-lab="lossMode">' +
          opts('lossMode', [{ v: 'dupack', t: T('lossDup') }, { v: 'timeout', t: T('lossTimeout') }]) + '</select></label>' +
        '<label>' + esc(T('labLossRound')) + '<select data-lab="lossRound">' +
          opts('lossRound', [6, 8, 10].map(v => ({ v: v, t: 'RTT ' + v }))) + '</select></label>' +
      '</div>' +
      '<div class="lab-btns">' +
        '<button data-lab-act="back" title="' + esc(T('labBack')) + '"><svg><use href="#i-left"/></svg></button>' +
        '<button class="primary" data-lab-act="play"><svg><use href="#' + (lab.playing ? 'i-pause' : 'i-play') + '"/></svg>' +
          esc(lab.playing ? T('labPause') : T('labPlay')) + '</button>' +
        '<button data-lab-act="step" title="' + esc(T('labStep')) + '"><svg><use href="#i-step"/></svg></button>' +
        '<button data-lab-act="reset" title="' + esc(T('labReset')) + '"><svg><use href="#i-reset"/></svg></button>' +
      '</div>' +
      '<div class="lab-metrics">' +
        metric(T('labRound'), (cur ? cur.r : 0) + ' / ' + rs.length) +
        metric(T('labCwnd'), (cur ? cur.cwnd : 1) + ' MSS') +
        metric(T('labSsthNow'), (cur ? cur.ssthresh : lab.cfg.ssthresh) + ' MSS') +
        metric(T('labSent'), (cur ? cur.sent : 0) + ' seg') +
        metric(T('labTotal'), (cur ? cur.total : 0) + ' seg') +
        metric(T('labRate'), rate) +
        metric(T('labPhase'), phaseName, true) +
      '</div>' +
      '<div class="lab-log-title">' + esc(T('labLog')) + '</div>' +
      '<div class="lab-log">' + (logs || '<div class="lab-empty">' + esc(T('labEmpty')) + '</div>') + '</div>' +
      (lab.at >= rs.length ? '<div class="lab-empty">' + esc(T('labDone')) + '</div>' : '');
  }

  function renderLab() {
    if (state.view !== 'lab' || state.scenario !== 'tcpcc') return;
    if (!lab.rounds.length) lab.rounds = D.labSimulate(lab.cfg);
    $('labSvg').innerHTML = labChartHTML(lab.rounds);
    $('labSide').innerHTML = labSideHTML(lab.rounds);
    const cur = lab.at > 0 ? lab.rounds[lab.at - 1] : null;
    const ex = $('labExplain');
    ex.className = 'lab-explain' + (cur && cur.event ? ' evt' : '');
    const body = cur
      ? (state.lang === 'en' ? cur.en.replace(/^RTT \d+: /, '') : cur.zh.replace(/^RTT \d+：/, ''))
      : T('labEmpty');
    ex.innerHTML = cur
      ? '<b>RTT ' + cur.r + '</b><span>' + esc(body) + '</span>'
      : '<b>—</b><span>' + esc(body) + '</span>';
  }

  /* ---------------- 动画 ---------------- */
  function clearAnim() {
    if (state.raf) cancelAnimationFrame(state.raf);
    if (state.timer) clearTimeout(state.timer);
    state.raf = state.timer = null;
    $('packetLayer').innerHTML = '';
  }

  function animatePacket(p, done) {
    const path = $('link_' + [p.from, p.to].sort().join('_'));
    if (!path || state.view !== 'network') { done(); return; }
    const len = path.getTotalLength();
    if (!len) { done(); return; }
    const reverse = path.dataset.a !== p.from;
    const color = D.kindColors[p.kind] || '#2340c4';
    $('packetLayer').innerHTML =
      '<circle class="pk-halo" id="pkHalo" r="22"/>' +
      '<circle class="pk-circle" id="pkCircle" r="15" style="fill:' + color + '"/>' +
      '<text class="pk-label" id="pkLabel">' + esc(p.proto.slice(0, 4)) + '</text>';
    const dur = 620 / state.speed;
    const start = performance.now();
    const halo = $('pkHalo'), circle = $('pkCircle'), label = $('pkLabel');
    function frame(now) {
      const t = clamp((now - start) / dur, 0, 1);
      const e = t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
      const d = reverse ? len * (1 - e) : len * e;
      const pt = path.getPointAtLength(d);
      [halo, circle].forEach(el => { el.setAttribute('cx', pt.x); el.setAttribute('cy', pt.y); });
      label.setAttribute('x', pt.x); label.setAttribute('y', pt.y);
      halo.setAttribute('r', 18 + 8 * Math.sin(t * Math.PI));
      if (t < 1) state.raf = requestAnimationFrame(frame);
      else { state.raf = null; done(); }
    }
    state.raf = requestAnimationFrame(frame);
  }

  function renderCurrent() {
    renderHeader();
    renderSidebar();
    renderTable();
    renderSummary();
    renderNetworkState();
    if (state.view === 'sequence') renderSequence();
    if (state.view === 'lab') renderLab();
    $('visualHint').textContent = state.index < 0 ? T('visualHint') :
      (pk().title + '  ·  ' + pk().info);
    $('sceneChip').textContent = (state.lang === 'en' ? 'SCENE ' : '场景 ') +
      String(D.order.indexOf(state.scenario) + 1).padStart(2, '0');
  }

  function advance(auto) {
    const s = sc();
    if (state.index >= s.packets.length - 1) { finish(); return; }
    state.index++;
    renderCurrent();
    const p = pk();
    animatePacket(p, () => {
      if (auto && state.playing && state.index < sc().packets.length - 1)
        state.timer = setTimeout(() => advance(true), 210 / state.speed);
      else if (auto && state.playing) finish();
    });
  }

  function finish() {
    state.playing = false;
    state.index = sc().packets.length - 1;
    state.finished.add(state.scenario);
    updatePlayBtn();
    renderCurrent();
  }
  function updatePlayBtn() {
    const b = $('playBtn');
    b.classList.toggle('playing', state.playing);
    b.querySelector('use').setAttribute('href', state.playing ? '#i-pause' : '#i-play');
    b.querySelector('span').textContent = state.playing ? T('pause') : T('play');
  }
  function play() {
    if (state.playing) { state.playing = false; clearTimeout(state.timer); updatePlayBtn(); return; }
    clearAnim();
    if (state.index >= sc().packets.length - 1) state.index = -1;
    state.playing = true;
    updatePlayBtn();
    renderCurrent();
    advance(true);
  }
  function stepOne(dir) {
    state.playing = false; clearAnim(); updatePlayBtn();
    if (dir < 0) state.index = clamp(state.index - 1, 0, sc().packets.length - 1);
    else if (state.index < sc().packets.length - 1) state.index++;
    else state.index = 0;
    renderCurrent();
    animatePacket(pk(), function () {});
  }
  function resetAll() {
    state.playing = false; clearAnim(); updatePlayBtn();
    if (state.view === 'lab') { labReset(); return; }
    state.index = -1;
    renderCurrent();
    renderNetworkState();
  }
  function switchScenario(id) {
    if (!D.scenarios[id]) return;
    state.playing = false; clearAnim(); updatePlayBtn(); labStop();
    state.scenario = id;
    state.index = sc().packets.length - 1; // 初始展示完成态，便于直接阅读
    closeModal();
    syncLabTab();
    if (id === 'tcpcc' && state.view === 'lab') labRebuild();
    renderNetwork();
    renderCurrent();
  }

  /* ---------------- 报文详情弹窗 ---------------- */
  let dlgPacket = null, byteMap = [], fieldMap = [];

  function buildByteMap(p) {
    byteMap = []; fieldMap = [];
    p.layers.forEach((l, li) => {
      l.bytes.forEach((_, i) => byteMap.push({ layer: li, color: l.color }));
      l.fields.forEach((f, fi) => { if (f.l > 0) fieldMap.push({ f, li, fi }); });
    });
    fieldMap.sort((a, b) => a.f.l - b.f.l);
  }

  function openModal(i) {
    const p = sc().packets[i];
    if (!p) return;
    state.dlgIndex = i; dlgPacket = p;
    state.selectedField = state.lockedField = null;
    buildByteMap(p);
    $('dlgProto').textContent = p.proto;
    $('dlgProto').style.background = D.kindColors[p.kind] || 'var(--blue)';
    $('dlgTitle').textContent = p.title;
    $('dlgSub').textContent = p.src + '  →  ' + p.dst + '   ·   ' + p.proto + '   ·   ' + sizeOf(p);
    $('dlgNote').textContent = p.note || (state.lang === 'en' ? 'Captured on the local network adapter' : '在记录本电脑的网络适配器上抓到');
    $('hexCount').textContent = p.size + ' bytes' + (p.truncated ? ' (' + (state.lang === 'en' ? 'first segment' : '仅首段') + ')' : '');

    $('layerStrip').innerHTML = p.layers.map((l, li) =>
      '<div class="ls-seg" data-li="' + li + '" style="flex:' + l.bytes.length + ' 1 0;background:' + l.color + '" title="' + esc(l.name) + ' · ' + l.bytes.length + ' B">' +
      '<span>' + esc(l.short) + '</span><small>' + l.bytes.length + ' B</small></div>'
    ).join('');

    $('fieldsPane').innerHTML = p.layers.map((l, li) =>
      '<div class="layer-card" id="lc_' + li + '">' +
      '<div class="layer-card-head" data-li="' + li + '">' +
      '<span class="lc-bar" style="background:' + l.color + '"></span>' +
      '<span class="lc-name">' + esc(l.name) + '</span>' +
      '<span class="lc-size">' + l.bytes.length + ' B · ' + esc(l.short) + '</span>' +
      '<svg class="lc-chev"><use href="#i-chev-down"/></svg></div>' +
      '<div class="layer-fields">' +
      (l.note ? '<div style="padding:8px 11px 2px;font-size:10px;color:var(--muted);line-height:1.6">' + esc(l.note) + '</div>' : '') +
      l.fields.map((f, fi) =>
        '<div class="field-row" data-g="' + f.g + '" data-l="' + f.l + '" data-li="' + li + '" data-fi="' + fi + '">' +
        '<div><div class="field-name">' + esc(f.n) + '</div>' +
        (f.v ? '<div class="field-value">' + esc(f.v) + '</div>' : '') + '</div>' +
        '<div class="field-meta">' + (f.l ? '[' + f.g + '..' + (f.g + f.l - 1) + ']<br>' + f.l + ' B' : '—') + '</div>' +
        '<div class="field-desc">' + esc(f.d) + '</div></div>'
      ).join('') + '</div></div>'
    ).join('');

    renderHex(p);
    $('detailModal').hidden = false;
    document.body.style.overflow = 'hidden';
  }

  function renderHex(p) {
    const limit = Math.min(p.bytes.length, 1024);
    const dark = state.theme === 'dark';
    let out = '';
    for (let off = 0; off < limit; off += 16) {
      let cells = '', chars = '';
      for (let j = 0; j < 16; j++) {
        const idx = off + j;
        if (idx < limit) {
          const b = p.bytes[idx], bm = byteMap[idx];
          const col = bm ? bm.color : '#888';
          const printable = b >= 32 && b <= 126;
          cells += '<span class="hex-b" data-i="' + idx + '" style="background-color:' + rgba(col, dark ? .22 : .12) +
            ';box-shadow:inset 0 -2px 0 ' + col + '">' + b.toString(16).padStart(2, '0') + '</span>';
          chars += '<span class="ha ' + (printable ? '' : 'dim') + '" data-i="' + idx + '">' +
            esc(printable ? String.fromCharCode(b) : '.') + '</span>';
        } else {
          cells += '<span class="hex-b"></span>'; chars += '<span class="ha"></span>';
        }
      }
      out += '<div class="hex-row"><span class="hex-off">' + off.toString(16).padStart(4, '0') + '</span>' +
        '<span class="hex-bytes">' + cells + '</span><span class="hex-ascii">' + chars + '</span></div>';
    }
    if (p.bytes.length > limit) out += '<div style="padding:10px 0;font-size:10px;color:var(--muted)">… ' +
      (state.lang === 'en' ? 'truncated' : '后续字节已截断') + '</div>';
    $('hexDump').innerHTML = out;
  }

  function highlightBytes(g, l, hl) {
    const root = $('hexDump');
    root.querySelectorAll('.hl').forEach(el => el.classList.remove('hl'));
    if (!hl || !l) return;
    for (let i = g; i < g + l && i < byteMap.length; i++) {
      const b = root.querySelector('.hex-b[data-i="' + i + '"]');
      const a = root.querySelector('.ha[data-i="' + i + '"]');
      if (b) b.classList.add('hl');
      if (a) a.classList.add('hl');
    }
  }
  function highlightField(row) {
    $('fieldsPane').querySelectorAll('.field-row.hl').forEach(el => el.classList.remove('hl'));
    if (!row) return;
    row.classList.add('hl');
    highlightBytes(+row.dataset.g, +row.dataset.l, true);
  }
  function fieldForByte(i) {
    for (let k = 0; k < fieldMap.length; k++) {
      const m = fieldMap[k], f = m.f;
      if (i >= f.g && i < f.g + f.l)
        return $('fieldsPane').querySelector('.field-row[data-li="' + m.li + '"][data-fi="' + m.fi + '"]');
    }
    return null;
  }
  function closeModal() {
    $('detailModal').hidden = true;
    document.body.style.overflow = '';
  }
  function navDlg(step) {
    const n = sc().packets.length;
    state.dlgIndex = (state.dlgIndex + step + n) % n;
    openModal(state.dlgIndex);
  }

  /* SVG 元素没有 HTMLElement.hidden 的 IDL 属性，须显式控制 display */
  function setView(v) {
    if (v === 'lab' && state.scenario !== 'tcpcc') v = 'network';
    state.view = v;
    const net = $('networkSvg'), seq = $('sequenceWrap'), wrap = $('labWrap');
    seq.removeAttribute('hidden');
    wrap.removeAttribute('hidden');
    net.style.display = v === 'network' ? '' : 'none';
    seq.style.display = v === 'sequence' ? '' : 'none';
    wrap.style.display = v === 'lab' ? '' : 'none';
    $('canvas').classList.toggle('lab-mode', v === 'lab');
    document.querySelectorAll('.view-tabs button').forEach(b =>
      b.classList.toggle('active', b.dataset.view === v));
    if (v !== 'lab') labStop();
    if (v === 'sequence') renderSequence();
    else if (v === 'lab') renderLab();
    else renderNetworkState();
  }

  /* ---------------- 事件绑定 ---------------- */
  function bind() {
    $('catTabs').addEventListener('click', e => {
      const b = e.target.closest('button[data-cat]');
      if (!b) return;
      state.category = b.dataset.cat;
      renderSidebar();
    });
    $('protocolList').addEventListener('click', e => {
      const row = e.target.closest('.proto-row');
      if (row) switchScenario(row.dataset.id);
    });
    $('protocolList').addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ' ') && e.target.classList.contains('proto-row')) {
        e.preventDefault(); switchScenario(e.target.dataset.id);
      }
    });

    document.querySelectorAll('.view-tabs button').forEach(b => b.addEventListener('click', () => {
      setView(b.dataset.view);
    }));

    /* 实验面板：事件委托，面板内容每次重绘也不会丢监听 */
    $('labWrap').addEventListener('click', e => {
      const hit = e.target.closest('[data-lab-r]');
      if (hit) {
        labStop();
        lab.at = clamp(+hit.dataset.labR, 1, lab.rounds.length);
        labSyncTable(lab.at);
        renderLab();
        return;
      }
      const btn = e.target.closest('[data-lab-act]');
      if (!btn) return;
      const act = btn.dataset.labAct;
      if (act === 'play') labPlay();
      else if (act === 'step') labStep(1);
      else if (act === 'back') labStep(-1);
      else if (act === 'reset') labReset();
    });
    $('labWrap').addEventListener('change', e => {
      const sel = e.target.closest('select[data-lab]');
      if (!sel) return;
      const key = sel.dataset.lab;
      lab.cfg[key] = (key === 'ssthresh' || key === 'lossRound') ? +sel.value : sel.value;
      labRebuild();
    });

    $('playBtn').addEventListener('click', play);
    $('stepBtn').addEventListener('click', () => stepOne(1));
    $('prevBtn').addEventListener('click', () => stepOne(-1));
    $('resetBtn').addEventListener('click', resetAll);
    $('sumReset').addEventListener('click', resetAll);
    $('speedControl').addEventListener('click', e => {
      const b = e.target.closest('button[data-speed]');
      if (!b) return;
      state.speed = +b.dataset.speed;
      $('speedControl').querySelectorAll('button').forEach(x => x.classList.toggle('active', x === b));
    });

    $('packetBody').addEventListener('click', e => {
      const tr = e.target.closest('tr[data-i]');
      if (!tr) return;
      const i = +tr.dataset.i;
      state.playing = false; if (state.timer) clearTimeout(state.timer); updatePlayBtn();
      state.index = i;
      renderCurrent();
      openModal(i);
    });

    $('themeBtn').addEventListener('click', () => {
      state.theme = state.theme === 'light' ? 'dark' : 'light';
      document.documentElement.setAttribute('data-theme', state.theme);
      $('themeBtn').querySelector('use').setAttribute('href', state.theme === 'dark' ? '#i-sun' : '#i-moon');
      if (!$('detailModal').hidden) renderHex(dlgPacket);
      if (state.view === 'lab') renderLab();
    });
    $('langBtn').addEventListener('click', () => {
      state.lang = state.lang === 'zh' ? 'en' : 'zh';
      $('langBtn').querySelector('span').textContent = state.lang === 'zh' ? 'Zh' : 'En';
      document.documentElement.lang = state.lang === 'zh' ? 'zh-CN' : 'en';
      document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = T(el.dataset.i18n); });
      renderNetwork(); renderCurrent();
      if (!$('detailModal').hidden) openModal(state.dlgIndex);
    });

    // modal
    $('dlgClose').addEventListener('click', closeModal);
    $('modalBackdrop').addEventListener('click', closeModal);
    $('dlgPrev').addEventListener('click', () => navDlg(-1));
    $('dlgNext').addEventListener('click', () => navDlg(1));

    $('fieldsPane').addEventListener('click', e => {
      const head = e.target.closest('.layer-card-head');
      if (head) { head.closest('.layer-card').classList.toggle('collapsed'); return; }
      const row = e.target.closest('.field-row');
      if (!row) return;
      state.lockedField = state.lockedField === row ? null : row;
      highlightField(state.lockedField || row);
    });
    $('fieldsPane').addEventListener('mouseover', e => {
      const row = e.target.closest('.field-row');
      if (row && !state.lockedField) highlightField(row);
    });
    $('fieldsPane').addEventListener('mouseleave', () => {
      if (!state.lockedField) { highlightField(null); highlightBytes(0, 0, false); }
    });

    $('hexDump').addEventListener('mouseover', e => {
      const cell = e.target.closest('[data-i]');
      if (!cell || state.lockedField) return;
      const row = fieldForByte(+cell.dataset.i);
      if (row) highlightField(row);
    });
    $('hexDump').addEventListener('click', e => {
      const cell = e.target.closest('[data-i]');
      if (!cell) return;
      const row = fieldForByte(+cell.dataset.i);
      state.lockedField = row || null;
      highlightField(row);
      if (row) row.scrollIntoView({ block: 'nearest' });
    });
    $('layerStrip').addEventListener('click', e => {
      const seg = e.target.closest('.ls-seg');
      if (!seg) return;
      const li = +seg.dataset.li, l = dlgPacket.layers[li];
      $('layerStrip').querySelectorAll('.ls-seg').forEach(x => x.classList.toggle('dim', x !== seg));
      $('fieldsPane').querySelectorAll('.layer-card').forEach(x => x.classList.toggle('dim', x.id !== 'lc_' + li));
      highlightBytes(l.base, l.bytes.length, true);
      const card = $('lc_' + li);
      if (card) { card.classList.remove('collapsed'); card.scrollIntoView({ block: 'nearest', behavior: 'smooth' }); }
    });
    $('layerStrip').addEventListener('dblclick', () => {
      $('layerStrip').querySelectorAll('.ls-seg').forEach(x => x.classList.remove('dim'));
      $('fieldsPane').querySelectorAll('.layer-card').forEach(x => x.classList.remove('dim'));
      highlightBytes(0, 0, false);
    });

    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && !$('detailModal').hidden) { closeModal(); return; }
      if (!$('detailModal').hidden) {
        if (e.key === 'ArrowLeft') navDlg(-1);
        if (e.key === 'ArrowRight') navDlg(1);
        return;
      }
      if (state.view === 'lab') {
        if (e.key === ' ') { e.preventDefault(); labPlay(); return; }
        if (e.key === 'ArrowRight') { e.preventDefault(); labStep(1); return; }
        if (e.key === 'ArrowLeft') { e.preventDefault(); labStep(-1); return; }
      }
      if (e.key === ' ') { e.preventDefault(); play(); }
      if (e.key === 'ArrowRight') { e.preventDefault(); stepOne(1); }
      if (e.key === 'ArrowLeft') { e.preventDefault(); stepOne(-1); }
    });
  }

  /* ---------------- 初始化 ---------------- */
  function init() {
    document.documentElement.setAttribute('data-theme', 'light');
    bind();
    updatePlayBtn();
    renderNetwork();
    state.index = sc().packets.length - 1; // 首屏直接展示「课程完成」态
    state.finished.add('http');
    syncLabTab();
    renderCurrent();
    renderNetworkState();

    // 深链接：#sc=tcpcc&view=lab&packet=1 可直接定位到某个课程 / 视图 / 报文
    const q = new URLSearchParams(location.hash.replace(/^#/, ''));
    if (q.get('sc') && D.scenarios[q.get('sc')]) switchScenario(q.get('sc'));
    const v = q.get('view');
    if (v === 'network' || v === 'sequence' || v === 'lab') {
      const tab = document.querySelector('.view-tabs button[data-view="' + v + '"]');
      if (tab && !tab.hidden) setView(v);
    }
    // #sc=tcpcc&view=lab&lab=8 可直接停在第 8 个 RTT
    const lr = parseInt(q.get('lab'), 10);
    if (!isNaN(lr) && state.view === 'lab') {
      lab.at = clamp(lr, 0, lab.rounds.length);
      if (lab.at > 0) labSyncTable(lab.at);
      renderLab();
    }
    const n = parseInt(q.get('packet'), 10);
    if (!isNaN(n)) openModal(clamp(n, 0, sc().packets.length - 1));
  }
  init();
})();
