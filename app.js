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
      labReady: '尚未开始', labDone: '本轮实验结束，可重置后换参数再跑',
      swLabView: '自学习实验', stpLabView: '生成树实验',
      xlTitleSw: '交换机自学习实验台', xlTitleStp: '生成树协议实验台',
      xlNoteSw: '下方抓包表记录默认帧序列（标准自学习）；这里改参数或发送自定义帧会重算转发表，抓包表只做对应定位。',
      xlNoteStp: '下方抓包表记录默认参数（根桥 SW1 / 故障 SW1—SW2 / STP）下的一次过程；这里改参数会重算端口角色。',
      xlChartSw: '帧转发路径 · 蓝=入端口 · 绿/橙=出端口 · 红=过滤',
      xlChartStp: '二层拓扑与端口角色 · 实线=转发 · 红虚线=阻塞 · 灰虚线=故障',
      xlCfgScript: '演示序列', xlScriptLearn: '标准自学习 (9 帧)', xlScriptAging: '表项老化', xlScriptMove: '主机迁移',
      xlCfgAging: '表项老化', xlAgingOff: '300 s（默认）', xlAgingShort: '2 帧即过期',
      xlCfgSrc: '源主机', xlCfgDst: '目的主机', xlCfgIn: '入端口', xlInAuto: '按主机自动',
      xlBroadcast: '广播 FF:FF…', xlSend: '发送自定义帧',
      xlTable: 'MAC 转发表', xlThMac: 'MAC 地址', xlThPort: '端口', xlThAge: '静默帧数', xlTableEmpty: '（空表）',
      xlAction: '转发决策', xlActFlood: '未知单播 · 泛洪', xlActForward: '已知单播 · 单播转发',
      xlActFilter: '同端口 · 过滤', xlActBcast: '广播 · 泛洪',
      xlLearnAdd: '新建表项', xlLearnMove: '表项覆盖（迁移）', xlLearnRefresh: '仅刷新老化',
      xlTableNum: '表项数', xlFloodNum: '泛洪次数', xlFwdNum: '单播次数', xlFilterNum: '过滤次数',
      xlIngress: '入端口', xlEgress: '出端口', xlStep: '当前帧', xlPhase: '当前阶段',
      xlCfgRoot: '根桥（优先级 4096）', xlCfgFail: '故障链路', xlFailNone: '无故障（对照）',
      xlCfgProto: '协议版本', xlProtoStp: 'STP · 802.1D', xlProtoRstp: 'RSTP · 802.1w',
      xlRootMetric: '根桥', xlBlockMetric: '阻塞端口', xlCostMetric: '最大根开销', xlConvMetric: '收敛耗时',
      xlRoles: '端口角色', xlRoleDP: '指定端口 DP', xlRoleRP: '根端口 RP', xlRoleALT: '阻塞 ALT', xlRoleDOWN: '链路中断',
      xlLegendFwd: '转发链路', xlLegendBlk: '阻塞链路', xlLegendFail: '故障链路',
      xlBpdu: 'BPDU 流向', xlTcnFlow: 'TCN 上报', xlRootBadge: 'ROOT',
      xlPhBoot: '各自称根', xlPhElect: '根桥选举', xlPhRootPort: '选根端口', xlPhDesignated: '选指定端口',
      xlPhBlock: '阻塞冗余端口', xlPhStable: '稳定转发', xlPhFail: '链路故障', xlPhDetect: '感知变化 · TCN',
      xlPhTcn: '根桥通告 TC', xlPhConverge: '重新收敛', xlPhFinal: '新树稳定',
      xlNoFrame: '尚未发送帧', xlStepDone: '本轮实验结束，可重置后换参数再跑', xlTimeline: '步骤时间轴（点击跳转）',
      cdLabView: 'CSMA/CD 实验', wfLabView: 'CSMA/CA 实验',
      cdTitle: 'CSMA/CD 共享介质实验台', wfTitle: '802.11 CSMA/CA 实验台',
      cdNote: '下方抓包表记录默认参数（2 站点 / 64 B 最短帧 / BEB）下的一次过程；此处改参数会重算时隙推演，抓包表只做对应定位。',
      wfNote: '下方抓包表记录一次完整接入与数据交换；此处改参数会重算 DIFS / 退避 / RTS-CTS / ACK 的时隙推演。',
      cdChart: '共享总线时隙推演 · 每行一个站点 · 点击任一列可跳转',
      wfChart: '无线信道时隙推演 · NAV 为虚拟载波侦听 · 点击任一列可跳转',
      cdCfgHosts: '争用站点数', cdCfgFrame: '帧长', cdCfgBackoff: '退避算法',
      cdFrameMin: '64 B · 合法最短帧', cdFrameShort: '40 B · 违规过短帧', cdFrameLong: '1518 B · 最大帧',
      cdBeb: 'BEB · 指数退避', cdFixed: '固定窗口 (0~3)', cdNone: '不退避（立即重发）',
      cdMetricStep: '当前时隙', cdMetricColl: '冲突次数', cdMetricSucc: '成功帧', cdMetricWin: '退避窗口',
      cdMetricFrame: '帧长 / 争用期', cdMetricAttempt: '重传次数', cdFrameCheck: '最短帧长校验',
      cdOk: '≥ 512 bit · 冲突可检出', cdBad: '< 512 bit · 会出现迟到冲突',
      cdTable: '站点退避状态', cdThSite: '站点', cdThRetry: '重传', cdThK: 'k', cdThR: 'r', cdThState: '状态',
      cdMedium: '介质', cdMinLine: '争用期 512 bit = 51.2 μs = 64 B',
      wfCfgStations: '站点数', wfCfgRts: 'RTS / CTS', wfCfgHidden: '隐藏节点', wfCfgCw: '竞争窗口',
      wfRtsOff: '关闭（直接发 DATA）', wfRtsOn: '开启（先预约信道）',
      wfHiddenOff: '无（彼此可听）', wfHiddenOn: '有（互相听不到）',
      wfCw15: 'CW 15 · 4 槽示意', wfCw63: 'CW 63 · 8 槽示意',
      wfMetricPhase: '当前阶段', wfMetricNav: 'NAV 预留', wfMetricCw: '当前 CW', wfMetricIfs: 'DIFS / SIFS',
      wfTable: '站点 / AP 状态', wfThSite: '节点', wfThBackoff: '退避', wfThNav: 'NAV', wfThState: '状态',
      wfMedium: '信道', wfNavLine: 'NAV · 虚拟载波侦听'
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
      labReady: 'Not started', labDone: 'Run complete — reset and try another configuration',
      swLabView: 'MAC Learning Lab', stpLabView: 'STP Lab',
      xlTitleSw: 'Switch MAC Learning Lab', xlTitleStp: 'Spanning Tree Protocol Lab',
      xlNoteSw: 'The capture table below records the default frame sequence. Changing parameters or sending a custom frame here recomputes the forwarding table only.',
      xlNoteStp: 'The capture table below shows one run with default settings (root SW1 / failure SW1—SW2 / STP). Changing parameters here recomputes port roles.',
      xlChartSw: 'Frame path · blue = ingress · green/orange = egress · red = filtered',
      xlChartStp: 'Layer-2 topology & port roles · solid = forwarding · red dashed = blocked · grey dashed = failed',
      xlCfgScript: 'Frame sequence', xlScriptLearn: 'Standard learning (9 frames)', xlScriptAging: 'Table aging', xlScriptMove: 'Host move',
      xlCfgAging: 'Aging', xlAgingOff: '300 s (default)', xlAgingShort: 'Expires in 2 frames',
      xlCfgSrc: 'Source host', xlCfgDst: 'Destination', xlCfgIn: 'Ingress port', xlInAuto: 'Auto by host',
      xlBroadcast: 'Broadcast', xlSend: 'Send custom frame',
      xlTable: 'MAC forwarding table', xlThMac: 'MAC address', xlThPort: 'Port', xlThAge: 'Idle frames', xlTableEmpty: '(empty)',
      xlAction: 'Forwarding decision', xlActFlood: 'Unknown unicast · flood', xlActForward: 'Known unicast · forward',
      xlActFilter: 'Same port · filter', xlActBcast: 'Broadcast · flood',
      xlLearnAdd: 'New entry', xlLearnMove: 'Entry overwritten (move)', xlLearnRefresh: 'Timer refreshed',
      xlTableNum: 'Table entries', xlFloodNum: 'Flood count', xlFwdNum: 'Unicast count', xlFilterNum: 'Filtered count',
      xlIngress: 'Ingress', xlEgress: 'Egress', xlStep: 'Current frame', xlPhase: 'Current stage',
      xlCfgRoot: 'Root bridge (priority 4096)', xlCfgFail: 'Failed link', xlFailNone: 'No failure (control)',
      xlCfgProto: 'Protocol', xlProtoStp: 'STP · 802.1D', xlProtoRstp: 'RSTP · 802.1w',
      xlRootMetric: 'Root bridge', xlBlockMetric: 'Blocked ports', xlCostMetric: 'Max root cost', xlConvMetric: 'Convergence',
      xlRoles: 'Port roles', xlRoleDP: 'Designated DP', xlRoleRP: 'Root port RP', xlRoleALT: 'Blocking ALT', xlRoleDOWN: 'Link down',
      xlLegendFwd: 'Forwarding', xlLegendBlk: 'Blocked', xlLegendFail: 'Failed',
      xlBpdu: 'BPDU flow', xlTcnFlow: 'TCN upstream', xlRootBadge: 'ROOT',
      xlPhBoot: 'All claim root', xlPhElect: 'Root election', xlPhRootPort: 'Root ports', xlPhDesignated: 'Designated ports',
      xlPhBlock: 'Blocking', xlPhStable: 'Steady state', xlPhFail: 'Link failure', xlPhDetect: 'Detection · TCN',
      xlPhTcn: 'Root TC flood', xlPhConverge: 'Reconvergence', xlPhFinal: 'New tree stable',
      xlNoFrame: 'No frame yet', xlStepDone: 'Run complete — reset and try another configuration', xlTimeline: 'Step timeline (click to jump)',
      cdLabView: 'CSMA/CD Lab', wfLabView: 'CSMA/CA Lab',
      cdTitle: 'CSMA/CD Shared Medium Lab', wfTitle: '802.11 CSMA/CA Lab',
      cdNote: 'The capture table below records one default run (2 stations / 64 B minimum frame / BEB). Changing parameters here recomputes the slot timeline; the table only jumps to the matching frame.',
      wfNote: 'The capture table below shows one full association and data exchange. Changing parameters here recomputes the DIFS / backoff / RTS-CTS / ACK timeline.',
      cdChart: 'Shared bus slot timeline · one row per station · click any column to jump',
      wfChart: 'Wireless channel timeline · NAV = virtual carrier sensing · click any column to jump',
      cdCfgHosts: 'Contending stations', cdCfgFrame: 'Frame length', cdCfgBackoff: 'Backoff algorithm',
      cdFrameMin: '64 B · legal minimum', cdFrameShort: '40 B · illegal runt', cdFrameLong: '1518 B · maximum',
      cdBeb: 'BEB (exponential)', cdFixed: 'Fixed window (0–3)', cdNone: 'No backoff (retry at once)',
      cdMetricStep: 'Current slot', cdMetricColl: 'Collisions', cdMetricSucc: 'Frames delivered', cdMetricWin: 'Backoff window',
      cdMetricFrame: 'Frame / contention', cdMetricAttempt: 'Retries', cdFrameCheck: 'Minimum frame check',
      cdOk: '≥ 512 bit · collision detectable', cdBad: '< 512 bit · late collision',
      cdTable: 'Station backoff state', cdThSite: 'Station', cdThRetry: 'Retry', cdThK: 'k', cdThR: 'r', cdThState: 'State',
      cdMedium: 'Medium', cdMinLine: 'Contention period 512 bit = 51.2 μs = 64 B',
      wfCfgStations: 'Stations', wfCfgRts: 'RTS / CTS', wfCfgHidden: 'Hidden node', wfCfgCw: 'Contention window',
      wfRtsOff: 'Off (send DATA directly)', wfRtsOn: 'On (reserve the channel first)',
      wfHiddenOff: 'None (all hear each other)', wfHiddenOn: 'Present (mutually deaf)',
      wfCw15: 'CW 15 · 4 slots', wfCw63: 'CW 63 · 8 slots',
      wfMetricPhase: 'Current stage', wfMetricNav: 'NAV reserved', wfMetricCw: 'Current CW', wfMetricIfs: 'DIFS / SIFS',
      wfTable: 'Station / AP state', wfThSite: 'Node', wfThBackoff: 'Backoff', wfThNav: 'NAV', wfThState: 'State',
      wfMedium: 'Channel', wfNavLine: 'NAV · virtual carrier sensing'
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
    '发送窗口': 'Send window', 'MSS / RTT': 'MSS / RTT',
    '工作层次': 'Layer', '学习依据': 'Learns from', '转发依据': 'Forwards by',
    '三种动作': 'Three actions', '默认老化': 'Default aging', '表项容量': 'Table capacity',
    '协议标准': 'Standard', 'BPDU 组播': 'BPDU multicast', 'LLC 地址': 'LLC SAP',
    'Bridge ID': 'Bridge ID', '链路开销': 'Link cost', 'STP 定时器': 'STP timers', '收敛时间': 'Convergence',
    '介质访问': 'Medium access', '争用期': 'Contention period', '最短帧长': 'Minimum frame',
    '强化冲突': 'Jam signal', '退避窗口': 'Backoff window', '最大重传': 'Max retries',
    '帧间隙': 'Interframe gap', '帧间隔': 'Interframe spaces', '竞争窗口': 'Contention window',
    '确认机制': 'Acknowledgement', '地址字段': 'Address fields', '安全机制': 'Security', '隐藏节点': 'Hidden node'
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
    tcpcc: '拥塞窗口已收敛', switch: 'MAC 转发表已建立', stp: '无环生成树已建立',
    csma: '共享介质争用已完成', wifi: '无线接入与确认已完成'
  };
  const sc = () => D.scenarios[state.scenario];
  const pk = () => sc().packets[state.index] || null;

  /* ---------------- 节点坐标与 SVG 图形 ---------------- */
  const POS = {
    url: { x: 218, y: 92 }, client: { x: 245, y: 352 }, gateway: { x: 522, y: 182 },
    dns: { x: 838, y: 96 }, dhcp: { x: 838, y: 96 }, web: { x: 838, y: 350 },
    target: { x: 838, y: 350 }, mail: { x: 838, y: 350 }, ftp: { x: 838, y: 350 },
    r1: { x: 220, y: 300 }, r3: { x: 820, y: 300 },
    sw: { x: 500, y: 250 },
    ha: { x: 150, y: 96 }, hb: { x: 150, y: 410 }, hc: { x: 850, y: 96 }, hd: { x: 850, y: 410 },
    s1: { x: 270, y: 130 }, s2: { x: 730, y: 130 }, s3: { x: 500, y: 382 },
    bus: { x: 500, y: 250 }, sta: { x: 200, y: 355 }, sta2: { x: 200, y: 120 },
    ap: { x: 500, y: 235 }, ds: { x: 840, y: 235 }
  };
  const XL_HOST_NODES = ['ha', 'hb', 'hc', 'hd', 'sta', 'sta2'];
  const XL_SW_NODES = ['sw', 's1', 's2', 's3'];
  const ROUTER_NODES = ['gateway', 'r1', 'r3'];
  const NODE_NAMES = {
    client: 'nodeClient', gateway: 'nodeGateway', dns: 'nodeDns', dhcp: 'nodeDhcp',
    web: 'nodeWeb', target: 'nodeTarget', mail: 'nodeMail', ftp: 'nodeFtp',
    r1: 'nodeR1', r3: 'nodeR3', sw: 'nodeWeb', ha: 'nodeWeb', hb: 'nodeWeb',
    hc: 'nodeWeb', hd: 'nodeWeb', s1: 'nodeWeb', s2: 'nodeWeb', s3: 'nodeWeb',
    bus: 'nodeWeb', sta: 'nodeWeb', sta2: 'nodeWeb', ap: 'nodeWeb', ds: 'nodeWeb'
  };
  const NODE_IPS = {
    client: D.ipClient, gateway: '192.168.1.1', dns: D.ipDns, dhcp: '192.168.1.1',
    web: D.ipWeb, target: D.ipWeb, mail: '198.51.100.25', ftp: '198.51.100.40',
    r1: '10.0.12.1', r3: '10.0.23.3', sw: '4 × 100 Mbps', s1: '', s2: '', s3: '',
    ha: '', hb: '', hc: '', hd: '', bus: '', sta: '', sta2: '', ap: '', ds: ''
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
  function switchSvg(n) {
    const count = n || 4, pw = 26, gap = 40, left = -((count - 1) * gap + pw) / 2;
    return '' +
      '<rect class="node-shape" x="-98" y="-40" width="196" height="80" rx="7"/>' +
      '<rect class="node-detail" x="-88" y="-30" width="176" height="60" rx="4"/>' +
      '<path class="node-faint" d="M-84,-16 h168"/>' +
      '<text class="node-tag" x="0" y="-21" text-anchor="middle">SWITCH · L2</text>' +
      Array.from({ length: count }, (_, i) => {
        const x = left + i * gap;
        return '<rect class="node-detail" x="' + x + '" y="2" width="' + pw + '" height="16" rx="2"/>' +
          '<text class="node-tag" x="' + (x + pw / 2) + '" y="14" text-anchor="middle">P' + (i + 1) + '</text>' +
          '<path class="node-faint" d="M' + x + ',24 l20,-10"/>';
      }).join('');
  }
  /* 共享同轴总线 / 集线器：一条贯穿的总线 + 四个抽头 */
  function busSvg() {
    return '' +
      '<rect class="node-shape" x="-112" y="-38" width="224" height="76" rx="8"/>' +
      '<path class="node-detail" style="stroke-width:4" d="M-98,0 h196"/>' +
      '<text class="node-tag" x="0" y="-22" text-anchor="middle">SHARED BUS · 10 Mbps</text>' +
      [-72, -24, 24, 72].map((x, i) =>
        '<circle class="node-glow" cx="' + x + '" cy="0" r="5"/>' +
        '<path class="node-detail" d="M' + x + ',6 v14"/>' +
        '<text class="node-tag" x="' + x + '" y="30" text-anchor="middle">P' + (i + 1) + '</text>').join('');
  }
  /* 无线 AP：机身上两根天线 + 无线电波弧 */
  function apSvg() {
    return '' +
      '<path class="node-detail" style="stroke-width:2" d="M-26,-44 q10,-14 20,0 M-4,-44 q10,-14 20,0"/>' +
      '<path class="node-faint" d="M-34,-58 a42,42 0 0 1 68,0 M-46,-70 a58,58 0 0 1 92,0"/>' +
      '<path class="node-detail" d="M-16,-44 v14 M16,-44 v14"/>' +
      '<rect class="node-shape" x="-66" y="-30" width="132" height="60" rx="7"/>' +
      '<rect class="node-detail" x="-56" y="-20" width="112" height="40" rx="3"/>' +
      '<text class="node-tag" x="0" y="-4" text-anchor="middle">AP · BSSID</text>' +
      '<circle class="node-glow" cx="-38" cy="10" r="3.5"/><circle class="node-glow" cx="-24" cy="10" r="3.5"/>' +
      '<circle class="node-glow" cx="-10" cy="10" r="3.5"/>' +
      '<path class="node-faint" d="M10,10 h44"/>';
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
    const s = sc();
    const p1 = (s.pos && s.pos[a]) || POS[a], p2 = (s.pos && s.pos[b]) || POS[b], g = POS.gateway;
    if (!p1 || !p2) return '';
    if (sc().links) return 'M' + p1.x + ',' + p1.y + ' L' + p2.x + ',' + p2.y;
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
    // links：优先使用场景显式给出的物理链路（交换 / STP 拓扑），否则从报文推导
    const pairs = [];
    if (s.links) {
      s.links.forEach(l => pairs.push({ key: [l[0], l[1]].sort().join('|'), a: l[0], b: l[1] }));
    } else {
      s.packets.forEach(p => {
        const key = [p.from, p.to].sort().join('|');
        if (p.from !== p.to && !pairs.some(x => x.key === key)) pairs.push({ key, a: p.from, b: p.to });
      });
    }
    const wirelessKeys = (s.wirelessLinks || []).map(l => l.slice().sort().join('|'));
    $('linkLayer').innerHTML = pairs.map(x =>
      '<path class="link-line' + (wirelessKeys.indexOf(x.key) >= 0 ? ' wireless' : '') +
      '" id="link_' + x.key.replace('|', '_') + '" data-a="' + x.a + '" data-b="' + x.b +
      '" d="' + linkPath(x.a, x.b) + '" marker-end="url(#arrowHeadDim)"/>'
    ).join('');

    // nodes
    $('nodeLayer').innerHTML = s.nodes.map(key => {
      const pos = (s.pos && s.pos[key]) || POS[key];
      if (!pos) return '';
      const inner = key === 'url' ? urlSvg(s) :
        key === 'bus' ? busSvg() :
          key === 'ap' ? apSvg() :
            (key === 'client' || XL_HOST_NODES.indexOf(key) >= 0) ? laptopSvg() :
              XL_SW_NODES.indexOf(key) >= 0 ? switchSvg(key === 'sw' ? 4 : (key === 's2' ? 2 : 3)) :
                serverSvg(ROUTER_NODES.indexOf(key) >= 0 ? 'gateway' : key);
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
      const route = p.via ? [[p.from, p.via], [p.via, p.to]] : [[p.from, p.to]];
      route.forEach(pair => {
        const el = $('link_' + pair.slice().sort().join('_'));
        if (el) el.classList.add('active');
      });
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

  /* ---------------- 通用实验台：按课程分派仿真内核与渲染器 ---------------- */
  const lab = {
    cfg: Object.assign({}, D.labDefault),
    rounds: D.labSimulate(D.labDefault),
    at: 0, playing: false, timer: null,
    xl: { src: 'A', dst: 'B', in: 'auto' }
  };
  const labDef = () => LAB_DEFS[state.scenario];

  function labStop() {
    lab.playing = false;
    if (lab.timer) clearTimeout(lab.timer);
    lab.timer = null;
  }
  /* 切换课程时载入该实验的默认参数与步骤，避免不同实验共用一份状态 */
  function labLoad(id) {
    const def = LAB_DEFS[id];
    if (!def) return;
    labStop();
    lab.at = 0;
    lab.cfg = def.cfg();
    lab.rounds = def.simulate(lab.cfg);
  }
  /* 把实验进度同步到抓包表 / 总结 / 拓扑（不重绘实验面板，避免递归） */
  function labSyncTable(r) {
    const s = sc(), def = labDef();
    if (!s || !def) return;
    const step = lab.rounds[r - 1];
    let idx = -1;
    if (step && step.p != null) idx = step.p;
    else s.packets.forEach((p, i) => { if (p.rtt === r) idx = i; });
    if (idx < 0 || idx >= s.packets.length) return;
    state.index = idx;
    renderHeader(); renderSidebar(); renderTable(); renderSummary(); renderNetworkState();
    $('visualHint').textContent = pk().title + '  ·  ' + pk().info;
  }
  function labRebuild() {
    const def = labDef();
    if (!def) return;
    labStop(); lab.at = 0;
    lab.rounds = def.simulate(lab.cfg);
    state.index = 0;
    renderHeader(); renderSidebar(); renderTable(); renderSummary(); renderNetworkState();
    $('visualHint').textContent = T('labEmpty');
    renderLab();
  }
  function labPlay() {
    const def = labDef();
    if (!def) return;
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
    if (!labDef()) return;
    labStop();
    lab.at = clamp(lab.at + (dir || 1), 0, lab.rounds.length);
    if (lab.at > 0) labSyncTable(lab.at);
    renderLab();
  }
  function labReset() {
    const def = labDef();
    if (!def) return;
    labStop(); lab.at = 0;
    lab.rounds = def.simulate(lab.cfg);
    state.index = 0;
    renderHeader(); renderSidebar(); renderTable(); renderSummary(); renderNetworkState();
    $('visualHint').textContent = T('labEmpty');
    renderLab();
  }
  function syncLabTab() {
    const def = labDef();
    $('labTab').hidden = !def;
    if (def) {
      const label = $('labTab').querySelector('[data-i18n]');
      label.dataset.i18n = def.tab;
      label.textContent = T(def.tab);
    }
    if (!def && state.view === 'lab') setView('network');
  }
  /* 自定义帧：追加一帧并重算转发表，让「自学习」可以自己动手试 */
  function xlSendFrame() {
    if (state.scenario !== 'switch') return;
    const src = lab.xl.src, dst = lab.xl.dst, inV = lab.xl.in;
    if (!src || !dst) return;
    const frames = (lab.cfg.frames || D.swScripts[lab.cfg.script] || D.swScripts.learn).slice();
    const f = { src: src, dst: dst };
    if (inV && inV !== 'auto') f.in = +inV;
    frames.push(f);
    lab.cfg.frames = frames;
    labStop();
    lab.rounds = D.swSimulate(lab.cfg);
    lab.at = lab.rounds.length;
    labSyncTable(lab.at);
    renderLab();
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

  /* ---------------- 实验台通用零件 ---------------- */
  function xlOpts(key, list) {
    return '<select data-lab="' + key + '">' + list.map(x =>
      '<option value="' + esc(x.v) + '"' + (String(lab.cfg[key]) === String(x.v) ? ' selected' : '') +
      '>' + esc(x.t) + '</option>').join('') + '</select>';
  }
  function xlCtrls(items, wideLast) {
    return '<div class="lab-ctrl">' + items.map((it, i) =>
      '<label' + (wideLast && i === items.length - 1 ? ' class="wide"' : '') + '>' +
      esc(it.k) + xlOpts(it.key, it.list) + '</label>').join('') + '</div>';
  }
  function xlButtons() {
    return '<div class="lab-btns">' +
      '<button data-lab-act="back" title="' + esc(T('labBack')) + '"><svg><use href="#i-left"/></svg></button>' +
      '<button class="primary" data-lab-act="play"><svg><use href="#' + (lab.playing ? 'i-pause' : 'i-play') +
      '"/></svg>' + esc(lab.playing ? T('labPause') : T('labPlay')) + '</button>' +
      '<button data-lab-act="step" title="' + esc(T('labStep')) + '"><svg><use href="#i-step"/></svg></button>' +
      '<button data-lab-act="reset" title="' + esc(T('labReset')) + '"><svg><use href="#i-reset"/></svg></button>' +
      '</div>';
  }
  function xlMetric(k, v, wide) {
    return '<div class="lab-metric' + (wide ? ' wide' : '') + '"><span class="k">' + esc(k) +
      '</span><span class="v">' + esc(v) + '</span></div>';
  }
  function xlLogs(items) {
    const body = items.slice(-7).reverse().map(x =>
      '<div class="lab-log-item ' + (x.evt ? 'evt ' : '') + (x.r === lab.at ? 'cur' : '') + '">' +
      '<b>' + esc(x.badge) + '</b><span>' + esc(x.text) + '</span></div>').join('');
    return '<div class="lab-log-title">' + esc(T('labLog')) + '</div>' +
      '<div class="lab-log">' + (body || '<div class="lab-empty">' + esc(T('labEmpty')) + '</div>') + '</div>';
  }
  function xlTimeline(rs, x, y, w, h) {
    const n = rs.length, gap = 4;
    const bw = Math.min(38, (w - gap * (n - 1)) / n);
    const start = x + (w - (bw * n + gap * (n - 1))) / 2;
    let o = '<text class="xl-tick" x="' + x + '" y="' + (y - 6) + '">' + esc(T('xlTimeline')) + '</text>';
    rs.forEach((r, i) => {
      const bx = start + i * (bw + gap);
      o += '<g class="xl-tl-g' + (r.r <= lab.at ? ' on' : '') + '" data-lab-r="' + r.r + '">' +
        '<rect class="xl-tl" x="' + bx + '" y="' + y + '" width="' + bw + '" height="' + h + '" rx="3"/>' +
        '<text class="xl-tl-t" x="' + (bx + bw / 2) + '" y="' + (y + h / 2 + 3.5) + '">' + r.r + '</text></g>';
    });
    return o;
  }
  function xlArrow(a, b, t, color) {
    const x = a.x + (b.x - a.x) * t, y = a.y + (b.y - a.y) * t;
    const ang = Math.atan2(b.y - a.y, b.x - a.x) * 180 / Math.PI;
    return '<path class="xl-arrow" style="fill:' + color + '" d="M0,0 L-11,-5 L-11,5 Z" ' +
      'transform="translate(' + x + ',' + y + ') rotate(' + ang + ')"/>';
  }
  function xlBox(x, y, w, h, cls) {
    return '<rect class="' + cls + '" x="' + (x - w / 2) + '" y="' + (y - h / 2) +
      '" width="' + w + '" height="' + h + '" rx="6"/>';
  }

  /* ---------------- 交换机自学习实验：拓扑图 ---------------- */
  const SW_X = { A: { x: 100, y: 74 }, B: { x: 100, y: 286 }, C: { x: 620, y: 74 }, D: { x: 620, y: 286 } };
  const SW_PT = { 1: { x: 274, y: 150 }, 2: { x: 274, y: 202 }, 3: { x: 446, y: 150 }, 4: { x: 446, y: 202 } };
  const SW_PORT_HOST = { 1: 'A', 2: 'B', 3: 'C', 4: 'D' };

  function swChartHTML(rs) {
    const cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const en = state.lang === 'en';
    let o = '<text class="xl-chart-title" x="16" y="18">' + esc(T('xlChartSw')) + '</text>';

    [1, 2, 3, 4].forEach(p => {
      const h = SW_X[SW_PORT_HOST[p]], q = SW_PT[p];
      let cls = 'xl-link';
      if (cur) {
        if (cur.inPort === p) cls = 'xl-link in';
        else if (cur.egress.indexOf(p) >= 0) cls = cur.action === 'forward' ? 'xl-link out' : 'xl-link outflood';
      }
      o += '<path class="' + cls + '" d="M' + h.x + ',' + h.y + ' L' + q.x + ',' + q.y + '"/>';
    });
    if (cur) {
      o += xlArrow(SW_X[SW_PORT_HOST[cur.inPort]], SW_PT[cur.inPort], 0.84, 'var(--blue-2)');
      cur.egress.forEach(p => o += xlArrow(SW_PT[p], SW_X[SW_PORT_HOST[p]], 0.84,
        cur.action === 'forward' ? 'var(--green)' : 'var(--amber)'));
    }

    o += '<rect class="xl-sw-box" x="274" y="116" width="172" height="116" rx="8"/>';
    o += '<text class="xl-sw-title" x="360" y="142" text-anchor="middle">SW1</text>';
    o += '<text class="xl-tick" x="360" y="158" text-anchor="middle">' +
      esc(en ? 'MAC forwarding table' : '源 MAC 学习 → 目的查表') + '</text>';
    if (cur) {
      const lt = { add: T('xlLearnAdd'), move: T('xlLearnMove'), refresh: T('xlLearnRefresh') }[cur.learn];
      o += '<text class="xl-learn" x="360" y="226" text-anchor="middle">' +
        esc(cur.frame.src + ' ↔ P' + cur.inPort + ' · ' + lt) + '</text>';
    }
    if (cur && cur.action === 'filter') {
      o += '<path class="xl-cross" d="M349,174 l22,20 M371,174 l-22,20"/>';
      o += '<text class="xl-cross-t" x="360" y="212" text-anchor="middle">' + esc(en ? 'FILTERED' : '过滤丢弃') + '</text>';
    }

    [1, 2, 3, 4].forEach(p => {
      const q = SW_PT[p];
      const on = cur && (cur.inPort === p || cur.egress.indexOf(p) >= 0);
      o += '<circle class="xl-port' + (on ? ' on' : '') + '" cx="' + q.x + '" cy="' + q.y + '" r="11"/>';
      o += '<text class="xl-port-t" x="' + q.x + '" y="' + (q.y + 3) + '" text-anchor="middle">P' + p + '</text>';
    });

    Object.keys(SW_X).forEach(k => {
      const p = SW_X[k];
      const isSrc = cur && cur.frame.src === k;
      const isDst = cur && cur.egress.indexOf(D.swPort[k]) >= 0;
      o += xlBox(p.x, p.y, 118, 44, 'xl-node' + (isSrc ? ' src' : '') + (isDst ? ' dst' : ''));
      o += '<text class="xl-node-t" x="' + p.x + '" y="' + (p.y - 3) + '" text-anchor="middle">' +
        esc((en ? 'Host ' : '主机 ') + k) + '</text>';
      o += '<text class="xl-node-s" x="' + p.x + '" y="' + (p.y + 12) + '" text-anchor="middle">' +
        esc(D.swMac[k].slice(-8)) + '</text>';
    });

    const actTxt = cur ? {
      flood: T('xlActFlood'), forward: T('xlActForward'), filter: T('xlActFilter'), bcast: T('xlActBcast')
    }[cur.action] : T('xlNoFrame');
    const badgeColor = cur && cur.action === 'filter' ? 'var(--red)' :
      (cur && cur.action === 'forward' ? 'var(--green)' : 'var(--amber)');
    o += '<rect class="xl-badge" x="452" y="30" width="248" height="26" rx="5" style="stroke:' + badgeColor + '"/>';
    o += '<text class="xl-badge-t" x="576" y="47" text-anchor="middle" style="fill:' + badgeColor + '">' +
      esc(actTxt) + '</text>';
    o += '<text class="xl-tick" x="16" y="300">' + esc(en ?
      'Frame ' + (cur ? cur.r : 0) + ' / ' + rs.length + '  ·  table entries: ' + (cur ? cur.table.length : 0) :
      '第 ' + (cur ? cur.r : 0) + ' 帧 / 共 ' + rs.length + ' 帧  ·  表项 ' + (cur ? cur.table.length : 0) + ' 条') + '</text>';
    o += xlTimeline(rs, 16, 336, 688, 24);
    return o;
  }

  function swSideHTML(rs) {
    const cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const en = state.lang === 'en';
    const actTxt = cur ? {
      flood: T('xlActFlood'), forward: T('xlActForward'), filter: T('xlActFilter'), bcast: T('xlActBcast')
    }[cur.action] : T('xlNoFrame');
    const shortAct = { flood: en ? 'FLOOD' : '泛洪', forward: en ? 'FORWARD' : '单播', filter: en ? 'FILTER' : '过滤', bcast: en ? 'BROADCAST' : '广播' };

    const hostOpts = withBcast => D.swHosts.map(h =>
      '<option value="' + h + '"' + (lab.xl[withBcast ? 'dst' : 'src'] === h ? ' selected' : '') + '>' +
      esc((en ? 'Host ' : '主机 ') + h) + '</option>').join('') +
      (withBcast ? '<option value="FF"' + (lab.xl.dst === 'FF' ? ' selected' : '') + '>' + esc(T('xlBroadcast')) + '</option>' : '');
    const inOpts = '<option value="auto"' + (lab.xl.in === 'auto' ? ' selected' : '') + '>' + esc(T('xlInAuto')) + '</option>' +
      [1, 2, 3, 4].map(p => '<option value="' + p + '"' + (lab.xl.in === String(p) ? ' selected' : '') +
        '>P' + p + '</option>').join('');

    const rows = cur && cur.table.length ? cur.table.map(x =>
      '<tr' + ((cur.learn === 'add' || cur.learn === 'move') && cur.srcMac === x.mac ? ' class="hit"' : '') + '>' +
      '<td>' + esc(x.mac) + '</td><td>P' + x.port + '</td><td>' + x.age + '</td></tr>').join('')
      : '<tr><td colspan="3" class="xl-empty">' + esc(T('xlTableEmpty')) + '</td></tr>';

    const logs = rs.slice(0, lab.at).map(x => ({
      r: x.r, badge: 'F' + x.r,
      text: x.frame.src + '→' + (x.frame.dst === 'FF' ? 'FF' : x.frame.dst) + ' · P' + x.inPort +
        ' → ' + (x.egress.length ? 'P' + x.egress.join('/P') : '—') + ' · ' + shortAct[x.action],
      evt: x.action === 'flood' || x.learn === 'move'
    }));

    return '<div class="lab-panel-title">' + esc(T('xlTitleSw')) + '</div>' +
      '<div class="lab-note">' + esc(T('xlNoteSw')) + '</div>' +
      xlCtrls([
        { k: T('xlCfgScript'), key: 'script', list: [
          { v: 'learn', t: T('xlScriptLearn') }, { v: 'aging', t: T('xlScriptAging') }, { v: 'move', t: T('xlScriptMove') }] },
        { k: T('xlCfgAging'), key: 'aging', list: [
          { v: 'off', t: T('xlAgingOff') }, { v: 'short', t: T('xlAgingShort') }] }
      ]) +
      '<div class="xl-custom">' +
        '<label>' + esc(T('xlCfgSrc')) + '<select data-xl="src">' + hostOpts(false) + '</select></label>' +
        '<label>' + esc(T('xlCfgDst')) + '<select data-xl="dst">' + hostOpts(true) + '</select></label>' +
        '<label>' + esc(T('xlCfgIn')) + '<select data-xl="in">' + inOpts + '</select></label>' +
      '</div>' +
      '<button class="xl-send" data-xl-act="send">' + esc(T('xlSend')) + '</button>' +
      xlButtons() +
      '<div class="xl-table-title">' + esc(T('xlTable')) + '</div>' +
      '<table class="xl-table"><thead><tr><th>' + esc(T('xlThMac')) + '</th><th>' + esc(T('xlThPort')) +
        '</th><th>' + esc(T('xlThAge')) + '</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      '<div class="lab-metrics">' +
        xlMetric(T('xlStep'), (cur ? cur.r : 0) + ' / ' + rs.length) +
        xlMetric(T('xlTableNum'), cur ? cur.table.length : 0) +
        xlMetric(T('xlFloodNum'), cur ? cur.floods : 0) +
        xlMetric(T('xlFwdNum'), cur ? cur.forwards : 0) +
        xlMetric(T('xlFilterNum'), cur ? cur.filters : 0) +
        xlMetric(T('xlIngress'), cur ? 'P' + cur.inPort : '—') +
        xlMetric(T('xlAction'), actTxt, true) +
      '</div>' +
      xlLogs(logs) +
      (lab.at >= rs.length ? '<div class="lab-empty">' + esc(T('xlStepDone')) + '</div>' : '');
  }

  /* ---------------- 生成树实验：拓扑图 ---------------- */
  const STP_X = { s1: { x: 200, y: 104 }, s2: { x: 520, y: 104 }, s3: { x: 360, y: 252 }, ha: { x: 88, y: 252 }, hd: { x: 640, y: 252 } };
  const STP_PHASE_KEY = {
    boot: 'xlPhBoot', elect: 'xlPhElect', rootport: 'xlPhRootPort', designated: 'xlPhDesignated',
    block: 'xlPhBlock', stable: 'xlPhStable', fail: 'xlPhFail', detect: 'xlPhDetect',
    tcn: 'xlPhTcn', converge: 'xlPhConverge', final: 'xlPhFinal'
  };

  function stpChartHTML(rs) {
    const cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const en = state.lang === 'en';
    const R = cur && cur.roles ? cur.roles : null;
    let o = '<text class="xl-chart-title" x="16" y="18">' + esc(T('xlChartStp')) + '</text>';

    // 接主机的边缘链路（永远转发）
    [['ha', 's1'], ['s3', 'hd']].forEach(pair => {
      const a = STP_X[pair[0]], b = STP_X[pair[1]];
      o += '<path class="xl-link" d="M' + a.x + ',' + a.y + ' L' + b.x + ',' + b.y + '"/>';
    });

    D.stpLinks.forEach(l => {
      const a = STP_X[l.a], b = STP_X[l.b];
      const failed = cur && cur.showFail && cur.fail === l.id;
      const ra = R ? R.roles[l.a + ':' + l.pa] : null;
      const rb = R ? R.roles[l.b + ':' + l.pb] : null;
      const blocked = ra === 'ALT' || rb === 'ALT';
      let cls = 'xl-link';
      if (failed) cls = 'xl-link fail';
      else if (blocked) cls = 'xl-link blk';
      else if (R) cls = 'xl-link on';
      if (cur && cur.focus === l.id) cls += ' focus';
      o += '<path class="' + cls + '" d="M' + a.x + ',' + a.y + ' L' + b.x + ',' + b.y + '"/>';

      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      if (failed) {
        o += '<path class="xl-cross" d="M' + (mx - 8) + ',' + (my - 8) + ' l16,16 M' + (mx + 8) + ',' + (my - 8) + ' l-16,16"/>';
        o += '<text class="xl-link-t" x="' + mx + '" y="' + (my + 24) + '" text-anchor="middle">' +
          esc(en ? 'LINK DOWN' : '链路中断') + '</text>';
      } else if (blocked) {
        o += '<path class="xl-cross" d="M' + (mx - 8) + ',' + (my - 8) + ' l16,16 M' + (mx + 8) + ',' + (my - 8) + ' l-16,16"/>';
        o += '<text class="xl-link-t" x="' + mx + '" y="' + (my + 24) + '" text-anchor="middle">' +
          esc(en ? 'BLOCKED' : '逻辑阻塞') + '</text>';
      }
      // 端口角色标签放在链路两端靠交换机处；链路已断开时不再显示旧角色
      if (R && !failed) {
        [[l.a, l.pa, a, b, 0.38], [l.b, l.pb, b, a, 0.38]].forEach(q => {
          const role = R.roles[q[0] + ':' + q[1]];
          const px = q[2].x + (q[3].x - q[2].x) * q[4], py = q[2].y + (q[3].y - q[2].y) * q[4];
          o += '<circle class="xl-role-dot r-' + role + '" cx="' + px + '" cy="' + py + '" r="11"/>';
          o += '<text class="xl-role-dot-t" x="' + px + '" y="' + (py + 3) + '" text-anchor="middle">' +
            esc(role === 'ALT' ? '×' : role) + '</text>';
        });
      }
      // BPDU 流向：从根桥（或距离根更近的一端）向外，避开端口角色圆点
      if (cur && cur.arrows && R && !failed && !blocked) {
        const da = R.dist[l.a], db = R.dist[l.b];
        const from = da <= db ? a : b, to = da <= db ? b : a;
        o += xlArrow(from, to, 0.52, 'var(--blue)');
      }
    });

    if (cur && (cur.phase === 'detect' || cur.phase === 'tcn')) {
      o += '<path class="xl-tcn" d="M' + STP_X.s2.x + ',' + (STP_X.s2.y + 28) + ' Q 440,220 ' +
        STP_X.s3.x + ',' + (STP_X.s3.y - 28) + ' M' + STP_X.s3.x + ',' + (STP_X.s3.y - 28) +
        ' Q 280,170 ' + STP_X.s1.x + ',' + (STP_X.s1.y + 28) + '"/>';
      o += '<text class="xl-link-t" x="440" y="196" text-anchor="middle">' + esc(T('xlTcnFlow')) + '</text>';
    }

    Object.keys(D.stpSwitches).forEach(k => {
      const sw = D.stpSwitches[k], p = STP_X[k];
      const isRoot = R && R.root === k;
      const cls = 'xl-node' + (isRoot ? ' root' : '') + (cur && cur.focus === k ? ' focus' : '');
      o += xlBox(p.x, p.y, 126, 48, cls);
      o += '<text class="xl-node-t" x="' + p.x + '" y="' + (p.y - 3) + '" text-anchor="middle">' + esc(sw.name) + '</text>';
      o += '<text class="xl-node-s" x="' + p.x + '" y="' + (p.y + 12) + '" text-anchor="middle">' +
        esc(sw.mac.slice(-8)) + '</text>';
      if (isRoot) {
        o += '<rect class="xl-root-badge" x="' + (p.x - 26) + '" y="' + (p.y - 40) + '" width="52" height="17" rx="4"/>';
        o += '<text class="xl-root-t" x="' + p.x + '" y="' + (p.y - 28) + '" text-anchor="middle">' +
          esc(T('xlRootBadge')) + '</text>';
      }
      const rolesText = Object.keys(sw.ports).map(pn =>
        'P' + pn + ' ' + (R ? (R.roles[k + ':' + pn] || '—') : '—')).join('  ');
      o += '<text class="xl-role-line" x="' + p.x + '" y="' + (p.y + 38) + '" text-anchor="middle">' +
        esc(rolesText) + '</text>';
    });

    [['ha', 'A'], ['hd', 'B']].forEach(pair => {
      const p = STP_X[pair[0]];
      o += xlBox(p.x, p.y, 84, 34, 'xl-node host');
      o += '<text class="xl-node-t" x="' + p.x + '" y="' + (p.y + 4) + '" text-anchor="middle">' +
        esc((en ? 'Host ' : '主机 ') + pair[1]) + '</text>';
    });

    const lx = 16, ly = 300;
    o += '<rect class="xl-lg" x="' + lx + '" y="' + (ly - 8) + '" width="16" height="3"/>' +
      '<text class="xl-tick" x="' + (lx + 22) + '" y="' + (ly - 2) + '">' + esc(T('xlLegendFwd')) + '</text>' +
      '<rect class="xl-lg blk" x="' + (lx + 116) + '" y="' + (ly - 8) + '" width="16" height="3"/>' +
      '<text class="xl-tick" x="' + (lx + 138) + '" y="' + (ly - 2) + '">' + esc(T('xlLegendBlk')) + '</text>' +
      '<rect class="xl-lg fail" x="' + (lx + 232) + '" y="' + (ly - 8) + '" width="16" height="3"/>' +
      '<text class="xl-tick" x="' + (lx + 254) + '" y="' + (ly - 2) + '">' + esc(T('xlLegendFail')) + '</text>';
    o += '<text class="xl-tick" x="704" y="' + (ly - 2) + '" text-anchor="end">' +
      esc(cur ? T(STP_PHASE_KEY[cur.phase]) : T('xlNoFrame')) + '</text>';
    o += xlTimeline(rs, 16, 336, 688, 24);
    return o;
  }

  function stpSideHTML(rs) {
    const cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const en = state.lang === 'en';
    const R = cur && cur.roles ? cur.roles : null;
    const failOpts = [{ v: 'none', t: T('xlFailNone') }].concat(D.stpLinks.map(l => ({ v: l.id, t: l.label })));
    const rolesRows = Object.keys(D.stpSwitches).map(k => {
      const sw = D.stpSwitches[k];
      const chips = Object.keys(sw.ports).map(pn => {
        const role = R ? (R.roles[k + ':' + pn] || 'DOWN') : null;
        return '<i class="xl-role' + (role ? ' r-' + role : '') + '" title="' +
          esc(role ? T('xlRole' + role) : T('labReady')) + '">P' + pn + ' ' + (role || '—') + '</i>';
      }).join('');
      return '<div class="xl-role-row"><b>' + esc(sw.name) + '</b><span>' + chips + '</span></div>';
    }).join('');
    const logs = rs.slice(0, lab.at).map(x => ({
      r: x.r, badge: 'S' + x.r, text: T(STP_PHASE_KEY[x.phase]),
      evt: x.phase === 'fail' || x.phase === 'detect' || x.phase === 'tcn' || x.phase === 'converge'
    }));

    return '<div class="lab-panel-title">' + esc(T('xlTitleStp')) + '</div>' +
      '<div class="lab-note">' + esc(T('xlNoteStp')) + '</div>' +
      xlCtrls([
        { k: T('xlCfgRoot'), key: 'root', list: Object.keys(D.stpSwitches).map(k => ({ v: k, t: D.stpSwitches[k].name })) },
        { k: T('xlCfgFail'), key: 'fail', list: failOpts },
        { k: T('xlCfgProto'), key: 'proto', list: [
          { v: 'stp', t: T('xlProtoStp') }, { v: 'rstp', t: T('xlProtoRstp') }] }
      ]) +
      xlButtons() +
      '<div class="lab-metrics">' +
        xlMetric(T('xlStep'), (cur ? cur.r : 0) + ' / ' + rs.length) +
        xlMetric(T('xlRootMetric'), cur ? D.stpSwitches[cur.root].name : '—') +
        xlMetric(T('xlBlockMetric'), cur ? cur.blockedCount : 0) +
        xlMetric(T('xlCostMetric'), cur ? cur.rootCost : 0) +
        xlMetric(T('xlConvMetric'), cur ? cur.convTime : '—') +
        xlMetric(T('xlPhase'), cur ? T(STP_PHASE_KEY[cur.phase]) : T('xlNoFrame'), true) +
      '</div>' +
      '<div class="xl-table-title">' + esc(T('xlRoles')) + '</div>' +
      '<div class="xl-roles">' + rolesRows + '</div>' +
      xlLogs(logs) +
      (lab.at >= rs.length ? '<div class="lab-empty">' + esc(T('xlStepDone')) + '</div>' : '');
  }

  /* ---------------- CSMA/CD 与 802.11 共用：时隙泳道图 ---------------- */
  const lang = () => state.lang === 'en' ? 'en' : 'zh';
  const ph = (map, k) => (map[k] || { zh: k, en: k })[lang()];
  const CD_PHASE = {
    sense: { zh: '载波侦听', en: 'Carrier sense' }, tx: { zh: '发送帧', en: 'Transmitting' },
    collision: { zh: '冲突检测', en: 'Collision' }, jam: { zh: '强化冲突', en: 'Jam' },
    backoff: { zh: '退避', en: 'Backoff' }, slot: { zh: '空闲时隙', en: 'Idle slot' },
    success: { zh: '发送成功', en: 'Delivered' }, late: { zh: '迟到冲突', en: 'Late collision' },
    giveup: { zh: '重传放弃', en: 'Give up' }, done: { zh: '本轮结束', en: 'Complete' }
  };
  const WF_PHASE = {
    difs: { zh: '等待 DIFS', en: 'DIFS' }, backoff: { zh: '随机退避', en: 'Backoff' },
    slot: { zh: '空闲时隙', en: 'Idle slot' }, rts: { zh: 'RTS 预约', en: 'RTS' },
    cts: { zh: 'CTS / NAV', en: 'CTS / NAV' }, data: { zh: 'DATA 发送', en: 'DATA' },
    tx: { zh: '隐藏节点同发', en: 'Hidden-node TX' }, collision: { zh: 'AP 处冲突', en: 'Collision at AP' },
    timeout: { zh: 'ACK 超时', en: 'ACK timeout' }, retry: { zh: 'CW 翻倍重传', en: 'CW doubled' },
    sifs: { zh: 'SIFS 优先', en: 'SIFS' }, success: { zh: 'ACK 确认', en: 'ACK received' },
    done: { zh: '本轮结束', en: 'Complete' }
  };
  const CD_ST = {
    sense: { c: 's-idle', zh: '侦听', en: 'SENSE' }, tx: { c: 's-tx', zh: '发送', en: 'TX' },
    collision: { c: 's-collision', zh: '冲突', en: 'COLL' }, jam: { c: 's-jam', zh: 'JAM', en: 'JAM' },
    backoff: { c: 's-backoff', zh: '退避', en: 'BKOFF' }, frozen: { c: 's-frozen', zh: '冻结', en: 'HOLD' },
    success: { c: 's-success', zh: '成功', en: 'OK' }, done: { c: 's-success', zh: '完成', en: 'DONE' }
  };
  const WF_ST = {
    difs: { c: 's-idle', zh: 'DIFS', en: 'DIFS' }, backoff: { c: 's-backoff', zh: '退避', en: 'BKOFF' },
    frozen: { c: 's-frozen', zh: '冻结', en: 'HOLD' }, rts: { c: 's-tx', zh: 'RTS', en: 'RTS' },
    nav: { c: 's-nav', zh: 'NAV', en: 'NAV' }, data: { c: 's-tx', zh: 'DATA', en: 'DATA' },
    tx: { c: 's-tx', zh: 'DATA', en: 'DATA' }, wait: { c: 's-wait', zh: '等 ACK', en: 'W-ACK' },
    success: { c: 's-success', zh: 'OK', en: 'OK' }, idle: { c: 's-idle', zh: '空闲', en: 'IDLE' },
    cts: { c: 's-teal', zh: 'CTS', en: 'CTS' }, rx: { c: 's-tx', zh: 'RX', en: 'RX' },
    ack: { c: 's-success', zh: 'ACK', en: 'ACK' }
  };
  const MED_ST = {
    idle: { c: 's-idle', zh: '空闲', en: 'IDLE' }, busy: { c: 's-tx', zh: '忙', en: 'BUSY' },
    collision: { c: 's-collision', zh: '冲突', en: 'COLL' }, jam: { c: 's-jam', zh: 'JAM', en: 'JAM' },
    nav: { c: 's-nav', zh: 'NAV', en: 'NAV' }
  };
  const LANE_LEGEND_EN = ['Sense / idle', 'Transmit', 'Collision', 'Backoff / freeze', 'Jam / NAV', 'Success'];
  const LANE_LEGEND_ZH = ['侦听 / 空闲', '发送 / 载波', '冲突', '退避 / 冻结', 'Jam / NAV', '成功'];

  function laneLegend(y) {
    const cls = ['s-idle', 's-tx', 's-collision', 's-backoff', 's-jam', 's-success'];
    const texts = state.lang === 'en' ? LANE_LEGEND_EN : LANE_LEGEND_ZH;
    let x = 16;
    return texts.map((t, i) => {
      const s = '<rect class="lane-cell ' + cls[i] + ' on" x="' + x + '" y="' + (y - 8) +
        '" width="12" height="10" rx="2"/>' +
        '<text class="xl-tick" x="' + (x + 16) + '" y="' + (y + 1) + '">' + esc(t) + '</text>';
      x += 112;
      return s;
    }).join('');
  }

  function laneChart(rs, o) {
    const n = rs.length, x0 = 76, x1 = 704, W = x1 - x0, gap = 2;
    const cw = Math.max(10, Math.min(56, (W - gap * (n - 1)) / n));
    const used = cw * n + gap * (n - 1);
    const sx = x0 + (W - used) / 2;
    const top = 58, rh = 34, ch = 27;
    let out = '<text class="xl-chart-title" x="16" y="18">' + esc(o.title) + '</text>' +
      '<text class="xl-tick" x="16" y="34">' + esc(o.sub) + '</text>';
    rs.forEach((r, i) => {
      out += '<text class="lane-ruler' + (r.r === lab.at ? ' cur' : '') + '" x="' +
        (sx + i * (cw + gap) + cw / 2) + '" y="' + (top - 7) + '" text-anchor="middle">' + r.r + '</text>';
    });
    o.lanes.forEach((ln, li) => {
      const y = top + li * rh;
      out += '<text class="lane-name" x="16" y="' + (y + ch / 2 + 3.5) + '">' + esc(ln.label) + '</text>';
      out += '<rect class="lane-bg' + (ln.medium ? ' med' : '') + '" x="' + x0 + '" y="' + y +
        '" width="' + W + '" height="' + ch + '" rx="3"/>';
      rs.forEach((r, i) => {
        const cell = ln.cell(r) || { c: 's-idle', t: '' };
        const bx = sx + i * (cw + gap);
        out += '<g class="lane-g" data-lab-r="' + r.r + '">' +
          '<rect class="lane-cell ' + cell.c + (r.r <= lab.at ? ' on' : '') + (r.r === lab.at ? ' now' : '') +
          '" x="' + bx + '" y="' + y + '" width="' + cw + '" height="' + ch + '" rx="2"/>' +
          (cw >= 22 ? '<text class="lane-cell-t" x="' + (bx + cw / 2) + '" y="' + (y + ch / 2 + 2.8) +
            '" text-anchor="middle">' + esc(cell.t || '') + '</text>' : '') + '</g>';
      });
    });
    out += o.footer(top + o.lanes.length * rh + 6);
    out += xlTimeline(rs, 16, 336, 688, 24);
    return out;
  }
  function laneBadge(text, color) {
    return '<rect class="xl-badge" x="452" y="30" width="248" height="26" rx="5" style="stroke:' + color + '"/>' +
      '<text class="xl-badge-t" x="576" y="47" text-anchor="middle" style="fill:' + color + '">' +
      esc(text) + '</text>';
  }

  /* ---------------- CSMA/CD 实验：共享总线时隙推演 ---------------- */
  function cdChartHTML(rs) {
    const L = lang(), cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const names = rs[0].names;
    const lanes = names.map(n => ({
      label: (L === 'en' ? 'Station ' : '站点 ') + n,
      cell: r => {
        const s = r.st[n] || { s: 'sense', remain: 0 };
        const m = CD_ST[s.s] || CD_ST.sense;
        return { c: m.c, t: (s.s === 'backoff' || s.s === 'frozen') ? 'r' + s.remain : m[L] };
      }
    }));
    lanes.push({
      label: T('cdMedium'), medium: true,
      cell: r => { const m = MED_ST[r.bus] || MED_ST.idle; return { c: m.c, t: m[L] }; }
    });
    return laneChart(rs, {
      title: T('cdChart'),
      sub: (L === 'en' ? 'Step ' : '步骤 ') + (cur ? cur.r : 0) + ' / ' + rs.length +
        '  ·  t = ' + (cur ? cur.t : 0) + ' μs  ·  ' + (cur ? ph(CD_PHASE, cur.phase) : T('labReady')),
      lanes: lanes,
      footer: y => {
        const fi = D.cdFrameInfo[lab.cfg.frame] || D.cdFrameInfo.min;
        const maxUs = Math.max(51.2, fi.txUs), bw = 410, bx = 76;
        let o = '';
        o += '<rect class="lane-bar-bg" x="' + bx + '" y="' + (y - 9) + '" width="' + bw + '" height="11" rx="3"/>';
        o += '<rect class="lane-bar-c" x="' + bx + '" y="' + (y - 9) + '" width="' +
          (bw * 51.2 / maxUs) + '" height="11" rx="3"/>';
        o += '<rect class="lane-bar-bg" x="' + bx + '" y="' + (y + 6) + '" width="' + bw + '" height="11" rx="3"/>';
        o += '<rect class="lane-bar-f' + (fi.bytes < 64 ? ' bad' : '') + '" x="' + bx + '" y="' + (y + 6) +
          '" width="' + (bw * fi.txUs / maxUs) + '" height="11" rx="3"/>';
        o += '<text class="xl-tick" x="' + (bx + bw + 8) + '" y="' + y + '">' +
          esc(L === 'en' ? 'contention 51.2 μs' : '争用期 51.2 μs') + '</text>';
        o += '<text class="xl-tick" x="' + (bx + bw + 8) + '" y="' + (y + 15) + '">' +
          esc(fi.bytes + ' B / ' + fi.txUs + ' μs') + '</text>';
        o += '<text class="xl-tick" x="16" y="' + (y + 30) + '">' + esc(T('cdMinLine')) + '</text>';
        o += laneLegend(y + 50);
        return o + laneBadge(cur ? ph(CD_PHASE, cur.phase) : T('labReady'),
          cur && ['collision', 'late', 'giveup'].indexOf(cur.phase) >= 0 ? 'var(--red)' :
            (cur && cur.phase === 'success' ? 'var(--green)' : 'var(--blue)'));
      }
    });
  }

  function cdSideHTML(rs) {
    const L = lang(), cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const fi = D.cdFrameInfo[lab.cfg.frame] || D.cdFrameInfo.min;
    const names = rs[0].names;
    const rows = names.map(n => {
      const s = cur ? cur.st[n] : { attempt: 0, k: 0, remain: 0, s: 'sense' };
      return '<tr><td>' + esc(n) + '</td><td>' + s.attempt + '</td><td>' + s.k + '</td><td>' + s.remain +
        '</td><td>' + esc((CD_ST[s.s] || CD_ST.sense)[L]) + '</td></tr>';
    }).join('');
    const logs = rs.slice(0, lab.at).map(x => ({
      r: x.r, badge: 'S' + x.r, text: ph(CD_PHASE, x.phase) + ' · t = ' + x.t + ' μs',
      evt: ['collision', 'late', 'giveup', 'jam'].indexOf(x.phase) >= 0
    }));
    const k = cur ? cur.st[names[0]].k : 0;
    const winTxt = !cur ? '—' : (lab.cfg.backoff === 'beb' ? '2^' + k + ' = ' + Math.pow(2, k) :
      (lab.cfg.backoff === 'fixed' ? '0~3' : '0'));
    return '<div class="lab-panel-title">' + esc(T('cdTitle')) + '</div>' +
      '<div class="lab-note">' + esc(T('cdNote')) + '</div>' +
      xlCtrls([
        { k: T('cdCfgHosts'), key: 'hosts', list: [2, 3, 4].map(v => ({ v: v, t: v + (L === 'en' ? ' stations' : ' 个站点') })) },
        { k: T('cdCfgFrame'), key: 'frame', list: [
          { v: 'min', t: T('cdFrameMin') }, { v: 'short', t: T('cdFrameShort') }, { v: 'long', t: T('cdFrameLong') }] },
        { k: T('cdCfgBackoff'), key: 'backoff', list: [
          { v: 'beb', t: T('cdBeb') }, { v: 'fixed', t: T('cdFixed') }, { v: 'none', t: T('cdNone') }] }
      ], true) +
      xlButtons() +
      '<div class="lab-metrics">' +
        xlMetric(T('cdMetricStep'), (cur ? cur.r : 0) + ' / ' + rs.length) +
        xlMetric(T('cdMetricColl'), cur ? cur.collisions : 0) +
        xlMetric(T('cdMetricSucc'), cur ? cur.successes : 0) +
        xlMetric(T('cdMetricWin'), winTxt) +
        xlMetric(T('cdMetricFrame'), fi.bytes + ' B / ' + fi.txUs + ' μs') +
        xlMetric(T('cdMetricAttempt'), cur ? cur.attempts : 0) +
        xlMetric(T('cdFrameCheck'), fi.bytes >= 64 ? T('cdOk') : T('cdBad'), true) +
      '</div>' +
      '<div class="xl-table-title">' + esc(T('cdTable')) + '</div>' +
      '<table class="xl-table"><thead><tr><th>' + esc(T('cdThSite')) + '</th><th>' + esc(T('cdThRetry')) +
        '</th><th>' + esc(T('cdThK')) + '</th><th>' + esc(T('cdThR')) + '</th><th>' + esc(T('cdThState')) +
        '</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      xlLogs(logs) +
      (lab.at >= rs.length ? '<div class="lab-empty">' + esc(T('xlStepDone')) + '</div>' : '');
  }

  /* ---------------- 802.11 CSMA/CA 实验：无线信道时隙推演 ---------------- */
  function wfChartHTML(rs) {
    const L = lang(), cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const names = rs[0].names;
    const stateCell = key => r => {
      const s = r.st[key] || { s: 'idle', remain: 0 };
      const m = WF_ST[s.s] || WF_ST.idle;
      return { c: m.c, t: (s.s === 'backoff' || s.s === 'frozen') ? 'r' + s.remain : m[L] };
    };
    const lanes = names.map(n => ({ label: n, cell: stateCell(n) }));
    lanes.push({ label: 'AP', cell: stateCell('AP') });
    lanes.push({
      label: T('wfMedium'), medium: true,
      cell: r => { const m = MED_ST[r.medium] || MED_ST.idle; return { c: m.c, t: m[L] }; }
    });
    return laneChart(rs, {
      title: T('wfChart'),
      sub: (L === 'en' ? 'Step ' : '步骤 ') + (cur ? cur.r : 0) + ' / ' + rs.length +
        '  ·  t = ' + (cur ? cur.t : 0) + ' μs  ·  ' + (cur ? ph(WF_PHASE, cur.phase) : T('labReady')),
      lanes: lanes,
      footer: y => {
        const segDefs = [
          { k: 'difs', w: 92, label: 'DIFS' },
          { k: 'backoff', w: 128, label: 'BACKOFF' },
          { k: 'data', w: 176, label: cur && cur.rtsOn ? 'RTS/CTS + DATA' : 'DATA' },
          { k: 'sifs', w: 74, label: 'SIFS' },
          { k: 'ack', w: 92, label: 'ACK' }
        ];
        const SEG_OF = { difs: 0, backoff: 1, slot: 1, rts: 2, cts: 2, data: 2,
          tx: 2, collision: 2, timeout: 2, retry: 2, sifs: 3, success: 4, done: 4 };
        const active = cur && SEG_OF[cur.phase] != null ? SEG_OF[cur.phase] : -1;
        let o = '', x = 76;
        segDefs.forEach((s, i) => {
          o += '<rect class="lane-seg' + (i === active ? ' on' : '') + '" x="' + x + '" y="' + (y - 9) +
            '" width="' + (s.w - 3) + '" height="18" rx="3"/>';
          o += '<text class="lane-seg-t" x="' + (x + (s.w - 3) / 2) + '" y="' + (y + 3.5) +
            '" text-anchor="middle">' + esc(s.label) + '</text>';
          x += s.w;
        });
        o += '<text class="xl-tick" x="76" y="' + (y + 24) + '">' +
          esc('DIFS 50 μs  ·  Slot 9 μs  ·  SIFS 10 μs  ·  ACK 32 μs  ·  NAV ' + (cur ? cur.navUs : 300) + ' μs') + '</text>';
        o += '<text class="xl-tick" x="16" y="' + (y + 40) + '">' + esc(T('wfNavLine')) + '</text>';
        o += laneLegend(y + 58);
        return o + laneBadge(cur ? ph(WF_PHASE, cur.phase) : T('labReady'),
          cur && ['collision', 'timeout', 'retry'].indexOf(cur.phase) >= 0 ? 'var(--red)' :
            (cur && cur.phase === 'success' ? 'var(--green)' : 'var(--blue)'));
      }
    });
  }

  function wfSideHTML(rs) {
    const L = lang(), cur = lab.at > 0 ? rs[lab.at - 1] : null;
    const keys = rs[0].names.concat(['AP']);
    const rows = keys.map(n => {
      const s = cur ? cur.st[n] : { s: n === 'AP' ? 'idle' : 'difs', remain: 0, nav: 0 };
      return '<tr><td>' + esc(n) + '</td><td>' + s.remain + '</td><td>' + (s.nav || 0) +
        '</td><td>' + esc((WF_ST[s.s] || WF_ST.idle)[L]) + '</td></tr>';
    }).join('');
    const logs = rs.slice(0, lab.at).map(x => ({
      r: x.r, badge: 'S' + x.r, text: ph(WF_PHASE, x.phase) + ' · t = ' + x.t + ' μs',
      evt: ['collision', 'timeout', 'retry', 'cts'].indexOf(x.phase) >= 0
    }));
    return '<div class="lab-panel-title">' + esc(T('wfTitle')) + '</div>' +
      '<div class="lab-note">' + esc(T('wfNote')) + '</div>' +
      xlCtrls([
        { k: T('wfCfgStations'), key: 'stations', list: [
          { v: 2, t: '2 ' + (L === 'en' ? 'stations' : '个站点') }, { v: 3, t: '3 ' + (L === 'en' ? 'stations' : '个站点') }] },
        { k: T('wfCfgRts'), key: 'rts', list: [
          { v: 'off', t: T('wfRtsOff') }, { v: 'on', t: T('wfRtsOn') }] },
        { k: T('wfCfgHidden'), key: 'hidden', list: [
          { v: 'off', t: T('wfHiddenOff') }, { v: 'on', t: T('wfHiddenOn') }] },
        { k: T('wfCfgCw'), key: 'cw', list: [
          { v: 'cw15', t: T('wfCw15') }, { v: 'cw63', t: T('wfCw63') }] }
      ]) +
      xlButtons() +
      '<div class="lab-metrics">' +
        xlMetric(T('cdMetricStep'), (cur ? cur.r : 0) + ' / ' + rs.length) +
        xlMetric(T('cdMetricColl'), cur ? cur.collisions : 0) +
        xlMetric(T('cdMetricSucc'), cur ? cur.successes : 0) +
        xlMetric(T('wfMetricCw'), cur ? '0~' + cur.cw : '—') +
        xlMetric(T('wfMetricNav'), cur ? cur.navUs + ' μs' : '—') +
        xlMetric(T('wfMetricIfs'), (cur ? cur.difs : 50) + ' / ' + (cur ? cur.sifs : 10) + ' μs') +
        xlMetric(T('wfMetricPhase'), cur ? ph(WF_PHASE, cur.phase) : T('labReady'), true) +
      '</div>' +
      '<div class="xl-table-title">' + esc(T('wfTable')) + '</div>' +
      '<table class="xl-table"><thead><tr><th>' + esc(T('wfThSite')) + '</th><th>' + esc(T('wfThBackoff')) +
        '</th><th>' + esc(T('wfThNav')) + '</th><th>' + esc(T('wfThState')) +
        '</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      xlLogs(logs) +
      (lab.at >= rs.length ? '<div class="lab-empty">' + esc(T('xlStepDone')) + '</div>' : '');
  }

  /* ---------------- 实验注册表 ---------------- */
  const LAB_DEFS = {
    tcpcc: {
      tab: 'labView', cfg: () => Object.assign({}, D.labDefault), simulate: c => D.labSimulate(c),
      chart: rs => labChartHTML(rs), side: rs => labSideHTML(rs), aria: () => T('labChartTitle'),
      strip: (t, en) => en ? t.replace(/^RTT \d+: /, '') : t.replace(/^RTT \d+：/, ''),
      tag: r => 'RTT ' + r,
      evt: cur => !!(cur && cur.event)
    },
    switch: {
      tab: 'swLabView', cfg: () => Object.assign({}, D.swDefault), simulate: c => D.swSimulate(c),
      chart: rs => swChartHTML(rs), side: rs => swSideHTML(rs), aria: () => T('xlChartSw'),
      strip: (t, en) => en ? t.replace(/^Frame \d+: /, '') : t.replace(/^帧 \d+：/, ''),
      tag: r => (state.lang === 'en' ? 'Frame ' : '帧 ') + r,
      evt: cur => !!(cur && (cur.action === 'flood' || cur.learn === 'move' || cur.action === 'filter'))
    },
    stp: {
      tab: 'stpLabView', cfg: () => Object.assign({}, D.stpDefault), simulate: c => D.stpSimulate(c),
      chart: rs => stpChartHTML(rs), side: rs => stpSideHTML(rs), aria: () => T('xlChartStp'),
      strip: (t, en) => en ? t.replace(/^Stage \d+ · [^:]+: /, '') : t.replace(/^阶段 \d+ · [^：]+：/, ''),
      tag: r => (state.lang === 'en' ? 'Stage ' : '阶段 ') + r,
      evt: cur => !!(cur && ['fail', 'detect', 'tcn', 'converge'].indexOf(cur.phase) >= 0)
    },
    csma: {
      tab: 'cdLabView', cfg: () => Object.assign({}, D.cdDefault), simulate: c => D.cdSimulate(c),
      chart: rs => cdChartHTML(rs), side: rs => cdSideHTML(rs), aria: () => T('cdChart'),
      strip: t => t,
      tag: r => (state.lang === 'en' ? 'Slot ' : '时隙 ') + r,
      evt: cur => !!(cur && ['collision', 'late', 'giveup', 'jam', 'success'].indexOf(cur.phase) >= 0)
    },
    wifi: {
      tab: 'wfLabView', cfg: () => Object.assign({}, D.wfDefault), simulate: c => D.wfSimulate(c),
      chart: rs => wfChartHTML(rs), side: rs => wfSideHTML(rs), aria: () => T('wfChart'),
      strip: t => t,
      tag: r => (state.lang === 'en' ? 'Slot ' : '时隙 ') + r,
      evt: cur => !!(cur && ['collision', 'timeout', 'retry', 'success'].indexOf(cur.phase) >= 0)
    }
  };

  function renderLab() {
    const def = labDef();
    if (state.view !== 'lab' || !def) return;
    if (!lab.rounds.length) lab.rounds = def.simulate(lab.cfg);
    const svg = $('labSvg');
    svg.innerHTML = def.chart(lab.rounds);
    svg.setAttribute('aria-label', def.aria());
    $('labSide').innerHTML = def.side(lab.rounds);
    const cur = lab.at > 0 ? lab.rounds[lab.at - 1] : null;
    const ex = $('labExplain');
    ex.className = 'lab-explain' + (def.evt(cur) ? ' evt' : '');
    ex.innerHTML = cur
      ? '<b>' + esc(def.tag(cur.r)) + '</b><span>' +
        esc(def.strip(state.lang === 'en' ? cur.en : cur.zh, state.lang === 'en')) + '</span>'
      : '<b>—</b><span>' + esc(T('labEmpty')) + '</span>';
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
    if (LAB_DEFS[id]) labLoad(id);
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
    if (v === 'lab' && !LAB_DEFS[state.scenario]) v = 'network';
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
      const xa = e.target.closest('[data-xl-act]');
      if (xa && xa.dataset.xlAct === 'send') { xlSendFrame(); return; }
      const btn = e.target.closest('[data-lab-act]');
      if (!btn) return;
      const act = btn.dataset.labAct;
      if (act === 'play') labPlay();
      else if (act === 'step') labStep(1);
      else if (act === 'back') labStep(-1);
      else if (act === 'reset') labReset();
    });
    $('labWrap').addEventListener('change', e => {
      const custom = e.target.closest('select[data-xl]');
      if (custom) { lab.xl[custom.dataset.xl] = custom.value; return; }
      const sel = e.target.closest('select[data-lab]');
      if (!sel) return;
      const key = sel.dataset.lab;
      lab.cfg[key] = /^-?\d+$/.test(sel.value) ? +sel.value : sel.value;
      if (key === 'script') lab.cfg.frames = null;
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
