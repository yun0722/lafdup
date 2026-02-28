#include "discovery.h"
#include "peer.h"

#include <QtCore/qloggingcategory.h>
#include <QtCore/qdir.h>
#include <QtNetwork/qhostaddress.h>

static Q_LOGGING_CATEGORY(logger, "lafdup.discovery");

const quint16 DefaultPort = 7951;

LafdupDiscovery::LafdupDiscovery(const QByteArray &uuid, quint16 port, LafdupPeer *parent)
    : QObject(parent)
    , kcpSocket(new qtng::KcpSocket(qtng::HostAddress::IPv4Protocol))
    , dnsServer(new qtng::DnsServer(this))
    , operations(new qtng::CoroutineGroup())
    , uuid(uuid)
    , parent(parent)
    , port(port)
{
    kcpSocket->setOption(qtng::Socket::BroadcastSocketOption, true);
    connect(dnsServer.data(), &qtng::DnsServer::messageReceived, this, &LafdupDiscovery::handleQuery);
}

LafdupDiscovery::~LafdupDiscovery()
{
    delete operations;
}

bool LafdupDiscovery::start()
{
    if (operations->has("serve")) {
        // 已在运行
        return true;
    }

            // 绑定 KCP 套接字并开始监听
    if (!kcpSocket->bind(port)) {
        qCWarning(logger) << "Failed to bind KCP socket on port" << port;
        return false;
    }
    kcpSocket->listen(50);

            // 启动接受连接的协程
    operations->spawnWithName("serve", [this] { serve(); });

            // 启动 mDNS 浏览器（发现 _lafdup._tcp.local. 服务）
    browser.reset(new qtng::Browser(dnsServer.data(), "_lafdup._tcp.local.", nullptr, this));
    connect(browser.data(), &qtng::Browser::serviceAdded, this, &LafdupDiscovery::onServiceAdded);
    connect(browser.data(), &qtng::Browser::serviceRemoved, this, &LafdupDiscovery::onServiceRemoved);

            // 启动定期发布定时器（每 60 秒宣告一次本机服务）
    publishTimer.setInterval(60 * 1000);
    connect(&publishTimer, &QTimer::timeout, this, &LafdupDiscovery::publishServices);
    publishTimer.start();

            // 立即发布一次
    publishServices();

    qCDebug(logger) << "mDNS discovery started for UUID" << uuid;
    return true;
}

void LafdupDiscovery::stop()
{
    publishTimer.stop();
    browser.reset();          // 停止浏览
    dnsServer.reset();        // 停止 mDNS 服务器
    operations->killall();    // 停止 serve 协程
    kcpSocket.reset(new qtng::KcpSocket(qtng::HostAddress::IPv4Protocol));
    kcpSocket->setOption(qtng::Socket::BroadcastSocketOption, true);
    qCDebug(logger) << "mDNS discovery stopped";
}

void LafdupDiscovery::setExtraKnownPeers(const QSet<QPair<qtng::HostAddress, quint16>> &extraKnownPeers)
{
    this->extraKnownPeers = extraKnownPeers;
    qCInfo(logger) << "Extra known peers set (mDNS mode: these will be ignored)";
}

QSet<QPair<qtng::HostAddress, quint16>> LafdupDiscovery::getExtraKnownPeers()
{
    return extraKnownPeers;
}

QStringList LafdupDiscovery::getAllBoundAddresses()
{
    QStringList addresses;
    const auto list = qtng::NetworkInterface::allAddresses();
    for (const qtng::HostAddress &addr : list) {
        if (!addr.isLoopback() && !addr.isMulticast() && addr.protocol() == qtng::HostAddress::IPv4Protocol) {
            addresses.append(addr.toString());
        }
    }
    return addresses;
}

quint16 LafdupDiscovery::getPort()
{
    if (port == 0) {
        return kcpSocket->localPort();
    } else {
        return port;
    }
}

QByteArray LafdupDiscovery::getUuid()
{
    return uuid;
}

quint16 LafdupDiscovery::getDefaultPort()
{
    return DefaultPort;
}
void LafdupDiscovery::serve()
{
    while (true) {
        QSharedPointer<qtng::KcpSocket> client(kcpSocket->accept());
        if (client.isNull()) {
            return; // 套接字已关闭
        }
        parent->tryToConnectPeer(client);
    }
}

void LafdupDiscovery::publishServices()
{
    qtng::Message msg;
    msg.setResponse(true);

    QByteArray serviceType = "_lafdup._tcp.local.";
    QByteArray instanceName = uuid;
    QByteArray fullInstanceName = instanceName + "." + serviceType;
    QByteArray hostName = uuid + ".local.";

            // PTR 记录：服务类型 -> 完整实例名
    qtng::Record ptr;
    ptr.setName(serviceType);
    ptr.setType(qtng::PTR);
    ptr.setTarget(fullInstanceName);
    ptr.setTtl(4500);
    msg.addRecord(ptr);

            // SRV 记录：完整实例名 -> 目标主机名、端口
    qtng::Record srv;
    srv.setName(fullInstanceName);
    srv.setType(qtng::SRV);
    srv.setTarget(hostName);
    srv.setPort(port);
    srv.setPriority(0);
    srv.setWeight(0);
    srv.setTtl(4500);
    msg.addRecord(srv);

            // TXT 记录：版本信息（可扩展）
    qtng::Record txt;
    txt.setName(fullInstanceName);
    txt.setType(qtng::TXT);
    txt.setTtl(4500);
    txt.addAttribute("version", "1");
    msg.addRecord(txt);

            // A/AAAA 记录：将 hostName 解析到本机所有非回环地址
    const auto addresses = qtng::NetworkInterface::allAddresses();
    for (const qtng::HostAddress &addr : addresses) {
        if (addr.isLoopback()) continue;
        if (addr.protocol() == qtng::HostAddress::IPv4Protocol) {
            qtng::Record a;
            a.setName(hostName);
            a.setType(qtng::A);
            a.setAddress(addr);
            a.setTtl(120);
            msg.addRecord(a);
        } else if (addr.protocol() == qtng::HostAddress::IPv6Protocol) {
            qtng::Record aaaa;
            aaaa.setName(hostName);
            aaaa.setType(qtng::AAAA);
            aaaa.setAddress(addr);
            aaaa.setTtl(120);
            msg.addRecord(aaaa);
        }
    }
    qCDebug(logger) << "Publishing mDNS service...";
    dnsServer->sendMessageToAll(msg);
    qCDebug(logger) << "Published" << msg.records().size() << "records";
}

void LafdupDiscovery::handleQuery(const qtng::Message &query)
{
    if (query.isResponse()) return;   // 只处理查询
    qCDebug(logger) << "Received query from" << query.address() << "with" << query.queries().size() << "questions";
    qtng::Message reply;
    reply.reply(query);

    QByteArray serviceType = "_lafdup._tcp.local.";
    QByteArray instanceName = uuid;
    QByteArray fullInstanceName = instanceName + "." + serviceType;
    QByteArray hostName = uuid + ".local.";

    const auto queries = query.queries();
    for (const qtng::Query &q : queries) {
        if (q.type() == qtng::PTR && q.name() == serviceType) {
            qtng::Record ptr;
            ptr.setName(serviceType);
            ptr.setType(qtng::PTR);
            ptr.setTarget(fullInstanceName);
            ptr.setTtl(4500);
            reply.addRecord(ptr);
        } else if (q.type() == qtng::SRV && q.name() == fullInstanceName) {
            qtng::Record srv;
            srv.setName(fullInstanceName);
            srv.setType(qtng::SRV);
            srv.setTarget(hostName);
            srv.setPort(port);
            srv.setPriority(0);
            srv.setWeight(0);
            srv.setTtl(4500);
            reply.addRecord(srv);
        } else if (q.type() == qtng::TXT && q.name() == fullInstanceName) {
            qtng::Record txt;
            txt.setName(fullInstanceName);
            txt.setType(qtng::TXT);
            txt.setTtl(4500);
            txt.addAttribute("version", "1");
            reply.addRecord(txt);
        } else if ((q.type() == qtng::A || q.type() == qtng::AAAA) && q.name() == hostName) {
            const auto addresses = qtng::NetworkInterface::allAddresses();
            for (const qtng::HostAddress &addr : addresses) {
                if (addr.isLoopback()) continue;
                if (addr.protocol() == qtng::HostAddress::IPv4Protocol && q.type() == qtng::A) {
                    qtng::Record a;
                    a.setName(hostName);
                    a.setType(qtng::A);
                    a.setAddress(addr);
                    a.setTtl(120);
                    reply.addRecord(a);
                } else if (addr.protocol() == qtng::HostAddress::IPv6Protocol && q.type() == qtng::AAAA) {
                    qtng::Record aaaa;
                    aaaa.setName(hostName);
                    aaaa.setType(qtng::AAAA);
                    aaaa.setAddress(addr);
                    aaaa.setTtl(120);
                    reply.addRecord(aaaa);
                }
            }
        }
    }

    if (!reply.records().isEmpty()) {
        dnsServer->sendMessage(reply);
    }
}

void LafdupDiscovery::onServiceAdded(const qtng::Service &service)
{
    qCDebug(logger) << "Service added:" << service.name() << service.hostname() << "port" << service.port();
    QString peerName = service.name();  // 对方的 UUID
    if (parent->hasPeer(peerName)) return;
    if (resolvingPeers.contains(peerName)) return;

    resolvingPeers.insert(peerName);
    QByteArray target = service.hostname();  // 例如 "uuid.local."
    quint16 peerPort = service.port();

            // 使用 Resolver 解析目标域名获得 IP 地址
    qtng::Resolver *resolver = new qtng::Resolver(dnsServer.data(), target, nullptr, this);
    connect(resolver, &qtng::Resolver::resolved, this, [=](const qtng::HostAddress &addr) {
        if (!parent->hasPeer(peerName) && !parent->hasPeer(addr, peerPort)) {
            parent->tryToConnectPeer(peerName, addr, peerPort);
        }
        resolver->deleteLater();
        resolvingPeers.remove(peerName);
    });
    // 如果解析失败（超时），Resolver 内部会超时并自行销毁，这里只需从 resolvingPeers 移除
    // 但 Resolver 没有直接发出失败信号，可以用定时器兜底
    QTimer::singleShot(5000, this, [this, peerName]() {
        resolvingPeers.remove(peerName);
    });
}

void LafdupDiscovery::onServiceRemoved(const qtng::Service &service)
{
    QString peerName = service.name();
    // 可选：从 knownPeers 中移除，并关闭相应连接
    qCDebug(logger) << "Service removed:" << peerName;
    // 如果需要，可以通知 parent 关闭对应 Peer
}

void LafdupDiscovery::onResolved(const qtng::HostAddress &address)
{

   // 此槽原用于广播解析，现未使用，但可保留以备将来扩展
}
