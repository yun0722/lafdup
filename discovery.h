#ifndef LAFDUP_DISCOVERY_H
#define LAFDUP_DISCOVERY_H

#include "lafrpc.h"
class LafdupPeer;

class LafdupDiscovery : public QObject
{
    Q_OBJECT
public:
    LafdupDiscovery(const QByteArray &uuid, quint16 port, LafdupPeer *parent);
    ~LafdupDiscovery();

    bool start();
    void stop();

            // 保留原接口（但 extraKnownPeers 在 mDNS 模式下不再用于广播）
    void setExtraKnownPeers(const QSet<QPair<qtng::HostAddress, quint16>> &extraKnownPeers);
    QSet<QPair<qtng::HostAddress, quint16>> getExtraKnownPeers();

    QStringList getAllBoundAddresses();
    quint16 getPort();
    QByteArray getUuid();

    static quint16 getDefaultPort();

private slots:
    void onServiceAdded(const qtng::Service &service);
    void onServiceRemoved(const qtng::Service &service);
    void publishServices();
    void handleQuery(const qtng::Message &message);

private:
    void serve();  // KCP 接受连接的协程

private:
    QSharedPointer<qtng::KcpSocket> kcpSocket;               // 传输层 KCP 套接字
    QSharedPointer<qtng::DnsServer> dnsServer;               // mDNS 服务器
    QSharedPointer<qtng::Browser> browser;                    // 服务浏览器
    qtng::CoroutineGroup *operations;                          // 协程组
    QTimer publishTimer;                                 // 定期发布定时器

    QHash<QString, QPair<qtng::HostAddress, quint16>> knownPeers;   // 已发现节点（保留，但不再主动使用）
    QSet<QPair<qtng::HostAddress, quint16>> extraKnownPeers;        // 手动指定节点（mDNS 模式下无效）
    QByteArray uuid;
    LafdupPeer *parent;
    quint16 port;

            // 用于跟踪正在解析中的节点，避免重复连接
    QSet<QString> resolvingPeers;
};

#endif // LAFDUP_DISCOVERY_H
