package me.smartproxy.core;

import android.annotation.SuppressLint;
import android.os.Build;

import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Timer;
import java.util.TimerTask;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import me.smartproxy.tcpip.CommonMethods;
import me.smartproxy.tunnel.Config;
import me.smartproxy.tunnel.httpconnect.HttpConnectConfig;
import me.smartproxy.tunnel.shadowsocks.ShadowsocksConfig;

public class ProxyConfig {
    public static final ProxyConfig Instance = new ProxyConfig();
    public final static boolean IS_DEBUG = true;
    public static String AppInstallID;
    public static String AppVersion;
    public final static int FAKE_NETWORK_MASK = CommonMethods.ipStringToInt("255.255.0.0");
    public final static int FAKE_NETWORK_IP = CommonMethods.ipStringToInt("10.231.0.0");

    ArrayList<IPAddress> m_IpList;
    ArrayList<IPAddress> m_DnsList;
    ArrayList<Config> m_ProxyList;
    HashMap<String, Boolean> m_DomainMap;

    int m_dns_ttl = 10;
    String m_welcome_info = "welcome_info";
    String m_session_name = "session_name";
    String m_user_agent = System.getProperty("http.agent");

    //尝试发送请求头的一部分，让请求头的host在第二个包里面发送，从而绕过机房的白名单机制。
    boolean m_isolate_http_host_header = true;
    int m_mtu = 1500;

    public ProxyConfig() {
        m_IpList = new ArrayList<IPAddress>();
        m_DnsList = new ArrayList<IPAddress>();
        m_ProxyList = new ArrayList<Config>();
        m_DomainMap = new HashMap<String, Boolean>();

        m_IpList.add(new IPAddress("26.26.26.2", 32));
        m_DnsList.add(new IPAddress("119.29.29.29"));
        m_DnsList.add(new IPAddress("223.5.5.5"));
        m_DnsList.add(new IPAddress("8.8.8.8"));
    }

    public void addProxy(String proxy) {
        Config config = HttpConnectConfig.parse(proxy);
        if (!m_ProxyList.contains(config)) {
            m_ProxyList.add(config);
        }
    }

    public static boolean isFakeIP(int ip) {
        return (ip & ProxyConfig.FAKE_NETWORK_MASK) == ProxyConfig.FAKE_NETWORK_IP;
    }

    public Config getDefaultProxy() {
        if (m_ProxyList.isEmpty()) {
            return HttpConnectConfig.parse("http://127.0.0.1:8787");
        } else {
            return m_ProxyList.get(0);
        }
    }

    public Config getDefaultTunnelConfig(InetSocketAddress destAddress) {
        return getDefaultProxy();
    }

    public IPAddress getDefaultLocalIP() {
        if (m_IpList.size() > 0) {
            return m_IpList.get(0);
        } else {
            return new IPAddress("10.8.0.2", 32);
        }
    }

    public ArrayList<IPAddress> getDnsList() {
        return m_DnsList;
    }

    public int getDnsTTL() {
        return m_dns_ttl;
    }

    public String getWelcomeInfo() {
        return m_welcome_info;
    }

    public String getSessionName() {
        if (m_session_name == null) {
            m_session_name = getDefaultProxy().ServerAddress.getHostName();
        }
        return m_session_name;
    }

    public String getUserAgent() {
        if (m_user_agent == null || m_user_agent.isEmpty()) {
            m_user_agent = System.getProperty("http.agent");
        }
        return m_user_agent;
    }

    public int getMTU() {
        return m_mtu;
    }

    public void resetDomain(String[] items) {
        m_DomainMap.clear();
        addDomainToHashMap(items, 0, true);
    }

    private void addDomainToHashMap(String[] items, int offset, Boolean state) {
        for (int i = offset; i < items.length; i++) {
            String domainString = items[i].toLowerCase().trim();
            if (domainString.length() == 0) continue;
            if (domainString.charAt(0) == '.') {
                domainString = domainString.substring(1);
            }
            m_DomainMap.put(domainString, state);
        }
    }

    private Boolean getDomainState(String domain) {
        domain = domain.toLowerCase(Locale.ENGLISH);
        while (domain.length() > 0) {
            Boolean stateBoolean = m_DomainMap.get(domain);
            if (stateBoolean != null) {
                return stateBoolean;
            } else {
                int start = domain.indexOf('.') + 1;
                if (start > 0 && start < domain.length()) {
                    domain = domain.substring(start);
                } else {
                    return null;
                }
            }
        }
        return null;
    }

    public boolean needProxy(String host, int ip) {
        if (host != null) {
            Boolean stateBoolean = getDomainState(host);
            if (stateBoolean != null) {
                return stateBoolean.booleanValue();
            }
        }

        if (isFakeIP(ip)) {
            return true;
        }

        if (ip != 0) {
            if (!ChinaIpMaskManager.isIPInChina(ip)) {
                return true;
            }
        }
        return false;
    }

    public boolean isIsolateHttpHostHeader() {
        return m_isolate_http_host_header;
    }

    public class IPAddress {
        public final String Address;
        public final int PrefixLength;

        public IPAddress(String address, int prefixLength) {
            this.Address = address;
            this.PrefixLength = prefixLength;
        }

        public IPAddress(String ipAddresString) {
            String[] arrStrings = ipAddresString.split("/");
            String address = arrStrings[0];
            int prefixLength = 32;
            if (arrStrings.length > 1) {
                prefixLength = Integer.parseInt(arrStrings[1]);
            }
            this.Address = address;
            this.PrefixLength = prefixLength;
        }

        @Override
        public String toString() {
            return String.format(Locale.ENGLISH, "%s/%d", Address, PrefixLength);
        }

        @Override
        public boolean equals(Object o) {
            if (o == null) {
                return false;
            } else {
                return this.toString().equals(o.toString());
            }
        }
    }

}
