import streamlit as st
import pandas as pd
import plotly.express as px
import time
from datetime import datetime, timedelta
import threading
import logging
import os
import random
from collections import defaultdict

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Автоматическое определение режима
def get_environment_mode():
    """Определяет, где запущено приложение"""
    # Streamlit Cloud или другая облачная платформа
    cloud_env_vars = ['STREAMLIT_SHARING', 'STREAMLIT_SERVER_HEADLESS', 'COLAB_GPU']
    if any(var in os.environ for var in cloud_env_vars):
        return "CLOUD"

    # Локальная Windows с правами администратора
    try:
        if os.name == 'nt':
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return "LOCAL_ADMIN"
    except:
        pass

    # Локальная Windows/Mac/Linux без прав
    return "LOCAL_NO_ADMIN"


ENVIRONMENT_MODE = get_environment_mode()

# Настройка страницы
st.set_page_config(
    page_title="Network Traffic Analyzer",
    layout="wide",
    page_icon="🌐"
)

st.title("🌐 Network Traffic Analyzer")

# Показываем информацию о режиме
if ENVIRONMENT_MODE == "CLOUD":
    st.warning("🌐 **Веб-версия**: Режим демонстрации с искусственными данными")
    st.info("""
    💡 **Для реального мониторинга сети:**
    - Скачайте код с GitHub
    - Запустите локально с правами администратора
    - Получите доступ к реальному сетевому трафику
    """)
    DEMO_MODE = True
elif ENVIRONMENT_MODE == "LOCAL_ADMIN":
    st.success("🔴 **Локальная версия**: Режим реального захвата пакетов")
    DEMO_MODE = False
else:
    st.warning("💻 **Локальная версия**: Запустите с правами администратора для реального захвата")
    DEMO_MODE = True


class UniversalPacketProcessor:
    """Универсальный процессор для любого окружения"""

    def __init__(self, demo_mode=True):
        self.demo_mode = demo_mode
        self.protocol_map = {
            0: 'HOPOPT', 1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP',
            41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF'
        }

        # Основные структуры данных
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.packet_data = []
        self.protocol_stats = defaultdict(int)
        self.source_stats = defaultdict(int)
        self.destination_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.total_packets = 0
        self._running = True

        # Для аналитики
        self.timeline_data = []
        self.last_timeline_update = datetime.now()
        self.current_second_stats = defaultdict(int)
        self.suspicious_activity = []

        # Порты для классификации
        self.common_ports = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH',
            25: 'SMTP', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS',
            995: 'POP3S', 21: 'FTP', 23: 'Telnet', 3389: 'RDP'
        }

        if not demo_mode:
            self.setup_real_capture()
        else:
            self.setup_demo_capture()

    def get_protocol_name(self, protocol_num):
        return self.protocol_map.get(protocol_num, f'UNKNOWN({protocol_num})')

    def classify_port(self, port):
        return self.common_ports.get(port, f'Port {port}')

    def detect_anomalies(self, packet_info):
        anomalies = []
        if packet_info['size'] > 1500:
            anomalies.append(f"Большой пакет: {packet_info['size']} байт")
        return anomalies

    def setup_demo_capture(self):
        def demo_capture():
            sources = [f"192.168.1.{i}" for i in range(1, 50)] + ["10.0.0.5", "172.16.0.10"]
            destinations = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '10.0.0.1', 'google.com', 'youtube.com']
            protocols = ['TCP', 'UDP', 'ICMP']

            while self._running:
                try:
                    current_time = datetime.now()
                    current_second = current_time.replace(microsecond=0)

                    packets_to_generate = random.randint(5, 25)

                    with self.lock:
                        for _ in range(packets_to_generate):
                            protocol = random.choice(protocols)
                            src_port = random.choice([80, 443, 53, 22, 8080, 3000, 5000])
                            dst_port = random.choice([80, 443, 53, 22, 8080])

                            packet = {
                                'timestamp': current_time,
                                'source': random.choice(sources),
                                'destination': random.choice(destinations),
                                'protocol': protocol,
                                'src_port': src_port,
                                'dst_port': dst_port,
                                'size': random.randint(60, 1200),
                                'service': self.classify_port(dst_port)
                            }

                            if random.random() < 0.03:
                                packet['size'] = random.randint(2000, 5000)
                                packet['anomalies'] = ["Большой пакет для тестирования"]

                            self.packet_data.append(packet)
                            self.protocol_stats[protocol] += 1
                            self.source_stats[packet['source']] += 1
                            self.destination_stats[packet['destination']] += 1
                            self.port_stats[packet['service']] += 1
                            self.total_packets += 1
                            self.current_second_stats[protocol] += 1

                        if current_time - self.last_timeline_update >= timedelta(seconds=1):
                            timeline_entry = {
                                'timestamp': current_second,
                                'total': sum(self.current_second_stats.values())
                            }
                            for protocol, count in self.current_second_stats.items():
                                timeline_entry[protocol] = count

                            self.timeline_data.append(timeline_entry)
                            self.last_timeline_update = current_time
                            self.current_second_stats.clear()

                            if len(self.timeline_data) > 120:
                                self.timeline_data.pop(0)

                        if len(self.packet_data) > 5000:
                            self.packet_data = self.packet_data[-5000:]

                    time.sleep(0.05)

                except Exception as e:
                    logger.error(f"Demo error: {e}")
                    time.sleep(1)

        thread = threading.Thread(target=demo_capture, daemon=True)
        thread.start()

    def setup_real_capture(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP

            def real_capture():
                current_second = datetime.now().replace(microsecond=0)

                def process_packet(packet):
                    nonlocal current_second

                    if not self._running:
                        return False

                    try:
                        if IP in packet:
                            with self.lock:
                                protocol_num = packet[IP].proto
                                protocol_name = self.get_protocol_name(protocol_num)
                                current_time = datetime.now()

                                packet_info = {
                                    'timestamp': current_time,
                                    'source': packet[IP].src,
                                    'destination': packet[IP].dst,
                                    'protocol': protocol_name,
                                    'size': len(packet)
                                }

                                if TCP in packet:
                                    packet_info['src_port'] = packet[TCP].sport
                                    packet_info['dst_port'] = packet[TCP].dport
                                    packet_info['service'] = self.classify_port(packet[TCP].dport)
                                elif UDP in packet:
                                    packet_info['src_port'] = packet[UDP].sport
                                    packet_info['dst_port'] = packet[UDP].dport
                                    packet_info['service'] = self.classify_port(packet[UDP].dport)

                                anomalies = self.detect_anomalies(packet_info)
                                if anomalies:
                                    packet_info['anomalies'] = anomalies
                                    self.suspicious_activity.append({
                                        'timestamp': current_time,
                                        'source': packet_info['source'],
                                        'anomaly': anomalies[0]
                                    })

                                self.packet_data.append(packet_info)
                                self.protocol_stats[protocol_name] += 1
                                self.source_stats[packet_info['source']] += 1
                                self.destination_stats[packet_info['destination']] += 1

                                if 'service' in packet_info:
                                    self.port_stats[packet_info['service']] += 1

                                self.total_packets += 1
                                self.current_second_stats[protocol_name] += 1

                                if current_time - current_second >= timedelta(seconds=1):
                                    timeline_entry = {
                                        'timestamp': current_second,
                                        'total': sum(self.current_second_stats.values())
                                    }
                                    for protocol, count in self.current_second_stats.items():
                                        timeline_entry[protocol] = count

                                    self.timeline_data.append(timeline_entry)
                                    current_second = current_time.replace(microsecond=0)
                                    self.current_second_stats.clear()

                                    if len(self.timeline_data) > 120:
                                        self.timeline_data.pop(0)

                                if len(self.packet_data) > 5000:
                                    self.packet_data.pop(0)

                    except Exception as e:
                        logger.error(f"Packet processing error: {e}")

                while self._running:
                    try:
                        sniff(prn=process_packet, store=False, count=50, timeout=1)
                    except Exception as e:
                        logger.error(f"Sniff error: {e}")
                        time.sleep(1)

            thread = threading.Thread(target=real_capture, daemon=True)
            thread.start()

        except ImportError:
            self.demo_mode = True
            self.setup_demo_capture()

    # ... остальные методы (get_dataframe, get_protocol_stats_df и т.д.) ...
    def get_dataframe(self):
        with self.lock:
            return pd.DataFrame(self.packet_data)

    def get_protocol_stats_df(self):
        with self.lock:
            data = []
            total = sum(self.protocol_stats.values())
            for protocol, count in self.protocol_stats.items():
                percentage = (count / total * 100) if total > 0 else 0
                data.append({'protocol': protocol, 'count': count, 'percentage': percentage})
            return pd.DataFrame(data)

    def get_timeline_df(self):
        with self.lock:
            return pd.DataFrame(self.timeline_data)

    def get_protocols_timeline_df(self):
        with self.lock:
            if not self.timeline_data:
                return pd.DataFrame()
            long_data = []
            for entry in self.timeline_data:
                timestamp = entry['timestamp']
                for protocol, count in entry.items():
                    if protocol not in ['timestamp', 'total']:
                        long_data.append({
                            'timestamp': timestamp,
                            'protocol': protocol,
                            'packets_per_second': count
                        })
            return pd.DataFrame(long_data)

    def get_service_stats_df(self):
        with self.lock:
            data = []
            total = sum(self.port_stats.values())
            for service, count in self.port_stats.items():
                percentage = (count / total * 100) if total > 0 else 0
                data.append({'service': service, 'count': count, 'percentage': percentage})
            return pd.DataFrame(data)

    def get_anomalies_df(self):
        with self.lock:
            return pd.DataFrame(self.suspicious_activity)

    def get_traffic_summary(self):
        with self.lock:
            duration = (datetime.now() - self.start_time).total_seconds()
            total_size = sum(p['size'] for p in self.packet_data) if self.packet_data else 0
            return {
                'total_packets': self.total_packets,
                'total_bytes': total_size,
                'duration': duration,
                'avg_packet_size': total_size / self.total_packets if self.total_packets > 0 else 0,
                'unique_sources': len(self.source_stats),
                'unique_destinations': len(self.destination_stats),
                'unique_services': len(self.port_stats),
                'anomalies_detected': len(self.suspicious_activity)
            }

    def stop(self):
        self._running = False


# Инициализация процессора
if 'processor' not in st.session_state:
    st.session_state.processor = UniversalPacketProcessor(demo_mode=DEMO_MODE)

processor = st.session_state.processor
summary = processor.get_traffic_summary()

# Боковая панель
st.sidebar.title("📊 Панель управления")
mode_status = "🎭 Демо-режим" if DEMO_MODE else "🔴 Режим реального захвата"
st.sidebar.write(f"**Режим:** {mode_status}")

if ENVIRONMENT_MODE == "CLOUD":
    st.sidebar.info("""
    **Для реального мониторинга:**
    1. Скачайте код с GitHub
    2. Установите Python и зависимости
    3. Запустите с правами администратора
    """)

# Основные метрики и вкладки (остальной код как раньше)...
st.subheader("📈 Основные метрики")
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Пакеты", f"{summary['total_packets']:,}")
with col2:
    st.metric("Объем", f"{summary['total_bytes'] / 1024:.1f} KB")
with col3:
    st.metric("Источники", summary['unique_sources'])
with col4:
    st.metric("Сервисы", summary['unique_services'])
with col5:
    st.metric("Аномалии", summary['anomalies_detected'])

# Вкладки
tab1, tab2, tab3 = st.tabs(["📊 Обзор трафика", "🌐 Аналитика сервисов", "⚠️ Безопасность"])

with tab1:
    # Графики из предыдущей версии
    protocols_timeline_df = processor.get_protocols_timeline_df()
    if len(protocols_timeline_df) > 0:
        fig = px.line(
            protocols_timeline_df,
            x='timestamp',
            y='packets_per_second',
            color='protocol',
            title="Пакеты в секунду по протоколам"
        )
        st.plotly_chart(fig, use_container_width=True)

with tab2:
    service_df = processor.get_service_stats_df()
    if len(service_df) > 0:
        fig = px.pie(service_df, values='count', names='service', title="Распределение по сервисам")
        st.plotly_chart(fig, use_container_width=True)

with tab3:
    anomalies_df = processor.get_anomalies_df()
    if len(anomalies_df) > 0:
        st.warning(f"Обнаружено аномалий: {len(anomalies_df)}")
        st.dataframe(anomalies_df, use_container_width=True)
    else:
        st.success("✅ Аномалий не обнаружено")

# Кнопки управления
st.sidebar.markdown("---")
if st.sidebar.button("🔄 Перезапустить"):
    if 'processor' in st.session_state:
        st.session_state.processor.stop()
    st.session_state.clear()
    st.rerun()

# Инструкция для пользователей
st.sidebar.markdown("---")
st.sidebar.subheader("📖 Инструкция")
st.sidebar.write("""
1. **Веб-версия**: Только демонстрация
2. **Локальный запуск**: Реальный мониторинг
3. **Требуется**: Права администратора
""")

# Авто-обновление
time.sleep(3)
st.rerun()