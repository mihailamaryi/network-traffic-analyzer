import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
from datetime import datetime, timedelta
import threading
import logging
import os
import random
from collections import defaultdict
import numpy as np

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Настройка страницы
st.set_page_config(
    page_title="Advanced Network Analysis",
    layout="wide",
    page_icon="🌐"
)

st.title("🌐 Advanced Network Traffic Analysis")
st.write("Расширенная версия с аналитикой и обнаружением аномалий")


class AdvancedPacketProcessor:
    """Продвинутый процессор с аналитикой"""

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

        # Для расширенной аналитики
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
        """Классифицирует порт по типу сервиса"""
        return self.common_ports.get(port, f'Port {port}')

    def detect_anomalies(self, packet_info):
        """Обнаружение подозрительной активности"""
        anomalies = []

        # Проверка необычно больших пакетов
        if packet_info['size'] > 1500:
            anomalies.append(f"Большой пакет: {packet_info['size']} байт")

        # Проверка нестандартных портов
        if 'src_port' in packet_info:
            if packet_info['src_port'] < 1024 and packet_info['src_port'] not in self.common_ports:
                anomalies.append(f"Нестандартный системный порт: {packet_info['src_port']}")

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

                    packets_to_generate = random.randint(3, 15)

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

                            # Обнаружение аномалий (иногда искусственно создаем)
                            if random.random() < 0.05:  # 5% chance for demo anomalies
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

                    time.sleep(0.1)

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

                                # Извлекаем порты
                                if TCP in packet:
                                    packet_info['src_port'] = packet[TCP].sport
                                    packet_info['dst_port'] = packet[TCP].dport
                                    packet_info['service'] = self.classify_port(packet[TCP].dport)
                                elif UDP in packet:
                                    packet_info['src_port'] = packet[UDP].sport
                                    packet_info['dst_port'] = packet[UDP].dport
                                    packet_info['service'] = self.classify_port(packet[UDP].dport)

                                # Обнаружение аномалий
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

    # ДОБАВЛЯЕМ ОТСУТСТВУЮЩИЕ МЕТОДЫ:

    def get_dataframe(self):
        """Возвращает DataFrame с данными"""
        with self.lock:
            return pd.DataFrame(self.packet_data)

    def get_protocol_stats_df(self):
        """Возвращает статистику по протоколам"""
        with self.lock:
            data = []
            total = sum(self.protocol_stats.values())

            for protocol, count in self.protocol_stats.items():
                percentage = (count / total * 100) if total > 0 else 0
                data.append({
                    'protocol': protocol,
                    'count': count,
                    'percentage': percentage
                })

            return pd.DataFrame(data)

    def get_timeline_df(self):
        """Возвращает данные для графика пакетов в секунду"""
        with self.lock:
            return pd.DataFrame(self.timeline_data)

    def get_protocols_timeline_df(self):
        """Возвращает данные для графика по протоколам в длинном формате"""
        with self.lock:
            if not self.timeline_data:
                return pd.DataFrame()

            # Преобразуем в длинный формат для Plotly
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

    def get_metrics(self):
        """Возвращает метрики"""
        with self.lock:
            duration = (datetime.now() - self.start_time).total_seconds()
            rate = self.total_packets / duration if duration > 0 else 0

            # Текущая скорость (последние 5 секунд)
            recent_total = 0
            recent_entries = []
            if self.timeline_data:
                recent_entries = self.timeline_data[-5:]
                recent_total = sum(entry.get('total', 0) for entry in recent_entries)
            current_rate = recent_total / 5 if recent_entries else rate

            return {
                'total_packets': self.total_packets,
                'duration': duration,
                'rate_per_sec': rate,
                'current_rate': current_rate,
                'unique_sources': len(self.source_stats),
                'unique_protocols': len(self.protocol_stats),
                'mode': 'DEMO' if self.demo_mode else 'REAL'
            }

    def get_service_stats_df(self):
        """Статистика по сервисам"""
        with self.lock:
            data = []
            total = sum(self.port_stats.values())

            for service, count in self.port_stats.items():
                percentage = (count / total * 100) if total > 0 else 0
                data.append({
                    'service': service,
                    'count': count,
                    'percentage': percentage
                })

            return pd.DataFrame(data)

    def get_anomalies_df(self):
        """Данные об аномалиях"""
        with self.lock:
            return pd.DataFrame(self.suspicious_activity)

    def get_traffic_summary(self):
        """Сводка по трафику"""
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
        """Останавливает захват"""
        self._running = False


# Инициализация процессора
if 'processor' not in st.session_state:
    demo_mode = True
    try:
        import scapy

        if os.name == 'nt':
            import ctypes

            demo_mode = not ctypes.windll.shell32.IsUserAnAdmin()
    except:
        demo_mode = True

    st.session_state.processor = AdvancedPacketProcessor(demo_mode=demo_mode)

processor = st.session_state.processor
summary = processor.get_traffic_summary()

# Боковая панель
st.sidebar.title("📊 Панель управления")
st.sidebar.write(f"**Режим:** {'🎭 Демо' if processor.demo_mode else '🔴 Реальный'}")

# Основные метрики
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

# Вкладки для разных видов аналитики
tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Обзор", "🔍 Аналитика", "⚠️ Безопасность", "🌐 Сервисы", "📋 Данные"])

with tab1:
    st.subheader("📊 Обзор трафика")

    # Графики пакетов по протоколам
    protocols_timeline_df = processor.get_protocols_timeline_df()
    if len(protocols_timeline_df) > 0:
        fig_protocols_timeline = px.line(
            protocols_timeline_df,
            x='timestamp',
            y='packets_per_second',
            color='protocol',
            title="Пакеты в секунду по протоколам",
            labels={'packets_per_second': 'Пакетов/секунду', 'timestamp': 'Время'},
            color_discrete_map={
                'TCP': 'blue',
                'UDP': 'green',
                'ICMP': 'red',
                'IGMP': 'orange'
            }
        )
        fig_protocols_timeline.update_layout(
            hovermode='x unified',
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig_protocols_timeline, use_container_width=True)

    # Распределение протоколов
    protocol_df = processor.get_protocol_stats_df()
    if len(protocol_df) > 0:
        col1, col2 = st.columns(2)

        with col1:
            fig_pie = px.pie(
                protocol_df,
                values='count',
                names='protocol',
                title="Распределение протоколов"
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with col2:
            fig_bar = px.bar(
                protocol_df,
                x='protocol',
                y='percentage',
                title="Процентное распределение",
                text=protocol_df['percentage'].round(1).astype(str) + '%'
            )
            fig_bar.update_traces(textposition='outside')
            st.plotly_chart(fig_bar, use_container_width=True)

with tab2:
    st.subheader("🔍 Детальная аналитика")

    # Распределение по сервисам
    service_df = processor.get_service_stats_df()
    if len(service_df) > 0:
        col1, col2 = st.columns(2)

        with col1:
            fig_services = px.pie(
                service_df,
                values='count',
                names='service',
                title="Распределение по сервисам"
            )
            st.plotly_chart(fig_services, use_container_width=True)

        with col2:
            # Топ источников трафика
            sources_df = pd.DataFrame([
                {'source': source, 'count': count}
                for source, count in list(processor.source_stats.items())[:10]
            ])

            if len(sources_df) > 0:
                fig_sources = px.bar(
                    sources_df,
                    x='source',
                    y='count',
                    title="Топ 10 источников трафика"
                )
                st.plotly_chart(fig_sources, use_container_width=True)

with tab3:
    st.subheader("⚠️ Мониторинг безопасности")

    anomalies_df = processor.get_anomalies_df()
    if len(anomalies_df) > 0:
        st.warning(f"Обнаружено подозрительных событий: {len(anomalies_df)}")

        # График аномалий по времени
        if 'timestamp' in anomalies_df.columns:
            anomalies_df['time'] = pd.to_datetime(anomalies_df['timestamp']).dt.strftime('%H:%M:%S')
            st.dataframe(anomalies_df[['time', 'source', 'anomaly']], use_container_width=True)
    else:
        st.success("✅ Подозрительная активность не обнаружена")

with tab4:
    st.subheader("🌐 Анализ сервисов")

    # Статистика по портам/сервисам
    if len(service_df) > 0:
        # Детальная таблица сервисов
        st.dataframe(service_df.sort_values('count', ascending=False), use_container_width=True)

        # График использования сервисов
        fig_service_trend = px.area(
            service_df.nlargest(8, 'count'),
            x='service',
            y='count',
            title="Наиболее активные сервисы"
        )
        st.plotly_chart(fig_service_trend, use_container_width=True)

with tab5:
    st.subheader("📋 Детальные данные")

    # Расширенная таблица пакетов
    df = processor.get_dataframe()
    if len(df) > 0:
        display_df = df.tail(50).copy()
        if 'timestamp' in display_df.columns:
            display_df['time'] = pd.to_datetime(display_df['timestamp']).dt.strftime('%H:%M:%S.%f')[:-3]

        # Показываем только нужные колонки
        columns_to_show = ['time', 'source', 'destination', 'protocol', 'service', 'size']
        if 'anomalies' in display_df.columns:
            columns_to_show.append('anomalies')

        st.dataframe(display_df[columns_to_show], use_container_width=True, height=500)

# Кнопки управления
st.sidebar.markdown("---")
if st.sidebar.button("🔄 Перезапустить"):
    if 'processor' in st.session_state:
        st.session_state.processor.stop()
    st.session_state.clear()
    st.rerun()

if st.sidebar.button("📊 Экспорт данных"):
    # Здесь можно добавить экспорт в CSV
    st.sidebar.info("Экспорт данных (в разработке)")

# Авто-обновление
time.sleep(3)
st.rerun()