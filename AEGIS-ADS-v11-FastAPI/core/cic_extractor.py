# core/cic_extractor.py
import subprocess, os, tempfile, logging, time

logger = logging.getLogger(__name__)

def extract_features_from_pcap(pcap_path, timeout=30):
    """
    تشغيل cicflowmeter على ملف pcap وإرجاع مسار ملف CSV الناتج.
    """
    try:
        csv_path = pcap_path.replace('.pcap', '.csv')
        cmd = f'cicflowmeter -f "{pcap_path}" -c "{csv_path}"'
        logger.info(f"🔄 Running cicflowmeter: {cmd}")

        result = subprocess.run(cmd, shell=True, timeout=timeout, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"cicflowmeter error: {result.stderr}")
            return None

        waited = 0
        while not os.path.exists(csv_path) and waited < 10:
            time.sleep(0.5)
            waited += 0.5

        if os.path.exists(csv_path):
            size = os.path.getsize(csv_path)
            if size == 0:
                logger.warning(f"⚠️ cicflowmeter produced empty CSV (0 bytes)")
                os.remove(csv_path)
                return None
            logger.info(f"✅ cicflowmeter generated CSV: {csv_path} ({size} bytes)")
            # طباعة أول 5 أسطر للتشخيص
            try:
                with open(csv_path, 'r') as f:
                    for i in range(5):
                        line = f.readline()
                        if line:
                            logger.info(f"CSV line {i+1}: {line.strip()}")
            except Exception as e:
                logger.warning(f"Could not read CSV preview: {e}")
            return csv_path
        else:
            logger.error("cicflowmeter did not produce CSV")
            return None
    except Exception as e:
        logger.error(f"cicflowmeter failed: {e}")
        return None

def load_features(csv_path, expected_features):
    """تحميل الميزات من CSV وتنظيفها وإرجاع list of dicts"""
    import pandas as pd
    try:
        df = pd.read_csv(csv_path)
        if df.empty:
            logger.warning("CSV file is empty, no flows found")
            return []

        df.columns = [c.strip() for c in df.columns]
        logger.info(f"CSV columns: {list(df.columns)}")
        logger.info(f"Number of rows: {len(df)}")

        # محاولة مطابقة الأسماء الأصلية لـ CIC-IDS2017 (قد تختلف قليلاً)
        available = [f for f in expected_features if f in df.columns]
        if not available:
            logger.warning(f"No direct match. Trying to map common names...")
            # قاموس ترجمة بسيط
            name_map = {
                'Source IP': 'Src IP',
                'Destination IP': 'Dst IP',
                'Source Port': 'Src Port',
                'Destination Port': 'Dst Port',
                'Protocol': 'Protocol',
                'Flow Duration': 'Flow Duration',
                'Total Fwd Packets': 'Total Fwd Packets',
                'Total Backward Packets': 'Total Backward Packets',
                # أضف المزيد حسب الحاجة
            }
            for csv_col in df.columns:
                if csv_col in name_map:
                    df.rename(columns={csv_col: name_map[csv_col]}, inplace=True)
            # إعادة المحاولة
            available = [f for f in expected_features if f in df.columns]
        
        if not available:
            logger.warning(f"Still no matching features. Expected: {expected_features[:5]}...")
            logger.warning(f"Actual columns: {list(df.columns)[:10]}...")
            return []
        
        logger.info(f"Found {len(available)}/{len(expected_features)} matching features")
        return df[available].fillna(0).to_dict('records')
    except Exception as e:
        logger.error(f"Failed to load features from CSV: {e}")
        return []
    finally:
        if os.path.exists(csv_path):
            os.remove(csv_path)