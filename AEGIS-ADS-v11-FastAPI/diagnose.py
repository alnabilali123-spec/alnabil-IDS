import pickle
import sys
import os

# إعداد المسارات بناءً على هيكل مشروعك
MODEL_DIR = "models"
FEATURES_FILE = os.path.join(MODEL_DIR, "features.pkl")

print("="*50)
print("تشخيص نظام AEGIS-ADS")
print("="*50)

# 1. فحص ملف features.pkl (ما يتوقعه النموذج)
print("\n[1] فحص ملف الميزات المرجعي (features.pkl):")
try:
    with open(FEATURES_FILE, 'rb') as f:
        reference_features = pickle.load(f)
    print(f"   ✅ تم تحميل الميزات المرجعية.")
    print(f"   📊 العدد: {len(reference_features)} ميزة")
    # طباعة أول 5 ميزات للتأكد
    print(f"   📝 أول 5 ميزات: {reference_features[:5]}")
except Exception as e:
    print(f"   ❌ فشل تحميل features.pkl: {e}")
    reference_features = None

# 2. محاولة معرفة الميزات التي يستخرجها الـ Sniffer
print("\n[2] فحص الميزات المنتجة من الـ Feature Extractor:")
try:
    # نحاول استيراد دالة extract_features
    sys.path.append(os.getcwd()) # إضافة المجلد الحالي للمسار
    from core.feature_extractor import extract_features
    
    # إنشاء حزمة وهمية للفحص
    class MockPacket:
        def __init__(self):
            self.src = "192.168.1.1"
            self.dst = "8.8.8.8"
            self.sport = 12345
            self.dport = 80
            self.proto = 6 # TCP
            self.len = 500
        def haslayer(self, layer):
            return False

    mock_packet = MockPacket()
    features_dict = extract_features(mock_packet)
    
    if isinstance(features_dict, dict):
        print(f"   ✅ تم استخراج الميزات التجريبية.")
        print(f"   📊 العدد: {len(features_dict)} ميزة")
        print(f"   📝 أسماء الميزات: {list(features_dict.keys())[:10]}...")
    else:
        print(f"   ⚠️ دالة extract_features لم ترجع dict.")
        
except ImportError:
    print("   ❌ لا يمكن استيراد extract_features. تأكد من وجود core.feature_extractor.py")
except Exception as e:
    print(f"   ❌ فشل استخراج الميزات: {e}")

# 3. خلاصة التشخيص
print("\n" + "="*50)
if reference_features:
    print("🔴 الخلاصة: يجب أن ينتج feature_extractor عدد ميزات مساوٍ تماماً لـ:")
    print(f"   {len(reference_features)} ميزة (الموجودة في features.pkl).")
    print("   إذا كان عدد الميزات التي استخرجتها مختلفاً، فهذا هو سبب المشكلة.")
else:
    print("🔴 الخلاصة: لم يتم العثور على ملف features.pkl. تأكد من مساره.")
print("="*50)