import pickle, os

model_path = "models/xgb_classifier.pkl"
model = pickle.load(open(model_path, "rb"))

# محاولة استخراج أسماء الميزات من النموذج
try:
    # XGBoost يحفظ أسماء الميزات في booster.feature_names
    names = model.get_booster().feature_names
    print("✅ أسماء الميزات العشر المطلوبة (xgb_classifier):")
    for i, n in enumerate(names, 1):
        print(f"  {i}. {n}")
except Exception as e:
    print("❌ لا يمكن استخراج الأسماء تلقائياً:", e)
    print("عدد الميزات المتوقع:", model.n_features_in_)