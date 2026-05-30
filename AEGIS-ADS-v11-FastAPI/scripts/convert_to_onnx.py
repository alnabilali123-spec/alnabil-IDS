import os, torch
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

def convert(model_path, output_path):
    os.makedirs(output_path, exist_ok=True)
    tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)

    # تحميل النموذج مع تجاهل عدم تطابق الأحجام
    model = DistilBertForSequenceClassification.from_pretrained(
        model_path,
        ignore_mismatched_sizes=True  # هذا يحل المشكلة
    )
    model.eval()

    # إدخال وهمي
    dummy_text = "test"
    inputs = tokenizer(dummy_text, return_tensors="pt")

    torch.onnx.export(
        model,
        (inputs["input_ids"], inputs["attention_mask"]),
        os.path.join(output_path, "model.onnx"),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "sequence"},
            "attention_mask": {0: "batch", 1: "sequence"},
            "logits": {0: "batch"},
        },
        opset_version=14,
    )
    tokenizer.save_pretrained(output_path)
    print(f"✅ ONNX model saved to {output_path}")

if __name__ == "__main__":
    convert("models/deep", "models/deep_onnx")