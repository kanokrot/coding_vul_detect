import google.generativeai as genai

# ใส่ Key คุณตรงนี้
genai.configure(api_key="AIzaSyCJcBadA2FsVbkh0NjzGtear4Yr5duPmcI")

print("Checking available models...")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f"✅ Found: {m.name}")
except Exception as e:
    print(f"❌ Error: {e}")