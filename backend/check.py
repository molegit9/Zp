from google import genai

try:
    client = genai.Client()
    print("--- 내 계정에서 사용 가능한 모델 진짜 이름 ---")
    for model in client.models.list():
        # 리스트가 너무 길어질 수 있으니 3.1이나 gemma가 들어간 것만 필터링합니다
        if "3.1" in model.name or "gemma" in model.name:
            print(model.name)
except Exception as e:
    print("에러:", e)