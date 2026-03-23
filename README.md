# [cite_start]LLM 기반 마우스 액션 연동 개인용 보안 시스템 [cite: 2, 3]

## 📌 프로젝트 소개
[cite_start]웹 서핑 중 발생하는 사회공학적 피싱 및 지능형 위협을 LLM(Gemini)을 통해 실시간으로 탐지하는 시스템입니다. [cite: 11, 13]

## 🛠 주요 기능
1. [cite_start]**호버링 분석**: 링크 위에 마우스를 올리면 URL 위험도 판별 [cite: 31, 54]
2. [cite_start]**드래그 분석**: 메일이나 메시지 텍스트를 드래그하면 사기 의도 파악 [cite: 12, 48]
3. [cite_start]**쉬운 보안 가이드**: 🟢🟡🔴 신호등 이모지와 쉬운 언어로 위험성 설명 [cite: 58]

## ⚙️ 기술 스택
- **Backend**: FastAPI, google-genai, Redis, SQLite
- **Frontend**: Chrome Extension (Manifest V3)
