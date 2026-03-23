# 🛡️ AI 기반 실시간 보안 링크 검사기 (AI Security Link Analyzer)

웹 서핑 중 클릭하기 전, **마우스를 올리거나(Hover) 드래그하는 텍스트/링크**를 실시간으로 분석하여 피싱, 악성코드 등 보안 위협을 경고해주는 Chrome 확장 프로그램 및 백엔드 시스템입니다. (VirusTotal 및 Google Gemini API 사용)

---

## ⚙️ 프로젝트 구동 방식 (How it works)

이 프로젝트는 크게 **Chrome 익스텐션(Frontend)**과 **FastAPI(Backend)** 두 부분으로 나누어 동작합니다.

1. **Chrome 확장 프로그램 분기:** 사용자가 웹페이지 내의 링크에 마우스를 올리면 `content.js`가 해당 링크를 가로채어 백엔드 서버(`/api/analyze`)로 전송합니다.
2. **백엔드 분석 흐름 (FastAPI + Redis + SQLite):** 
   - **캐시 검사 (Cache Check):** 빠른 응답 속도와 API 비용 절감을 위해 이전에 검사된 결과가 Redis 캐시나 SQLite DB에 있는지 우선 확인합니다.
   - **1차 검증 (VirusTotal API):** 요청이 링크(URL)인 경우 `VirusTotal API`를 통해 악성 URL 여부를 1차 검증합니다. 안전한 경우 `VT_SAFE` (🟢) 상태를 반환합니다.
   - **2차 심층 분석 (Google Gemini API):** VirusTotal에서 판단이 불가능하거나 악성으로 의심될 경우, 일반 텍스트 문맥 분석을 위해 LLM인 `Gemini API`에 전달하여 문맥과 의도를 파악합니다. 분석 결과에 따라 `GEMINI_SAFE` (🟡) 또는 `DANGER` (🔴) 상태를 판단합니다.
3. **분석 결과 시각화:** 익스텐션은 백엔드의 응답을 받아 안전(초록), 주의(노랑), 위험(빨강) 등의 시각적 표시(이모지 및 색상)와 함께 툴팁으로 상세한 이유를 렌더링합니다.

---

## 🚀 다운로드 및 실행 방법 (How to Run)

### 1단계: 사전 필수 환경 준비
이 프로젝트를 실행하기 위해 아래 프로그램과 API 키가 필요합니다.
* **Python 3.8 이상** 설치
* **[Redis](https://redis.io/docs/install/install-redis/)**: (선택 사항) 캐싱을 위한 데이터베이스입니다. 설치되어 있지 않아도 프로그램은 돌아갑니다.
* **Google Gemini API Key** 발급
* **VirusTotal API Key** 발급

### 2단계: 프로젝트 다운로드
1. GitHub 페이지에서 `Code` 버튼을 눌러 프로젝트를 **다운로드 (Download ZIP)** 하거나 터미널에서 다음 명령어로 클론합니다:
   ```bash
   git clone https://github.com/본인계정/프로젝트명.git
   cd 프로젝트명
   ```

### 3단계: 백엔드 서버 구동 (Backend Setup)
1. 백엔드 디렉토리로 이동합니다.
   ```bash
   cd backend
   ```
2. API 통신을 위한 환경 변수를 설정합니다. (`본인_API_키` 대신 발급받은 실제 키를 넣으세요.)
   * **Windows (PowerShell)**
     ```powershell
     $env:GEMINI_API_KEY="본인_Gemini_API_키"
     $env:VIRUSTOTAL_API_KEY="본인_VirusTotal_API_키"
     ```
   * **Mac/Linux (Terminal)**
     ```bash
     export GEMINI_API_KEY="본인_Gemini_API_키"
     export VIRUSTOTAL_API_KEY="본인_VirusTotal_API_키"
     ```
3. 필요한 패키지 모듈을 설치합니다.
   ```bash
   pip install -r requirements.txt
   ```
4. FastAPI 백엔드 서버를 실행합니다.
   ```bash
   python main.py
   ```
   > 정상적으로 실행되면 `http://0.0.0.0:8000` (또는 `http://localhost:8000`)에서 서버가 열린 것을 확인할 수 있습니다.

### 4단계: Chrome 확장 프로그램 설치 (Extension Setup)
1. 크롬 브라우저를 열고 주소창에 `chrome://extensions/`를 입력하여 설정 페이지에 접속합니다.
2. 우측 상단의 **'개발자 모드(Developer mode)'** 스위치를 켭니다.
3. 좌측 상단에 나타나는 **'압축해제된 확장 프로그램을 로드합니다(Load unpacked)'** 버튼을 클릭합니다.
4. 다운로드 받은 프로젝트 폴더 내부에 있는 `extension` 폴더를 찾아 **선택(로드)** 합니다.
5. 브라우저 주소창 옆 퍼즐 버튼을 눌러 익스텐션이 성공적으로 추가되었는지 확인합니다.

---

🎉 **이제 모든 준비가 끝났습니다!** 브라우저에서 알 수 없는 링크 주변에 마우스를 맴돌면, 자동으로 동작하며 툴팁 경고창이 나타나는 것을 테스트해보세요.
