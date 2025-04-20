# FUZZmap 

<div align="center">

[![Python 3.13.0](https://img.shields.io/badge/python-3.13.0-yellow.svg)](https://www.python.org/)
[![라이센스](https://img.shields.io/badge/license-MIT-red.svg)](LICENSE)

**웹 애플리케이션 취약점 퍼징 도구**

*현재 버전: 0.2 (SQL Injection, XSS)*

</div>

<p align="center">
  <img src="https://img.shields.io/badge/%F0%9F%94%8D-퍼징-blueviolet" alt="퍼징">
  <img src="https://img.shields.io/badge/%F0%9F%93%8A-파라미터%20수집-green" alt="파라미터 수집">
  <img src="https://img.shields.io/badge/%F0%9F%9B%A1%EF%B8%8F-취약점%20탐지-orange" alt="취약점 탐지">
</p>

FUZZmap은 취약점을 탐지하는 웹 애플리케이션 취약점 퍼징 도구입니다. 자동화된 파라미터 수집과 심화 페이로드 테스트를 통해 웹 애플리케이션의 보안 취약점을 식별합니다.
![alt text](image.png)

## 💻 FUZZmap 개발자
- [arrester](https://github.com/arrester)
- [jhanks](https://github.com/jeongahn)
- [mathe](https://github.com/ma4the)
- [arecia](https://github.com/areciah)
- [hansowon](https://github.com/hansowon)

## ✨ 주요 기능

- **파라미터 수집**
- **공통 페이로드 검사**
- **심화 페이로드 검사** 
  - **SQL Injection 검사** - error based, time based, boolean based를 포함한 심화 분석 (v0.1)
  - **XSS 검사** - Advanced XSS (v0.2)
  - **SSTI 검사** - *(v0.3에서 심화 분석 추가 예정)*
- **비동기 아키텍처** - 최적화된 동시 테스트를 위한 `asyncio`와 세마포어 활용
- **확장 가능한 프레임워크** - 향후 버전에서 새로운 취약점 유형을 쉽게 추가할 수 있도록 설계

## 📋 설치 방법

### pip
```bash
# 설치
pip install fuzzmap
```

### Github
```bash
# 저장소 복제
git clone https://github.com/offensive-tooling/FUZZmap.git
cd fuzzmap

# 설치
pip install -e .
```

## 🚀 사용법

### 명령줄 사용법

```bash
# 특정 파라미터 테스트
fuzzmap -t <target_url> -m get -p <target_parameter>

# 여러 파라미터 테스트
fuzzmap -t <target_url> -m get -p <target_parameter 1>, <target_parameter 2>

# POST 메소드 사용
fuzzmap -t <target_url> -m post -p <target_parameter>

# 자동 파라미터 수집 후 테스트
fuzzmap -t <target_url> -rp
```

### Python 모듈 사용법

```python
import asyncio
from fuzzmap.core.controller.controller import Controller

async def main():
    # Test with specific parameters
    fm = Controller(target="http://target.com", method="GET", param=["target_parameter"])
    results = await fm.async_run()
    
    # Test with Parameter Reconnaissance
    fm = Controller(target="http://target.com", recon_param=True)
results = await fm.async_run()

asyncio.run(main())
```

## 🛠️ 작동 방식

FUZZmap은 다음 네 가지 주요 단계로 작동합니다:

1. **파라미터 수집**: 다음을 통해 자동으로 파라미터를 식별합니다:
   - URL 쿼리 추출
   - Form field 분석 (입력, 선택, 텍스트영역)
   - Form action path와 method로 부터 수집
   - (JavaScript에 숨겨진 파라미터 - 향후 추가 예정)
   - *(향후 동적 파라미터 수집 모듈 추가 예정)*

2. **공통 페이로드 검사**: 공통 페이로드를 통해 여러 취약점들의 가능성을 판단합니다:
   - SQL Injection
   - XSS (Cross Site Scripting)
   - SSTI (Server Side Template Injection)
   - *(향후 지속적으로 추가 예정)*

3. **심화 페이로드 검사** (현재 SQL Injection만 지원): 공통 페이로드를 통해 발견된 취약점에 대한 자세한 검사를 진행합니다.
   - SQL Injection (error based, time based, boolean based)
   - *(v0.2에서 XSS 페이로드 및 기능 추가 예정)*
   - *(v0.3에서 SSTI 페이로드 및 기능 추가 예정)*

4. **결과 분류**: 다음과 같이 발견 내용을 분류합니다:
   - 취약점 유형 및 하위 유형
   - 탐지 신뢰도 점수 (0-100%)
   - 탐지 내용 및 증거

## 📊 출력 예시

```
handler: common, advanced
🎯 url: http://target.com/
parameters: ['test', 'searchFor']
method: GET
Type: xss
💰 Detected: True
Common_payload: '"><iframe onload=alert('{{1234**3}}');>
Common_Confidence: 50
🔍 Detail_Vuln: Error-Based SQL Injection
Advanced_payload: ' UNION SELECT NULL-- -
Advanced_Confidence: 100
Context: ECT NULL-- -</h2>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '

------------------------------------------------------------------
handler: common, advanced
🎯 url: http://target.com/
parameters: ['test', 'searchFor']
method: GET
Type: sql_injection
💰 Detected: True
Common_payload: ' || BEGIN DBMS_SESSION.SLEEP(5); END; -- 
Common_Confidence: 70
🔍 Detail_Vuln: Error-Based SQL Injection
Advanced_payload: ' UNION SELECT NULL-- -
Advanced_Confidence: 100
Context: ECT NULL-- -</h2>Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '
```

## ⚙️ 명령줄 옵션

```
-t, --target    🎯 스캔할 대상 URL
-m, --method    📡 HTTP 메소드 (GET/POST)
-p, --param     🔍 테스트할 파라미터 (쉼표로 구분)
-rp, --recon    🔎 파라미터 자동 수집(정찰) 활성화
-v, --verbose   📝 상세 출력 활성화
-h, --help      ℹ️  도움말 메시지 표시
```

## 📝 번역

- [영어 (원문)](../../../README.md)
- [한국어](README-ko-KR.md)


## 🔔 면책 조항

FUZZmap은 적절한 권한이 있는 정당한 보안 테스트를 위해 설계되었습니다. 웹사이트나 애플리케이션을 테스트하기 전에 항상 권한이 있는지 확인하세요.

---

<div align="center">
>FUZZmap - 슬로건 (추가 예정)</b>
</div>