# Web Scanner

`web-scanner`는 승인된 대상에 대해서만 사용하는 CLI 중심의 방어적 스캐닝 오케스트레이터입니다.
검증된 외부 도구를 감싸서 사용하고, 재개 가능한 상태를 SQLite에 저장하며, 원시 아티팩트를
보관하고, 결과를 일관된 증거 기반 포맷으로 정규화합니다.

## 안전 범위

- 승인된 방어적 진단에만 사용해야 합니다.
- 안전한 기본값만 제공합니다.
- 익스플로잇 전달 기능은 없습니다.
- 자격 증명 공격 기능은 없습니다.
- 은닉, 우회, 지속성, 파괴적 점검 기능은 없습니다.
- CVE 매칭은 후보(candidate)만 제공합니다. 취약점 확정 결과가 아닙니다.

## 현재 기능

- `subdomain_enum`: `subfinder`, `assetfinder`, `crt.sh`를 우선 사용하는 무료 도구 중심 서브도메인 수집
- `http_probe`: `httpx` 기반 도달 가능 여부, 타이틀, 기본 HTTP 증거 수집
- `dir_enum`: 살아 있는 HTTP 대상에 대한 `ffuf` 디렉터리 열거
- `port_scan`: `nmap` 기반 TCP 포트 및 서비스 탐지
- `cve_match`: 기존 관측 증거만 사용하는 오프라인 후보 CVE 매칭

## 요구 사항

- Python 3.12+
- `PATH`에서 실행 가능한 `subfinder`
- `PATH`에서 실행 가능한 `assetfinder`
- 인증서 투명성 조회를 위한 `crt.sh` 접근 가능 상태
- `PATH`에서 실행 가능한 `httpx`
- `PATH`에서 실행 가능한 `ffuf`
- `PATH`에서 실행 가능한 `nmap`
- `dir_enum` 실행 시 사용할 로컬 `ffuf` 워드리스트

권장 확인 명령:

```bash
subfinder -version
assetfinder --help | head -n 3
httpx -version
ffuf -V
nmap --version | head -n 1
```

기본 `ffuf` 워드리스트 경로는 현재 `wordlists/test.txt` 입니다.

## 설치

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## 환경 변수

페이즈 실행 전에 예제 파일을 복사한 뒤 셸에 export 해서 사용하세요.
이 프로젝트는 `.env` 파일을 자동으로 로드하지 않습니다.

```bash
cp .env.example .env
set -a
source .env
set +a
```

기본 무료 수집 흐름에서는 필수 환경 변수가 없습니다.

## `source .venv/bin/activate` 이후 바로 할 일

새 터미널이라면 먼저 `~/go/bin`이 잡히도록 한 번 읽어오는 것이 안전합니다.

```bash
source ~/.zshrc
cd Vantage-AI
source .venv/bin/activate
cp .env.example .env
set -a
source .env
set +a
```

그다음 외부 도구가 실제로 보이는지 확인합니다.

```bash
subfinder -version
assetfinder --help | head -n 3
httpx -version
ffuf -V
nmap --version | head -n 1
```

여기까지 끝나면 run 생성과 phase 실행을 바로 시작할 수 있습니다.

## 웹 UI 사용

웹 UI는 현재 3단계 흐름으로 분리되어 있습니다.

1. `/`
   - 최초 진입 landing 페이지
   - `Run Scan` / `Show Result` 두 개의 큰 진입 버튼 제공
2. `/execution`
   - run 생성과 기본 설정
   - target, preset, profile, wordlist, scope, auth header 입력
3. `/progress/<run_id>`
   - 실행 중 task 스택 확인
   - `pending`, `running`, `completed`, `failed`, `cancelled` 상태를 누적 형태로 표시
   - start / resume / cancel / live logs 확인
4. `/results/<run_id>`
   - host-centric 결과 분석
   - host별 포트, HTTP, 디렉터리, CVE 후보, artifacts, diff 확인

UI 실행:

```bash
python -m scanner.cli ui --host 127.0.0.1 --port 8000
```

브라우저에서:

```text
http://127.0.0.1:8000/
```

페이지 역할은 이렇게 이해하면 됩니다.

- Execution: 스캔을 만들고 옵션을 조정하는 곳
- Progress: 실제 진행 상황과 작업 스택을 보는 곳
- Results: 결과를 host 중심으로 분석하는 곳

## Target 입력 규칙

입력값은 대상 유형에 맞게 넣는 것이 중요합니다.

- 도메인/FQDN:
  - `example.com`
  - `naver.com`
- 로컬/특정 포트 호스트:
  - `localhost:3000`
  - `127.0.0.1:8080`
- URL 형태:
  - 가능하면 권장하지 않음
  - 특별한 이유가 없으면 `http://` / `https://` 없이 입력하는 편이 안전함

현재 분기 원칙:

- 도메인/FQDN:
  - domain-first
  - 필요 시 `subdomain_enum`부터 시작
- IP / localhost / private host:
  - host-first
  - `port_scan -> http_probe` 중심으로 시작

즉 로컬 Docker 앱은 보통 `localhost:3000`처럼 넣는 것이 가장 안정적입니다.

## 워드리스트

이 저장소는 실제 디렉터리 워드리스트를 포함하지 않습니다. 직접 준비한 안전하고, 라이선스상
문제가 없고, 사용 권한이 있는 워드리스트를 `wordlists/` 아래나 별도 경로에 두고 사용하세요.

중요 사항:

- `dir_enum` 실행 전에는 `ffuf_wordlist_path`가 반드시 설정되어 있어야 합니다.
- 현재 CLI에는 `--wordlist` 옵션이 아직 없습니다.
- UI 기본값은 `wordlists/test.txt` 입니다.
- `dir_enum`을 실행할 계획이라면, 실행 전에 run config가 유효한 로컬 워드리스트 경로를
  가리키는지 확인하세요.

자세한 내용은 `wordlists/README.md`를 참고하세요.

## CLI 흐름

현재 CLI 표면은 작고 안전하게 유지되어 있습니다.

- `scan`: 새 run을 만들고, 설정/상태를 저장하고, 선택한 모듈의 pending task를 큐에 넣습니다.
- `extend`: 기존 run에 새 모듈을 추가하고, 저장된 finding/artifact/완료 task는 유지한 채 후속 phase를 붙입니다.
- `resume`: 기존 run을 불러와 아직 끝나지 않은 task를 보여줍니다.
- `report`: 저장된 finding/artifact를 읽어 JSON 요약을 stdout으로 출력합니다.
- `report --html`: JSON 요약을 계속 출력하면서 읽기 쉬운 HTML 보고서도 함께 작성합니다.

중요 사항:

- `scan`은 외부 스캐너를 즉시 실행하지 않습니다.
- `resume`도 task를 실행하지 않습니다.
- 실제 페이즈 실행은 애플리케이션 레이어의 phase runner가 담당합니다.

서브도메인 수집의 기본 소스 순서는 다음과 같습니다.

- `subfinder`
- `assetfinder`
- `crt.sh`

## 현재 페이즈 실행 방법

아직 페이즈 실행 전용 CLI 명령은 노출되어 있지 않습니다. 큐에 들어간 페이즈를 실행하려면,
run을 만든 동일한 워크스페이스에서 phase helper를 호출하세요.

```bash
python - <<'PY'
from scanner.runner import (
    execute_cve_match_tasks,
    execute_dir_enum_tasks,
    execute_http_probe_tasks,
    execute_port_scan_tasks,
    execute_subdomain_enum_tasks,
)

run_id = "run-20260409123000-ab12cd34"

print(execute_subdomain_enum_tasks(run_id))
print(execute_http_probe_tasks(run_id))
print(execute_dir_enum_tasks(run_id))
print(execute_port_scan_tasks(run_id))
print(execute_cve_match_tasks(run_id))
PY
```

페이즈는 순서대로 실행하세요. 각 페이즈는 재개 가능하며, 이전 페이즈의 저장된 결과를
입력으로 사용합니다. `dir_enum`을 실행할 계획이라면 먼저 `ffuf_wordlist_path`가 설정되어
있는지 확인하세요.

## CLI 예시 명령

기본 모듈 세트로 run 생성:

```bash
python -m scanner.cli scan example.com
```

특정 모듈과 속도 프로필로 run 생성:

```bash
python -m scanner.cli scan example.com \
  --module subdomain_enum \
  --module http_probe \
  --profile balanced
```

실제 테스트를 시작할 때는 먼저 `dir_enum` 없이 돌리는 것을 권장합니다.
현재 공개 CLI에는 워드리스트 경로를 직접 넘기는 옵션이 없기 때문입니다.

권장 시작 명령:

```bash
python -m scanner.cli scan example.com \
  --module subdomain_enum \
  --module http_probe \
  --module port_scan \
  --module cve_match \
  --profile safe
```

이 명령은 실제 스캐너를 바로 실행하지 않고, 새 run을 만들고 pending task만 큐에 넣습니다.
출력 JSON의 `run_id` 값을 다음 단계에서 사용합니다.

예를 들어 출력에 다음과 같은 값이 보이면:

```json
{
  "run_id": "run-20260409170000-ab12cd34"
}
```

다음처럼 실제 phase를 순서대로 실행합니다.

```bash
python - <<'PY'
from scanner.runner import (
    execute_cve_match_tasks,
    execute_http_probe_tasks,
    execute_port_scan_tasks,
    execute_subdomain_enum_tasks,
)

run_id = "run-20260409170000-ab12cd34"

print(execute_subdomain_enum_tasks(run_id))
print(execute_http_probe_tasks(run_id))
print(execute_port_scan_tasks(run_id))
print(execute_cve_match_tasks(run_id))
PY
```

`dir_enum`까지 포함해 실제 스캔하려면 먼저 유효한 워드리스트 경로가 run config에 들어가 있어야 합니다.
그 전에는 아래처럼 `dir_enum`을 포함한 run만 만들어 두고 실제 실행은 보류하는 편이 안전합니다.

```bash
python -m scanner.cli scan example.com \
  --module subdomain_enum \
  --module http_probe \
  --module dir_enum \
  --module port_scan \
  --module cve_match \
  --profile balanced
```

기존 run의 재개 가능한 상태 확인:

```bash
python -m scanner.cli resume run-20260409123000-ab12cd34
```

저장된 결과를 유지한 채 기존 run에 후속 phase 추가:

```bash
python -m scanner.cli extend run-20260409123000-ab12cd34 \
  --module subdomain_enum \
  --module dir_enum
```

run의 JSON 요약 보고서 출력:

```bash
python -m scanner.cli report run-20260409123000-ab12cd34
```

JSON 요약을 계속 stdout에 출력하면서 HTML 보고서도 작성:

```bash
python -m scanner.cli report run-20260409123000-ab12cd34 \
  --html reports/run-20260409123000-ab12cd34.html
```

## 중간 결과 기반 후속 실행

run은 저장된 상태를 기준으로 이어서 실행할 수 있습니다. 예를 들어:

1. 처음에는 `port_scan`만 포함한 run 생성
2. 해당 phase 실행 후 SQLite/state/artifact 확인
3. 같은 run에 `subdomain_enum`, `dir_enum` 같은 모듈을 `extend` 또는 Progress 화면의 Run Options에서 추가
4. 다시 실행하면 새로 추가된 pending task만 이어서 수행

기존 finding, artifact, 완료된 task는 같은 run에 그대로 유지됩니다.

## 웹 UI 권장 사용 흐름

가장 추천하는 흐름은 다음과 같습니다.

1. landing 페이지 `/` 접속
2. `Run Scan` 클릭
3. `/execution`에서 run 생성
4. 생성 직후 `/progress/<run_id>`에서 실행 스택과 logs 확인
5. 필요하면 `View Results` 또는 `/results/<run_id>`로 이동
6. host별로 triage
7. 필요하면 HTML 보고서 열기

### 실행 페이지에서 보는 것

- target
- preset / profile
- modules
- `FFUF Wordlist Path`
- `Nmap Ports`
- `Extra Headers`
- `Cookies`
- `Bearer Token`
- `Host Header`
- `Scope Include` / `Scope Exclude`

### 진행 페이지에서 보는 것

- 현재 상태 hero
- pending / running / completed / failed / cancelled task stack
- progress
- execution notes
- live logs

### 결과 페이지에서 보는 것

- run summary
- key findings
- diff
- host navigator
- host detail tabs
  - overview
  - port scan
  - subdomains
  - directory scan
  - http probe
  - candidate CVEs
  - artifacts / logs

## 로컬 테스트 예시

예를 들어 Docker로 띄운 Juice Shop이 `http://localhost:3000/`에 있다면:

- Target: `localhost:3000`
- Modules:
  - `http_probe`
  - `dir_enum`
  - `port_scan`
  - `cve_match`
- FFUF Wordlist Path:
  - `wordlists/test.txt`
- Nmap Ports:
  - `3000`
- Profile:
  - `safe`

이 경우 보통:

- `http_probe`는 alive/title/기술 증거를 수집하고
- `dir_enum`은 `test.txt` 기준으로 빠르게 경로를 확인하고
- `port_scan`은 `3000/tcp` 상태를 확인하고
- `cve_match`는 후보 CVE만 추론합니다

후보 CVE는 어디까지나 후보이며 확정 취약점이 아닙니다.

## 출력물

### `runs/`

각 run은 자체 디렉터리를 가집니다.

```text
runs/<run_id>/
├── state.db
└── artifacts/
```

- `state.db`: run 상태, task, finding, artifact 참조를 담는 SQLite 데이터베이스
- `artifacts/`: `subfinder`, `assetfinder`, `crt.sh`, `httpx`, `ffuf`, `nmap` 같은 도구의 원시 출력 파일

### `reports/`

- `report --html`로 생성되는 HTML 보고서
- 생성된 보고서 파일을 위한 기본 디렉터리

참고: 현재 CLI는 JSON 요약을 stdout으로 출력합니다. JSON 보고서 파일을 자동으로 디스크에
저장하지는 않습니다.

### Artifacts

원시 도구 출력은 `runs/<run_id>/artifacts/` 아래에 저장되고 SQLite에서 참조됩니다.
데이터베이스에는 경로, 해시, 크기, 콘텐츠 타입 같은 메타데이터만 저장되며, 원시 본문은
SQLite 행에 직접 저장되지 않습니다.

### Findings

정규화된 finding은 SQLite에 저장되며 `report` 명령으로 조회할 수 있습니다.
모든 finding은 증거 기반이며 보고서에서는 다음처럼 구분됩니다.

- 서브도메인
- 살아 있는 호스트 / HTTP 프로브 결과
- 디렉터리 결과
- 열린 포트 / 서비스
- 후보 CVE

## 후보 CVE

이 프로젝트의 CVE 매칭은 추론 기반 후보 결과입니다. 타이틀, 제품명, 버전, 서비스 배너 같은
이전에 관측된 증거를 바탕으로 생성됩니다.

모든 후보는 수동 검증이 필요한 단서로 취급해야 하며, 확정된 취약점으로 간주하면 안 됩니다.
