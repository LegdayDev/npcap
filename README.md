## 0. 시작 전 세팅
- npcap 파일들을 C드라이브 바로 아래에 두고 `npcap` 이라는 명칭으로 이름변경
- 해당 프로젝트를 시작프로젝트로 설정
- 프로젝트를 더블클릭 후 alt + F7 클릭하여 속성창 열기
1. VC++ 디렉터리 -> 일반 -> 외부 include 디렉터리 -> `C:\npcap\include` 추가
2. VC++ 디렉터리 -> 일반 -> 라이브러리 디렉터리 -> `C:\npcap\Lib\x64` 추가
3. 링커 -> 입력 -> 지연 로드된 DLL 에 `wpcap.dll` 추가.

## 1. 빌드 및 실행
- `F7` 로 빌드 후 `Ctrl + F5` 로 실행
![image](https://github.com/user-attachments/assets/9bfd5ef1-0264-4827-b5a2-ca82b0aeb2a1)
