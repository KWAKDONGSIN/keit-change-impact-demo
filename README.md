# 규정 변경영향 검토 시제품

규정의 변경 전·후 조항을 비교하고, 바뀐 조항이 제품 표시 문안에 줄 수 있는 영향을 **사람이 검토할 후보**로 정리하는 정적 웹 시제품입니다. 「2026 AI 라이프 솔루션 챌린지」 출품용 시제품입니다.

- 테스트 주소: https://kwakdongsin.github.io/keit-change-impact-demo/
- 예시 데이터는 모두 **가상 규정·가상 문안(합성 데이터)**이며 실제 법규가 아닙니다.
- 이 도구의 결과는 정답이나 **법적 판정이 아닙니다.** 최종 판단은 사람이 원문을 보고 합니다.
- 서버·API 키·외부 라이브러리가 없습니다. 화면은 AI를 직접 호출하지 않고, 선택한 파일은 브라우저 안에서만 읽습니다.

## 써 보기
1. 예시 파일을 내려받습니다: [before.json](samples/before.json) · [after.json](samples/after.json) · [labels.json](samples/labels.json) (보류 사례 `samples/hold/`, 명령문 의심 사례 `samples/after-malicious.json`)
2. 테스트 주소에서 세 파일을 차례로 고르면 조항이 변경없음·수정·추가·삭제로 나뉘고 AI 입력(프롬프트와 SHA-256)이 만들어집니다.
3. 4단계에서 [evidence/claude-inference.json](evidence/claude-inference.json)(위 예시로 실제 받은 Claude 결과)을 고르면 인용·해시 검증 결과가 표시됩니다.

## 시험
Node 18 이상에서 저장소 루트에서 `node --test`를 실행합니다(설치할 것 없음).
