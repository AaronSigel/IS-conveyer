# Формат Технического Отчёта

Итоговый markdown-отчёт является техническим отчётом по результатам проверки защищённости хостов. Он не является академической пояснительной запиской и не содержит титульный лист, реферат, содержание, приложения, сводную таблицу findings или отдельный remediation plan.

Основной результат отчёта - раздел `5 ПАСПОРТА ВЫЯВЛЕННЫХ УЯЗВИМОСТЕЙ И НЕСООТВЕТСТВИЙ`. Для каждого finding, прошедшего фильтрацию, формируется отдельный паспорт выявленной уязвимости / несоответствия.

## Структура

```text
ОТЧЁТ О РЕЗУЛЬТАТАХ ПРОВЕРКИ ЗАЩИЩЁННОСТИ ХОСТОВ

0 СВЕДЕНИЯ ОБ ОТЧЁТЕ
1 ОБЩИЕ СВЕДЕНИЯ О ПРОВЕРКЕ
2 СВЕДЕНИЯ ОБ ОБЪЕКТЕ ПРОВЕРКИ
3 МЕТОДИКА ПРОВЕДЕНИЯ ПРОВЕРКИ
4 ОБОБЩЁННЫЕ РЕЗУЛЬТАТЫ ПРОВЕРКИ
5 ПАСПОРТА ВЫЯВЛЕННЫХ УЯЗВИМОСТЕЙ И НЕСООТВЕТСТВИЙ
6 ЗАКЛЮЧЕНИЕ
```

Сводка в разделе 4 строится только по findings, которые прошли фильтрацию. Отдельная таблица со списком всех findings не используется.

## Паспорт

Паспорт строится по подходу ГОСТ Р 56545-2015 и содержит:

- наименование уязвимости / несоответствия;
- идентификатор паспорта `ISCV-YYYY-NNNN`;
- внешние идентификаторы, включая Rule ID, CVE, CWE, BDU при наличии;
- класс уязвимости;
- тип недостатка;
- место возникновения / проявления;
- объект проверки;
- способ обнаружения и источник данных;
- уровень опасности, статус и CVSS;
- описание, доказательство, возможные последствия и возможные меры устранения.

План устранения не выносится в отдельный раздел. Он находится внутри каждого паспорта в поле `Возможные меры по устранению уязвимости`.

## Фильтры

`scripts/generate-report.py` поддерживает фильтры:

- `--status`
- `--severity`
- `--category`
- `--source`
- `--host`
- `--rule-id`
- `--finding-type`
- `--cvss-min`
- `--cvss-max`

Фильтры со списками принимают значения через запятую. Если фильтры не указаны, в отчёт включаются все findings. Если после фильтрации findings не осталось, отчёт всё равно создаётся, а раздел 5 содержит сообщение об отсутствии уязвимостей и несоответствий по заданным критериям.

## Примеры

```bash
python scripts/generate-report.py \
  --findings artifacts/unified-findings.json \
  --profile profiles/host-baseline-v1.yml \
  --metadata config/report-metadata.yml \
  --output report/technical-report.md \
  --status failed \
  --severity high,critical
```

```bash
python scripts/generate-report.py \
  --findings artifacts/unified-findings.json \
  --output report/cvss-report.md \
  --source wazuh_vulnerability \
  --cvss-min 5.0
```

```bash
python scripts/generate-report.py \
  --findings artifacts/unified-findings.json \
  --output report/target1-report.md \
  --host target1 \
  --status failed
```

## Mapping Finding -> Passport

Для SCA findings используется тип `configuration_noncompliance`. Способ обнаружения формируется как `Wazuh SCA check <sca_check_id>`, CVSS считается неприменимым. Если в профиле у правила есть блок `passport`, из него берутся класс уязвимости, тип недостатка, affected component, location, impact, detection method и external IDs.

Для CVE findings с `source == wazuh_vulnerability`, `source == wazuh-indexer-vulnerabilities` или `finding_type == software_vulnerability` используется класс `Уязвимость программного обеспечения`. Наименование ПО и версия берутся из `affected_component` или evidence `Package: ...`; CVE берётся из `external_ids.cve`, `finding.cve`, `rule_id` или evidence; CVSS берётся из `finding.cvss` или evidence `CVSS base: ...`.

При отсутствии данных генератор использует безопасные значения `не определено`, `не применимо` и `данные отсутствуют`.
