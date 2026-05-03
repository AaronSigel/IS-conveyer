# {{ report.title }}

Дата формирования: {{ report.generated_at }}

Проверяемый объект: {{ report.system_name }}

Проверенные хосты: {{ report.stats.hosts|join(", ") if report.stats.hosts else "нет данных" }}

Версия инструмента: {{ report.tool_version }}

Источник данных: {{ report.source }}

## 1. Общие сведения о проверке

Цель проверки: автоматизированная оценка состояния конфигурации устройства и установленного программного обеспечения по данным Wazuh.

Объект проверки: {{ report.system_name }}.

Используемые инструменты: Wazuh SCA, Wazuh Vulnerability Detection, IS-conveyer reporting.

Ограничения проверки: система анализирует конфигурацию устройства и установленное программное обеспечение, но не выполняет полноценное исследование архитектуры, организационных процессов и эксплуатации ИС.

## 2. Методика проверки

Данные получены из Wazuh JSON, нормализованы, дедуплицированы и преобразованы в технические findings/passport. Результаты разделены на два класса: уязвимости кода, выявляемые через CVE в установленных пакетах, и уязвимости конфигурации, выявляемые через SCA-проверки настроек, политик и небезопасных параметров.

## 3. Агрегированная статистика

| Показатель | Значение |
|---|---:|
| Проверено хостов | {{ report.stats.hosts_count }} |
| Обработано исходных findings | {{ report.stats.processed_findings }} |
| Нормализовано findings | {{ report.stats.normalized_findings }} |
| Уникальных findings после дедупликации | {{ report.stats.unique_findings }} |
| Включено в основной отчёт | {{ report.stats.included_findings }} |
| Уникальных CVE | {{ report.stats.unique_cve }} |
| Уязвимых пакетов | {{ report.stats.vulnerable_packages }} |
| Конфигурационных нарушений | {{ report.stats.configuration_failures }} |
| Отброшено фильтрами | {{ report.stats.dropped|json|md }} |

### Распределение по критичности

| Уровень | Количество |
|---|---:|
{% for severity, count in report.stats.by_severity.items() -%}
| {{ severity }} | {{ count }} |
{% endfor %}

### Распределение по статусам SCA/findings

| Статус | Количество |
|---|---:|
{% for status, count in report.stats.by_status.items() -%}
| {{ status }} | {{ count }} |
{% endfor %}

## 4. Уязвимости установленного программного обеспечения

{% for host, rows in report.software_by_host.items() %}
### {{ host }}

| Host ID | Хост | ОС | Пакет | Установленная версия | Исправленная версия | CVE | Критичность | CVSS | Описание | Источник | Рекомендации/ссылки | Статус |
|---|---|---|---|---|---|---|---|---:|---|---|---|---|
{% for row in rows -%}
| {{ row.host_id|md }} | {{ row.host|md }} | {{ row.os|md }} | {{ row.package|md }} | {{ row.installed_version|md }} | {{ row.fixed_version|md }} | {{ row.cve|md }} | {{ row.severity|md }} | {{ row.cvss|md }} | {{ row.description|md }} | {{ row.source|md }} | {{ row.references|md }} | {{ row.status|md }} |
{% endfor %}

{% else %}
Значимые уязвимости установленного ПО по заданным фильтрам не выявлены.
{% endfor %}

## 5. Нарушения конфигурации

{% for host, rows in report.configuration_by_host.items() %}
### {{ host }}

| Host ID | Хост | ID проверки | Название проверки | Описание нарушения | Критичность | Фактическое значение | Ожидаемое состояние | Рекомендация | Стандарт/политика |
|---|---|---|---|---|---|---|---|---|---|
{% for row in rows -%}
| {{ row.host_id|md }} | {{ row.host|md }} | {{ row.check_id|md }} | {{ row.title|md }} | {{ row.description|md }} | {{ row.severity|md }} | {{ row.actual|md }} | {{ row.expected|md }} | {{ row.remediation|md }} | {{ row.standard|md }} |
{% endfor %}

{% else %}
Значимые конфигурационные нарушения по заданным фильтрам не выявлены.
{% endfor %}

## 6. Приоритеты устранения

| Проблема | Тип | Критичность | Затронутые хосты | Количество | Рекомендация |
|---|---|---|---|---:|---|
{% for item in report.priorities -%}
| {{ item.title|md }} | {{ item.type|md }} | {{ item.severity|md }} | {{ item.assets|md }} | {{ item.count }} | {{ item.recommendation|md }} |
{% else -%}
| нет данных | нет данных | нет данных | нет данных | 0 | нет данных |
{% endfor %}

## 7. Вывод

{{ report.conclusion }}

## 8. Приложение A. Паспортная модель findings

| ID | Тип уязвимости | Источник | Объект воздействия | Компонент | Описание | Условия проявления | Уровень опасности | Возможные последствия | Способ обнаружения | Рекомендации | Ссылки | Статус |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
{% for passport in report.passports -%}
| {{ passport.id|md }} | {{ passport.type|md }} | {{ passport.source|md }} | {{ passport.target_object|md }} | {{ passport.component|md }} | {{ passport.description|md }} | {{ passport.conditions|md }} | {{ passport.severity|md }} | {{ passport.impact|md }} | {{ passport.detection_method|md }} | {{ passport.remediation|md }} | {{ passport.references|md }} | {{ passport.status|md }} |
{% endfor %}

{% if report.options.include_raw_appendix %}
## 9. Приложение B. Исходные JSON-артефакты

```json
{{ report.raw_appendix|json }}
```
{% endif %}
