# Технический отчёт по результатам автоматизированной проверки ИБ

Дата формирования: 2026-05-03T09:22:08+03:00

Проверяемый объект: Проверяемая информационная система

Проверенные хосты: target1, target2

Версия инструмента: IS-conveyer technical MVP

Источник данных: report\samples\wazuh-mvp

## 1. Общие сведения о проверке

Цель проверки: автоматизированная оценка состояния конфигурации устройства и установленного программного обеспечения по данным Wazuh.

Объект проверки: Проверяемая информационная система.

Используемые инструменты: Wazuh SCA, Wazuh Vulnerability Detection, IS-conveyer reporting.

Ограничения проверки: система анализирует конфигурацию устройства и установленное программное обеспечение, но не выполняет полноценное исследование архитектуры, организационных процессов и эксплуатации ИС.

## 2. Методика проверки

Данные получены из Wazuh JSON, нормализованы, дедуплицированы и преобразованы в технические findings/passport. Результаты разделены на два класса: уязвимости кода, выявляемые через CVE в установленных пакетах, и уязвимости конфигурации, выявляемые через SCA-проверки настроек, политик и небезопасных параметров.

## 3. Агрегированная статистика

| Показатель | Значение |
|---|---:|
| Проверено хостов | 2 |
| Обработано исходных findings | 4 |
| Нормализовано findings | 4 |
| Уникальных findings после дедупликации | 4 |
| Включено в основной отчёт | 3 |
| Уникальных CVE | 1 |
| Уязвимых пакетов | 1 |
| Конфигурационных нарушений | 2 |
| Отброшено фильтрами | {<br>  "passed": 1<br>} |

### Распределение по критичности

| Уровень | Количество |
|---|---:|
| critical | 1 |
| high | 1 |
| medium | 1 |
| low | 0 |
| info | 0 |

### Распределение по статусам SCA/findings

| Статус | Количество |
|---|---:|
| fail | 3 |
| pass | 1 |
| not_applicable | 0 |
| unknown | 0 |

## 4. Уязвимости установленного программного обеспечения

### target1

| Host ID | Хост | ОС | Пакет | Установленная версия | Исправленная версия | CVE | Критичность | CVSS | Описание | Источник | Рекомендации/ссылки | Статус |
|---|---|---|---|---|---|---|---|---:|---|---|---|---|
| 001 | target1 | Ubuntu 24.04.4 LTS (Noble Numbat) | sudo | 1.9.15p5-3ubuntu5 | 1.9.15p5-3ubuntu5.24.04.1 | CVE-2025-32463 | critical | 9.3 | Sudo chroot option local privilege escalation. | Canonical Security Tracker | https://cti.wazuh.com/vulnerabilities/cves/CVE-2025-32463, https://ubuntu.com/security/CVE-2025-32463, https://www.cve.org/CVERecord?id=CVE-2025-32463 | fail |


## 5. Нарушения конфигурации

### target1

| Host ID | Хост | ID проверки | Название проверки | Описание нарушения | Критичность | Фактическое значение | Ожидаемое состояние | Рекомендация | Стандарт/политика |
|---|---|---|---|---|---|---|---|---|---|
| unknown | target1 | cis 1.1.1.1 | 1.1.1.1 Ensure cramfs kernel module is not available (Automated) | The cramfs filesystem type is not commonly used and should be disabled. | high | failed | r:^install /bin/false | Edit or create a file in `/etc/modprobe.d/` ending in `.conf` and add `install cramfs /bin/false`. | cis |
| unknown | target1 | cis 5.1.20 | 5.1.20 Ensure X11 forwarding is disabled (Automated) | The SSH daemon should not permit X11 forwarding. | medium | failed | r:^x11forwarding no$ | Set `X11Forwarding no` in sshd configuration and restart SSH. | cis |


## 6. Приоритеты устранения

| Проблема | Тип | Критичность | Затронутые хосты | Количество | Рекомендация |
|---|---|---|---|---:|---|
| CVE-2025-32463 | software_vulnerability | critical | target1 | 1 | Update affected package to a fixed version |
| 1.1.1.1 Ensure cramfs kernel module is not available (Automated) | configuration_noncompliance | high | target1 | 1 | Edit or create a file in `/etc/modprobe.d/` ending in `.conf` and add `install cramfs /bin/false`. |
| 5.1.20 Ensure X11 forwarding is disabled (Automated) | configuration_noncompliance | medium | target1 | 1 | Set `X11Forwarding no` in sshd configuration and restart SSH. |

## 7. Вывод

Проверено устройств: 2. В основной части отчёта отражено 3 значимых находок. Выявлено CVE: 1, конфигурационных нарушений: 2. основной риск связан с критичными и высокими находками. В первую очередь рекомендуется устранить записи из раздела приоритетов устранения.

## 8. Приложение A. Паспортная модель findings

| ID | Тип уязвимости | Источник | Объект воздействия | Компонент | Описание | Условия проявления | Уровень опасности | Возможные последствия | Способ обнаружения | Рекомендации | Ссылки | Статус |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| PKG-CVE-2025-32463-sudo-1.9.15p5-3ubuntu5-Package-less-than-1.9.15p5-3ubuntu5.24.04.1-18adb5d1 | уязвимость кода | wazuh_vulnerability | target1 | sudo | Sudo chroot option local privilege escalation. | Package less than 1.9.15p5-3ubuntu5.24.04.1 | critical | риск определяется классом найденной уязвимости и уровнем критичности | Wazuh Vulnerability Detector | Update affected package to a fixed version | https://cti.wazuh.com/vulnerabilities/cves/CVE-2025-32463, https://ubuntu.com/security/CVE-2025-32463, https://www.cve.org/CVERecord?id=CVE-2025-32463 | fail |
| CFG-cis-1.1.1.1-modprobe--n--v-cramfs-r-install-bin-false-5b68d250 | уязвимость конфигурации | wazuh_sca | target1 | cis 1.1.1.1 | The cramfs filesystem type is not commonly used and should be disabled. | modprobe -n -v cramfs | high | Disabling uncommon filesystems reduces the kernel attack surface. | Wazuh SCA | Edit or create a file in `/etc/modprobe.d/` ending in `.conf` and add `install cramfs /bin/false`. | cis, mitre, nist, iso, pci_dss | fail |
| CFG-cis-5.1.20-sshd--T-r-x11forwarding-no-eba27012 | уязвимость конфигурации | wazuh_sca | target1 | cis 5.1.20 | The SSH daemon should not permit X11 forwarding. | sshd -T | medium | X11 forwarding expands the SSH session attack surface. | Wazuh SCA | Set `X11Forwarding no` in sshd configuration and restart SSH. | cis, mitre, nist, iso, pci_dss | fail |
