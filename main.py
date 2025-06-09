import os
import re
import argparse
import logging
from datetime import datetime, timedelta
import json

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from jinja2 import Template


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("security_analyzer.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


Base = declarative_base()


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    event_type = Column(String(100))
    user = Column(String(100))
    command = Column(Text)
    result = Column(String(50))
    pid = Column(Integer)
    raw_log = Column(Text)


class ParsecLog(Base):
    __tablename__ = "parsec_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    event_type = Column(String(100))
    user = Column(String(100))
    action = Column(String(200))
    object_name = Column(String(200))
    result = Column(String(50))
    raw_log = Column(Text)


class MandatoryPolicy(Base):
    __tablename__ = "mandatory_policies"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    event_type = Column(String(100))
    user = Column(String(100))
    policy_name = Column(String(200))
    old_level = Column(String(50))
    new_level = Column(String(50))
    action = Column(String(100))
    raw_log = Column(Text)


class USBConnection(Base):
    __tablename__ = "usb_connections"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    event_type = Column(String(100))
    user = Column(String(100))
    device_id = Column(String(100))
    device_name = Column(String(200))
    action = Column(String(50))
    authorized = Column(Boolean)
    raw_log = Column(Text)


class SuspiciousActivity(Base):
    __tablename__ = "suspicious_activities"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime)
    category = Column(String(100))
    severity = Column(String(20))
    user = Column(String(100))
    description = Column(Text)
    details = Column(Text)


class SecurityAnalyzer:
    def __init__(self, db_path: str = "sqlite:///security_analysis.db"):
        self.db_path = db_path
        self.engine = create_engine(
            f"postgresql+psycopg2://admin:strongpassword@localhost:5432/security_db"
        )

        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def __del__(self):
        if hasattr(self, "session"):
            self.session.close()

    def collect_audit_logs(self, log_path: str = "/var/log/audit/audit.log"):
        logger.info("Начинаем сбор данных из журналов аудита...")

        if not os.path.exists(log_path):
            logger.warning(f"Файл аудита не найден: {log_path}")

            return

        try:
            with open(log_path, "r") as f:
                for line in f:
                    if line.strip():
                        self._parse_audit_line(line.strip())

            self.session.commit()
            logger.info("Сбор данных аудита завершен")

        except Exception as e:
            logger.error(f"Ошибка при сборе данных аудита: {e}")
            self.session.rollback()

    def _parse_audit_line(self, line: str):
        try:
            type_match = re.search(r"type=(\w+)", line)
            timestamp_match = re.search(r"msg=audit\((\d+\.\d+):\d+\)", line)

            if not type_match or not timestamp_match:
                return

            event_type = type_match.group(1)
            timestamp = datetime.fromtimestamp(float(timestamp_match.group(1)))

            user_match = re.search(r"uid=(\d+)", line)
            user = user_match.group(1) if user_match else "unknown"

            cmd_match = re.search(r'cmd="?([^"\s]+)"?', line)
            command = ""
            if cmd_match:
                cmd_value = cmd_match.group(1)

                if re.match(r"^[0-9a-fA-F]+$", cmd_value) and len(cmd_value) % 2 == 0:
                    try:
                        command = bytes.fromhex(cmd_value).decode("utf-8")
                    except:
                        command = cmd_value
                else:
                    command = cmd_value

            cwd_match = re.search(r'cwd="([^"]+)"', line)
            cwd = cwd_match.group(1) if cwd_match else "unknown"

            res_match = re.search(r"res=([^\s]+)", line)
            result = res_match.group(1) if res_match else "unknown"

            pid_match = re.search(r"pid=(\d+)", line)
            pid = int(pid_match.group(1)) if pid_match else 0

            full_command = f"[cwd={cwd}] {command}" if cwd != "unknown" else command

            audit_entry = AuditLog(
                timestamp=timestamp,
                event_type=event_type,
                user=user,
                command=full_command,
                result=result,
                pid=pid,
                raw_log=line,
            )

            self.session.add(audit_entry)

        except Exception as e:
            logger.error(f"Ошибка при парсинге строки аудита: {line[:100]}... - {e}")

    def collect_parsec_logs(self, log_path: str = "/var/log/parsec/parsec.log"):
        logger.info("Начинаем сбор данных из журналов Parsec...")

        if not os.path.exists(log_path):
            logger.warning(f"Файл Parsec не найден: {log_path}")
            return

        try:
            line_count = 0
            with open(log_path, "r") as f:
                for line in f:
                    if line.strip():
                        self._parse_parsec_line(line.strip())
                        line_count += 1

            self.session.commit()
            logger.info(f"Сбор данных Parsec завершен. Обработано {line_count} строк.")

        except Exception as e:
            logger.error(f"Ошибка при сборе данных Parsec: {e}")
            self.session.rollback()

        try:
            with open(log_path, "r") as f:
                for line in f:
                    if line.strip():
                        self._parse_parsec_line(line.strip())

            self.session.commit()
            logger.info("Сбор данных Parsec завершен")

        except Exception as e:
            logger.error(f"Ошибка при сборе данных Parsec: {e}")
            self.session.rollback()

    def _parse_parsec_line(self, line: str):
        try:
            main_pattern = r"\[([^\]]+)\]\s+(\w+):\s+(.*)"
            main_match = re.search(main_pattern, line)
            if not main_match:
                return

            timestamp_str, event_level, message = main_match.groups()
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            user = "unknown"
            obj_name = ""
            action = ""
            result = "unknown"
            event_type = "UNKNOWN_EVENT"

            if "subject" in message and "object" in message:

                if "tried to access" in message:
                    event_type = "ACCESS_ATTEMPT"
                    access_pattern = (
                        r"subject\s+'([^']+)'.*object\s+'([^']+)'.*\s—\s(ACCESS\s\w+)"
                    )
                    access_match = re.search(access_pattern, message)
                    if access_match:
                        user, obj_name, result = access_match.groups()
                        action = "access_object"
                elif "changed label of" in message:
                    event_type = "LABEL_CHANGE"
                    label_pattern = (
                        r"subject\s+'([^']+)'.*object\s+'([^']+)'.*to\s+(\w+)"
                    )
                    label_match = re.search(label_pattern, message)
                    if label_match:
                        user, obj_name, new_label = label_match.groups()
                        action = "change_label"
                        result = "success"
                elif "opened object" in message:
                    event_type = "OBJECT_ACCESS"
                    open_pattern = (
                        r"subject\s+'([^']+)'.*object\s+'([^']+)'\s—\s(ACCESS\s\w+)"
                    )
                    open_match = re.search(open_pattern, message)
                    if open_match:
                        user, obj_name, result = open_match.groups()
                        action = "open_object"
            elif "attempt to execute" in message:
                event_type = "EXECUTION_ATTEMPT"
                exec_pattern = (
                    r"subject\s+'([^']+)'.*file\s+'([^']+)'.*\s—\s(EXECUTION\s\w+)"
                )
                exec_match = re.search(exec_pattern, message)
                if exec_match:
                    user, obj_name, result = exec_match.groups()
                    action = "execute_file"
            elif "authenticated successfully" in message:
                event_type = "AUTHENTICATION"
                auth_pattern = r"subject\s+'([^']+)'"
                auth_match = re.search(auth_pattern, message)
                if auth_match:
                    user = auth_match.group(1)
                    obj_name = "authentication"
                    action = "authenticate"
                    result = "success"
            else:

                return

            parsec_entry = ParsecLog(
                timestamp=timestamp,
                event_type=event_type,
                user=user,
                action=action,
                object_name=obj_name,
                result=result.lower(),
                raw_log=line,
            )

            self.session.add(parsec_entry)

        except Exception as e:
            logger.error(f"Ошибка при парсинге строки Parsec: {line[:100]}... - {e}")

    def collect_mandatory_policies(self, log_path: str = "/var/log/messages"):
        logger.info(f"Начинаем сбор данных о мандатных политиках из {log_path}...")

        if not os.path.exists(log_path):
            logger.warning(f"Файл логов не найден: {log_path}")
            return

        try:
            count = 0
            with open(log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and self._parse_mandatory_line(line):
                        count += 1

            self.session.commit()
            logger.info(
                f"Сбор данных о мандатных политиках завершен. Добавлено {count} записей."
            )

        except Exception as e:
            logger.error(f"Ошибка при сборе данных о мандатных политиках: {e}")
            self.session.rollback()
            raise

    def _parse_mandatory_line(self, line: str) -> bool:
        """Парсинг строки журнала /var/log/messages на предмет мандатных политик"""
        try:

            date_match = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", line)
            if not date_match:
                return False

            month, day, time = date_match.groups()
            current_year = datetime.now().year
            timestamp_str = f"{current_year}-{month}-{day} {time}"

            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%b-%d %H:%M:%S")
            except ValueError:
                return False

            patterns = [
                (r".*SECMARK.*old=(\w+).*new=(\w+).*user=(\w+)", "SECMARK_CHANGE"),
                (
                    r".*ACCESS DENIED.*subject=\'(\w+)\'.*object=\'([^\']+)\'.*label=(\w+)",
                    "ACCESS_DENIED",
                ),
                (
                    r".*PRIVILEGE CHANGE.*user=(\w+).*old=(\w+).*new=(\w+)",
                    "PRIVILEGE_CHANGE",
                ),
                (
                    r".*LEVEL CHANGE.*user=(\w+).*object=\'([^\']+)\'.*old=(\w+).*new=(\w+)",
                    "LEVEL_CHANGE",
                ),
            ]

            for pattern, event_type in patterns:
                match = re.search(pattern, line)

                if match:
                    if event_type == "SECMARK_CHANGE":
                        old_level, new_level, user = match.groups()
                        action = "upgrade" if new_level > old_level else "downgrade"
                        policy_name = f"secmark_{old_level}_to_{new_level}"

                        policy_entry = MandatoryPolicy(
                            timestamp=timestamp,
                            event_type=event_type,
                            user=user,
                            policy_name=policy_name,
                            old_level=old_level,
                            new_level=new_level,
                            action=action,
                            raw_log=line[:1000],
                        )

                        self.session.add(policy_entry)
                        return True

                    elif event_type == "ACCESS_DENIED":
                        user, obj_name, label = match.groups()

                        policy_entry = MandatoryPolicy(
                            timestamp=timestamp,
                            event_type=event_type,
                            user=user,
                            policy_name=f"access_denied_{label}",
                            old_level=label,
                            new_level="",
                            action="access_denied",
                            raw_log=line[:1000],
                        )

                        self.session.add(policy_entry)
                        return True

                    elif event_type == "PRIVILEGE_CHANGE":
                        user, old_priv, new_priv = match.groups()

                        policy_entry = MandatoryPolicy(
                            timestamp=timestamp,
                            event_type=event_type,
                            user=user,
                            policy_name=f"privilege_{old_priv}_to_{new_priv}",
                            old_level=old_priv,
                            new_level=new_priv,
                            action="privilege_change",
                            raw_log=line[:1000],
                        )

                        self.session.add(policy_entry)
                        return True

                    elif event_type == "LEVEL_CHANGE":
                        user, obj_name, old_level, new_level = match.groups()

                        policy_entry = MandatoryPolicy(
                            timestamp=timestamp,
                            event_type=event_type,
                            user=user,
                            policy_name=f"level_change_{obj_name}",
                            old_level=old_level,
                            new_level=new_level,
                            action="level_change",
                            raw_log=line[:1000],
                        )

                        self.session.add(policy_entry)
                        return True

            return False

        except Exception as e:
            logger.error(f"Ошибка при парсинге строки: {line[:100]}... - {e}")
            return False

    def collect_usb_connections(self, log_path: str = "/var/log/kern.log"):
        """Сбор данных о подключениях USB"""
        logger.info("Начинаем сбор данных о подключениях USB...")

        if not os.path.exists(log_path):
            logger.warning(f"Файл USB не найден: {log_path}")

            return

        try:
            with open(log_path, "r") as f:
                for line in f:
                    if line.strip():
                        self._parse_usb_line(line.strip())

            self.session.commit()
            logger.info("Сбор данных USB завершен")

        except Exception as e:
            logger.error(f"Ошибка при сборе данных USB: {e}")
            self.session.rollback()

    def _parse_usb_line(self, line: str):
        try:

            date_match = re.match(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})", line)
            if not date_match:
                return

            month_str, day, time_str = date_match.groups()
            current_year = datetime.now().year
            timestamp = datetime.strptime(
                f"{current_year} {month_str} {day} {time_str}", "%Y %b %d %H:%M:%S"
            )

            manufacturer_match = re.search(r"Manufacturer:\s+(.+)", line)
            product_match = re.search(r"Product:\s+(.+)", line)
            serial_match = re.search(r"SerialNumber:\s+(.+)", line)
            id_match = re.search(
                r"idVendor=([0-9a-fA-F]+), idProduct=([0-9a-fA-F]+)", line
            )

            if manufacturer_match or product_match:
                device_name = product_match.group(1) if product_match else "Unknown"
                device_id = "unknown"
                if id_match:
                    device_id = f"{id_match.group(1)}:{id_match.group(2)}"

                usb_entry = USBConnection(
                    timestamp=timestamp,
                    event_type="USB_CONNECT",
                    user="system",
                    device_id=device_id,
                    device_name=device_name,
                    action="connect",
                    authorized=False,
                    raw_log=line[:1000],
                )
                self.session.add(usb_entry)

        except Exception as e:
            logger.error(f"Ошибка при парсинге строки USB: {line[:100]}... - {e}")

    def analyze_suspicious_activities(self):
        """Анализ подозрительных активностей"""
        logger.info("Начинаем анализ подозрительных активностей...")

        self.session.query(SuspiciousActivity).delete()

        self._analyze_audit_logs()
        self._analyze_parsec_logs()
        self._analyze_mandatory_policies()
        self._analyze_usb_connections()

        self.session.commit()
        logger.info("Анализ подозрительных активностей завершен")

    def _analyze_audit_logs(self):
        """Анализ журналов аудита на подозрительные активности"""

        failed_logins = (
            self.session.query(AuditLog)
            .filter(AuditLog.event_type == "USER_LOGIN", AuditLog.result == "failed")
            .all()
        )

        user_failures = {}
        for login in failed_logins:
            if login.user not in user_failures:
                user_failures[login.user] = []
            user_failures[login.user].append(login)

        for user, failures in user_failures.items():
            if len(failures) > 3:
                recent_failures = [
                    f
                    for f in failures
                    if f.timestamp > datetime.now() - timedelta(hours=1)
                ]
                if len(recent_failures) > 3:
                    suspicious = SuspiciousActivity(
                        timestamp=datetime.now(),
                        category="AUDIT",
                        severity="HIGH",
                        user=user,
                        description=f"Множественные неудачные попытки входа: {len(recent_failures)} за последний час",
                        details=json.dumps([f.raw_log for f in recent_failures[:5]]),
                    )
                    self.session.add(suspicious)

        privilege_escalations = (
            self.session.query(AuditLog)
            .filter(
                AuditLog.event_type.in_(["USER_ROLE_CHANGE", "SYSCALL"]),
                AuditLog.command.contains("sudo"),
            )
            .all()
        )

        for escalation in privilege_escalations:
            suspicious = SuspiciousActivity(
                timestamp=escalation.timestamp,
                category="AUDIT",
                severity="MEDIUM",
                user=escalation.user,
                description="Попытка повышения привилегий",
                details=escalation.raw_log,
            )
            self.session.add(suspicious)

    def _analyze_parsec_logs(self):
        """Анализ журналов Parsec"""

        rule_changes = (
            self.session.query(ParsecLog)
            .filter(ParsecLog.action.contains("modify_rule"))
            .all()
        )

        for change in rule_changes:
            suspicious = SuspiciousActivity(
                timestamp=change.timestamp,
                category="PARSEC",
                severity="MEDIUM",
                user=change.user,
                description=f"Изменение правила доступа: {change.object_name}",
                details=change.raw_log,
            )
            self.session.add(suspicious)

        user_changes = {}
        for change in rule_changes:
            if change.user not in user_changes:
                user_changes[change.user] = []
            user_changes[change.user].append(change)

        for user, changes in user_changes.items():
            if len(changes) > 5:
                suspicious = SuspiciousActivity(
                    timestamp=datetime.now(),
                    category="PARSEC",
                    severity="HIGH",
                    user=user,
                    description=f"Подозрительно высокая активность изменения правил: {len(changes)} изменений",
                    details=json.dumps([c.object_name for c in changes]),
                )
                self.session.add(suspicious)

    def _analyze_mandatory_policies(self):
        """Анализ мандатных политик"""

        downgrades = (
            self.session.query(MandatoryPolicy)
            .filter(MandatoryPolicy.action == "downgrade")
            .all()
        )

        for downgrade in downgrades:
            severity = (
                "HIGH" if downgrade.old_level in ["secret", "top_secret"] else "MEDIUM"
            )
            suspicious = SuspiciousActivity(
                timestamp=downgrade.timestamp,
                category="MANDATORY_POLICY",
                severity=severity,
                user=downgrade.user,
                description=f"Понижение уровня конфиденциальности: {downgrade.old_level} -> {downgrade.new_level}",
                details=f"Политика: {downgrade.policy_name}",
            )
            self.session.add(suspicious)

        deletions = (
            self.session.query(MandatoryPolicy)
            .filter(MandatoryPolicy.action == "delete")
            .all()
        )

        for deletion in deletions:
            suspicious = SuspiciousActivity(
                timestamp=deletion.timestamp,
                category="MANDATORY_POLICY",
                severity="HIGH",
                user=deletion.user,
                description=f"Удаление метки доступа: {deletion.policy_name}",
                details=deletion.raw_log,
            )
            self.session.add(suspicious)

    def _analyze_usb_connections(self):
        """Анализ подключений USB"""

        unauthorized = (
            self.session.query(USBConnection)
            .filter(USBConnection.authorized == False)
            .all()
        )

        for usb in unauthorized:
            suspicious = SuspiciousActivity(
                timestamp=usb.timestamp,
                category="USB",
                severity="HIGH",
                user=usb.user,
                description=f"Неавторизованное подключение USB: {usb.device_name}",
                details=f"Device ID: {usb.device_id}",
            )
            self.session.add(suspicious)

        user_connections = {}
        all_connections = self.session.query(USBConnection).all()

        for conn in all_connections:
            if conn.user not in user_connections:
                user_connections[conn.user] = []
            user_connections[conn.user].append(conn)

        for user, connections in user_connections.items():
            recent_connections = [
                c
                for c in connections
                if c.timestamp > datetime.now() - timedelta(hours=24)
            ]
            if len(recent_connections) > 10:
                suspicious = SuspiciousActivity(
                    timestamp=datetime.now(),
                    category="USB",
                    severity="MEDIUM",
                    user=user,
                    description=f"Подозрительно высокая активность USB: {len(recent_connections)} подключений за 24 часа",
                    details=json.dumps(
                        [c.device_name for c in recent_connections[:10]]
                    ),
                )
                self.session.add(suspicious)

    def generate_pdf_report(self, output_path: str = "security_report.pdf"):
        """Генерация PDF отчета с проверкой данных"""

        if self.session.query(MandatoryPolicy).count() == 0:
            logger.warning("Нет данных о мандатных политиках для отчета!")
            return

        logger.info("Генерируем PDF отчет...")
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=18,
                spaceAfter=30,
                alignment=1,
            )
            story.append(
                Paragraph("Отчет по анализу безопасности Astra Linux", title_style)
            )
            story.append(Spacer(1, 20))

            story.append(Paragraph("Мандатные политики", styles["Heading2"]))

            policies = (
                self.session.query(MandatoryPolicy)
                .order_by(MandatoryPolicy.timestamp.desc())
                .limit(50)
                .all()
            )

            if not policies:
                story.append(
                    Paragraph(
                        "Данные о мандатных политиках не найдены.", styles["Normal"]
                    )
                )
            else:

                data = [["Дата", "Тип события", "Пользователь", "Политика", "Действие"]]

                for policy in policies:
                    data.append(
                        [
                            policy.timestamp.strftime("%Y-%m-%d %H:%M"),
                            policy.event_type,
                            policy.user,
                            policy.policy_name,
                            policy.action,
                        ]
                    )

                table = Table(
                    data, colWidths=[1.5 * inch, 1.5 * inch, inch, 2 * inch, inch]
                )
                table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                            ("FONTSIZE", (0, 0), (-1, 0), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                            ("GRID", (0, 0), (-1, -1), 1, colors.black),
                            ("FONTSIZE", (0, 1), (-1, -1), 8),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ]
                    )
                )
                story.append(table)
                story.append(Spacer(1, 20))

            doc.build(story)
            logger.info(f"PDF отчет успешно сохранен: {output_path}")

        except Exception as e:
            logger.error(f"Ошибка при генерации PDF отчета: {e}")
            raise

    def _add_statistics_to_pdf(self, story, styles):
        """Добавление статистики в PDF"""
        story.append(Paragraph("Статистика собранных данных", styles["Heading2"]))

        audit_count = self.session.query(AuditLog).count()
        parsec_count = self.session.query(ParsecLog).count()
        policy_count = self.session.query(MandatoryPolicy).count()
        usb_count = self.session.query(USBConnection).count()
        suspicious_count = self.session.query(SuspiciousActivity).count()

        data = [
            ["Источник данных", "Количество записей"],
            ["Журналы аудита", str(audit_count)],
            ["Журналы Parsec", str(parsec_count)],
            ["Мандатные политики", str(policy_count)],
            ["USB подключения", str(usb_count)],
            ["Подозрительные активности", str(suspicious_count)],
        ]

        table = Table(data)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 14),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )

        story.append(table)
        story.append(Spacer(1, 20))

    def _add_suspicious_activities_to_pdf(self, story, styles):
        """Добавление подозрительных активностей в PDF"""
        story.append(
            Paragraph("Выявленные подозрительные активности", styles["Heading2"])
        )

        activities = (
            self.session.query(SuspiciousActivity)
            .order_by(
                SuspiciousActivity.severity.desc(), SuspiciousActivity.timestamp.desc()
            )
            .limit(20)
            .all()
        )

        if not activities:
            story.append(
                Paragraph("Подозрительных активностей не обнаружено.", styles["Normal"])
            )
            return

        for activity in activities:
            color = (
                colors.red
                if activity.severity == "HIGH"
                else colors.orange if activity.severity == "MEDIUM" else colors.yellow
            )

            activity_style = ParagraphStyle(
                "ActivityStyle",
                parent=styles["Normal"],
                leftIndent=20,
                bulletIndent=10,
                bulletFontName="Helvetica-Bold",
                bulletColor=color,
            )

            story.append(
                Paragraph(
                    f"<b>[{activity.severity}]</b> {activity.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - "
                    f"<b>{activity.user}</b>: {activity.description}",
                    activity_style,
                )
            )

            if activity.details and len(activity.details) < 200:
                story.append(Paragraph(f"Детали: {activity.details}", styles["Normal"]))

            story.append(Spacer(1, 10))

    def generate_html_report(self, output_path: str = "security_report.html"):
        logger.info("Генерируем HTML отчет...")

        audit_count = self.session.query(AuditLog).count()
        parsec_count = self.session.query(ParsecLog).count()
        policy_count = self.session.query(MandatoryPolicy).count()
        usb_count = self.session.query(USBConnection).count()

        activities = (
            self.session.query(SuspiciousActivity)
            .order_by(
                SuspiciousActivity.severity.desc(), SuspiciousActivity.timestamp.desc()
            )
            .all()
        )

        activities_by_category = {}
        for activity in activities:
            if activity.category not in activities_by_category:
                activities_by_category[activity.category] = []
            activities_by_category[activity.category].append(activity)

        html_template = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Панель анализа безопасности Astra Linux</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }

        .header p {
            opacity: 0.9;
            font-size: 1.1em;
        }

        .controls {
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
        }

        .date-controls {
            display: flex;
            gap: 20px;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }

        .date-group {
            display: flex;
            flex-direction: column;
            gap: 5px;
        }

        .date-group label {
            font-weight: 600;
            color: #495057;
            font-size: 0.9em;
        }

        .date-group input {
            padding: 10px 15px;
            border: 2px solid #dee2e6;
            border-radius: 8px;
            font-size: 1em;
            transition: border-color 0.3s ease;
        }

        .date-group input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        .filter-btn {
            padding: 12px 25px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 1em;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .filter-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
        }

        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
            border: 1px solid #e9ecef;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(0,0,0,0.15);
        }

        .stat-card.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            transform: translateY(-5px);
            box-shadow: 0 15px 30px rgba(102, 126, 234, 0.4);
        }

        .stat-number {
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .stat-card.active .stat-number {
            color: white;
            -webkit-text-fill-color: white;
        }

        .stat-label {
            font-size: 1.1em;
            font-weight: 600;
            color: #495057;
        }

        .stat-card.active .stat-label {
            color: white;
        }

        .data-section {
            padding: 30px;
            display: none;
        }

        .data-section.active {
            display: block;
        }

        .data-section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }

        .data-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.08);
        }

        .data-table th {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }

        .data-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #e9ecef;
        }

        .data-table tr:hover {
            background: #f8f9fa;
        }

        .severity-high {
            background: #ffebee !important;
            border-left: 4px solid #f44336;
        }

        .severity-medium {
            background: #fff3e0 !important;
            border-left: 4px solid #ff9800;
        }

        .severity-low {
            background: #f3e5f5 !important;
            border-left: 4px solid #9c27b0;
        }

        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-success {
            background: #d4edda;
            color: #155724;
        }

        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }

        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }

        .no-data {
            text-align: center;
            padding: 40px;
            color: #6c757d;
            font-size: 1.1em;
        }

        .loading {
            text-align: center;
            padding: 40px;
            color: #667eea;
            font-size: 1.1em;
        }

        @media (max-width: 768px) {
            .date-controls {
                flex-direction: column;
                align-items: stretch;
            }

            .stats-grid {
                grid-template-columns: 1fr;
            }

            .data-table {
                font-size: 0.9em;
            }

            .data-table th,
            .data-table td {
                padding: 8px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Панель анализа безопасности Astra Linux</h1>
            <p>Мониторинг и анализ событий безопасности системы</p>
        </div>

        <div class="controls">
            <div class="date-controls">
                <div class="date-group">
                    <label for="startDate">Дата начала:</label>
                    <input type="datetime-local" id="startDate">
                </div>
                <div class="date-group">
                    <label for="endDate">Дата окончания:</label>
                    <input type="datetime-local" id="endDate">
                </div>
                <button class="filter-btn" onclick="filterData()">
                    Применить фильтр
                </button>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card" onclick="showData('audit')" id="audit-card">
                <div class="stat-number" id="audit-count">0</div>
                <div class="stat-label">Записи аудита</div>
            </div>
            <div class="stat-card" onclick="showData('parsec')" id="parsec-card">
                <div class="stat-number" id="parsec-count">0</div>
                <div class="stat-label">Журналы Parsec</div>
            </div>
            <div class="stat-card" onclick="showData('policies')" id="policies-card">
                <div class="stat-number" id="policies-count">0</div>
                <div class="stat-label">Мандатные политики</div>
            </div>
            <div class="stat-card" onclick="showData('usb')" id="usb-card">
                <div class="stat-number" id="usb-count">0</div>
                <div class="stat-label">USB подключения</div>
            </div>
            <div class="stat-card" onclick="showData('suspicious')" id="suspicious-card">
                <div class="stat-number" id="suspicious-count">0</div>
                <div class="stat-label">⚠Подозрительные активности</div>
            </div>
        </div>

        <!-- Секции данных -->
        <div id="audit-section" class="data-section">
            <h2>Записи аудита</h2>
            <div id="audit-data"></div>
        </div>

        <div id="parsec-section" class="data-section">
            <h2>Журналы Parsec</h2>
            <div id="parsec-data"></div>
        </div>

        <div id="policies-section" class="data-section">
            <h2>Мандатные политики</h2>
            <div id="policies-data"></div>
        </div>

        <div id="usb-section" class="data-section">
            <h2>USB подключения</h2>
            <div id="usb-data"></div>
        </div>

        <div id="suspicious-section" class="data-section">
            <h2>Подозрительные активности</h2>
            <div id="suspicious-data"></div>
        </div>
    </div>

    <script>
        // Симуляция данных (в реальном приложении данные будут загружаться с сервера)
        const mockData = {{ mock_data_json | safe }};

        let filteredData = { ...mockData };
        let currentSection = null;

        // Инициализация
        document.addEventListener('DOMContentLoaded', function() {
            // Устанавливаем дату по умолчанию (последние 7 дней)
            const endDate = new Date();
            const startDate = new Date();
            startDate.setDate(startDate.getDate() - 7);
            
            document.getElementById('startDate').value = formatDateForInput(startDate);
            document.getElementById('endDate').value = formatDateForInput(endDate);
            
            updateCounts();
        });

        function formatDateForInput(date) {
            return date.toISOString().slice(0, 16);
        }

        function filterData() {
            const startDate = new Date(document.getElementById('startDate').value);
            const endDate = new Date(document.getElementById('endDate').value);
            
            if (!startDate || !endDate) {
                alert('Пожалуйста, выберите период времени');
                return;
            }
            
            if (startDate > endDate) {
                alert('Дата начала не может быть позже даты окончания');
                return;
            }
            
            // Фильтруем данные по выбранному периоду
            filteredData = {};
            
            Object.keys(mockData).forEach(key => {
                filteredData[key] = mockData[key].filter(item => {
                    const itemDate = new Date(item.timestamp);
                    return itemDate >= startDate && itemDate <= endDate;
                });
            });
            
            updateCounts();
            
            // Если какая-то секция открыта, обновляем её
            if (currentSection) {
                showData(currentSection);
            }
        }

        function updateCounts() {
            document.getElementById('audit-count').textContent = filteredData.audit.length;
            document.getElementById('parsec-count').textContent = filteredData.parsec.length;
            document.getElementById('policies-count').textContent = filteredData.policies.length;
            document.getElementById('usb-count').textContent = filteredData.usb.length;
            document.getElementById('suspicious-count').textContent = filteredData.suspicious.length;
        }

        function showData(type) {
            // Скрываем все секции
            document.querySelectorAll('.data-section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Убираем активное состояние со всех карточек
            document.querySelectorAll('.stat-card').forEach(card => {
                card.classList.remove('active');
            });
            
            // Показываем выбранную секцию
            document.getElementById(`${type}-section`).classList.add('active');
            document.getElementById(`${type}-card`).classList.add('active');
            
            currentSection = type;
            
            // Загружаем данные
            loadDataForSection(type);
        }

        function loadDataForSection(type) {
            const container = document.getElementById(`${type}-data`);
            container.innerHTML = '<div class="loading">Загрузка данных...</div>';
            
            setTimeout(() => {
                const data = filteredData[type];
                
                if (!data || data.length === 0) {
                    container.innerHTML = '<div class="no-data">Данные за выбранный период не найдены</div>';
                    return;
                }
                
                let tableHTML = '';
                
                switch(type) {
                    case 'audit':
                        tableHTML = generateAuditTable(data);
                        break;
                    case 'parsec':
                        tableHTML = generateParsecTable(data);
                        break;
                    case 'policies':
                        tableHTML = generatePoliciesTable(data);
                        break;
                    case 'usb':
                        tableHTML = generateUSBTable(data);
                        break;
                    case 'suspicious':
                        tableHTML = generateSuspiciousTable(data);
                        break;
                }
                
                container.innerHTML = tableHTML;
            }, 500);
        }

        function generateAuditTable(data) {
            let html = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>Тип события</th>
                            <th>Пользователь</th>
                            <th>Команда</th>
                            <th>Результат</th>
                            <th>PID</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            data.forEach(item => {
                const resultClass = item.result === 'success' ? 'badge-success' : 'badge-danger';
                html += `
                    <tr>
                        <td>${item.timestamp}</td>
                        <td>${item.event_type}</td>
                        <td>${item.user}</td>
                        <td>${item.command}</td>
                        <td><span class="badge ${resultClass}">${item.result}</span></td>
                        <td>${item.pid}</td>
                    </tr>
                `;
            });
            
            html += '</tbody></table>';
            return html;
        }

        function generateParsecTable(data) {
            let html = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>Тип события</th>
                            <th>Пользователь</th>
                            <th>Действие</th>
                            <th>Объект</th>
                            <th>Результат</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            data.forEach(item => {
                const resultClass = item.result.includes('success') ? 'badge-success' : 'badge-danger';
                html += `
                    <tr>
                        <td>${item.timestamp}</td>
                        <td>${item.event_type}</td>
                        <td>${item.user}</td>
                        <td>${item.action}</td>
                        <td>${item.object_name}</td>
                        <td><span class="badge ${resultClass}">${item.result}</span></td>
                    </tr>
                `;
            });
            
            html += '</tbody></table>';
            return html;
        }

        function generatePoliciesTable(data) {
            let html = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>Тип события</th>
                            <th>Пользователь</th>
                            <th>Политика</th>
                            <th>Старый уровень</th>
                            <th>Новый уровень</th>
                            <th>Действие</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            data.forEach(item => {
                const actionClass = item.action === 'downgrade' ? 'badge-danger' : 'badge-warning';
                html += `
                    <tr>
                        <td>${item.timestamp}</td>
                        <td>${item.event_type}</td>
                        <td>${item.user}</td>
                        <td>${item.policy_name}</td>
                        <td>${item.old_level}</td>
                        <td>${item.new_level}</td>
                        <td><span class="badge ${actionClass}">${item.action}</span></td>
                    </tr>
                `;
            });
            
            html += '</tbody></table>';
            return html;
        }

        function generateUSBTable(data) {
            let html = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>Пользователь</th>
                            <th>ID устройства</th>
                            <th>Название устройства</th>
                            <th>Действие</th>
                            <th>Авторизовано</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            data.forEach(item => {
                const authClass = item.authorized ? 'badge-success' : 'badge-danger';
                const authText = item.authorized ? 'Да' : 'Нет';
                html += `
                    <tr>
                        <td>${item.timestamp}</td>
                        <td>${item.user}</td>
                        <td>${item.device_id}</td>
                        <td>${item.device_name}</td>
                        <td>${item.action}</td>
                        <td><span class="badge ${authClass}">${authText}</span></td>
                    </tr>
                `;
            });
            
            html += '</tbody></table>';
            return html;
        }

        function generateSuspiciousTable(data) {
            let html = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>Категория</th>
                            <th>Серьезность</th>
                            <th>Пользователь</th>
                            <th>Описание</th>
                            <th>Детали</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            data.forEach(item => {
                const severityClass = `severity-${item.severity.toLowerCase()}`;
                html += `
                    <tr class="${severityClass}">
                        <td>${item.timestamp}</td>
                        <td>${item.category}</td>
                        <td><span class="badge badge-danger">${item.severity}</span></td>
                        <td>${item.user}</td>
                        <td>${item.description}</td>
                        <td>${item.details}</td>
                    </tr>
                `;
            });
            
            html += '</tbody></table>';
            return html;
        }
    </script>
</body>
</html>
        """

        def serialize(queryset):
            serialized = []
            for row in queryset:
                data = {}
                for column in row.__table__.columns:
                    value = getattr(row, column.name)
                    if isinstance(value, datetime):
                        value = value.strftime("%Y-%m-%d %H:%M:%S")
                    data[column.name] = value
                serialized.append(data)
            return serialized

        mock_data = {
            "audit": serialize(self.session.query(AuditLog).all()),
            "parsec": serialize(self.session.query(ParsecLog).all()),
            "policies": serialize(self.session.query(MandatoryPolicy).all()),
            "usb": serialize(self.session.query(USBConnection).all()),
            "suspicious": serialize(self.session.query(SuspiciousActivity).all()),
        }

        mock_data_json = json.dumps(mock_data, ensure_ascii=False, indent=2)

        template = Template(html_template)
        html_content = template.render(
            generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            audit_count=audit_count,
            parsec_count=parsec_count,
            policy_count=policy_count,
            usb_count=usb_count,
            total_suspicious=len(activities),
            activities_by_category=activities_by_category,
            mock_data_json=mock_data_json,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"HTML отчет сохранен: {output_path}")

    def run_full_analysis(self):
        logger.info("=== Начинаем полный анализ безопасности ===")

        try:
            self.collect_audit_logs()
            self.collect_parsec_logs()
            self.collect_mandatory_policies()
            self.collect_usb_connections()

            mandatory_count = self.session.query(MandatoryPolicy).count()
            logger.info(f"Собрано записей о мандатных политиках: {mandatory_count}")

            self.analyze_suspicious_activities()

            self.generate_pdf_report()
            self.generate_html_report()

            logger.info("=== Анализ безопасности завершен ===")

        except Exception as e:
            logger.error(f"Ошибка при выполнении анализа: {e}")
            raise


def main():
    parser = argparse.ArgumentParser(description="Анализатор безопасности Astra Linux")
    parser.add_argument("--collect", action="store_true", help="Только сбор данных")
    parser.add_argument("--analyze", action="store_true", help="Только анализ данных")
    parser.add_argument(
        "--report", action="store_true", help="Только генерация отчетов"
    )
    parser.add_argument(
        "--db", default="security_analysis.db", help="Путь к базе данных"
    )

    args = parser.parse_args()

    parser.add_argument(
        "--db-url",
        default="postgresql+psycopg2://postgres:mysecretpassword@localhost:5432/security_db",
        help="URL подключения к БД",
    )
    analyzer = SecurityAnalyzer(args.db)

    try:
        if args.collect:
            analyzer.collect_audit_logs()
            analyzer.collect_parsec_logs()
            analyzer.collect_mandatory_policies()
            analyzer.collect_usb_connections()
        elif args.analyze:
            analyzer.analyze_suspicious_activities()
        elif args.report:
            analyzer.generate_pdf_report()
            analyzer.generate_html_report()
        else:
            analyzer.run_full_analysis()

    except KeyboardInterrupt:
        logger.info("Анализ прерван пользователем")
    except Exception as e:
        logger.error(f"Ошибка при выполнении анализа: {e}")
        raise
    finally:
        analyzer.session.close()


if __name__ == "__main__":
    main()
