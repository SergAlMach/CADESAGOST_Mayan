import argparse
import os
import re
import secrets
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, field
import hashlib
from datetime import timezone
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Tuple
from urllib.error import URLError

from asn1crypto import algos, cms, core, ocsp, pem, tsp, x509
import tkinter
from tkinter import simpledialog


# Алгоритм хэширования ГОСТ Р 34.11-2012 256 бит
OID_GOST12_256 = "1.2.643.7.1.1.2.2"
# Алгоритм электронной подписи ГОСТ Р 34.10-2012 256 бит
OID_GOST_SIGN_256 = "1.2.643.7.1.1.3.2"
# Алгоритм открытого ключа ГОСТ Р 34.10-2012 256 бит
OID_GOST_2012_256_MODULUS = "1.2.643.7.1.1.1.1"
# Штамп времени подписи
OID_SIG_TST = "1.2.840.113549.1.9.16.2.14"
# Ссылки на сертификаты
OID_CERT_REFS = "1.2.840.113549.1.9.16.2.21"
# Ссылки на данные проверки статуса сертификатов
OID_REV_REFS = "1.2.840.113549.1.9.16.2.22"
# Значения сертификатов
OID_CERT_VALS = "1.2.840.113549.1.9.16.2.23"
# Значения данных проверки статуса сертификатов
OID_REV_VALS = "1.2.840.113549.1.9.16.2.24"
# Штамп времени на проверочные данные
OID_ESC_TST = "1.2.840.113549.1.9.16.2.25"
# Архивный штамп времени версии 3
OID_ARCHIVE_TST_V3 = "0.4.0.1733.2.4"
# Индекс хэшей для архивного штампа времени версии 3
OID_ATS_HASH_INDEX_V3 = "0.4.0.19122.1.5"

# Режимы работы программы: создание подписи разных уровней и обновление CAdES-A
MODE_BES = "bes"
MODE_T = "t"
MODE_XLT = "xlt"
MODE_A = "a"
MODE_RENEW_A = "renew_a"

# Дополнительные адреса тестовых OCSP-сервисов CryptoPro
EXTRA_OCSP_URLS = [
    "http://testgost2012.cryptopro.ru/ocsp2012g/ocsp.srf",
    "http://testgost2012.cryptopro.ru/ocsp2012gst/ocsp.srf",
]

# Хэш-значение вместе с указанием алгоритма хэширования
class OtherHashAlgAndValue(core.Sequence):
    _fields = [
        ("hash_algorithm", algos.DigestAlgorithm),
        ("hash_value", core.OctetString),
    ]

# Вариант представления хэша: SHA-1 или другой алгоритм
class OtherHash(core.Choice):
    _alternatives = [
        ("sha1_hash", core.OctetString),
        ("other_hash", OtherHashAlgAndValue),
    ]

# Издатель сертификата и его серийный номер
class IssuerSerial(core.Sequence):
    _fields = [
        ("issuer", x509.GeneralNames),
        ("serial_number", core.Integer),
    ]

# Ссылка на сертификат через его хэш
class OtherCertID(core.Sequence):
    _fields = [
        ("other_cert_hash", OtherHash),
        ("issuer_serial", IssuerSerial, {"optional": True}),
    ]

# Набор ссылок на сертификаты
class CompleteCertificateRefs(core.SequenceOf):
    _child_spec = OtherCertID

# Набор значений сертификатов
class CertificateValues(core.SequenceOf):
    _child_spec = x509.Certificate

# Идентификатор OCSP-ответа
class OcspIdentifier(core.Sequence):
    _fields = [
        ("ocsp_responder_id", ocsp.ResponderId),
        ("produced_at", core.GeneralizedTime),
    ]

# Ссылка на OCSP-ответ
class OcspResponsesID(core.Sequence):
    _fields = [
        ("ocsp_identifier", OcspIdentifier),
        ("ocsp_rep_hash", OtherHash, {"optional": True}),
    ]

# Набор ссылок на OCSP-ответы
class OcspResponses(core.SequenceOf):
    _child_spec = OcspResponsesID

# Список OCSP-ответов
class OcspListID(core.Sequence):
    _fields = [
        ("ocsp_responses", OcspResponses),
    ]

# Ссылка на данные проверки статуса сертификата
class CrlOcspRef(core.Sequence):
    _fields = [
        ("ocspids", OcspListID, {"explicit": 1, "optional": True}),
    ]

# Набор ссылок на данные проверки статуса сертификатов
class CompleteRevocationRefs(core.SequenceOf):
    _child_spec = CrlOcspRef

# Набор OCSP-ответов в исходном ASN.1-виде
class RawBasicOcspResponses(core.SequenceOf):
    _child_spec = core.Any

# Значения данных проверки статуса сертификатов
class RawRevocationValues(core.Sequence):
    _fields = [
        ("ocsp_vals", RawBasicOcspResponses, {"explicit": 1, "optional": True}),
    ]

# Последовательность байтовых строк
class OctetStringSequence(core.SequenceOf):
    _child_spec = core.OctetString

# Индекс хэшей для archive-time-stamp-v3
class ATSHashIndexV3(core.Sequence):
    _fields = [
        ("hash_ind_algorithm", algos.DigestAlgorithm),
        ("certificates_hash_index", OctetStringSequence),
        ("crls_hash_index", OctetStringSequence),
        ("unsigned_attrs_hash_index", OctetStringSequence),
    ]

# Набор путей, используемых при создании CAdES-подписи
@dataclass(slots=True)
class SigningPaths:
    # Путь к исходному подписываемому файлу
    input_path: Path
    # Путь к сертификату подписанта
    signer_cert_path: Optional[Path]
    # Путь к закрытому ключу подписанта
    signer_key_path: Path
    # Путь к цепочке сертификатов
    chain_path: Path
    # Путь к конфигурационному файлу OpenSSL
    openssl_conf_path: Path
    # Путь для сохранения итоговой подписи
    output_path: Optional[Path] = None

# Конфигурация формирования новой CAdES-подписи
@dataclass(slots=True)
class SigningConfig:
    # Выбранный уровень подписи
    mode: str
    # Адрес TSA-сервиса
    tsa_url: str
    # Набор файловых путей
    paths: SigningPaths
    # Признак подробного режима вывода
    verbose: bool = True

# Конфигурация обновления архивной CAdES-A подписи
@dataclass(slots=True)
class RenewCadesAConfig:
    # Путь к исходному файлу
    input_path: Path
    # Путь к текущей CAdES-A подписи
    current_signature_path: Path
    # Путь для сохранения обновленной подписи
    output_path: Path
    # Путь к конфигурационному файлу OpenSSL
    openssl_conf_path: Path
    # Адрес TSA-сервиса
    tsa_url: str
    # Путь к сертификату подписанта для формирования метаданных
    signer_cert_path: Optional[Path] = None

# Результат формирования или обновления CAdES-подписи
@dataclass(slots=True)
class SigningResult:
    # Режим, в котором была сформирована подпись
    mode: str
    # Путь к сохраненной подписи
    signature_path: Path
    # Адрес использованного TSA-сервиса
    tsa_url: str
    # Размер итоговой подписи в байтах
    output_size: int
    # Выбранный OCSP-адрес при формировании XLT-данных
    selected_ocsp_url: Optional[str] = None
    # Сведения о подписи и сертификатах для последующей записи в метаданные
    details: dict = field(default_factory=dict)

# Выполнение внешней команды и получение ее вывода
def run_cmd(cmd: Sequence[str], env: dict[str, str], stdin: Optional[bytes] = None) -> bytes:
    result = subprocess.run(
        cmd,                        # Список аргументов выполняемой команды
        env=env,                    # Переменные окружения для запуска команды
        input=stdin,                # Данные, передаваемые во входной поток команды
        stdout=subprocess.PIPE,     # Сохранение стандартного вывода команды
        stderr=subprocess.STDOUT,   # Объединение вывода ошибок со стандартным выводом
    )
    # Возврат результата выполнения команды в виде байтов
    return result.stdout

# Отправка HTTP POST-запроса и получение тела ответа
def send_post(url: str, body: bytes, content_type: str, accept: str, timeout: int = 60) -> bytes:
    # Формирование HTTP-запроса с указанным телом и заголовками
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": content_type, "Accept": accept},
        method="POST",
    )
    # Выполнение HTTP-запроса
    with urllib.request.urlopen(request, timeout=timeout) as response:
        # Возврат тела HTTP-ответа
        return response.read()

# Вычисление хэша ГОСТ Р 34.11-2012 с длиной 256 бит
def calc_gost256(data: bytes, env: dict[str, str]) -> bytes:
    # Вызов OpenSSL для вычисления хэша переданных данных
    digest = run_cmd(["openssl", "dgst", "-md_gost12_256", "-binary"], env, stdin=data)
    # Возврат хэша в бинарном виде
    return digest

# Создание ASN.1-описания алгоритма хэширования ГОСТ Р 34.11-2012 256 бит
def make_gost_digest_alg() -> algos.DigestAlgorithm:
    # Формирование структуры DigestAlgorithm с OID ГОСТ Р 34.11-2012 256 бит
    alg = algos.DigestAlgorithm({"algorithm": OID_GOST12_256})
    # Возврат структуры алгоритма хэширования
    return alg

# Получение PEM-блоков из переданного набора байтов
def iter_pem_blocks(data: bytes) -> Iterator[bytes]:
    # Поиск всех участков вида BEGIN/END в PEM-представлении
    for match in re.finditer(rb"-----BEGIN [^-]+-----.*?-----END [^-]+-----", data, re.S):
        # Возврат найденного PEM-блока
        yield match.group(0)

# Безопасная загрузка сертификата из DER-представления
def load_cert_safely(blob: bytes) -> Optional[x509.Certificate]:
    try:
        # Разбор сертификата средствами asn1crypto
        cert = x509.Certificate.load(blob)
        # Проверка возможности повторной сериализации сертификата
        cert.dump()
        # Возврат корректно разобранного сертификата
        return cert
    except (TypeError, ValueError):
        # Возврат пустого значения при невозможности разобрать сертификат
        return None

# Получение сертификатов из набора данных в PEM-формате
def read_certs_from_blob(blob: bytes) -> List[x509.Certificate]:
    # Создание списка найденных сертификатов
    found_certificates = []
    # Последовательный разбор всех PEM-блоков
    for pem_block in iter_pem_blocks(blob):
        # Извлечение DER-представления сертификата из PEM-блока
        _, _, certificate_der = pem.unarmor(pem_block)
        # Безопасная загрузка сертификата
        certificate = load_cert_safely(certificate_der)
        # Добавление сертификата при успешном разборе
        if certificate is not None:
            found_certificates.append(certificate)
    # Возврат списка найденных сертификатов
    return found_certificates

# Чтение сертификатов из файла
def read_certs(path: Path) -> List[x509.Certificate]:
    # Чтение содержимого файла с сертификатом или цепочкой сертификатов
    raw_blob = path.read_bytes()
    # Получение сертификатов из прочитанного набора данных
    return read_certs_from_blob(raw_blob)

# Получение DER-представления сертификата
def cert_to_der(cert: x509.Certificate) -> bytes:
    # Сериализация ASN.1-структуры сертификата в DER
    return cert.dump()

# Объединение списков сертификатов с удалением дубликатов
def merge_certs_unique(cert_lists: Sequence[Sequence[x509.Certificate]]) -> List[x509.Certificate]:
    # Набор DER-представлений уже добавленных сертификатов
    already_seen_der = set()
    # Итоговый список уникальных сертификатов
    merged_certs = []
    # Последовательный обход переданных списков сертификатов
    for cert_list in cert_lists:
        for cert in cert_list:
            # Получение DER-представления сертификата для сравнения
            cert_der = cert_to_der(cert)
            # Добавление сертификата только при отсутствии такого DER-представления
            if cert_der not in already_seen_der:
                already_seen_der.add(cert_der)
                merged_certs.append(cert)
    # Возврат списка уникальных сертификатов
    return merged_certs

# Получение неподписанных атрибутов из структуры SignerInfo
def read_unsigned_attrs(signer_info: cms.SignerInfo) -> List[cms.CMSAttribute]:
    # Получение поля unsignedAttrs из SignerInfo
    unsigned_attrs_field = signer_info["unsigned_attrs"]
    # Преобразование набора unsignedAttrs в список CMSAttribute
    return list(unsigned_attrs_field)

# Добавление неподписанного атрибута в структуру SignerInfo
def append_unsigned_attr(signer_info: cms.SignerInfo, attr_oid: str, attr_value: core.Asn1Value) -> cms.SignerInfo:
    # Получение текущего списка неподписанных атрибутов
    unsigned_attrs_list = read_unsigned_attrs(signer_info)
    # Добавление нового CMS-атрибута с указанным OID и значением
    unsigned_attrs_list.append(cms.CMSAttribute({"type": attr_oid, "values": [attr_value]}))
    # Запись обновленного списка неподписанных атрибутов обратно в SignerInfo
    signer_info["unsigned_attrs"] = cms.CMSAttributes(unsigned_attrs_list)
    # Возврат обновленной структуры SignerInfo
    return signer_info

# Поиск первого неподписанного атрибута по OID
def find_unsigned_attr(signer_info: cms.SignerInfo, attr_oid: str) -> Optional[cms.CMSAttribute]:
    # Последовательный обход неподписанных атрибутов SignerInfo
    for unsigned_attr in read_unsigned_attrs(signer_info):
        # Сравнение OID текущего атрибута с требуемым OID
        if unsigned_attr["type"].dotted == attr_oid:
            return unsigned_attr
    # Возврат пустого значения при отсутствии атрибута
    return None

# Поиск последнего неподписанного атрибута по OID
def find_last_unsigned_attr(signer_info: cms.SignerInfo, attr_oid: str) -> Optional[cms.CMSAttribute]:
    # Переменная для хранения последнего найденного атрибута
    found_attr = None
    # Последовательный обход неподписанных атрибутов SignerInfo
    for unsigned_attr in read_unsigned_attrs(signer_info):
        # Обновление найденного значения при совпадении OID
        if unsigned_attr["type"].dotted == attr_oid:
            found_attr = unsigned_attr
    # Возврат последнего найденного атрибута
    return found_attr

# Получение расширения сертификата по имени
def get_extension(cert: x509.Certificate, extension_name: str):
    # Последовательный обход расширений сертификата
    for extension in cert["tbs_certificate"]["extensions"]:
        # Сравнение имени текущего расширения с требуемым
        if extension["extn_id"].native == extension_name:
            # Возврат разобранного значения расширения
            return extension["extn_value"].parsed
    # Возврат пустого значения при отсутствии расширения
    return None

# Поиск сертификата издателя по связке AKI/SKI
def find_issuer_cert(signer_cert: x509.Certificate, chain_certs: Sequence[x509.Certificate]) -> x509.Certificate:
    # Получение Authority Key Identifier из проверяемого сертификата
    authority_key_identifier = get_extension(signer_cert, "authority_key_identifier")
    # Проверка наличия Authority Key Identifier
    if authority_key_identifier is None:
        raise ValueError("В сертификате не найден Authority Key Identifier.")
    # Получение идентификатора ключа издателя из AKI
    signer_aki = authority_key_identifier["key_identifier"].native
    # Поиск сертификата с соответствующим Subject Key Identifier
    for chain_cert in chain_certs:
        # Получение Subject Key Identifier из сертификата цепочки
        subject_key_identifier = get_extension(chain_cert, "key_identifier")
        # Сравнение SKI сертификата цепочки с AKI проверяемого сертификата
        if subject_key_identifier is not None and subject_key_identifier.native == signer_aki:
            return chain_cert
    # Ошибка при невозможности найти сертификат издателя
    raise ValueError("Не найден сертификат издателя по AKI/SKI.")

# Получение OCSP-адресов из сертификата средствами OpenSSL
def get_ocsp_urls_from_file(cert_path: Path, env: dict[str, str]) -> List[str]:
    # Вызов OpenSSL для чтения OCSP URI из сертификата
    out = run_cmd(["openssl", "x509", "-in", str(cert_path), "-noout", "-ocsp_uri"], env)
    # Получение непустых строк из вывода OpenSSL
    urls = [line.strip() for line in out.decode("utf-8", "replace").splitlines() if line.strip()]
    # Возврат списка OCSP-адресов без повторов
    return list(dict.fromkeys(urls))

# Получение OCSP-ответа для сертификата по заданному адресу
def load_ocsp_response_for_url(cert_path: Path, issuer_pem_path: Path, ocsp_url: str, env) -> Tuple[bytes, bytes]:
    # Создание временного файла для сохранения OCSP-ответа OpenSSL
    with tempfile.NamedTemporaryFile(delete=False) as response_file:
        response_path = Path(response_file.name)
    try:
        # Формирование OCSP-запроса средствами OpenSSL
        run_cmd(
            [
                "openssl",                 # Вызов OpenSSL
                "ocsp",                    # Использование OCSP-команды
                "-md_gost12_256",          # Алгоритм хэширования ГОСТ Р 34.11-2012 256 бит
                "-issuer",                 # Указание сертификата издателя
                str(issuer_pem_path),       # Путь к сертификату издателя
                "-cert",                   # Указание проверяемого сертификата
                str(cert_path),             # Путь к проверяемому сертификату
                "-url",                    # Указание адреса OCSP-сервиса
                ocsp_url,                   # URL OCSP-сервиса
                "-respout",                # Указание файла для сохранения ответа
                str(response_path),         # Путь к временному файлу ответа
                "-noverify",               # Отключение проверки доверия ответа на данном этапе
            ],
            env,
        )
        # Чтение полного OCSPResponse в DER-представлении
        ocsp_response_der = response_path.read_bytes()
        # Разбор OCSPResponse
        ocsp_response = ocsp.OCSPResponse.load(ocsp_response_der)
        # Получение поля responseBytes
        response_bytes = ocsp_response["response_bytes"]
        # Извлечение вложенного BasicOCSPResponse
        basic_ocsp_response_der = bytes(response_bytes["response"].contents)
        # Возврат полного OCSPResponse и BasicOCSPResponse
        return ocsp_response_der, basic_ocsp_response_der
    finally:
        # Удаление временного файла OCSP-ответа
        response_path.unlink(missing_ok=True)

# Выбор подходящего OCSP-ответа из набора доступных OCSP-адресов
def pick_best_ocsp_response(cert_path: Path, issuer_pem_path: Path, ocsp_urls: Sequence[str], env: dict[str, str]) -> Tuple[bytes, bytes, str]:
    # Список успешно полученных вариантов OCSP-ответов
    response_variants = []
    # Последовательная проверка уникальных OCSP-адресов
    for ocsp_url in list(dict.fromkeys(ocsp_urls)):
        try:
            # Получение OCSP-ответа по текущему адресу
            ocsp_response_der, basic_ocsp_response_der = load_ocsp_response_for_url(
                cert_path,
                issuer_pem_path,
                ocsp_url,
                env,
            )
        except (RuntimeError, ValueError):
            # Переход к следующему адресу при ошибке получения или разбора ответа
            continue
        # Сохранение варианта ответа вместе с его размером
        response_variants.append((len(basic_ocsp_response_der), ocsp_response_der, basic_ocsp_response_der, ocsp_url))
    # Сортировка ответов по размеру BasicOCSPResponse
    response_variants.sort(key=lambda item: item[0])
    # Выбор минимального подходящего ответа
    _basic_response_size, ocsp_response_der, basic_ocsp_response_der, chosen_ocsp_url = response_variants[0]
    # Возврат выбранного OCSP-ответа и адреса, с которого он был получен
    return ocsp_response_der, basic_ocsp_response_der, chosen_ocsp_url

# Извлечение сертификатов из BasicOCSPResponse
def extract_certs_from_basic_ocsp(basic_ocsp_response_der: bytes) -> List[x509.Certificate]:
    # Разбор BasicOCSPResponse
    basic_ocsp_response = ocsp.BasicOCSPResponse.load(basic_ocsp_response_der)
    # Получение сертификатов, вложенных в OCSP-ответ
    embedded_certificates = basic_ocsp_response["certs"]
    # Возврат списка сертификатов из OCSP-ответа
    return list(embedded_certificates)

# Удаление вложенных сертификатов из BasicOCSPResponse
def drop_basic_ocsp_certs(basic_ocsp_response_der: bytes) -> bytes:
    # Разбор исходного BasicOCSPResponse
    basic_ocsp_response = ocsp.BasicOCSPResponse.load(basic_ocsp_response_der)
    # Пересборка BasicOCSPResponse без поля certs
    rebuilt_basic_ocsp_response = ocsp.BasicOCSPResponse(
        {
            "tbs_response_data": basic_ocsp_response["tbs_response_data"],
            "signature_algorithm": basic_ocsp_response["signature_algorithm"],
            "signature": basic_ocsp_response["signature"],
            # certs намеренно не включаем
        }
    )
    # Возврат очищенного BasicOCSPResponse в DER-представлении
    return rebuilt_basic_ocsp_response.dump()

# Получение токена штампа времени от TSA-сервиса
def request_timestamp_token(imprint: bytes, tsa_url: str) -> cms.ContentInfo:
    # Формирование RFC 3161-запроса на штамп времени
    req = tsp.TimeStampReq(
        {
            "version": 1,
            "message_imprint": tsp.MessageImprint(
                {
                    # Указание алгоритма хэширования для imprint
                    "hash_algorithm": make_gost_digest_alg(),
                    # Передача хэша данных, для которых запрашивается штамп времени
                    "hashed_message": imprint,
                }
            ),
            # Формирование случайного значения для защиты запроса от повторного использования
            "nonce": core.Integer(secrets.randbits(64)),
            # Запрос сертификата TSA в составе ответа
            "cert_req": True,
        }
    )
    # Отправка запроса в TSA-сервис и получение ответа
    tsr = send_post(
        tsa_url,
        req.dump(),
        content_type="application/timestamp-query",
        accept="application/timestamp-reply",
    )
    # Разбор ответа TSA
    resp = tsp.TimeStampResp.load(tsr)
    # Получение TimeStampToken из ответа TSA
    token = resp["time_stamp_token"]
    # Возврат токена штампа времени
    return token

# Создание атрибута complete-certificate-references
def make_complete_certificate_refs(certs_for_refs: Sequence[x509.Certificate], env: dict[str, str]) -> CompleteCertificateRefs:
    # Создание списка ссылок на сертификаты
    items = []
    # Последовательное формирование ссылки для каждого сертификата
    for cert in certs_for_refs:
        # Вычисление хэша DER-представления сертификата
        digest = calc_gost256(cert_to_der(cert), env)
        # Добавление ссылки на сертификат через хэш
        items.append(
            OtherCertID(
                {
                    "other_cert_hash": OtherHash(
                        name="other_hash",
                        value=OtherHashAlgAndValue(
                            {
                                "hash_algorithm": make_gost_digest_alg(),
                                "hash_value": digest,
                            }
                        ),
                    ),
                }
            )
        )
    # Возврат набора ссылок на сертификаты
    return CompleteCertificateRefs(items)

# Создание атрибута complete-revocation-references
def make_complete_revocation_refs(basic_ocsp_response_der_without_certs: bytes, env: dict[str, str]) -> CompleteRevocationRefs:
    # Разбор BasicOCSPResponse без вложенных сертификатов
    basic_ocsp_response = ocsp.BasicOCSPResponse.load(basic_ocsp_response_der_without_certs)
    # Получение данных ответа, подписанных OCSP-сервером
    tbs_response_data = basic_ocsp_response["tbs_response_data"]
    # Создание идентификатора OCSP-ответа
    ocsp_identifier = OcspIdentifier(
        {
            "ocsp_responder_id": tbs_response_data["responder_id"],
            "produced_at": tbs_response_data["produced_at"],
        }
    )
    # Создание ссылки на OCSP-ответ с хэшем ответа
    ocsp_response_id = OcspResponsesID(
        {
            "ocsp_identifier": ocsp_identifier,
            "ocsp_rep_hash": OtherHash(
                name="other_hash",
                value=OtherHashAlgAndValue(
                    {
                        "hash_algorithm": make_gost_digest_alg(),
                        "hash_value": calc_gost256(basic_ocsp_response_der_without_certs, env),
                    }
                ),
            ),
        }
    )
    # Формирование структуры ссылки на данные проверки статуса сертификата
    crl_ocsp_ref_list = [CrlOcspRef({"ocspids": OcspListID({"ocsp_responses": OcspResponses([ocsp_response_id])})})]
    # Возврат набора ссылок на данные проверки статуса сертификатов
    return CompleteRevocationRefs(crl_ocsp_ref_list)

# Создание атрибута revocation-values
def make_revocation_values(cleaned_basic_der: bytes) -> RawRevocationValues:
    # Включение BasicOCSPResponse в значения данных проверки статуса сертификатов
    return RawRevocationValues(
        {
            "ocsp_vals": RawBasicOcspResponses([core.Any.load(cleaned_basic_der)]),
        }
    )

# Формирование хэша для esc-time-stamp
def build_esc_imprint_v1(signature_value: bytes, attrs_for_esc: Sequence[cms.CMSAttribute], env: dict[str, str]) -> bytes:
    # Создание набора данных, начинающегося со значения электронной подписи
    esc_imprint_input = bytearray(signature_value)
    # Добавление DER-представлений типа и значений проверочных атрибутов
    for cms_attribute in attrs_for_esc:
        esc_imprint_input += cms_attribute["type"].dump()
        esc_imprint_input += cms_attribute["values"].dump()
    # Возврат хэша сформированного набора данных
    return calc_gost256(bytes(esc_imprint_input), env)

# Получение пароля к закрытому ключу через диалоговое окно
def ask_key_password() -> str:
    # Создание скрытого окна Tkinter
    root = tkinter.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        # Отображение окна ввода пароля к закрытому ключу
        password = simpledialog.askstring(
            "Пароль к ключу",
            "Введите пароль к закрытому ключу\n"
            "Если пароля нет - оставьте поле пустым.",
            show="*",
            parent=root,
        )
    finally:
        # Закрытие окна Tkinter после ввода
        root.destroy()
    # Возврат введенного пароля или пустой строки
    return password or ""

# Формирование базового CMS/CAdES-BES контейнера средствами OpenSSL
def build_bes_container(paths: SigningPaths, env: dict[str, str]) -> bytes:
    # Формирование команды OpenSSL для создания отсоединенной CAdES-BES подписи
    cmd = [
        "openssl",  # Вызов OpenSSL
        "cms",  # Работа с CMS-контейнером
        "-sign",  # Формирование электронной подписи
        "-binary",  # Обработка входного файла как бинарных данных
        "-cades",  # Формирование подписи CAdES
        "-md",  # Указание алгоритма хэширования
        "md_gost12_256",  # ГОСТ Р 34.11-2012, 256 бит
        "-in",  # Указание входного файла
        str(paths.input_path),  # Путь к подписываемому файлу
        "-signer",  # Указание сертификата подписанта
        str(paths.signer_cert_path),  # Путь к сертификату подписанта
        "-inkey",  # Указание закрытого ключа
        str(paths.signer_key_path),  # Путь к закрытому ключу
        "-certfile",  # Указание цепочки сертификатов
        str(paths.chain_path),  # Путь к цепочке сертификатов
        "-outform",  # Указание формата выходных данных
        "DER",  # DER-кодировка итоговой подписи
        "-nosmimecap",  # Исключение атрибута SMIMECapabilities
    ]
    # Подготовка локального окружения для передачи пароля к закрытому ключу
    local_env = env.copy()
    key_password = ask_key_password()
    local_env["CADES_KEY_PASSWORD"] = key_password
    # Передача пароля в OpenSSL через переменную окружения
    cmd.extend(["-passin", "env:CADES_KEY_PASSWORD"])
    # Выполнение команды OpenSSL и возврат DER-представления подписи
    return run_cmd(cmd, local_env)

# Разбор DER-представления CMS/CAdES-подписи и получение основных структур
def load_context(signature_der: bytes) -> tuple[cms.ContentInfo, cms.SignedData, cms.SignerInfos, cms.SignerInfo, bytes]:
    # Загрузка верхнего CMS-контейнера ContentInfo
    content_info = cms.ContentInfo.load(signature_der)
    # Получение структуры SignedData из ContentInfo
    signed_data = content_info["content"]
    # Получение набора сведений о подписантах
    signer_infos = signed_data["signer_infos"]
    # Получение сведений о первом подписанте
    signer_info = signer_infos[0]
    # Получение значения электронной подписи
    signature_value = signer_info["signature"].native
    # Возврат основных структур, необходимых для дальнейшего расширения подписи
    return content_info, signed_data, signer_infos, signer_info, signature_value

# Добавление штампа времени подписи для формирования уровня CAdES-T
def attach_signature_timestamp(
    content_info: cms.ContentInfo,
    signer_infos: cms.SignerInfos,
    signer_info: cms.SignerInfo,
    signature_value: bytes,
    tsa_url: str,
    env: dict[str, str]
) -> tuple[cms.ContentInfo, cms.SignerInfo]:
    # Получение TimeStampToken для хэша значения электронной подписи
    signature_timestamp_token = request_timestamp_token(calc_gost256(signature_value, env), tsa_url)
    # Добавление TimeStampToken в неподписанные атрибуты SignerInfo
    signer_info = append_unsigned_attr(signer_info, OID_SIG_TST, signature_timestamp_token)
    # Обновление набора SignerInfos после изменения SignerInfo
    signer_infos[0] = signer_info
    # Запись обновленного набора SignerInfos обратно в CMS-контейнер
    content_info["content"]["signer_infos"] = signer_infos
    # Возврат обновленного CMS-контейнера и измененной структуры SignerInfo
    return content_info, signer_info

# Формирование неподписанных атрибутов для уровня CAdES-XLT1
def build_xlt_unsigned_attrs(
    content_info: cms.ContentInfo,
    signer_info: cms.SignerInfo,
    signature_value: bytes,
    signer_cert_path: Path,
    chain_path: Path,
    tsa_url: str,
    env: dict[str, str],
) -> tuple[cms.SignerInfo, Optional[str]]:
    # Чтение сертификатов цепочки
    chain_certs = read_certs(chain_path)
    # Чтение сертификата подписанта
    signer_cert = read_certs(signer_cert_path)[0]
    # Поиск сертификата издателя сертификата подписанта
    issuer_cert = find_issuer_cert(signer_cert, chain_certs)
    # Формирование PEM-представления сертификата издателя
    issuer_pem = pem.armor("CERTIFICATE", cert_to_der(issuer_cert))
    # Создание временного файла для передачи сертификата издателя в OpenSSL
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        issuer_pem_path = Path(temp_file.name)
    # Переменная для хранения выбранного OCSP-адреса
    chosen_ocsp_url = None
    try:
        # Запись сертификата издателя во временный файл
        issuer_pem_path.write_bytes(issuer_pem)
        # Получение OCSP-адресов из сертификата подписанта
        ocsp_urls = get_ocsp_urls_from_file(signer_cert_path, env)
        # Объединение адресов из сертификата и дополнительных тестовых OCSP-адресов
        all_ocsp_urls = ocsp_urls + EXTRA_OCSP_URLS
        # Получение подходящего OCSP-ответа
        _ocsp_response_der, basic_ocsp_response_der, chosen_ocsp_url = pick_best_ocsp_response(
            signer_cert_path,
            issuer_pem_path,
            all_ocsp_urls,
            env,
        )
    finally:
        # Удаление временного файла с сертификатом издателя
        issuer_pem_path.unlink(missing_ok=True)
    # Извлечение сертификатов, вложенных в OCSP-ответ
    ocsp_extra_certs = extract_certs_from_basic_ocsp(basic_ocsp_response_der)
    # Удаление вложенных сертификатов из BasicOCSPResponse
    basic_ocsp_response_der_without_certs = drop_basic_ocsp_certs(basic_ocsp_response_der)
    # Подготовка сертификатов для атрибута complete-certificate-references
    cert_refs_certs = merge_certs_unique([chain_certs, ocsp_extra_certs])
    # Создание ссылок на сертификаты
    complete_cert_refs = make_complete_certificate_refs(cert_refs_certs, env)
    # Создание ссылок на данные проверки статуса сертификатов
    complete_rev_refs = make_complete_revocation_refs(
        basic_ocsp_response_der_without_certs,
        env,
    )
    # Создание значений данных проверки статуса сертификатов
    revocation_values = make_revocation_values(basic_ocsp_response_der_without_certs)
    # Получение DER-представлений сертификатов, уже находящихся в SignedData.certificates
    signed_data_cert_ders = {cert.dump() for cert in read_signed_data_certificates(content_info)}
    # Подготовка сертификатов для certificate-values без повторного включения уже имеющихся сертификатов
    cert_values_certs = [
        cert
        for cert in merge_certs_unique([[signer_cert], chain_certs, ocsp_extra_certs])
        if cert.dump() not in signed_data_cert_ders
    ]
    # Создание атрибута certificate-values
    certificate_values = CertificateValues(cert_values_certs)
    # Добавление complete-certificate-references в неподписанные атрибуты
    signer_info = append_unsigned_attr(signer_info, OID_CERT_REFS, complete_cert_refs)
    # Добавление certificate-values в неподписанные атрибуты
    signer_info = append_unsigned_attr(signer_info, OID_CERT_VALS, certificate_values)
    # Добавление complete-revocation-references в неподписанные атрибуты
    signer_info = append_unsigned_attr(signer_info, OID_REV_REFS, complete_rev_refs)
    # Добавление revocation-values в неподписанные атрибуты
    signer_info = append_unsigned_attr(signer_info, OID_REV_VALS, revocation_values)
    # Получение атрибута signature-time-stamp
    signature_timestamp_attr = find_unsigned_attr(signer_info, OID_SIG_TST)
    # Получение атрибута complete-certificate-references
    certificate_refs_attr = find_unsigned_attr(signer_info, OID_CERT_REFS)
    # Получение атрибута complete-revocation-references
    revocation_refs_attr = find_unsigned_attr(signer_info, OID_REV_REFS)
    # Формирование хэша для esc-time-stamp
    esc_imprint = build_esc_imprint_v1(
        signature_value,
        [signature_timestamp_attr, certificate_refs_attr, revocation_refs_attr],
        env,
    )
    # Получение токена штампа времени для проверочных данных
    esc_timestamp_token = request_timestamp_token(esc_imprint, tsa_url)
    # Добавление esc-time-stamp в неподписанные атрибуты
    signer_info = append_unsigned_attr(signer_info, OID_ESC_TST, esc_timestamp_token)
    # Возврат обновленного SignerInfo и выбранного OCSP-адреса
    return signer_info, chosen_ocsp_url

# Чтение сертификатов из SignedData.certificates
def read_signed_data_certificates(content_info: cms.ContentInfo) -> List[x509.Certificate]:
    # Получение структуры SignedData
    signed_data = content_info["content"]
    # Получение поля certificates из SignedData
    certificate_choices_field = signed_data["certificates"]
    # Создание списка сертификатов
    signed_data_certificates = []
    # Последовательный разбор сертификатов из SignedData.certificates
    for certificate_choice in certificate_choices_field:
        # Получение DER-представления текущего сертификата
        certificate_der = certificate_choice.chosen.dump()
        # Безопасная загрузка сертификата
        certificate = load_cert_safely(certificate_der)
        # Добавление сертификата при успешном разборе
        if certificate is not None:
            signed_data_certificates.append(certificate)
    # Возврат списка сертификатов из SignedData
    return signed_data_certificates

# Чтение сертификатов из TimeStampToken
def read_timestamp_certs(timestamp_token: cms.ContentInfo) -> List[x509.Certificate]:
    # Создание списка сертификатов TimeStampToken
    certificates = []
    # Получение сертификатов из SignedData внутри TimeStampToken
    for certificate_item in timestamp_token["content"]["certificates"]:
        # Добавление выбранного значения CertificateChoices
        certificates.append(certificate_item.chosen)
    # Возврат сертификатов из TimeStampToken
    return certificates

# Поиск сертификата TSA, которым подписан TimeStampToken
def find_timestamp_signer_cert(timestamp_token: cms.ContentInfo) -> x509.Certificate:
    # Получение SignerInfo из TimeStampToken
    tsa_signer_info = timestamp_token["content"]["signer_infos"][0]
    # Получение идентификатора подписанта TSA
    signer_id = tsa_signer_info["sid"].chosen
    # Поиск сертификата, соответствующего issuer и serialNumber из SignerInfo
    for certificate in read_timestamp_certs(timestamp_token):
        cert_tbs = certificate["tbs_certificate"]
        if (
            cert_tbs["issuer"] == signer_id["issuer"]
            and cert_tbs["serial_number"].native == signer_id["serial_number"].native
        ):
            return certificate
    # Ошибка при отсутствии сертификата подписанта TSA
    raise ValueError("В TimeStampToken не найден сертификат TSA.")

# Чтение сертификатов из атрибутов certificate-values структуры SignerInfo
def read_cert_values_from_signer_info(signer_info: cms.SignerInfo) -> List[x509.Certificate]:
    # Создание списка сертификатов
    certificates = []
    # Последовательный обход неподписанных атрибутов
    for unsigned_attr in read_unsigned_attrs(signer_info):
        # Пропуск атрибутов, не являющихся certificate-values
        if unsigned_attr["type"].dotted != OID_CERT_VALS:
            continue
        # Чтение сертификатов из значений атрибута certificate-values
        for attr_value in unsigned_attr["values"]:
            certificates.extend(CertificateValues.load(attr_value.dump()))
    # Возврат найденных сертификатов
    return certificates

# Получение OCSP-ответа для заданного сертификата
def get_ocsp_for_cert(cert: x509.Certificate, issuer_cert: x509.Certificate, env: dict[str, str]) -> bytes:
    # Создание временного файла для проверяемого сертификата
    with tempfile.NamedTemporaryFile(delete=False) as cert_file:
        cert_path = Path(cert_file.name)
    # Создание временного файла для сертификата издателя
    with tempfile.NamedTemporaryFile(delete=False) as issuer_file:
        issuer_path = Path(issuer_file.name)
    try:
        # Запись проверяемого сертификата во временный PEM-файл
        cert_path.write_bytes(pem.armor("CERTIFICATE", cert.dump()))
        # Запись сертификата издателя во временный PEM-файл
        issuer_path.write_bytes(pem.armor("CERTIFICATE", issuer_cert.dump()))
        # Получение OCSP-адресов из проверяемого сертификата
        ocsp_urls = get_ocsp_urls_from_file(cert_path, env)
        # Получение подходящего OCSP-ответа
        _ocsp_response_der, basic_ocsp_der, _chosen_url = pick_best_ocsp_response(
            cert_path,
            issuer_path,
            ocsp_urls + EXTRA_OCSP_URLS,
            env,
        )
        # Возврат BasicOCSPResponse без вложенных сертификатов
        return drop_basic_ocsp_certs(basic_ocsp_der)
    finally:
        # Удаление временного файла проверяемого сертификата
        cert_path.unlink(missing_ok=True)
        # Удаление временного файла сертификата издателя
        issuer_path.unlink(missing_ok=True)

# Дополнение архивных штампов времени проверочными данными TSA
def extend_all_archive_timestamps_validation_material(
    content_info: cms.ContentInfo,
    signer_infos: cms.SignerInfos,
    signer_info: cms.SignerInfo,
    env: dict[str, str],
) -> tuple[cms.ContentInfo, cms.SignerInfo]:
    # Получение неподписанных атрибутов основной подписи
    unsigned_attrs = read_unsigned_attrs(signer_info)
    # Подготовка набора сертификатов, доступных для поиска издателя TSA
    available_certs = merge_certs_unique(
        [
            read_signed_data_certificates(content_info),
            read_cert_values_from_signer_info(signer_info),
        ]
    )
    # Признак изменения структуры подписи
    changed = False
    # Последовательный обход неподписанных атрибутов основной подписи
    for index, unsigned_attr in enumerate(unsigned_attrs):
        # Обработка только архивных штампов времени версии 3
        if unsigned_attr["type"].dotted != OID_ARCHIVE_TST_V3:
            continue
        # Загрузка TimeStampToken из значения archive-time-stamp-v3
        timestamp_token = cms.ContentInfo.load(unsigned_attr["values"][0].dump())
        # Получение SignedData внутри TimeStampToken
        timestamp_signed_data = timestamp_token["content"]
        # Получение SignerInfos внутри TimeStampToken
        timestamp_signer_infos = timestamp_signed_data["signer_infos"]
        # Получение SignerInfo подписанта TSA
        timestamp_signer_info = timestamp_signer_infos[0]
        # Проверка наличия certificate-values внутри TimeStampToken
        has_cert_values = find_unsigned_attr(timestamp_signer_info, OID_CERT_VALS) is not None
        # Проверка наличия revocation-values внутри TimeStampToken
        has_rev_values = find_unsigned_attr(timestamp_signer_info, OID_REV_VALS) is not None
        # Пропуск штампа времени при наличии всех проверочных данных
        if has_cert_values and has_rev_values:
            continue
        # Чтение сертификатов из TimeStampToken
        timestamp_certs = read_timestamp_certs(timestamp_token)
        # Определение сертификата TSA, подписавшего TimeStampToken
        tsa_cert = find_timestamp_signer_cert(timestamp_token)
        # Поиск сертификата издателя сертификата TSA
        issuer_cert = find_issuer_cert(
            tsa_cert,
            merge_certs_unique([timestamp_certs, available_certs]),
        )
        # Получение OCSP-ответа для сертификата TSA
        ocsp_der = get_ocsp_for_cert(tsa_cert, issuer_cert, env)
        # Добавление certificate-values при его отсутствии
        if not has_cert_values:
            timestamp_signer_info = append_unsigned_attr(
                timestamp_signer_info,
                OID_CERT_VALS,
                CertificateValues(merge_certs_unique([[tsa_cert, issuer_cert]])),
            )
        # Добавление revocation-values при его отсутствии
        if not has_rev_values:
            timestamp_signer_info = append_unsigned_attr(
                timestamp_signer_info,
                OID_REV_VALS,
                make_revocation_values(ocsp_der),
            )
        # Запись обновленного SignerInfo обратно в TimeStampToken
        timestamp_signer_infos[0] = timestamp_signer_info
        timestamp_signed_data["signer_infos"] = timestamp_signer_infos
        timestamp_token["content"] = timestamp_signed_data
        # Замена исходного archive-time-stamp-v3 обновленным значением
        unsigned_attrs[index] = cms.CMSAttribute({"type": OID_ARCHIVE_TST_V3, "values": [timestamp_token]})
        # Фиксация факта изменения подписи
        changed = True
    # Обновление основной подписи при изменении архивных штампов времени
    if changed:
        signer_info["unsigned_attrs"] = cms.CMSAttributes(unsigned_attrs)
        signer_infos[0] = signer_info
        content_info["content"]["signer_infos"] = signer_infos
    # Возврат обновленного CMS-контейнера и SignerInfo
    return content_info, signer_info

# Получение неподписанных атрибутов для расчета ATSHashIndexV3
def der_sorted_unsigned_attrs_for_ats_hash_index(signer_info: cms.SignerInfo) -> List[cms.CMSAttribute]:
    # Возврат неподписанных атрибутов в текущем порядке SignerInfo
    return read_unsigned_attrs(signer_info)

# Вычисление хэшей неподписанных атрибутов для ATSHashIndexV3
def ats_v3_unsigned_attr_value_hashes(signer_info: cms.SignerInfo, env: dict[str, str]) -> List[bytes]:
    # Создание списка хэшей значений неподписанных атрибутов
    unsigned_attr_value_hashes: List[bytes] = []
    # Последовательный обход неподписанных атрибутов
    for unsigned_attr in der_sorted_unsigned_attrs_for_ats_hash_index(signer_info):
        # Получение DER-представления OID атрибута
        attr_type_der = unsigned_attr["type"].dump()
        # Последовательный обход значений текущего атрибута
        for attr_value in unsigned_attr["values"]:
            # Вычисление хэша от DER(type) + DER(value)
            unsigned_attr_value_hashes.append(calc_gost256(attr_type_der + attr_value.dump(), env))
    # Возврат списка хэшей неподписанных атрибутов
    return unsigned_attr_value_hashes

# Формирование структуры ATSHashIndexV3
def make_ats_hash_index_v3(content_info: cms.ContentInfo, signer_info: cms.SignerInfo, env: dict[str, str]) -> ATSHashIndexV3:
    # Вычисление хэшей сертификатов из SignedData.certificates
    certificate_hashes = [calc_gost256(cert.dump(), env) for cert in read_signed_data_certificates(content_info)]
    # Вычисление хэшей неподписанных атрибутов SignerInfo
    unsigned_attr_hashes = ats_v3_unsigned_attr_value_hashes(signer_info, env)
    # Создание ASN.1-структуры ATSHashIndexV3
    return ATSHashIndexV3({
        "hash_ind_algorithm": make_gost_digest_alg(),
        "certificates_hash_index": OctetStringSequence(certificate_hashes),
        "crls_hash_index": OctetStringSequence([]),
        "unsigned_attrs_hash_index": OctetStringSequence(unsigned_attr_hashes),
    })

# Получение DER-представлений основных полей SignerInfo для archive-time-stamp-v3
def signer_info_archive_fields_der(signer_info: cms.SignerInfo) -> bytes:
    # Формирование списка полей SignerInfo, защищаемых архивным штампом времени
    signer_info_field_der_parts = [
        signer_info["version"].dump(),
        signer_info["sid"].dump(),
        signer_info["digest_algorithm"].dump(),
        signer_info["signed_attrs"].dump(),
        signer_info["signature_algorithm"].dump(),
        signer_info["signature"].dump(),
    ]
    # Объединение DER-представлений полей SignerInfo
    return b"".join(signer_info_field_der_parts)

# Извлечение messageDigest из подписанных атрибутов SignerInfo
def extract_message_digest_from_signed_attrs(signer_info: cms.SignerInfo) -> bytes:
    # Получение подписанных атрибутов
    signed_attrs = signer_info["signed_attrs"]
    # Поиск атрибута messageDigest
    for signed_attr in signed_attrs:
        if signed_attr["type"].dotted == "1.2.840.113549.1.9.4":
            return signed_attr["values"][0].native
    # Ошибка при отсутствии messageDigest
    raise ValueError("В signedAttrs не найден messageDigest.")

# Проверка наличия archive-time-stamp-v3 в подписи
def ensure_has_archive_timestamp_v3(signer_info: cms.SignerInfo) -> None:
    # Поиск архивного штампа времени версии 3
    archive_timestamp_attr = find_unsigned_attr(signer_info, OID_ARCHIVE_TST_V3)
    # Ошибка при отсутствии archive-time-stamp-v3
    if archive_timestamp_attr is None:
        raise ValueError("В подписи не найден archiveTimestampV3. Это не CAdES-A подпись.")

# Проверка соответствия исходного файла атрибуту messageDigest
def ensure_input_matches_signed_attrs(
    input_path: Path,
    signer_info: cms.SignerInfo,
    env: dict[str, str],
) -> None:
    # Получение ожидаемого хэша из signedAttrs
    expected_digest = extract_message_digest_from_signed_attrs(signer_info)
    # Вычисление фактического хэша исходного файла
    actual_digest = calc_gost256(input_path.read_bytes(), env)
    # Сравнение фактического хэша с messageDigest из подписи
    if actual_digest != expected_digest:
        raise ValueError("Исходный файл не соответствует messageDigest из CAdES-подписи.")

# Формирование хэша для archive-time-stamp-v3
def build_archive_timestamp_v3_imprint(
    content_info: cms.ContentInfo,
    signer_info: cms.SignerInfo,
    ats_hash_index: ATSHashIndexV3,
    env: dict[str, str],
) -> bytes:
    # Получение структуры SignedData
    signed_data = content_info["content"]
    # Получение хэша подписанного содержимого из signedAttrs
    signed_content_hash = extract_message_digest_from_signed_attrs(signer_info)
    # Формирование набора данных, защищаемых архивным штампом времени
    archive_imprint_parts = [
        signed_data["encap_content_info"]["content_type"].dump(),
        signed_content_hash,
        signer_info_archive_fields_der(signer_info),
        ats_hash_index.dump(),
    ]
    # Возврат хэша набора данных archive-time-stamp-v3
    return calc_gost256(b"".join(archive_imprint_parts), env)

# Добавление ATSHashIndexV3 внутрь TimeStampToken
def add_ats_hash_index_v3_to_timestamp_token(timestamp_token: cms.ContentInfo, ats_hash_index: ATSHashIndexV3) -> cms.ContentInfo:
    # Создание независимой копии TimeStampToken через DER-сериализацию
    timestamp_token = cms.ContentInfo.load(timestamp_token.dump())
    # Получение SignedData внутри TimeStampToken
    signed_data = timestamp_token["content"]
    # Получение набора SignerInfos TSA
    signer_infos = signed_data["signer_infos"]
    # Получение SignerInfo подписанта TSA
    tsa_signer_info = signer_infos[0]
    # Добавление ATSHashIndexV3 в неподписанные атрибуты TimeStampToken
    tsa_signer_info = append_unsigned_attr(
        tsa_signer_info,
        OID_ATS_HASH_INDEX_V3,
        ats_hash_index,
    )
    # Запись обновленного SignerInfo обратно в TimeStampToken
    signer_infos[0] = tsa_signer_info
    signed_data["signer_infos"] = signer_infos
    timestamp_token["content"] = signed_data
    # Возврат TimeStampToken с добавленным ATSHashIndexV3
    return timestamp_token

# Добавление archive-time-stamp-v3 для формирования или обновления CAdES-A
def append_archive_timestamp(
    content_info: cms.ContentInfo,
    signer_infos: cms.SignerInfos,
    signer_info: cms.SignerInfo,
    tsa_url: str,
    env: dict[str, str],
) -> cms.ContentInfo:
    # Запись актуального SignerInfo в CMS-контейнер перед расчетом архивного штампа
    signer_infos[0] = signer_info
    content_info["content"]["signer_infos"] = signer_infos
    # Формирование ATSHashIndexV3
    ats_hash_index = make_ats_hash_index_v3(content_info, signer_info, env)
    # Формирование хэша данных для archive-time-stamp-v3
    archive_imprint = build_archive_timestamp_v3_imprint(
        content_info=content_info,
        signer_info=signer_info,
        ats_hash_index=ats_hash_index,
        env=env,
    )
    # Получение TimeStampToken для архивного штампа времени
    archive_timestamp_token = request_timestamp_token(archive_imprint, tsa_url)
    # Добавление ATSHashIndexV3 внутрь полученного TimeStampToken
    archive_timestamp_token = add_ats_hash_index_v3_to_timestamp_token(archive_timestamp_token, ats_hash_index)
    # Добавление archive-time-stamp-v3 в неподписанные атрибуты SignerInfo
    signer_info = append_unsigned_attr(signer_info, OID_ARCHIVE_TST_V3, archive_timestamp_token)
    # Запись обновленного SignerInfo обратно в CMS-контейнер
    signer_infos[0] = signer_info
    content_info["content"]["signer_infos"] = signer_infos
    # Возврат CMS-контейнера с архивным штампом времени
    return content_info

# Преобразование ASN.1-времени в формат для метаданных
def format_datetime_node(value: object) -> dict[str, str]:
    # Получение Python-представления значения времени
    dt = value.native
    # Приведение времени к UTC при поддержке astimezone
    if hasattr(dt, "astimezone"):
        dt = dt.astimezone(timezone.utc)
        return {
            "iso": dt.isoformat(),
            "display": dt.strftime("%d.%m.%Y %H:%M:%S"),
        }
    # Возврат строкового представления для нестандартных значений
    return {"iso": str(dt), "display": str(dt)}

# Преобразование ASN.1-имени сертификата в строку
def name_to_string(name: object) -> str:
    # Преобразование имени сертификата в строковое представление key=value
    return ", ".join(
        f"{key}={value}"
        for key, value in name.native.items()
    )

# Формирование сведений о сертификате для метаданных
def cert_details(cert: x509.Certificate) -> dict[str, object]:
    # Получение структуры tbsCertificate
    tbs = cert["tbs_certificate"]
    # Получение периода действия сертификата
    validity = tbs["validity"]
    # Форматирование даты начала действия сертификата
    valid_from = format_datetime_node(validity["not_before"])
    # Форматирование даты окончания действия сертификата
    valid_to = format_datetime_node(validity["not_after"])
    # Формирование словаря сведений о сертификате
    return {
        "subject": name_to_string(tbs["subject"]),
        "issuer": name_to_string(tbs["issuer"]),
        "serial_number": format(tbs["serial_number"].native, "X"),
        "valid_from": valid_from,
        "valid_to": valid_to,
        "validity_period_display": f"{valid_from.get('display','')} - {valid_to.get('display','')}",
        "fingerprint_sha1": hashlib.sha1(cert.dump()).hexdigest().upper(),
    }

# Извлечение времени штампа и сертификата TSA из атрибута timestamp
def extract_tst_info_and_cert(timestamp_attr: Optional[cms.CMSAttribute]) -> Tuple[dict[str, str], dict[str, object]]:
    # Возврат пустых значений при отсутствии атрибута timestamp
    if not timestamp_attr:
        return {}, {}
    # Загрузка TimeStampToken из значения атрибута
    timestamp_token = cms.ContentInfo.load(timestamp_attr["values"][0].dump())
    # Получение структуры TSTInfo из TimeStampToken
    tst_info = timestamp_token["content"]["encap_content_info"]["content"].parsed
    # Создание списка сертификатов TSA
    tsa_certificates = []
    # Получение набора сертификатов из TimeStampToken
    certificate_set = timestamp_token["content"]["certificates"]
    # Чтение сертификатов из TimeStampToken
    for certificate_item in certificate_set:
        tsa_certificates.append(x509.Certificate.load(certificate_item.dump()))
    # Получение первого сертификата TSA
    tsa_signer_cert = tsa_certificates[0]
    # Возврат времени штампа и сведений о сертификате TSA
    return format_datetime_node(tst_info["gen_time"]), cert_details(tsa_signer_cert)

# Извлечение сведений о подписи для метаданных
def extract_signing_details(signer_info: cms.SignerInfo, paths: SigningPaths, env: dict[str, str]) -> dict[str, object]:
    # Создание словаря сведений о подписи
    details = {}
    # Поиск штампа времени подписи
    signature_timestamp_attr = find_unsigned_attr(signer_info, OID_SIG_TST)
    # Поиск последнего архивного штампа времени
    archive_timestamp_attr = find_last_unsigned_attr(signer_info, OID_ARCHIVE_TST_V3)
    # Получение времени штампа подписи и сертификата TSA
    signature_timestamp_time, signing_timestamp_cert = extract_tst_info_and_cert(signature_timestamp_attr)
    # Запись времени штампа подписи
    if signature_timestamp_time:
        details["signature_time_from_timestamp"] = signature_timestamp_time
    # Запись сведений о сертификате TSA
    if signing_timestamp_cert:
        details["signing_time_stamp_certificate"] = signing_timestamp_cert
    # Создание переменной для времени signing-time
    signing_time = {}
    try:
        # Получение подписанных атрибутов
        signed_attrs = signer_info["signed_attrs"]
        # Поиск атрибута signing-time
        for signed_attr in signed_attrs:
            if signed_attr["type"].dotted == "1.2.840.113549.1.9.5":
                signing_time = format_datetime_node(signed_attr["values"][0])
                break
    except Exception:
        # Сохранение пустого значения при невозможности прочитать signing-time
        signing_time = {}
    # Запись времени signing-time
    if signing_time:
        details["signing_time"] = signing_time
    # Получение времени последнего архивного штампа
    archive_timestamp_time, _unused_archive_cert = extract_tst_info_and_cert(archive_timestamp_attr)
    # Запись времени архивного штампа
    if archive_timestamp_time:
        details["archive_timestamp_time"] = archive_timestamp_time
    # Запись сведений о сертификате подписанта при наличии пути к нему
    if paths.signer_cert_path is not None:
        signer_cert = read_certs(paths.signer_cert_path)[0]
        details["signer_certificate"] = cert_details(signer_cert)
    # Получение OID алгоритма электронной подписи
    signature_algorithm_oid = signer_info["signature_algorithm"]["algorithm"].dotted
    # Сопоставление OID алгоритмов с читаемыми названиями
    signature_algorithm_names = {
        OID_GOST_SIGN_256: "ГОСТ Р 34.10-2012 256 бит",
        OID_GOST_2012_256_MODULUS: "ГОСТ Р 34.10-2012 с 256-битным модулем",
    }
    # Запись названия алгоритма электронной подписи
    details["signature_algorithm"] = signature_algorithm_names.get(signature_algorithm_oid, signature_algorithm_oid)
    # Возврат сведений о подписи
    return details

# Сохранение итоговой подписи и формирование результата выполнения
def save_signature(
    content_info: cms.ContentInfo,
    signer_info: cms.SignerInfo,
    paths: SigningPaths,
    mode: str,
    path_out: Path,
    env: dict[str, str],
    tsa_url: str,
    selected_ocsp_url: Optional[str] = None,
) -> SigningResult:
    # Получение DER-представления итогового CMS-контейнера
    output_der = content_info.dump()
    # Запись подписи в файл
    path_out.write_bytes(output_der)
    # Формирование объекта результата
    return SigningResult(
        mode=mode,
        signature_path=path_out,
        tsa_url=tsa_url,
        output_size=len(output_der),
        selected_ocsp_url=selected_ocsp_url,
        details=extract_signing_details(signer_info, paths, env),
    )

# Обновление архивной CAdES-A подписи
def renew_cades_a_signature(config: RenewCadesAConfig) -> SigningResult:
    # Подготовка переменных окружения для вызова OpenSSL
    env = os.environ.copy()
    # Указание конфигурационного файла OpenSSL с поддержкой ГОСТ-алгоритмов
    env["OPENSSL_CONF"] = str(config.openssl_conf_path)
    # Чтение текущей CAdES-A подписи
    signature_der = config.current_signature_path.read_bytes()
    # Разбор CMS-контейнера текущей подписи
    content_info, _signed_data, signer_infos, signer_info, _signature_value = load_context(signature_der)
    # Проверка наличия archive-time-stamp-v3 в подписи
    ensure_has_archive_timestamp_v3(signer_info)
    # Проверка соответствия исходного файла текущей подписи
    ensure_input_matches_signed_attrs(config.input_path, signer_info, env)
    # Дополнение существующих архивных штампов времени проверочными данными TSA
    content_info, signer_info = extend_all_archive_timestamps_validation_material(
        content_info=content_info,
        signer_infos=signer_infos,
        signer_info=signer_info,
        env=env,
    )
    # Добавление нового archive-time-stamp-v3
    content_info = append_archive_timestamp(
        content_info=content_info,
        signer_infos=signer_infos,
        signer_info=signer_info,
        tsa_url=config.tsa_url,
        env=env,
    )
    # Получение обновленного SignerInfo после добавления архивного штампа
    signer_info = content_info["content"]["signer_infos"][0]
    # Создание набора путей для сохранения результата и извлечения метаданных
    paths = SigningPaths(
        input_path=config.input_path,
        signer_cert_path=config.signer_cert_path,
        signer_key_path=Path(""),
        chain_path=Path(""),
        openssl_conf_path=config.openssl_conf_path,
        output_path=config.output_path,
    )
    # Сохранение обновленной CAdES-A подписи
    return save_signature(
        content_info=content_info,
        signer_info=signer_info,
        paths=paths,
        mode=MODE_RENEW_A,
        path_out=config.output_path,
        env=env,
        tsa_url=config.tsa_url,
        selected_ocsp_url=None,
    )

# Формирование новой CAdES-подписи выбранного уровня
def sign_document(config: SigningConfig) -> SigningResult:
    # Определение пути для сохранения итоговой подписи
    output_path = config.paths.output_path
    # Формирование имени файла подписи по умолчанию
    if output_path is None:
        output_path = config.paths.input_path.with_name(f"{config.paths.input_path.name}.sig")
    # Подготовка переменных окружения для вызова OpenSSL
    env = os.environ.copy()
    # Указание конфигурационного файла OpenSSL с поддержкой ГОСТ-алгоритмов
    env["OPENSSL_CONF"] = str(config.paths.openssl_conf_path)
    # Формирование базовой подписи CAdES-BES средствами OpenSSL
    bes_der = build_bes_container(config.paths, env)
    # Разбор CMS-контейнера и получение основных структур подписи
    content_info, _signed_data, signer_infos, signer_info, signature_value = load_context(bes_der)
    # Завершение работы при необходимости формирования только уровня CAdES-BES
    if config.mode == MODE_BES:
        return save_signature(
            content_info=content_info,
            signer_info=signer_info,
            paths=config.paths,
            mode=config.mode,
            path_out=output_path,
            env=env,
            tsa_url=config.tsa_url,
            selected_ocsp_url=None,
        )
    # Добавление штампа времени подписи для формирования уровня CAdES-T
    content_info, signer_info = attach_signature_timestamp(
        content_info=content_info,
        signer_infos=signer_infos,
        signer_info=signer_info,
        signature_value=signature_value,
        tsa_url=config.tsa_url,
        env=env,
    )
    # Завершение работы при необходимости формирования уровня CAdES-T
    if config.mode == MODE_T:
        return save_signature(
            content_info=content_info,
            signer_info=signer_info,
            paths=config.paths,
            mode=config.mode,
            path_out=output_path,
            env=env,
            tsa_url=config.tsa_url,
            selected_ocsp_url=None,
        )
    # Начальное значение выбранного OCSP-адреса
    chosen_ocsp_url = None
    # Добавление проверочных данных для формирования уровня CAdES-XLT1
    signer_info, chosen_ocsp_url = build_xlt_unsigned_attrs(
        content_info=content_info,
        signer_info=signer_info,
        signature_value=signature_value,
        signer_cert_path=config.paths.signer_cert_path,
        chain_path=config.paths.chain_path,
        tsa_url=config.tsa_url,
        env=env,
    )
    # Запись обновленного SignerInfo в CMS-контейнер
    signer_infos[0] = signer_info
    content_info["content"]["signer_infos"] = signer_infos
    # Завершение работы при необходимости формирования уровня CAdES-XLT1
    if config.mode == MODE_XLT:
        return save_signature(
            content_info=content_info,
            signer_info=signer_info,
            paths=config.paths,
            mode=config.mode,
            path_out=output_path,
            env=env,
            tsa_url=config.tsa_url,
            selected_ocsp_url=chosen_ocsp_url,
        )
    # Добавление архивного штампа времени для формирования уровня CAdES-A
    content_info = append_archive_timestamp(
        content_info=content_info,
        signer_infos=signer_infos,
        signer_info=signer_info,
        tsa_url=config.tsa_url,
        env=env,
    )
    # Получение SignerInfo после добавления archive-time-stamp-v3
    signer_info = content_info["content"]["signer_infos"][0]
    # Сохранение итоговой CAdES-A подписи
    return save_signature(
        content_info=content_info,
        signer_info=signer_info,
        paths=config.paths,
        mode=config.mode,
        path_out=output_path,
        env=env,
        tsa_url=config.tsa_url,
        selected_ocsp_url=chosen_ocsp_url,
    )

# Создание конфигурации для формирования новой CAdES-подписи
def create_default_sign_config(
    base_dir: Path,
    mode: str,
    input_path: Optional[Path] = None,
    signer_cert_path: Optional[Path] = None,
    signer_key_path: Optional[Path] = None,
    chain_path: Optional[Path] = None,
    openssl_conf_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    tsa_url: str = "http://testgost2012.cryptopro.ru/tsp2012g/tsp.srf",
    verbose: bool = True,
) -> SigningConfig:
    # Определение пути к конфигурационному файлу OpenSSL по умолчанию
    if openssl_conf_path is None:
        openssl_conf_path = base_dir / "openssl_gost.cnf"
    # Объединение путей к исходному файлу, сертификату, ключу, цепочке сертификатов и конфигурации OpenSSL
    paths = SigningPaths(
        input_path=input_path,
        signer_cert_path=signer_cert_path,
        signer_key_path=signer_key_path,
        chain_path=chain_path,
        openssl_conf_path=openssl_conf_path,
        output_path=output_path,
    )
    # Создание общей конфигурации для формирования CAdES-подписи
    return SigningConfig(
        mode=mode,
        tsa_url=tsa_url,
        paths=paths,
        verbose=verbose,
    )

# Создание конфигурации для обновления CAdES-A подписи
def create_default_renew_a_config(
    base_dir: Path,
    input_path: Path,
    current_signature_path: Path,
    output_path: Optional[Path] = None,
    openssl_conf_path: Optional[Path] = None,
    tsa_url: str = "http://testgost2012.cryptopro.ru/tsp2012g/tsp.srf",
    signer_cert_path: Optional[Path] = None,
) -> RenewCadesAConfig:
    # Формирование имени файла обновленной подписи по умолчанию
    if output_path is None:
        output_path = input_path.with_name(f"{input_path.name}.renewed.sig")
    # Определение пути к конфигурационному файлу OpenSSL по умолчанию
    if openssl_conf_path is None:
        openssl_conf_path = base_dir / "openssl_gost.cnf"
    # Создание общей конфигурации для обновления CAdES-A подписи
    return RenewCadesAConfig(
        input_path=input_path,
        current_signature_path=current_signature_path,
        output_path=output_path,
        openssl_conf_path=openssl_conf_path,
        tsa_url=tsa_url,
        signer_cert_path=signer_cert_path,
    )

# Создание объекта парсера аргументов командной строки
def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Формирование CAdES-BES / T / XLT / A подписей.",
    )
    parser.add_argument(
        "--mode",
        choices=[MODE_BES, MODE_T, MODE_XLT, MODE_A, MODE_RENEW_A],
        default=MODE_BES,
        help="Режим подписи.",
    )
    parser.add_argument("--input", dest="input_path", type=Path, help="Путь к подписываемому файлу.")
    parser.add_argument("--current-signature", dest="current_signature_path", type=Path, help="Путь к текущей CAdES-A подписи для обновления.")
    parser.add_argument("--signer", dest="signer_cert_path", type=Path, help="Путь к сертификату подписанта.")
    parser.add_argument("--key", dest="signer_key_path", type=Path, help="Путь к закрытому ключу.")
    parser.add_argument("--chain", dest="chain_path", type=Path, help="Путь к цепочке сертификатов.")
    parser.add_argument(
        "--openssl-conf",
        dest="openssl_conf_path",
        type=Path,
        help="Путь к конфигурации OpenSSL.",
    )
    parser.add_argument("--output", dest="output_path", type=Path, help="Путь к итоговой подписи.")
    parser.add_argument(
        "--tsa-url",
        default="http://testgost2012.cryptopro.ru/tsp2012g/tsp.srf",
        help="URL TSA-сервиса.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Отключить вывод шагов выполнения.",
    )
    return parser

# Основная функция управления режимами выполнения программы
def main(argv: Optional[Sequence[str]] = None) -> int:
    # Создание парсера аргументов командной строки
    parser = build_arg_parser()
    # Чтение аргументов, переданных при запуске программы
    args = parser.parse_args(argv)
    # Каталог, в котором находится make_cades.py
    base_dir = Path(__file__).resolve().parent
    try:
        # Ветка для обновления уже существующей CAdES-A подписи
        if args.mode == MODE_RENEW_A:
            config = create_default_renew_a_config(
                base_dir=base_dir,
                input_path=args.input_path,
                current_signature_path=args.current_signature_path,
                output_path=args.output_path,
                openssl_conf_path=args.openssl_conf_path,
                tsa_url=args.tsa_url,
                signer_cert_path=args.signer_cert_path,
            )
            renew_cades_a_signature(config)
            return 0
        # Ветка создания новой CAdES-подписи
        config = create_default_sign_config(
            base_dir=base_dir,
            mode=args.mode,
            input_path=args.input_path,
            signer_cert_path=args.signer_cert_path,
            signer_key_path=args.signer_key_path,
            chain_path=args.chain_path,
            openssl_conf_path=args.openssl_conf_path,
            output_path=args.output_path,
            tsa_url=args.tsa_url,
            verbose=not args.quiet,
        )
        sign_document(config)
    except (RuntimeError, ValueError, URLError) as exc:
        parser.exit(status=1, message=f"Ошибка: {exc}\n")
    return 0

# Точка входа при запуске файла как самостоятельной программы
if __name__ == "__main__":
    raise SystemExit(main())
