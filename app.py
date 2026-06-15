import os
import tempfile
import tkinter
from pathlib import Path
from tkinter import simpledialog
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool

from make_cades import (
    MODE_A,
    MODE_BES,
    MODE_RENEW_A,
    MODE_T,
    MODE_XLT,
    create_default_renew_a_config,
    create_default_sign_config,
    renew_cades_a_signature,
    sign_document,
)
from mayan_client import MayanAPIError, MayanClient

# Название FastAPI-приложения
APP_TITLE = "CAdES MAYAN"
# Версия FastAPI-приложения
APP_VERSION = "1"
# URL TSA-сервиса по умолчанию
DEFAULT_TSA_URL = "http://testgost2012.cryptopro.ru/tsp2012g/tsp.srf"
# Допустимые режимы формирования и обновления подписи
ALLOWED_MODES = {MODE_BES, MODE_T, MODE_XLT, MODE_A, MODE_RENEW_A}

# Определение базового каталога приложения
BASE_DIR = Path(os.getenv("CADES_BASE_DIR", Path(__file__).resolve().parent)).resolve()
# Определение пути к конфигурационному файлу OpenSSL
OPENSSL_CONF_PATH = Path(
    os.getenv("CADES_OPENSSL_CONF_PATH", BASE_DIR / "openssl_gost.cnf")
).expanduser().resolve()
# Определение базового адреса Mayan EDMS
MAYAN_BASE_URL = os.getenv("CADES_MAYAN_BASE_URL", "http://127.0.0.1").rstrip("/")
# Определение наименования типа документа в Mayan EDMS
DOCUMENT_TYPE_LABEL = os.getenv("CADES_DOCUMENT_TYPE_LABEL", "CADES")

# Создание экземпляра FastAPI-приложения
app = FastAPI(title=APP_TITLE, version=APP_VERSION)


# Получение API-токена Mayan EDMS через диалоговое окно
def ask_mayan_token() -> str:
    # Создание скрытого окна tkinter
    root = tkinter.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        # Запрос API-токена Mayan EDMS
        token = simpledialog.askstring(
            "Mayan API token",
            "Введите Mayan API token",
            show="*",
            parent=root,
        )
    finally:
        # Закрытие окна tkinter после завершения запроса
        root.destroy()
    # Очистка введенного значения токена
    token = (token or "").strip()
    # Проверка наличия введенного API-токена
    if not token:
        raise HTTPException(
            status_code=400,
            detail="Mayan API token не введен",
        )
    # Возврат API-токена Mayan EDMS
    return token


# Преобразование значения метаданных в строковое представление
def format_display(value):
    # Получение отображаемого значения из словаря даты и времени
    if isinstance(value, dict):
        return str(value.get("display") or value.get("iso") or "")
    # Возврат строкового представления простого значения
    return str(value or "")


# Формирование набора метаданных для записи в Mayan EDMS
def build_mayan_metadata(filename, mode, result):
    # Получение сведений, сформированных модулем CAdES
    details = getattr(result, "details", {}) or {}
    # Получение сведений о сертификате подписанта
    signer = details.get("signer_certificate") or {}
    # Получение сведений о сертификате TSA
    tsa = details.get("signing_time_stamp_certificate") or {}
    # Создание словаря метаданных подписи и документа
    values = {
        "signature_mode": mode,
        "selected_ocsp_url": str(getattr(result, "selected_ocsp_url", "") or ""),
        "original_filename": filename,
        "signature_filename": getattr(result, "signature_path", Path(f"{filename}.sig")).name,
        "signature_time_from_timestamp": format_display(details.get("signature_time_from_timestamp")),
        "signing_time": format_display(details.get("signing_time")),
        "archive_timestamp_time": format_display(details.get("archive_timestamp_time")),
        "signature_algorithm": str(details.get("signature_algorithm") or ""),
        "signer_subject": str(signer.get("subject") or ""),
        "signer_issuer": str(signer.get("issuer") or ""),
        "signer_serial_number": str(signer.get("serial_number") or ""),
        "signer_valid_from": format_display(signer.get("valid_from")),
        "signer_valid_to": format_display(signer.get("valid_to")),
        "signer_fingerprint_sha1": str(signer.get("fingerprint_sha1") or ""),
        "tsa_subject": str(tsa.get("subject") or ""),
        "tsa_issuer": str(tsa.get("issuer") or ""),
        "tsa_serial_number": str(tsa.get("serial_number") or ""),
        "tsa_valid_from": format_display(tsa.get("valid_from")),
        "tsa_valid_to": format_display(tsa.get("valid_to")),
        "tsa_fingerprint_sha1": str(tsa.get("fingerprint_sha1") or ""),
    }
    # Исключение пустых значений перед записью метаданных
    return {key: value for key, value in values.items() if value}


# Обработка GET-запроса к главной странице приложения
@app.get("/", response_class=HTMLResponse)
def index():
    # Формирование HTML-страницы с формами создания и обновления подписи
    return f"""
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>{APP_TITLE}</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 860px; margin: 40px auto; line-height: 1.5; }}
    h1 {{ margin-bottom: 16px; }}
    h2 {{ margin-top: 0; }}
    section {{ border: 1px solid #d8d8d8; border-radius: 12px; padding: 20px; margin-top: 20px; }}
    label {{ display: block; margin-top: 12px; font-weight: 600; }}
    input, select, textarea {{ width: 100%; padding: 8px; margin-top: 4px; box-sizing: border-box; }}
    textarea {{ min-height: 96px; resize: vertical; }}
    .row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    button {{ margin-top: 18px; padding: 10px 16px; cursor: pointer; }}
    .note {{ color: #666; font-size: 14px; margin-top: 8px; }}
  </style>
</head>
<body>
  <h1>{APP_TITLE}</h1>

  <section>
    <h2>Создать CAdES-подпись</h2>
    <form action="/sign-and-upload" method="post" enctype="multipart/form-data">
      <label for="file_create">Файл</label>
      <input id="file_create" type="file" name="file" required>

      <div class="row">
        <div>
          <label for="mode_create">Режим подписи</label>
          <select id="mode_create" name="mode">
            <option value="bes">BES</option>
            <option value="t">T</option>
            <option value="xlt">XLT</option>
            <option value="a">A</option>
          </select>
        </div>
        <div>
          <label for="container_label_create">Название контейнера в Mayan</label>
          <input id="container_label_create" type="text" name="container_label" required>
        </div>
      </div>

      <label for="description_create">Описание документа в Mayan</label>
      <textarea id="description_create" name="description"></textarea>

      <label for="signer_cert_path">Путь к сертификату подписанта</label>
      <input id="signer_cert_path" type="text" name="signer_cert_path" required>

      <label for="signer_key_path">Путь к закрытому ключу</label>
      <input id="signer_key_path" type="text" name="signer_key_path" required>

      <label for="chain_path">Путь к цепочке сертификатов</label>
      <input id="chain_path" type="text" name="chain_path" required>

      <button type="submit">Подписать и загрузить</button>
    </form>
  </section>

  <section>
    <h2>Обновить CAdES-A</h2>
    <form action="/sign-and-upload" method="post" enctype="multipart/form-data">
      <input type="hidden" name="mode" value="renew_a">

      <label for="file_renew">Исходный файл</label>
      <input id="file_renew" type="file" name="file" required>

      <label for="signature_file">Текущая CAdES-A подпись</label>
      <input id="signature_file" type="file" name="signature_file" required>

      <label for="signer_cert_path_renew">Путь к сертификату подписанта</label>
      <input id="signer_cert_path_renew" type="text" name="signer_cert_path">

      <label for="container_label_renew">Название контейнера в Mayan</label>
      <input id="container_label_renew" type="text" name="container_label" required>

      <label for="description_renew">Описание документа в Mayan</label>
      <textarea id="description_renew" name="description"></textarea>


      <button type="submit">Обновить CAdES-A и загрузить</button>
    </form>
  </section>
</body>
</html>
"""


# Обработка отправки формы, формирование подписи и загрузка результата в Mayan EDMS
@app.post("/sign-and-upload", response_class=HTMLResponse)
async def sign_and_upload(
    file: UploadFile = File(...),
    signature_file: Optional[UploadFile] = File(None),
    mode: str = Form(MODE_BES),
    container_label: str = Form(...),
    description: str = Form(""),
    signer_cert_path: str = Form(""),
    signer_key_path: str = Form(""),
    chain_path: str = Form(""),
    verbose: bool = Form(False),
):
    # Получение безопасного имени исходного файла
    filename = Path(file.filename).name
    # Чтение содержимого исходного файла из формы
    file_bytes = await file.read()
    try:
        # Получение API-токена Mayan EDMS
        mayan_token = await run_in_threadpool(ask_mayan_token)
        # Создание клиента Mayan EDMS
        mayan = MayanClient(MAYAN_BASE_URL, mayan_token)
        # Получение типа документа Mayan EDMS по заданному названию
        document_type = await run_in_threadpool(
            mayan.get_document_type_by_label,
            DOCUMENT_TYPE_LABEL,
        )
        # Создание временного каталога для исходного файла и подписи
        with tempfile.TemporaryDirectory(prefix="cades_service_local_") as temp_dir_name:
            # Определение пути временного каталога
            temp_dir = Path(temp_dir_name)
            # Определение временного пути к исходному файлу
            input_path = temp_dir / filename
            # Определение временного пути к итоговой подписи
            signature_path = temp_dir / (
                f"{filename}.renewed.sig"
                if mode == MODE_RENEW_A
                else f"{filename}.sig"
            )
            # Сохранение исходного файла во временный каталог
            input_path.write_bytes(file_bytes)
            # Подготовка пути к сертификату подписанта для режима обновления CAdES-A
            signer_cert_path_obj = (
                Path(signer_cert_path).expanduser().resolve()
                if signer_cert_path.strip()
                else None
            )
            # Ветка обновления существующей подписи CAdES-A
            if mode == MODE_RENEW_A:
                # Получение имени текущего файла подписи
                current_signature_filename = Path(signature_file.filename).name
                # Определение временного пути к текущей подписи
                current_signature_path = temp_dir / current_signature_filename
                # Сохранение текущей подписи во временный каталог
                current_signature_path.write_bytes(await signature_file.read())
                # Создание конфигурации для обновления CAdES-A
                config = create_default_renew_a_config(
                    base_dir=BASE_DIR,
                    input_path=input_path,
                    current_signature_path=current_signature_path,
                    output_path=signature_path,
                    openssl_conf_path=OPENSSL_CONF_PATH,
                    tsa_url=DEFAULT_TSA_URL,
                    signer_cert_path=signer_cert_path_obj,
                )
                # Выполнение обновления CAdES-A
                result = await run_in_threadpool(renew_cades_a_signature, config)
            else:
                # Создание конфигурации для формирования новой CAdES-подписи
                config = create_default_sign_config(
                    base_dir=BASE_DIR,
                    mode=mode,
                    input_path=input_path,
                    signer_cert_path=Path(signer_cert_path).expanduser().resolve(),
                    signer_key_path=Path(signer_key_path).expanduser().resolve(),
                    chain_path=Path(chain_path).expanduser().resolve(),
                    openssl_conf_path=OPENSSL_CONF_PATH,
                    output_path=signature_path,
                    tsa_url=DEFAULT_TSA_URL,
                    verbose=verbose,
                )
                # Выполнение формирования CAdES-подписи
                result = await run_in_threadpool(sign_document, config)
            # Создание документа в Mayan EDMS
            document = await run_in_threadpool(
                mayan.create_document,
                int(document_type["id"]),
                container_label,
                description,
            )
            # Получение идентификатора созданного документа
            document_id = int(document["id"])
            # Загрузка исходного файла как основной версии документа
            await run_in_threadpool(mayan.upload_document_file, document_id, input_path, "replace")
            # Загрузка файла подписи как дополнительного файла документа
            await run_in_threadpool(mayan.upload_document_file, document_id, result.signature_path, "append")
            # Запись метаданных электронной подписи в Mayan EDMS
            await run_in_threadpool(mayan.upsert_document_metadata, document_id, build_mayan_metadata(filename, mode, result))
            # Блокировка документа от загрузки новых файлов на заданный срок
            await run_in_threadpool(mayan.checkout_document, document_id, True, 3650)
    except (RuntimeError, ValueError, MayanAPIError) as exc:
        # Преобразование ошибок формирования подписи и Mayan EDMS в HTTP-ошибку
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    # Формирование страницы успешного завершения операции
    return f"""
<!doctype html>
<html lang=\"ru\">
<head>
  <meta charset=\"utf-8\">
  <title>{APP_TITLE}</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 760px; margin: 40px auto; line-height: 1.5; }}
    section {{ border: 1px solid #d8d8d8; border-radius: 12px; padding: 24px; }}
    a {{ display: inline-block; margin-top: 16px; }}
  </style>
</head>
<body>
  <section>
    <h1>Документ успешно подписан и загружен</h1>
    <a href=\"/\">Вернуться назад</a>
  </section>
</body>
</html>
"""