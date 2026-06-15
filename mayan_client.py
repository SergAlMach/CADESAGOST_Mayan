import re
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests


# Ошибка при выполнении запроса к Mayan API
class MayanAPIError(RuntimeError):
    # Создание исключения с сообщением, HTTP-статусом и текстом ответа
    def __init__(self, message, status_code=None, response_text=""):
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


# Клиент для взаимодействия с Mayan EDMS через REST API
class MayanClient:
    # Создание клиента Mayan EDMS и настройка HTTP-сессии
    def __init__(self, base_url, token, timeout=60, current_user_endpoint="/api/v4/users/current/"):
        # Сохранение базового адреса Mayan EDMS без завершающего символа /
        self.base_url = base_url.rstrip("/")
        # Сохранение времени ожидания HTTP-запросов
        self.timeout = timeout
        # Сохранение endpoint для получения текущего пользователя
        self.current_user_endpoint = current_user_endpoint
        # Создание постоянной HTTP-сессии
        self.session = requests.Session()
        # Установка заголовков авторизации и формата ответа
        self.session.headers.update({
            "Authorization": f"Token {token}",
            "Accept": "application/json",
        })

    # Формирование полного URL для запроса к Mayan API
    def build_url(self, path):
        # Возврат готового URL либо добавление пути к базовому адресу Mayan EDMS
        return path if path.startswith("http") else f"{self.base_url}{path}"

    # Разбор JSON-ответа Mayan API
    def parse_response(self, response):
        # Возврат пустого значения при отсутствии тела ответа
        if not response.content:
            return None
        # Возврат JSON-данных из тела ответа
        return response.json()

    # Формирование исключения при ошибке Mayan API
    def raise_error(self, response):
        # Получение текста ответа Mayan API
        body = response.text.strip()
        # Генерация исключения с HTTP-статусом, методом запроса, URL и текстом ответа
        raise MayanAPIError(
            f"Ошибка Mayan API: HTTP {response.status_code} для {response.request.method} {response.request.url}. Ответ: {body or '<empty>'}",
            status_code=response.status_code,
            response_text=body,
        )

    # Выполнение HTTP-запроса к Mayan API
    def send_api_request(self, method, path, expected=(200,), retry_429=False, **kwargs):
        # Формирование полного URL запроса
        url = self.build_url(path)
        # Определение количества попыток при ограничении частоты запросов
        attempts = 4 if retry_429 else 1
        # Выполнение запроса с учетом возможных повторных попыток
        for attempt in range(attempts):
            # Отправка HTTP-запроса через сохраненную сессию
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
            # Возврат разобранного ответа при ожидаемом HTTP-статусе
            if response.status_code in expected:
                return self.parse_response(response)
            # Повтор запроса при получении HTTP 429
            if response.status_code == 429 and attempt < attempts - 1:
                time.sleep(1.2)
                continue
            # Формирование ошибки при неуспешном ответе
            self.raise_error(response)
        # Формирование ошибки при исчерпании всех попыток
        raise MayanAPIError(f"Не удалось выполнить запрос {method} {url}")

    # Получение всех элементов из постраничного ответа Mayan API
    def get_all_pages(self, path):
        # Формирование URL первой страницы
        url = self.build_url(path)
        # Создание списка для накопления результатов
        items = []
        # Последовательное получение всех страниц ответа
        while url:
            # Получение текущей страницы
            data = self.send_api_request("GET", url)
            # Добавление элементов текущей страницы в общий список
            items.extend(data["results"])
            # Переход к следующей странице при ее наличии
            url = data.get("next")
        # Возврат полного списка элементов
        return items

    # Получение типа документа Mayan EDMS по названию
    def get_document_type_by_label(self, label):
        # Нормализация искомого названия типа документа
        wanted = label.strip().lower()
        # Поиск типа документа среди всех типов Mayan EDMS
        for item in self.get_all_pages("/api/v4/document_types/"):
            # Возврат найденного типа документа
            if item["label"].strip().lower() == wanted:
                return item
        # Формирование ошибки при отсутствии типа документа
        raise MayanAPIError(f"В Mayan не найден Document type {label!r}")

    # Получение данных текущего пользователя Mayan EDMS
    def get_current_user(self):
        # Выполнение GET-запроса к endpoint текущего пользователя
        return self.send_api_request("GET", self.current_user_endpoint)

    # Создание документа в Mayan EDMS
    def create_document(self, document_type_id, label, description=""):
        # Выполнение POST-запроса на создание карточки документа
        return self.send_api_request(
            "POST",
            "/api/v4/documents/",
            expected=(201,),
            data={
                "document_type_id": str(document_type_id),
                "label": label,
                "description": description,
            },
        )

    # Загрузка файла документа в Mayan EDMS
    def upload_document_file(self, document_id, file_path, action_name="replace"):
        # Приведение пути к файлу к абсолютному виду
        file_path = Path(file_path).expanduser().resolve()
        # Открытие файла для передачи в Mayan EDMS
        with file_path.open("rb") as file_handler:
            # Выполнение POST-запроса на загрузку файла документа
            self.send_api_request(
                "POST",
                f"/api/v4/documents/{document_id}/files/",
                expected=(202,),
                data={"action_name": action_name},
                files={"file_new": (file_path.name, file_handler, "application/octet-stream")},
            )

    # Получение списка типов метаданных Mayan EDMS
    def list_metadata_types(self):
        # Получение всех типов метаданных с учетом постраничной выдачи
        return self.get_all_pages("/api/v4/metadata_types/")

    # Получение метаданных конкретного документа
    def list_document_metadata(self, document_id):
        # Получение всех метаданных документа с учетом постраничной выдачи
        return self.get_all_pages(f"/api/v4/documents/{document_id}/metadata/")

    # Создание или обновление метаданных документа
    def upsert_document_metadata(self, document_id, values):
        # Формирование словаря доступных типов метаданных по их именам
        type_map = {item["name"]: item for item in self.list_metadata_types()}
        # Формирование словаря уже существующих метаданных документа по именам типов
        existing_map = {
            item["metadata_type"]["name"]: item
            for item in self.list_document_metadata(document_id)
        }
        # Последовательная обработка переданных значений метаданных
        for name, value in values.items():
            # Пропуск пустых значений и отсутствующих типов метаданных
            if value in (None, "") or name not in type_map:
                continue
            # Получение уже существующего значения метаданных
            existing = existing_map.get(name)
            # Обновление существующего значения метаданных
            if existing:
                # Получение текущего значения метаданных
                current_value = str(existing.get("value") or "")
                # Пропуск обновления при совпадении значения
                if current_value == value:
                    continue
                # Выполнение PATCH-запроса для обновления метаданных
                self.send_api_request(
                    "PATCH",
                    f"/api/v4/documents/{document_id}/metadata/{int(existing['id'])}/",
                    expected=(200,),
                    retry_429=True,
                    data={"value": value},
                )
            else:
                # Выполнение POST-запроса для создания нового значения метаданных
                self.send_api_request(
                    "POST",
                    f"/api/v4/documents/{document_id}/metadata/",
                    expected=(201,),
                    retry_429=True,
                    data={"metadata_type_id": int(type_map[name]["id"]), "value": value},
                )
                # Небольшая задержка между запросами создания метаданных
                time.sleep(0.15)

    # Получение сведений о блокировке документа
    def get_document_checkout(self, document_id):
        # Выполнение запроса к endpoint блокировки документа
        response = self.session.get(self.build_url(f"/api/v4/documents/{document_id}/checkout/"), timeout=self.timeout)
        # Возврат пустого значения при отсутствии блокировки
        if response.status_code == 404:
            return None
        # Формирование ошибки при неуспешном ответе
        if response.status_code != 200:
            self.raise_error(response)
        # Возврат разобранного ответа с данными блокировки
        return self.parse_response(response)

    # Создание блокировки документа в Mayan EDMS
    def checkout_document(self, document_id, block_new_file=True, expiration_days=3650):
        # Определение даты окончания блокировки документа
        expiration_datetime = datetime.now(UTC) + timedelta(days=expiration_days)
        # Формирование данных для создания блокировки
        payload = {
            "document_pk": str(document_id),
            "block_new_file": block_new_file,
            "expiration_datetime": expiration_datetime.isoformat().replace("+00:00", "Z"),
        }
        # Выполнение POST-запроса на создание блокировки документа
        self.send_api_request(
            "POST",
            "/api/v4/checkouts/",
            expected=(201,),
            retry_429=True,
            data=payload,
        )
