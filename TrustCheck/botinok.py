import asyncio
import logging
import re
import socket
import ssl
import datetime
import aiosqlite
from urllib.parse import urlparse
from waybackpy import WaybackMachineCDXServerAPI
import os
import requests
import whois
import tldextract
from bs4 import BeautifulSoup
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import Message

# --- КОНФИГУРАЦИЯ ---
BOT_TOKEN = os.getenv("BOT_TOKEN")  # Вставь токен от @BotFather
DB_PATH = "trustcheck.db"
ADMIN_IDS = [123456789]  # Впиши свой Telegram ID (узнать у @userinfobot)

# 🎯 ПОРОГИ АВТО-ДОБАВЛЕНИЯ
AUTO_BLACKLIST_SCORE = 10  # Если риск >= 10, автоматически в ЧС
AUTO_WHITELIST_SCORE = 2   # Если риск <= 2, возможно в БС
MIN_DOMAIN_AGE_FOR_WHITELIST = 365  # Мин. возраст домена для БС (дней)

SUSPICIOUS_TLDS = ["xyz", "top", "click", "work", "buzz", "gq", "ml", "cf", "tk"]
SUSPICIOUS_WORDS = ["verify", "account blocked", "wallet", "crypto", "password", "login", "sign in"]

logging.basicConfig(level=logging.INFO)
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# --- БАЗА ДАННЫХ ---

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                reason TEXT,
                added_by TEXT,
                auto_added INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE,
                reason TEXT,
                added_by TEXT,
                auto_added INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS check_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                user_id TEXT,
                risk_score INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        await db.commit()

async def add_to_blacklist(domain: str, reason: str, added_by: str, auto_added: int = 0):
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT INTO blacklist (domain, reason, added_by, auto_added) VALUES (?, ?, ?, ?)",
                (domain, reason, added_by, auto_added)
            )
            await db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

async def add_to_whitelist(domain: str, reason: str, added_by: str, auto_added: int = 0):
    async with aiosqlite.connect(DB_PATH) as db:
        try:
            await db.execute(
                "INSERT INTO whitelist (domain, reason, added_by, auto_added) VALUES (?, ?, ?, ?)",
                (domain, reason, added_by, auto_added)
            )
            await db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

async def remove_from_blacklist(domain: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM blacklist WHERE domain = ?", (domain,))
        await db.commit()

async def remove_from_whitelist(domain: str):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM whitelist WHERE domain = ?", (domain,))
        await db.commit()

async def check_blacklist(domain: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT reason, added_by, created_at, auto_added FROM blacklist WHERE domain = ?", (domain,))
        return await cursor.fetchone()

async def check_whitelist(domain: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT reason, added_by, created_at, auto_added FROM whitelist WHERE domain = ?", (domain,))
        return await cursor.fetchone()

async def get_all_blacklist():
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT domain, reason, added_by, created_at, auto_added FROM blacklist")
        return await cursor.fetchall()

async def get_all_whitelist():
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT domain, reason, added_by, created_at, auto_added FROM whitelist")
        return await cursor.fetchall()

async def save_check_history(domain: str, user_id: str, risk_score: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO check_history (domain, user_id, risk_score) VALUES (?, ?, ?)",
            (domain, user_id, risk_score)
        )
        await db.commit()

async def get_check_count(domain: str):
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM check_history WHERE domain = ?", (domain,))
        result = await cursor.fetchone()
        return result[0] if result else 0

# --- ЛОГИКА АНАЛИЗА ---

def extract_domain(url: str) -> str:
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    return parsed.netloc.lower()

def get_webarchive_info(domain: str):
    try:
        url = f"https://{domain}"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        cdx_api = WaybackMachineCDXServerAPI(url, user_agent)

        oldest = cdx_api.oldest()

        if not oldest:
            return None, None

        first_date = oldest.timestamp

        first_date_parsed = datetime.datetime.strptime(first_date, "%Y%m%d%H%M%S")

        age_days = (datetime.datetime.now() - first_date_parsed).days

        return first_date_parsed, age_days

    except Exception as e:
        print("WebArchive error:", e)
        return None, None

def check_indexing(domain: str):
    google_indexed = False
    yandex_indexed = False

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        google_url = f"https://www.google.com/search?q=site:{domain}"
        r = requests.get(google_url, headers=headers, timeout=5)

        if "did not match any documents" not in r.text.lower():
            google_indexed = True
    except:
        pass

    try:
        yandex_url = f"https://yandex.ru/search/?text=site:{domain}"
        r = requests.get(yandex_url, headers=headers, timeout=5)

        if "ничего не нашлось" not in r.text.lower():
            yandex_indexed = True
    except:
        pass

    return google_indexed, yandex_indexed

def check_indexing(domain: str):
    google_indexed = False
    yandex_indexed = False

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        # Google
        google_url = f"https://www.google.com/search?q=site:{domain}"
        r = requests.get(google_url, headers=headers, timeout=5)

        if "did not match any documents" not in r.text.lower():
            google_indexed = True

    except:
        pass

    try:
        # Yandex
        yandex_url = f"https://yandex.ru/search/?text=site:{domain}"
        r = requests.get(yandex_url, headers=headers, timeout=5)

        if "ничего не нашлось" not in r.text.lower():
            yandex_indexed = True

    except:
        pass

    return google_indexed, yandex_indexed

async def analyze_site_async(url: str):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, analyze_site_sync, url)

def analyze_site_sync(url: str):
    domain = extract_domain(url)
    risk_score = 0
    reasons = []
    domain_age = 0
    ip_address = None
    try:
        ip_address = socket.gethostbyname(domain)
    except:
        ip_address = "Не удалось определить"

    extracted = tldextract.extract(domain)
    tld = extracted.suffix
    root_domain = f"{extracted.domain}.{extracted.suffix}"

    if tld in SUSPICIOUS_TLDS:
        risk_score += 3
        reasons.append(f"⚠️ Подозрительная зона .{tld}")

    if len(domain) > 25:
        risk_score += 1
        reasons.append("📏 Слишком длинный домен")

    if re.search(r"\d", domain):
        risk_score += 1
        reasons.append("🔢 Домен содержит цифры")

    try:
        w = whois.whois(root_domain)
        creation_date = w.creation_date
        wa_first_date, wa_age_days = get_webarchive_info(domain)
        google_indexed, yandex_indexed = check_indexing(domain)

        if not google_indexed and not yandex_indexed:
            risk_score += 3
            reasons.append("🚨 Сайт не индексируется поисковиками (подозрительно)")

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.datetime.strptime(creation_date, "%Y-%m-%d")
                except:
                    creation_date = datetime.datetime.now()

            domain_age = (datetime.datetime.now() - creation_date).days

            if domain_age < 30:
                risk_score += 5
                reasons.append("🆕 Домен создан МЕНЕЕ 30 дней назад (КРИТИЧНО)")
            elif domain_age < 90:
                risk_score += 3
                reasons.append(f"🗓 Домен создан недавно ({domain_age} дн.)")
            else:
                reasons.append(f"✅ Домену {domain_age} дней")
        else:
            reasons.append("❓ Дата создания скрыта")
    except:
        reasons.append("⚠️ WHOIS недоступен")

        wa_first_date, wa_age_days = get_webarchive_info(domain)

        if wa_first_date:
            reasons.append(f"🕰 WebArchive: с {wa_first_date.date()}")
        else:
            reasons.append("🕰 WebArchive: нет данных")

            if wa_age_days and wa_age_days < 30:
                risk_score += 3
                reasons.append("🕰 Сайт недавно появился в WebArchive")

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            reasons.append("🔒 SSL сертификат найден")
    except:
        risk_score += 2
        reasons.append("❌ Нет HTTPS или сертификат невалиден")

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(f"https://{domain}", timeout=5, headers=headers)
        soup = BeautifulSoup(response.text, "html.parser")
        text = soup.get_text().lower()

        found_suspicious = False
        for word in SUSPICIOUS_WORDS:
            if word in text:
                risk_score += 1
                if not found_suspicious:
                    reasons.append(f"🔍 Подозрительный контент: '{word}'")
                    found_suspicious = True

        if soup.find("input", {"type": "password"}):
            risk_score += 2
            reasons.append("🔑 Обнаружено поле ввода пароля")

        if soup.find("iframe"):
            risk_score += 1
            reasons.append("🖼 На странице есть iframe")

    except:
        risk_score += 1
        reasons.append("⚠️ Не удалось загрузить контент сайта")

    level = "🟢 Низкий"
    if risk_score > 3: level = "🟡 Средний"
    if risk_score > 7: level = "🔴 ВЫСОКИЙ"
    if risk_score > 10: level = "☠️ КРИТИЧЕСКИЙ"

    return {
        "google_indexed": google_indexed,
        "yandex_indexed": yandex_indexed,
        "url": url,
        "domain": root_domain,
        "score": risk_score,
        "level": level,
        "reasons": reasons,
        "domain_age": domain_age,
        "ip": ip_address,  # 👈 ВОТ ЭТО ОБЯЗАТЕЛЬНО
        "wa_first_date": wa_first_date,
        "wa_age_days": wa_age_days
    }

# --- АВТО-УПРАВЛЕНИЕ СПИСКАМИ ---

async def auto_manage_lists(result: dict):
    domain = result['domain']
    score = result['score']
    domain_age = result.get('domain_age', 0)
    reasons = result['reasons']

    added_to_list = None

    if score >= AUTO_BLACKLIST_SCORE:
        reason = f"Авто: Risk Score {score} - " + "; ".join(reasons[:2])
        success = await add_to_blacklist(domain, reason, "TrustCheck_Bot", auto_added=1)
        if success:
            added_to_list = "blacklist"

    elif score <= AUTO_WHITELIST_SCORE and domain_age >= MIN_DOMAIN_AGE_FOR_WHITELIST:
        reason = f"Авто: Risk Score {score}, возраст {domain_age} дней"
        success = await add_to_whitelist(domain, reason, "TrustCheck_Bot", auto_added=1)
        if success:
            added_to_list = "whitelist"

    return added_to_list

# --- ПРОВЕРКА АДМИНА ---

def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS

# --- ТЕЛЕГРАМ БОТ ---

@dp.message(Command("start"))
async def cmd_start(message: Message):
    user_id = message.from_user.id
    is_admin_user = is_admin(user_id)

    admin_commands = ""
    if is_admin_user:
        admin_commands = (
            "\n\n🔐 Команды администратора:\n"
            "/blacklist — добавить в ЧС\n"
            "/whitelist — добавить в БС\n"
            "/unblack — удалить из ЧС\n"
            "/unwhite — удалить из БС\n"
            "/stats — статистика"
        )

    await message.answer(
        "👋 Привет! Я TrustCheck Bot.\n\n"
        "Отправь мне ссылку на сайт, и я проверю его на признаки фишинга и мошенничества.\n"
        "Я анализирую возраст домена, SSL, контент и структуру.\n\n"
        "📝 Команды:\n"
        "• Отправь ссылку для проверки\n"
        "/lists — посмотреть чёрный и белый списки\n"
        "/help — помощь"
        f"{admin_commands}",
        parse_mode="HTML"
    )

@dp.message(Command("help"))
async def cmd_help(message: Message):
    user_id = message.from_user.id
    is_admin_user = is_admin(user_id)

    admin_commands = ""
    if is_admin_user:
        admin_commands = (
            "\n\n🔐 Команды администратора:\n"
            "/blacklist domain.com причина — добавить в ЧС\n"
            "/whitelist domain.com причина — добавить в БС\n"
            "/unblack domain.com — удалить из ЧС\n"
            "/unwhite domain.com — удалить из БС\n"
            "/stats — статистика проверок"
        )

    await message.answer(
        "📖 Справка TrustCheck Bot\n\n"
        "🔹 Проверка сайта:\n"
        "Просто отправь ссылку (например: google.com)\n\n"
        "🔹 Просмотр списков:\n"
        "/lists — показать все чёрные и белые списки\n\n"
        "🔹 Авто-списки:\n"
        f"• Risk ≥ {AUTO_BLACKLIST_SCORE} → Чёрный список\n"
        f"• Risk ≤ {AUTO_WHITELIST_SCORE} + возраст ≥ {MIN_DOMAIN_AGE_FOR_WHITELIST} дн. → Белый список"
        f"{admin_commands}",
        parse_mode="HTML"
    )

@dp.message(Command("lists"))
async def cmd_lists(message: Message):
    """Доступно ВСЕМ пользователям - только просмотр"""
    blacklist = await get_all_blacklist()
    whitelist = await get_all_whitelist()

    black_text = ""
    if blacklist:
        for b in blacklist[:20]:
            mark = "🤖" if b[4] == 1 else "👤"
            black_text += f"{mark} <code>{b[0]}</code>\n"
        if len(blacklist) > 20:
            black_text += f"\n... и ещё {len(blacklist) - 20} доменов"
    else:
        black_text = "Пусто"

    white_text = ""
    if whitelist:
        for w in whitelist[:20]:
            mark = "🤖" if w[4] == 1 else "👤"
            white_text += f"{mark} <code>{w[0]}</code>\n"
        if len(whitelist) > 20:
            white_text += f"\n... и ещё {len(whitelist) - 20} доменов"
    else:
        white_text = "Пусто"

    await message.answer(
        f"📋 Списки доменов TrustCheck\n\n"
        f"🚫 Чёрный список ({len(blacklist)}):\n{black_text}\n\n"
        f"✅ Белый список ({len(whitelist)}):\n{white_text}\n\n"
        f"ℹ️ Показаны первые 20 записей в каждом списке",
        parse_mode="HTML"
    )

@dp.message(Command("stats"))
async def cmd_stats(message: Message):
    """Только для админов"""
    if not is_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только администраторам.")
        return

    blacklist = await get_all_blacklist()
    whitelist = await get_all_whitelist()

    auto_black = sum(1 for b in blacklist if b[4] == 1)
    auto_white = sum(1 for w in whitelist if w[4] == 1)

    await message.answer(
        f"📊 Статистика TrustCheck\n\n"
        f"🚫 Чёрный список: {len(blacklist)}\n"
        f"   └─ Авто: {auto_black}\n"
        f"   └─ Вручную: {len(blacklist) - auto_black}\n\n"
        f"✅ Белый список: {len(whitelist)}\n"
        f"   └─ Авто: {auto_white}\n"
        f"   └─ Вручную: {len(whitelist) - auto_white}",
        parse_mode="HTML"
    )

@dp.message()
async def handle_message(message: Message):
    url = message.text.strip()

    if url.startswith("/"):
        return

    if not ("." in url and len(url) > 4):
        await message.answer("🤔 Это не похоже на ссылку. Отправь адрес сайта.")
        return

    domain = extract_domain(url)
    user_id = message.from_user.id
    username = message.from_user.username or f"user_{user_id}"

    status_msg = await message.answer("🔍 Проверяю сайт...")

    try:
        # 1️⃣ Проверка белого списка
        whitelist_entry = await check_whitelist(domain)
        if whitelist_entry:
            auto_mark = "🤖 Авто" if whitelist_entry[3] == 1 else "👤 Вручную"
            await status_msg.edit_text(
                f"✅ САЙТ В БЕЛОМ СПИСКЕ!\n\n"
                f"🌐 <code>{domain}</code>\n\n"
                f"📝 Причина: {whitelist_entry[0]}\n"
                f"👤 Добавил: @{whitelist_entry[1]}\n"
                f"🏷 Тип: {auto_mark}\n"
                f"📅 Дата: {whitelist_entry[2]}\n\n"
                f"🟢 Доверенный сайт.",
                parse_mode="HTML"
            )
            await save_check_history(domain, str(user_id), 0)
            return

        # 2️⃣ Проверка чёрного списка
        blacklist_entry = await check_blacklist(domain)
        if blacklist_entry:
            auto_mark = "🤖 Авто" if blacklist_entry[3] == 1 else "👤 Вручную"
            await status_msg.edit_text(
                f"🚨 САЙТ В ЧЁРНОМ СПИСКЕ!\n\n"
                f"🌐 <code>{domain}</code>\n\n"
                f"❌ Причина: {blacklist_entry[0]}\n"
                f"👤 Добавил: @{blacklist_entry[1]}\n"
                f"🏷 Тип: {auto_mark}\n"
                f"📅 Дата: {blacklist_entry[2]}\n\n"
                f"🔴 НЕ ВВОДИТЕ ЛИЧНЫЕ ДАННЫЕ!",
                parse_mode="HTML"
            )
            await save_check_history(domain, str(user_id), 100)
            return

        # 3️⃣ Полный анализ
        result = await analyze_site_async(url)

        # 4️⃣ Авто-управление списками
        added_to_list = await auto_manage_lists(result)

        # 5️⃣ Сохраняем историю
        await save_check_history(domain, str(user_id), result['score'])

        # 6️⃣ Формируем ответ
        reasons_text = "\n".join([f"• {r}" for r in result['reasons']])

        auto_info = ""
        if added_to_list == "blacklist":
            auto_info = "\n\n🚨 Сайт автоматически добавлен в ЧЁРНЫЙ список!"
        elif added_to_list == "whitelist":
            auto_info = "\n\n✅ Сайт автоматически добавлен в БЕЛЫЙ список!"

        wa_text = ""
        if result.get("wa_first_date"):
            years = result["wa_age_days"] // 365
            wa_text = (
                f"\n🕰 <b>WebArchive:</b>\n"
                f"• Первое упоминание: {result['wa_first_date'].date()}\n"
                f"• Возраст сайта: ~{years} лет"
            )
        else:
            wa_text = "\n🕰 <b>WebArchive:</b> нет данных"

        index_text = (
            f"\n🔎 <b>Индексация:</b>\n"
            f"• Google: {'✅ ︎ присутствует' if result.get('google_indexed') else '❌ ︎ отсутствует'}\n"
            f"• Яндекс: {'✅ ︎ присутствует' if result.get('yandex_indexed') else '︎❌ отсутствует'}"
        )

        response_text = (
            f"🔎 <b>ПРОВЕРКА САЙТА</b>\n"
            f"━━━━━━━━━━━━━━━\n"

            f"🌐 <b>Домен:</b> <code>{result['domain']}</code>\n"
            f"📦 <b>IP:</b> <code>{result['ip']}</code>\n"
            f"{wa_text}\n\n"

            f"📊 <b>Risk Score:</b> {result['score']}/15\n"
            f"🚦 <b>Статус:</b> {result['level']}\n\n"

            f"📝 <b>Детали:</b>\n{reasons_text}\n\n" 
            f"{index_text}\n\n"

            f"📈 Проверок: {await get_check_count(domain)}"
            f"{auto_info}"
        )

        await status_msg.edit_text(response_text, parse_mode="HTML")

        # Уведомление админам об авто-добавлении в ЧС
        if added_to_list == "blacklist":
            for admin_id in ADMIN_IDS:
                try:
                    await bot.send_message(
                        admin_id,
                        f"🚨 Авто-добавление в ЧС\n\n"
                        f"🌐 <code>{domain}</code>\n"
                        f"📉 Score: {result['score']}\n"
                        f"👤 Проверил: @{username}",
                        parse_mode="HTML"
                    )
                except:
                    pass

    except Exception as e:
        logging.error(e)
        await status_msg.edit_text("❌ Ошибка при анализе. Попробуйте позже.")

# --- АДМИН КОМАНДЫ (защищены проверкой) ---

@dp.message(Command("blacklist"))
async def cmd_blacklist(message: Message):
    if not is_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только администраторам.")
        return

    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        await message.answer("❌ Использование: /blacklist domain.com причина")
        return

    domain = args[1].lower()
    reason = args[2]
    username = message.from_user.username or f"user_{message.from_user.id}"

    success = await add_to_blacklist(domain, reason, username, auto_added=0)
    if success:
        await message.answer(f"✅ <code>{domain}</code> добавлен в ЧС.\n📝 Причина: {reason}", parse_mode="HTML")
    else:
        await message.answer(f"⚠️ <code>{domain}</code> уже в ЧС.", parse_mode="HTML")

@dp.message(Command("whitelist"))
async def cmd_whitelist(message: Message):
    if not is_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только администраторам.")
        return

    args = message.text.split(maxsplit=2)
    if len(args) < 3:
        await message.answer("❌ Использование: /whitelist domain.com причина")
        return

    domain = args[1].lower()
    reason = args[2]
    username = message.from_user.username or f"user_{message.from_user.id}"

    success = await add_to_whitelist(domain, reason, username, auto_added=0)
    if success:
        await message.answer(f"✅ <code>{domain}</code> добавлен в БС.\n📝 Причина: {reason}", parse_mode="HTML")
    else:
        await message.answer(f"⚠️ <code>{domain}</code> уже в БС.", parse_mode="HTML")

@dp.message(Command("unblack"))
async def cmd_unblack(message: Message):
    if not is_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только администраторам.")
        return

    args = message.text.split()
    if len(args) < 2:
        await message.answer("❌ Использование: /unblack domain.com")
        return

    domain = args[1].lower()
    await remove_from_blacklist(domain)
    await message.answer(f"✅ <code>{domain}</code> удалён из ЧС.", parse_mode="HTML")

@dp.message(Command("unwhite"))
async def cmd_unwhite(message: Message):
    if not is_admin(message.from_user.id):
        await message.answer("❌ Эта команда доступна только администраторам.")
        return

    args = message.text.split()
    if len(args) < 2:
        await message.answer("❌ Использование: /unwhite domain.com")
        return

    domain = args[1].lower()
    await remove_from_whitelist(domain)
    await message.answer(f"✅ <code>{domain}</code> удалён из БС.", parse_mode="HTML")

# --- ЗАПУСК ---

async def main():
    await init_db()
    logging.info("✅ База данных инициализирована.")
    logging.info(f"🎯 Авто-ЧС: риск >= {AUTO_BLACKLIST_SCORE}")
    logging.info(f"🎯 Авто-БС: риск <= {AUTO_WHITELIST_SCORE}, возраст >= {MIN_DOMAIN_AGE_FOR_WHITELIST} дн.")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())