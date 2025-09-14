import discord
from discord.ext import commands, tasks
import os
from dotenv import load_dotenv
import aiohttp
import asyncio
import requests
import whois
import dns.resolver
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import hashlib
import base64
import random
import string
import socket
import validators
from PIL import Image, ImageDraw
import io
import exiftool
import aiofiles
import sqlite3
from scapy.all import traceroute as scapy_traceroute
import subprocess
import json
import feedparser
from datetime import datetime, timedelta
from googletrans import Translator, LANGUAGES
import logging

# Configura logging
logging.basicConfig(filename='bot.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# Carica variabili d'ambiente
load_dotenv()
TOKEN = ('tua_chiave')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', 'tua_chiave')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'tua_chiave')
HIBP_API_KEY = os.getenv('HIBP_API_KEY', 'tua_chiave')
OTX_API_KEY = os.getenv('OTX_API_KEY', 'tua_chiave')
IPINFO_API_TOKEN = 'tua_chiave' 

# Configura database SQLite
conn = sqlite3.connect('bot.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS monitors (url TEXT, hash TEXT, user_id INTEGER, frequency INTEGER)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS stats (command TEXT, count INTEGER)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS prefixes (guild_id INTEGER PRIMARY KEY, prefix TEXT)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS log_channels (guild_id INTEGER PRIMARY KEY, channel_id INTEGER)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS geoip_cache (ip TEXT PRIMARY KEY, data TEXT)''')
conn.commit()

# Bot personalizzato
class CustomBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.translator = Translator()
        self.languages = {}  # Lingua per utente
        self.encryption_keys = {}  # Temporaneo per encrypt/decrypt
        self.antiraid_enabled = {}
        self.join_times = {}
        self.prefixes = {}

    async def get_prefix(self, message):
        guild_id = message.guild.id if message.guild else 0
        return self.prefixes.get(guild_id, '$')

    async def send_translated(self, ctx, message):
        lang = self.languages.get(ctx.author.id, 'it')
        if lang != 'it':
            try:
                if isinstance(message, discord.Embed):
                    translated = discord.Embed(
                        title=self.translator.translate(message.title, dest=lang).text,
                        description=self.translator.translate(message.description, dest=lang).text,
                        color=message.color,
                        timestamp=message.timestamp
                    )
                    for field in message.fields:
                        translated.add_field(
                            name=self.translator.translate(field.name, dest=lang).text,
                            value=self.translator.translate(field.value, dest=lang).text,
                            inline=field.inline
                        )
                    if message.footer.text:
                        translated.set_footer(text=self.translator.translate(message.footer.text, dest=lang).text)
                    if message.author:
                        translated.set_author(name=self.translator.translate(message.author.name, dest=lang).text, icon_url=message.author.icon_url)
                    if message.thumbnail:
                        translated.set_thumbnail(url=message.thumbnail.url)
                    await ctx.send(embed=translated)
                else:
                    translated = self.translator.translate(message, dest=lang).text
                    await ctx.send(translated)
            except Exception as e:
                logging.error(f"Errore traduzione: {e}")
                await ctx.send(embed=message if isinstance(message, discord.Embed) else message)
        else:
            await ctx.send(embed=message if isinstance(message, discord.Embed) else message)

# Definisci il bot
bot = CustomBot(command_prefix=lambda bot, msg: bot.get_prefix(msg), intents=discord.Intents.all())

# Rimuovi il comando $help predefinito
bot.remove_command('help')

# Carica prefissi
cursor.execute('SELECT * FROM prefixes')
for row in cursor.fetchall():
    bot.prefixes[row[0]] = row[1]

# Evento: Bot pronto
@bot.event
async def on_ready():
    logging.info(f'Connesso come {bot.user.name}')
    await bot.change_presence(activity=discord.Game(name="Crypt0n v2.1 | $help"))
    monitor_changes.start()

# Evento: Antiraid
@bot.event
async def on_member_join(member):
    guild_id = member.guild.id
    if bot.antiraid_enabled.get(guild_id, False):
        now = datetime.now()
        if guild_id not in bot.join_times:
            bot.join_times[guild_id] = []
        bot.join_times[guild_id] = [t for t in bot.join_times[guild_id] if now - t < timedelta(minutes=1)]
        bot.join_times[guild_id].append(now)
        if len(bot.join_times[guild_id]) > 10:
            await member.ban(reason="Raid detectato")
            cursor.execute('SELECT channel_id FROM log_channels WHERE guild_id = ?', (guild_id,))
            row = cursor.fetchone()
            if row:
                channel = bot.get_channel(row[0])
                await bot.send_translated(channel, f"Raid detectato: {member} bannato automaticamente.")
            logging.warning(f"Raid detectato in {guild_id}: {member}")

# Task monitoraggio
@tasks.loop(minutes=1)
async def monitor_changes():
    cursor.execute('SELECT * FROM monitors')
    for row in cursor.fetchall():
        url, old_hash, user_id, freq = row
        if (datetime.now() - datetime.now()) % timedelta(minutes=freq) == timedelta(0):  # Semplificato
            try:
                response = requests.get(url)
                new_hash = hashlib.md5(response.content).hexdigest()
                if new_hash != old_hash:
                    user = await bot.fetch_user(user_id)
                    await bot.send_translated(user, f"Cambiamento rilevato su {url}!")
                    cursor.execute('UPDATE monitors SET hash = ? WHERE url = ?', (new_hash, url))
                    conn.commit()
            except Exception as e:
                logging.error(f"Errore monitoraggio {url}: {e}")

# Update stats
def update_stats(command):
    cursor.execute('SELECT count FROM stats WHERE command = ?', (command,))
    row = cursor.fetchone()
    if row:
        cursor.execute('UPDATE stats SET count = ? WHERE command = ?', (row[0] + 1, command))
    else:
        cursor.execute('INSERT INTO stats VALUES (?, 1)', (command,))
    conn.commit()

# Cog Analisi Avanzata
class AnalisiAvanzata(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def traceroute(self, ctx, target: str = None):
        update_stats('traceroute')
        if target is None:
            await self.bot.send_translated(ctx, "Errore: specifica un target. Esempio: `$traceroute google.com`")
            return
        try:
            ans, unans = scapy_traceroute(target)
            result = "\n".join([f"Hop {hop}: {addr}" for hop, addr in ans.res])
            embed = discord.Embed(
                title=f"🔎 Traceroute per {target}",
                description=f"```{result[:1000]}```",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            try:
                result = subprocess.getoutput(f'traceroute {target}')
                embed = discord.Embed(
                    title=f"🔎 Traceroute (Fallback) per {target}",
                    description=f"```{result[:1000]}```",
                    color=discord.Color.from_rgb(0, 51, 102),
                    timestamp=datetime.now()
                )
                embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
                await self.bot.send_translated(ctx, embed)
            except:
                await self.bot.send_translated(ctx, f"Errore: {str(e)}. Assicurati di avere Npcap/libpcap installato.")

    @commands.command()
    async def sslcheck(self, ctx, domain: str):
        update_stats('sslcheck')
        try:
            import ssl
            cert = ssl.get_server_certificate((domain, 443))
            embed = discord.Embed(
                title=f"🔒 Certificato SSL per {domain}",
                description=f"```{cert[:500]}...```",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def subdomains(self, ctx, domain: str):
        update_stats('subdomains')
        common_subs = ['www', 'mail', 'ftp', 'api', 'test', 'dev', 'blog']
        results = []
        for sub in common_subs:
            try:
                dns.resolver.resolve(f"{sub}.{domain}", 'A')
                results.append(f"{sub}.{domain}")
            except:
                pass
        embed = discord.Embed(
            title=f"🌐 Subdomini per {domain}",
            description=f"Subdomini trovati: {', '.join(results) or 'Nessuno'}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def geoip(self, ctx, ip: str):
        update_stats('geoip')
        cursor.execute('SELECT data FROM geoip_cache WHERE ip = ?', (ip,))
        cached = cursor.fetchone()
        if cached:
            data = json.loads(cached[0])
            embed = discord.Embed(
                title=f"📍 GeoIP per {ip}",
                description=f"Città: {data.get('city', 'N/A')}\nPaese: {data.get('country', 'N/A')}\nISP: {data.get('org', 'N/A')}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
            return
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_API_TOKEN}")
            data = response.json()
            if 'error' not in data:
                cursor.execute('INSERT INTO geoip_cache (ip, data) VALUES (?, ?)', (ip, json.dumps(data)))
                conn.commit()
                embed = discord.Embed(
                    title=f"📍 GeoIP per {ip}",
                    description=f"Città: {data.get('city', 'N/A')}\nPaese: {data.get('country', 'N/A')}\nISP: {data.get('org', 'N/A')}",
                    color=discord.Color.from_rgb(0, 51, 102),
                    timestamp=datetime.now()
                )
                embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
                await self.bot.send_translated(ctx, embed)
            else:
                await self.bot.send_translated(ctx, f"Errore: {data['error']['message']}")
        except Exception as e:
            if response.status_code == 429:
                await self.bot.send_translated(ctx, "Limite di richieste superato. Riprova tra un minuto.")
            else:
                await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def webtech(self, ctx, url: str):
        update_stats('webtech')
        try:
            response = requests.get(url)
            headers = response.headers
            techs = []
            if 'server' in headers: techs.append(headers['server'])
            if 'x-powered-by' in headers: techs.append(headers['x-powered-by'])
            embed = discord.Embed(
                title=f"🛠️ Tecnologie per {url}",
                description=f"Tecnologie rilevate: {', '.join(techs) or 'Nessuna'}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def robotstxt(self, ctx, domain: str):
        update_stats('robotstxt')
        try:
            response = requests.get(f"https://{domain}/robots.txt")
            embed = discord.Embed(
                title=f"📜 robots.txt per {domain}",
                description=f"```{response.text[:1000]}...```",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

# Cog Analisi Forense
class AnalisiForense(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def filehash(self, ctx):
        update_stats('filehash')
        if not ctx.message.attachments:
            return await self.bot.send_translated(ctx, "Allega un file!")
        attachment = ctx.message.attachments[0]
        async with aiohttp.ClientSession() as session:
            async with session.get(attachment.url) as resp:
                content = await resp.read()
        hashes = {
            'md5': hashlib.md5(content).hexdigest(),
            'sha1': hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest()
        }
        embed = discord.Embed(
            title="🔍 Hash del File",
            description=f"```{json.dumps(hashes, indent=2)}```",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def integrity(self, ctx, expected_hash: str):
        update_stats('integrity')
        if not ctx.message.attachments:
            return await self.bot.send_translated(ctx, "Allega un file!")
        attachment = ctx.message.attachments[0]
        async with aiohttp.ClientSession() as session:
            async with session.get(attachment.url) as resp:
                content = await resp.read()
        actual_hash = hashlib.sha256(content).hexdigest()
        embed = discord.Embed(
            title="🔎 Verifica Integrità",
            description="Integrità verificata!" if actual_hash == expected_hash else f"Integrità fallita!\nHash atteso: {expected_hash}\nHash reale: {actual_hash}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def multihash(self, ctx, *, text: str):
        update_stats('multihash')
        hashes = {
            'md5': hashlib.md5(text.encode()).hexdigest(),
            'sha1': hashlib.sha1(text.encode()).hexdigest(),
            'sha256': hashlib.sha256(text.encode()).hexdigest()
        }
        embed = discord.Embed(
            title=f"🔍 Hash Multipli per '{text}'",
            description=f"```{json.dumps(hashes, indent=2)}```",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def rsagen(self, ctx, size: int = 2048):
        update_stats('rsagen')
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
        public_key = private_key.public_key()
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        embed = discord.Embed(
            title=f"🔐 Chiavi RSA ({size} bit)",
            description=f"**Pubblica:**\n```{pub_pem}```\n**Privata:**\n```{priv_pem}```",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

# Cog Intelligenza Minacce
class IntelligenzaMinacce(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def threatip(self, ctx, ip: str):
        update_stats('threatip')
        if not ABUSEIPDB_API_KEY:
            return await self.bot.send_translated(ctx, "Configura ABUSEIPDB_API_KEY!")
        headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        response = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params)
        data = response.json()
        score = data['data']['abuseConfidenceScore']
        embed = discord.Embed(
            title=f"⚠️ Analisi Minaccia per {ip}",
            description=f"Abuse Confidence: {score}%",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)
        if score > 80:
            await ctx.author.send(f"⚠️ Allerta: {ip} ha un alto punteggio di rischio ({score}%)!")

    @commands.command()
    async def blacklist(self, ctx, target: str):
        update_stats('blacklist')
        embed = discord.Embed(
            title=f"📋 Verifica Liste Nere per {target}",
            description="Placeholder - Integra API come Spamhaus",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def threatfeed(self, ctx):
        update_stats('threatfeed')
        if not OTX_API_KEY:
            return await self.bot.send_translated(ctx, "Configura OTX_API_KEY!")
        url = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit=5"
        headers = {'X-OTX-API-KEY': OTX_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            data = response.json()
            feeds = "\n".join([p['name'] for p in data['results']])
            embed = discord.Embed(
                title="🔔 Ultimi Threat Feed",
                description=feeds,
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

# Cog OSINT Avanzato
class OSINTAvanzato(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def socialsearch(self, ctx, username: str):
        update_stats('socialsearch')
        sites = ['twitter', 'instagram', 'facebook', 'github', 'linkedin']
        results = []
        for site in sites:
            url = f"https://www.{site}.com/{username}"
            try:
                response = requests.get(url)
                if response.status_code == 200:
                    results.append(url)
            except:
                pass
        embed = discord.Embed(
            title=f"🌐 Ricerca OSINT per {username}",
            description=f"Risultati: {', '.join(results) or 'Nessuno'}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

# Cog Monitoraggio
class Monitoraggio(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def monitor(self, ctx, url: str, freq: int = 5):
        update_stats('monitor')
        try:
            response = requests.get(url)
            page_hash = hashlib.md5(response.content).hexdigest()
            cursor.execute('INSERT INTO monitors VALUES (?, ?, ?, ?)', (url, page_hash, ctx.author.id, freq))
            conn.commit()
            embed = discord.Embed(
                title="📊 Monitoraggio Avviato",
                description=f"Monitoraggio avviato per {url} ogni {freq} minuti.",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def stopmonitor(self, ctx, url: str):
        update_stats('stopmonitor')
        cursor.execute('DELETE FROM monitors WHERE url = ? AND user_id = ?', (url, ctx.author.id))
        conn.commit()
        embed = discord.Embed(
            title="🛑 Monitoraggio Fermato",
            description=f"Monitoraggio fermato per {url}.",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def monitors(self, ctx):
        update_stats('monitors')
        cursor.execute('SELECT url, frequency FROM monitors WHERE user_id = ?', (ctx.author.id,))
        urls = [f"{row[0]} (ogni {row[1]} min)" for row in cursor.fetchall()]
        embed = discord.Embed(
            title="📊 I Tuoi Monitor",
            description=f"Monitor attivi: {', '.join(urls) or 'Nessuno'}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def stats(self, ctx):
        update_stats('stats')
        cursor.execute('SELECT * FROM stats')
        stats = "\n".join([f"{cmd}: {count}" for cmd, count in cursor.fetchall()])
        embed = discord.Embed(
            title="📈 Statistiche Bot",
            description=f"```{stats or 'Nessuna statistica disponibile'}```",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def report(self, ctx):
        update_stats('report')
        embed = discord.Embed(
            title="📊 Report Personale",
            description="Placeholder - Aggiungi log utente",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

# Cog Comandi Base
class ComandiBase(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def ipinfo(self, ctx, ip: str):
        update_stats('ipinfo')
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_API_TOKEN}")
            data = response.json()
            if 'error' not in data:
                embed = discord.Embed(
                    title=f"📍 Informazioni IP {ip}",
                    description=f"Città: {data.get('city', 'N/A')}\nPaese: {data.get('country', 'N/A')}\nISP: {data.get('org', 'N/A')}",
                    color=discord.Color.from_rgb(0, 51, 102),
                    timestamp=datetime.now()
                )
                embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
                await self.bot.send_translated(ctx, embed)
            else:
                await self.bot.send_translated(ctx, f"Errore: {data['error']['message']}")
        except Exception as e:
            if response.status_code == 429:
                await self.bot.send_translated(ctx, "Limite di richieste superato. Riprova tra un minuto.")
            else:
                await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def dnslookup(self, ctx, domain: str):
        update_stats('dnslookup')
        try:
            ips = [str(ip) for ip in dns.resolver.resolve(domain, 'A')]
            embed = discord.Embed(
                title=f"🔍 DNS Lookup per {domain}",
                description=f"Indirizzi IP: {', '.join(ips)}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def whois(self, ctx, domain: str):
        update_stats('whois')
        try:
            w = whois.whois(domain)
            embed = discord.Embed(
                title=f"📜 WHOIS per {domain}",
                description=f"Registrante: {w.name}\nEmail: {w.email}\nData Creazione: {w.creation_date}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def hash(self, ctx, algorithm: str, *, text: str):
        update_stats('hash')
        try:
            h = hashlib.new(algorithm)
            h.update(text.encode())
            embed = discord.Embed(
                title=f"🔍 Hash {algorithm.upper()}",
                description=f"Hash: {h.hexdigest()}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}. Algoritmi: md5, sha1, sha256, etc.")

    @commands.command()
    async def encode64(self, ctx, *, text: str):
        update_stats('encode64')
        encoded = base64.b64encode(text.encode()).decode()
        embed = discord.Embed(
            title="🔐 Base64 Encode",
            description=f"Testo codificato: {encoded}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def decode64(self, ctx, *, encoded: str):
        update_stats('decode64')
        try:
            decoded = base64.b64decode(encoded).decode()
            embed = discord.Embed(
                title="🔓 Base64 Decode",
                description=f"Testo decodificato: {decoded}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def genpassword(self, ctx, length: int = 12):
        update_stats('genpassword')
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for _ in range(length))
        embed = discord.Embed(
            title="🔑 Password Generata",
            description=f"Password: {password}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def headers(self, ctx, url: str):
        update_stats('headers')
        try:
            response = requests.get(url)
            headers = json.dumps(dict(response.headers), indent=2)
            embed = discord.Embed(
                title=f"🌐 Header per {url}",
                description=f"```{headers[:1000]}```",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def checkemail(self, ctx, email: str):
        update_stats('checkemail')
        result = "valida" if validators.email(email) else "non valida"
        embed = discord.Embed(
            title="📧 Verifica Email",
            description=f"L'email {email} è {result}.",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def portscan(self, ctx, ip: str, start: int = 1, end: int = 1024):
        update_stats('portscan')
        open_ports = []
        for port in range(start, min(end + 1, 1024)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            sock.close()
        embed = discord.Embed(
            title=f"🔎 Port Scan per {ip}",
            description=f"Porte aperte: {', '.join(map(str, open_ports)) or 'Nessuna'}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def analyzeurl(self, ctx, url: str):
        update_stats('analyzeurl')
        if not VIRUSTOTAL_API_KEY:
            return await self.bot.send_translated(ctx, "Configura VIRUSTOTAL_API_KEY!")
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': url}
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        data = response.json()
        embed = discord.Embed(
            title=f"🔎 Analisi URL {url}",
            description=f"Positivi: {data['positives']}/{data['total']}" if data['response_code'] == 1 else "Nessuna analisi disponibile.",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def passwordstrength(self, ctx, password: str):
        update_stats('passwordstrength')
        strength = 0
        if len(password) >= 8: strength += 1
        if any(c.islower() for c in password): strength += 1
        if any(c.isupper() for c in password): strength += 1
        if any(c.isdigit() for c in password): strength += 1
        if any(c in string.punctuation for c in password): strength += 1
        levels = ['Molto Debole', 'Debole', 'Media', 'Forte', 'Molto Forte']
        embed = discord.Embed(
            title="🔐 Forza Password",
            description=f"Forza: {levels[strength - 1]} ({strength}/5)",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def cybernews(self, ctx):
        update_stats('cybernews')
        feed = feedparser.parse('https://krebsonsecurity.com/feed/')
        news = "\n".join([entry.title for entry in feed.entries[:5]])
        embed = discord.Embed(
            title="📰 Notizie Cybersecurity",
            description=news,
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def checkleak(self, ctx, query: str):
        update_stats('checkleak')
        if not HIBP_API_KEY:
            return await self.bot.send_translated(ctx, "HIBP API non configurata. Usa $checkleak_manual per alternative.")
        headers = {'hibp-api-key': HIBP_API_KEY, 'user-agent': 'Crypt0n-Bot'}
        response = requests.get(f'https://haveibeenpwned.com/api/v3/breachedaccount/{query}', headers=headers)
        if response.status_code == 200:
            breaches = ", ".join([b['Name'] for b in response.json()])
            embed = discord.Embed(
                title=f"🔍 Verifica Violazioni per {query}",
                description=f"Filtrazioni: {breaches}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        else:
            await self.bot.send_translated(ctx, "Nessuna filtrazione trovata o errore.")

    @commands.command()
    async def checkleak_manual(self, ctx):
        update_stats('checkleak_manual')
        embed = discord.Embed(
            title="🔍 Verifica Violazioni Manuale",
            description="Verifica violazioni su https://haveibeenpwned.com",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def metadata(self, ctx):
        update_stats('metadata')
        if not ctx.message.attachments:
            return await self.bot.send_translated(ctx, "Allega un file!")
        attachment = ctx.message.attachments[0]
        if attachment.filename.endswith(('.jpg', '.png', '.tiff')):
            async with aiofiles.open('temp_file', 'wb') as f:
                await attachment.save(f.name)
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata('temp_file')
            os.remove('temp_file')
            embed = discord.Embed(
                title="📷 Metadati Immagine",
                description=f"```{json.dumps(metadata, indent=2)[:1000]}...```",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        else:
            await self.bot.send_translated(ctx, "Supportato solo immagini.")

    @commands.command()
    async def encrypt(self, ctx, *, message: str):
        update_stats('encrypt')
        key = Fernet.generate_key()
        f = Fernet(key)
        encrypted = f.encrypt(message.encode())
        self.bot.encryption_keys[ctx.author.id] = key
        embed = discord.Embed(
            title="🔐 Messaggio Cifrato",
            description=f"Messaggio: {encrypted.decode()}\nChiave (salvala!): {key.decode()}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def decrypt(self, ctx, *, encrypted: str):
        update_stats('decrypt')
        key = self.bot.encryption_keys.get(ctx.author.id)
        if not key:
            return await self.bot.send_translated(ctx, "Nessuna chiave trovata. Usa $encrypt o fornisci chiave.")
        f = Fernet(key)
        try:
            decrypted = f.decrypt(encrypted.encode()).decode()
            embed = discord.Embed(
                title="🔓 Messaggio Decifrato",
                description=f"Messaggio: {decrypted}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    async def scanfile(self, ctx):
        update_stats('scanfile')
        if not ctx.message.attachments:
            return await self.bot.send_translated(ctx, "Allega un file!")
        if not VIRUSTOTAL_API_KEY:
            return await self.bot.send_translated(ctx, "Configura VIRUSTOTAL_API_KEY!")
        attachment = ctx.message.attachments[0]
        params = {'apikey': VIRUSTOTAL_API_KEY}
        files = {'file': (attachment.filename, await attachment.read())}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        data = response.json()
        embed = discord.Embed(
            title="🔍 Scansione File",
            description=f"Scan avviato: Resource {data['scan_id']}. Controlla dopo con API report.",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

# Cog Moderazione
class Moderazione(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    @commands.has_permissions(ban_members=True)
    async def ban(self, ctx, member: discord.Member, *, reason: str = "Nessun motivo"):
        update_stats('ban')
        await member.ban(reason=reason)
        embed = discord.Embed(
            title="🛡️ Ban Eseguito",
            description=f"{member} bannato per: {reason}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    @commands.has_permissions(kick_members=True)
    async def kick(self, ctx, member: discord.Member, *, reason: str = "Nessun motivo"):
        update_stats('kick')
        await member.kick(reason=reason)
        embed = discord.Embed(
            title="🛡️ Kick Eseguito",
            description=f"{member} espulso per: {reason}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    @commands.has_permissions(administrator=True)
    async def antiraid(self, ctx, state: str = None):
        update_stats('antiraid')
        if state is None:
            await self.bot.send_translated(ctx, "Errore: specifica 'on' o 'off'. Esempio: `$antiraid on`")
            return
        guild_id = ctx.guild.id
        if state.lower() == 'on':
            self.bot.antiraid_enabled[guild_id] = True
            embed = discord.Embed(
                title="🛡️ Protezione Antiraid",
                description="Protezione antiraid attivata.",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        elif state.lower() == 'off':
            self.bot.antiraid_enabled[guild_id] = False
            embed = discord.Embed(
                title="🛡️ Protezione Antiraid",
                description="Protezione antiraid disattivata.",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        else:
            await self.bot.send_translated(ctx, "Usa 'on' o 'off'.")

    @commands.command()
    @commands.has_permissions(administrator=True)
    async def setlogchannel(self, ctx, channel: discord.TextChannel):
        update_stats('setlogchannel')
        guild_id = ctx.guild.id
        cursor.execute('REPLACE INTO log_channels VALUES (?, ?)', (guild_id, channel.id))
        conn.commit()
        embed = discord.Embed(
            title="📜 Log Channel Impostato",
            description=f"Log channel impostato su {channel.name}.",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

# Cog Utilità
class Utilita(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    @commands.command()
    async def setlanguage(self, ctx, lang: str):
        update_stats('setlanguage')
        if lang in LANGUAGES:
            self.bot.languages[ctx.author.id] = lang
            embed = discord.Embed(
                title="🌐 Imposta Lingua",
                description=f"Lingua impostata su {LANGUAGES[lang]} ({lang}).",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        else:
            await self.bot.send_translated(ctx, "Lingua non supportata. Usa codici come 'en', 'fr', 'it', etc.")

    @commands.command()
    async def listlanguages(self, ctx):
        update_stats('listlanguages')
        langs = ", ".join([f"{code}: {name}" for code, name in list(LANGUAGES.items())[:50]])
        embed = discord.Embed(
            title="🌐 Lingue Supportate",
            description=f"Prime 50 lingue: {langs}... (Totale: {len(LANGUAGES)})",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def translate(self, ctx, *, args: str):
        update_stats('translate')
        parts = args.split()
        if len(parts) < 2:
            return await self.bot.send_translated(ctx, "Usa: $translate [testo] [a_lingua] [da_lingua opzionale]")
        to_lang = parts[-1]
        from_lang = parts[-2] if len(parts) > 2 and len(parts[-2]) == 2 else None
        text = " ".join(parts[:-1 if from_lang else -2])
        try:
            translated = self.bot.translator.translate(text, src=from_lang or 'auto', dest=to_lang).text
            embed = discord.Embed(
                title="🌐 Traduzione",
                description=f"Testo: {text}\nTradotto in {LANGUAGES.get(to_lang, to_lang)}: {translated}",
                color=discord.Color.from_rgb(0, 51, 102),
                timestamp=datetime.now()
            )
            embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
            await self.bot.send_translated(ctx, embed)
        except Exception as e:
            await self.bot.send_translated(ctx, f"Errore: {str(e)}")

    @commands.command()
    @commands.has_permissions(administrator=True)
    async def setprefix(self, ctx, prefix: str):
        update_stats('setprefix')
        guild_id = ctx.guild.id
        self.bot.prefixes[guild_id] = prefix
        cursor.execute('REPLACE INTO prefixes VALUES (?, ?)', (guild_id, prefix))
        conn.commit()
        embed = discord.Embed(
            title="🔧 Imposta Prefisso",
            description=f"Prefisso impostato su `{prefix}` per questo server.",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def userinfo(self, ctx, member: discord.Member = None):
        update_stats('userinfo')
        member = member or ctx.author
        embed = discord.Embed(
            title=f"👤 Informazioni Utente: {member}",
            description=f"ID: {member.id}\nCreato il: {member.created_at.strftime('%Y-%m-%d %H:%M:%S')}\nEntrato il: {member.joined_at.strftime('%Y-%m-%d %H:%M:%S') if member.joined_at else 'N/A'}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_thumbnail(url=member.avatar.url if member.avatar else member.default_avatar.url)
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def serverinfo(self, ctx):
        update_stats('serverinfo')
        guild = ctx.guild
        embed = discord.Embed(
            title=f"🌐 Informazioni Server: {guild.name}",
            description=f"ID: {guild.id}\nCreato il: {guild.created_at.strftime('%Y-%m-%d %H:%M:%S')}\nMembri: {guild.member_count}\nCanali: {len(guild.channels)}",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_thumbnail(url=guild.icon.url if guild.icon else None)
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def invite(self, ctx):
        update_stats('invite')
        invite_url = "https://discord.com/oauth2/authorize?client_id=1416440463618998282&permissions=8&integration_type=0&scope=bot+applications.commands"
        embed = discord.Embed(
            title="📩 Invita Crypt0n",
            description=f"[Clicca qui per invitare Crypt0n]({invite_url}) nel tuo server!",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def avatar(self, ctx, member: discord.Member = None):
        update_stats('avatar')
        member = member or ctx.author
        embed = discord.Embed(
            title=f"🖼️ Avatar di {member}",
            description=f"[Clicca per scaricare]({member.avatar.url if member.avatar else member.default_avatar.url})",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_image(url=member.avatar.url if member.avatar else member.default_avatar.url)
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def credits(self, ctx):
        update_stats('credits')
        embed = discord.Embed(
            title="🔒 Crypt0n v2.1 - Crediti",
            description="Il bot di sicurezza informatica più avanzato e completo per Discord!\nSviluppato dal **Team Crypt0n** con le ultime tecnologie in sicurezza digitale.",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.add_field(
            name="🛠️ Caratteristiche v2.1",
            value=(
                "• 80+ comandi di sicurezza informatica\n"
                "• Analisi forense avanzata\n"
                "• Intelligenza sulle minacce in tempo reale\n"
                "• Monitoraggio automatico di siti web\n"
                "• Crittografia di livello militare\n"
                "• Tecniche OSINT e pentesting avanzate\n"
                "• Database SQLite integrato\n"
                "• Report personalizzati dettagliati\n"
                "• Sistema antiraid intelligente\n"
                "• Comandi di moderazione completi\n"
                "• Analisi di metadati e file\n"
                "• Crittografia e decrittografia AES\n"
                "• Rilevamento di tecnologie web\n"
                "• Verifica di liste nere\n"
                "• Ricerca su social media\n"
                "• E molto altro..."
            ),
            inline=False
        )
        embed.add_field(
            name="🙏 Ringraziamenti",
            value="Grazie per aver scelto **Crypt0n** per la tua sicurezza digitale!\n[Visita il nostro sito](https://crypt0nbotv1.netlify.app/) | [Unisciti al nostro server Discord](https://discord.gg/UrcZhk3ASR)",
            inline=False
        )
        embed.set_thumbnail(url="https://imgur.com/a/O3bldbC")  # Sostituisci con il tuo logo
        embed.set_footer(text="Crypt0n v2.1 | Sviluppato da Team Crypt0n")
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def help(self, ctx):
        update_stats('help')
        embed = discord.Embed(
            title="🔒 Crypt0n - Elenco Comandi",
            description="Scopri tutti i comandi disponibili di **Crypt0n**, il bot di sicurezza informatica !\nUsa `$infocommands` per dettagli su ogni comando.",
            color=discord.Color.from_rgb(0, 51, 102),
            timestamp=datetime.now()
        )
        embed.set_author(name="Crypt0n Bot", icon_url="https://imgur.com/a/O3bldbC")  # Sostituisci con il tuo logo
        embed.set_thumbnail(url="https://imgur.com/a/keAZgty")  # Sostituisci con il tuo logo
        embed.add_field(
            name="🛠️ Analisi Avanzata",
            value="`$traceroute`, `$sslcheck`, `$subdomains`, `$geoip`, `$webtech`, `$robotstxt`",
            inline=False
        )
        embed.add_field(
            name="🔍 Analisi Forense",
            value="`$filehash`, `$integrity`, `$multihash`, `$rsagen`",
            inline=False
        )
        embed.add_field(
            name="⚠️ Intelligenza Minacce",
            value="`$threatip`, `$blacklist`, `$threatfeed`",
            inline=False
        )
        embed.add_field(
            name="🌐 OSINT",
            value="`$socialsearch`",
            inline=False
        )
        embed.add_field(
            name="📊 Monitoraggio",
            value="`$monitor`, `$stopmonitor`, `$monitors`, `$stats`, `$report`",
            inline=False
        )
        embed.add_field(
            name="🔧 Comandi Base",
            value="`$ipinfo`, `$dnslookup`, `$whois`, `$hash`, `$encode64`, `$decode64`, `$genpassword`, `$headers`, `$checkemail`, `$portscan`, `$analyzeurl`, `$passwordstrength`, `$cybernews`, `$checkleak`, `$checkleak_manual`, `$metadata`, `$encrypt`, `$decrypt`, `$scanfile`",
            inline=False
        )
        embed.add_field(
            name="🛡️ Moderazione",
            value="`$ban`, `$kick`, `$antiraid`, `$setlogchannel`",
            inline=False
        )
        embed.add_field(
            name="⚙️ Utilità",
            value="`$setlanguage`, `$listlanguages`, `$translate`, `$setprefix`, `$userinfo`, `$serverinfo`, `$invite`, `$avatar`, `$credits`, `$help`, `$infocommands`",
            inline=False
        )
        embed.set_footer(
            text="Crypt0n v2.1 | Sviluppato da Team Crypt0n",
            icon_url=""  # Sostituisci con il tuo logo
        )
        await self.bot.send_translated(ctx, embed)

    @commands.command()
    async def infocommands(self, ctx):
     update_stats('infocommands')
     embed = discord.Embed(
        title="🔒 Crypt0n - Informazioni sui Comandi",
        description="Dettagli e utilizzo di tutti i comandi di **Crypt0n**.",
        color=discord.Color.from_rgb(0, 51, 102),
        timestamp=datetime.now()
    )
     embed.set_author(name="Crypt0n Bot", icon_url="https://imgur.com/a/O3bldbC")
     embed.set_thumbnail(url="https://imgur.com/a/keAZgty")
     embed.add_field(
        name="🛠️ Analisi Avanzata",
        value=(
            "`$traceroute <target>`: Esegue un traceroute verso un dominio/IP. Es: `$traceroute google.com`\n"
            "`$sslcheck <domain>`: Verifica il certificato SSL di un dominio. Es: `$sslcheck example.com`\n"
            "`$subdomains <domain>`: Cerca subdomini comuni. Es: `$subdomains example.com`\n"
            "`$geoip <ip>`: Ottiene informazioni geografiche di un IP. Es: `$geoip 8.8.8.8`\n"
            "`$webtech <url>`: Rileva tecnologie usate da un sito. Es: `$webtech https://example.com`\n"
            "`$robotstxt <domain>`: Mostra il file robots.txt. Es: `$robotstxt example.com`"
        ),
        inline=False
    )
     embed.add_field(
        name="🔍 Analisi Forense",
        value=(
            "`$filehash`: Calcola hash (MD5, SHA1, SHA256) di un file allegato. Es: `$filehash` (con allegato)\n"
            "`$integrity <hash>`: Verifica l'integrità di un file confrontando il suo hash. Es: `$integrity <hash>` (con allegato)\n"
            "`$multihash <text>`: Calcola hash multipli di un testo. Es: `$multihash ciao`\n"
            "`$rsagen [size]`: Genera chiavi RSA. Es: `$rsagen 2048`"
        ),
        inline=False
    )
     embed.add_field(
        name="⚠️ Intelligenza Minacce",
        value=(
            "`$threatip <ip>`: Verifica se un IP è segnalato come minaccia. Es: `$threatip 1.2.3.4`\n"
            "`$blacklist <target>`: Verifica liste nere (placeholder). Es: `$blacklist example.com`\n"
            "`$threatfeed`: Mostra gli ultimi threat feed da AlienVault OTX. Es: `$threatfeed`"
        ),
        inline=False
    )
     embed.add_field(
        name="🌐 OSINT",
        value="`$socialsearch <username>`: Cerca un username sui social media. Es: `$socialsearch john_doe`",
        inline=False
    )
     embed.add_field(
        name="📊 Monitoraggio",
        value=(
            "`$monitor <url> [freq]`: Avvia il monitoraggio di un sito web. Es: `$monitor https://example.com 5`\n"
            "`$stopmonitor <url>`: Ferma il monitoraggio di un URL. Es: `$stopmonitor https://example.com`\n"
            "`$monitors`: Elenca i tuoi monitor attivi. Es: `$monitors`\n"
            "`$stats`: Mostra statistiche di utilizzo del bot. Es: `$stats`\n"
            "`$report`: Genera un report personale (placeholder). Es: `$report`"
        ),
        inline=False
    )
     embed.add_field(
        name="🔧 Comandi Base (Parte 1)",
        value=(
            "`$ipinfo <ip>`: Informazioni su un IP. Es: `$ipinfo 8.8.8.8`\n"
            "`$dnslookup <domain>`: Risolve un dominio in IP. Es: `$dnslookup example.com`\n"
            "`$whois <domain>`: Informazioni WHOIS di un dominio. Es: `$whois example.com`\n"
            "`$hash <algo> <text>`: Calcola hash di un testo. Es: `$hash sha256 ciao`\n"
            "`$encode64 <text>`: Codifica in Base64. Es: `$encode64 ciao`\n"
            "`$decode64 <encoded>`: Decodifica da Base64. Es: `$decode64 Y2lhbw==`\n"
            "`$genpassword [length]`: Genera una password casuale. Es: `$genpassword 16`\n"
            "`$headers <url>`: Mostra gli header HTTP di un URL. Es: `$headers https://example.com`\n"
            "`$checkemail <email>`: Verifica la validità di un'email. Es: `$checkemail user@example.com`"
        ),
        inline=False
    )
     embed.add_field(
        name="🔧 Comandi Base (Parte 2)",
        value=(
            "`$portscan <ip> [start] [end]`: Esegue un port scan. Es: `$portscan 1.2.3.4 1 100`\n"
            "`$analyzeurl <url>`: Analizza un URL con VirusTotal. Es: `$analyzeurl https://example.com`\n"
            "`$passwordstrength <password>`: Valuta la forza di una password. Es: `$passwordstrength Pass123!`\n"
            "`$cybernews`: Mostra le ultime notizie di cybersecurity. Es: `$cybernews`\n"
            "`$checkleak <query>`: Verifica violazioni di dati su HIBP. Es: `$checkleak user@example.com`\n"
            "`$checkleak_manual`: Link per verifica manuale su HIBP. Es: `$checkleak_manual`\n"
            "`$metadata`: Estrae metadati da un'immagine allegata. Es: `$metadata` (con allegato)\n"
            "`$encrypt <message>`: Cifra un messaggio con AES. Es: `$encrypt messaggio segreto`\n"
            "`$decrypt <encrypted>`: Decifra un messaggio AES. Es: `$decrypt <encrypted_text>`\n"
            "`$scanfile`: Scansiona un file con VirusTotal. Es: `$scanfile` (con allegato)"
        ),
        inline=False
    )
     embed.add_field(
        name="🛡️ Moderazione",
        value=(
            "`$ban <membro> [motivo]`: Banna un membro. Es: `$ban @utente Spam`\n"
            "`$kick <membro> [motivo]`: Espelle un membro. Es: `$kick @utente Comportamento scorretto`\n"
            "`$antiraid <on/off>`: Attiva/disattiva la protezione antiraid. Es: `$antiraid on`\n"
            "`$setlogchannel <canale>`: Imposta il canale di log. Es: `$setlogchannel #logs`"
        ),
        inline=False
    )
     embed.add_field(
        name="⚙️ Utilità",
        value=(
            "`$setlanguage <lang>`: Imposta la lingua del bot. Es: `$setlanguage en`\n"
            "`$listlanguages`: Elenca le lingue supportate. Es: `$listlanguages`\n"
            "`$translate <testo> [da_lingua] <a_lingua>`: Traduce un testo. Es: `$translate ciao en`\n"
            "`$setprefix <prefix>`: Imposta il prefisso del server. Es: `$setprefix !`\n"
            "`$userinfo [membro]`: Mostra informazioni su un utente. Es: `$userinfo @utente`\n"
            "`$serverinfo`: Mostra informazioni sul server. Es: `$serverinfo`\n"
            "`$invite`: Genera un link per invitare il bot. Es: `$invite`\n"
            "`$avatar [membro]`: Mostra l'avatar di un utente. Es: `$avatar @utente`\n"
            "`$credits`: Mostra i crediti del bot. Es: `$credits`\n"
            "`$help`: Elenca tutti i comandi. Es: `$help`\n"
            "`$infocommands`: Dettagli su tutti i comandi. Es: `$infocommands`"
        ),
        inline=False
    )
     embed.set_footer(
        text="Crypt0n v2.1 | Sviluppato da Team Crypt0n",
        icon_url="https://imgur.com/a/keAZgty"
    )
     await self.bot.send_translated(ctx, embed)

# Setup dei cog
async def setup(bot):
    print("Caricamento cog...")
    await bot.add_cog(AnalisiAvanzata(bot))
    await bot.add_cog(AnalisiForense(bot))
    await bot.add_cog(IntelligenzaMinacce(bot))
    await bot.add_cog(OSINTAvanzato(bot))
    await bot.add_cog(Monitoraggio(bot))
    await bot.add_cog(ComandiBase(bot))
    await bot.add_cog(Moderazione(bot))
    await bot.add_cog(Utilita(bot))
    print("Cog Utilita caricato con successo!")

# Avvia il bot
asyncio.run(setup(bot))
bot.run(TOKEN)
