import json
import os
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext
import pyotp
from pyzbar.pyzbar import decode
from PIL import Image
import io
import requests
import base64
import urllib.parse
from google.protobuf import text_format
from OtpMigration_pb2 import MigrationPayload

# Ruta del archivo para guardar los secretos
SECRETS_FILE = 'secrets.json'

# Cargar los secretos desde un archivo al iniciar
def load_secrets():
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, 'r') as f:
            return json.load(f)
    return {}

# Guardar los secretos en un archivo
def save_secrets():
    with open(SECRETS_FILE, 'w') as f:
        json.dump(secrets, f)

# Diccionario para almacenar correos y claves secretas
secrets = load_secrets()

# Configuración de logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Función para decodificar el payload del QR exportado desde Google Authenticator
def decode_otpauth_migration(uri):
    try:
        # Extraer la parte codificada en base64 del URI
        base64_data = uri.split('data=')[1]
        
        # Decodificar cualquier codificación de URL en la cadena base64
        base64_data = urllib.parse.unquote(base64_data)
        
        # Corregir el padding manualmente
        missing_padding = len(base64_data) % 4
        if missing_padding != 0:
            base64_data += '=' * (4 - missing_padding)
        
        logger.info(f"Base64 con Padding: {base64_data}")
        
        # Decodificar de base64
        decoded_data = base64.urlsafe_b64decode(base64_data)
        
        # Crear un objeto MigrationPayload de protobuf
        payload = MigrationPayload()
        payload.ParseFromString(decoded_data)

        # Procesar las cuentas en el payload
        for otp in payload.otp_parameters:
            account_name = otp.name
            secret = base64.b32encode(otp.secret).decode('utf-8').replace('=', '')
            secrets[account_name] = secret
            logger.info(f"Clave registrada para {account_name}: {secret}")

        return True

    except Exception as e:
        logger.error(f"Error al decodificar el URI: {e}")
        return False


# Función para manejar el registro del usuario con un QR
async def register(update: Update, context: CallbackContext) -> None:
    logger.info("Imagen recibida para registro.")
    if update.message.photo:
        photo = update.message.photo[-1]
        file = await photo.get_file()
        file_url = file.file_path
        response = requests.get(file_url)
        img = Image.open(io.BytesIO(response.content))
        decoded_objects = decode(img)

        if decoded_objects:
            qr_data = decoded_objects[0].data.decode('utf-8')
            logger.info(f"QR decodificado: {qr_data}")

            if qr_data.startswith("otpauth-migration://"):
                if decode_otpauth_migration(qr_data):
                    save_secrets()  # Guardar los cambios después de la decodificación
                    await update.message.reply_text("Registro exitoso de las cuentas migradas.")
                else:
                    await update.message.reply_text("Error al procesar el QR exportado.")
            
            elif qr_data.startswith("otpauth://"):
                totp = pyotp.parse_uri(qr_data)
                correo = totp.name  # Extraer el nombre de la cuenta, que suele ser el correo
                
                secrets[correo] = totp.secret
                save_secrets()  # Guardar los cambios después del registro
                await update.message.reply_text(f'Registro exitoso para: {correo}')
                logger.info(f"Registro exitoso para {correo} con la clave secreta {totp.secret}")
            else:
                await update.message.reply_text("El QR no contiene un URI TOTP válido.")
                logger.warning("El QR no contiene un URI TOTP válido.")
        else:
            await update.message.reply_text('No se pudo decodificar el QR.')
            logger.warning("No se pudo decodificar el QR.")
    else:
        await update.message.reply_text('Por favor, envíame una imagen con un QR.')
        logger.warning("No se envió una imagen.")

# Función para generar y enviar el código TOTP
async def get_code(update: Update, context: CallbackContext) -> None:
    logger.info("Comando /code recibido.")
    if context.args:
        email = context.args[0]
        if email in secrets:
            totp = pyotp.TOTP(secrets[email])
            code = totp.now()
            await update.message.reply_text(f'{code}')  # Enviar solo el código
            logger.info(f"Código TOTP generado para {email}: {code}")
        else:
            await update.message.reply_text('Correo no registrado.')
            logger.warning(f"Correo no registrado: {email}")
    else:
        await update.message.reply_text('Por favor, proporciona un correo electrónico.')
        logger.warning("No se proporcionó un correo electrónico.")

def main():
    # Obtener el token desde la variable de entorno
    token = os.getenv("TELEGRAM_TOKEN")
    application = Application.builder().token(token).build()

    # Registrar comandos y manejadores
    application.add_handler(CommandHandler("code", get_code))
    application.add_handler(MessageHandler(filters.PHOTO, register))

    # Iniciar el bot
    logger.info("El bot está comenzando.")
    application.run_polling()

if __name__ == '__main__':
    main()