#!/bin/bash
# Двойной клик чтобы запустить локальный сервер для теста с телефона

cd "$(dirname "$0")"
PORT=8000

IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "127.0.0.1")

echo ""
echo "================================================"
echo "  Каталог Сочи — CRM запущена"
echo "================================================"
echo ""
echo "  На Mac:   http://localhost:$PORT"
echo "  С телефона (та же Wi-Fi): http://$IP:$PORT"
echo ""
echo "  Чтобы остановить — закройте это окно или Ctrl+C"
echo "================================================"
echo ""

# Открыть в браузере
sleep 1
open "http://localhost:$PORT" 2>/dev/null

python3 -m http.server $PORT
