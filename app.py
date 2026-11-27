"""
Baseera Sec - Main Desktop Entry Point
تشغيل تطبيق سطح المكتب وفتح نافذة التحكم السيبرانية
مدعوم بمحرك FastAPI وخادم Uvicorn وقاعدة بيانات SQLite لضمان أعلى معايير الـ VAPT العالمية
"""
import os
import sys
import time
import threading
import uvicorn
from api.main import app

def start_fastapi_server(port=8765):
    """تشغيل خادم FastAPI في الخلفية"""
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")

def main():
    port = 8765
    local_url = f"http://127.0.0.1:{port}"

    print("[+] Launching Baseera Sec local security scanner...")
    print(f"[+] FastAPI Server starting at: {local_url}")

    # تشغيل خادم FastAPI عبر Uvicorn في ثريد خلفي
    server_thread = threading.Thread(target=start_fastapi_server, daemon=True)
    server_thread.start()
    
    # مهلة قصيرة للتأكد من إقلاع السيرفر
    time.sleep(1.2)

    try:
        import webview
        window = webview.create_window(
            title="Baceer — بصير الثغرات الأمنية | Enterprise Cognitive VAPT Platform",
            url=local_url,
            width=1350,
            height=880,
            resizable=True,
            background_color="#090d16"
        )
        webview.start(debug=False)
    except Exception as e:
        print(f"[!] Native GTK notice: {e}")
        print(f"[+] Opening in browser app mode: {local_url}")
        os.system(f"google-chrome --app={local_url} 2>/dev/null || xdg-open {local_url}")
        try:
            while True:
                threading.Event().wait(1)
        except KeyboardInterrupt:
            print("\n[+] Baseera Sec platform closed safely.")

if __name__ == "__main__":
    main()
