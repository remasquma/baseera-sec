"""
Baseera Sec - One-Click Hugging Face Spaces Deployer
أداة الرفع السحابي التلقائي لمشروع بصيرة إلى منصة Hugging Face Spaces
"""
import os
import sys

def main():
    try:
        from huggingface_hub import HfApi
    except ImportError:
        print("[!] مكتبة huggingface_hub غير مثبتة. جارٍ التثبيت...")
        os.system(f"{sys.executable} -m pip install huggingface_hub")
        from huggingface_hub import HfApi

    print("=" * 65)
    print("🚀 BASEERA SEC — HUGGING FACE SPACES CLOUD DEPLOYER")
    print("=" * 65)
    print("هذه الأداة سترفع مشروع Baseera Sec سحابياً ليصبح له رابط مباشر يعمل أونلاين.")
    print("حجم الكود المرفوع خفيف جداً، ومجلد .venv مستثنى بالكامل.\n")
    
    token = input("1. الصقي Hugging Face Access Token (يبدأ بـ hf_...): ").strip()
    if not token:
        print("[!] لم يتم إدخال الرمز (Token). يُرجى نسخه من Settings > Access Tokens في Hugging Face.")
        return

    space_name = input("2. اختاري اسماً للمشروع على السحابة (اضغطي Enter للافتراضي: baseera-sec): ").strip() or "baseera-sec"

    try:
        api = HfApi(token=token)
        user_info = api.whoami()
        username = user_info["name"]
        repo_id = f"{username}/{space_name}"
        
        print(f"\n[+] مرحباً {username}! جارٍ تجهيز المساحة: {repo_id}...")
        api.create_repo(
            repo_id=repo_id,
            repo_type="space",
            space_sdk="docker",
            exist_ok=True
        )

        project_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"[+] جارٍ رفع ملفات المشروع خفيفة الوزن...")
        print("[+] يتم استبعاد .venv والتقارير المؤقتة لتسريع الرفع...")

        api.upload_folder(
            folder_path=project_dir,
            repo_id=repo_id,
            repo_type="space",
            ignore_patterns=[
                ".venv/**",
                "venv/**",
                ".git/**",
                "*.db",
                "*.sqlite3",
                "__pycache__/**",
                "*/__pycache__/**",
                ".pytest_cache/**",
                "reports/*.pdf",
                "reports/*.sarif",
                "reports/*.html",
                "reports/*.json",
                "uploads/*"
            ]
        )

        space_url = f"https://huggingface.co/spaces/{repo_id}"
        print("\n" + "=" * 65)
        print("🎉 مبروك يا رموسة! تم رفع المشروع وبناء الحاوية السحابية بنجاح!")
        print(f"🔗 رابط المنصة الحي (Live Demo URL):")
        print(f"👉 {space_url}")
        print("=" * 65)
        print("ملاحظة: سيستغرق بناء الحاوية السحابية من 2 إلى 3 دقائق لأول مرة،")
        print("ثم ستفتح لوحة التحكم فوراً من الرابط أعلاه!")

    except Exception as e:
        print(f"\n[!] حدث خطأ أثناء الرفع: {e}")

if __name__ == "__main__":
    main()
