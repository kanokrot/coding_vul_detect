import os
import tempfile
import shutil
import subprocess
import re

def clone_and_read_repo(git_url):
    scanned_files = []
    temp_dir = tempfile.mkdtemp()
    
    #1. ระบบซ่อมลิงก์: ตัด /blob/ หรือ /tree/ ออกให้เหลือแค่ Repo หลัก
    match = re.match(r"(https?://github\.com/[^/]+/[^/]+)", git_url)
    if match:
        git_url = match.group(1)
        # ลบ .git ออกก่อนเผื่อมี แล้วค่อยเติมเข้าไปใหม่ให้ชัวร์
        git_url = git_url.replace('.git', '') + '.git'
            
    print(f"DEBUG: Processed Git URL -> {git_url}")

    try:
        # 2. ใช้ Subprocess แทน GitPython (แก้ปัญหา WinError 5 ไฟล์ล็อก)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", git_url, temp_dir],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise Exception(f"Git Clone Failed: {result.stderr}")
            
        # 3. เดินหาไฟล์ .c, .cpp, .h, .hpp
        for root, dirs, files in os.walk(temp_dir):
            if '.git' in dirs:
                dirs.remove('.git') # ข้ามโฟลเดอร์ .git
                
            for file in files:
                if file.endswith(('.c', '.cpp', '.h', '.hpp')):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            relative_path = os.path.relpath(full_path, temp_dir)
                            scanned_files.append((relative_path, content))
                    except Exception as e:
                        pass # มองข้ามไฟล์ที่อ่านไม่ได้

    except Exception as e:
        raise Exception(str(e))
        
    finally:
        # 🟢 4. ลบโฟลเดอร์ทิ้งแบบไม่สน Error (แก้ปัญหา WinError 5 ตอนจบ)
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

    return scanned_files