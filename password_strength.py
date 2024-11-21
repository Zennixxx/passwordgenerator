import string
import re
import hashlib
import requests

def load_passwords(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        print(f"Файл не знайдено")
        return []

def calc_pass_strength(password):
    score = 0
    issues = []
    
    worst_passwords = load_passwords('worst_passwords.txt')
    
    def check_password(password):
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f'https://api.pwnedpasswords.com/range/{prefix}'
        try:
            response = requests.get(url)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return int(count)
            return 0
        except requests.RequestException:
            return None
    
    leaks_count = check_password(password)
    try:
        if leaks_count is None:
            issues.append("Не вдалося перевірити пароль на витоки")
        elif leaks_count:
            score -= 2
            issues.append(f"Цей пароль був використаний {leaks_count} разів у витоках")
    except Exception as e:
        print(e)
    
    if len(password) < 8:
        issues.append("Пароль повинен містити мінімум 8 символів")
    elif len(password) < 10:
        score += 1
    elif len(password) < 14:
        score += 2
    else:
        score += 3
        
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    
    categories = sum([has_lower, has_upper, has_digit, has_special])
    score += categories
    
    if not (has_lower or has_upper):
        issues.append("Додайте літери")
    if not has_digit and not has_special:
        issues.append("Додайте цифри або спеціальні символи")
        
    if re.search(r'(.)\1{3,}', password):
        score -= 1
        issues.append("Уникайте довгих повторень символів")
    
    if password.lower() in worst_passwords:
        score -= 2
        issues.append("Цей пароль занадто простий")

    unique_chars = len(set(password))
    if unique_chars < len(password) / 3:
        score -= 1
        issues.append("Використовуйте більш різноманітні символи")
    
    score = max(0, min(10, score))
    
    color = 'red' if score < 3 else 'orange' if score < 5 else 'green'
    
    return {
        'score': score,
        'strength': 'Слабкий' if score < 3 else 'Середній' if score < 5 else 'Сильний',
        'issues': issues,
        'color': color
    }