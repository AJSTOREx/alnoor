<?php
session_start();
require_once 'db2.php';

if (isset($_SESSION['admin'])) {
    header('Location: dashboard/');
    exit;
}

// إعدادات البوت
define('BOT_TOKEN', '8839164594:');

function sendTelegramCode($chatId, $code, $name) {
    $msg = "🔐 *كود التحقق الثنائي*\n\nمرحباً *{$name}*\n\nكودك هو: `{$code}`\n\n⏰ صالح لمدة 5 دقائق فقط\n⚠️ لا تشارك هذا الكود مع أحد";
    $url = "https://api.telegram.org/bot" . BOT_TOKEN . "/sendMessage";
    $data = ['chat_id' => $chatId, 'text' => $msg, 'parse_mode' => 'Markdown'];
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $result = curl_exec($ch);
    curl_close($ch);
    return json_decode($result, true);
}

$error = '';
$step = $_SESSION['2fa_step'] ?? 1;

// ===== الخطوة الأولى: التحقق من البريد وكلمة المرور =====
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $email = trim($_POST['email']);
    $password = $_POST['password'];

    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND role IN ('admin', 'employee')");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {

        // إذا ما عنده telegram_chat_id — دخول مباشر
        if (empty($user['telegram_chat_id'])) {
            $_SESSION['admin'] = $user;
            header('Location: dashboard/');
            exit;
        }

        // توليد كود 4 أرقام
        $code = str_pad(rand(0, 9999), 4, '0', STR_PAD_LEFT);
        $expires = date('Y-m-d H:i:s', time() + 300);

        $pdo->prepare("UPDATE users SET two_factor_code = ?, two_factor_expires = ?, two_factor_attempts = 0 WHERE id = ?")
            ->execute([$code, $expires, $user['id']]);

        // إرسال للتلغرام
        $result = sendTelegramCode($user['telegram_chat_id'], $code, $user['name']);

        if (!($result['ok'] ?? false)) {
            $error = '⚠️ تعذر إرسال كود التحقق عبر تلغرام. تواصل مع الدعم الفنى.';
        } else {
            $_SESSION['2fa_user_id'] = $user['id'];
            $_SESSION['2fa_step'] = 2;
            $step = 2;
        }

    } else {
        $error = 'البريد الإلكتروني أو كلمة المرور غير صحيحة';
    }
}

// ===== الخطوة الثانية: التحقق من الكود =====
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_code'])) {
    $enteredCode = implode('', array_map('trim', $_POST['code'] ?? []));
    $userId = $_SESSION['2fa_user_id'] ?? null;

    if (!$userId) {
        unset($_SESSION['2fa_step'], $_SESSION['2fa_user_id']);
        $step = 1;
        $error = 'انتهت الجلسة، يرجى المحاولة مجدداً';
    } else {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user['two_factor_attempts'] >= 3) {
            $pdo->prepare("UPDATE users SET two_factor_code = NULL, two_factor_expires = NULL, two_factor_attempts = 0 WHERE id = ?")
                ->execute([$userId]);
            unset($_SESSION['2fa_user_id'], $_SESSION['2fa_step']);
            $step = 1;
            $error = '❌ تجاوزت عدد المحاولات. يرجى تسجيل الدخول مجدداً.';

        } elseif (strtotime($user['two_factor_expires']) < time()) {
            $pdo->prepare("UPDATE users SET two_factor_code = NULL WHERE id = ?")->execute([$userId]);
            unset($_SESSION['2fa_user_id'], $_SESSION['2fa_step']);
            $step = 1;
            $error = '⏰ انتهت صلاحية الكود. يرجى تسجيل الدخول مجدداً.';

        } elseif ($enteredCode === $user['two_factor_code']) {
            $pdo->prepare("UPDATE users SET two_factor_code = NULL, two_factor_expires = NULL, two_factor_attempts = 0 WHERE id = ?")
                ->execute([$userId]);
            unset($_SESSION['2fa_user_id'], $_SESSION['2fa_step']);
            $_SESSION['admin'] = $user;
            header('Location: dashboard/');
            exit;

        } else {
            $pdo->prepare("UPDATE users SET two_factor_attempts = two_factor_attempts + 1 WHERE id = ?")
                ->execute([$userId]);
            $remaining = 3 - ($user['two_factor_attempts'] + 1);
            $error = "❌ الكود غير صحيح. تبقّى لك {$remaining} محاولة.";
            $step = 2;
        }
    }
}

// ===== إعادة إرسال الكود =====
if (isset($_GET['resend']) && isset($_SESSION['2fa_user_id'])) {
    $userId = $_SESSION['2fa_user_id'];
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    $code = str_pad(rand(0, 9999), 4, '0', STR_PAD_LEFT);
    $expires = date('Y-m-d H:i:s', time() + 300);
    $pdo->prepare("UPDATE users SET two_factor_code = ?, two_factor_expires = ?, two_factor_attempts = 0 WHERE id = ?")
        ->execute([$code, $expires, $userId]);
    sendTelegramCode($user['telegram_chat_id'], $code, $user['name']);
    header('Location: index.php');
    exit;
}

// ===== العودة لتسجيل الدخول =====
if (isset($_GET['back'])) {
    unset($_SESSION['2fa_user_id'], $_SESSION['2fa_step']);
    header('Location: index.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تسجيل الدخول | لوحة التحكم</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@300;400;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="css/login.css">
<link rel="stylesheet" href="css/dark.css">
<link rel="stylesheet" href="css/index.css">
<link rel="icon" type="image/png" href="https://ettqan.top/img/mutqan b.png">
<style>
/* ===== 2FA ===== */
.code-inputs {
    display: flex;
    gap: 12px;
    justify-content: center;
    margin: 25px 0 10px;
    direction: ltr;
}

.code-input {
    width: 62px;
    height: 68px;
    text-align: center;
    font-size: 28px;
    font-weight: 700;
    border: 2px solid #eaeaea;
    border-radius: 14px;
    font-family: 'Cairo', sans-serif;
    color: #111;
    background: #fafafa;
    transition: 0.3s;
    outline: none;
    caret-color: transparent;
}

.code-input:focus {
    border-color: #111;
    background: #fff;
    transform: scale(1.06);
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

.code-input.filled {
    border-color: #111;
    background: #f0f0f0;
}

.tfa-icon {
    font-size: 48px;
    display: block;
    text-align: center;
    margin-bottom: 10px;
    animation: bounce 2s infinite;
}

@keyframes bounce {
    0%, 100% { transform: translateY(0); }
    50% { transform: translateY(-8px); }
}

.tfa-desc {
    font-size: 13px;
    color: #777;
    text-align: center;
    line-height: 1.8;
    margin-bottom: 5px;
}

.tfa-timer {
    text-align: center;
    font-size: 13px;
    color: #aaa;
    margin-bottom: 20px;
}

.tfa-timer span {
    color: #ef4444;
    font-weight: 700;
    font-size: 15px;
}

.tfa-links {
    display: flex;
    justify-content: space-between;
    margin-top: 15px;
    font-size: 13px;
}

.tfa-links a {
    color: #777;
    text-decoration: none;
    transition: 0.2s;
}

.tfa-links a:hover { color: #111; }

.tfa-attempts {
    display: flex;
    justify-content: center;
    gap: 6px;
    margin-top: 10px;
}

.tfa-attempt-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #eaeaea;
    transition: 0.3s;
}

.tfa-attempt-dot.used { background: #ef4444; }

/* DARK */
body.dark .code-input {
    background: #1e1e1e;
    border-color: #333;
    color: #f0f0f0;
}

body.dark .code-input:focus {
    border-color: #f0f0f0;
    background: #2a2a2a;
}

body.dark .code-input.filled {
    background: #222;
    border-color: #f0f0f0;
}
</style>
</head>
<body>

<button class="theme-btn" onclick="toggleTheme()" title="تبديل الوضع">
    <svg id="theme-icon" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.72 9.72 0 0 1 18 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 0 0 3 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 0 0 9.002-5.998Z" />
    </svg>
</button>

<div class="login-wrap">
    <div class="login-left">
        <div class="login-left-content">
            <img src="https://ettqan.top/img/mutqan b.png" alt="Logo" class="side-logo">
            <h1>مرحباً بك</h1>
            <p>لوحة تحكم مُتقَن — إدارة متكاملة لموقعك وفريقك بكل سهولة واحترافية.</p>
            <div class="side-stats">
                <div class="side-stat">
                    <h3 id="userCount">0</h3>
                    <p>مستخدم</p>
                </div>
                <div class="side-stat">
                    <h3 id="projectCount">0</h3>
                    <p>مشروع</p>
                </div>
                <div class="side-stat">
                    <h3 id="msgCount">0</h3>
                    <p>رسالة</p>
                </div>
            </div>
        </div>
    </div>

    <div class="login-right">
        <div class="login-box">
            <img id="loginLogo" src="https://ettqan.top/img/mutqan 2.png" alt="Logo" class="login-logo">

            <?php if ($step === 1): ?>
            <!-- ===== الخطوة الأولى ===== -->
            <h2>تسجيل الدخول</h2>
            <p>أدخل بياناتك للوصول للوحة التحكم</p>

            <?php if ($error): ?>
            <div class="alert error"><?= $error ?></div>
            <?php endif; ?>

            <form method="POST">
                <div class="form-group">
                    <label>البريد الإلكتروني</label>
                    <div class="input-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75" />
                        </svg>
                        <input type="email" name="email" placeholder="user@example.com" required autofocus>
                    </div>
                </div>
                <div class="form-group">
                    <label>كلمة المرور</label>
                    <div class="input-icon">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
                        </svg>
                        <input type="password" name="password" id="passInput" placeholder="••••••••" required>
                        <button type="button" class="toggle-pass" onclick="togglePass()">👁</button>
                    </div>
                </div>
                <button type="submit" name="login" class="submit-btn">دخول</button>
                <a href="https://ad.ettqan.top/reset-password" class="back-link">نسيت كلمة المرور؟</a>
            </form>

            <?php else: ?>
            <!-- ===== الخطوة الثانية ===== -->
            <span class="tfa-icon">🔐</span>
            <h2 style="text-align:center;">التحقق الثنائي</h2>
            <p class="tfa-desc">تم إرسال كود مكون من 4 أرقام<br>إلى حساب تلغرام الخاص بك</p>

            <?php if ($error): ?>
            <div class="alert error"><?= $error ?></div>
            <?php endif; ?>

            <form method="POST" id="codeForm">
                <div class="code-inputs">
                    <input type="text" name="code[]" class="code-input" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off" id="c1">
                    <input type="text" name="code[]" class="code-input" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off" id="c2">
                    <input type="text" name="code[]" class="code-input" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off" id="c3">
                    <input type="text" name="code[]" class="code-input" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off" id="c4">
                </div>

                <div class="tfa-timer">
                    ينتهي خلال: <span id="timer">05:00</span>
                </div>

                <!-- نقاط المحاولات -->
                <div class="tfa-attempts">
                    <div class="tfa-attempt-dot"></div>
                    <div class="tfa-attempt-dot"></div>
                    <div class="tfa-attempt-dot"></div>
                </div>

                <button type="submit" name="verify_code" class="submit-btn" id="verifyBtn" style="margin-top:20px;" disabled>
                    تحقق من الكود
                </button>
            </form>

            <div class="tfa-links">
                <a href="?resend=1">🔄 إعادة إرسال الكود</a>
                <a href="?back=1">← العودة</a>
            </div>

            <?php endif; ?>

            <a href="https://ettqan.top" class="back-link" style="margin-top:15px; display:block; text-align:center;">← العودة للموقع</a>
        </div>
    </div>
</div>

<script>
// ===== TOGGLE PASS =====
function togglePass() {
    const input = document.getElementById('passInput');
    if (input) input.type = input.type === 'password' ? 'text' : 'password';
}

// ===== CODE INPUTS =====
const codeInputs = document.querySelectorAll('.code-input');
if (codeInputs.length > 0) {
    // فوكس على أول خانة
    codeInputs[0].focus();

    codeInputs.forEach((input, idx) => {
        input.addEventListener('input', (e) => {
            const val = e.target.value.replace(/[^0-9]/g, '');
            e.target.value = val;

            if (val) {
                e.target.classList.add('filled');
                if (idx < codeInputs.length - 1) codeInputs[idx + 1].focus();
            } else {
                e.target.classList.remove('filled');
            }

            // تفعيل زر التحقق
            const allFilled = [...codeInputs].every(i => i.value.length === 1);
            const btn = document.getElementById('verifyBtn');
            if (btn) btn.disabled = !allFilled;

            // إرسال تلقائي
            if (allFilled) {
            document.getElementById('verifyBtn').disabled = false;
           }
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace') {
                if (!input.value && idx > 0) {
                    codeInputs[idx - 1].focus();
                    codeInputs[idx - 1].value = '';
                    codeInputs[idx - 1].classList.remove('filled');
                }
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasted = e.clipboardData.getData('text').replace(/[^0-9]/g, '').slice(0, 4);
            pasted.split('').forEach((char, i) => {
                if (codeInputs[i]) {
                    codeInputs[i].value = char;
                    codeInputs[i].classList.add('filled');
                }
            });
            const allFilled = [...codeInputs].every(i => i.value.length === 1);
            const btn = document.getElementById('verifyBtn');
            if (btn) btn.disabled = !allFilled;
            if (allFilled) {
    document.getElementById('verifyBtn').disabled = false;
}
        });
    });

    // ===== TIMER =====
    let timeLeft = 300;
    const timerEl = document.getElementById('timer');
    const countdown = setInterval(() => {
        timeLeft--;
        const m = String(Math.floor(timeLeft / 60)).padStart(2, '0');
        const s = String(timeLeft % 60).padStart(2, '0');
        if (timerEl) timerEl.textContent = `${m}:${s}`;
        if (timeLeft <= 60 && timerEl) timerEl.style.color = '#ef4444';
        if (timeLeft <= 0) {
            clearInterval(countdown);
            if (timerEl) timerEl.textContent = '00:00';
        }
    }, 1000);
}

// ===== ANIMATE COUNT =====
function animateCount(id, target) {
    let count = 0;
    const step = Math.ceil(target / 30);
    const interval = setInterval(() => {
        count += step;
        if (count >= target) { count = target; clearInterval(interval); }
        const el = document.getElementById(id);
        if (el) el.textContent = count + '+';
    }, 50);
}

// ===== DARK MODE =====
const sunIcon = `<path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0Z" />`;
const moonIcon = `<path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.72 9.72 0 0 1 18 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 0 0 3 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 0 0 9.002-5.998Z" />`;
const logoLight = 'https://ettqan.top/img/mutqan 2.png';
const logoDark = 'https://ettqan.top/img/mutqan b.png';

function updateLogo(isDark) {
    const logo = document.getElementById('loginLogo');
    if (logo) logo.src = isDark ? logoDark : logoLight;
}

function toggleTheme() {
    const isDark = document.body.classList.toggle('dark');
    localStorage.setItem('admin_theme', isDark ? 'dark' : 'light');
    const icon = document.getElementById('theme-icon');
    if (icon) icon.innerHTML = isDark ? sunIcon : moonIcon;
    updateLogo(isDark);
}

window.addEventListener('DOMContentLoaded', () => {
    animateCount('userCount', 20);
    animateCount('projectCount', 15);
    animateCount('msgCount', 50);

    const saved = localStorage.getItem('admin_theme');
    const icon = document.getElementById('theme-icon');
    if (saved === 'dark') {
        document.body.classList.add('dark');
        if (icon) icon.innerHTML = sunIcon;
        updateLogo(true);
    } else {
        if (icon) icon.innerHTML = moonIcon;
    }
});
</script>

</body>
</html>
