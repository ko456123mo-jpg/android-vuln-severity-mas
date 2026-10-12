/**
 * التقاط لقطات الواجهة الحقيقية / Real UI screenshots (توثيق التسليم v1.0)
 *
 *   node scripts/capture_ui.js --base http://localhost:8501 --out docs/screenshots
 *
 * يفتح الواجهة العربية الحيّة، يسجّل الدخول بـ admin، ويلتقط:
 *   01_login.png       شاشة الدخول (شعار الهوية + النموذج)
 *   02_dashboard.png   لوحة المعلومات (KPIs + رسم الخطورة)
 * كما يطبع عرض الكتل الرئيسية للتأكد من وصول الصفحة (فحص صحة للالتقاط).
 *
 * المتطلبات: puppeteer + Chromium (تُثبَّت محلياً: npm install puppeteer)
 */
const fs = require("fs");
const path = require("path");
const puppeteer = require("puppeteer");

function arg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index > -1 && process.argv[index + 1] ? process.argv[index + 1] : fallback;
}

const BASE = arg("base", "http://localhost:8501");
const OUT = arg("out", "docs/screenshots");
const USER = arg("user", "admin");
const PASS = arg("pass", "admin123");
const WIDTH = Number(arg("width", "1440"));
const HEIGHT = Number(arg("height", "900"));

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waitForText(page, text, timeoutMs = 45000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = await page.evaluate((needle) => document.body.innerText.includes(needle), text);
    if (found) return true;
    await sleep(500);
  }
  return false;
}

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await puppeteer.launch({
    headless: "new",
    args: ["--no-sandbox", "--disable-dev-shm-usage", "--font-render-hinting=none"],
  });
  const page = await browser.newPage();
  await page.setViewport({ width: WIDTH, height: HEIGHT, deviceScaleFactor: 2 });
  page.on("console", (msg) => {
    if (msg.type() === "error") console.log("  [browser] ", msg.text().slice(0, 140));
  });

  console.log(`◉ فتح ${BASE}`);
  await page.goto(BASE, { waitUntil: "networkidle2", timeout: 90000 });

  const loginReady = await waitForText(page, "تسجيل الدخول", 60000);
  console.log(`  شاشة الدخول جاهزة: ${loginReady}`);
  await sleep(2500);
  const loginPath = path.join(OUT, "01_login.png");
  await page.screenshot({ path: loginPath });
  console.log(`  ✅ ${loginPath}`);

  // ── تسجيل الدخول ──
  const inputs = await page.$$("input");
  if (inputs.length < 2) throw new Error("لم أجد حقول الدخول — تحقق من تشغيل الواجهة");
  await inputs[0].click({ clickCount: 3 });
  await inputs[0].type(USER);
  await inputs[1].click({ clickCount: 3 });
  await inputs[1].type(PASS);

  const buttons = await page.$$("button");
  for (const button of buttons) {
    const text = await page.evaluate((el) => el.innerText, button);
    if (text && text.includes("دخول")) {
      await button.click();
      break;
    }
  }

  const loggedIn = await waitForText(page, "لوحة المعلومات", 60000);
  console.log(`  تسجيل الدخول ناجح: ${loggedIn}`);
  await sleep(5000);
  const dashboardPath = path.join(OUT, "02_dashboard.png");
  await page.screenshot({ path: dashboardPath });
  console.log(`  ✅ ${dashboardPath}`);

  // فحص صحة الالتقاط: الصفحة تحتوي بيانات فعلية لا شاشة فارغة
  const stats = await page.evaluate(() => ({
    blocks: document.querySelectorAll('[data-testid="stMetric"], [data-testid="stVerticalBlock"]').length,
    text: document.body.innerText.slice(0, 300).replace(/\s+/g, " "),
  }));
  console.log(`  عناصر مقيسة: ${stats.blocks} · نص: ${stats.text.slice(0, 160)}…`);

  await browser.close();
  console.log("تم.");
})().catch((error) => {
  console.error("✗ فشل الالتقاط:", error.message);
  process.exit(1);
});
