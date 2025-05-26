// server.js
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const multer = require('multer');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const PORT = 3000;

// Basit kullanıcı veritabanı (üretim ortamında gerçek bir veritabanı kullanın)
const users = [];
const userFiles = {}; // Kullanıcıya göre yüklenen dosyaların bilgileri

// Şablon motoru ve statik dosya ayarları
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));

// Oturum ayarları
app.use(session({
  secret: 'gizliAnahtar',
  resave: false,
  saveUninitialized: true
}));

// Statik uploads klasörü
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// AdminAuth Middleware: Admin oturumu kontrolü
function adminAuth(req, res, next) {
  if (req.session && req.session.isAdmin) {
    next();
  } else {
    res.redirect('/admin-login');
  }
}

// Basit captcha üretimi (iki sayı toplama)
function generateCaptcha() {
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  return { question: `${a} + ${b} = ?`, answer: a + b };
}

// Multer yapılandırması: Yalnızca belirlenen dosya türlerini kabul et
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads'); // uploads klasörüne kaydet
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

// Dosya türü kontrol fonksiyonu
function fileFilter(req, file, cb) {
  const allowedTypes = [
    'application/pdf',
    'image/jpeg',
    'image/svg+xml',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Bu dosya formatı kabul edilmiyor!'), false);
  }
}

const upload = multer({ storage: storage, fileFilter: fileFilter });

// Rotalar

// Ana sayfa yönlendirmesi
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Kayıt sayfası (GET)
app.get('/register', (req, res) => {
  const captcha = generateCaptcha();
  req.session.captchaAnswer = captcha.answer;
  res.render('register', { captchaQuestion: captcha.question, error: null });
});

// Kayıt işlemi (POST)
app.post('/register', async (req, res) => {
  const { username, email, password, captcha } = req.body;

  // Captcha doğrulaması
  if (parseInt(captcha) !== req.session.captchaAnswer) {
    const newCaptcha = generateCaptcha();
    req.session.captchaAnswer = newCaptcha.answer;
    return res.render('register', { captchaQuestion: newCaptcha.question, error: 'Captcha doğrulaması başarısız!' });
  }

  // Şifreyi hash’le
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), username, email, password: hashedPassword };
  users.push(user);

  // Kullanıcı dosya bilgileri için başlangıç
  userFiles[user.id] = [];

  res.redirect('/login');
});

// Giriş sayfası (GET)
app.get('/login', (req, res) => {
  const captcha = generateCaptcha();
  req.session.captchaAnswer = captcha.answer;
  res.render('login', { captchaQuestion: captcha.question, error: null });
});

// Giriş işlemi (POST)
app.post('/login', async (req, res) => {
  const { email, password, captcha } = req.body;
  
  // Captcha kontrolü
  if (parseInt(captcha) !== req.session.captchaAnswer) {
    const newCaptcha = generateCaptcha();
    req.session.captchaAnswer = newCaptcha.answer;
    return res.render('login', { captchaQuestion: newCaptcha.question, error: 'Captcha doğrulaması başarısız!' });
  }

  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    const newCaptcha = generateCaptcha();
    req.session.captchaAnswer = newCaptcha.answer;
    return res.render('login', { captchaQuestion: newCaptcha.question, error: 'Geçersiz giriş bilgileri!' });
  }
  
  req.session.userId = user.id;
  res.redirect('/dashboard');
});

// Dashboard: Kullanıcı hesabı sayfası
app.get('/dashboard', (req, res) => {
  const user = users.find(u => u.id === req.session.userId);
  if (!user) return res.redirect('/login');
  res.render('dashboard', { user });
});

// Dosya yükleme işlemi (dashboard üzerinden POST)
app.post('/upload', upload.single('file'), (req, res) => {
  const userId = req.session.userId;
  if (!userId) return res.redirect('/login');

  if (req.file) {
    // Dosya bilgilerini userFiles objesine ekle (MIME tipini de saklıyoruz)
    userFiles[userId].push({
      originalname: req.file.originalname,
      filename: req.file.filename,
      path: req.file.path,
      mimetype: req.file.mimetype,
      uploadDate: new Date()
    });
  }
  res.redirect('/dashboard');
});

// Basit hesaplama işlemleri için örnek rota (POST: hesaplama)
app.post('/calculate', (req, res) => {
  const { num1, num2, operation } = req.body;
  let result;
  const a = parseFloat(num1);
  const b = parseFloat(num2);
  
  switch (operation) {
    case 'topla':
      result = a + b;
      break;
    case 'carp':
      result = a * b;
      break;
    case 'yuzde':
      result = (a / 100) * b;
      break;
    default:
      result = 'Geçersiz işlem';
  }
  
  res.send(`Sonuç: ${result}`);
});

// Admin giriş sayfası (GET)
app.get('/admin-login', (req, res) => {
  res.render('admin-login', { error: null });
});

// Admin giriş işlemi (POST)
app.post('/admin-login', (req, res) => {
  const { adminPassword } = req.body;
  // Sabit admin şifresi, üretimde güvenli yöntemlerle saklayın
  if (adminPassword === 'adminsecret123') {
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.render('admin-login', { error: 'Geçersiz şifre, lütfen tekrar deneyin.' });
  }
});

// Admin paneli: adminAuth middleware kullanılarak korunuyor
app.get('/admin', adminAuth, (req, res) => {
  res.render('admin', { users, userFiles });
});

// Belirli bir kullanıcının dosyalarını görüntüleme (JSON olarak)
app.get('/user/:id/files', (req, res) => {
  const userId = req.params.id;
  const files = userFiles[userId] || [];
  res.json(files); // Alternatif olarak EJS şablonunda render edilebilir
});

app.listen(PORT, () => {
  console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor...`);
});
