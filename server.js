const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Sequelize, DataTypes, Op } = require('sequelize');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'aurapharma_ultra_secure_secret_key_2026';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// الاتصال بقاعدة البيانات
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: path.join(__dirname, 'database.sqlite'),
  logging: false
});

/* ==========================================
   تعريف الجداول (Database Models)
   ========================================== */

const User = sequelize.define('User', {
  username: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.STRING, defaultValue: 'user' } // 'user' أو 'admin'
});

const Compound = sequelize.define('Compound', {
  name: { type: DataTypes.STRING, allowNull: false, unique: true },
  category: { type: DataTypes.STRING, allowNull: false },
  description: { type: DataTypes.TEXT, allowNull: false },
  price: { type: DataTypes.FLOAT, defaultValue: 0.0 },
  imageUrl: { type: DataTypes.STRING, allowNull: true }
});

const Consultation = sequelize.define('Consultation', {
  fullName: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false },
  organization: { type: DataTypes.STRING, allowNull: false },
  message: { type: DataTypes.TEXT, allowNull: false }
});

/* ==========================================
   دوال فحص وتنظيف المدخلات (Validation & Sanitization Helpers)
   ========================================== */

function validateEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(String(email).toLowerCase());
}

function cleanInput(text) {
  if (typeof text !== 'string') return '';
  // منع هجمات XSS الأساسية عبر استبدال وسوم HTML
  return text.replace(/</g, "&lt;").replace(/>/g, "&gt;").trim();
}

/* ==========================================
   برمجيات التحقق الوسطية (Authentication Middlewares)
   ========================================== */

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'الرجاء تسجيل الدخول للوصول إلى هذا المصدر' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'جلسة العمل منتهية أو غير صالحة' });
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'هذا الإجراء مخصص لمدير النظام فقط' });
  }
  next();
}

/* ==========================================
   نقاط اتصال الـ API (RESTful Endpoints)
   ========================================== */

// --- 1. نظام الحماية والتوثيق (Auth API) ---

// التسجيل
app.post('/api/auth/register', async (req, res) => {
  try {
    let { username, email, password } = req.body;
    username = cleanInput(username);
    email = cleanInput(email);

    // التحقق من المدخلات
    if (!username || username.length < 3) {
      return res.status(400).json({ error: 'يجب أن يكون اسم المستخدم 3 أحرف على الأقل' });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'بريد إلكتروني غير صالح' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'يجب أن تكون كلمة المرور 6 أحرف على الأقل' });
    }

    // التحقق من وجود الحساب مسبقاً
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'البريد الإلكتروني مسجل بالفعل' });
    }

    // تشفير كلمة المرور وحفظ الحساب
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      role: 'user' // المستخدمون الجدد يسجلون كـ user افتراضياً
    });

    return res.status(201).json({ message: 'تم إنشاء الحساب بنجاح' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'حدث خطأ أثناء معالجة طلبك' });
  }
});

// تسجيل الدخول وإصدار Token
app.post('/api/auth/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    email = cleanInput(email);

    if (!validateEmail(email) || !password) {
      return res.status(400).json({ error: 'يرجى تقديم بريد إلكتروني وكلمة مرور صالحة' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
    }

    // توليد الرمز
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    return res.json({
      message: 'تم تسجيل الدخول بنجاح',
      token,
      user: { username: user.username, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'حدث خطأ أثناء معالجة تسجيل الدخول' });
  }
});

// التحقق من صلاحية الجلسة الحالية وبينات المستخدم
app.get('/api/auth/me', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});


// --- 2. إدارة طلبات الاستشارات (Consultations API) ---

app.post('/api/consultations', async (req, res) => {
  try {
    let { fullName, email, organization, message } = req.body;
    fullName = cleanInput(fullName);
    email = cleanInput(email);
    organization = cleanInput(organization);
    message = cleanInput(message);

    if (!fullName || !email || !organization || !message) {
      return res.status(400).json({ error: 'جميع الحقول مطلوبة لإرسال الطلب' });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'البريد الإلكتروني المقدم غير صالح' });
    }

    const request = await Consultation.create({ fullName, email, organization, message });
    return res.status(201).json({ message: 'تم إرسال طلبك بنجاح', data: request });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'فشل إرسال الطلب، يرجى المحاولة لاحقاً' });
  }
});

// جلب الاستشارات (للمسؤول فقط)
app.get('/api/consultations', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const list = await Consultation.findAll({ order: [['createdAt', 'DESC']] });
    return res.json(list);
  } catch (error) {
    return res.status(500).json({ error: 'فشل جلب قائمة الطلبات' });
  }
});

// حذف استشارة (للمسؤول فقط)
app.delete('/api/consultations/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Consultation.destroy({ where: { id } });
    if (deleted) {
      return res.json({ message: 'تم حذف طلب الاستشارة بنجاح' });
    }
    return res.status(404).json({ error: 'الطلب غير موجود' });
  } catch (error) {
    return res.status(500).json({ error: 'فشل حذف الطلب' });
  }
});


// --- 3. إدارة المركبات الطبية (Compounds API) ---

app.get('/api/compounds', async (req, res) => {
  try {
    const { search } = req.query;
    let queryOptions = {};

    if (search) {
      const cleanSearch = cleanInput(search);
      queryOptions.where = {
        [Op.or]: [
          { name: { [Op.like]: `%${cleanSearch}%` } },
          { category: { [Op.like]: `%${cleanSearch}%` } },
          { description: { [Op.like]: `%${cleanSearch}%` } }
        ]
      };
    }

    const list = await Compound.findAll(queryOptions);
    return res.json(list);
  } catch (error) {
    return res.status(500).json({ error: 'فشل جلب المركبات الطبية' });
  }
});

// إضافة مركب (للمسؤول فقط)
app.post('/api/compounds', authenticateToken, requireAdmin, async (req, res) => {
  try {
    let { name, category, description, price, imageUrl } = req.body;
    name = cleanInput(name);
    category = cleanInput(category);
    description = cleanInput(description);
    imageUrl = cleanInput(imageUrl);

    const parsedPrice = parseFloat(price);
    if (isNaN(parsedPrice) || parsedPrice < 0) {
      return res.status(400).json({ error: 'السعر المقدم غير صالح' });
    }

    if (!name || !category || !description) {
      return res.status(400).json({ error: 'تأكد من ملء جميع تفاصيل المركب الجديد' });
    }

    const newComp = await Compound.create({ 
      name, 
      category, 
      description,
      price: parsedPrice,
      imageUrl: imageUrl || 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?auto=format&fit=crop&w=600&q=80'
    });
    return res.status(201).json(newComp);
  } catch (error) {
    return res.status(500).json({ error: 'فشل الإضافة، قد يكون المركب مسجل مسبقاً' });
  }
});

// حذف مركب (للمسؤول فقط)
app.delete('/api/compounds/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const deleted = await Compound.destroy({ where: { id } });
    if (deleted) {
      return res.json({ message: 'تم حذف المركب من السجل بنجاح' });
    }
    return res.status(404).json({ error: 'المركب غير موجود' });
  } catch (error) {
    return res.status(500).json({ error: 'فشل حذف المركب' });
  }
});


// --- 4. إدارة المستخدمين (للمسؤول فقط للوحة التحكم) ---
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'username', 'email', 'role', 'createdAt'],
      order: [['createdAt', 'DESC']]
    });
    return res.json(users);
  } catch (error) {
    return res.status(500).json({ error: 'فشل جلب قائمة المستخدمين' });
  }
});


/* ==========================================
   بدء الخادم وبذر حساب المسؤول الافتراضي
   ========================================== */
sequelize.sync({ alter: true }).then(async () => {
  console.log('Database Synced.');

  // بذر حساب مسؤول افتراضي إذا لم يتواجد أي مسؤول
  const adminExists = await User.findOne({ where: { role: 'admin' } });
  if (!adminExists) {
    const hashedAdminPassword = await bcrypt.hash('adminPassword123', 10);
    await User.create({
      username: 'System Admin',
      email: 'admin@aurapharma.com',
      password: hashedAdminPassword,
      role: 'admin'
    });
    console.log('====================================================');
    console.log('Admin account created successfully.');
    console.log('Email: admin@aurapharma.com');
    console.log('Password: adminPassword123');
    console.log('====================================================');
  }

  // بذر مركبات طبية كعرض منتجات افتراضي في حال كان الجدول فارغاً
  const compoundsCount = await Compound.count();
  if (compoundsCount === 0) {
    await Compound.bulkCreate([
      {
        name: 'Aura-Amoxicillin 500mg',
        category: 'Antibiotic / Therapeutic',
        description: 'Broad-spectrum bactericidal antibiotic of the aminopenicillin family. Structured to demonstrate exceptional biological absorption, targeted action, and structural stability across complex cellular systems.',
        price: 45.99,
        imageUrl: 'https://images.unsplash.com/photo-1584308666744-24d5c474f2ae?auto=format&fit=crop&w=600&q=80'
      },
      {
        name: 'Aura-Metformin XR 1000mg',
        category: 'Metabolic Regulator',
        description: 'Extended-release metabolic regulator engineered to assist glycemic control. Helps control hepatic glucose production while safely improving peripheral insulin sensitivity indices.',
        price: 29.50,
        imageUrl: 'https://images.unsplash.com/photo-1471864190281-a93a3070b6de?auto=format&fit=crop&w=600&q=80'
      },
      {
        name: 'Aura-Atorvastatin Bio',
        category: 'Cardiovascular / Lipid agent',
        description: 'Pure synthetic lipid modulator developed for effective HMG-CoA reductase pathway restriction. Provides consistent stabilization profiles for patients requiring long-term cardiovascular monitoring.',
        price: 64.00,
        imageUrl: 'https://images.unsplash.com/photo-1576091160550-2173dba999ef?auto=format&fit=crop&w=600&q=80'
      }
    ]);
    console.log('Seed: Default products populated successfully.');
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
  });
});
