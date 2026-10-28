require("dotenv").config();

const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const MONGO_URI =
  process.env.MONGO_URI || "mongodb://127.0.0.1:27017";
const DB_NAME =
  process.env.DB_NAME || "online_examination_system";
const SESSION_SECRET =
  process.env.SESSION_SECRET || "replace-this-with-a-long-random-secret";

const client = new MongoClient(MONGO_URI);
let db;

app.use(express.json({ limit: "1mb" }));

app.use(
  session({
    name: "oes.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 8 * 60 * 60 * 1000
    }
  })
);

app.use(express.static(path.join(__dirname)));

const cleanUser = (user) => ({
  id: String(user._id),
  name: user.name || "",
  email: user.email || "",
  role: user.role || "Student",
  rollNumber: user.rollNumber || "",
  contactNumber: user.contactNumber || ""
});

const isAdmin = (req) =>
  req.session.user &&
  String(req.session.user.role).toLowerCase() === "admin";

const requireLogin = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({
      success: false,
      message: "Please log in first."
    });
  }

  next();
};

const requireAdmin = (req, res, next) => {
  if (!isAdmin(req)) {
    return res.status(403).json({
      success: false,
      message: "Administrator access required."
    });
  }

  next();
};

const asObjectId = (value) =>
  ObjectId.isValid(String(value))
    ? new ObjectId(String(value))
    : null;

const normaliseEmail = (email) =>
  String(email || "").trim().toLowerCase();

const publicQuestion = (question) => ({
  _id: String(question._id),
  courseCode: question.courseCode,
  question: question.question,
  options: question.options,
  marks: Number(question.marks || 1)
});

// --------------------------------------------------
// HOME AND HEALTH
// --------------------------------------------------

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    database: DB_NAME,
    connected: Boolean(db)
  });
});

// --------------------------------------------------
// CURRENT USER
// --------------------------------------------------

app.get("/api/me", (req, res) => {
  res.json({
    success: Boolean(req.session.user),
    user: req.session.user || null
  });
});

// --------------------------------------------------
// STUDENT REGISTRATION
// --------------------------------------------------

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const rollNumber = String(req.body.rollNumber || "").trim();
    const contactNumber = String(req.body.contactNumber || "").trim();
    const email = normaliseEmail(req.body.email);
    const password = String(req.body.password || "");

    if (
      !name ||
      !rollNumber ||
      !contactNumber ||
      !email ||
      !password
    ) {
      return res.status(400).json({
        success: false,
        message: "All fields are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    const existing = await db.collection("users").findOne({
      $or: [{ email }, { rollNumber }]
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "Email or roll number is already registered."
      });
    }

    const user = {
      name,
      rollNumber,
      contactNumber,
      email,
      password: await bcrypt.hash(password, 12),
      role: "Student",
      createdAt: new Date()
    };

    const result = await db.collection("users").insertOne(user);

    req.session.user = cleanUser({
      ...user,
      _id: result.insertedId
    });

    res.status(201).json({
      success: true,
      message: "Registration successful.",
      user: req.session.user
    });
  } catch (error) {
    console.error("Registration error:", error);

    res.status(500).json({
      success: false,
      message: "Registration failed due to a server error."
    });
  }
});

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post("/api/login", async (req, res) => {
  try {
    const email = normaliseEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required."
      });
    }

    const user = await db.collection("users").findOne({ email });

    if (!user || !user.password) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    let passwordMatch = false;

    if (String(user.password).startsWith("$2")) {
      passwordMatch = await bcrypt.compare(
        password,
        user.password
      );
    } else if (user.password === password) {
      // Migrate an old plain-text development password to a hash.
      passwordMatch = true;

      await db.collection("users").updateOne(
        { _id: user._id },
        {
          $set: {
            password: await bcrypt.hash(password, 12)
          }
        }
      );
    }

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    req.session.user = cleanUser(user);

    res.json({
      success: true,
      message: "Login successful.",
      user: req.session.user
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      success: false,
      message: "Login failed due to a server error."
    });
  }
});

// --------------------------------------------------
// PROFILE: VIEW AND CUSTOMIZE
// --------------------------------------------------

app.get("/api/profile", requireLogin, async (req, res) => {
  try {
    const userId = asObjectId(req.session.user.id);

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "Invalid user account."
      });
    }

    const user = await db.collection("users").findOne(
      { _id: userId },
      { projection: { password: 0 } }
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User account not found."
      });
    }

    res.json({
      success: true,
      user: cleanUser(user)
    });
  } catch (error) {
    console.error("Profile fetch error:", error);

    res.status(500).json({
      success: false,
      message: "Could not load profile."
    });
  }
});

// Update the current user's profile.
app.put("/api/profile", requireLogin, async (req, res) => {
  try {
    const userId = asObjectId(req.session.user.id);

    if (!userId) {
      return res.status(400).json({
        success: false,
        message: "Invalid user account."
      });
    }

    const name = String(req.body.name || "").trim();
    const email = normaliseEmail(req.body.email);
    const contactNumber = String(
      req.body.contactNumber || ""
    ).trim();

    if (!name || !email) {
      return res.status(400).json({
        success: false,
        message: "Name and email are required."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid email address."
      });
    }

    const duplicateEmail = await db.collection("users").findOne({
      email,
      _id: { $ne: userId }
    });

    if (duplicateEmail) {
      return res.status(409).json({
        success: false,
        message: "That email address is already in use."
      });
    }

    const updates = {
      name,
      email,
      contactNumber,
      updatedAt: new Date()
    };

    // Students can update their roll number.
    // Admin accounts do not need a student roll number.
    if (!isAdmin(req)) {
      const rollNumber = String(
        req.body.rollNumber || ""
      ).trim();

      if (!rollNumber) {
        return res.status(400).json({
          success: false,
          message: "Roll number is required."
        });
      }

      const duplicateRoll = await db.collection("users").findOne({
        rollNumber,
        _id: { $ne: userId }
      });

      if (duplicateRoll) {
        return res.status(409).json({
          success: false,
          message: "That roll number is already in use."
        });
      }

      updates.rollNumber = rollNumber;
    }

    await db.collection("users").updateOne(
      { _id: userId },
      { $set: updates }
    );

    const updatedUser = await db.collection("users").findOne({
      _id: userId
    });

    req.session.user = cleanUser(updatedUser);

    res.json({
      success: true,
      message: "Profile updated successfully.",
      user: req.session.user
    });
  } catch (error) {
    console.error("Profile update error:", error);

    res.status(500).json({
      success: false,
      message: "Could not update profile."
    });
  }
});

// --------------------------------------------------
// CHANGE PASSWORD
// --------------------------------------------------

app.put(
  "/api/profile/password",
  requireLogin,
  async (req, res) => {
    try {
      const currentPassword = String(
        req.body.currentPassword || ""
      );

      const newPassword = String(
        req.body.newPassword || ""
      );

      if (!currentPassword || newPassword.length < 8) {
        return res.status(400).json({
          success: false,
          message:
            "Enter your current password and a new password of at least 8 characters."
        });
      }

      const userId = asObjectId(req.session.user.id);

      const user = userId
        ? await db.collection("users").findOne({
            _id: userId
          })
        : null;

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User account not found."
        });
      }

      const matches = String(user.password || "").startsWith("$2")
        ? await bcrypt.compare(currentPassword, user.password)
        : user.password === currentPassword;

      if (!matches) {
        return res.status(401).json({
          success: false,
          message: "Current password is incorrect."
        });
      }

      await db.collection("users").updateOne(
        { _id: userId },
        {
          $set: {
            password: await bcrypt.hash(newPassword, 12),
            updatedAt: new Date()
          }
        }
      );

      res.json({
        success: true,
        message: "Password updated successfully."
      });
    } catch (error) {
      console.error("Password update error:", error);

      res.status(500).json({
        success: false,
        message: "Could not update password."
      });
    }
  }
);

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

app.post("/api/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        success: false,
        message: "Could not log out."
      });
    }

    res.clearCookie("oes.sid");

    res.json({
      success: true,
      message: "Logged out successfully."
    });
  });
});

// --------------------------------------------------
// USER MANAGEMENT: ADMIN ONLY
// --------------------------------------------------

app.get(
  "/api/users",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const users = await db
        .collection("users")
        .find({}, { projection: { password: 0 } })
        .sort({ name: 1 })
        .toArray();

      res.json(
        users.map((user) => ({
          ...user,
          _id: String(user._id)
        }))
      );
    } catch (error) {
      console.error("Users error:", error);

      res.status(500).json({
        success: false,
        message: "Could not retrieve users."
      });
    }
  }
);

// --------------------------------------------------
// SUBJECTS / COURSES
// --------------------------------------------------

app.get("/api/courses", requireLogin, async (req, res) => {
  try {
    const courses = await db
      .collection("courses")
      .find()
      .sort({ courseCode: 1 })
      .toArray();

    res.json(
      courses.map((course) => ({
        ...course,
        _id: String(course._id)
      }))
    );
  } catch (error) {
    console.error("Courses error:", error);

    res.status(500).json({
      success: false,
      message: "Could not retrieve subjects."
    });
  }
});

app.post(
  "/api/courses",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const courseCode = String(
        req.body.courseCode || ""
      ).trim().toUpperCase();

      const courseName = String(
        req.body.courseName || ""
      ).trim();

      const description = String(
        req.body.description || ""
      ).trim();

      if (!courseCode || !courseName) {
        return res.status(400).json({
          success: false,
          message: "Subject code and name are required."
        });
      }

      const existing = await db.collection("courses").findOne({
        courseCode
      });

      if (existing) {
        return res.status(409).json({
          success: false,
          message: "That subject code already exists."
        });
      }

      await db.collection("courses").insertOne({
        courseCode,
        courseName,
        description,
        createdAt: new Date()
      });

      res.status(201).json({
        success: true,
        message: "Subject added successfully."
      });
    } catch (error) {
      console.error("Add course error:", error);

      res.status(500).json({
        success: false,
        message: "Could not add subject."
      });
    }
  }
);

// --------------------------------------------------
// QUESTION BANK
// --------------------------------------------------

// Students may retrieve questions, but correct answers are hidden.
app.get("/api/questions", requireLogin, async (req, res) => {
  try {
    const questions = await db
      .collection("questions")
      .find()
      .sort({ courseCode: 1, createdAt: -1 })
      .toArray();

    res.json(
      questions.map((question) => {
        const output = {
          ...question,
          _id: String(question._id)
        };

        if (!isAdmin(req)) {
          delete output.correctAnswer;
          delete output.correctOption;
        }

        return output;
      })
    );
  } catch (error) {
    console.error("Questions error:", error);

    res.status(500).json({
      success: false,
      message: "Could not retrieve questions."
    });
  }
});

app.post(
  "/api/questions",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const courseCode = String(
        req.body.courseCode || ""
      ).trim().toUpperCase();

      const question = String(
        req.body.question || ""
      ).trim();

      const options = Array.isArray(req.body.options)
        ? req.body.options.map((option) => String(option).trim())
        : [];

      const correctOption = String(
        req.body.correctOption || ""
      ).trim().toUpperCase();

      const correctAnswer = String(
        req.body.correctAnswer || ""
      ).trim();

      const marks = Number(req.body.marks || 1);

      if (
        !courseCode ||
        !question ||
        options.length !== 4 ||
        options.some((option) => !option) ||
        !correctAnswer ||
        !["A", "B", "C", "D"].includes(correctOption) ||
        !Number.isFinite(marks) ||
        marks < 1
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter a subject, question, four options, correct answer, and valid marks."
        });
      }

      await db.collection("questions").insertOne({
        courseCode,
        question,
        options,
        correctAnswer,
        correctOption,
        marks,
        createdAt: new Date(),
        createdBy: req.session.user.id
      });

      res.status(201).json({
        success: true,
        message: "Question saved successfully."
      });
    } catch (error) {
      console.error("Add question error:", error);

      res.status(500).json({
        success: false,
        message: "Could not save question."
      });
    }
  }
);

app.put(
  "/api/questions/:id",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const _id = asObjectId(req.params.id);

      if (!_id) {
        return res.status(400).json({
          success: false,
          message: "Invalid question ID."
        });
      }

      const courseCode = String(
        req.body.courseCode || ""
      ).trim().toUpperCase();

      const question = String(
        req.body.question || ""
      ).trim();

      const options = Array.isArray(req.body.options)
        ? req.body.options.map((option) => String(option).trim())
        : [];

      const correctOption = String(
        req.body.correctOption || ""
      ).trim().toUpperCase();

      const correctAnswer = String(
        req.body.correctAnswer || ""
      ).trim();

      const marks = Number(req.body.marks || 1);

      if (
        !courseCode ||
        !question ||
        options.length !== 4 ||
        options.some((option) => !option) ||
        !correctAnswer ||
        !["A", "B", "C", "D"].includes(correctOption) ||
        !Number.isFinite(marks) ||
        marks < 1
      ) {
        return res.status(400).json({
          success: false,
          message: "Please complete all question fields."
        });
      }

      const result = await db.collection("questions").updateOne(
        { _id },
        {
          $set: {
            courseCode,
            question,
            options,
            correctAnswer,
            correctOption,
            marks,
            updatedAt: new Date()
          }
        }
      );

      if (!result.matchedCount) {
        return res.status(404).json({
          success: false,
          message: "Question not found."
        });
      }

      res.json({
        success: true,
        message: "Question updated successfully."
      });
    } catch (error) {
      console.error("Update question error:", error);

      res.status(500).json({
        success: false,
        message: "Could not update question."
      });
    }
  }
);

app.delete(
  "/api/questions/:id",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const _id = asObjectId(req.params.id);

      if (!_id) {
        return res.status(400).json({
          success: false,
          message: "Invalid question ID."
        });
      }

      const result = await db.collection("questions").deleteOne({
        _id
      });

      if (!result.deletedCount) {
        return res.status(404).json({
          success: false,
          message: "Question not found."
        });
      }

      res.json({
        success: true,
        message: "Question deleted successfully."
      });
    } catch (error) {
      console.error("Delete question error:", error);

      res.status(500).json({
        success: false,
        message: "Could not delete question."
      });
    }
  }
);

// --------------------------------------------------
// EXAMINATION MANAGEMENT
// --------------------------------------------------

app.get("/api/exams", requireLogin, async (req, res) => {
  try {
    const exams = await db
      .collection("exams")
      .find()
      .sort({ createdAt: -1 })
      .toArray();

    const studentId = req.session.user.id;

    const formattedExams = await Promise.all(
      exams.map(async (exam) => {
        const output = {
          ...exam,
          _id: String(exam._id)
        };

        if (!isAdmin(req)) {
          const result = await db.collection("results").findOne({
            examId: exam._id,
            studentId
          });

          output.completed = Boolean(result);
        }

        return output;
      })
    );

    res.json(formattedExams);
  } catch (error) {
    console.error("Exams error:", error);

    res.status(500).json({
      success: false,
      message: "Could not retrieve examinations."
    });
  }
});

app.post(
  "/api/exams",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const examName = String(
        req.body.examName || ""
      ).trim();

      const courseCode = String(
        req.body.courseCode || ""
      ).trim().toUpperCase();

      const duration = Number(req.body.duration);
      const questionCount = Number(req.body.questionCount);

      const startTime = req.body.startTime
        ? new Date(req.body.startTime)
        : null;

      if (
        !examName ||
        !courseCode ||
        !Number.isInteger(duration) ||
        duration < 1 ||
        duration > 300 ||
        !Number.isInteger(questionCount) ||
        questionCount < 1
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Enter an exam name, subject, valid duration and question count."
        });
      }

      if (startTime && Number.isNaN(startTime.getTime())) {
        return res.status(400).json({
          success: false,
          message: "Enter a valid examination start time."
        });
      }

      const available = await db.collection("questions").countDocuments({
        courseCode
      });

      if (available < questionCount) {
        return res.status(400).json({
          success: false,
          message: `This subject has only ${available} question(s). Add more questions or reduce the question count.`
        });
      }

      // Randomly choose the questions for this exam.
      const questionDocs = await db
        .collection("questions")
        .aggregate([
          { $match: { courseCode } },
          { $sample: { size: questionCount } },
          { $project: { _id: 1 } }
        ])
        .toArray();

      const exam = {
        examName,
        courseCode,
        duration,
        questionCount,
        questionIds: questionDocs.map((question) => question._id),
        startTime,
        createdAt: new Date(),
        createdBy: req.session.user.id
      };

      const result = await db.collection("exams").insertOne(exam);

      res.status(201).json({
        success: true,
        message: "Examination created successfully.",
        examId: String(result.insertedId)
      });
    } catch (error) {
      console.error("Create exam error:", error);

      res.status(500).json({
        success: false,
        message: "Could not create examination."
      });
    }
  }
);

// --------------------------------------------------
// GET EXAM QUESTIONS
// Each student gets a persisted randomized order.
// --------------------------------------------------

app.get(
  "/api/exams/:id/questions",
  requireLogin,
  async (req, res) => {
    try {
      const examId = asObjectId(req.params.id);

      if (!examId) {
        return res.status(400).json({
          success: false,
          message: "Invalid examination ID."
        });
      }

      const exam = await db.collection("exams").findOne({
        _id: examId
      });

      if (!exam) {
        return res.status(404).json({
          success: false,
          message: "Examination not found."
        });
      }

      if (
        exam.startTime &&
        new Date(exam.startTime).getTime() > Date.now()
      ) {
        return res.status(403).json({
          success: false,
          message: "This examination has not started yet."
        });
      }

      const studentId = req.session.user.id;

      const existingResult = await db.collection("results").findOne({
        examId,
        studentId
      });

      if (existingResult) {
        return res.status(409).json({
          success: false,
          message: "You have already submitted this examination."
        });
      }

      const responses = db.collection("responses");

      let response = await responses.findOne({
        examId,
        studentId
      });

      let questionOrder = response?.questionOrder;
      const now = new Date();

      // Create one stable shuffled question order and one server-side deadline
      // per student/exam. Refreshing the page will not reshuffle or reset time.
      if (
        !Array.isArray(questionOrder) ||
        questionOrder.length !== (exam.questionIds || []).length
      ) {
        questionOrder = [...(exam.questionIds || [])];
        for (let i = questionOrder.length - 1; i > 0; i--) {
          const j = Math.floor(Math.random() * (i + 1));
          [questionOrder[i], questionOrder[j]] = [questionOrder[j], questionOrder[i]];
        }
      }

      const startedAt = response?.startedAt || now;
      const expiresAt = response?.expiresAt || new Date(startedAt.getTime() + Number(exam.duration || 30) * 60000);
      await responses.updateOne(
        { examId, studentId },
        {
          $set: { questionOrder, startedAt, expiresAt, updatedAt: now },
          $setOnInsert: { answers: {}, submitted: false }
        },
        { upsert: true }
      );
      response = await responses.findOne({ examId, studentId });

      const objectIds = questionOrder
        .map(asObjectId)
        .filter(Boolean);

      const docs = await db.collection("questions")
        .find({ _id: { $in: objectIds } })
        .toArray();

      const byId = new Map(
        docs.map((question) => [
          String(question._id),
          question
        ])
      );

      const orderedQuestions = questionOrder
        .map((id) => byId.get(String(id)))
        .filter(Boolean);

      res.json({
        questions: orderedQuestions.map(publicQuestion),
        duration: exam.duration,
        examName: exam.examName,
        savedAnswers: response?.answers || {},
        startedAt: response?.startedAt,
        expiresAt: response?.expiresAt,
        remainingSeconds: Math.max(0, Math.ceil((new Date(response?.expiresAt || Date.now()).getTime() - Date.now()) / 1000))
      });
    } catch (error) {
      console.error("Get exam questions error:", error);

      res.status(500).json({
        success: false,
        message: "Could not load examination questions."
      });
    }
  }
);

// --------------------------------------------------
// SAVE ANSWERS BEFORE SUBMISSION
// --------------------------------------------------

app.post(
  "/api/responses/save",
  requireLogin,
  async (req, res) => {
    try {
      const examId = asObjectId(req.body.examId);

      if (!examId) {
        return res.status(400).json({
          success: false,
          message: "Invalid examination ID."
        });
      }

      const exam = await db.collection("exams").findOne({
        _id: examId
      });

      if (!exam) {
        return res.status(404).json({
          success: false,
          message: "Examination not found."
        });
      }

      const studentId = req.session.user.id;

      const existingResult = await db.collection("results").findOne({
        examId,
        studentId
      });

      if (existingResult) {
        return res.status(409).json({
          success: false,
          message: "This examination has already been submitted."
        });
      }

      const answers =
        req.body.answers &&
        typeof req.body.answers === "object" &&
        !Array.isArray(req.body.answers)
          ? req.body.answers
          : {};

      const response = await db.collection("responses").findOne({ examId, studentId });

      if (response?.expiresAt && new Date(response.expiresAt).getTime() <= Date.now()) {
        return res.status(409).json({ success: false, message: "Time has expired. Submit the examination now." });
      }

      if (response?.submitted) {
        return res.status(409).json({
          success: false,
          message: "This examination has already been submitted."
        });
      }

      const allowedQuestionIds = new Set((exam.questionIds || []).map(String));
      const cleanAnswers = {};
      for (const [questionId, answer] of Object.entries(answers)) {
        if (allowedQuestionIds.has(String(questionId)) && typeof answer === "string") {
          cleanAnswers[questionId] = answer;
        }
      }

      await db.collection("responses").updateOne(
        { examId, studentId, submitted: { $ne: true } },
        { $set: { answers: cleanAnswers, updatedAt: new Date(), submitted: false } },
        { upsert: true }
      );

      res.json({
        success: true,
        message: "Answers saved successfully."
      });
    } catch (error) {
      console.error("Save answers error:", error);

      res.status(500).json({
        success: false,
        message: "Could not save answers."
      });
    }
  }
);

// --------------------------------------------------
// SUBMIT EXAM AND AUTOMATICALLY EVALUATE
// --------------------------------------------------

app.post(
  "/api/exams/:id/submit",
  requireLogin,
  async (req, res) => {
    try {
      const examId = asObjectId(req.params.id);

      if (!examId) {
        return res.status(400).json({
          success: false,
          message: "Invalid examination ID."
        });
      }

      const exam = await db.collection("exams").findOne({
        _id: examId
      });

      if (!exam) {
        return res.status(404).json({
          success: false,
          message: "Examination not found."
        });
      }

      const studentId = req.session.user.id;

      const existingResult = await db.collection("results").findOne({
        examId,
        studentId
      });

      if (existingResult) {
        return res.status(409).json({
          success: false,
          message: "This examination has already been submitted."
        });
      }

      const saved = await db.collection("responses").findOne({
        examId,
        studentId
      });

      if (saved?.submitted) {
        return res.status(409).json({
          success: false,
          message: "This examination has already been submitted."
        });
      }

      const submittedAnswers =
        req.body.answers && typeof req.body.answers === "object" && !Array.isArray(req.body.answers)
          ? req.body.answers : {};
      const allowedQuestionIds = new Set((exam.questionIds || []).map(String));
      const answers = { ...(saved?.answers || {}) };
      // Submitted selections are accepted only for questions belonging to this exam.
      for (const [questionId, answer] of Object.entries(submittedAnswers)) {
        if (allowedQuestionIds.has(String(questionId)) && typeof answer === "string") {
          answers[questionId] = answer;
        }
      }
      const timedOut = Boolean(saved?.expiresAt && new Date(saved.expiresAt).getTime() <= Date.now());

      const questions = await db.collection("questions")
        .find({
          _id: { $in: exam.questionIds || [] }
        })
        .toArray();

      let marksObtained = 0;
      let totalMarks = 0;
      let correctCount = 0;
      let wrongCount = 0;
      let skippedCount = 0;

      for (const question of questions) {
        const marks = Number(question.marks || 1);
        totalMarks += marks;

        const answer = answers[String(question._id)];

        if (
          answer === undefined ||
          answer === null ||
          String(answer).trim() === ""
        ) {
          skippedCount++;
        } else if (
          String(answer) === String(question.correctAnswer)
        ) {
          correctCount++;
          marksObtained += marks;
        } else {
          wrongCount++;
        }
      }

      const attemptedCount = correctCount + wrongCount;

      const userId = asObjectId(studentId);

      const user = userId
        ? await db.collection("users").findOne({
            _id: userId
          })
        : null;

      const percentage = totalMarks > 0
        ? Number(((marksObtained / totalMarks) * 100).toFixed(2))
        : 0;

      const resultDoc = {
        examId,
        examName: exam.examName,
        courseCode: exam.courseCode,
        studentId,
        studentName: user?.name || req.session.user.name,
        rollNumber:
          user?.rollNumber ||
          req.session.user.rollNumber ||
          "",
        marksObtained,
        totalMarks,
        percentage,
        correctCount,
        wrongCount,
        skippedCount,
        attemptedCount,
        totalQuestions: questions.length,
        automatic: Boolean(req.body.automatic) || timedOut,
        submittedAt: new Date()
      };

      // Unique index on examId + studentId prevents duplicate results.
      await db.collection("results").insertOne(resultDoc);

      await db.collection("responses").updateOne(
        { examId, studentId },
        {
          $set: {
            answers,
            submitted: true,
            submittedAt: new Date()
          },
          $setOnInsert: {
            questionOrder: exam.questionIds || []
          }
        },
        { upsert: true }
      );

      res.json({
        success: true,
        message: "Examination submitted and evaluated.",
        result: {
          ...resultDoc,
          examId: String(examId)
        }
      });
    } catch (error) {
      console.error("Submit examination error:", error);

      if (error.code === 11000) {
        return res.status(409).json({
          success: false,
          message: "This examination has already been submitted."
        });
      }

      res.status(500).json({
        success: false,
        message: "Could not submit examination."
      });
    }
  }
);

// --------------------------------------------------
// RESULTS: ADMIN SEES ALL RESULTS
// --------------------------------------------------

app.get(
  "/api/results",
  requireLogin,
  requireAdmin,
  async (req, res) => {
    try {
      const results = await db.collection("results")
        .find()
        .sort({
          marksObtained: -1,
          submittedAt: 1
        })
        .toArray();

      res.json(
        results.map((result) => ({
          ...result,
          _id: String(result._id),
          examId: String(result.examId)
        }))
      );
    } catch (error) {
      console.error("Results error:", error);

      res.status(500).json({
        success: false,
        message: "Could not retrieve results."
      });
    }
  }
);

// --------------------------------------------------
// RESULTS: STUDENTS SEE THEIR OWN RESULTS
// --------------------------------------------------

app.get(
  "/api/results/mine",
  requireLogin,
  async (req, res) => {
    try {
      const results = await db.collection("results")
        .find({
          studentId: req.session.user.id
        })
        .sort({
          submittedAt: -1
        })
        .toArray();

      res.json(
        results.map((result) => ({
          ...result,
          _id: String(result._id),
          examId: String(result.examId)
        }))
      );
    } catch (error) {
      console.error("My results error:", error);

      res.status(500).json({
        success: false,
        message: "Could not retrieve your results."
      });
    }
  }
);

// --------------------------------------------------
// START SERVER AND CONNECT TO MONGODB
// --------------------------------------------------

async function start() {
  try {
    await client.connect();

    db = client.db(DB_NAME);

    await db.collection("users").createIndex(
      { email: 1 },
      { unique: true }
    );

    await db.collection("users").createIndex(
      { rollNumber: 1 },
      { unique: true, sparse: true }
    );

    await db.collection("courses").createIndex(
      { courseCode: 1 },
      { unique: true }
    );

    await db.collection("responses").createIndex(
      { examId: 1, studentId: 1 },
      { unique: true }
    );

    await db.collection("results").createIndex(
      { examId: 1, studentId: 1 },
      { unique: true }
    );

    app.listen(PORT, () => {
      console.log("MongoDB connected successfully!");
      console.log("Database:", DB_NAME);
      console.log(
        `Online Examination System running at http://localhost:${PORT}`
      );
    });
  } catch (error) {
    console.error("Startup failed:", error);
    process.exit(1);
  }
}

process.on("SIGINT", async () => {
  await client.close();
  process.exit(0);
});

start();