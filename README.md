# 💰 Expense Tracker

A full-stack expense tracking application built with **Node.js**, **Express.js**, and **MongoDB**. The application allows users to manage their monthly budget, record daily expenses, and visualize spending through interactive charts.

## 📌 What This Project Does

This project allows users to:

- **Register and log in** securely using JWT authentication
- **Set a monthly budget** to track spending limits
- **Add expenses** with category, amount, date, and notes
- **View spending analytics** including total expenses and remaining budget
- **Visualize data** using category-wise pie charts and daily spending bar charts

---

## 🛠️ Tech Stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Node.js, Express.js
- **Database:** MongoDB (Mongoose)
- **Authentication:** JWT & bcrypt
- **Charts:** Chart.js

---

## ⚙️ How to Run

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/Expense-tracker.git
cd Expense-tracker
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Configure Environment Variables

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Add the following values:

```env
MONGO_URI=your_mongodb_connection_string
JWT_SECRET=your_secret_key
PORT=5000
```

### 4. Start the Server

```bash
npm start
```

Open your browser and visit:

```
http://localhost:5000
```

---

## 📂 Project Structure

```
Expense-tracker/
├── index.html
├── server.js
├── package.json
├── .env.example
├── .gitignore
└── README.md
```

---

## 📡 API Endpoints

| Method | Route |
|--------|-------|
| POST | `/api/auth/register` |
| POST | `/api/auth/login` |
| GET | `/api/me` |
| POST | `/api/budget` |
| POST | `/api/expenses` |
| GET | `/api/expenses` |
| GET | `/api/analytics` |

> **Note:** Protected routes require the header:
>
> `x-auth-token: <JWT_TOKEN>`

---

## 📄 License

This project was developed for learning and academic purposes.
