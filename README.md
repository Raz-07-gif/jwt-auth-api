# JWT Authentication API

A simple, secure user authentication system built with Flask and JWT. This API provides routes for user registration, login, logout, access token refresh, and a protected profile endpoint.

---

## 🔐 Features

- User registration with hashed passwords
- Login with JWT-based access and refresh tokens
- Logout with token blacklisting
- Refresh token support to issue new access tokens
- Protected route (`/profile`) for authenticated users
- SQLite database for user storage

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/Raz-07-gif/jwt-auth-api.git

cd jwt-auth-api
2. Install Dependencies
We recommend using a virtual environment.

bash

pip install -r requirements.txt

3. Run the App

bash

python app.py
🔧 API Endpoints
Method	Route	Description
POST	/register	Register a new user
POST	/login	Login and receive access + refresh tokens
GET	/profile	Access protected user info (access token required)
POST	/logout	Log out and revoke token
POST	/refresh	Get a new access token using a refresh token

🧪 Testing with Postman
Register a user with /register

Login via /login to receive your tokens

Use the access token to hit /profile

Use the refresh token to get a new access token via /refresh

Use /logout to invalidate the current token

📁 File Structure
├── app_jwt.py
├── requirements.txt
└── README.md


📜LICENSE
This project is licensed under the MIT License.
🤝 Contributions
Pull requests are welcome. If you find a bug or want to improve something, feel free to open an issue or submit a PR.

sql

---

📄 `LICENSE` (MIT License)
MIT License

Copyright (c) 2025 Raz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell     
copies of the Software, and to permit persons to whom the Software is         
furnished to do so, subject to the following conditions:                       

The above copyright notice and this permission notice shall be included in    
all copies or substantial portions of the Software.                           

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN     
THE SOFTWARE.

