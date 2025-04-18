# User Management System

A comprehensive user management system built with Spring Boot and MySQL that provides user authentication, profile management, and role-based access control.

## Features

- **User Authentication**
  - Registration with email verification
  - Login with email/phone + password
  - Two-factor authentication
  - JWT-based authentication
  - Session management
  - Password management (change, reset)

- **User Profile Management**
  - View and update profile information
  - Profile photo upload
  - Email and phone verification
  - Two-factor authentication setup

- **Role-Based Access Control (RBAC)**
  - Predefined roles (Admin, Moderator, User)
  - Permission-based access
  - Role assignment and management

- **Admin Features**
  - User management (search, filter, enable/disable)
  - Role management
  - Session management
  - Audit logs

## Technology Stack

- **Backend**: Spring Boot 3.x, Java 17
- **Security**: Spring Security, JWT
- **Database**: MySQL 8.x with JPA/Hibernate
- **Email**: Spring Mail with Thymeleaf templates
- **Validation**: Jakarta Bean Validation (JSR 380)
- **Build Tool**: Maven

## Getting Started

### Prerequisites

- JDK 17+
- MySQL 8.x
- Maven 3.x

### Configuration

1. Clone the repository
2. Update `application.yml` with your database and email settings:

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/userdb?createDatabaseIfNotExist=true
    username: your_username
    password: your_password
  mail:
    host: smtp.gmail.com
    port: 587
    username: your_email@gmail.com
    password: your_app_password
```

### Running the Application

```bash
mvn spring-boot:run
```

### Default Admin Account

On first startup, a default admin account is created:
- Email: admin@example.com
- Password: Admin@123

(Change this immediately in production)

## API Documentation

### Authentication Endpoints

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/verify-email` - Verify email
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password
- `POST /api/auth/refresh-token` - Refresh JWT token

### User Endpoints

- `GET /api/users/me` - Get current user profile
- `PUT /api/users/me` - Update profile
- `POST /api/users/me/change-password` - Change password
- `POST /api/users/me/photo` - Upload profile photo
- `DELETE /api/users/me/photo` - Delete profile photo
- `POST /api/users/2fa/enable` - Enable 2FA
- `POST /api/users/2fa/disable` - Disable 2FA

### Admin Endpoints

- `GET /api/admin/users` - Get all users
- `GET /api/admin/users/search` - Search users
- `GET /api/admin/users/{id}` - Get user by ID
- `PUT /api/admin/users/{id}/enable` - Enable user
- `PUT /api/admin/users/{id}/disable` - Disable user
- `DELETE /api/admin/users/{id}` - Delete user
- `POST /api/admin/users/{id}/roles` - Assign role
- `DELETE /api/admin/users/{id}/roles` - Remove role
- `GET /api/admin/users/{id}/roles` - Get user roles

## Security Considerations

- Passwords are hashed using BCrypt
- JWT tokens expire after 24 hours
- Refresh tokens expire after 7 days
- Email verification is required
- Two-factor authentication is supported
- Failed login attempts are logged

## License

This project is licensed under the MIT License - see the LICENSE file for details. 