Inwit Tix - Digital Ticketing Platform

Inwit Tix is a full-featured, secure, and modern web application for event ticketing in Zambia. It provides a seamless experience for both ticket buyers and event organizers, from event creation and ticket sales to secure QR code scanning and real-time sales analytics.

This platform is built with a robust Python and Flask backend, a PostgreSQL database, and a clean, responsive user interface.

Key Features

The application is divided into three main user roles, each with a dedicated set of features:

For Ticket Buyers

Event Discovery: Browse a clean, modern interface of upcoming events.

Secure Registration: A straightforward, secure sign-up process with email activation.

Password Management: A complete "Forgot Password" flow for secure account recovery.

Easy Ticket Purchase: A simple and clear process for selecting and buying tickets.

Instant Ticket Access: Receive tickets instantly via email (as a PDF attachment) and access them anytime in the user profile section.

Digital Wallet: All purchased tickets are available in the "My Tickets" section of the user's profile for easy access.

For Event Organizers

Separate Registration Flow: A dedicated sign-up process for organizers, requiring company details for verification.

Admin Approval System: Organizer accounts are held in a pending state until manually approved by a site administrator, ensuring quality control.

Event Creation: An easy-to-use form to create new events, upload artwork, and set prices for different ticket tiers (e.g., Ordinary, VIP, VVIP).

Real-Time Sales Dashboard: A secure dashboard for each event showing:

Total revenue generated.

Total number of tickets sold.

A detailed breakdown of sales by ticket type.

A complete list of all registered attendees.

QR Code Scanner: A web-based scanner app for verifying tickets at the event entrance using a smartphone camera.

For Site Administrators

Secure Admin Role: A special user role that can be assigned via a command-line interface.

Organizer Approval Dashboard: A dedicated page to review and approve pending event organizer applications, giving admins full control over who can create events on the platform.

Technology Stack

Backend: Python with Flask

Database: PostgreSQL

Frontend: HTML5, CSS3 (with custom styling)

Security: Bcrypt for password hashing, Flask-Login for session management, Flask-Limiter for rate limiting.

Ticket Generation: WeasyPrint for creating PDF tickets.

Email: Flask-Mail for sending transactional emails (activations, password resets, tickets).

Deployment: Docker, Gunicorn, and Render.

Getting Started & Deployment

This application is designed for deployment on the Render platform using Docker. For full setup and deployment instructions, please see the Deployment Guide.
