Inwit Tix User Guide

Welcome to the Inwit Tix platform! This guide provides a complete overview of how to use the application, whether you are buying tickets, organizing an event, or administering the site.

For Ticket Buyers

1. Creating Your Account

Choose Your Role: On the main registration page, select the option to "Buy Tickets".

Fill Out Your Details: Complete the simple sign-up form. We require a username, a valid email address, and a secure password.

Activate Your Email: After registering, you will receive an email with an activation link. You must click this link to confirm your email and activate your account before you can log in.

2. Finding and Purchasing Tickets

Browse Events: The homepage displays all upcoming events. You can browse them to find something that interests you.

View Details: Click "View Details & Buy Ticket" on any event card to see more information, including a detailed description, venue, and all available ticket prices.

Purchase a Ticket: On the event detail page, select your desired ticket type (e.g., Ordinary, VIP) and click "Buy Ticket".

3. Accessing Your Ticket

Once your purchase is complete, your ticket is immediately available in three ways:

On-Screen: You'll be redirected to a page displaying your digital ticket with its unique QR code.

Via Email: A confirmation email will be sent to you with a PDF version of your ticket attached.

In Your Profile: You can access all your purchased tickets at any time by logging in and clicking "My Profile". From there, you can view, download the PDF, or resend the ticket to your email.

For Event Organizers

1. Creating an Organizer Account

Choose Your Role: On the registration page, select the option to "Organize Events".

Submit Your Application: You must fill out the form with your name or company name, a valid contact email, a phone number, and details about your organization.

Activate & Wait for Approval:

First, you must click the activation link sent to your email.

After your email is confirmed, your application will be placed in a queue for review by a site administrator.

You will not be able to create events until your account is approved.

2. Creating an Event

Access the Form: Once your organizer account is approved, the "Create Event" link will appear in the navigation bar when you are logged in.

Fill Out Event Details: Complete the form with all the required information, including the event name, a detailed description, the venue, date, time, and promotional artwork.

Set Ticket Prices: Enter the price for each ticket tier you wish to offer (Ordinary, VIP, VVIP). If you leave a price blank, that ticket type will not be shown for sale.

3. The Organizer Dashboard

Access: Go to your "My Profile" page. Next to each event you have created, there will be a "View Dashboard" button.

Key Insights: The dashboard provides a real-time overview of your event's performance, including:

Total revenue generated.

Total number of tickets sold.

A breakdown of sales by each ticket type.

A complete list of all registered attendees with their names and email addresses.

4. Scanning Tickets at Your Event

Access: Log in to your approved organizer account on a smartphone and click the "Scan Ticket" link in the navigation.

How it Works: The scanner app uses your phone's camera to read the QR code on a user's ticket (either on their phone or a printout). It provides instant feedback:

Success: The ticket is valid.

Warning: The ticket is valid but has already been scanned.

Danger: The ticket is invalid or does not belong to your event.

Security: Only the user who created an event is authorized to scan tickets for that event.

For Site Administrators

1. Becoming an Administrator

Register a User: First, create a regular user account through the website (a "Buyer" account is fine).

Connect to the Shell: Log in to your Render dashboard, go to your web service, and open the "Shell" tab.

Run the Command: Execute the command python -m flask make-admin "YourUsername", replacing "YourUsername" with the exact, case-sensitive username you want to promote.

2. Approving Organizers

Access: After logging in as an admin, an "Admin" link will appear in your navigation bar. Click it to go to the admin dashboard.

View & Approve: Click "View Organizer Approvals" to see a list of pending applications. Review the details provided by the applicant and click "Approve" to grant them the ability to create events.
