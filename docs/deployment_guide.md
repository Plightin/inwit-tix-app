Deployment Guide for Inwit Tix

This application is designed to be deployed on Render using a Docker environment. This guide provides the complete, step-by-step process for a successful production deployment.

Prerequisites

A Render account.

A GitHub account with this project's code pushed to a repository.

A transactional email service provider (e.g., Postmark or SendGrid) to handle sending emails.

Step 1: Create the Database on Render

The application requires a PostgreSQL database. It is essential to create this manually in the Render dashboard before deploying the web service.

On your Render dashboard, click New + and select PostgreSQL.

Give it a unique Name (e.g., inwit-tix-db).

Select a paid plan (e.g., Starter). Free-tier databases are not suitable for this application as they spin down.

Click Create Database.

Once the database is ready, navigate to its page and copy the "Internal Connection String" from the "Connections" section. You will need this in the next step.

Step 2: Deploy the Web Service using a Blueprint

The render.yaml file in the repository defines the web service.

On your Render dashboard, click New + and select Blueprint.

Connect your GitHub repository. Render will automatically detect the render.yaml file.

On the configuration screen, find the inwit-tix-app service and navigate to its "Environment" section.

Click "Add Environment Variable" and create the following key-value pair:

Key: DATABASE_URL

Value: Paste the Internal Connection String you copied in Step 1.

Add the environment variables for your chosen email provider (e.g., MAIL_SERVER, MAIL_PASSWORD, etc.).

Click "Create New Services" to start the deployment.

Step 3: Manually Initialize the Database

After the first deployment is live, the application will show a server error. This is expected because the database tables have not been created yet.

On your Render dashboard, go to your inwit-tix-app web service.

Click on the "Shell" tab to open a live terminal.

In the shell prompt, run the following command and press Enter:

python -m flask init-db


You should see the output: Database initialized.

Step 4: Restart the Service

This final step restarts your application so it can connect to the now-prepared database.

Go back to your inwit-tix-app service page.

Click the "Manual Deploy" button.

From the dropdown menu, select "Restart service".

Your application is now fully deployed and functional.

Creating an Administrator

To manage organizer approvals, you must promote a user to the "admin" role.

Register a normal user account on your live website.

Connect to the Shell for your web service on Render.

Run the command: python -m flask make-admin "YourAdminUsername".

Log out of the website and then log back in with that same user. The "Admin" link will now be visible.
