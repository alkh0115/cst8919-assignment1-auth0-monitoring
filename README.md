# CST8919 - Assignment1: Securing and Monitoring an Authenticated Flask App

## Setup Instructions

### 1. Auth0 Configuration

1. Sign in to the [Auth0 Dashboard](https://manage.auth0.com/)
2. Use the existing **Regular Web Application**.
   - Configure the following:
     - Callback URL: `https://rahaf-auth0-app-1751775775.azurewebsites.net/callback`
     - Logout URL: `https://rahaf-auth0-app-1751775775.azurewebsites.net`
     - Web Origin: `https://rahaf-auth0-app-1751775775.azurewebsites.net`
3. Copy the `Client ID`, `Client Secret`, and `Domain` for your `.env` file.

### 2. Azure Deployment

1. Deploy the Flask app to Azure App Service using the **Python 3.10** runtime.
2. Link the app to **Application Insights**.
3. Enable Diagnostic Settings:
   - Navigate to the App Service > Monitoring > Diagnostic Settings.
   - Ensure **AppServiceHTTPLogs** are sent to the connected **Log Analytics Workspace**.
   - Set up a Log Analytics workspace (e.g., `cst8919-logs`) and connect it to the App Service.

### 3. Running Locally

1. Create a `.env` file from `.env.example` and populate it with your Auth0 values.
2. Set up the virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

---

## Logging and Detection

### Logging Setup

- Logging is handled using Python’s built-in `logging` module in plain text format.
- Upon accessing `/protected`, the app logs the user’s ID, email, and timestamp.
- Logs appear in both **AppServiceHTTPLogs** and **Application Insights**.

### Querying Access Logs

```kql
AppServiceHTTPLogs
| where TimeGenerated > ago(15m)
| where CsUriStem == "/protected"
| summarize access_count = count(), timestamps = make_list(TimeGenerated) by client_ip = CIp
| where access_count > 10
```

>  **Note:** During implementation, `AppServiceConsoleLogs` did not capture custom trace logs as expected. After troubleshooting, we used `AppServiceHTTPLogs`, which logged requests to `/protected` accurately. This simplified detection but limited access to specific user metadata (e.g., user_id from token).

---

## Alert Configuration

- **Signal Type**: Custom log search
- **Query**: See above
- **Threshold**: access_count > 10
- **Aggregation granularity**: 5 minutes
- **Frequency**: 1 minute
- **Severity**: 3 (Low)
- **Notification**: Configured via Action Group to send alert email

---

## Testing with HTTP File

### test-app.http

```http
### Valid (authenticated) access to protected route
GET http://rahaf-auth0-app-1751775775.azurewebsites.net/protected
Authorization: Bearer <VALID_JWT_TOKEN>

### Invalid (unauthenticated) access to protected route
GET http://rahaf-auth0-app-1751775775.azurewebsites.net/protected
```

Replace `<VALID_JWT_TOKEN>` with a valid token from the Auth0 API tester.

---

### Manual Testing Steps

To simulate repeated access and trigger the alert:

1. Navigate to your deployed web app: `https://rahaf-auth0-app-1751775775.azurewebsites.net`

2. Log in via Auth0.

3. Access the `/protected` route more than 10 times within a 15-minute window.

4. In Azure, go to **Monitor > Logs** and run the KQL query above.

5. Verify that the alert was triggered:

   - Go to **Monitor > Alerts**.
   - Look for the triggered rule.
   - Check your email inbox for the Action Group notification.

---

## Reflection

### Successes
- Flask app successfully integrated with Auth0 and Azure Monitor
- `/protected` route logging worked reliably in AppServiceHTTPLogs
- Alert rule correctly triggered on repeated access

### Lessons Learned
- Some traces (like `app.logger.info`) were not appearing in `AppServiceConsoleLogs` as expected, requiring fallback to HTTP logs
- Structured logging could be improved to support deeper parsing in KQL
- For richer telemetry, future work may include sending logs directly using `opencensus-ext-azure`




