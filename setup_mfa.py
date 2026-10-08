import pyotp
import qrcode

# 1. Generate a unique secret key for the user
# In a real app, you would save this secret in your database (e.g., PostgreSQL)
secret = pyotp.random_base32()
print(f"Your Secret Key (Save this!): {secret}")

# 2. Create a link for Google Authenticator
otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
    name="user@enterprise.com", 
    issuer_name="ZeroTrustApp"
)

# 3. Generate and save the QR Code image
img = qrcode.make(otp_uri)
img.save("mfa_qr_code.png")

print("Success! Scan 'mfa_qr_code.png' with your Google Authenticator app.")