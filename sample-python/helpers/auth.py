import os
import time
import hmac
import hashlib
import json
import requests

# Retrieve API credentials from environment variables
api_key = os.getenv("AQUA_API_KEY")
api_secret = os.getenv("AQUA_API_SECRET")

if not api_key or not api_secret:
    raise ValueError("API key and secret must be set as environment variables AQUA_API_KEY and AQUA_API_SECRET.")


def headers(url: str, method: str, body: dict) -> dict:
    timestamp = str(int(time.time()))  # Use Unix timestamp in seconds
    path = "/v2/tokens"  # Path of the endpoint
    body_json = json.dumps(body, separators=(",", ":"))  # Compact JSON format

    # String to sign
    string_to_sign = f"{timestamp}{method}{path}{body_json}"

    # Create the HMAC signature
    secret_bytes = bytes(api_secret, "utf-8")
    string_bytes = bytes(string_to_sign, "utf-8")
    sig = hmac.new(secret_bytes, msg=string_bytes, digestmod=hashlib.sha256).hexdigest()

    # Construct the headers
    headers = {
        "accept": "application/json",
        "x-api-key": api_key,
        "x-signature": sig,
        "x-timestamp": timestamp,
        "content-type": "application/json",
    }
    return headers


def get_bearer_token():
    url = "https://api.cloudsploit.com/v2/tokens"
    method = "POST"
    body = {
        "validity": 240,  # Lifetime of the token in minutes
        "allowed_endpoints": ["GET"],  # Allowed API methods
    }

    # Generate headers for the request
    request_headers = headers(url, method, body)

    try:
        # Make the POST request
        response = requests.post(url, headers=request_headers, json=body)

        # Check the response status code
        if response.status_code == 200:
            data = response.json()
            print("Bearer Token:", data.get("data"))  # Assuming token is in the 'data' field
            return data.get("data")
        else:
            print(f"Error: Received status code {response.status_code}")
            print("Response:", response.text)
            return None
    except Exception as e:
        print("An error occurred:", str(e))
        return None


# Main block to call the function
if __name__ == "__main__":
    bearer_token = get_bearer_token()
    if bearer_token:
        print("Successfully retrieved bearer token!")
    else:
        print("Failed to retrieve bearer token.")
